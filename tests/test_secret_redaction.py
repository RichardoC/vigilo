"""Cookie redaction: encoded forms, the MR text, the final deliverables pass, and the
non-redirecting GitLab client."""
from __future__ import annotations

import html
import os
import urllib.error
import urllib.parse

import pytest

from src.audit import redact as redact_mod
from src.audit.redact import redact, register_secret
from src.services import gitlab_mr
from src.services.deliverable_redact import redact_tree

COOKIE = "session=abc/def+ghi==; csrftoken=Zx9&y<z>\"q'"


@pytest.fixture(autouse=True)
def _clean():
    redact_mod.clear()
    yield
    redact_mod.clear()


class TestRedactForms:
    def test_url_and_html_encoded_forms_are_masked(self):
        register_secret(COOKIE)
        value = "abc/def+ghi=="
        for form in (
            COOKIE, urllib.parse.quote(COOKIE), urllib.parse.quote(COOKIE, safe=""),
            urllib.parse.quote_plus(COOKIE), html.escape(COOKIE), html.escape(COOKIE, quote=False),
            urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value), value,
            html.escape("Zx9&y<z>\"q'"), urllib.parse.quote("Zx9&y<z>\"q'", safe=""),
        ):
            assert redact(f"before {form} after") == "before *** after", form


class TestMrText:
    async def test_cookie_in_evidence_never_reaches_the_mr(self, tmp_path, monkeypatch):
        register_secret("session=SUPERSECRETCOOKIE123")
        ledger = tmp_path / "deliverables" / "evidence"
        ledger.mkdir(parents=True)
        (ledger / "VG-001.md").write_text(
            "curl -H 'Cookie: session=SUPERSECRETCOOKIE123' https://t/x\n"
            "encoded session%3DSUPERSECRETCOOKIE123\n")
        (tmp_path / "deliverables" / "findings_index.json").write_text(
            '{"by_type": {"x": [{"ID": "VG-001", "title": "SUPERSECRETCOOKIE123 in title", "severity": "high"}]}}')
        sent = []

        def fake(url, token, method, endpoint, data=None):
            sent.append((method, data))
            return {"default_branch": "main"} if method == "GET" else {"web_url": "u", "iid": 1}

        monkeypatch.setattr(gitlab_mr, "_gitlab_api_request", fake)
        await gitlab_mr.create_remediation_mrs(
            str(tmp_path), "s", ["fix/VG-001"], token="t", remote_url="https://gl.example/g/p.git")
        post = next(d for m, d in sent if m == "POST")
        assert "SUPERSECRETCOOKIE123" not in post["description"] + post["title"]
        assert "***" in post["description"]


class TestDeliverablesPass:
    def test_rewrites_text_skips_binaries_and_symlinks(self, tmp_path):
        register_secret("session=ABCDEFGH12345")
        d = tmp_path / "repo" / ".vigilo" / "s1" / "deliverables"
        (d / "evidence").mkdir(parents=True)
        (d / "report.md").write_text("Cookie: session=ABCDEFGH12345\n")
        (d / "evidence" / "VG-1.md").write_text("x session%3DABCDEFGH12345 y ABCDEFGH12345")
        (d / "shot.png").write_bytes(b"\x89PNG\0\0session=ABCDEFGH12345")
        outside = tmp_path / "outside.txt"
        outside.write_text("session=ABCDEFGH12345")
        os.symlink(outside, d / "link.md")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "a.md").write_text("session=ABCDEFGH12345")
        os.symlink(elsewhere, d / "linkdir")
        stats = redact_tree(str(tmp_path / "repo"), ".vigilo", "s1", "deliverables")
        assert stats["redacted"] == 2 and stats["errors"] == 0
        assert (d / "report.md").read_text() == "Cookie: ***\n"
        assert "ABCDEFGH12345" not in (d / "evidence" / "VG-1.md").read_text()
        assert b"ABCDEFGH12345" in (d / "shot.png").read_bytes()        # binary untouched
        assert outside.read_text() == "session=ABCDEFGH12345"            # symlink target untouched
        assert (elsewhere / "a.md").read_text() == "session=ABCDEFGH12345"
        assert os.path.islink(d / "link.md")
        assert not [p for p in os.listdir(d) if "vigilo-redact" in p]

    def test_symlinked_deliverables_dir_is_left_alone(self, tmp_path):
        register_secret("session=ABCDEFGH12345")
        real = tmp_path / "real"
        real.mkdir()
        (real / "r.md").write_text("session=ABCDEFGH12345")
        ws = tmp_path / "repo" / ".vigilo" / "s1"
        ws.mkdir(parents=True)
        os.symlink(real, ws / "deliverables")
        assert redact_tree(str(tmp_path / "repo"), ".vigilo", "s1", "deliverables")["scanned"] == 0
        assert (real / "r.md").read_text() == "session=ABCDEFGH12345"

    async def test_activity_redeems_cookie_then_redacts(self, tmp_path, monkeypatch):
        from tests.test_whitebox_engine import ActivityInput, acts  # noqa: F401
        from src.services import run_secrets
        asked = []

        async def fake(secrets, want, **kw):
            asked.append(list(want))
            register_secret("session=ABCDEFGH12345")
            return {"cookie_header": "session=ABCDEFGH12345"}

        monkeypatch.setattr(run_secrets, "redeem", fake)
        d = tmp_path / "repo" / ".vigilo" / "s1" / "deliverables"
        d.mkdir(parents=True)
        (d / "report.md").write_text("leak session=ABCDEFGH12345")
        ai = ActivityInput(repo_path=str(tmp_path / "repo"), session_id="s1", workflow_id="w",
                           auth={"cookie": True}, secrets={"ref": "r" * 8, "key": "k" * 32})
        out = await acts.redact_deliverables(ai)
        assert asked == [["cookie_header"]] and out["redacted"] == 1
        assert "ABCDEFGH12345" not in (d / "report.md").read_text()


class TestGitlabClientDoesNotFollowRedirects:
    def test_redirect_is_an_error_and_token_is_not_replayed(self):
        import http.server
        import threading

        hits = []

        class Evil(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.headers.get("PRIVATE-TOKEN"))
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/stolen")
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), Evil)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with pytest.raises(RuntimeError, match="redirect"):
                gitlab_mr._gitlab_api_request(f"http://127.0.0.1:{srv.server_port}", "glpat-T", "GET", "/projects/1")
        finally:
            srv.shutdown()
        assert hits == ["glpat-T"]   # exactly one request: the redirect target was never contacted
