"""Merge-request content for ledger finding ids (VG-001) and multi-finding branches."""
from __future__ import annotations

import json

import pytest

from src.services import gitlab_mr

REMOTE = "https://gitlab.corp.example/team/app.git"

INDEX = {"total_vulnerabilities": 3, "by_type": {
    "injection": [{
        "ID": "VG-001", "title": "SQL injection in the search endpoint", "category": "injection",
        "category_label": "SQL Injection", "vulnerability_type": "injection", "severity": "high",
        "confidence": "high", "file": "app/search.py", "line": 42, "cwe": "CWE-89",
        "description": "User input is concatenated into the query.",
        "source": "request.args['q']", "sink": "cursor.execute(query)",
        "entry_point": "GET /search", "attack_path": "q=' OR 1=1 -- dumps the users table",
        "status": "exploited", "verdict": "confirmed",
        "verdict_summary": "The harness dumped all rows through the q parameter.",
        "harness_path": "deliverables/harness/VG-001.py",
        "screenshots": ["screenshots/vg_001_dump.png"],
    }],
    "xss": [{
        "ID": "VG-002", "title": "Reflected XSS in the greeting", "category": "xss",
        "severity": "medium", "status": "potential", "file": "web/greet.py", "line": 7,
        "sink": "render_template_string(name)", "verdict_summary": "Reachable, not proven.",
    }],
}}


@pytest.fixture
def deliv(tmp_path):
    d = tmp_path / "repo" / "deliverables"
    (d / "evidence").mkdir(parents=True)
    (d / "screenshots").mkdir()
    (d / "findings_index.json").write_text(json.dumps(INDEX))
    (d / "evidence" / "VG-001.md").write_text("Request `GET /search?q=' OR 1=1 --` returned 57 users.")
    (d / "screenshots" / "vg_001_dump.png").write_bytes(b"x")
    (d / "screenshots" / "unrelated_0010.png").write_bytes(b"x")   # shares the digits "001"
    (d / "screenshots" / "vg_0010.png").write_bytes(b"x")
    return tmp_path / "repo"


def manifest(repo, branches):
    (repo / "deliverables" / "remediation_manifest.json").write_text(json.dumps({"branches": branches}))


@pytest.fixture
def api(monkeypatch):
    calls = []

    def fake(url, token, method, endpoint, data=None):
        calls.append((method, endpoint, data))
        if method == "GET":
            return {"default_branch": "main"}
        return {"web_url": "https://gitlab.corp.example/team/app/-/merge_requests/3", "iid": 3}

    monkeypatch.setattr(gitlab_mr, "_gitlab_api_request", fake)
    return calls


class TestLedgerIds:
    async def test_vg_001_title_and_description(self, deliv, api):
        manifest(deliv, [{"branch": "fix/VG-001", "finding_ids": ["VG-001"]}])
        out = await gitlab_mr.create_remediation_mrs(
            str(deliv), "sess", ["fix/VG-001"], token="t", remote_url=REMOTE)
        assert out["created"][0]["mr_url"].endswith("/3")
        data = [c for c in api if c[0] == "POST"][0][2]
        assert "Unknown" not in data["title"] and "unknown" not in data["description"].lower()
        assert data["title"].startswith("[HIGH] Fix VG-001: SQL injection in the search endpoint")
        d = data["description"]
        assert "SQL Injection" in d                              # category label
        assert "cursor.execute(query)" in d                      # sink
        assert "request.args['q']" in d                          # source
        assert "The harness dumped all rows" in d                # verdict summary
        assert "returned 57 users" in d                          # evidence write-up
        assert "Exploited" in d and "CWE-89" in d and "app/search.py:42" in d
        assert "User input is concatenated" in d                 # root cause
        assert "vg_001_dump.png" in d
        assert "unrelated_0010.png" not in d and "vg_0010.png" not in d   # no bare-digit matches
        assert data["target_branch"] == "main" and data["source_branch"] == "fix/VG-001"

    async def test_one_mr_per_branch_covering_several_findings(self, deliv, api):
        manifest(deliv, [{"branch": "fix/VG-001-VG-002", "finding_ids": ["VG-001", "VG-002"]}])
        out = await gitlab_mr.create_remediation_mrs(
            str(deliv), "sess", ["fix/VG-001-VG-002"], token="t", remote_url=REMOTE)
        assert len(out["created"]) == 1 and out["created"][0]["finding_ids"] == ["VG-001", "VG-002"]
        posts = [c for c in api if c[0] == "POST"]
        assert len(posts) == 1
        data = posts[0][2]
        assert data["title"].startswith("[HIGH] Fix VG-001, VG-002:")
        for needle in ("VG-001", "VG-002", "cursor.execute(query)", "render_template_string(name)",
                       "Reachable, not proven.", "Potential"):
            assert needle in data["description"]

    async def test_branch_name_is_used_when_manifest_lacks_the_branch(self, deliv, api):
        manifest(deliv, [])
        await gitlab_mr.create_remediation_mrs(
            str(deliv), "s", ["fix/VG-001-VG-002"], token="t", remote_url=REMOTE)
        data = [c for c in api if c[0] == "POST"][0][2]
        assert "SQL Injection" in data["description"] and "Reflected XSS" in data["description"]

    async def test_legacy_ids_still_work(self, tmp_path, api):
        d = tmp_path / "r" / "deliverables"
        d.mkdir(parents=True)
        (d / "findings_index.json").write_text(json.dumps({"by_type": {"injection": [
            {"ID": "INJ-VULN-01", "severity": "critical", "status": "exploited",
             "vulnerability_type": "injection"}]}}))
        (d / "injection_exploitation_evidence.md").write_text(
            "### INJ-VULN-01 proof\nlegacy evidence text\n\n### INJ-VULN-02\nother\n")
        await gitlab_mr.create_remediation_mrs(
            str(tmp_path / "r"), "s", ["fix/INJ-VULN-01"], token="t", remote_url=REMOTE)
        data = [c for c in api if c[0] == "POST"][0][2]
        assert data["title"].startswith("[CRITICAL] Fix INJ-VULN-01")
        assert "legacy evidence text" in data["description"] and "other" not in data["description"]

    async def test_target_comes_from_the_argument_not_from_files(self, deliv, api):
        (deliv / ".vigilo-remote-url").write_text("https://evil.example/x/y.git\n")
        await gitlab_mr.create_remediation_mrs(
            str(deliv), "s", ["fix/VG-001"], token="t", remote_url=REMOTE)
        assert any("team%2Fapp" in c[1] for c in api)
        with pytest.raises(RuntimeError):
            await gitlab_mr.create_remediation_mrs(str(deliv), "s", ["fix/VG-001"], token="t", remote_url="")

    def test_screenshot_matching_requires_the_full_id(self, deliv):
        shots = gitlab_mr._find_screenshots(str(deliv), "VG-001")
        assert [p.name for p in shots] == ["vg_001_dump.png"]   # not vg_0010 / unrelated_0010
        (deliv / "deliverables" / "screenshots" / "VG-001-login.png").write_bytes(b"x")
        names = [p.name for p in gitlab_mr._find_screenshots(str(deliv), "VG-001")]
        assert names == ["VG-001-login.png", "vg_001_dump.png"]
