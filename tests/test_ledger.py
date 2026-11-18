"""Findings ledger (src/pipeline/ledger.py) and the vigilo-record CLI."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

from src.pipeline.ledger import (
    Ledger,
    LedgerError,
    build_findings_index,
    coverage_summary,
)
from src.services.findings_aggregator import FindingsAggregator

CLI = Path(__file__).resolve().parent.parent / "scripts" / "vigilo_record.py"


def _finding(**over):
    base = {
        "title": "SQL injection in order search",
        "description": "The q parameter is concatenated into a raw query.",
        "severity": "high",
        "category": "injection",
        "location": {"file": "app/orders.py", "line": 88},
        "cwe": "89",
    }
    base.update(over)
    return base


@pytest.fixture
def ledger(tmp_path) -> Ledger:
    return Ledger.for_repo(tmp_path)


class TestValidation:
    def test_finding_gets_id_and_normalised_fields(self, ledger):
        rec = ledger.record("finding", _finding(severity="HIGH"), actor="investigator-1")
        assert rec["id"] == "VG-001"
        assert rec["severity"] == "high"
        assert rec["cwe"] == "CWE-89"
        assert rec["confidence"] == "medium"
        assert rec["recorded_by"] == "investigator-1"

    def test_location_string_is_accepted(self, ledger):
        rec = ledger.record("finding", _finding(location="app/views.py:42"))
        assert rec["location"] == {"file": "app/views.py", "line": 42}

    def test_unknown_category_is_kept_not_rejected(self, ledger):
        rec = ledger.record("finding", _finding(category="Race condition"))
        assert rec["category"] == "other"
        assert rec["category_label"] == "Race condition"

    def test_all_problems_reported_at_once(self, ledger):
        with pytest.raises(LedgerError) as exc:
            ledger.record("finding", {"severity": "catastrophic", "cwe": "nope"})
        joined = " | ".join(exc.value.problems)
        for needle in ("'title'", "'description'", "'severity'", "'location'", "'cwe'"):
            assert needle in joined

    def test_verdict_must_reference_known_finding(self, ledger):
        with pytest.raises(LedgerError, match="no recorded finding"):
            ledger.record("verdict", {"finding_id": "VG-404", "verdict": "exploited",
                                      "summary": "x"})

    def test_confirmed_verdict_requires_harness_path(self, ledger):
        ledger.record("finding", _finding())
        with pytest.raises(LedgerError, match="harness_path"):
            ledger.record("verdict", {"finding_id": "VG-001", "verdict": "Confirmed",
                                      "summary": "harness ran"})
        rec = ledger.record("verdict", {"finding_id": "VG-001", "verdict": "confirmed",
                                        "summary": "harness ran",
                                        "harness_path": "deliverables/harnesses/VG-001_harness.py"})
        assert rec["verdict"] == "confirmed"
        # other verdicts do not need one
        ledger.record("verdict", {"finding_id": "VG-001", "verdict": "not_testable", "summary": "s"})

    def test_verdict_spelling_variants(self, ledger):
        ledger.record("finding", _finding())
        rec = ledger.record("verdict", {"finding_id": "VG-001", "verdict": "False-Positive",
                                        "summary": "input is an enum"})
        assert rec["verdict"] == "false_positive"

    def test_lead_priority_bounds(self, ledger):
        with pytest.raises(LedgerError, match="priority"):
            ledger.record("lead", {"title": "t", "hypothesis": "h", "priority": 9})

    def test_chain_needs_two_known_findings(self, ledger):
        ledger.record("finding", _finding())
        with pytest.raises(LedgerError) as exc:
            ledger.record("chain", {"title": "c", "narrative": "n", "severity": "high",
                                    "finding_ids": ["VG-001", "VG-777"]})
        assert "VG-777" in str(exc.value)

    def test_chain_needs_two_distinct_findings(self, ledger):
        ledger.record("finding", _finding())
        with pytest.raises(LedgerError, match="two different"):
            ledger.record("chain", {"title": "c", "narrative": "n", "severity": "high",
                                    "finding_ids": ["VG-001", "VG-001"]})
        assert ledger.chains() == {}

    def test_chain_duplicate_ids_are_collapsed(self, ledger):
        ledger.record("finding", _finding())
        ledger.record("finding", _finding(title="second", location="app/orders.py:300"))
        rec = ledger.record("chain", {"title": "c", "narrative": "n", "severity": "high",
                                      "finding_ids": ["VG-001", "VG-002", "VG-001"]})
        assert rec["finding_ids"] == ["VG-001", "VG-002"]


class TestBatches:
    """An array call is all or nothing, so an agent can resend it whole."""

    def test_invalid_item_stores_nothing(self, ledger):
        with pytest.raises(LedgerError) as exc:
            ledger.record_many("lead", [{"title": "a", "hypothesis": "h"}, {"title": "b"}])
        assert exc.value.problems == ["item 2: 'hypothesis' is required and must be a non-empty string"]
        assert ledger.raw("lead") == []

    def test_unknown_reference_in_batch_stores_nothing(self, ledger):
        ledger.record("lead", {"title": "a", "hypothesis": "h"})
        with pytest.raises(LedgerError, match="item 2: no recorded lead"):
            ledger.record_many("lead-done", [{"lead_id": "L-001", "outcome": "clean"},
                                             {"lead_id": "L-404", "outcome": "clean"}])
        assert ledger.lead_status() == {}

    def test_valid_batch_gets_consecutive_ids(self, ledger):
        ledger.record("finding", _finding())
        recs = ledger.record_many("finding", [_finding(title="x", location="app/orders.py:200"),
                                              _finding(id="VG-001", title="fix"),
                                              _finding(title="y", location="app/orders.py:300")])
        assert [r["id"] for r in recs] == ["VG-002", "VG-001", "VG-003"]
        assert ledger.findings()["VG-001"]["title"] == "fix"

    def test_resending_fixed_batch_does_not_duplicate(self, ledger):
        batch = [{"title": "a", "hypothesis": "h"}, {"title": "b"}]
        with pytest.raises(LedgerError):
            ledger.record_many("lead", batch)
        batch[1]["hypothesis"] = "h2"
        ledger.record_many("lead", batch)
        assert sorted(ledger.leads()) == ["L-001", "L-002"]

    def test_non_object_item_rejected(self, ledger):
        with pytest.raises(LedgerError, match="item 2: the record must be a JSON object"):
            ledger.record_many("lead", [{"title": "a", "hypothesis": "h"}, "nope"])
        assert ledger.raw("lead") == []


class TestLedgerState:
    def test_rerecording_same_id_supersedes(self, ledger):
        ledger.record("finding", _finding())
        ledger.record("finding", _finding(id="VG-001", severity="low"))
        assert ledger.findings()["VG-001"]["severity"] == "low"
        assert len(ledger.raw("finding")) == 2

    def test_unknown_client_id_is_replaced(self, ledger):
        rec = ledger.record("finding", _finding(id="MY-OWN-ID"))
        assert rec["id"] == "VG-001"

    def test_open_leads_sorted_by_priority(self, ledger):
        ledger.record("lead", {"title": "a", "hypothesis": "h", "priority": 4})
        ledger.record("lead", {"title": "b", "hypothesis": "h", "priority": 1})
        ledger.record("lead", {"title": "c", "hypothesis": "h", "priority": 2})
        ledger.record("lead-done", {"lead_id": "L-003", "outcome": "clean"})
        assert [lead["title"] for lead in ledger.open_leads()] == ["b", "a"]

    def test_torn_line_is_ignored(self, ledger):
        ledger.record("finding", _finding())
        with open(ledger.path("finding"), "a") as fh:
            fh.write('{"id": "VG-00')
        assert list(ledger.findings()) == ["VG-001"]

    def test_coverage_summary(self, ledger):
        ledger.record("lead", {"title": "a", "hypothesis": "h"})
        ledger.record("lead", {"title": "b", "hypothesis": "h"})
        ledger.record("finding", _finding(lead_id="L-001"))
        ledger.record("lead-done", {"lead_id": "L-001", "outcome": "finding",
                                    "finding_ids": ["VG-001"]})
        cov = coverage_summary(ledger)
        assert cov["leads_total"] == 2 and cov["leads_open"] == 1
        assert cov["findings_unproven"] == ["VG-001"]
        assert cov["outcomes"]["finding"] == 1


def _record_many(args):
    root, worker = args
    ledger = Ledger.for_repo(root)
    for i in range(15):
        ledger.record("finding", _finding(title=f"w{worker}-{i}",
                                         location=f"app/w{worker}.py:{i * 100 + 1}"))


def test_parallel_writers_get_unique_ids(tmp_path):
    with ProcessPoolExecutor(max_workers=4) as pool:
        list(pool.map(_record_many, [(str(tmp_path), w) for w in range(4)]))
    findings = Ledger.for_repo(tmp_path).findings()
    assert len(findings) == 60
    assert sorted(findings) == [f"VG-{i:03d}" for i in range(1, 61)]


class TestIndex:
    def test_index_shape_matches_downstream_contract(self, ledger):
        ledger.record("finding", _finding(code_fixable=True))
        ledger.record("finding", _finding(title="IDOR on invoices", category="authorization",
                                          location="app/invoices.py:12"))
        ledger.record("finding", _finding(title="Debug endpoint", category="configuration",
                                          location="app/debug.py"))
        ledger.record("verdict", {"finding_id": "VG-001", "verdict": "exploited",
                                  "summary": "dumped users table", "evidence_ref": "evidence/VG-001.md"})
        ledger.record("verdict", {"finding_id": "VG-002", "verdict": "confirmed",
                                  "summary": "harness", "harness_path": "deliverables/h/VG-002.py"})
        ledger.record("verdict", {"finding_id": "VG-003", "verdict": "refuted",
                                  "summary": "disabled in production settings"})
        ledger.record("chain", {"title": "c", "narrative": "n", "severity": "critical",
                                "finding_ids": ["VG-001", "VG-002"], "status": "exploited"})

        index = build_findings_index(ledger)
        assert index["total_vulnerabilities"] == 4
        inj = index["by_type"]["injection"][0]
        assert inj["ID"] == "VG-001" and inj["status"] == "exploited"
        assert inj["file"] == "app/orders.py" and inj["line"] == 88
        assert inj["evidence_ref"] == "evidence/VG-001.md"
        authz = index["by_type"]["authorization"][0]
        assert authz["status"] == "potential" and authz["harness_confirmed"] is True
        assert authz["harness_path"] == "deliverables/h/VG-002.py"
        cfg = index["by_type"]["configuration"][0]
        assert cfg["status"] == "suppressed"
        assert cfg["suppression_reason"] == "disabled in production settings"
        chain = index["by_type"]["chain"][0]
        assert chain["chain_components"] == ["VG-001", "VG-002"] and chain["code_fixable"] is False

    async def test_aggregator_includes_ledger(self, tmp_path):
        ledger = Ledger.for_repo(tmp_path)
        ledger.record("finding", _finding())
        index = await FindingsAggregator().aggregate_and_write(str(tmp_path))
        assert index["by_type"]["injection"][0]["ID"] == "VG-001"
        on_disk = json.loads((tmp_path / "deliverables" / "findings_index.json").read_text())
        assert on_disk["total_vulnerabilities"] == 1


def _make_repo(path: Path) -> Path:
    """A minimal checkout: ``.git`` and ``deliverables/`` at the root."""
    (path / ".git").mkdir(parents=True, exist_ok=True)
    (path / "deliverables").mkdir(exist_ok=True)
    return path


class TestCli:
    def _run(self, cwd, *args, stdin=None, env=None):
        _make_repo(Path(cwd))
        proc = subprocess.run(
            [sys.executable, str(CLI), *args], cwd=cwd, input=stdin,
            capture_output=True, text=True, env={**os.environ, **(env or {})},
        )
        return proc.returncode, json.loads(proc.stdout)

    def test_record_and_show_roundtrip(self, tmp_path):
        code, out = self._run(tmp_path, "lead", "--json", json.dumps(
            [{"title": "a", "hypothesis": "h"}, {"title": "b", "hypothesis": "h", "priority": 1}]))
        assert code == 0 and out["ids"] == ["L-001", "L-002"]

        code, out = self._run(tmp_path, "finding", stdin=json.dumps(_finding(lead_id="L-001")),
                              env={"VIGILO_AGENT": "investigator-2"})
        assert code == 0 and out["ids"] == ["VG-001"]

        (tmp_path / "VG-001.md").write_text("# Evidence\nrequest/response here")
        code, out = self._run(tmp_path, "verdict", "--evidence-file", "VG-001.md", "--json",
                              json.dumps({"finding_id": "VG-001", "verdict": "exploited",
                                          "summary": "worked"}))
        assert code == 0
        assert (tmp_path / "deliverables" / "evidence" / "VG-001.md").is_file()

        code, out = self._run(tmp_path, "show", "leads", "--open")
        assert [lead["id"] for lead in out["leads"]] == ["L-002", "L-001"]
        code, out = self._run(tmp_path, "show", "finding", "VG-001")
        assert out["finding"]["recorded_by"] == "investigator-2"
        assert out["verdict"]["evidence_ref"] == "evidence/VG-001.md"

    def test_invalid_record_lists_problems_and_fails(self, tmp_path):
        code, out = self._run(tmp_path, "finding", "--json", '{"title": "x"}')
        assert code == 1 and out["status"] == "invalid"
        assert any("'location'" in p for p in out["problems"])

    def test_bad_json(self, tmp_path):
        code, out = self._run(tmp_path, "lead", "--json", "{nope")
        assert code == 1 and "not valid JSON" in out["problems"][0]

    def test_file_outside_repo_rejected(self, tmp_path):
        code, out = self._run(tmp_path, "finding", "--file", "/etc/hosts")
        assert code == 1 and "inside the repository" in out["problems"][0]

    def test_array_with_invalid_item_stores_nothing(self, tmp_path):
        code, out = self._run(tmp_path, "lead", "--json", json.dumps(
            [{"title": "a", "hypothesis": "h"}, {"title": "b"}]))
        assert code == 1 and out["status"] == "invalid"
        assert "recorded" not in out
        assert out["problems"] == ["item 2: 'hypothesis' is required and must be a non-empty string"]
        assert Ledger.for_repo(tmp_path).raw("lead") == []

    def test_rejected_verdict_leaves_evidence_untouched(self, tmp_path):
        self._run(tmp_path, "finding", "--json", json.dumps(_finding()))
        evidence = tmp_path / "deliverables" / "evidence"
        (tmp_path / "good.md").write_text("good")
        (tmp_path / "bad.md").write_text("bad")
        code, _ = self._run(tmp_path, "verdict", "--evidence-file", "good.md", "--json",
                            json.dumps({"finding_id": "VG-001", "verdict": "exploited", "summary": "s"}))
        assert code == 0
        # An invalid verdict must not overwrite the stored write-up ...
        code, out = self._run(tmp_path, "verdict", "--evidence-file", "bad.md", "--json",
                              json.dumps({"finding_id": "VG-001", "verdict": "bogus", "summary": "s"}))
        assert code == 1 and any("'verdict'" in p for p in out["problems"])
        assert (evidence / "VG-001.md").read_text() == "good"
        # ... and a verdict for an unknown finding must not leave an orphan file.
        code, out = self._run(tmp_path, "verdict", "--evidence-file", "bad.md", "--json",
                              json.dumps({"finding_id": "VG-999", "verdict": "exploited", "summary": "s"}))
        assert code == 1 and "no recorded finding" in out["problems"][0]
        assert sorted(p.name for p in evidence.iterdir()) == ["VG-001.md"]

    def test_missing_evidence_file_is_reported(self, tmp_path):
        self._run(tmp_path, "finding", "--json", json.dumps(_finding()))
        code, out = self._run(tmp_path, "verdict", "--evidence-file", "missing.md", "--json",
                              json.dumps({"finding_id": "VG-001", "verdict": "exploited", "summary": "s"}))
        assert code == 1 and "cannot read --evidence-file" in out["problems"][0]
        assert Ledger.for_repo(tmp_path).verdicts() == {}


class TestRepoRootResolution:
    """vigilo-record must hit the one ledger however the agent's cwd drifts."""

    def _cli(self, cwd, *args, env=None, unset=()):
        base = {k: v for k, v in os.environ.items() if k not in unset}
        proc = subprocess.run([sys.executable, str(CLI), *args], cwd=cwd, capture_output=True,
                              text=True, env={**base, **(env or {})})
        return proc.returncode, json.loads(proc.stdout)

    def test_subdirectory_reaches_the_repo_ledger(self, tmp_path):
        repo = _make_repo(tmp_path / "repo")
        sub = repo / "src" / "pkg"
        sub.mkdir(parents=True)
        code, out = self._cli(repo, "lead", "--json", '{"title": "a", "hypothesis": "h"}',
                              unset=("VIGILO_REPO_PATH",))
        assert code == 0 and out["ids"] == ["L-001"]
        code, out = self._cli(sub, "lead", "--json", '{"title": "b", "hypothesis": "h"}',
                              unset=("VIGILO_REPO_PATH",))
        assert code == 0 and out["ids"] == ["L-002"]
        assert not (sub / "deliverables").exists()
        code, out = self._cli(sub, "show", "leads", unset=("VIGILO_REPO_PATH",))
        assert [lead["id"] for lead in out["leads"]] == ["L-001", "L-002"]

    def test_first_record_from_subdirectory_uses_symlinked_deliverables(self, tmp_path):
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        out_dir = tmp_path / "out" / "deliverables"
        out_dir.mkdir(parents=True)
        (repo / "deliverables").symlink_to(out_dir)
        (repo / "sub").mkdir()
        code, out = self._cli(repo / "sub", "lead", "--json", '{"title": "a", "hypothesis": "h"}',
                              unset=("VIGILO_REPO_PATH",))
        assert code == 0 and out["ids"] == ["L-001"]
        assert (out_dir / "ledger" / "leads.jsonl").is_file()
        assert not (repo / "sub" / "deliverables").exists()

    def test_env_var_wins_over_cwd(self, tmp_path):
        repo = _make_repo(tmp_path / "repo")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        code, out = self._cli(elsewhere, "lead", "--json", '{"title": "a", "hypothesis": "h"}',
                              env={"VIGILO_REPO_PATH": str(repo)})
        assert code == 0 and out["ids"] == ["L-001"]
        assert (repo / "deliverables" / "ledger" / "leads.jsonl").is_file()
        assert not (elsewhere / "deliverables").exists()

    def test_no_repo_fails_loudly_and_creates_nothing(self, tmp_path):
        stray = tmp_path / "stray"
        stray.mkdir()
        for args in (("lead", "--json", '{"title": "a", "hypothesis": "h"}'), ("show", "summary")):
            code, out = self._cli(stray, *args, unset=("VIGILO_REPO_PATH",))
            assert code == 1 and out["status"] == "invalid"
            assert "repository root" in out["problems"][0]
        assert list(stray.iterdir()) == []

    def test_env_var_without_deliverables_fails(self, tmp_path):
        code, out = self._cli(tmp_path, "show", "summary",
                              env={"VIGILO_REPO_PATH": str(tmp_path / "nope")})
        assert code == 1 and "VIGILO_REPO_PATH" in out["problems"][0]

    def test_evidence_file_written_to_repo_not_cwd(self, tmp_path):
        repo = _make_repo(tmp_path / "repo")
        sub = repo / "a"
        sub.mkdir()
        unset = ("VIGILO_REPO_PATH",)
        self._cli(repo, "finding", "--json", json.dumps(_finding()), unset=unset)
        (sub / "w.md").write_text("walkthrough")
        code, _ = self._cli(sub, "verdict", "--evidence-file", "w.md", "--json", json.dumps(
            {"finding_id": "VG-001", "verdict": "exploited", "summary": "s"}), unset=unset)
        assert code == 0
        assert (repo / "deliverables" / "evidence" / "VG-001.md").read_text() == "walkthrough"
        assert not (sub / "deliverables").exists()

    def test_discover_helper(self, tmp_path):
        from src.pipeline.ledger import LedgerLocationError, find_repo_root
        repo = _make_repo(tmp_path / "repo")
        (repo / "x" / "y").mkdir(parents=True)
        assert find_repo_root(repo / "x" / "y", env={}) == repo.resolve()
        with pytest.raises(LedgerLocationError):
            find_repo_root(tmp_path, env={})
