"""Offline end-to-end test of the structured hand-off (no Docker/LLM).

Simulates what an engine run produces — findings and verdicts in the ledger, a
critic adjudication — then runs the REAL aggregator and recall guard over them
and asserts the false-positive-reduction behaviour holds end-to-end:

  * confirmed true positives keep their status/severity,
  * a prover false_positive is suppressed (kept + reasoned, not exploited),
  * the guard passes when the critique is complete and floor-compliant,
  * the guard flags a silently-dropped finding and a buried serious+reachable one.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.pipeline.ledger import Ledger  # noqa: E402
from src.services.findings_aggregator import FindingsAggregator  # noqa: E402
from src.services.findings_guard import audit_critique  # noqa: E402
from src.services.patch_verify import verify_patches  # noqa: E402


def _finding(title: str, file: str, line: int, category: str = "injection", **over) -> dict:
    base = {
        "title": title, "description": f"{title}.", "severity": "high",
        "category": category, "location": {"file": file, "line": line},
    }
    base.update(over)
    return base


def test_code_only_run_produces_potential_and_verifies_patches(tmp_path: Path):
    """A code-only run confirms findings via harness -> `potential`, SCA dedups,
    and verify_patches classifies the fix branches."""
    d = tmp_path / "deliverables"
    ledger = Ledger(d)
    for n in (1, 2, 3):
        ledger.record("finding", _finding(f"Injection {n}", f"app/m{n}.py", 10 * n))
    ledger.record("verdict", {"finding_id": "VG-001", "verdict": "confirmed", "summary": "s",
                              "harness_path": "harnesses/VG-001.py"})
    ledger.record("verdict", {"finding_id": "VG-002", "verdict": "not_testable", "summary": "s"})
    ledger.record("verdict", {"finding_id": "VG-003", "verdict": "refuted",
                              "summary": "parameterised; no effect"})
    # SCA with duplicates
    (d / "sca_findings.json").write_text(json.dumps({"vulnerabilities": [
        {"package": "lodash", "cve_ids": ["CVE-1"]},
        {"package": "lodash", "cve_ids": ["CVE-1"]},   # dup
        {"package": "minimatch", "cve_ids": ["CVE-2"]},
    ]}))
    index = asyncio.run(FindingsAggregator().aggregate_and_write(str(tmp_path)))
    by = {v["ID"]: v for vs in index["by_type"].values() for v in vs if v.get("ID")}
    assert by["VG-001"]["status"] == "potential" and by["VG-001"]["harness_confirmed"] is True
    assert by["VG-002"]["status"] == "potential"
    assert by["VG-003"]["status"] == "suppressed"
    # SCA deduped 3 -> 2
    assert len(index["by_type"]["supply_chain"]) == 2

    # verify_patches over a manifest (stub checker: VG-001 fixed via harness)
    (d / "remediation_manifest.json").write_text(json.dumps({"branches": [
        {"branch": "fix/VG-001", "finding_ids": ["VG-001"], "pushed": False, "diff_nonempty": True},
    ]}))
    summary = asyncio.run(verify_patches(str(tmp_path),
        checker=lambda b, ids, hp: {"verified": "pass", "method": "harness"}))
    assert summary["verified"] == 1


def _seed_deliverables(repo: Path) -> Path:
    d = repo / "deliverables"
    ledger = Ledger(d)
    ledger.record("finding", _finding("SQL injection", "app/db.py", 10))              # VG-001
    ledger.record("finding", _finding("Command injection", "app/ping.py", 40))        # VG-002
    ledger.record("finding", _finding("SQL injection (dup)", "app/db2.py", 90))       # VG-003
    ledger.record("finding", _finding("SSRF in fetch", "app/fetch.py", 7, "ssrf"))    # VG-004
    ledger.record("finding", _finding("MD5 password hash", "app/pw.py", 3, "cryptography",
                                      severity="medium"))                             # VG-005
    ledger.record("verdict", {"finding_id": "VG-001", "verdict": "exploited", "summary": "s"})
    ledger.record("verdict", {"finding_id": "VG-002", "verdict": "exploited", "summary": "s"})
    ledger.record("verdict", {"finding_id": "VG-003", "verdict": "false_positive",
                              "summary": "same sink as VG-001; not a distinct bug"})
    ledger.record("verdict", {"finding_id": "VG-004", "verdict": "exploited", "summary": "s"})
    # VG-005: no verdict
    return d


def _by_id(index: dict) -> dict:
    out = {}
    for vulns in index["by_type"].values():
        for v in vulns:
            out[v.get("ID") or v.get("id")] = v
    return out


def test_aggregator_handoff_reduces_false_positives(tmp_path: Path):
    repo = tmp_path
    _seed_deliverables(repo)

    index = asyncio.run(FindingsAggregator().aggregate_and_write(str(repo)))
    findings = _by_id(index)

    assert findings["VG-001"]["status"] == "exploited"
    assert findings["VG-001"]["severity"] == "high"
    assert findings["VG-004"]["status"] == "exploited"

    # The duplicate the prover dismissed is suppressed (kept, reasoned).
    assert findings["VG-003"]["status"] == "suppressed"
    assert "distinct" in findings["VG-003"]["suppression_reason"]

    # An unproven finding stays unconfirmed at its recorded severity.
    assert findings["VG-005"]["status"] == "unconfirmed"
    assert findings["VG-005"]["severity"] == "medium"

    # Everything is still recorded in the index — nothing silently dropped.
    assert set(findings) == {"VG-001", "VG-002", "VG-003", "VG-004", "VG-005"}


def _clean_critique() -> dict:
    """A complete, floor-compliant critique for the seeded findings."""
    def ann(sev, reach, include, **extra):
        a = {"severity_adjusted": sev, "reachability": reach, "include_in_report": include,
             "confidence": "confirmed", "group_id": None, "possible_false_positive": False}
        a.update(extra)
        return a
    return {"annotations": {
        "VG-001": ann("critical", "external", True, group_id="sqli-user"),
        # VG-003 grouped with 001 (dedup) and excluded as a dup — low, so floor OK.
        "VG-003": ann("low", "external", False, group_id="sqli-user", confidence="theoretical"),
        "VG-002": ann("high", "external", True, group_id="cmdi-ping"),
        "VG-004": ann("high", "external", True, group_id="ssrf-fetch"),
        "VG-005": ann("medium", "authenticated", True, group_id="md5-pw"),
    }}


def test_guard_passes_on_complete_floor_compliant_critique(tmp_path: Path):
    d = _seed_deliverables(tmp_path)
    asyncio.run(FindingsAggregator().aggregate_and_write(str(tmp_path)))
    (d / "findings_critique.json").write_text(json.dumps(_clean_critique()))

    result = asyncio.run(audit_critique(str(tmp_path)))
    assert result["ok"] is True, result
    assert result["counts"]["annotations"] == 5


def test_guard_flags_dropped_and_buried_findings(tmp_path: Path):
    d = _seed_deliverables(tmp_path)
    asyncio.run(FindingsAggregator().aggregate_and_write(str(tmp_path)))

    critique = _clean_critique()
    del critique["annotations"]["VG-004"]                                # silently dropped
    critique["annotations"]["VG-002"]["include_in_report"] = False       # buried high+external
    (d / "findings_critique.json").write_text(json.dumps(critique))

    result = asyncio.run(audit_critique(str(tmp_path)))
    assert result["ok"] is False
    assert "VG-004" in result["missing_annotations"]
    assert any(v["id"] == "VG-002" for v in result["floor_violations"])
