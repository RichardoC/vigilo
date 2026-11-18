"""Tests for the findings aggregator.

The index is built from structured files only: the findings ledger plus the
SCA and integrity JSON deliverables. Status comes from the prover's verdict,
never from scraping evidence prose, and the old per-class queue/verdict files
are no longer read.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Make `src` importable when pytest is run from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.pipeline.ledger import Ledger  # noqa: E402
from src.services.findings_aggregator import FindingsAggregator  # noqa: E402


def _write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


def _aggregate(repo: Path) -> dict:
    return asyncio.run(FindingsAggregator().aggregate(str(repo)))


def _by_id(index: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for vulns in index["by_type"].values():
        for v in vulns:
            out[v.get("ID") or v.get("id")] = v
    return out


def _ledger(repo: Path) -> Ledger:
    return Ledger(repo / "deliverables")


def _finding(n: int, **over) -> dict:
    base = {
        "title": f"Finding number {n}",
        "description": f"Distinct flaw {n}.",
        "severity": "high",
        "category": "injection",
        "location": {"file": f"app/mod{n}.py", "line": 10 * n},
    }
    base.update(over)
    return base


def test_verdict_drives_status(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    for n in (1, 2, 3):
        ledger.record("finding", _finding(n))
    ledger.record("verdict", {"finding_id": "VG-001", "verdict": "exploited", "summary": "s",
                              "evidence_ref": "e.md#1"})
    ledger.record("verdict", {"finding_id": "VG-002", "verdict": "blocked", "summary": "s"})
    # VG-003 has no verdict

    findings = _by_id(_aggregate(tmp_path))
    assert findings["VG-001"]["status"] == "exploited"
    assert findings["VG-001"]["evidence_ref"] == "e.md#1"
    assert findings["VG-002"]["status"] == "potential"      # blocked-by-control
    assert findings["VG-003"]["status"] == "unconfirmed"    # no verdict


def test_code_only_harness_verdicts(tmp_path: Path) -> None:
    """Code-only confirmation verdicts keep findings at `potential` and carry
    harness evidence; `refuted` is suppressed with its reason."""
    ledger = _ledger(tmp_path)
    for n in (1, 2, 3):
        ledger.record("finding", _finding(n))
    ledger.record("verdict", {"finding_id": "VG-001", "verdict": "confirmed", "summary": "s",
                              "harness_path": "harnesses/VG-001.py"})
    ledger.record("verdict", {"finding_id": "VG-002", "verdict": "not_testable", "summary": "s"})
    ledger.record("verdict", {"finding_id": "VG-003", "verdict": "refuted",
                              "summary": "input is parameterised; payload had no effect"})

    f = _by_id(_aggregate(tmp_path))
    assert f["VG-001"]["status"] == "potential"
    assert f["VG-001"]["harness_confirmed"] is True
    assert f["VG-001"]["harness_path"] == "harnesses/VG-001.py"
    assert f["VG-002"]["status"] == "potential"
    assert f["VG-003"]["status"] == "suppressed"
    assert "parameterised" in f["VG-003"]["suppression_reason"]
    assert f["VG-003"]["harness_confirmed"] is False


def test_false_positive_is_suppressed_not_exploited(tmp_path: Path) -> None:
    """A finding whose ID appears in an evidence markdown file is still
    suppressed when its verdict says false_positive: prose is never scraped."""
    d = tmp_path / "deliverables"
    _ledger(tmp_path).record("finding", _finding(1, category="ssrf", severity="critical"))
    _ledger(tmp_path).record("verdict", {
        "finding_id": "VG-001", "verdict": "false_positive",
        "summary": "URL is validated against an allowlist before the request.",
    })
    (d / "ssrf_exploitation_evidence.md").write_text(
        "## Successfully Exploited Vulnerabilities\n### VG-001\n...", encoding="utf-8",
    )

    finding = _by_id(_aggregate(tmp_path))["VG-001"]
    assert finding["status"] == "suppressed"
    assert "allowlist" in finding["suppression_reason"]


def test_severity_is_carried_through(tmp_path: Path) -> None:
    _ledger(tmp_path).record("finding", _finding(1, severity="low"))
    assert _by_id(_aggregate(tmp_path))["VG-001"]["severity"] == "low"


def test_chains_come_from_the_ledger(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    ledger.record("finding", _finding(1))
    ledger.record("finding", _finding(2, category="authentication"))
    ledger.record("chain", {"title": "SQLi to auth bypass", "narrative": "n", "severity": "high",
                            "finding_ids": ["VG-001", "VG-002"], "status": "exploited"})
    chain = _aggregate(tmp_path)["by_type"]["chain"][0]
    assert chain["ID"] == "CH-01"
    assert chain["status"] == "exploited"
    assert chain["code_fixable"] is False
    assert chain["chain_components"] == ["VG-001", "VG-002"]


def test_sca_and_integrity_are_merged(tmp_path: Path) -> None:
    d = tmp_path / "deliverables"
    _ledger(tmp_path).record("finding", _finding(1))
    _write(d / "sca_findings.json", {"vulnerabilities": [
        {"ID": "SCA-1", "package": "lodash", "cve_ids": ["CVE-1"]},
        {"ID": "SCA-2", "package": "lodash", "cve_ids": ["CVE-1"]},  # duplicate
        {"ID": "SCA-3", "package": "minimatch", "cve_ids": ["CVE-2"]},
    ]})
    _write(d / "integrity_analysis.json", {"findings": [{"ID": "INT-1", "severity": "high"}]})
    index = _aggregate(tmp_path)
    assert len(index["by_type"]["supply_chain"]) == 2
    assert index["by_type"]["integrity"] == [{"ID": "INT-1", "severity": "high"}]
    assert index["total_vulnerabilities"] == 1 + 2 + 1


def test_per_class_queue_files_are_ignored(tmp_path: Path) -> None:
    d = tmp_path / "deliverables"
    _write(d / "injection_exploitation_queue.json", {"vulnerabilities": [{"ID": "INJ-VULN-01"}]})
    _write(d / "chain_findings.json", {"chains": [{"ID": "CHAIN-001"}]})
    index = _aggregate(tmp_path)
    assert index["total_vulnerabilities"] == 0
    assert index["by_type"] == {}


def test_empty_workspace_is_valid(tmp_path: Path) -> None:
    index = _aggregate(tmp_path)
    assert index["total_vulnerabilities"] == 0
    assert isinstance(index["by_type"], dict)


def test_malformed_sca_file_is_skipped(tmp_path: Path) -> None:
    d = tmp_path / "deliverables"
    d.mkdir(parents=True, exist_ok=True)
    (d / "sca_findings.json").write_text("{not json", encoding="utf-8")
    index = _aggregate(tmp_path)
    assert "supply_chain" not in index["by_type"]
