"""Duplicate guard of the findings ledger and the prompt wording that supports it."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.pipeline.ledger import Ledger, LedgerError, build_findings_index, coverage_summary

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "scripts" / "vigilo_record.py"
PROMPTS = ROOT / "prompts" / "whitebox"


def _f(**over):
    base = {"title": "SQLi in search", "description": "q is concatenated.", "severity": "high",
            "category": "injection", "location": {"file": "app.py", "line": 38}}
    base.update(over)
    return base


def _lead(**over):
    base = {"title": "Org boundary on project update", "hypothesis": "IDOR on update.",
            "entry_points": ["PUT /api/projects/{id}"], "files": ["views.py"]}
    base.update(over)
    return base


@pytest.fixture
def ledger(tmp_path) -> Ledger:
    return Ledger.for_repo(tmp_path)


def _problem(kind, ledger, rec):
    with pytest.raises(LedgerError) as exc:
        ledger.record(kind, rec)
    return " ".join(exc.value.problems)


# -- findings ---------------------------------------------------------------


def test_same_file_category_nearby_line_is_rejected_with_actionable_message(ledger):
    ledger.record("finding", _f())
    msg = _problem("finding", ledger, _f(title="Other words", location="app.py:41"))
    assert "looks like VG-001 (app.py:38, injection)" in msg
    assert "lead-done" in msg and 'finding_ids: ["VG-001"]' in msg
    assert '"distinct_from": ["VG-001"]' in msg
    assert len(ledger.findings()) == 1


@pytest.mark.parametrize("over", [
    {"location": {"file": "app.py", "line": 80}},                       # far away
    {"category": "xss"},                                                # other category
    {"location": {"file": "other.py", "line": 38}},                     # other file
])
def test_distinct_findings_are_accepted(ledger, over):
    ledger.record("finding", _f())
    ledger.record("finding", _f(**over))
    assert len(ledger.findings()) == 2


def test_same_sink_in_same_file_matches_across_categories(ledger):
    sink = 'cursor.execute(f"... ORDER BY {sort}") (app.py:38)'
    ledger.record("finding", _f(sink=sink))
    msg = _problem("finding", ledger, _f(category="other", location="app.py:50",
                                         sink='cursor.execute(f"... ORDER BY {sort}") (app.py:50)'))
    assert "VG-001" in msg


def test_same_sink_without_lines_needs_the_same_title(ledger):
    sink = 'cursor.execute(f"... ORDER BY {sort}")'
    ledger.record("finding", _f(location="app.py", sink=sink))
    # a line is missing on both sides and the titles differ: not the same flaw
    ledger.record("finding", _f(location="app.py", category="xss", title="Other", sink=sink))
    assert "VG-001" in _problem("finding", ledger, _f(location="app.py", category="other",
                                                     title="SQLi in search", sink=sink))


def test_rejection_explains_the_matching_rule(ledger):
    ledger.record("finding", _f())
    msg = _problem("finding", ledger, _f())
    assert "looks like VG-001 (app.py:38, injection)" in msg
    assert "within 5 lines" in msg and '"distinct_from": ["VG-001"]' in msg


def test_short_sink_does_not_match(ledger):
    ledger.record("finding", _f(sink="run(q)", category="xss"))
    ledger.record("finding", _f(sink="run(q)", category="authorization", location="app.py:40"))


def test_no_line_falls_back_to_title(ledger):
    ledger.record("finding", _f(location="app.py"))
    ledger.record("finding", _f(location="app.py", title="Different thing"))
    assert "VG-001" in _problem("finding", ledger, _f(location="app.py"))


def test_distinct_from_overrides_and_is_kept(ledger):
    ledger.record("finding", _f())
    rec = ledger.record("finding", _f(location="app.py:40", distinct_from=["VG-001"]))
    assert rec["distinct_from"] == ["VG-001"]
    index = build_findings_index(ledger)
    assert index["total_vulnerabilities"] == 2
    assert index["by_type"]["injection"][1]["distinct_from"] == ["VG-001"]


def test_distinct_from_must_reference_existing_findings(ledger):
    ledger.record("finding", _f())
    msg = _problem("finding", ledger, _f(location="app.py:90", distinct_from=["VG-099"]))
    assert "VG-099" in msg


def test_duplicate_inside_one_batch_rejects_everything(ledger):
    with pytest.raises(LedgerError) as exc:
        ledger.record_many("finding", [_f(), _f(location="app.py:39"), _f(location="z.py:1")])
    assert any(p.startswith("item 2:") and "item 1" in p for p in exc.value.problems)
    assert ledger.findings() == {}
    ok = ledger.record_many("finding", [_f(), _f(location="app.py:39", distinct_from=["item 1"])])
    assert [r["id"] for r in ok] == ["VG-001", "VG-002"]


def test_correcting_a_finding_by_id_is_not_a_duplicate(ledger):
    ledger.record("finding", _f())
    rec = ledger.record("finding", _f(id="VG-001", description="Better text."))
    assert rec["id"] == "VG-001"


# -- leads ------------------------------------------------------------------


def test_lead_with_same_title_or_entry_point_and_flaw_is_rejected(ledger):
    ledger.record("lead", _lead())
    assert "L-001" in _problem("lead", ledger, _lead(title="org boundary on PROJECT update!",
                                                     entry_points=[], hypothesis="x"))
    msg = _problem("lead", ledger, _lead(title="Another view", entry_points=["put /api/projects/{pk}/"],
                                         hypothesis="Insecure direct object reference"))
    assert "looks like L-001" in msg and '"distinct_from": ["L-001"]' in msg


def test_lead_overlap_is_conservative(ledger):
    ledger.record("lead", _lead())
    ledger.record("lead", _lead(title="Mass assignment on update", hypothesis="mass assignment of role"))
    ledger.record("lead", _lead(title="IDOR on delete", entry_points=["DELETE /api/projects/{id}"]))
    ledger.record("lead", _lead(title="IDOR in exports", entry_points=["GET /api/exports"],
                                files=["views.py"]))
    assert len(ledger.leads()) == 4


def test_closed_leads_still_count_and_distinct_from_overrides(ledger):
    ledger.record("lead", _lead())
    ledger.record("lead-done", {"lead_id": "L-001", "outcome": "clean"})
    assert "L-001" in _problem("lead", ledger, _lead(title="Second look"))
    ledger.record("lead", _lead(title="Second look", distinct_from=["L-001"]))
    with pytest.raises(LedgerError):
        ledger.record("lead", _lead(title="Third", distinct_from=["VG-001"]))


# -- lead-done links / index ------------------------------------------------


def test_lead_done_may_link_any_recorded_finding_from_several_leads(ledger):
    ledger.record_many("lead", [_lead(), _lead(title="Other", entry_points=["GET /x"])])
    ledger.record("finding", _f(recorded_by="investigator-2"))
    for lid in ("L-001", "L-002"):
        ledger.record("lead-done", {"lead_id": lid, "outcome": "finding", "finding_ids": ["VG-001"]})
    summary = coverage_summary(ledger)
    assert summary["findings_total"] == 1 and summary["leads_open"] == 0
    assert summary["outcomes"]["finding"] == 2
    assert build_findings_index(ledger)["total_vulnerabilities"] == 1


def test_lead_done_rejects_unknown_finding_ids(ledger):
    ledger.record("lead", _lead())
    assert "VG-009" in _problem("lead-done", ledger,
                                {"lead_id": "L-001", "outcome": "finding", "finding_ids": ["VG-009"]})


# -- CLI --------------------------------------------------------------------


def _cli(cwd, *args):
    (Path(cwd) / ".git").mkdir(exist_ok=True)
    (Path(cwd) / "deliverables").mkdir(exist_ok=True)
    r = subprocess.run([sys.executable, str(CLI), *args], cwd=cwd, capture_output=True, text=True)
    return r.returncode, json.loads(r.stdout)


def test_cli_rejects_duplicate_and_accepts_distinct(tmp_path):
    assert _cli(tmp_path, "finding", "--json", json.dumps(_f()))[0] == 0
    code, out = _cli(tmp_path, "finding", "--json", json.dumps(_f(location="app.py:39")))
    assert code == 1 and "VG-001" in out["problems"][0]
    code, out = _cli(tmp_path, "finding", "--json",
                     json.dumps(_f(location="app.py:39", distinct_from=["VG-001"])))
    assert code == 0 and out["ids"] == ["VG-002"]
    assert len(_cli(tmp_path, "show", "findings")[1]["findings"]) == 2
    assert _cli(tmp_path, "show", "chains")[1] == {"chains": []}


# -- prompts ----------------------------------------------------------------


def _read(*parts):
    return (PROMPTS.joinpath(*parts)).read_text(encoding="utf-8")


def test_prompts_document_the_duplicate_rule():
    ledger = _read("shared", "_ledger.txt")
    for needle in ("distinct_from", "No duplicates", "lead-done", "finding_ids", "within 5 lines"):
        assert needle in ledger
    inv = _read("investigator.txt")
    assert "vigilo-record show findings" in inv and "vigilo-record show leads" in inv
    assert "distinct_from" in inv
    assert "show chains" in _read("prover.txt")
    assert "distinct_from" in _read("planner.txt")
