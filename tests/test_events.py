"""Structured run events (src/audit/events.py) and the audit session on top."""
from __future__ import annotations

import json

import pytest

from src.audit.events import (
    AGENT_FINISHED,
    AGENT_TURN,
    RUN_STARTED,
    STAGE_STARTED,
    EventLog,
    RunEvent,
    format_duration,
    latest_stage,
    read_events,
)
from src.audit.session import AuditSession
from src.types.audit import SessionMetadata
from src.types.metrics import AgentMetrics


def _lines(path) -> list[str]:
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


class TestRunEvent:
    def test_step_derived_from_stage_or_actor(self):
        assert RunEvent(kind="x", msg="", stage="plan").step == "hunt"
        assert RunEvent(kind="x", msg="", actor="prover-3").step == "prove"
        assert RunEvent(kind="x", msg="", actor="xss-vuln").step == "hunt"  # historical
        assert RunEvent(kind="x", msg="").step is None

    def test_json_roundtrip(self):
        ev = RunEvent(kind=STAGE_STARTED, msg="stage started", run="r1",
                      stage="survey", actor="engine", data={"a": 1})
        back = RunEvent.from_json(ev.to_json())
        assert back == ev

    def test_from_json_rejects_garbage(self):
        assert RunEvent.from_json("not json") is None
        assert RunEvent.from_json('{"no": "kind"}') is None

    def test_unknown_level_is_normalised(self):
        assert RunEvent(kind="x", msg="", level="shouting").level == "info"

    def test_render_is_aligned_single_line(self):
        ev = RunEvent(kind=STAGE_STARTED, msg="stage started", stage="survey",
                      actor="engine", ts="2026-11-18T10:32:01.512Z")
        assert ev.render() == (
            "2026-11-18 10:32:01Z  INFO   survey        engine            stage started"
        )


@pytest.mark.parametrize("ms,expected", [
    (None, "-"), (900, "0.9s"), (59_000, "59.0s"), (252_000, "4m12s"), (3_780_000, "1h03m"),
])
def test_format_duration(ms, expected):
    assert format_duration(ms) == expected


class TestEventLog:
    def test_writes_json_and_text(self, tmp_path):
        log = EventLog(str(tmp_path), "run-1")
        log.run_started("https://app.example")
        log.stage("survey", "start")
        log.agent_started("surveyor", 1, "survey")
        log.agent_finished("surveyor", "survey", duration_ms=1500, cost_usd=0.25,
                           turns=7, model="m")
        log.stage("survey", "complete")

        raw = [json.loads(l) for l in _lines(tmp_path / "events.jsonl")]
        assert [r["kind"] for r in raw] == [
            RUN_STARTED, STAGE_STARTED, "agent.started", AGENT_FINISHED, "stage.finished",
        ]
        assert all(r["run"] == "run-1" for r in raw)
        assert raw[3]["data"] == {"duration_ms": 1500, "cost_usd": 0.25, "turns": 7, "model": "m"}

        text = _lines(tmp_path / "workflow.log")
        assert len(text) == 5
        assert "finished in 1.5s ($0.2500, 7 turns)" in text[3]

    def test_agent_turn_is_debug_and_truncated(self, tmp_path):
        log = EventLog(str(tmp_path), "r")
        log.agent_turn("investigator-2", 3, "word " * 2000, "investigate")
        (ev,), _ = read_events(str(tmp_path / "events.jsonl"))
        assert ev.kind == AGENT_TURN and ev.level == "debug" and ev.step == "hunt"
        assert len(ev.data["text"]) == 2000
        assert len(_lines(tmp_path / "workflow.log")[0]) < 400

    def test_run_finished_renders_summary_block(self, tmp_path):
        log = EventLog(str(tmp_path), "r")
        log.run_finished({
            "status": "failed", "total_cost_usd": 1.5, "total_duration_ms": 60_000,
            "completed_agents": ["surveyor"], "error": "boom",
            "agent_metrics": {"surveyor": {"duration_ms": 1000, "cost_usd": 1.5}},
        })
        (ev,), _ = read_events(str(tmp_path / "events.jsonl"))
        assert ev.level == "error" and ev.data["status"] == "failed"
        text = (tmp_path / "workflow.log").read_text()
        assert "run failed" in text and "error: boom" in text and "- surveyor: 1.0s, $1.5000" in text

    def test_read_events_skips_partial_trailing_line(self, tmp_path):
        log = EventLog(str(tmp_path), "r")
        log.stage("survey", "start")
        path = tmp_path / "events.jsonl"
        with open(path, "a") as fh:
            fh.write('{"kind": "stage.started", "msg": "half')
        events, offset = read_events(str(path))
        assert len(events) == 1
        with open(path, "a") as fh:
            fh.write('", "stage": "plan"}\n')
        more, _ = read_events(str(path), offset)
        assert [e.stage for e in more] == ["plan"]

    def test_latest_stage(self, tmp_path):
        log = EventLog(str(tmp_path), "r")
        assert latest_stage(log.events_path) is None
        log.stage("survey", "start")
        log.stage("survey", "complete")
        log.stage("plan", "start")
        log.agent_started("planner", 1, "plan")
        assert latest_stage(log.events_path) == "plan"


class TestAuditSession:
    async def test_run_started_written_once_across_sessions(self, tmp_path):
        meta = SessionMetadata(id="s1", web_url="https://t", repo_path=str(tmp_path))
        for _ in range(3):  # every activity builds its own AuditSession
            audit = AuditSession(meta)
            await audit.initialize("wf")
            await audit.log_stage("survey", "start")
        events, _ = read_events(str(tmp_path / ".vigilo" / "s1" / "events.jsonl"))
        assert [e.kind for e in events].count(RUN_STARTED) == 1
        assert [e.kind for e in events].count(STAGE_STARTED) == 3

    async def test_agent_lifecycle_events(self, tmp_path):
        meta = SessionMetadata(id="s2", web_url="", repo_path=str(tmp_path))
        audit = AuditSession(meta)
        await audit.initialize("wf")
        await audit.start_agent("investigator-1", 2)
        await audit.log_agent_turn("investigator-1", 1, "looking at routes")
        await audit.end_agent("investigator-1", AgentMetrics(duration_ms=10, cost_usd=0.1, num_turns=1))
        await audit.fail_agent("prover-1", "harness crashed")
        events, _ = read_events(str(tmp_path / ".vigilo" / "s2" / "events.jsonl"))
        by_kind = {e.kind: e for e in events}
        assert by_kind["agent.started"].stage == "investigate"
        assert by_kind["agent.started"].data["attempt"] == 2
        assert by_kind["agent.turn"].step == "hunt"
        assert by_kind["agent.failed"].level == "error" and by_kind["agent.failed"].step == "prove"
        session = json.loads((tmp_path / ".vigilo" / "s2" / "session.json").read_text())
        assert "investigator-1" in json.dumps(session)


class TestStageWarnFail:
    def test_warn_and_fail_are_finished_events_with_level_and_status(self, tmp_path):
        log = EventLog(str(tmp_path), "r")
        warn = log.stage("prove", "warn", reason="all 2 provers failed")
        fail = log.stage("remediation", "fail", reason="boom")
        assert (warn.kind, warn.level, warn.data["status"]) == ("stage.finished", "warn", "warning")
        assert (fail.kind, fail.level, fail.data["status"]) == ("stage.finished", "error", "failed")
        assert "finished with warnings (all 2 provers failed)" in warn.msg
        assert fail.msg == "stage failed (boom)"


def test_agent_retrying_event(tmp_path):
    from src.audit.events import AGENT_RETRYING, EventLog, read_events

    log = EventLog(str(tmp_path), "run-1")
    log.agent_retrying("surveyor", "survey", attempt=1, error_type="ExecutionError",
                       reason="boom", next_attempt_at="2026-11-18T10:00:20+00:00",
                       retry_in_s=20, max_attempts=6)
    events, _ = read_events(log.events_path)
    ev = events[-1]
    assert ev.kind == AGENT_RETRYING and ev.level == "warn"
    assert ev.data["attempt"] == 1 and ev.data["retry_in_s"] == 20
    assert "retrying in ~20.0s" in ev.msg
