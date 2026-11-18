"""Structured run events.

Every notable thing that happens during a white-box run is recorded as one
JSON object per line in ``{workspace}/events.jsonl``::

    {"ts": "2026-11-18T10:32:01.512Z", "run": "web-4f1c…", "kind": "agent.finished",
     "level": "info", "stage": "survey", "step": "survey", "actor": "surveyor",
     "msg": "finished in 4m12s ($1.8031, 41 turns)", "data": {...}}

The same event is also rendered as one aligned, human-readable line in
``{workspace}/workflow.log`` (for ``tail -f`` and for runs viewed without the
UI)::

    2026-11-18 10:32:01Z  INFO   survey        surveyor          finished in 4m12s ($1.8031, 41 turns)

Machines (the web API, the UI, tests) read ``events.jsonl`` and never parse
the text log. Event writes are single ``write()`` calls on a file opened in
append mode, so concurrent activities on one worker never interleave lines.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.pipeline.stages import RUN_STAGE, step_for_actor, step_for_stage

EVENTS_FILENAME = "events.jsonl"
LOG_FILENAME = "workflow.log"

# Event kinds -----------------------------------------------------------------
RUN_STARTED = "run.started"
RUN_FINISHED = "run.finished"
STAGE_STARTED = "stage.started"
STAGE_FINISHED = "stage.finished"
STAGE_SKIPPED = "stage.skipped"
AGENT_STARTED = "agent.started"
AGENT_TURN = "agent.turn"
AGENT_FINISHED = "agent.finished"
AGENT_FAILED = "agent.failed"
AGENT_RETRYING = "agent.retrying"

LEVELS = ("debug", "info", "warn", "error")

# Agent output is kept in full in the per-agent log under agents/. The event
# stream only carries an excerpt so events.jsonl stays small enough to stream.
_TURN_EVENT_CHARS = 2000
_TURN_LINE_CHARS = 280


def _now() -> datetime:
    return datetime.now(timezone.utc)


def format_duration(ms: int | float | None) -> str:
    """``1234`` → ``1.2s``; ``252000`` → ``4m12s``; ``None`` → ``-``."""
    if ms is None:
        return "-"
    seconds = ms / 1000
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def _one_line(text: str, limit: int) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


@dataclass
class RunEvent:
    """One entry of ``events.jsonl``."""

    kind: str
    msg: str
    run: str = ""
    stage: str | None = None
    actor: str | None = None
    level: str = "info"
    step: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    ts: str = ""

    def __post_init__(self) -> None:
        if self.level not in LEVELS:
            self.level = "info"
        if not self.ts:
            self.ts = _now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        if self.step is None:
            self.step = step_for_stage(self.stage) or step_for_actor(self.actor)

    def to_json(self) -> str:
        payload = {k: v for k, v in asdict(self).items() if v not in (None, {}, "")}
        payload.setdefault("msg", "")
        return json.dumps(payload, ensure_ascii=False, default=str)

    @classmethod
    def from_json(cls, line: str) -> "RunEvent | None":
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(raw, dict) or "kind" not in raw:
            return None
        known = {k: raw[k] for k in cls.__dataclass_fields__ if k in raw}
        known.setdefault("msg", "")
        return cls(**known)

    def render(self) -> str:
        """Render as an aligned, human-readable log line (or block)."""
        stamp = self.ts.replace("T", " ")[:19] + "Z"
        head = (
            f"{stamp}  {self.level.upper():<5}  {(self.stage or '-'):<12}  "
            f"{(self.actor or '-'):<16}  "
        )
        if self.kind == RUN_FINISHED:
            return head + self.msg + "".join(
                f"\n{'':>22}{line}" for line in self.data.get("lines", [])
            )
        return head + self.msg


class EventLog:
    """Append-only writer for a run's ``events.jsonl`` + ``workflow.log``."""

    def __init__(self, workspace: str, run_id: str) -> None:
        self.workspace = workspace
        self.run_id = run_id
        self.events_path = os.path.join(workspace, EVENTS_FILENAME)
        self.log_path = os.path.join(workspace, LOG_FILENAME)

    def exists(self) -> bool:
        return os.path.isfile(self.events_path)

    def emit(
        self,
        kind: str,
        msg: str,
        *,
        stage: str | None = None,
        actor: str | None = None,
        level: str = "info",
        **data: Any,
    ) -> RunEvent:
        event = RunEvent(
            kind=kind, msg=msg, run=self.run_id, stage=stage, actor=actor,
            level=level, data=data,
        )
        self.write(event)
        return event

    def write(self, event: RunEvent) -> None:
        os.makedirs(self.workspace, exist_ok=True)
        from src.audit.redact import redact

        # Agents may echo a per-run secret in their output: mask it in both files.
        with open(self.events_path, "a", encoding="utf-8") as fh:
            fh.write(redact(event.to_json()) + "\n")
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(redact(event.render()) + "\n")

    # -- convenience wrappers ------------------------------------------------

    def run_started(self, target: str, *, engine: str = "whitebox") -> RunEvent:
        return self.emit(
            RUN_STARTED,
            f"run {self.run_id} started against {target or 'source code only'}",
            stage=RUN_STAGE, actor="engine", target=target, engine=engine,
        )

    def stage(self, stage: str, event: str, **data: Any) -> RunEvent:
        """``event``: ``start``, ``complete``, ``skip``, or — for a stage that
        ended but did not do its job while the run carries on — ``warn``
        (finished with a warning) and ``fail`` (finished, failed). The last two
        are ``stage.finished`` events with ``level`` warn/error and
        ``data.status`` ``warning``/``failed``."""
        kind = {
            "start": STAGE_STARTED,
            "complete": STAGE_FINISHED,
            "skip": STAGE_SKIPPED,
            "warn": STAGE_FINISHED,
            "fail": STAGE_FINISHED,
        }.get(event, STAGE_STARTED)
        verb = {"start": "started", "complete": "finished", "skip": "skipped",
                "warn": "finished with warnings", "fail": "failed"}.get(event, "started")
        level = {"warn": "warn", "fail": "error"}.get(event, "info")
        if event in ("warn", "fail"):
            data.setdefault("status", "warning" if event == "warn" else "failed")
        reason = data.get("reason")
        msg = f"stage {verb}" + (f" ({reason})" if reason else "")
        return self.emit(kind, msg, stage=stage, actor="engine", level=level, **data)

    def agent_started(self, actor: str, attempt: int, stage: str | None) -> RunEvent:
        return self.emit(
            AGENT_STARTED, f"started (attempt {attempt})",
            stage=stage, actor=actor, attempt=attempt,
        )

    def agent_turn(self, actor: str, turn: int, content: str, stage: str | None) -> RunEvent:
        event = RunEvent(
            kind=AGENT_TURN,
            msg=f"turn {turn}: {_one_line(content, _TURN_LINE_CHARS)}",
            run=self.run_id, stage=stage, actor=actor, level="debug",
            data={"turn": turn, "text": content[:_TURN_EVENT_CHARS]},
        )
        self.write(event)
        return event

    def agent_finished(
        self,
        actor: str,
        stage: str | None,
        *,
        duration_ms: int,
        cost_usd: float | None,
        turns: int | None,
        model: str | None,
    ) -> RunEvent:
        cost = f"${cost_usd:.4f}" if cost_usd is not None else "cost n/a"
        turn_txt = f", {turns} turns" if turns else ""
        return self.emit(
            AGENT_FINISHED,
            f"finished in {format_duration(duration_ms)} ({cost}{turn_txt})",
            stage=stage, actor=actor, duration_ms=duration_ms,
            cost_usd=cost_usd, turns=turns, model=model,
        )

    def agent_failed(self, actor: str, stage: str | None, error: str) -> RunEvent:
        return self.emit(
            AGENT_FAILED, f"failed: {_one_line(error, 400)}",
            stage=stage, actor=actor, level="error", error=error[:2000],
        )

    def agent_retrying(
        self,
        actor: str,
        stage: str | None,
        *,
        attempt: int,
        error_type: str,
        reason: str,
        next_attempt_at: str | None = None,
        retry_in_s: float | None = None,
        max_attempts: int | None = None,
    ) -> RunEvent:
        """An agent attempt failed with a retryable error and will run again."""
        when = f" - retrying in ~{format_duration(retry_in_s * 1000)}" if retry_in_s else " - retrying"
        return self.emit(
            AGENT_RETRYING,
            f"attempt {attempt} failed: {_one_line(reason, 300)}{when}",
            stage=stage, actor=actor, level="warn", attempt=attempt,
            error_type=error_type, reason=reason[:600],
            next_attempt_at=next_attempt_at, retry_in_s=retry_in_s,
            max_attempts=max_attempts,
        )

    def run_finished(self, summary: dict[str, Any]) -> RunEvent:
        status = summary.get("status", "unknown")
        cost = summary.get("total_cost_usd") or 0.0
        agents: dict[str, Any] = summary.get("agent_metrics") or {}
        lines = [
            f"duration {format_duration(summary.get('total_duration_ms'))}, "
            f"cost ${cost:.4f}, {len(summary.get('completed_agents') or [])} agent runs",
        ]
        if summary.get("error"):
            lines.append(f"error: {_one_line(str(summary['error']), 400)}")
        for name, m in agents.items():
            m = m or {}
            c = m.get("cost_usd")
            lines.append(
                f"- {name}: {format_duration(m.get('duration_ms'))}, "
                + (f"${c:.4f}" if c is not None else "cost n/a")
            )
        return self.emit(
            RUN_FINISHED, f"run {status}",
            stage=RUN_STAGE, actor="engine",
            level="error" if status == "failed" else "info",
            status=status, total_cost_usd=cost,
            total_duration_ms=summary.get("total_duration_ms"),
            error=summary.get("error"), lines=lines,
        )


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------


def read_events(path: str, offset: int = 0) -> tuple[list[RunEvent], int]:
    """Return complete events after byte ``offset`` and the new offset.

    A trailing partial line (being written right now) is left for the next
    call rather than returned half-parsed.
    """
    if not os.path.isfile(path):
        return [], offset
    with open(path, "rb") as fh:
        fh.seek(offset)
        chunk = fh.read()
    end = chunk.rfind(b"\n")
    if end < 0:
        return [], offset
    complete = chunk[: end + 1]
    events = [
        ev for ev in (
            RunEvent.from_json(line)
            for line in complete.decode("utf-8", errors="replace").splitlines()
            if line.strip()
        ) if ev is not None
    ]
    return events, offset + len(complete)


def latest_stage(path: str) -> str | None:
    """The most recently started stage recorded in ``events.jsonl``."""
    events, _ = read_events(path)
    for ev in reversed(events):
        if ev.kind == STAGE_STARTED and ev.stage:
            return ev.stage
    return None
