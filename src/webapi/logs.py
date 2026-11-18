"""Run log access.

A run's workspace (``{data_dir}/repo/.vigilo/{session_id}/``) holds two logs:

* ``events.jsonl`` — structured events (see :mod:`src.audit.events`). This is
  what the API serves when it exists: every entry carries its rendered line
  plus the trace-rail ``step`` it belongs to, so the UI never parses text.
* ``workflow.log`` — the human-readable rendering. Runs recorded before the
  event log existed only have this file; for those the raw lines are served.

Reads are byte-offset based so the API can paginate or stream incrementally.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from collections.abc import AsyncGenerator, Awaitable, Callable

from src.audit.events import (
    AGENT_RETRYING,
    EVENTS_FILENAME,
    LOG_FILENAME,
    STAGE_STARTED,
    RunEvent,
)
from src.webapi import safefs


def workspace_for(data_dir: str, session_id: str) -> str:
    return os.path.join(data_dir, "repo", ".vigilo", session_id)


def log_path_for(data_dir: str, session_id: str) -> str:
    return os.path.join(workspace_for(data_dir, session_id), LOG_FILENAME)


def events_path_for(data_dir: str, session_id: str) -> str:
    return os.path.join(workspace_for(data_dir, session_id), EVENTS_FILENAME)


class WorkspaceFile:
    """A log file inside a run workspace, always opened without following symlinks.

    The workspace is writable by AI agents, so a symlinked ``events.jsonl`` must
    never be served (e.g. pointing at ``/proc/self/environ``)."""

    def __init__(self, data_dir: str, session_id: str, name: str) -> None:
        self.data_dir = data_dir
        self.parts = ("repo", ".vigilo", session_id, name)

    def exists(self) -> bool:
        return safefs.is_safe_file(self.data_dir, *self.parts)

    def read_from(self, offset: int = 0) -> tuple[bytes, int] | None:
        fh = safefs.open_file(self.data_dir, *self.parts)
        if fh is None:
            return None
        with fh:
            fh.seek(offset)
            data = fh.read()
            return data, fh.tell()


def read_from(path: str, offset: int = 0, *, data_dir: str | None = None, session_id: str | None = None) -> tuple[list[str], int]:
    """Return (new non-empty text lines since ``offset``, new byte offset).

    Without ``data_dir``/``session_id`` the path's own parent directory is the
    trusted root and only the final component is opened with O_NOFOLLOW."""
    if data_dir is not None and session_id is not None:
        got = WorkspaceFile(data_dir, session_id, os.path.basename(path)).read_from(offset)
    else:
        fd = safefs.open_nofollow(os.path.dirname(path) or ".", os.path.basename(path))
        got = None
        if fd is not None:
            with os.fdopen(fd, "rb") as fh:
                fh.seek(offset)
                got = (fh.read(), fh.tell())
    if got is None:
        return [], offset
    data, new_offset = got
    lines = [ln for ln in data.decode("utf-8", errors="replace").splitlines() if ln.strip()]
    return lines, new_offset


def _read_events(f: WorkspaceFile, offset: int = 0) -> tuple[list[RunEvent], int]:
    """Complete events after ``offset`` (a trailing partial line is left for later)."""
    got = f.read_from(offset)
    if got is None:
        return [], offset
    chunk, _ = got
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


_LEGACY_STAGE_MARKER = re.compile(r"\[PHASE\]\s+Starting:\s*(\S.*?)\s*$")


def current_stage(data_dir: str, session_id: str) -> str | None:
    """The stage a run is in right now, from its event log (or legacy text log)."""
    events_file = WorkspaceFile(data_dir, session_id, EVENTS_FILENAME)
    if events_file.exists():
        events, _ = _read_events(events_file)
        for ev in reversed(events):
            if ev.kind == STAGE_STARTED and ev.stage:
                return ev.stage
        return None
    lines, _ = read_from(log_path_for(data_dir, session_id), 0, data_dir=data_dir, session_id=session_id)
    for ln in reversed(lines):
        m = _LEGACY_STAGE_MARKER.search(ln)
        if m:
            return m.group(1)
    return None


def entry_for(event: RunEvent) -> dict:
    """The JSON shape the UI consumes for one event."""
    entry = {
        "ts": event.ts,
        "kind": event.kind,
        "level": event.level,
        "stage": event.stage,
        "step": event.step,
        "actor": event.actor,
        "line": event.render(),
    }
    if event.kind == AGENT_RETRYING:
        # attempt, error_type, reason, next_attempt_at, retry_in_s, max_attempts:
        # the run page shows a "retrying" banner from these.
        entry["data"] = event.data
    return entry


class RunLogSource:
    """Picks the structured event log when present, else the legacy text log."""

    def __init__(self, data_dir: str, session_id: str) -> None:
        self.events_path = events_path_for(data_dir, session_id)
        self.text_path = log_path_for(data_dir, session_id)
        self._events = WorkspaceFile(data_dir, session_id, EVENTS_FILENAME)
        self._text = WorkspaceFile(data_dir, session_id, LOG_FILENAME)

    @property
    def structured(self) -> bool:
        return self._events.exists()

    def read(self, offset: int = 0, structured: bool | None = None) -> tuple[list[dict], int]:
        """Entries after ``offset``. Legacy text lines become ``{"line": ...}``."""
        if structured is None:
            structured = self.structured
        if structured:
            events, new_offset = _read_events(self._events, offset)
            return [entry_for(ev) for ev in events], new_offset
        got = self._text.read_from(offset)
        if got is None:
            return [], offset
        new_offset = got[1]
        lines = [ln for ln in got[0].decode("utf-8", errors="replace").splitlines() if ln.strip()]
        if self.structured:
            # The event log appeared while we were reading the text log: drop
            # the text so the caller restarts on the structured source.
            return [], offset
        return [{"line": ln} for ln in lines], new_offset


async def stream_entries(
    source: RunLogSource,
    is_done: Callable[[], Awaitable[bool]],
    poll_seconds: float = 0.5,
    max_ticks: int = 100_000,
) -> AsyncGenerator[str, None]:
    """Yield SSE messages (one JSON entry each) as they appear; stop once
    ``is_done()`` resolves true (after a final drain)."""
    offset = 0
    ticks = 0
    structured = source.structured
    while True:
        if not structured and source.structured:
            # The worker created the event log after we started streaming.
            structured, offset = True, 0
        entries, offset = source.read(offset, structured)
        for entry in entries:
            yield f"data: {json.dumps(entry, ensure_ascii=False)}\n\n"
        ticks += 1
        if await is_done() or ticks >= max_ticks:
            if not structured and source.structured:
                structured, offset = True, 0
            entries, offset = source.read(offset, structured)
            for entry in entries:
                yield f"data: {json.dumps(entry, ensure_ascii=False)}\n\n"
            yield "event: end\ndata: {}\n\n"
            return
        await asyncio.sleep(poll_seconds)
