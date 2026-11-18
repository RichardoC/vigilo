"""session.json is shared by every activity's own MetricsTracker: concurrent
read-modify-write cycles must not lose updates (cross-tracker flock)."""
from __future__ import annotations

import asyncio
import contextlib
import json

import pytest

from src.audit.metrics_tracker import MetricsTracker
from src.types.audit import SessionMetadata

pytestmark = pytest.mark.asyncio

N = 12


async def _agent(path: str, i: int) -> None:
    tracker = MetricsTracker(path)  # own tracker + own asyncio lock, like an activity
    await tracker.start_agent(f"investigator-{i}", 1)
    await asyncio.sleep(0)
    await tracker.end_agent(f"investigator-{i}", 1, 1000, 0.5, "success", model="m")


async def _run(path: str) -> dict:
    meta = SessionMetadata(id="s", web_url="", repo_path="/x")
    await MetricsTracker(path).initialize(meta, "wf")
    await asyncio.gather(*(_agent(path, i) for i in range(N)))
    return json.loads(open(path).read())


async def test_concurrent_trackers_keep_every_agent(tmp_path):
    data = await _run(str(tmp_path / "session.json"))
    assert len(data["metrics"]["agents"]) == N
    assert data["metrics"]["total_cost_usd"] == pytest.approx(0.5 * N)
    assert data["metrics"]["total_duration_ms"] == 1000 * N


async def test_without_the_file_lock_updates_are_lost(tmp_path, monkeypatch):
    """Guards the test above: it must fail when the cross-tracker lock is removed."""
    @contextlib.asynccontextmanager
    async def only_asyncio_lock(self):
        async with self._lock:
            yield

    monkeypatch.setattr(MetricsTracker, "_locked", only_asyncio_lock)
    data = await _run(str(tmp_path / "session.json"))
    assert len(data["metrics"]["agents"]) < N


async def test_lock_file_is_next_to_session_json(tmp_path):
    path = str(tmp_path / "session.json")
    await MetricsTracker(path).initialize(SessionMetadata(id="s", web_url="", repo_path="/x"))
    assert (tmp_path / "session.json.lock").exists()
