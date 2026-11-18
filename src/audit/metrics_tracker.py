"""Metrics Tracker.

Manages ``session.json`` with atomic writes. Every read-modify-write runs
under an ``fcntl.flock`` on ``session.json.lock``: each activity builds its own
tracker (so an in-process asyncio lock cannot serialise them), and parallel
agents would otherwise overwrite each other's updates.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import json
import os
import tempfile
from datetime import datetime, timezone

import aiofiles

from src.types.audit import SessionMetadata


def _ts() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class MetricsTracker:
    """Manages the ``session.json`` file for a pentest session."""

    def __init__(self, session_path: str) -> None:
        self.session_path = session_path
        self.lock_path = session_path + ".lock"
        self._lock = asyncio.Lock()

    @contextlib.asynccontextmanager
    async def _locked(self):
        """Exclusive lock across tasks, trackers and processes.

        The flock is taken non-blocking and polled: a blocking flock would stall
        the event loop while another tracker in this same process holds it.
        """
        async with self._lock:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o644)
            try:
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        await asyncio.sleep(0.01)
                try:
                    yield
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    async def initialize(
        self,
        metadata: SessionMetadata,
        workflow_id: str = "",
    ) -> None:
        """Create or load ``session.json`` with the initial structure."""
        async with self._locked():
            if os.path.exists(self.session_path):
                data = await self._read_unsafe()
            else:
                data = {
                    "session": {
                        "id": metadata.id,
                        "webUrl": metadata.web_url,
                        "status": "in-progress",
                        "createdAt": _ts(),
                    },
                    "metrics": {
                        "total_duration_ms": 0,
                        "total_cost_usd": 0.0,
                        "phases": {},
                        "agents": {},
                    },
                }
                if metadata.repo_path:
                    data["session"]["repoPath"] = metadata.repo_path
                if workflow_id:
                    data["session"]["originalWorkflowId"] = workflow_id
                await self._write_unsafe(data)

    # ------------------------------------------------------------------
    # Agent lifecycle
    # ------------------------------------------------------------------

    async def start_agent(self, agent_name: str, attempt: int) -> None:
        """Record that an agent execution has started."""
        async with self._locked():
            data = await self._read_unsafe()
            agents = data["metrics"].setdefault("agents", {})
            if agent_name not in agents:
                agents[agent_name] = {
                    "status": "in-progress",
                    "attempts": [],
                    "final_duration_ms": 0,
                    "total_cost_usd": 0.0,
                }
            else:
                agents[agent_name]["status"] = "in-progress"
            await self._write_unsafe(data)

    async def end_agent(
        self,
        agent_name: str,
        attempt: int,
        duration_ms: int,
        cost_usd: float,
        status: str,
        model: str | None = None,
        checkpoint: str | None = None,
    ) -> None:
        """Record agent completion with metrics."""
        async with self._locked():
            data = await self._read_unsafe()
            agents = data["metrics"].setdefault("agents", {})
            agent = agents.setdefault(agent_name, {
                "status": "in-progress",
                "attempts": [],
                "final_duration_ms": 0,
                "total_cost_usd": 0.0,
            })

            # Append attempt record
            attempt_record: dict = {
                "attempt_number": attempt,
                "duration_ms": duration_ms,
                "cost_usd": cost_usd,
                "success": status == "success",
                "timestamp": _ts(),
            }
            if model:
                attempt_record["model"] = model
            agent["attempts"].append(attempt_record)

            # Recalculate total cost across all attempts
            agent["total_cost_usd"] = sum(
                a["cost_usd"] for a in agent["attempts"]
            )

            # Update status and metadata on success
            agent["status"] = status
            if status == "success":
                agent["final_duration_ms"] = duration_ms
                if model:
                    agent["model"] = model
                if checkpoint:
                    agent["checkpoint"] = checkpoint

            # Recalculate session-level aggregations
            self._recalculate(data)

            await self._write_unsafe(data)

    # ------------------------------------------------------------------
    # Session status
    # ------------------------------------------------------------------

    async def update_status(self, status: str) -> None:
        """Update the top-level session status."""
        async with self._locked():
            data = await self._read_unsafe()
            data["session"]["status"] = status
            if status in ("completed", "failed"):
                data["session"]["completedAt"] = _ts()
            await self._write_unsafe(data)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get_data(self) -> dict:
        """Return the current contents of session.json."""
        async with self._locked():
            return await self._read_unsafe()

    # ------------------------------------------------------------------
    # Internal I/O (call only inside ``_locked()``)
    # ------------------------------------------------------------------

    async def _read_unsafe(self) -> dict:
        """Read session.json without taking the lock."""
        async with aiofiles.open(self.session_path, mode="r") as f:
            raw = await f.read()
        return json.loads(raw)

    async def _write_unsafe(self, data: dict) -> None:
        """Atomic write: write to a temp file in the same directory, then rename."""
        dir_name = os.path.dirname(self.session_path)
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
        os.close(fd)
        try:
            async with aiofiles.open(tmp_path, mode="w") as f:
                from src.audit.redact import redact

                await f.write(redact(json.dumps(data, indent=2)))
            os.replace(tmp_path, self.session_path)
        except BaseException:
            # Clean up the temp file on failure
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    # ------------------------------------------------------------------
    # Aggregation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _recalculate(data: dict) -> None:
        """Recalculate session-level totals from agent metrics."""
        agents: dict = data["metrics"].get("agents", {})
        successful = {
            name: info
            for name, info in agents.items()
            if info.get("status") == "success"
        }

        total_duration = sum(
            info.get("final_duration_ms", 0) for info in successful.values()
        )
        total_cost = sum(
            info.get("total_cost_usd", 0.0) for info in successful.values()
        )

        data["metrics"]["total_duration_ms"] = total_duration
        data["metrics"]["total_cost_usd"] = total_cost
