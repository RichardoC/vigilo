"""Run log access: paginated read + Server-Sent-Events live stream."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.acl import require_run_access
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.logs import RunLogSource, stream_entries
from src.webapi.models import RUN_TERMINAL, Run, User

router = APIRouter(tags=["logs"])


async def _get_run_or_404(run_id: uuid.UUID, session: AsyncSession, user: User) -> Run:
    run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    await require_run_access(session, user, run)
    return run


@router.get("/runs/{run_id}/logs")
async def get_logs(
    run_id: uuid.UUID,
    offset: int = 0,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    """Paginated read of the run's log from a byte offset.

    ``entries`` carries structured events (with their trace-rail ``step``) when
    the run has an event log; ``lines`` is the rendered text either way.
    """
    run = await _get_run_or_404(run_id, session, user)
    source = RunLogSource(run.data_dir, run.session_id)
    entries, new_offset = source.read(offset)
    return {
        "lines": [e["line"] for e in entries],
        "entries": entries,
        "structured": source.structured,
        "offset": new_offset,
        "status": run.status,
    }


@router.get("/runs/{run_id}/logs/stream")
async def stream_logs(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> StreamingResponse:
    """Live SSE stream of log entries (JSON) until the run reaches a terminal state."""
    run = await _get_run_or_404(run_id, session, user)
    source = RunLogSource(run.data_dir, run.session_id)

    async def _is_done() -> bool:
        await session.refresh(run)
        return run.status in RUN_TERMINAL

    return StreamingResponse(
        stream_entries(source, _is_done, poll_seconds=0.2),
        media_type="text/event-stream",
    )
