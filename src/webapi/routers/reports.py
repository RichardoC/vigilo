"""Report + artifact access for a run."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.acl import require_run_access
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.models import Run, User
from src.webapi.reports import (
    PATCHES_KIND,
    PATCHES_ZIP_NAME,
    open_artifact,
    available_artifacts,
    build_patches_zip,
    read_report,
)

router = APIRouter(tags=["reports"])


async def _run_or_404(run_id: uuid.UUID, session: AsyncSession, user: User) -> Run:
    run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    await require_run_access(session, user, run)
    return run


@router.get("/runs/{run_id}/report")
async def get_report(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    run = await _run_or_404(run_id, session, user)
    markdown = read_report(run.data_dir, run.session_id)
    return {"exists": markdown is not None, "markdown": markdown or ""}


@router.get("/runs/{run_id}/artifacts")
async def list_artifacts(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    run = await _run_or_404(run_id, session, user)
    return {"artifacts": available_artifacts(run.data_dir, run.session_id)}


@router.get("/runs/{run_id}/artifacts/{kind}", response_model=None)
async def download_artifact(
    run_id: uuid.UUID,
    kind: str,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> FileResponse | StreamingResponse:
    run = await _run_or_404(run_id, session, user)
    if kind == PATCHES_KIND:
        buf = build_patches_zip(run.data_dir, run.session_id)
        if buf is None:
            raise HTTPException(status_code=404, detail="Artifact not found")

        def _chunks():
            try:
                while chunk := buf.read(64 * 1024):
                    yield chunk
            finally:
                buf.close()

        return StreamingResponse(
            _chunks(), media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{PATCHES_ZIP_NAME}"'},
        )
    opened = open_artifact(run.data_dir, run.session_id, kind)
    if opened is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    fh, name, media_type = opened

    def _file_chunks():
        try:
            while chunk := fh.read(64 * 1024):
                yield chunk
        finally:
            fh.close()

    return StreamingResponse(
        _file_chunks(), media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
