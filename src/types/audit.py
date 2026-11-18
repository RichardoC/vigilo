"""Audit system type definitions."""

from __future__ import annotations

from pydantic import BaseModel


class SessionMetadata(BaseModel):
    """Cross-cutting session metadata used by services, temporal, and audit."""

    id: str
    web_url: str
    repo_path: str
    output_path: str | None = None
