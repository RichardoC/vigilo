"""Work batching for the white-box engine's parallel agents.

Pure, stdlib-only and deterministic, so the workflow sandbox can import it.

The investigate and prove stages hand each numbered agent (``investigator-3``,
``prover-1``) a small slice of the ledger: a few leads or findings, in priority
order, passed through ``extra_context`` as one line the prompts treat as the
agent's authoritative assignment::

    LEADS: L-001,L-004
    FINDINGS: VG-002,VG-007
"""
from __future__ import annotations

from dataclasses import dataclass

LEADS_PREFIX = "LEADS"
FINDINGS_PREFIX = "FINDINGS"

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Batch:
    """One agent's assignment."""

    actor: str             # e.g. "investigator-3"
    ids: tuple[str, ...]   # e.g. ("L-001", "L-004")
    extra_context: str     # e.g. "LEADS: L-001,L-004"


def chunk(ids: list[str], size: int) -> list[list[str]]:
    """Split ``ids`` (already in priority order) into consecutive chunks of ``size``.

    Consecutive rather than round-robin, so the first agents to start (the
    workflow runs batches under a concurrency limit, in order) get the
    highest-priority work.
    """
    size = max(1, int(size))
    return [ids[i:i + size] for i in range(0, len(ids), size)]


def assignment_line(prefix: str, ids: list[str] | tuple[str, ...]) -> str:
    """``LEADS: L-001,L-004`` — comma-separated, no spaces."""
    return f"{prefix}: {','.join(ids)}"


def parse_assignment(extra_context: str | None, prefix: str) -> list[str]:
    """Inverse of :func:`assignment_line`: the IDs on the ``prefix:`` line, if any."""
    for line in (extra_context or "").splitlines():
        head, sep, tail = line.strip().partition(":")
        if sep and head.strip() == prefix:
            return [x.strip() for x in tail.split(",") if x.strip()]
    return []


def make_batches(
    base_actor: str,
    prefix: str,
    ids: list[str],
    size: int,
    *,
    first_instance: int = 1,
) -> list[Batch]:
    """Build numbered batches: ``{base_actor}-{n}`` for n from ``first_instance``."""
    return [
        Batch(
            actor=f"{base_actor}-{first_instance + i}",
            ids=tuple(group),
            extra_context=assignment_line(prefix, group),
        )
        for i, group in enumerate(chunk(ids, size))
    ]


def order_leads(leads: list[dict]) -> list[str]:
    """Lead IDs by priority (1 = highest), then ID."""
    return [
        str(lead["id"])
        for lead in sorted(leads, key=lambda x: (_int(x.get("priority"), 3), str(x.get("id"))))
        if lead.get("id")
    ]


def order_findings(findings: list[dict]) -> list[str]:
    """Finding IDs by severity (critical first), then ID."""
    return [
        str(f["id"])
        for f in sorted(
            findings,
            key=lambda x: (_SEVERITY_RANK.get(str(x.get("severity") or "").lower(), 5), str(x.get("id"))),
        )
        if f.get("id")
    ]


def _int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
