"""Stage registry — the one place that names the white-box engine's stages.

Every consumer (the workflow, the event log, the web API's progress
tracking, and the UI's trace rail) reads stage identifiers from here instead of
keeping its own list. Adding or renaming a stage is a one-file change.

Vocabulary
----------
* **stage** — a unit of work the workflow runs and logs (``survey``, ``plan``…).
* **step** — a coarser, user-facing bucket shown on the UI trace rail. Several
  stages can share one step (e.g. ``survey``, ``supply-chain`` and
  ``integrity`` all show as *Survey*).
* **actor** — whoever emits an event: an agent (``surveyor``,
  ``investigator-3``…) or the engine itself (``engine``).

Runs recorded before this registry existed used other identifiers; those are
kept in ``LEGACY_STAGE_STEPS`` / ``LEGACY_ACTOR_STEPS`` purely so historical
runs still render on the trace rail.

This module is stdlib-only and side-effect free, so it is safe to import from
the workflow sandbox.
"""
from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Steps (UI trace rail), in display order
# ---------------------------------------------------------------------------

STEPS: tuple[tuple[str, str], ...] = (
    ("preflight", "Preflight"),
    ("survey", "Survey"),
    ("hunt", "Hunt"),
    ("prove", "Prove"),
    ("review", "Review"),
    ("remediation", "Remediation"),
    ("report", "Report"),
)
STEP_KEYS: frozenset[str] = frozenset(k for k, _ in STEPS)


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Stage:
    """A workflow stage.

    ``toggle`` names the ``StageSelection`` flag that enables the stage, or is
    ``None`` for stages that always run.
    """

    key: str
    label: str
    step: str
    toggle: str | None = None


STAGES: tuple[Stage, ...] = (
    Stage("preflight", "Preflight checks", "preflight"),
    Stage("survey", "Code and attack-surface survey", "survey"),
    Stage("supply-chain", "Supply-chain review", "survey", toggle="run_sca"),
    Stage("integrity", "Code integrity review", "survey", toggle="run_integrity"),
    Stage("plan", "Lead planning", "hunt"),
    Stage("investigate", "Lead investigation", "hunt"),
    Stage("prove", "Proof of findings", "prove"),
    Stage("review", "Findings review", "review"),
    Stage("remediation", "Remediation", "remediation", toggle="run_remediation"),
    Stage("report", "Reporting", "report"),
)
STAGES_BY_KEY: dict[str, Stage] = {s.key: s for s in STAGES}

# Engine-level pseudo stage for run-wide events (run.started, run.finished…).
RUN_STAGE = "run"


# ---------------------------------------------------------------------------
# Actors → stage. Agents that run as numbered instances ("investigator-3")
# are matched on their base name.
# ---------------------------------------------------------------------------

ACTOR_STAGES: dict[str, str] = {
    "surveyor": "survey",
    "supply-chain": "supply-chain",
    "integrity": "integrity",
    "planner": "plan",
    "investigator": "investigate",
    "prover": "prove",
    "reviewer": "review",
    "remediator": "remediation",
    "reporter": "report",
}


# ---------------------------------------------------------------------------
# Identifiers written by earlier versions of the engine (historical runs only)
# ---------------------------------------------------------------------------

LEGACY_STAGE_STEPS: dict[str, str] = {
    "pre-recon": "survey",
    "recon": "survey",
    "sca": "survey",
    "vulnerability-analysis": "hunt",
    "vulnerability-exploitation": "hunt",
    "exploitation": "prove",
    "chain-exploitation": "prove",
    "critique": "review",
    "reporting": "report",
}

LEGACY_ACTOR_STEPS: dict[str, str] = {
    "pre-recon": "survey",
    "recon": "survey",
    "sca": "survey",
    "integrity": "survey",
    "chain-exploit": "prove",
    "report-critic": "review",
    "remediation": "remediation",
    "report": "report",
    **{f"{t}-vuln": "hunt" for t in (
        "injection", "xss", "auth", "ssrf", "authz", "graphql", "websocket", "crypto",
    )},
    **{f"{t}-exploit": "prove" for t in (
        "injection", "xss", "auth", "ssrf", "authz", "graphql", "websocket",
    )},
}


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------


def base_actor(actor: str) -> str:
    """Strip a trailing instance number: ``investigator-3`` → ``investigator``."""
    head, sep, tail = actor.rpartition("-")
    return head if sep and tail.isdigit() else actor


def stage_for_actor(actor: str | None) -> str | None:
    """Return the stage an actor belongs to, or ``None`` if unknown."""
    if not actor:
        return None
    return ACTOR_STAGES.get(base_actor(actor))


def step_for_stage(stage: str | None) -> str | None:
    """Map a stage identifier (current or legacy) onto its trace-rail step."""
    if not stage:
        return None
    if stage in STAGES_BY_KEY:
        return STAGES_BY_KEY[stage].step
    if stage in STEP_KEYS:
        return stage
    return LEGACY_STAGE_STEPS.get(stage)


def step_for_actor(actor: str | None) -> str | None:
    """Map an actor identifier (current or legacy) onto its trace-rail step."""
    if not actor:
        return None
    stage = stage_for_actor(actor)
    if stage:
        return step_for_stage(stage)
    return LEGACY_ACTOR_STEPS.get(actor)


def stage_to_step_map() -> dict[str, str]:
    """Every known stage identifier (current + legacy) → step."""
    out = dict(LEGACY_STAGE_STEPS)
    out.update({s.key: s.step for s in STAGES})
    return out


def actor_to_step_map() -> dict[str, str]:
    """Every known actor base name (current + legacy) → step."""
    out = dict(LEGACY_ACTOR_STEPS)
    out.update({a: STAGES_BY_KEY[s].step for a, s in ACTOR_STAGES.items()})
    return out


def _check_registry() -> None:
    bad = [s.key for s in STAGES if s.step not in STEP_KEYS]
    bad += [a for a, s in ACTOR_STAGES.items() if s not in STAGES_BY_KEY]
    bad += [k for k, v in {**LEGACY_STAGE_STEPS, **LEGACY_ACTOR_STEPS}.items()
            if v not in STEP_KEYS]
    if bad:
        raise RuntimeError(f"stage registry is inconsistent: {sorted(bad)}")


_check_registry()
