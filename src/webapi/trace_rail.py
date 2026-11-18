"""Trace-rail configuration served to the UI.

The UI shows a coarse rail of user-facing *steps*. Which stages and agents feed
each step is defined once in :mod:`src.pipeline.stages`; this module only
packages that registry (plus the per-preset step lists) for
``GET /pipeline/trace-rail`` so the frontend never hardcodes a stage name.
"""
from __future__ import annotations

from src.pipeline.stages import (
    STAGES,
    STEPS,
    actor_to_step_map,
    stage_to_step_map,
    step_for_actor,
    step_for_stage,
)
from src.types.stages import VALID_PRESETS, stages_for_preset

STEP_ORDER: list[tuple[str, str]] = list(STEPS)

# Every known stage / actor identifier (current and historical) → rail step.
PHASE_TO_STEP: dict[str, str] = stage_to_step_map()
AGENT_TO_STEP: dict[str, str] = actor_to_step_map()


def _steps_for_preset(preset: str) -> list[str]:
    """Ordered step keys that actually run for a preset."""
    sel = stages_for_preset(preset)
    keys: list[str] = []
    for stage in STAGES:
        if stage.toggle and not getattr(sel, stage.toggle, True):
            continue
        if stage.step not in keys:
            keys.append(stage.step)
    return [k for k, _ in STEPS if k in keys]


PRESET_STEPS: dict[str, list[str]] = {p: _steps_for_preset(p) for p in VALID_PRESETS}


def step_for_marker(identifier: str | None) -> str | None:
    """Map a stage-or-actor identifier onto a rail step."""
    return step_for_stage(identifier) or step_for_actor(identifier)


def trace_rail_config() -> dict:
    """The full mapping payload served to the UI."""
    return {
        "steps": [{"key": k, "label": lbl} for k, lbl in STEP_ORDER],
        "presets": PRESET_STEPS,
        "phase_to_step": PHASE_TO_STEP,
        "agent_to_step": AGENT_TO_STEP,
    }
