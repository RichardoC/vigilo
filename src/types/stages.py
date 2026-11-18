"""Pipeline stage selection.

Maps a user-facing preset (``vuln`` / ``vuln_patch`` / ``full``) to the optional
stages ``WhiteboxEngineWorkflow`` runs: ``run_sca`` (supply-chain), ``run_integrity``
and ``run_remediation``. Survey, plan, investigate, prove, review and report always
run; review (the false-positive gate) can never be switched off.

Older stored jobs carry flags that no longer exist (``run_vuln``, ``run_chain``,
``run_critique``); ``resolve_stages`` accepts and ignores them.

Implemented with a stdlib frozen dataclass (deterministic, no third-party import) so
it is safe to import inside the Temporal workflow sandbox.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

# Canonical preset names exposed to API consumers.
PRESET_VULN = "vuln"
PRESET_VULN_PATCH = "vuln_patch"
PRESET_FULL = "full"

VALID_PRESETS = (PRESET_VULN, PRESET_VULN_PATCH, PRESET_FULL)


@dataclass(frozen=True)
class StageSelection:
    """Which optional stages run. The other stages always run."""

    run_sca: bool = True          # supply-chain analysis
    run_integrity: bool = True    # integrity analysis
    run_remediation: bool = True  # fix branches / patches / MRs

    def normalized(self) -> "StageSelection":
        """Kept for callers that normalise; there are no cross-flag invariants."""
        return self


def stages_for_preset(preset: str) -> StageSelection:
    """Return the StageSelection for a named preset."""
    if preset == PRESET_VULN:
        return StageSelection(run_sca=False, run_integrity=False, run_remediation=False)
    if preset == PRESET_VULN_PATCH:
        return StageSelection(run_sca=False, run_integrity=False, run_remediation=True)
    if preset == PRESET_FULL:
        return StageSelection()
    raise ValueError(
        f"Unknown stage preset {preset!r}; expected one of {VALID_PRESETS}"
    )


def resolve_stages(raw: object) -> StageSelection:
    """Resolve a workflow-input ``stages`` value into a StageSelection.

    Accepts ``None`` (→ full pipeline), a preset name
    string, or a dict of flag overrides (unknown keys are ignored).
    """
    if raw is None:
        return StageSelection().normalized()
    if isinstance(raw, str):
        return stages_for_preset(raw)
    if isinstance(raw, StageSelection):
        return raw.normalized()
    if isinstance(raw, dict):
        if "preset" in raw:
            base = stages_for_preset(raw["preset"])
        else:
            base = StageSelection()
        fields = {
            k: bool(v) for k, v in raw.items()
            if k in StageSelection.__dataclass_fields__
        }
        return replace(base, **fields).normalized()
    raise TypeError(f"Cannot resolve stages from {type(raw).__name__}")
