"""Tests for pipeline stage selection (src/types/stages.py)."""
from __future__ import annotations

import pytest

from src.types.stages import (
    PRESET_FULL,
    PRESET_VULN,
    PRESET_VULN_PATCH,
    StageSelection,
    resolve_stages,
    stages_for_preset,
)


class TestPresets:
    def test_vuln_preset_runs_no_optional_stage(self):
        s = stages_for_preset(PRESET_VULN)
        assert (s.run_sca, s.run_integrity, s.run_remediation) == (False, False, False)

    def test_vuln_patch_adds_remediation(self):
        s = stages_for_preset(PRESET_VULN_PATCH)
        assert s.run_remediation is True
        assert s.run_sca is False and s.run_integrity is False

    def test_full_runs_everything(self):
        s = stages_for_preset(PRESET_FULL)
        assert all([s.run_sca, s.run_integrity, s.run_remediation])

    def test_unknown_preset_raises(self):
        with pytest.raises(ValueError):
            stages_for_preset("nonsense")

    def test_only_live_flags_exist(self):
        assert set(StageSelection.__dataclass_fields__) == {"run_sca", "run_integrity", "run_remediation"}


class TestResolveStages:
    def test_none_is_full_pipeline(self):
        s = resolve_stages(None)
        assert s.run_remediation is True and s.run_sca is True

    def test_string_preset(self):
        assert resolve_stages("vuln").run_remediation is False

    def test_dict_with_preset(self):
        assert resolve_stages({"preset": "vuln"}).run_remediation is False

    def test_dict_overrides_are_applied(self):
        s = resolve_stages({"preset": "vuln", "run_sca": True})
        assert s.run_sca is True and s.run_remediation is False

    def test_legacy_keys_from_stored_jobs_are_ignored(self):
        s = resolve_stages({
            "run_vuln": False, "run_chain": True, "run_critique": False,
            "run_sca": False, "run_integrity": True, "run_remediation": False,
        })
        assert (s.run_sca, s.run_integrity, s.run_remediation) == (False, True, False)

    def test_bad_type_raises(self):
        with pytest.raises(TypeError):
            resolve_stages(123)
