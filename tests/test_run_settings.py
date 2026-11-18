"""Per-run settings: pipeline_config validation, model_overrides -> executor env,
VIGILO_PIPELINE_CONFIG in the single-scan worker, remediation gate."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from src.ai import claude_executor, codex_executor, executor, opencode_executor
from src.types.config import (
    PipelineConfig,
    clean_model_overrides,
    model_override_env,
)


class TestPipelineConfig:
    def test_defaults(self):
        c = PipelineConfig.from_input(None)
        assert (c.max_concurrent_pipelines, c.leads_per_investigator, c.findings_per_prover,
                c.investigation_followup_rounds, c.retry_preset) == (8, 3, 3, 1, None)

    def test_valid_values_pass_through(self):
        c = PipelineConfig.from_input({
            "max_concurrent_pipelines": 4, "leads_per_investigator": "5",
            "findings_per_prover": 2, "investigation_followup_rounds": 0,
            "retry_preset": "subscription",
        })
        assert (c.max_concurrent_pipelines, c.leads_per_investigator, c.findings_per_prover,
                c.investigation_followup_rounds, c.retry_preset) == (4, 5, 2, 0, "subscription")

    def test_bounds_are_clamped(self):
        c = PipelineConfig.from_input({
            "max_concurrent_pipelines": 0, "leads_per_investigator": 10_000,
            "findings_per_prover": -3, "investigation_followup_rounds": 99,
        })
        assert c.max_concurrent_pipelines == 1
        assert c.leads_per_investigator == PipelineConfig.BOUNDS["leads_per_investigator"][1]
        assert c.findings_per_prover == 1
        assert c.investigation_followup_rounds == PipelineConfig.BOUNDS["investigation_followup_rounds"][1]

    def test_garbage_falls_back_and_unknown_keys_are_ignored(self):
        c = PipelineConfig.from_input({
            "max_concurrent_pipelines": "many", "leads_per_investigator": True,
            "findings_per_prover": [1], "retry_preset": "yolo", "bogus": 1,
        })
        assert (c.max_concurrent_pipelines, c.leads_per_investigator, c.findings_per_prover) == (8, 3, 3)
        assert c.retry_preset is None
        assert PipelineConfig.from_input("not a dict").max_concurrent_pipelines == 8


class TestModelOverrides:
    def test_models_go_to_the_overridden_executors_variables(self):
        assert model_override_env({
            "executor": "opencode", "model_small": "a", "model_medium": "b", "model_large": "c",
        }) == {"VIGILO_EXECUTOR": "opencode", "OPENCODE_SMALL_MODEL": "a",
               "OPENCODE_MEDIUM_MODEL": "b", "OPENCODE_LARGE_MODEL": "c"}

    def test_models_follow_the_effective_executor_when_not_overridden(self):
        # Worker runs codex (from its env); only models are overridden.
        assert model_override_env({"model_large": "gpt-5-5"}, "codex") == {"CODEX_LARGE_MODEL": "gpt-5-5"}
        assert model_override_env({"model_large": "m"}, "claude") == {"ANTHROPIC_LARGE_MODEL": "m"}
        assert model_override_env({"model_small": "s"}) == {"ANTHROPIC_SMALL_MODEL": "s"}

    def test_codex_override_never_sets_anthropic_model_vars(self):
        env = model_override_env({"executor": "codex", "model_large": "gpt-5-5"}, "codex")
        assert env == {"VIGILO_EXECUTOR": "codex", "CODEX_LARGE_MODEL": "gpt-5-5"}
        assert not any(k.startswith("ANTHROPIC_") for k in env)

    def test_cleaning(self):
        assert clean_model_overrides(None) is None
        assert clean_model_overrides({"executor": None, "model_large": "  "}) is None
        assert clean_model_overrides({"model_large": " x ", "api_key": "secret", "executor": 3}) == {"model_large": "x"}
        assert clean_model_overrides({"model_large": "x" * 500}) is None


class TestExecutorUsesOverrides:
    """Overrides arrive as extra env, not os.environ: the worker is shared."""

    def test_executor_choice_from_env_mapping(self, monkeypatch):
        monkeypatch.delenv("VIGILO_EXECUTOR", raising=False)
        assert executor.get_executor_type({"VIGILO_EXECUTOR": "codex"}) == "codex"
        assert executor.get_executor_type({}) == "claude"

    def test_resolve_model_reads_given_env(self, monkeypatch):
        for var in ("ANTHROPIC_LARGE_MODEL", "OPENCODE_LARGE_MODEL", "CODEX_LARGE_MODEL"):
            monkeypatch.delenv(var, raising=False)
        assert claude_executor.resolve_model("large", {"ANTHROPIC_LARGE_MODEL": "claude-x"}) == "claude-x"
        assert opencode_executor.resolve_model("large", {"OPENCODE_LARGE_MODEL": "q"}) == "litellm/q"
        assert codex_executor.resolve_model("large", {"CODEX_LARGE_MODEL": "g"}) == "g"
        assert claude_executor.resolve_model("large") == claude_executor.MODEL_DEFAULTS["large"]

    @pytest.mark.asyncio
    async def test_execute_dispatches_on_extra_env(self, monkeypatch):
        monkeypatch.delenv("VIGILO_EXECUTOR", raising=False)
        seen = {}

        async def fake(**kw):
            seen.update(kw)
            return SimpleNamespace(success=True)

        monkeypatch.setattr("src.ai.opencode_executor.execute", fake)
        await executor.execute(
            prompt="p", agent_name="a", model_tier="large", cwd="/",
            extra_env={"VIGILO_EXECUTOR": "opencode", "ANTHROPIC_LARGE_MODEL": "m"},
        )
        assert seen["extra_env"]["VIGILO_EXECUTOR"] == "opencode"
        assert seen["extra_env"]["VIGILO_AGENT"] == "a"


class TestSingleScanWorkerPipelineConfig:
    def _data(self, monkeypatch, value):
        from src.temporal.worker import _build_pipeline_input

        monkeypatch.delenv("VIGILO_PIPELINE_CONFIG", raising=False)
        if value is not None:
            monkeypatch.setenv("VIGILO_PIPELINE_CONFIG", value)
        args = SimpleNamespace(web_url="", repo_path="/repos/target", stages=None)
        return _build_pipeline_input(args, "wf", "sess")

    def test_reads_json_object(self, monkeypatch):
        cfg = {"max_concurrent_pipelines": 2, "retry_preset": "subscription"}
        assert self._data(monkeypatch, json.dumps(cfg))["pipeline_config"] == cfg

    @pytest.mark.parametrize("bad", ["{not json", "[1, 2]", '"str"', "", "  "])
    def test_ignores_invalid(self, monkeypatch, bad):
        assert "pipeline_config" not in self._data(monkeypatch, bad)

    def test_absent(self, monkeypatch):
        assert "pipeline_config" not in self._data(monkeypatch, None)


class TestRemediationGate:
    INDEX = {"by_type": {
        "injection": [
            {"ID": "VG-001", "vulnerability_type": "injection", "status": "exploited"},
            {"ID": "VG-002", "vulnerability_type": "injection", "status": "suppressed"},
            {"ID": "VG-003", "vulnerability_type": "injection", "status": "potential", "code_fixable": False},
        ],
        "chain": [{"ID": "CH-01", "vulnerability_type": "chain", "status": "potential"}],
    }}

    def test_counts(self):
        from src.temporal.activities import count_remediable

        assert count_remediable(self.INDEX, None) == {"total": 4, "remediable": 1}

    def test_critique_can_exclude_everything(self):
        from src.temporal.activities import count_remediable

        critique = {"annotations": {"VG-001": {"include_in_report": False}}}
        assert count_remediable(self.INDEX, critique)["remediable"] == 0
        critique = {"annotations": {"VG-001": {"include_in_report": True, "confidence": "theoretical"}}}
        assert count_remediable(self.INDEX, critique)["remediable"] == 0
        critique = {"annotations": {"VG-001": {"include_in_report": True, "confidence": "conditional"}}}
        assert count_remediable(self.INDEX, critique)["remediable"] == 1

    def test_empty_index(self):
        from src.temporal.activities import count_remediable

        assert count_remediable({}, None) == {"total": 0, "remediable": 0}


def test_api_pipeline_bounds_are_the_workflow_bounds():
    import pytest

    from src.webapi.schemas import PIPELINE_INT_BOUNDS, validate_pipeline_overrides

    assert PIPELINE_INT_BOUNDS == dict(PipelineConfig.BOUNDS)
    for key, (lo, hi) in PipelineConfig.BOUNDS.items():
        assert validate_pipeline_overrides({key: hi}) == {key: hi}
        with pytest.raises(ValueError, match=f"{key} must be an integer between {lo} and {hi}"):
            validate_pipeline_overrides({key: hi + 1})
