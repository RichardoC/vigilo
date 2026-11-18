"""Trace-rail configuration (src/webapi/trace_rail.py) built from the stage registry."""
import pytest

from src.pipeline.stages import ACTOR_STAGES, STAGES, STEP_KEYS
from src.webapi import trace_rail


class TestTraceRailMapping:
    def test_every_stage_is_mapped(self):
        for stage in STAGES:
            assert trace_rail.PHASE_TO_STEP[stage.key] == stage.step
            assert stage.step in STEP_KEYS

    def test_every_actor_maps_to_a_step(self):
        for actor in ACTOR_STAGES:
            assert trace_rail.step_for_marker(actor) in STEP_KEYS, actor

    @pytest.mark.parametrize("identifier,expected", [
        ("survey", "survey"),
        ("supply-chain", "survey"),
        ("plan", "hunt"),
        ("investigate", "hunt"),
        ("investigator-4", "hunt"),
        ("prover-2", "prove"),
        ("reviewer", "review"),
        ("remediator", "remediation"),
        ("reporter", "report"),
    ])
    def test_current_identifiers(self, identifier, expected):
        assert trace_rail.step_for_marker(identifier) == expected

    @pytest.mark.parametrize("identifier,expected", [
        # identifiers stored by runs recorded before the stage registry
        ("pre-recon", "survey"),
        ("vulnerability-exploitation", "hunt"),
        ("injection-vuln", "hunt"),
        ("xss-exploit", "prove"),
        ("chain-exploitation", "prove"),
        ("report-critic", "review"),
        ("critique", "review"),
        ("reporting", "report"),
    ])
    def test_historical_identifiers_still_render(self, identifier, expected):
        assert trace_rail.step_for_marker(identifier) == expected

    def test_unknown_marker_returns_none(self):
        assert trace_rail.step_for_marker("totally-made-up") is None
        assert trace_rail.step_for_marker(None) is None

    def test_preset_steps_reflect_stage_selection(self):
        core = ["preflight", "survey", "hunt", "prove", "review"]
        assert trace_rail.PRESET_STEPS["vuln"] == core + ["report"]
        assert trace_rail.PRESET_STEPS["vuln_patch"] == core + ["remediation", "report"]
        assert trace_rail.PRESET_STEPS["full"] == core + ["remediation", "report"]


class TestTraceRailEndpoint:
    async def test_endpoint_returns_config(self, client, user_token):
        r = await client.get("/pipeline/trace-rail", headers={"Authorization": f"Bearer {user_token}"})
        assert r.status_code == 200
        cfg = r.json()
        assert {"steps", "presets", "phase_to_step", "agent_to_step"} <= cfg.keys()
        assert [s["key"] for s in cfg["steps"]][:2] == ["preflight", "survey"]
        assert cfg["phase_to_step"]["investigate"] == "hunt"
        assert cfg["agent_to_step"]["reviewer"] == "review"
        assert cfg["agent_to_step"]["report-critic"] == "review"
