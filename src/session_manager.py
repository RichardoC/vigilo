"""Session manager: agent registry and Playwright session mapping.

The white-box engine's actors and 8 base Playwright sessions.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from src.types.agents import (
    AgentDefinition,
    AgentName,
    PlaywrightSession,
)


# ---------------------------------------------------------------------------
# AGENTS registry
# ---------------------------------------------------------------------------
# Immutable mapping of every agent in the pipeline. Each entry defines the
# agent's identity, prompt template, deliverable filename and model tier.
# ---------------------------------------------------------------------------

AGENTS: Mapping[AgentName, AgentDefinition] = MappingProxyType({
    # --- Integrity analysis (malicious code detection) ---
    "integrity": AgentDefinition(
        name="integrity",
        prompt_template="integrity",
        deliverable_filename="integrity_analysis.json",
        model_tier="large",
    ),
    # ===================================================================
    # White-box engine actors (WhiteboxEngineWorkflow / PatchWorkflow).
    # Names match the actors in src/pipeline/stages.py. investigator and
    # prover run as numbered instances (investigator-3); run_agent resolves
    # those to these base definitions. Agents whose output is the findings
    # ledger name a ledger file as their deliverable; investigator and prover
    # are additionally checked against their batch assignment in run_agent.
    # ===================================================================
    "surveyor": AgentDefinition(
        name="surveyor",
        prompt_template="whitebox/surveyor",
        deliverable_filename="code_analysis_deliverable.md",
        model_tier="large",
    ),
    "supply-chain": AgentDefinition(
        name="supply-chain",
        prompt_template="sca",
        deliverable_filename="sca_findings.json",
        model_tier="medium",
    ),
    "planner": AgentDefinition(
        name="planner",
        prompt_template="whitebox/planner",
        deliverable_filename="ledger/leads.jsonl",
        model_tier="large",
    ),
    "investigator": AgentDefinition(
        name="investigator",
        prompt_template="whitebox/investigator",
        deliverable_filename="ledger/lead_status.jsonl",
        model_tier="large",
    ),
    "prover": AgentDefinition(
        name="prover",
        prompt_template="whitebox/prover",
        deliverable_filename="ledger/verdicts.jsonl",
        model_tier="large",
    ),
    "reviewer": AgentDefinition(
        name="reviewer",
        prompt_template="critic",
        deliverable_filename="findings_critique.json",
        model_tier="large",
    ),
    "remediator": AgentDefinition(
        name="remediator",
        prompt_template="remediation",
        deliverable_filename="remediation_report.md",
        model_tier="medium",
    ),
    "reporter": AgentDefinition(
        name="reporter",
        prompt_template="report-executive",
        deliverable_filename="comprehensive_security_assessment_report.md",
        model_tier="medium",
    ),
})

# ---------------------------------------------------------------------------
# PLAYWRIGHT_SESSION_MAPPING — assigns prompt templates to browser sessions
# ---------------------------------------------------------------------------
# Agents running in parallel must not share a browser session; the generic
# white-box actors additionally get per-instance sessions (see below).
#
# Single source of truth: src/services/prompt_manager.py imports this mapping
# (session_for_prompt / load_prompt). Prompts not listed fall back to agent1.
# ---------------------------------------------------------------------------

PLAYWRIGHT_SESSION_MAPPING: Mapping[str, PlaywrightSession] = MappingProxyType({
    # Supply-chain + integrity (no browser needed, share a slot)
    "sca": "agent8",
    "integrity": "agent8",
    # Review (read-only — uses agent2 to avoid the agent1 lane)
    "critic": "agent2",
    # Remediation
    "remediation": "agent1",
    # Reporting
    "report-executive": "agent3",
    # White-box engine (generic actors). These are base sessions; numbered
    # parallel instances (investigator-3) get their own via
    # prompt_manager.session_for_prompt(): agent2 + 3 -> agent2-3.
    "whitebox/surveyor": "agent1",
    "whitebox/planner": "agent1",
    "whitebox/investigator": "agent2",
    "whitebox/prover": "agent3",
})
