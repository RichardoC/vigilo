"""Agent type definitions for the Vigilo pipeline.

Defines the agent inventory, model tiers, stage names and agent definitions
for the white-box engine's actors (surveyor, planner, investigator, prover, ...).
"""

from __future__ import annotations

from typing import Literal, get_args

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Agent names — single source of truth, in execution order.
# ---------------------------------------------------------------------------

AgentName = Literal[
    "integrity",
    # White-box engine actors (src/pipeline/stages.py). Agents that run as
    # numbered parallel instances ("investigator-3") resolve to these base names.
    "surveyor",
    "supply-chain",
    "planner",
    "investigator",
    "prover",
    "reviewer",
    "remediator",
    "reporter",
]

ALL_AGENTS: list[AgentName] = list(get_args(AgentName))


# ---------------------------------------------------------------------------
# Playwright sessions — base slots ("agent1"..) plus per-instance variants
# ---------------------------------------------------------------------------

# A base session ("agent2") or, for numbered parallel instances of one prompt,
# a per-instance session ("agent2-3", see prompt_manager.session_for_prompt).
# A plain ``str`` because a Literal cannot express the numbered form.
PlaywrightSession = str


# ---------------------------------------------------------------------------
# Model tiers — resolved to concrete model names by claude_executor
# ---------------------------------------------------------------------------

ModelTier = Literal["small", "medium", "large"]


# ---------------------------------------------------------------------------
# Pipeline stage names (white-box engine stage keys)
# ---------------------------------------------------------------------------

PhaseName = Literal[
    "preflight",
    "integrity",
    # White-box engine stage keys (src/pipeline/stages.py)
    "survey",
    "supply-chain",
    "plan",
    "investigate",
    "prove",
    "review",
    "remediation",
    "report",
]


# ---------------------------------------------------------------------------
# Agent definition — describes an agent's configuration in the registry
# ---------------------------------------------------------------------------


class AgentDefinition(BaseModel):
    """Static definition of an agent in the pipeline registry."""

    name: AgentName
    prompt_template: str
    deliverable_filename: str
    model_tier: ModelTier = "medium"
