"""Type definitions for the Vigilo pipeline.

Re-exports key types so consumers can write:
    from src.types import AgentName, PipelineConfig, AgentMetrics
"""

from src.types.agents import (
    ALL_AGENTS,
    AgentDefinition,
    AgentName,
    ModelTier,
    PhaseName,
    PlaywrightSession,
)
from src.types.audit import SessionMetadata
from src.types.config import (
    Authentication,
    Credentials,
    PipelineConfig,
    Rule,
    SuccessCondition,
)
from src.types.deliverables import (
    DELIVERABLE_FILENAMES,
    DeliverableType,
)
from src.types.metrics import (
    AgentMetrics,
    PipelineState,
    PipelineSummary,
)

__all__ = [
    # agents
    "AgentName",
    "ALL_AGENTS",
    "PlaywrightSession",
    "ModelTier",
    "PhaseName",
    "AgentDefinition",
    # metrics
    "AgentMetrics",
    "PipelineSummary",
    "PipelineState",
    # config
    "Rule",
    "SuccessCondition",
    "Credentials",
    "Authentication",
    "PipelineConfig",
    # audit
    "SessionMetadata",
    # deliverables
    "DeliverableType",
    "DELIVERABLE_FILENAMES",
]
