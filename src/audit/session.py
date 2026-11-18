"""Audit session facade.

Coordinates the run's :class:`EventLog` (``events.jsonl`` + ``workflow.log``),
:class:`MetricsTracker` (``session.json``) and :class:`AgentLogger`
(``agents/*.log``) behind a single entry point.
"""

from __future__ import annotations

import os

from src.pipeline.stages import stage_for_actor
from src.types.audit import SessionMetadata
from src.types.metrics import AgentMetrics

from .agent_logger import AgentLogger
from .metrics_tracker import MetricsTracker
from .events import EventLog


def get_workspace_path(
    session_id: str,
    repo_path: str,
    output_path: str | None = None,
) -> str:
    """Return the workspace directory for *session_id*.

    Uses *output_path* as the base when provided, otherwise defaults to
    ``{repo_path}/.vigilo``.  This places all scan artefacts inside the
    target repository so users find results where they expect them.
    """
    base = output_path or os.path.join(repo_path, ".vigilo")
    return os.path.join(base, session_id)


class AuditSession:
    """Main audit system facade for one run (session).

    Usage::

        session = AuditSession(metadata)
        await session.initialize(workflow_id="wf-123")
        await session.log_phase_start("survey")
        await session.start_agent("surveyor", attempt=1)
        # ... agent runs ...
        await session.end_agent("surveyor", metrics, checkpoint="abc123")
        await session.log_phase_complete("survey")
        await session.log_workflow_complete(summary)
    """

    def __init__(self, metadata: SessionMetadata) -> None:
        self.metadata = metadata
        self._initialized = False

        # Sub-components (created in ``initialize``)
        self._events: EventLog | None = None
        self._metrics_tracker: MetricsTracker | None = None
        self._agent_logger: AgentLogger | None = None
        self._attempts: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    async def initialize(self, workflow_id: str = "") -> None:
        """Set up the audit directory structure and initialise sub-components.

        Creates:
        - ``{repo_path}/.vigilo/{session_id}/``
        - ``{repo_path}/.vigilo/{session_id}/agents/``
        - ``{repo_path}/.vigilo/{session_id}/prompts/``
        - ``{repo_path}/.vigilo/{session_id}/deliverables/``
        """
        if self._initialized:
            return

        workspace = get_workspace_path(
            self.metadata.id,
            self.metadata.repo_path,
            self.metadata.output_path,
        )

        # Create directory tree
        for subdir in ("agents", "prompts", "deliverables"):
            os.makedirs(os.path.join(workspace, subdir), exist_ok=True)

        # Event log. Every activity builds its own AuditSession, so only the
        # first one to touch the workspace records the run.started event.
        self._events = EventLog(workspace, self.metadata.id)
        if not self._events.exists():
            self._events.run_started(self.metadata.web_url)

        # Metrics tracker
        session_json_path = os.path.join(workspace, "session.json")
        self._metrics_tracker = MetricsTracker(session_json_path)
        await self._metrics_tracker.initialize(self.metadata, workflow_id)

        # Agent logger
        self._agent_logger = AgentLogger(workspace)

        self._initialized = True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _ensure_initialized(self) -> None:
        if not self._initialized:
            await self.initialize()

    @staticmethod
    def _stage_for(agent_name: str, stage: str | None) -> str | None:
        """The stage recorded on an agent's events: an explicit ``stage`` wins,
        then the stage registry's actor mapping (numbered instances included)."""
        return stage or stage_for_actor(agent_name)

    # ------------------------------------------------------------------
    # Agent lifecycle
    # ------------------------------------------------------------------

    async def start_agent(
        self, agent_name: str, attempt: int, stage: str | None = None
    ) -> None:
        """Record the start of an agent execution."""
        await self._ensure_initialized()
        assert self._events is not None
        assert self._metrics_tracker is not None
        assert self._agent_logger is not None

        self._attempts[agent_name] = attempt
        self._events.agent_started(agent_name, attempt, self._stage_for(agent_name, stage))
        await self._metrics_tracker.start_agent(agent_name, attempt)

        # Create per-attempt log file with header banner
        await self._agent_logger.start_agent_log(
            agent_name,
            attempt,
            session_id=self.metadata.id,
            web_url=self.metadata.web_url,
        )
        await self._agent_logger.log_event(
            agent_name,
            "agent_start",
            {"agentName": agent_name, "attemptNumber": attempt},
        )

    async def log_agent_turn(
        self, agent_name: str, turn: int, content: str, stage: str | None = None
    ) -> None:
        """Record one model turn: an excerpt in the event log, full text in the agent log."""
        await self._ensure_initialized()
        assert self._events is not None
        assert self._agent_logger is not None
        self._events.agent_turn(agent_name, turn, content, self._stage_for(agent_name, stage))
        await self._agent_logger.log_event(
            agent_name, "llm_response", {"turn": turn, "content": content}
        )

    async def end_agent(
        self,
        agent_name: str,
        metrics: AgentMetrics,
        checkpoint: str | None = None,
        stage: str | None = None,
    ) -> None:
        """Record agent completion with collected metrics."""
        await self._ensure_initialized()
        assert self._events is not None
        assert self._metrics_tracker is not None
        assert self._agent_logger is not None

        cost = metrics.cost_usd or 0.0
        self._events.agent_finished(
            agent_name,
            self._stage_for(agent_name, stage),
            duration_ms=metrics.duration_ms,
            cost_usd=metrics.cost_usd,
            turns=metrics.num_turns,
            model=metrics.model,
        )
        await self._metrics_tracker.end_agent(
            agent_name=agent_name,
            attempt=self._attempts.get(agent_name, 1),
            duration_ms=metrics.duration_ms,
            cost_usd=cost,
            status="success",  # Caller is responsible for not calling on failure
            model=metrics.model,
            checkpoint=checkpoint,
        )
        await self._agent_logger.log_event(
            agent_name,
            "agent_end",
            {
                "duration_ms": metrics.duration_ms,
                "cost_usd": cost,
                "model": metrics.model,
            },
        )

    async def fail_agent(
        self, agent_name: str, error: str, stage: str | None = None
    ) -> None:
        """Record an agent attempt that raised."""
        await self._ensure_initialized()
        assert self._events is not None
        assert self._agent_logger is not None
        self._events.agent_failed(agent_name, self._stage_for(agent_name, stage), error)
        await self._agent_logger.log_event(
            agent_name, "agent_error", {"error": error[:500]}
        )

    async def retry_agent(
        self, agent_name: str, *, attempt: int, error_type: str, reason: str,
        next_attempt_at: str | None = None, retry_in_s: float | None = None,
        max_attempts: int | None = None, stage: str | None = None,
    ) -> None:
        """Record that a failed attempt will be retried (and when)."""
        await self._ensure_initialized()
        assert self._events is not None
        self._events.agent_retrying(
            agent_name, self._stage_for(agent_name, stage), attempt=attempt,
            error_type=error_type, reason=reason, next_attempt_at=next_attempt_at,
            retry_in_s=retry_in_s, max_attempts=max_attempts,
        )

    # ------------------------------------------------------------------
    # Stage events
    # ------------------------------------------------------------------

    async def log_stage(self, stage: str, event: str, **data: object) -> None:
        """Record a stage transition; ``event`` is ``start``, ``complete``, ``skip``,
        ``warn`` or ``fail`` (see :meth:`EventLog.stage`)."""
        await self._ensure_initialized()
        assert self._events is not None
        self._events.stage(stage, event, **data)

    async def log_phase_start(self, phase: str) -> None:
        await self.log_stage(phase, "start")

    async def log_phase_complete(self, phase: str) -> None:
        await self.log_stage(phase, "complete")

    # ------------------------------------------------------------------
    # Workflow lifecycle
    # ------------------------------------------------------------------

    async def log_workflow_complete(self, summary: dict) -> None:
        await self._ensure_initialized()
        assert self._events is not None
        self._events.run_finished(summary)

    async def update_session_status(self, status: str) -> None:
        await self._ensure_initialized()
        assert self._metrics_tracker is not None
        await self._metrics_tracker.update_status(status)
