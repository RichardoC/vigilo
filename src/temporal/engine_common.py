"""Helpers shared by the white-box engine workflows (WhiteboxEngineWorkflow,
PatchWorkflow).

Workflow-sandbox safe: only deterministic code, Temporal APIs, and modules
passed through the sandbox. Holds the retry policies and activity timeouts the
engines share.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

with workflow.unsafe.imports_passed_through():
    from src.temporal.activities import ActivityInput, scan_config_from_input
    from src.types.config import MODEL_OVERRIDE_ENV, PipelineConfig, clean_model_overrides
    from src.types.metrics import AgentMetrics, PipelineState, PipelineSummary

__all__ = [
    "AGENT_HEARTBEAT",
    "AGENT_START_TO_CLOSE",
    "OPTIONAL_RETRY",
    "PREFLIGHT_RETRY",
    "PRODUCTION_RETRY",
    "SUBSCRIPTION_RETRY",
    "DELIVER_HEARTBEAT",
    "DELIVER_START_TO_CLOSE",
    "EXPORT_HEARTBEAT",
    "EXPORT_START_TO_CLOSE",
    "PREFLIGHT_START_TO_CLOSE",
    "REBUILD_GIT_HEARTBEAT",
    "REBUILD_GIT_START_TO_CLOSE",
    "REMEDIATION_START_TO_CLOSE",
    "VERIFY_HEARTBEAT",
    "VERIFY_START_TO_CLOSE",
    "REPORT_START_TO_CLOSE",
    "UTILITY_START_TO_CLOSE",
    "ActivityInput",
    "EngineState",
]

# ---------------------------------------------------------------------------
# Retry policies
# ---------------------------------------------------------------------------

# Non-retryable error types, shared across all retry policies.
_NON_RETRYABLE_TYPES: list[str] = [
    "AuthenticationError",
    "PermissionError",
    "InvalidRequestError",
    "RequestTooLargeError",
    "ConfigurationError",
    "InvalidTargetError",
    "ExecutionLimitError",
    "ModelRefusalError",
]

# Default for agent activities. Permanent errors (bad credentials, unknown model,
# safety refusal) are classified by src.ai.errors and never retried; this policy
# only covers transient or unrecognised failures. Delays 20s, 40s, 80s, 2m, 2m
# between 6 attempts: a blip recovers within a minute or two, and a persistent
# unrecognised failure ends the run in roughly 10-15 min (attempts included)
# instead of keeping it "running" for hours. Rate-limited subscription plans opt
# in to SUBSCRIPTION_RETRY (retry_preset="subscription").
PRODUCTION_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=20),
    maximum_interval=timedelta(minutes=2),
    backoff_coefficient=2.0,
    maximum_attempts=6,
    non_retryable_error_types=_NON_RETRYABLE_TYPES,
)

PREFLIGHT_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=10),
    maximum_interval=timedelta(minutes=1),
    backoff_coefficient=2.0,
    maximum_attempts=3,
    non_retryable_error_types=_NON_RETRYABLE_TYPES,
)

# Optional stages (supply-chain, integrity) and non-fatal utilities
# (evidence rendering, critique audit, export/verify/deliver): a few quick
# attempts (10s, 20s), then give up: a run must not wait long on something it can
# do without. Same shape as PRODUCTION_RETRY, with fewer attempts and a shorter cap.
OPTIONAL_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=10),
    maximum_interval=timedelta(minutes=1),
    backoff_coefficient=2.0,
    maximum_attempts=3,
    non_retryable_error_types=_NON_RETRYABLE_TYPES,
)

# Subscription plans have 5h+ rolling rate limit windows
SUBSCRIPTION_RETRY = RetryPolicy(
    initial_interval=timedelta(minutes=5),
    maximum_interval=timedelta(hours=6),
    backoff_coefficient=2.0,
    maximum_attempts=100,
    non_retryable_error_types=_NON_RETRYABLE_TYPES,
)

# ---------------------------------------------------------------------------
# Activity timeout defaults
# ---------------------------------------------------------------------------

AGENT_START_TO_CLOSE = timedelta(hours=2)
REMEDIATION_START_TO_CLOSE = timedelta(hours=4)  # Remediation orchestrates many sub-agents
AGENT_HEARTBEAT = timedelta(minutes=60)
UTILITY_START_TO_CLOSE = timedelta(minutes=5)
PREFLIGHT_START_TO_CLOSE = timedelta(minutes=2)
REPORT_START_TO_CLOSE = timedelta(minutes=10)
# Long utility activities heartbeat every few seconds (they never block the
# worker's event loop), so a short heartbeat timeout detects a dead attempt.
EXPORT_START_TO_CLOSE = timedelta(minutes=15)
EXPORT_HEARTBEAT = timedelta(minutes=2)
# verify_patches re-runs up to several harnesses (3 min cap each) per fix branch.
VERIFY_START_TO_CLOSE = timedelta(minutes=90)
VERIFY_HEARTBEAT = timedelta(minutes=2)
# rebuild_git / deliver_patches heartbeat while their git subprocesses run, so a dead
# attempt is noticed within the heartbeat timeout and a retry never overlaps a live one.
REBUILD_GIT_START_TO_CLOSE = timedelta(minutes=15)
REBUILD_GIT_HEARTBEAT = timedelta(minutes=2)
DELIVER_START_TO_CLOSE = timedelta(minutes=30)
DELIVER_HEARTBEAT = timedelta(minutes=2)


def pipeline_config(input: dict[str, Any]) -> PipelineConfig:
    """The validated per-run ``pipeline_config`` (unknown keys ignored)."""
    return PipelineConfig.from_input(input.get("pipeline_config"))


def select_retry(cfg: PipelineConfig | dict[str, Any] | None) -> RetryPolicy:
    if not isinstance(cfg, PipelineConfig):
        cfg = PipelineConfig.from_input(cfg)
    if cfg.retry_preset == "subscription":
        return SUBSCRIPTION_RETRY
    return PRODUCTION_RETRY


def _model_overrides(input: dict[str, Any]) -> dict[str, str] | None:
    """``model_overrides`` from the input; platforms that pass the repository's
    whole pipeline_config (with executor / model_* keys in it) are honoured too."""
    overrides = clean_model_overrides(input.get("model_overrides"))
    if overrides:
        return overrides
    cfg = input.get("pipeline_config")
    if isinstance(cfg, dict):
        return clean_model_overrides({k: cfg.get(k) for k in MODEL_OVERRIDE_ENV})
    return None


def build_activity_input(input: dict[str, Any]) -> ActivityInput:
    """Resolve workflow/session ids and build the shared activity input."""
    wf_id = input.get("workflow_id") or workflow.info().workflow_id
    session_id = input.get("session_id") or wf_id
    return ActivityInput(
        web_url=input.get("web_url", ""),
        repo_path=input["repo_path"],
        workflow_id=wf_id,
        session_id=session_id,
        output_path=input.get("output_path"),
        scan_config=scan_config_from_input(input),
        push=input.get("push") or None,
        source=input.get("source") or None,
        auth=input.get("auth") or None,
        secrets=input.get("secrets") or None,
        model_overrides=_model_overrides(input),
    )


def unwrap_error(e: BaseException) -> str:
    """The real ApplicationError reason (``type: message``) behind Temporal's
    ActivityError / ChildWorkflowError wrappers, else ``str(e)``."""
    cur: BaseException | None = e
    for _ in range(12):
        if cur is None:
            break
        msg = getattr(cur, "message", None)
        if isinstance(cur, ApplicationError) and msg:
            typ = getattr(cur, "type", None)
            return (f"{typ}: {msg}" if typ else msg)[:2000]
        cur = getattr(cur, "cause", None)
    return str(e)[:2000]


class EngineState:
    """PipelineState plus the bookkeeping both engine workflows share."""

    def __init__(self) -> None:
        self.state = PipelineState(status="running", start_time=0.0)

    # -- query ---------------------------------------------------------------

    def progress(self) -> dict[str, Any]:
        """The shape the web API polls."""
        elapsed_ms = int((workflow.now().timestamp() - self.state.start_time) * 1000)
        return {
            **self.state.model_dump(),
            "workflow_id": workflow.info().workflow_id,
            "elapsed_ms": elapsed_ms,
        }

    # -- bookkeeping -----------------------------------------------------------

    def at(self, stage: str | None, actor: str | None) -> None:
        self.state.current_phase = stage
        self.state.current_agent = actor

    def record(self, actor: str, metrics: dict[str, Any] | None) -> None:
        if metrics is not None:
            self.state.agent_metrics[actor] = metrics
        self.state.completed_agents.append(actor)

    def merge(self, child: dict[str, Any] | None) -> None:
        """Fold a child workflow's returned state into this one."""
        if not isinstance(child, dict):
            return
        for actor, metrics in (child.get("agent_metrics") or {}).items():
            self.state.agent_metrics[actor] = metrics
        for actor in child.get("completed_agents") or []:
            if actor not in self.state.completed_agents:
                self.state.completed_agents.append(actor)

    def summary(self) -> PipelineSummary:
        total_cost = 0.0
        total_turns = 0
        for metrics in self.state.agent_metrics.values():
            if isinstance(metrics, dict):
                total_cost += metrics.get("cost_usd") or 0.0
                total_turns += metrics.get("num_turns") or 0
            elif isinstance(metrics, AgentMetrics):
                total_cost += metrics.cost_usd or 0.0
                total_turns += metrics.num_turns or 0
        return PipelineSummary(
            total_cost_usd=total_cost,
            total_duration_ms=int((workflow.now().timestamp() - self.state.start_time) * 1000),
            total_turns=total_turns,
            agent_count=len(self.state.completed_agents),
        )

    def workflow_summary(self, status: str) -> dict[str, Any]:
        """Payload for the log_workflow_complete activity."""
        summary = self.summary()
        return {
            "status": status,
            "total_cost_usd": summary.total_cost_usd,
            "total_duration_ms": summary.total_duration_ms,
            "total_turns": summary.total_turns,
            "agent_count": summary.agent_count,
            "completed_agents": list(self.state.completed_agents),
            "failed_agent": self.state.failed_agent,
            "error": self.state.error,
            "agent_metrics": {
                k: v if isinstance(v, dict) else v.model_dump()
                for k, v in self.state.agent_metrics.items()
            },
        }

    def complete(self) -> dict[str, Any]:
        self.state.status = "completed"
        self.at(None, None)
        self.state.summary = self.summary()
        return self.state.model_dump()

    def fail(self, e: BaseException) -> None:
        self.state.status = "failed"
        self.state.failed_agent = self.state.current_agent
        self.state.error = unwrap_error(e)
        self.state.summary = self.summary()


async def log_stage(
    ai: ActivityInput,
    stage: str,
    event: str,
    retry: RetryPolicy,
    reason: str | None = None,
) -> None:
    """Record a stage transition (stage-registry key) in the run's event log."""
    # Always send every parameter, ``reason`` included even when None: Temporal
    # drops ALL argument type hints when the payload count differs from the
    # activity's parameter count, and the activity then receives plain dicts.
    await workflow.execute_activity(
        "log_phase_transition",
        args=[ai, stage, event, reason],
        start_to_close_timeout=timedelta(minutes=2),
        retry_policy=retry,
    )


async def log_run_complete(ai: ActivityInput, st: EngineState, status: str, retry: RetryPolicy) -> None:
    await workflow.execute_activity(
        "log_workflow_complete",
        args=[ai, st.workflow_summary(status)],
        start_to_close_timeout=UTILITY_START_TO_CLOSE,
        retry_policy=retry,
    )


async def run_agent(
    ai: ActivityInput,
    actor: str,
    retry: RetryPolicy,
    *,
    timeout: timedelta = AGENT_START_TO_CLOSE,
) -> dict[str, Any]:
    return await workflow.execute_activity(
        "run_agent",
        args=[actor, ai],
        activity_id=f"run_agent:{actor}",
        start_to_close_timeout=timeout,
        heartbeat_timeout=AGENT_HEARTBEAT,
        retry_policy=retry,
    )


async def utility(name: str, ai: ActivityInput, retry: RetryPolicy, *,
                  timeout: timedelta = UTILITY_START_TO_CLOSE,
                  heartbeat: timedelta | None = None) -> Any:
    """Run a utility activity. Set ``heartbeat`` only for activities that
    heartbeat; it is how a retry learns the previous attempt is gone."""
    return await workflow.execute_activity(
        name, args=[ai], start_to_close_timeout=timeout,
        heartbeat_timeout=heartbeat, retry_policy=retry,
    )
