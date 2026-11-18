"""Temporal worker for the Vigilo white-box pentest pipeline.

Two modes, both driven by the web platform:

* Single-scan (manual CLI use): starts a worker on a per-run task queue, submits
  the pipeline workflow, waits for the result, and exits::

      python -m src.temporal.worker /repos/target --task-queue <queue> \
          --url <target_url> --session-id <id> --stages <preset|json>

  Runs ``WhiteboxEngineWorkflow``. ``--patch-only`` instead runs
  ``PatchWorkflow`` against the existing run ``--session-id`` (re-generate
  patches without re-scanning).

* Persistent (``temporal`` engine, ``deploy/docker-compose.full.yml``): hosts
  the workflow + activities on a shared task queue; the API starts workflows::

      python -m src.temporal.worker --serve --task-queue vigilo-pipeline

  The ``docker`` engine runs the same ``--serve`` mode in one container per run on a
  per-run queue, plus ``--exit-with-workflow <id>`` so the container exits when the
  API-started workflow closes.

Environment:
    TEMPORAL_ADDRESS - Temporal server address (default: localhost:7233)
    VIGILO_INTERNAL_API_URL - internal API the worker redeems per-run secrets from
        (default: http://api:8081)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from typing import Any
from urllib.parse import urlparse

from temporalio.client import Client
from temporalio.worker import Worker

from src.temporal import activities
from src.temporal.patch_workflow import PatchWorkflow
from src.temporal.whitebox_workflow import WhiteboxEngineWorkflow

logger = logging.getLogger(__name__)

# Progress query interval in seconds
PROGRESS_POLL_INTERVAL_S = 30

# Every workflow type this worker hosts (both modes).
ALL_WORKFLOWS = [WhiteboxEngineWorkflow, PatchWorkflow]


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Vigilo Pipeline Worker — combined Temporal worker + client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m src.temporal.worker /repos/target --task-queue scan-001 "
            "--url http://target --session-id scan-001 --stages full\n"
            "  python -m src.temporal.worker --serve --task-queue vigilo-pipeline\n"
        ),
    )
    parser.add_argument(
        "repo_path", nargs="?", default=None,
        help="Path to the repository under test (omit in --serve mode)",
    )
    parser.add_argument(
        "--url",
        dest="web_url",
        default="",
        help="Target URL to test (optional; omit for a code-only scan)",
    )
    parser.add_argument(
        "--task-queue",
        required=True,
        help="Temporal task queue name (must be unique per scan)",
    )
    parser.add_argument(
        "--stages",
        dest="stages",
        default=None,
        help=(
            "Stage selection: a preset name (vuln|vuln_patch|full) or a JSON "
            "flag-dict. Omit for the full pipeline."
        ),
    )
    parser.add_argument(
        "--session-id",
        dest="session_id",
        default=None,
        help=(
            "Force the session/workflow id (platform use). When set, overrides the "
            "auto-generated hostname-timestamp id so outputs land at a known path."
        ),
    )
    parser.add_argument(
        "--patch-only",
        dest="patch_only",
        action="store_true",
        default=False,
        help=(
            "Single-scan mode: run only PatchWorkflow (rebuild git, remediation, "
            "export + verify patches) against the existing run given by --session-id."
        ),
    )
    parser.add_argument(
        "--serve",
        dest="serve",
        action="store_true",
        default=False,
        help=(
            "Persistent-worker mode (platform use): host the pipeline workflow + "
            "activities on --task-queue and run forever WITHOUT starting a workflow. "
            "The API starts workflows on this queue via the Temporal client."
        ),
    )
    parser.add_argument(
        "--exit-with-workflow",
        dest="exit_with_workflow",
        default=None,
        metavar="WORKFLOW_ID",
        help=(
            "With --serve (per-run container engine): exit once this workflow has "
            "closed. The platform starts the workflow itself, so no secret reference "
            "has to be placed in this container's environment."
        ),
    )
    return parser


# ---------------------------------------------------------------------------
# Hostname sanitization
# ---------------------------------------------------------------------------


def sanitize_hostname(url: str) -> str:
    """Extract and sanitize hostname from a URL for use in identifiers."""
    parsed = urlparse(url)
    hostname = parsed.hostname or "unknown"
    # Replace dots and colons with hyphens for Temporal workflow ID compatibility
    return hostname.replace(".", "-").replace(":", "-")


# ---------------------------------------------------------------------------
# Pipeline input construction
# ---------------------------------------------------------------------------


def _default_workflow_id(web_url: str) -> str:
    """Generate a workflow/session id from the target hostname + timestamp."""
    hostname = sanitize_hostname(web_url) if web_url else "code-only"
    return f"{hostname}_vigilo-{int(time.time() * 1000)}"


def _pipeline_config_from_env() -> dict[str, Any] | None:
    """``VIGILO_PIPELINE_CONFIG`` (a JSON object) or None; bad values are ignored."""
    raw = os.environ.get("VIGILO_PIPELINE_CONFIG", "").strip()
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        logger.warning("Ignoring VIGILO_PIPELINE_CONFIG: not valid JSON")
        return None
    if not isinstance(value, dict):
        logger.warning("Ignoring VIGILO_PIPELINE_CONFIG: not a JSON object")
        return None
    return value


def _build_pipeline_input(
    args: argparse.Namespace,
    workflow_id: str,
    session_id: str,
) -> dict[str, Any]:
    """Build the PipelineInput dict for the workflow."""
    input_data: dict[str, Any] = {
        "web_url": args.web_url,
        "repo_path": args.repo_path,
        "workflow_id": workflow_id,
        "session_id": session_id,
    }

    stages = getattr(args, "stages", None)
    if stages:
        # Accept a JSON flag-dict or a bare preset name; the workflow's
        # resolve_stages() handles both. Only attach when provided so the
        # default remains the full pipeline.
        try:
            input_data["stages"] = json.loads(stages)
        except (ValueError, TypeError):
            input_data["stages"] = stages

    # Per-repository scan settings: the platform's per-run container engine passes
    # them as VIGILO_SCAN_* environment variables.
    scan = {
        key: os.environ[env]
        for key, env in (
            ("description", "VIGILO_SCAN_DESCRIPTION"),
            ("focus", "VIGILO_SCAN_FOCUS"),
            ("avoid", "VIGILO_SCAN_AVOID"),
        )
        if os.environ.get(env)
    }
    if scan:
        input_data["scan"] = scan

    # Per-run tuning (per-run container engine): the platform's pipeline_config
    # as a JSON object (batch sizes, concurrency, retry preset). Validated by the
    # workflow; invalid JSON is ignored here. Executor / model overrides need no
    # input field: the container's own VIGILO_EXECUTOR / ANTHROPIC_*_MODEL
    # variables already apply to every agent it runs.
    pipeline_config = _pipeline_config_from_env()
    if pipeline_config:
        input_data["pipeline_config"] = pipeline_config

    # Patch push-back and authenticated testing need per-run secrets, which only
    # the platform issues (workflow input ``secrets`` reference); a hand-started
    # single scan has none, so patches stay local and testing is unauthenticated.

    return input_data


def _select_workflow(args: argparse.Namespace, workflow_id: str) -> tuple[Any, str]:
    """Return ``(workflow class, Temporal workflow id)`` for single-scan mode.

    ``--patch-only`` gets its own Temporal id (the run's id may already be
    taken by the scan that produced it); its input keeps the run's
    workflow/session id so it writes into that run's workspace and log.
    """
    if getattr(args, "patch_only", False):
        return PatchWorkflow, f"{workflow_id}-patch-{int(time.time() * 1000)}"
    return WhiteboxEngineWorkflow, workflow_id


# ---------------------------------------------------------------------------
# Progress polling
# ---------------------------------------------------------------------------


async def _poll_progress(handle: Any, interval: int = PROGRESS_POLL_INTERVAL_S) -> None:
    """Periodically query workflow progress and print status updates.

    Elapsed time is wall-clock (measured here), NOT the workflow's ``elapsed_ms``:
    that value is Temporal workflow-time, which freezes while the workflow is
    parked ``await``-ing long-running activities — so a perfectly healthy run
    would otherwise appear stuck at the same second. ``current_phase`` /
    ``current_agent`` still reflect the last state set before such an ``await``
    (e.g. one of several agents running concurrently), which is why they can lag.
    """
    start = time.monotonic()
    consecutive_errors = 0
    while True:
        await asyncio.sleep(interval)
        elapsed = int(time.monotonic() - start)
        try:
            # Every engine workflow exposes the same get_progress query.
            progress = await handle.query("get_progress")
            consecutive_errors = 0
            phase = progress.get("current_phase") or "unknown"
            agent = progress.get("current_agent") or "none"
            completed = len(progress.get("completed_agents", []) or [])
            failed = progress.get("failed_agent")
            suffix = f" | Failed: {failed}" if failed else ""
            print(
                f"[{elapsed}s] Phase: {phase} | Agent: {agent} | "
                f"Completed: {completed}{suffix}"
            )
        except Exception as e:
            # Workflow may have completed, or a query timed out mid-activity.
            # Don't swallow silently forever — surface it periodically.
            consecutive_errors += 1
            if consecutive_errors in (1, 10, 50):
                logger.debug(
                    "progress query failed (%dx): %s", consecutive_errors, e
                )


async def _run_until_workflow_closes(
    worker: Any, client: Any, workflow_id: str, *,
    poll_s: float = 10.0, start_grace_s: float = 900.0,
) -> None:
    """Run ``worker`` until the workflow ``workflow_id`` has closed (or never started
    within ``start_grace_s``), then shut it down gracefully."""
    task = asyncio.create_task(worker.run())
    started = time.monotonic()
    try:
        while not task.done():
            await asyncio.sleep(poll_s)
            try:
                desc = await client.get_workflow_handle(workflow_id).describe()
                # WorkflowExecutionStatus.RUNNING == 1; anything else is closed.
                if getattr(desc.status, "value", 1) != 1:
                    break
            except Exception:
                # Not started yet (the API starts it right after the container) or a
                # transient error; give up only if it never appears.
                if time.monotonic() - started > start_grace_s:
                    break
    finally:
        await worker.shutdown()
        try:
            await task
        except Exception:
            pass


# ---------------------------------------------------------------------------
# All activity functions (collected for worker registration)
# ---------------------------------------------------------------------------

ALL_ACTIVITIES = [
    activities.run_agent,
    activities.preflight_validation,
    activities.aggregate_findings,
    activities.read_ledger_work,
    activities.count_remediable_findings,
    activities.materialize_ledger_evidence,
    activities.attach_workspace,
    activities.audit_critique,
    activities.verify_patches,
    activities.assemble_report,
    activities.inject_report_metadata,
    activities.redact_deliverables,
    activities.log_phase_transition,
    activities.log_workflow_complete,
    activities.rebuild_git,
    activities.export_patches,
    activities.deliver_patches,
]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    """Parse CLI args, start Temporal worker, submit workflow, wait for result."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Parse CLI arguments
    parser = _build_parser()
    args = parser.parse_args()
    if not args.serve and not args.repo_path:
        parser.error("repo_path is required unless --serve is given")
    if args.patch_only and not args.session_id:
        parser.error("--patch-only needs --session-id of the run to patch")

    # Connect to Temporal server
    address = os.environ.get("TEMPORAL_ADDRESS", "localhost:7233")
    print(f"Connecting to Temporal at {address}...")

    client = await Client.connect(address)

    # Persistent-worker mode (platform): host the workflow + activities on the shared
    # task queue and run forever. The API starts workflows via the Temporal client.
    if getattr(args, "serve", False):
        print(f"Serving pipeline worker on task queue: {args.task_queue}")
        worker = Worker(
            client,
            task_queue=args.task_queue,
            workflows=ALL_WORKFLOWS,
            activities=ALL_ACTIVITIES,
        )
        if getattr(args, "exit_with_workflow", None):
            await _run_until_workflow_closes(worker, client, args.exit_with_workflow)
        else:
            await worker.run()
        return

    # The platform passes --session-id so outputs land at a predictable path
    # (.vigilo/<session_id>/) the API can tail for logs/report.
    workflow_id = args.session_id or _default_workflow_id(args.web_url)
    session_id = workflow_id

    input_data = _build_pipeline_input(args, workflow_id, session_id)
    workflow_cls, temporal_id = _select_workflow(args, workflow_id)

    # Create and start worker
    print(f"Starting worker on task queue: {args.task_queue}")

    worker = Worker(
        client,
        task_queue=args.task_queue,
        workflows=ALL_WORKFLOWS,
        activities=ALL_ACTIVITIES,
    )

    # Start worker in background
    worker_task = asyncio.create_task(worker.run())

    try:
        # Submit workflow
        handle = await client.start_workflow(
            workflow_cls.run,
            input_data,
            id=temporal_id,
            task_queue=args.task_queue,
        )

        print(f"Workflow started: {temporal_id} ({workflow_cls.__name__})")

        # Start progress polling in background
        progress_task = asyncio.create_task(_poll_progress(handle))

        try:
            # Wait for workflow result
            result = await handle.result()
            progress_task.cancel()

            print("\nPipeline completed successfully!")

            summary = result.get("summary") if isinstance(result, dict) else None
            if summary:
                duration_s = summary.get("total_duration_ms", 0) // 1000
                agent_count = summary.get("agent_count", 0)
                total_turns = summary.get("total_turns", 0)
                cost = summary.get("total_cost_usd", 0.0)

                print(f"Duration: {duration_s}s")
                print(f"Agents completed: {agent_count}")
                print(f"Total turns: {total_turns}")
                print(f"Run cost: ${cost:.4f}")

        except Exception as e:
            progress_task.cancel()
            print(f"\nPipeline failed: {e}", file=sys.stderr)
            sys.exit(1)

    finally:
        # Graceful shutdown
        await worker.shutdown()
        try:
            await worker_task
        except Exception:
            pass  # Worker may already have stopped


if __name__ == "__main__":
    asyncio.run(main())
