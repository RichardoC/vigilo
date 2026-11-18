"""PatchWorkflow — generate, export and verify fix branches for a run.

The remediation stage:

1. ``rebuild_git`` — re-clone upstream history so fix branches are pushable
   (non-fatal).
2. ``remediator`` agent (prompt ``remediation``, 4h budget) — writes the fix
   branches, ``remediation_report.md`` and ``remediation_manifest.json``.
3. ``export_patches`` — fix branches → ``deliverables/patches/*.patch``
   (non-fatal).
4. ``verify_patches`` — re-run each finding's confirmation harness against its
   fix branch (non-fatal).
5. ``deliver_patches`` — when the run has ``push.enabled`` and a secrets
   reference (the token is redeemed just in time), push each fix branch and open one GitLab MR per branch; the
   outcome per branch goes into the manifest. Otherwise a no-op: patches stay
   local (non-fatal).

Runs two ways, with the same input dict as the other pipeline workflows:

* as a child of ``WhiteboxEngineWorkflow`` (its remediation stage), sharing the
  parent's run log; the parent records run completion;
* standalone, against an existing run's workspace, to re-generate patches
  without re-scanning. It then first attaches ``<repo>/deliverables`` to the
  run workspace (``attach_workspace``; never clears it, unlike preflight) and
  records run completion itself. The stage selection is ignored: starting
  this workflow is the request to patch.
"""
from __future__ import annotations

from typing import Any

from temporalio import workflow

from src.temporal import engine_common as ec


@workflow.defn
class PatchWorkflow:
    def __init__(self) -> None:
        self._st = ec.EngineState()

    @workflow.query
    def get_progress(self) -> dict[str, Any]:
        return self._st.progress()

    @workflow.run
    async def run(self, input: dict[str, Any]) -> dict[str, Any]:
        self._st.state.start_time = workflow.now().timestamp()
        retry = ec.select_retry(ec.pipeline_config(input))
        ai = ec.build_activity_input(input)
        standalone = workflow.info().parent is None

        try:
            if standalone:
                self._st.at("remediation", None)
                await workflow.execute_activity(
                    "attach_workspace",
                    args=[ai],
                    start_to_close_timeout=ec.UTILITY_START_TO_CLOSE,
                    retry_policy=ec.PREFLIGHT_RETRY,
                )

            await run_patch_stage(self._st, ai, retry)
            if standalone:
                # A parent run redacts after its report stage; a standalone patch run
                # writes deliverables (remediation report, manifest) on its own.
                await ec.utility("redact_deliverables", ai, retry)

            result = self._st.complete()
            if standalone:
                await ec.log_run_complete(ai, self._st, "completed", retry)
            return result

        except Exception as e:
            self._st.fail(e)
            if standalone:
                try:
                    await ec.log_run_complete(ai, self._st, "failed", retry)
                except Exception:
                    workflow.logger.warning("Failed to log workflow completion on error")
            raise


async def run_patch_stage(st: ec.EngineState, ai: ec.ActivityInput, retry: Any) -> None:
    """The remediation stage body, logged as stage ``remediation``."""
    st.at("remediation", None)
    await ec.log_stage(ai, "remediation", "start", retry)

    # Rebuild git from upstream so fix branches have correct ancestry for
    # direct push. Non-fatal: remediation still runs if this fails.
    try:
        rebuilt = await ec.utility(
            "rebuild_git", ai, ec.OPTIONAL_RETRY,
            timeout=ec.REBUILD_GIT_START_TO_CLOSE, heartbeat=ec.REBUILD_GIT_HEARTBEAT,
        )
        rebuild_ok = bool(rebuilt.get("ok")) if isinstance(rebuilt, dict) else bool(rebuilt)
        workflow.logger.info(
            "Git rebuild %s — fix branches will %s be pushable upstream",
            "succeeded" if rebuild_ok else "did not establish an upstream",
            "" if rebuild_ok else "not",
        )
    except Exception as exc:
        workflow.logger.warning("Git rebuild failed (non-fatal): %s", exc)

    st.at("remediation", "remediator")
    metrics = await ec.run_agent(ai, "remediator", retry, timeout=ec.REMEDIATION_START_TO_CLOSE)
    st.record("remediator", metrics)

    try:
        patch_result = await ec.utility(
            "export_patches", ai, ec.OPTIONAL_RETRY,
            timeout=ec.EXPORT_START_TO_CLOSE, heartbeat=ec.EXPORT_HEARTBEAT,
        )
        if patch_result and patch_result.get("exported"):
            workflow.logger.info(
                "Exported %d patches to deliverables/patches/", len(patch_result["exported"]),
            )
    except Exception as exc:
        workflow.logger.warning("Patch export failed (non-fatal): %s", exc)

    try:
        verify_result = await ec.utility(
            "verify_patches", ai, ec.OPTIONAL_RETRY,
            timeout=ec.VERIFY_START_TO_CLOSE, heartbeat=ec.VERIFY_HEARTBEAT,
        )
        workflow.logger.info("Patch verification: %s", verify_result)
    except Exception as exc:
        workflow.logger.warning("Patch verification failed (non-fatal): %s", exc)

    # Deliver: push the fix branches and open one MR each. Deterministic (the
    # remediator never holds the credential) and a no-op unless the run was
    # started with push enabled + a per-run token; records the outcome per
    # branch in the manifest. Non-fatal.
    try:
        delivery = await ec.utility(
            "deliver_patches", ai, ec.OPTIONAL_RETRY,
            timeout=ec.DELIVER_START_TO_CLOSE, heartbeat=ec.DELIVER_HEARTBEAT,
        )
        workflow.logger.info("Patch delivery: %s", delivery)
    except Exception as exc:
        workflow.logger.warning("Patch delivery failed (non-fatal): %s", exc)

    st.at("remediation", None)
    await ec.log_stage(ai, "remediation", "complete", retry)
