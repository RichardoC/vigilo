"""WhiteboxEngineWorkflow — the ledger-driven white-box engine.

Generic actors instead of one hard-coded agent pair per vulnerability class.
Agents record their work in the findings ledger (``vigilo-record``,
``deliverables/ledger/``); the workflow reads the ledger to split work between
parallel agents. Stage and actor names come from src/pipeline/stages.py.

Stages
------
preflight     ``preflight_validation``
survey        ``surveyor`` → code_analysis_deliverable.md + shared_context.json.
              Then, when enabled, ``supply-chain`` and ``integrity`` start in the
              background (they read the survey) and are collected before review.
              Both are non-fatal.
plan          ``planner`` records leads.
investigate   open leads (priority order) split into batches of
              ``leads_per_investigator``; ``investigator-1..N`` run in parallel
              (at most ``max_concurrent_pipelines`` at once), each told its batch
              as ``LEADS: L-001,L-004``. One failing investigator does not stop
              the others; the run fails only when every investigator fails. A
              planner that records no leads (clean repository) is a valid
              outcome: investigate and prove are skipped with a reason. Up to ``investigation_followup_rounds`` (default 1)
              follow-up rounds run while open leads remain (new leads recorded
              by investigators, or leads left open).
prove         unproven findings (severity order) split into batches of
              ``findings_per_prover``; ``prover-1..M`` in parallel with
              ``FINDINGS: VG-002,VG-007``. Provers also record chains. Verdicts
              are optional (the findings are already recorded): when every
              prover fails the stage ends with a warning and the run goes on.
review        ``aggregate_findings`` (ledger + SCA + integrity →
              findings_index.json), ledger evidence files, ``reviewer`` (critic
              prompt), ``audit_critique`` (non-fatal).
remediation   when enabled and the findings index has findings remediation would
              act on: ``PatchWorkflow`` as a child workflow (otherwise a ``skip``
              event, "no fixable findings"). A failing PatchWorkflow is recorded
              as a failed stage and the run goes on to the report.
report        ``assemble_report`` → ``reporter`` → ``inject_report_metadata``.

Optional stages and non-fatal utilities use ``ec.OPTIONAL_RETRY`` (3 quick
attempts); agents on the critical path keep the production/subscription policy.

The ``get_progress`` query returns the PipelineState the web API polls.
"""
from __future__ import annotations

import asyncio
from typing import Any

from temporalio import workflow
from temporalio.exceptions import ApplicationError

from src.temporal import engine_common as ec
from src.temporal.batching import (
    FINDINGS_PREFIX,
    LEADS_PREFIX,
    Batch,
    make_batches,
    order_findings,
    order_leads,
)

with workflow.unsafe.imports_passed_through():
    import dataclasses

    from src.types.stages import resolve_stages

# Told to the reporter: evidence files are named after the ledger's finding
# categories (e.g. authorization_exploitation_evidence.md), not a fixed list.
REPORTER_CONTEXT = (
    "Evidence for this engagement is in one deliverables/<category>_exploitation_evidence.md "
    "file per finding category (for example authorization_exploitation_evidence.md or "
    "business-logic_exploitation_evidence.md), plus chain_exploitation_evidence.md when "
    "attack chains were found. Read every deliverables/*_exploitation_evidence.md file. "
    "Finding IDs look like VG-001 and chain IDs like CH-01; the per-finding write-ups are "
    "also under deliverables/evidence/."
)


@workflow.defn
class WhiteboxEngineWorkflow:
    def __init__(self) -> None:
        self._st = ec.EngineState()

    @workflow.query
    def get_progress(self) -> dict[str, Any]:
        return self._st.progress()

    # -------------------------------------------------------------------

    @workflow.run
    async def run(self, input: dict[str, Any]) -> dict[str, Any]:
        self._st.state.start_time = workflow.now().timestamp()
        cfg = ec.pipeline_config(input)  # validated and clamped; unknown keys ignored
        retry = ec.select_retry(cfg)
        self._max_concurrent = cfg.max_concurrent_pipelines
        self._leads_per = cfg.leads_per_investigator
        self._findings_per = cfg.findings_per_prover
        self._followups = cfg.investigation_followup_rounds

        stages = resolve_stages(input.get("stages"))
        workflow.logger.info(
            "Stage selection: sca=%s integrity=%s remediation=%s",
            stages.run_sca, stages.run_integrity, stages.run_remediation,
        )
        ai = ec.build_activity_input(input)
        side_tasks: list[asyncio.Task[None]] = []

        try:
            # ---- preflight --------------------------------------------------
            self._st.at("preflight", None)
            await ec.log_stage(ai, "preflight", "start", retry)
            await workflow.execute_activity(
                "preflight_validation",
                args=[ai],
                start_to_close_timeout=ec.PREFLIGHT_START_TO_CLOSE,
                retry_policy=ec.PREFLIGHT_RETRY,
            )
            await ec.log_stage(ai, "preflight", "complete", retry)

            # ---- survey (+ supply-chain / integrity in the background) -----
            await self._agent_stage("survey", "surveyor", ai, retry)

            # Their start events are written here, before plan starts, so the
            # UI's current stage never jumps back from "plan" to "survey".
            for stage, actor, enabled in (
                ("supply-chain", "supply-chain", stages.run_sca),
                ("integrity", "integrity", stages.run_integrity),
            ):
                if enabled:
                    await ec.log_stage(ai, stage, "start", ec.OPTIONAL_RETRY)
                    side_tasks.append(asyncio.create_task(
                        self._optional_stage(stage, actor, ai)
                    ))
                else:
                    await ec.log_stage(ai, stage, "skip", retry, reason="disabled")

            # ---- plan / investigate / prove ---------------------------------
            await self._agent_stage("plan", "planner", ai, retry)
            await self._investigate(ai, retry)
            await self._prove(ai, retry)

            # supply-chain / integrity feed the findings index built in review.
            for task in side_tasks:
                await task

            # ---- review ------------------------------------------------------
            await self._review(ai, retry)

            # ---- remediation -------------------------------------------------
            if stages.run_remediation:
                await self._remediate(input, ai, retry)
            else:
                await ec.log_stage(ai, "remediation", "skip", retry, reason="disabled")

            # ---- report ------------------------------------------------------
            await self._report(ai, retry)

            result = self._st.complete()
            await ec.log_run_complete(ai, self._st, "completed", retry)
            return result

        except Exception as e:
            await self._stop_side_tasks(side_tasks)
            self._st.fail(e)
            try:
                await ec.log_run_complete(ai, self._st, "failed", retry)
            except Exception:
                workflow.logger.warning("Failed to log workflow completion on error")
            raise

    # -------------------------------------------------------------------
    # Stage helpers
    # -------------------------------------------------------------------

    async def _agent_stage(
        self, stage: str, actor: str, ai: ec.ActivityInput, retry: Any,
    ) -> None:
        """A stage that is one agent run, bracketed by stage events."""
        self._st.at(stage, actor)
        await ec.log_stage(ai, stage, "start", retry)
        metrics = await ec.run_agent(ai, actor, retry)
        self._st.record(actor, metrics)
        await ec.log_stage(ai, stage, "complete", retry)

    async def _optional_stage(self, stage: str, actor: str, ai: ec.ActivityInput) -> None:
        """A non-fatal background stage (supply-chain, integrity). Its start event
        was logged by the caller. Capped retries; a failure is recorded, not raised."""
        try:
            metrics = await ec.run_agent(ai, actor, ec.OPTIONAL_RETRY)
            self._st.record(actor, metrics)
            await ec.log_stage(ai, stage, "complete", ec.OPTIONAL_RETRY)
        except Exception as exc:
            reason = ec.unwrap_error(exc)
            workflow.logger.warning("%s failed (non-fatal): %s", actor, reason)
            try:
                await ec.log_stage(ai, stage, "fail", ec.OPTIONAL_RETRY, reason=reason[:300])
            except Exception:
                pass

    @staticmethod
    async def _stop_side_tasks(tasks: list[asyncio.Task[None]]) -> None:
        """The run is failing: do not leave background agents running."""
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _remediate(self, input: dict[str, Any], ai: ec.ActivityInput, retry: Any) -> None:
        """Remediation as a child workflow, skipped when there is nothing to fix and
        non-fatal: the report is still produced when patch generation fails."""
        remediable = 1  # fail open: if the gate itself fails, remediate
        try:
            gate = await ec.utility("count_remediable_findings", ai, ec.OPTIONAL_RETRY)
            remediable = int((gate or {}).get("remediable", 1))
        except Exception as exc:
            workflow.logger.warning("Remediation gate failed, remediating anyway: %s", exc)
        if remediable == 0:
            await ec.log_stage(ai, "remediation", "skip", retry, reason="no fixable findings")
            return

        self._st.at("remediation", "remediator")
        try:
            child = await workflow.execute_child_workflow(
                "PatchWorkflow",
                input,
                id=f"{workflow.info().workflow_id}-patch",
            )
            self._st.merge(child)
        except Exception as exc:
            reason = ec.unwrap_error(exc)
            workflow.logger.warning("PatchWorkflow failed (non-fatal): %s", reason)
            await ec.log_stage(ai, "remediation", "fail", retry, reason=reason[:300])
        self._st.at("remediation", None)

    async def _read_work(self, ai: ec.ActivityInput, retry: Any) -> dict[str, Any]:
        return await ec.utility("read_ledger_work", ai, retry)

    async def _run_batches(
        self, stage: str, batches: list[Batch], ai: ec.ActivityInput, retry: Any,
        *, fatal: bool = True,
    ) -> list[str]:
        """Run numbered agents in parallel under the concurrency limit.

        Failures are isolated (``return_exceptions=True``): the stage goes on
        with whatever the others recorded. When every agent of the stage fails
        and ``fatal`` is set, the stage fails the run; otherwise the caller
        decides (compare the returned list with ``batches``). Returns the failed
        actors.
        """
        sem = asyncio.Semaphore(self._max_concurrent)

        async def _one(batch: Batch) -> dict[str, Any]:
            async with sem:
                self._st.at(stage, batch.actor)
                metrics = await ec.run_agent(
                    dataclasses.replace(ai, extra_context=batch.extra_context),
                    batch.actor,
                    retry,
                )
                self._st.record(batch.actor, metrics)
                return metrics

        results = await asyncio.gather(*(_one(b) for b in batches), return_exceptions=True)
        failed: list[tuple[str, BaseException]] = [
            (b.actor, r) for b, r in zip(batches, results) if isinstance(r, BaseException)
        ]
        for actor, err in failed:
            workflow.logger.warning("%s failed: %s", actor, ec.unwrap_error(err))
        self._st.at(stage, None)
        if fatal and batches and len(failed) == len(batches):
            actor, err = failed[0]
            self._st.state.current_agent = actor
            raise ApplicationError(
                f"All {len(batches)} agents of stage {stage} failed; first ({actor}): "
                f"{ec.unwrap_error(err)}",
                type="StageFailedError",
                non_retryable=True,
            )
        return [actor for actor, _ in failed]

    async def _investigate(self, ai: ec.ActivityInput, retry: Any) -> None:
        self._st.at("investigate", None)
        work = await self._read_work(ai, retry)
        leads = order_leads(work["open_leads"])
        if not leads:
            # An empty ledger is a valid outcome: the planner found nothing to chase.
            reason = (
                "planner recorded no leads"
                if not (work.get("coverage") or {}).get("leads_total") else "no open leads"
            )
            await ec.log_stage(ai, "investigate", "skip", retry, reason=reason)
            return

        await ec.log_stage(ai, "investigate", "start", retry)
        next_instance = 1
        rounds = 0
        while True:
            batches = make_batches(
                "investigator", LEADS_PREFIX, leads, self._leads_per, first_instance=next_instance,
            )
            next_instance += len(batches)
            workflow.logger.info(
                "Investigation round %d: %d leads across %d investigators",
                rounds + 1, len(leads), len(batches),
            )
            await self._run_batches("investigate", batches, ai, retry)

            if rounds >= self._followups:
                break
            leads = order_leads((await self._read_work(ai, retry))["open_leads"])
            if not leads:
                break
            rounds += 1

        await ec.log_stage(ai, "investigate", "complete", retry)

    async def _prove(self, ai: ec.ActivityInput, retry: Any) -> None:
        self._st.at("prove", None)
        work = await self._read_work(ai, retry)
        findings = order_findings(work["unproven_findings"])
        if not findings:
            reason = (
                "no findings recorded"
                if not (work.get("coverage") or {}).get("findings_total") else "no findings to prove"
            )
            await ec.log_stage(ai, "prove", "skip", retry, reason=reason)
            return

        await ec.log_stage(ai, "prove", "start", retry)
        batches = make_batches("prover", FINDINGS_PREFIX, findings, self._findings_per)
        workflow.logger.info(
            "Proving %d findings across %d provers", len(findings), len(batches),
        )
        # Verdicts are optional (the findings are already in the ledger and the
        # reviewer judges unproven ones too), so failing provers never fail the run.
        failed = await self._run_batches("prove", batches, ai, retry, fatal=False)
        if len(failed) == len(batches):
            await ec.log_stage(
                ai, "prove", "warn", retry,
                reason=f"all {len(batches)} provers failed; {len(findings)} findings left unproven",
            )
            return
        await ec.log_stage(ai, "prove", "complete", retry)

    async def _review(self, ai: ec.ActivityInput, retry: Any) -> None:
        self._st.at("review", None)
        await ec.log_stage(ai, "review", "start", retry)

        # findings_index.json: the aggregator folds in the ledger
        # (build_findings_index) next to SCA and integrity findings.
        await ec.utility("aggregate_findings", ai, retry)
        try:
            await ec.utility("materialize_ledger_evidence", ai, ec.OPTIONAL_RETRY)
        except Exception as exc:
            workflow.logger.warning("Ledger evidence rendering failed (non-fatal): %s", exc)

        self._st.at("review", "reviewer")
        metrics = await ec.run_agent(ai, "reviewer", retry)
        self._st.record("reviewer", metrics)

        try:
            await ec.utility("audit_critique", ai, ec.OPTIONAL_RETRY)
        except Exception as exc:
            workflow.logger.warning("Critique audit failed (non-fatal): %s", exc)

        self._st.at("review", None)
        await ec.log_stage(ai, "review", "complete", retry)

    async def _report(self, ai: ec.ActivityInput, retry: Any) -> None:
        self._st.at("report", None)
        await ec.log_stage(ai, "report", "start", retry)

        # Restores deliverables displaced by remediation's branch checkouts and
        # re-renders the ledger evidence files the reporter reads.
        await ec.utility("assemble_report", ai, retry, timeout=ec.REPORT_START_TO_CLOSE)

        self._st.at("report", "reporter")
        metrics = await ec.run_agent(
            dataclasses.replace(ai, extra_context=REPORTER_CONTEXT), "reporter", retry,
        )
        self._st.record("reporter", metrics)

        await ec.utility("inject_report_metadata", ai, retry)
        # Evidence and report may quote the run's cookie: mask it before the run ends.
        await ec.utility("redact_deliverables", ai, retry)
        self._st.at("report", None)
        await ec.log_stage(ai, "report", "complete", retry)
