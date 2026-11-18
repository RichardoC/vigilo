"""Tests for the ledger-driven white-box engine.

Covers batching, numbered-actor resolution in run_agent, the ledger activities
(work reading, findings index, evidence rendering, report assembly), worker
registration, and — with Temporal's time-skipping test server — the
WhiteboxEngineWorkflow / PatchWorkflow orchestration with mocked activities.

Some grey-box test modules replace ``temporalio`` (and ``aiofiles``) in
``sys.modules`` with MagicMocks at import time. This module imports the real
packages once and swaps them in around each of its tests, restoring whatever
was there afterwards, so it neither depends on nor disturbs those mocks.
"""
from __future__ import annotations

import asyncio
import dataclasses
import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Real temporalio / src.temporal modules, isolated from other tests' mocks
# ---------------------------------------------------------------------------


def _swap_keys() -> list[str]:
    return [
        k for k in list(sys.modules)
        if k.split(".")[0] in ("temporalio", "aiofiles")
        or k == "src.temporal" or k.startswith("src.temporal.")
        or k == "src.services.findings_aggregator"
    ]


def _mocked() -> bool:
    return any(isinstance(sys.modules.get(k), MagicMock) for k in ("temporalio", "temporalio.activity", "aiofiles"))


_outside: dict[str, Any] = {}
if _mocked():
    _outside = {k: sys.modules.pop(k) for k in _swap_keys()}

importlib.import_module("aiofiles")  # real package, imported while unmocked
import temporalio.testing  # noqa: E402
from temporalio import activity  # noqa: E402
from temporalio.client import WorkflowFailureError  # noqa: E402
from temporalio.exceptions import ApplicationError  # noqa: E402
from temporalio.worker import Worker  # noqa: E402

from src.pipeline.ledger import Ledger  # noqa: E402
from src.services.report_ledger import GENERATED_MARKER, write_ledger_evidence  # noqa: E402
from src.session_manager import AGENTS  # noqa: E402
from src.temporal import activities as acts  # noqa: E402
from src.temporal import batching  # noqa: E402
from src.temporal import worker as worker_mod  # noqa: E402
from src.temporal.activities import ActivityInput  # noqa: E402
from src.temporal.patch_workflow import PatchWorkflow  # noqa: E402
from src.temporal.whitebox_workflow import WhiteboxEngineWorkflow  # noqa: E402

_REAL: dict[str, Any] = {k: sys.modules[k] for k in _swap_keys()}
if _outside:
    for _k in _swap_keys():
        del sys.modules[_k]
    sys.modules.update(_outside)


@pytest.fixture(autouse=True)
def _real_temporal_modules():
    before = {k: sys.modules.pop(k) for k in _swap_keys()}
    sys.modules.update(_REAL)
    try:
        yield
    finally:
        _REAL.update({k: sys.modules[k] for k in _swap_keys()})
        for k in _swap_keys():
            del sys.modules[k]
        sys.modules.update(before)


ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Batching
# ---------------------------------------------------------------------------


class TestBatching:
    def test_chunk_consecutive(self) -> None:
        assert batching.chunk(["a", "b", "c", "d", "e"], 2) == [["a", "b"], ["c", "d"], ["e"]]
        assert batching.chunk([], 3) == []
        assert batching.chunk(["a"], 0) == [["a"]]  # size floored at 1

    def test_make_batches_contract_format(self) -> None:
        batches = batching.make_batches("investigator", "LEADS", ["L-001", "L-004", "L-002"], 2)
        assert [b.actor for b in batches] == ["investigator-1", "investigator-2"]
        assert batches[0].extra_context == "LEADS: L-001,L-004"
        assert batches[1].extra_context == "LEADS: L-002"
        assert batches[0].ids == ("L-001", "L-004")

    def test_make_batches_numbering_continues(self) -> None:
        batches = batching.make_batches("investigator", "LEADS", ["L-9"], 3, first_instance=5)
        assert batches[0].actor == "investigator-5"

    def test_findings_line(self) -> None:
        (b,) = batching.make_batches("prover", "FINDINGS", ["VG-002", "VG-007"], 3)
        assert b.actor == "prover-1"
        assert b.extra_context == "FINDINGS: VG-002,VG-007"

    def test_parse_assignment_roundtrip(self) -> None:
        ctx = "something else\nLEADS: L-001,L-004\nFINDINGS: VG-1"
        assert batching.parse_assignment(ctx, "LEADS") == ["L-001", "L-004"]
        assert batching.parse_assignment(ctx, "FINDINGS") == ["VG-1"]
        assert batching.parse_assignment(None, "LEADS") == []
        assert batching.parse_assignment("no assignment", "LEADS") == []

    def test_order_leads_by_priority_then_id(self) -> None:
        leads = [
            {"id": "L-003", "priority": 2},
            {"id": "L-001", "priority": 3},
            {"id": "L-002", "priority": 1},
            {"id": "L-004"},  # default priority 3
        ]
        assert batching.order_leads(leads) == ["L-002", "L-003", "L-001", "L-004"]

    def test_order_findings_by_severity_then_id(self) -> None:
        findings = [
            {"id": "VG-001", "severity": "low"},
            {"id": "VG-003", "severity": "critical"},
            {"id": "VG-002", "severity": "high"},
            {"id": "VG-004", "severity": "weird"},
        ]
        assert batching.order_findings(findings) == ["VG-003", "VG-002", "VG-001", "VG-004"]


# ---------------------------------------------------------------------------
# Agent registry
# ---------------------------------------------------------------------------


class TestRegistry:
    ACTORS = ("surveyor", "supply-chain", "integrity", "planner", "investigator",
              "prover", "reviewer", "remediator", "reporter")

    def test_engine_actors_registered(self) -> None:
        from src.pipeline.stages import ACTOR_STAGES

        for actor in self.ACTORS:
            assert actor in AGENTS, actor
            assert AGENTS[actor].name == actor
            assert actor in ACTOR_STAGES

    def test_prompts_exist(self) -> None:
        for actor in self.ACTORS:
            prompt = ROOT / "prompts" / f"{AGENTS[actor].prompt_template}.txt"
            assert prompt.is_file(), prompt

    def test_reused_prompts(self) -> None:
        assert AGENTS["supply-chain"].prompt_template == "sca"
        assert AGENTS["reviewer"].prompt_template == "critic"
        assert AGENTS["remediator"].prompt_template == "remediation"
        assert AGENTS["reporter"].prompt_template == "report-executive"
        assert AGENTS["investigator"].prompt_template == "whitebox/investigator"
        assert AGENTS["prover"].prompt_template == "whitebox/prover"

    def test_resolve_agent(self) -> None:
        d, inst = acts._resolve_agent("investigator-3", AGENTS)
        assert (d.name, inst) == ("investigator", 3)
        d, inst = acts._resolve_agent("supply-chain", AGENTS)
        assert (d.name, inst) == ("supply-chain", None)
        d, inst = acts._resolve_agent("reporter", AGENTS)
        assert (d.name, inst) == ("reporter", None)
        with pytest.raises(ApplicationError):
            acts._resolve_agent("report", AGENTS)  # retired per-class name
        with pytest.raises(ApplicationError) as exc:
            acts._resolve_agent("nobody-2", AGENTS)
        assert exc.value.non_retryable


# ---------------------------------------------------------------------------
# Ledger fixtures
# ---------------------------------------------------------------------------


def _finding(title: str, severity: str, category: str, file: str = "app.py", line: int = 10) -> dict[str, Any]:
    return {
        "title": title, "description": f"{title} description", "severity": severity,
        # Callers give distinct lines; the sink is distinct per title, so the
        # ledger's duplicate guard treats each fixture finding as its own flaw.
        "category": category, "location": {"file": file, "line": line},
        "source": "request.args['q']", "sink": f"handler_for_{title.replace(' ', '_')}(request)",
    }


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "deliverables").mkdir()
    return tmp_path


@pytest.fixture
def ledger(repo: Path) -> Ledger:
    led = Ledger.for_repo(repo)
    for i, prio in enumerate((2, 1, 3), 1):
        led.record("lead", {"title": f"lead {i}", "hypothesis": "h", "priority": prio})
    led.record("finding", _finding("SQL injection", "high", "injection"))
    led.record("finding", _finding("IDOR", "critical", "authorization", line=200))
    led.record("finding", _finding("Info leak", "low", "information-disclosure", line=400))
    led.record("lead-done", {"lead_id": "L-002", "outcome": "finding", "finding_ids": ["VG-001"]})
    led.record("verdict", {"finding_id": "VG-001", "verdict": "exploited", "summary": "dumped users"})
    led.save_evidence("VG-001", "## Steps\n\ncurl 'http://t/?q=1%27--'\n")
    led.record("chain", {"title": "leak to takeover", "narrative": "n", "severity": "critical",
                         "finding_ids": ["VG-001", "VG-002"]})
    return led


def _input(repo: Path, extra: str | None = None) -> ActivityInput:
    return ActivityInput(repo_path=str(repo), workflow_id="wf", session_id="s", extra_context=extra)


# ---------------------------------------------------------------------------
# Ledger activities
# ---------------------------------------------------------------------------


class TestLedgerActivities:
    def test_read_ledger_work(self, repo: Path, ledger: Ledger) -> None:
        work = asyncio.run(acts.read_ledger_work(_input(repo)))
        assert [lead["id"] for lead in work["open_leads"]] == ["L-001", "L-003"]
        assert {f["id"] for f in work["unproven_findings"]} == {"VG-002", "VG-003"}
        assert work["coverage"]["leads_open"] == 2

    def test_read_ledger_work_empty(self, repo: Path) -> None:
        work = asyncio.run(acts.read_ledger_work(_input(repo)))
        assert work["open_leads"] == [] and work["unproven_findings"] == []

    def test_aggregate_builds_index_from_ledger(self, repo: Path, ledger: Ledger) -> None:
        asyncio.run(acts.aggregate_findings(_input(repo)))
        index = json.loads((repo / "deliverables" / "findings_index.json").read_text())
        ids = {e["ID"] for entries in index["by_type"].values() for e in entries}
        assert {"VG-001", "VG-002", "VG-003", "CH-01"} <= ids
        (inj,) = index["by_type"]["injection"]
        assert inj["status"] == "exploited"

    def test_assignment_check(self, repo: Path, ledger: Ledger) -> None:
        assert acts._ledger_assignment_done("investigator", _input(repo, "LEADS: L-002,L-001")) is True
        assert acts._ledger_assignment_done("investigator", _input(repo, "LEADS: L-001")) is False
        assert acts._ledger_assignment_done("prover", _input(repo, "FINDINGS: VG-001")) is True
        assert acts._ledger_assignment_done("prover", _input(repo, "FINDINGS: VG-002")) is False
        assert acts._ledger_assignment_done("prover", _input(repo)) is None
        assert acts._ledger_assignment_done("surveyor", _input(repo, "LEADS: L-001")) is None


# ---------------------------------------------------------------------------
# Evidence rendering / report assembly
# ---------------------------------------------------------------------------


class TestLedgerEvidence:
    def test_writes_category_and_chain_files(self, repo: Path, ledger: Ledger) -> None:
        result = write_ledger_evidence(repo / "deliverables")
        d = repo / "deliverables"
        assert set(result["written"]) == {
            "injection_exploitation_evidence.md",
            "authorization_exploitation_evidence.md",
            "information-disclosure_exploitation_evidence.md",
            "chain_exploitation_evidence.md",
        }
        inj = (d / "injection_exploitation_evidence.md").read_text()
        assert inj.startswith(GENERATED_MARKER)
        assert "VG-001: SQL injection" in inj
        assert "exploited" in inj and "dumped users" in inj
        assert "curl 'http://t/?q=1%27--'" in inj  # evidence write-up verbatim
        assert "app.py:10" in inj
        assert "Not yet tested" in (d / "authorization_exploitation_evidence.md").read_text()
        assert "CH-01" in (d / "chain_exploitation_evidence.md").read_text()

    def test_empty_ledger_writes_nothing(self, repo: Path) -> None:
        result = write_ledger_evidence(repo / "deliverables")
        assert result["written"] == []
        assert list((repo / "deliverables").glob("*_exploitation_evidence.md")) == []

    def test_never_overwrites_agent_written_file(self, repo: Path, ledger: Ledger) -> None:
        legacy = repo / "deliverables" / "injection_exploitation_evidence.md"
        legacy.write_text("# written by the legacy injection-exploit agent\n")
        result = write_ledger_evidence(repo / "deliverables")
        assert "injection_exploitation_evidence.md" in result["skipped"]
        assert legacy.read_text() == "# written by the legacy injection-exploit agent\n"

    def test_removes_stale_generated_files(self, repo: Path, ledger: Ledger) -> None:
        stale = repo / "deliverables" / "xss_exploitation_evidence.md"
        stale.write_text(GENERATED_MARKER + "\nold\n")
        result = write_ledger_evidence(repo / "deliverables")
        assert "xss_exploitation_evidence.md" in result["removed"]
        assert not stale.exists()

    def test_assemble_report_renders_ledger(self, repo: Path, ledger: Ledger) -> None:
        asyncio.run(acts.assemble_report(_input(repo)))
        assert (repo / "deliverables" / "authorization_exploitation_evidence.md").is_file()

    def test_assemble_report_legacy_run_untouched(self, repo: Path) -> None:
        legacy = repo / "deliverables" / "xss_exploitation_evidence.md"
        legacy.write_text("legacy evidence\n")
        asyncio.run(acts.assemble_report(_input(repo)))
        assert sorted(p.name for p in (repo / "deliverables").iterdir()) == ["xss_exploitation_evidence.md"]
        assert legacy.read_text() == "legacy evidence\n"


# ---------------------------------------------------------------------------
# run_agent with numbered actors
# ---------------------------------------------------------------------------


class _FakeAudit:
    started: list[str] = []
    failed: list[str] = []

    def __init__(self, metadata: Any) -> None:
        self._agent_logger = None
        self._initialized = True

    async def initialize(self, workflow_id: str = "") -> None:
        pass

    async def start_agent(self, name: str, attempt: int, stage: str | None = None) -> None:
        _FakeAudit.started.append(name)

    async def end_agent(self, name: str, metrics: Any, checkpoint: Any = None) -> None:
        pass

    async def fail_agent(self, name: str, error: str, stage: str | None = None) -> None:
        _FakeAudit.failed.append(name)

    async def log_agent_turn(self, *a: Any, **k: Any) -> None:
        pass


@pytest.fixture
def agent_env(monkeypatch: pytest.MonkeyPatch, repo: Path):
    calls: dict[str, Any] = {}
    _FakeAudit.started, _FakeAudit.failed = [], []

    async def fake_load_prompt(name, web_url, repo_path, config=None, extra_context="", instance=None):
        calls["prompt"] = {"name": name, "extra_context": extra_context, "instance": instance}
        return "PROMPT"

    async def fake_execute(prompt, agent_name, model_tier, cwd, on_stream=None, idle_timeout_s=None,
                           extra_env=None):
        calls["execute"] = {"agent_name": agent_name, "model_tier": model_tier}
        calls["extra_env"] = extra_env
        hook = calls.get("on_execute")
        if hook:
            hook()
        return SimpleNamespace(success=True, error=None, input_tokens=1, output_tokens=2,
                               cost_usd=0.5, num_turns=3, model="m")

    async def noop(*a: Any, **k: Any) -> Any:
        return "abc123"

    monkeypatch.setattr("src.services.prompt_manager.load_prompt", fake_load_prompt)
    monkeypatch.setattr("src.ai.executor.execute", fake_execute)
    monkeypatch.setattr("src.audit.session.AuditSession", _FakeAudit)
    # run_agent must never checkpoint/commit/reset the shared checkout; make any
    # such call fail the test.
    async def forbidden(*a: Any, **k: Any) -> Any:
        raise AssertionError("run_agent touched the shared checkout")

    for name in ("create_checkpoint", "commit_success", "rollback_workspace"):
        monkeypatch.setattr(f"src.services.git_manager.{name}", forbidden)
    monkeypatch.setattr("src.services.git_manager.get_commit_hash", noop)
    monkeypatch.setattr(acts, "_sync_deliverables", noop)
    return calls


class TestRunAgentNumbered:
    def _run(self, actor: str, inp: ActivityInput) -> Any:
        env = temporalio.testing.ActivityEnvironment()
        return asyncio.run(env.run(acts.run_agent, actor, inp))

    def test_investigator_instance(self, agent_env: dict, repo: Path) -> None:
        led = Ledger.for_repo(repo)
        led.record("lead", {"title": "t", "hypothesis": "h"})
        agent_env["on_execute"] = lambda: led.record("lead-done", {"lead_id": "L-001", "outcome": "clean"})

        metrics = self._run("investigator-3", _input(repo, "LEADS: L-001"))

        assert agent_env["prompt"] == {
            "name": "whitebox/investigator", "extra_context": "LEADS: L-001", "instance": 3,
        }
        assert agent_env["execute"] == {"agent_name": "investigator-3", "model_tier": "large"}
        assert _FakeAudit.started == ["investigator-3"]
        assert metrics["cost_usd"] == 0.5

    def test_prover_without_verdict_fails_validation(self, agent_env: dict, repo: Path) -> None:
        Ledger.for_repo(repo).record("finding", _finding("x", "high", "injection"))
        with pytest.raises(ApplicationError) as exc:
            self._run("prover-1", _input(repo, "FINDINGS: VG-001"))
        assert exc.value.type == "OutputValidationError"
        assert _FakeAudit.failed == ["prover-1"]

    def test_model_overrides_and_repo_path_reach_the_executor_env(self, agent_env: dict, repo: Path) -> None:
        (repo / "deliverables" / "code_analysis_deliverable.md").write_text("survey")
        inp = _input(repo)
        inp.model_overrides = {"executor": "opencode", "model_large": "big-1", "model_small": "s-1"}
        self._run("surveyor", inp)
        assert agent_env["extra_env"] == {
            "VIGILO_EXECUTOR": "opencode", "OPENCODE_LARGE_MODEL": "big-1",
            "OPENCODE_SMALL_MODEL": "s-1", "VIGILO_REPO_PATH": str(repo),
        }

    def test_no_overrides_only_sets_repo_path(self, agent_env: dict, repo: Path) -> None:
        (repo / "deliverables" / "code_analysis_deliverable.md").write_text("survey")
        self._run("surveyor", _input(repo))
        assert agent_env["extra_env"] == {"VIGILO_REPO_PATH": str(repo)}

    def test_planner_with_no_leads_is_valid(self, agent_env: dict, repo: Path) -> None:
        """A clean repository: the planner records nothing, which must not fail."""
        metrics = self._run("planner", _input(repo))
        assert metrics["cost_usd"] == 0.5
        assert (repo / "deliverables" / "ledger" / "leads.jsonl").is_file()
        work = asyncio.run(acts.read_ledger_work(_input(repo)))
        assert work["open_leads"] == [] and work["unproven_findings"] == []

    def test_single_actor_uses_deliverable_check(self, agent_env: dict, repo: Path) -> None:
        (repo / "deliverables" / "code_analysis_deliverable.md").write_text("survey")
        self._run("surveyor", _input(repo))
        assert agent_env["prompt"]["instance"] is None
        assert agent_env["prompt"]["name"] == "whitebox/surveyor"


class TestGitPolicy:
    """Read-only actors never touch git; the remediator is returned to its base ref."""

    @staticmethod
    def _git(repo: Path, *args: str) -> str:
        import subprocess
        return subprocess.run(
            ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
            cwd=repo, check=True, capture_output=True, text=True,
        ).stdout.strip()

    @pytest.fixture
    def gitrepo(self, repo: Path) -> Path:
        self._git(repo, "init", "-q", "-b", "main")
        (repo / "app.py").write_text("v1\n")
        (repo / ".gitignore").write_text("deliverables\n")
        self._git(repo, "add", "-A")
        self._git(repo, "commit", "-q", "-m", "base")
        return repo

    def _run(self, actor: str, inp: ActivityInput, attempt: int = 1) -> Any:
        env = temporalio.testing.ActivityEnvironment()
        env.info = dataclasses.replace(env.info, attempt=attempt)
        return asyncio.run(env.run(acts.run_agent, actor, inp))

    def test_parallel_agents_files_survive_a_failing_agent(self, agent_env: dict, gitrepo: Path) -> None:
        """Regression: a failing agent's cleanup used to `git reset --hard` +
        `git clean -fd`, wiping files other agents running at the same time wrote."""
        other = gitrepo / "poc_from_other_agent.py"
        other.write_text("print('wip')\n")
        (gitrepo / "app.py").write_text("v2 edited by another agent\n")

        def boom() -> None:
            raise RuntimeError("boom")

        agent_env["on_execute"] = boom
        Ledger.for_repo(gitrepo).record("finding", _finding("x", "high", "injection"))
        with pytest.raises(ApplicationError):
            self._run("prover-1", _input(gitrepo, "FINDINGS: VG-001"))
        assert other.read_text() == "print('wip')\n"
        assert (gitrepo / "app.py").read_text() == "v2 edited by another agent\n"
        assert self._git(gitrepo, "rev-list", "--count", "HEAD") == "1"  # no commits added

    def test_read_only_success_commits_nothing(self, agent_env: dict, gitrepo: Path) -> None:
        (gitrepo / ".vigilo-remote-url").write_text("https://example/x.git\n")
        (gitrepo / "deliverables" / "code_analysis_deliverable.md").write_text("survey")
        self._run("surveyor", _input(gitrepo))
        assert self._git(gitrepo, "rev-list", "--count", "HEAD") == "1"
        assert ".vigilo-remote-url" in self._git(gitrepo, "status", "--porcelain")  # still untracked

    def test_remediator_returns_to_base_branch_without_committing(self, agent_env: dict, gitrepo: Path) -> None:
        (gitrepo / ".vigilo-remote-url").write_text("u\n")
        (gitrepo / "deliverables" / "remediation_report.md").write_text("r")

        def leave_head_on_fix_branch() -> None:
            self._git(gitrepo, "checkout", "-q", "-b", "fix/VG-001")
            (gitrepo / "app.py").write_text("fixed\n")
            self._git(gitrepo, "commit", "-qam", "fix")

        agent_env["on_execute"] = leave_head_on_fix_branch
        self._run("remediator", _input(gitrepo))
        assert self._git(gitrepo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
        assert self._git(gitrepo, "rev-list", "--count", "main") == "1"  # nothing added to main
        assert ".vigilo-remote-url" not in self._git(gitrepo, "show", "--stat", "fix/VG-001")

    def test_remediator_failure_and_retry_return_to_base(self, agent_env: dict, gitrepo: Path) -> None:
        def fail_on_fix_branch() -> None:
            self._git(gitrepo, "checkout", "-q", "-b", "fix/VG-009")
            (gitrepo / "app.py").write_text("half done\n")
            raise RuntimeError("remediator crashed")

        agent_env["on_execute"] = fail_on_fix_branch
        with pytest.raises(ApplicationError):
            self._run("remediator", _input(gitrepo))
        assert self._git(gitrepo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
        assert (gitrepo / "app.py").read_text() == "v1\n"  # half-done edit discarded
        assert "fix/VG-009" in self._git(gitrepo, "branch", "--list", "fix/*")  # partial branch kept

        # a retry that finds HEAD left on a fix branch must treat main as the base
        self._git(gitrepo, "checkout", "-q", "fix/VG-009")
        (gitrepo / "deliverables" / "remediation_report.md").write_text("r")
        agent_env["on_execute"] = None
        self._run("remediator", _input(gitrepo), attempt=2)
        assert self._git(gitrepo, "rev-parse", "--abbrev-ref", "HEAD") == "main"


# ---------------------------------------------------------------------------
# Worker registration and CLI
# ---------------------------------------------------------------------------


_ACTIVITY_CALL = r'(?:execute_activity|ec\.utility)\(\s*"([a-z_]+)"'


class TestWorker:
    def test_workflows_registered(self) -> None:
        names = {w.__name__ for w in worker_mod.ALL_WORKFLOWS}
        assert names == {"WhiteboxEngineWorkflow", "PatchWorkflow"}

    def test_every_called_activity_registered(self) -> None:
        import re

        registered = {
            getattr(fn, "__temporal_activity_definition").name for fn in worker_mod.ALL_ACTIVITIES
        }
        called: set[str] = {"run_agent", "log_phase_transition", "log_workflow_complete"}
        for mod in ("whitebox_workflow", "patch_workflow", "engine_common"):
            src = (ROOT / "src" / "temporal" / f"{mod}.py").read_text()
            called |= set(re.findall(_ACTIVITY_CALL, src))
        assert {"read_ledger_work", "materialize_ledger_evidence", "attach_workspace"} <= called
        assert called - registered == set()

    def test_single_scan_runs_whitebox_engine(self) -> None:
        parser = worker_mod._build_parser()
        args = parser.parse_args(["/repo", "--task-queue", "q"])
        assert worker_mod._select_workflow(args, "run-1") == (WhiteboxEngineWorkflow, "run-1")
        with pytest.raises(SystemExit):
            parser.parse_args(["/repo", "--task-queue", "q", "--engine", "legacy"])

    def test_activities_have_no_optional_parameters_workflows_omit(self) -> None:
        """Temporal drops every argument type hint when the payload count differs
        from the parameter count, so a workflow must send all parameters."""
        import inspect

        for fn in worker_mod.ALL_ACTIVITIES:
            optional = [
                p.name for p in inspect.signature(fn).parameters.values()
                if p.default is not inspect.Parameter.empty
            ]
            assert optional in ([], ["reason"]), (fn.__name__, optional)  # log_stage sends reason

    def test_patch_only(self) -> None:
        args = worker_mod._build_parser().parse_args(
            ["/repo", "--task-queue", "q", "--patch-only", "--session-id", "run-1"])
        cls, wid = worker_mod._select_workflow(args, "run-1")
        assert cls is PatchWorkflow
        assert wid.startswith("run-1-patch-")


# ---------------------------------------------------------------------------
# Workflow orchestration (Temporal time-skipping test server, mocked activities)
# ---------------------------------------------------------------------------


class FakeRun:
    """Mocked activities recording what the workflow asked for."""

    def __init__(self, *, leads: list[dict], followup_leads: list[dict] | None = None,
                 findings: list[dict], fail: set[str] | None = None,
                 fail_activities: set[str] | None = None, remediable: int = 1,
                 leads_total: int | None = None) -> None:
        self.fail_activities = fail_activities or set()
        self.remediable = remediable
        self.leads_total = leads_total
        self.reasons: dict[tuple[str, str], str | None] = {}
        self.leads = leads
        self.followup_leads = followup_leads or []
        self.findings = findings
        self.fail = fail or set()
        self.agents: list[tuple[str, str | None]] = []
        self.stages: list[tuple[str, str]] = []
        self.calls: list[str] = []
        self.reads = 0
        self.in_flight = 0
        self.max_in_flight: dict[str, int] = {}
        self.summaries: list[dict] = []

    def activities(self) -> list[Any]:
        run = self

        @activity.defn(name="run_agent")
        async def run_agent(agent_name: str, input: ActivityInput) -> dict:
            from src.pipeline.stages import base_actor

            base = base_actor(agent_name)
            run.in_flight += 1
            run.max_in_flight[base] = max(run.max_in_flight.get(base, 0), run.in_flight)
            try:
                await asyncio.sleep(0.05)
                run.agents.append((agent_name, input.extra_context))
                if agent_name in run.fail:
                    raise ApplicationError(f"{agent_name} broke", type="ExecutionError", non_retryable=True)
                return {"duration_ms": 1, "cost_usd": 0.25, "num_turns": 1}
            finally:
                run.in_flight -= 1

        @activity.defn(name="log_phase_transition")
        async def log_phase_transition(input: ActivityInput, phase: str, event: str,
                                       reason: str | None = None) -> None:
            run.stages.append((phase, event))
            run.reasons[(phase, event)] = reason

        @activity.defn(name="read_ledger_work")
        async def read_ledger_work(input: ActivityInput) -> dict:
            run.reads += 1
            if run.reads == 1:
                leads = run.leads
            elif run.reads == 2:
                leads = run.followup_leads
            else:
                leads = []
            findings = run.findings if run.reads >= 2 else []
            coverage = {} if run.leads_total is None else {"leads_total": run.leads_total}
            return {"open_leads": leads, "unproven_findings": findings, "coverage": coverage}

        @activity.defn(name="log_workflow_complete")
        async def log_workflow_complete(input: ActivityInput, summary: dict) -> None:
            run.summaries.append(summary)

        @activity.defn(name="count_remediable_findings")
        async def count_remediable_findings(input: ActivityInput) -> dict:
            run.calls.append("count_remediable_findings")
            return {"total": run.remediable, "remediable": run.remediable}

        def simple(name: str, result: Any = None) -> Any:
            @activity.defn(name=name)
            async def _act(input: ActivityInput) -> Any:
                run.calls.append(name)
                if name in run.fail_activities:
                    raise ApplicationError(f"{name} broke", type="ExecutionError", non_retryable=True)
                return result
            return _act

        return [
            run_agent, log_phase_transition, read_ledger_work, log_workflow_complete,
            simple("preflight_validation"), simple("aggregate_findings"),
            simple("materialize_ledger_evidence", {}), simple("audit_critique", {}),
            simple("rebuild_git", True), simple("export_patches", {"exported": ["fix/VG-001"]}),
            simple("verify_patches", {}), simple("assemble_report"),
            simple("inject_report_metadata"), simple("redact_deliverables", {}),
            simple("attach_workspace", {}),
            count_remediable_findings,
        ]

    def agent_names(self) -> list[str]:
        return [a for a, _ in self.agents]

    def stage_events(self, *keys: str) -> list[tuple[str, str]]:
        return [s for s in self.stages if s[0] in keys]


_env_cache: dict[str, Any] = {}


async def _execute(workflow: Any, fake: FakeRun, input: dict) -> Any:
    try:
        env = await temporalio.testing.WorkflowEnvironment.start_time_skipping()
    except Exception as exc:  # pragma: no cover - offline without a cached test server
        pytest.skip(f"Temporal test server unavailable: {exc}")
    async with env:
        async with Worker(
            env.client,
            task_queue="wb-test",
            workflows=[WhiteboxEngineWorkflow, PatchWorkflow],
            activities=fake.activities(),
        ):
            handle = await env.client.start_workflow(
                workflow.run, input, id=f"wf-{workflow.__name__}", task_queue="wb-test",
            )
            try:
                return await handle.result(), None
            except WorkflowFailureError as err:
                return None, err


def _wf_input(stages: str = "full", **cfg: Any) -> dict:
    return {
        "web_url": "http://target", "repo_path": "/repo", "workflow_id": "run-1",
        "session_id": "run-1", "stages": stages, "pipeline_config": cfg,
    }


LEADS = [{"id": f"L-00{i}", "priority": p} for i, p in ((1, 3), (2, 1), (3, 2), (4, 3), (5, 1))]
FINDINGS = [{"id": "VG-001", "severity": "low"}, {"id": "VG-002", "severity": "critical"},
            {"id": "VG-003", "severity": "high"}]
MAIN_STAGES = ("preflight", "survey", "plan", "investigate", "prove", "review", "remediation", "report")


class TestWhiteboxEngineWorkflow:
    def test_full_run(self) -> None:
        fake = FakeRun(leads=LEADS, followup_leads=[{"id": "L-006", "priority": 1}], findings=FINDINGS)
        result, err = asyncio.run(_execute(
            WhiteboxEngineWorkflow, fake, _wf_input("full", leads_per_investigator=2, findings_per_prover=2),
        ))
        assert err is None, err

        # Stage order (supply-chain / integrity run in the background).
        assert fake.stage_events(*MAIN_STAGES) == [
            (s, e) for s in MAIN_STAGES for e in ("start", "complete")
        ]
        assert ("supply-chain", "complete") in fake.stages
        assert ("integrity", "complete") in fake.stages

        agents = fake.agent_names()
        # Leads in priority order, two per investigator; follow-up numbering continues.
        ctx = dict(fake.agents)
        assert ctx["investigator-1"] == "LEADS: L-002,L-005"
        assert ctx["investigator-2"] == "LEADS: L-003,L-001"
        assert ctx["investigator-3"] == "LEADS: L-004"
        assert ctx["investigator-4"] == "LEADS: L-006"
        assert ctx["prover-1"] == "FINDINGS: VG-002,VG-003"
        assert ctx["prover-2"] == "FINDINGS: VG-001"
        assert fake.max_in_flight["investigator"] > 1  # ran in parallel

        order = [a for a in agents if a not in ("supply-chain", "integrity")]
        assert order[:2] == ["surveyor", "planner"]
        assert order[-3:] == ["reviewer", "remediator", "reporter"]
        assert agents.index("supply-chain") < agents.index("reviewer")
        assert ctx["reporter"] and "_exploitation_evidence.md" in ctx["reporter"]

        assert fake.calls.index("aggregate_findings") < fake.calls.index("audit_critique")
        assert fake.calls.index("rebuild_git") < fake.calls.index("export_patches") < fake.calls.index("verify_patches")
        assert fake.calls.index("verify_patches") < fake.calls.index("assemble_report")
        assert "attach_workspace" not in fake.calls  # child mode

        assert result["status"] == "completed"
        assert "remediator" in result["completed_agents"]  # merged from the child
        assert result["summary"]["total_cost_usd"] == pytest.approx(0.25 * len(agents))
        assert [s["status"] for s in fake.summaries] == ["completed"]

    def test_remediation_disabled_and_concurrency_bound(self) -> None:
        fake = FakeRun(leads=LEADS, findings=FINDINGS)
        result, err = asyncio.run(_execute(
            WhiteboxEngineWorkflow, fake,
            _wf_input("vuln", leads_per_investigator=1, max_concurrent_pipelines=2),
        ))
        assert err is None, err
        agents = fake.agent_names()
        assert "remediator" not in agents
        assert "supply-chain" not in agents and "integrity" not in agents
        assert ("remediation", "skip") in fake.stages
        assert ("supply-chain", "skip") in fake.stages
        assert "rebuild_git" not in fake.calls
        assert sum(a.startswith("investigator-") for a in agents) == 5
        assert fake.max_in_flight["investigator"] <= 2
        assert result["status"] == "completed"

    def test_one_failing_investigator_does_not_stop_the_others(self) -> None:
        fake = FakeRun(leads=LEADS, findings=FINDINGS, fail={"investigator-2"})
        result, err = asyncio.run(_execute(
            WhiteboxEngineWorkflow, fake, _wf_input("vuln", leads_per_investigator=2),
        ))
        assert err is None, err
        agents = fake.agent_names()
        assert {"investigator-1", "investigator-2", "investigator-3", "reporter"} <= set(agents)
        assert "investigator-2" not in result["completed_agents"]
        assert "investigator-1" in result["completed_agents"]
        assert result["status"] == "completed"

    def test_all_investigators_failing_fails_the_run(self) -> None:
        fake = FakeRun(leads=LEADS[:2], findings=[], fail={"investigator-1"})
        result, err = asyncio.run(_execute(
            WhiteboxEngineWorkflow, fake, _wf_input("vuln", leads_per_investigator=2),
        ))
        assert result is None and err is not None
        assert "prover-1" not in fake.agent_names()
        assert [s["status"] for s in fake.summaries] == ["failed"]
        assert fake.summaries[0]["failed_agent"] == "investigator-1"
        assert "investigator-1 broke" in fake.summaries[0]["error"]

    def test_nothing_to_investigate_or_prove(self) -> None:
        fake = FakeRun(leads=[], findings=[])
        result, err = asyncio.run(_execute(WhiteboxEngineWorkflow, fake, _wf_input("vuln")))
        assert err is None, err
        assert ("investigate", "skip") in fake.stages
        assert ("prove", "skip") in fake.stages
        assert fake.agent_names() == ["surveyor", "planner", "reviewer", "reporter"]


class TestFailureSemantics:
    def test_zero_leads_skips_investigate_and_prove_with_reason(self) -> None:
        """4a: a clean repository (empty ledger) is a valid outcome."""
        fake = FakeRun(leads=[], findings=[], leads_total=0)
        result, err = asyncio.run(_execute(WhiteboxEngineWorkflow, fake, _wf_input("vuln")))
        assert err is None, err
        assert result["status"] == "completed"
        assert fake.reasons[("investigate", "skip")] == "planner recorded no leads"
        assert fake.reasons[("prove", "skip")] == "no findings recorded"
        assert ("investigate", "start") not in fake.stages
        assert fake.agent_names() == ["surveyor", "planner", "reviewer", "reporter"]

    def test_all_provers_failing_is_not_fatal(self) -> None:
        """4b: findings are recorded; verdicts are optional."""
        fake = FakeRun(leads=LEADS[:1], findings=FINDINGS,
                       fail={"prover-1", "prover-2"})
        result, err = asyncio.run(_execute(
            WhiteboxEngineWorkflow, fake, _wf_input("vuln", findings_per_prover=2),
        ))
        assert err is None, err
        assert result["status"] == "completed"
        assert ("prove", "warn") in fake.stages and ("prove", "complete") not in fake.stages
        assert "all 2 provers failed" in fake.reasons[("prove", "warn")]
        assert {"reviewer", "reporter"} <= set(fake.agent_names())

    def test_some_provers_failing_still_completes_the_stage(self) -> None:
        fake = FakeRun(leads=LEADS[:1], findings=FINDINGS, fail={"prover-2"})
        result, err = asyncio.run(_execute(
            WhiteboxEngineWorkflow, fake, _wf_input("vuln", findings_per_prover=2),
        ))
        assert err is None, err
        assert ("prove", "complete") in fake.stages

    def test_patch_workflow_failure_does_not_prevent_the_report(self) -> None:
        """4c"""
        fake = FakeRun(leads=LEADS[:1], findings=[], fail={"remediator"})
        result, err = asyncio.run(_execute(WhiteboxEngineWorkflow, fake, _wf_input("vuln_patch")))
        assert err is None, err
        assert result["status"] == "completed"
        assert ("remediation", "fail") in fake.stages
        assert "remediator broke" in fake.reasons[("remediation", "fail")]
        assert fake.agent_names()[-1] == "reporter"
        assert "assemble_report" in fake.calls
        assert "remediator" not in result["completed_agents"]
        assert [s["status"] for s in fake.summaries] == ["completed"]

    def test_no_fixable_findings_skips_remediation(self) -> None:
        """4d"""
        fake = FakeRun(leads=LEADS[:1], findings=[], remediable=0)
        result, err = asyncio.run(_execute(WhiteboxEngineWorkflow, fake, _wf_input("vuln_patch")))
        assert err is None, err
        assert fake.reasons[("remediation", "skip")] == "no fixable findings"
        assert "remediator" not in fake.agent_names() and "rebuild_git" not in fake.calls
        assert result["status"] == "completed"

    def test_optional_stage_start_events_precede_plan(self) -> None:
        """7: the stage rail must not jump back from plan to survey."""
        fake = FakeRun(leads=LEADS[:1], findings=[])
        _, err = asyncio.run(_execute(WhiteboxEngineWorkflow, fake, _wf_input("full")))
        assert err is None, err
        plan = fake.stages.index(("plan", "start"))
        assert fake.stages.index(("supply-chain", "start")) < plan
        assert fake.stages.index(("integrity", "start")) < plan

    def test_failing_optional_stage_is_recorded_and_capped(self) -> None:
        fake = FakeRun(leads=LEADS[:1], findings=[], fail={"supply-chain"})
        result, err = asyncio.run(_execute(WhiteboxEngineWorkflow, fake, _wf_input("full")))
        assert err is None, err
        assert result["status"] == "completed"
        assert ("supply-chain", "fail") in fake.stages
        assert ("integrity", "complete") in fake.stages

    def test_non_fatal_utilities_use_capped_retries(self) -> None:
        fake = FakeRun(leads=LEADS[:1], findings=[],
                       fail_activities={"materialize_ledger_evidence", "audit_critique"})
        result, err = asyncio.run(_execute(WhiteboxEngineWorkflow, fake, _wf_input("vuln")))
        assert err is None, err
        assert result["status"] == "completed"
        assert fake.calls.count("audit_critique") == 1  # non-retryable error: one attempt


class TestPatchWorkflow:
    def test_standalone(self) -> None:
        fake = FakeRun(leads=[], findings=[])
        result, err = asyncio.run(_execute(PatchWorkflow, fake, _wf_input("vuln")))
        assert err is None, err
        assert fake.calls == ["attach_workspace", "rebuild_git", "export_patches", "verify_patches",
                              "redact_deliverables"]
        assert fake.agent_names() == ["remediator"]
        assert fake.stages == [("remediation", "start"), ("remediation", "complete")]
        assert [s["status"] for s in fake.summaries] == ["completed"]
        assert result["status"] == "completed"
        assert result["completed_agents"] == ["remediator"]

    def test_remediator_failure_fails_workflow(self) -> None:
        fake = FakeRun(leads=[], findings=[], fail={"remediator"})
        result, err = asyncio.run(_execute(PatchWorkflow, fake, _wf_input()))
        assert err is not None
        assert [s["status"] for s in fake.summaries] == ["failed"]
        assert fake.summaries[0]["failed_agent"] == "remediator"


def test_log_stage_sends_every_activity_parameter(monkeypatch):
    """Regression: Temporal ignores argument type hints when the number of payloads
    differs from the activity's parameter count, so the activity got a dict instead
    of ActivityInput ('dict' object has no attribute 'session_id')."""
    import asyncio
    import inspect

    from temporalio.common import RetryPolicy

    from src.temporal import activities, engine_common

    sent: list[list] = []

    async def fake_execute_activity(name, args, **_kw):
        sent.append(list(args))

    monkeypatch.setattr(engine_common.workflow, "execute_activity", fake_execute_activity)
    ai = activities.ActivityInput(repo_path="/r", workflow_id="w", session_id="s")
    asyncio.run(engine_common.log_stage(ai, "survey", "start", RetryPolicy()))
    asyncio.run(engine_common.log_stage(ai, "integrity", "skip", RetryPolicy(), reason="off"))
    n_params = len(inspect.signature(activities.log_phase_transition).parameters)
    assert [len(a) for a in sent] == [n_params, n_params]


def test_activity_input_survives_temporal_decoding():
    """Decode an ActivityInput payload with the arg types Temporal derives for
    log_phase_transition: the activity must receive an ActivityInput, not a dict."""
    import asyncio

    import temporalio.converter
    from temporalio.common import _type_hints_from_func

    from src.temporal import activities

    ai = activities.ActivityInput(repo_path="/r", workflow_id="w", session_id="s",
                                  scan_config={"focus": "the API"})
    conv = temporalio.converter.DataConverter.default
    payloads = asyncio.run(conv.encode([ai, "survey", "start", None]))
    arg_types, _ = _type_hints_from_func(activities.log_phase_transition)
    assert len(arg_types) == len(payloads)
    decoded = asyncio.run(conv.decode(payloads, type_hints=arg_types))
    assert isinstance(decoded[0], activities.ActivityInput)
    assert decoded[0].scan_config == {"focus": "the API"}
