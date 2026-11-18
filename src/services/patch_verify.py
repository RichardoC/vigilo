"""Patch verification — deterministic proof that a fix actually fixes the finding.

Instead of trusting the remediation agent's "tests pass" prose, this re-runs, on
each ``fix/*`` branch, the source-level harness the prover built to confirm the
finding (``deliverables/harnesses/``). The harness contract is strict:

    prints ``VIGILO_RESULT: VULNERABLE``      and exits 0 -> the flaw still reproduces
    prints ``VIGILO_RESULT: NOT_VULNERABLE``  and exits 1 -> the payload is blocked (VERIFIED)
    anything else (crash, timeout, missing marker, marker/exit mismatch,
    other exit code)                                      -> error: ``not_tested``

A crashing harness is therefore never a "verified fix". When a finding has no
harness, we fall back to a build check, which can only ever be ``not_tested``
(or ``fail`` when the build breaks). Results (``pass`` | ``fail`` | ``not_tested``
+ method + detail) are written back into ``remediation_manifest.json`` per
branch; the report badges a fix "verified" only on ``pass``. Never mutates
findings; non-fatal.

The checker never blocks the event loop (asyncio subprocesses), reports liveness
through an optional heartbeat callback, serialises overlapping attempts with a
file lock (a retried activity can overlap the first attempt) and always restores
the checkout it started from.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import inspect
import json
import logging
import os
import re
import signal
from pathlib import Path
from typing import Any, Awaitable, Callable

import aiofiles

logger = logging.getLogger(__name__)

# A branch checker takes (branch, finding_ids, harness_paths) and returns
# {"verified": "pass|fail|not_tested", "method": str, "detail": str} (directly or
# as an awaitable). Injected for testability; the default does the real git work.
BranchChecker = Callable[[str, list[str], list[str]], "dict[str, Any] | Awaitable[dict[str, Any]]"]
Heartbeat = Callable[[], None]

HARNESS_TIMEOUT_S = 180
BUILD_TIMEOUT_S = 180
GIT_TIMEOUT_S = 60
LOCK_WAIT_S = 600
_OUTPUT_LIMIT = 64 * 1024

_MARKER = re.compile(r"^\s*VIGILO_RESULT:\s*(VULNERABLE|NOT_VULNERABLE)\s*$", re.MULTILINE)

# Harness verdicts
VULNERABLE = "vulnerable"
NOT_VULNERABLE = "not_vulnerable"
ERROR = "error"


def interpret_harness_run(
    returncode: int | None, stdout: str, timed_out: bool = False,
) -> tuple[str, str]:
    """Map one harness execution to ``(verdict, reason)``.

    ``verdict`` is ``vulnerable``, ``not_vulnerable`` or ``error``; ``reason``
    says why (recorded in the manifest).
    """
    if timed_out:
        return ERROR, "timed out"
    if returncode is None or returncode < 0:
        return ERROR, f"did not run to completion (exit={returncode})"
    markers = _MARKER.findall(stdout or "")
    if not markers:
        return ERROR, f"no VIGILO_RESULT marker (exit={returncode})"
    marker = markers[-1]
    if marker == "VULNERABLE" and returncode == 0:
        return VULNERABLE, "VULNERABLE exit=0"
    if marker == "NOT_VULNERABLE" and returncode == 1:
        return NOT_VULNERABLE, "NOT_VULNERABLE exit=1"
    return ERROR, f"marker {marker} inconsistent with exit={returncode}"


def classify_patch(
    harness: str | None,
    build_ok: bool | None,
    tests_ok: bool | None,
) -> tuple[str, str]:
    """Pure decision: (verified, method) from the available signals, in priority order.

    ``harness`` is the harness verdict (``vulnerable`` / ``not_vulnerable`` /
    ``error``) or None when there was no harness. The harness is authoritative
    (it directly re-tests the vulnerability); build/tests are weaker fallbacks.
    """
    if harness is not None:
        if harness == NOT_VULNERABLE:
            return "pass", "harness"
        if harness == VULNERABLE:
            return "fail", "harness"
        return "not_tested", "harness_error"
    if tests_ok is not None:
        return ("pass" if tests_ok else "fail", "tests")
    if build_ok is not None:
        # A passing build does NOT prove the vulnerability is fixed — it only
        # shows the patch didn't break compilation. So build-ok is `not_tested`
        # (never `pass`/"verified"); a build *failure* is a real `fail`.
        return ("not_tested", "build") if build_ok else ("fail", "build")
    return ("not_tested", "none")


def combine_harness_verdicts(verdicts: list[str]) -> str:
    """One verdict for a branch that fixes several findings: any still-vulnerable
    finding fails the branch; verified only when every harness says not-vulnerable."""
    if VULNERABLE in verdicts:
        return VULNERABLE
    if ERROR in verdicts:
        return ERROR
    return NOT_VULNERABLE


def _harness_paths_for(finding_ids: list[str], harness_by_id: dict[str, str]) -> list[str]:
    return [harness_by_id[fid] for fid in finding_ids if fid in harness_by_id]


async def _write_manifest(manifest_path: Path, deliverables: Path, manifest: dict[str, Any]) -> None:
    tmp = deliverables / f"remediation_manifest.{os.getpid()}.tmp"
    async with aiofiles.open(tmp, mode="w", encoding="utf-8") as f:
        await f.write(json.dumps(manifest, indent=2, ensure_ascii=False))
    tmp.replace(manifest_path)


@contextlib.asynccontextmanager
async def _exclusive(lock_path: Path, wait_s: float = LOCK_WAIT_S):
    """Cross-attempt lock. Polled (non-blocking flock) so it never stalls the loop."""
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        waited = 0.0
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if waited >= wait_s:
                    raise TimeoutError(f"another patch verification holds {lock_path}")
                await asyncio.sleep(1.0)
                waited += 1.0
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


async def verify_patches(
    repo_path: str,
    checker: BranchChecker | None = None,
    heartbeat: Heartbeat | None = None,
) -> dict[str, Any]:
    """Verify every branch in remediation_manifest.json; write results back into it.

    Returns a summary dict. Non-fatal: missing manifest yields an empty summary.
    ``heartbeat`` is called between steps (the activity also heartbeats on a timer).
    """
    deliverables = Path(repo_path) / "deliverables"
    manifest_path = deliverables / "remediation_manifest.json"
    if not manifest_path.is_file():
        logger.info("verify_patches: no remediation_manifest.json — nothing to verify")
        return {"verified": 0, "failed": 0, "not_tested": 0, "branches": 0}

    try:
        async with aiofiles.open(manifest_path, mode="r", encoding="utf-8") as f:
            manifest = json.loads(await f.read())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("verify_patches: cannot read manifest: %s", exc)
        return {"verified": 0, "failed": 0, "not_tested": 0, "branches": 0}

    # Map finding ID -> harness path from the findings index (set by the provers).
    harness_by_id: dict[str, str] = {}
    index_path = deliverables / "findings_index.json"
    if index_path.is_file():
        try:
            async with aiofiles.open(index_path, mode="r", encoding="utf-8") as f:
                index = json.loads(await f.read())
            for vulns in (index.get("by_type") or {}).values():
                for v in (vulns if isinstance(vulns, list) else []):
                    hp = v.get("harness_path")
                    fid = str(v.get("ID") or v.get("id") or "")
                    if hp and fid:
                        harness_by_id[fid] = hp
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("verify_patches: cannot read findings_index: %s", exc)

    async with _exclusive(deliverables / ".verify_patches.lock"):
        if checker is None:
            checker = await _make_default_checker(repo_path, heartbeat)
        return await _verify_branches(manifest, manifest_path, deliverables, harness_by_id, checker)


async def _verify_branches(
    manifest: dict[str, Any],
    manifest_path: Path,
    deliverables: Path,
    harness_by_id: dict[str, str],
    checker: BranchChecker,
) -> dict[str, Any]:
    counts = {"pass": 0, "fail": 0, "not_tested": 0}
    for branch in manifest.get("branches", []):
        if not isinstance(branch, dict):
            continue
        name = str(branch.get("branch", ""))
        fids = [str(x) for x in branch.get("finding_ids", [])]
        hpaths = _harness_paths_for(fids, harness_by_id)
        try:
            result = checker(name, fids, hpaths)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:  # never let one branch abort the rest
            logger.warning("verify_patches: checker failed for %s: %s", name, exc)
            result = {"verified": "not_tested", "method": "error", "detail": str(exc)}
        branch["verified"] = result.get("verified", "not_tested")
        branch["verify_method"] = result.get("method", "none")
        if result.get("detail"):
            branch["verify_detail"] = result["detail"]
        counts[branch["verified"]] = counts.get(branch["verified"], 0) + 1
        logger.info("verify_patches: %s -> %s (%s)", name, branch["verified"], branch["verify_method"])
        # Persist after EACH branch so a mid-run timeout still keeps prior results.
        await _write_manifest(manifest_path, deliverables, manifest)

    summary = {
        "branches": len(manifest.get("branches", [])),
        "verified": counts.get("pass", 0),
        "failed": counts.get("fail", 0),
        "not_tested": counts.get("not_tested", 0),
    }
    logger.info("verify_patches summary: %s", summary)
    return summary


def _resolve_harness(repo_path: str, hp: str) -> str | None:
    """Resolve a recorded harness path relative to the repo root or ``deliverables/``.

    Harnesses live under ``deliverables/harnesses/`` (git-ignored, so they survive
    fix-branch checkouts) but agents may record the path with or without the
    ``deliverables/`` prefix; try both so a path-convention slip doesn't silently
    degrade verification to the weak build-only check.
    """
    for cand in (hp, os.path.join("deliverables", hp)):
        full = os.path.join(repo_path, cand)
        if os.path.isfile(full):
            return full
    return None


async def _run(
    cmd: list[str], cwd: str, timeout: float, *, env: dict[str, str] | None = None,
) -> tuple[int | None, str, bool]:
    """Run a command without blocking the loop: ``(returncode, stdout, timed_out)``.

    ``returncode`` is None when the command could not be launched. The command
    runs in its own process group so a timeout kills its children too.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd, env=env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError:
        return None, "", False
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, out[-_OUTPUT_LIMIT:].decode("utf-8", errors="replace"), False
    except asyncio.TimeoutError:
        _kill_group(proc)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=10)
        return None, "", True
    except asyncio.CancelledError:
        _kill_group(proc)
        raise


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(proc.pid, signal.SIGKILL)


async def _default_branch(repo_path: str) -> str:
    """Where to return when HEAD was left on a fix branch: the upstream default
    (``origin/HEAD``) first — it need not be main/master — then main/master.
    Same order as ``patch_export._base_branch`` / ``git_push._base_branch``."""
    rc, out, _ = await _run(["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
                            repo_path, GIT_TIMEOUT_S)
    if rc == 0 and out.strip():
        name = out.strip().removeprefix("origin/")
        rc2, _, _ = await _run(["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{name}"],
                               repo_path, GIT_TIMEOUT_S)
        if rc2 == 0 and not name.startswith("fix/"):
            return name
    for name in ("main", "master"):
        rc, _, _ = await _run(["git", "rev-parse", "--verify", "--quiet", name], repo_path, GIT_TIMEOUT_S)
        if rc == 0:
            return name
    return "main"


async def _starting_ref(repo_path: str) -> str:
    """The ref to restore afterwards. Never a ``fix/*`` branch (a previous,
    interrupted attempt may have left HEAD on one) and, for a detached HEAD,
    the commit rather than the useless name ``HEAD``."""
    rc, out, _ = await _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], repo_path, GIT_TIMEOUT_S)
    ref = out.strip() if rc == 0 else ""
    if ref == "HEAD":
        rc, out, _ = await _run(["git", "rev-parse", "HEAD"], repo_path, GIT_TIMEOUT_S)
        return out.strip() if rc == 0 and out.strip() else "HEAD"
    if not ref or ref.startswith("fix/"):
        return await _default_branch(repo_path)
    return ref


async def _make_default_checker(repo_path: str, heartbeat: Heartbeat | None = None) -> BranchChecker:
    """Real checker: checkout each fix branch, re-run its harnesses (or build), restore."""
    original_ref = await _starting_ref(repo_path)
    # The harness is agent-written code: never hand it the worker's secrets.
    from src.ai.envguard import strip_secret_env
    env = strip_secret_env({**os.environ, "VIGILO_REPO_PATH": repo_path})

    def beat() -> None:
        if heartbeat:
            heartbeat()

    async def checker(branch: str, finding_ids: list[str], harness_paths: list[str]) -> dict[str, Any]:
        beat()
        # The restore in `finally` also covers a cancellation that lands while
        # the checkout itself is running.
        try:
            rc, out, _ = await _run(["git", "checkout", "--quiet", branch], repo_path, GIT_TIMEOUT_S)
            if rc != 0:
                return {"verified": "not_tested", "method": "checkout_failed",
                        "detail": f"{branch}: {out.strip()[:200]}"}
            # Prefer the harnesses — they directly re-test the vuln on the patched code.
            verdicts: list[str] = []
            details: list[str] = []
            for hp in harness_paths:
                beat()
                full = _resolve_harness(repo_path, hp)
                if not full:
                    verdicts.append(ERROR)
                    details.append(f"{hp}: harness file not found")
                    continue
                cmd = ["python3", full] if full.endswith(".py") else ["bash", full]
                code, stdout, timed_out = await _run(cmd, repo_path, HARNESS_TIMEOUT_S, env=env)
                verdict, reason = interpret_harness_run(code, stdout, timed_out)
                verdicts.append(verdict)
                details.append(f"{hp}: {reason}")
            if verdicts:
                verified, method = classify_patch(combine_harness_verdicts(verdicts), None, None)
                return {"verified": verified, "method": method, "detail": "; ".join(details)}

            # Fallback: build-only. This does NOT prove the fix — classify_patch
            # deliberately maps build-ok to `not_tested`, not `pass`.
            beat()
            code, _, _ = await _run(
                ["python3", "-m", "compileall", "-q", "."], repo_path, BUILD_TIMEOUT_S)
            verified, method = classify_patch(None, code == 0, None)
            return {"verified": verified, "method": method,
                    "detail": "no recorded harness; build-only (not a fix proof)"}
        finally:
            # Shield: a cancelled attempt must still leave the checkout where it found it.
            await asyncio.shield(_restore(repo_path, original_ref))

    return checker


async def _restore(repo_path: str, ref: str) -> None:
    rc, out, _ = await _run(["git", "checkout", "--quiet", ref], repo_path, GIT_TIMEOUT_S)
    if rc != 0:
        logger.warning("verify_patches: could not restore %s: %s", ref, out.strip()[:200])
