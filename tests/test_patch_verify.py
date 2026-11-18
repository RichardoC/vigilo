"""Tests for patch verification (WS1/A1)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402

from src.services.patch_verify import (  # noqa: E402
    classify_patch,
    combine_harness_verdicts,
    interpret_harness_run,
    verify_patches,
)


def test_classify_harness_is_authoritative():
    # still reproduces = patch FAILED
    assert classify_patch("vulnerable", True, True) == ("fail", "harness")
    # blocked = VERIFIED
    assert classify_patch("not_vulnerable", False, False) == ("pass", "harness")
    # a harness that crashed/timed out is never a verified fix, whatever build/tests say
    assert classify_patch("error", True, True) == ("not_tested", "harness_error")


@pytest.mark.parametrize("rc,out,timed_out,expected", [
    (0, "VIGILO_RESULT: VULNERABLE\n", False, "vulnerable"),
    (1, "noise\nVIGILO_RESULT: NOT_VULNERABLE\n", False, "not_vulnerable"),
    (1, "Traceback ...\n", False, "error"),                      # crash: old contract said "fixed"
    (2, "VIGILO_RESULT: NOT_VULNERABLE\n", False, "error"),      # wrong exit code
    (0, "VIGILO_RESULT: NOT_VULNERABLE\n", False, "error"),      # marker/exit mismatch
    (1, "VIGILO_RESULT: VULNERABLE\n", False, "error"),
    (0, "", False, "error"),                                      # missing marker
    (None, "", True, "error"),                                    # timeout
    (-9, "VIGILO_RESULT: NOT_VULNERABLE\n", False, "error"),     # killed by a signal
])
def test_interpret_harness_run(rc, out, timed_out, expected):
    verdict, reason = interpret_harness_run(rc, out, timed_out)
    assert verdict == expected and reason


def test_combine_harness_verdicts():
    assert combine_harness_verdicts(["not_vulnerable", "not_vulnerable"]) == "not_vulnerable"
    assert combine_harness_verdicts(["not_vulnerable", "error"]) == "error"
    assert combine_harness_verdicts(["error", "vulnerable"]) == "vulnerable"


def test_classify_fallbacks():
    # build-ok does NOT prove the fix -> not_tested (never "pass"/verified)
    assert classify_patch(None, True, None) == ("not_tested", "build")
    # a build failure IS a real signal the patch is broken
    assert classify_patch(None, False, None) == ("fail", "build")
    assert classify_patch(None, None, True) == ("pass", "tests")
    assert classify_patch(None, None, None) == ("not_tested", "none")
    # tests take priority over build when both present
    assert classify_patch(None, True, False) == ("fail", "tests")


def test_build_ok_is_never_verified():
    """Regression: 'code compiles' must never be badged as a verified fix."""
    verified, method = classify_patch(None, True, None)
    assert verified != "pass"


def _seed(tmp_path: Path):
    d = tmp_path / "deliverables"
    d.mkdir(parents=True)
    (d / "remediation_manifest.json").write_text(json.dumps({"branches": [
        {"branch": "fix/INJ-VULN-01", "finding_ids": ["INJ-VULN-01"], "pushed": False, "diff_nonempty": True},
        {"branch": "fix/AUTH-VULN-01", "finding_ids": ["AUTH-VULN-01"], "pushed": False, "diff_nonempty": True},
    ]}))
    (d / "findings_index.json").write_text(json.dumps({"by_type": {"injection": [
        {"ID": "INJ-VULN-01", "harness_path": "harnesses/INJ-VULN-01.py"},
    ]}}))
    return d


def test_verify_patches_writes_results_and_summary(tmp_path: Path):
    d = _seed(tmp_path)

    def stub_checker(branch, finding_ids, harness_paths):
        # INJ branch has a harness and is fixed; AUTH has none -> not_tested
        if harness_paths:
            return {"verified": "pass", "method": "harness", "detail": f"{harness_paths[0]} exit=1"}
        return {"verified": "not_tested", "method": "none", "detail": "no harness"}

    summary = asyncio.run(verify_patches(str(tmp_path), checker=stub_checker))
    assert summary == {"branches": 2, "verified": 1, "failed": 0, "not_tested": 1}

    manifest = json.loads((d / "remediation_manifest.json").read_text())
    by = {b["branch"]: b for b in manifest["branches"]}
    assert by["fix/INJ-VULN-01"]["verified"] == "pass"
    assert by["fix/INJ-VULN-01"]["verify_method"] == "harness"
    assert by["fix/AUTH-VULN-01"]["verified"] == "not_tested"


def test_verify_patches_no_manifest_is_safe(tmp_path: Path):
    (tmp_path / "deliverables").mkdir(parents=True)
    summary = asyncio.run(verify_patches(str(tmp_path)))
    assert summary["branches"] == 0


def test_verify_patches_checker_exception_is_contained(tmp_path: Path):
    _seed(tmp_path)

    def boom(branch, finding_ids, harness_paths):
        raise RuntimeError("kaboom")

    summary = asyncio.run(verify_patches(str(tmp_path), checker=boom))
    assert summary["branches"] == 2 and summary["not_tested"] == 2


# ---------------------------------------------------------------------------
# Real git checkouts + real harness processes (scratch repo)
# ---------------------------------------------------------------------------

def _git(repo: Path, *args: str) -> str:
    import subprocess
    return subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    ).stdout.strip()


def _scratch_repo(tmp_path: Path, harness_body: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / ".gitignore").write_text("deliverables\n")
    (repo / "app.txt").write_text("vulnerable\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "checkout", "-q", "-b", "fix/VG-001")
    (repo / "app.txt").write_text("fixed\n")
    _git(repo, "commit", "-qam", "fix")
    _git(repo, "checkout", "-q", "main")
    d = repo / "deliverables"
    (d / "harnesses").mkdir(parents=True)
    (d / "harnesses" / "VG-001.sh").write_text(harness_body)
    (d / "remediation_manifest.json").write_text(json.dumps({"branches": [
        {"branch": "fix/VG-001", "finding_ids": ["VG-001"]},
    ]}))
    (d / "findings_index.json").write_text(json.dumps({"by_type": {"auth": [
        {"ID": "VG-001", "harness_path": "harnesses/VG-001.sh"},
    ]}}))
    return repo


HARNESS = """#!/bin/bash
if grep -q fixed app.txt; then
  echo "VIGILO_RESULT: NOT_VULNERABLE"; exit 1
fi
echo "VIGILO_RESULT: VULNERABLE"; exit 0
"""


def _result(repo: Path) -> dict:
    return json.loads((repo / "deliverables" / "remediation_manifest.json").read_text())["branches"][0]


def test_real_harness_verified_and_checkout_restored(tmp_path: Path):
    repo = _scratch_repo(tmp_path, HARNESS)
    beats = []
    summary = asyncio.run(verify_patches(str(repo), heartbeat=lambda: beats.append(1)))
    assert summary["verified"] == 1
    assert _result(repo)["verified"] == "pass" and _result(repo)["verify_method"] == "harness"
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert beats


def test_crashing_harness_is_not_a_verified_fix(tmp_path: Path):
    repo = _scratch_repo(tmp_path, "#!/bin/bash\nexit 3\n")
    summary = asyncio.run(verify_patches(str(repo)))
    assert summary == {"branches": 1, "verified": 0, "failed": 0, "not_tested": 1}
    b = _result(repo)
    assert b["verified"] == "not_tested" and b["verify_method"] == "harness_error"
    assert "no VIGILO_RESULT marker" in b["verify_detail"]


def test_still_vulnerable_harness_fails_the_branch(tmp_path: Path):
    repo = _scratch_repo(tmp_path, "#!/bin/bash\necho VIGILO_RESULT: VULNERABLE\nexit 0\n")
    assert asyncio.run(verify_patches(str(repo)))["failed"] == 1


def test_harness_path_with_deliverables_prefix_resolves(tmp_path: Path):
    repo = _scratch_repo(tmp_path, HARNESS)
    idx = repo / "deliverables" / "findings_index.json"
    idx.write_text(json.dumps({"by_type": {"auth": [
        {"ID": "VG-001", "harness_path": "deliverables/harnesses/VG-001.sh"}]}}))
    assert asyncio.run(verify_patches(str(repo)))["verified"] == 1


def test_missing_harness_file_is_not_tested(tmp_path: Path):
    repo = _scratch_repo(tmp_path, HARNESS)
    (repo / "deliverables" / "harnesses" / "VG-001.sh").unlink()
    assert asyncio.run(verify_patches(str(repo)))["not_tested"] == 1
    assert "not found" in _result(repo)["verify_detail"]


def test_does_not_record_fix_branch_as_original_ref(tmp_path: Path):
    """A previous, interrupted attempt left HEAD on a fix branch: restore to main."""
    repo = _scratch_repo(tmp_path, HARNESS)
    _git(repo, "checkout", "-q", "fix/VG-001")
    asyncio.run(verify_patches(str(repo)))
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"


def test_harness_timeout_restores_checkout_and_does_not_block_loop(tmp_path: Path, monkeypatch):
    import src.services.patch_verify as pv

    repo = _scratch_repo(tmp_path, "#!/bin/bash\nsleep 30\n")
    monkeypatch.setattr(pv, "HARNESS_TIMEOUT_S", 0.5)

    async def scenario():
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.05)
                ticks += 1

        t = asyncio.create_task(ticker())
        summary = await verify_patches(str(repo))
        t.cancel()
        return summary, ticks

    summary, ticks = asyncio.run(scenario())
    assert summary["not_tested"] == 1 and "timed out" in _result(repo)["verify_detail"]
    assert ticks >= 5  # the event loop kept running while the harness ran
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"


def test_cancellation_restores_checkout(tmp_path: Path):
    repo = _scratch_repo(tmp_path, "#!/bin/bash\nsleep 30\n")

    async def scenario():
        task = asyncio.create_task(verify_patches(str(repo)))
        for _ in range(100):  # wait until the branch is checked out
            await asyncio.sleep(0.05)
            if _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "fix/VG-001":
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
