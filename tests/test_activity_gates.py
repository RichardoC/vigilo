"""Remediation gate and base-ref fallback in src/temporal/activities.py."""
from __future__ import annotations

import subprocess

import pytest

from src.temporal.activities import _git_base_ref, _return_to_base_ref, count_remediable


def _index(*entries):
    return {"by_type": {"x": list(entries)}}


def test_repromoted_suppressed_finding_is_remediable():
    idx = _index({"ID": "VG-001", "status": "suppressed"}, {"ID": "VG-002", "status": "suppressed"})
    crit = {"annotations": {"VG-001": {"include_in_report": True, "confidence": "confirmed"},
                            "VG-002": {"include_in_report": False}}}
    assert count_remediable(idx, crit) == {"total": 2, "remediable": 1}
    # no critique: suppression stands
    assert count_remediable(idx, None)["remediable"] == 0


def test_sca_and_integrity_are_not_remediable():
    idx = _index({"ID": "SCA-VULN-001"}, {"ID": "INTEGRITY-001"}, {"ID": "VG-001"})
    assert count_remediable(idx, None) == {"total": 3, "remediable": 1}
    only = _index({"ID": "SCA-VULN-001"}, {"ID": "INTEGRITY-002"})
    assert count_remediable(only, None)["remediable"] == 0


def _run(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
                        "HOME": str(cwd)})


@pytest.mark.asyncio
async def test_base_ref_falls_back_to_origin_head_not_fix_branch(tmp_path):
    origin = tmp_path / "origin"
    origin.mkdir()
    _run(origin, "init", "-q", "-b", "develop")
    (origin / "a").write_text("1")
    _run(origin, "add", "a")
    _run(origin, "commit", "-qm", "init")
    work = tmp_path / "work"
    _run(tmp_path, "clone", "-q", str(origin), str(work))
    _run(work, "checkout", "-q", "-b", "fix/VG-001")

    ref = await _git_base_ref(str(work))
    assert ref == "develop"
    await _return_to_base_ref(str(work), ref, force=True)
    out = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=work,
                         capture_output=True, text=True).stdout.strip()
    assert out == "develop"


@pytest.mark.asyncio
async def test_base_ref_none_when_only_fix_branch(tmp_path):
    _run(tmp_path, "init", "-q", "-b", "fix/VG-001")
    (tmp_path / "a").write_text("1")
    _run(tmp_path, "add", "a")
    _run(tmp_path, "commit", "-qm", "init")
    assert await _git_base_ref(str(tmp_path)) is None
