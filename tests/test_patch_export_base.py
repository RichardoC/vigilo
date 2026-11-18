"""export_patches diffs fix branches against the branch they were cut from,
which need not be main/master (e.g. an upstream whose default is ``develop``)."""
from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

from src.services.patch_export import _base_branch, export_patches


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def _repo_with_develop_default(tmp_path: Path) -> Path:
    seed = tmp_path / "seed"
    seed.mkdir()
    _git(seed, "init", "-q", "-b", "develop")
    _git(seed, "config", "user.email", "t@t")
    _git(seed, "config", "user.name", "t")
    (seed / "app.py").write_text("print('hi')\n")
    _git(seed, "add", "app.py")
    _git(seed, "commit", "-qm", "init")
    origin = tmp_path / "origin.git"
    _git(tmp_path, "clone", "-q", "--bare", str(seed), str(origin))
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(origin), str(work))
    _git(work, "config", "user.email", "t@t")
    _git(work, "config", "user.name", "t")
    return work


def _add_fix_branch(work: Path, base: str) -> None:
    _git(work, "checkout", "-q", "-b", "fix/VG-001", base)
    (work / "app.py").write_text("print('fixed')\n")
    _git(work, "commit", "-qam", "fix VG-001")


def test_uses_upstream_default_branch_not_main(tmp_path):
    work = _repo_with_develop_default(tmp_path)
    _add_fix_branch(work, "develop")
    _git(work, "checkout", "-q", "develop")
    assert asyncio.run(_base_branch(str(work))) == "develop"

    result = asyncio.run(export_patches(str(work)))
    assert result["exported"] == ["fix/VG-001"] and not result["failed"]
    patch = (work / "deliverables" / "patches" / "VG-001.patch").read_text()
    assert "+print('fixed')" in patch and "-print('hi')" in patch


def test_falls_back_to_current_branch_and_skips_fix_branches(tmp_path):
    work = _repo_with_develop_default(tmp_path)
    _git(work, "remote", "set-head", "origin", "-d")  # no origin/HEAD known
    assert asyncio.run(_base_branch(str(work))) == "develop"
    _add_fix_branch(work, "develop")  # HEAD is now on fix/VG-001
    assert asyncio.run(_base_branch(str(work))) != "fix/VG-001"
