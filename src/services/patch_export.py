"""Export fix/* branches as .patch files into deliverables.

After the remediator creates fix branches, this module generates a unified
diff for each branch (relative to the repository's base branch) and writes it to
deliverables/patches/<branch-name-without-"fix/">.patch (for ``fix/VG-001`` that is
``VG-001.patch``). These files persist to the host via the deliverables symlink
and can be shared or applied with `git apply`. Git runs through asyncio
subprocesses (execute_git_command), so the worker's event loop is never blocked.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from src.services.git_manager import execute_git_command

logger = logging.getLogger(__name__)


async def _get_fix_branches(repo_path: str) -> list[str]:
    """List all local fix/* branches."""
    stdout, _ = await execute_git_command(
        ["git", "branch", "--list", "fix/*"],
        cwd=repo_path,
        description="list fix branches",
    )
    branches = []
    for line in stdout.strip().splitlines():
        branch = line.strip().lstrip("* ")
        if branch:
            branches.append(branch)
    return sorted(branches)


async def _git_ok(args: list[str], repo_path: str) -> str | None:
    """Run a read-only git command; return stripped stdout, or None on failure."""
    try:
        out, _ = await execute_git_command(args, cwd=repo_path, description=" ".join(args[1:3]))
        return out.strip() or None
    except Exception:
        return None


async def _base_branch(repo_path: str) -> str:
    """The branch fix/* branches were cut from.

    The remediator branches from the checkout's current branch (after rebuild_git
    that is the upstream default, which need not be main/master). Prefer the
    upstream default (``origin/HEAD``), then the current branch unless it is a
    fix branch, then main/master — the same order as ``git_push._base_branch``
    and ``patch_verify._default_branch``.
    """
    ref = await _git_ok(["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"], repo_path)
    if ref:
        name = ref.removeprefix("origin/")
        if await _git_ok(["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{name}"], repo_path):
            return name
        return ref  # only the remote-tracking ref exists locally
    current = await _git_ok(["git", "rev-parse", "--abbrev-ref", "HEAD"], repo_path)
    if current and current != "HEAD" and not current.startswith("fix/"):
        return current
    for name in ("main", "master"):
        if await _git_ok(["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{name}"], repo_path):
            return name
    return "HEAD"


async def export_patches(repo_path: str) -> dict:
    """Generate .patch files for all fix/* branches.

    Each patch is the unified diff of the branch against the base branch the
    remediator branched from (``git diff <base>...<branch>``), applicable with
    `git apply`. See :func:`_base_branch` for how the base is chosen.

    Returns:
        {"exported": ["fix/VG-001", ...], "failed": [...]}
    """
    branches = await _get_fix_branches(repo_path)
    if not branches:
        logger.info("No fix/* branches found — nothing to export")
        return {"exported": [], "failed": []}

    patches_dir = Path(repo_path) / "deliverables" / "patches"
    await asyncio.to_thread(patches_dir.mkdir, parents=True, exist_ok=True)

    exported: list[str] = []
    failed: list[str] = []

    default_branch = await _base_branch(repo_path)

    for branch in branches:
        patch_name = branch.removeprefix("fix/") + ".patch"
        patch_path = patches_dir / patch_name

        try:
            # Show all changes on this branch vs default branch (supports multi-commit branches)
            stdout, _ = await execute_git_command(
                ["git", "diff", f"{default_branch}...{branch}"],
                cwd=repo_path,
                description=f"generate patch for {branch}",
            )
            if stdout.strip():
                await asyncio.to_thread(patch_path.write_text, stdout)
                exported.append(branch)
                logger.info("Exported %s → %s", branch, patch_path.name)
            else:
                # Diagnose: check if branch has commits ahead of default branch
                try:
                    log_out, _ = await execute_git_command(
                        ["git", "log", f"{default_branch}..{branch}", "--oneline"],
                        cwd=repo_path,
                        description=f"check commits on {branch}",
                    )
                    if log_out.strip():
                        logger.warning(
                            "Empty diff for %s but branch has commits: %s "
                            "— branch was likely merged into %s",
                            branch, log_out.strip(), default_branch,
                        )
                    else:
                        logger.warning(
                            "Empty diff for %s — branch has no commits ahead of %s "
                            "(sub-agent may have failed to commit on the branch)",
                            branch, default_branch,
                        )
                except Exception:
                    logger.warning("Empty diff for %s — skipping", branch)
                failed.append(branch)
        except Exception as exc:
            failed.append(branch)
            logger.warning("Failed to export %s: %s", branch, exc)

    logger.info(
        "Patch export complete: %d exported, %d failed",
        len(exported), len(failed),
    )
    return {"exported": exported, "failed": failed}
