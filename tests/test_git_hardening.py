"""The token-bearing git commands must not be steerable by the agent-writable checkout.

Reproduces the two reviewed attacks against local bare repositories: a repo-local
``url.<evil>.pushInsteadOf`` redirecting the explicit-URL push, and a planted
``.git/hooks/pre-push`` that prints ``VIGILO_GIT_TOKEN``."""
from __future__ import annotations

import os
import stat
import subprocess

import pytest

from src.services import git_push
from tests.test_patch_push import (  # noqa: F401 - fixtures
    REMOTE,
    TOKEN,
    deliver,
    git,
    gitlab,
    origin_branches,
    redeemed,
    world,
)


def _evil_bare(tmp_path):
    evil = tmp_path / "evil.git"
    subprocess.run(["git", "init", "--bare", "-q", str(evil)], check=True)
    return evil


class TestPushCannotBeHijackedByCheckout:
    async def test_repo_config_insteadof_redirect_is_ignored(self, world, gitlab, redeemed):
        evil = _evil_bare(world.tmp)
        with open(os.path.join(world.repo, ".git", "config"), "a") as fh:
            fh.write(f'[url "file://{evil}"]\n\tpushInsteadOf = {REMOTE}\n\tinsteadOf = {REMOTE}\n')
        res = await deliver(world)
        assert res["status"] == "delivered"
        assert "fix/VG-001" in origin_branches(world)                      # went where the record says
        refs = subprocess.run(["git", "-C", str(evil), "for-each-ref"], capture_output=True, text=True).stdout
        assert refs.strip() == ""                                           # nothing reached the attacker

    async def test_planted_pre_push_hook_never_sees_the_token(self, world, gitlab, redeemed):
        loot = world.tmp / "loot.txt"
        for name in ("pre-push", "pre-receive", "post-checkout", "reference-transaction"):
            hook = os.path.join(world.repo, ".git", "hooks", name)
            with open(hook, "w") as fh:
                fh.write(f'#!/bin/sh\nenv > "{loot}"\nprintf "%s" "$VIGILO_GIT_TOKEN" >> "{loot}"\n')
            os.chmod(hook, stat.S_IRWXU)
        # also configure the hooks path of the checkout to a directory of hostile hooks
        evil_hooks = world.tmp / "hooks"
        evil_hooks.mkdir()
        h = evil_hooks / "pre-push"
        h.write_text(f'#!/bin/sh\nenv > "{loot}"\n')
        h.chmod(stat.S_IRWXU)
        with open(os.path.join(world.repo, ".git", "config"), "a") as fh:
            fh.write(f"[core]\n\thooksPath = {evil_hooks}\n")
        res = await deliver(world)
        assert res["status"] == "delivered" and "fix/VG-001" in origin_branches(world)
        assert not loot.exists(), "a hook of the agent-writable checkout ran"

    async def test_token_only_reaches_the_clean_repo_push(self, world, gitlab, redeemed, monkeypatch):
        seen = []
        real = git_push._run_git

        async def spy(args, cwd, token=None, timeout=300, **kw):
            if token:
                seen.append((args, cwd, kw))
            return await real(args, cwd, token=token, timeout=timeout, **kw)

        monkeypatch.setattr(git_push, "_run_git", spy)
        await deliver(world)
        assert seen and all(a[1] == "push" and c != world.repo
                            and os.path.basename(c) == "push.git" for a, c, _k in seen)

    def test_environment_is_rebuilt_not_inherited(self, monkeypatch):
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/tmp/attacker")
        monkeypatch.setenv("GIT_SSH_COMMAND", "evil")
        monkeypatch.setenv("VIGILO_GIT_TOKEN", "leak")
        monkeypatch.setenv("VIGILO_FERNET_KEY", "leak")
        monkeypatch.setattr(git_push, "_TRUSTED_GIT_CONFIG", None)
        env = git_push._hardened_env(with_token=True)
        assert env["GIT_CONFIG_GLOBAL"] == "/dev/null" and env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert env["GIT_ALLOW_PROTOCOL"] == "https"   # token => https only (file only in tests)
        assert "GIT_SSH_COMMAND" not in env and "VIGILO_GIT_TOKEN" not in env
        assert "VIGILO_FERNET_KEY" not in env
        cmd = git_push._git_cmd(["git", "push", "x"])
        assert "core.hooksPath=/dev/null" in cmd and "credential.helper=" in cmd

    async def test_http_remote_never_gets_a_token(self, world, gitlab, redeemed):
        world.source = {**world.source, "remote_url": "http://gitlab.corp.example/team/app.git"}
        res = await deliver(world)
        assert res["status"] == "failed" and "https" in res["reason"]
        assert origin_branches(world) == ["main"]
        res = await git_push.rebuild_git_from_remote(
            world.repo, remote_url="http://gitlab.corp.example/team/app.git", token=TOKEN)
        assert not res["ok"] and "https" in res["reason"]
