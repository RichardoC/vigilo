"""Classification of permanent vs transient agent-executor failures."""
from __future__ import annotations

import json
import stat

import pytest
from temporalio.exceptions import ApplicationError

from src.ai.errors import classify_agent_error, flatten_error, format_agent_error
from src.temporal import engine_common as ec
from src.temporal.activities import NON_RETRYABLE_ERROR_TYPES, _failure_parts

FOUNDRY = (
    "Microsoft Foundry authentication failed · refresh your Foundry credential … · "
    "API Error: 403 team not allowed to access model. This team can only access "
    "models=['cloud', 'on-prem']. Tried to access claude-opus-4-6"
)
CYBER = (
    "API Error: Claude Code is unable to respond to this request, which appears to "
    "violate our Usage Policy; safeguards flagged this session [cyber]"
)


@pytest.mark.parametrize("text,status,etype", [
    (FOUNDRY, None, "AuthenticationError"),
    (FOUNDRY, 403, "AuthenticationError"),
    ("API Error: 401 invalid x-api-key", None, "AuthenticationError"),
    ("authentication_failed: Invalid API key", None, "AuthenticationError"),
    ("unexpected status 401 Unauthorized: missing bearer", None, "AuthenticationError"),
    ("opencode: HTTP 403 permission denied for this deployment", None, "AuthenticationError"),
    ("APIError: forbidden", 403, "AuthenticationError"),
    ("API Error: 404 {\"error\":{\"code\":\"model_not_found\"}}", None, "ConfigurationError"),
    ("The API deployment for this resource does not exist. DeploymentNotFound", None, "ConfigurationError"),
    ("The model `gpt-9` does not exist or you do not have access", None, "ConfigurationError"),
    ("unexpected status 404 Not Found: model foo", None, "ConfigurationError"),
    (CYBER, None, "ModelRefusalError"),
    ("Your request was blocked: content_filter", 400, "ModelRefusalError"),
    ("ResponsibleAIPolicyViolation: the prompt triggered the filter", 400, "ModelRefusalError"),
])
def test_permanent_errors(text, status, etype):
    found = classify_agent_error(text, status)
    assert found is not None and found.error_type == etype and found.non_retryable
    assert found.error_type in NON_RETRYABLE_ERROR_TYPES


@pytest.mark.parametrize("text,status", [
    ("claude exited with code 1", None),
    ("", None),
    ("API Error: 429 rate limit exceeded", None),
    ("rate limit reached for requests", 429),
    ("API Error: 529 overloaded_error", None),
    ("Internal server error", 500),
    ("503 Service Unavailable: permission denied upstream", 503),
    ("connection reset by peer", None),
    ("idle timeout: no stdout for 900s (tool call likely hung)", None),
    ("stream disconnected before completion", None),
    ("Spending cap likely reached (turns=1, cost=$0.0)", None),
])
def test_transient_or_unknown_stay_retryable(text, status):
    assert classify_agent_error(text, status) is None


def test_message_names_agent_executor_model_and_provider_text():
    msg, etype, non_retryable = _failure_parts("surveyor", "claude", "claude-opus-4-6", FOUNDRY, 403)
    assert etype == "AuthenticationError" and non_retryable
    assert msg.startswith("surveyor (claude, claude-opus-4-6): ")
    assert "team not allowed to access model" in msg
    assert "Models & executor" in msg


def test_refusal_message_suggests_another_model():
    msg, etype, non_retryable = _failure_parts("exploiter", "claude", "claude-opus-4-6", CYBER)
    assert etype == "ModelRefusalError" and non_retryable
    assert "another model" in msg


def test_unknown_failure_is_retryable_execution_error():
    msg, etype, non_retryable = _failure_parts("surveyor", "codex", "gpt-5", "codex exited with code 1")
    assert etype == "ExecutionError" and not non_retryable
    assert msg == "surveyor (codex, gpt-5): codex exited with code 1"


def test_message_redacts_registered_secrets():
    from src.audit import redact

    redact.register_secret("sessionid=SUPERSECRET123")
    try:
        msg, _, _ = _failure_parts("surveyor", "claude", "m", "API Error: 403 Cookie: sessionid=SUPERSECRET123")
        assert "SUPERSECRET123" not in msg
    finally:
        redact.clear()


def test_flatten_error_shapes():
    assert flatten_error("x") == ("x", None)
    text, status = flatten_error({"name": "APIError", "data": {"message": "nope", "statusCode": 403}})
    assert status == 403 and "nope" in text and "APIError" in text
    assert flatten_error({"message": "bad"}) == ("bad", None)
    assert format_agent_error("a", "claude", None, "r") == "a (claude): r"


def test_retry_policies_are_quick_and_bounded():
    p = ec.PRODUCTION_RETRY
    assert p.initial_interval.total_seconds() <= 30
    assert p.maximum_interval.total_seconds() <= 180
    assert 3 <= p.maximum_attempts <= 6
    assert "ModelRefusalError" in p.non_retryable_error_types
    # the subscription preset keeps its long backoff
    assert ec.SUBSCRIPTION_RETRY.maximum_interval.total_seconds() >= 3600
    assert ec.OPTIONAL_RETRY.maximum_attempts <= p.maximum_attempts
    assert ec.select_retry({"retry_preset": "subscription"}) is ec.SUBSCRIPTION_RETRY


# -- executors against fake CLIs ------------------------------------------------

def _fake_cli(tmp_path, name, stdout_lines, rc=1, stderr=""):
    script = tmp_path / name
    body = "\n".join(f"printf '%s\\n' {json.dumps(json.dumps(l))}" for l in stdout_lines)
    script.write_text(f"#!/bin/sh\n{body}\necho {json.dumps(stderr)} >&2\nexit {rc}\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)


@pytest.mark.asyncio
async def test_claude_is_error_result_is_classified(tmp_path, monkeypatch):
    from src.ai.claude_executor import execute

    _fake_cli(tmp_path, "claude", [
        {"type": "assistant", "message": {"content": [{"type": "text", "text": FOUNDRY}]},
         "error": "authentication_failed"},
        {"type": "result", "subtype": "success", "is_error": True,
         "api_error_status": 403, "result": FOUNDRY, "num_turns": 1},
    ])
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    result = await execute(prompt="x", agent_name="surveyor", model_tier="medium", cwd=str(tmp_path))
    assert not result.success and result.error_status == 403
    assert "team not allowed" in result.error
    found = classify_agent_error(result.error, result.error_status)
    assert found and found.error_type == "AuthenticationError"


@pytest.mark.asyncio
async def test_claude_assistant_api_error_without_result(tmp_path, monkeypatch):
    from src.ai.claude_executor import execute

    _fake_cli(tmp_path, "claude", [
        {"type": "assistant", "message": {"content": [{"type": "text", "text": CYBER}]},
         "error": "invalid_request"},
    ])
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    result = await execute(prompt="x", agent_name="a", model_tier="medium", cwd=str(tmp_path))
    assert not result.success
    found = classify_agent_error(result.error, result.error_status)
    assert found and found.error_type == "ModelRefusalError"


@pytest.mark.asyncio
async def test_claude_bare_exit_is_unclassified(tmp_path, monkeypatch):
    from src.ai.claude_executor import execute

    _fake_cli(tmp_path, "claude", [])
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    result = await execute(prompt="x", agent_name="a", model_tier="medium", cwd=str(tmp_path))
    assert not result.success
    assert classify_agent_error(result.error, result.error_status) is None


@pytest.mark.asyncio
async def test_codex_turn_failed_is_classified(tmp_path, monkeypatch):
    from src.ai.codex_executor import execute

    _fake_cli(tmp_path, "codex", [
        {"type": "turn.failed",
         "error": {"message": "unexpected status 401 Unauthorized: Incorrect API key provided"}},
    ])
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    monkeypatch.setenv("CODEX_API_KEY", "x")
    result = await execute(prompt="x", agent_name="a", model_tier="medium", cwd=str(tmp_path))
    assert not result.success
    found = classify_agent_error(result.error, result.error_status)
    assert found and found.error_type == "AuthenticationError"


@pytest.mark.asyncio
async def test_opencode_error_event_is_classified(tmp_path, monkeypatch):
    from src.ai.opencode_executor import execute

    _fake_cli(tmp_path, "opencode", [
        {"type": "error", "part": {"error": {
            "name": "APIError",
            "data": {"message": "team not allowed to access model", "statusCode": 403}}}},
    ])
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    monkeypatch.setenv("LITELLM_BASE_URL", "http://x")
    result = await execute(prompt="x", agent_name="a", model_tier="medium", cwd=str(tmp_path))
    assert not result.success and result.error_status == 403
    found = classify_agent_error(result.error, result.error_status)
    assert found and found.error_type == "AuthenticationError"


def test_entry_for_exposes_retry_data_only(tmp_path):
    from src.audit.events import EventLog
    from src.webapi.logs import entry_for

    log = EventLog(str(tmp_path), "r")
    retry = entry_for(log.agent_retrying("surveyor", "survey", attempt=1, error_type="ExecutionError",
                                         reason="boom", retry_in_s=20, max_attempts=6))
    assert retry["data"]["attempt"] == 1 and retry["data"]["max_attempts"] == 6
    assert "data" not in entry_for(log.agent_started("surveyor", 2, "survey"))


# Some greybox tests replace the temporalio modules with mocks at collection time.
@pytest.mark.skipif(not isinstance(ApplicationError, type), reason="temporalio is mocked by greybox tests")
@pytest.mark.asyncio
async def test_record_retry_uses_policy_and_skips_permanent(tmp_path, monkeypatch):
    from datetime import timedelta
    from types import SimpleNamespace

    from temporalio.common import RetryPolicy

    from src.temporal import activities

    calls = []

    class _Audit:
        async def retry_agent(self, name, **kw):
            calls.append((name, kw))

    def info(attempt):
        return SimpleNamespace(attempt=attempt, retry_policy=RetryPolicy(
            initial_interval=timedelta(seconds=20), maximum_interval=timedelta(minutes=2),
            backoff_coefficient=2.0, maximum_attempts=6))

    transient = ApplicationError("surveyor (claude, m): boom", type="ExecutionError")
    monkeypatch.setattr(activities.activity, "info", lambda: info(3))
    await activities._record_retry(_Audit(), "surveyor", transient)
    assert calls[-1][1]["retry_in_s"] == 80 and calls[-1][1]["max_attempts"] == 6

    n = len(calls)
    await activities._record_retry(_Audit(), "surveyor", ApplicationError("x", type="AuthenticationError", non_retryable=True))
    monkeypatch.setattr(activities.activity, "info", lambda: info(6))  # last attempt
    await activities._record_retry(_Audit(), "surveyor", transient)
    assert len(calls) == n


@pytest.mark.parametrize("text", [
    "exceeded retry limit, last status: 503 Service Unavailable, request id: x, body: Forbidden",
    "API Error: 503 upstream said forbidden",
    'API Error: 500 {"error":"model not found in cache, retry"}',
    "API Error: 429 rate limit: model is not available in this region quota",
    "EACCES: permission denied, open '/x'",
    "unauthorized",
    "HTTP 502 Bad Gateway: unauthorized upstream",
    "API Error: 529 forbidden usage policy",
    "stream failed status=504 forbidden",
])
def test_transient_text_without_status_stays_retryable(text):
    assert classify_agent_error(text, None) is None


def test_unmistakable_refusal_wins_over_5xx_but_policy_word_does_not():
    assert classify_agent_error("API Error: 500 safeguards flagged this session [cyber]").error_type == "ModelRefusalError"
    assert classify_agent_error("API Error: 429 too many requests per usage policy") is None


def test_opus_refusal_text():
    t = ("Opus 5.5's safeguards flagged this session (https://www.anthropic.com/legal/aup) "
         "Details: `[cyber]`")
    assert classify_agent_error(t).error_type == "ModelRefusalError"


@pytest.mark.asyncio
async def test_claude_fallback_ignores_agent_free_text(tmp_path, monkeypatch):
    """The agent's own turns ("permission denied" after a pentest step) must not
    become the error when the CLI dies without a result event."""
    from src.ai.claude_executor import execute

    _fake_cli(tmp_path, "claude", [
        {"type": "assistant", "message": {"content": [{"type": "text", "text": "target returned permission denied, unauthorized"}]}},
        {"type": "assistant", "message": {"content": [{"type": "text", "text": "x"}]}, "error": "unknown"},
    ])
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    result = await execute(prompt="x", agent_name="a", model_tier="medium", cwd=str(tmp_path))
    assert not result.success
    assert "permission denied" not in result.error
    assert classify_agent_error(result.error, result.error_status) is None


@pytest.mark.asyncio
async def test_claude_exit0_refusal_result_is_failure(tmp_path, monkeypatch):
    from src.ai.claude_executor import execute

    _fake_cli(tmp_path, "claude", [
        {"type": "result", "subtype": "success", "is_error": True, "result": CYBER, "num_turns": 1},
    ], rc=0)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    result = await execute(prompt="x", agent_name="a", model_tier="medium", cwd=str(tmp_path))
    assert not result.success
    assert classify_agent_error(result.error, result.error_status).error_type == "ModelRefusalError"


@pytest.mark.asyncio
async def test_codex_error_cleared_after_recovery(tmp_path, monkeypatch):
    from src.ai.codex_executor import execute

    _fake_cli(tmp_path, "codex", [
        {"type": "turn.failed", "error": {"message": "unexpected status 401 Unauthorized"}},
        {"type": "turn.started"},
        {"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 1}},
    ], rc=1, stderr="boom")
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    monkeypatch.setenv("CODEX_API_KEY", "x")
    result = await execute(prompt="x", agent_name="a", model_tier="medium", cwd=str(tmp_path))
    assert not result.success and result.error_status is None
    assert "401" not in result.error


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["claude", "codex", "opencode"])
async def test_cancellation_kills_cli_process_group(tmp_path, monkeypatch, name):
    import asyncio
    import importlib
    import os
    import time

    mod = importlib.import_module(f"src.ai.{name}_executor")
    pidfile = tmp_path / "pids"
    script = tmp_path / name
    # CLI plus a child it spawned (a "tool"), both recorded.
    script.write_text(f"#!/bin/sh\nsleep 300 &\necho $$ $! > {pidfile}\nsleep 300\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    monkeypatch.setenv("CODEX_API_KEY", "x")
    monkeypatch.setenv("LITELLM_BASE_URL", "http://x")

    task = asyncio.create_task(mod.execute(prompt="x", agent_name="a", model_tier="medium",
                                           cwd=str(tmp_path), idle_timeout_s=60))
    for _ in range(100):
        if pidfile.exists() and pidfile.read_text().strip().count(" ") == 1:
            break
        await asyncio.sleep(0.05)
    pids = [int(p) for p in pidfile.read_text().split()]
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    def alive(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    deadline = time.time() + 5
    while time.time() < deadline and any(alive(p) for p in pids):
        await asyncio.sleep(0.1)
    # zombies of already-reaped children are gone; nothing may still run
    assert not any(alive(p) for p in pids)
