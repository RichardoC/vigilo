"""Classification of agent-executor failures.

A CLI executor (claude / codex / opencode) that exits non-zero reports why in a
stream ``result`` / ``error`` event or on stderr. Most causes are transient (rate
limit, overload, dropped connection) and worth a retry; a few are permanent and
retrying only keeps the run "running" for hours: bad or unauthorised credentials,
a model the gateway does not serve, a safety refusal. :func:`classify_agent_error`
tells them apart. It is deliberately conservative: unrecognised text (a bare
"exited with code 1") returns ``None`` and stays retryable.

Matching uses the HTTP status the executor extracted from structured output when
there is one, plus specific phrases. Provider text is redacted (registered
secrets) and trimmed before it goes into a message.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from src.audit.redact import redact

# Temporal ApplicationError types (all but ModelRefusalError are in the shared
# non-retryable lists of engine_common / activities).
AUTH_ERROR = "AuthenticationError"
CONFIG_ERROR = "ConfigurationError"
REFUSAL_ERROR = "ModelRefusalError"

_WHERE = "check the executor/model in Admin → Models & executor or the repository override"

_REFUSAL = (
    "safeguards flagged", "usage policy", "content_filter",
    "responsibleaipolicyviolation", "[cyber]",
)
# A refusal that is not a throttling/overload message in disguise.
_REFUSAL_UNMISTAKABLE = ("safeguards flagged", "[cyber]", "responsibleaipolicyviolation")
# Provider-specific phrases only: bare "permission denied" / "forbidden" /
# "unauthorized" also appear in filesystem errors and upstream proxies, so they
# count only together with a 401/403 status (below).
_AUTH = (
    "authentication failed", "authentication_error", "authentication_failed", "invalid api key",
    "invalid x-api-key", "incorrect api key", "not allowed to access model",
    "team not allowed",
)
_AUTH_STATUS = re.compile(r"(?:api error|status|http|error)[:=\s]*\(?(?:401|403)\b", re.I)
_STATUS_404 = re.compile(r"(?:api error|status|http|error)[:=\s]*\(?404\b", re.I)
_STATUS_PATTERNS = (
    re.compile(r"last status:\s*(\d{3})\b", re.I),
    re.compile(r"api error:?\s*(\d{3})\b", re.I),
    re.compile(r"\bhttp[/ ]?(?:\d(?:\.\d)?\s+)?(\d{3})\b", re.I),
    re.compile(r"\bstatus(?:[ _]?code)?[=: ]\s*(\d{3})\b", re.I),
)
_MODEL_MISSING = (
    "model_not_found", "deploymentnotfound", "model_not_available",
)
_MODEL_MISSING_RE = re.compile(
    r"model\b.{0,80}\b(?:does not exist|not found|is not available|not deployed)"
    r"|api error[:\s]*404\b.{0,120}\bmodel", re.I | re.S,
)


@dataclass(frozen=True)
class ClassifiedError:
    error_type: str        # Temporal ApplicationError type
    reason: str            # trimmed provider message
    hint: str              # what to do about it
    non_retryable: bool = True


def provider_message(text: str, limit: int = 300) -> str:
    """The provider's message from ``text``: redacted, whitespace collapsed,
    the CLI's ``API Error:`` prefix dropped, trimmed to ``limit`` characters."""
    msg = " ".join(redact(text or "").split())
    m = re.search(r"api error:?\s*", msg, re.I)
    if m and m.end() < len(msg):
        msg = msg[m.end():]
    return msg if len(msg) <= limit else msg[: limit - 1] + "…"


def status_from_text(text: str | None) -> int | None:
    """An HTTP status mentioned in provider error text, or ``None``."""
    for pat in _STATUS_PATTERNS:
        m = pat.search(text or "")
        if m and 100 <= int(m.group(1)) <= 599:
            return int(m.group(1))
    return None


def classify_agent_error(text: str | None, status: int | None = None) -> ClassifiedError | None:
    """Classify a failed executor run from its error text and, when the executor
    parsed one, the HTTP status. ``None`` means unknown or transient: retry."""
    if not text and not status:
        return None
    low = (text or "").lower()
    reason = provider_message(text or f"HTTP {status}")

    if status is None:
        status = status_from_text(text)
    # Transient statuses never become permanent because of an incidental phrase
    # in the body ("... 503 ... forbidden", "500 model not found in cache").
    transient = status is not None and (status in (408, 409, 425, 429) or status >= 500)
    if transient:
        if status in (429,) or status >= 500:
            if any(p in low for p in _REFUSAL_UNMISTAKABLE):
                return _refusal(reason)
        return None
    if any(p in low for p in _REFUSAL):
        return _refusal(reason)
    if (any(p in low for p in _MODEL_MISSING) or _MODEL_MISSING_RE.search(low)
            or (status == 404 or _STATUS_404.search(low)) and "model" in low):
        return ClassifiedError(CONFIG_ERROR, reason, "the model is not available; " + _WHERE)
    if status in (401, 403) or any(p in low for p in _AUTH) or _AUTH_STATUS.search(low):
        return ClassifiedError(AUTH_ERROR, reason, _WHERE + " and the credentials")
    return None


def _refusal(reason: str) -> ClassifiedError:
    return ClassifiedError(
        REFUSAL_ERROR, reason,
        "the model refused this session; try another model (" + _WHERE + ")",
    )


def format_agent_error(agent: str, executor: str, model: str | None,
                       reason: str, hint: str | None = None) -> str:
    """``surveyor (claude, claude-opus-4-6): <reason> — <hint>``."""
    who = f"{agent} ({executor}, {model})" if model else f"{agent} ({executor})"
    return f"{who}: {reason}" + (f" — {hint}" if hint else "")


def flatten_error(value: object) -> tuple[str, int | None]:
    """``(text, http_status)`` from an executor error payload: a string, or a dict
    such as opencode's ``{"name": "APIError", "data": {"message": ..., "statusCode": 403}}``
    or codex's ``{"message": ...}``."""
    if isinstance(value, str):
        return value, None
    if not isinstance(value, dict):
        return ("" if value is None else str(value)), None
    data = value.get("data") if isinstance(value.get("data"), dict) else {}
    status = None
    for src in (data, value):
        for key in ("statusCode", "status_code", "status", "http_status"):
            raw = src.get(key)
            if isinstance(raw, int) and not isinstance(raw, bool) and 100 <= raw <= 599:
                status = raw
                break
        if status:
            break
    text = (data.get("message") or value.get("message") or value.get("error")
            or "")
    if not isinstance(text, str) or not text:
        import json
        text = json.dumps(value, separators=(",", ":"), default=str)
    name = value.get("name")
    if isinstance(name, str) and name and name not in text:
        text = f"{name}: {text}"
    return text, status
