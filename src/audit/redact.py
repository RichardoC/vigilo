"""Redaction of known secret values from everything Vigilo persists.

The worker registers a secret the moment it holds one (a cookie header redeemed for an
agent prompt); the audit writers (event log, workflow log, agent logs, prompt
snapshots, session metadata) then replace every occurrence with ``***``. Agents may
echo the value in their output, so this runs on all text written, not just prompts.

Registered per process for its lifetime (memory only; a handful of short strings).
Besides the whole value, each ``name=value`` pair and each cookie value of a Cookie
header is registered, plus URL-encoded forms.
"""
from __future__ import annotations

import html
import json
import threading
from urllib.parse import quote, quote_plus

MASK = "***"
_MIN_LEN = 6  # shorter fragments would mangle ordinary text

_lock = threading.Lock()
_secrets: list[str] = []  # longest first


def _variants(value: str) -> set[str]:
    base = {value}
    if "=" in value or ";" in value:  # a Cookie header: also each pair and each value
        for part in value.split(";"):
            part = part.strip()
            if not part:
                continue
            base.add(part)
            if "=" in part:
                base.add(part.split("=", 1)[1].strip().strip('"'))
    out = set(base)
    for v in base:
        # URL-encoded (path style and form style) and HTML-escaped (with and without
        # quote escaping) forms of the value, of every cookie pair and of every value.
        out |= {quote(v, safe=""), quote(v), quote_plus(v), quote_plus(v, safe=""),
                html.escape(v, quote=True), html.escape(v, quote=False)}
    out |= {html.escape(v, quote=True).replace("&#x27;", "&#39;") for v in base}
    out |= {json.dumps(v)[1:-1] for v in list(out)}  # as embedded in JSON text
    return {v for v in out if len(v) >= _MIN_LEN}


def register_secret(value: str | None) -> None:
    """Start masking ``value`` (and its derived forms) in everything persisted."""
    if not value or len(value) < _MIN_LEN:
        return
    with _lock:
        have = set(_secrets)
        new = _variants(value) - have
        if new:
            _secrets.extend(new)
            _secrets.sort(key=len, reverse=True)


def redact(text: str) -> str:
    """``text`` with every registered secret replaced by ``***``."""
    if not text or not _secrets:
        return text
    with _lock:
        known = list(_secrets)
    for secret in known:
        if secret in text:
            text = text.replace(secret, MASK)
    return text


def clear() -> None:
    """Forget all registered secrets (tests)."""
    with _lock:
        _secrets.clear()
