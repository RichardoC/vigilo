"""Configuration type definitions: the scan YAML config models and the
per-run ``pipeline_config`` / ``model_overrides`` validators.

Deterministic and sandbox-safe: the white-box workflows import this inside the
Temporal workflow sandbox.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from pydantic import BaseModel, Field, model_validator


class Rule(BaseModel):
    """A scope rule that tells agents what to avoid or focus on."""

    description: str
    type: str = "path"
    url_path: str = ""


class SuccessCondition(BaseModel):
    """Condition to verify successful authentication."""

    type: str
    value: str


class Credentials(BaseModel):
    """Login credentials for authenticated testing."""

    username: str
    password: str
    totp_secret: str | None = None


class Authentication(BaseModel):
    """Full authentication configuration for the target application."""

    login_type: Literal["form", "sso", "cookie"] = "form"
    login_url: str = ""
    credentials: Credentials | None = None
    login_flow: list[str] = Field(default_factory=list)
    success_condition: SuccessCondition | None = None
    cookie_header: str | None = None

    @model_validator(mode="after")
    def _validate_cookie_auth(self) -> Authentication:
        if self.login_type == "cookie":
            if not self.cookie_header or not self.cookie_header.strip():
                raise ValueError(
                    "cookie_header is required when login_type is 'cookie'"
                )
        elif self.login_type in ("form", "sso"):
            if self.credentials is None:
                raise ValueError(
                    f"credentials are required when login_type is '{self.login_type}'"
                )
        return self


RETRY_PRESETS = ("production", "subscription")


class PipelineConfig(BaseModel):
    """Validated per-run ``pipeline_config`` of the workflow input.

    Use :meth:`from_input`: it never raises. Unknown keys are ignored; a value
    that is not an integer (or not a known preset) falls back to the default and
    integers are clamped to their bounds.
    """

    retry_preset: str | None = None
    # Concurrent investigator / prover agents.
    max_concurrent_pipelines: int = 8
    # Batch sizes for the parallel investigator / prover agents.
    leads_per_investigator: int = 3
    findings_per_prover: int = 3
    # Follow-up investigation rounds while open leads remain.
    investigation_followup_rounds: int = 1

    # key -> (minimum, maximum)
    BOUNDS: ClassVar[dict[str, tuple[int, int]]] = {
        "max_concurrent_pipelines": (1, 32),
        "leads_per_investigator": (1, 25),
        "findings_per_prover": (1, 25),
        "investigation_followup_rounds": (0, 5),
    }

    @classmethod
    def from_input(cls, raw: Any) -> PipelineConfig:
        cfg = raw if isinstance(raw, dict) else {}
        values: dict[str, Any] = {}
        for key, (lo, hi) in cls.BOUNDS.items():
            value = cfg.get(key)
            if value is None or isinstance(value, bool):
                continue
            try:
                values[key] = min(hi, max(lo, int(value)))
            except (TypeError, ValueError):
                continue
        preset = cfg.get("retry_preset")
        if isinstance(preset, str) and preset in RETRY_PRESETS:
            values["retry_preset"] = preset
        return cls(**values)


# Workflow-input ``model_overrides`` key -> executor environment variable.
# Same mapping the platform's per-run container engine
# (src/webapi/engine/docker_temporal.py) applies to the worker container.
MODEL_OVERRIDE_ENV: dict[str, str] = {
    "executor": "VIGILO_EXECUTOR",
    "model_small": "ANTHROPIC_SMALL_MODEL",
    "model_medium": "ANTHROPIC_MEDIUM_MODEL",
    "model_large": "ANTHROPIC_LARGE_MODEL",
}

_MODEL_OVERRIDE_MAX_LEN = 200


def clean_model_overrides(raw: Any) -> dict[str, str] | None:
    """Keep only the known, non-empty string overrides; ``None`` when none."""
    if not isinstance(raw, dict):
        return None
    cleaned = {
        key: value.strip()
        for key, value in raw.items()
        if key in MODEL_OVERRIDE_ENV
        and isinstance(value, str)
        and value.strip()
        and len(value.strip()) <= _MODEL_OVERRIDE_MAX_LEN
    }
    return cleaned or None


# Per-executor environment variables for the three model tiers. Each backend
# only reads its own (src/ai/{claude,codex,opencode}_executor.py).
EXECUTOR_MODEL_ENV: dict[str, dict[str, str]] = {
    "claude": {"model_small": "ANTHROPIC_SMALL_MODEL", "model_medium": "ANTHROPIC_MEDIUM_MODEL",
               "model_large": "ANTHROPIC_LARGE_MODEL"},
    "codex": {"model_small": "CODEX_SMALL_MODEL", "model_medium": "CODEX_MEDIUM_MODEL",
              "model_large": "CODEX_LARGE_MODEL"},
    "opencode": {"model_small": "OPENCODE_SMALL_MODEL", "model_medium": "OPENCODE_MEDIUM_MODEL",
                 "model_large": "OPENCODE_LARGE_MODEL"},
}


def model_override_env(
    overrides: dict[str, Any] | None, executor: str | None = None
) -> dict[str, str]:
    """Executor env vars for a (cleaned or raw) ``model_overrides`` dict.

    Model names go to the tier variables of the executor that will actually run:
    ``executor`` (the effective backend, resolved by the caller from the override
    and the worker environment), else the override's own ``executor``, else
    claude. Mapping them to the wrong backend's variables would silently ignore
    them (e.g. ``ANTHROPIC_LARGE_MODEL`` is never read by the codex executor).
    """
    cleaned = clean_model_overrides(overrides) or {}
    backend = (executor or cleaned.get("executor") or "claude").strip().lower()
    tier_env = EXECUTOR_MODEL_ENV.get(backend, EXECUTOR_MODEL_ENV["claude"])
    env: dict[str, str] = {}
    if cleaned.get("executor"):
        env["VIGILO_EXECUTOR"] = cleaned["executor"]
    for key, var in tier_env.items():
        if cleaned.get(key):
            env[var] = cleaned[key]
    return env
