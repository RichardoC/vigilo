"""First-boot admin_config follows the deployment's executor configuration."""
from __future__ import annotations

from src.webapi.bootstrap import _seed_models
from src.webapi.settings import get_settings

_VARS = ("VIGILO_DEFAULT_EXECUTOR", "VIGILO_EXECUTOR", "VIGILO_DEFAULT_MODEL_SMALL",
         "VIGILO_DEFAULT_MODEL_MEDIUM", "VIGILO_DEFAULT_MODEL_LARGE",
         "CODEX_SMALL_MODEL", "CODEX_MEDIUM_MODEL", "CODEX_LARGE_MODEL",
         "ANTHROPIC_SMALL_MODEL", "ANTHROPIC_MEDIUM_MODEL", "ANTHROPIC_LARGE_MODEL",
         "CODEX_BASE_URL", "CODEX_API_KEY", "CODEX_HOME", "OPENAI_API_KEY",
         "LITELLM_BASE_URL", "LITELLM_API_KEY", "CLAUDE_CODE_USE_BEDROCK")


def _clear(monkeypatch):
    for v in _VARS:
        monkeypatch.delenv(v, raising=False)


def test_codex_deployment_is_seeded_with_codex_models(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("VIGILO_EXECUTOR", "codex")
    for tier in ("SMALL", "MEDIUM", "LARGE"):
        monkeypatch.setenv(f"CODEX_{tier}_MODEL", "gpt-5-5")
    seeded = _seed_models(get_settings())
    assert seeded == {"executor": "codex", "model_small": "gpt-5-5",
                      "model_medium": "gpt-5-5", "model_large": "gpt-5-5"}


def test_explicit_defaults_win(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("VIGILO_EXECUTOR", "codex")
    monkeypatch.setenv("VIGILO_DEFAULT_EXECUTOR", "claude")
    monkeypatch.setenv("VIGILO_DEFAULT_MODEL_LARGE", "claude-opus-x")
    seeded = _seed_models(get_settings())
    assert seeded["executor"] == "claude" and seeded["model_large"] == "claude-opus-x"


def test_codex_without_model_vars_defers_to_worker(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("VIGILO_EXECUTOR", "codex")
    seeded = _seed_models(get_settings())
    assert seeded == {"executor": "codex", "model_small": "", "model_medium": "", "model_large": ""}


def test_unconfigured_deployment_is_claude_with_worker_default_models(monkeypatch):
    _clear(monkeypatch)
    seeded = _seed_models(get_settings())
    assert seeded == {"executor": "claude", "model_small": "", "model_medium": "", "model_large": ""}


def test_codex_signal_vars_autodetect_codex(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("CODEX_BASE_URL", "https://gw.example/v1")
    monkeypatch.setenv("CODEX_API_KEY", "k")
    assert _seed_models(get_settings())["executor"] == "codex"


def test_bedrock_without_model_vars_leaves_models_to_the_worker(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    seeded = _seed_models(get_settings())
    assert seeded["executor"] == "claude" and seeded["model_large"] == ""
    monkeypatch.setenv("ANTHROPIC_LARGE_MODEL", "eu.anthropic.claude-opus-x")
    assert _seed_models(get_settings())["model_large"] == "eu.anthropic.claude-opus-x"


def test_admin_update_accepts_clearing_a_model():
    from src.webapi.schemas import AdminConfigUpdate

    assert AdminConfigUpdate(model_large="  ").model_large == ""
    assert AdminConfigUpdate(model_large="x").model_large == "x"
    assert AdminConfigUpdate().model_dump(exclude_unset=True) == {}


def _admin(**kw):
    from types import SimpleNamespace
    base = dict(executor="claude", model_small="claude-haiku-4-5", model_medium="claude-sonnet-4-6",
                model_large="claude-opus-4-6")
    base.update(kw)
    return SimpleNamespace(**base)


def _repo(cfg):
    from types import SimpleNamespace
    return SimpleNamespace(pipeline_config=cfg)


def test_repo_executor_override_does_not_inherit_admin_models():
    from src.webapi.engine.common import build_model_overrides

    assert build_model_overrides(_admin(), _repo({"executor": "codex"})) == {"executor": "codex"}
    assert build_model_overrides(_admin(), _repo({"executor": "codex", "model_large": "gpt-5"})) == {
        "executor": "codex", "model_large": "gpt-5"}


def test_same_executor_inherits_admin_models_and_empty_means_unset():
    from src.webapi.engine.common import build_model_overrides

    out = build_model_overrides(_admin(), _repo({"model_large": "", "model_small": "h2"}))
    assert out == {"executor": "claude", "model_small": "h2", "model_medium": "claude-sonnet-4-6",
                   "model_large": "claude-opus-4-6"}
    out = build_model_overrides(_admin(model_small="", model_medium="", model_large=""), _repo(None))
    assert out == {"executor": "claude"}
