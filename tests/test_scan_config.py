"""Per-repository scan settings (description / focus / avoid) reach every agent.

The platform sends them in the workflow input (temporal engine) or as
VIGILO_SCAN_* environment variables (per-run container engine); run_agent merges
them into the config that load_prompt renders.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from src.services.prompt_manager import load_prompt
from src.temporal.activities import merge_scan_config, scan_config_from_input


def test_scan_from_input_reads_scan_block_and_legacy_description():
    assert scan_config_from_input({}) is None
    assert scan_config_from_input({"description": "Shop"}) == {"description": "Shop"}
    got = scan_config_from_input(
        {"description": "", "scan": {"focus": "the API", "avoid": "", "other": "x"}}
    )
    assert got == {"focus": "the API"}


def test_config_file_wins_and_platform_fills_gaps():
    file_cfg = {"description": "From file", "rules": {"avoid": [{"description": "no /admin"}]}}
    merged = merge_scan_config(file_cfg, {"description": "From UI", "avoid": "x", "focus": "the API"})
    assert merged["description"] == "From file"
    assert "avoid" not in merged  # the file's nested rules.avoid wins
    assert merged["focus"] == "the API"
    assert merge_scan_config(None, None) is None
    assert merge_scan_config(None, {"focus": "f"}) == {"focus": "f"}


def test_platform_rules_render_in_whitebox_prompt():
    config = merge_scan_config(None, {
        "description": "Customer portal",
        "focus": "Prioritise the billing API\nCheck tenant isolation",
        "avoid": "Do not touch /admin/delete",
    })
    rendered = asyncio.run(load_prompt("whitebox/investigator", "http://t.local", "/repo", config))
    for text in ("Customer portal", "Prioritise the billing API", "Check tenant isolation",
                 "Do not touch /admin/delete"):
        assert text in rendered


def test_single_scan_worker_reads_platform_env(monkeypatch):
    from src.temporal.worker import _build_pipeline_input

    monkeypatch.setenv("VIGILO_SCAN_FOCUS", "the API")
    monkeypatch.setenv("VIGILO_SCAN_AVOID", "no DoS")
    monkeypatch.delenv("VIGILO_SCAN_DESCRIPTION", raising=False)
    args = SimpleNamespace(web_url="http://t", repo_path="/repos/target", stages=None)
    data = _build_pipeline_input(args, "wf", "sess")
    assert data["scan"] == {"focus": "the API", "avoid": "no DoS"}
    assert scan_config_from_input(json.loads(json.dumps(data))) == data["scan"]
