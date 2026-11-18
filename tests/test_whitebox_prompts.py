"""Tests for the white-box engine prompts (prompts/whitebox/).

These guard the contract between the prompts and the findings ledger
(src/pipeline/ledger.py, scripts/vigilo_record.py): agents must be told the
record kinds and required fields they are actually allowed to write, and every
prompt must render with no unresolved ``{{PLACEHOLDER}}`` tokens. They also
check that operator rules and authentication reach the agents for every real
config shape, and that the per-instance assignment line is authoritative.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest
import yaml

from src.pipeline.ledger import LEAD_OUTCOMES, RECORD_KINDS, SEVERITIES, VERDICT_STATUS
from src.services import prompt_manager
from src.services.prompt_manager import _PLACEHOLDER_RE, load_prompt, session_for_prompt
from src.session_manager import AGENTS

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_WHITEBOX = _PROJECT_ROOT / "prompts" / "whitebox"
PROMPTS = ("surveyor", "planner", "investigator", "prover")
_LIVE = ("surveyor", "investigator", "prover")  # actors that may touch the live target

# The nested config shape load_prompt() supports (rules under ``rules:`` as Rule
# dicts, form login with login_flow and success_condition).
_CONFIG = yaml.safe_load("""
description: "Example web application for security testing"
authentication:
  login_type: form
  login_url: "http://localhost:8080/login"
  credentials:
    username: "test@example.com"
    password: "testpassword"
  login_flow:
    - "Type $username into the email field"
    - "Type $password into the password field"
    - "Click the 'Sign In' button"
  success_condition:
    type: url_contains
    value: "/dashboard"
rules:
  avoid:
    - description: "Do not test logout functionality"
      type: path
      url_path: "/logout"
    - description: "Do not test admin panel"
      type: path
      url_path: "/admin"
  focus:
    - description: "Focus on API endpoints"
      type: path
      url_path: "/api"
""")

# Flat shape (platform scan settings, older callers): top-level avoid/focus.
_FLAT_CONFIG = {
    "description": "Test app",
    "avoid": ["Do not touch /admin"],
    "focus": ["Prioritise the API"],
}


def _render(
    name: str,
    config: dict | None = _CONFIG,
    instance: int | None = None,
    web_url: str = "http://target.local",
    extra_context: str = "",
) -> str:
    return asyncio.run(
        load_prompt(
            f"whitebox/{name}",
            web_url=web_url,
            repo_path="/repo",
            config=config,
            instance=instance,
            extra_context=extra_context,
        )
    )


def _section(rendered: str, tag: str) -> str:
    m = re.search(rf"<{tag}>(.*?)</{tag}>", rendered, re.DOTALL)
    assert m, f"<{tag}> block missing"
    return m.group(1)


@pytest.mark.parametrize("name", PROMPTS)
def test_prompt_exists_and_is_not_truncated(name: str) -> None:
    path = _WHITEBOX / f"{name}.txt"
    assert path.is_file(), f"Missing white-box prompt: {path}"
    text = path.read_text(encoding="utf-8")
    # A prompt must close the tags it opens and end on a completion instruction.
    assert text.rstrip().endswith("</completion>"), f"{name}.txt looks truncated"


@pytest.mark.parametrize("name", PROMPTS)
@pytest.mark.parametrize("config", [None, _CONFIG, _FLAT_CONFIG], ids=["none", "yaml", "flat"])
def test_prompt_renders_without_placeholders(name: str, config: dict | None) -> None:
    rendered = _render(name, config)
    leftover = sorted(set(_PLACEHOLDER_RE.findall(rendered)))
    assert not leftover, f"{name}.txt has unresolved placeholders: {leftover}"
    assert "http://target.local" in rendered


# What each prompt itself (not a shared partial) must tell its agent to run.
_REQUIRED_COMMANDS = {
    "surveyor": ["save-deliverable --type CODE_ANALYSIS"],
    "planner": ["vigilo-record show leads", "vigilo-record lead --file"],
    "investigator": ["vigilo-record show leads --mine", "`lead-done`", "`finding`"],
    "prover": ["vigilo-record show finding", "vigilo-record verdict --file", "--evidence-file"],
}


@pytest.mark.parametrize("name", PROMPTS)
def test_each_prompt_names_the_commands_its_stage_needs(name: str) -> None:
    text = (_WHITEBOX / f"{name}.txt").read_text(encoding="utf-8")
    for command in _REQUIRED_COMMANDS[name]:
        assert command in text, f"{name}.txt does not tell its agent to use {command!r}"


@pytest.mark.parametrize("name", ["planner", "investigator", "prover"])
def test_ledger_writers_get_the_ledger_contract(name: str) -> None:
    rendered = _render(name)
    assert "<ledger>" in rendered and "vigilo-record show summary" in rendered


def test_surveyor_does_not_write_the_ledger() -> None:
    assert "<ledger>" not in _render("surveyor")


def test_ledger_partial_documents_the_real_contract() -> None:
    """The ledger partial must list every record kind and the values the CLI accepts.

    Values are checked in their backticked form: bare substrings would pass via
    words such as "lowest", "highest" or "information-disclosure".
    """
    ledger = (_WHITEBOX / "shared" / "_ledger.txt").read_text(encoding="utf-8")
    for kind in RECORD_KINDS:
        assert f"`{kind}`" in ledger, f"record kind {kind!r} not documented for agents"
    for severity in SEVERITIES:
        assert f"`{severity}`" in ledger, f"severity {severity!r} not documented"
    for outcome in LEAD_OUTCOMES:
        assert f"`{outcome}`" in ledger, f"lead outcome {outcome!r} not documented"
    for verdict in VERDICT_STATUS:
        assert f"`{verdict}`" in ledger, f"verdict {verdict!r} not documented"
    assert "--evidence-file" in ledger
    assert "`harness_path`" in ledger


def test_ledger_partial_describes_all_or_nothing_calls() -> None:
    ledger = (_WHITEBOX / "shared" / "_ledger.txt").read_text(encoding="utf-8")
    assert "nothing from that call is stored" in ledger
    assert "send the whole call again" in ledger


def test_prompts_are_not_hardcoded_to_one_category_set() -> None:
    """The redesign is open-ended: prompts must not enumerate a fixed agent roster."""
    for name in PROMPTS:
        text = (_WHITEBOX / f"{name}.txt").read_text(encoding="utf-8")
        assert "vuln-injection" not in text
        assert "exploit-auth" not in text


# ---------------------------------------------------------------------------
# Operator rules reach the agents, whatever the config shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", PROMPTS)
def test_yaml_rules_reach_the_prompt(name: str) -> None:
    rules = _section(_render(name, _CONFIG), "rules")
    assert "No specific rules" not in rules
    assert "- Do not test admin panel (path: /admin)" in rules
    assert "- Do not test logout functionality (path: /logout)" in rules
    assert "- Focus on API endpoints (path: /api)" in rules


def test_flat_rules_reach_the_prompt() -> None:
    rules = _section(_render("investigator", _FLAT_CONFIG), "rules")
    assert "- Do not touch /admin" in rules
    assert "- Prioritise the API" in rules


def test_free_text_rules_are_split_per_line() -> None:
    """Platform scan settings are textareas: one rule per line, bullets optional."""
    config = {"avoid": "- no /admin\n\n* no DoS", "focus": "the API"}
    rules = _section(_render("investigator", config), "rules")
    assert "- no /admin\n- no DoS" in rules
    assert "- the API" in rules


def test_no_rules_renders_clean_block() -> None:
    rules = _section(_render("investigator", {"description": "x"}), "rules")
    assert "No specific rules" in rules


# ---------------------------------------------------------------------------
# Authentication reaches the agents
# ---------------------------------------------------------------------------

_FORM_LOGIN = {
    "authentication": {
        "login_type": "form",
        "login_url": "http://target/login",
        "credentials": {"username": "alice", "password": "S3cret-pw"},
        "login_flow": ["Type $username into Email", "Type $password into Password", "Click Sign in"],
        "success_condition": {"type": "url_contains", "value": "/dashboard"},
    },
}
_FORM_NO_FLOW = {
    "authentication": {
        "login_type": "form",
        "login_url": "http://target/login",
        "credentials": {"username": "bob", "password": "Hunter-2", "totp_secret": "JBSWY3DP"},
        "success_condition": {"type": "element_present", "value": "#logout"},
    },
}
_SSO_NO_FLOW = {
    "authentication": {
        "login_type": "sso",
        "login_url": "https://idp.example/login",
        "credentials": {"username": "carol", "password": "Sso-pw"},
    },
}
_COOKIE_LOGIN = {
    "authentication": {
        "login_type": "cookie",
        "login_url": "https://sso.example/app",
        "cookie_header": 'SESSION=cookie-abc123; pref="a b"',
    },
}


@pytest.mark.parametrize("name", _LIVE)
def test_form_login_flow_and_credentials_reach_the_prompt(name: str) -> None:
    rendered = _render(name, _FORM_LOGIN, instance=2)
    assert not _PLACEHOLDER_RE.findall(rendered)
    login = _section(rendered, "login")
    assert "Type alice into Email" in login
    assert "Type S3cret-pw into Password" in login
    assert "Click Sign in" in login
    assert "Logged in when: the browser URL contains `/dashboard`." in login
    assert "-s=" + session_for_prompt(f"whitebox/{name}", 2) in login


@pytest.mark.parametrize("name", _LIVE)
def test_form_without_login_flow_still_gets_credentials(name: str) -> None:
    rendered = _render(name, _FORM_NO_FLOW)
    assert not _PLACEHOLDER_RE.findall(rendered)
    login = _section(rendered, "login")
    assert "Username: `bob`" in login
    assert "Password: `Hunter-2`" in login
    assert "generate-totp --secret JBSWY3DP" in login
    assert "Login URL: http://target/login" in login
    assert "Logged in when: the page shows an element matching `#logout`." in login


def test_sso_without_login_flow_gets_credentials_and_default_success_check() -> None:
    login = _section(_render("investigator", _SSO_NO_FLOW), "login")
    assert "Password: `Sso-pw`" in login and "single sign-on" in login
    assert "no success condition is configured" in login


def test_yaml_config_success_condition_reaches_the_prompt() -> None:
    login = _section(_render("surveyor", _CONFIG), "login")
    assert "Password: `testpassword`" in login
    assert "Logged in when: the browser URL contains `/dashboard`." in login


@pytest.mark.parametrize("name", _LIVE)
def test_failed_login_does_not_halt_the_agent(name: str) -> None:
    login = _section(_render(name, _FORM_LOGIN), "login")
    assert "Do not stop" in login
    assert "halt" not in login.lower() and "do not begin the primary task" not in login.lower()


@pytest.mark.parametrize("name", _LIVE)
def test_cookie_session_uses_playwright_cli_and_curl_scoped_to_target(name: str) -> None:
    rendered = _render(name, _COOKIE_LOGIN, instance=3)
    assert not _PLACEHOLDER_RE.findall(rendered)
    login = _section(rendered, "login")
    session = session_for_prompt(f"whitebox/{name}", 3)
    assert f"playwright-cli -s={session} cookie-set SESSION cookie-abc123 --domain=target.local" in login
    assert f"playwright-cli -s={session} cookie-set pref '\"a b\"' --domain=target.local" in login
    assert """curl -H 'Cookie: SESSION=cookie-abc123; pref="a b"' http://target.local""" in login
    assert "Do not log in yourself" in login
    assert "setExtraHTTPHeaders" not in rendered


def test_planner_gets_no_login_or_secrets() -> None:
    for config in (_CONFIG, _FORM_LOGIN, _COOKIE_LOGIN):
        rendered = _render("planner", config)
        assert "<login>" not in rendered
        assert "testpassword" not in rendered and "S3cret-pw" not in rendered
        assert "cookie-abc123" not in rendered


@pytest.mark.parametrize("name", PROMPTS)
def test_code_only_run_has_no_login_block(name: str) -> None:
    rendered = _render(name, _FORM_LOGIN, web_url="")
    assert not _PLACEHOLDER_RE.findall(rendered)
    assert "<login>" not in rendered and "S3cret-pw" not in rendered
    assert "no live target in this run" in rendered


@pytest.mark.parametrize("name", PROMPTS)
def test_no_authentication_leaves_no_login_block(name: str) -> None:
    rendered = _render(name, None)
    assert "<login>" not in rendered
    assert "user_provided_configuration" not in rendered
    assert not _PLACEHOLDER_RE.findall(rendered)


def test_reused_prompts_get_no_login_block() -> None:
    """The reused (non white-box) prompts never carry credentials."""
    rendered = asyncio.run(load_prompt("critic", "http://target.local", "/repo", config=_CONFIG))
    assert "<user_provided_configuration>" not in rendered
    assert "<login>" not in rendered
    assert "S3cret-pw" not in rendered


# ---------------------------------------------------------------------------
# Investigators and provers work exactly their assigned slice
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "line"), [("investigator", "LEADS: L-001,L-004"),
                                            ("prover", "FINDINGS: VG-002,VG-007")])
def test_assignment_line_is_appended_and_authoritative(name: str, line: str) -> None:
    rendered = _render(name, extra_context=line)
    assert rendered.endswith(f"--- Your Assignment ---\n{line}")
    assert "Feedback Loop" not in rendered
    prefix = line.split(":")[0]
    assignment = _section(rendered, "assignment")
    assert f"`{prefix}:`" in assignment and "authoritative" in assignment
    assert "Your Assignment" in assignment
    # Missing line: report and stop, never self-select.
    assert "NO ASSIGNMENT" in assignment
    assert "highest-priority" not in assignment and "highest-severity" not in assignment


def test_reused_prompt_extra_context_header() -> None:
    rendered = asyncio.run(load_prompt("report-executive", "http://target.local", "/repo",
                                       extra_context="retry X"))
    assert rendered.endswith("--- Additional Context ---\nretry X")
    assert "Feedback Loop" not in rendered


# ---------------------------------------------------------------------------
# Parallel instances get isolated browser sessions
# ---------------------------------------------------------------------------


def test_session_for_prompt_base_and_instances() -> None:
    assert session_for_prompt("whitebox/investigator") == "agent2"
    assert session_for_prompt("whitebox/investigator", 1) == "agent2-1"
    assert session_for_prompt("whitebox/investigator", 3) == "agent2-3"
    assert session_for_prompt("not-a-prompt") == "agent1"
    # Out-of-range instance numbers (the contract is 1-based) fall back to the
    # base session, which no numbered instance uses, instead of failing the load.
    assert session_for_prompt("whitebox/investigator", 0) == "agent2"
    assert session_for_prompt("whitebox/investigator", -1) == "agent2"


def test_session_mapping_has_one_source_of_truth() -> None:
    from src import session_manager

    assert prompt_manager.PLAYWRIGHT_SESSION_MAPPING is session_manager.PLAYWRIGHT_SESSION_MAPPING
    for agent in AGENTS.values():
        assert agent.prompt_template in prompt_manager.PLAYWRIGHT_SESSION_MAPPING, (
            f"{agent.prompt_template} has no Playwright session"
        )


def test_parallel_investigators_render_distinct_sessions() -> None:
    first = _render("investigator", instance=1)
    second = _render("investigator", instance=2)
    assert "-s=agent2-1" in first and "-s=agent2-2" not in first
    assert "-s=agent2-2" in second and "-s=agent2-1" not in second


@pytest.mark.parametrize("name", PROMPTS)
def test_every_stage_documents_the_tools(name: str) -> None:
    """Every agent runs with the full tool set; every prompt must describe it."""
    rendered = _render(name)
    assert "<tools>" in rendered and "</tools>" in rendered


# -- harness contract, screenshots, paths, code-only wording ------------------


def test_prover_states_the_harness_contract() -> None:
    text = _render("prover", instance=1)
    assert "deliverables/harnesses/<finding-id>_harness.py" in text
    assert "VIGILO_RESULT: VULNERABLE" in text and "VIGILO_RESULT: NOT_VULNERABLE" in text
    assert "required for `confirmed`" in text
    assert "could not test" in text
    # harnesses no longer live under /tmp
    assert "/tmp/VG-004_harness" not in text


def test_remediation_runs_the_harness_and_uses_the_current_branch() -> None:
    text = asyncio.run(load_prompt("remediation", web_url="", repo_path="/repo", config=None))
    assert "BASE=$(git branch --show-current)" in text
    assert "VIGILO_RESULT: NOT_VULNERABLE" in text
    assert "git checkout main" not in text and "-b fix/{FINDING_ID} main" not in text
    assert "VULN-" not in text.replace("SCA-VULN-", "")


def test_screenshot_rule_is_consistent() -> None:
    for name in ("prover", "investigator"):
        text = _render(name, instance=1)
        assert "deliverables/screenshots/" in text
        assert "screenshots/VG-004_login-bypass.png" in text or name == "investigator"


def test_provers_do_not_record_leads() -> None:
    text = _render("prover", instance=1)
    assert "do not record a lead" in text


@pytest.mark.parametrize("name", PROMPTS)
def test_final_reply_names_unknown_ids_only_for_batched_agents(name: str) -> None:
    text = _render(name, instance=1)
    if name in ("investigator", "prover"):
        assert "preceded by one line for any assigned ID that was not in the ledger" in text


@pytest.mark.parametrize("name", _LIVE)
def test_code_only_wording_reads_correctly(name: str) -> None:
    code_only = _render(name, config=None, web_url="", instance=1)
    live = _render(name, config=None, instance=1)
    assert "no target URL" in code_only
    assert "at [no target URL" not in code_only and "to [no target URL" not in code_only
    assert "http://target.local" in live
    for text in (code_only, live):
        assert not _PLACEHOLDER_RE.findall(text) and "@include" not in text


def test_planner_covers_every_place_input_is_rendered_back() -> None:
    text = _render("planner")
    assert "rendered back" in text and "stored" in text and "innerHTML" in text
