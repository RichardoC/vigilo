"""Render the findings ledger as the evidence files the review, remediation and
report agents read.

Those agents (prompts ``critic``, ``remediation``, ``report-executive``) look
for evidence in ``deliverables/{category}_exploitation_evidence.md`` (and
``chain_exploitation_evidence.md``), keyed by the ``vulnerability_type`` of each
entry in ``findings_index.json``. The white-box engine records findings,
verdicts and chains in the ledger instead (``deliverables/ledger/``) with one
write-up per finding under ``deliverables/evidence/``. This module bridges the
two: for every ledger category it writes ``{category}_exploitation_evidence.md``
containing each finding's record, its verdict and its evidence write-up
verbatim, plus ``chain_exploitation_evidence.md`` for recorded chains.

Rules:

* An empty ledger writes nothing.
* Every generated file starts with :data:`GENERATED_MARKER`. A file without the
  marker was written by an agent and is never overwritten.
* Generated files whose category no longer has findings are removed, so a
  finding re-recorded under another category does not linger.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from src.pipeline.ledger import (
    EVIDENCE_DIRNAME,
    SUPPRESSING_VERDICTS,
    VERDICT_STATUS,
    Ledger,
)

logger = logging.getLogger(__name__)

GENERATED_MARKER = "<!-- vigilo: generated from the findings ledger; do not edit -->"
EVIDENCE_SUFFIX = "_exploitation_evidence.md"
CHAIN_FILENAME = "chain" + EVIDENCE_SUFFIX

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _is_generated(path: Path) -> bool:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.readline().strip() == GENERATED_MARKER
    except OSError:
        return False


def _fmt(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, indent=2)


def _title(category: str) -> str:
    return category.replace("-", " ").replace("_", " ").title()


def _read_evidence(deliverables: Path, finding_id: str, verdict: dict[str, Any] | None) -> str | None:
    candidates: list[Path] = []
    ref = (verdict or {}).get("evidence_ref")
    if isinstance(ref, str) and ref:
        ref_path = Path(ref)
        if not ref_path.is_absolute():
            # evidence_ref may be deliverables-relative or repo-relative.
            parts = ref_path.parts
            if parts and parts[0] == "deliverables":
                ref_path = Path(*parts[1:]) if len(parts) > 1 else ref_path
            candidates.append(deliverables / ref_path)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", finding_id)
    candidates.append(deliverables / EVIDENCE_DIRNAME / f"{safe}.md")
    for path in candidates:
        try:
            resolved = path.resolve()
            if resolved.is_relative_to(deliverables.resolve()) and path.is_file():
                return path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
    return None


def _render_finding(deliverables: Path, finding: dict[str, Any], verdict: dict[str, Any] | None) -> str:
    fid = str(finding["id"])
    loc = finding.get("location") or {}
    where = loc.get("file") or "unknown"
    if loc.get("line"):
        where = f"{where}:{loc['line']}"
    severity = str(finding.get("severity") or "medium").lower()
    verdict_name = (verdict or {}).get("verdict")
    status = VERDICT_STATUS.get(verdict_name, "unconfirmed") if verdict_name else "unconfirmed"

    out = [f"### {fid}: {finding.get('title', '').strip()}", ""]
    meta = [f"**Severity:** {severity}"]
    if verdict and verdict.get("severity") and verdict["severity"] != severity:
        meta.append(f"**Severity as proven:** {verdict['severity']}")
    meta.append(f"**Status:** {status}" + (f" (verdict: {verdict_name})" if verdict_name else ""))
    meta.append(f"**Confidence:** {finding.get('confidence', 'medium')}")
    if finding.get("cwe"):
        meta.append(f"**CWE:** {finding['cwe']}")
    out.append(" | ".join(meta))
    out.append(f"**Location:** `{where}`")
    if finding.get("category_label"):
        out.append(f"**Category:** {finding['category_label']}")
    if finding.get("code_fixable") is False:
        out.append("**Code-fixable:** no")
    out.append("")

    out += ["#### Description", "", _fmt(finding.get("description", "")).strip(), ""]

    trace = [(label, finding.get(key)) for key, label in (
        ("entry_point", "Entry point"), ("source", "Source"), ("sink", "Sink"), ("witness", "Witness"),
    ) if finding.get(key) not in (None, "", [])]
    if trace:
        out += ["#### Source to sink", ""]
        for label, val in trace:
            text = _fmt(val)
            out.append(f"- **{label}:** {text}" if "\n" not in text else f"- **{label}:**\n\n```\n{text}\n```")
        out.append("")
    if finding.get("preconditions"):
        out += ["#### Preconditions", ""] + [f"- {p}" for p in finding["preconditions"]] + [""]
    if finding.get("attack_path"):
        out += ["#### Attack path", ""] + [f"{i}. {s}" for i, s in enumerate(finding["attack_path"], 1)] + [""]

    if verdict:
        out += ["#### Verdict", "", f"**{verdict_name}**: {_fmt(verdict.get('summary', '')).strip()}", ""]
        if verdict_name in SUPPRESSING_VERDICTS:
            out += ["This finding did not hold up under testing and is not a confirmed vulnerability.", ""]
        if verdict.get("harness_path"):
            out += [f"Harness: `{verdict['harness_path']}`", ""]
        shots = verdict.get("screenshots") or []
        if shots:
            out += ["Screenshots:", ""] + [f"- {s}" for s in shots] + [""]
    else:
        out += ["#### Verdict", "", "Not yet tested (no verdict recorded).", ""]

    evidence = _read_evidence(deliverables, fid, verdict)
    if evidence:
        out += ["#### Evidence", "", evidence, ""]
    return "\n".join(out)


def _render_chain(chain: dict[str, Any]) -> str:
    comps = ", ".join(chain.get("finding_ids") or [])
    out = [
        f"### {chain['id']}: {chain.get('title', '').strip()}",
        "",
        f"**Severity:** {chain.get('severity', 'high')} | **Status:** {chain.get('status', 'potential')}"
        f" | **Components:** {comps}",
        "",
        _fmt(chain.get("narrative", "")).strip(),
        "",
    ]
    return "\n".join(out)


def write_ledger_evidence(deliverables_dir: str | Path) -> dict[str, Any]:
    """Write ``{category}_exploitation_evidence.md`` files from the ledger.

    Returns ``{"written": [...], "skipped": [...], "removed": [...],
    "findings": n, "chains": m}``. Never raises on a malformed ledger line (the
    ledger reader skips those); I/O errors on individual files are logged.
    """
    deliverables = Path(deliverables_dir)
    ledger = Ledger(deliverables)
    findings = ledger.findings()
    verdicts = ledger.verdicts()
    chains = ledger.chains()
    result: dict[str, Any] = {
        "written": [], "skipped": [], "removed": [],
        "findings": len(findings), "chains": len(chains),
    }
    if not findings and not chains:
        return result

    by_category: dict[str, list[dict[str, Any]]] = {}
    for finding in findings.values():
        by_category.setdefault(str(finding.get("category") or "other"), []).append(finding)

    targets: dict[str, str] = {}
    for category, items in sorted(by_category.items()):
        items.sort(key=lambda f: (_SEVERITY_RANK.get(str(f.get("severity")).lower(), 5), str(f["id"])))
        body = [
            GENERATED_MARKER,
            "",
            f"# {_title(category)} findings",
            "",
            "Findings recorded during source review, each with its proof verdict and"
            " evidence write-up. Finding IDs (VG-NNN) match deliverables/findings_index.json.",
            "",
        ]
        body += [_render_finding(deliverables, f, verdicts.get(str(f["id"]))) for f in items]
        targets[f"{category}{EVIDENCE_SUFFIX}"] = "\n".join(body).rstrip() + "\n"

    if chains:
        body = [
            GENERATED_MARKER,
            "",
            "# Attack chains",
            "",
            "Multi-step attacks combining recorded findings (component IDs refer to"
            " the per-category evidence files).",
            "",
        ]
        body += [_render_chain(c) for _, c in sorted(chains.items())]
        targets[CHAIN_FILENAME] = "\n".join(body).rstrip() + "\n"

    deliverables.mkdir(parents=True, exist_ok=True)
    for name, content in targets.items():
        path = deliverables / name
        if path.exists() and not _is_generated(path):
            logger.warning("Not overwriting agent-written %s with ledger evidence", name)
            result["skipped"].append(name)
            continue
        try:
            path.write_text(content, encoding="utf-8")
            result["written"].append(name)
        except OSError as exc:
            logger.warning("Failed to write %s: %s", name, exc)

    for path in deliverables.glob(f"*{EVIDENCE_SUFFIX}"):
        if path.name not in targets and _is_generated(path):
            try:
                path.unlink()
                result["removed"].append(path.name)
            except OSError:
                pass

    logger.info(
        "Ledger evidence: %d findings, %d chains -> %s",
        len(findings), len(chains), ", ".join(result["written"]) or "nothing written",
    )
    return result
