"""Reporting service — post-processing of the report the reporter agent writes.

The report itself is authored by the reporter agent (LLM) from the evidence
files; this module only injects run metadata (the models used) into it.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

import aiofiles

logger = logging.getLogger(__name__)


async def inject_model_into_report(repo_path: str, output_path: str) -> None:
    """Inject model information into the final security report.

    Reads ``session.json`` from *output_path* to extract unique model names
    from all agents, then injects a ``**Models:** ...`` line after the
    Assessment Date metadata in the structured report at *repo_path*.

    Parameters
    ----------
    repo_path:
        Path to the repository containing ``deliverables/``.
    output_path:
        Path to the workspace directory containing ``session.json``.
    """
    session_json_path = Path(output_path) / "session.json"

    if not session_json_path.is_file():
        logger.warning("session.json not found at %s, skipping model injection", session_json_path)
        return

    # 1. Read session.json and extract unique models
    try:
        async with aiofiles.open(session_json_path, mode="r", encoding="utf-8") as f:
            content = await f.read()
        session_data: dict[str, Any] = json.loads(content)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read session.json: %s", exc)
        return

    models: set[str] = set()
    agents_metrics = session_data.get("metrics", {}).get("agents", {})
    for agent_data in agents_metrics.values():
        if isinstance(agent_data, dict) and agent_data.get("model"):
            models.add(agent_data["model"])

    if not models:
        logger.warning("No model information found in session.json")
        return

    model_str = ", ".join(sorted(models))
    logger.info("Injecting model info into report: %s", model_str)

    # 2. Read the final report
    report_path = Path(repo_path) / "deliverables" / "comprehensive_security_assessment_report.md"

    if not report_path.is_file():
        logger.warning("Final report not found at %s, skipping model injection", report_path)
        return

    async with aiofiles.open(report_path, mode="r", encoding="utf-8") as f:
        report_content = await f.read()

    # 3. Inject model line after "Assessment Date" in structured report.
    # New format: "**Assessment Date:** ..." (bold, no bullet prefix)
    assessment_date_pattern = re.compile(
        r"^(\*\*Assessment Date:\*\* .+)$", re.MULTILINE
    )
    match = assessment_date_pattern.search(report_content)

    if match:
        model_line = f"**Models:** {model_str}"
        report_content = assessment_date_pattern.sub(
            rf"\1\n{model_line}", report_content
        )
        logger.info("Model info injected after Assessment Date line")
    else:
        # Fallback: inject after the title
        title_pattern = re.compile(
            r"^(# Comprehensive Security Assessment Report)$", re.MULTILINE
        )
        if title_pattern.search(report_content):
            report_content = title_pattern.sub(
                rf"\1\n\n**Models:** {model_str}", report_content
            )
            logger.info("Model info added after report title")
        else:
            logger.warning("Could not find injection point for model info")
            return

    # 4. Write modified report
    async with aiofiles.open(report_path, mode="w", encoding="utf-8") as f:
        await f.write(report_content)
