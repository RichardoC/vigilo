"""Deliverable type definitions and filename mappings.

The narrative / structured documents agents register with ``save-deliverable``.
Findings themselves go through the ledger (``vigilo-record``), not through here.
"""

from __future__ import annotations

from typing import Literal


# ---------------------------------------------------------------------------
# Deliverable type — every document agents register with save-deliverable
# ---------------------------------------------------------------------------

DeliverableType = Literal[
    # Survey
    "CODE_ANALYSIS",
    # SCA (supply chain analysis)
    "SCA_FINDINGS",
    # Integrity (malicious code detection)
    "INTEGRITY_ANALYSIS",
    # Review
    "FINDINGS_CRITIQUE",
    # Reporting and remediation
    "REPORT",
    "REMEDIATION_REPORT",
    # Structured remediation manifest (consumed by the report author)
    "REMEDIATION_MANIFEST",
]


# ---------------------------------------------------------------------------
# Filename mappings — hard-coded from agent prompts
# ---------------------------------------------------------------------------

DELIVERABLE_FILENAMES: dict[DeliverableType, str] = {
    "CODE_ANALYSIS": "code_analysis_deliverable.md",
    "SCA_FINDINGS": "sca_findings.json",
    "INTEGRITY_ANALYSIS": "integrity_analysis.json",
    "FINDINGS_CRITIQUE": "findings_critique.json",
    "REPORT": "comprehensive_security_assessment_report.md",
    "REMEDIATION_REPORT": "remediation_report.md",
    "REMEDIATION_MANIFEST": "remediation_manifest.json",
}
