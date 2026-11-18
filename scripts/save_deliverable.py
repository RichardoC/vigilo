#!/usr/bin/env python3
"""
save-deliverable — Agent-callable CLI for saving structured deliverables.

Usage:
    save-deliverable --type CODE_ANALYSIS --file-path /tmp/report.md
    save-deliverable --type SCA_FINDINGS --content '{"vulnerabilities": [...]}'

Output: JSON to stdout
    {"status": "success", "filepath": "deliverables/code_analysis_deliverable.md", "validated": true}
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Inline the deliverable mappings to avoid import issues when script is on PATH
DELIVERABLE_FILENAMES = {
    "CODE_ANALYSIS": "code_analysis_deliverable.md",
    "SCA_FINDINGS": "sca_findings.json",
    "INTEGRITY_ANALYSIS": "integrity_analysis.json",
    "FINDINGS_CRITIQUE": "findings_critique.json",
    "REPORT": "comprehensive_security_assessment_report.md",
    "REMEDIATION_REPORT": "remediation_report.md",
    "REMEDIATION_MANIFEST": "remediation_manifest.json",
}


def _error(message: str, *, retryable: bool = False) -> None:
    """Print JSON error and exit."""
    print(json.dumps({"status": "error", "message": message, "retryable": retryable}))
    sys.exit(1)


def _repo_root() -> str:
    """The repository root, independent of a stray ``cd`` into a sub-directory.

    ``$VIGILO_REPO_PATH`` if set; else the nearest directory at or above the cwd
    with a ``deliverables`` directory/symlink next to ``.git`` (or already
    holding ``deliverables/ledger``); else the cwd (a fresh checkout).
    """
    configured = (os.environ.get("VIGILO_REPO_PATH") or "").strip()
    if configured:
        return os.path.realpath(configured)
    here = os.path.realpath(os.getcwd())
    probe = here
    while True:
        deliverables = os.path.join(probe, "deliverables")
        if os.path.isdir(os.path.join(deliverables, "ledger")) or (
            os.path.exists(deliverables) and os.path.exists(os.path.join(probe, ".git"))
        ):
            return probe
        parent = os.path.dirname(probe)
        if parent == probe:
            return here
        probe = parent


def _within(resolved: str, root: str) -> bool:
    return resolved == root or resolved.startswith(root.rstrip(os.sep) + os.sep)


def _allowed_source(path: str) -> str | None:
    """Resolve *path* and return it if it may be read, else None.

    Allowed: anything inside the repository, under /tmp, or under the real path
    of ``<repo>/deliverables`` (which may be a symlink to the run's output
    directory outside the checkout). Everything else, including ``..``
    traversal and symlinks pointing elsewhere, is rejected. A relative path is
    taken from the cwd, or from the repository root when that does not exist.
    """
    repo = _repo_root()
    resolved = os.path.realpath(os.path.join(os.getcwd(), path))
    if not os.path.exists(resolved) and not os.path.isabs(path):
        resolved = os.path.realpath(os.path.join(repo, path))
    roots = (
        os.path.realpath(repo),
        os.path.realpath("/tmp"),
        os.path.realpath(os.path.join(repo, "deliverables")),
    )
    return resolved if any(_within(resolved, r) for r in roots) else None


def _validate_list_json(content: str, key: str) -> None:
    """Validate JSON with a required top-level array property named *key*."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        _error(f"Invalid JSON: {exc}", retryable=True)

    if not isinstance(data, dict) or key not in data or not isinstance(data[key], list):
        _error(
            f"Invalid structure: expected an object with a '{key}' array. "
            f'Expected: {{"{key}": [...]}}',
            retryable=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Save agent deliverable")
    parser.add_argument("--type", required=True, help="Deliverable type")
    parser.add_argument("--file-path", help="Path to source file")
    parser.add_argument("--content", help="Direct content string")
    args = parser.parse_args()

    dtype = args.type.upper()

    # 1. Validate --type
    if dtype not in DELIVERABLE_FILENAMES:
        _error(f"Unknown deliverable type: {dtype}", retryable=False)

    filename = DELIVERABLE_FILENAMES[dtype]

    # 2. Resolve content from --content or --file-path
    content: str
    if args.content:
        content = args.content
    elif args.file_path:
        # Path traversal protection: only the repository, /tmp and deliverables/
        resolved = _allowed_source(args.file_path)
        if resolved is None:
            _error(f"Path traversal detected: {args.file_path}", retryable=False)
        try:
            with open(resolved, "r") as f:
                content = f.read()
        except OSError as exc:
            _error(f"Failed to read file: {exc}", retryable=True)
    else:
        _error("Either --content or --file-path is required", retryable=False)

    # 3. Validate content is non-empty
    if not content.strip():
        _error("Content is empty", retryable=True)

    # 4. Validate structured JSON types
    validated = False
    if dtype == "REMEDIATION_MANIFEST":
        _validate_list_json(content, "branches")
        validated = True

    # 5. Save the file
    try:
        deliverables_dir = os.path.join(_repo_root(), "deliverables")
        os.makedirs(deliverables_dir, exist_ok=True)
        # Also ensure the screenshots directory exists for agents that capture evidence
        os.makedirs(os.path.join(deliverables_dir, "screenshots"), exist_ok=True)

        dest = os.path.join(deliverables_dir, filename)
        with open(dest, "w") as f:
            f.write(content)

        print(json.dumps({"status": "success", "filepath": dest, "validated": validated}))
    except OSError as exc:
        _error(f"Failed to save: {exc}", retryable=True)


if __name__ == "__main__":
    main()
