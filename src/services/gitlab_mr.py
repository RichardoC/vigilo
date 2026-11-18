"""GitLab Merge Request creation for remediation patches.

After the remediation agent creates fix/* branches and git_push.py pushes them
to the remote (deterministically, after verification), this service creates one MR per
fix branch. A branch may fix several findings (``fix/VG-001-VG-002``; the manifest's
``finding_ids`` say which), so the MR describes every finding it covers, from the
findings ledger index: category, location, source/sink, attack path, verdict and the
evidence write-up. The GitLab instance and project come from the repository record
(``remote_url``, platform input), never from files in the checkout.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import asyncio
from pathlib import Path
from typing import Any

from src.audit.redact import redact

logger = logging.getLogger(__name__)

def _extract_project_path(remote_url: str) -> str:
    """Extract GitLab project path from remote URL.

    Handles both SSH and HTTPS formats:
      git@gitlab.example.com:group/project.git -> group/project
      https://gitlab.example.com/group/project.git -> group/project
    """
    ssh_match = re.match(r"git@[^:]+:(.+?)(?:\.git)?$", remote_url)
    if ssh_match:
        return ssh_match.group(1)

    parsed = urllib.parse.urlparse(remote_url)
    path = parsed.path.lstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    return path


def _https_remote(remote_url: str) -> str:
    """Remote URL as a credential-free https URL (ssh ``git@host:path`` converted)."""
    remote_url = remote_url.strip()
    ssh = re.match(r"^(?:ssh://)?git@([^:/]+)[:/](.+)$", remote_url)
    if ssh:
        return f"https://{ssh.group(1)}/{ssh.group(2)}"
    parsed = urllib.parse.urlparse(remote_url)
    host = parsed.hostname or ""
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return urllib.parse.urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))


def resolve_gitlab_target(remote_url: str, base_hint: str | None = None) -> tuple[str, str]:
    """Return ``(api_base_url, project_path)`` for a repository remote.

    The API base is derived from the remote itself (``scheme://host[:port]``).
    ``base_hint`` — the optional ``gitlab_url`` of the run's push settings, else
    the ``GITLAB_URL`` environment variable — is only used when the remote lives
    under it (GitLab served from a sub-path, ``https://host/gitlab``) or when the
    remote has no host to derive from.
    """
    remote = _https_remote(remote_url)
    hint = (base_hint or os.environ.get("GITLAB_URL", "")).strip().rstrip("/")
    if hint and remote.startswith(hint + "/"):
        return hint, _extract_project_path(remote[len(hint):])
    parsed = urllib.parse.urlparse(remote)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}", _extract_project_path(remote)
    if hint:
        return hint, _extract_project_path(remote)
    raise ValueError("cannot determine the GitLab instance from the repository remote")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Treat 3xx as an error (HTTPError) instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


# No proxies from the environment either: the token must only go where the URL says.
_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def _gitlab_api_request(
    gitlab_url: str,
    token: str,
    method: str,
    endpoint: str,
    data: dict | None = None,
) -> dict:
    """Make a GitLab REST API request."""
    url = f"{gitlab_url}/api/v4{endpoint}"
    headers = {
        "PRIVATE-TOKEN": token,
        "Content-Type": "application/json",
    }

    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with _NO_REDIRECT_OPENER.open(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            # Never follow a redirect: it would replay PRIVATE-TOKEN to another host.
            raise RuntimeError(
                f"GitLab API answered with a redirect (HTTP {exc.code}); refusing to follow it"
            ) from exc
        error_body = exc.read().decode("utf-8", errors="replace")
        logger.error("GitLab API error %d: %s", exc.code, error_body)
        raise RuntimeError(f"GitLab API error {exc.code}: {error_body}") from exc


def _get_default_branch_from_api(
    gitlab_url: str, token: str, project_path_encoded: str
) -> str:
    """Query GitLab API for the project's default branch."""
    try:
        project_info = _gitlab_api_request(
            gitlab_url, token, "GET",
            f"/projects/{project_path_encoded}",
        )
        return project_info.get("default_branch", "main")
    except Exception as exc:
        logger.warning("Could not query default branch from API: %s", exc)
        return "main"


# ---------------------------------------------------------------------------
# Finding context for MR descriptions (findings_index.json written from the ledger)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_STATUS_LABEL = {
    "exploited": "Exploited (proven)",
    "potential": "Potential",
    "unconfirmed": "Unconfirmed",
    "suppressed": "Suppressed by review",
}
_EVIDENCE_MAX = 5000


def _load_findings_index(repo_path: str) -> dict[str, Any]:
    """Load findings_index.json if it exists."""
    path = Path(repo_path) / "deliverables" / "findings_index.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _find_vuln_in_index(index: dict[str, Any], vuln_id: str) -> dict[str, Any] | None:
    """Find a specific finding in the index (``by_type`` -> list of entries)."""
    for vulns in (index.get("by_type") or {}).values():
        for vuln in vulns or []:
            vid = vuln.get("ID", vuln.get("id", ""))
            if str(vid).upper() == vuln_id.upper():
                return vuln
    return None


def _manifest_finding_ids(repo_path: str) -> dict[str, list[str]]:
    """``{branch: [finding ids]}`` from remediation_manifest.json."""
    path = Path(repo_path) / "deliverables" / "remediation_manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out: dict[str, list[str]] = {}
    for entry in (manifest.get("branches") or []) if isinstance(manifest, dict) else []:
        if isinstance(entry, dict) and entry.get("branch"):
            ids = [str(i) for i in (entry.get("finding_ids") or []) if i]
            out[str(entry["branch"])] = ids
    return out


def _branch_finding_ids(
    branch: str, manifest_ids: dict[str, list[str]], index: dict[str, Any],
) -> list[str]:
    """The findings a fix branch covers: the manifest's ``finding_ids``; else the IDs
    in the branch name that exist in the index (``fix/VG-001-VG-002``); else the whole
    name (legacy ``fix/AUTH-VULN-01``)."""
    ids = manifest_ids.get(branch)
    if ids:
        return ids
    name = branch.removeprefix("fix/")
    known = [
        part for part in re.findall(r"[A-Za-z]+-\d+", name)
        if _find_vuln_in_index(index, part) is not None
    ]
    return known or [name]


def _category_label(entry: dict[str, Any] | None, fallback: str = "Security") -> str:
    """The ledger's human label (verbatim), else the category id made readable."""
    if not entry:
        return fallback
    if entry.get("category_label"):
        return str(entry["category_label"]).strip()
    raw = entry.get("category") or entry.get("vulnerability_type")
    return str(raw).replace("_", " ").replace("-", " ").strip().title() if raw else fallback


def _severity(entry: dict[str, Any] | None) -> str:
    sev = str((entry or {}).get("severity_proven") or (entry or {}).get("severity") or "").lower()
    return sev if sev in _SEVERITY_ORDER else ""


def _read_evidence(repo_path: str, vuln_id: str, entry: dict[str, Any] | None) -> str:
    """The finding's evidence write-up: ``deliverables/evidence/<id>.md`` (or the
    verdict's ``evidence_ref``), else its section of a legacy
    ``<category>_exploitation_evidence.md``."""
    deliverables = Path(repo_path) / "deliverables"
    try:
        from src.services.report_ledger import _read_evidence as ledger_evidence

        text = ledger_evidence(deliverables, vuln_id, entry or {})
    except Exception:  # noqa: BLE001
        text = None
    if not text:
        category = str((entry or {}).get("category") or (entry or {}).get("vulnerability_type") or "")
        for name in ([f"{category}_exploitation_evidence.md"] if category else []):
            path = deliverables / name
            try:
                if not path.resolve().is_relative_to(deliverables.resolve()):
                    continue
                content = path.read_text(encoding="utf-8")
            except OSError:
                continue
            m = re.search(
                rf"(###?\s+[^\n]*{re.escape(vuln_id)}[^\n]*\n)(.*?)(?=\n###?\s|\n---|\Z)",
                content, re.DOTALL | re.IGNORECASE,
            )
            if m:
                text = (m.group(1) + m.group(2)).strip()
                break
    if text and len(text) > _EVIDENCE_MAX:
        text = text[:_EVIDENCE_MAX] + "\n\n... *(truncated)*"
    return text or ""


def _find_screenshots(repo_path: str, vuln_id: str, entry: dict[str, Any] | None = None) -> list[Path]:
    """Screenshots of a finding: those the verdict lists, else files whose name carries
    the COMPLETE finding id (``VG-001`` / ``vg_001``), never a bare number."""
    shots_dir = Path(repo_path) / "deliverables" / "screenshots"
    if not shots_dir.is_dir():
        return []
    found: list[Path] = []
    for ref in (entry or {}).get("screenshots") or []:
        p = (Path(repo_path) / "deliverables" / str(ref))
        if not p.is_file():
            p = shots_dir / Path(str(ref)).name
        try:
            if p.is_file() and p.resolve().is_relative_to(shots_dir.resolve()):
                found.append(p)
        except OSError:
            continue
    if found:
        return found
    pattern = re.compile(
        r"(?<![A-Za-z0-9])" + re.escape(vuln_id).replace(r"\-", "[-_]") + r"(?![0-9])", re.IGNORECASE,
    )
    return [img for img in sorted(shots_dir.glob("*.png")) if pattern.search(img.stem)]


def _finding_section(repo_path: str, vuln_id: str, entry: dict[str, Any] | None) -> str:
    """Markdown for one finding."""
    lines: list[str] = []
    if not entry:
        lines.append(f"### `{vuln_id}`\n\nNo details were recorded for this finding.")
        return "\n".join(lines)

    title = entry.get("title") or ""
    lines.append(f"### `{vuln_id}`" + (f": {title}" if title else ""))
    sev = _severity(entry)
    status = str(entry.get("status") or "unconfirmed")
    rows = [
        ("Severity", sev.capitalize() if sev else "unknown"),
        ("Status", _STATUS_LABEL.get(status, status)),
        ("Category", _category_label(entry)),
    ]
    if entry.get("cwe"):
        rows.append(("CWE", str(entry["cwe"])))
    if entry.get("confidence"):
        rows.append(("Confidence", str(entry["confidence"])))
    if entry.get("file"):
        loc = f"{entry['file']}:{entry['line']}" if entry.get("line") else str(entry["file"])
        rows.append(("Location", f"`{loc}`"))
    for key, label in (("entry_point", "Entry point"), ("source", "Source"), ("sink", "Sink")):
        if entry.get(key):
            rows.append((label, f"`{str(entry[key]).replace('`', chr(39))}`"))
    if entry.get("verdict"):
        rows.append(("Verdict", str(entry["verdict"])))
    lines.append("\n| Property | Value |\n|----------|-------|\n" + "\n".join(
        f"| **{k}** | {v} |" for k, v in rows
    ))
    if entry.get("description"):
        lines.append(f"\n**Root cause.** {entry['description']}")
    if entry.get("attack_path"):
        ap = entry["attack_path"]
        ap = ap if isinstance(ap, str) else json.dumps(ap, ensure_ascii=False, indent=2)
        lines.append(f"\n**Attack path.** {ap}")
    if entry.get("verdict_summary"):
        lines.append(f"\n**Verification.** {entry['verdict_summary']}")
    if entry.get("harness_path"):
        lines.append(f"\nConfirmation harness: `{entry['harness_path']}`")

    evidence = _read_evidence(repo_path, vuln_id, entry)
    if evidence:
        lines.append(
            "\n<details>\n<summary>Evidence</summary>\n\n" + evidence + "\n\n</details>"
        )
    shots = _find_screenshots(repo_path, vuln_id, entry)
    if shots:
        lines.append("\n**Screenshots:** " + ", ".join(f"`{s.name}`" for s in shots))
    return "\n".join(lines)


def _build_mr_title(branch: str, ids: list[str], entries: list[dict[str, Any] | None]) -> str:
    sevs = [_severity(e) for e in entries if _severity(e)]
    sev = min(sevs, key=_SEVERITY_ORDER.index) if sevs else ""
    prefix = f"[{sev.upper()}] " if sev else ""
    cats = []
    for e in entries:
        if e:
            label = _category_label(e)
            if label not in cats:
                cats.append(label)
    if len(ids) == 1:
        e = entries[0]
        what = (e or {}).get("title") or (f"{cats[0]} vulnerability" if cats else "vulnerability")
        title = f"{prefix}Fix {ids[0]}: {what}"
    else:
        what = ", ".join(cats[:3]) if cats else "security"
        title = f"{prefix}Fix {', '.join(ids[:4])}{' and more' if len(ids) > 4 else ''}: {what} vulnerabilities"
    return title if len(title) <= 200 else title[:197] + "..."


def _build_mr_description(
    repo_path: str, branch: str, ids: list[str], session_id: str,
    entries: list[dict[str, Any] | None],
) -> str:
    """MR description for one fix branch covering ``ids``."""
    sections = [
        f"## Security fix: {', '.join(f'`{i}`' for i in ids)}\n",
        f"Automated security patch generated by **Vigilo**.\n\n"
        f"**Branch:** `{branch}`  \n**Session:** `{session_id}`",
    ]
    for vuln_id, entry in zip(ids, entries):
        sections.append("\n" + _finding_section(repo_path, vuln_id, entry))
    sections.append("\n---\n\n*Generated by Vigilo security scanner*")
    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def create_remediation_mrs(
    repo_path: str,
    session_id: str,
    pushed_branches: list[str],
    *,
    token: str,
    remote_url: str,
) -> dict[str, Any]:
    """Create one GitLab MR per pushed fix branch.

    ``token`` is the run's GitLab credential (redeemed just in time by the caller);
    ``remote_url`` is the repository's remote from the platform (the GitLab instance
    and project path are derived from it, see :func:`resolve_gitlab_target`).

    Each MR targets the default branch and describes every finding the branch fixes.
    The blocking HTTP calls run in a thread so the activity keeps heartbeating.

    Returns ``{"created": [{"branch", "mr_url", "mr_iid", "finding_ids"}], "failed":
    [{"branch", "error"}], "total": n}``.
    """
    if not pushed_branches:
        logger.info("No pushed branches — skipping MR creation")
        return {"created": [], "failed": [], "total": 0}
    if not remote_url:
        raise RuntimeError("no repository remote URL — cannot determine the GitLab project")

    gitlab_url, project_path = resolve_gitlab_target(remote_url)
    project_path_encoded = urllib.parse.quote(project_path, safe="")

    default_branch = await asyncio.to_thread(
        _get_default_branch_from_api, gitlab_url, token, project_path_encoded
    )
    index = _load_findings_index(repo_path)
    manifest_ids = _manifest_finding_ids(repo_path)

    created: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    for branch in pushed_branches:
        ids = _branch_finding_ids(branch, manifest_ids, index)
        entries = [_find_vuln_in_index(index, i) for i in ids]
        title = _build_mr_title(branch, ids, entries)
        description = _build_mr_description(repo_path, branch, ids, session_id, entries)
        # Evidence write-ups may quote the run's cookie (curl -H 'Cookie: ...'): mask
        # every registered secret in what leaves the platform.
        title, description = redact(title), redact(description)
        try:
            mr_data = await asyncio.to_thread(
                _gitlab_api_request, gitlab_url, token, "POST",
                f"/projects/{project_path_encoded}/merge_requests",
                {
                    "source_branch": branch,
                    "target_branch": default_branch,
                    "title": title,
                    "description": description,
                    "remove_source_branch": True,
                    "labels": "security,vigilo,automated",
                },
            )
            mr_url = mr_data.get("web_url", "")
            mr_iid = mr_data.get("iid", 0)
            created.append({"branch": branch, "finding_ids": ids, "mr_url": mr_url, "mr_iid": mr_iid})
            logger.info("Created MR !%s for %s: %s", mr_iid, branch, mr_url)
        except Exception as exc:  # noqa: BLE001
            failed.append({"branch": branch, "finding_ids": ids,
                           "error": str(exc).replace(token, "<token>")[:500]})
            logger.warning("Failed to create MR for %s: %s", branch, str(exc).replace(token, "<token>"))

    logger.info("MR creation complete: %d created, %d failed out of %d branches",
                len(created), len(failed), len(pushed_branches))
    return {"created": created, "failed": failed, "total": len(pushed_branches)}
