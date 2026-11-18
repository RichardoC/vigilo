"""Findings ledger — the shared, append-only record every white-box agent writes to.

Agents never hand-write result files. They call the ``vigilo-record`` command
(``scripts/vigilo_record.py``), which validates each record against the schemas
below and appends it to ``deliverables/ledger/``:

==============  ======================  ===========================================
record kind     file                    written by
==============  ======================  ===========================================
``lead``        ``leads.jsonl``         planner (and investigators that spot more)
``lead-done``   ``lead_status.jsonl``   investigators, when a lead is closed
``finding``     ``findings.jsonl``      investigators
``verdict``     ``verdicts.jsonl``      provers
``chain``       ``chains.jsonl``        provers (multi-step attacks)
==============  ======================  ===========================================

Every file is JSON Lines, append-only, and written under an exclusive ``flock``
so parallel agents in one container never corrupt each other's records. IDs
(``L-001``, ``VG-001``, ``CH-01``) are assigned under the same lock. A later
record with the same ID supersedes an earlier one, so agents can correct
themselves by re-recording.

``build_findings_index`` folds the ledger into the ``findings_index.json`` shape
that the review, remediation and reporting stages (and the web API's metrics)
already consume.

Duplicate guard. Parallel investigators can reach the same flaw through
different leads, so a new ``finding`` (or ``lead``) that clearly matches an
existing one is rejected with a problem that names the existing ID. The agent
either links to the existing record (``lead-done`` with ``finding_ids``) or
records the item again with ``"distinct_from": ["VG-003"]`` to say it is a
different flaw. See ``find_duplicate_finding`` and ``find_duplicate_lead`` for
the exact rules.

Validation is deliberately forgiving about *how* an agent words things and
strict only about what downstream code depends on: a missing title or an
unknown severity is rejected with a precise message the agent can act on; an
extra field is simply kept.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LEDGER_DIRNAME = "ledger"
EVIDENCE_DIRNAME = "evidence"

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")
LEAD_OUTCOMES = ("finding", "clean", "inconclusive", "out-of-scope")

# Open category vocabulary. Agents may use any of these; anything else is
# accepted and filed under "other" with the agent's label kept in
# ``category_label`` — the engine must never reject a real bug because it does
# not fit a box.
CATEGORIES = (
    "injection",
    "xss",
    "authentication",
    "authorization",
    "ssrf",
    "cryptography",
    "graphql",
    "websocket",
    "business-logic",
    "file-handling",
    "deserialization",
    "configuration",
    "information-disclosure",
    "other",
)

# Verdicts a prover can return, and how each maps onto the index status.
#   exploited      demonstrated end-to-end against the running target
#   confirmed      a source-level harness demonstrated it at the sink
#   blocked        real flaw, but a control stopped exploitation
#   not_testable   trace holds but no live/harness test was feasible
#   unreachable    the in-scope attacker cannot reach it
#   refuted        a test ran and the flaw did not reproduce
#   false_positive not a vulnerability on inspection
VERDICT_STATUS: dict[str, str] = {
    "exploited": "exploited",
    "confirmed": "potential",
    "blocked": "potential",
    "not_testable": "potential",
    "unreachable": "suppressed",
    "refuted": "suppressed",
    "false_positive": "suppressed",
}
SUPPRESSING_VERDICTS = frozenset(k for k, v in VERDICT_STATUS.items() if v == "suppressed")

_ID_PREFIX = {"lead": "L-", "finding": "VG-", "chain": "CH-"}
_ID_WIDTH = {"lead": 3, "finding": 3, "chain": 2}
_FILES = {
    "lead": "leads.jsonl",
    "lead-done": "lead_status.jsonl",
    "finding": "findings.jsonl",
    "verdict": "verdicts.jsonl",
    "chain": "chains.jsonl",
}
RECORD_KINDS = tuple(_FILES)


class LedgerError(ValueError):
    """A record failed validation. ``problems`` lists every issue found."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _text(rec: dict, key: str, problems: list[str], *, required: bool = True) -> None:
    val = rec.get(key)
    if val is None or (isinstance(val, str) and not val.strip()):
        if required:
            problems.append(f"'{key}' is required and must be a non-empty string")
        return
    if not isinstance(val, str):
        problems.append(f"'{key}' must be a string")


def _choice(rec: dict, key: str, allowed: tuple[str, ...], problems: list[str],
            *, required: bool = True, default: str | None = None) -> None:
    val = rec.get(key)
    if val is None:
        if default is not None:
            rec[key] = default
        elif required:
            problems.append(f"'{key}' is required: one of {', '.join(allowed)}")
        return
    norm = str(val).strip().lower()
    if key == "verdict":
        norm = norm.replace(" ", "_").replace("-", "_")
    else:
        norm = norm.replace(" ", "-").replace("_", "-")
    if norm not in allowed:
        problems.append(f"'{key}' must be one of {', '.join(allowed)} (got {val!r})")
    else:
        rec[key] = norm


def _str_list(rec: dict, key: str, problems: list[str]) -> None:
    val = rec.get(key)
    if val is None:
        return
    if isinstance(val, str):
        rec[key] = [val]
    elif not (isinstance(val, list) and all(isinstance(x, str) for x in val)):
        problems.append(f"'{key}' must be a list of strings")


def _location(rec: dict, problems: list[str]) -> None:
    loc = rec.get("location")
    if loc is None:
        problems.append(
            "'location' is required: {\"file\": \"path/in/repo\", \"line\": 42}"
            " (use the entry point file if the flaw spans several)"
        )
        return
    if isinstance(loc, str):  # "app/views.py:42"
        path, _, line = loc.partition(":")
        loc = {"file": path}
        if line.isdigit():
            loc["line"] = int(line)
        rec["location"] = loc
    if not isinstance(loc, dict) or not isinstance(loc.get("file"), str) or not loc["file"]:
        problems.append("'location.file' must be a repository-relative path")
        return
    if "line" in loc and loc["line"] is not None:
        try:
            loc["line"] = int(loc["line"])
        except (TypeError, ValueError):
            problems.append("'location.line' must be an integer")


def _validate_lead(rec: dict) -> list[str]:
    p: list[str] = []
    _text(rec, "title", p)
    _text(rec, "hypothesis", p)
    _str_list(rec, "files", p)
    _str_list(rec, "entry_points", p)
    _str_list(rec, "playbooks", p)
    _str_list(rec, "distinct_from", p)
    prio = rec.get("priority", 3)
    if not isinstance(prio, int) or not 1 <= prio <= 5:
        p.append("'priority' must be an integer from 1 (highest) to 5 (lowest)")
    else:
        rec["priority"] = prio
    return p


def _validate_lead_done(rec: dict) -> list[str]:
    p: list[str] = []
    _text(rec, "lead_id", p)
    _choice(rec, "outcome", LEAD_OUTCOMES, p)
    _str_list(rec, "finding_ids", p)
    return p


def _validate_finding(rec: dict) -> list[str]:
    p: list[str] = []
    _text(rec, "title", p)
    _text(rec, "description", p)
    _choice(rec, "severity", SEVERITIES, p)
    _choice(rec, "confidence", CONFIDENCES, p, default="medium")
    _location(rec, p)
    _str_list(rec, "preconditions", p)
    _str_list(rec, "attack_path", p)
    _str_list(rec, "distinct_from", p)
    cat = str(rec.get("category") or "other").strip().lower().replace(" ", "-")
    if cat not in CATEGORIES:
        rec["category_label"] = rec.get("category")
        cat = "other"
    rec["category"] = cat
    cwe = rec.get("cwe")
    if cwe is not None:
        m = re.fullmatch(r"(?:CWE-)?(\d{1,4})", str(cwe).strip(), re.IGNORECASE)
        if not m:
            p.append("'cwe' must look like 'CWE-89'")
        else:
            rec["cwe"] = f"CWE-{m.group(1)}"
    if "code_fixable" in rec and not isinstance(rec["code_fixable"], bool):
        p.append("'code_fixable' must be true or false")
    return p


def _validate_verdict(rec: dict) -> list[str]:
    p: list[str] = []
    _text(rec, "finding_id", p)
    _choice(rec, "verdict", tuple(VERDICT_STATUS), p)
    _text(rec, "summary", p)
    if rec.get("severity") is not None:
        _choice(rec, "severity", SEVERITIES, p)
    _str_list(rec, "screenshots", p)
    if rec.get("verdict") == "confirmed" and not str(rec.get("harness_path") or "").strip():
        p.append("'harness_path' is required for a 'confirmed' verdict "
                 "(the harness patch verification re-runs); use 'not_testable' if you have none")
    return p


def _validate_chain(rec: dict) -> list[str]:
    p: list[str] = []
    _text(rec, "title", p)
    _text(rec, "narrative", p)
    _choice(rec, "severity", SEVERITIES, p)
    _str_list(rec, "finding_ids", p)
    ids = rec.get("finding_ids")
    if isinstance(ids, list):
        # A chain combines distinct findings: repeating one ID is not a chain.
        ids = list(dict.fromkeys(i.strip() for i in ids if i.strip()))
        rec["finding_ids"] = ids
    if not isinstance(ids, list) or len(ids) < 2:
        p.append("'finding_ids' must list at least two different recorded findings")
    _choice(rec, "status", ("exploited", "potential"), p, default="potential")
    return p


# ---------------------------------------------------------------------------
# Duplicate detection
# ---------------------------------------------------------------------------

# Findings: two findings are duplicates when they are in the same file and
#   (a) same category and both lines are within LINE_WINDOW of each other, or
#   (b) same normalised sink text (at least 12 characters, so ``execute(q)``
#       style stubs do not match), regardless of category, and both lines
#       within SINK_LINE_WINDOW (when a line is missing the titles must also
#       match), or
#   (c) neither has a line, same category and the same normalised title.
# The windows are small on purpose: a flaw is normally reported at the sink
# statement, and two independent reports of it land on the same line or the
# few lines of one statement/call. Distinct bugs further apart (or in another
# category) are never blocked, and a real neighbour can always be recorded
# with ``distinct_from``.
LINE_WINDOW = 5
SINK_LINE_WINDOW = 30
_MIN_SINK_LEN = 12


def _norm_words(text: Any) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", str(text or "").lower()))


def _norm_file(path: Any) -> str:
    p = str(path or "").strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def _norm_sink(sink: Any) -> str:
    text = re.sub(r"[\w./-]+:\d+(?:-\d+)?", "", str(sink or ""))  # drop path:line refs
    return " ".join(re.sub(r"[()\[\]]*$", "", text.lower()).split())


def _cat_key(rec: dict) -> str:
    cat = str(rec.get("category") or "other")
    if cat == "other":
        return "other:" + _norm_words(rec.get("category_label"))
    return cat


def _describe_finding(f: dict) -> str:
    loc = f.get("location") or {}
    where = str(loc.get("file") or "?") + (f":{loc['line']}" if loc.get("line") else "")
    return f"{where}, {f.get('category', 'other')}"


def _findings_overlap(a: dict, b: dict) -> bool:
    la, lb = a.get("location") or {}, b.get("location") or {}
    fa, fb = _norm_file(la.get("file")), _norm_file(lb.get("file"))
    if not fa or fa != fb:
        return False
    na, nb = la.get("line"), lb.get("line")
    both_lines = isinstance(na, int) and isinstance(nb, int)
    same_cat = _cat_key(a) == _cat_key(b)
    if both_lines and same_cat and abs(na - nb) <= LINE_WINDOW:
        return True
    sa = _norm_sink(a.get("sink"))
    if len(sa) >= _MIN_SINK_LEN and sa == _norm_sink(b.get("sink")):
        # The same sink text filed under another category is the same flaw, but only
        # when both lines say so: with a line missing, the titles must match too.
        if both_lines and abs(na - nb) <= SINK_LINE_WINDOW:
            return True
        if not both_lines:
            t = _norm_words(a.get("title"))
            return bool(t) and t == _norm_words(b.get("title"))
    if not both_lines and same_cat:
        t = _norm_words(a.get("title"))
        return bool(t) and t == _norm_words(b.get("title"))
    return False


def find_duplicate_finding(rec: dict, existing: dict[str, dict]) -> str | None:
    """ID of the first recorded finding that ``rec`` duplicates, or None.

    Records named in ``rec['distinct_from']`` and a record with ``rec``'s own
    ``id`` (a correction) never match.
    """
    skip = set(rec.get("distinct_from") or []) | {str(rec.get("id") or "")}
    for fid, other in sorted(existing.items()):
        if fid not in skip and _findings_overlap(rec, other):
            return fid
    return None


# Leads: deliberately conservative, because a planner legitimately records
# many leads on one file. Two leads are duplicates only when
#   (a) their normalised titles are equal, or
#   (b) they share an entry point (method + path, parameter placeholders and
#       query strings ignored) AND name the same flaw class in title or
#       hypothesis (see _FLAW_CLASSES).
# Files alone never match, and neither do shared entry points with different
# flaw classes ("IDOR on PUT /p/{id}" vs "mass assignment on PUT /p/{id}").
_FLAW_CLASSES: dict[str, re.Pattern[str]] = {
    "sqli": re.compile(r"sql\s*injection|\bsqli\b|nosql"),
    "command-injection": re.compile(r"command injection|os command|shell injection|\brce\b|code execution"),
    "xss": re.compile(r"\bxss\b|cross[- ]site scripting"),
    "ssrf": re.compile(r"\bssrf\b|server[- ]side request"),
    "idor": re.compile(r"\bidor\b|object[- ]level|insecure direct object|\bbola\b"),
    "authorization": re.compile(r"authori[sz]ation|access control|privilege escalation|missing (?:permission|role|ownership)"),
    "authentication": re.compile(r"authentication|login|password|credential|brute[- ]force"),
    "session": re.compile(r"session|cookie|\bjwt\b|token"),
    "csrf": re.compile(r"\bcsrf\b|cross[- ]site request forgery"),
    "mass-assignment": re.compile(r"mass assignment|overposting"),
    "deserialization": re.compile(r"deseriali[sz]|pickle|unserialize"),
    "file-handling": re.compile(r"path traversal|file upload|\bupload\b|directory traversal|\blfi\b"),
    "xxe": re.compile(r"\bxxe\b|xml external"),
    "redirect": re.compile(r"open redirect"),
    "crypto": re.compile(r"cryptograph|weak hash|hard-?coded (?:key|secret)|\bcrypto\b"),
    "template-injection": re.compile(r"template injection|\bssti\b"),
    "info-disclosure": re.compile(r"information disclosure|info leak|data exposure|verbose error|stack trace"),
    "business-logic": re.compile(r"business logic|race condition|workflow|price|quota|rate limit"),
}


def _flaw_classes(rec: dict) -> set[str]:
    text = f"{rec.get('title', '')} {rec.get('hypothesis', '')}".lower()
    return {name for name, rx in _FLAW_CLASSES.items() if rx.search(text)}


def _norm_entry_point(ep: str) -> str:
    text = str(ep).strip().split("?", 1)[0]
    parts = text.split(None, 1)
    method, path = ("", text) if len(parts) == 1 else (parts[0].upper(), parts[1])
    if method and not method.isalpha():
        method, path = "", text
    path = re.sub(r"\{[^}]*\}|<[^>]*>|:\w+|\b\d+\b", "{}", path.strip().lower()).rstrip("/")
    return f"{method} {path}".strip()


def _lead_entry_points(rec: dict) -> set[str]:
    eps = {_norm_entry_point(e) for e in rec.get("entry_points") or [] if str(e).strip()}
    # a bare "/" or "{}" is too generic to identify anything
    return {e for e in eps if len(e.split()[-1]) > 2}


def _leads_overlap(a: dict, b: dict) -> bool:
    ta = _norm_words(a.get("title"))
    if ta and ta == _norm_words(b.get("title")):
        return True
    if _lead_entry_points(a) & _lead_entry_points(b):
        return bool(_flaw_classes(a) & _flaw_classes(b))
    return False


def find_duplicate_lead(rec: dict, existing: dict[str, dict]) -> str | None:
    """ID of the first recorded lead (open or closed) that ``rec`` duplicates."""
    skip = set(rec.get("distinct_from") or []) | {str(rec.get("id") or "")}
    for lid, other in sorted(existing.items()):
        if lid not in skip and _leads_overlap(rec, other):
            return lid
    return None


_VALIDATORS = {
    "lead": _validate_lead,
    "lead-done": _validate_lead_done,
    "finding": _validate_finding,
    "verdict": _validate_verdict,
    "chain": _validate_chain,
}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


REPO_ENV = "VIGILO_REPO_PATH"


class LedgerLocationError(ValueError):
    """The repository root (and so the ledger) could not be located."""


def find_repo_root(start: str | os.PathLike[str] | None = None,
                   env: dict[str, str] | None = None) -> Path:
    """Locate the repository root that owns the ledger, whatever the cwd is.

    Order: ``$VIGILO_REPO_PATH`` (must contain ``deliverables``); otherwise the
    nearest directory at or above *start* (default: cwd) that has a
    ``deliverables/ledger`` directory, or a ``deliverables`` directory/symlink
    next to ``.git``. Never invents a location: raises
    :class:`LedgerLocationError` so a command run from a sub-directory cannot
    quietly create a second ledger there.
    """
    environ = os.environ if env is None else env
    configured = (environ.get(REPO_ENV) or "").strip()
    if configured:
        root = Path(configured)
        if not (root / "deliverables").exists():
            raise LedgerLocationError(
                f"{REPO_ENV}={configured} has no deliverables/ directory")
        return root
    here = Path(start if start is not None else os.getcwd()).resolve()
    for d in (here, *here.parents):
        deliverables = d / "deliverables"
        if (deliverables / LEDGER_DIRNAME).is_dir() or (
                deliverables.exists() and (d / ".git").exists()):
            return d
    raise LedgerLocationError(
        f"cannot find the repository root from {here}: no deliverables/ledger or "
        f"deliverables/ next to .git in it or its parents. Run vigilo-record from "
        f"the repository root, or set {REPO_ENV}.")


@dataclass
class Ledger:
    """Read/write access to ``{deliverables}/ledger``."""

    deliverables_dir: Path

    @classmethod
    def for_repo(cls, repo_path: str | os.PathLike[str]) -> "Ledger":
        return cls(Path(repo_path) / "deliverables")

    @classmethod
    def discover(cls, start: str | os.PathLike[str] | None = None,
                 env: dict[str, str] | None = None) -> "Ledger":
        """The ledger of the repository containing *start* (see find_repo_root)."""
        return cls.for_repo(find_repo_root(start, env))

    @property
    def root(self) -> Path:
        return self.deliverables_dir / LEDGER_DIRNAME

    @property
    def evidence_dir(self) -> Path:
        return self.deliverables_dir / EVIDENCE_DIRNAME

    def path(self, kind: str) -> Path:
        return self.root / _FILES[kind]

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.root.mkdir(parents=True, exist_ok=True)
        with open(self.root / ".lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    # -- reading -------------------------------------------------------------

    def raw(self, kind: str) -> list[dict[str, Any]]:
        path = self.path(kind)
        if not path.is_file():
            return []
        out = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue  # a torn line never blocks the rest of the ledger
            if isinstance(rec, dict):
                out.append(rec)
        return out

    def current(self, kind: str, key: str = "id") -> dict[str, dict[str, Any]]:
        """Latest record per ``key`` (later records supersede earlier ones)."""
        out: dict[str, dict[str, Any]] = {}
        for rec in self.raw(kind):
            k = str(rec.get(key) or "")
            if k:
                out[k] = rec
        return out

    def leads(self) -> dict[str, dict[str, Any]]:
        return self.current("lead")

    def findings(self) -> dict[str, dict[str, Any]]:
        return self.current("finding")

    def verdicts(self) -> dict[str, dict[str, Any]]:
        return self.current("verdict", key="finding_id")

    def chains(self) -> dict[str, dict[str, Any]]:
        return self.current("chain")

    def lead_status(self) -> dict[str, dict[str, Any]]:
        return self.current("lead-done", key="lead_id")

    def open_leads(self) -> list[dict[str, Any]]:
        closed = self.lead_status()
        return sorted(
            (lead for lid, lead in self.leads().items() if lid not in closed),
            key=lambda lead: (lead.get("priority", 3), lead["id"]),
        )

    # -- writing -------------------------------------------------------------

    def _next_id(self, kind: str) -> str:
        prefix = _ID_PREFIX[kind]
        highest = 0
        for rec in self.raw(kind):
            m = re.fullmatch(re.escape(prefix) + r"(\d+)", str(rec.get("id", "")))
            if m:
                highest = max(highest, int(m.group(1)))
        return f"{prefix}{highest + 1:0{_ID_WIDTH[kind]}d}"

    def record(self, kind: str, rec: dict[str, Any], *, actor: str = "") -> dict[str, Any]:
        """Validate and append one record; returns it with its assigned ID."""
        if not isinstance(rec, dict):
            raise LedgerError(["the record must be a JSON object"])
        return self.record_many(kind, [rec], actor=actor)[0]

    def record_many(
        self,
        kind: str,
        items: list[Any],
        *,
        actor: str = "",
        evidence: str | None = None,
    ) -> list[dict[str, Any]]:
        """Validate and append several records of one kind, all or nothing.

        Every item is validated (including references to other records) under
        the ledger lock before anything is written. If any item is invalid,
        nothing is stored and :class:`LedgerError` lists every problem, prefixed
        ``item N:`` when there is more than one item, so the caller can fix the
        batch and send all of it again without creating duplicates.

        ``evidence`` (verdicts only) is written as each finding's evidence
        write-up once the whole batch is known to be valid, so a rejected
        verdict never overwrites or orphans an evidence file.
        """
        if kind not in _VALIDATORS:
            raise LedgerError([f"unknown record kind {kind!r}; use one of {', '.join(RECORD_KINDS)}"])
        if not items:
            raise LedgerError(["nothing to record: pass a JSON object or a non-empty array"])
        prefix = (lambda n: f"item {n}: ") if len(items) > 1 else (lambda n: "")
        problems: list[str] = []
        recs: list[dict[str, Any]] = []
        for n, item in enumerate(items, 1):
            if not isinstance(item, dict):
                problems.append(prefix(n) + "the record must be a JSON object")
                recs.append({})
                continue
            rec = dict(item)
            problems.extend(prefix(n) + p for p in _VALIDATORS[kind](rec))
            recs.append(rec)
        if problems:
            raise LedgerError(problems)
        with self._locked():
            findings = self.findings() if kind in ("verdict", "chain", "lead-done", "finding") else {}
            leads = self.leads() if kind in ("lead-done", "lead") else {}
            for n, rec in enumerate(recs, 1):
                if kind == "verdict" and rec["finding_id"] not in findings:
                    problems.append(prefix(n) + f"no recorded finding has id {rec['finding_id']!r}")
                if kind == "lead-done" and rec["lead_id"] not in leads:
                    problems.append(prefix(n) + f"no recorded lead has id {rec['lead_id']!r}")
                if kind == "lead-done":
                    unknown = [f for f in rec.get("finding_ids") or [] if f not in findings]
                    if unknown:
                        problems.append(prefix(n) + (
                            f"finding_ids names unknown findings: {', '.join(unknown)} "
                            "(any finding recorded by anyone is valid; check `vigilo-record show findings`)"))
                if kind == "chain":
                    missing = [f for f in rec["finding_ids"] if f not in findings]
                    if missing:
                        problems.append(prefix(n) + f"unknown finding ids in chain: {', '.join(missing)}")
            if kind in ("finding", "lead"):
                problems.extend(self._duplicate_problems(kind, recs, findings if kind == "finding" else leads, prefix))
            if problems:
                raise LedgerError(problems)
            if problems:
                raise LedgerError(problems)
            if kind == "verdict" and evidence is not None:
                for rec in recs:
                    rec["evidence_ref"] = self.save_evidence(rec["finding_id"], evidence)
            if kind in _ID_PREFIX:
                existing = self.current(kind)
                next_num = int(self._next_id(kind)[len(_ID_PREFIX[kind]):])
                for rec in recs:
                    if not rec.get("id") or str(rec["id"]) not in existing:
                        rec["id"] = f"{_ID_PREFIX[kind]}{next_num:0{_ID_WIDTH[kind]}d}"
                        next_num += 1
            lines = []
            for rec in recs:
                rec["recorded_at"] = _now()
                if actor:
                    rec.setdefault("recorded_by", actor)
                lines.append(json.dumps(rec, ensure_ascii=False) + "\n")
            with open(self.path(kind), "a", encoding="utf-8") as fh:
                fh.write("".join(lines))
        return recs

    def _duplicate_problems(self, kind: str, recs: list[dict], existing: dict[str, dict],
                            prefix) -> list[str]:
        """Check distinct_from references and duplicates against the ledger and the batch."""
        label, id_prefix = ("finding", "VG-") if kind == "finding" else ("lead", "L-")
        find = find_duplicate_finding if kind == "finding" else find_duplicate_lead
        overlap = _findings_overlap if kind == "finding" else _leads_overlap
        problems: list[str] = []
        for n, rec in enumerate(recs, 1):
            declared = rec.get("distinct_from") or []
            bad = [d for d in declared if d not in existing and not re.fullmatch(r"item (\d+)", d.strip())]
            bad += [d for d in declared if re.fullmatch(r"item (\d+)", d.strip())
                    and not 1 <= int(d.split()[1]) < n]
            if bad:
                problems.append(prefix(n) + (
                    f"'distinct_from' must list IDs of existing {label}s ({id_prefix}...), "
                    f"or 'item M' for an earlier item of this call; unknown: {', '.join(bad)}"))
                continue
            dup = find(rec, existing)
            if dup is not None:
                other = existing[dup]
                if kind == "finding":
                    seen = (f"{dup} ({_describe_finding(other)}) (findings match when they are in the "
                            "same file and share a category within 5 lines or the same sink text "
                            "within 30 lines)")
                    same = ("close your lead with `lead-done` and "
                            f"`finding_ids: [\"{dup}\"]` instead")
                else:
                    seen = f"{dup} ({other.get('title', '')!r})"
                    same = (f"do not record it; if it is covered by {dup} just carry on "
                            "(the planner or an investigator already owns it)")
                problems.append(prefix(n) + (
                    f"looks like {seen}. If it is the same {label}, {same}; if it is a "
                    f"different {label}, record it again with `\"distinct_from\": [\"{dup}\"]` "
                    f"and say why in the {'description' if kind == 'finding' else 'hypothesis'}."))
                continue
            skip = {d.strip() for d in declared}
            for m in range(1, n):
                if f"item {m}" not in skip and overlap(rec, recs[m - 1]):
                    problems.append(prefix(n) + (
                        f"duplicates item {m} of this same call. Merge them into one {label}, or if "
                        f"they are different add `\"distinct_from\": [\"item {m}\"]` to this item "
                        f"and explain the difference."))
                    break
        return problems

    def save_evidence(self, finding_id: str, markdown: str) -> str:
        """Write a finding's evidence write-up; returns the deliverables-relative path."""
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", finding_id)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        path = self.evidence_dir / f"{safe}.md"
        path.write_text(markdown, encoding="utf-8")
        return f"{EVIDENCE_DIRNAME}/{path.name}"


# ---------------------------------------------------------------------------
# Folding into findings_index.json
# ---------------------------------------------------------------------------


def _index_entry(finding: dict[str, Any], verdict: dict[str, Any] | None) -> dict[str, Any]:
    loc = finding.get("location") or {}
    entry: dict[str, Any] = {
        "ID": finding["id"],
        "title": finding.get("title", ""),
        "vulnerability_type": finding.get("category", "other"),
        "category": finding.get("category", "other"),
        "severity": str(finding.get("severity") or "medium").lower(),
        "confidence": finding.get("confidence", "medium"),
        "file": loc.get("file"),
        "line": loc.get("line"),
        "description": finding.get("description", ""),
        "code_fixable": bool(finding.get("code_fixable", True)),
        "status": "unconfirmed",
    }
    for key in ("cwe", "category_label", "entry_point", "source", "sink", "witness",
                "preconditions", "attack_path", "lead_id", "recorded_by", "distinct_from"):
        if finding.get(key) not in (None, "", []):
            entry[key] = finding[key]
    if verdict is not None:
        v = verdict["verdict"]
        entry["status"] = VERDICT_STATUS.get(v, "unconfirmed")
        entry["verdict"] = v
        entry["verdict_summary"] = verdict.get("summary", "")
        if v in SUPPRESSING_VERDICTS:
            entry["suppression_reason"] = verdict.get("summary") or v
        if v in ("confirmed", "refuted"):
            entry["harness_confirmed"] = v == "confirmed"
        for key in ("harness_path", "evidence_ref", "screenshots"):
            if verdict.get(key):
                entry[key] = verdict[key]
        if verdict.get("severity"):
            entry["severity_proven"] = verdict["severity"]
    return entry


def build_findings_index(ledger: Ledger) -> dict[str, Any]:
    """Fold the ledger into ``{"total_vulnerabilities": n, "by_type": {...}}``."""
    verdicts = ledger.verdicts()
    by_type: dict[str, list[dict[str, Any]]] = {}
    for fid, finding in sorted(ledger.findings().items()):
        entry = _index_entry(finding, verdicts.get(fid))
        by_type.setdefault(entry["category"], []).append(entry)

    chains = []
    for cid, chain in sorted(ledger.chains().items()):
        chains.append({
            "ID": cid,
            "title": chain.get("title", ""),
            "vulnerability_type": "chain",
            "severity": chain.get("severity", "high"),
            "status": chain.get("status", "potential"),
            "code_fixable": False,  # fixed by patching the component findings
            "chain_components": chain.get("finding_ids", []),
            "notes": chain.get("narrative", ""),
        })
    if chains:
        by_type["chain"] = chains

    total = sum(len(v) for v in by_type.values())
    return {"total_vulnerabilities": total, "by_type": by_type}


def coverage_summary(ledger: Ledger) -> dict[str, Any]:
    """Lead and verdict counts the workflow uses to decide on follow-up passes."""
    leads = ledger.leads()
    status = ledger.lead_status()
    findings = ledger.findings()
    verdicts = ledger.verdicts()
    return {
        "leads_total": len(leads),
        "leads_open": sum(1 for lid in leads if lid not in status),
        "findings_total": len(findings),
        "findings_unproven": sorted(fid for fid in findings if fid not in verdicts),
        "outcomes": {
            o: sum(1 for s in status.values() if s.get("outcome") == o) for o in LEAD_OUTCOMES
        },
    }
