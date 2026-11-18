#!/usr/bin/env python3
"""vigilo-record — how white-box agents write to, and read from, the findings ledger.

Run from the repository root. The ledger is located from $VIGILO_REPO_PATH, or by
searching upward from the working directory, so a stray `cd` into a sub-directory
still reaches the one ledger; if none is found the command fails (it never creates
a ledger elsewhere).

Record (the JSON can be passed inline, from a file, or on stdin):

    vigilo-record lead      --json '{"title": "...", "hypothesis": "...", "priority": 2}'
    vigilo-record finding   --file /tmp/finding.json
    vigilo-record verdict   --json '{"finding_id": "VG-004", "verdict": "exploited", ...}' \
                            --evidence-file /tmp/VG-004.md
    vigilo-record lead-done --json '{"lead_id": "L-007", "outcome": "clean", "notes": "..."}'
    vigilo-record chain     --json '{"title": "...", "finding_ids": ["VG-002", "VG-005"], ...}'

A JSON array records several items of one kind in one call, all or nothing.
Each call prints one JSON object: ``{"status": "ok", "ids": [...]}`` or
``{"status": "invalid", "problems": [...]}`` (exit code 1). An invalid call
stores nothing (not even the ``--evidence-file`` write-up): fix every listed
problem (``item N:`` names the array element) and send the whole call again.

A new finding (or lead) that clearly matches an existing one is rejected with a
problem naming the existing ID, for example "looks like VG-003 (app.py:38,
injection)". Same flaw: link to it (``lead-done`` with ``finding_ids``). Different
flaw: record it again with ``"distinct_from": ["VG-003"]``.

Read:

    vigilo-record show leads [--open] [--mine L-003,L-004]
    vigilo-record show findings [--unproven]
    vigilo-record show finding VG-004
    vigilo-record show chains
    vigilo-record show summary
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# The command is installed as a symlink on PATH; resolve it so the project
# package is importable no matter where it is invoked from.
_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.pipeline.ledger import (  # noqa: E402
    RECORD_KINDS,
    Ledger,
    LedgerError,
    LedgerLocationError,
    find_repo_root,
    build_findings_index,
    coverage_summary,
)


def _emit(payload: dict, code: int = 0) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    sys.exit(code)


def _ledger() -> Ledger:
    try:
        return Ledger.discover()
    except LedgerLocationError as exc:
        _emit({"status": "invalid", "problems": [str(exc)]}, 1)
    raise AssertionError  # unreachable


def _inside_cwd(path: str) -> str:
    resolved = os.path.realpath(path)
    repo = os.path.realpath(str(find_repo_root()))
    roots = (
        repo,
        os.path.realpath("/tmp"),
        # deliverables/ may be a symlink to the run's output directory
        os.path.realpath(os.path.join(repo, "deliverables")),
    )
    if not any(resolved.startswith(r + os.sep) for r in roots):
        _emit({"status": "invalid", "problems": [
            f"{path} must be inside the repository, /tmp or deliverables/"]}, 1)
    return resolved


def _load_payload(args: argparse.Namespace) -> object:
    if args.json is not None:
        text = args.json
    elif args.file is not None:
        with open(_inside_cwd(args.file), encoding="utf-8") as fh:
            text = fh.read()
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        _emit({"status": "invalid", "problems": ["pass the record with --json, --file or stdin"]}, 1)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        _emit({"status": "invalid", "problems": [f"not valid JSON: {exc}"]}, 1)
    return None  # unreachable


def _record(args: argparse.Namespace) -> None:
    ledger = _ledger()
    payload = _load_payload(args)
    items = payload if isinstance(payload, list) else [payload]
    actor = os.environ.get("VIGILO_AGENT", "")
    evidence = None
    if getattr(args, "evidence_file", None):
        try:
            with open(_inside_cwd(args.evidence_file), encoding="utf-8") as fh:
                evidence = fh.read()
        except OSError as exc:
            _emit({"status": "invalid", "problems": [
                f"cannot read --evidence-file {args.evidence_file}: {exc.strerror or exc}"]}, 1)
    # All or nothing: either every item is stored, or none is and the problems
    # are listed (``item N:`` per array element), so the whole call can be
    # fixed and sent again without duplicating anything.
    try:
        recs = ledger.record_many(args.kind, items, actor=actor, evidence=evidence)
    except LedgerError as exc:
        _emit({"status": "invalid", "problems": exc.problems}, 1)
    _emit({"status": "ok",
           "ids": [str(r.get("id") or r.get("finding_id") or r.get("lead_id")) for r in recs]})


def _show(args: argparse.Namespace) -> None:
    ledger = _ledger()
    what = args.what
    if what == "leads":
        leads = ledger.open_leads() if args.open else sorted(
            ledger.leads().values(), key=lambda lead: lead["id"])
        if args.mine:
            wanted = {x.strip() for x in args.mine.split(",") if x.strip()}
            leads = [lead for lead in leads if lead["id"] in wanted]
        _emit({"leads": leads, "status_by_lead": ledger.lead_status()})
    if what == "findings":
        verdicts = ledger.verdicts()
        findings = [
            {**f, "verdict": verdicts.get(fid, {}).get("verdict")}
            for fid, f in sorted(ledger.findings().items())
            if not args.unproven or fid not in verdicts
        ]
        _emit({"findings": findings})
    if what == "chains":
        _emit({"chains": [c for _, c in sorted(ledger.chains().items())]})
    if what == "finding":
        if not args.id:
            _emit({"status": "invalid", "problems": ["give the finding id"]}, 1)
        finding = ledger.findings().get(args.id)
        if finding is None:
            _emit({"status": "invalid", "problems": [f"no finding {args.id}"]}, 1)
        _emit({"finding": finding, "verdict": ledger.verdicts().get(args.id)})
    if what == "summary":
        _emit({"coverage": coverage_summary(ledger),
               "index_total": build_findings_index(ledger)["total_vulnerabilities"]})


def main() -> None:
    parser = argparse.ArgumentParser(prog="vigilo-record", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="kind", required=True)
    for kind in RECORD_KINDS:
        p = sub.add_parser(kind, help=f"record a {kind}")
        p.add_argument("--json", help="the record (or an array of records) as JSON")
        p.add_argument("--file", help="read the JSON from this file")
        if kind == "verdict":
            p.add_argument("--evidence-file",
                           help="markdown write-up of how the verdict was reached")
        p.set_defaults(func=_record)
    show = sub.add_parser("show", help="read the ledger")
    show.add_argument("what", choices=("leads", "findings", "finding", "chains", "summary"))
    show.add_argument("id", nargs="?")
    show.add_argument("--open", action="store_true", help="only leads not yet closed")
    show.add_argument("--mine", help="comma-separated lead ids to show")
    show.add_argument("--unproven", action="store_true", help="only findings without a verdict")
    show.set_defaults(func=_show)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
