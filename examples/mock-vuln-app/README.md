# Mock vulnerable app — Vigilo white-box smoke target

A tiny, intentionally-insecure Flask app used to smoke-test the white-box
pipeline (and, specifically, the false-positive-reduction work on the
`fp-reduction` branch). **Never deploy this.**

## What it plants

| Kind | Where | Expected pipeline outcome |
|------|-------|---------------------------|
| SQL injection | `app.py` `/user` | True positive — Injection, exploited/potential |
| Command injection | `app.py` `/ping` | True positive — Injection, exploited/potential |
| SSRF | `app.py` `/fetch` | True positive — SSRF |
| Weak password hash (MD5) | `app.py` `hash_password` | True positive — Cryptography (analysis-only) |
| Debug route gated off by default | `app.py` `/debug` | **Noise** — should be conditional / hardening (reachability `mitigated_by_deployment`), not a live critical |
| Hardcoded credential in a test | `tests/test_smoke.py` | **Noise** — should be demoted (test fixture, not a prod secret) |

The two "noise" items are the interesting ones: a pre-`fp-reduction` run tended
to report them as high/critical findings. After the change, the critic should
mark them `include_in_report=false` (with a logged reason) so they land in the
Hardening appendix, not the headline count.

## Run Vigilo against it

With the web platform running (see the main README), package the app and upload it:

```bash
cd examples && zip -r mock-vuln-app.zip mock-vuln-app
```

In the UI, create a repository from `mock-vuln-app.zip`, then create a job for it and run it —
code-only, or with a target URL if you serve the app (`python app.py`, port 5000). Follow the
run on its page; the report and the files below are available from the run's artifacts.

## What to check after a run (the FP-reduction acceptance signals)

- `findings_critique.json` — every finding annotated; `group_id` collapses
  duplicates; the `/debug` and test-fixture findings have `include_in_report=false`.
- `findings_critique_audit.json` — `ok: true` (no un-annotated findings, no
  recall-floor violations). If `missing_annotations` is non-empty, the report
  still includes those findings (recovery path).
- `comprehensive_security_assessment_report.md` — the real injection/SSRF bugs
  are in the body; the debug/test noise is in the Hardening appendix; the
  headline severity counts reflect the critique, not raw pre-critique severities.
- No `report_stats.json` is produced (it was removed; the critique is the source
  of truth).
