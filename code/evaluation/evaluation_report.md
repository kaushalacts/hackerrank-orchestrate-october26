# Evaluation Report

Reproduce: `python3 code/evaluation/main.py --custom` (deterministic path, `--no-llm` gives identical numbers).

## Metrics

| Metric | Definition |
|---|---|
| Status accuracy | `deletion_status` exact match per case |
| Step precision / recall / F1 | a step = (phase, system_id, resource_id, operation, state, evidence_id); set overlap per case |
| Field accuracy | position-aligned comparison of all 7 step fields against gold |
| Sequence accuracy | share of cases whose whole `steps_json` array equals gold exactly (order included) |
| Resource discovery | share of gold resource_ids surfaced at all (identity resolution + discovery) |

## Results on the 32 public samples

| Subset | Cases | Status acc. | Step P | Step R | Step F1 | Field acc. | Sequence acc. | Discovery |
|---|---|---|---|---|---|---|---|---|
| All samples | 32 | **0.969** | 0.989 | 0.933 | 0.960 | 0.916 | 0.688 | 0.910 |
| Generated-style (case_11–32) | 22 | **1.000** | 0.994 | 0.988 | 0.991 | 0.970 | 0.864 | 0.978 |
| Hand-built (case_01–10) | 10 | 0.900 | 0.952 | 0.645 | 0.769 | 0.636 | 0.300 | 0.579 |

The 518 evaluation requests follow the generated style (cases cluster on evidence captures, workflow
activity around `reported_at`), so the case_11–32 row is the best estimate of hidden-set behaviour.

### Remaining sample errors (understood, not patched case-by-case)
- **case_18, case_20** — gold verifies an `audit_record_*` that appears in no participant-visible file or activity row. Not derivable; we do not invent ids.
- **case_17** — we additionally verify `tombstone_17` (catalog-linked, captured in a March screenshot; redacted). Kept because it is grounded evidence of a retained record.
- **case_01/02/04/06/07/08** — hand-built accounts (`account_00N`) are deleted at offsets outside the generator's window (e.g. +5 min after `reported_at`), so the workflow linker does not attribute them. Widening the window caused cross-case mis-attribution on generated cases, so it was rejected.
- **case_07** — the object-storage attachment (`object_19`) is reported in addition to `support_001`; gold treats only the support-platform copy as in scope at that audit time.
- **case_10** — a legacy contact-index row (`support_002`) is a secondary identifier that gold deletes; we treat it as a support message.

## Custom evaluation cases (5/5 pass)

Built as self-contained mini-datasets in `code/evaluation/custom_cases.py` and run through the real pipeline.

| # | Case | What it tests | Expected |
|---|---|---|---|
| 1 | Historical-email evidence | Request uses the current email; leftover search doc indexed under the *old* email from the audit log | INCOMPLETE: delete `search_9101`, keep audit record |
| 2 | Replica drift | Primary table clean, failover replica still holds the profile | INCOMPLETE: report + delete account |
| 3 | Post-audit evidence | A capture *after* `audit_at` shows the search doc back; at audit time it was gone | COMPLETE, cites only pre-audit evidence |
| 4 | Non-deletion request | Export request with "don't delete anything" while evidence shows live records | NOT_APPLICABLE, `[]` |
| 5 | Tombstone PII + active connector | Tombstone keeps `user_id` but still has email; connector enabled | Disable flow **before** redacting; verify both |

## Submission checks
`python3 code/evaluation/validate_output.py` → `rows=518 errors=0` (header, all case ids, consecutive
step numbers, phase order, op/state/phase consistency, cited evidence exists and is captured at/before
`audit_at`, future steps carry `""`).

## Failures found and improvements made

| Iteration | Failure observed | Change | Effect (all samples) |
|---|---|---|---|
| v1 | Baseline: identifier matching only | — | status 0.78, step F1 0.77, sequence 0.22 |
| v2 | 5 deletion requests flagged NOT_APPLICABLE ("still appears", "copy of my profile"); compliant records (404 accounts, anonymized analytics) never linked because they carry no identifier | Narrowed non-deletion patterns + LLM cross-check; workflow reconstruction from `system_activity.csv` around `reported_at` | status 0.91, step F1 0.85 |
| v3 | Tombstones read as absent (`account_status=DELETED`); an empty SQL inventory "proved" an account absent while a replica still had it; overlapping workflow windows mixed cases sharing a `reported_at` (~60% of cases share one) | Status field means absence only for profiles; empty captures prove nothing; per-activity cluster plausibility | status 0.97, step F1 0.93, sequence 0.50 |
| v4 | Same-type actions in a shared cluster attributed to the wrong case | Run fingerprint: downstream steps sit at fixed second-offsets from that run's profile deletion | step F1 0.94, sequence 0.63 |
| v5 | 404 lookups by email linked unrelated account ids; empty-listing snapshots overrode explicit observations | Empty lookups don't link (but rule the id out for others); implicit absence only without explicit observation | step F1 0.95, sequence 0.69 |
| v6 | Month-old screenshot (expired export) attached to a later case | Catalog-linked artifacts only speak for 14 days after capture | precision 0.989, step F1 0.96 |

## Known limitations
- OCR fallback is rule-based per console type; the VLM path is more robust but needs an API key.
- Workflow attribution can still be ambiguous when several same-type actions share a fingerprint; such actions are left unattributed rather than guessed.
- Category refinements (secondary identifiers inside analytics, attachment vs message) rely on event / field names.
