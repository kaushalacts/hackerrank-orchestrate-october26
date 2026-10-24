# Ghost Data Still Exists — Deletion Audit Agent

An evidence-grounded agent that decides, for every privacy request, whether a deletion is
`COMPLETE`, `INCOMPLETE` or `NOT_APPLICABLE`, and emits the ordered findings → remediation →
verification plan required by `problem_statement.md`.

## Run

```bash
# from the repository root; Python 3.10+, stdlib only
sudo apt-get install -y tesseract-ocr poppler-utils   # OCR + pdftotext (macOS: brew install tesseract poppler)

python3 code/main.py                          # -> ./output.csv  (+ code/evaluation/usage_report.md)
python3 code/evaluation/main.py --custom      # score vs dataset/sample_output.csv + custom cases
python3 code/evaluation/validate_output.py    # submission contract checks on ./output.csv
```

Optional LLM / VLM layer: `export ANTHROPIC_API_KEY=...` (never committed). Without a key every
LLM step falls back to a deterministic path, so the run is reproducible offline. `--no-llm` forces
the deterministic path. LLM responses are cached in `code/cache/llm_cache.json`.

## Architecture

```
dataset/ ──► EvidenceStore (ghostaudit/evidence.py)        one Observation per (evidence, resource)
              ├─ SQL snapshots   → sqlite in-memory, primary+replica rows merged (drift = still present)
              ├─ JSON exports    → recursive walker, any dict with a resource_id is a record
              ├─ text handovers  → "ts | system | id | type | result | subject" lines
              ├─ logs (6 styles) → key=value / JSON / bracket / pipe / syslog parsing, lines merged by trace_id
              ├─ PDFs            → pdftotext + catalog aliases (e.g. statement NST-… → export_1842)
              └─ screenshots     → Claude vision (JSON) or Tesseract OCR + console-specific rules
           IdentityIndex (identity.py)   current + historical email / phone / email-hash / user_id
           Auditor (auditor.py)
              1. scope:   evidence identifiers → user; catalog links; workflow reconstruction
              2. state:   latest observation at/before audit_at (later captures ignored);
                          complete primary-profile listings prove absence of unlisted accounts
              3. policy:  deletion_rules.csv → DELETE / REDACT / ANONYMIZE / RETAIN, plus flows & restores
              4. plan:    findings, remediation (flows/restores first), verification; spec ordering
           IntentClassifier (intent.py)  LLM + multilingual rules: does the text authorize deletion?
```

### Workflow reconstruction (the non-obvious part)
Records that are already compliant (404 accounts, anonymized analytics) carry no identifier, so the
only link to a case is the deletion workflow in `system_activity.csv`. Activity is attributed by:
1. timing relative to `reported_at` (profile deletion 40–80 min before; policy actions/checks −36…+125 min);
2. grounded links first (evidence identifiers, data-catalog links);
3. the reported status mirroring the profile-deletion result (COMPLETE↔SUCCESS, PARTIALLY_COMPLETE↔PARTIAL, NOT_STARTED↔FAILED);
4. a run fingerprint: each run's downstream steps sit at fixed second-offsets from its profile deletion.

Activity *results* are never used as proof of state — only to decide which resources belong to a case.
Reported statuses are claims; state always comes from captured evidence at/before `audit_at`.

## Layout
```
code/main.py                     pipeline entry point, usage-report writer
code/ghostaudit/                 identity, evidence, vision, intent, llm, auditor
code/evaluation/main.py          metrics vs labelled samples
code/evaluation/custom_cases.py  5 hand-built adversarial mini-datasets
code/evaluation/validate_output.py
code/evaluation/evaluation_report.md, usage_report.md
```
Prompts live in source: `ghostaudit/intent.py` (`INTENT_SYSTEM`) and `ghostaudit/vision.py` (`VISION_SYSTEM`, `VISION_PROMPT`).
No labels, case ids or file-specific answers are hardcoded.
