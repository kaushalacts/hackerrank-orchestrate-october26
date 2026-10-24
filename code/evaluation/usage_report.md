# Token Usage and Cost Report

Generated automatically by `code/main.py` for the final full-dataset run that produced `output.csv`.

- Requests processed: **518**
- Wall-clock time: **1.7s**
- Screenshot extraction mode counts: VLM=0, OCR fallback=11

| Provider | Model | Live calls | Cached calls | Input tokens | Output tokens | Total tokens | Est. cost (USD) |
|---|---|---|---|---|---|---|---|
| **All** | **overall** | **0** | **0** | **0** | **0** | **0** | **0.0000** |

- Average tokens per request: **0.0**
- Estimated cost per request: **$0.000000**

Token counts include cache hits (the tokens the call originally consumed), so the numbers describe
the full cost of producing the run from a cold cache. Pricing table lives in `ghostaudit/llm.py`.
If the table is empty, the run used the deterministic fallbacks only (no API key, empty cache).
