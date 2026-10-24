"""Ghost Data Still Exists - deletion audit agent.

Usage (from repo root):
    python3 code/main.py                       # audits dataset/deletion_requests.csv -> ./output.csv
    python3 code/main.py --requests dataset/sample_deletion_requests.csv --out /tmp/sample_pred.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from ghostaudit.auditor import Auditor, load_rules, serialize  # noqa: E402
from ghostaudit.evidence import EvidenceStore  # noqa: E402
from ghostaudit.identity import IdentityIndex  # noqa: E402
from ghostaudit.intent import IntentClassifier  # noqa: E402
from ghostaudit.llm import LLM, USAGE  # noqa: E402
from ghostaudit.vision import Vision  # noqa: E402


def case_key(cid: str):
    head, _, num = cid.rpartition("_")
    return (head, int(num)) if num.isdigit() else (cid, 0)


class Pipeline:
    def __init__(self, dataset_dir: str, use_llm: bool = True):
        self.dataset_dir = dataset_dir
        self.llm = LLM(os.path.join(HERE, "cache", "llm_cache.json")) if use_llm else None
        self.ids = IdentityIndex(os.path.join(dataset_dir, "user_identities.csv"),
                                 os.path.join(dataset_dir, "user_audit_log.csv"))
        # catalog links/aliases come from the activity stream and help screenshot reading
        pre = EvidenceStore.__new__(EvidenceStore)
        pre.dataset_dir = dataset_dir
        pre.catalog_links, pre.aliases, pre.catalog_times = {}, {}, {}
        pre._load_activity()
        self.vision = Vision(self.llm, pre.aliases, pre.catalog_links)
        self.store = EvidenceStore(dataset_dir, vision=self.vision)
        self.rules = load_rules(os.path.join(dataset_dir, "deletion_rules.csv"))
        reqs = []
        for name in ("deletion_requests.csv", "sample_deletion_requests.csv"):
            fp = os.path.join(dataset_dir, name)
            if os.path.exists(fp):
                reqs += list(csv.DictReader(open(fp, encoding="utf-8")))
        self.auditor = Auditor(self.store, self.ids, self.rules, reqs)
        from ghostaudit.intent import rule_intent
        self.auditor.build_workflow_links(lambda r: rule_intent(r["request_text"]))
        self.intent = IntentClassifier(self.llm)

    def audit(self, req: dict) -> tuple[str, list[dict], dict]:
        trace = {"case_id": req["case_id"]}
        if not self.intent.is_deletion(req["case_id"], req["request_text"]):
            trace["reason"] = "non-deletion request"
            return "NOT_APPLICABLE", [], trace
        uid = self.ids.resolve_email(req["email"])
        trace["user_id"] = uid
        if uid is None:
            trace["reason"] = "identity not resolved"
            return "INCOMPLETE", [], trace
        ok, f, r, v, states = self.auditor.plan(uid, req["audit_at"], req["case_id"])
        status = "COMPLETE" if ok else "INCOMPLETE"
        if not states:
            trace["reason"] = "no evidence linked"
        trace["resources"] = [(s.system, s.resource_id, s.category, s.state, s.evidence_id, s.observed_at)
                              for s in states]
        return status, serialize(status, f, r, v), trace

    def run(self, requests_csv: str, out_csv: str, trace_path: str | None = None):
        reqs = list(csv.DictReader(open(requests_csv, encoding="utf-8")))
        reqs.sort(key=lambda r: case_key(r["case_id"]))
        rows, traces = [], []
        for req in reqs:
            status, steps, trace = self.audit(req)
            rows.append((req["case_id"], status, json.dumps(steps, ensure_ascii=False, separators=(",", ":"))))
            traces.append(trace)
        with open(out_csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["case_id", "deletion_status", "steps_json"])
            w.writerows(rows)
        if trace_path:
            json.dump(traces, open(trace_path, "w", encoding="utf-8"), indent=1, default=list)
        return rows


def write_usage_report(path: str, n_requests: int, elapsed: float, vision_modes: dict):
    lines = ["# Token Usage and Cost Report", "",
             "Generated automatically by `code/main.py` for the final full-dataset run that produced `output.csv`.", "",
             f"- Requests processed: **{n_requests}**", f"- Wall-clock time: **{elapsed:.1f}s**",
             f"- Screenshot extraction mode counts: VLM={vision_modes.get('vlm', 0)}, OCR fallback={vision_modes.get('ocr', 0)}",
             "", "| Provider | Model | Live calls | Cached calls | Input tokens | Output tokens | Total tokens | Est. cost (USD) |",
             "|---|---|---|---|---|---|---|---|"]
    tot = {"calls": 0, "cached": 0, "in": 0, "out": 0, "cost": 0.0}
    for model, m in sorted(USAGE.by_model.items()):
        c = USAGE.cost(model)
        lines.append(f"| Anthropic | {model} | {m['calls']} | {m['cached_calls']} | {m['input']:,} | {m['output']:,} | "
                     f"{m['input'] + m['output']:,} | {c:.4f} |")
        tot["calls"] += m["calls"]
        tot["cached"] += m["cached_calls"]
        tot["in"] += m["input"]
        tot["out"] += m["output"]
        tot["cost"] += c
    lines.append(f"| **All** | **overall** | **{tot['calls']}** | **{tot['cached']}** | **{tot['in']:,}** | "
                 f"**{tot['out']:,}** | **{tot['in'] + tot['out']:,}** | **{tot['cost']:.4f}** |")
    n = max(n_requests, 1)
    lines += ["", f"- Average tokens per request: **{(tot['in'] + tot['out']) / n:.1f}**",
              f"- Estimated cost per request: **${tot['cost'] / n:.6f}**", "",
              "Token counts include cache hits (the tokens the call originally consumed), so the numbers describe",
              "the full cost of producing the run from a cold cache. Pricing table lives in `ghostaudit/llm.py`.",
              "If the table is empty, the run used the deterministic fallbacks only (no API key, empty cache)."]
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=os.path.join(ROOT, "dataset"))
    ap.add_argument("--requests", default=None)
    ap.add_argument("--out", default=os.path.join(ROOT, "output.csv"))
    ap.add_argument("--trace", default=os.path.join(HERE, "cache", "audit_trace.json"))
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--usage-report", default=os.path.join(HERE, "evaluation", "usage_report.md"))
    a = ap.parse_args()
    t0 = time.time()
    os.makedirs(os.path.join(HERE, "cache"), exist_ok=True)
    p = Pipeline(a.dataset, use_llm=not a.no_llm)
    rows = p.run(a.requests or os.path.join(a.dataset, "deletion_requests.csv"), a.out, a.trace)
    if a.requests is None:
        write_usage_report(a.usage_report, len(rows), time.time() - t0, p.vision.mode_counts)
    print(f"wrote {len(rows)} rows -> {a.out}  {dict(Counter(r[1] for r in rows))}")
    if p.intent.disagreements:
        print("intent rule/LLM disagreements:", p.intent.disagreements)


if __name__ == "__main__":
    main()
