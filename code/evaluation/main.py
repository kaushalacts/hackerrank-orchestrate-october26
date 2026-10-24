"""Evaluation harness.

    python3 code/evaluation/main.py                 # samples: predict + score vs dataset/sample_output.csv
    python3 code/evaluation/main.py --custom        # also run the hand-built adversarial cases
    python3 code/evaluation/main.py --pred X --gold Y

Metrics
- case status accuracy: deletion_status exact match
- step precision / recall / F1: a step = (phase, system_id, resource_id, operation, state, evidence_id)
- field accuracy: for aligned steps (same position), share of the 7 fields that match
- sequence accuracy: share of cases whose full steps_json array equals gold exactly
- identity accuracy: share of gold resource_ids that we surface at all (resolution / discovery)
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.dirname(HERE)
ROOT = os.path.dirname(CODE)
sys.path.insert(0, CODE)

FIELDS = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def load(path):
    out = {}
    for r in csv.DictReader(open(path, encoding="utf-8")):
        out[r["case_id"]] = (r["deletion_status"], json.loads(r["steps_json"]))
    return out


def key(s):
    return tuple(s[f] for f in FIELDS[1:])


def score(pred, gold, verbose=True):
    n = len(gold)
    status_ok = seq_ok = 0
    tp = fp = fn = 0
    field_hits = field_total = 0
    rid_hit = rid_total = 0
    failures = []
    for cid, (gs, gsteps) in sorted(gold.items()):
        ps, psteps = pred.get(cid, ("MISSING", []))
        status_ok += ps == gs
        seq_ok += [key(s) for s in psteps] == [key(s) for s in gsteps]
        gk = [key(s) for s in gsteps]
        pk = [key(s) for s in psteps]
        gset, pset = set(gk), set(pk)
        tp += len(gset & pset)
        fp += len(pset - gset)
        fn += len(gset - pset)
        for i, g in enumerate(gsteps):
            p = psteps[i] if i < len(psteps) else {}
            for f in FIELDS:
                field_total += 1
                field_hits += p.get(f) == g[f]
        grids = {s["resource_id"] for s in gsteps}
        prids = {s["resource_id"] for s in psteps}
        rid_total += len(grids)
        rid_hit += len(grids & prids)
        if ps != gs or pk != gk:
            failures.append((cid, gs, ps, sorted(gset - pset), sorted(pset - gset)))
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    res = {
        "cases": n,
        "status_accuracy": status_ok / n,
        "step_precision": prec, "step_recall": rec, "step_f1": f1,
        "field_accuracy": field_hits / field_total if field_total else 1.0,
        "sequence_accuracy": seq_ok / n,
        "resource_discovery": rid_hit / rid_total if rid_total else 1.0,
    }
    if verbose:
        for k, v in res.items():
            print(f"{k:22s} {v:.3f}" if isinstance(v, float) else f"{k:22s} {v}")
        for cid, gs, ps, missing, extra in failures:
            print(f"\n[{cid}] gold={gs} pred={ps}")
            for m in missing:
                print("   missing:", m)
            for e in extra:
                print("   extra:  ", e)
    return res, failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred")
    ap.add_argument("--gold", default=os.path.join(ROOT, "dataset", "sample_output.csv"))
    ap.add_argument("--custom", action="store_true", help="run hand-built evaluation cases too")
    ap.add_argument("--no-llm", action="store_true")
    a = ap.parse_args()
    pred_path = a.pred
    if not pred_path:
        from main import Pipeline
        pred_path = os.path.join(CODE, "cache", "sample_pred.csv")
        os.makedirs(os.path.dirname(pred_path), exist_ok=True)
        p = Pipeline(os.path.join(ROOT, "dataset"), use_llm=not a.no_llm)
        p.run(os.path.join(ROOT, "dataset", "sample_deletion_requests.csv"), pred_path,
              os.path.join(CODE, "cache", "sample_trace.json"))
    print("=== Public samples ===")
    score(load(pred_path), load(a.gold))
    if a.custom:
        from evaluation.custom_cases import run_custom
        print("\n=== Custom adversarial cases ===")
        run_custom()


if __name__ == "__main__":
    main()
