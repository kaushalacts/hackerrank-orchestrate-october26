"""Submission checks: schema, row count/order, step numbering, phase order, allowed ops,
evidence rules (cited ids exist, were captured at/before audit_at, remediation uses "")."""
import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "code"))
from ghostaudit.auditor import OP_STATE  # noqa: E402

PHASE_OF = {op: ("FINDING" if op.startswith("REPORT") else "VERIFICATION" if op.startswith("VERIFY") else "REMEDIATION")
            for op in OP_STATE}


def main(path=os.path.join(ROOT, "output.csv")):
    ds = os.path.join(ROOT, "dataset")
    req = {r["case_id"]: r for r in csv.DictReader(open(os.path.join(ds, "deletion_requests.csv"), encoding="utf-8"))}
    files = {r["file_id"]: r["captured_at"] for r in csv.DictReader(open(os.path.join(ds, "evidence_files.csv")))}
    acts = {r["activity_id"]: r["event_time"] for r in csv.DictReader(open(os.path.join(ds, "system_activity.csv")))}
    audits = {r["audit_id"]: r["event_time"] for r in csv.DictReader(open(os.path.join(ds, "user_audit_log.csv")))}
    when = {**files, **acts, **audits}
    rows = list(csv.reader(open(path, encoding="utf-8")))
    errs = []
    if rows[0] != ["case_id", "deletion_status", "steps_json"]:
        errs.append("bad header")
    body = rows[1:]
    if sorted(r[0] for r in body) != sorted(req):
        errs.append("case_id set mismatch")
    for cid, status, sj in body:
        steps = json.loads(sj)
        if status == "NOT_APPLICABLE" and steps:
            errs.append(f"{cid}: NOT_APPLICABLE with steps")
        rank = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
        last = -1
        for i, s in enumerate(steps, 1):
            if s["step_no"] != i:
                errs.append(f"{cid}: step_no {s['step_no']} != {i}")
            if OP_STATE.get(s["operation"]) != s["state"] or PHASE_OF[s["operation"]] != s["phase"]:
                errs.append(f"{cid}: bad op/state/phase {s}")
            if rank[s["phase"]] < last:
                errs.append(f"{cid}: phase order")
            last = rank[s["phase"]]
            ev = s["evidence_id"]
            cited = s["phase"] == "FINDING" or status == "COMPLETE"
            if cited:
                if ev not in when:
                    errs.append(f"{cid}: unknown evidence {ev}")
                elif when[ev] > req[cid]["audit_at"]:
                    errs.append(f"{cid}: evidence {ev} captured after audit_at")
            elif ev != "":
                errs.append(f"{cid}: future step with evidence")
        if status == "COMPLETE" and any(s["phase"] != "VERIFICATION" for s in steps):
            errs.append(f"{cid}: COMPLETE with non-verification steps")
    print(f"rows={len(body)} errors={len(errs)}")
    for e in errs[:30]:
        print("  ", e)
    return not errs


if __name__ == "__main__":
    sys.exit(0 if main(*sys.argv[1:]) else 1)
