"""Hand-built evaluation cases.

Each case is a tiny self-contained dataset (identities, audit log, activity, rules,
evidence) written to a temp dir, run through the real Pipeline, and compared with an
expected (status, steps) answer written by hand from the problem statement's rules.
They target failure modes the public samples under-represent.
"""
from __future__ import annotations

import csv
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.dirname(HERE)
ROOT = os.path.dirname(CODE)
sys.path.insert(0, CODE)

IDENTITIES = [
    ["user_901", "Rhea Kapoor", "rhea.kapoor@example.org", "+91 98111 22334", "a" * 64, "2026-05-01T00:00:00Z"],
    ["user_902", "Tomas Lind", "tomas.lind@example.org", "+46 70 111 2233", "b" * 64, "2026-05-01T00:00:00Z"],
    ["user_903", "Ines Duarte", "ines.duarte@example.org", "+351 912 000 111", "c" * 64, "2026-05-01T00:00:00Z"],
    ["user_904", "Kwasi Boateng", "kwasi.b@example.org", "+233 20 000 1111", "d" * 64, "2026-05-01T00:00:00Z"],
    ["user_905", "Mei Lin", "mei.lin@example.org", "+86 138 0000 1111", "e" * 64, "2026-05-01T00:00:00Z"],
]
AUDIT = [["audit_9001", "user_901", "2026-04-01T00:00:00Z", "email", "rhea.old@example.org", "rhea.kapoor@example.org"]]


def handover(lines):
    body = "CUSTOMER PLATFORM - SHIFT HANDOVER\n\n" + "\n".join(
        f"- {t} | {s} | {r} | {k} | {res} | {subj}" for t, s, r, k, res, subj in lines)
    return body


CASES = [
    {
        "name": "historical-email-only evidence",
        "why": "request uses the CURRENT email; the leftover search entry is indexed under the OLD email",
        "request": ["cc_1", "rhea.kapoor@example.org", "2026-08-01T00:00:00Z", "COMPLETE", "2026-08-02T00:00:00Z",
                    "2026-08-10T00:00:00Z", "Please delete my account and personal data."],
        "files": {"evidence/records/h1.txt": ("2026-08-09T00:00:00Z", handover([
            ("2026-08-09T00:00:00Z", "account_service", "account_9101", "USER_PROFILE", "NOT_FOUND", "rhea.kapoor@example.org"),
            ("2026-08-09T00:00:00Z", "search_service", "search_9101", "SEARCH_INDEX_ENTRY", "FOUND", "rhea.old@example.org"),
            ("2026-08-09T00:00:00Z", "security_service", "audit_record_9101", "SECURITY_AUDIT_LOG", "FOUND", "user_901")]))},
        "expect": ("INCOMPLETE", [
            ("FINDING", "search_service", "search_9101", "REPORT_REMAINING_RECORD"),
            ("REMEDIATION", "search_service", "search_9101", "DELETE_RECORD"),
            ("VERIFICATION", "account_service", "account_9101", "VERIFY_RECORD_ABSENT"),
            ("VERIFICATION", "search_service", "search_9101", "VERIFY_RECORD_ABSENT"),
            ("VERIFICATION", "security_service", "audit_record_9101", "VERIFY_RECORD_PRESENT")]),
    },
    {
        "name": "replica drift",
        "why": "primary table is clean but a failover replica still holds the profile",
        "request": ["cc_2", "tomas.lind@example.org", "2026-08-01T00:00:00Z", "COMPLETE", "2026-08-02T00:00:00Z",
                    "2026-08-10T00:00:00Z", "Erase my account, please."],
        "files": {"evidence/databases/d2.sql": ("2026-08-09T00:00:00Z", """
CREATE TABLE customer_profiles_primary (resource_id TEXT, user_id TEXT, full_name TEXT, email TEXT, phone TEXT, account_status TEXT, updated_at TEXT);
CREATE TABLE customer_profiles_failover_replica (resource_id TEXT, user_id TEXT, full_name TEXT, email TEXT, phone TEXT, account_status TEXT, updated_at TEXT);
INSERT INTO customer_profiles_primary VALUES('account_7777','user_7777','Someone Else','someone@example.org','+1 555 0100','ACTIVE','2026-08-09T00:00:00Z');
INSERT INTO customer_profiles_failover_replica VALUES('account_9202','user_902','Tomas Lind','tomas.lind@example.org','+46 70 111 2233','ACTIVE','2026-08-09T00:00:00Z');
""")},
        "expect": ("INCOMPLETE", [
            ("FINDING", "account_service", "account_9202", "REPORT_REMAINING_RECORD"),
            ("REMEDIATION", "account_service", "account_9202", "DELETE_RECORD"),
            ("VERIFICATION", "account_service", "account_9202", "VERIFY_RECORD_ABSENT")]),
    },
    {
        "name": "evidence after audit_at must be ignored",
        "why": "a capture AFTER audit_at shows a re-indexed search doc; at audit time it was gone",
        "request": ["cc_3", "ines.duarte@example.org", "2026-08-01T00:00:00Z", "COMPLETE", "2026-08-02T00:00:00Z",
                    "2026-08-10T00:00:00Z", "Je demande la suppression définitive de mon compte."],
        "files": {
            "evidence/records/h3a.txt": ("2026-08-09T00:00:00Z", handover([
                ("2026-08-09T00:00:00Z", "account_service", "account_9303", "USER_PROFILE", "NOT_FOUND", "ines.duarte@example.org"),
                ("2026-08-09T00:00:00Z", "search_service", "search_9303", "SEARCH_INDEX_ENTRY", "NOT_FOUND", "ines.duarte@example.org")])),
            "evidence/records/h3b.txt": ("2026-08-20T00:00:00Z", handover([
                ("2026-08-20T00:00:00Z", "search_service", "search_9303", "SEARCH_INDEX_ENTRY", "FOUND", "ines.duarte@example.org")]))},
        "expect": ("COMPLETE", [
            ("VERIFICATION", "account_service", "account_9303", "VERIFY_RECORD_ABSENT"),
            ("VERIFICATION", "search_service", "search_9303", "VERIFY_RECORD_ABSENT")]),
    },
    {
        "name": "non-deletion request despite deletion-looking evidence",
        "why": "export request; evidence shows records but nothing is authorized",
        "request": ["cc_4", "kwasi.b@example.org", "2026-08-01T00:00:00Z", "NOT_STARTED", "2026-08-02T00:00:00Z",
                    "2026-08-10T00:00:00Z", "Could you send me a copy of my data? Please don't delete anything."],
        "files": {"evidence/records/h4.txt": ("2026-08-09T00:00:00Z", handover([
            ("2026-08-09T00:00:00Z", "account_service", "account_9404", "USER_PROFILE", "FOUND", "kwasi.b@example.org")]))},
        "expect": ("NOT_APPLICABLE", []),
    },
    {
        "name": "tombstone still exposing PII + active connector",
        "why": "tombstone must keep user_id but lose email; connector must be disabled before redaction",
        "request": ["cc_5", "mei.lin@example.org", "2026-08-01T00:00:00Z", "PARTIALLY_COMPLETE", "2026-08-02T00:00:00Z",
                    "2026-08-10T00:00:00Z", "请删除我的账户。 Please delete my account."],
        "files": {"evidence/records/r5.json": ("2026-08-09T00:00:00Z", json.dumps({"exported_at": "2026-08-09T00:00:00Z", "snapshots": [
            {"captured_at": "2026-08-09T00:00:00Z", "data_store": "identity_service", "collection": "account_tombstones",
             "records": [{"resource_id": "tombstone_9505", "subject_reference": "user_905", "name": "Mei Lin",
                          "email": "mei.lin@example.org", "phone": None, "email_hash": None, "account_status": "DELETED"}]},
            {"captured_at": "2026-08-09T00:00:00Z", "data_store": "integration_service", "collection": "connector_configurations",
             "records": [{"resource_id": "data_flow_9505", "subject_selector": "user_905", "enabled": True}]},
            {"captured_at": "2026-08-09T00:00:00Z", "data_store": "account_service", "collection": "customer_profiles", "records": []}]}))},
        "expect": ("INCOMPLETE", [
            ("FINDING", "identity_service", "tombstone_9505", "REPORT_EXPOSED_PII"),
            ("FINDING", "integration_service", "data_flow_9505", "REPORT_ACTIVE_DATA_FLOW"),
            ("REMEDIATION", "integration_service", "data_flow_9505", "DISABLE_DATA_FLOW"),
            ("REMEDIATION", "identity_service", "tombstone_9505", "REDACT_RECORD"),
            ("VERIFICATION", "identity_service", "tombstone_9505", "VERIFY_RECORD_REDACTED"),
            ("VERIFICATION", "integration_service", "data_flow_9505", "VERIFY_DATA_FLOW_DISABLED")]),
    },
]


def build(tmp, case):
    ds = os.path.join(tmp, "dataset")
    os.makedirs(os.path.join(ds, "evidence"), exist_ok=True)
    shutil.copy(os.path.join(ROOT, "dataset", "deletion_rules.csv"), ds)
    with open(os.path.join(ds, "user_identities.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["user_id", "name", "email", "phone", "email_hash", "updated_at"]); w.writerows(IDENTITIES)
    with open(os.path.join(ds, "user_audit_log.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"]); w.writerows(AUDIT)
    with open(os.path.join(ds, "system_activity.csv"), "w", newline="") as f:
        csv.writer(f).writerow(["activity_id", "event_time", "event_type", "source_system", "target_system",
                                "resource_id", "reported_result", "details"])
    manifest = []
    for i, (path, (cap, content)) in enumerate(case["files"].items(), 1):
        full = os.path.join(ds, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        open(full, "w", encoding="utf-8").write(content)
        manifest.append([f"evidence_c{i}", path, "custom", cap])
    with open(os.path.join(ds, "evidence_files.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["file_id", "file_path", "origin", "captured_at"]); w.writerows(manifest)
    with open(os.path.join(ds, "deletion_requests.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"])
        w.writerow(case["request"])
    return ds


def run_custom(use_llm=False):
    from main import Pipeline
    passed = 0
    for case in CASES:
        tmp = tempfile.mkdtemp()
        ds = build(tmp, case)
        p = Pipeline(ds, use_llm=use_llm)
        out = os.path.join(tmp, "out.csv")
        p.run(os.path.join(ds, "deletion_requests.csv"), out)
        row = next(csv.DictReader(open(out)))
        got = (row["deletion_status"], [(s["phase"], s["system_id"], s["resource_id"], s["operation"])
                                        for s in json.loads(row["steps_json"])])
        ok = got == case["expect"]
        passed += ok
        print(f"[{'PASS' if ok else 'FAIL'}] {case['name']}: {case['why']}")
        if not ok:
            print("   expected:", case["expect"])
            print("   got:     ", got)
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"custom cases passed: {passed}/{len(CASES)}")
    return passed, len(CASES)


if __name__ == "__main__":
    run_custom()
