"""Evidence normalization.

Every participant-visible source (SQL snapshots, JSON exports, text handovers, logs,
PDFs, screenshots, and the global activity stream) is turned into a list of
`Observation` objects with one uniform shape:

    (evidence_id, captured_at, observed_at, system, resource_id, category, state, tokens)

`state` is one of PRESENT, ABSENT, IDENTIFIABLE, ANONYMIZED, REDACTED, ACTIVE,
DISABLED, BLOCKED. `tokens` are identifier tokens (email:/phone:/hash:/user:/name:)
that occur in the record, used to link the record to a person.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field

from .identity import tokens_from_value

RID_RE = re.compile(
    r"\b(audit_record|data_flow|email_delivery|legal_hold|tombstone|account|search|analytics|"
    r"support|export|backup|cache|marketing|object|telemetry)_(\d{1,6})\b"
)

PREFIX_SYSTEM = {
    "account": "account_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "support": "support_platform",
    "export": "export_service",
    "backup": "backup_service",
    "data_flow": "integration_service",
    "audit_record": "security_service",
    "tombstone": "identity_service",
    "cache": "cache_service",
    "marketing": "marketing_platform",
    "object": "object_storage",
    "legal_hold": "legal_service",
    "email_delivery": "email_delivery_service",
    "telemetry": "telemetry_service",
}
PREFIX_CATEGORY = {
    "account": "USER_PROFILE",
    "search": "SEARCH_INDEX_ENTRY",
    "analytics": "ANALYTICS_PROFILE",
    "support": "SUPPORT_MESSAGE",
    "export": "USER_EXPORT",
    "backup": "BACKUP_ARCHIVE",
    "data_flow": "DATA_FLOW",
    "audit_record": "SECURITY_AUDIT_LOG",
    "tombstone": "ACCOUNT_TOMBSTONE",
    "cache": "CACHE_ENTRY",
    "marketing": "MARKETING_PROFILE",
    "object": "SUPPORT_ATTACHMENT",
    "legal_hold": "LEGAL_HOLD_RECORD",
    "email_delivery": "EMAIL_DELIVERY_LOG",
    "telemetry": "PRODUCT_TELEMETRY",
}
RESULT_STATE = {
    "FOUND": "PRESENT", "PRESENT": "PRESENT", "NOT_FOUND": "ABSENT", "ABSENT": "ABSENT",
    "DELETED": "ABSENT", "IDENTIFIABLE": "IDENTIFIABLE", "ANONYMIZED": "ANONYMIZED",
    "REDACTED": "REDACTED", "ACTIVE": "ACTIVE", "ENABLED": "ACTIVE", "DISABLED": "DISABLED",
    "BLOCKED": "BLOCKED", "RETAINED": "PRESENT",
}
# keys whose values are lookup/query keys: they say what was searched, which links a trace
# to a person, but they are NOT contents of the record.
LOOKUP_KEYS = {"lookup_key", "match_key", "scan_key", "subject_key", "owner_key", "query",
               "correlation_key", "subject_ref", "subject_selector"}
DIRECT_ID_KEYS = re.compile(r"(email|phone|full_name|display_name|requester_name|email_hash|^name$)")
NULLS = {None, "", "null", "none", "None", "NULL"}


def rid_prefix(rid: str) -> str | None:
    m = RID_RE.fullmatch(rid)
    return m.group(1) if m else None


@dataclass
class Observation:
    evidence_id: str
    captured_at: str           # when the evidence item was captured (citation eligibility)
    observed_at: str           # when this particular record state was observed
    system: str
    resource_id: str
    category: str
    state: str
    tokens: set[str] = field(default_factory=set)        # identifiers contained in the record
    link_tokens: set[str] = field(default_factory=set)   # identifiers used to look it up
    linked_user: str | None = None                       # explicit link (catalog / subject ref)
    source: str = ""


def _truthy(v) -> bool | None:
    if isinstance(v, bool):
        return v
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in {"true", "1", "yes", "allow", "allowed", "enabled"}:
        return True
    if s in {"false", "0", "no", "deny", "denied", "disabled"}:
        return False
    return None


def interpret(rid: str, rec: dict, hint: str = "") -> tuple[str, str, str, set[str]] | None:
    """Return (system, category, state, content_tokens) for a flattened record dict."""
    pre = rid_prefix(rid)
    if pre is None:
        return None
    system = rec.get("system") if rec.get("system") in PREFIX_SYSTEM.values() else PREFIX_SYSTEM[pre]
    category = str(rec.get("record_type") or "").upper() or PREFIX_CATEGORY[pre]
    hint_l = (hint + " " + " ".join(str(v) for k, v in rec.items() if k in ("event", "collection", "table"))).lower()

    # identifier tokens contained in the record (not lookup keys)
    content: set[str] = set()
    for k, v in rec.items():
        if k in LOOKUP_KEYS or k == "resource_id":
            continue
        kl = k.lower()
        if DIRECT_ID_KEYS.search(kl) or kl in {"matched_value", "message_text", "message_excerpt",
                                             "subject_reference", "customer_reference", "user_id",
                                             "detail", "text"}:
            content |= tokens_from_value(kl, v)
    direct = {t for t in content if not t.startswith("user:")}
    try:
        di = int(str(rec.get("direct_identifiers", "")).strip() or -1)
    except ValueError:
        di = -1

    # explicit result field from lookup-style evidence
    res = str(rec.get("result") or "").upper()
    if res in RESULT_STATE:
        return system, category, RESULT_STATE[res], content

    absent = False
    for k in ("status_code", "http_status"):
        if str(rec.get(k, "")).strip() == "404":
            absent = True
    if str(rec.get("rows", "")).strip() == "0":
        absent = True
    if pre == "account" and str(rec.get("account_status", "")).upper() in {"DELETED", "CLOSED", "PURGED"}:
        absent = True
    if pre == "search":
        if str(rec.get("result", "")).lower() == "miss":
            absent = True
        for k in ("total", "total_hits", "hits.total"):
            if str(rec.get(k, "")).strip() == "0":
                absent = True
    if pre == "export":
        for k in ("download_available", "available"):
            if _truthy(rec.get(k)) is False:
                absent = True
    if rec.get("__profile_null__"):
        absent = True
    if absent:
        return system, category, "ABSENT", content

    if pre == "data_flow":
        en = _truthy(rec.get("enabled"))
        st = "DISABLED" if en is False else "ACTIVE"
        if str(rec.get("last_delivery_status", "")).lower() == "stopped" and en is None:
            st = "DISABLED"
        return system, category, st, content
    if pre == "backup":
        allowed = _truthy(rec.get("restore_allowed"))
        if allowed is None and "decision" in rec:
            allowed = _truthy(rec.get("decision"))
        if allowed is None and "eligible" in rec:
            allowed = _truthy(rec.get("eligible")) and not _truthy(rec.get("deletion_block"))
        return system, category, ("BLOCKED" if allowed is False else "ACTIVE"), content
    if pre == "analytics":
        if "contact_lookup" in hint_l or "email_opt_in" in rec:
            return system, "SECONDARY_IDENTIFIER", "PRESENT", content
        ident = bool(content) or di > 0
        if di == 0 and not direct:
            ident = False
        return system, category, ("IDENTIFIABLE" if ident else "ANONYMIZED"), content
    if pre == "support":
        if "attachment" in hint_l or str(rec.get("file", "")).lower().endswith((".pdf", ".jpg", ".png")):
            return system, "SUPPORT_ATTACHMENT", "PRESENT", content
        return system, category, ("IDENTIFIABLE" if direct else "REDACTED"), content
    if pre in ("tombstone",):
        return system, category, ("IDENTIFIABLE" if direct else "REDACTED"), content
    if pre == "email_delivery":
        return system, category, ("IDENTIFIABLE" if direct else "REDACTED"), content
    if pre == "telemetry":
        return system, category, ("IDENTIFIABLE" if content else "ANONYMIZED"), content
    return system, category, "PRESENT", content


# ----------------------------------------------------------------------------- JSON

def _flatten(d: dict, prefix: str = "", out: dict | None = None) -> dict:
    out = {} if out is None else out
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            _flatten(v, key + ".", out)
            # keep leaf names reachable without prefix too
            for kk, vv in v.items():
                if not isinstance(vv, (dict, list)):
                    out.setdefault(kk, vv)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    for kk, vv in item.items():
                        if not isinstance(vv, (dict, list)):
                            out.setdefault(kk, vv)
                            out.setdefault(f"{key}.{kk}", vv)
        else:
            out[key] = v
    return out


TIME_KEYS = ("observed_at", "recorded_at", "captured_at")


def _walk_json(node, ctx: dict, emit):
    if isinstance(node, dict):
        ctx = dict(ctx)
        for k in TIME_KEYS:
            if isinstance(node.get(k), str):
                ctx["time"] = node[k]
        for k in ("data_store", "collection", "source"):
            if isinstance(node.get(k), str):
                ctx[k] = node[k]
        rid = node.get("resource_id")
        if isinstance(rid, str) and rid_prefix(rid):
            flat = _flatten(node)
            if "profile" in node and node["profile"] is None:
                flat["__profile_null__"] = True
            emit(rid, flat, ctx)
            return  # nested docs belong to this record
        for k, v in node.items():
            sub = dict(ctx)
            if k.endswith("_service") or k.endswith("_platform"):
                sub["system_key"] = k
            if isinstance(v, (dict, list)):
                if k in ("profile_lookups", "index_queries", "profiles", "tickets", "exports",
                         "connectors", "restore_entries", "audit_records"):
                    sub["collection"] = k
                _walk_json(v, sub, emit)
    elif isinstance(node, list):
        for item in node:
            _walk_json(item, ctx, emit)


# ----------------------------------------------------------------------------- logs

KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_\.]*)=("(?:[^"\\]|\\.)*"|\S+)')
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")


def parse_log_line(line: str) -> dict | None:
    m = TS_RE.match(line)
    if not m:
        return None
    ts = m.group(1)
    rest = line[m.end():].strip()
    f: dict = {"__ts": ts}
    if rest.startswith("{"):
        try:
            f.update(json.loads(rest))
            f["__trace"] = f.get("trace_id") or f.get("instance")
            return f
        except json.JSONDecodeError:
            pass
    # bracket style: [LEVEL] [service] [trace] event: k="v" ...
    b = re.match(r"\[(\w+)\]\s+\[([\w\-]+)\]\s+\[([\w\-]+)\]\s+([\w]+):\s*(.*)$", rest)
    if b:
        f.update(level=b.group(1), service=b.group(2), __trace=b.group(3), event=b.group(4))
        rest = b.group(5)
    p = re.match(r"(\w+)\s*\|\s*([\w\-]+)\s*\|\s*([\w\-]+)\s*\|\s*(\w+)\s*\|\s*(.*)$", rest)
    if p:
        f.update(level=p.group(1), service=p.group(2), __trace=p.group(3), event=p.group(4))
        rest = p.group(5)
    s = re.match(r"<\d+>\d+\s+\S+\s+([\w\-]+)\s+([\w\-]+)\s+-\s+-\s+(.*)$", rest)
    if s:
        f.update(service=s.group(1), __trace=s.group(2))
        rest = s.group(3)
    for k, v in KV_RE.findall(rest):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        f[k] = v
    if "message" in f and "=" in str(f["message"]):
        for k, v in KV_RE.findall(f["message"]):
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            f.setdefault(k, v)
    if "function" in f and "service" not in f:
        f["service"] = f["function"]
    f.setdefault("__trace", f.get("trace_id") or f.get("requestId"))
    return f


def parse_log(path: str) -> list[tuple[str, dict, str]]:
    """Group lines by trace, merge fields, return (resource_id, merged_fields, observed_at)."""
    traces: dict[str, list[dict]] = defaultdict(list)
    singles: list[dict] = []
    for line in open(path, encoding="utf-8", errors="replace"):
        f = parse_log_line(line.rstrip("\n"))
        if not f:
            continue
        t = f.get("__trace")
        if t and str(t).startswith(("tr-", "rb-")):
            traces[t].append(f)
        else:
            singles.append(f)
    out = []
    for t, lines in traces.items():
        merged: dict = {}
        events = []
        for f in lines:
            events.append(str(f.get("event", "")))
            for k, v in f.items():
                if k in ("__ts",):
                    continue
                if k in merged and k != "event":
                    continue
                merged[k] = v
        merged["event"] = " ".join(events)
        rids = {f["resource_id"] for f in lines if rid_prefix(str(f.get("resource_id", "")))}
        last = max(f["__ts"] for f in lines)
        for rid in rids:
            out.append((rid, merged, last))
    for f in singles:
        rid = str(f.get("resource_id", ""))
        if rid_prefix(rid):
            out.append((rid, f, f["__ts"]))
    return out


# ----------------------------------------------------------------------------- SQL

def parse_sql(path: str) -> list[tuple[str, dict, str | None]]:
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(open(path, encoding="utf-8").read())
    except sqlite3.Error:
        return []
    out = []
    snap = None
    for line in open(path, encoding="utf-8"):
        m = re.search(r"(?:Captured at|snapshot_completed_at)[:=]\s*(\S+)", line)
        if m:
            snap = m.group(1)
            break
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    for t in tables:
        cur = con.execute(f'select * from "{t}"')
        cols = [c[0] for c in cur.description]
        for row in cur.fetchall():
            d = dict(zip(cols, row))
            rid = d.get("resource_id")
            if not isinstance(rid, str) or not rid_prefix(rid):
                continue
            for k, v in list(d.items()):
                if isinstance(v, str) and v.startswith("{"):
                    try:
                        d.update(_flatten(json.loads(v)))
                    except json.JSONDecodeError:
                        pass
            d["table"] = t
            out.append((rid, d, snap))
    return out


def sql_covered_systems(path: str) -> set[str]:
    """Systems a SQL snapshot fully covers (so a missing row means the record is absent)."""
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(open(path, encoding="utf-8").read())
    except sqlite3.Error:
        return set()
    systems = set()
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    for t in tables:
        n = con.execute(f'select count(*) from "{t}"').fetchone()[0]
        if n == 0:
            continue  # an empty capture proves nothing about absence
        if "profiles" in t and "analytics" not in t:
            systems.add("account_service")
        if "search_documents" in t:
            systems.add("search_service")
    return systems


# ----------------------------------------------------------------------------- docs & images

def pdf_text(path: str) -> str:
    try:
        return subprocess.run(["pdftotext", "-layout", path, "-"], capture_output=True,
                              text=True, timeout=60).stdout
    except Exception:
        return ""


# --------------------------------------------------------------------------- main loader

class EvidenceStore:
    def __init__(self, dataset_dir: str, vision=None):
        self.dataset_dir = dataset_dir
        self.obs: list[Observation] = []
        self.files: dict[str, dict] = {}
        self.sql_coverage: dict[str, set[str]] = {}
        # full-listing captures: (evidence_id, system, observed_at). A record of that system
        # missing from such a listing is absent at that time.
        self.coverage: list[tuple[str, str, str]] = []
        self.catalog_links: dict[str, str] = {}   # resource_id -> user_id (explicit)
        self.catalog_times: dict[str, str] = {}
        self.aliases: dict[str, str] = {}         # business ref (NST-...) -> resource_id
        self.vision = vision
        self._load_activity()
        self._load_files()

    # -- activity stream (claims + a few grounded checks)
    def _load_activity(self):
        path = os.path.join(self.dataset_dir, "system_activity.csv")
        self.activity = list(csv.DictReader(open(path, encoding="utf-8")))
        for a in self.activity:
            d = a["details"]
            if a["event_type"] == "LINK_RESOURCE_IDENTITY":
                m = re.search(r"linked (\S+) \(([^)]+)\) to (\S+) and (user_\d+)", d) or \
                    re.search(r"confirmed (\S+) \(([^)]+)\) belongs only to (\S+) and (user_\d+)", d)
                if m:
                    self.catalog_links[m.group(1)] = m.group(4)
                    self.catalog_times[m.group(1)] = a["event_time"]
                    self.aliases[m.group(2)] = m.group(1)
                    if "Attachment catalog" in d:
                        self.aliases[m.group(2).replace(".pdf", "")] = m.group(1)

    def _load_files(self):
        path = os.path.join(self.dataset_dir, "evidence_files.csv")
        for r in csv.DictReader(open(path, encoding="utf-8")):
            self.files[r["file_id"]] = r
            full = os.path.join(self.dataset_dir, r["file_path"])
            if not os.path.exists(full):
                continue
            ext = full.rsplit(".", 1)[-1].lower()
            try:
                if ext == "json":
                    self._ingest_json(r, full)
                elif ext == "sql":
                    self._ingest_sql(r, full)
                elif ext == "log":
                    self._ingest_log(r, full)
                elif ext == "txt":
                    self._ingest_text(r, open(full, encoding="utf-8").read())
                elif ext == "pdf":
                    self._ingest_document(r, pdf_text(full))
                elif ext in ("png", "jpg", "jpeg"):
                    self._ingest_image(r, full)
            except Exception as e:  # never let one bad file kill the run
                print(f"[warn] failed to parse {r['file_id']} {r['file_path']}: {e}")

    def _add(self, fid, cap, observed, rid, flat, hint="", link_user=None):
        it = interpret(rid, flat, hint)
        if it is None:
            return
        system, category, state, content = it
        link = set()
        for k in LOOKUP_KEYS:
            if k in flat:
                link |= tokens_from_value(k, flat[k])
        if "subject_reference" in flat:
            link |= tokens_from_value("subject_reference", flat["subject_reference"])
        obs_t = observed or cap
        # an observation can never be later than the capture of the evidence that holds it
        if obs_t > cap:
            obs_t = cap
        self.obs.append(Observation(fid, cap, obs_t, system, rid, category, state,
                                    content, link, link_user, hint))

    def _ingest_json(self, r, full):
        data = json.load(open(full, encoding="utf-8"))
        cap = r["captured_at"]
        if isinstance(data, dict) and isinstance(data.get("snapshots"), list):
            for snap in data["snapshots"]:
                # only primary-profile listings are treated as complete listings
                if snap.get("data_store") == "account_service" and isinstance(snap.get("records"), list):
                    self.coverage.append((r["file_id"], "account_service", cap))

        def emit(rid, flat, ctx):
            hint = " ".join(str(ctx.get(k, "")) for k in ("data_store", "collection", "system_key"))
            self._add(r["file_id"], cap, ctx.get("time"), rid, flat, hint)
        _walk_json(data, {}, emit)

    def _ingest_sql(self, r, full):
        cap = r["captured_at"]
        self.sql_coverage[r["file_id"]] = sql_covered_systems(full)
        for system in self.sql_coverage[r["file_id"]] & {"account_service"}:
            self.coverage.append((r["file_id"], system, cap))
        rows = parse_sql(full)
        # merge copies of the same resource across primary/replica tables: present anywhere = present
        by_rid: dict[str, list[dict]] = defaultdict(list)
        for rid, d, snap in rows:
            by_rid[rid].append(d)
        for rid, ds in by_rid.items():
            # prefer the copy that still exposes the most identifiers (drift = data still there)
            ds.sort(key=lambda d: -sum(1 for v in d.values() if v not in NULLS))
            self._add(r["file_id"], cap, cap, rid, ds[0], " ".join(d["table"] for d in ds))
            self.obs[-1].source = "sql:" + ",".join(d["table"] for d in ds) if self.obs else ""

    def _ingest_log(self, r, full):
        cap = r["captured_at"]
        for rid, merged, ts in parse_log(full):
            self._add(r["file_id"], cap, ts, rid, merged, str(merged.get("event", "")))

    def _ingest_text(self, r, text):
        cap = r["captured_at"]
        line_re = re.compile(r"^-?\s*(\S+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(.+)$")
        for line in text.splitlines():
            m = line_re.match(line.strip())
            if m:
                ts, system, rid, rtype, result, subj = m.groups()
                flat = {"system": system, "resource_id": rid, "record_type": rtype,
                        "result": result, "subject_reference": subj.strip()}
                self._add(r["file_id"], cap, ts, rid, flat)

    def _ingest_document(self, r, text):
        """PDFs: business documents. Resolve resource ids directly or via catalog aliases."""
        cap = r["captured_at"]
        rids = set(m.group(0) for m in RID_RE.finditer(text))
        for alias, rid in self.aliases.items():
            if alias and alias in text:
                rids.add(rid)
        toks = tokens_from_value("text", text)
        for rid in rids:
            pre = rid_prefix(rid)
            if pre in ("support",) and ("attachment" in text.lower() or ".pdf" in text.lower()):
                flat = {"resource_id": rid, "record_type": "SUPPORT_ATTACHMENT", "result": "FOUND"}
            else:
                flat = {"resource_id": rid, "text": text if pre in ("analytics", "support", "tombstone") else ""}
            self._add(r["file_id"], cap, cap, rid, flat, "document")
            self.obs[-1].link_tokens |= toks

    def _ingest_image(self, r, full):
        if self.vision is None:
            return
        cap = r["captured_at"]
        for item in self.vision.extract(full, r):
            rid = item.get("resource_id")
            if not rid or not rid_prefix(rid):
                continue
            flat = dict(item.get("fields") or {})
            flat["resource_id"] = rid
            if item.get("result"):
                flat["result"] = item["result"]
            if item.get("record_type"):
                flat["record_type"] = item["record_type"]
            self._add(r["file_id"], cap, item.get("observed_at") or cap, rid, flat, "screenshot")
            self.obs[-1].link_tokens |= set(item.get("tokens") or [])
