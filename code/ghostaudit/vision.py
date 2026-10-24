"""Screenshot evidence -> structured resource observations.

Primary path: a vision-language model (Claude) reads the screenshot and returns JSON.
Fallback path: Tesseract OCR + deterministic rules (fuzzy resource-id repair, catalog
aliases, and per-console state semantics). Both paths emit the same schema:

    {"resource_id", "result", "record_type", "tokens": [...]}
"""
from __future__ import annotations

import re
import subprocess

from .evidence import PREFIX_CATEGORY, RID_RE, rid_prefix
from .identity import tokens_from_value
from .llm import DEFAULT_VISION_MODEL, LLM, image_block, parse_json

VISION_SYSTEM = """You are an evidence extraction agent for a privacy deletion audit.
You read one internal admin-console screenshot and report, as JSON, every customer data
record it shows that is identified by an internal resource id (e.g. account_123,
search_42, analytics_7, support_9, export_5, backup_8, data_flow_3, audit_record_1,
tombstone_4, marketing_2, object_19). Do not guess ids that are not visible."""

VISION_PROMPT = """Return ONLY a JSON array. One object per visible resource id:
{
 "resource_id": "<exact id, underscore form>",
 "result": one of "FOUND" (record exists), "NOT_FOUND", "IDENTIFIABLE" (record shows a
   direct identifier: email, phone, full name, or email hash), "ANONYMIZED", "REDACTED"
   (record exists but shows no direct identifier, at most an internal user_N reference),
   "ACTIVE" (connector enabled / archive still restorable), "DISABLED", "BLOCKED",
 "record_type": one of USER_PROFILE, SEARCH_INDEX_ENTRY, ANALYTICS_PROFILE, SUPPORT_MESSAGE,
   SUPPORT_ATTACHMENT, USER_EXPORT, MARKETING_PROFILE, SECURITY_AUDIT_LOG, BACKUP_ARCHIVE,
   DATA_FLOW, ACCOUNT_TOMBSTONE,
 "identifiers": [emails, phones, user_N references shown on the same row/panel as the id]
}
Screenshot origin system: {origin}. File name: {name}.
If a customer is identified only by an internal reference such as user_17 that belongs to a
deleted-account reference registry, report it with resource_id "tombstone_<N>"."""

FUZZY_RID = re.compile(
    r"\b(audit[_ .]record|data[_ .]flow|tombstone|account|search|analytics|support|export|backup|marketing|object)"
    r"[_ .,]{1,2}(\d{1,6})\b", re.I)

ORIGIN_STATE = {
    # console origin -> default observed state of the primary record on screen
    "account_admin_portal": "FOUND",
    "search_index_admin": "FOUND",
    "export_service": "FOUND",
    "marketing_platform": "FOUND",
    "object_storage": "FOUND",
    "security_service": "FOUND",
    "integration_admin": "ACTIVE",
    "backup_service": "ACTIVE",
}
NEGATIVE_WORDS = {
    "integration_admin": ("disabled", "paused", "stopped"),
    "backup_service": ("restore blocked", "restore disabled", "legal block", "restore: blocked"),
    "export_service": ("expired", "deleted", "revoked"),
}


class Vision:
    def __init__(self, llm: LLM | None, catalog_aliases: dict[str, str], catalog_links: dict[str, str]):
        self.llm = llm
        self.aliases = catalog_aliases
        self.links = catalog_links
        self.mode_counts = {"vlm": 0, "ocr": 0}

    def extract(self, path: str, manifest_row: dict) -> list[dict]:
        out = None
        if self.llm is not None and self.llm.available:
            out = self._vlm(path, manifest_row)
        if out:
            self.mode_counts["vlm"] += 1
            return out
        self.mode_counts["ocr"] += 1
        return self._ocr(path, manifest_row)

    # ---------------------------------------------------------------- VLM
    def _vlm(self, path, row):
        prompt = VISION_PROMPT.replace("{origin}", row.get("origin", "")).replace("{name}", path.rsplit("/", 1)[-1])
        text = self.llm.complete(DEFAULT_VISION_MODEL, VISION_SYSTEM,
                                 [image_block(path), {"type": "text", "text": prompt}], max_tokens=1500)
        data = parse_json(text)
        if not isinstance(data, list):
            return None
        out = []
        for d in data:
            rid = str(d.get("resource_id", "")).strip().lower().replace(" ", "_")
            if not rid_prefix(rid):
                continue
            toks = set()
            for v in d.get("identifiers") or []:
                toks |= tokens_from_value("lookup_key", v)
            out.append({"resource_id": rid, "result": str(d.get("result", "")).upper() or None,
                        "record_type": d.get("record_type"), "tokens": sorted(toks)})
        return out

    # ---------------------------------------------------------------- OCR fallback
    def _ocr(self, path, row):
        try:
            text = subprocess.run(["tesseract", path, "-", "--psm", "3"], capture_output=True,
                                  text=True, timeout=120).stdout
        except Exception:
            return []
        origin = row.get("origin", "")
        low = text.lower()
        found: dict[str, set[str]] = {}
        for line in text.splitlines():
            line_toks = tokens_from_value("lookup_key", line) | tokens_from_value("text", line)
            for m in FUZZY_RID.finditer(line):
                pre = re.sub(r"[ .]", "_", m.group(1).lower())
                rid = f"{pre}_{m.group(2)}"
                found.setdefault(rid, set()).update(line_toks)
            for alias, rid in self.aliases.items():
                if alias and re.search(r"(?<![\w])" + re.escape(alias) + r"(?![\w])", line, re.I):
                    found.setdefault(rid, set()).update(line_toks)
            # OCR often renders '_' as ' ' or '.' inside file names
            for alias, rid in self.aliases.items():
                if alias.endswith(".pdf") or alias.startswith("delivery_confirmation"):
                    loose = re.escape(alias).replace(r"_", r"[_ .]")
                    if re.search(loose, line, re.I):
                        found.setdefault(rid, set())
        out = []
        email_on_screen = bool(tokens_from_value("text", text) & {t for t in tokens_from_value("text", text) if t.startswith("email:")})
        for rid, toks in found.items():
            pre = rid_prefix(rid)
            if pre is None:
                continue
            # only report records that the screen is actually about: catalog-linked ones
            # or rows carrying an identifier on the same line
            if rid not in self.links and not toks:
                continue
            if pre in ("analytics", "support", "tombstone"):
                res = "IDENTIFIABLE" if email_on_screen and pre != "tombstone" else "REDACTED"
                if pre == "tombstone":
                    res = "IDENTIFIABLE" if any(t.startswith(("email:", "phone:")) for t in tokens_from_value("text", text)) else "REDACTED"
                if pre == "analytics" and res == "REDACTED":
                    res = "ANONYMIZED"
            else:
                res = ORIGIN_STATE.get(origin, "FOUND")
                if pre == "data_flow":
                    res = "ACTIVE"
                elif pre == "backup":
                    res = "ACTIVE"
                for w in NEGATIVE_WORDS.get(origin, ()):
                    if w in low:
                        res = {"ACTIVE": "DISABLED" if pre == "data_flow" else "BLOCKED"}.get(res, "NOT_FOUND")
            rtype = PREFIX_CATEGORY.get(pre)
            if pre == "object":
                rtype = "SUPPORT_ATTACHMENT"
            out.append({"resource_id": rid, "result": res, "record_type": rtype, "tokens": sorted(toks)})
        return out
