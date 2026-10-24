"""Identity resolution: current snapshot + historical audit log -> identifier tokens per user."""
from __future__ import annotations

import csv
import re
from collections import defaultdict
from dataclasses import dataclass, field

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
USER_RE = re.compile(r"\buser_\d+\b")


def norm_email(v: str) -> str:
    return v.strip().lower()


def norm_phone(v: str) -> str:
    return "".join(c for c in v if c.isdigit())


def norm_name(v: str) -> str:
    return " ".join(v.strip().lower().split())


def tokens_from_value(key: str | None, value) -> set[str]:
    """Turn one field value into identifier tokens (email:, phone:, hash:, user:, name:)."""
    out: set[str] = set()
    if value is None:
        return out
    if isinstance(value, (int, float, bool)):
        return out
    s = str(value).strip()
    if not s or s.lower() in {"null", "none", "[redacted]", "redacted"}:
        return out
    k = (key or "").lower()
    for m in EMAIL_RE.findall(s):
        out.add("email:" + norm_email(m))
    for m in HASH_RE.findall(s):
        out.add("hash:" + m)
    for m in USER_RE.findall(s):
        out.add("user:" + m)
    if "phone" in k or k in {"scan_key", "lookup_key", "subject_key", "match_key", "owner_key", "correlation_key", "query"}:
        if re.fullmatch(r"[+()\d\s.\-]{7,}", s):
            out.add("phone:" + norm_phone(s))
    if k in {"full_name", "display_name", "requester_name", "name", "customer_name"}:
        out.add("name:" + norm_name(s))
    return out


@dataclass
class Person:
    user_id: str
    name: str
    tokens: set[str] = field(default_factory=set)       # all current + historical identifiers
    direct_tokens: set[str] = field(default_factory=set)  # email/phone/hash/name (not user_id)
    history: list[dict] = field(default_factory=list)   # audit rows (audit_id, field, old, new, time)


class IdentityIndex:
    def __init__(self, identities_csv: str, audit_csv: str):
        self.people: dict[str, Person] = {}
        self.owner: dict[str, set[str]] = defaultdict(set)
        for r in csv.DictReader(open(identities_csv, encoding="utf-8")):
            p = Person(r["user_id"], r["name"])
            self.people[p.user_id] = p
            self._add(p, "email:" + norm_email(r["email"]))
            self._add(p, "phone:" + norm_phone(r["phone"]))
            self._add(p, "hash:" + r["email_hash"].strip().lower())
            self._add(p, "name:" + norm_name(r["name"]))
            self._add(p, "user:" + p.user_id, direct=False)
        for r in csv.DictReader(open(audit_csv, encoding="utf-8")):
            p = self.people.get(r["user_id"])
            if p is None:
                p = Person(r["user_id"], "")
                self.people[p.user_id] = p
                self._add(p, "user:" + p.user_id, direct=False)
            p.history.append(r)
            f = r["field_name"]
            for v in (r["old_value"], r["new_value"]):
                if not v:
                    continue
                if f == "email":
                    self._add(p, "email:" + norm_email(v))
                elif f == "phone":
                    self._add(p, "phone:" + norm_phone(v))
                elif f == "email_hash":
                    self._add(p, "hash:" + v.strip().lower())
                elif f == "name":
                    self._add(p, "name:" + norm_name(v))

    def _add(self, p: Person, tok: str, direct: bool = True):
        p.tokens.add(tok)
        if direct:
            p.direct_tokens.add(tok)
        self.owner[tok].add(p.user_id)

    def resolve_email(self, email: str) -> str | None:
        owners = self.owner.get("email:" + norm_email(email), set())
        return next(iter(owners)) if len(owners) == 1 else None

    def owners_of(self, tokens: set[str]) -> set[str]:
        """Users unambiguously identified by strong tokens (names only count when unique)."""
        found: set[str] = set()
        for t in tokens:
            o = self.owner.get(t)
            if not o:
                continue
            if t.startswith("name:") and len(o) != 1:
                continue
            found |= o
        return found

    def strong_owner(self, tokens: set[str]) -> str | None:
        strong = {t for t in tokens if not t.startswith("name:")}
        o = self.owners_of(strong)
        if len(o) == 1:
            return next(iter(o))
        if not strong:
            o = self.owners_of(tokens)
            if len(o) == 1:
                return next(iter(o))
        return None
