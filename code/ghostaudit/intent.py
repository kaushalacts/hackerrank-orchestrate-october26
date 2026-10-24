"""Does the request text authorize deletion? Multilingual; LLM-first with a rule fallback.

Rule fallback: a request is NON-deletion when it carries an explicit non-deletion signal
(keep/continue using the account, access/export/copy, correction, marketing opt-out,
login help), unless it also contains an unambiguous erasure verb aimed at the account.
"""
from __future__ import annotations

import re

from .llm import DEFAULT_TEXT_MODEL, LLM, parse_json

INTENT_SYSTEM = """You classify customer privacy requests for an e-commerce company.
Decide whether the customer AUTHORIZES deletion/erasure of their account and personal data.
Requests for access, a copy/export, correction, email change, login help, invoices, or
marketing opt-out are NOT deletion, even if they mention data. Partial wording such as
"close my account", "erase", "remove my profile" in any language IS deletion.
Answer with JSON only: {"deletion": true|false, "reason": "<= 12 words"}"""

NON_DELETION = [
    r"not asking for deletion", r"don'?t delete", r"do not (close|delete)", r"keep the account",
    r"leave (the|my) (account|profile)", r"continue using", r"still (use|need|want)",
    r"information request", r"(send me|need) a copy", r"portable format", r"download my", r"marketing lists only",
    r"stop the promotional", r"correct it", r"misspelled", r"out of date", r"resetting the login",
    r"change the email", r"without removing", r"not a request to erase",
]
DELETION = [
    r"delet", r"eras", r"remove (my|the) (account|profile)", r"close (my|this|the) account",
    r"\bremov", r"\bgone\b", r"supprim", r"suppression", r"elimin", r"exclus", r"삭제", r"削除", r"lösch", r"cancel",
]


def rule_intent(text: str) -> bool:
    t = text.lower()
    neg = any(re.search(p, t) for p in NON_DELETION)
    pos = any(re.search(p, t) for p in DELETION)
    if neg:
        return False
    return pos


class IntentClassifier:
    def __init__(self, llm: LLM | None):
        self.llm = llm
        self.disagreements: list[tuple[str, bool, bool]] = []

    def is_deletion(self, case_id: str, text: str) -> bool:
        rule = rule_intent(text)
        if self.llm is None or not self.llm.available:
            return rule
        out = parse_json(self.llm.complete(DEFAULT_TEXT_MODEL, INTENT_SYSTEM, text, max_tokens=60))
        if not isinstance(out, dict) or "deletion" not in out:
            return rule
        llm = bool(out["deletion"])
        if llm != rule:
            self.disagreements.append((case_id, rule, llm))
            # explicit "do not delete"-style signals are high precision: trust them
            if not rule and any(re.search(p, text.lower()) for p in NON_DELETION):
                return False
        return llm
