"""Minimal Anthropic Messages API client (stdlib only) with disk cache and usage accounting.

The pipeline is fully runnable without an API key: every LLM-backed step has a
deterministic fallback. When ANTHROPIC_API_KEY is set, responses are cached on disk
(keyed by model + prompt hash) so repeated runs are free and reproducible.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import urllib.request
from collections import defaultdict

API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_TEXT_MODEL = os.environ.get("GHOST_TEXT_MODEL", "claude-haiku-4-5")
DEFAULT_VISION_MODEL = os.environ.get("GHOST_VISION_MODEL", "claude-sonnet-4-5")

# USD per million tokens (input, output). Update if pricing changes.
PRICING = {
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-sonnet-4-5": (3.00, 15.00),
}


class Usage:
    def __init__(self):
        self.by_model = defaultdict(lambda: {"calls": 0, "cached_calls": 0, "input": 0, "output": 0})

    def record(self, model: str, inp: int, out: int, cached: bool):
        m = self.by_model[model]
        if cached:
            m["cached_calls"] += 1
        else:
            m["calls"] += 1
        m["input"] += inp
        m["output"] += out

    def cost(self, model: str) -> float:
        pin, pout = PRICING.get(model, (0.0, 0.0))
        m = self.by_model[model]
        return m["input"] / 1e6 * pin + m["output"] / 1e6 * pout


USAGE = Usage()


class LLM:
    def __init__(self, cache_path: str):
        self.key = os.environ.get("ANTHROPIC_API_KEY")
        self.cache_path = cache_path
        self.cache = {}
        if os.path.exists(cache_path):
            try:
                self.cache = json.load(open(cache_path, encoding="utf-8"))
            except json.JSONDecodeError:
                self.cache = {}

    @property
    def available(self) -> bool:
        return bool(self.key) or bool(self.cache)

    def save(self):
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        json.dump(self.cache, open(self.cache_path, "w", encoding="utf-8"), indent=1, sort_keys=True)

    def complete(self, model: str, system: str, content: list | str, max_tokens: int = 1024) -> str | None:
        payload = {"model": model, "max_tokens": max_tokens, "temperature": 0, "system": system,
                   "messages": [{"role": "user", "content": content}]}
        key = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        if key in self.cache:
            c = self.cache[key]
            USAGE.record(model, c.get("input_tokens", 0), c.get("output_tokens", 0), cached=True)
            return c["text"]
        if not self.key:
            return None
        req = urllib.request.Request(API_URL, data=json.dumps(payload).encode(), method="POST", headers={
            "content-type": "application/json", "x-api-key": self.key, "anthropic-version": "2023-06-01"})
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    data = json.loads(resp.read())
                break
            except Exception as e:  # retry transient errors
                if attempt == 3:
                    print(f"[llm] request failed: {e}")
                    return None
                time.sleep(2 ** attempt)
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        u = data.get("usage", {})
        USAGE.record(model, u.get("input_tokens", 0), u.get("output_tokens", 0), cached=False)
        self.cache[key] = {"text": text, "input_tokens": u.get("input_tokens", 0),
                           "output_tokens": u.get("output_tokens", 0)}
        self.save()
        return text


def image_block(path: str) -> dict:
    data = base64.b64encode(open(path, "rb").read()).decode()
    mt = "image/png" if path.lower().endswith(".png") else "image/jpeg"
    return {"type": "image", "source": {"type": "base64", "media_type": mt, "data": data}}


def parse_json(text: str | None):
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        t = t[t.find("\n") + 1:] if "\n" in t else t
    for opener, closer in (("[", "]"), ("{", "}")):
        i, j = t.find(opener), t.rfind(closer)
        if i != -1 and j > i:
            try:
                return json.loads(t[i:j + 1])
            except json.JSONDecodeError:
                continue
    return None
