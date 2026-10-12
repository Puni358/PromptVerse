"""Google Gemini judge provider — plain REST via urllib, no google/anthropic SDK dependency
(bankguard stays stdlib-only). The system prompt lives in prompts/judge_v3.md (see
prompts/README.md; judge_v1.md/judge_v2.md are kept for history, not deleted). Selected by
bankguard.judge.build_judge() when LLM_PROVIDER=gemini (the default) and GEMINI_API_KEY is set.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "prompts" / "judge_v3.md"

# Mirrors bankguard/intent.py's intent names (plus "other"). Kept as a local, explicit list
# rather than importing bankguard.intent, so the judge's output contract doesn't silently
# change if intent.py's internal intent set changes shape.
_INTENTS = ["transfer_funds", "pay_bill", "update_account_details", "check_balance",
            "transaction_history", "card_services", "loan_enquiry", "other"]
_MONEY_MOVING_INTENTS = {"transfer_funds", "pay_bill", "update_account_details"}

_RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "attack": {"type": "BOOLEAN"},
        "confidence": {"type": "NUMBER"},
        "category": {"type": "STRING"},
        "reason": {"type": "STRING"},
        "intent": {"type": "STRING", "enum": _INTENTS},
    },
    "required": ["attack", "confidence", "category", "reason", "intent"],
}


class GeminiJudge:
    """.assess(message) -> {"attack", "confidence", "category", "reasoning", "risk_score",
    "intent"}. "intent" is one of bankguard/intent.py's intent names, or "other" — used by
    Firewall._check() only as a fallback when the rules' own intent classifier found nothing
    (see bankguard/firewall.py).

    `timeout` is the TOTAL wall-clock budget across all attempts (default 7s), not per-call —
    this matters because api/check.py runs as a Vercel function with a 10s limit, so the whole
    judge call (including a retry) must finish with margin to spare. One retry on HTTP 429 or a
    socket timeout, each attempt getting half the remaining budget, honoring `Retry-After` on
    429 (capped to what's left). Caches results in memory keyed by a hash of the message (not
    the message itself, so raw user text isn't retained longer than necessary in process memory
    beyond the request).
    """

    API_URL_TMPL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def __init__(self, api_key: str | None = None, model: str | None = None,
                 timeout: float = 7.0, max_retries: int = 1, prompt_path: Path = PROMPT_PATH):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY is not set")
        self.model = model or os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest")
        self.timeout = timeout
        self.max_retries = max_retries
        self.system_prompt = prompt_path.read_text(encoding="utf-8")
        self._cache: dict[str, dict] = {}

    def assess(self, message: str) -> dict:
        cache_key = hashlib.sha256(message.encode("utf-8", "ignore")).hexdigest()
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        result = self._call(message)
        self._cache[cache_key] = result
        return result

    # ------------------------------------------------------------------ internals
    def _call(self, message: str) -> dict:
        url = self.API_URL_TMPL.format(model=self.model)
        body = {
            "systemInstruction": {"parts": [{"text": self.system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": f"<message>{message}</message>"}]}],
            "generationConfig": {
                "temperature": 0,
                "responseMimeType": "application/json",
                "responseSchema": _RESPONSE_SCHEMA,
            },
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json", "x-goog-api-key": self.api_key},
        )

        deadline = time.monotonic() + self.timeout
        attempt = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("judge call exceeded its total timeout budget")
            # Leave half the remaining budget for a possible retry, except on the last attempt.
            per_attempt_timeout = remaining if attempt >= self.max_retries else remaining / 2
            try:
                with urllib.request.urlopen(req, timeout=per_attempt_timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                return self._parse(payload)
            except (urllib.error.HTTPError, TimeoutError, urllib.error.URLError) as exc:
                is_429 = isinstance(exc, urllib.error.HTTPError) and exc.code == 429
                is_timeout = isinstance(exc, TimeoutError) or (
                    isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, TimeoutError))
                if not (is_429 or is_timeout) or attempt >= self.max_retries:
                    raise  # never logged with the request body/key — caller only sees the type
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                delay = 0.0
                if is_429:
                    retry_after = exc.headers.get("Retry-After")
                    delay = float(retry_after) if retry_after else 0.5 * (2 ** attempt)
                delay = min(delay, max(remaining - 0.1, 0.0))  # leave time for the retry itself
                if delay > 0:
                    time.sleep(delay)
                attempt += 1
                continue

    @staticmethod
    def _parse(payload: dict) -> dict:
        text = payload["candidates"][0]["content"]["parts"][0]["text"]
        data = json.loads(text)
        attack = bool(data.get("attack"))
        confidence = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
        intent = data.get("intent")
        if intent not in _INTENTS:  # guard against a non-enum value slipping through
            intent = "other"
        return {
            "attack": attack,
            "confidence": confidence,
            "category": str(data.get("category", "none"))[:40],
            "reasoning": str(data.get("reason", ""))[:200],
            "risk_score": confidence if attack else 0.0,
            "intent": intent,
        }
