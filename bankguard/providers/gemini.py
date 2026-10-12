"""Google Gemini judge provider — plain REST via urllib, no google/anthropic SDK dependency
(bankguard stays stdlib-only). The system prompt lives in prompts/judge_v3.md (see
prompts/README.md; judge_v1.md/judge_v2.md are kept for history, not deleted). Selected by
bankguard.judge.build_judge() when LLM_PROVIDER=gemini (the default) and GEMINI_API_KEY is set.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

logger = logging.getLogger("bankguard.gemini")

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
    "intent", "prompt_version"}. "intent" is one of bankguard/intent.py's intent names, or
    "other" — used by Firewall._check() only as a fallback when the rules' own intent
    classifier found nothing (see bankguard/firewall.py). "prompt_version" (e.g. "v3") says
    which prompts/judge_vN.md produced this verdict, so a verdict is attributable to a specific
    prompt even after the default is bumped.

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
        self.prompt_version = prompt_path.stem.removeprefix("judge_")  # e.g. "judge_v3.md" -> "v3"
        self._cache: dict[str, dict] = {}

    def assess(self, message: str) -> dict:
        cache_key = hashlib.sha256(message.encode("utf-8", "ignore")).hexdigest()
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        result = self._call(message)
        result["prompt_version"] = self.prompt_version
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
            t0 = time.monotonic()
            remaining = deadline - t0
            if remaining <= 0:
                logger.error("Gemini judge call exceeded timeout budget attempt=%d timeout=%.2fs", attempt, self.timeout)
                exc = TimeoutError("judge call exceeded its total timeout budget")
                exc.status_code = 408
                exc.error_type = "timeout"
                exc.gemini_message = "Judge call exceeded total timeout budget"
                exc.latency_ms = (time.monotonic() - t0) * 1000
                exc.is_transient = True
                raise exc

            per_attempt_timeout = remaining if attempt >= self.max_retries else remaining / 2
            try:
                with urllib.request.urlopen(req, timeout=per_attempt_timeout) as resp:
                    raw_data = resp.read().decode("utf-8")
                    latency_ms = (time.monotonic() - t0) * 1000
                    payload = json.loads(raw_data)
                logger.info("Gemini judge call succeeded model=%s latency_ms=%.1f attempt=%d", self.model, latency_ms, attempt)
                return self._parse(payload)
            except Exception as exc:
                latency_ms = (time.monotonic() - t0) * 1000
                status_code = getattr(exc, "code", None)
                gemini_status = None
                gemini_msg = ""

                if isinstance(exc, urllib.error.HTTPError):
                    try:
                        err_body = exc.read().decode("utf-8", "ignore")
                        err_json = json.loads(err_body)
                        gemini_err = err_json.get("error", {})
                        gemini_msg = gemini_err.get("message", "")
                        gemini_status = gemini_err.get("status", "")
                    except Exception:
                        gemini_msg = str(exc)

                is_timeout = isinstance(exc, TimeoutError) or (
                    isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, TimeoutError)
                )

                if status_code == 429:
                    msg_lower = gemini_msg.lower()
                    if "daily" in msg_lower or "quota exceeded" in msg_lower or "per day" in msg_lower:
                        error_type = "quota_exhausted"
                        is_transient = False
                    else:
                        error_type = "rate_limit"
                        is_transient = True
                elif status_code in (401, 403):
                    error_type = "auth_error"
                    is_transient = False
                elif status_code == 400:
                    error_type = "invalid_request"
                    is_transient = False
                elif status_code in (500, 502, 503, 504):
                    error_type = "service_error"
                    is_transient = True
                elif is_timeout:
                    error_type = "timeout"
                    is_transient = True
                    status_code = status_code or 408
                elif isinstance(exc, urllib.error.URLError):
                    error_type = "network_error"
                    is_transient = True
                else:
                    error_type = "unknown"
                    is_transient = False

                # Attach diagnostics to exception
                exc.status_code = status_code
                exc.error_type = error_type
                exc.gemini_status = gemini_status
                exc.gemini_message = gemini_msg or str(exc)
                exc.latency_ms = latency_ms
                exc.is_transient = is_transient

                # Log diagnostics without leaking API key or sensitive user text
                logger.warning(
                    "Gemini judge error model=%s status_code=%s error_type=%s gemini_status=%s message=%s latency_ms=%.1f attempt=%d is_transient=%s",
                    self.model, status_code, error_type, gemini_status, gemini_msg, latency_ms, attempt, is_transient
                )

                if not is_transient or attempt >= self.max_retries:
                    raise exc

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise exc

                delay = 0.5 * (2 ** attempt)
                if status_code == 429 and isinstance(exc, urllib.error.HTTPError):
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    if retry_after:
                        try:
                            delay = float(retry_after)
                        except (ValueError, TypeError):
                            pass
                delay = min(delay, max(remaining - 0.1, 0.0))
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
