"""Google Gemini judge provider — plain REST via urllib, no google/anthropic SDK dependency
(bankguard stays stdlib-only). The system prompt lives in prompts/judge_v1.md (see
prompts/README.md). Selected by bankguard.judge.build_judge() when LLM_PROVIDER=gemini
(the default) and GEMINI_API_KEY is set.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "prompts" / "judge_v1.md"

_RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "attack": {"type": "BOOLEAN"},
        "confidence": {"type": "NUMBER"},
        "category": {"type": "STRING"},
        "reason": {"type": "STRING"},
    },
    "required": ["attack", "confidence", "category", "reason"],
}


class GeminiJudge:
    """.assess(message) -> {"attack", "confidence", "category", "reasoning", "risk_score"}.

    Retries once on HTTP 429 with a short backoff (free-tier rate limits are low), applies a
    hard `timeout` per HTTP call so the Firewall's overall latency budget is respected, and
    caches results in memory keyed by a hash of the message (not the message itself, so raw
    user text isn't retained longer than necessary in process memory beyond the request).
    """

    API_URL_TMPL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def __init__(self, api_key: str | None = None, model: str | None = None,
                 timeout: float = 4.0, max_retries: int = 1, prompt_path: Path = PROMPT_PATH):
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

        attempt = 0
        while True:
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                return self._parse(payload)
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < self.max_retries:
                    retry_after = exc.headers.get("Retry-After")
                    delay = float(retry_after) if retry_after else 0.5 * (2 ** attempt)
                    time.sleep(min(delay, self.timeout))
                    attempt += 1
                    continue
                raise  # never logged with the request body/key — caller only sees the type

    @staticmethod
    def _parse(payload: dict) -> dict:
        text = payload["candidates"][0]["content"]["parts"][0]["text"]
        data = json.loads(text)
        attack = bool(data.get("attack"))
        confidence = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
        return {
            "attack": attack,
            "confidence": confidence,
            "category": str(data.get("category", "none"))[:40],
            "reasoning": str(data.get("reason", ""))[:200],
            "risk_score": confidence if attack else 0.0,
        }
