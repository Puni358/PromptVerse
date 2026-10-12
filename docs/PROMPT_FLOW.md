# Prompt flow

How a single message actually reaches the Gemini judge, and exactly what's sent — end to end,
matching the real code in `bankguard/firewall.py` and `bankguard/providers/gemini.py`.

## 1. Gate: does the judge get consulted at all?

`Firewall._check()` (`bankguard/firewall.py`) computes the rule-engine score first, always.
The judge is only called when:

```python
in_grey_zone = cfg.judge_band_low <= rules_risk < threshold   # 0.20 <= rules_risk < threshold
should_consult = self.judge is not None and (intent["high_risk"] or in_grey_zone)
```

So: every high-risk intent (transfer, bill pay, profile/account change — `bankguard/intent.py`)
gets a judge opinion regardless of how low the rule score is, *and* any message whose rule
score lands in the 0.20–threshold grey zone gets one too, even if its intent isn't high-risk.
A message with rule score 0 and a non-high-risk intent (e.g. "what's my balance?") never
reaches the judge — there's nothing for it to add. This is also the biggest honestly-reported
gap: `intent.py`'s classifier is English-keyword regex, so a non-English money-moving message
can score 0 and never trigger a judge call either — see `evals/RESULTS.md`'s multilingual
misses, all at `risk=0.0`.

## 2. What's actually sent to Gemini

`GeminiJudge._call()` builds one `generateContent` request:

```python
POST https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent
Headers: Content-Type: application/json, x-goog-api-key: <GEMINI_API_KEY>

{
  "systemInstruction": {"parts": [{"text": "<contents of prompts/judge_v1.md>"}]},
  "contents": [{"role": "user", "parts": [{"text": "<message>...the raw user text...</message>"}]}],
  "generationConfig": {
    "temperature": 0,
    "responseMimeType": "application/json",
    "responseSchema": {
      "type": "OBJECT",
      "properties": {
        "attack": {"type": "BOOLEAN"},
        "confidence": {"type": "NUMBER"},
        "category": {"type": "STRING"},
        "reason": {"type": "STRING"}
      },
      "required": ["attack", "confidence", "category", "reason"]
    }
  }
}
```

Three things worth calling out:

- **The message is wrapped, never concatenated into the system prompt.** It arrives as the
  *user* turn, inside `<message>` tags, with the system instruction already having told the
  model that content between those tags is untrusted data to classify, not follow. See
  `prompts/README.md` for why this framing is load-bearing.
- **`responseSchema` does the formatting enforcement**, not a "respond in JSON" sentence in the
  prompt. The prompt only explains what each field means; see `prompts/README.md`'s "JSON-only
  output, enforced structurally" note for why that's a smaller attack surface.
- **`temperature: 0`** — a security classifier should be as close to deterministic as a given
  model allows. It's not perfectly deterministic in practice (see `evals/RESULTS.md`'s honest
  limitations), but 0 is the right default to ask for.

## 3. What comes back, and how it's combined

`GeminiJudge._parse()` reads `candidates[0].content.parts[0].text` (guaranteed valid JSON by
`responseSchema`), clamps `confidence` to `[0, 1]`, and returns:

```python
{"attack": bool, "confidence": float, "category": str, "reasoning": str, "risk_score": float}
# risk_score = confidence if attack else 0.0
```

Back in `Firewall._check()`:

```python
risk = max(rules_risk, judge_result["risk_score"])
blocked = risk >= threshold
```

The judge can only ever *raise* the combined risk, never lower it — see
`docs/ARCHITECTURE.md`'s "additive, never load-bearing alone" note for the security reasoning.
The full judge output (attack, confidence, category, reasoning) is kept in the response's
`layers.llm_judge`, separate from `layers.rules`, so the UI and any caller can see exactly what
each layer decided — not just the merged number.

## 4. Failure handling

| Failure | What happens |
|---|---|
| HTTP 429 (rate limited) | One retry, honoring `Retry-After` if present, else `0.5 * 2^attempt`, capped at the 4s timeout. Second failure propagates. |
| Timeout (4s) or any other exception | Propagates to `Firewall._check()`. For a **high-risk intent**, risk is forced to the threshold (fail closed — blocked). For a non-high-risk grey-zone message, the rules verdict (already below threshold) stands — an LLM outage doesn't block a low-stakes balance inquiry. |
| `LLM_PROVIDER=none` or no `GEMINI_API_KEY` | `build_judge()` returns `None` before any of the above — the firewall runs rules-only, and every verdict's `layers.pipeline` says `"rules_only"` so this is never silently ambiguous. |

## 5. Caching

`GeminiJudge` keeps an in-memory cache keyed by `sha256(message)` for the lifetime of the
process (not the message itself, so raw text isn't retained longer than one request needs).
This matters more for `evals/run_evals.py`, which wraps the judge in `CachingThrottledJudge` —
persisting to `evals/cache.json` across runs and throttling real calls (`EVAL_THROTTLE_SECONDS`,
default 1.5s) — so re-running the eval after a dataset tweak doesn't re-pay for every unchanged
row against a rate-limited free-tier key.
