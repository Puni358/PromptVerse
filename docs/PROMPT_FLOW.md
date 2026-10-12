# Prompt flow

How a single message actually reaches the Gemini judge, and exactly what's sent — end to end,
matching the real code in `bankguard/firewall.py` and `bankguard/providers/gemini.py`.

## 1. Gate: does the judge get consulted at all?

`Firewall._check()` (`bankguard/firewall.py`) computes the rule-engine score first, always.
The judge is consulted if *any* of six conditions hold (first version of this doc only had the
first and last — the rest were added specifically to close a multilingual gap found in
`evals/RESULTS.md`, see below):

```python
triggers = []
if intent["high_risk"]: triggers.append("high_risk_intent")
if intent["name"] == "unknown": triggers.append("unknown_intent")
if contains_non_latin_script(message): triggers.append("non_latin_script")
if any(h.category == "obfuscation" for h in hits): triggers.append("obfuscation_detected")
if source != "user": triggers.append("untrusted_source")
if rules_risk >= cfg.judge_band_low: triggers.append("rules_risk_at_or_above_grey_zone")  # >= 0.20
should_consult = self.judge is not None and bool(triggers)
```

A message with rule score 0, a recognized non-high-risk intent, Latin script, no obfuscation
flags, and `source="user"` is the one case that never reaches the judge — e.g. "what's my
balance?" — because there's genuinely nothing for the judge to add there. Every other case now
gets a second opinion even at rule score 0, specifically because **zero rules_risk is not
evidence of safety for text the rule engine can't parse in the first place.** `triggers` is
kept in the response as `layers.llm_judge.triggered_by`, so you can always see exactly why
(or whether) the judge ran for a given message.

**Why this got wider.** The original version only consulted for high-risk intent or the
grey-zone band. `intent.py`'s classifier is English-keyword regex, so a non-English
money-moving message scored 0 on both intent and rules and never reached the judge at all — the
first eval run's own `multilingual_override` misses were all at `risk_score=0.0`, meaning
Gemini was never asked, not that it answered wrong. Widening the intent classifier's language
coverage (see `bankguard/intent.py`'s Hindi/Kannada/Tamil/Telugu/Hinglish/Spanish patterns) and
widening this gate (non-Latin script, unknown intent, obfuscation, untrusted source) were both
done to close that gap — `evals/RESULTS.md` reports whether it actually closed it or just
narrowed it, including on `evals/heldout.jsonl`, a held-out set the gate wasn't tuned against.

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
| HTTP 429 or a socket timeout | One retry. `GeminiJudge.timeout` (default 7s) is a **total** wall-clock budget across both attempts, not per-call — each attempt gets roughly half the remaining budget, so first-attempt-plus-retry stays well inside Vercel's 10s function limit. 429s additionally honor `Retry-After` if present, capped to what's left of the budget. Second failure propagates. |
| Timeout or any other exception | Propagates to `Firewall._check()`. For a **high-risk intent**, risk is forced to the threshold (fail closed — blocked), and `layers.llm_judge.fail_closed` is set. For any other trigger (non-high-risk), the rules verdict stands as-is — an LLM outage doesn't block a low-stakes request. For a non-English message specifically, the blocked/safe verdict's `reasons` says so explicitly ("llm_judge unavailable for a non-English message..."), since a silent rules-only fallback is less reliable there by construction. |
| `LLM_PROVIDER=none` or no `GEMINI_API_KEY` | `build_judge()` returns `None` before any of the above — the firewall runs rules-only, and every verdict's `layers.pipeline` says `"rules_only"` so this is never silently ambiguous. |

This isn't just theoretical: the eval run behind the current `evals/RESULTS.md` numbers hit
real timeouts under sustained load (hundreds of calls at a 1.5s throttle against a free-tier
key) — a handful of genuine multilingual messages got fail-closed to `blocked` because the
judge call for them specifically timed out, not because it misclassified them. Re-running just
those rows individually afterward confirmed they classify correctly when the API isn't under
that load. `evals/RESULTS.md` reports this honestly rather than hiding it behind a quiet re-run.

## 5. Caching

`GeminiJudge` keeps an in-memory cache keyed by `sha256(message)` for the lifetime of the
process (not the message itself, so raw text isn't retained longer than one request needs).
This matters more for `evals/run_evals.py`, which wraps the judge in `CachingThrottledJudge` —
persisting to `evals/cache.json` across runs and throttling real calls (`EVAL_THROTTLE_SECONDS`,
default 1.5s) — so re-running the eval after a dataset tweak doesn't re-pay for every unchanged
row against a rate-limited free-tier key.
