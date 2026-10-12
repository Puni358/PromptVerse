# Jury Q&A

Honest answers, including the parts that don't flatter the project. Numbers cited here come
from `evals/RESULTS.md` (a real run, not hand-estimated) unless noted otherwise.

**1. Why not just use the LLM for everything — why bother with regex rules at all?**
Latency and determinism. The rule engine runs in under a millisecond with zero network
dependency; the judge takes ~1.3–2.3s per call in our testing (see `evals/RESULTS.md`'s latency
column) and needs a key, a network, and a provider that's up. Rules also behave the same way
every time, which matters for a security control you want to reason about. The LLM adds
judgment on novel phrasing the rules can't anticipate — it's a complement, not a replacement.

**2. Isn't the judge itself attackable — it's an LLM reading untrusted text?**
Yes, in principle. That's exactly why it's wired to only ever *raise* the combined risk score,
never lower it (`risk = max(rules_risk, judge_risk)` in `bankguard/firewall.py`). A successful
prompt injection against the judge can at worst make it agree the message is "fine" — which
just means the hybrid pipeline degrades to rules-only behavior for that message. It cannot cause
the judge to *unblock* something the rules already flagged.

**3. What's your actual accuracy?**
Rules-only: 88.6% overall accuracy, 84.1% attack catch rate, 1.7% false-positive rate, on 184
labelled messages. Hybrid (Gemini): 91.8% accuracy, 88.9% catch rate, same 1.7% false-positive
rate. Full per-category breakdown and every miss, by id and text, is in `evals/RESULTS.md`.

**4. Is that eval dataset a fair test?**
Partially — and we say so in the results file. We wrote both the rules and the dataset, so some
attack phrasings track rule vocabulary closely (e.g. "ignore...instructions") and will
over-state real-world catch rate. The multilingual and obfuscated categories are a better
generalization proxy since they paraphrase rather than reuse wording — and those are exactly
where the system does worse (60% and 93.3% respectively, rules-only).

**5. What's the biggest real gap you found?**
The judge-consultation gate itself. It only fires for high-risk intents or grey-zone rule
scores. `intent.py`'s classifier is English-keyword regex, so a Chinese/Japanese/Arabic/Russian
message asking to move money scores 0 on intent and 0 on rules, and the judge is never called —
not because it failed, but because it was never asked. Every hybrid miss in the
`multilingual_override` category has `risk_score=0.0`, confirming this directly. The fix is
widening the intent classifier's language coverage, not tuning the judge prompt.

**6. Why Gemini specifically?**
Google AI Studio API keys are free to obtain and the REST API needs no SDK — fits a hard
stdlib-only constraint for the rest of the codebase. The provider is behind a one-method
interface (`bankguard/judge.py`), so swapping to another vendor means implementing
`.assess(message) -> dict` and adding one line to `build_judge()`; nothing in `Firewall` or the
server layer is Gemini-specific.

**7. How do you handle the LLM provider's own model deprecations?**
We hit this directly while building: `gemini-2.5-flash` returned a 404 telling us it's "no
longer available to new users," pointing at a replacement. The default model is one env var
(`GEMINI_MODEL`), and `.env.example` documents the verified-working default along with a note
to re-check Google's model list before deploying, rather than hardcoding a model id anywhere.

**8. What happens if the Gemini API is down or slow?**
A 4-second timeout per call, one retry on HTTP 429 with backoff. If it still fails: for a
high-risk (money-moving) intent, the firewall fails closed — blocks the request — rather than
letting a transfer through on an LLM outage. For a non-high-risk grey-zone message, the rules
verdict (already below the block threshold) stands, so a low-stakes balance question isn't
blocked by an unrelated outage.

**9. Can an attacker bypass the firewall by making the judge time out on purpose?**
Not for money-moving actions — that's exactly the fail-closed case above; a timeout blocks, it
doesn't allow. For non-high-risk messages it could suppress the judge's extra scrutiny, but the
rules layer still runs unconditionally and independently, so the attacker is back to needing to
beat the rules alone.

**10. What does "strict mode" do, and why would you not always use it?**
`Config(strict_intent=True)` blocks any message that doesn't match a recognized banking intent
at all — useful for a narrowly-scoped assistant that should refuse "tell me a joke" outright.
It's off by default because a general-purpose assistant may legitimately field FAQ-style
questions that aren't a specific banking action.

**11. How is this deployed, and what's the blast radius of a bad deploy?**
Vercel: `api/check.py`/`api/health.py` as Python serverless functions, `web/` as static assets.
No persistent state beyond an in-memory per-instance rate limiter and judge cache — a bad
deploy affects only new requests to that instance, there's no database to corrupt. See
`docs/DEPLOY.md` for exactly what is and isn't covered (notably: the rate limiter is
per-instance, not a global guarantee, on a multi-instance serverless platform).

**12. Do you ever log or store the user's message?**
No persistent storage at all in this codebase — `log_message` is overridden to suppress
`http.server`'s default access logging specifically so raw user text never hits stdout/a log
file. The judge's in-memory cache is keyed by a hash of the message, not the message itself,
and is process-lifetime only.

**13. How do you keep account numbers from leaking?**
`bankguard/intent.py`'s entity extraction only ever returns the last 4 digits
(`"****" + n[-4:]`) of any detected account number; the full number never leaves that function.
Covered by a dedicated test (`test_no_raw_account_numbers_echoed`).

**14. What would you add with another week?**
(a) Widen `intent.py` beyond English regex — the single highest-leverage fix given finding #5.
(b) A shared rate-limit/cache store (Redis) for true cross-instance limits on Vercel. (c)
Structured logging of `blocked` verdicts (never the raw message) for operational visibility —
currently there's none. (d) A second LLM provider behind the same interface, to A/B the judge
and reduce single-vendor risk.

**15. Why trust a hackathon project's security claims at all?**
We tried to make that unnecessary to take on faith: the rule engine, the eval dataset, and the
eval runner are all in this repo — `python evals/run_evals.py` reproduces every number above on
demand, against whichever model/version is current when you run it. Misses are listed by exact
message text, not summarized away. That's a lower bar than a production audit, but it's a
verifiable one.
