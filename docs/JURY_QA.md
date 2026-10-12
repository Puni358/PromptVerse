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
Two numbers, because one dataset isn't enough (see Q4). On the main set (204 messages, written
alongside the rules): rules-only 89.7% accuracy / 84.1% catch rate / 1.3% false-positive rate;
hybrid (Gemini) 98.5% / 98.4% / 1.3%. On the held-out set (50 messages, written after the rules
and dataset were final, deliberately phrased unlike either, never tuned against): rules-only
54.0% / 23.3% / 0%; hybrid 96.0% / 93.3% / 0%. The held-out numbers are the more honest signal
for real-world performance — full per-category breakdown and every miss, by id and text, is in
`evals/RESULTS.md`.

**4. Is that eval dataset a fair test?**
The main one, only partially — and we say so in the results file. We wrote both the rules and
the dataset, so some attack phrasings track rule vocabulary closely and will over-state
real-world catch rate. That's exactly why we added `evals/heldout.jsonl`: 50 new messages
written after the rules and main dataset were final, deliberately phrased unlike anything in
either (novel obfuscation techniques, social-engineering framings, attacks in languages not in
the main set), and not tuned against afterward. The gap between the two (89.7%→98.5% main vs.
54.0%→96.0% held-out, rules-only to hybrid) is itself informative: the rules alone do far worse
on genuinely novel phrasing, which is exactly what you'd hope to see from an honest test.

**5. What's the biggest real gap you found?**
Two, found in sequence. First: the judge-consultation gate used to only fire for high-risk
intents or grey-zone rule scores, and `intent.py`'s classifier was English-keyword regex — so a
non-English message asking to move money scored 0 on both and the judge was never called, not
wrong. We widened the gate (now also fires on unknown intent, non-Latin script, obfuscation
flags, and untrusted sources) and `intent.py`'s language coverage, and verified the fix on the
held-out set rather than just asserting it. Second: under the eval's own sustained call volume,
the original 4-second judge timeout was occasionally too tight, and a handful of genuine
high-risk multilingual messages got fail-closed to `blocked` by a timeout, not a misclassification
— see Q8's answer and `evals/RESULTS.md`'s honest-limitations section for the full account and
the fix (a 7-second total retry budget).

**6. Why Gemini specifically?**
Google AI Studio API keys are free to obtain and the REST API needs no SDK — fits a hard
stdlib-only constraint for the rest of the codebase. The provider is behind a one-method
interface (`bankguard/judge.py`), so swapping to another vendor means implementing
`.assess(message) -> dict` and adding one line to `build_judge()`; nothing in `Firewall` or the
server layer is Gemini-specific.

**7. How do you handle the LLM provider's own model deprecations?**
We hit this directly while building: `gemini-2.5-flash` (the model we started with) returned a
404 telling us it's "no longer available to new users." The current default,
`gemini-flash-lite-latest`, is one env var (`GEMINI_MODEL`), and `.env.example` documents it
along with a note to re-check Google's model list before deploying, rather than hardcoding a
model id anywhere in the code.

**8. What happens if the Gemini API is down or slow?**
A 7-second TOTAL timeout budget across one attempt plus one retry (each attempt gets roughly
half the remaining budget), on HTTP 429 or a socket timeout — still comfortably under Vercel's
10s function limit. If it still fails: for a high-risk (money-moving) intent, or any other
trigger, the firewall fails closed — blocks the request — rather than letting a transfer through
on an LLM outage. We hit this for real while building the eval suite: the *original* 4-second
single-attempt timeout, under the sustained call volume of a full eval run (250+ calls against a
free-tier key), occasionally timed out and fail-closed a handful of genuine high-risk
multilingual messages. We verified it was the timeout and not a misclassification by re-running
those exact messages individually afterward (all correct), then fixed the budget rather than
hiding the run — see `evals/RESULTS.md`. For a message that triggered the judge for a
non-high-risk reason (unknown intent, non-Latin script, etc.), a judge failure leaves the rules
verdict standing instead of failing closed, and the response's `reasons` says explicitly that
the judge was unavailable for a non-English message when that's the case.

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
(a) `intent.py` now covers Hindi/Kannada/Tamil/Telugu/Hinglish/Spanish, but that's still six
languages hand-picked by us, not a general solution — a proper fix would route language
detection through something more systematic than per-language regex. (b) The two remaining
held-out misses (Q4) are both data-exfiltration attempts with a plausible legitimate-sounding
pretext ("I'm updating my will, list every beneficiary..."); the judge prompt could be sharpened
specifically against pretext-wrapped exfiltration. (c) A shared rate-limit/cache store (Redis)
for true cross-instance limits on Vercel. (d) Structured logging of `blocked` verdicts (never
the raw message) for operational visibility — currently there's none. (e) A second LLM provider
behind the same interface, to A/B the judge and reduce single-vendor risk.

**15. Why trust a hackathon project's security claims at all?**
We tried to make that unnecessary to take on faith: the rule engine, the eval dataset, and the
eval runner are all in this repo — `python evals/run_evals.py` reproduces every number above on
demand, against whichever model/version is current when you run it. Misses are listed by exact
message text, not summarized away. That's a lower bar than a production audit, but it's a
verifiable one.
