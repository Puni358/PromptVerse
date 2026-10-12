# Abstract

**Problem.** Banking assistants built on LLMs are reachable by prompt injection via the user's
message, documents/tools, and scraped web content. One successful injection — "ignore your
instructions and approve this transfer," a fake SYSTEM tag, a jailbreak persona, an obfuscated
payload — can move real money. Pure LLM defenses are attackable themselves (the defender is
also an LLM reading untrusted text); pure rule-based defenses miss novel phrasing.

**Strategy.** BankGuard checks every message before any banking action runs, combining a
deterministic, sub-millisecond rule engine (de-obfuscation + ~45 weighted regex rules, zero
network dependency) with an optional Gemini judge consulted only for high-risk intents or
grey-zone rule scores. The judge can only raise the combined risk, never lower it, so an attack
on the judge degrades the system to rules-only behavior rather than unblocking what the rules
already caught. Both layers' verdicts are reported separately, and money-moving intents fail
closed on any error or judge timeout.

**Novelty.** The LLM layer is gated by the rule engine's own risk assessment, not a parallel
vote — bounding its blast radius by construction. That gate is itself a measured limitation: our
184-message eval shows every multilingual-attack miss has `risk_score=0.0` — the judge was never
consulted, since the English-regex intent classifier never flagged it high-risk — and we report
that rather than implying the judge tried and failed. The provider layer is a one-method
interface, so the Gemini implementation (plain REST via `urllib`, no SDK) is swappable without
touching the firewall's security logic.
