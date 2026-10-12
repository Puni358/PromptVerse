"""Pluggable LLM judge layer. `Firewall(judge=...)` only requires a duck-typed
`.assess(message: str) -> dict` returning {"attack", "confidence", "category", "reasoning",
"risk_score"} (see bankguard/firewall.py's _check() for exactly how it's combined with the
rule-engine verdict, and docs/PROMPT_FLOW.md for the full decision flow).

LLM_PROVIDER selects the implementation:
  - "gemini" (default): bankguard.providers.gemini.GeminiJudge — Google Gemini via the plain
    REST API (urllib, no SDK). Needs GEMINI_API_KEY.
  - "none": no judge; the firewall runs rules-only regardless of any key being set.

To add another provider: implement a class with the same `.assess()` contract (see
bankguard/providers/gemini.py for the shape), drop it in bankguard/providers/, and add one
branch to build_judge() below. Nothing else in the codebase needs to change — firewall.py,
server.py, and evals/run_evals.py all go through this factory.
"""
from __future__ import annotations

import os


def build_judge():
    """Returns a judge instance, or None if no judge should run. Never raises for a missing
    key — missing credentials just mean "no judge", handled the same as LLM_PROVIDER=none."""
    provider = os.environ.get("LLM_PROVIDER", "gemini").strip().lower()
    if provider in ("none", ""):
        return None
    if provider == "gemini":
        if not os.environ.get("GEMINI_API_KEY"):
            return None
        from .providers.gemini import GeminiJudge
        return GeminiJudge()
    raise ValueError(f"Unknown LLM_PROVIDER: {provider!r} (expected 'gemini' or 'none')")
