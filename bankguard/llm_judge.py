"""Second-opinion LLM layer. Combined with the rule engine in Firewall._check() — see
docs/PROMPT_FLOW.md for exactly when it runs and how its output is weighed.

    from bankguard import Firewall
    from bankguard.llm_judge import ClaudeJudge
    fw = Firewall(judge=ClaudeJudge())     # needs `pip install anthropic` and ANTHROPIC_API_KEY

The system prompt lives in prompts/judge_v1.md (versioned separately from this code; see
prompts/README.md for why). Not exercised by the test-suite, which mocks `judge.assess()` instead
of hitting the network (see tests/test_firewall.py::HybridJudge). Errors raise out of `assess()`;
the Firewall fails closed for high-risk (money-moving) intents, per Config.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "judge_v1.md"


def _load_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


class ClaudeJudge:
    def __init__(self, model: str = "claude-haiku-5-5", timeout: float = 4.0,
                 prompt_path: Path = PROMPT_PATH):
        import anthropic  # imported lazily so the core package has zero dependencies
        self.client = anthropic.Anthropic(timeout=timeout)
        self.model = model
        self.prompt_path = prompt_path
        self.system_prompt = prompt_path.read_text(encoding="utf-8")

    def assess(self, message: str) -> dict:
        """Returns {"attack": bool, "confidence": float, "category": str, "reasoning": str,
        "risk_score": float}. Raises on network/parse errors; callers decide how to fail."""
        resp = self.client.messages.create(
            model=self.model, max_tokens=150, system=self.system_prompt,
            messages=[{"role": "user", "content": f"<message>{message}</message>"}],
        )
        text = resp.content[0].text
        data = json.loads(re.search(r"\{.*\}", text, re.S).group(0))
        attack = bool(data.get("attack"))
        confidence = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
        return {
            "attack": attack,
            "confidence": confidence,
            "category": str(data.get("category", "none"))[:40],
            "reasoning": str(data.get("reasoning", ""))[:200],
            "risk_score": confidence if attack else 0.0,
        }
