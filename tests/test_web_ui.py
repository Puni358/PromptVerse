"""Lightweight regression guard for web/app.js. There's no JS test runner in this repo, so this
checks the Bank Action card's rendering logic by inspecting the source directly — not a
substitute for exercising it in a real browser (done manually when this was built), but enough
to catch an accidental revert of the "Step-up verification" behaviour."""
import os
import re
import unittest
from pathlib import Path

APP_JS = Path(os.path.dirname(__file__)).resolve().parent / "web" / "app.js"


class BankActionCard(unittest.TestCase):
    def setUp(self):
        self.source = APP_JS.read_text(encoding="utf-8")

    def test_render_action_result_function_exists(self):
        self.assertIn("function renderActionResult(v)", self.source)

    def test_high_risk_safe_shows_step_up_verification_not_action_executed(self):
        # Pull out the renderActionResult function body so this test only inspects the logic
        # it's actually guarding, not incidental mentions elsewhere in the file.
        match = re.search(r"function renderActionResult\(v\)\s*\{(.*?)\n  \}", self.source, re.S)
        self.assertIsNotNone(match, "could not locate renderActionResult() body")
        body = match.group(1)

        self.assertIn("Step-up verification (OTP) required", body)
        self.assertIn("v.intent.high_risk", body)

        # The high-risk branch must not also render "Action executed" — the whole point of
        # this change is that a high-risk request shows step-up verification INSTEAD of it.
        high_risk_branch = body.split("if (v.intent && v.intent.high_risk)")[1].split("} else {")[0]
        self.assertNotIn("Action executed", high_risk_branch)

        # The non-high-risk branch must still say "Action executed".
        low_risk_branch = body.split("} else {")[1]
        self.assertIn("Action executed:", low_risk_branch)


if __name__ == "__main__":
    unittest.main()
