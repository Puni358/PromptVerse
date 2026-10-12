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

    def test_missing_details_branch_takes_priority_over_otp_message(self):
        match = re.search(r"function renderActionResult\(v\)\s*\{(.*?)\n  \}", self.source, re.S)
        self.assertIsNotNone(match, "could not locate renderActionResult() body")
        body = match.group(1)

        self.assertIn("More details needed", body)
        self.assertIn("v.missing_details", body)

        # "missing_details" must be checked (and its branch must come) before the high-risk/OTP
        # check, so an incomplete high-risk request shows "more details needed" instead of OTP.
        missing_details_pos = body.index("v.missing_details")
        high_risk_pos = body.index("v.intent && v.intent.high_risk")
        self.assertLess(missing_details_pos, high_risk_pos)

        missing_details_branch = body.split("if (v.missing_details)")[1].split("} else if")[0]
        self.assertNotIn("Step-up verification", missing_details_branch)
        self.assertNotIn("Action executed", missing_details_branch)


if __name__ == "__main__":
    unittest.main()
