"""Integration layer: every banking action goes through the firewall first.

The firewall decides whether the *message* is safe. It does NOT replace authentication or
step-up verification (OTP etc.) for money-moving actions; the mock executor below shows
where those hooks belong.
"""
from __future__ import annotations

import functools
from typing import Any, Callable, Optional

from .firewall import Firewall


class BlockedRequest(Exception):
    def __init__(self, verdict: dict):
        super().__init__(verdict.get("code", "blocked"))
        self.verdict = verdict


def guarded(firewall: Optional[Firewall] = None) -> Callable:
    """Decorator: the wrapped banking function only runs if the message is safe.

        @guarded()
        def do_action(message, user_id, verdict=None): ...
    """
    fw = firewall or Firewall()

    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(message: Any, *args, **kwargs):
            verdict = fw.check(message)
            if verdict["status"] != "safe":
                raise BlockedRequest(verdict)
            return fn(message, *args, verdict=verdict, **kwargs)
        return wrapper
    return deco


# ---- demo executor (mock) ----------------------------------------------------------------
_fw = Firewall()


def _execute_action(verdict: dict) -> dict:
    intent = verdict["intent"]
    result = {"executed_intent": intent["name"], "entities": intent["entities"], "mock": True}
    if intent["high_risk"]:
        result["next_step"] = "require_step_up_auth"   # OTP / biometric before moving money
    return result


def handle_request(message: Any, user_id: str = "demo-user") -> dict:
    """Returns {'firewall': <verdict>, 'result': ...}. Blocked requests never reach the banking layer."""
    verdict = _fw.check(message)
    if verdict["status"] != "safe":
        return {"firewall": verdict, "result": None}
    return {"firewall": verdict, "result": _execute_action(verdict)}
