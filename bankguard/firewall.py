"""The firewall engine. `Firewall.check(message)` always returns a JSON-serialisable dict and never raises
(fail-closed: any internal error => status "blocked")."""
from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

from .intent import classify_intent, missing_transfer_details
from .normalize import analyze, contains_non_latin_script
from .rules import RULES, SQUASHED_PHRASES

VERSION = "1.0.0"
_PLAIN_VARIANTS = {"plain", "leet"}
# Mirrors bankguard/intent.py's high_risk=True intents. Used only to decide whether a judge-
# reported intent is allowed to raise scrutiny when the rules' own classifier found nothing.
_MONEY_MOVING_INTENTS = {"transfer_funds", "pay_bill", "update_account_details"}


@dataclass
class Config:
    block_threshold: float = 0.60       # normal requests
    high_risk_threshold: float = 0.40   # transfers, bill-pay, profile changes: stricter
    untrusted_threshold: float = 0.35   # text that came from documents/tools/web, not the user
    max_length: int = 2000
    strict_intent: bool = False         # True => block anything that isn't a recognised banking request
    verbose: bool = True                # False => hide matched text/rule ids from the caller (production)
    judge_band_low: float = 0.20        # optional LLM judge only runs for scores in [low, threshold)


@dataclass
class Hit:
    id: str
    category: str
    weight: float
    description: str
    variant: str = "plain"
    matched: str = ""


class Firewall:
    def __init__(self, config: Optional[Config] = None, judge: Any = None):
        self.cfg = config or Config()
        self.judge = judge  # optional object with .assess(message) -> float in [0,1]

    # ------------------------------------------------------------------ public
    def check(self, message: Any, *, source: str = "user") -> dict:
        t0 = time.perf_counter()
        try:
            verdict = self._check(message, source)
        except Exception as exc:  # fail closed
            verdict = self._verdict(blocked=True, risk=1.0, threshold=self.cfg.block_threshold, hits=[],
                                    intent=None, reasons=["internal_error: request blocked as a precaution"],
                                    message=message if isinstance(message, str) else "", source=source,
                                    code="internal_error")
            verdict["error"] = type(exc).__name__
        verdict["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        return verdict

    # ------------------------------------------------------------------ internals
    def _check(self, message: Any, source: str) -> dict:
        cfg = self.cfg
        if not isinstance(message, str):
            return self._early(message, source, "invalid_input", "Message must be a string")
        if not message.strip():
            return self._early(message, source, "empty_message", "Message is empty")
        if len(message) > cfg.max_length:
            return self._early(message, source, "message_too_long",
                               f"Message exceeds {cfg.max_length} characters")

        analysis = analyze(message)
        hits = self._scan(analysis)
        intent = classify_intent(analysis.plain)

        threshold = cfg.high_risk_threshold if intent["high_risk"] else cfg.block_threshold
        if source != "user":
            threshold = min(threshold, cfg.untrusted_threshold)

        rules_risk = self._score(hits)
        risk = rules_risk
        reasons_extra = []

        # Why consult the judge at all? Any one of these is sufficient. A rule score of 0 is
        # NOT evidence of safety for text the rule engine can't read in the first place (a
        # non-Latin script, or anything already flagged as obfuscated/untrusted) — so those
        # route to the judge even at risk 0, unlike the plain grey-zone case.
        non_latin = contains_non_latin_script(message)
        obfuscation_flagged = any(h.category == "obfuscation" for h in hits)
        triggers = []
        if intent["high_risk"]:
            triggers.append("high_risk_intent")
        if intent["name"] == "unknown":
            triggers.append("unknown_intent")
        if non_latin:
            triggers.append("non_latin_script")
        if obfuscation_flagged:
            triggers.append("obfuscation_detected")
        if source != "user":
            triggers.append("untrusted_source")
        if rules_risk >= cfg.judge_band_low:
            triggers.append("rules_risk_at_or_above_grey_zone")
        should_consult = self.judge is not None and bool(triggers)

        judge_layer: dict = {"used": False, "reason": "no_judge_configured" if self.judge is None
                              else "no_trigger_condition_met"}
        if should_consult:
            try:
                result = self.judge.assess(message)
                judge_layer = {
                    "used": True,
                    "triggered_by": triggers,
                    "attack": result["attack"],
                    "confidence": round(float(result["confidence"]), 3),
                    "category": result.get("category", "none"),
                    "reasoning": result.get("reasoning", ""),
                    "risk_score": round(float(result["risk_score"]), 3),
                    "prompt_version": result.get("prompt_version"),
                }

                # Defense-in-depth guardrail: do not allow judge to flag a request as
                # unauthorized_funds_movement if rules engine found no unauthorized system/bank
                # account and the message is merely missing details or mentioning a third-party account.
                if (result["attack"] and result.get("category") == "unauthorized_funds_movement"
                        and not any(h.id == "ua_not_users_account" for h in hits)):
                    judge_layer["attack"] = False
                    judge_layer["risk_score"] = 0.0
                    judge_layer["note"] = "third_party_or_incomplete_not_classified_as_attack"
                else:
                    risk = max(risk, result["risk_score"])

                reasons_extra.append("llm_judge consulted")

                # Intent fallback: only when the rules' own classifier found nothing at all,
                # and only to RAISE scrutiny — never overrides a rules-detected intent, and
                # never lowers the threshold below what the rules already decided.
                judge_intent = result.get("intent")
                if intent["name"] == "unknown" and judge_intent in _MONEY_MOVING_INTENTS:
                    intent["name"] = judge_intent
                    intent["high_risk"] = True
                    intent["detected"] = [judge_intent]
                    judge_layer["intent_override"] = judge_intent
                    reasons_extra.append(f"intent inferred by llm_judge: {judge_intent}")
                    new_threshold = cfg.high_risk_threshold
                    if source != "user":
                        new_threshold = min(new_threshold, cfg.untrusted_threshold)
                    threshold = min(threshold, new_threshold)  # only ever tighten, never relax
            except Exception as exc:
                error_type = getattr(exc, "error_type", type(exc).__name__)
                status_code = getattr(exc, "status_code", getattr(exc, "code", None))
                gemini_msg = getattr(exc, "gemini_message", str(exc))
                latency_ms = getattr(exc, "latency_ms", None)

                judge_layer = {
                    "used": True,
                    "triggered_by": triggers,
                    "error": type(exc).__name__,
                    "error_type": error_type,
                }
                if status_code is not None:
                    judge_layer["status_code"] = status_code
                if gemini_msg:
                    judge_layer["error_message"] = gemini_msg
                if latency_ms is not None:
                    judge_layer["latency_ms"] = round(latency_ms, 1)

                if non_latin:
                    reasons_extra.append(
                        "llm_judge unavailable for a non-English message; rules-only verdict "
                        "may be less reliable for this text")
                else:
                    reasons_extra.append(f"llm_judge unavailable ({error_type})")
                if intent["high_risk"]:  # fail closed on money-moving actions
                    risk = max(risk, threshold)
                    judge_layer["fail_closed"] = True

        blocked = risk >= threshold
        code = None
        if not blocked and cfg.strict_intent and intent["name"] == "unknown":
            blocked, code = True, "no_recognized_banking_intent"
            reasons_extra.append("Not a recognised banking request (strict mode)")

        layers = {
            "rules": {"risk_score": round(rules_risk, 3), "blocked": rules_risk >= threshold},
            "llm_judge": judge_layer,
            "pipeline": "hybrid" if self.judge is not None else "rules_only",
        }

        # Informational only — never affects risk/threshold/blocked. Computed after any
        # judge-intent fallback above, so it reflects whichever intent the verdict settled on.
        missing_details = missing_transfer_details(intent["name"], message) if not blocked else None

        return self._verdict(blocked, risk, threshold, hits, intent, reasons_extra, message, source,
                             code, layers, missing_details)

    def _scan(self, a) -> list[Hit]:
        hits: dict[str, Hit] = {}
        obfuscated = False
        for vname, text in a.variants.items():
            for rule in RULES:
                if rule.id in hits:
                    continue
                m = rule.pattern.search(text)
                if m:
                    hits[rule.id] = Hit(rule.id, rule.category, rule.weight, rule.description, vname, m.group(0)[:80])
                    if vname not in _PLAIN_VARIANTS:
                        obfuscated = True
        for vname, sq in a.squashed.items():
            for phrase, cat, w in SQUASHED_PHRASES:
                key = f"sq_{phrase}"
                if phrase in sq and key not in hits:
                    hits[key] = Hit("squashed_phrase", cat, w, "Attack phrase hidden by splitting characters", vname, phrase)
        for fid, cat, w, desc in a.flags:
            hits[fid] = Hit(fid, cat, w, desc, "structure")
        if obfuscated:
            hits["obfuscated_payload"] = Hit("obfuscated_payload", "obfuscation", 0.5,
                                             "Attack text was only visible after decoding (base64/hex/ROT13/reversed/URL)",
                                             "decoded")
        return sorted(hits.values(), key=lambda h: -h.weight)

    @staticmethod
    def _score(hits: list[Hit]) -> float:
        """Max weight per category, noisy-OR across categories."""
        per_cat: dict[str, float] = {}
        for h in hits:
            per_cat[h.category] = max(per_cat.get(h.category, 0.0), h.weight)
        safe = 1.0
        for w in per_cat.values():
            safe *= (1.0 - w)
        return 1.0 - safe

    def _early(self, message, source, code, reason) -> dict:
        layers = {"rules": {"risk_score": 1.0, "blocked": True},
                  "llm_judge": {"used": False, "reason": "blocked_before_judge"},
                  "pipeline": "hybrid" if self.judge is not None else "rules_only"}
        return self._verdict(True, 1.0, self.cfg.block_threshold, [], None, [reason],
                             message if isinstance(message, str) else "", source, code, layers)

    def _verdict(self, blocked, risk, threshold, hits, intent, reasons, message, source, code=None,
                 layers=None, missing_details=None) -> dict:
        cfg = self.cfg
        risk = round(min(max(risk, 0.0), 1.0), 3)
        seen, reason_list = set(), []
        for h in hits:
            if h.description not in seen and len(reason_list) < 5:
                seen.add(h.description)
                reason_list.append(h.description)
        reason_list += [r for r in reasons if r not in reason_list]
        if not reason_list:
            reason_list = ["No threats detected"]
        if not blocked and hits:
            reason_list.insert(0, "Weak signals only, below block threshold")

        if code is None and blocked:
            if layers and layers.get("llm_judge", {}).get("fail_closed") and not hits:
                code = "service_unavailable"
                reason_list.insert(0, "Security verification service temporarily unavailable; request stopped for safety")
            else:
                top = hits[0].category if hits else "policy"
                code = f"blocked_{top}"
        if not blocked:
            code = "ok"

        # A safe verdict with no recognised banking intent at all (and the judge's intent
        # fallback didn't find one either) isn't a banking request — nothing should be
        # "executed" for it. Real recognised intents (including judge-inferred ones, which
        # replace "unknown" — see above) are unaffected.
        off_domain = (not blocked) and intent is not None and intent.get("name") == "unknown"
        next_step = "not_a_banking_request" if off_domain else None

        out = {
            "request_id": uuid.uuid4().hex[:12],
            "status": "blocked" if blocked else "safe",
            "action": "block" if blocked else "allow",
            "code": code,
            "risk_score": risk,
            "risk_level": "high" if risk >= 0.6 else "medium" if risk >= 0.3 else "low",
            "threshold": threshold,
            "source": source,
            "intent": intent,
            "categories": sorted({h.category for h in hits}),
            "reasons": reason_list,
            "message_sha256": hashlib.sha256(message.encode("utf-8", "ignore")).hexdigest()[:16],
            "firewall_version": VERSION,
            "layers": layers or {"rules": {"risk_score": risk, "blocked": blocked},
                                  "llm_judge": {"used": False}, "pipeline": "rules_only"},
            "missing_details": missing_details,
            "off_domain": off_domain,
            "next_step": next_step,
        }
        if cfg.verbose:
            out["threats"] = [{"rule": h.id, "category": h.category, "weight": h.weight,
                               "variant": h.variant, "matched": h.matched} for h in hits]
        else:  # don't teach an attacker which rule (or judge reasoning) fired
            out["reasons"] = ["Request blocked by security policy"] if blocked else ["OK"]
            out.pop("categories")
            out["layers"] = {"pipeline": out["layers"].get("pipeline", "rules_only")}
        return out
