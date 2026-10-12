"""Banking-intent allowlist. Tells us *what* the user wants so we can apply a stricter
threshold to money-moving / account-changing actions."""
from __future__ import annotations

import re

_FLAGS = re.I | re.M

# (name, high_risk, pattern)  -- order matters: first match is the primary intent.
_INTENTS = [
    ("pay_bill", True, re.compile(
        r"\b(?:pay|settle|clear|pay off|payment)\b[^.\n]{0,30}\b(?:bill|bills|invoice|emi|premium|rent|dues|credit card|"
        r"electricity|water|gas|utility|recharge|fee|fees|tuition)\b|\b(?:bill\s*pay(?:ment)?|recharge)\b|"
        # Hindi, Kannada, Tamil, Telugu, Hinglish, Spanish — common bill-payment phrasings.
        r"बिल\s*(?:का\s*)?(?:भुगतान|भरें|भरना|जमा)|ಬಿಲ್\s*(?:ಪಾವತಿ|ಕಟ್ಟಿ)|பில்(?:\s*)?(?:செலுத்த|கட்ட)|"
        r"బిల్లు\s*(?:చెల్లించ|కట్ట)|\bbill\s*(?:bharo|bharna|pay\s*karo)\b|\b(?:pagar|pago\s+de)\s+(?:la\s+)?factura\b|"
        # Kannada, Tamil, Telugu — romanized (transliterated) bill-payment phrasings.
        r"\bbill\s*(?:katti|kattu|kattbeku|pay\s*madi)\b|\bbill\s*(?:seluthu|seluthanum|kattanum)\b|"
        r"\bbill(?:u)?\s*(?:chellinchandi|kattandi)\b",
        _FLAGS)),
    ("transfer_funds", True, re.compile(
        r"\b(?:transfer|wire|remit|neft|rtgs|imps|upi)\b|"
        r"\b(?:send|move|pay|give)\b[^.\n]{0,30}(?:\b(?:money|funds|amount|rupees|dollars|euros|inr|usd|rs\.?)\b|[$₹€£]\s?\d)|"
        r"\b(?:send|move)\b\s+\d+(?:,\d+)*(?:\.\d+)?\b|"
        r"\b(?:send|move|pay|give)\b\s+\d+(?:,\d+)*(?:\.\d+)?\s*(?:to\b|from\b|into\b)|"
        # Hindi, Kannada, Tamil, Telugu, Hinglish, Spanish — common "send/transfer money" phrasings.
        r"पैसे?\s*(?:भेजो|भेजें|भेजना|ट्रांसफर)|रुपये?\s*भेज|ट्रांसफर\s*(?:करो|करें|कीजिए)|"
        r"ಹಣ\s*ಕಳುಹಿಸ|ವರ್ಗಾವಣೆ\s*ಮಾಡ|"
        r"பணம்\s*அனுப்ப|பரிமாற்ற|"
        r"డబ్బు\s*పంప|బదిలీ\s*చేయ|"
        r"\bpaise\s*(?:bhejo|bhejna|transfer)\b|\bpaisa\s*transfer\b|\btransfer\s*karo\b|"
        r"\btransferir\s+dinero\b|\benviar\s+dinero\b|\bhacer\s+una\s+transferencia\b|"
        # Hinglish/Hindi spelling variants: send-verb + money-word, either order, plus "<number> ko <verb>".
        r"\b(?:bejo|bhejo|bhej|bheje|bhejna)\b(?:\s+\w+){0,3}?\s*\b(?:paisa|paise|paiso|rupaye?|rupay)\b|"
        r"\b(?:paisa|paise|paiso|rupaye?|rupay)\b(?:\s+\w+){0,3}?\s*\b(?:bejo|bhejo|bhej|bheje|bhejna)\b|"
        r"\d+\s*ko\s*(?:bejo|bhejo|bhej|bheje|bhejna)\b|"
        r"\b(?:bejo|bhejo|bhej|bheje|bhejna)\b(?:\s+\w+){0,5}?\s*\bko\b|"
        # Kannada, Tamil, Telugu — romanized (transliterated) "send money" phrasings.
        r"\bhana\s*kalisi\b|\bkalisi\b(?:\s+\w+){0,2}?\s*\bhana\b|"
        r"\b(?:nange|nanage)\b[^.\n]{0,30}\b(?:kalsu|kalisu|kalsi|kalisi|kallsu|kaluhisu|kalsbeku|kalisbeku)\b|"
        r"\b(?:kalsu|kalisu|kalsi|kalisi|kallsu|kaluhisu|kalsbeku|kalisbeku)\b[^.\n]{0,30}\b(?:nange|nanage)\b|"
        r"\b(?:hana|duddu|dudd|rupayi|rupees|kaasu|\d+)\b[^.\n]{0,30}\b(?:kalsu|kalisu|kalsi|kalisi|kallsu|kaluhisu|kalsbeku|kalisbeku)\b|"
        r"\b(?:kalsu|kalisu|kalsi|kalisi|kallsu|kaluhisu|kalsbeku|kalisbeku)\b(?:\s+\w+){0,2}?\s*(?:\b(?:hana|duddu|dudd|rupayi|rupees|kaasu)\b|\d+)|"
        r"\bpanam\s*anuppu\b|\banuppu\b(?:\s+\w+){0,2}?\s*\bpanam\b|"
        r"\bdabbu\s*pampandi\b|\bpampandi\b(?:\s+\w+){0,2}?\s*\bdabbu\b",
        _FLAGS)),
    ("update_account_details", True, re.compile(
        r"\b(?:change|update|edit|modify|add|remove|set|reset)\b[^.\n]{0,25}\b(?:address|phone|mobile|email|beneficiary|"
        r"payee|nominee|password|pin|username|login)\b", _FLAGS)),
    ("dispute_transaction", False, re.compile(
        r"\b(?:dispute|chargeback|unauthori[sz]ed (?:charge|transaction)|wrong charge|refund)\b", _FLAGS)),
    ("card_services", False, re.compile(
        r"\b(?:block|freeze|unblock|activate|cancel|replace|report)\b[^.\n]{0,20}\b(?:card|debit|credit)\b|"
        r"\b(?:lost|stolen)\b[^.\n]{0,15}\bcard\b|\bcard\b[^.\n]{0,20}\b(?:lost|stolen|blocked|limit)\b", _FLAGS)),
    ("check_balance", False, re.compile(
        r"\b(?:balance|how much (?:money|do i have)|available funds)\b|"
        # Hindi, Kannada, Tamil, Telugu, Hinglish, Spanish — common "what's my balance" phrasings.
        r"(?:मेरा\s*)?बैलेंस|शेष\s*राशि|खाते\s*में\s*कितना|"
        r"ಬ್ಯಾಲೆನ್ಸ್|ಶಿಲ್ಕು|ಖಾತೆಯಲ್ಲಿ\s*ಎಷ್ಟಿದೆ|"
        r"இருப்பு|பேலன்ஸ்|கணக்கில்\s*எவ்வளவு|"
        r"బ్యాలెన్స్|మిగులు|ఖాతాలో\s*ఎంత|"
        r"\bmera\s*balance\b|\bbalance\s*kitna\s*hai\b|"
        r"\b(?:cu[aá]l\s+es\s+mi\s+saldo|cu[aá]nto\s+dinero\s+tengo|mi\s+saldo)\b|"
        # Kannada, Tamil, Telugu — romanized (transliterated) "what's my balance" phrasings.
        r"\bbalance\s*(?:eshtide|eshtu\s*ide)\b|\bshilku\s*(?:eshtide|eshtu\s*ide)?\b|"
        r"\birupu\s*evvalavu\b|\bbalance\s*evvalavu\b|"
        r"\bbalance\s*entha\b|\bmigulu\s*entha\b",
        _FLAGS)),
    ("transaction_history", False, re.compile(
        r"\b(?:transactions?|statements?|history|passbook|mini statement|spent|spending)\b", _FLAGS)),
    ("loan_enquiry", False, re.compile(
        r"\b(?:loan|emi|mortgage|interest rate|credit limit|eligib\w+)\b", _FLAGS)),
    ("account_services", False, re.compile(
        r"\b(?:open|close|create)\b[^.\n]{0,15}\b(?:account|fd|fixed deposit|rd|savings)\b|"
        r"\b(?:fixed deposit|recurring deposit|chequebook|cheque book|account type)\b", _FLAGS)),
    ("branch_atm_info", False, re.compile(r"\b(?:branch|atm|ifsc|swift|working hours|timings?)\b", _FLAGS)),
    ("exchange_rates", False, re.compile(r"\b(?:exchange rate|forex|currency rate|convert)\b", _FLAGS)),
    ("customer_support", False, re.compile(r"\b(?:help|support|complaint|agent|human|customer care)\b", _FLAGS)),
]

_AMT = re.compile(
    r"(?P<cur>rs\.?|inr|usd|eur|gbp|[$₹€£])?\s?(?P<num>\d{1,3}(?:,\d{2,3})+(?:\.\d+)?|\d+(?:\.\d+)?)"
    r"\s?(?P<mult>k|lakhs?|crore|million)?(?:\s?(?P<cur2>rupees|dollars|euros|usd|inr|eur|gbp))?\b", re.I)
_MULT = {"k": 1e3, "lakh": 1e5, "lakhs": 1e5, "crore": 1e7, "million": 1e6}
_CUR = {"$": "USD", "usd": "USD", "dollars": "USD", "₹": "INR", "rs": "INR", "rs.": "INR", "inr": "INR",
        "rupees": "INR", "€": "EUR", "eur": "EUR", "euros": "EUR", "£": "GBP", "gbp": "GBP"}


def extract_entities(text: str) -> dict:
    amounts = []
    for m in _AMT.finditer(text):
        cur = (m.group("cur") or m.group("cur2") or "").lower()
        if not cur:
            continue
        try:
            val = float(m.group("num").replace(",", ""))
        except ValueError:
            continue
        mult = (m.group("mult") or "").lower()
        val *= _MULT.get(mult, 1)
        amounts.append({"value": val, "currency": _CUR.get(cur, cur.upper())})
        if len(amounts) == 3:
            break
    refs = ["****" + n[-4:] for n in re.findall(r"\b\d{9,18}\b", text)][:3]  # never echo full numbers
    return {"amounts": amounts, "account_refs_last4": refs}


_SOURCE_PHRASE_RE = re.compile(
    r"\bfrom\b|\binda\b|-inda\b|\bse\b|-se\b|\birunthu\b|\bnundi\b", re.I
)
# "to" followed by something other than the infinitive use ("want to transfer", "need to pay")
# signals an actual destination clause ("to my savings account", "to bob"); an account-number-
# shaped token or recipient pronouns ("nange", "to me") also count even without a "to".
_TARGET_PHRASE_RE = re.compile(
    r"\b(?:to|into|for)\s+(?!transfer\b|pay\b|send\b|move\b|wire\b|give\b|check\b|do\b|make\b)\S|"
    r"\b\d{6,18}\b|\bto\s+me\b|\b(?:nange|nanage)\b|\b(?:mujhe|mere\s+ko)\b|\benakku\b|\bnaaku\b|"
    r"\bge\b|-ge\b|\bkke\b|-kke\b|\bko\b|-ko\b",
    re.I
)
_THIRD_PARTY_SOURCE_RE = re.compile(
    r"\bfrom\s+(?:my\s+)?(?:brother'?s?|sister'?s?|father'?s?|mother'?s?|friend'?s?|wife'?s?|husband'?s?|"
    r"someone\s+else'?s?|another\s+(?:person|user|customer)'?s?|their|his|her)\s+account\b|"
    r"\bfrom\s+another\s+account\b",
    re.I
)


def missing_transfer_details(intent_name: str, text: str) -> dict | None:
    """Returns a structured dictionary when a transfer_funds/pay_bill message lacks
    essential details (source account, recipient, or third-party authorization), or
    None when all details are present.
    Always None for other intents; this never affects risk scoring, it drives the UI's
    'more details needed' clarification response (see Firewall._check())."""
    if intent_name == "transfer_funds":
        has_source = bool(_SOURCE_PHRASE_RE.search(text))
        has_recipient = bool(_TARGET_PHRASE_RE.search(text))
        is_third_party = bool(_THIRD_PARTY_SOURCE_RE.search(text))

        needed = []
        if not has_source:
            needed.append("source_account")
        if not has_recipient:
            needed.append("recipient")
        if is_third_party:
            needed.append("third_party_authorization")

        if not needed:
            return None

        if not has_source and not has_recipient:
            prompt = "Please specify which account to send from, and who or which account to send to."
        elif not has_source:
            prompt = "Please specify which account to send from."
        elif not has_recipient and is_third_party:
            prompt = "Please specify who or which account to send to. Note that transferring from a third-party account requires authorization."
        elif not has_recipient:
            prompt = "Please specify who or which account to send to."
        else:
            prompt = "Third-party account authorization required to transfer from another person's account."

        return {
            "needed": needed,
            "missing_source": not has_source,
            "missing_recipient": not has_recipient,
            "third_party_source": is_third_party,
            "prompt": prompt,
            "message": prompt,
        }

    if intent_name == "pay_bill":
        has_source = bool(_SOURCE_PHRASE_RE.search(text))
        if not has_source:
            prompt = "Please specify which account to pay from."
            return {
                "needed": ["source_account"],
                "missing_source": True,
                "missing_recipient": False,
                "third_party_source": False,
                "prompt": prompt,
                "message": prompt,
            }
        return None

    return None


def classify_intent(plain_text: str) -> dict:
    matched = [(name, hr) for name, hr, pat in _INTENTS if pat.search(plain_text)]
    if not matched:
        return {"name": "unknown", "confidence": 0.0, "high_risk": False, "detected": [],
                "entities": extract_entities(plain_text)}
    return {
        "name": matched[0][0],
        "confidence": 0.9 if len(matched) == 1 else 0.7,
        "high_risk": any(hr for _, hr in matched),   # ANY money-moving intent raises scrutiny
        "detected": [n for n, _ in matched],
        "entities": extract_entities(plain_text),
    }
