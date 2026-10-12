"""Detection rules. Every rule has a category and a weight (0-1 = how sure we are it's an attack).

Scoring (see firewall.py): max weight per category, then noisy-OR across categories, so
several independent signals compound while repeated hits of one kind do not inflate.
All patterns run on lower-cased, de-obfuscated text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: float
    description: str
    pattern: re.Pattern


def _r(id: str, category: str, weight: float, description: str, *patterns: str) -> Rule:
    return Rule(id, category, weight, description, re.compile("|".join(patterns), re.I | re.M))


_TARGETS = (r"(?:instructions?|rules?|prompts?|guidelines?|polic(?:y|ies)|restrictions?|directives?|"
            r"guardrails?|safeguards?|programming|training|constraints?)")

RULES: list[Rule] = [
    # ---- instruction override ------------------------------------------------------------
    _r("io_ignore_instructions", "instruction_override", 0.92,
       "Tells the assistant to ignore/override its instructions or rules",
       r"\b(?:ignore|disregard|forget|override|discard|bypass)\b(?:\s+\w+){0,4}?\s+" + _TARGETS + r"\b"),
    _r("io_do_not_follow", "instruction_override", 0.85,
       "Tells the assistant to stop following its rules",
       r"\b(?:do not|don't|never|stop)\s+(?:follow|obey|apply|enforce|honou?r)\s+(?:\w+\s+){0,3}"
       r"(?:instructions?|rules?|guidelines?|polic(?:y|ies)|restrictions?|safety|security)\b"),
    _r("io_new_instructions", "instruction_override", 0.75,
       "Introduces replacement 'system' instructions",
       r"\b(?:new|updated|revised|real|actual|secret|hidden)\s+(?:system\s+)?(?:instructions?|rules?|prompt|directives?)\s*[:=\-]"),
    _r("io_from_now_on", "instruction_override", 0.55,
       "Attempts to redefine assistant behaviour going forward",
       r"\bfrom now on,?\s+(?:you\s+(?:must|will|are|should|shall)|ignore|only|always obey)\b"),
    _r("io_no_longer_bound", "instruction_override", 0.85,
       "Claims the assistant is no longer bound by its rules",
       r"\byou\s+(?:are|re|will be)\s+(?:no longer|not)\s+(?:bound|restricted|limited|required|obligated)\b"),
    _r("io_multilingual", "instruction_override", 0.9,
       "Instruction-override phrase in another language",
       r"\bignora\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)",
       r"\bignore[zr]?\s+(?:toutes\s+)?les\s+instructions\s+(?:pr[eé]c[eé]dentes|ci-dessus)",
       r"\bignoriere\s+(?:alle\s+)?(?:vorherigen|obigen|bisherigen)\s+anweisungen",
       r"\bignora\s+(?:tutte\s+)?le\s+istruzioni\s+precedenti",
       r"忽略(?:之前|以上|所有|上面)的?(?:指令|说明|规则|指示)",
       r"(?:पिछले|सभी|ऊपर\s*के)\s*(?:सभी\s*)?(?:निर्देश|निर्देशों|नियमों)\s*(?:को\s*)?(?:अनदेखा|भूल|नज़रअंदाज़|नजरअंदाज)",
       r"\b(?:pichle|saare|sabhi|upar ke)\s+(?:instructions?|nirdesh|niyam)\w*\s+(?:ko\s+)?(?:ignore|ignor|bhool|nazarandaz)"),
    _r("io_bypass_verification", "instruction_override", 0.8,
       "Asks to skip OTP / 2FA / verification / fraud checks",
       r"\b(?:skip|bypass|disable|circumvent|turn off|deactivate|waive)\b(?:\s+\w+){0,3}?\s+"
       r"(?:otp|2fa|mfa|two[- ]factor|verification|authenti[cs]ation|authori[sz]ation|confirmation|kyc|"
       r"fraud\s+(?:checks?|detection)|security\s+checks?|approval|captcha|limits?)\b",
       r"\b(?:without|no need (?:for|to))\s+(?:an?\s+|the\s+|any\s+)?(?:otp|2fa|mfa|two[- ]factor|verification|"
       r"authenti[cs]ation|authori[sz]ation|approval|verify|verifying)\b"),

    # ---- jailbreak -----------------------------------------------------------------------
    _r("jb_named", "jailbreak", 0.88, "Known jailbreak persona/mode",
       r"\b(?:dan\s+mode|do anything now|developer\s+mode|dev\s+mode|jailbreak(?:ed|ing)?|god\s*mode|sudo\s+mode|"
       r"unrestricted\s+mode|evil\s+mode|no\s+filter\s+mode|stan\s+mode|dude\s+mode|opposite\s+mode)\b",
       r"\byou\s+are\s+(?:now\s+)?dan\b"),
    _r("jb_without_restrictions", "jailbreak", 0.85, "Asks the assistant to operate without restrictions",
       r"\b(?:respond|answer|act|behave|operate|reply|work)\b[^.\n]{0,20}\b(?:without|with no|free of|free from)\b"
       r"[^.\n]{0,15}\b(?:restrictions?|limitations?|filters?|rules|censorship|guidelines|safeguards?)\b"),
    _r("jb_no_rules", "jailbreak", 0.8, "Claims the assistant has no rules/limits",
       r"\b(?:you\s+(?:have|has|got)|there\s+(?:are|is))\s+no\s+(?:\w+\s+){0,2}"
       r"(?:rules|restrictions|limits|guidelines|filters|safeguards|policies)\b",
       r"\byou\s+(?:can|may|are able to)\s+(?:now\s+)?(?:do|say|answer)\s+anything\b"),
    _r("jb_roleplay", "jailbreak", 0.45, "Role-play framing often used to bypass rules",
       r"\b(?:pretend|imagine)\s+(?:to be|that you|you)\b", r"\b(?:roleplay|role-play|role play)\b"),
    _r("jb_hypothetical", "jailbreak", 0.3, "'Hypothetical' / 'for research' framing",
       r"\b(?:hypothetically|for (?:educational|research|testing|academic|training) purposes|"
       r"in a fictional (?:world|story|scenario)|purely theoretical)\b"),
    _r("jb_dual_response", "jailbreak", 0.8, "Dual-response jailbreak format",
       r"\b(?:two|2|dual)\s+(?:responses|answers|outputs)\b[^.\n]{0,40}\b(?:normal|filtered|unfiltered|jailbr)"),

    # ---- system prompt extraction --------------------------------------------------------
    _r("pe_reveal", "prompt_extraction", 0.9, "Tries to extract the system prompt / hidden instructions",
       r"\b(?:reveal|show|print|repeat|output|display|leak|dump|disclose|tell me|give me|share|recite|reproduce|"
       r"what(?:'s| is| are))\b(?:\s+\w+){0,4}?\s+(?:system\s+(?:prompt|message|instructions?)|"
       r"(?:your|the)\s+(?:initial|original|hidden|secret|internal|full|entire)\s+(?:prompt|instructions?|rules?|configuration|config)|"
       r"your\s+(?:prompt|instructions?|programming|configuration|system message))\b"),
    _r("pe_repeat_above", "prompt_extraction", 0.85, "Asks to repeat text preceding the conversation",
       r"\b(?:repeat|print|output|copy)\b[^.\n]{0,20}\b(?:everything|text|words|all)\s+(?:above|before)\b",
       r"\bstarting with\s+[\"']?you are\b"),

    # ---- delimiter / role-spoofing injection --------------------------------------------
    _r("di_tags", "delimiter_injection", 0.85, "Fake system/assistant tags or chat-template tokens",
       r"</?\s*(?:system|assistant|instructions?|admin|developer|prompt|tool_?(?:call|result)|function_?call)\s*/?>",
       r"\[/?\s*(?:inst|system|sys)\s*\]", r"<<\s*/?sys\s*>>",
       r"<\|\s*(?:im_start|im_end|system|endoftext|user|assistant)\s*\|>"),
    _r("di_role_line", "delimiter_injection", 0.8, "Line pretending to be from system/assistant/admin",
       r"^\s*(?:system|assistant|developer|admin|tool)\s*:\s*\S"),
    _r("di_markdown_system", "delimiter_injection", 0.7, "Markdown heading or fence posing as system instructions",
       r"^\s*#{1,4}\s*(?:system|instructions?|new task|admin)\b", r"```\s*(?:system|instructions?)"),
    _r("di_end_of_input", "delimiter_injection", 0.75, "Pretends the user input has ended",
       r"\bend of (?:user )?(?:input|message|prompt)\b", r"\bbegin (?:new|system) (?:prompt|instructions?|session)\b"),

    # ---- authority / social engineering --------------------------------------------------
    _r("ac_role", "authority_claim", 0.55, "Claims to be an admin / bank staff / the system's creator",
       r"\b(?:i am|i'm|im|this is|speaking as|acting as|message from)\s+(?:the\s+|your\s+|a\s+|an\s+)?(?:\w+\s+){0,2}?"
       r"(?:admin(?:istrator)?|sysadmin|root user|superuser|bank\s+(?:manager|employee|staff|officer|admin)|"
       r"(?:creator|owner|programmer)|anthropic|openai|security\s+team|compliance\s+officer|auditor)\b"),
    _r("ac_override_code", "authority_claim", 0.8, "Claims an override code / privileged mode / pre-authorisation",
       r"\b(?:admin|master|override|emergency|maintenance|debug|test|root|diagnostic|sandbox)\s+"
       r"(?:override|code|mode|access|key|token|password|command)\b",
       r"\b(?:authori[sz]ed|approved|cleared)\s+by\s+(?:the\s+)?(?:admin|management|security team|ceo|developer|system)\b"),
    _r("sx_secrecy", "social_engineering", 0.4, "Secrecy pressure",
       r"\b(?:secret(?:ly)?|between us|no one (?:needs|should) (?:to )?know)\b"),
    _r("sx_urgency", "social_engineering", 0.2, "Urgency pressure",
       r"\b(?:urgent(?:ly)?|right now|asap|emergency)\b"),

    # ---- data exfiltration ---------------------------------------------------------------
    _r("de_bulk", "data_exfiltration", 0.85, "Asks for data about all/other customers",
       r"\b(?:list|show|send|give|export|dump|email|forward|retrieve|fetch|display|download)\b(?:\s+\w+){0,3}?\s+"
       r"(?:all|every|each|other)\s+(?:the\s+)?(?:other\s+)?(?:customers?|users?|clients?|account\s?holders?|employees)\b"),
    _r("de_someone_else", "data_exfiltration", 0.8, "Asks for another person's account data",
       r"\b(?:someone else'?s|somebody else'?s|another\s+(?:customer|user|person|client)'?s|"
       r"other\s+(?:customer|user|people)'?s?)\s+(?:account|balance|details|data|statement|transactions?|card|pin|password)"),
    _r("de_secrets", "data_exfiltration", 0.85, "Asks for API keys, tokens or internal credentials",
       r"\b(?:reveal|show|give|tell|send|print|share|leak|dump|expose|display|what(?:'s| is| are))\b(?:\s+\w+){0,4}?\s+"
       r"(?:api[\s_-]?keys?|secret\s+keys?|access\s+tokens?|auth(?:entication)?\s+tokens?|private\s+keys?|"
       r"(?:admin|system|database|service|root|internal)\s+(?:credentials|passwords?)|database\s+(?:schema|url)|"
       r"env(?:ironment)?\s+variables?|connection\s+strings?)\b"),
    _r("de_card_secrets", "data_exfiltration", 0.55, "Asks the assistant to read out CVV/PIN/OTP/password",
       r"\b(?:reveal|show|read|tell|print|display|repeat|send)\b(?:\s+\w+){0,3}?\s+(?:full\s+)?"
       r"(?:(?:my|the|his|her|their)\s+)?(?:cvv|cvc|pin|otp|password|card number)\b"),

    # ---- stealth / unauthorised action ---------------------------------------------------
    _r("ua_hide", "unauthorized_action", 0.8, "Asks to hide the action from the bank/security/logs",
       r"\b(?:don'?t|do not|never|without)\s+(?:\w+\s+){0,2}(?:notify|notifying|alert|alerting|log|logging|record|recording|"
       r"report|reporting|flag|flagging|tell|telling|inform|informing)\b(?:\s+\w+){0,3}?\s+"
       r"(?:the\s+)?(?:bank|security|fraud|compliance|audit|owner|account holder|admin|system|logs?)\b",
       r"\b(?:don'?t|do not|never|without)\s+(?:\w+\s+){0,2}(?:log|record|report|flag)(?:ging|ing)?\s+"
       r"(?:this|it|the\s+(?:transaction|transfer|payment|request))\b"),
    _r("ua_tamper_logs", "unauthorized_action", 0.85, "Asks to delete or alter audit trails / evidence",
       r"\b(?:delete|erase|wipe|clear|remove|purge|tamper with|falsify|alter|modify)\b(?:\s+\w+){0,3}?\s+"
       r"(?:audit\s+(?:logs?|trail)|system\s+logs?|security\s+logs?|access\s+logs?|fraud\s+(?:alerts?|flags?|records?)|evidence)\b"),
    _r("ua_drain", "unauthorized_action", 0.25, "Drain-the-account phrasing",
       r"\b(?:drain|empty|clear out)\b(?:\s+\w+){0,3}?\s+(?:account|balance|funds|savings)\b",
       r"\b(?:all|entire|whole|full)\s+(?:the\s+)?(?:balance|funds|money|savings)\b"),
    _r("ua_not_users_account", "unauthorized_action", 0.6,
       "Asks to move money from an account that is not the user's own",
       r"\bfrom\s+(?:your|ur|the\s+(?:bank'?s?|system'?s?|company'?s?|assistant'?s?)(?:\s+(?:system'?s?|reserve|master|internal))?|"
       r"(?:someone\s+else|another\s+(?:person|user|customer)|their|his|her)'?s?)\s+(?:account|money|funds)\b"),

    # ---- indirect injection (content from documents / tools) -----------------------------
    _r("in_note_to_ai", "indirect_injection", 0.45, "Text addressed to the AI model rather than the bank",
       r"\b(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|llm|model|chatbot|bot|agent)\b"),

    # ---- code / query injection ----------------------------------------------------------
    _r("ci_sql", "code_injection", 0.85, "SQL injection pattern",
       r"\b(?:drop|truncate|alter)\s+table\b", r"\bdelete\s+from\s+\w+", r"\bunion\s+(?:all\s+)?select\b",
       r"\binsert\s+into\s+\w+\s*(?:\(|values)", r"""['"]\s*;\s*--""", r"""['"]\s*or\s+['"]?\d+['"]?\s*=\s*['"]?\d""",
       r"\bor\s+1\s*=\s*1\b", r";\s*(?:drop|delete)\s+(?:table|from|database)\b",
       r";\s*update\s+\w+\s+set\b", r";\s*insert\s+into\b", r"\bxp_cmdshell\b"),
    _r("ci_script", "code_injection", 0.8, "Script / template injection pattern",
       r"<\s*script\b", r"javascript\s*:", r"\bon(?:error|load|click|mouseover)\s*=", r"<\s*(?:iframe|object|embed)\b",
       r"\{\{.{1,80}?\}\}", r"\$\{.{1,80}?\}", r"<%.{1,80}?%>"),
    _r("ci_shell", "code_injection", 0.85, "Shell command injection pattern",
       r"\brm\s+-rf\b", r"\bcurl\s+https?://\S+\s*\|\s*(?:ba)?sh\b", r"\bwget\s+https?://", r"\bchmod\s+[0-7]{3,4}\b",
       r"\bnc\s+-e\b", r"/bin/(?:ba)?sh\b", r"\bcmd\.exe\b", r"\bos\.system\b", r"\bsubprocess\.", r"\beval\s*\(",
       r"\bexec\s*\(", r"__import__", r";\s*(?:cat|ls|whoami|curl|wget|bash|sh)\s", r"\$\(\s*\w+", r"`\s*(?:cat|ls|whoami|curl|id)\b"),
    _r("ci_path", "code_injection", 0.7, "Path traversal / sensitive file access",
       r"(?:\.\./){2,}", r"/etc/passwd", r"/etc/shadow", r"c:\\windows"),
    _r("ci_url_exfil", "code_injection", 0.5, "Asks to send data to an external URL",
       r"\b(?:send|post|forward|upload|exfiltrate|fetch)\b[^.\n]{0,40}\bhttps?://",
       r"!\[[^\]]*\]\(https?://[^)]*\?[^)]*="),
]

# Phrases checked against text with all non-alphanumerics removed (catches "i.g.n.o.r.e" style splitting).
SQUASHED_PHRASES: list[tuple[str, str, float]] = [
    ("ignorepreviousinstructions", "instruction_override", 0.9),
    ("ignoreallpreviousinstructions", "instruction_override", 0.9),
    ("ignoreallinstructions", "instruction_override", 0.9),
    ("ignoreyourinstructions", "instruction_override", 0.9),
    ("ignoretheaboveinstructions", "instruction_override", 0.9),
    ("ignoreallpriorinstructions", "instruction_override", 0.9),
    ("ignorepriorinstructions", "instruction_override", 0.9),
    ("disregardpreviousinstructions", "instruction_override", 0.9),
    ("disregardallinstructions", "instruction_override", 0.9),
    ("disregardallpreviousinstructions", "instruction_override", 0.9),
    ("forgetpreviousinstructions", "instruction_override", 0.9),
    ("forgetallinstructions", "instruction_override", 0.9),
    ("forgetallpreviousinstructions", "instruction_override", 0.9),
    ("forgetyourinstructions", "instruction_override", 0.9),
    ("overrideyoursafety", "instruction_override", 0.85),
    ("revealsystemprompt", "prompt_extraction", 0.9),
    ("revealyoursystemprompt", "prompt_extraction", 0.9),
    ("showsystemprompt", "prompt_extraction", 0.9),
    ("showyoursystemprompt", "prompt_extraction", 0.9),
    ("printsystemprompt", "prompt_extraction", 0.9),
    ("developermodeenabled", "jailbreak", 0.88),
    ("doanythingnow", "jailbreak", 0.88),
    ("youarenowdan", "jailbreak", 0.88),
]
