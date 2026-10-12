"""Text normalisation and de-obfuscation.

Attackers hide injections with zero-width characters, look-alike letters, leetspeak,
spaced-out letters, reversed text, ROT13, URL-encoding, base64 and hex. We reduce a
message to several canonical "variants" so the same rules can see through all of it.
"""
from __future__ import annotations

import base64
import codecs
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

# Cyrillic / Greek / misc letters that look like Latin ones.
_HOMO_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ɡ": "g", "ⅼ": "l", "ԛ": "q", "ԝ": "w",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "ρ": "p",
    "υ": "u", "β": "b", "η": "n", "μ": "u",
}
_HOMO = str.maketrans(_HOMO_MAP)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

# i g n o r e  /  i.g.n.o.r.e  /  i-g-n-o-r-e   (single-char tokens, single separators)
_SPACED = re.compile(r"(?<![a-z0-9])(?:[a-z0-9][ .\-_*]){3,}[a-z0-9](?![a-z0-9])")
_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX_TOKEN = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){10,}(?![0-9a-fA-F])")

# Scripts the English-regex rule/intent engine can't natively read: used to route messages to
# the LLM judge even when the rules see nothing (zero score on text they can't parse is not
# evidence of safety). Devanagari (Hindi/Marathi), Kannada, Tamil, Telugu, Arabic, CJK
# (Chinese/Japanese incl. Hiragana/Katakana), Hangul (Korean), Cyrillic (Russian etc).
_NON_LATIN_SCRIPT = re.compile(
    "[" +
    "ऀ-ॿ"      # Devanagari
    "ಀ-೿"      # Kannada
    "஀-௿"      # Tamil
    "ఀ-౿"      # Telugu
    "؀-ۿݐ-ݿ"  # Arabic (+ supplement)
    "一-鿿㐀-䶿"  # CJK Unified Ideographs (+ ext A)
    "぀-ヿ"      # Hiragana / Katakana
    "가-힣"      # Hangul
    "Ѐ-ӿ"      # Cyrillic
    "]"
)


def contains_non_latin_script(text: str) -> bool:
    """True if `text` contains a character from a script the English-regex rule/intent engine
    can't read (see _NON_LATIN_SCRIPT). Checked against the raw message, not the normalized
    one — fold() only remaps a small set of Latin-look-alike confusables, so most genuine
    non-Latin text (Hindi, Arabic, CJK, Cyrillic sentences) survives normalization intact."""
    return bool(_NON_LATIN_SCRIPT.search(text))


@dataclass
class Analysis:
    plain: str
    variants: dict = field(default_factory=dict)   # name -> folded text
    squashed: dict = field(default_factory=dict)   # name -> text with only [a-z0-9]
    flags: list = field(default_factory=list)      # (id, category, weight, description)


def clean(text: str) -> tuple[str, int]:
    """NFKC-normalise and strip invisible/control characters. Returns (text, removed_count)."""
    t = unicodedata.normalize("NFKC", text)
    kept, removed = [], 0
    for ch in t:
        if unicodedata.category(ch) in ("Cf", "Cc") and ch not in "\n\t\r":
            removed += 1
        else:
            kept.append(ch)
    return "".join(kept), removed


def fold(s: str) -> str:
    s = s.casefold().translate(_HOMO)
    s = _SPACED.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group(0)), s)
    s = re.sub(r"[ \t]+", " ", s)
    return s.strip()


def _printable_ratio(s: str) -> float:
    return sum(ch.isprintable() or ch in "\n\t" for ch in s) / max(len(s), 1)


def _try_b64(tok: str) -> str | None:
    tok = tok.replace("-", "+").replace("_", "/")
    tok += "=" * (-len(tok) % 4)
    try:
        raw = base64.b64decode(tok, validate=True)
        s = raw.decode("utf-8")
    except Exception:
        return None
    if len(s) >= 8 and _printable_ratio(s) >= 0.95 and sum(c.isalpha() for c in s) >= len(s) * 0.4:
        return s
    return None


def _try_hex(tok: str) -> str | None:
    try:
        s = bytes.fromhex(tok).decode("utf-8")
    except Exception:
        return None
    if len(s) >= 8 and _printable_ratio(s) >= 0.95 and sum(c.isalpha() for c in s) >= len(s) * 0.4:
        return s
    return None


def decode_payloads(text: str, depth: int = 2, limit: int = 5) -> list[str]:
    """Find base64/hex blobs and decode them (recursively, a couple of levels)."""
    found: list[str] = []
    queue = [text]
    for _ in range(depth):
        nxt = []
        for chunk in queue:
            for tok in _B64_TOKEN.findall(chunk):
                dec = _try_b64(tok)
                if dec and dec not in found:
                    found.append(dec)
                    nxt.append(dec)
            for tok in _HEX_TOKEN.findall(chunk):
                dec = _try_hex(tok)
                if dec and dec not in found:
                    found.append(dec)
                    nxt.append(dec)
        queue = nxt
        if not queue or len(found) >= limit:
            break
    return found[:limit]


def analyze(text: str) -> Analysis:
    cleaned, removed = clean(text)
    plain = fold(cleaned)

    variants = {"plain": plain, "leet": plain.translate(_LEET)}
    variants["rot13"] = fold(codecs.decode(cleaned, "rot_13"))
    variants["reversed"] = plain[::-1]
    if "%" in cleaned:
        unq = fold(unquote(cleaned))
        if unq != plain:
            variants["url"] = unq
    decoded = decode_payloads(cleaned)
    for i, d in enumerate(decoded):
        variants[f"decoded_{i}"] = fold(d)

    squashed = {
        "plain": re.sub(r"[^a-z0-9]", "", plain),
        "leet": re.sub(r"[^a-z0-9]", "", variants["leet"]),
    }

    flags = []
    if removed >= 3:
        flags.append(("hidden_characters", "obfuscation", 0.6,
                      f"{removed} invisible/control characters hidden in the message"))

    # Homoglyphs: a word mixing real Latin letters with look-alike Cyrillic/Greek letters.
    pre = cleaned.casefold()
    homo_words = [w for w in re.findall(r"\w+", pre)
                  if any(c in _HOMO_MAP for c in w) and any("a" <= c <= "z" for c in w)]
    if homo_words:
        flags.append(("homoglyph_obfuscation", "obfuscation", 0.6,
                      "Look-alike letters from other alphabets mixed into words"))

    if len(cleaned) >= 40:
        noisy = sum(1 for c in cleaned if not (c.isalnum() or c.isspace()))
        if noisy / len(cleaned) > 0.35:
            flags.append(("symbol_noise", "obfuscation", 0.35, "Unusually high density of symbols"))

    if decoded:
        flags.append(("encoded_content", "obfuscation", 0.3, "Message contains an encoded text blob"))

    return Analysis(plain=plain, variants=variants, squashed=squashed, flags=flags)
