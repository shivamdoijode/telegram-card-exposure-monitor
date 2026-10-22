"""
card_parser.py - extract and mask payment-card exposure from message text.

Design rules:
  - The full card number (PAN) and CVV are NEVER returned or stored.
  - Only BIN (first 6), last 4, expiry and a salted hash (for dedupe) are kept.
  - Numbers failing the Luhn check are discarded as fake/random.
  - The parser is tolerant: any separator symbol, labels like "Exp:" / "CVV:",
    spaced card numbers, fancy Unicode fonts and invisible characters are handled.
"""
import hashlib
import os
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

# PAN <sep> month <sep> year <sep> CVV. Separators may be any non-digit text on the same line.
CARD_RE = re.compile(
    r"(?<!\d)(\d{13,19})[^\d\n]{1,30}?(\d{1,2})[^\d\n]{1,10}?(\d{4}|\d{2})[^\d\n]{1,30}?(\d{3,4})(?!\d)"
)
SPACED_PAN_RE = re.compile(r"(?<!\d)(\d{4})[ \-](\d{4})[ \-](\d{4})[ \-](\d{1,7})(?!\d)")
DIGIT_RUN_RE = re.compile(r"\d{13,19}")
ISSUER_RE = re.compile(
    r"(?:issuer|bank(?:\s*info|\s*data)?)\s*[^\w\n]*\s*([^\n|]{2,60})", re.I
)
TYPE_RE = re.compile(r"\b(credit|debit|prepaid)\b", re.I)
BRAND_RE = re.compile(r"\b(visa|mastercard|amex|american express|discover|rupay|maestro)\b", re.I)

_INVISIBLE = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad"
                               "\u202a\u202b\u202c\u202d\u202e"), None)
HASH_SALT = os.getenv("CARD_HASH_SALT", "change-me")


@dataclass
class CardFinding:
    bin6: str
    last4: str
    expiry: str          # MM/YYYY
    expired: bool
    issuer: str
    card_type: str
    brand: str
    card_hash: str       # salted SHA-256 of the PAN, used only for dedupe


def luhn_valid(number: str) -> bool:
    total, alt = 0, False
    for ch in reversed(number):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _normalize(text: str) -> str:
    # NFKC turns fancy unicode fonts into plain ASCII; also drop invisible characters
    text = unicodedata.normalize("NFKC", text or "").translate(_INVISIBLE)
    return SPACED_PAN_RE.sub(lambda m: "".join(m.groups()), text)  # "4111 1111 1111 1111" -> joined


def _squash(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def analyze(text: str) -> Tuple[List[CardFinding], int]:
    """Return (valid findings, number of card-shaped candidates before Luhn/date checks)."""
    text = _normalize(text)
    candidates = CARD_RE.findall(text)
    if not candidates:
        return [], 0

    issuer_m = ISSUER_RE.search(text)
    type_m = TYPE_RE.search(text)
    brand_m = BRAND_RE.search(text)
    issuer = issuer_m.group(1).strip() if issuer_m else "--"
    card_type = type_m.group(1).title() if type_m else "--"
    brand = brand_m.group(1).title() if brand_m else "--"

    now = datetime.utcnow()
    findings = []
    for pan, month, year, _cvv in candidates:  # CVV is intentionally dropped
        if not luhn_valid(pan):
            continue
        month_i = int(month)
        year_i = int(year) + 2000 if len(year) == 2 else int(year)
        if not (1 <= month_i <= 12 and 2010 <= year_i <= 2050):
            continue
        findings.append(
            CardFinding(
                bin6=pan[:6],
                last4=pan[-4:],
                expiry=f"{month_i:02d}/{year_i}",
                expired=(year_i, month_i) < (now.year, now.month),
                issuer=issuer,
                card_type=card_type,
                brand=brand,
                card_hash=hashlib.sha256((HASH_SALT + pan).encode()).hexdigest(),
            )
        )
    return findings, len(candidates)


def extract_cards(text: str) -> List[CardFinding]:
    return analyze(text)[0]


def has_digit_run(text: str) -> bool:
    return bool(DIGIT_RUN_RE.search(_normalize(text)))


def mask_digits(text: str) -> str:
    """Mask card numbers (keep BIN + last 4) and CVV/year-like numbers for safe debug display."""
    def repl(m):
        d = m.group()
        if len(d) >= 13:
            return d[:6] + "*" * (len(d) - 10) + d[-4:]
        if len(d) in (3, 4):
            return "#" * len(d)
        return d
    return re.sub(r"\d+", repl, text)


def debug_sample(text: str, max_len: int = 300) -> str:
    """Masked excerpt of a message that has a card-sized number but did not parse."""
    t = _normalize(text)
    lines = [l for l in t.splitlines() if DIGIT_RUN_RE.search(l)] or t.splitlines()[:1]
    joined = " / ".join(lines)
    odd = sorted({c for c in joined if not c.isascii() and not c.isalpha()})
    odd_txt = " ".join(f"U+{ord(c):04X}{c}" for c in odd[:10])
    out = mask_digits(joined)[:max_len]
    return out + (f"   [non-ASCII symbols: {odd_txt}]" if odd else "")


def matches_watchlist(finding: CardFinding, text: str, keywords: List[str]) -> Optional[str]:
    """Return the keyword that matched (BIN prefix or bank/issuer name), else None.
    Bank names are compared ignoring case, punctuation and extra spaces."""
    low = _squash(_normalize(text))
    issuer = _squash(finding.issuer)
    for kw in keywords:
        k = kw.strip()
        if not k:
            continue
        if k.isdigit():
            if finding.bin6.startswith(k[:6]) or k.startswith(finding.bin6[: len(k)]):
                return kw
        else:
            ks = _squash(k)
            if ks and (ks in low or ks in issuer):
                return kw
    return None
