"""Text views that undo the cheap obfuscations an attacker can ask a model for.

Used by both the detector (attacks/detector.py) and egress (tenantguard/egress.py).
Sharing the *decoding* is fine; what the detector must not share with egress is the
knowledge of which canaries exist (see the "B3 without canary check" run).

Neither Sectum nor AgentLeak decode before matching; this is where TenantGuard goes further.
"""

import base64
import binascii
import codecs
import re
from urllib.parse import unquote_plus

# 12+ chars: a single 11-char canary base64-encodes to only 15 chars + "=" padding.
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX_TOKEN = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]")


def _b64_decodes(text: str) -> list[str]:
    out = []
    for token in _B64_TOKEN.findall(text):
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(token + "=" * (-len(token) % 4))
                decoded = raw.decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if decoded.isprintable() or "\n" in decoded:
                out.append(decoded)
                break
    return out


def _hex_decodes(text: str) -> list[str]:
    out = []
    for token in _HEX_TOKEN.findall(text):
        try:
            out.append(bytes.fromhex(token).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
    return out


def views(text: str, depth: int = 2) -> list[str]:
    """Every decoded form of `text` worth matching against, including the original.

    Covers URL-encoding, base64 (standard and URL-safe, also when the whole answer is
    one blob), hex, ROT13, reversal, and a compacted form with every separator removed
    so "A C M E - 7 F 3 A 9 C" and "ACME 7F3A 9C" still match "ACME7F3A9C".
    """
    seen: list[str] = []
    frontier = [text]
    for _ in range(depth + 1):
        nxt = []
        for t in frontier:
            if t in seen:
                continue
            seen.append(t)
            nxt.append(unquote_plus(t))
            nxt.extend(_b64_decodes(t))
            nxt.extend(_hex_decodes(t))
        frontier = [t for t in nxt if t not in seen]
        if not frontier:
            break
    extra = []
    for t in seen:
        extra.append(t[::-1])
        extra.append(codecs.decode(t, "rot13"))
    return seen + extra


def compact(text: str) -> str:
    return _NON_ALNUM.sub("", text).upper()


def compact_views(text: str) -> list[str]:
    return [compact(v) for v in views(text)]
