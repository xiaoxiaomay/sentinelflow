"""
gates/gate_0_decode.py

Gate 0 Pre-processor: Encoding Detection and Normalization

Runs BEFORE Gate 0a. Detects common encoding schemes and decodes them,
then passes the decoded text to the normal gate pipeline.

Supported encodings:
- Base64 (detect by pattern + decode attempt + printability check)
- ROT13 (statistical letter frequency analysis)
- Hex encoding (0x... patterns or pure hex strings)
- URL encoding (%XX patterns)
- Unicode escape sequences (\\uXXXX)
- Reversed text (simple heuristic)

Does NOT block — transforms input for downstream gates.
Logs detected encoding type to audit chain.

Inputs:  raw query string, config dict
Outputs: dict with decoded_text, encoding_detected, encoding_type, original_text
"""

import base64
import codecs
import re
import string
from typing import Any, Dict, List, Optional
from urllib.parse import unquote


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
_BASE64_INLINE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_PATTERN = re.compile(r"(?:0x)?([0-9a-fA-F]{2}(?:\s*[0-9a-fA-F]{2}){4,})")
_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
_URL_ENCODED = re.compile(r"(%[0-9a-fA-F]{2})[^%]*(%[0-9a-fA-F]{2})[^%]*(%[0-9a-fA-F]{2})")
_UNICODE_ESCAPE = re.compile(r"(\\u[0-9a-fA-F]{4}){3,}")


def _printable_ratio(text: str) -> float:
    """Fraction of characters that are printable ASCII."""
    if not text:
        return 0.0
    printable = sum(1 for c in text if c in string.printable)
    return printable / len(text)


def _letter_ratio(text: str) -> float:
    """Fraction of characters that are letters."""
    if not text:
        return 0.0
    letters = sum(1 for c in text if c.isalpha())
    return letters / len(text)


def detect_base64(text: str, min_length: int = 20,
                  require_printable_ratio: float = 0.60) -> Optional[str]:
    """
    Detect and decode Base64 content.
    Returns decoded text if Base64 is detected, None otherwise.
    """
    text = text.strip()

    # Try full-string match first
    if _BASE64_PATTERN.match(text) and len(text) >= min_length:
        try:
            decoded = base64.b64decode(text).decode("utf-8", errors="replace")
            if _printable_ratio(decoded) >= require_printable_ratio and _letter_ratio(decoded) > 0.30:
                return decoded
        except Exception:
            pass

    # Try inline Base64 segments
    for match in _BASE64_INLINE.finditer(text):
        segment = match.group()
        if len(segment) < min_length:
            continue
        try:
            decoded = base64.b64decode(segment).decode("utf-8", errors="replace")
            if _printable_ratio(decoded) >= require_printable_ratio and _letter_ratio(decoded) > 0.30:
                # Replace the Base64 segment with decoded text
                return text[:match.start()] + decoded + text[match.end():]
        except Exception:
            continue

    return None


def detect_rot13(text: str) -> Optional[str]:
    """
    Detect ROT13 by decoding and checking if result contains more
    recognizable English patterns.
    """
    text = text.strip()
    if not text or _letter_ratio(text) < 0.40:
        return None

    decoded = codecs.decode(text, "rot_13")

    # Common attack-related words that would appear after decoding
    attack_indicators = [
        "secret", "confidential", "internal", "threshold", "strategy",
        "parameter", "password", "reveal", "system", "prompt",
        "trading", "alpha", "risk", "model", "rule",
        "ignore", "override", "jailbreak", "instructions",
    ]

    decoded_lower = decoded.lower()
    original_lower = text.lower()

    decoded_hits = sum(1 for w in attack_indicators if w in decoded_lower)
    original_hits = sum(1 for w in attack_indicators if w in original_lower)

    if decoded_hits > original_hits and decoded_hits >= 1:
        return decoded

    return None


def detect_hex(text: str) -> Optional[str]:
    """Detect hex-encoded content (\\xNN sequences or raw hex)."""
    text = text.strip()

    # \\xNN escape sequences
    if _HEX_ESCAPE.search(text):
        try:
            decoded = _HEX_ESCAPE.sub(
                lambda m: chr(int(m.group(1), 16)), text
            )
            if decoded != text and _printable_ratio(decoded) > 0.60:
                return decoded
        except Exception:
            pass

    # Raw hex strings
    match = _HEX_PATTERN.search(text)
    if match:
        hex_str = match.group(1).replace(" ", "")
        try:
            decoded = bytes.fromhex(hex_str).decode("utf-8", errors="replace")
            if _printable_ratio(decoded) > 0.60 and _letter_ratio(decoded) > 0.30:
                return text[:match.start()] + decoded + text[match.end():]
        except Exception:
            pass

    return None


def detect_url_encoding(text: str) -> Optional[str]:
    """Detect URL-encoded content (%XX sequences)."""
    if not _URL_ENCODED.search(text):
        return None

    try:
        decoded = unquote(text)
        if decoded != text and _printable_ratio(decoded) > 0.60:
            return decoded
    except Exception:
        pass

    return None


def detect_unicode_escape(text: str) -> Optional[str]:
    """Detect \\uXXXX unicode escape sequences."""
    if not _UNICODE_ESCAPE.search(text):
        return None

    try:
        decoded = text.encode("utf-8").decode("unicode_escape")
        if decoded != text and _printable_ratio(decoded) > 0.60:
            return decoded
    except Exception:
        pass

    return None


def detect_reversed(text: str) -> Optional[str]:
    """
    Detect reversed text. Heuristic: reverse and check if it contains
    more recognizable patterns.
    """
    text = text.strip()
    if not text or len(text) < 10 or _letter_ratio(text) < 0.40:
        return None

    reversed_text = text[::-1]

    indicators = [
        "secret", "confidential", "internal", "threshold", "strategy",
        "reveal", "system", "prompt", "password", "trading", "alpha",
        "ignore", "override", "jailbreak",
    ]

    reversed_lower = reversed_text.lower()
    original_lower = text.lower()

    rev_hits = sum(1 for w in indicators if w in reversed_lower)
    orig_hits = sum(1 for w in indicators if w in original_lower)

    if rev_hits > orig_hits and rev_hits >= 1:
        return reversed_text

    return None


# ---------------------------------------------------------------------------
# Main gate function
# ---------------------------------------------------------------------------

def decode_gate(
    query: str,
    config: Optional[dict] = None,
) -> Dict[str, Any]:
    """
    Gate 0 Pre-processor: Encoding Detection and Normalization.

    Returns:
        {
            "original_text": str,
            "decoded_text": str,         # same as original if no encoding found
            "encoding_detected": bool,
            "encoding_type": str|None,   # "base64", "rot13", "hex", "url", "unicode", "reversed"
            "all_detections": list,       # all detected encodings
        }
    """
    config = config or {}
    min_length = int(config.get("base64_min_length", 20))
    printable_ratio = float(config.get("require_printable_ratio", 0.60))

    detections: List[Dict[str, str]] = []
    decoded_text = query

    # Try each detector in priority order
    detectors = [
        ("base64", lambda t: detect_base64(t, min_length, printable_ratio)),
        ("hex", detect_hex),
        ("url", detect_url_encoding),
        ("unicode", detect_unicode_escape),
        ("rot13", detect_rot13),
        ("reversed", detect_reversed),
    ]

    for enc_type, detector in detectors:
        try:
            result = detector(decoded_text)
            if result is not None:
                detections.append({
                    "encoding_type": enc_type,
                    "original_segment": decoded_text[:200],
                    "decoded_segment": result[:200],
                })
                decoded_text = result
        except Exception:
            continue

    return {
        "original_text": query,
        "decoded_text": decoded_text,
        "encoding_detected": len(detections) > 0,
        "encoding_type": detections[0]["encoding_type"] if detections else None,
        "all_detections": detections,
    }
