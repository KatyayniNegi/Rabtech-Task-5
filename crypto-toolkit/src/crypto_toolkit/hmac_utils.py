"""HMAC-SHA256 message authentication.

Use HMAC when two parties share a secret and need integrity + authenticity
(webhook signatures, signed cookies, API request signing). It does NOT provide
confidentiality and is not a password hash.
"""

from __future__ import annotations

import hashlib
import hmac

MIN_KEY_BYTES = 32


def compute_hmac(key: bytes, message: bytes, digest=hashlib.sha256) -> bytes:
    """Return the raw HMAC tag of ``message``."""
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"HMAC key should be at least {MIN_KEY_BYTES} random bytes")
    return hmac.new(key, message, digest).digest()


def verify_hmac(key: bytes, message: bytes, tag: bytes, digest=hashlib.sha256) -> bool:
    """Constant-time tag verification (prevents timing attacks).

    Never compare tags with ``==``; it leaks how many leading bytes matched.
    """
    expected = compute_hmac(key, message, digest)
    return hmac.compare_digest(expected, tag)
