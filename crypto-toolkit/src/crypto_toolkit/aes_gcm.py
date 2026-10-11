"""AES-256-GCM authenticated encryption.

Design notes
------------
* Key: exactly 32 bytes (256 bit) from a CSPRNG (``os.urandom``).
* Nonce/IV: 12 random bytes per message (the size GCM is optimised for).
  A nonce MUST NEVER repeat under the same key. With random 96-bit nonces,
  stay below ~2^32 messages per key, then rotate the key.
* Output layout: ``version(1) || nonce(12) || ciphertext || tag(16)``.
  The leading version byte allows future algorithm migration.
* AAD (associated data) is authenticated but not encrypted. Bind context to
  it (user id, record id, protocol version) so ciphertexts can't be replayed
  in a different context.
* Any tampering raises ``DecryptionError`` -- no partial plaintext is released.
"""

from __future__ import annotations

import base64
import os
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32      # bytes -> AES-256
NONCE_SIZE = 12    # bytes -> 96-bit GCM nonce
TAG_SIZE = 16
VERSION = b"\x01"


class DecryptionError(Exception):
    """Raised when authentication fails or the payload is malformed."""


def generate_key() -> bytes:
    """Return a fresh random 256-bit key."""
    return AESGCM.generate_key(bit_length=256)


def _check_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
        raise ValueError(f"key must be exactly {KEY_SIZE} bytes (AES-256)")


def encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
    """Encrypt and authenticate ``plaintext``. A new random nonce is used every call."""
    _check_key(key)
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)  # ct includes the 16-byte tag
    return VERSION + nonce + ct


def decrypt(key: bytes, payload: bytes, aad: Optional[bytes] = None) -> bytes:
    """Verify and decrypt a payload produced by :func:`encrypt`."""
    _check_key(key)
    if len(payload) < 1 + NONCE_SIZE + TAG_SIZE or payload[:1] != VERSION:
        raise DecryptionError("malformed or unsupported payload")
    nonce = payload[1:1 + NONCE_SIZE]
    ct = payload[1 + NONCE_SIZE:]
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ct, aad)
    except InvalidTag:
        # Deliberately generic: don't reveal whether key, data or AAD was wrong.
        raise DecryptionError("authentication failed") from None


def encrypt_to_b64(key: bytes, text: str, aad: Optional[bytes] = None) -> str:
    """Convenience: str -> URL-safe base64 string."""
    return base64.urlsafe_b64encode(encrypt(key, text.encode("utf-8"), aad)).decode("ascii")


def decrypt_from_b64(key: bytes, token: str, aad: Optional[bytes] = None) -> str:
    """Convenience: URL-safe base64 string -> str."""
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
    except Exception:
        raise DecryptionError("malformed payload") from None
    return decrypt(key, raw, aad).decode("utf-8")
