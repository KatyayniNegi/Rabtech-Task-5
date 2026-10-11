"""Password hashing with bcrypt (automatic per-hash salt + adjustable work factor).

Design notes
------------
* ``bcrypt.gensalt(rounds=N)`` generates a unique random 128-bit salt; the salt
  and cost are embedded in the output string, so no separate salt storage.
* Work factor: cost 12 is the default here (~250 ms on modern hardware). Tune
  so one hash takes roughly 250-500 ms on YOUR production hardware and raise it
  over time. ``needs_rehash`` supports transparent upgrades at login.
* bcrypt only reads the first 72 bytes of input and rejects NUL bytes. To avoid
  silent truncation we pre-hash with SHA-256 and base64-encode (44 ASCII chars).
* Verification uses bcrypt's constant-time comparison.
* For new systems also consider Argon2id (memory-hard); bcrypt remains a sound,
  widely-deployed choice.
"""

from __future__ import annotations

import base64
import hashlib

import bcrypt

DEFAULT_COST = 12
MIN_COST = 10


def _prepare(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str, cost: int = DEFAULT_COST) -> str:
    if cost < MIN_COST:
        raise ValueError(f"cost must be >= {MIN_COST}")
    if not password:
        raise ValueError("password must not be empty")
    return bcrypt.hashpw(_prepare(password), bcrypt.gensalt(rounds=cost)).decode("ascii")


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prepare(password), stored_hash.encode("ascii"))
    except ValueError:
        return False


def needs_rehash(stored_hash: str, target_cost: int = DEFAULT_COST) -> bool:
    """True if the stored hash uses a lower cost than ``target_cost``.

    Call after a successful login; if True, re-hash the plaintext and store it.
    """
    try:
        # Format: $2b$<cost>$<22-char salt><31-char hash>
        return int(stored_hash.split("$")[2]) < target_cost
    except (IndexError, ValueError):
        return True
