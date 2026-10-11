"""crypto_toolkit: small, well-documented wrappers around vetted crypto primitives."""

from .aes_gcm import DecryptionError, generate_key, encrypt, decrypt, encrypt_to_b64, decrypt_from_b64
from .hmac_utils import compute_hmac, verify_hmac
from .password_hashing import hash_password, verify_password, needs_rehash
from .rsa_signatures import (
    generate_rsa_keypair,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    load_public_key,
    sign,
    verify,
)

__all__ = [
    "DecryptionError", "generate_key", "encrypt", "decrypt", "encrypt_to_b64", "decrypt_from_b64",
    "compute_hmac", "verify_hmac",
    "hash_password", "verify_password", "needs_rehash",
    "generate_rsa_keypair", "serialize_private_key", "serialize_public_key",
    "load_private_key", "load_public_key", "sign", "verify",
]
