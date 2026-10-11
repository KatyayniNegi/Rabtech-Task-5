"""RSA-2048 key generation and RSA-PSS digital signatures (SHA-256).

Design notes
------------
* 2048-bit modulus, public exponent 65537 (the standard safe choice).
* Signatures use PSS padding (probabilistic, preferred over PKCS#1 v1.5).
* Private keys are serialised as PKCS#8 PEM and should be encrypted with a
  passphrase at rest (``BestAvailableEncryption``).
* ``verify`` returns a bool and never raises on a bad signature.
"""

from __future__ import annotations

from typing import Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

KEY_BITS = 2048
PUBLIC_EXPONENT = 65537


def generate_rsa_keypair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=KEY_BITS)
    return private, private.public_key()


def serialize_private_key(private_key: rsa.RSAPrivateKey, passphrase: Optional[bytes] = None) -> bytes:
    """PKCS#8 PEM. Provide a passphrase to encrypt the key at rest (strongly recommended)."""
    enc = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
    )


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key(pem: bytes, passphrase: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem, password=passphrase)


def load_public_key(pem: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(pem)


def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


def sign(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    return private_key.sign(message, _pss(), hashes.SHA256())


def verify(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, _pss(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
