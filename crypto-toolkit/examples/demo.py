"""End-to-end demo. Run from repo root:  PYTHONPATH=src python examples/demo.py"""

import os

from crypto_toolkit import (
    compute_hmac, decrypt, encrypt, generate_key, generate_rsa_keypair,
    hash_password, needs_rehash, serialize_private_key, serialize_public_key,
    load_private_key, load_public_key, sign, verify, verify_hmac, verify_password,
)


def main() -> None:
    print("== AES-256-GCM ==")
    key = generate_key()
    aad = b"user:42|record:7"
    blob = encrypt(key, b"top secret", aad)
    print("payload bytes:", len(blob), "| roundtrip:", decrypt(key, blob, aad))
    print("two encryptions differ (random IV):", encrypt(key, b"x") != encrypt(key, b"x"))

    print("\n== HMAC-SHA256 ==")
    hkey = os.urandom(32)
    tag = compute_hmac(hkey, b"payload")
    print("valid:", verify_hmac(hkey, b"payload", tag), "| tampered:", verify_hmac(hkey, b"payl0ad", tag))

    print("\n== RSA-2048 / PSS signatures ==")
    priv, pub = generate_rsa_keypair()
    pem = serialize_private_key(priv, passphrase=b"correct horse battery staple")
    priv2 = load_private_key(pem, b"correct horse battery staple")
    pub2 = load_public_key(serialize_public_key(pub))
    sig = sign(priv2, b"contract v1")
    print("valid:", verify(pub2, b"contract v1", sig), "| tampered:", verify(pub2, b"contract v2", sig))

    print("\n== bcrypt ==")
    h = hash_password("hunter2-but-longer!")
    print(h)
    print("correct:", verify_password("hunter2-but-longer!", h), "| wrong:", verify_password("nope", h))
    print("needs rehash at cost 13:", needs_rehash(h, 13))


if __name__ == "__main__":
    main()
