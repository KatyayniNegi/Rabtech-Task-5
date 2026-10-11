# crypto-toolkit

Small, readable Python utilities demonstrating secure use of standard cryptographic primitives:

| Module | What it does |
|---|---|
| `aes_gcm.py` | AES-256-GCM authenticated encryption, random 96-bit IV per message, optional AAD |
| `rsa_signatures.py` | RSA-2048 key generation, passphrase-encrypted PEM export, RSA-PSS/SHA-256 sign & verify |
| `hmac_utils.py` | HMAC-SHA256 with constant-time verification |
| `password_hashing.py` | bcrypt with per-hash salt, configurable work factor, rehash-on-login support |

Built on [`cryptography`](https://cryptography.io) and [`bcrypt`](https://pypi.org/project/bcrypt/). **No custom cryptography is implemented.**

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src python examples/demo.py
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Usage

```python
from crypto_toolkit import *

# AES-256-GCM
key = generate_key()                                  # 32 random bytes
blob = encrypt(key, b"secret", aad=b"user:42")        # version || nonce || ciphertext || tag
assert decrypt(key, blob, aad=b"user:42") == b"secret"

# RSA-PSS signatures
priv, pub = generate_rsa_keypair()
sig = sign(priv, b"message")
assert verify(pub, b"message", sig)

# HMAC
tag = compute_hmac(key, b"webhook body")
assert verify_hmac(key, b"webhook body", tag)

# Passwords
h = hash_password("correct horse battery staple")     # bcrypt, cost 12
assert verify_password("correct horse battery staple", h)
```

## Security properties covered by tests

* Fresh random IV every encryption; ciphertext/nonce/tag tampering, wrong key, and AAD mismatch all fail closed
* RSA signatures are probabilistic (PSS), reject modified messages and wrong keys; private key PEM encrypts with a passphrase
* HMAC matches the RFC 4231 known-answer vector; short keys rejected; comparison is constant-time
* bcrypt hashes are uniquely salted, passwords >72 bytes are not silently truncated, `needs_rehash` detects outdated work factors

## Documentation

* [`docs/KEY_MANAGEMENT.md`](docs/KEY_MANAGEMENT.md): secret/key storage, rotation, and incident response
* [`docs/SECURITY.md`](docs/SECURITY.md): threat model, design decisions, and limitations

## Disclaimer

This is an educational reference implementation. Have a qualified security professional review it before protecting production data.

## License

MIT
