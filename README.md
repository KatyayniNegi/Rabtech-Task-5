This project implements secure cryptographic protocols in Python using the vetted cryptography and bcrypt libraries, with no custom primitives.

AES-256-GCM: authenticated encryption with a fresh random 96-bit IV for every message and optional associated data. Tampering, a wrong key or a mismatched context fails closed.
RSA-2048: key pair generation, passphrase-encrypted PEM export, and RSA-PSS (SHA-256) digital signatures with verification.
HMAC-SHA256: message authentication with constant-time tag comparison.
bcrypt: password hashing with a unique salt per hash, a configurable work factor (default cost 12), SHA-256 pre-hashing to avoid the 72-byte truncation limit, and rehash-on-login support.
Documentation: docs/KEY_MANAGEMENT.md covers secret and key storage (KMS/HSM, secrets managers, envelope encryption), rotation schedules, a zero-downtime rotation procedure and incident response. docs/SECURITY.md covers the threat model and limitations.
Quality checks: 23 unit tests, including an RFC 4231 HMAC reference vector, and a GitHub Actions workflow that runs the tests and demo on every push.
