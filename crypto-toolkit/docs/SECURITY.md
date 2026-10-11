# Design Decisions & Threat Model

## Algorithm choices

| Need | Choice | Why |
|---|---|---|
| Confidentiality + integrity | AES-256-GCM | AEAD standard; hardware accelerated; detects tampering |
| Nonces | 12 random bytes/message | Never reused under one key; rotate keys before ~2^32 messages |
| Signatures | RSA-2048, PSS, SHA-256 | PSS has a security proof and is preferred over PKCS#1 v1.5; 2048 bits ≈ 112-bit security (use 3072+ for long-lived data, or Ed25519 for new systems) |
| Message authentication | HMAC-SHA256 | Shared-secret integrity; constant-time compare |
| Password storage | bcrypt, cost 12, SHA-256 prehash | Slow, salted, adaptive; prehash avoids 72-byte truncation |

## Threats addressed

* **Ciphertext tampering / bit flipping:** GCM tag verification fails closed.
* **Ciphertext replay across contexts:** AAD binds ciphertext to its context.
* **Timing attacks on MAC comparison:** `hmac.compare_digest`.
* **Offline password cracking after DB leak:** per-password salt + tunable cost.
* **Signature forgery / message modification:** RSA-PSS verification.
* **Private key theft from disk:** passphrase-encrypted PKCS#8 PEM.
* **Oracle leakage:** decryption errors are generic.

## Known limitations

* GCM nonce reuse is catastrophic; this library uses random nonces, which is only safe up to the volume limit above. For very high volumes use AES-GCM-SIV or XChaCha20-Poly1305 or derive per-message keys.
* RSA signatures here do not provide key distribution or trust (no PKI / certificates).
* The password prehash means hashes are not interchangeable with plain bcrypt hashes of the raw password.
* bcrypt is not memory-hard; consider Argon2id for new systems.
* Python can't guarantee zeroisation of key material in memory.
* No side-channel hardening beyond what OpenSSL provides.
* Reference code, not an audited library.

## Do-not list

* Don't use ECB/CBC-without-MAC, MD5/SHA-1 for security, or unsalted hashes.
* Don't compare MACs/hashes with `==`.
* Don't reuse one key for multiple purposes.
* Don't roll your own primitives or protocols.
