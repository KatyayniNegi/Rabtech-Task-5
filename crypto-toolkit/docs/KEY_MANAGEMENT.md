# Secret & Key Management: Storage and Rotation

## 1. Principles

1. **Never hard-code secrets** in source, images, notebooks, or client-side code.
2. **Never commit secrets.** `.gitignore` excludes `*.pem`, `*.key`, `.env`; add a pre-commit scanner (`gitleaks`, `trufflehog`) and enable GitHub secret scanning + push protection.
3. **Least privilege:** each service gets only the keys it needs; separate keys per purpose (encryption vs. signing vs. HMAC) and per environment (dev/staging/prod).
4. **Generate with a CSPRNG** (`os.urandom`, `AESGCM.generate_key`). Human-chosen strings are not keys; derive keys from passwords only via a KDF (Argon2id, scrypt, PBKDF2 with a high iteration count).
5. **Keep keys out of logs, error messages, crash dumps, and analytics.**

## 2. Where to store secrets

| Option | Use for | Notes |
|---|---|---|
| **Cloud KMS / HSM** (AWS KMS, GCP KMS, Azure Key Vault) | Master/root keys, signing keys | Key material never leaves the HSM; you call encrypt/sign APIs. Best option for high-value keys. |
| **Secrets manager** (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager) | API tokens, DB credentials, HMAC keys | Central audit logs, access policies, automatic rotation. |
| **Envelope encryption** | Encrypting application data | A KMS-held Key Encryption Key (KEK) wraps per-record/per-tenant Data Encryption Keys (DEKs). Store the wrapped DEK beside the ciphertext. |
| **Environment variables** | Injecting secrets at runtime | Acceptable if populated from a secrets manager at deploy time; avoid for long-lived root keys (visible in process listings, crash dumps, `docker inspect`). |
| **Encrypted PEM on disk** | Local/dev only | Use `serialize_private_key(key, passphrase=...)`, `chmod 600`, owned by the service user. |
| **Plain files / DB columns / repo** | Never | |

### Envelope encryption pattern

```
KMS (KEK)  --wraps-->  DEK (AES-256)  --encrypts-->  data
store: { wrapped_dek, key_id, ciphertext }
```

Benefits: the KEK never touches application memory, rotating the KEK only requires re-wrapping DEKs (not re-encrypting all data), and each record's blast radius is limited.

## 3. Rotation

### Schedule (recommended defaults, adjust to policy)

| Secret | Rotate every | Also rotate immediately when |
|---|---|---|
| AES data keys (DEKs) | On volume limit (< 2^32 messages/key for random nonces) or 12 months | Suspected exposure |
| KMS KEK | 12 months (automatic) | Suspected exposure |
| RSA signing keys | 12-24 months | Suspected exposure; staff with access leave |
| HMAC/API secrets | 90 days | Suspected exposure; partner offboarding |
| DB/service credentials | 30-90 days (dynamic secrets preferred) | Suspected exposure |
| bcrypt cost factor | Review yearly; raise when hashing < ~250 ms | Hardware upgrades |

### Zero-downtime rotation procedure

1. **Create** a new key with a new `key_id`/`kid`.
2. **Dual-read:** deploy code that can *verify/decrypt* with both old and new keys, selecting by `key_id` stored with each payload (extend the 1-byte version header or add a key-id field).
3. **Switch writes:** start *encrypting/signing* with the new key only.
4. **Migrate:** re-encrypt old data lazily (on read) or via a background job; re-sign long-lived artifacts if required.
5. **Retire:** after the grace period, disable the old key (verify-only), then destroy it once no data depends on it. Keep old *public* keys available to verify historical signatures.
6. **Audit:** record who rotated what and when.

### Passwords (bcrypt)

* On successful login, call `needs_rehash(stored_hash, target_cost)`; if true, re-hash the submitted password and update the record. This upgrades users transparently.
* Optional **pepper**: an HMAC of the password using a secret kept in a KMS/secrets manager (not in the DB). Plan for pepper rotation by storing a pepper version.

## 4. Operational controls

* **Access:** role-based access, MFA for humans, short-lived credentials (OIDC/IAM roles) for machines; no shared accounts.
* **Audit:** enable KMS/Vault audit logs; alert on unusual decrypt volume or access from new principals.
* **Backups:** back up key material only in encrypted form with separate access controls; test restores.
* **Memory hygiene:** minimise key lifetime in memory; don't log or serialise key objects. (Python cannot reliably zero memory; prefer KMS-resident keys.)
* **Separation of duties:** people who can read data should not also administer the keys.

## 5. Incident response: suspected key compromise

1. Revoke/disable the key and issue a replacement immediately (rotate).
2. Identify what the key protected and the exposure window from audit logs.
3. Re-encrypt/re-sign affected data with new keys; invalidate sessions/tokens derived from the old key.
4. Rotate any secrets that were stored alongside or encrypted by the compromised key.
5. Notify per legal/regulatory obligations; run a post-incident review and fix the root cause (leak path).

## 6. Checklist

- [ ] No secrets in git history (scan with gitleaks/trufflehog)
- [ ] Secret scanning + push protection enabled
- [ ] Keys generated by CSPRNG, one purpose per key
- [ ] Root/signing keys in KMS/HSM
- [ ] Rotation schedule documented and automated
- [ ] Payloads carry `key_id`/version to allow dual-read rotation
- [ ] Audit logging and alerting enabled
- [ ] Incident-response runbook tested
