# SECR4483 / SCSR4483 — Secure Programming
## Alternative Assessment: HealthVault-API Supply Chain Compromise & Legacy Debt Architecture — Security Audit & Secure Refactor

This repository contains the secure, refactored version of the vulnerable
`HealthVault-API` files reviewed in the accompanying Security Audit Report.

## Files

| File | Purpose | Key fixes |
|---|---|---|
| `search.php` | Patient record search endpoint | PDO prepared statements (SQLi fix), `htmlspecialchars()` output encoding (XSS fix) |
| `auth.php` | Staff key authentication | `mb_strlen()` character-safe bound check, `password_verify()` + Argon2id (replaces MD5) |
| `crypto_vault.php` | Patient data encryption at rest | AES-256-GCM with random IV + auth tag (replaces AES-128-ECB), key sourced from `.env` (no hardcoding) |
| `db_config.php` | Shared PDO connection | Least-privilege DB user, credentials from `.env` |
| `schema.sql` | Database schema + seed data | `patient_records`, `staff_credentials` tables |

The full vulnerability analysis, root-cause discussion, and PDPA 2010
mapping for each flaw are documented in the Security Audit Report
(submitted separately as per assignment instructions).

## Setup

```bash
composer install
cp .env.example .env
# edit .env with real DB credentials and a base64-encoded 32-byte AES key
mysql -u root -p < schema.sql
```

Generate a key for `VAULT_KEY_B64`:

```bash
php -r "echo base64_encode(random_bytes(32)) . PHP_EOL;"
```

## Notes

- `.env` is git-ignored and must never be committed.
- `db_config.php` should connect using a least-privilege MySQL user
  (e.g. `vault_app_user`) with `SELECT`/`INSERT`/`UPDATE` only on
  `patient_records` and `staff_credentials` — not root.

## Author

Muhamad Dzarhan Azmy
