# Architecture Alignment (Diagram Implementation)

## 1. Component Mapping

This project implements the diagram components as service modules inside one Flask app process:

- **AuthN + AuthZ** `app/security/sessions.py`
  - Authenticated session claims (`user_id`, `username`, `session_id`).
- **KMS / HSM**: `app/services/kms_hsm.py`
  - Holds RSA key pair, returns public key, unwraps AES session key.
- **Crypto Service (AES-256-GCM)**: `app/services/crypto_service.py`
  - Decrypts ciphertext, verifies GCM tag, parses JSON plaintext.
- **Payment Service**: `app/services/payment_service.py`
  - Validates transfer business rules, updates balances atomically, stores encrypted record.
- **Audit / Logging**: `app/services/audit_service.py`
  - Writes audit events for key exchange, integrity failures, and transfer outcomes.

## 2. Secure Data Store
Encrypted transaction payload is stored in:

- Table: `secure_transactions`
- Columns: `key_id`, `nonce`, `aad`, `ciphertext`, `auth_tag`, `status`, `risk_*`, `actor_user_id`
- Replay control: `nonce` is unique
- No plaintext transfer payload is stored in this table

Schema location: `app/models/schemas.py`

## 3. Sequence Flow (Hybrid RSA + AES-GCM)

1. Client requests bank RSA public key:
   - `GET /crypto/public-key`
2. Client generates AES-256 key (browser WebCrypto).
3. Client wraps AES key with RSA-OAEP and sends:
   - `POST /crypto/session-key`
4. Server unwraps AES key in KMS/HSM service and keeps it in-memory only:
   - `app/services/secure_session_keys.py`
5. Client encrypts transfer payload with AES-GCM using AAD and random nonce.
6. Client sends encrypted payload:
   - `POST /transfer`
   - Body includes `key_id`, `nonce`, `aad`, `ciphertext`, `auth_tag`
7. Server validates input (gateway), loads claims (IAM), decrypts/verifies (crypto service), scores risk, executes payment, writes audit logs.

## 4. Endpoints

- `GET /transfer` - secure transfer page
- `GET /crypto/public-key` - returns RSA public key metadata
- `POST /crypto/session-key` - RSA-encrypted AES key encapsulation
- `POST /transfer` - encrypted transfer message processing

