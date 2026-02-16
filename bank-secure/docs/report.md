# Midterm Report Notes (Updated to Diagram)

## Implemented

- Hybrid key exchange for application payload channel:
  - RSA-2048 public key distribution
  - RSA-OAEP session key encapsulation
  - AES-256-GCM encrypted transfer payload with AAD and tag
- Diagram-style service responsibilities inside code modules:
  - API Gateway/WAF input checks
  - IAM claims
  - KMS/HSM key unwrap
  - Crypto service integrity verification
  - Risk engine scoring
  - Payment orchestration
  - Audit logging
- Database secure transaction record:
  - `secure_transactions` table stores encrypted payload fields and metadata
  - replay protection with unique nonce

## Evidence to Capture

1. Public key exchange:
   - browser/network capture for `GET /crypto/public-key`
   - response showing `key_id`, `algorithm`, `public_key_pem`
2. Encapsulated session key:
   - `POST /crypto/session-key` request body includes `encrypted_key`
3. Encrypted transfer payload:
   - `POST /transfer` body includes `nonce`, `aad`, `ciphertext`, `auth_tag`
4. Database proof:
   - query `secure_transactions` showing ciphertext/auth_tag/nonces, no plaintext amount
5. Integrity failure path:
   - tamper one field and show server response `Tag verification failed`

