# Note
- Main workflow with Python code with API fastAPI and Uvicorn ? Yes

- Project Title: Secure Online Banking Session Implementation with TLS

- Objective: 
    Demonstrate practical application of cryptographic protocols (TLS 1.3) 
    and secure session management in a simulated banking web application.

- Banking Flow:
    1. Login: User authenticates with username/password
    2. View Balance: Authenticated user retrieves account balance
    3. Transfer Money: User initiates fund transfer to another account

- Target: 
    Build a working prototype that shows how cryptography protects each 
    step of this flow against common attacks (MITM, session hijacking, 
    replay attacks).


# Project Scope: Secure Online Banking Session

## 1. Objective
[What you're building and why - 2-3 sentences]

## 2. Banking Flow
- Login: [describe]
- View Balance: [describe]  
- Transfer Money: [describe]

## 3. System Architecture
[Simple text diagram:]
Browser (Client) <--TLS 1.3--> Flask Server <--> SQLite DB

## 4. Assumptions
[Copy the table above]

## 5. Scope Boundaries
In-Scope: [bullet list]
Out-of-Scope: [bullet list]

## 6. Threat Focus
Primary threats addressed:
- MITM attacks (via TLS)
- Session hijacking (via secure cookies)
- CSRF (via tokens)
- Credential stuffing (via rate limiting)
- Replay attacks (via nonces/timestamps)

## 7. Technologies
- Python 3.x
- Flask web framework
- OpenSSL for certificates
- bcrypt for password hashing
- Wireshark for verification

## 8. Success Criteria
- TLS 1.3 handshake visible in Wireshark
- Browser shows valid HTTPS padlock
- Session tokens are HttpOnly and Secure
- Transfer requests require CSRF token
- Passwords stored as hashes, never plaintext

WHAT HAPPPENS HERE, NEED TO ANALYZE AND FIX
# Secure Banking Application - Cryptography Course Project

**Course**: Introduction to Cryptography  
**Project**: Secure Online Banking Session Implementation  
**Security Features**: TLS 1.3, Bcrypt, CSRF Protection, Session Management, Replay Protection

---

## 📁 Project Structure

```
bank-secure/
├── app/
│   ├── main.py                 # Application entry point
│   ├── routes/
│   │   ├── auth.py            # Authentication (login/logout)
│   │   ├── account.py         # Account dashboard
│   │   └── transfer.py        # Money transfers
│   ├── security/
│   │   ├── sessions.py        # Session management & rate limiting
│   │   ├── csrf.py            # CSRF protection
│   │   ├── passwords.py       # Password hashing (bcrypt)
│   │   └── mfa.py             # MFA design (architecture only)
│   └── models/
│       └── schemas.py         # Database schema & data access
├── tests/
│   ├── test_auth.py           # Authentication tests
│   ├── test_session.py        # Session management tests
│   └── test_transfer.py       # Transfer security tests
├── scripts/
│   ├── gen_local_certs.sh     # Generate TLS certificates
│   └── run_https.sh           # Start HTTPS server
├── docs/
│   ├── threat_model.md        # Comprehensive threat analysis
│   ├── architecture.md        # System architecture (Step 2)
│   └── report.md              # Final project report template
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate TLS Certificates

```bash
bash scripts/gen_local_certs.sh
```

This creates:
- `cert.pem` - Public certificate (RSA-4096)
- `key.pem` - Private key

### 3. Run the Application

```bash
bash scripts/run_https.sh
```

Or manually:
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
python3 app/main.py
```

### 4. Access the Application

Open browser to: **https://localhost:5000**

⚠️ **Accept the certificate warning** (expected for self-signed certificates)

### 5. Login

**Demo Accounts:**
- Username: `alice` | Password: `Alice123!` (Balance: $5000)
- Username: `bob` | Password: `Bob123!` (Balance: $3000)

---

## 🔒 Security Features Implemented

### Transport Layer
- ✅ **TLS 1.3** - Encryption in transit (AES-256-GCM)
- ✅ **Perfect Forward Secrecy** - Ephemeral Diffie-Hellman key exchange
- ✅ **Certificate Validation** - RSA-4096 self-signed (demo)

### Authentication
- ✅ **Bcrypt Password Hashing** - Cost factor 12 (2^12 iterations)
- ✅ **Rate Limiting** - 5 login attempts per 5 minutes
- ✅ **Account Lockout** - 5-minute cooldown after max attempts
- ✅ **Constant-Time Comparison** - Prevents timing attacks

### Session Management
- ✅ **Secure Cookies** - `Secure`, `HttpOnly`, `SameSite=Lax`
- ✅ **Session Regeneration** - Prevents fixation attacks
- ✅ **Idle Timeout** - 30 minutes inactivity
- ✅ **Absolute Timeout** - 8 hours maximum session duration

### Transaction Security
- ✅ **CSRF Protection** - 256-bit cryptographic tokens
- ✅ **Replay Attack Prevention** - Unique 128-bit nonce per transaction
- ✅ **Server-Side Validation** - Balance checks, account verification
- ✅ **Atomic Transactions** - Database rollback on failure

### Code Security
- ✅ **Parameterized Queries** - SQL injection prevention
- ✅ **Input Validation** - XSS protection
- ✅ **Audit Logging** - Session events tracked

---

## 🧪 Running Tests

```bash
# Run all tests
python3 -m unittest discover tests/

# Run specific test file
python3 -m unittest tests/test_auth.py

# Run with verbose output
python3 -m unittest discover -v tests/
```

**Test Coverage:**
- Authentication (login, logout, rate limiting)
- Session management (timeouts, cookie security)
- Transfer security (CSRF, replay protection, validation)
- Password security (hashing, strength validation)

---

## 📊 For Your Report

### Step 1: Scope Definition ✅
- **File**: `README.md` (this file) + `docs/threat_model.md`
- Banking operations: Login → View Balance → Transfer Money
- Technology stack: Python, Flask, SQLite, TLS 1.3, Bcrypt

### Step 2: Architecture Diagrams ✅
- **File**: `docs/architecture.md`
- Component diagram
- Data flow (login, transfer)
- Security layers

### Step 3: Threat Model ✅
- **File**: `docs/threat_model.md`
- 15 identified threats
- Impact analysis
- Mitigation strategies
- Compliance mapping (OWASP, NIST, PCI DSS)

### Step 4-7: TLS Implementation ✅
- **Files**: `scripts/gen_local_certs.sh`, `app/main.py`
- Certificate generation
- TLS 1.3 configuration
- Verification procedures

### Step 8: Authentication ✅
- **File**: `app/security/passwords.py`, `app/routes/auth.py`
- Bcrypt implementation
- Rate limiting logic
- Password strength validation

### Step 9: Session Management ✅
- **File**: `app/security/sessions.py`
- Cookie security flags
- Timeout implementation
- Session regeneration

### Step 10: CSRF/Replay Protection ✅
- **Files**: `app/security/csrf.py`, `app/routes/transfer.py`
- CSRF token generation/validation
- Nonce-based replay prevention
- Database unique constraints

### Step 11: Key Management ✅
- **Files**: `docs/threat_model.md`, `scripts/gen_local_certs.sh`
- Long-term keys (TLS certificates)
- Ephemeral keys (session keys)
- Perfect forward secrecy

### Step 12: HTTPS Enforcement ✅
- **File**: `app/main.py`
- All routes require HTTPS
- Secure cookie flags
- TLS-only communication

### Step 13: Final Report ✅
- **Template**: `docs/report.md`
- Combines all above sections
- Screenshots and evidence
- References and citations

---

## 📸 Evidence for Report

### TLS 1.3 Verification

**1. Browser Proof:**
```
1. Open https://localhost:5000
2. Click padlock icon
3. View certificate details
4. Screenshot showing "TLS 1.3"
```

**2. OpenSSL Proof:**
```bash
openssl s_client -connect localhost:5000 -tls1_3
# Look for: "Protocol: TLSv1.3"
```

**3. Wireshark Capture:**
```
1. Start Wireshark on Loopback interface
2. Filter: tcp.port == 5000
3. Capture TLS handshake
4. Screenshot showing "Application Data" (encrypted)
```

### Security Feature Proofs

**Session Cookies:**
```
1. Login to application
2. Open DevTools → Application → Cookies
3. Screenshot showing Secure, HttpOnly, SameSite flags
```

**CSRF Protection:**
```
1. Open Network tab in DevTools
2. Submit a transfer
3. Screenshot showing csrf_token in POST data
```

**Rate Limiting:**
```
1. Attempt login with wrong password 6 times
2. Screenshot showing "Too many login attempts" message
```

---

## 🔑 Cryptographic Algorithms Used

| Purpose | Algorithm | Key Size | Details |
|---------|-----------|----------|---------|
| Transport Encryption | AES-GCM | 256-bit | TLS 1.3 bulk encryption |
| Password Hashing | Bcrypt | N/A | Cost factor 12 (4096 iterations) |
| Key Exchange | ECDHE | 256-bit | Ephemeral Diffie-Hellman |
| Session Tokens | HMAC-SHA256 | 256-bit | Cookie signing |
| CSRF Tokens | Random | 256-bit | secrets.token_hex(32) |
| Nonce | Random | 128-bit | secrets.token_hex(16) |
| TLS Certificates | RSA | 4096-bit | Self-signed for demo |

---

## 📚 References

### Standards & Guidelines
- **NIST SP 800-52 Rev. 2**: Guidelines for TLS Configuration
- **NIST SP 800-57**: Key Management Recommendations
- **NIST SP 800-63B**: Digital Identity Guidelines
- **OWASP Top 10 2021**: Web Application Security Risks
- **OWASP Session Management Cheat Sheet**
- **OWASP CSRF Prevention Cheat Sheet**

### RFCs
- **RFC 8446**: TLS 1.3
- **RFC 6238**: TOTP (for MFA design)
- **RFC 2898**: PBKDF2 (password hashing reference)

### Python Libraries
- **Flask**: https://flask.palletsprojects.com/
- **Bcrypt**: https://pypi.org/project/bcrypt/
- **Python secrets module**: https://docs.python.org/3/library/secrets.html

---

## 🎓 Grading Checklist

### Implementation (40 points)
- [x] Working TLS 1.3 server
- [x] Secure authentication (bcrypt, rate limiting)
- [x] Session management (timeouts, secure cookies)
- [x] CSRF protection on transfers
- [x] Replay attack prevention
- [x] Clean, modular code structure

### Documentation (30 points)
- [x] Threat model with 15+ threats
- [x] Architecture diagrams
- [x] Code comments explaining security decisions
- [x] Clear README with setup instructions

### Testing & Verification (20 points)
- [x] Unit tests for all security features
- [x] TLS handshake verification
- [x] Security feature demonstrations
- [x] Attack prevention proofs

### Theory & Understanding (10 points)
- [x] Cryptographic algorithm justifications
- [x] Security best practices
- [x] References to standards (NIST, OWASP)
- [x] Residual risk analysis

---

## 🛠️ Development Notes

### Code Organization
- **Separation of Concerns**: Routes, security, models in separate modules
- **Security-First**: Security functions in dedicated `app/security/` directory
- **Testability**: All security features have unit tests
- **Documentation**: Every function has docstring explaining security implications

### Security Best Practices
- **Never commit certificates** to version control (add to .gitignore)
- **Use environment variables** for SECRET_KEY in production
- **Rotate certificates** annually
- **Enable MFA** for production deployment
- **Use CA-signed certificates** (Let's Encrypt) in production
- **Enable logging** for audit trail

### Production Deployment Considerations
1. Use proper WSGI server (Gunicorn, uWSGI)
2. Put behind reverse proxy (nginx)
3. Use Redis for rate limiting (not in-memory)
4. Enable database connection pooling
5. Implement proper logging (ELK stack)
6. Add monitoring (Prometheus, Grafana)
7. Use managed database (PostgreSQL, not SQLite)
8. Enable MFA for all users
9. Implement API rate limiting
10. Add DDoS protection (Cloudflare)

---

## 🆘 Troubleshooting

### Certificate Errors
**Problem**: "Certificate warning won't go away"  
**Solution**: Self-signed certificates always show warnings. Click "Advanced" → "Proceed to localhost"

### Import Errors
**Problem**: `ModuleNotFoundError: No module named 'app'`  
**Solution**: Run from `bank-secure/` directory and ensure PYTHONPATH is set:
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### Port Already in Use
**Problem**: `Address already in use`  
**Solution**: Kill existing process:
```bash
lsof -ti:5000 | xargs kill
```

### Database Locked
**Problem**: `database is locked`  
**Solution**: Only one instance can run at a time. Close previous instance.

---

## 📝 License

This is an educational project for academic purposes.

---

## 🙏 Acknowledgments

Built with Flask, Bcrypt, and adherence to OWASP and NIST security guidelines.

---

**Good luck with your cryptography project! 🔒🎓**

For questions about specific security implementations, refer to:
- `docs/threat_model.md` - Detailed threat analysis
- `docs/architecture.md` - System design
- Code comments in `app/security/` modules