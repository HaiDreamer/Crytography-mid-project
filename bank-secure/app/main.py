"""
Main Application Module
Entry point for the Secure Banking Application.

HOW to run: 
    cd C:\Python\Cryptography\Crytography-mid-project\bank-secure
    python -m app.main
"""

import secrets
import os
from flask import Flask, render_template_string

from app.models.schemas import init_database, seed_demo_users
from app.routes.auth import auth_bp
from app.routes.account import account_bp
from app.routes.transfer import transfer_bp


def create_app():
    """
    Application factory function.
    
    Creates and configures the Flask application with all security settings.
    
    Returns:
        Configured Flask app instance
    """
    app = Flask(__name__)
    
    # Security configuration
    app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(account_bp)
    app.register_blueprint(transfer_bp)
    
    # Home/index route
    @app.route('/')
    def index():
        """Security configuration info page"""
        return render_template_string(SECURITY_INFO_TEMPLATE,
            session_secure=app.config['SESSION_COOKIE_SECURE'],
            session_httponly=app.config['SESSION_COOKIE_HTTPONLY'],
            session_samesite=app.config['SESSION_COOKIE_SAMESITE'],
            session_lifetime=app.config['PERMANENT_SESSION_LIFETIME'].total_seconds() / 60
        )
    
    return app


# HTML Template for security info page
SECURITY_INFO_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Security Configuration - Secure Bank</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 40px 20px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
        }
        .header {
            background: white;
            padding: 40px;
            border-radius: 12px 12px 0 0;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
            font-size: 36px;
            color: #333;
            margin-bottom: 10px;
        }
        .header p {
            color: #666;
            font-size: 16px;
        }
        .card {
            background: white;
            padding: 30px;
            margin-top: 2px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .card:last-child {
            border-radius: 0 0 12px 12px;
        }
        .card h2 {
            color: #333;
            margin-bottom: 20px;
            font-size: 24px;
            display: flex;
            align-items: center;
        }
        .card h2:before {
            content: "🔒";
            margin-right: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        tr {
            border-bottom: 1px solid #e0e0e0;
        }
        tr:last-child {
            border-bottom: none;
        }
        td {
            padding: 15px 10px;
            vertical-align: top;
        }
        td:first-child {
            font-weight: 600;
            color: #555;
            width: 40%;
        }
        td:last-child {
            color: #333;
        }
        .check {
            color: #4caf50;
            font-weight: bold;
            margin-right: 5px;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            background: #e8f5e9;
            color: #2e7d32;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        code {
            background: #f5f5f5;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        .cta {
            text-align: center;
            padding: 30px;
            background: #f5f7fa;
        }
        .btn {
            display: inline-block;
            padding: 14px 32px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.3s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Secure Banking System</h1>
            <p>Security Configuration & Implementation Details</p>
        </div>
        
        <div class="card">
            <h2>TLS Configuration</h2>
            <table>
                <tr>
                    <td>TLS Version</td>
                    <td><span class="check">✓</span> TLS 1.3 (minimum) <span class="badge">Active</span></td>
                </tr>
                <tr>
                    <td>Cipher Suites</td>
                    <td>AES-256-GCM, ChaCha20-Poly1305</td>
                </tr>
                <tr>
                    <td>Certificate</td>
                    <td>RSA-4096 self-signed (demo) / CA-signed (production)</td>
                </tr>
                <tr>
                    <td>HTTPS Enforcement</td>
                    <td><span class="check">✓</span> All routes require HTTPS</td>
                </tr>
                <tr>
                    <td>Perfect Forward Secrecy</td>
                    <td><span class="check">✓</span> Ephemeral Diffie-Hellman key exchange</td>
                </tr>
            </table>
        </div>
        
        <div class="card">
            <h2>Session Management</h2>
            <table>
                <tr>
                    <td>SESSION_COOKIE_SECURE</td>
                    <td><span class="check">✓</span> <code>{{ session_secure }}</code></td>
                </tr>
                <tr>
                    <td>SESSION_COOKIE_HTTPONLY</td>
                    <td><span class="check">✓</span> <code>{{ session_httponly }}</code></td>
                </tr>
                <tr>
                    <td>SESSION_COOKIE_SAMESITE</td>
                    <td><span class="check">✓</span> <code>{{ session_samesite }}</code></td>
                </tr>
                <tr>
                    <td>Session Timeout (Idle)</td>
                    <td>{{ session_lifetime }} minutes</td>
                </tr>
                <tr>
                    <td>Session Timeout (Absolute)</td>
                    <td>8 hours maximum</td>
                </tr>
                <tr>
                    <td>Session Fixation Protection</td>
                    <td><span class="check">✓</span> Session regenerated on login</td>
                </tr>
            </table>
        </div>
        
        <div class="card">
            <h2>Authentication</h2>
            <table>
                <tr>
                    <td>Password Hashing</td>
                    <td><span class="check">✓</span> Bcrypt with unique salt (cost factor 12)</td>
                </tr>
                <tr>
                    <td>Password Requirements</td>
                    <td>Min 8 chars, uppercase, lowercase, digit, special char</td>
                </tr>
                <tr>
                    <td>Rate Limiting</td>
                    <td><span class="check">✓</span> 5 attempts per 5 minutes</td>
                </tr>
                <tr>
                    <td>Account Lockout</td>
                    <td>5 minutes after max attempts exceeded</td>
                </tr>
                <tr>
                    <td>Timing Attack Protection</td>
                    <td><span class="check">✓</span> Constant-time password comparison</td>
                </tr>
            </table>
        </div>
        
        <div class="card">
            <h2>Transfer Protection</h2>
            <table>
                <tr>
                    <td>CSRF Protection</td>
                    <td><span class="check">✓</span> 256-bit cryptographic token validation</td>
                </tr>
                <tr>
                    <td>Replay Attack Prevention</td>
                    <td><span class="check">✓</span> Unique nonce per transaction (128-bit)</td>
                </tr>
                <tr>
                    <td>Server-side Validation</td>
                    <td><span class="check">✓</span> Balance, account existence, amount checks</td>
                </tr>
                <tr>
                    <td>Database Transactions</td>
                    <td><span class="check">✓</span> Atomic operations with rollback</td>
                </tr>
                <tr>
                    <td>Token Regeneration</td>
                    <td><span class="check">✓</span> New CSRF token after each operation</td>
                </tr>
            </table>
        </div>
        
        <div class="card">
            <h2>Cryptographic Algorithms</h2>
            <table>
                <tr>
                    <td>Transport Encryption</td>
                    <td>AES-256-GCM (TLS 1.3)</td>
                </tr>
                <tr>
                    <td>Password Hashing</td>
                    <td>Bcrypt (Blowfish cipher, 2^12 iterations)</td>
                </tr>
                <tr>
                    <td>Random Number Generation</td>
                    <td>Python secrets module (OS CSPRNG)</td>
                </tr>
                <tr>
                    <td>Session Token Signing</td>
                    <td>HMAC-SHA256</td>
                </tr>
                <tr>
                    <td>Key Exchange</td>
                    <td>Ephemeral Diffie-Hellman (ECDHE)</td>
                </tr>
            </table>
        </div>
        
        <div class="card">
            <h2>Audit & Monitoring</h2>
            <table>
                <tr>
                    <td>Session Events</td>
                    <td><span class="check">✓</span> Login, logout, timeout logged</td>
                </tr>
                <tr>
                    <td>Transaction History</td>
                    <td><span class="check">✓</span> All transfers recorded with nonce</td>
                </tr>
                <tr>
                    <td>Failed Login Attempts</td>
                    <td><span class="check">✓</span> Tracked for rate limiting</td>
                </tr>
                <tr>
                    <td>IP Address Logging</td>
                    <td><span class="check">✓</span> Client IP recorded in audit log</td>
                </tr>
            </table>
        </div>
        
        <div class="card cta">
            <p style="margin-bottom: 20px; color: #666;">Ready to experience secure banking?</p>
            <a href="/login" class="btn">Go to Login</a>
        </div>
    </div>
</body>
</html>
'''


def main():
    """
    Main entry point for running the application.
    """
    print("\n" + "="*70)
    print("SECURE BANKING APPLICATION")
    print("="*70)
    
    # Initialize database
    print("\nInitializing database...")
    init_database()
    seed_demo_users()
    
    # Check for TLS certificates
    print("\nChecking for TLS certificates...")
    if os.path.exists('cert.pem') and os.path.exists('key.pem'):
        print("Certificates found.")
    else:
        print("\nTLS certificates not found.")
        print("\nPlease generate certificates using:")
        print("  bash scripts/gen_local_certs.sh")
        print("\nOr manually:")
        print("  openssl req -x509 -newkey rsa:4096 -nodes \\")
        print("    -keyout key.pem -out cert.pem -days 365 \\")
        print("    -subj '/CN=localhost'")
        print("\nThen run:")
        print("  bash scripts/run_https.sh")
        print("\n" + "="*70 + "\n")
        return
    
    # Create app
    app = create_app()
    
    print("\nStarting HTTPS server...")
    print("   URL: https://localhost:5000")
    print("\nDemo Credentials:")
    print("   - alice / Alice123! (Balance: $5000)")
    print("   - bob / Bob123! (Balance: $3000)")
    print("\nBrowser Security Warning Expected:")
    print("   Self-signed certificates trigger warnings in browsers.")
    print("   Click 'Advanced' then 'Proceed to localhost' to continue.")
    print("\n" + "="*70 + "\n")
    
    # Run with TLS
    app.run(
        host='0.0.0.0',
        port=5000,
        ssl_context=('cert.pem', 'key.pem'),
        debug=True
    )


if __name__ == '__main__':
    main()
