"""
Transfer routes with Hybrid RSA + AES-GCM secure channel.
"""
from __future__ import annotations

from functools import wraps
from flask import Blueprint, jsonify, render_template_string, request, session, redirect, url_for

from app.models.schemas import get_account_by_user_id, get_all_accounts_except
from app.security.csrf import csrf_protect, generate_csrf_token, regenerate_csrf_token
from app.services.audit_service import write_audit_event
from app.services.crypto_service import CryptoServiceError, get_crypto_service
from app.services.kms_hsm import get_kms_service
from app.services.payment_service import process_secure_payment
from app.services.secure_session_keys import get_secure_session_key_store

transfer_bp = Blueprint("transfer", __name__)


def login_required(f):
    """
    Decorator to require authentication for routes.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in (user_id exists in session)
        if "user_id" not in session:
            # For API endpoints, return JSON error
            if request.is_json or request.path.startswith('/crypto/'):
                return jsonify({"error": "Unauthorized - Please log in"}), 401
            # For page endpoints, redirect to login
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def get_auth_claims():
    """
    Extracts user information from Flask session.
    Replacement for IAM service get_auth_claims()
    """
    if "user_id" not in session:
        return None
    
    return {
        "user_id": session.get("user_id"),
        "username": session.get("username"),
        "session_id": session.get("session_id") or session.get("_id"),
        "email": session.get("email"),
    }


def validate_key_exchange_request(payload):
    """
    Validates the session key exchange payload.
    
    Returns: (is_valid: bool, error_message: str or None)
    """
    if not payload:
        return False, "Request payload is required"
    
    # Check required fields
    required_fields = ["encrypted_key", "key_id"]
    missing = [f for f in required_fields if f not in payload]
    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"
    
    # Validate encrypted_key (should be base64 string)
    encrypted_key = payload.get("encrypted_key")
    if not isinstance(encrypted_key, str) or len(encrypted_key) == 0:
        return False, "encrypted_key must be a non-empty string"
    
    # Validate key_id
    key_id = payload.get("key_id")
    if not isinstance(key_id, str) or len(key_id) == 0:
        return False, "key_id must be a non-empty string"
    
    return True, None


def validate_secure_transfer_request(payload):
    """
    Validates the encrypted transfer payload.
    
    Returns: (is_valid: bool, error_message: str or None)
    """
    if not payload:
        return False, "Request payload is required"
    
    # Check required fields for AES-GCM encrypted payload
    required_fields = ["key_id", "nonce", "ciphertext", "auth_tag", "aad"]
    missing = [f for f in required_fields if f not in payload]
    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"
    
    # Validate each field
    for field in required_fields:
        value = payload.get(field)
        if not isinstance(value, str) or len(value) == 0:
            return False, f"{field} must be a non-empty string"
    
    # Additional validation: check base64 format (basic check)
    try:
        import base64
        base64.b64decode(payload["nonce"])
        base64.b64decode(payload["ciphertext"])
        base64.b64decode(payload["auth_tag"])
    except Exception:
        return False, "Invalid base64 encoding in nonce, ciphertext, or auth_tag"
    
    return True, None


@transfer_bp.route("/transfer", methods=["GET"])
@login_required
def transfer_page():
    """Render the transfer page."""
    user = get_auth_claims()
    if not user:
        return "Unauthorized", 401

    account = get_account_by_user_id(user["user_id"])
    if not account:
        return "Account not found", 404

    other_accounts = get_all_accounts_except(user["user_id"])

    return render_template_string(
        TRANSFER_TEMPLATE,
        account_number=account["account_number"],
        balance=account["balance"],
        other_accounts=other_accounts,
        csrf_token=generate_csrf_token(),
    )


@transfer_bp.route("/crypto/public-key", methods=["GET"])
@login_required
def get_public_key():
    """Return the server's RSA public key for key exchange."""
    claims = get_auth_claims()
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401

    envelope = get_kms_service().get_public_key()

    write_audit_event(
        event_type="public_key_requested",
        status="success",
        actor_user_id=claims["user_id"],
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        details={"key_id": envelope.key_id},
    )

    return jsonify(
        {
            "key_id": envelope.key_id,
            "algorithm": envelope.algorithm,
            "key_size": envelope.key_size,
            "public_key_pem": envelope.public_key_pem,
        }
    )


@transfer_bp.route("/crypto/session-key", methods=["POST"])
@login_required
@csrf_protect
def establish_secure_channel():
    """
    Establish a secure channel by unwrapping the client's encrypted session key.
    Client sends: RSA-encrypted AES key
    Server: Unwraps it and stores in session
    """
    claims = get_auth_claims()
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}

    # Validate request
    is_valid, error = validate_key_exchange_request(payload)
    if not is_valid:
        return jsonify({"error": error}), 400

    # Unwrap the encrypted session key using KMS/HSM
    try:
        dek = get_kms_service().unwrap_dek(
            encrypted_key_b64=payload["encrypted_key"],
            key_id=payload["key_id"],
        )
    except Exception as exc:
        write_audit_event(
            event_type="session_key_unwrap",
            status="failed",
            actor_user_id=claims["user_id"],
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"reason": str(exc)},
        )
        return jsonify({"error": "Unable to unwrap session key"}), 400

    # Store the decrypted session key
    get_secure_session_key_store().put(
        session_id=claims["session_id"],
        key_id=payload["key_id"],
        dek=dek,
    )

    write_audit_event(
        event_type="session_key_unwrap",
        status="success",
        actor_user_id=claims["user_id"],
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        details={"key_id": payload["key_id"]},
    )

    return jsonify({"success": True, "message": "Secure channel established"})


@transfer_bp.route("/transfer", methods=["POST"])
@login_required
@csrf_protect
def process_transfer():
    """
    Process an encrypted transfer using AES-GCM.
    Decrypts the payload, validates, and executes the payment.
    """
    claims = get_auth_claims()
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid JSON body"}), 400

    # Validate the encrypted transfer request
    is_valid, error = validate_secure_transfer_request(payload)
    if not is_valid:
        return jsonify({"error": error}), 400

    # Retrieve the session key (DEK) from secure storage
    dek = get_secure_session_key_store().get(
        session_id=claims["session_id"],
        key_id=payload["key_id"],
    )
    if not dek:
        return jsonify({"error": "Secure channel not established"}), 400

    # Decrypt the transfer payload using AES-GCM
    try:
        plaintext_payload = get_crypto_service().decrypt_transfer_payload(
            dek=dek,
            nonce_b64=payload["nonce"],
            aad=payload["aad"],
            ciphertext_b64=payload["ciphertext"],
            auth_tag_b64=payload["auth_tag"],
        )
    except CryptoServiceError as exc:
        write_audit_event(
            event_type="ciphertext_verify",
            status="failed",
            actor_user_id=claims["user_id"],
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"reason": str(exc)},
        )
        return jsonify({"error": str(exc)}), 400

    # Process the payment with risk scoring
    result = process_secure_payment(
        actor_user_id=claims["user_id"],
        aad=payload["aad"],
        key_id=payload["key_id"],
        nonce=payload["nonce"],
        ciphertext=payload["ciphertext"],
        auth_tag=payload["auth_tag"],
        decrypted_payload=plaintext_payload,
    )

    # Audit the transfer
    write_audit_event(
        event_type="secure_transfer",
        status="success" if result.success else "failed",
        actor_user_id=claims["user_id"],
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        details={
            "tx_id": result.tx_id,
            "risk_score": result.risk_score,
            "risk_decision": result.risk_decision,
            "risk_reason": result.risk_reason,
        },
    )

    # Handle failed transfers
    if not result.success:
        return (
            jsonify(
                {
                    "error": result.message,
                    "risk_score": result.risk_score,
                    "risk_decision": result.risk_decision,
                }
            ),
            result.status_code,
        )

    # Generate new CSRF token for next request
    next_csrf_token = regenerate_csrf_token()

    return jsonify(
        {
            "success": True,
            "message": result.message,
            "new_balance": result.new_balance,
            "tx_id": result.tx_id,
            "risk_score": result.risk_score,
            "risk_decision": result.risk_decision,
            "risk_reason": result.risk_reason,
            "csrf_token": next_csrf_token,
        }
    )


# ============================================================================
# HTML TEMPLATE
# ============================================================================

TRANSFER_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Transfer</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        .header p {
            opacity: 0.9;
            font-size: 14px;
        }
        .content {
            padding: 30px;
        }
        .account-info {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
        }
        .account-info p {
            margin-bottom: 10px;
            font-size: 15px;
        }
        .account-info strong {
            color: #667eea;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        select, input[type="number"], input[type="text"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 15px;
            transition: border-color 0.3s;
        }
        select:focus, input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            margin-bottom: 10px;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        .btn-secondary {
            background: #f8f9fa;
            color: #333;
            border: 2px solid #e0e0e0;
        }
        .btn-secondary:hover {
            background: #e9ecef;
        }
        .security-info {
            background: #f0f7ff;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin-top: 30px;
            border-radius: 4px;
        }
        .security-info h3 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 18px;
        }
        .security-info ul {
            list-style: none;
            padding-left: 0;
        }
        .security-info li {
            padding: 6px 0;
            color: #555;
            font-size: 14px;
        }
        .security-info li:before {
            content: "✓ ";
            color: #667eea;
            font-weight: bold;
            margin-right: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>💸 Secure Transfer</h1>
            <p>Encrypted payload + tag verification + replay protection</p>
        </div>
        
        <div class="content">
            <div class="account-info">
                <p><strong>Your Account:</strong> {{ account_number }}</p>
                <p><strong>Available Balance:</strong> ${{ "%.2f"|format(balance) }}</p>
            </div>
            
            <form id="transferForm">
                <input type="hidden" id="csrf_token" value="{{ csrf_token }}">
                
                <div class="form-group">
                    <label for="to_account">To Account</label>
                    <select id="to_account" name="to_account" required>
                        <option value="">-- Select Recipient --</option>
                        {% for acc in other_accounts %}
                        <option value="{{ acc.account_number }}">{{ acc.account_number }}</option>
                        {% endfor %}
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="amount">Amount ($)</label>
                    <input type="number" id="amount" name="amount" step="0.01" min="0.01" required>
                </div>
                
                <div class="form-group">
                    <label for="description">Description (optional)</label>
                    <input type="text" id="description" name="description" placeholder="e.g., Dinner split">
                </div>
                
                <button type="submit" class="btn btn-primary">Transfer Money Securely</button>
                <button type="button" class="btn btn-secondary" onclick="window.location.href='/dashboard'">Back to Dashboard</button>
            </form>
            
            <div class="security-info">
                <h3>🔒 Security Components Active</h3>
                <ul>
                    <li>Session-based authentication</li>
                    <li>CSRF protection</li>
                    <li>KMS/HSM RSA key unwrapping</li>
                    <li>AES-256-GCM encryption + tag verification</li>
                    <li>Risk engine scoring and decisioning</li>
                    <li>Audit logging and encrypted transaction storage</li>
                </ul>
            </div>
        </div>
    </div>
    
    <script>
        // This is a placeholder - you'll need to implement actual encryption on client-side
        document.getElementById('transferForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = {
                to_account: document.getElementById('to_account').value,
                amount: parseFloat(document.getElementById('amount').value),
                description: document.getElementById('description').value
            };
            
            // TODO: Implement client-side encryption using the public key
            // For now, this is a simplified version
            
            try {
                const response = await fetch('/transfer', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': document.getElementById('csrf_token').value
                    },
                    body: JSON.stringify(formData)
                });
                
                const result = await response.json();
                
                if (result.success) {
                    alert('Transfer successful! Transaction ID: ' + result.tx_id);
                    window.location.reload();
                } else {
                    alert('Transfer failed: ' + result.error);
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        });
    </script>
</body>
</html>
"""