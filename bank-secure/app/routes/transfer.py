"""
Transfer routes with Hybrid RSA + AES-GCM secure channel.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, render_template_string, request

from app.models.schemas import get_account_by_user_id, get_all_accounts_except
from app.security.csrf import csrf_protect, generate_csrf_token, regenerate_csrf_token
from app.security.sessions import login_required
from app.services.api_gateway import (
    validate_key_exchange_request,
    validate_secure_transfer_request,
)
from app.services.audit_service import write_audit_event
from app.services.crypto_service import CryptoServiceError, get_crypto_service
from app.services.iam_service import get_auth_claims
from app.services.kms_hsm import get_kms_service
from app.services.payment_service import process_secure_payment
from app.services.secure_session_keys import get_secure_session_key_store


transfer_bp = Blueprint("transfer", __name__)


@transfer_bp.route("/transfer", methods=["GET"])
@login_required
def transfer_page():
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
    claims = get_auth_claims()
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    is_valid, error = validate_key_exchange_request(payload)
    if not is_valid:
        return jsonify({"error": error}), 400

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
    claims = get_auth_claims()
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid JSON body"}), 400

    is_valid, error = validate_secure_transfer_request(payload)
    if not is_valid:
        return jsonify({"error": error}), 400

    dek = get_secure_session_key_store().get(
        session_id=claims["session_id"],
        key_id=payload["key_id"],
    )
    if not dek:
        return jsonify({"error": "Secure channel not established"}), 400

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

    result = process_secure_payment(
        actor_user_id=claims["user_id"],
        aad=payload["aad"],
        key_id=payload["key_id"],
        nonce=payload["nonce"],
        ciphertext=payload["ciphertext"],
        auth_tag=payload["auth_tag"],
        decrypted_payload=plaintext_payload,
    )

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

    if not result.success:
        return jsonify(
            {
                "error": result.message,
                "risk_score": result.risk_score,
                "risk_decision": result.risk_decision,
            }
        ), result.status_code

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


TRANSFER_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Transfer Money - Secure Bank</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f5f7fa;
            padding: 20px;
        }
        .container {
            max-width: 700px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
            font-size: 32px;
            margin-bottom: 8px;
        }
        .card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .account-info {
            background: #f5f7fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .account-info p { margin: 5px 0; color: #666; }
        .account-info strong { color: #333; }
        .balance { font-size: 24px; color: #2e7d32; font-weight: bold; }
        .form-group { margin-bottom: 20px; }
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
            font-size: 14px;
        }
        select, input[type="number"], input[type="text"] {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 15px;
        }
        select:focus, input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #4caf50 0%, #2e7d32 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        .btn-back {
            background: linear-gradient(135deg, #757575 0%, #616161 100%);
            margin-top: 10px;
            text-decoration: none;
            display: block;
            text-align: center;
            color: white;
            padding: 14px;
            border-radius: 6px;
            font-weight: 600;
        }
        .message {
            padding: 15px;
            margin: 15px 0;
            border-radius: 6px;
            display: none;
        }
        .message.success {
            background: #d4edda;
            border-left: 4px solid #28a745;
            color: #155724;
            display: block;
        }
        .message.error {
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            color: #721c24;
            display: block;
        }
        .message.info {
            background: #e3f2fd;
            border-left: 4px solid #1e88e5;
            color: #0d47a1;
            display: block;
        }
        .security-notice {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            border-radius: 4px;
            font-size: 13px;
        }
        .security-notice strong {
            color: #856404;
            display: block;
            margin-bottom: 8px;
        }
        .security-notice ul {
            list-style: none;
            padding-left: 0;
        }
        .security-notice li { padding: 3px 0; }
        .security-notice li:before {
            content: "✓ ";
            color: #28a745;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>💸 Secure Transfer (Hybrid RSA + AES-GCM)</h1>
            <p>Encrypted payload + tag verification + replay protection</p>
        </div>

        <div class="card">
            <div class="account-info">
                <p><strong>Your Account:</strong> {{ account_number }}</p>
                <p><strong>Available Balance:</strong> <span class="balance">${{ "%.2f"|format(balance) }}</span></p>
            </div>

            <div id="message" class="message"></div>

            <form id="transferForm">
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
                    <input type="number" id="amount" name="amount" step="0.01" min="0.01" max="{{ balance }}" required>
                </div>

                <div class="form-group">
                    <label for="description">Description (optional)</label>
                    <input type="text" id="description" name="description" placeholder="e.g., Rent payment">
                </div>

                <input type="hidden" id="csrf_token" name="csrf_token" value="{{ csrf_token }}">

                <button type="submit" id="submitBtn">Transfer Money Securely</button>
                <a href="{{ url_for('account.dashboard') }}" class="btn-back">Back to Dashboard</a>
            </form>
        </div>

        <div class="card">
            <div class="security-notice">
                <strong>🔒 Security Components Active</strong>
                <ul>
                    <li>API Gateway input validation</li>
                    <li>IAM claims from authenticated session</li>
                    <li>KMS/HSM RSA key unwrapping</li>
                    <li>Crypto Service AES-256-GCM + tag verification</li>
                    <li>Risk Engine scoring and decisioning</li>
                    <li>Audit logging and encrypted transaction storage</li>
                </ul>
            </div>
        </div>
    </div>

    <script>
        const form = document.getElementById('transferForm');
        const submitBtn = document.getElementById('submitBtn');
        const messageDiv = document.getElementById('message');
        const csrfInput = document.getElementById('csrf_token');

        let aesKey = null;
        let keyId = null;
        let channelReady = false;

        function setMessage(text, type) {
            messageDiv.className = `message ${type}`;
            messageDiv.textContent = text;
        }

        function bytesToBase64(bytes) {
            let binary = '';
            const chunk = 0x8000;
            for (let i = 0; i < bytes.length; i += chunk) {
                binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
            }
            return btoa(binary);
        }

        function pemToArrayBuffer(pem) {
            const b64 = pem
                .replace('-----BEGIN PUBLIC KEY-----', '')
                .replace('-----END PUBLIC KEY-----', '')
                .replace(/\\s+/g, '');
            const binary = atob(b64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        }

        async function bootstrapSecureChannel() {
            if (channelReady) {
                return;
            }

            setMessage('Establishing secure channel...', 'info');

            const keyResponse = await fetch('{{ url_for("transfer.get_public_key") }}');
            const keyData = await keyResponse.json();
            if (!keyResponse.ok) {
                throw new Error(keyData.error || 'Failed to get public key');
            }

            keyId = keyData.key_id;

            const rsaPublicKey = await crypto.subtle.importKey(
                'spki',
                pemToArrayBuffer(keyData.public_key_pem),
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                false,
                ['encrypt']
            );

            aesKey = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt']
            );

            const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);
            const encryptedAesKey = await crypto.subtle.encrypt(
                { name: 'RSA-OAEP' },
                rsaPublicKey,
                rawAesKey
            );

            const handshakeResponse = await fetch('{{ url_for("transfer.establish_secure_channel") }}', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    encrypted_key: bytesToBase64(new Uint8Array(encryptedAesKey)),
                    key_id: keyId,
                    csrf_token: csrfInput.value
                })
            });
            const handshakeData = await handshakeResponse.json();

            if (!handshakeResponse.ok) {
                throw new Error(handshakeData.error || 'Failed to establish secure channel');
            }

            channelReady = true;
            setMessage('Secure channel ready (RSA + AES-GCM)', 'success');
        }

        async function encryptTransferPayload(payload) {
            const aadObject = {
                txid: crypto.randomUUID(),
                actor: 'customer',
                channel: 'web',
                ts: new Date().toISOString()
            };
            const aad = JSON.stringify(aadObject);

            const iv = crypto.getRandomValues(new Uint8Array(12));
            const plaintext = new TextEncoder().encode(JSON.stringify(payload));
            const aadBytes = new TextEncoder().encode(aad);

            const encrypted = new Uint8Array(await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv,
                    additionalData: aadBytes,
                    tagLength: 128
                },
                aesKey,
                plaintext
            ));

            const tag = encrypted.slice(encrypted.length - 16);
            const ciphertext = encrypted.slice(0, encrypted.length - 16);

            return {
                key_id: keyId,
                nonce: bytesToBase64(iv),
                aad,
                ciphertext: bytesToBase64(ciphertext),
                auth_tag: bytesToBase64(tag)
            };
        }

        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            submitBtn.disabled = true;
            submitBtn.textContent = 'Processing...';

            try {
                await bootstrapSecureChannel();

                const amount = parseFloat(document.getElementById('amount').value);
                const transferPayload = {
                    to_account: document.getElementById('to_account').value,
                    amount,
                    description: document.getElementById('description').value
                };

                const encryptedPayload = await encryptTransferPayload(transferPayload);
                encryptedPayload.csrf_token = csrfInput.value;

                const response = await fetch('{{ url_for("transfer.process_transfer") }}', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(encryptedPayload)
                });
                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || 'Transfer failed');
                }

                setMessage(
                    `${data.message} | tx=${data.tx_id} | risk=${data.risk_score} (${data.risk_decision})`,
                    'success'
                );

                if (data.csrf_token) {
                    csrfInput.value = data.csrf_token;
                }
                form.reset();

                setTimeout(() => {
                    window.location.href = '{{ url_for("account.dashboard") }}';
                }, 1800);

            } catch (error) {
                setMessage(error.message, 'error');
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Transfer Money Securely';
            }
        });

        bootstrapSecureChannel().catch((error) => setMessage(error.message, 'error'));
    </script>
</body>
</html>
"""
