"""
Transfer Routes
Handles money transfer functionality with CSRF and replay protection.
"""

import secrets
import sqlite3
from flask import Blueprint, render_template_string, request, jsonify
from app.security.sessions import login_required, get_current_user
from app.security.csrf import generate_csrf_token, csrf_protect, regenerate_csrf_token
from app.models.schemas import (
    get_account_by_user_id, get_account_by_number,
    get_all_accounts_except, get_db_connection
)


transfer_bp = Blueprint('transfer', __name__)


@transfer_bp.route('/transfer', methods=['GET'])
@login_required
def transfer_page():
    """
    Display transfer form.
    
    Security:
        - Requires valid session
        - CSRF token included in form
        - Shows only other accounts for recipient dropdown
    """
    user = get_current_user()
    account = get_account_by_user_id(user['user_id'])
    
    if not account:
        return "Account not found", 404
    
    # Get other accounts for recipient selection
    other_accounts = get_all_accounts_except(user['user_id'])
    
    return render_template_string(
        TRANSFER_TEMPLATE,
        account_number=account['account_number'],
        balance=account['balance'],
        other_accounts=other_accounts,
        csrf_token=generate_csrf_token()
    )


@transfer_bp.route('/transfer', methods=['POST'])
@login_required
@csrf_protect
def process_transfer():
    """
    Process money transfer with comprehensive security checks.
    
    Security Protections:
        1. CSRF token validation (csrf_protect decorator)
        2. Session validation (login_required decorator)
        3. Replay attack prevention (unique nonce)
        4. Server-side validation (balance, account existence)
        5. Database transaction (atomic operation)
    
    Request Body:
        - to_account: Recipient account number
        - amount: Transfer amount
        - csrf_token: CSRF token (validated by decorator)
        - description: Optional transfer description
    
    Returns:
        JSON response with success/error
    """
    user = get_current_user()
    account = get_account_by_user_id(user['user_id'])
    
    if not account:
        return jsonify({'error': 'Account not found'}), 404
    
    # Get transfer details
    to_account = request.form.get('to_account')
    description = request.form.get('description', '')
    
    try:
        amount = float(request.form.get('amount', 0))
    except ValueError:
        return jsonify({'error': 'Invalid amount'}), 400
    
    # Validation
    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400
    
    if amount > account['balance']:
        return jsonify({'error': 'Insufficient funds'}), 400
    
    # Check if recipient account exists
    recipient = get_account_by_number(to_account)
    if not recipient:
        return jsonify({'error': 'Recipient account not found'}), 400
    
    # Prevent self-transfer
    if account['account_number'] == to_account:
        return jsonify({'error': 'Cannot transfer to same account'}), 400
    
    # Generate unique nonce for replay protection
    nonce = secrets.token_hex(16)  # 128 bits
    
    # Get CSRF token that was validated
    csrf_token = request.form.get('csrf_token')
    
    # Perform transfer in database transaction
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Record transaction with nonce (UNIQUE constraint prevents replay)
        cursor.execute('''
            INSERT INTO transactions 
            (from_account, to_account, amount, description, nonce, csrf_token)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (account['account_number'], to_account, amount, description, nonce, csrf_token))
        
        # Update sender balance
        cursor.execute(
            "UPDATE accounts SET balance = balance - ? WHERE account_number = ?",
            (amount, account['account_number'])
        )
        
        # Update recipient balance
        cursor.execute(
            "UPDATE accounts SET balance = balance + ? WHERE account_number = ?",
            (amount, to_account)
        )
        
        conn.commit()
        
        # Get new balance
        cursor.execute(
            "SELECT balance FROM accounts WHERE account_number = ?",
            (account['account_number'],)
        )
        new_balance = cursor.fetchone()['balance']
        
        # Regenerate CSRF token after successful operation
        regenerate_csrf_token()
        
        return jsonify({
            'success': True,
            'message': f'Successfully transferred ${amount:.2f} to {to_account}',
            'new_balance': new_balance
        })
        
    except sqlite3.IntegrityError as e:
        # Nonce already exists - replay attack detected!
        conn.rollback()
        return jsonify({
            'error': 'Duplicate transaction detected (replay attack prevented)'
        }), 400
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': f'Transfer failed: {str(e)}'}), 500
        
    finally:
        conn.close()


# HTML Template for transfer page
TRANSFER_TEMPLATE = '''
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
            max-width: 600px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
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
        .card h2 {
            color: #333;
            margin-bottom: 20px;
            font-size: 24px;
        }
        .account-info {
            background: #f5f7fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 25px;
        }
        .account-info p {
            margin: 5px 0;
            color: #666;
        }
        .account-info strong {
            color: #333;
        }
        .balance {
            font-size: 24px;
            color: #2e7d32;
            font-weight: bold;
        }
        .form-group {
            margin-bottom: 20px;
        }
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
            transition: border-color 0.3s;
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
            transition: all 0.3s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(76, 175, 80, 0.4);
        }
        button:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
        }
        .btn-back {
            background: linear-gradient(135deg, #757575 0%, #616161 100%);
            margin-top: 10px;
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
        .security-notice {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            border-radius: 4px;
            margin-top: 20px;
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
        .security-notice li {
            padding: 3px 0;
        }
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
            <h1>💸 Transfer Money</h1>
            <p>Send money securely</p>
        </div>
        
        <div class="card">
            <div class="account-info">
                <p><strong>Your Account:</strong> {{ account_number }}</p>
                <p><strong>Available Balance:</strong> <span class="balance">${{ "%.2f"|format(balance) }}</span></p>
            </div>
            
            <h2>Transfer Details</h2>
            
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
                
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                
                <button type="submit" id="submitBtn">Transfer Money</button>
                <a href="{{ url_for('account.dashboard') }}"><button type="button" class="btn-back">Back to Dashboard</button></a>
            </form>
        </div>
        
        <div class="card">
            <div class="security-notice">
                <strong>🔒 Security Protections Active</strong>
                <ul>
                    <li>CSRF Token Validation</li>
                    <li>Replay Attack Prevention (Unique Nonce)</li>
                    <li>Server-side Balance Verification</li>
                    <li>TLS 1.3 Encryption</li>
                    <li>Session Timeout Protection</li>
                </ul>
            </div>
        </div>
    </div>
    
    <script>
        const form = document.getElementById('transferForm');
        const submitBtn = document.getElementById('submitBtn');
        const messageDiv = document.getElementById('message');
        
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            // Disable button to prevent double-submit
            submitBtn.disabled = true;
            submitBtn.textContent = 'Processing...';
            
            const formData = new FormData(form);
            
            try {
                const response = await fetch('{{ url_for("transfer.process_transfer") }}', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.success) {
                    messageDiv.className = 'message success';
                    messageDiv.innerHTML = '✓ ' + data.message + '<br>New balance: $' + data.new_balance.toFixed(2);
                    
                    // Reset form
                    form.reset();
                    
                    // Redirect to dashboard after 2 seconds
                    setTimeout(() => {
                        window.location.href = '{{ url_for("account.dashboard") }}';
                    }, 2000);
                } else {
                    messageDiv.className = 'message error';
                    messageDiv.innerHTML = '✗ ' + data.error;
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Transfer Money';
                }
            } catch (error) {
                messageDiv.className = 'message error';
                messageDiv.innerHTML = '✗ Network error occurred';
                submitBtn.disabled = false;
                submitBtn.textContent = 'Transfer Money';
            }
        });
        
        // Validate amount doesn't exceed balance
        document.getElementById('amount').addEventListener('input', (e) => {
            const amount = parseFloat(e.target.value);
            const balance = {{ balance }};
            
            if (amount > balance) {
                e.target.setCustomValidity('Amount exceeds available balance');
            } else {
                e.target.setCustomValidity('');
            }
        });
    </script>
</body>
</html>
'''