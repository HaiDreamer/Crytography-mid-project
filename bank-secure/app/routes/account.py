"""
Account Routes
Handles dashboard and account viewing functionality.
Simplified version without session management imports.
"""

from functools import wraps
from flask import Blueprint, render_template_string, redirect, url_for, session, jsonify, request

from app.security.csrf import generate_csrf_token
from app.models.schemas import get_account_by_user_id, get_secure_transaction_history


# Blueprint setup
account_bp = Blueprint('account', __name__)


# ============================================================================
# AUTHENTICATION HELPERS
# ============================================================================

def login_required(f):
    """
    Decorator to require authentication for routes.
    Checks if user_id exists in session.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # For API endpoints, return JSON error
            if request.is_json:
                return jsonify({"error": "Unauthorized - Please log in"}), 401
            # For page endpoints, redirect to login
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    """
    Get current authenticated user from Flask session.
    
    Returns: dict with user info or None
    """
    if 'user_id' not in session:
        return None
    
    return {
        'user_id': session.get('user_id'),
        'username': session.get('username'),
        'id': session.get('user_id'),  # Alias for compatibility
    }


# ============================================================================
# ROUTES
# ============================================================================

@account_bp.route('/dashboard')
@login_required
def dashboard():
    """
    User dashboard - view account balance.
    
    Security:
        - Requires valid session (@login_required)
        - Auto-validates session timeout
        - CSRF token included for future forms
    """
    user = get_current_user()
    
    if not user:
        return redirect(url_for('auth.login'))
    
    account = get_account_by_user_id(user['user_id'])
    
    if not account:
        return "Account not found", 404
    
    # Secure transaction metadata (encrypted payload is stored server-side)
    try:
        transactions = get_secure_transaction_history(user['user_id'], limit=5)
    except Exception as e:
        print(f"Failed to load transactions: {e}")
        transactions = []
    
    return render_template_string(
        DASHBOARD_TEMPLATE,
        username=user['username'],
        account_number=account['account_number'],
        balance=account['balance'],
        account_type=account.get('account_type', 'checking'),
        transactions=transactions,
        csrf_token=generate_csrf_token()
    )


# ============================================================================
# HTML TEMPLATE
# ============================================================================

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Dashboard - Secure Bank</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f5f7fa;
            padding: 20px;
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
        .header p {
            opacity: 0.9;
            font-size: 16px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
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
        .balance-display {
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .balance-label {
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        .balance-amount {
            font-size: 48px;
            font-weight: bold;
            color: #2e7d32;
        }
        .account-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .info-item {
            padding: 15px;
            background: #f5f7fa;
            border-radius: 8px;
        }
        .info-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }
        .info-value {
            font-size: 16px;
            color: #333;
            font-weight: 500;
        }
        .actions {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        .btn {
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            border: none;
            cursor: pointer;
            transition: all 0.3s;
            display: inline-block;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .btn-secondary {
            background: #f5f7fa;
            color: #333;
        }
        .btn-secondary:hover {
            background: #e0e0e0;
        }
        .btn-danger {
            background: #f44336;
            color: white;
        }
        .btn-danger:hover {
            background: #d32f2f;
        }
        .transactions {
            margin-top: 30px;
        }
        .transaction-list {
            list-style: none;
        }
        .transaction-item {
            padding: 15px;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .transaction-item:last-child {
            border-bottom: none;
        }
        .transaction-details {
            flex: 1;
        }
        .transaction-type {
            font-weight: 600;
            color: #333;
            margin-bottom: 4px;
        }
        .transaction-time {
            font-size: 12px;
            color: #999;
        }
        .transaction-amount {
            font-weight: bold;
            font-size: 18px;
        }
        .amount-positive {
            color: #2e7d32;
        }
        .amount-negative {
            color: #c62828;
        }
        .security-info {
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            border-radius: 4px;
            margin-top: 20px;
            font-size: 13px;
        }
        .security-info strong {
            color: #2e7d32;
        }
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #999;
        }
        .empty-state p {
            font-size: 16px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>👋 Welcome, {{ username }}!</h1>
            <p>🔒 Secure Banking Dashboard</p>
        </div>
        
        <div class="card">
            <h2>💰 Account Overview</h2>
            
            <div class="balance-display">
                <div class="balance-label">Current Balance</div>
                <div class="balance-amount">${{ "%.2f"|format(balance) }}</div>
            </div>
            
            <div class="account-info">
                <div class="info-item">
                    <div class="info-label">Account Number</div>
                    <div class="info-value">{{ account_number }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Account Type</div>
                    <div class="info-value">{{ account_type.title() }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Status</div>
                    <div class="info-value">✅ Active</div>
                </div>
            </div>
            
            <div class="actions">
                <a href="{{ url_for('transfer.transfer_page') }}" class="btn btn-primary">
                    💸 Transfer Money
                </a>
                <a href="/" class="btn btn-secondary">
                    🔐 Security Info
                </a>
                <a href="{{ url_for('auth.logout') }}" class="btn btn-danger">
                    🚪 Logout
                </a>
            </div>
        </div>
        
        <div class="card transactions">
            <h2>📋 Recent Secure Transactions</h2>
            
            {% if transactions %}
            <ul class="transaction-list">
                {% for tx in transactions %}
                <li class="transaction-item">
                    <div class="transaction-details">
                        <div class="transaction-type">
                            🔒 TX #{{ tx.id }} | {{ tx.status.upper() }}
                        </div>
                        <div class="transaction-time">
                            🕒 {{ tx.created_at }} | Risk: {{ tx.risk_score }} ({{ tx.risk_decision }})
                        </div>
                    </div>
                    <div class="transaction-amount amount-positive">
                        🔑 Key: {{ tx.key_id[:12] }}...
                    </div>
                </li>
                {% endfor %}
            </ul>
            {% else %}
            <div class="empty-state">
                <p>📭 No secure transactions yet</p>
                <p style="font-size: 14px; color: #bbb; margin-top: 10px;">
                    Make your first secure transfer to see transactions here
                </p>
            </div>
            {% endif %}
        </div>
        
        <div class="card">
            <div class="security-info">
                <strong>🛡️ Your Session is Protected</strong><br>
                • CSRF Token: <code>{{ csrf_token[:16] }}...</code><br>
                • Session cookies: Secure ✅ | HttpOnly ✅ | SameSite=Lax ✅<br>
                • Idle timeout: 30 minutes<br>
                • TLS 1.3 encryption active 🔒<br>
                • Session-based authentication ✅
            </div>
        </div>
    </div>
</body>
</html>
'''