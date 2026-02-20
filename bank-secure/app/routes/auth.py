"""
Authentication Routes
Handles login, logout, and authentication-related endpoints.
Fully simplified version with minimal dependencies.
"""

from functools import wraps
from flask import Blueprint, render_template_string, request, redirect, url_for, session, jsonify
from datetime import datetime, timedelta

from app.security.csrf import generate_csrf_token
from app.security.passwords import verify_password
from app.models.schemas import get_user_by_username, update_last_login, log_session_event


auth_bp = Blueprint('auth', __name__)


# ============================================================================
# SESSION AND RATE LIMITING HELPERS
# ============================================================================

# In-memory rate limiting storage (replace with Redis/database in production)
_rate_limit_store = {}

def check_rate_limit(username, max_attempts=5, window_minutes=5):
    """
    Check if user has exceeded rate limit.
    
    Returns: (is_allowed: bool, error_message: str or None)
    """
    now = datetime.now()
    
    if username not in _rate_limit_store:
        _rate_limit_store[username] = {
            'attempts': 0,
            'window_start': now
        }
    
    user_data = _rate_limit_store[username]
    
    # Check if window has expired
    if now - user_data['window_start'] > timedelta(minutes=window_minutes):
        # Reset window
        user_data['attempts'] = 0
        user_data['window_start'] = now
    
    # Check if exceeded limit
    if user_data['attempts'] >= max_attempts:
        time_remaining = window_minutes - (now - user_data['window_start']).seconds // 60
        return False, f"Too many login attempts. Try again in {time_remaining} minutes."
    
    # Increment attempts
    user_data['attempts'] += 1
    
    return True, None


def reset_rate_limit(username):
    """Reset rate limit for a user after successful login."""
    if username in _rate_limit_store:
        del _rate_limit_store[username]


def create_session(user_id, username):
    """
    Create a new session for authenticated user.
    Stores user info in Flask session.
    """
    # Clear any existing session data
    session.clear()
    
    # Set new session data
    session['user_id'] = user_id
    session['username'] = username
    session['logged_in'] = True
    session['login_time'] = datetime.now().isoformat()
    
    # Regenerate session ID to prevent session fixation
    session.modified = True


def destroy_session():
    """
    Destroy the current session.
    Clears all session data.
    """
    session.clear()


def get_current_user():
    """
    Get current authenticated user from session.
    
    Returns: dict with user info or None
    """
    if 'user_id' not in session:
        return None
    
    return {
        'user_id': session.get('user_id'),
        'username': session.get('username'),
        'id': session.get('user_id'),  # Alias for compatibility
    }


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


# ============================================================================
# ROUTES
# ============================================================================

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login endpoint with rate limiting and secure authentication.
    
    GET: Display login form
    POST: Process login credentials
    
    Security:
        - Rate limiting (5 attempts per 5 minutes)
        - Bcrypt password verification (constant-time comparison)
        - Session regeneration on successful login (prevents fixation)
        - CSRF token for form
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Basic validation
        if not username or not password:
            return render_template_string(
                LOGIN_TEMPLATE,
                error='Username and password are required',
                csrf_token=generate_csrf_token()
            )
        
        # Check rate limiting
        is_allowed, error_msg = check_rate_limit(username)
        if not is_allowed:
            return render_template_string(
                LOGIN_TEMPLATE,
                error=error_msg,
                csrf_token=generate_csrf_token()
            )
        
        # Get user from database
        user = get_user_by_username(username)
        
        if not user:
            return render_template_string(
                LOGIN_TEMPLATE,
                error='Invalid username or password',
                csrf_token=generate_csrf_token()
            )
        
        # Check if account is locked
        if user.get('account_locked', False):
            return render_template_string(
                LOGIN_TEMPLATE,
                error='Account is locked. Contact administrator.',
                csrf_token=generate_csrf_token()
            )
        
        # Verify password using bcrypt
        if verify_password(password, user['password_hash']):
            # Successful login
            create_session(user['id'], user['username'])
            update_last_login(user['id'])
            reset_rate_limit(username)
            
            # Log successful login
            try:
                log_session_event(
                    user['id'],
                    'login_success',
                    request.remote_addr,
                    request.user_agent.string
                )
            except Exception as e:
                # Don't fail login if logging fails
                print(f"Failed to log session event: {e}")
            
            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):  # Security: prevent open redirect
                return redirect(next_page)
            return redirect(url_for('account.dashboard'))
        else:
            # Failed login
            try:
                log_session_event(
                    user['id'],
                    'login_failure',
                    request.remote_addr,
                    request.user_agent.string
                )
            except Exception as e:
                print(f"Failed to log session event: {e}")
            
            return render_template_string(
                LOGIN_TEMPLATE,
                error='Invalid username or password',
                csrf_token=generate_csrf_token()
            )
    
    # GET request - show login form
    return render_template_string(
        LOGIN_TEMPLATE,
        error=request.args.get('error'),
        csrf_token=generate_csrf_token()
    )


@auth_bp.route('/logout')
@login_required
def logout():
    """
    Logout endpoint - destroys session.
    
    Security:
        - Clears all session data
        - Invalidates session cookie
    """
    user = get_current_user()
    if user:
        try:
            log_session_event(
                user.get('user_id') or user.get('id'),
                'logout',
                request.remote_addr,
                request.user_agent.string
            )
        except Exception as e:
            print(f"Failed to log session event: {e}")
    
    destroy_session()
    return redirect(url_for('auth.login'))


# ============================================================================
# HTML TEMPLATE
# ============================================================================

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Secure Bank - Login</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 420px;
            width: 100%;
            padding: 40px;
        }
        .lock-icon {
            font-size: 64px;
            text-align: center;
            margin-bottom: 20px;
        }
        .lock-icon::before {
            content: "🔒";
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .security-badge {
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin-bottom: 25px;
            border-radius: 4px;
        }
        .security-badge strong {
            display: block;
            color: #1976D2;
            margin-bottom: 8px;
        }
        .security-badge ul {
            list-style: none;
            font-size: 13px;
            color: #555;
        }
        .security-badge li {
            padding: 3px 0;
        }
        .security-badge li:before {
            content: "✓ ";
            color: #4CAF50;
            font-weight: bold;
        }
        .error {
            background: #ffebee;
            border-left: 4px solid #f44336;
            color: #c62828;
            padding: 12px;
            margin-bottom: 20px;
            border-radius: 4px;
            font-size: 14px;
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
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 15px;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        button:active {
            transform: translateY(0);
        }
        .demo-accounts {
            background: #fff9c4;
            border-left: 4px solid #fbc02d;
            padding: 15px;
            margin-top: 25px;
            border-radius: 4px;
            font-size: 13px;
        }
        .demo-accounts strong {
            display: block;
            color: #f57f17;
            margin-bottom: 8px;
        }
        .demo-accounts code {
            background: #fff;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        .footer-link {
            text-align: center;
            margin-top: 20px;
        }
        .footer-link a {
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
        }
        .footer-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="lock-icon"></div>
        <h1>🏦 Secure Bank</h1>
        <p class="subtitle">Login to your account</p>
        
        <div class="security-badge">
            <strong>🔐 Security Features Active</strong>
            <ul>
                <li>Session-based authentication</li>
                <li>Bcrypt password hashing</li>
                <li>Rate limiting (5 attempts/5min)</li>
                <li>Session fixation protection</li>
                <li>CSRF token protection</li>
            </ul>
        </div>
        
        {% if error %}
        <div class="error">⚠️ {{ error }}</div>
        {% endif %}
        
        <form method="POST" action="{{ url_for('auth.login') }}">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus autocomplete="username">
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            
            <button type="submit">🔓 Sign In Securely</button>
        </form>
        
        <div class="demo-accounts">
            <strong>📝 Demo Accounts</strong>
            <div style="margin-top: 8px;">
                <strong>User 1:</strong> <code>alice</code> / <code>Alice123!</code><br>
                <strong>User 2:</strong> <code>bob</code> / <code>Bob123!</code>
            </div>
        </div>
        
        <div class="footer-link">
            <a href="/">← Back to Home</a>
        </div>
    </div>
</body>
</html>
'''