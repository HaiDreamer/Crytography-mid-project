"""
Authentication Routes
Handles login, logout, and authentication-related endpoints.
"""

from flask import Blueprint, render_template_string, request, redirect, url_for
from app.security.sessions import (
    create_session, destroy_session, check_rate_limit, 
    reset_rate_limit, login_required
)
from app.security.csrf import generate_csrf_token
from app.security.passwords import verify_password
from app.models.schemas import get_user_by_username, update_last_login, log_session_event


auth_bp = Blueprint('auth', __name__)

# GET: take user input (handle error) 
# POST: rate limiting, read username and password, handle error case, account lock check, password verification
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
        if user['account_locked']:
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
            log_session_event(
                user['id'],
                'login_success',
                request.remote_addr,
                request.user_agent.string
            )
            
            return redirect(url_for('account.dashboard'))
        else:
            # Failed login
            log_session_event(
                user['id'],
                'login_failure',
                request.remote_addr,
                request.user_agent.string
            )
            
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
    from app.security.sessions import get_current_user
    
    user = get_current_user()
    if user:
        log_session_event(
            user['user_id'],
            'logout',
            request.remote_addr,
            request.user_agent.string
        )
    
    destroy_session()
    return redirect(url_for('auth.login'))


# HTML Template for login page
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
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
        <h1>Secure Bank</h1>
        <p class="subtitle">Login to your account</p>
        
        <div class="security-badge">
            <strong>Security Features Active</strong>
            <ul>
                <li>TLS 1.3 Encryption</li>
                <li>Bcrypt Password Hashing</li>
                <li>Rate Limiting (5 attempts/5min)</li>
                <li>Session Timeout Protection</li>
            </ul>
        </div>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            
            <button type="submit">Sign In</button>
        </form>
        
        <div class="demo-accounts">
            <strong>Demo Accounts</strong>
            Username: <code>alice</code> | Password: <code>Alice123!</code><br>
            Username: <code>bob</code> | Password: <code>Bob123!</code>
        </div>
        
        <div class="footer-link">
            <a href="{{ url_for('index') }}">View Security Configuration</a>
        </div>
    </div>
</body>
</html>
'''