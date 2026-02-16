"""
Session Management Module
Handles secure session creation, validation, and timeout management.
"""

from datetime import datetime, timedelta
import secrets
from flask import session
from functools import wraps


# Session configuration constants
SESSION_TIMEOUT_MINUTES = 30  # Idle timeout
SESSION_ABSOLUTE_TIMEOUT_HOURS = 8  # Absolute timeout
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300  # 5 minutes


# In-memory rate limiting (in production, use Redis)
login_attempts = {}


def configure_session(app):
    """
    Configure Flask session with security settings.
    
    Args:
        app: Flask application instance
        
    Security Settings:
        - SESSION_COOKIE_SECURE: Only send over HTTPS
        - SESSION_COOKIE_HTTPONLY: Prevent JavaScript access (XSS protection)
        - SESSION_COOKIE_SAMESITE: CSRF protection
        - PERMANENT_SESSION_LIFETIME: Session timeout
    """
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    )


def create_session(user_id: int, username: str):
    """
    Create a new authenticated session.
    
    Args:
        user_id: Database user ID
        username: Username
        
    Security:
        - Clears any existing session first (prevents session fixation)
        - Sets session as permanent (enables timeout)
        - Records creation time for absolute timeout check
    """
    # Clear existing session to prevent fixation attacks
    session.clear()
    
    # Create new session
    session['user_id'] = user_id
    session['username'] = username
    session['session_id'] = secrets.token_hex(16)
    session['created_at'] = datetime.now().isoformat()
    session['last_activity'] = datetime.now().isoformat()
    session.permanent = True


def validate_session() -> tuple[bool, str]:
    """
    Validate current session and check timeouts.
    
    Returns:
        Tuple of (is_valid, error_message)
        
    Checks:
        1. User is logged in (user_id exists)
        2. Idle timeout (last_activity within limit)
        3. Absolute timeout (session age within limit)
    """
    # Check if user is logged in
    if 'user_id' not in session:
        return False, "Not authenticated"
    
    # Check idle timeout
    if 'last_activity' in session:
        last_activity = datetime.fromisoformat(session['last_activity'])
        idle_time = (datetime.now() - last_activity).total_seconds()
        
        if idle_time > SESSION_TIMEOUT_MINUTES * 60:
            _revoke_session_key()
            session.clear()
            return False, "Session expired due to inactivity"
    
    # Check absolute timeout
    if 'created_at' in session:
        created_at = datetime.fromisoformat(session['created_at'])
        session_age = (datetime.now() - created_at).total_seconds()
        
        if session_age > SESSION_ABSOLUTE_TIMEOUT_HOURS * 3600:
            _revoke_session_key()
            session.clear()
            return False, "Session expired (maximum duration reached)"
    
    # Update last activity
    session['last_activity'] = datetime.now().isoformat()
    
    return True, ""


def login_required(f):
    """
    Decorator to protect routes that require authentication.
    
    Usage:
        @app.route('/dashboard')
        @login_required
        def dashboard():
            # Your code here
    
    Security:
        - Validates session on every request
        - Checks idle and absolute timeouts
        - Redirects to login if session invalid
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import redirect, url_for
        
        is_valid, error = validate_session()
        
        if not is_valid:
            # Session invalid - redirect to login
            return redirect(url_for('auth.login', error=error))
        
        return f(*args, **kwargs)
    
    return decorated_function


def check_rate_limit(username: str) -> tuple[bool, str]:
    """
    Check if user has exceeded login attempt rate limit.
    
    Args:
        username: Username attempting to login
        
    Returns:
        Tuple of (is_allowed, error_message)
        
    Security:
        - Prevents brute force attacks
        - Max 5 attempts per 5 minutes per username
        - Lockout duration: 5 minutes
    """
    now = datetime.now()
    
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        
        # Check if lockout period has passed
        time_since_last = (now - last_attempt).total_seconds()
        if time_since_last > LOCKOUT_DURATION_SECONDS:
            # Reset counter
            login_attempts[username] = (1, now)
            return True, ""
        
        # Check if locked out
        if attempts >= MAX_LOGIN_ATTEMPTS:
            remaining = LOCKOUT_DURATION_SECONDS - time_since_last
            return False, f"Too many login attempts. Try again in {int(remaining)} seconds."
        
        # Increment attempts
        login_attempts[username] = (attempts + 1, now)
        return True, ""
    else:
        # First attempt
        login_attempts[username] = (1, now)
        return True, ""


def reset_rate_limit(username: str):
    """
    Reset rate limiting for a user (call after successful login).
    
    Args:
        username: Username to reset
    """
    if username in login_attempts:
        del login_attempts[username]


def destroy_session():
    """
    Securely destroy current session (logout).
    
    Security:
        - Clears all session data
        - Invalidates session cookie
    """
    _revoke_session_key()
    session.clear()


def get_current_user() -> dict:
    """
    Get current authenticated user information from session.
    
    Returns:
        Dictionary with user_id and username, or None if not authenticated
    """
    if 'user_id' in session:
        return {
            'user_id': session['user_id'],
            'username': session['username']
        }
    return None


def _revoke_session_key() -> None:
    session_id = session.get('session_id')
    if not session_id:
        return

    from app.services.secure_session_keys import get_secure_session_key_store
    get_secure_session_key_store().revoke(session_id)
