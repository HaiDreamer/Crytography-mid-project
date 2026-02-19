"""
CSRF Protection Module
Implements Cross-Site Request Forgery protection using secure tokens.
"""

import secrets
from flask import session
from functools import wraps


def generate_csrf_token() -> str:
    """
    Generate a cryptographically secure CSRF token.
    
    Returns:
        256-bit random token as hex string
        
    Security:
        - Uses secrets.token_hex() which calls OS's CSPRNG
        - 256 bits of entropy (2^256 possible values)
        - Stored in server-side session
    """
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)  # 32 bytes = 256 bits
    return session['csrf_token']


def validate_csrf_token(submitted_token: str) -> bool:
    """
    Validate submitted CSRF token against session token.
    
    Args:
        submitted_token: Token from form/request
        
    Returns:
        True if valid, False otherwise
        
    Security:
        - Prevents cross-site request forgery attacks
        - Token must match session-stored value exactly
    """
    session_token = session.get('csrf_token')
    
    if not session_token or not submitted_token:
        return False
    
    # Use constant-time comparison to prevent timing attacks
    return secrets.compare_digest(session_token, submitted_token)


def csrf_protect(f):
    """
    Decorator to require CSRF token validation on POST requests.
    
    Usage:
        @app.route('/transfer', methods=['POST'])
        @csrf_protect
        def transfer():
            # Your code here
            
    Security:
        - Automatically validates CSRF token on POST/PUT/DELETE
        - Returns 403 Forbidden if token is invalid
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import request, jsonify, current_app

        if current_app.config.get('WTF_CSRF_ENABLED') is False:
            return f(*args, **kwargs)
        
        if request.method in ['POST', 'PUT', 'DELETE']:
            json_payload = request.get_json(silent=True) or {}
            token = request.form.get('csrf_token') or json_payload.get('csrf_token')
            
            if not validate_csrf_token(token):
                return jsonify({'error': 'Invalid CSRF token'}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


def regenerate_csrf_token():
    """
    Generate a new CSRF token (call after successful form submission).
    
    Security:
        - Prevents token reuse attacks
        - Should be called after state-changing operations
    """
    session.pop('csrf_token', None)
    return generate_csrf_token()
