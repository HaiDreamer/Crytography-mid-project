"""
Password Security Module
Handles secure password hashing and verification using bcrypt.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash a password using bcrypt with automatic salt generation.
    
    Args:
        password: Plain text password
        
    Returns:
        Bcrypt hash as bytes
        
    Security:
        - Uses bcrypt with cost factor 12 (2^12 = 4096 iterations)
        - Automatically generates unique salt per password
        - Resistant to rainbow table attacks
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def verify_password(password: str, password_hash: bytes) -> bool:
    """
    Verify a password against a bcrypt hash.
    
    Args:
        password: Plain text password to verify
        password_hash: Stored bcrypt hash
        
    Returns:
        True if password matches, False otherwise
        
    Security:
        - Uses constant-time comparison (prevents timing attacks)
        - bcrypt.checkpw() handles salt extraction automatically
    """
    return bcrypt.checkpw(password.encode('utf-8'), password_hash)


def is_strong_password(password: str) -> tuple[bool, str]:
    """
    Check if password meets security requirements.
    
    Requirements:
        - Minimum 8 characters
        - Contains uppercase letter
        - Contains lowercase letter
        - Contains digit
        - Contains special character
        
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain an uppercase letter"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain a lowercase letter"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain a digit"
    
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        return False, "Password must contain a special character"
    
    return True, ""