"""
Session Management Tests
Tests for session creation, validation, and timeout.
"""

import unittest
from datetime import datetime, timedelta
from app.main import create_app
from app.security.sessions import (
    create_session, validate_session, destroy_session,
    check_rate_limit, reset_rate_limit
)
from flask import session as flask_session


class TestSessionManagement(unittest.TestCase):
    """Test cases for session management"""
    
    def setUp(self):
        """Set up test client"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
    
    def test_session_creation(self):
        """Test that session is created correctly"""
        with self.app.test_request_context():
            create_session(user_id=1, username='alice')
            
            self.assertEqual(flask_session['user_id'], 1)
            self.assertEqual(flask_session['username'], 'alice')
            self.assertIn('created_at', flask_session)
            self.assertIn('last_activity', flask_session)
    
    def test_session_validation_success(self):
        """Test successful session validation"""
        with self.app.test_request_context():
            create_session(user_id=1, username='alice')
            
            is_valid, error = validate_session()
            self.assertTrue(is_valid)
            self.assertEqual(error, "")
    
    def test_session_validation_not_authenticated(self):
        """Test session validation fails when not logged in"""
        with self.app.test_request_context():
            is_valid, error = validate_session()
            
            self.assertFalse(is_valid)
            self.assertEqual(error, "Not authenticated")
    
    def test_session_timeout_idle(self):
        """Test that session expires after idle timeout"""
        with self.app.test_request_context():
            create_session(user_id=1, username='alice')
            
            # Manually set last_activity to 31 minutes ago (past timeout)
            past_time = datetime.now() - timedelta(minutes=31)
            flask_session['last_activity'] = past_time.isoformat()
            
            is_valid, error = validate_session()
            
            self.assertFalse(is_valid)
            self.assertIn("inactivity", error)
    
    def test_session_destroy(self):
        """Test that session is properly destroyed"""
        with self.app.test_request_context():
            create_session(user_id=1, username='alice')
            
            # Verify session exists
            self.assertIn('user_id', flask_session)
            
            # Destroy session
            destroy_session()
            
            # Verify session is cleared
            self.assertNotIn('user_id', flask_session)
    
    def test_session_regeneration_prevents_fixation(self):
        """Test that session is regenerated on login"""
        with self.app.test_request_context():
            # Simulate attacker setting a session
            flask_session['attacker_data'] = 'malicious'
            
            # User logs in - should clear all previous session data
            create_session(user_id=1, username='alice')
            
            # Attacker's data should be gone
            self.assertNotIn('attacker_data', flask_session)
            
            # Only legitimate session data should exist
            self.assertEqual(flask_session['user_id'], 1)


class TestRateLimiting(unittest.TestCase):
    """Test cases for rate limiting"""
    
    def setUp(self):
        """Clear rate limiting state before each test"""
        from app.security.sessions import login_attempts
        login_attempts.clear()
    
    def test_rate_limit_allows_initial_attempts(self):
        """Test that first attempts are allowed"""
        is_allowed, error = check_rate_limit('testuser')
        
        self.assertTrue(is_allowed)
        self.assertEqual(error, "")
    
    def test_rate_limit_blocks_after_max_attempts(self):
        """Test that user is blocked after max attempts"""
        # Make 5 attempts
        for i in range(5):
            check_rate_limit('testuser')
        
        # 6th attempt should be blocked
        is_allowed, error = check_rate_limit('testuser')
        
        self.assertFalse(is_allowed)
        self.assertIn("Too many", error)
    
    def test_rate_limit_reset_after_successful_login(self):
        """Test that rate limit is reset after successful login"""
        # Make several failed attempts
        for i in range(3):
            check_rate_limit('testuser')
        
        # Simulate successful login
        reset_rate_limit('testuser')
        
        # Should be able to try again
        is_allowed, error = check_rate_limit('testuser')
        self.assertTrue(is_allowed)


class TestSessionCookieSettings(unittest.TestCase):
    """Test cases for secure cookie configuration"""
    
    def test_session_cookie_secure_flag(self):
        """Test that SESSION_COOKIE_SECURE is enabled"""
        app = create_app()
        self.assertTrue(app.config['SESSION_COOKIE_SECURE'])
    
    def test_session_cookie_httponly_flag(self):
        """Test that SESSION_COOKIE_HTTPONLY is enabled"""
        app = create_app()
        self.assertTrue(app.config['SESSION_COOKIE_HTTPONLY'])
    
    def test_session_cookie_samesite_setting(self):
        """Test that SESSION_COOKIE_SAMESITE is set to Lax"""
        app = create_app()
        self.assertEqual(app.config['SESSION_COOKIE_SAMESITE'], 'Lax')
    
    def test_session_lifetime_configured(self):
        """Test that session lifetime is configured"""
        app = create_app()
        self.assertIn('PERMANENT_SESSION_LIFETIME', app.config)
        
        # Should be 30 minutes
        lifetime_seconds = app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()
        self.assertEqual(lifetime_seconds, 30 * 60)


if __name__ == '__main__':
    unittest.main()