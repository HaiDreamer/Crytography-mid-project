"""
Authentication Tests
Tests for login, logout, and rate limiting functionality.
"""

import unittest
from app.main import create_app
from app.models.schemas import init_database, seed_demo_users, get_db_connection
from app.security.sessions import login_attempts


class TestAuthentication(unittest.TestCase):
    """Test cases for authentication functionality"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test database once for all tests"""
        init_database()
        seed_demo_users()
    
    def setUp(self):
        """Set up test client for each test"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
        self.client = self.app.test_client()
        
        # Clear rate limiting between tests
        login_attempts.clear()
    
    def test_login_page_loads(self):
        """Test that login page loads successfully"""
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Secure Bank', response.data)
    
    def test_successful_login(self):
        """Test successful login with valid credentials"""
        response = self.client.post('/login', data={
            'username': 'alice',
            'password': 'Alice123!'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome', response.data)
    
    def test_failed_login_wrong_password(self):
        """Test login failure with wrong password"""
        response = self.client.post('/login', data={
            'username': 'alice',
            'password': 'wrongpassword'
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid username or password', response.data)
    
    def test_failed_login_nonexistent_user(self):
        """Test login failure with non-existent username"""
        response = self.client.post('/login', data={
            'username': 'nonexistent',
            'password': 'password123'
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid username or password', response.data)
    
    def test_rate_limiting(self):
        """Test that rate limiting kicks in after 5 failed attempts"""
        # Attempt 5 failed logins
        for i in range(5):
            self.client.post('/login', data={
                'username': 'alice',
                'password': 'wrongpassword'
            })
        
        # 6th attempt should be blocked
        response = self.client.post('/login', data={
            'username': 'alice',
            'password': 'wrongpassword'
        })
        
        self.assertIn(b'Too many login attempts', response.data)
    
    def test_logout(self):
        """Test logout functionality"""
        # First login
        self.client.post('/login', data={
            'username': 'alice',
            'password': 'Alice123!'
        })
        
        # Then logout
        response = self.client.get('/logout', follow_redirects=True)
        
        # Should redirect to login page
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Secure Bank - Login', response.data)
    
    def test_protected_route_without_login(self):
        """Test that protected routes redirect when not logged in"""
        response = self.client.get('/dashboard', follow_redirects=True)
        
        # Should redirect to login
        self.assertIn(b'Secure Bank - Login', response.data)
    
    def test_session_creation_on_login(self):
        """Test that session is created on successful login"""
        with self.client:
            self.client.post('/login', data={
                'username': 'alice',
                'password': 'Alice123!'
            })
            
            # Check session
            from flask import session
            self.assertIn('user_id', session)
            self.assertEqual(session['username'], 'alice')


class TestPasswordSecurity(unittest.TestCase):
    """Test cases for password hashing and verification"""
    
    def test_password_hashing(self):
        """Test that passwords are hashed correctly"""
        from app.security.passwords import hash_password, verify_password
        
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        # Verify it's actually hashed (not plaintext)
        self.assertNotEqual(password.encode(), hashed)
        
        # Verify correct password validates
        self.assertTrue(verify_password(password, hashed))
        
        # Verify wrong password doesn't validate
        self.assertFalse(verify_password("WrongPassword", hashed))
    
    def test_unique_salts(self):
        """Test that same password generates different hashes (unique salts)"""
        from app.security.passwords import hash_password
        
        password = "SamePassword123!"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        # Hashes should be different due to unique salts
        self.assertNotEqual(hash1, hash2)
    
    def test_password_strength_validation(self):
        """Test password strength requirements"""
        from app.security.passwords import is_strong_password
        
        # Valid password
        is_valid, _ = is_strong_password("StrongPass123!")
        self.assertTrue(is_valid)
        
        # Too short
        is_valid, msg = is_strong_password("Sh0rt!")
        self.assertFalse(is_valid)
        self.assertIn("8 characters", msg)
        
        # No uppercase
        is_valid, msg = is_strong_password("lowercase123!")
        self.assertFalse(is_valid)
        self.assertIn("uppercase", msg)
        
        # No digit
        is_valid, msg = is_strong_password("NoDigitPass!")
        self.assertFalse(is_valid)
        self.assertIn("digit", msg)


if __name__ == '__main__':
    unittest.main()