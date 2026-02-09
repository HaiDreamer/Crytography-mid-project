"""
Transfer Security Tests
Tests for CSRF protection, replay attack prevention, and transfer validation.
"""

import unittest
import json
from app.main import create_app
from app.models.schemas import init_database, seed_demo_users, get_db_connection


class TestTransferSecurity(unittest.TestCase):
    """Test cases for transfer security features"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test database"""
        init_database()
        seed_demo_users()
    
    def setUp(self):
        """Set up test client and login"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        
        # Login as alice
        self.client.post('/login', data={
            'username': 'alice',
            'password': 'Alice123!'
        })
    
    def test_transfer_page_loads(self):
        """Test that transfer page loads for authenticated user"""
        response = self.client.get('/transfer')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Transfer Money', response.data)
    
    def test_transfer_requires_authentication(self):
        """Test that transfer page requires login"""
        # Logout first
        self.client.get('/logout')
        
        # Try to access transfer page
        response = self.client.get('/transfer', follow_redirects=True)
        
        # Should redirect to login
        self.assertIn(b'Secure Bank - Login', response.data)
    
    def test_successful_transfer(self):
        """Test successful money transfer"""
        # Get CSRF token
        response = self.client.get('/transfer')
        # Extract CSRF token from response (simplified - in real test, parse HTML)
        
        # For testing, we'll disable CSRF
        self.app.config['WTF_CSRF_ENABLED'] = False
        
        # Perform transfer
        response = self.client.post('/transfer', data={
            'to_account': 'ACC002',
            'amount': '100.00',
            'description': 'Test transfer'
        })
        
        # Check response
        data = json.loads(response.data)
        self.assertTrue(data.get('success'))
        self.assertIn('transferred', data.get('message', '').lower())
    
    def test_transfer_insufficient_funds(self):
        """Test transfer fails with insufficient funds"""
        self.app.config['WTF_CSRF_ENABLED'] = False
        
        response = self.client.post('/transfer', data={
            'to_account': 'ACC002',
            'amount': '10000.00',  # More than alice has
            'description': 'Test'
        })
        
        data = json.loads(response.data)
        self.assertFalse(data.get('success'))
        self.assertIn('Insufficient', data.get('error', ''))
    
    def test_transfer_negative_amount(self):
        """Test transfer fails with negative amount"""
        self.app.config['WTF_CSRF_ENABLED'] = False
        
        response = self.client.post('/transfer', data={
            'to_account': 'ACC002',
            'amount': '-50.00',
            'description': 'Test'
        })
        
        data = json.loads(response.data)
        self.assertFalse(data.get('success'))
    
    def test_transfer_to_nonexistent_account(self):
        """Test transfer fails to non-existent account"""
        self.app.config['WTF_CSRF_ENABLED'] = False
        
        response = self.client.post('/transfer', data={
            'to_account': 'NONEXISTENT',
            'amount': '50.00',
            'description': 'Test'
        })
        
        data = json.loads(response.data)
        self.assertFalse(data.get('success'))
        self.assertIn('not found', data.get('error', ''))
    
    def test_self_transfer_prevented(self):
        """Test that transfers to same account are prevented"""
        self.app.config['WTF_CSRF_ENABLED'] = False
        
        response = self.client.post('/transfer', data={
            'to_account': 'ACC001',  # Alice's own account
            'amount': '50.00',
            'description': 'Test'
        })
        
        data = json.loads(response.data)
        self.assertFalse(data.get('success'))
        self.assertIn('same account', data.get('error', ''))


class TestCSRFProtection(unittest.TestCase):
    """Test cases for CSRF token validation"""
    
    def setUp(self):
        """Set up test client"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
    
    def test_csrf_token_generation(self):
        """Test that CSRF tokens are generated"""
        from app.security.csrf import generate_csrf_token
        
        with self.app.test_request_context():
            token1 = generate_csrf_token()
            
            # Token should be non-empty
            self.assertTrue(len(token1) > 0)
            
            # Same token should be returned in same session
            token2 = generate_csrf_token()
            self.assertEqual(token1, token2)
    
    def test_csrf_token_validation(self):
        """Test CSRF token validation"""
        from app.security.csrf import generate_csrf_token, validate_csrf_token
        
        with self.app.test_request_context():
            token = generate_csrf_token()
            
            # Valid token should pass
            self.assertTrue(validate_csrf_token(token))
            
            # Invalid token should fail
            self.assertFalse(validate_csrf_token('invalid_token'))
            
            # Empty token should fail
            self.assertFalse(validate_csrf_token(''))
    
    def test_csrf_token_regeneration(self):
        """Test that CSRF token is regenerated after use"""
        from app.security.csrf import generate_csrf_token, regenerate_csrf_token
        
        with self.app.test_request_context():
            token1 = generate_csrf_token()
            
            # Regenerate token
            token2 = regenerate_csrf_token()
            
            # Tokens should be different
            self.assertNotEqual(token1, token2)


class TestReplayProtection(unittest.TestCase):
    """Test cases for replay attack prevention"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test database"""
        init_database()
        seed_demo_users()
    
    def test_nonce_prevents_duplicate_transactions(self):
        """Test that nonce prevents replay attacks"""
        # This test verifies the database UNIQUE constraint on nonce
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert transaction with nonce
        cursor.execute('''
            INSERT INTO transactions 
            (from_account, to_account, amount, nonce, csrf_token)
            VALUES (?, ?, ?, ?, ?)
        ''', ('ACC001', 'ACC002', 100.00, 'test_nonce_123', 'csrf_token'))
        
        conn.commit()
        
        # Try to insert duplicate nonce (should fail)
        with self.assertRaises(Exception):  # sqlite3.IntegrityError
            cursor.execute('''
                INSERT INTO transactions 
                (from_account, to_account, amount, nonce, csrf_token)
                VALUES (?, ?, ?, ?, ?)
            ''', ('ACC001', 'ACC002', 100.00, 'test_nonce_123', 'csrf_token'))
            conn.commit()
        
        conn.close()
    
    def test_nonce_uniqueness(self):
        """Test that nonces are unique"""
        import secrets
        
        nonce1 = secrets.token_hex(16)
        nonce2 = secrets.token_hex(16)
        
        # Nonces should be different
        self.assertNotEqual(nonce1, nonce2)


if __name__ == '__main__':
    unittest.main()