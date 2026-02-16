"""
Transfer Security Tests
Strict flow: Hybrid RSA + AES-GCM only.
"""

import base64
import json
import os
import re
import sqlite3
import unittest
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.main import create_app
from app.models.schemas import get_db_connection, init_database, seed_demo_users


class TestTransferSecurity(unittest.TestCase):
    """Test cases for transfer security features in strict encrypted mode."""

    @classmethod
    def setUpClass(cls):
        init_database()
        seed_demo_users()

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.client.post("/login", data={"username": "alice", "password": "Alice123!"})

        transfer_page = self.client.get("/transfer")
        self.assertEqual(transfer_page.status_code, 200)
        self.csrf_token = self._extract_csrf_token(transfer_page.data.decode("utf-8"))

        self.key_id, self.aes_key = self._establish_secure_channel(self.csrf_token)

    @staticmethod
    def _extract_csrf_token(html: str) -> str:
        match = re.search(r'id="csrf_token"\s+name="csrf_token"\s+value="([^"]+)"', html)
        if not match:
            raise AssertionError("CSRF token not found in transfer page")
        return match.group(1)

    def _establish_secure_channel(self, csrf_token: str) -> tuple[str, bytes]:
        key_resp = self.client.get("/crypto/public-key")
        self.assertEqual(key_resp.status_code, 200)
        key_data = key_resp.get_json()

        key_id = key_data["key_id"]
        public_key = serialization.load_pem_public_key(
            key_data["public_key_pem"].encode("utf-8")
        )

        aes_key = os.urandom(32)
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        kex_resp = self.client.post(
            "/crypto/session-key",
            json={
                "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
                "key_id": key_id,
                "csrf_token": csrf_token,
            },
        )
        self.assertEqual(kex_resp.status_code, 200)
        self.assertTrue(kex_resp.get_json().get("success"))

        return key_id, aes_key

    def _build_encrypted_transfer(
        self,
        *,
        to_account: str,
        amount: float,
        description: str,
        tamper_tag: bool = False,
    ) -> dict:
        plaintext_payload = {
            "to_account": to_account,
            "amount": amount,
            "description": description,
        }

        aad = json.dumps(
            {
                "txid": f"test-{uuid.uuid4().hex}",
                "actor": "customer",
                "channel": "test",
            }
        )
        nonce = os.urandom(12)
        encrypted = AESGCM(self.aes_key).encrypt(
            nonce,
            json.dumps(plaintext_payload).encode("utf-8"),
            aad.encode("utf-8"),
        )

        ciphertext = encrypted[:-16]
        auth_tag = bytearray(encrypted[-16:])
        if tamper_tag:
            auth_tag[0] ^= 0x01

        return {
            "key_id": self.key_id,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "aad": aad,
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "auth_tag": base64.b64encode(bytes(auth_tag)).decode("utf-8"),
            "csrf_token": self.csrf_token,
        }

    def _post_secure_transfer(self, **kwargs):
        body = self._build_encrypted_transfer(**kwargs)
        return self.client.post("/transfer", json=body)

    def test_transfer_page_loads(self):
        response = self.client.get("/transfer")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Secure Transfer", response.data)

    def test_transfer_requires_authentication(self):
        self.client.get("/logout")
        response = self.client.get("/transfer", follow_redirects=True)
        self.assertIn(b"Secure Bank - Login", response.data)

    def test_successful_transfer(self):
        response = self._post_secure_transfer(
            to_account="ACC002",
            amount=100.00,
            description="Test transfer",
        )
        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("transferred", data.get("message", "").lower())
        self.assertIn("tx_id", data)
        self.assertIn("risk_decision", data)

    def test_transfer_insufficient_funds(self):
        response = self._post_secure_transfer(
            to_account="ACC002",
            amount=10000.00,
            description="Too much",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Insufficient", response.get_json().get("error", ""))

    def test_transfer_negative_amount(self):
        response = self._post_secure_transfer(
            to_account="ACC002",
            amount=-50.00,
            description="Negative",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("positive", response.get_json().get("error", ""))

    def test_transfer_to_nonexistent_account(self):
        response = self._post_secure_transfer(
            to_account="NONEXISTENT",
            amount=50.00,
            description="No recipient",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("not found", response.get_json().get("error", ""))

    def test_self_transfer_prevented(self):
        response = self._post_secure_transfer(
            to_account="ACC001",
            amount=50.00,
            description="Self transfer",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("same account", response.get_json().get("error", ""))

    def test_tampered_tag_is_rejected(self):
        response = self._post_secure_transfer(
            to_account="ACC002",
            amount=10.00,
            description="Tamper test",
            tamper_tag=True,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Tag verification failed", response.get_json().get("error", ""))

    def test_transfer_rejects_non_json_payload(self):
        response = self.client.post(
            "/transfer",
            data={
                "to_account": "ACC002",
                "amount": "10",
                "csrf_token": self.csrf_token,
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid JSON body", response.get_json().get("error", ""))


class TestStrictFlowValidation(unittest.TestCase):
    """Validation checks specific to strict diagram flow."""

    @classmethod
    def setUpClass(cls):
        init_database()
        seed_demo_users()

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.client.post("/login", data={"username": "alice", "password": "Alice123!"})

        page = self.client.get("/transfer")
        html = page.data.decode("utf-8")
        match = re.search(r'id="csrf_token"\s+name="csrf_token"\s+value="([^"]+)"', html)
        self.assertIsNotNone(match)
        self.csrf_token = match.group(1)

    def test_transfer_requires_established_secure_channel(self):
        payload = {
            "key_id": "unknown",
            "nonce": base64.b64encode(os.urandom(12)).decode("utf-8"),
            "aad": '{"txid":"x","actor":"customer","channel":"test"}',
            "ciphertext": base64.b64encode(b"abc").decode("utf-8"),
            "auth_tag": base64.b64encode(b"0" * 16).decode("utf-8"),
            "csrf_token": self.csrf_token,
        }
        response = self.client.post("/transfer", json=payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Secure channel not established", response.get_json().get("error", ""))


class TestCSRFProtection(unittest.TestCase):
    """Test cases for CSRF token validation."""

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_csrf_token_generation(self):
        from app.security.csrf import generate_csrf_token

        with self.app.test_request_context():
            token1 = generate_csrf_token()
            self.assertTrue(len(token1) > 0)
            token2 = generate_csrf_token()
            self.assertEqual(token1, token2)

    def test_csrf_token_validation(self):
        from app.security.csrf import generate_csrf_token, validate_csrf_token

        with self.app.test_request_context():
            token = generate_csrf_token()
            self.assertTrue(validate_csrf_token(token))
            self.assertFalse(validate_csrf_token("invalid_token"))
            self.assertFalse(validate_csrf_token(""))

    def test_csrf_token_regeneration(self):
        from app.security.csrf import generate_csrf_token, regenerate_csrf_token

        with self.app.test_request_context():
            token1 = generate_csrf_token()
            token2 = regenerate_csrf_token()
            self.assertNotEqual(token1, token2)


class TestReplayProtection(unittest.TestCase):
    """Test cases for replay attack prevention."""

    @classmethod
    def setUpClass(cls):
        init_database()
        seed_demo_users()

    def test_nonce_prevents_duplicate_transactions(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        nonce = f"secure_test_nonce_{uuid.uuid4().hex}"

        try:
            cursor.execute(
                """
                INSERT INTO secure_transactions
                (actor_user_id, key_id, nonce, aad, ciphertext, auth_tag, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (1, "test-key", nonce, '{"txid":"a"}', "ciphertext", "auth-tag", "completed"),
            )
            conn.commit()

            with self.assertRaises(sqlite3.IntegrityError):
                cursor.execute(
                    """
                    INSERT INTO secure_transactions
                    (actor_user_id, key_id, nonce, aad, ciphertext, auth_tag, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (1, "test-key", nonce, '{"txid":"b"}', "ciphertext2", "auth-tag2", "completed"),
                )
                conn.commit()
        finally:
            conn.close()

    def test_nonce_uniqueness(self):
        nonce1 = uuid.uuid4().hex
        nonce2 = uuid.uuid4().hex
        self.assertNotEqual(nonce1, nonce2)


if __name__ == "__main__":
    unittest.main()
