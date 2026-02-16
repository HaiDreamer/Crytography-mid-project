"""
Crypto service for AES-256-GCM payload processing.
"""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoServiceError(Exception):
    """Raised when encrypted payload validation/decryption fails."""


class CryptoService:
    """Encrypt/decrypt sensitive fields and verify tag integrity."""

    @staticmethod
    def _b64decode(field_name: str, value: str) -> bytes:
        try:
            return base64.b64decode(value, validate=True)
        except Exception as exc:
            raise CryptoServiceError(f"Invalid base64 in field: {field_name}") from exc

    def decrypt_transfer_payload(
        self,
        dek: bytes,
        nonce_b64: str,
        aad: str,
        ciphertext_b64: str,
        auth_tag_b64: str,
    ) -> dict:
        nonce = self._b64decode("nonce", nonce_b64)
        ciphertext = self._b64decode("ciphertext", ciphertext_b64)
        auth_tag = self._b64decode("auth_tag", auth_tag_b64)

        if len(nonce) != 12:
            raise CryptoServiceError("Invalid nonce length (expected 12 bytes)")
        if len(auth_tag) != 16:
            raise CryptoServiceError("Invalid auth_tag length (expected 16 bytes)")
        if len(dek) != 32:
            raise CryptoServiceError("Invalid DEK length (expected 32 bytes)")

        aead_ciphertext = ciphertext + auth_tag

        try:
            plaintext = AESGCM(dek).decrypt(
                nonce=nonce,
                data=aead_ciphertext,
                associated_data=aad.encode("utf-8"),
            )
        except Exception as exc:
            raise CryptoServiceError("Tag verification failed") from exc

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise CryptoServiceError("Payload is not valid JSON") from exc

        if not isinstance(payload, dict):
            raise CryptoServiceError("Payload must be a JSON object")

        return payload


_crypto_service = CryptoService()


def get_crypto_service() -> CryptoService:
    return _crypto_service

