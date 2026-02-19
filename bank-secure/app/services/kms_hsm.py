"""
KMS/HSM service facade.

Responsibilities:
- Maintain server RSA key pair used for session-key encapsulation.
- Expose public key metadata to clients.
- Unwrap (decrypt) AES session keys in-memory only.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


KEY_DIR = Path(__file__).resolve().parent.parent / "keys"
PRIVATE_KEY_PATH = KEY_DIR / "hybrid_rsa_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "hybrid_rsa_public.pem"


@dataclass(frozen=True)
class PublicKeyEnvelope:
    key_id: str
    algorithm: str
    key_size: int
    public_key_pem: str


class KMSHSMService:
    """Minimal demo KMS/HSM abstraction for key encapsulation."""

    def __init__(self) -> None:
        self._private_key = self._load_or_create_private_key()
        self._public_key = self._private_key.public_key()
        self._key_id = self._derive_key_id()

    def _load_or_create_private_key(self):
        KEY_DIR.mkdir(parents=True, exist_ok=True)

        if PRIVATE_KEY_PATH.exists():
            key_bytes = PRIVATE_KEY_PATH.read_bytes()
            return serialization.load_pem_private_key(key_bytes, password=None)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        PRIVATE_KEY_PATH.write_bytes(private_pem)
        PUBLIC_KEY_PATH.write_bytes(public_pem)

        return private_key

    def _derive_key_id(self) -> str:
        public_der = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.sha256(public_der).hexdigest()
        return digest[:16]

    def get_public_key(self) -> PublicKeyEnvelope:
        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        return PublicKeyEnvelope(
            key_id=self._key_id,
            algorithm="RSA-OAEP-SHA256",
            key_size=self._public_key.key_size,
            public_key_pem=public_pem,
        )

    def unwrap_dek(self, encrypted_key_b64: str, key_id: str) -> bytes:
        if key_id != self._key_id:
            raise ValueError("Unknown key_id")

        encrypted_key = base64.b64decode(encrypted_key_b64, validate=True)
        dek = self._private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        if len(dek) != 32:
            raise ValueError("Invalid DEK length (expected 32 bytes)")

        return dek


_kms_service = KMSHSMService()


def get_kms_service() -> KMSHSMService:
    return _kms_service

