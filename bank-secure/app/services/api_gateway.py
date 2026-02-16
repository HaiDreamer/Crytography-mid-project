"""
API Gateway / WAF style request validation for secure transfer endpoints.
"""

from __future__ import annotations

import base64


REQUIRED_TRANSFER_FIELDS = (
    "key_id",
    "nonce",
    "aad",
    "ciphertext",
    "auth_tag",
)


def _is_valid_base64(value: str) -> bool:
    try:
        base64.b64decode(value, validate=True)
        return True
    except Exception:
        return False


def validate_secure_transfer_request(payload: dict) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, "Invalid JSON body"

    for field in REQUIRED_TRANSFER_FIELDS:
        if field not in payload:
            return False, f"Missing field: {field}"
        if not isinstance(payload[field], str) or not payload[field].strip():
            return False, f"Invalid field: {field}"

    if len(payload["aad"]) > 4096:
        return False, "AAD too large"

    for b64_field in ("nonce", "ciphertext", "auth_tag"):
        if not _is_valid_base64(payload[b64_field]):
            return False, f"Invalid base64 field: {b64_field}"

    if len(payload["ciphertext"]) > 16384:
        return False, "Ciphertext too large"

    return True, ""


def validate_key_exchange_request(payload: dict) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, "Invalid JSON body"

    encrypted_key = payload.get("encrypted_key")
    key_id = payload.get("key_id")

    if not isinstance(encrypted_key, str) or not encrypted_key.strip():
        return False, "Missing encrypted_key"
    if not _is_valid_base64(encrypted_key):
        return False, "Invalid encrypted_key format"
    if not isinstance(key_id, str) or not key_id.strip():
        return False, "Missing key_id"

    return True, ""

