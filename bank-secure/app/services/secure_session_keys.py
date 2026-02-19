"""
In-memory store for decrypted session keys (DEKs).

The diagram requires DEKs to be returned and used in-memory only.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock


@dataclass
class SessionKeyRecord:
    key_id: str
    dek: bytes
    created_at: float
    last_used_at: float


class SecureSessionKeyStore:
    def __init__(self, ttl_seconds: int = 30 * 60) -> None:
        self._ttl_seconds = ttl_seconds
        self._records: dict[str, SessionKeyRecord] = {}
        self._lock = Lock()

    def _purge_expired(self) -> None:
        now = time.time()
        expired_ids = [
            session_id
            for session_id, record in self._records.items()
            if now - record.last_used_at > self._ttl_seconds
        ]
        for session_id in expired_ids:
            self._records.pop(session_id, None)

    def put(self, session_id: str, key_id: str, dek: bytes) -> None:
        now = time.time()
        with self._lock:
            self._purge_expired()
            self._records[session_id] = SessionKeyRecord(
                key_id=key_id,
                dek=dek,
                created_at=now,
                last_used_at=now,
            )

    def get(self, session_id: str, key_id: str) -> bytes | None:
        with self._lock:
            self._purge_expired()
            record = self._records.get(session_id)
            if not record:
                return None
            if record.key_id != key_id:
                return None
            record.last_used_at = time.time()
            return record.dek

    def revoke(self, session_id: str) -> None:
        with self._lock:
            self._records.pop(session_id, None)


_secure_store = SecureSessionKeyStore()


def get_secure_session_key_store() -> SecureSessionKeyStore:
    return _secure_store

