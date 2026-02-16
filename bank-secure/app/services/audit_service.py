"""
Audit logging service.
"""

from __future__ import annotations

import json
from typing import Any

from app.models.schemas import get_db_connection


def write_audit_event(
    event_type: str,
    status: str,
    actor_user_id: int | None,
    ip_address: str | None,
    user_agent: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO audit_events (event_type, status, actor_user_id, ip_address, user_agent, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            event_type,
            status,
            actor_user_id,
            ip_address,
            user_agent,
            json.dumps(details or {}),
        ),
    )
    conn.commit()
    conn.close()

