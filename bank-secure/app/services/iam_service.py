"""
IAM service facade over the application's authenticated session.
"""

from __future__ import annotations

from flask import session

from app.security.sessions import get_current_user


def get_auth_claims() -> dict | None:
    user = get_current_user()
    if not user:
        return None

    session_id = session.get("session_id")
    if not session_id:
        return None

    return {
        "user_id": user["user_id"],
        "username": user["username"],
        "session_id": session_id,
    }

