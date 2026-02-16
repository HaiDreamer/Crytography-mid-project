"""
Payment service orchestration.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from app.models.schemas import (
    count_recent_secure_transactions,
    get_account_by_number,
    get_account_by_user_id,
    get_db_connection,
)
from app.services.risk_engine import RiskDecision, evaluate_transfer_risk


@dataclass
class PaymentResult:
    success: bool
    status_code: int
    message: str
    new_balance: float | None = None
    tx_id: int | None = None
    risk_score: int | None = None
    risk_decision: str | None = None
    risk_reason: str | None = None


def process_secure_payment(
    *,
    actor_user_id: int,
    aad: str,
    key_id: str,
    nonce: str,
    ciphertext: str,
    auth_tag: str,
    decrypted_payload: dict,
) -> PaymentResult:
    sender_account = get_account_by_user_id(actor_user_id)
    if not sender_account:
        return PaymentResult(False, 404, "Account not found")

    to_account = str(decrypted_payload.get("to_account", "")).strip()
    description = str(decrypted_payload.get("description", "")).strip()

    try:
        amount = float(decrypted_payload.get("amount", 0))
    except Exception:
        return PaymentResult(False, 400, "Invalid amount")

    if amount <= 0:
        return PaymentResult(False, 400, "Amount must be positive")
    if amount > sender_account["balance"]:
        return PaymentResult(False, 400, "Insufficient funds")
    if sender_account["account_number"] == to_account:
        return PaymentResult(False, 400, "Cannot transfer to same account")

    recipient = get_account_by_number(to_account)
    if not recipient:
        return PaymentResult(False, 400, "Recipient account not found")

    recent_count = count_recent_secure_transactions(actor_user_id, 5)
    risk: RiskDecision = evaluate_transfer_risk(amount, recent_count, aad)

    if risk.decision == "deny":
        return PaymentResult(
            False,
            403,
            "Transaction blocked by risk engine",
            risk_score=risk.score,
            risk_decision=risk.decision,
            risk_reason=risk.reason,
        )

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO secure_transactions
            (actor_user_id, key_id, nonce, aad, ciphertext, auth_tag, status, risk_score, risk_decision, risk_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                actor_user_id,
                key_id,
                nonce,
                aad,
                ciphertext,
                auth_tag,
                "completed",
                risk.score,
                risk.decision,
                risk.reason,
            ),
        )
        tx_id = cursor.lastrowid

        cursor.execute(
            "UPDATE accounts SET balance = balance - ? WHERE account_number = ?",
            (amount, sender_account["account_number"]),
        )
        cursor.execute(
            "UPDATE accounts SET balance = balance + ? WHERE account_number = ?",
            (amount, to_account),
        )
        cursor.execute(
            "SELECT balance FROM accounts WHERE account_number = ?",
            (sender_account["account_number"],),
        )
        new_balance = float(cursor.fetchone()["balance"])

        conn.commit()

        return PaymentResult(
            True,
            200,
            f"Successfully transferred ${amount:.2f} to {to_account}",
            new_balance=new_balance,
            tx_id=tx_id,
            risk_score=risk.score,
            risk_decision=risk.decision,
            risk_reason=risk.reason,
        )

    except sqlite3.IntegrityError:
        conn.rollback()
        return PaymentResult(False, 400, "Duplicate transaction detected (replay prevented)")
    except Exception as exc:
        conn.rollback()
        return PaymentResult(False, 500, f"Transfer failed: {exc}")
    finally:
        conn.close()
