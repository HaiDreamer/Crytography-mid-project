"""
Risk engine for transfer decisioning.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RiskDecision:
    score: int
    decision: str
    reason: str


def evaluate_transfer_risk(amount: float, recent_tx_count: int, aad_text: str) -> RiskDecision:
    score = 0
    reasons: list[str] = []

    if amount >= 5000:
        score += 70
        reasons.append("high_amount")
    elif amount >= 1000:
        score += 30
        reasons.append("medium_amount")

    if recent_tx_count >= 5:
        score += 40
        reasons.append("velocity_spike")
    elif recent_tx_count >= 3:
        score += 20
        reasons.append("elevated_velocity")

    if "mobile" in aad_text.lower():
        score += 5
        reasons.append("mobile_channel")

    if score >= 80:
        decision = "deny"
    elif score >= 50:
        decision = "review"
    else:
        decision = "allow"

    if not reasons:
        reasons.append("normal")

    return RiskDecision(
        score=score,
        decision=decision,
        reason=",".join(reasons),
    )

