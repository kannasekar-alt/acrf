"""
Guardian Agent - ACRF-07 defense layer.

Monitors every conversation turn for intent drift.
Checks if the conversation is still doing what it was supposed to do.
Flags suspicious changes that require re-verification.

This implements ACRF-07 control objectives:
  MT-1: Session limits enforced
  MT-2: Deterministic policy layer checks every turn
  MT-3: Context drift detected and flagged
"""

MAX_TURNS = 10
HIGH_RISK_PATTERNS = [
    "shipping address",
    "ship to",
    "send to",
    "deliver to",
    "change address",
    "update address",
    "different address",
    "gift address",
    "friend address",
]

def check_turn(session: dict, message: str, new_address: str = None) -> tuple[bool, str]:
    turn = session.get("turn", 0)

    # MT-1: Session limit
    if turn > MAX_TURNS:
        return False, f"Session limit reached ({MAX_TURNS} turns). Start a new session."

    # MT-2: Address change after order started requires re-verification
    original_address = session.get("original_address")
    session.get("shipping_address")

    if new_address and original_address and new_address != original_address:
        return False, (
            f"Shipping address change detected mid-session. "
            f"Original: {original_address}. "
            f"New: {new_address}. "
            f"Re-verification required before address can be changed."
        )

    # MT-3: Detect high-risk patterns late in conversation
    message_lower = message.lower()
    for pattern in HIGH_RISK_PATTERNS:
        if pattern in message_lower and turn > 3 and not session.get("address_change_verified"):
            return False, (
                f"Intent drift detected at Turn {turn}. "
                f"Shipping address change requested after order was initiated. "
                f"Flagged for re-verification."
            )

    return True, "OK"

def get_session_summary(session: dict) -> dict:
    return {
        "turn": session.get("turn"),
        "original_address": session.get("original_address"),
        "current_address": session.get("shipping_address"),
        "address_changed": session.get("original_address") != session.get("shipping_address"),
        "drift_flags": session.get("drift_flags", [])
    }
