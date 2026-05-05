"""
acrf-turn-guardian
==================

Multi-turn conversation drift detection for AI agents.
Implements the ACRF-07 (Multi-Turn Defense Collapse) defense pattern.

Quick start:

    from acrf_turn_guardian import ConversationGuard

    guard = ConversationGuard(max_turns=20)
    guard.start(
        initial_intent="purchase_laptop",
        initial_context={"user_id": "alice", "destination": "123 Home Street"}
    )

    # Add each turn as it happens
    guard.add_turn(role="user", text="I would like to buy a MacBook Pro")
    guard.add_turn(role="assistant", text="Sure, what configuration?")
    guard.add_turn(role="user", text="16GB RAM, 1TB storage")

    # Before executing a sensitive action, check it against the original intent
    guard.check_action({
        "action": "modify_shipping",
        "new_address": "999 Attacker Street",
    })
    # raises IntentDriftError if action contradicts initial intent

Detection rules:

    - Action verb mismatch (purchase intent vs modify/transfer/refund action)
    - Sensitive operation introduced after initial scope was set
    - Recipient or destination changes mid-conversation
    - Turn count exceeds configured limit
    - Sudden topic shift detected via keyword analysis

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
"""
from acrf_turn_guardian.conversation import (
    ConversationGuard,
    ConversationState,
    Turn,
)
from acrf_turn_guardian.exceptions import (
    ConversationNotFoundError,
    IntentDriftError,
    SensitiveActionError,
    TopicShiftError,
    TurnGuardError,
    TurnLimitExceededError,
)
from acrf_turn_guardian.session_manager import SessionManager

__version__ = "0.1.0"
__all__ = [
    "ConversationGuard",
    "ConversationState",
    "Turn",
    "SessionManager",
    "TurnGuardError",
    "IntentDriftError",
    "TurnLimitExceededError",
    "TopicShiftError",
    "SensitiveActionError",
    "ConversationNotFoundError",
]
