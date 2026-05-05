"""Tests for acrf_turn_guardian.conversation"""
import pytest
from acrf_turn_guardian import (
    ConversationGuard,
    IntentDriftError,
    SensitiveActionError,
    TopicShiftError,
    TurnLimitExceededError,
)


def _start_purchase_guard(max_turns=20, topic_threshold=0.05):
    guard = ConversationGuard(max_turns=max_turns, topic_shift_threshold=topic_threshold)
    guard.start(
        initial_intent="purchase_laptop",
        initial_context={"user_id": "alice", "destination": "123 Home Street"},
    )
    return guard


def test_start_assigns_conversation_id():
    guard = _start_purchase_guard()
    assert guard.state.conversation_id
    assert guard.state.initial_intent == "purchase_laptop"


def test_start_infers_intent_family():
    guard = _start_purchase_guard()
    assert guard.intent_family == "purchase"


def test_add_turn_appends_to_history():
    guard = _start_purchase_guard()
    guard.add_turn(role="user", text="I want a MacBook Pro")
    guard.add_turn(role="assistant", text="What configuration?")
    assert guard.turn_count() == 2


def test_max_turns_enforced():
    guard = _start_purchase_guard(max_turns=2)
    guard.add_turn(role="user", text="t1")
    guard.add_turn(role="assistant", text="t2")
    with pytest.raises(TurnLimitExceededError):
        guard.add_turn(role="user", text="t3")


def test_check_action_allows_consistent_action():
    guard = _start_purchase_guard()
    # purchase intent + buy action = OK
    guard.check_action({"action": "add_to_cart", "product": "macbook"})


def test_check_action_blocks_unrelated_action():
    guard = _start_purchase_guard()
    with pytest.raises(IntentDriftError):
        guard.check_action({"action": "open_ticket", "subject": "x"})


def test_check_action_blocks_destructive_action():
    guard = _start_purchase_guard()
    with pytest.raises(SensitiveActionError):
        guard.check_action({"action": "refund_all"})


def test_check_action_blocks_destination_change():
    guard = _start_purchase_guard()
    with pytest.raises(IntentDriftError):
        guard.check_action({
            "action": "checkout",
            "destination": "999 Attacker Street",
        })


def test_check_action_allows_matching_destination():
    guard = _start_purchase_guard()
    guard.check_action({
        "action": "checkout",
        "destination": "123 Home Street",
    })


def test_check_action_blocks_recipient_change():
    guard = ConversationGuard(max_turns=20)
    guard.start(
        initial_intent="purchase_gift",
        initial_context={"recipient": "alice@example.com"},
    )
    with pytest.raises(IntentDriftError):
        guard.check_action({
            "action": "checkout",
            "recipient": "attacker@example.com",
        })


def test_user_introducing_sensitive_keyword_is_blocked():
    guard = _start_purchase_guard()
    guard.add_turn(role="user", text="I want a MacBook Pro")
    guard.add_turn(role="assistant", text="What configuration?")
    with pytest.raises(SensitiveActionError):
        # User suddenly asks for a refund - drift from purchase intent
        guard.add_turn(role="user", text="actually please refund my last order")


def test_user_repeating_intent_keyword_is_allowed():
    """If the initial intent contains a keyword, repeating it is fine."""
    guard = ConversationGuard(max_turns=20)
    guard.start(initial_intent="refund_order", initial_context={})
    # refund is in initial intent, so referencing it again is allowed
    guard.add_turn(role="user", text="please refund my order")


def test_topic_shift_detected_after_history_built():
    guard = _start_purchase_guard(topic_threshold=0.5)
    # Build baseline of purchase-related text
    guard.add_turn(role="user", text="I want a MacBook Pro 16 inch")
    guard.add_turn(role="assistant", text="Sure, configuration?")
    guard.add_turn(role="user", text="MacBook Pro 16 inch with 16GB and 1TB")
    guard.add_turn(role="assistant", text="Color preference?")
    # Sudden unrelated turn
    with pytest.raises(TopicShiftError):
        guard.add_turn(role="user", text="totally different topic about cooking")


def test_close_marks_conversation_closed():
    guard = _start_purchase_guard()
    guard.close()
    assert guard.state.closed


def test_cannot_start_twice():
    guard = _start_purchase_guard()
    with pytest.raises(RuntimeError):
        guard.start(initial_intent="x")


def test_state_property_raises_when_not_started():
    guard = ConversationGuard()
    with pytest.raises(RuntimeError):
        _ = guard.state


def test_to_json_and_restore_round_trip():
    guard = _start_purchase_guard()
    guard.add_turn(role="user", text="I want a MacBook Pro")

    raw = guard.to_json()
    restored = ConversationGuard.restore(raw, max_turns=20)
    assert restored.state.initial_intent == guard.state.initial_intent
    assert restored.turn_count() == 1
    assert restored.intent_family == guard.intent_family
