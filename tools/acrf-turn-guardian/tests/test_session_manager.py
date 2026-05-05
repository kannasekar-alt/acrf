"""Tests for acrf_turn_guardian.session_manager"""
import pytest
from acrf_turn_guardian import (
    ConversationNotFoundError,
    IntentDriftError,
    SessionManager,
)


def test_start_creates_conversation():
    manager = SessionManager()
    guard = manager.start(initial_intent="purchase_laptop", initial_context={})
    assert guard.state.conversation_id in manager.conversation_ids()


def test_get_returns_existing_conversation():
    manager = SessionManager()
    guard1 = manager.start(initial_intent="purchase_laptop", initial_context={})
    guard2 = manager.get(guard1.state.conversation_id)
    assert guard2 is guard1


def test_get_raises_for_unknown_id():
    manager = SessionManager()
    with pytest.raises(ConversationNotFoundError):
        manager.get("does-not-exist")


def test_close_marks_conversation_closed():
    manager = SessionManager()
    guard = manager.start(initial_intent="purchase_laptop", initial_context={})
    manager.close(guard.state.conversation_id)
    assert guard.state.closed


def test_discard_removes_conversation():
    manager = SessionManager()
    guard = manager.start(initial_intent="purchase_laptop", initial_context={})
    manager.discard(guard.state.conversation_id)
    with pytest.raises(ConversationNotFoundError):
        manager.get(guard.state.conversation_id)


def test_save_and_load_round_trip(tmp_path):
    manager = SessionManager(max_turns=10)
    guard = manager.start(
        initial_intent="purchase_laptop",
        initial_context={"destination": "123 Home Street"},
    )
    guard.add_turn(role="user", text="I want a MacBook Pro")

    path = tmp_path / "sessions.json"
    manager.save(path)

    loaded = SessionManager.load(path)
    restored = loaded.get(guard.state.conversation_id)
    assert restored.state.initial_intent == "purchase_laptop"
    assert restored.turn_count() == 1
    assert loaded.max_turns == 10


def test_loaded_guard_still_blocks_drift(tmp_path):
    manager = SessionManager()
    guard = manager.start(
        initial_intent="purchase_laptop",
        initial_context={"destination": "123 Home Street"},
    )
    path = tmp_path / "sessions.json"
    manager.save(path)

    loaded = SessionManager.load(path)
    restored = loaded.get(guard.state.conversation_id)
    with pytest.raises(IntentDriftError):
        restored.check_action({
            "action": "checkout",
            "destination": "999 Attacker Street",
        })


def test_multiple_conversations_isolated():
    manager = SessionManager()
    g1 = manager.start(initial_intent="purchase_laptop", initial_context={})
    g2 = manager.start(initial_intent="support_ticket", initial_context={})
    assert g1.state.conversation_id != g2.state.conversation_id
    assert g1.intent_family == "purchase"
    assert g2.intent_family == "support"
