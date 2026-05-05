"""Tests for acrf_identity.trust_store"""
import time

import pytest
from acrf_identity import AgentCard, MessageEnvelope, TrustStore
from acrf_identity.exceptions import (
    AgentNotTrustedError,
    AgentRevokedError,
    InvalidSignatureError,
    MessageExpiredError,
    NonceReusedError,
)


def _make_envelope(card, recipient="Receiver", payload=None):
    return MessageEnvelope.create(
        payload=payload or {"x": 1},
        sender=card,
        recipient=recipient,
    )


def test_add_and_verify():
    card = AgentCard.generate(agent_name="Agent1")
    store = TrustStore()
    store.add(card.public_only())

    envelope = _make_envelope(card)
    payload = store.verify(envelope)
    assert payload == {"x": 1}


def test_verify_fails_for_unknown_agent():
    card = AgentCard.generate(agent_name="Stranger")
    store = TrustStore()
    envelope = _make_envelope(card)
    with pytest.raises(AgentNotTrustedError):
        store.verify(envelope)


def test_revoke_blocks_verification():
    card = AgentCard.generate(agent_name="Agent1")
    store = TrustStore()
    store.add(card.public_only())
    store.revoke("Agent1")

    envelope = _make_envelope(card)
    with pytest.raises(AgentRevokedError):
        store.verify(envelope)


def test_cannot_add_revoked_agent():
    card = AgentCard.generate(agent_name="Agent1")
    store = TrustStore()
    store.revoke("Agent1")
    with pytest.raises(AgentRevokedError):
        store.add(card.public_only())


def test_invalid_signature_fails():
    card = AgentCard.generate(agent_name="Agent1")
    store = TrustStore()
    store.add(card.public_only())

    envelope = _make_envelope(card)
    envelope.payload["amount"] = 999999  # tamper
    with pytest.raises(InvalidSignatureError):
        store.verify(envelope)


def test_replay_protection_old_message():
    card = AgentCard.generate(agent_name="Agent1")
    store = TrustStore(max_message_age=1)
    store.add(card.public_only())

    envelope = _make_envelope(card)
    time.sleep(1.5)
    with pytest.raises(MessageExpiredError):
        store.verify(envelope)


def test_replay_protection_future_timestamp():
    card = AgentCard.generate(agent_name="Agent1")
    store = TrustStore()
    store.add(card.public_only())

    envelope = _make_envelope(card)
    envelope.timestamp = time.time() + 3600  # 1h in the future
    with pytest.raises(MessageExpiredError):
        store.verify(envelope)


def test_replay_protection_nonce_reuse():
    card = AgentCard.generate(agent_name="Agent1")
    store = TrustStore()
    store.add(card.public_only())

    envelope = _make_envelope(card)
    store.verify(envelope)  # First time - OK

    with pytest.raises(NonceReusedError):
        store.verify(envelope)  # Same nonce - blocked


def test_key_rotation():
    old_card = AgentCard.generate(agent_name="Agent1")
    store = TrustStore()
    store.add(old_card.public_only())

    # Generate a new keypair, same agent name
    new_card = AgentCard.generate(agent_name="Agent1")
    store.rotate_key(new_card.public_only())

    # New key works
    envelope_new = _make_envelope(new_card)
    store.verify(envelope_new)

    # Old key still works during grace period (looked up by agent_id)
    envelope_old = _make_envelope(old_card)
    store.verify(envelope_old)


def test_lookup_returns_active_card():
    card = AgentCard.generate(agent_name="Agent1")
    store = TrustStore()
    store.add(card.public_only())
    looked_up = store.lookup("Agent1")
    assert looked_up is not None
    assert looked_up.agent_id == card.agent_id


def test_lookup_returns_none_for_unknown():
    store = TrustStore()
    assert store.lookup("Unknown") is None


def test_save_and_load_round_trip(tmp_path):
    card1 = AgentCard.generate(agent_name="Agent1")
    card2 = AgentCard.generate(agent_name="Agent2")

    store = TrustStore()
    store.add(card1.public_only())
    store.add(card2.public_only())
    store.revoke("OldAgent")

    path = tmp_path / "store.json"
    store.save(path)

    loaded = TrustStore.load(path)
    assert "Agent1" in loaded.trusted_agent_names()
    assert "Agent2" in loaded.trusted_agent_names()
    assert "OldAgent" in loaded.revoked_agent_names()

    envelope = _make_envelope(card1)
    loaded.verify(envelope)


def test_audit_log_records_success():
    card = AgentCard.generate(agent_name="Agent1")
    store = TrustStore()
    store.add(card.public_only())
    envelope = _make_envelope(card)
    store.verify(envelope)

    log = store.audit_log()
    assert len(log) == 1
    assert log[0]["result"] == "success"
    assert log[0]["sender_name"] == "Agent1"


def test_audit_log_records_failure():
    card = AgentCard.generate(agent_name="Stranger")
    store = TrustStore()
    envelope = _make_envelope(card)
    with pytest.raises(AgentNotTrustedError):
        store.verify(envelope)

    log = store.audit_log()
    assert len(log) == 1
    assert log[0]["result"] == "not_trusted"


def test_revoked_agents_listed():
    store = TrustStore()
    store.revoke("Bad1")
    store.revoke("Bad2")
    revoked = store.revoked_agent_names()
    assert "Bad1" in revoked
    assert "Bad2" in revoked
