"""Tests for acrf_identity.envelope"""

import pytest
from acrf_identity import AgentCard, MessageEnvelope
from acrf_identity.exceptions import InvalidSignatureError


def test_create_envelope_signs_payload():
    card = AgentCard.generate(agent_name="Sender")
    envelope = MessageEnvelope.create(
        payload={"action": "test"},
        sender=card,
        recipient="Receiver",
    )
    assert envelope.sender_name == "Sender"
    assert envelope.sender_id == card.agent_id
    assert envelope.recipient == "Receiver"
    assert envelope.signature_b64
    assert envelope.nonce
    assert envelope.timestamp > 0


def test_verify_signature_passes_with_correct_key():
    card = AgentCard.generate(agent_name="Sender")
    envelope = MessageEnvelope.create(
        payload={"action": "test"},
        sender=card,
        recipient="Receiver",
    )
    # Should not raise
    envelope.verify_signature(card.public_only())


def test_verify_signature_fails_with_wrong_key():
    sender = AgentCard.generate(agent_name="Sender")
    other = AgentCard.generate(agent_name="Other")
    envelope = MessageEnvelope.create(
        payload={"action": "test"},
        sender=sender,
        recipient="Receiver",
    )
    with pytest.raises(InvalidSignatureError):
        envelope.verify_signature(other.public_only())


def test_verify_signature_fails_when_payload_tampered():
    card = AgentCard.generate(agent_name="Sender")
    envelope = MessageEnvelope.create(
        payload={"action": "transfer", "amount": 100},
        sender=card,
        recipient="Receiver",
    )
    # Tamper with payload
    envelope.payload["amount"] = 1000000
    with pytest.raises(InvalidSignatureError):
        envelope.verify_signature(card.public_only())


def test_verify_signature_fails_on_id_mismatch():
    sender = AgentCard.generate(agent_name="Sender")
    different_card = AgentCard.generate(agent_name="Sender").public_only()
    envelope = MessageEnvelope.create(
        payload={"x": 1},
        sender=sender,
        recipient="Receiver",
    )
    with pytest.raises(InvalidSignatureError) as exc_info:
        envelope.verify_signature(different_card)
    assert "sender_id mismatch" in str(exc_info.value)


def test_envelope_serialization_round_trip():
    card = AgentCard.generate(agent_name="Sender")
    envelope = MessageEnvelope.create(
        payload={"action": "test", "data": [1, 2, 3]},
        sender=card,
        recipient="Receiver",
    )
    raw = envelope.to_json()
    restored = MessageEnvelope.from_json(raw)

    assert restored.payload == envelope.payload
    assert restored.sender_id == envelope.sender_id
    assert restored.signature_b64 == envelope.signature_b64
    # Restored envelope should still verify
    restored.verify_signature(card.public_only())


def test_each_envelope_has_unique_nonce():
    card = AgentCard.generate(agent_name="Sender")
    e1 = MessageEnvelope.create(payload={"x": 1}, sender=card, recipient="R")
    e2 = MessageEnvelope.create(payload={"x": 1}, sender=card, recipient="R")
    assert e1.nonce != e2.nonce


def test_envelope_supports_complex_payload():
    card = AgentCard.generate(agent_name="Sender")
    payload = {
        "action": "trade",
        "details": {
            "ticker": "TSLA",
            "side": "BUY",
            "shares": 10,
            "metadata": [{"k": "v"}, None, True, 3.14],
        }
    }
    envelope = MessageEnvelope.create(payload=payload, sender=card, recipient="R")
    envelope.verify_signature(card.public_only())
