"""
acrf-identity
=============

Production-grade agent identity for AI systems.
Implements the ACRF-01 (Implicit Trust Between Agents) defense pattern.

Quick start:

    from acrf_identity import AgentCard, TrustStore, MessageEnvelope

    # Generate identity (one-time)
    card = AgentCard.generate(agent_name="PricingAgent", organization="acme")
    card.save("pricing_private.json")

    # Sign outgoing message
    envelope = MessageEnvelope.create(
        payload={"action": "book_flight", "amount": 500},
        sender=card,
        recipient="BookingAgent",
    )

    # Recipient verifies
    trust_store = TrustStore.load("trusted_agents.json")
    verified_payload = trust_store.verify(envelope)

Security features:

    - Ed25519 cryptographic signatures
    - Replay protection via timestamps
    - Nonce tracking prevents message replay
    - Agent revocation
    - Key rotation with grace period
    - Full audit trail

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
"""
from acrf_identity.card import AgentCard, PublicAgentCard
from acrf_identity.envelope import MessageEnvelope
from acrf_identity.exceptions import (
    AgentIdentityError,
    AgentNotTrustedError,
    AgentRevokedError,
    InvalidSignatureError,
    MessageExpiredError,
    NonceReusedError,
)
from acrf_identity.trust_store import TrustStore

__version__ = "0.1.0"
__all__ = [
    "AgentCard",
    "PublicAgentCard",
    "TrustStore",
    "MessageEnvelope",
    "AgentIdentityError",
    "AgentNotTrustedError",
    "AgentRevokedError",
    "InvalidSignatureError",
    "MessageExpiredError",
    "NonceReusedError",
]
