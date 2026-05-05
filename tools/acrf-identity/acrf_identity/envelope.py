"""
Message Envelope module.

A MessageEnvelope wraps a payload with the metadata needed for secure
agent-to-agent communication: sender ID, recipient, timestamp, nonce, and
an Ed25519 signature over the canonical form.
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from acrf_identity.card import AgentCard, PublicAgentCard
from acrf_identity.exceptions import InvalidSignatureError

ENVELOPE_FORMAT_VERSION = "1.0"


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _canonical_json(data: dict[str, Any]) -> bytes:
    """Deterministic JSON encoding for signing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class MessageEnvelope:
    """
    Signed message envelope for agent-to-agent communication.

    Structure (signed fields):
        - payload (the actual message)
        - sender_id (agent UUID)
        - sender_name (human-readable agent name)
        - recipient (intended recipient agent name)
        - timestamp (Unix time when envelope was created)
        - nonce (unique message ID)
        - format_version

    Plus:
        - signature (Ed25519 signature over canonical JSON of signed fields)
    """
    payload: Any
    sender_id: str
    sender_name: str
    recipient: str
    timestamp: float
    nonce: str
    signature_b64: str
    format_version: str = ENVELOPE_FORMAT_VERSION

    @classmethod
    def create(
        cls,
        payload: Any,
        sender: AgentCard,
        recipient: str,
    ) -> MessageEnvelope:
        """Create and sign a new message envelope."""
        timestamp = time.time()
        nonce = str(uuid.uuid4())

        signed_fields = {
            "format_version": ENVELOPE_FORMAT_VERSION,
            "payload": payload,
            "sender_id": sender.agent_id,
            "sender_name": sender.agent_name,
            "recipient": recipient,
            "timestamp": timestamp,
            "nonce": nonce,
        }

        signature_bytes = sender.private_key.sign(_canonical_json(signed_fields))

        return cls(
            payload=payload,
            sender_id=sender.agent_id,
            sender_name=sender.agent_name,
            recipient=recipient,
            timestamp=timestamp,
            nonce=nonce,
            signature_b64=_b64encode(signature_bytes),
            format_version=ENVELOPE_FORMAT_VERSION,
        )

    def signed_fields(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "payload": self.payload,
            "sender_id": self.sender_id,
            "sender_name": self.sender_name,
            "recipient": self.recipient,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        }

    def verify_signature(self, public_card: PublicAgentCard) -> None:
        """
        Verify the envelope signature against the given public card.
        Raises InvalidSignatureError on any failure.
        """
        if public_card.agent_id != self.sender_id:
            raise InvalidSignatureError(
                f"sender_id mismatch: envelope claims {self.sender_id}, "
                f"trust store has {public_card.agent_id} for {self.sender_name}"
            )

        public_key: Ed25519PublicKey = public_card.public_key()
        try:
            public_key.verify(
                _b64decode(self.signature_b64),
                _canonical_json(self.signed_fields()),
            )
        except InvalidSignature as exc:
            raise InvalidSignatureError(
                f"signature does not verify for sender {self.sender_name}"
            ) from exc

    def to_dict(self) -> dict[str, Any]:
        d = self.signed_fields()
        d["signature_b64"] = self.signature_b64
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MessageEnvelope:
        return cls(
            payload=data["payload"],
            sender_id=data["sender_id"],
            sender_name=data["sender_name"],
            recipient=data["recipient"],
            timestamp=float(data["timestamp"]),
            nonce=data["nonce"],
            signature_b64=data["signature_b64"],
            format_version=data.get("format_version", ENVELOPE_FORMAT_VERSION),
        )

    @classmethod
    def from_json(cls, raw: str) -> MessageEnvelope:
        return cls.from_dict(json.loads(raw))
