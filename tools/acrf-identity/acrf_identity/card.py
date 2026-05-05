"""
Agent Card module.

An AgentCard contains an agent's cryptographic identity (Ed25519 keypair plus metadata).
A PublicAgentCard contains only the public key and metadata - safe to share.
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

CARD_FORMAT_VERSION = "1.0"


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


@dataclass
class PublicAgentCard:
    """
    Public-only Agent Card. Safe to publish, share, or commit to a trust store.

    Contains the agent name, public key, organization, metadata, and version.
    Does NOT contain the private key.
    """
    agent_id: str
    agent_name: str
    public_key_b64: str
    organization: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    format_version: str = CARD_FORMAT_VERSION

    def public_key(self) -> Ed25519PublicKey:
        raw = _b64decode(self.public_key_b64)
        return Ed25519PublicKey.from_public_bytes(raw)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "public_key_b64": self.public_key_b64,
            "organization": self.organization,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PublicAgentCard:
        return cls(
            agent_id=data["agent_id"],
            agent_name=data["agent_name"],
            public_key_b64=data["public_key_b64"],
            organization=data.get("organization", ""),
            metadata=dict(data.get("metadata", {})),
            created_at=float(data.get("created_at", 0.0)),
            format_version=data.get("format_version", CARD_FORMAT_VERSION),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> PublicAgentCard:
        return cls.from_dict(json.loads(Path(path).read_text()))


@dataclass
class AgentCard:
    """
    Full Agent Card with both private and public key material.

    KEEP THE PRIVATE KEY SECRET. Never commit it. Never share it.
    Use save() to persist to disk; protect that file with appropriate permissions.

    Use public_only() to extract a PublicAgentCard for sharing.
    """
    agent_id: str
    agent_name: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    organization: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    format_version: str = CARD_FORMAT_VERSION

    @classmethod
    def generate(
        cls,
        agent_name: str,
        organization: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AgentCard:
        """Generate a brand new agent identity with a fresh Ed25519 keypair."""
        private_key = Ed25519PrivateKey.generate()
        return cls(
            agent_id=str(uuid.uuid4()),
            agent_name=agent_name,
            private_key=private_key,
            public_key=private_key.public_key(),
            organization=organization,
            metadata=metadata or {},
            created_at=time.time(),
        )

    def public_key_b64(self) -> str:
        raw = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _b64encode(raw)

    def private_key_b64(self) -> str:
        raw = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return _b64encode(raw)

    def public_only(self) -> PublicAgentCard:
        """Extract a public-only card safe to share."""
        return PublicAgentCard(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            public_key_b64=self.public_key_b64(),
            organization=self.organization,
            metadata=dict(self.metadata),
            created_at=self.created_at,
            format_version=self.format_version,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "public_key_b64": self.public_key_b64(),
            "private_key_b64": self.private_key_b64(),
            "organization": self.organization,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentCard:
        private_raw = _b64decode(data["private_key_b64"])
        private_key = Ed25519PrivateKey.from_private_bytes(private_raw)
        return cls(
            agent_id=data["agent_id"],
            agent_name=data["agent_name"],
            private_key=private_key,
            public_key=private_key.public_key(),
            organization=data.get("organization", ""),
            metadata=dict(data.get("metadata", {})),
            created_at=float(data.get("created_at", 0.0)),
            format_version=data.get("format_version", CARD_FORMAT_VERSION),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> AgentCard:
        return cls.from_dict(json.loads(Path(path).read_text()))
