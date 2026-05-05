"""
Credentials module.

Defines the two distinct credential types used by acrf-safety-shield:

    AdminCredential   - Ed25519 keypair, can sign safety state changes
    AgentCredential   - regular agent token, can only read safety state

The hard wall between these types is the entire point of ACRF-10.
A compromised agent token CANNOT escalate to an admin credential.
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

CREDENTIAL_FORMAT_VERSION = "1.0"


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


# ----------------------------------------------------------------------
# Public Admin Card (safe to ship to the shield)
# ----------------------------------------------------------------------

@dataclass
class PublicAdminCard:
    """
    Public-only view of an admin credential. Safe to share with shields.
    Contains the admin name, public key, and metadata - never the private key.
    """
    admin_id: str
    admin_name: str
    public_key_b64: str
    created_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    format_version: str = CREDENTIAL_FORMAT_VERSION

    def public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(_b64decode(self.public_key_b64))

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "admin_id": self.admin_id,
            "admin_name": self.admin_name,
            "public_key_b64": self.public_key_b64,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PublicAdminCard:
        return cls(
            admin_id=data["admin_id"],
            admin_name=data["admin_name"],
            public_key_b64=data["public_key_b64"],
            created_at=float(data.get("created_at", 0.0)),
            metadata=dict(data.get("metadata", {})),
            format_version=data.get("format_version", CREDENTIAL_FORMAT_VERSION),
        )

    def save_to(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> PublicAdminCard:
        return cls.from_dict(json.loads(Path(path).read_text()))


# ----------------------------------------------------------------------
# Admin Credential (private)
# ----------------------------------------------------------------------

@dataclass
class AdminCredential:
    """
    Admin credential capable of signing safety state changes.

    The private key MUST be stored offline (HSM, paper backup, hardware
    token). Never ship this object to an agent or to the shield.
    """
    admin_id: str
    admin_name: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    created_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    format_version: str = CREDENTIAL_FORMAT_VERSION

    @classmethod
    def generate(
        cls,
        admin_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> AdminCredential:
        private_key = Ed25519PrivateKey.generate()
        return cls(
            admin_id=str(uuid.uuid4()),
            admin_name=admin_name,
            private_key=private_key,
            public_key=private_key.public_key(),
            created_at=time.time(),
            metadata=metadata or {},
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

    def public_card(self) -> PublicAdminCard:
        return PublicAdminCard(
            admin_id=self.admin_id,
            admin_name=self.admin_name,
            public_key_b64=self.public_key_b64(),
            created_at=self.created_at,
            metadata=dict(self.metadata),
            format_version=self.format_version,
        )

    def sign(self, payload: dict[str, Any]) -> str:
        """Sign a state-change payload. Returns base64 signature."""
        signature = self.private_key.sign(_canonical_json(payload))
        return _b64encode(signature)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "admin_id": self.admin_id,
            "admin_name": self.admin_name,
            "public_key_b64": self.public_key_b64(),
            "private_key_b64": self.private_key_b64(),
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AdminCredential:
        private_raw = _b64decode(data["private_key_b64"])
        private_key = Ed25519PrivateKey.from_private_bytes(private_raw)
        return cls(
            admin_id=data["admin_id"],
            admin_name=data["admin_name"],
            private_key=private_key,
            public_key=private_key.public_key(),
            created_at=float(data.get("created_at", 0.0)),
            metadata=dict(data.get("metadata", {})),
            format_version=data.get("format_version", CREDENTIAL_FORMAT_VERSION),
        )

    def save_private(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def load_private(cls, path: str | Path) -> AdminCredential:
        return cls.from_dict(json.loads(Path(path).read_text()))


# ----------------------------------------------------------------------
# Agent Credential (low privilege, read-only on safety state)
# ----------------------------------------------------------------------

@dataclass
class AgentCredential:
    """
    Agent credential. Has NO ability to modify safety state.
    The shield accepts this only for read operations.
    """
    agent_name: str
    token: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "token": self.token,
            "metadata": dict(self.metadata),
        }
