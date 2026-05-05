"""
TokenIssuer module.

A TokenIssuer holds the Ed25519 private key used to mint AgentToken instances.
Keep the issuer private file SECRET. Distribute the public form to validators.
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from acrf_tokens.token import AgentToken

ISSUER_FORMAT_VERSION = "1.0"


def _raw_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _raw_b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


@dataclass
class TokenIssuer:
    """
    Issuer that mints scoped tokens for agents.

    Use generate() once to create a new issuer keypair. Save the private
    form to a secure location. Use public_card() to obtain the public-only
    form for validators.
    """
    issuer_id: str
    issuer_name: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    created_at: float = 0.0
    format_version: str = ISSUER_FORMAT_VERSION

    @classmethod
    def generate(cls, issuer_name: str) -> TokenIssuer:
        private_key = Ed25519PrivateKey.generate()
        return cls(
            issuer_id=str(uuid.uuid4()),
            issuer_name=issuer_name,
            private_key=private_key,
            public_key=private_key.public_key(),
            created_at=time.time(),
        )

    def public_key_b64(self) -> str:
        raw = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _raw_b64(raw)

    def private_key_b64(self) -> str:
        raw = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return _raw_b64(raw)

    def public_card(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "issuer_id": self.issuer_id,
            "issuer_name": self.issuer_name,
            "public_key_b64": self.public_key_b64(),
            "created_at": self.created_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "issuer_id": self.issuer_id,
            "issuer_name": self.issuer_name,
            "public_key_b64": self.public_key_b64(),
            "private_key_b64": self.private_key_b64(),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TokenIssuer:
        private_raw = _raw_b64decode(data["private_key_b64"])
        private_key = Ed25519PrivateKey.from_private_bytes(private_raw)
        return cls(
            issuer_id=data["issuer_id"],
            issuer_name=data["issuer_name"],
            private_key=private_key,
            public_key=private_key.public_key(),
            created_at=float(data.get("created_at", 0.0)),
            format_version=data.get("format_version", ISSUER_FORMAT_VERSION),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    def save_public(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.public_card(), indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> TokenIssuer:
        return cls.from_dict(json.loads(Path(path).read_text()))

    def issue(
        self,
        agent_name: str,
        scopes: list[str],
        ttl_seconds: float,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Mint a new token for an agent.

        Returns the wire-format token string (claims.signature).
        Save token_id (decoded later) somewhere if you may need to revoke.
        """
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        now = time.time()
        token = AgentToken(
            token_id=str(uuid.uuid4()),
            agent_name=agent_name,
            issuer_name=self.issuer_name,
            scopes=list(scopes),
            issued_at=now,
            expires_at=now + ttl_seconds,
            metadata=metadata or {},
        )

        from acrf_tokens.token import _canonical_json
        signed = _canonical_json(token.claims())
        signature = self.private_key.sign(signed)
        return token.encode(signature)
