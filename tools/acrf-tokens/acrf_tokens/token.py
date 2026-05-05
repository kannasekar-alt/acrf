"""
AgentToken module.

An AgentToken represents a single scoped credential issued to an agent.
Tokens are signed by the issuer (Ed25519) and serialized as a base64 string
of the form: BASE64(JSON(claims)).BASE64(signature)
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any

TOKEN_FORMAT_VERSION = "1.0"


def _b64encode(data: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    """URL-safe base64 with padding restored."""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data = data + ("=" * padding)
    return base64.urlsafe_b64decode(data.encode("ascii"))


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class AgentToken:
    """
    A scoped, signed token issued to an agent.

    Fields are exposed both individually (for use after validation) and as
    a single string form for transport (encode()/decode()).
    """
    token_id: str
    agent_name: str
    issuer_name: str
    scopes: list[str]
    issued_at: float
    expires_at: float
    metadata: dict[str, Any] = field(default_factory=dict)
    format_version: str = TOKEN_FORMAT_VERSION

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    def is_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) >= self.expires_at

    def claims(self) -> dict[str, Any]:
        """The signed portion of the token."""
        return {
            "format_version": self.format_version,
            "token_id": self.token_id,
            "agent_name": self.agent_name,
            "issuer_name": self.issuer_name,
            "scopes": list(self.scopes),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> AgentToken:
        return cls(
            token_id=claims["token_id"],
            agent_name=claims["agent_name"],
            issuer_name=claims["issuer_name"],
            scopes=list(claims.get("scopes", [])),
            issued_at=float(claims["issued_at"]),
            expires_at=float(claims["expires_at"]),
            metadata=dict(claims.get("metadata", {})),
            format_version=claims.get("format_version", TOKEN_FORMAT_VERSION),
        )

    def encode(self, signature: bytes) -> str:
        """Produce the wire format: BASE64(claims).BASE64(signature)"""
        claims_b64 = _b64encode(_canonical_json(self.claims()))
        sig_b64 = _b64encode(signature)
        return f"{claims_b64}.{sig_b64}"

    @classmethod
    def decode(cls, raw: str) -> tuple[AgentToken, bytes, bytes]:
        """
        Parse the wire format and return (AgentToken, signed_bytes, signature_bytes).

        signed_bytes is the canonical JSON of claims that was signed.
        signature_bytes is the raw Ed25519 signature.
        """
        if "." not in raw:
            from acrf_tokens.exceptions import InvalidTokenError
            raise InvalidTokenError("malformed token: missing separator")
        try:
            claims_b64, sig_b64 = raw.split(".", 1)
            signed_bytes = _b64decode(claims_b64)
            signature_bytes = _b64decode(sig_b64)
            claims = json.loads(signed_bytes.decode())
            agent_token = cls.from_claims(claims)
        except Exception as exc:
            from acrf_tokens.exceptions import InvalidTokenError
            raise InvalidTokenError(f"malformed token: {exc}") from exc
        return agent_token, signed_bytes, signature_bytes
