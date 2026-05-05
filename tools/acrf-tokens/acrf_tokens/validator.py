"""
TokenValidator module.

A TokenValidator holds the issuer public key plus a revocation list and
validates incoming token strings. Every validation produces an audit record.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from acrf_tokens.exceptions import (
    InvalidTokenError,
    TokenExpiredError,
    TokenRevokedError,
    TokenScopeError,
)
from acrf_tokens.token import AgentToken


def _raw_b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


@dataclass
class ValidationRecord:
    """Audit log entry for a token validation attempt."""
    timestamp: float
    token_id: str
    agent_name: str
    issuer_name: str
    result: str  # "success" | "invalid" | "expired" | "revoked" | "scope_missing"
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "token_id": self.token_id,
            "agent_name": self.agent_name,
            "issuer_name": self.issuer_name,
            "result": self.result,
            "detail": self.detail,
        }


@dataclass
class TokenValidator:
    """
    Validator that verifies token signatures and enforces revocation.

    Construct from the issuer public card. Maintains a set of revoked
    token IDs that are persisted alongside the validator state.
    """
    issuer_id: str
    issuer_name: str
    public_key: Ed25519PublicKey
    _revoked: set[str] = field(default_factory=set)
    _audit: list[ValidationRecord] = field(default_factory=list)
    format_version: str = "1.0"

    @classmethod
    def from_public_card(cls, card: dict[str, Any]) -> TokenValidator:
        public_key_raw = _raw_b64decode(card["public_key_b64"])
        return cls(
            issuer_id=card["issuer_id"],
            issuer_name=card["issuer_name"],
            public_key=Ed25519PublicKey.from_public_bytes(public_key_raw),
            format_version=card.get("format_version", "1.0"),
        )

    @classmethod
    def load(cls, path: str | Path) -> TokenValidator:
        """Load a validator from a public-card JSON file."""
        return cls.from_public_card(json.loads(Path(path).read_text()))

    @classmethod
    def load_with_revocations(cls, public_card_path: str | Path, revocation_list_path: str | Path) -> TokenValidator:
        """Load validator and merge in a persisted revocation list."""
        validator = cls.load(public_card_path)
        revocation_path = Path(revocation_list_path)
        if revocation_path.exists():
            data = json.loads(revocation_path.read_text())
            validator._revoked = set(data.get("revoked", []))
        return validator

    def save_revocations(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(
            {"revoked": sorted(self._revoked)},
            indent=2,
            sort_keys=True,
        ))

    # ------------------------------------------------------------------
    # Revocation management
    # ------------------------------------------------------------------

    def revoke(self, token_id: str) -> None:
        self._revoked.add(token_id)

    def is_revoked(self, token_id: str) -> bool:
        return token_id in self._revoked

    def revoked_token_ids(self) -> list[str]:
        return sorted(self._revoked)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self, token_string: str, required_scope: str | None = None) -> AgentToken:
        """
        Validate a token string.

        Checks (in order):
            1. Token is well-formed and signature parses
            2. Signature verifies against issuer public key
            3. Token has not been revoked
            4. Token has not expired
            5. (optional) Required scope is present

        Returns the AgentToken on success.
        Raises a TokenError subclass on any failure.
        """
        # 1. Decode and parse
        agent_token, signed_bytes, signature_bytes = AgentToken.decode(token_string)

        # 2. Signature check
        try:
            self.public_key.verify(signature_bytes, signed_bytes)
        except InvalidSignature as exc:
            self._record(agent_token, "invalid", "signature does not verify")
            raise InvalidTokenError(
                f"signature does not verify for token {agent_token.token_id}"
            ) from exc

        # 3. Revocation check
        if agent_token.token_id in self._revoked:
            self._record(agent_token, "revoked", "token was revoked")
            raise TokenRevokedError(f"token revoked: {agent_token.token_id}")

        # 4. Expiry check
        if agent_token.is_expired():
            self._record(agent_token, "expired", f"expired at {agent_token.expires_at}")
            raise TokenExpiredError(
                f"token expired at {agent_token.expires_at} (now={time.time()})"
            )

        # 5. Optional scope check
        if required_scope is not None and not agent_token.has_scope(required_scope):
            self._record(agent_token, "scope_missing", f"required scope: {required_scope}")
            raise TokenScopeError(
                f"required scope {required_scope!r} not present in token "
                f"(scopes={agent_token.scopes})"
            )

        self._record(agent_token, "success")
        return agent_token

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def audit_log(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._audit]

    def _record(self, agent_token: AgentToken, result: str, detail: str = "") -> None:
        self._audit.append(ValidationRecord(
            timestamp=time.time(),
            token_id=agent_token.token_id,
            agent_name=agent_token.agent_name,
            issuer_name=agent_token.issuer_name,
            result=result,
            detail=detail,
        ))
