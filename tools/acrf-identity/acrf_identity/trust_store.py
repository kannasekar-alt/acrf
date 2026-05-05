"""
Trust Store module.

A TrustStore maintains the set of agents whose messages this system trusts.
It supports adding agents, revoking compromised ones, rotating keys, and
verifying incoming MessageEnvelopes with full replay protection.
"""
from __future__ import annotations

import json
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acrf_identity.card import PublicAgentCard
from acrf_identity.envelope import MessageEnvelope
from acrf_identity.exceptions import (
    AgentNotTrustedError,
    AgentRevokedError,
    MessageExpiredError,
    NonceReusedError,
)

# Default replay protection window (seconds).
# Messages older than this are rejected even if signature is valid.
DEFAULT_MAX_MESSAGE_AGE = 300  # 5 minutes

# Default nonce cache size for replay protection.
# Each verified nonce is remembered for the duration of the message age window.
DEFAULT_NONCE_CACHE_SIZE = 10000


@dataclass
class AuditRecord:
    """Audit log entry for a verification attempt."""
    timestamp: float
    sender_name: str
    sender_id: str
    recipient: str
    nonce: str
    result: str  # "success" | "invalid_signature" | "not_trusted" | "revoked" | "expired" | "nonce_reused"
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "sender_name": self.sender_name,
            "sender_id": self.sender_id,
            "recipient": self.recipient,
            "nonce": self.nonce,
            "result": self.result,
            "detail": self.detail,
        }


@dataclass
class TrustStore:
    """
    Registry of trusted agents with verification and revocation support.

    Two indexes:
        - by agent_name: most recent active card for each agent name
        - by agent_id: every card ever trusted (including rotated old keys
          within their grace period)

    Revocation list: agent_names that should never verify, regardless of card.
    """
    # name -> active PublicAgentCard
    _agents_by_name: dict[str, PublicAgentCard] = field(default_factory=dict)
    # agent_id -> PublicAgentCard (allows old keys during grace period)
    _agents_by_id: dict[str, PublicAgentCard] = field(default_factory=dict)
    # set of revoked agent names
    _revoked: set[str] = field(default_factory=set)
    # nonce -> timestamp seen, for replay protection
    _nonces: OrderedDict[str, float] = field(default_factory=OrderedDict)
    # audit log
    _audit: list[AuditRecord] = field(default_factory=list)

    max_message_age: float = DEFAULT_MAX_MESSAGE_AGE
    nonce_cache_size: int = DEFAULT_NONCE_CACHE_SIZE

    # ------------------------------------------------------------------
    # Trust management
    # ------------------------------------------------------------------

    def add(self, card: PublicAgentCard) -> None:
        """Add or update an agent in the trust store."""
        if card.agent_name in self._revoked:
            raise AgentRevokedError(
                f"cannot add revoked agent: {card.agent_name}"
            )
        self._agents_by_name[card.agent_name] = card
        self._agents_by_id[card.agent_id] = card

    def rotate_key(self, new_card: PublicAgentCard) -> None:
        """
        Rotate to a new key for an existing agent name.

        The old card stays in _agents_by_id so messages signed with the
        old key during the grace period can still be verified, but new
        verifications will use the new card by default.
        """
        if new_card.agent_name in self._revoked:
            raise AgentRevokedError(
                f"cannot rotate key for revoked agent: {new_card.agent_name}"
            )
        self._agents_by_name[new_card.agent_name] = new_card
        self._agents_by_id[new_card.agent_id] = new_card

    def revoke(self, agent_name: str) -> None:
        """Permanently revoke an agent. Future messages will fail verification."""
        self._revoked.add(agent_name)
        self._agents_by_name.pop(agent_name, None)
        # Note: we leave _agents_by_id untouched so audit records can still
        # resolve historical agent_ids; the revocation list is the source
        # of truth for verification.

    def is_revoked(self, agent_name: str) -> bool:
        return agent_name in self._revoked

    def lookup(self, agent_name: str) -> PublicAgentCard | None:
        return self._agents_by_name.get(agent_name)

    def lookup_by_id(self, agent_id: str) -> PublicAgentCard | None:
        return self._agents_by_id.get(agent_id)

    def trusted_agent_names(self) -> list[str]:
        return sorted(self._agents_by_name.keys())

    def revoked_agent_names(self) -> list[str]:
        return sorted(self._revoked)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, envelope: MessageEnvelope) -> Any:
        """
        Verify a message envelope and return its payload.

        Checks:
            1. Sender not on revocation list
            2. Sender card is in the trust store
            3. Timestamp within max_message_age
            4. Nonce has not been seen before
            5. Signature is valid

        Raises:
            AgentRevokedError: sender is revoked
            AgentNotTrustedError: sender not in trust store
            MessageExpiredError: timestamp too old
            NonceReusedError: nonce already seen
            InvalidSignatureError: signature does not verify

        Returns:
            The verified payload (only after all checks pass)
        """
        sender_name = envelope.sender_name
        sender_id = envelope.sender_id
        nonce = envelope.nonce

        # 1. Revocation check first - fail fast
        if sender_name in self._revoked:
            self._record(envelope, "revoked", f"agent {sender_name} is revoked")
            raise AgentRevokedError(f"agent {sender_name} is revoked")

        # 2. Trust check - prefer lookup by sender_id (matches the exact key)
        card = self._agents_by_id.get(sender_id) or self._agents_by_name.get(sender_name)
        if card is None:
            self._record(envelope, "not_trusted", f"unknown agent {sender_name}")
            raise AgentNotTrustedError(f"agent not in trust store: {sender_name}")

        # 3. Timestamp check (replay protection - age)
        now = time.time()
        age = now - envelope.timestamp
        if age > self.max_message_age:
            self._record(envelope, "expired", f"message age {age:.1f}s > {self.max_message_age}s")
            raise MessageExpiredError(
                f"message timestamp too old: {age:.1f}s > {self.max_message_age}s"
            )
        # Reject far-future timestamps too (allow some clock skew, here 60s)
        if envelope.timestamp - now > 60:
            self._record(envelope, "expired", "message timestamp in the future")
            raise MessageExpiredError("message timestamp is in the future")

        # 4. Nonce check (replay protection - uniqueness)
        self._prune_nonces(now)
        if nonce in self._nonces:
            self._record(envelope, "nonce_reused", f"nonce {nonce} already seen")
            raise NonceReusedError(f"nonce already seen: {nonce}")

        # 5. Signature check
        try:
            envelope.verify_signature(card)
        except Exception as exc:
            self._record(envelope, "invalid_signature", str(exc))
            raise

        # All checks passed - remember nonce, record audit, return payload
        self._nonces[nonce] = now
        if len(self._nonces) > self.nonce_cache_size:
            self._nonces.popitem(last=False)

        self._record(envelope, "success")
        return envelope.payload

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def audit_log(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._audit]

    def _record(self, envelope: MessageEnvelope, result: str, detail: str = "") -> None:
        self._audit.append(AuditRecord(
            timestamp=time.time(),
            sender_name=envelope.sender_name,
            sender_id=envelope.sender_id,
            recipient=envelope.recipient,
            nonce=envelope.nonce,
            result=result,
            detail=detail,
        ))

    def _prune_nonces(self, now: float) -> None:
        """Drop nonces older than the message age window."""
        cutoff = now - self.max_message_age
        # Walk from oldest end of OrderedDict
        while self._nonces:
            oldest_nonce, oldest_ts = next(iter(self._nonces.items()))
            if oldest_ts < cutoff:
                self._nonces.popitem(last=False)
            else:
                break

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "agents": [c.to_dict() for c in self._agents_by_name.values()],
            "rotated_agents": [
                c.to_dict() for c in self._agents_by_id.values()
                if c.agent_id not in {a.agent_id for a in self._agents_by_name.values()}
            ],
            "revoked": sorted(self._revoked),
            "max_message_age": self.max_message_age,
            "nonce_cache_size": self.nonce_cache_size,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustStore:
        store = cls(
            max_message_age=float(data.get("max_message_age", DEFAULT_MAX_MESSAGE_AGE)),
            nonce_cache_size=int(data.get("nonce_cache_size", DEFAULT_NONCE_CACHE_SIZE)),
        )
        for raw in data.get("agents", []):
            card = PublicAgentCard.from_dict(raw)
            store._agents_by_name[card.agent_name] = card
            store._agents_by_id[card.agent_id] = card
        for raw in data.get("rotated_agents", []):
            card = PublicAgentCard.from_dict(raw)
            store._agents_by_id[card.agent_id] = card
        store._revoked = set(data.get("revoked", []))
        return store

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> TrustStore:
        return cls.from_dict(json.loads(Path(path).read_text()))
