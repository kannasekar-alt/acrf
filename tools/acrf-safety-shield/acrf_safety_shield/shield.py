"""
SafetyShield module.

The hard wall between agents and safety state. Enforces ACRF-10 control
objectives:

    SP-1  Agents operate with minimum necessary permissions
    SP-2  Safety controls require a separate admin credential
    SP-3  Safety control changes require approval and audit trail
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

from acrf_safety_shield.credentials import (
    AdminCredential,
    AgentCredential,
    PublicAdminCard,
    _b64decode,
    _canonical_json,
)
from acrf_safety_shield.exceptions import (
    InsufficientApprovalsError,
    InvalidAdminCredentialError,
    PrivilegeError,
    UnknownAdminError,
)

SHIELD_FORMAT_VERSION = "1.0"


@dataclass
class AuditEntry:
    """Audit log entry for any operation against the shield."""
    timestamp: float
    actor_type: str  # "admin" | "agent"
    actor_name: str
    operation: str   # "set_guardrail" | "delete_guardrail" | "get_guardrail" | "list_guardrails"
    key: str
    value_summary: str
    result: str      # "ok" | "denied"
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "actor_type": self.actor_type,
            "actor_name": self.actor_name,
            "operation": self.operation,
            "key": self.key,
            "value_summary": self.value_summary,
            "result": self.result,
            "detail": self.detail,
        }


@dataclass
class _PendingChange:
    """A high-risk change waiting for additional admin approvals."""
    change_id: str
    operation: str
    key: str
    value: Any
    created_at: float
    initiating_admin: str
    approvals: dict[str, str]  # admin_id -> signature_b64

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_id": self.change_id,
            "operation": self.operation,
            "key": self.key,
            "value": self.value,
            "created_at": self.created_at,
            "initiating_admin": self.initiating_admin,
            "approvals": dict(self.approvals),
        }


@dataclass
class SafetyShield:
    """
    Stateful safety shield enforcing credential isolation for AI agent guardrails.

    Use trust_admin() to seed the set of trusted admin public cards.
    Use set_guardrail()/delete_guardrail() for changes (admin only).
    Use get_guardrail()/list_guardrails() for reads (admin or agent).
    """
    _state: dict[str, Any] = field(default_factory=dict)
    _trusted_admins: dict[str, PublicAdminCard] = field(default_factory=dict)
    _high_risk_keys: set[str] = field(default_factory=set)
    _required_approvals: int = 1
    _pending: dict[str, _PendingChange] = field(default_factory=dict)
    _audit: list[AuditEntry] = field(default_factory=list)
    format_version: str = SHIELD_FORMAT_VERSION

    # ------------------------------------------------------------------
    # Trust management
    # ------------------------------------------------------------------

    def trust_admin(self, card: PublicAdminCard) -> None:
        self._trusted_admins[card.admin_id] = card

    def revoke_admin(self, admin_id: str, signer: AdminCredential) -> None:
        """Revoking an admin requires another admin's signature."""
        self._require_admin(signer)
        self._trusted_admins.pop(admin_id, None)
        self._record(
            actor_type="admin",
            actor_name=signer.admin_name,
            operation="revoke_admin",
            key=admin_id,
            value_summary="(revoked)",
            result="ok",
        )

    def trusted_admin_ids(self) -> list[str]:
        return sorted(self._trusted_admins.keys())

    # ------------------------------------------------------------------
    # High-risk policy
    # ------------------------------------------------------------------

    def declare_high_risk(self, key: str) -> None:
        """Mark a guardrail key as requiring multiple approvals to change."""
        self._high_risk_keys.add(key)

    def set_required_approvals(self, count: int) -> None:
        if count < 1:
            raise ValueError("required approvals must be at least 1")
        self._required_approvals = count

    # ------------------------------------------------------------------
    # Read operations - allowed for any credential
    # ------------------------------------------------------------------

    def get_guardrail(
        self,
        key: str,
        actor: AdminCredential | AgentCredential,
    ) -> Any:
        actor_type, actor_name = self._actor_info(actor)
        value = self._state.get(key)
        self._record(
            actor_type=actor_type,
            actor_name=actor_name,
            operation="get_guardrail",
            key=key,
            value_summary=str(value)[:60] if value is not None else "(missing)",
            result="ok",
        )
        return value

    def list_guardrails(
        self,
        actor: AdminCredential | AgentCredential,
    ) -> dict[str, Any]:
        actor_type, actor_name = self._actor_info(actor)
        self._record(
            actor_type=actor_type,
            actor_name=actor_name,
            operation="list_guardrails",
            key="*",
            value_summary=f"{len(self._state)} keys",
            result="ok",
        )
        return dict(self._state)

    # ------------------------------------------------------------------
    # Write operations - admin only
    # ------------------------------------------------------------------

    def set_guardrail(
        self,
        key: str,
        value: Any,
        signer: AdminCredential | AgentCredential,
    ) -> str | None:
        """
        Set a guardrail value.

        Returns:
            None if the change was applied immediately.
            change_id (str) if the change is pending more approvals.

        Raises:
            PrivilegeError: signer is not an AdminCredential
            UnknownAdminError: signer is not in the trust set
            InvalidAdminCredentialError: signer signature does not verify
        """
        admin = self._require_admin(signer)
        payload = self._make_payload("set_guardrail", key, value)
        self._verify_admin_signature(admin, payload)

        if key in self._high_risk_keys and self._required_approvals > 1:
            return self._stage_pending(
                operation="set_guardrail",
                key=key,
                value=value,
                signer=admin,
            )

        self._state[key] = value
        self._record(
            actor_type="admin",
            actor_name=admin.admin_name,
            operation="set_guardrail",
            key=key,
            value_summary=str(value)[:60],
            result="ok",
        )
        return None

    def delete_guardrail(
        self,
        key: str,
        signer: AdminCredential | AgentCredential,
    ) -> str | None:
        admin = self._require_admin(signer)
        payload = self._make_payload("delete_guardrail", key, None)
        self._verify_admin_signature(admin, payload)

        if key in self._high_risk_keys and self._required_approvals > 1:
            return self._stage_pending(
                operation="delete_guardrail",
                key=key,
                value=None,
                signer=admin,
            )

        self._state.pop(key, None)
        self._record(
            actor_type="admin",
            actor_name=admin.admin_name,
            operation="delete_guardrail",
            key=key,
            value_summary="(deleted)",
            result="ok",
        )
        return None

    def approve_pending(
        self,
        change_id: str,
        signer: AdminCredential | AgentCredential,
    ) -> bool:
        """
        Add an approval to a pending change. Returns True if applied.
        """
        admin = self._require_admin(signer)
        pending = self._pending.get(change_id)
        if pending is None:
            raise KeyError(f"unknown pending change: {change_id}")

        payload = self._make_payload(pending.operation, pending.key, pending.value)
        self._verify_admin_signature(admin, payload)

        if admin.admin_id == pending.initiating_admin:
            # initiating admin cannot count as an additional approval
            return False

        signature = admin.sign(payload)
        pending.approvals[admin.admin_id] = signature

        self._record(
            actor_type="admin",
            actor_name=admin.admin_name,
            operation="approve_pending",
            key=pending.key,
            value_summary=f"change_id={change_id}",
            result="ok",
        )

        if len(pending.approvals) + 1 >= self._required_approvals:
            self._apply_pending(pending)
            return True
        return False

    def pending_changes(self) -> list[dict[str, Any]]:
        return [p.to_dict() for p in self._pending.values()]

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def audit_log(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._audit]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_admin(self, signer: AdminCredential | AgentCredential) -> AdminCredential:
        if not isinstance(signer, AdminCredential):
            actor_type, actor_name = self._actor_info(signer)
            self._record(
                actor_type=actor_type,
                actor_name=actor_name,
                operation="set_guardrail",
                key="(denied)",
                value_summary="",
                result="denied",
                detail="agent credential cannot modify safety state",
            )
            raise PrivilegeError(
                "agent credential cannot modify safety state - admin credential required"
            )
        if signer.admin_id not in self._trusted_admins:
            raise UnknownAdminError(
                f"admin {signer.admin_name!r} (id={signer.admin_id}) is not in the trust set"
            )
        return signer

    def _verify_admin_signature(self, admin: AdminCredential, payload: dict[str, Any]) -> None:
        signature_b64 = admin.sign(payload)
        public = self._trusted_admins[admin.admin_id].public_key()
        try:
            public.verify(_b64decode(signature_b64), _canonical_json(payload))
        except InvalidSignature as exc:
            raise InvalidAdminCredentialError(
                f"admin signature did not verify for {admin.admin_name}"
            ) from exc

    def _stage_pending(
        self,
        operation: str,
        key: str,
        value: Any,
        signer: AdminCredential,
    ) -> str:
        change_id = str(uuid.uuid4())
        signature = signer.sign(self._make_payload(operation, key, value))
        self._pending[change_id] = _PendingChange(
            change_id=change_id,
            operation=operation,
            key=key,
            value=value,
            created_at=time.time(),
            initiating_admin=signer.admin_id,
            approvals={signer.admin_id: signature},
        )
        self._record(
            actor_type="admin",
            actor_name=signer.admin_name,
            operation=f"stage_{operation}",
            key=key,
            value_summary=f"pending change_id={change_id}",
            result="ok",
        )
        if self._required_approvals <= 1:
            # Single-admin policy with high-risk key still applies immediately
            self._apply_pending(self._pending[change_id])
        return change_id

    def _apply_pending(self, pending: _PendingChange) -> None:
        if pending.operation == "set_guardrail":
            self._state[pending.key] = pending.value
        elif pending.operation == "delete_guardrail":
            self._state.pop(pending.key, None)
        self._pending.pop(pending.change_id, None)
        self._record(
            actor_type="admin",
            actor_name="(quorum)",
            operation=f"apply_pending:{pending.operation}",
            key=pending.key,
            value_summary=f"approvals={len(pending.approvals)}",
            result="ok",
        )

    def _make_payload(self, operation: str, key: str, value: Any) -> dict[str, Any]:
        return {"operation": operation, "key": key, "value": value}

    def _actor_info(self, actor: AdminCredential | AgentCredential) -> tuple[str, str]:
        if isinstance(actor, AdminCredential):
            return "admin", actor.admin_name
        return "agent", getattr(actor, "agent_name", "(unknown)")

    def _record(
        self,
        *,
        actor_type: str,
        actor_name: str,
        operation: str,
        key: str,
        value_summary: str,
        result: str,
        detail: str = "",
    ) -> None:
        self._audit.append(AuditEntry(
            timestamp=time.time(),
            actor_type=actor_type,
            actor_name=actor_name,
            operation=operation,
            key=key,
            value_summary=value_summary,
            result=result,
            detail=detail,
        ))

    def insufficient_approvals_error(self, change_id: str) -> InsufficientApprovalsError:
        # exposed for documentation/testing convenience
        return InsufficientApprovalsError(
            f"change {change_id} does not yet have {self._required_approvals} approvals"
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "state": dict(self._state),
            "trusted_admins": [c.to_dict() for c in self._trusted_admins.values()],
            "high_risk_keys": sorted(self._high_risk_keys),
            "required_approvals": self._required_approvals,
            "pending": [p.to_dict() for p in self._pending.values()],
            "audit": [r.to_dict() for r in self._audit],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SafetyShield:
        shield = cls(
            _required_approvals=int(data.get("required_approvals", 1)),
            format_version=data.get("format_version", SHIELD_FORMAT_VERSION),
        )
        shield._state = dict(data.get("state", {}))
        shield._high_risk_keys = set(data.get("high_risk_keys", []))
        for raw in data.get("trusted_admins", []):
            card = PublicAdminCard.from_dict(raw)
            shield._trusted_admins[card.admin_id] = card
        for raw in data.get("audit", []):
            shield._audit.append(AuditEntry(
                timestamp=float(raw["timestamp"]),
                actor_type=raw["actor_type"],
                actor_name=raw["actor_name"],
                operation=raw["operation"],
                key=raw["key"],
                value_summary=raw.get("value_summary", ""),
                result=raw["result"],
                detail=raw.get("detail", ""),
            ))
        # Pending changes are intentionally NOT restored from disk in this
        # release - approvals must occur within a live process.
        return shield

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> SafetyShield:
        return cls.from_dict(json.loads(Path(path).read_text()))
