"""
acrf-safety-shield
==================

Safety control credential isolation for AI agents.
Implements the ACRF-10 (Safety Controls Not Self-Protecting) defense pattern.

Quick start:

    from acrf_safety_shield import (
        SafetyShield,
        AdminCredential,
        AgentCredential,
    )

    # One-time bootstrap by the ops/security team via secure channel
    admin = AdminCredential.generate(admin_name="security-team")
    admin.save_private("admin_private.json")          # KEEP OFFLINE
    admin.public_card().save_to("admin_public.json")  # share with shield

    shield = SafetyShield()
    shield.trust_admin(admin.public_card())
    shield.set_guardrail("max_trade_amount", 1000, signer=admin)

    # Agent operations - read allowed, write rejected
    agent = AgentCredential(agent_name="PricingAgent", token="agt_xxx")
    shield.get_guardrail("max_trade_amount", agent)  # OK -> 1000

    try:
        shield.set_guardrail("max_trade_amount", 999999, signer=agent)
    except PrivilegeError:
        # Agent cannot modify safety state. Only admin can.
        ...

Security features:

    - Two distinct credential types: AdminCredential (Ed25519) and AgentCredential
    - Hard wall: agents can READ safety state but cannot MODIFY it
    - Every modification requires an admin Ed25519 signature
    - Two-person rule support for high-risk keys
    - Tamper-evident audit log of every operation
    - Emergency revocation requires an admin credential

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
"""
from acrf_safety_shield.credentials import (
    AdminCredential,
    AgentCredential,
    PublicAdminCard,
)
from acrf_safety_shield.exceptions import (
    InsufficientApprovalsError,
    InvalidAdminCredentialError,
    PrivilegeError,
    SafetyShieldError,
    UnknownAdminError,
)
from acrf_safety_shield.shield import (
    AuditEntry,
    SafetyShield,
)

__version__ = "0.1.0"
__all__ = [
    "SafetyShield",
    "AdminCredential",
    "AgentCredential",
    "PublicAdminCard",
    "AuditEntry",
    "SafetyShieldError",
    "PrivilegeError",
    "InsufficientApprovalsError",
    "InvalidAdminCredentialError",
    "UnknownAdminError",
]
