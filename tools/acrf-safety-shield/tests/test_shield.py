"""Tests for acrf_safety_shield.shield"""
import pytest
from acrf_safety_shield import (
    AdminCredential,
    AgentCredential,
    PrivilegeError,
    SafetyShield,
    UnknownAdminError,
)


def _bootstrap():
    admin = AdminCredential.generate(admin_name="security-team")
    shield = SafetyShield()
    shield.trust_admin(admin.public_card())
    return shield, admin


# ----------------------------------------------------------------------
# Privilege isolation - the core ACRF-10 property
# ----------------------------------------------------------------------

def test_agent_cannot_set_guardrail():
    shield, admin = _bootstrap()
    agent = AgentCredential(agent_name="PricingAgent", token="agt_xxx")
    with pytest.raises(PrivilegeError):
        shield.set_guardrail("max_trade", 1000, signer=agent)


def test_agent_cannot_delete_guardrail():
    shield, admin = _bootstrap()
    shield.set_guardrail("max_trade", 1000, signer=admin)

    agent = AgentCredential(agent_name="PricingAgent", token="agt_xxx")
    with pytest.raises(PrivilegeError):
        shield.delete_guardrail("max_trade", signer=agent)


def test_agent_can_read_guardrail():
    shield, admin = _bootstrap()
    shield.set_guardrail("max_trade", 1000, signer=admin)

    agent = AgentCredential(agent_name="PricingAgent", token="agt_xxx")
    assert shield.get_guardrail("max_trade", agent) == 1000


def test_agent_can_list_guardrails():
    shield, admin = _bootstrap()
    shield.set_guardrail("a", 1, signer=admin)
    shield.set_guardrail("b", 2, signer=admin)

    agent = AgentCredential(agent_name="agent", token="t")
    state = shield.list_guardrails(agent)
    assert state == {"a": 1, "b": 2}


# ----------------------------------------------------------------------
# Admin happy path
# ----------------------------------------------------------------------

def test_admin_can_set_and_delete():
    shield, admin = _bootstrap()
    shield.set_guardrail("max_trade", 1000, signer=admin)
    assert shield.get_guardrail("max_trade", admin) == 1000

    shield.delete_guardrail("max_trade", signer=admin)
    assert shield.get_guardrail("max_trade", admin) is None


def test_admin_must_be_in_trust_set():
    shield, _ = _bootstrap()
    rogue = AdminCredential.generate(admin_name="rogue")
    with pytest.raises(UnknownAdminError):
        shield.set_guardrail("x", 1, signer=rogue)


# ----------------------------------------------------------------------
# Two-person rule
# ----------------------------------------------------------------------

def test_high_risk_key_with_two_admins_required():
    shield, admin1 = _bootstrap()
    admin2 = AdminCredential.generate(admin_name="security-2")
    shield.trust_admin(admin2.public_card())
    shield.set_required_approvals(2)
    shield.declare_high_risk("kill_switch")

    # First admin requests change - returns pending change_id
    change_id = shield.set_guardrail("kill_switch", "armed", signer=admin1)
    assert change_id is not None
    assert shield.get_guardrail("kill_switch", admin1) is None

    # Same admin cannot self-approve
    applied = shield.approve_pending(change_id, signer=admin1)
    assert applied is False
    assert shield.get_guardrail("kill_switch", admin1) is None

    # Second admin approves - applied
    applied = shield.approve_pending(change_id, signer=admin2)
    assert applied is True
    assert shield.get_guardrail("kill_switch", admin1) == "armed"


def test_low_risk_key_with_two_required_still_immediate():
    """Low-risk keys ignore the required_approvals threshold."""
    shield, admin = _bootstrap()
    shield.set_required_approvals(2)
    # max_trade is NOT declared high risk
    result = shield.set_guardrail("max_trade", 1000, signer=admin)
    assert result is None
    assert shield.get_guardrail("max_trade", admin) == 1000


# ----------------------------------------------------------------------
# Audit log
# ----------------------------------------------------------------------

def test_denied_attempt_is_logged():
    shield, admin = _bootstrap()
    agent = AgentCredential(agent_name="PricingAgent", token="agt_xxx")
    with pytest.raises(PrivilegeError):
        shield.set_guardrail("max_trade", 1000, signer=agent)
    log = shield.audit_log()
    assert any(r["result"] == "denied" for r in log)
    assert any(r["actor_type"] == "agent" for r in log)


def test_successful_set_is_logged():
    shield, admin = _bootstrap()
    shield.set_guardrail("max_trade", 1000, signer=admin)
    log = shield.audit_log()
    assert any(
        r["operation"] == "set_guardrail" and r["key"] == "max_trade" and r["result"] == "ok"
        for r in log
    )


def test_read_is_logged():
    shield, admin = _bootstrap()
    shield.set_guardrail("max_trade", 1000, signer=admin)
    agent = AgentCredential(agent_name="PricingAgent", token="agt_xxx")
    shield.get_guardrail("max_trade", agent)
    log = shield.audit_log()
    assert any(r["operation"] == "get_guardrail" and r["actor_type"] == "agent" for r in log)


# ----------------------------------------------------------------------
# Persistence
# ----------------------------------------------------------------------

def test_save_and_load_round_trip(tmp_path):
    shield, admin = _bootstrap()
    shield.set_guardrail("max_trade", 1000, signer=admin)
    shield.declare_high_risk("kill_switch")

    path = tmp_path / "shield.json"
    shield.save(path)

    loaded = SafetyShield.load(path)
    assert loaded.get_guardrail("max_trade", admin) == 1000
    assert "kill_switch" in loaded._high_risk_keys


# ----------------------------------------------------------------------
# Trust management
# ----------------------------------------------------------------------

def test_revoke_admin_requires_admin_credential():
    shield, admin = _bootstrap()
    other = AdminCredential.generate(admin_name="other")
    shield.trust_admin(other.public_card())

    # Agent cannot revoke
    agent = AgentCredential(agent_name="x", token="t")
    with pytest.raises(PrivilegeError):
        shield.revoke_admin(other.admin_id, signer=agent)

    # Admin can revoke
    shield.revoke_admin(other.admin_id, signer=admin)
    assert other.admin_id not in shield.trusted_admin_ids()


def test_set_required_approvals_validates():
    shield, _ = _bootstrap()
    with pytest.raises(ValueError):
        shield.set_required_approvals(0)
