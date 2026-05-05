"""Tests for acrf_safety_shield.credentials"""
import json

from acrf_safety_shield import AdminCredential, AgentCredential, PublicAdminCard


def test_generate_admin_creates_unique_ids():
    a = AdminCredential.generate(admin_name="security")
    b = AdminCredential.generate(admin_name="security")
    assert a.admin_id != b.admin_id
    assert a.public_key_b64() != b.public_key_b64()


def test_admin_save_and_load_round_trip(tmp_path):
    admin = AdminCredential.generate(admin_name="security-team")
    path = tmp_path / "admin_private.json"
    admin.save_private(path)

    loaded = AdminCredential.load_private(path)
    assert loaded.admin_id == admin.admin_id
    assert loaded.admin_name == admin.admin_name
    assert loaded.public_key_b64() == admin.public_key_b64()
    assert loaded.private_key_b64() == admin.private_key_b64()


def test_public_card_strips_private_key(tmp_path):
    admin = AdminCredential.generate(admin_name="security")
    public = admin.public_card()
    path = tmp_path / "admin_public.json"
    public.save_to(path)

    raw = json.loads(path.read_text())
    assert "private_key_b64" not in raw
    assert "public_key_b64" in raw


def test_admin_can_sign_and_public_can_verify(tmp_path):
    admin = AdminCredential.generate(admin_name="security")
    payload = {"operation": "set_guardrail", "key": "max_trade", "value": 1000}
    signature = admin.sign(payload)
    assert signature  # base64 string

    # Verify via the public card path
    public = admin.public_card()
    public_key = public.public_key()
    import base64

    from acrf_safety_shield.credentials import _canonical_json

    sig_bytes = base64.b64decode(signature.encode("ascii"))
    public_key.verify(sig_bytes, _canonical_json(payload))  # should not raise


def test_public_admin_card_round_trip(tmp_path):
    admin = AdminCredential.generate(admin_name="security")
    public_path = tmp_path / "p.json"
    admin.public_card().save_to(public_path)
    loaded = PublicAdminCard.load(public_path)
    assert loaded.admin_id == admin.admin_id


def test_agent_credential_simple():
    agent = AgentCredential(agent_name="PricingAgent", token="agt_xxx")
    assert agent.agent_name == "PricingAgent"
    assert agent.token == "agt_xxx"
    assert agent.to_dict()["agent_name"] == "PricingAgent"
