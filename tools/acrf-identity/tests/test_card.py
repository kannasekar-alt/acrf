"""Tests for acrf_identity.card"""
import json

from acrf_identity import AgentCard, PublicAgentCard


def test_generate_creates_unique_identities():
    card1 = AgentCard.generate(agent_name="Agent1")
    card2 = AgentCard.generate(agent_name="Agent2")
    assert card1.agent_id != card2.agent_id
    assert card1.public_key_b64() != card2.public_key_b64()


def test_generate_includes_metadata():
    card = AgentCard.generate(
        agent_name="PricingAgent",
        organization="acme",
        metadata={"version": "1.0", "team": "trading"}
    )
    assert card.agent_name == "PricingAgent"
    assert card.organization == "acme"
    assert card.metadata["version"] == "1.0"
    assert card.metadata["team"] == "trading"


def test_public_only_strips_private_key():
    card = AgentCard.generate(agent_name="Agent1")
    public = card.public_only()
    assert isinstance(public, PublicAgentCard)
    assert public.agent_id == card.agent_id
    assert public.agent_name == card.agent_name
    assert public.public_key_b64 == card.public_key_b64()


def test_save_and_load_private_card(tmp_path):
    card = AgentCard.generate(agent_name="Agent1", organization="acme")
    path = tmp_path / "agent.json"
    card.save(path)

    loaded = AgentCard.load(path)
    assert loaded.agent_id == card.agent_id
    assert loaded.agent_name == card.agent_name
    assert loaded.public_key_b64() == card.public_key_b64()
    assert loaded.private_key_b64() == card.private_key_b64()


def test_save_and_load_public_card(tmp_path):
    card = AgentCard.generate(agent_name="Agent1")
    public = card.public_only()
    path = tmp_path / "public.json"
    public.save(path)

    loaded = PublicAgentCard.load(path)
    assert loaded.agent_id == public.agent_id
    assert loaded.public_key_b64 == public.public_key_b64


def test_public_card_does_not_contain_private_key(tmp_path):
    card = AgentCard.generate(agent_name="Agent1")
    public_path = tmp_path / "public.json"
    card.public_only().save(public_path)

    raw = json.loads(public_path.read_text())
    assert "private_key_b64" not in raw


def test_public_key_is_valid_ed25519():
    card = AgentCard.generate(agent_name="Agent1")
    public = card.public_only()
    # Should not raise
    pk = public.public_key()
    assert pk is not None


def test_format_version_set():
    card = AgentCard.generate(agent_name="Agent1")
    assert card.format_version == "1.0"
    assert card.public_only().format_version == "1.0"
