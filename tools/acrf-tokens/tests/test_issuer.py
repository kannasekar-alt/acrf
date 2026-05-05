"""Tests for acrf_tokens.issuer"""
import json

import pytest
from acrf_tokens import AgentToken, TokenIssuer


def test_generate_creates_unique_issuers():
    a = TokenIssuer.generate(issuer_name="auth-a")
    b = TokenIssuer.generate(issuer_name="auth-b")
    assert a.issuer_id != b.issuer_id
    assert a.public_key_b64() != b.public_key_b64()


def test_issue_returns_wire_format():
    issuer = TokenIssuer.generate(issuer_name="auth")
    token_string = issuer.issue(
        agent_name="PricingAgent",
        scopes=["read"],
        ttl_seconds=60,
    )
    assert isinstance(token_string, str)
    assert "." in token_string


def test_issue_rejects_negative_ttl():
    issuer = TokenIssuer.generate(issuer_name="auth")
    with pytest.raises(ValueError):
        issuer.issue(agent_name="A", scopes=[], ttl_seconds=-1)


def test_issued_token_decodes_to_expected_claims():
    issuer = TokenIssuer.generate(issuer_name="auth")
    token_string = issuer.issue(
        agent_name="PricingAgent",
        scopes=["pricing:read", "trades:propose"],
        ttl_seconds=60,
        metadata={"team": "trading"},
    )
    agent_token, signed_bytes, signature_bytes = AgentToken.decode(token_string)
    assert agent_token.agent_name == "PricingAgent"
    assert agent_token.scopes == ["pricing:read", "trades:propose"]
    assert agent_token.metadata == {"team": "trading"}
    assert agent_token.issuer_name == "auth"


def test_issued_token_signature_verifies():
    issuer = TokenIssuer.generate(issuer_name="auth")
    token_string = issuer.issue(
        agent_name="A",
        scopes=["x"],
        ttl_seconds=60,
    )
    agent_token, signed_bytes, signature_bytes = AgentToken.decode(token_string)
    # Signature should verify against the issuer public key
    issuer.public_key.verify(signature_bytes, signed_bytes)


def test_save_and_load_private(tmp_path):
    issuer = TokenIssuer.generate(issuer_name="auth")
    path = tmp_path / "issuer.json"
    issuer.save(path)

    loaded = TokenIssuer.load(path)
    assert loaded.issuer_id == issuer.issuer_id
    assert loaded.public_key_b64() == issuer.public_key_b64()
    assert loaded.private_key_b64() == issuer.private_key_b64()


def test_save_public_strips_private_key(tmp_path):
    issuer = TokenIssuer.generate(issuer_name="auth")
    path = tmp_path / "public.json"
    issuer.save_public(path)
    data = json.loads(path.read_text())
    assert "private_key_b64" not in data
    assert "public_key_b64" in data
