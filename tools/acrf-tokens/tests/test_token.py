"""Tests for acrf_tokens.token"""
import time

import pytest
from acrf_tokens import AgentToken
from acrf_tokens.exceptions import InvalidTokenError


def test_token_has_scope():
    token = AgentToken(
        token_id="t1",
        agent_name="Agent",
        issuer_name="iss",
        scopes=["read", "write"],
        issued_at=time.time(),
        expires_at=time.time() + 60,
    )
    assert token.has_scope("read")
    assert token.has_scope("write")
    assert not token.has_scope("delete")


def test_token_is_expired_false_when_in_future():
    token = AgentToken(
        token_id="t1",
        agent_name="Agent",
        issuer_name="iss",
        scopes=[],
        issued_at=time.time(),
        expires_at=time.time() + 60,
    )
    assert not token.is_expired()


def test_token_is_expired_true_when_past():
    token = AgentToken(
        token_id="t1",
        agent_name="Agent",
        issuer_name="iss",
        scopes=[],
        issued_at=time.time() - 120,
        expires_at=time.time() - 60,
    )
    assert token.is_expired()


def test_claims_round_trip():
    original = AgentToken(
        token_id="t1",
        agent_name="Agent",
        issuer_name="iss",
        scopes=["read"],
        issued_at=1000.0,
        expires_at=2000.0,
        metadata={"team": "platform"},
    )
    claims = original.claims()
    restored = AgentToken.from_claims(claims)
    assert restored.token_id == original.token_id
    assert restored.scopes == original.scopes
    assert restored.metadata == original.metadata


def test_decode_rejects_malformed_string():
    with pytest.raises(InvalidTokenError):
        AgentToken.decode("not-a-valid-token")


def test_decode_rejects_garbage_after_separator():
    with pytest.raises(InvalidTokenError):
        AgentToken.decode("garbage.garbage")
