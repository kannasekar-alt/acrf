"""Tests for acrf_tokens.validator"""
import time

import pytest
from acrf_tokens import TokenIssuer, TokenValidator
from acrf_tokens.exceptions import (
    InvalidTokenError,
    TokenExpiredError,
    TokenRevokedError,
    TokenScopeError,
)


def _make_pair(issuer_name="auth"):
    issuer = TokenIssuer.generate(issuer_name=issuer_name)
    validator = TokenValidator.from_public_card(issuer.public_card())
    return issuer, validator


def test_validate_passes_for_fresh_token():
    issuer, validator = _make_pair()
    token = issuer.issue(agent_name="A", scopes=["read"], ttl_seconds=60)
    agent_token = validator.validate(token)
    assert agent_token.agent_name == "A"
    assert agent_token.has_scope("read")


def test_validate_fails_when_signed_by_other_issuer():
    issuer_good, validator = _make_pair(issuer_name="good")
    issuer_bad = TokenIssuer.generate(issuer_name="bad")

    bad_token = issuer_bad.issue(agent_name="A", scopes=["read"], ttl_seconds=60)
    with pytest.raises(InvalidTokenError):
        validator.validate(bad_token)


def test_validate_fails_when_token_expired():
    issuer, validator = _make_pair()
    token = issuer.issue(agent_name="A", scopes=["read"], ttl_seconds=0.01)
    time.sleep(0.05)
    with pytest.raises(TokenExpiredError):
        validator.validate(token)


def test_validate_fails_when_token_revoked():
    issuer, validator = _make_pair()
    token = issuer.issue(agent_name="A", scopes=["read"], ttl_seconds=60)

    # Decode to get the token id
    agent_token = validator.validate(token)
    validator.revoke(agent_token.token_id)

    with pytest.raises(TokenRevokedError):
        validator.validate(token)


def test_validate_fails_when_required_scope_missing():
    issuer, validator = _make_pair()
    token = issuer.issue(agent_name="A", scopes=["read"], ttl_seconds=60)
    with pytest.raises(TokenScopeError):
        validator.validate(token, required_scope="write")


def test_validate_passes_when_required_scope_present():
    issuer, validator = _make_pair()
    token = issuer.issue(agent_name="A", scopes=["read", "write"], ttl_seconds=60)
    agent_token = validator.validate(token, required_scope="write")
    assert agent_token.has_scope("write")


def test_validate_rejects_malformed_token():
    _, validator = _make_pair()
    with pytest.raises(InvalidTokenError):
        validator.validate("not-a-valid-token")


def test_audit_log_records_success():
    issuer, validator = _make_pair()
    token = issuer.issue(agent_name="A", scopes=["read"], ttl_seconds=60)
    validator.validate(token)
    log = validator.audit_log()
    assert len(log) == 1
    assert log[0]["result"] == "success"
    assert log[0]["agent_name"] == "A"


def test_audit_log_records_failure():
    issuer, validator = _make_pair()
    token = issuer.issue(agent_name="A", scopes=["read"], ttl_seconds=0.01)
    time.sleep(0.05)
    with pytest.raises(TokenExpiredError):
        validator.validate(token)
    log = validator.audit_log()
    assert len(log) == 1
    assert log[0]["result"] == "expired"


def test_save_and_load_revocations(tmp_path):
    issuer, validator = _make_pair()
    token = issuer.issue(agent_name="A", scopes=["read"], ttl_seconds=60)
    agent_token = validator.validate(token)
    validator.revoke(agent_token.token_id)

    public_path = tmp_path / "public.json"
    issuer.save_public(public_path)

    revocations_path = tmp_path / "revocations.json"
    validator.save_revocations(revocations_path)

    loaded = TokenValidator.load_with_revocations(public_path, revocations_path)
    assert loaded.is_revoked(agent_token.token_id)


def test_load_with_revocations_handles_missing_file(tmp_path):
    issuer = TokenIssuer.generate(issuer_name="auth")
    public_path = tmp_path / "public.json"
    issuer.save_public(public_path)
    nonexistent = tmp_path / "nonexistent.json"

    validator = TokenValidator.load_with_revocations(public_path, nonexistent)
    assert validator.revoked_token_ids() == []
