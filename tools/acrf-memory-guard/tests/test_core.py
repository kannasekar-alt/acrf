"""Tests for acrf_memory_guard.core"""
import pytest
from acrf_memory_guard import (
    MemoryIntegrityError,
    read_safe,
    sign_entry,
    verify_entry,
)

SECRET = "test-secret-key-do-not-use-in-production"


def test_sign_adds_integrity_field():
    entry = {"user_id": "john", "role": "Junior Dev"}
    signed = sign_entry(entry, SECRET)
    assert "_integrity" in signed
    assert signed["_integrity"].startswith("sha256:")


def test_sign_does_not_mutate_original():
    entry = {"user_id": "john"}
    sign_entry(entry, SECRET)
    assert "_integrity" not in entry


def test_sign_preserves_original_fields():
    entry = {"user_id": "john", "role": "Junior Dev", "team": "platform"}
    signed = sign_entry(entry, SECRET)
    assert signed["user_id"] == "john"
    assert signed["role"] == "Junior Dev"
    assert signed["team"] == "platform"


def test_verify_passes_for_signed_entry():
    signed = sign_entry({"user_id": "john"}, SECRET)
    valid, reason = verify_entry(signed, SECRET)
    assert valid is True
    assert reason == ""


def test_verify_fails_when_unsigned():
    valid, reason = verify_entry({"user_id": "john"}, SECRET)
    assert valid is False
    assert "No integrity signature" in reason


def test_verify_fails_when_tampered():
    signed = sign_entry({"user_id": "john", "role": "Junior Dev"}, SECRET)
    # Tamper - escalate role
    signed["role"] = "SysAdmin"
    valid, reason = verify_entry(signed, SECRET)
    assert valid is False
    assert "integrity check failed" in reason


def test_verify_fails_with_wrong_secret():
    signed = sign_entry({"user_id": "john"}, SECRET)
    valid, reason = verify_entry(signed, "different-secret")
    assert valid is False
    assert "integrity check failed" in reason


def test_read_safe_returns_entry_when_valid():
    signed = sign_entry({"user_id": "john", "role": "Junior Dev"}, SECRET)
    entry = read_safe(signed, SECRET)
    assert "_integrity" not in entry
    assert entry["user_id"] == "john"
    assert entry["role"] == "Junior Dev"


def test_read_safe_raises_when_tampered():
    signed = sign_entry({"user_id": "john", "role": "Junior Dev"}, SECRET)
    signed["role"] = "SysAdmin"
    with pytest.raises(MemoryIntegrityError):
        read_safe(signed, SECRET)


def test_read_safe_raises_when_missing_signature():
    with pytest.raises(MemoryIntegrityError) as exc_info:
        read_safe({"user_id": "john"}, SECRET)
    assert "No integrity signature" in str(exc_info.value)


def test_verify_fails_when_not_a_dict():
    valid, reason = verify_entry("not a dict", SECRET)
    assert valid is False
    assert "not a dict" in reason


def test_sign_strips_existing_integrity_before_resigning():
    """Signing twice with same content should produce the same signature."""
    entry = {"user_id": "john"}
    sig1 = sign_entry(entry, SECRET)["_integrity"]
    sig2 = sign_entry(sign_entry(entry, SECRET), SECRET)["_integrity"]
    assert sig1 == sig2


def test_sign_accepts_bytes_secret():
    signed = sign_entry({"user_id": "john"}, SECRET.encode())
    valid, _ = verify_entry(signed, SECRET.encode())
    assert valid is True


def test_sign_string_or_bytes_produces_same_signature():
    sig_str = sign_entry({"user_id": "john"}, SECRET)["_integrity"]
    sig_bytes = sign_entry({"user_id": "john"}, SECRET.encode())["_integrity"]
    assert sig_str == sig_bytes


def test_canonical_json_handles_key_order():
    """Same data with different key order should produce same signature."""
    sig_a = sign_entry({"a": 1, "b": 2}, SECRET)["_integrity"]
    sig_b = sign_entry({"b": 2, "a": 1}, SECRET)["_integrity"]
    assert sig_a == sig_b
