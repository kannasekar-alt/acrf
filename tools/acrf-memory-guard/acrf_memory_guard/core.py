"""
acrf-memory-guard core module.

Implements ACRF-04 defense pattern: memory poisoning.

The pattern:
1. Every memory entry is signed with HMAC-SHA256 when written
2. Signature is stored alongside the entry under "_integrity"
3. Every read recomputes the signature and compares
4. Tampered entries fail closed - never returned to the caller
"""
import hashlib
import hmac
import json
from typing import Any

INTEGRITY_FIELD = "_integrity"


class MemoryIntegrityError(Exception):
    """Raised when memory entry integrity verification fails."""


def _canonical_json(data: dict) -> bytes:
    """Produce deterministic JSON for signing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _compute_signature(data: dict, secret_key: bytes) -> str:
    """Compute HMAC-SHA256 signature for an entry."""
    canonical = _canonical_json(data)
    digest = hmac.new(secret_key, canonical, hashlib.sha256).hexdigest()
    return f"sha256:{digest}"


def sign_entry(entry: dict, secret_key: str | bytes) -> dict:
    """
    Sign a memory entry.

    Returns a new dict with the original entry plus an "_integrity" field.
    Does not mutate the input.

    Args:
        entry: The memory entry to sign
        secret_key: Secret key for signing (string or bytes)

    Returns:
        New dict containing all original fields plus "_integrity"
    """
    if isinstance(secret_key, str):
        secret_key = secret_key.encode()

    # Strip any existing signature before computing new one
    data = {k: v for k, v in entry.items() if k != INTEGRITY_FIELD}
    signature = _compute_signature(data, secret_key)
    data[INTEGRITY_FIELD] = signature
    return data


def verify_entry(entry: dict, secret_key: str | bytes) -> tuple[bool, str]:
    """
    Verify a memory entry without modifying it.

    Args:
        entry: The memory entry to verify
        secret_key: Secret key used to sign the entry

    Returns:
        Tuple of (is_valid, reason). reason is empty string when valid.
    """
    if isinstance(secret_key, str):
        secret_key = secret_key.encode()

    if not isinstance(entry, dict):
        return False, "Entry is not a dict"

    stored_signature = entry.get(INTEGRITY_FIELD)
    if not stored_signature:
        return False, f"No integrity signature found in entry (missing {INTEGRITY_FIELD} field)"

    data = {k: v for k, v in entry.items() if k != INTEGRITY_FIELD}
    expected_signature = _compute_signature(data, secret_key)

    if not hmac.compare_digest(stored_signature, expected_signature):
        return False, (
            f"Memory integrity check failed. "
            f"Expected: {expected_signature[:32]}... "
            f"Got: {stored_signature[:32]}... "
            f"Entry was modified after signing."
        )

    return True, ""


def read_safe(entry: dict, secret_key: str | bytes) -> dict[str, Any]:
    """
    Verify and return a memory entry safely.

    This is the main entry point for production use. Verifies the
    integrity signature before returning the entry. Fails closed
    if signature is missing or invalid.

    Args:
        entry: The signed memory entry
        secret_key: Secret key used to sign the entry

    Returns:
        The entry dict (with _integrity field stripped)

    Raises:
        MemoryIntegrityError: If the entry has no signature or the signature
                              does not match.
    """
    valid, reason = verify_entry(entry, secret_key)
    if not valid:
        raise MemoryIntegrityError(reason)

    return {k: v for k, v in entry.items() if k != INTEGRITY_FIELD}
