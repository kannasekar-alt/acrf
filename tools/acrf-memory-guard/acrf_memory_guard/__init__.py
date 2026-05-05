"""
acrf-memory-guard
=================

Memory integrity verification for AI agents.
Implements the ACRF-04 (Memory Poisoning) defense pattern.

Quick start:

    from acrf_memory_guard import sign_entry, read_safe
    import os

    secret = os.environ["ACRF_MEMORY_SECRET"]

    # When writing to agent memory
    entry = {"user_id": "john", "role": "Junior Developer"}
    signed = sign_entry(entry, secret)
    memory_store.write(signed)

    # When reading from agent memory
    raw = memory_store.read("john")
    entry = read_safe(raw, secret)  # raises MemoryIntegrityError if tampered

If the entry has been tampered with after signing, read_safe raises
MemoryIntegrityError. Your application fails closed.

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
"""
from acrf_memory_guard.core import (
    MemoryIntegrityError,
    read_safe,
    sign_entry,
    verify_entry,
)

__version__ = "0.1.0"
__all__ = [
    "sign_entry",
    "verify_entry",
    "read_safe",
    "MemoryIntegrityError",
]
