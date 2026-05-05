# acrf-memory-guard

Memory integrity verification for AI agents.
Implements the ACRF-04 (Memory Poisoning) defense pattern.

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
PyPI: https://pypi.org/project/acrf-memory-guard/
Presented at RSA Conference 2026.

---

## Try it in your environment right now

No Docker. No setup. Just Python 3.10+.

**Step 1 - Install:**

    pip install acrf-memory-guard

**Step 2 - Sign every memory write:**

    from acrf_memory_guard import sign_entry
    import os

    secret = os.environ["ACRF_MEMORY_SECRET"]
    entry = {"user_id": "john", "role": "Junior Developer"}
    signed = sign_entry(entry, secret)
    memory_store.write(signed)

**Step 3 - Verify on every memory read:**

    from acrf_memory_guard import read_safe
    import os

    secret = os.environ["ACRF_MEMORY_SECRET"]
    raw = memory_store.read("john")
    entry = read_safe(raw, secret)

If the entry has been modified between sign and read,
read_safe raises MemoryIntegrityError. Your application fails closed.

---

## The problem this solves

AI agents often store user profiles, session state, or contextual
information in memory stores. If an attacker tampers with these entries,
they can manipulate agent decisions.

Example:

- Agent stores: {"user_id": "john", "role": "Junior Developer"}
- Attacker modifies to: {"user_id": "john", "role": "SysAdmin"}
- Next time the agent reads memory, it grants admin access to John

This is ACRF-04: memory poisoning.

acrf-memory-guard makes every memory entry tamper-evident.
A signed entry that has been modified will not load.

---

## CLI - verify a memory store

Set your secret once:

    export ACRF_MEMORY_SECRET="your-secret-from-vault"

Verify all entries in a JSON memory store:

    acrf-memory-guard verify-store memory_store.json

Output when valid:

    OK: 5 entries verified

Output when tampered:

    FAIL: 1 of 5 entries failed integrity check
      john: Memory integrity check failed.
        Expected: sha256:9f4a2b8c1e6d3f7a0b5c9e2d4...
        Got: sha256:6343536004920d0fe642b02ca...

---

## How it works

1. sign_entry computes HMAC-SHA256 over the canonical JSON of the entry
2. The signature is stored in the entry under the "_integrity" field
3. read_safe recomputes the signature with the same secret
4. Match means the entry is byte-identical to what was signed
5. Mismatch means the entry was modified - MemoryIntegrityError raised

The defense is fail-closed. A tampered or unsigned entry never loads.

---

## What goes in the secret key

In production:

- AWS Secrets Manager / Azure Key Vault / GCP Secret Manager
- HashiCorp Vault
- Kubernetes secrets mounted at runtime

What NOT to do:

- Hardcode it in source code
- Store it alongside the memory data
- Use a short or guessable string

---

## Real-world use

Wrap your memory store with two helper functions:

    from acrf_memory_guard import sign_entry, read_safe
    import os

    SECRET = os.environ["ACRF_MEMORY_SECRET"]

    def write_memory(store, key, entry):
        store[key] = sign_entry(entry, SECRET)

    def read_memory(store, key):
        return read_safe(store[key], SECRET)

That is it. Every memory operation is now integrity-protected.
A tampered entry will never reach your agent decision logic.

---

## ACRF-04 control objectives addressed

    MP-1  All memory writes signed with a tamper-evident hash
    MP-2  Memory reads validated against signature before being used in decisions
    MP-3  Deny-by-default on signature mismatch

---

## What this library does NOT do

- It does not encrypt the entry
- It does not authenticate the user reading the entry
- It does not protect against rollback to a different signed version

It only ensures that the entry you read is byte-identical to the
entry you signed. That is the ACRF-04 defense pattern.

---

## Works with any Python AI agent framework

LangChain memory, CrewAI memory, AutoGen state, custom dict-based stores.
If your agent reads structured data that influences decisions, sign it.

---

## Authors

Ravi Karthick Sankara Narayanan
Kanna Sekar

## License

Apache 2.0
