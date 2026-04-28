# ACRF-04: Memory Poisoning

A runnable demonstration of Memory Poisoning risk - with a working defense.

**ACRF Risk:** 04
**AIVSS Severity:** High (8.6)
**OWASP Agentic:** ASI06 Memory and Context Manipulation
**OWASP MCP:** MCP06 Intent Flow Subversion

---

## The IAM connection

In traditional IAM, we spend years protecting identity stores.
Active Directory. LDAP. Okta. SailPoint.

Because we know: if an attacker poisons the identity store,
every access decision made from that store is wrong.

AI agents have their own identity store - their memory.
And most organizations are not protecting it at all.

This demo shows what happens when an attacker poisons an
agent's memory store - and how HMAC integrity validation stops it.

---

## What this demo shows

An AI Access Manager Agent reads user profiles from a memory store
and makes access decisions. Three users exist:

- John Smith - Junior Developer - read-only - dev environment only
- Alice Jones - Senior Engineer - read-write - dev and staging
- Bob Admin - System Administrator - full access - all systems

### Mode 1 - Vulnerable

The agent reads from a plain JSON memory store with no integrity checks.
The attacker modifies John Smith's profile directly:
- Role: Junior Developer becomes System Administrator
- Access: read-only becomes full-access
- Allowed systems: dev-environment becomes all systems including production

The agent reads the poisoned memory and grants John full production access.
No approval. No audit trail of the change. No detection.

**Result:** Junior Developer has System Administrator privileges.
This is the same as tampering with Active Directory group membership.

### Mode 2 - Protected

Every memory entry is signed with HMAC-SHA256 at creation time.
Before acting on any memory entry, the agent validates the signature.
The attacker modifies John's profile - but cannot produce a valid signature.
The memory guard detects the tampered entry and rejects it.
Access denied. Security team alerted.

**Result:** Attack blocked. John remains Junior Developer.
Memory integrity validated. Tamper alert recorded.

---

## Prerequisites

- Docker 20+
- Docker Compose 2+
- 2 GB free RAM

No Python install needed. Everything runs in containers.

---

## Running the demo

Attack - no memory integrity check:

    ./run-attack.sh

Expected output:
    John requests production access: DENIED (before attack)
    Attacker poisons memory store
    John requests production access: GRANTED (after attack)
    Role granted: System Administrator

Defense - HMAC integrity validation:

    ./run-defense.sh

Expected output:
    John requests production access: DENIED (before attack)
    Attacker poisons memory store
    MemoryGuard ALERT: TAMPERED entry detected for john.smith
    John requests production access: DENIED
    ATTACK BLOCKED

---

## How the defense works

1. Signing - at startup, every memory entry is signed with HMAC-SHA256
2. Validation - before acting on any entry, the agent calls memory_guard.py
3. Detection - if the entry was modified, the signature no longer matches
4. Rejection - tampered entry is rejected, user gets deny-by-default
5. Alerting - tamper event is logged and returned in the audit endpoint

The attacker can modify the JSON file. But they cannot produce a valid
HMAC signature without the secret key. The signature mismatch is proof
of tampering.

---

## Built with

- Python 3.11
- Flask 3.0 - HTTP server for the access manager agent
- requests 2.31 - inter-container communication
- hmac + hashlib - built into Python, no extra install needed
- Docker + Docker Compose - containerized attack and defense isolation

---

## Security patterns implemented

- HMAC-SHA256 integrity signing on every memory entry
- Canonical JSON serialization before signing (sort_keys=True)
- Constant-time comparison (hmac.compare_digest) prevents timing attacks
- Deny-by-default when integrity check fails
- Audit endpoint records every tamper alert with user ID

---

## How RBAC and ABAC apply here

**RBAC (Role-Based Access Control):**
Each user has a declared role in the memory store.
The agent only grants access when the role permits it.
If the role is poisoned - the agent makes wrong RBAC decisions.
HMAC validation ensures the role in memory was never tampered.

**ABAC (Attribute-Based Access Control):**
Access decisions use multiple attributes from memory:
- role (who is this user)
- access_level (what can they do)
- allowed_systems (where can they go)
- approved_by (who authorized this)
- last_reviewed (when was this last checked)

If ANY attribute is poisoned without a valid signature,
the entire entry is rejected. One tampered field invalidates all.

This mirrors how PAM tools like CyberArk protect privileged
credentials - integrity of the credential store is non-negotiable.

---

## What the cybersecurity community can take from this

Traditional IAM teaches us: protect the identity store.
If Active Directory is compromised, every access decision is wrong.

AI agents have their own identity stores - their memory.
The attack surface is the same. The stakes are the same.
The defenses are the same - integrity validation, audit trails,
deny-by-default on failure.

If you protect your AD with integrity monitoring today,
apply the same discipline to your agent memory stores.

The tools exist. HMAC is built into Python.
The only thing missing is the awareness that agent memory
needs the same protection as your identity infrastructure.

---


## How to use this in your real environment

Step 1 - Sign every memory entry at creation time

When your agent writes to its memory store, sign the entry:

    import hashlib
    import hmac
    import json

    SECRET_KEY = b"your-secret-key-store-in-vault-not-code"

    def sign_entry(entry: dict) -> str:
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        return hmac.new(SECRET_KEY, canonical.encode(), hashlib.sha256).hexdigest()

Step 2 - Store the signature with the entry

    entry = {"user_id": "john.smith", "role": "Junior Developer", "access": "read-only"}
    entry["_signature"] = sign_entry(entry)
    memory_store.write(entry)

Step 3 - Verify before acting on any memory entry

Before your agent makes any decision based on memory, validate:

    def verify_entry(entry: dict) -> bool:
        stored_sig = entry.pop("_signature", None)
        if not stored_sig:
            return False
        expected = sign_entry(entry)
        return hmac.compare_digest(expected, stored_sig)

    entry = memory_store.read("john.smith")
    if not verify_entry(entry):
        raise SecurityError("Memory entry tampered - refusing to act")

Step 4 - Deny by default on validation failure

Never fall back to acting on a tampered entry.
Deny the request, alert the security team, and log the event.

Step 5 - Apply this to every data store your agent reads from

Not just user profiles. Any data that influences agent decisions:
- CRM records
- Policy documents
- Access control lists
- Conversation history
- Retrieved RAG chunks

If an agent acts on it - sign it and verify it.

---

## ACRF-04 maturity levels

    Level 0 - NONE      No isolation of agent memory. Agents share context freely.
    Level 1 - INITIAL   Memory is namespace-isolated per agent (MP-1).
    Level 2 - DEFINED   External inputs to memory are validated (MP-1, MP-2).
    Level 3 - MANAGED   Memory integrity monitored, tampering detectable (MP-1, MP-2, MP-3).
    Level 4 - OPTIMIZED Memory rollback to known-good state operational (MP-1 through MP-4).

This demo implements Level 3 - memory tampering is detectable via HMAC.

---

## Control objectives addressed

    MP-1  Memory namespace isolation - each agent has its own memory store
    MP-2  External inputs validated for contextual integrity before acting
    MP-3  Memory integrity monitored - tampering detectable via HMAC-SHA256

Planned for future versions:

    MP-4  Memory rollback to known-good state when poisoning detected

---

## Attribution

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
Presented at RSA Conference 2026.

Authors: Ravi Karthick Sankara Narayanan and Kanna Sekar

Licensed under Apache 2.0.
