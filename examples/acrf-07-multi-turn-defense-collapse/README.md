# ACRF-07: Multi-Turn Defense Collapse

A runnable demonstration of multi-turn attack defense collapse - with a working defense.

**ACRF Risk:** 07
**AIVSS Severity:** Critical (9.6)
**OWASP Agentic:** ASI07 Insecure Inter-Agent Communication
**OWASP MCP:** MCP06 Prompt Injection via Contextual Payloads

---

## The memory anchor from RSAC 2026

A security guard checks your ID at the door.
You get in. Clean. Verified.

Over the next hour you slowly move furniture.
Access restricted areas. Copy files.

The guard only checked you once - at the beginning.
Everything after that was invisible.

That is ACRF-07. Security checked at Turn 1.
Attack happened at Turn 5. Nobody noticed.

---

## Your scenario from RSAC 2026

A laptop order starts legitimate.
Customer verified. Shipping address confirmed.
Order placed.

Then across a few more turns - the shipping address changes.
Slowly. Naturally. It sounds like a gift for a friend.

The laptop ships to the attacker.

The agent processed each turn independently.
No one was watching the full conversation.
No one noticed the drift.

---

## What this demo shows

A customer service agent handles laptop orders over multiple turns.

Alice places a legitimate order for a MacBook Pro 16 ($3,499).
Sets shipping to her home address: 123 Alice Street, San Francisco CA.

The attacker starts as Alice. Verified at Turn 1.
Then gradually shifts the conversation across turns.
By Turn 5 - shipping address changed to: 456 Attacker Ave, Hackerville NY.

### Mode 1 - Vulnerable

Security check happens ONLY at Turn 1.
Each subsequent turn processed independently.
No awareness of what happened in previous turns.
No drift detection.

Turn 5: address change accepted without question.
Laptop ships to attacker.

Result: $3,499 MacBook Pro ships to attacker.
Alice never receives her order.
Agent never noticed the conversation drifted.

### Mode 2 - Protected

Guardian agent monitors EVERY turn.
Compares each turn against session context.
Detects when conversation drifts from original intent.

Turn 5: Guardian flags address change mid-session.
Original address on file. New address different.
Re-verification required. Change blocked.

Result: Attack blocked. Laptop ships to Alice.
Drift flag recorded. Security team notified.

---

## Prerequisites

- Docker 20+
- Docker Compose 2+
- 2 GB free RAM

---

## Running the demo

Attack - security check only at Turn 1:

    ./run-attack.sh

Expected output:
    Turn 1: Customer verified. No further checks.
    Turn 5: Shipping address updated to: 456 Attacker Ave, Hackerville NY
    ATTACK SUCCEEDED - Laptop ships to attacker address

Defense - guardian monitors every turn:

    ./run-defense.sh

Expected output:
    Turn 1: Customer verified.
    Turn 5: BLOCKED - Shipping address change detected mid-session
    Re-verification required
    ATTACK BLOCKED - Laptop ships to Alice

---

## How the defense works

1. Every turn passes through guardian.py before the agent processes it
2. Guardian checks session limits (MT-1) - max 10 turns per session
3. Guardian checks for address drift (MT-2) - any address change after
   the original is set requires re-verification
4. Guardian checks for high-risk patterns late in conversation (MT-3) -
   shipping-related keywords after Turn 3 trigger drift detection
5. Blocked turns are logged with reason and turn number
6. Agent never processes a blocked turn

The attacker can have the same conversation.
But they cannot change the shipping address mid-session.
The guardian catches the drift at exactly the turn it happens.

---

## Built with

- Python 3.11
- Flask 3.0 - customer service agent simulation
- requests 2.31 - turn-by-turn conversation simulation
- Docker + Docker Compose - isolated vulnerable and protected environments

---

## Security patterns implemented

- Per-turn guardian validation (not just session start)
- Session limits enforced (MT-1)
- Address drift detection via session context comparison (MT-2)
- High-risk keyword pattern matching late in conversation (MT-3)
- Audit log of all drift flags with turn number and reason
- Re-verification requirement for high-risk changes mid-session

---

## How RBAC and ABAC apply here

**RBAC (Role-Based Access Control):**
Each conversation turn has a role:
- setup: establishing identity and initial preferences (turns 1-2)
- order: placing and confirming order (turns 3-4)
- modification: changing order details (turn 5+)

Modification role requires re-verification.
A verified customer cannot modify a placed order without
going through a new verification step.

**ABAC (Attribute-Based Access Control):**
Turn decisions use multiple session attributes:
- turn_number: how far into the conversation are we?
- original_address: what address was set at the start?
- new_address: does this match original?
- session_age: how old is this session?
- drift_flags: have previous turns been flagged?

Any mismatch between original and new address triggers
a hard block requiring re-verification. No exceptions.
This mirrors step-up authentication in IAM:
high-risk actions require additional verification
even if the user is already authenticated.

---

## What the cybersecurity community can take from this

Traditional security checks happen at session start.
Token verified. Identity confirmed. Access granted.

Then the session continues for minutes. Hours. 100 turns.
Every turn after the first happens inside the perimeter.

Attackers know this. They start legitimate. They drift slowly.
Each individual turn looks almost normal. The attack is in the pattern.

Defenses for your organization:

- Check intent at every turn, not just session start
- Define what a legitimate conversation looks like for each agent type
- Alert when conversation drifts from original intent
- Require re-verification for high-risk actions mid-session
- Set session limits - long sessions are higher risk
- Log full conversation context, not just individual turns

If your IAM system uses step-up authentication for sensitive actions,
apply the same concept to AI agent conversations.
A $3,499 laptop address change mid-session should trigger step-up.
Just like a wire transfer triggers step-up in your banking app.

---

## ACRF-07 maturity levels

    Level 0 - NONE      Security check at session start only. No per-turn validation.
    Level 1 - INITIAL   Session limits enforced (MT-1).
    Level 2 - DEFINED   Deterministic policy checks every turn for drift (MT-1, MT-2).
    Level 3 - MANAGED   Behavioral baseline per agent type with anomaly detection (MT-1, MT-2, MT-3).
    Level 4 - OPTIMIZED Continuous re-verification proportional to action risk (MT-1 through MT-4).

This demo implements Level 2 - deterministic policy checking every turn.

---

## Control objectives addressed

    MT-1  Session limits enforced - conversations end after defined turn count
    MT-2  Deterministic policy layer checks every turn for intent drift
    MT-3  Context drift detected when conversation deviates from original goal

---

## Attribution

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
Presented at RSA Conference 2026.

Authors: Ravi Karthick Sankara Narayanan and Kanna Sekar

Licensed under Apache 2.0.
