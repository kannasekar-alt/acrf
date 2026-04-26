# ACRF-01: Implicit Trust Between Agents

A runnable demonstration of the highest-severity risk in the ACRF framework - with a working defense.

**ACRF Risk:** 01
**AIVSS Severity:** Critical (9.4)
**OWASP Agentic:** ASI07 Insecure Inter-Agent Communication
**OWASP MCP:** MCP07 Insufficient Auth

## What this demo shows

Two small AI agents in a travel booking system:

- **TravelOrchestrator** - receives user requests, delegates to booking
- **BookingExecutor** - books the flight and charges the card

### Mode 1 - Vulnerable

The two agents communicate without authentication. An attacker spoofs the orchestrator's identity and books a fraudulent $8,200 flight, charging Alice's credit card. The booking service has no way to verify the sender - it trusts the sender field in the JSON message.

**Result:** Alice pays $8,200 for a flight she did not book.

### Mode 2 - Protected

The same scenario, but every message is cryptographically signed with Ed25519 using the orchestrator's private key. The booking service verifies the signature against the orchestrator's Agent Card before processing. The attacker cannot produce a valid signature without the private key.

**Result:** Attack blocked. Alice is only charged for her real flight.

This is the ACRF-01 defense pattern in action: mTLS plus cryptographically signed Agent Cards.

## Prerequisites

- Docker 20+
- Docker Compose 2+
- 2 GB free RAM

No Python install needed locally. Everything runs in containers.

## Running the demo

    ./run-attack.sh
    ./run-defense.sh

Each takes about 60 seconds to build and run.

## How the defense works

1. Key generation - each agent generates an Ed25519 keypair at startup
2. Agent Cards - a public Agent Card is created for each agent containing capabilities and public key
3. Signing - the orchestrator canonicalizes the message payload and signs it with its private key
4. Verification - the booking service loads the sender's Agent Card and verifies the signature

If verification fails - request rejected, audit event logged.

## What the attacker cannot do

- Sign a message as TravelOrchestrator (lacks the private key)
- Inject a new Agent Card into the booking service's trust store
- Replay a legitimate signed message to change its contents

Without the private key, forged messages cannot produce valid signatures.

## File layout

    acrf-01-implicit-trust/
    ├── README.md
    ├── WALKTHROUGH.md
    ├── docker-compose.yml
    ├── run-attack.sh
    ├── run-defense.sh
    ├── vulnerable/
    │   ├── orchestrator.py
    │   ├── booking.py
    │   ├── attacker.py
    │   └── Dockerfile
    └── protected/
        ├── keygen.py
        ├── orchestrator.py
        ├── booking.py
        ├── attacker.py
        └── Dockerfile

## Attribution

Part of the ACRF (Agent Communication Risk Framework) project.
Presented at RSA Conference 2026 by Kanna Sekar (Google) and Ravi Karthick Sankara Narayanan (Deloitte).

Licensed under Apache 2.0.

## Built with

- Python 3.11
- Flask 3.0 - lightweight HTTP server for agent simulation
- cryptography 42.0 - Ed25519 key generation and signature verification
- requests 2.31 - inter-agent HTTP communication
- Docker + Docker Compose - containerized attack and defense isolation

## Security patterns implemented

- Cryptographic identity verification - replaces implicit trust with proof
- Ed25519 asymmetric signatures - lightweight, fast, modern curve
- Agent Cards - public key distribution and capability declaration
- Warrant delegation - scoped authority per request, not per session
- Audit logging - every rejected attempt recorded with timestamp and reason

## How RBAC and ABAC apply here

**RBAC (Role-Based Access Control):**
Every agent has a declared role - orchestrator or executor.
Only agents with the orchestrator role are permitted to initiate
booking requests. The BookingExecutor checks the sender role
before processing any action.

**ABAC (Attribute-Based Access Control):**
Access decisions consider multiple attributes beyond role:
- Was the message signed? (requester attribute)
- Is the signature cryptographically valid? (request integrity attribute)
- Does the sender appear in the trust store? (identity attribute)
- Is the action reversible? (resource attribute)

All attributes must pass. A signed message from an unknown sender
is rejected. A known sender with a forged signature is rejected.
This is ACRF-01 defense implemented as attribute-based policy.

## What the cybersecurity community can take from this

Traditional IAM (SailPoint, Okta, CyberArk) secures human identity.
This demo shows the same Zero Trust principles applied to AI agents:

- Agents need cryptographic identities, not just API keys
- Trust must be verified on every request, not assumed from network position
- Every action needs an audit trail back to the originating identity
- Delegation must be explicit and scoped, not inherited

If you enforce Zero Trust for human access today,
your AI agents need the same treatment.
