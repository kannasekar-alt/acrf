# ACRF-01: Implicit Trust Between Agents

A runnable demonstration of the highest-severity risk in the ACRF framework — with a working defense.

**ACRF Risk:** 01
**AIVSS Severity:** Critical (9.2)
**OWASP Agentic:** ASI07 Insecure Inter-Agent Communication
**OWASP MCP:** MCP07 Insufficient Auth

## What this demo shows

Two small AI agents in a travel booking system:

- **TravelOrchestrator** — receives user requests, delegates to booking
- **BookingExecutor** — books the flight and charges the card

### Mode 1 — Vulnerable

The two agents communicate without authentication. An attacker spoofs the orchestrator's identity and books a fraudulent $8,200 flight, charging Alice's credit card. The booking service has no way to verify the sender — it trusts the sender field in the JSON message.

**Result:** Alice pays $8,200 for a flight she did not book.

### Mode 2 — Protected

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

1. Key generation — each agent generates an Ed25519 keypair at startup
2. Agent Cards — a public Agent Card is created for each agent containing capabilities and public key
3. Signing — the orchestrator canonicalizes the message payload and signs it with its private key
4. Verification — the booking service loads the sender's Agent Card and verifies the signature

If verification fails — request rejected, audit event logged.

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
