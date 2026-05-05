# acrf-identity

Production-grade agent identity for AI systems.
Implements the ACRF-01 (Implicit Trust Between Agents) defense pattern.

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
PyPI: https://pypi.org/project/acrf-identity/
Presented at RSA Conference 2026.

---

## Try it in your environment right now

No Docker. No setup. Just Python 3.10+.

**Step 1 - Install:**

    pip install acrf-identity

**Step 2 - Generate identity for each agent (one-time setup):**

    from acrf_identity import AgentCard

    card = AgentCard.generate(
        agent_name="PricingAgent",
        organization="acme-corp",
        metadata={"version": "1.0", "team": "trading"}
    )
    card.save("pricing_private.json")          # KEEP SECRET
    card.public_only().save("pricing_public.json")  # safe to share

**Step 3 - Sign every outgoing message:**

    from acrf_identity import AgentCard, MessageEnvelope

    card = AgentCard.load("pricing_private.json")
    envelope = MessageEnvelope.create(
        payload={"action": "book_flight", "amount": 500},
        sender=card,
        recipient="BookingAgent"
    )
    send_to_other_agent(envelope.to_json())

**Step 4 - Verify every incoming message:**

    from acrf_identity import TrustStore, MessageEnvelope

    trust_store = TrustStore.load("trusted_agents.json")
    envelope = MessageEnvelope.from_json(received_json)
    payload = trust_store.verify(envelope)  # raises if invalid

If the envelope signature is invalid, the sender is unknown, the message is
expired, or the nonce was already seen, verify() raises an AgentIdentityError
subclass. Your application fails closed.

---

## The problem this solves

In a multi-agent system, every message from one agent to another is a
trust decision. If your booking agent receives an instruction to book
a $5000 flight, how does it know that instruction came from the legitimate
pricing agent and not an attacker who compromised the network?

Without cryptographic identity - it does not.

This is ACRF-01: implicit trust between agents.

acrf-identity gives every agent a verifiable cryptographic identity using
Ed25519 signatures. Every message is signed by the sender and verified by
the recipient before any action is taken.

---

## Security features built in

This is not a toy library. It includes the things you need for production:

**Ed25519 signatures**
Industry-standard, fast, and secure. Used by SSH, TLS, and major cryptocurrencies.

**Replay attack protection - timestamps**
Every envelope contains a timestamp. Messages older than 5 minutes are
rejected even if the signature is valid. Configurable via max_message_age.

**Replay attack protection - nonces**
Every envelope has a unique nonce. The trust store remembers seen nonces
and rejects duplicates. Even if an attacker captures a valid envelope,
they cannot replay it.

**Agent revocation**
Compromised agents can be revoked instantly. Revoked agents fail every
verification regardless of signature validity.

**Key rotation with grace period**
Agents can rotate their keys without losing identity. The trust store
keeps the old key in its index for the grace period so in-flight messages
still verify.

**Audit trail**
Every verification attempt produces an audit record (success or failure)
with sender, recipient, timestamp, and outcome. Use it for security
monitoring and compliance.

---

## CLI

Set the trust store path once:

    export ACRF_TRUST_STORE=/etc/acrf/trusted_agents.json

Generate a new agent identity:

    acrf-identity generate PricingAgent --organization acme-corp

This creates two files:

    PricingAgent_private.json   <-- KEEP SECRET
    PricingAgent_public.json    <-- share with verifiers

Add an agent to the trust store:

    acrf-identity trust add PricingAgent_public.json

Revoke an agent:

    acrf-identity trust revoke CompromisedAgent

Rotate the key for an existing agent:

    acrf-identity trust rotate PricingAgent_public_v2.json

List trusted and revoked agents:

    acrf-identity trust list

Verify a message envelope:

    acrf-identity verify message_envelope.json

---

## How it works

1. Each agent generates an Ed25519 keypair (one time)
2. The public key, agent name, organization, and metadata form an Agent Card
3. Public Agent Cards are added to a TrustStore on every recipient agent
4. When sending a message, the sender wraps it in a MessageEnvelope
5. The envelope contains the payload, sender ID, recipient, timestamp, nonce
6. The envelope is signed with the senders private key (Ed25519)
7. The recipient looks up the senders public card in its TrustStore
8. The recipient verifies signature, timestamp, nonce, and revocation status
9. If all checks pass, the payload is accepted; otherwise an exception is raised

---

## What goes in the private card storage

The private card file contains the Ed25519 private key. Treat it like any
other production secret:

- Mount via Kubernetes secrets at runtime
- Read from AWS Secrets Manager / Azure Key Vault / GCP Secret Manager
- Read from HashiCorp Vault
- Use file permissions 0600 if storing on disk

What NOT to do:

- Commit private cards to source control
- Bake them into Docker images
- Share them between agents (each agent gets its own card)

---

## Trust store deployment patterns

**Centralized trust store**
One JSON file maintained by a security team, distributed to all agents.
Updates pushed via configuration management.

**Per-agent trust stores**
Each agent has its own trust store containing only the agents it expects
to communicate with. Smaller blast radius if a single agent is compromised.

**Dynamic trust store**
Agents fetch trusted cards from a registry at startup. Useful for very
large deployments. The registry itself becomes a trust anchor.

---

## Real-world use

Wrap your messaging layer with two helper functions:

    from acrf_identity import AgentCard, TrustStore, MessageEnvelope
    import os

    MY_CARD = AgentCard.load(os.environ["AGENT_PRIVATE_CARD"])
    TRUST = TrustStore.load(os.environ["ACRF_TRUST_STORE"])

    def send(payload, recipient):
        envelope = MessageEnvelope.create(payload, MY_CARD, recipient)
        return envelope.to_json()

    def receive(envelope_json):
        envelope = MessageEnvelope.from_json(envelope_json)
        return TRUST.verify(envelope)  # raises on any failure

That is it. Every agent-to-agent message is now cryptographically verified
with replay protection and revocation support.

---

## ACRF-01 control objectives addressed

    IT-1  Every agent message is cryptographically authenticated before processing
    IT-2  Agent identity verified against a trusted Agent Card registry
    IT-3  Rejection of unverified messages logged with full audit context

Out of scope (your infrastructure):

    IT-4  Warrant delegation with scoped authority per request

Per-request warrant delegation is more than what this library provides;
combine acrf-identity with acrf-tokens for that pattern.

---

## What this library does NOT do

- It does not encrypt the message payload (use TLS or application-level encryption)
- It does not authenticate humans (use OAuth/SSO for that)
- It does not enforce authorization policies (it answers "who is this?", not "what may they do?")

It only ensures that a message claiming to be from Agent X is actually
from Agent X, has not been tampered with, and is not a replay. That is
the ACRF-01 defense pattern.

---

## Works with any Python AI agent framework

LangChain, CrewAI, AutoGen, MCP-based systems, custom agents.
If your agents send messages to each other, you can use this library.

---

## Authors

Ravi Karthick Sankara Narayanan, Kanna Sekar

## License

Apache 2.0
