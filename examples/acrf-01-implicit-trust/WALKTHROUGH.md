# ACRF-01 Demo Walkthrough Script

Duration: 5 to 7 minutes
Audience: Security architects, developers working with AI agents
Purpose: Show ACRF-01 as a working concept, not just a framework entry

## Opening (30 seconds)

"This is ACRF-01 — Implicit Trust Between Agents. The highest-severity risk in our framework, scored Critical at 9.2 on AIVSS.

Most multi-agent systems today have this vulnerability by default. When Agent A sends a message to Agent B, Agent B trusts the sender field in the JSON. No signature. No cryptographic proof. Just words in a message.

I'm going to show you what that looks like when it fails, and what the defense looks like in running code. Under 60 seconds each."

## Part 1 — The Attack (2 minutes)

### Setup narration (20 sec)

"Here's a travel booking system with two agents. The TravelOrchestrator takes user requests and delegates to the BookingExecutor, which actually books the flight and charges the card.

The BookingExecutor has a simple rule: if the message claims to be from TravelOrchestrator, process it. That's the vulnerability."

### Run the vulnerable version

    ./run-attack.sh

### Narration while it runs (60 sec)

"First, a legitimate booking. Alice wants a flight from San Francisco to JFK. Four hundred and twenty dollars. The orchestrator sends the request. BookingExecutor sees the sender field says TravelOrchestrator. Trusts it. Charges Alice.

Now — the attacker. They've discovered this service. They know what the message format looks like. All they do is construct their own message, put TravelOrchestrator in the sender field, and ask the booking service to fly them to Dubai in first class. Eight thousand two hundred dollars. Charged to Alice.

The booking service happily processes it. Because from its perspective — that's a message from TravelOrchestrator. It has no way to tell the difference."

### Close (10 sec)

"Alice is out eight thousand dollars. The attacker has their ticket. No signature was checked because there was nothing to check. This is ACRF-01."

## Part 2 — The Defense (2 minutes)

### Transition (15 sec)

"Now the same scenario with the defense in place. Same two agents. Same attacker with the same goal. But this time — cryptographic identity."

### Run the protected version

    ./run-defense.sh

### Narration while it runs (60 sec)

"At startup, each agent generates an Ed25519 keypair. The public key is published in an Agent Card — a small JSON document that declares the agent's identity, capabilities, and public key.

When the orchestrator sends a booking request, it canonicalizes the message and signs it with its private key. The BookingExecutor has the orchestrator's Agent Card in its trust store. It uses the public key to verify the signature before processing anything.

Legitimate booking — signature verified. Alice charged. Four hundred and twenty dollars.

Now the attacker. Same message structure. Same sender claim. But the attacker doesn't have the private key — so their first attempt has no signature at all. Rejected.

Second attempt — they fabricate a signature. Just random bytes. The public key verification fails immediately. Rejected. Logged.

Alice is not charged. The attack is blocked."

### Close (15 sec)

"Note what we did NOT need — no firewall rule, no intrusion detection, no policy engine. The defense is cryptographic. The attacker could literally know the entire message format and still cannot produce a valid signature."

## Part 3 — Why This Matters (90 seconds)

### Ask and answer (45 sec)

"You might be thinking — this seems obvious. Who builds agent systems without signing messages?

Answer: almost everyone. Today. At scale.

Neither MCP nor A2A mandates message signing. They allow it. They support it. But they don't require it. Which means the default integration path ships without it. Four hundred and ninety-two MCP servers have been found internet-exposed with zero authentication."

### Action close (45 sec)

"ACRF-01's defense pattern is three things: warrant delegation, mTLS between agents, and cryptographically signed Agent Cards. Everything I just showed you is in the demo. Runnable. Apache 2.0 licensed.

If you have one takeaway: treat the sender field on any inter-agent message as untrusted input until a signature proves otherwise. That single discipline closes ACRF-01.

Repo is at github.com/kannasekar-alt/acrf. The full framework documents nine more risks like this one.

Thanks for watching."
