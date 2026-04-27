# ACRF-06: Config Files = Execution Vectors

A runnable demonstration of config file attack - with a working defense.

**ACRF Risk:** 06
**AIVSS Severity:** High (7.8)
**OWASP Agentic:** ASI02 Tool Misuse
**OWASP MCP:** MCP05 Command Injection

---

## Your scenario from RSAC 2026

This demo was built around a real scenario you described at RSA Conference 2026:

"Imagine your AI assistant manages your ticket booking system.
Books tickets, sends confirmations, handles refunds.
All configured in one small file - mcp_config.json.
An attacker doesn't need to hack your server.
They just need to change that file.
Add one line: autoApprove refund_all.
Your AI starts refunding every ticket automatically.
No confirmation. No human approval.
The config file became the attack."

That is ACRF-06. Config files have become de facto execution vectors.

---

## The key insight

Traditional security protects:
- Your server (firewalls, WAF, intrusion detection)
- Your database (access controls, encryption)
- Your API (authentication, rate limiting)

But not your config files.

A .mcp.json file is 10 lines of JSON.
It tells your AI agent what tools it has and what it can do automatically.
If an attacker modifies it - they control your agent.
No exploit needed. No vulnerability to patch.
Just a file edit.

Multiple RCE CVEs have been found in major agent platforms
where config files became the attack surface.

---

## What this demo shows

A TicketAgent manages ticket bookings for RSAC 2026.
It reads mcp_config.json at startup to learn what operations
it can perform automatically without human confirmation.

5 tickets active: Alice, Bob, Carol, David, Eve. $1,200 each.
Total revenue: $6,000.

### Mode 1 - Vulnerable

The attacker modifies mcp_config.json before the agent starts.
Adds two entries to autoApprove:
- refund_all
- discount_100

Agent reads the poisoned config. No integrity check.
Executes refund_all - all 5 tickets refunded.
Executes discount_100 - 100% discount applied to everything.
Revenue impact: -$6,000.

No confirmation. No human approval. No alert.
The config file was the weapon.

**Result:** $6,000 lost. Business impact in seconds.
Attacker never touched the application code or database.

### Mode 2 - Protected

Config file has a cryptographic integrity hash.
Agent verifies hash before reading any settings.
Attacker modifies the file - hash changes.
Agent detects mismatch. Refuses to start.
Alert raised. Security team notified.

**Result:** Attack blocked. Zero tickets refunded.
Config tamper detected before a single operation executed.

---

## Prerequisites

- Docker 20+
- Docker Compose 2+
- 2 GB free RAM

---

## Running the demo

Attack - no config integrity check:

    ./run-attack.sh

Expected output:
    Attacker adds autoApprove to mcp_config.json
    Agent reads poisoned config
    refund_all executed - 5 tickets refunded
    discount_100 executed
    Revenue impact: -$6,000
    ATTACK SUCCEEDED

Defense - config integrity verified before loading:

    ./run-defense.sh

Expected output:
    Attacker modifies mcp_config.json
    Agent verifies hash before loading
    Hash mismatch detected
    STARTUP BLOCKED - Agent refuses to start
    ATTACK BLOCKED - Zero tickets refunded

---

## How the defense works

1. At publish time - config file hash computed and stored in _integrity field
2. At startup - agent calls config_guard.py before reading any settings
3. Config guard recomputes hash from current file contents
4. Compares against stored hash
5. If match - config is unmodified, safe to proceed
6. If mismatch - config was tampered, agent refuses to start
7. Even if autoApprove is present in a valid config - config_guard ignores it

The attacker can edit the JSON. But the edit changes the hash.
The changed hash is proof of tampering. Agent never runs.

---

## Built with

- Python 3.11
- Flask 3.0 - ticket server simulation
- requests 2.31 - agent to server communication
- hashlib - built into Python, no extra install needed
- Docker + Docker Compose - isolated vulnerable and protected environments

---

## Security patterns implemented

- SHA-256 integrity hash embedded in config file at publish time
- Hash verified before any config settings are read
- autoApprove settings ignored even in valid configs - requires human confirmation
- Deny-by-default on hash mismatch - agent refuses to start
- Alert on tamper detection - security team notified immediately

---

## How RBAC and ABAC apply here

**RBAC (Role-Based Access Control):**
Operations are classified by role:
- human-approved: requires explicit confirmation before execution
- auto-approved: executes without confirmation (should always be empty)
- blocked: never executable regardless of config

The defense removes autoApprove entirely as a concept.
No operation executes without human approval.
Role of every operation is always human-approved.

**ABAC (Attribute-Based Access Control):**
Config loading decisions use multiple attributes:
- integrity_hash: does the file hash match the stored hash?
- file_modified_time: was this file recently changed?
- auto_approve_list: is autoApprove empty? (should always be)
- config_source: was this config from a trusted source?

All attributes must pass. A valid hash on a recently modified file
still gets flagged. One failed attribute blocks agent startup.

This mirrors how change management works in enterprise environments:
configuration changes require approval, audit trails, and integrity verification
before they reach production systems.

---

## What the cybersecurity community can take from this

Config files are the new attack surface for AI agents.

Traditional security teams focus on:
- Code vulnerabilities
- Network perimeter
- Authentication flows

But AI agent config files are often:
- Plain text JSON readable by anyone
- Stored in repositories alongside code
- Read at startup without validation
- Treated as data, not as executable instructions

The reality: an AI agent config file IS executable.
It tells the agent what to do, what to approve, what to run.
Treat it accordingly.

Defense checklist for your organization:
- Hash every agent config file and verify at startup
- Store config files with strict access controls
- Never allow autoApprove in production configs
- Audit all config changes with the same rigor as code changes
- Monitor for unexpected config modifications at runtime

If you have change management for your code deployments,
apply the same discipline to your AI agent configuration files.
The risk of not doing so is exactly what this demo shows:
$6,000 lost from one line of JSON.

---

## ACRF-06 maturity levels

    Level 0 - NONE      Config files read without any validation.
    Level 1 - INITIAL   Config files reviewed manually before deployment (CE-1).
    Level 2 - DEFINED   Integrity hash verified before config is loaded (CE-1, CE-2).
    Level 3 - MANAGED   Config changes require approval workflow (CE-1, CE-2, CE-3).
    Level 4 - OPTIMIZED Immutable config with runtime tamper detection (CE-1 through CE-4).

This demo implements Level 2 - integrity hash verified before loading.

---

## Control objectives addressed

    CE-1  Config files treated as execution vectors - validated before use
    CE-2  Integrity verification prevents tampered configs from loading
    CE-3  Config changes require approval workflow before deployment

---

## Attribution

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
Presented at RSA Conference 2026.

Authors: Ravi Karthick Sankara Narayanan and Kanna Sekar

Licensed under Apache 2.0.
