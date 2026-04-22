# ACRF Methodology v0.1

**Agent Communication Risk Framework  - Methodology Specification**

*Version 0.1, released April 2026. Open for public comment and contribution.*

*First presented at RSA Conference 2026 in the virtual seminar ["My AI Will Call Your AI: Securing Agent-to-Agent Communication"](https://www.rsaconference.com/Library/virtual-seminar/hds-22-agentic-ai-challenges-increased-autonomy) by Kanna Sekar (Google) and Ravi Karthick Sankara Narayanan (Deloitte).*

---

## 1. Purpose and scope

ACRF is a methodology for assessing the security risk posture of **agent-to-agent (A2A) communications** in systems where autonomous or semi-autonomous AI agents exchange messages that influence each other's behavior.

Neither MCP (the agent-to-tool boundary) nor A2A protocol alone solves all trust failures that emerge when agents communicate with other agents. **ACRF addresses the gap between them: the communication layer where agents talk to each other.** It identifies this gap, cross-maps it to two existing OWASP bodies of work  - the Agentic Top 10 (ASI) and the MCP Top 10  - and scores each risk dimension with AIVSS (AI Vulnerability Severity Scoring) so practitioners get one view across three frameworks.

ACRF is in scope for:

- Systems where two or more AI agents exchange structured messages (tool calls, natural-language requests, function invocations, event streams) and one or more agents takes action based on those messages.
- Systems that span trust boundaries  - e.g., an internal agent invoking an external agent, a first-party agent invoking a third-party agent, or a user-scoped agent invoking a service-scoped agent.
- Both synchronous (request/response) and asynchronous (event/queue) agent communication.

ACRF is **out of scope** for:

- Single-agent security (covered well by OWASP Top 10 for LLM Applications, MITRE ATLAS).
- The underlying model's adversarial robustness (covered by NIST AI 100-2, academic adversarial ML literature).
- Non-agent API security (covered by OWASP API Top 10, existing AppSec practice).

ACRF is designed to be **complementary** to those bodies of work. A mapping is provided in [`related-work.md`](related-work.md).

## 2. Assumptions and definitions

**Agent.** A software component that (a) accepts inputs in a non-trivial language (typically natural language or structured intent), (b) makes autonomous decisions about what actions to take in response, and (c) can invoke tools, other agents, or external systems.

**Communication.** Any message passed from one agent (the *sender*) to another agent (the *receiver*) with the expectation that the receiver may act on it. This includes direct function/tool invocations, natural-language requests, and event notifications.

**Trust boundary.** A line across which a message's trustworthiness cannot be assumed to be the same on both sides. Examples: tenant boundary, organizational boundary, user-scope boundary, network boundary.

**Assessment.** The application of ACRF to a concrete system, producing a maturity score per risk dimension and a remediation backlog.

**AIVSS.** AI Vulnerability Severity Scoring  - a severity scale (0.0–10.0) applied to each risk dimension, reflecting worst-case impact in a fully autonomous multi-agent deployment. Scores are assigned per dimension, not per finding.

## 3. The ten ACRF risk dimensions

ACRF organizes A2A communication risk into ten dimensions. Each dimension is defined by a **risk it addresses**, cross-mapped to the **OWASP Agentic Top 10 (ASI)** and **OWASP MCP Top 10**, scored with an **AIVSS severity rating**, and paired with a **defense pattern**. Each dimension has four **control objectives** and a **0–4 maturity scale**.

| # | Risk Dimension | OWASP Agentic | OWASP MCP | AIVSS | Defense Pattern |
|---|----------------|---------------|-----------|-------|-----------------|
| 01 | **Implicit Trust Between Agents** | ASI07 Insecure Inter-Agent | MCP07 Insufficient Auth | Critical (9.2) | Warrant delegation, mTLS, signed Agent Cards |
| 02 | **No Standard Agent Identity** | ASI03 Identity & Privilege | MCP01 Token Mismanagement | Critical (9.0) | Agent Naming Service, OAuth 2.1, scoped tokens |
| 03 | **MCP Server Sprawl** | ASI04 Supply Chain Vulns | MCP09 Shadow MCP Servers | High (8.4) | Agent inventory, mcp-scan, AIBOM |
| 04 | **Memory Poisoning** | ASI06 Memory & Context | MCP06 Intent Flow Subversion | Critical (9.1) | Namespace isolation, contextual integrity |
| 05 | **Supply Chain Toxicity** | ASI04 Supply Chain Vulns | MCP03, MCP04 Tool Poisoning | Critical (9.3) | Lock dependency versions, skill-scanner |
| 06 | **Config Files = Execution Vectors** | ASI05 Unexpected Code Exec | MCP05 Command Injection | High (8.7) | Sandboxing, read-only configs |
| 07 | **Multi-Turn Defense Collapse** | ASI01 Goal Hijack | MCP06 Intent Flow Subversion | Critical (9.4) | Deterministic intermediaries, session limits |
| 08 | **Cascading Failure Blindness** | ASI08 Cascading Failures | MCP08 Lack of Audit | High (8.5) | Circuit breakers, agent-aware SIEM |
| 09 | **Semantic Bypass** | ASI09 Human-Agent Trust | MCP10 Context Over-Sharing | High (8.6) | Guardian agents, intent validation |
| 10 | **Safety Controls Not Self-Protecting** | ASI10 Rogue Agents | MCP02 Privilege Escalation | Critical (9.5) | Least agency, immutable guardrails |

*AIVSS scores reflect worst-case severity in a fully autonomous, multi-agent deployment where agents make consequential real-world decisions without human-in-the-loop review. Scores should be contextualized to the specific system under assessment.*

### 3.1 ACRF-01  - Implicit Trust Between Agents

*Risk addressed: Agent A trusts messages from Agent B because they share a deployment, not because B authenticated or was delegated authority for the requested action.*

**OWASP cross-mapping:** ASI07 Insecure Inter-Agent Communication; MCP07 Insufficient Auth.
**AIVSS:** 9.2 (Critical).
**Defense pattern:** Warrant delegation, mTLS, signed Agent Cards.

**Control objectives:**

- **IT-1.** Every inter-agent message carries verifiable proof that the sender is who it claims to be  - authentication is verified on receipt, not assumed from network position or co-deployment.
- **IT-2.** Trust delegation is explicit: when Agent A asks Agent B to act, the scope of delegated authority is stated in the request and enforced by the receiver.
- **IT-3.** Trust delegation credentials are time-limited and rotatable; compromised credentials can be revoked without redeploying either agent.
- **IT-4.** The system can produce a verifiable audit trail showing, for any action, the complete delegation chain from the originating human (or policy) through every agent hop.

**Maturity scale:**

| Level | Description |
|-------|-------------|
| 0 | Agents trust by network position or shared deployment; no sender verification. |
| 1 | Sender authentication is verified on receipt (IT-1). |
| 2 | Trust delegation is explicit and scope-limited (IT-1, IT-2). |
| 3 | Delegation credentials are rotatable and revocable (IT-1, IT-2, IT-3). |
| 4 | Full delegation-chain audit trail is verifiable end-to-end (IT-1 through IT-4). |

### 3.2 ACRF-02  - No Standard Agent Identity

*Risk addressed: agents lack cryptographically verifiable, standards-based identities distinct from the identity of the human user on whose behalf they act, making it impossible to distinguish "which agent did this" from "which user did this."*

**OWASP cross-mapping:** ASI03 Identity & Privilege Failures; MCP01 Token Mismanagement.
**AIVSS:** 9.0 (Critical).
**Defense pattern:** Agent Naming Service, OAuth 2.1, scoped tokens.

**Control objectives:**

- **SI-1.** Every agent has a cryptographically verifiable identity, distinct from the identity of any human user, provisioned through a standards-based scheme (e.g., SPIFFE, OAuth 2.1 client credentials).
- **SI-2.** Tokens and credentials are scoped per agent; one agent's token cannot be used by another agent to access resources outside the first agent's authorized scope.
- **SI-3.** Identity material is rotated on a defined schedule and can be revoked on compromise without impacting other agents.
- **SI-4.** Agent identity is consistently distinguished from user identity in logs, authorization decisions, and audit records.

**Maturity scale:**

| Level | Description |
|-------|-------------|
| 0 | Agents have no distinct identity; they inherit the user's credentials or use shared secrets. |
| 1 | Agents have distinct, verifiable identities (SI-1). |
| 2 | Tokens are scoped per agent (SI-1, SI-2). |
| 3 | Identity material is rotated and revocable (SI-1, SI-2, SI-3). |
| 4 | Agent identity is distinguished from user identity in all logs and authorization (SI-1 through SI-4). |

### 3.3 ACRF-03  - MCP Server Sprawl

*Risk addressed: the number of MCP tool servers reachable by agents grows unchecked, expanding the attack surface and creating shadow dependencies that no one monitors.*

**OWASP cross-mapping:** ASI04 Supply Chain Vulnerabilities; MCP09 Shadow MCP Servers.
**AIVSS:** 8.4 (High).
**Defense pattern:** Agent inventory, mcp-scan, AIBOM.

**Control objectives:**

- **SS-1.** A centralized, maintained inventory of all MCP servers and tool endpoints reachable by agents exists and is current.
- **SS-2.** New MCP server additions require an approval process with a security review.
- **SS-3.** The inventory is continuously monitored for drift; shadow servers are detected and flagged.
- **SS-4.** An AI Bill of Materials (AIBOM) is generated and published, covering all agent-reachable tool endpoints and their dependencies.

**Maturity scale:**

| Level | Description |
|-------|-------------|
| 0 | No inventory of agent-reachable MCP servers. |
| 1 | A centralized inventory exists (SS-1). |
| 2 | New servers require approval and security review (SS-1, SS-2). |
| 3 | Continuous drift detection flags shadow servers (SS-1, SS-2, SS-3). |
| 4 | AIBOM is generated and published (SS-1 through SS-4). |

### 3.4 ACRF-04  - Memory Poisoning

*Risk addressed: an agent's persistent memory or context window is corrupted  - by another agent, a tool response, or a manipulated data source  - causing the agent to act on false premises in subsequent interactions.*

**OWASP cross-mapping:** ASI06 Memory & Context Manipulation; MCP06 Intent Flow Subversion.
**AIVSS:** 9.1 (Critical).
**Defense pattern:** Namespace isolation, contextual integrity.

**Control objectives:**

- **MP-1.** Agent memory and context are namespace-isolated; one agent cannot read or write another agent's persistent state without explicit authorization.
- **MP-2.** Inputs to agent memory from external sources (tool responses, other agents) are validated for contextual integrity before being persisted.
- **MP-3.** Memory tampering is detectable; integrity checks exist on persisted agent state.
- **MP-4.** Memory can be rolled back to a known-good state when poisoning is detected, without requiring full agent redeployment.

**Maturity scale:**

| Level | Description |
|-------|-------------|
| 0 | No isolation of agent memory; agents share context freely. |
| 1 | Memory is namespace-isolated per agent (MP-1). |
| 2 | External inputs to memory are validated (MP-1, MP-2). |
| 3 | Memory integrity is monitored and tampering is detectable (MP-1, MP-2, MP-3). |
| 4 | Memory rollback to known-good state is operational (MP-1 through MP-4). |

### 3.5 ACRF-05  - Supply Chain Toxicity

*Risk addressed: a malicious or compromised tool, skill, or plugin is introduced into the agent's dependency chain  - through a package registry, a skill marketplace, or a tool-poisoning attack  - and executes with the agent's authority.*

**OWASP cross-mapping:** ASI04 Supply Chain Vulnerabilities; MCP03 Tool Poisoning, MCP04 Tool Poisoning via Rug Pull.
**AIVSS:** 9.3 (Critical).
**Defense pattern:** Lock dependency versions, skill-scanner.

**Control objectives:**

- **SC-1.** All agent dependencies (tools, skills, plugins, packages) are pinned to specific versions with integrity-verified lockfiles.
- **SC-2.** An automated scanner runs in the CI/CD pipeline to detect known-vulnerable or known-malicious tools before deployment.
- **SC-3.** Runtime tool loading is restricted to an allow-list; agents cannot dynamically discover and invoke arbitrary tool endpoints.
- **SC-4.** A supply chain incident response plan exists, has been exercised, and can revoke a compromised tool across all agents within a defined SLA.

**Maturity scale:**

| Level | Description |
|-------|-------------|
| 0 | Dependencies are unpinned; agents can load tools dynamically without restriction. |
| 1 | Dependencies are pinned with lockfiles (SC-1). |
| 2 | Automated scanning in CI/CD (SC-1, SC-2). |
| 3 | Runtime tool loading is allow-list restricted (SC-1, SC-2, SC-3). |
| 4 | Incident response plan exercised with defined revocation SLA (SC-1 through SC-4). |

### 3.6 ACRF-06  - Config Files = Execution Vectors

*Risk addressed: agent configuration files are treated as inert data, but in practice they can specify tool endpoints, system prompts, allowed actions, and resource URIs  - making them execution vectors that, if modified, change agent behavior without touching code.*

**OWASP cross-mapping:** ASI05 Unexpected Code Execution; MCP05 Command Injection.
**AIVSS:** 8.7 (High).
**Defense pattern:** Sandboxing, read-only configs.

**Control objectives:**

- **CE-1.** Agent configuration files are read-only at runtime; changes require a controlled deployment pipeline.
- **CE-2.** Configuration files are validated against a schema before deployment; no executable or injection-capable content is permitted.
- **CE-3.** Configuration changes are audited with the same rigor as code changes (review, approval, rollback capability).
- **CE-4.** Sandboxing prevents a compromised config from escalating beyond the agent's authorized scope.

**Maturity scale:**

| Level | Description |
|-------|-------------|
| 0 | Configs are mutable at runtime; changes take effect without review. |
| 1 | Configs are read-only at runtime (CE-1). |
| 2 | Configs are schema-validated before deployment (CE-1, CE-2). |
| 3 | Config changes are audited with review and approval (CE-1, CE-2, CE-3). |
| 4 | Sandboxing limits blast radius of a compromised config (CE-1 through CE-4). |

### 3.7 ACRF-07  - Multi-Turn Defense Collapse

*Risk addressed: safety controls that hold on a single turn erode across multiple turns of agent interaction  - through gradual context manipulation, incremental permission escalation, or goal drift  - until the agent performs an action it would have refused in a single-turn context.*

**OWASP cross-mapping:** ASI01 Goal Hijack / Prompt Injection; MCP06 Intent Flow Subversion.
**AIVSS:** 9.4 (Critical).
**Defense pattern:** Deterministic intermediaries, session limits.

**Control objectives:**

- **MT-1.** Sessions have defined turn limits; agents cannot be engaged in unbounded multi-turn sequences.
- **MT-2.** Safety-critical decisions are re-evaluated at deterministic checkpoints, not just at the initial turn.
- **MT-3.** A deterministic intermediary (non-LLM logic) enforces invariants across turns, independent of the agent's context window.
- **MT-4.** Multi-turn defense erosion is tested in red-team exercises; regression tests cover known multi-turn attack patterns.

**Maturity scale:**

| Level | Description |
|-------|-------------|
| 0 | No turn limits or multi-turn safety checks. |
| 1 | Session turn limits are enforced (MT-1). |
| 2 | Safety decisions are re-evaluated at deterministic checkpoints (MT-1, MT-2). |
| 3 | Deterministic intermediary enforces cross-turn invariants (MT-1, MT-2, MT-3). |
| 4 | Multi-turn defense collapse is tested in red-team exercises (MT-1 through MT-4). |

### 3.8 ACRF-08  - Cascading Failure Blindness

*Risk addressed: Agent A calls B calls C calls D; when D does something wrong, there is no practical way to reconstruct whose intent initiated the chain, which hop introduced the error, or how to stop the cascade.*

**OWASP cross-mapping:** ASI08 Cascading Failures; MCP08 Lack of Audit.
**AIVSS:** 8.5 (High).
**Defense pattern:** Circuit breakers, agent-aware SIEM.

**Control objectives:**

- **CF-1.** Circuit breakers exist on all inter-agent channels; cascading failures are bounded by automatic trip thresholds.
- **CF-2.** Distributed tracing spans all agent hops; a full cascade can be reconstructed from any single action.
- **CF-3.** Trace and log integrity is protected against modification by parties who could benefit from modifying them.
- **CF-4.** The organization has a tested MTTR target for reconstructing an agent-action cause chain, and the target is met in practice.

**Maturity scale:**

| Level | Description |
|-------|-------------|
| 0 | No circuit breakers or cascade tracing. |
| 1 | Circuit breakers on inter-agent channels (CF-1). |
| 2 | Distributed tracing spans all hops (CF-1, CF-2). |
| 3 | Trace and log integrity is protected (CF-1, CF-2, CF-3). |
| 4 | Tested MTTR for cause-chain reconstruction (CF-1 through CF-4). |

### 3.9 ACRF-09  - Semantic Bypass

*Risk addressed: an attacker (or a compromised agent) uses semantically valid but misleading content  - natural-language reformulations, context over-sharing, or ambiguous intent  - to cause a receiving agent to take an action that formal controls would have blocked if the request had been expressed directly.*

**OWASP cross-mapping:** ASI09 Human-Agent Trust Failures; MCP10 Context Over-Sharing.
**AIVSS:** 8.6 (High).
**Defense pattern:** Guardian agents, intent validation.

**Control objectives:**

- **SB-1.** Responses from external or cross-boundary agents are validated against expected schemas; unstructured action-like content in data fields is blocked.
- **SB-2.** A guardian agent or intent-validation layer inspects inter-agent messages for semantic manipulation before the receiver acts.
- **SB-3.** Context sharing between agents is minimized to what is needed for the current task; over-sharing is flagged.
- **SB-4.** Semantic bypass is tested in red-team exercises; regression tests cover known natural-language reformulation attacks.

**Maturity scale:**

| Level | Description |
|-------|-------------|
| 0 | No validation of inter-agent message semantics. |
| 1 | Cross-boundary responses are schema-validated (SB-1). |
| 2 | Guardian agent or intent-validation layer in place (SB-1, SB-2). |
| 3 | Context sharing is minimized and over-sharing is flagged (SB-1, SB-2, SB-3). |
| 4 | Semantic bypass is covered in red-team exercises (SB-1 through SB-4). |

### 3.10 ACRF-10  - Safety Controls Not Self-Protecting

*Risk addressed: the guardrails themselves  - rate limits, authorization policies, audit pipelines  - can be disabled, reconfigured, or bypassed by the agents they are supposed to constrain, because the controls run with the same privileges or in the same trust domain as the agents.*

**OWASP cross-mapping:** ASI10 Rogue Agent Behavior; MCP02 Privilege Escalation.
**AIVSS:** 9.5 (Critical).
**Defense pattern:** Least agency, immutable guardrails.

**Control objectives:**

- **SP-1.** Guardrail configurations (rate limits, authorization policies, safety filters) are deployed immutably; no agent can modify them at runtime.
- **SP-2.** Safety controls run in a separate trust domain from the agents they constrain; an agent compromise does not grant the ability to disable its own guardrails.
- **SP-3.** Guardrail integrity is continuously monitored; tampering or drift triggers an alert independent of the agent's own reporting.
- **SP-4.** The principle of least agency is enforced: agents are granted the minimum capabilities needed for their task, and capability grants are reviewed on a defined cadence.

**Maturity scale:**

| Level | Description |
|-------|-------------|
| 0 | Safety controls are mutable by the agents they constrain. |
| 1 | Guardrail configs are immutable at runtime (SP-1). |
| 2 | Controls run in a separate trust domain from agents (SP-1, SP-2). |
| 3 | Guardrail integrity is continuously monitored (SP-1, SP-2, SP-3). |
| 4 | Least agency enforced with periodic capability review (SP-1 through SP-4). |

## 4. Assessment procedure

An ACRF assessment proceeds in four steps:

1. **Scope.** Define the system under assessment: which agents, which communication channels, which trust boundaries. Capture this in an ACRF system description file (see [`specs/system-description.schema.json`](../specs/system-description.schema.json)).

2. **Evidence collection.** For each of the ten risk dimensions, gather the evidence required to claim a maturity level. The assessor does not assign a level based on self-report; the evidence must exist and be reviewed.

3. **Scoring.** Assign the maturity level per dimension that is the highest level for which evidence fully supports the claim. Partial evidence drops the level by one. The AIVSS score for each dimension provides a severity-weighted view of the overall risk posture.

4. **Reporting.** Produce the ACRF report: per-dimension level, OWASP cross-mappings, AIVSS scores, evidence register, and a prioritized remediation backlog ordered by the gap between current and target level, weighted by dimension AIVSS severity and system-specific criticality.

The reference tool (`acrf assess`, `acrf report`) automates steps 3 and 4 given a system description and evidence file.

## 5. AIVSS scoring methodology

AIVSS (AI Vulnerability Severity Scoring) is a severity scale applied at the dimension level, not at the individual-finding level. Each ACRF risk dimension carries a fixed AIVSS score reflecting the worst-case impact of that risk category in a fully autonomous multi-agent deployment.

Scores were assigned by the authors based on three factors: (1) **worst-case blast radius**  - the scope of harm if the risk is fully exploited in a multi-agent chain, (2) **reversibility**  - whether the resulting damage can be undone without human intervention, and (3) **attacker accessibility**  - how easily an external or compromised agent can exploit the risk without privileged access. Each factor was evaluated against a reference deployment where agents make consequential real-world decisions (financial transactions, infrastructure changes, patient-affecting clinical decisions) without human-in-the-loop review. Systems with less autonomy or lower-consequence actions should contextualize the scores accordingly.

The severity bands are:

| AIVSS Range | Severity |
|-------------|----------|
| 9.0 – 10.0 | Critical |
| 7.0 – 8.9 | High |
| 4.0 – 6.9 | Medium |
| 0.0 – 3.9 | Low |

Six of the ten ACRF dimensions score Critical; four score High. No dimension scores below High because ACRF specifically targets the inter-agent communication layer, which is only relevant in systems with meaningful autonomy.

## 6. Governance of the methodology

This methodology is versioned. Breaking changes to dimension definitions, AIVSS scores, or maturity scales will be released under a new major version and announced via the repository's release notes. Non-breaking clarifications (examples, evidence suggestions, wording) may be released as patch versions. See [`docs/governance.md`](governance.md) for the full process.

## 7. What ACRF deliberately does not do

- **ACRF does not certify.** There is no ACRF certification, no ACRF auditor accreditation, and no "ACRF compliant" badge. A published assessment is a point-in-time evidence-backed claim about a specific system; it is not a standing certification.
- **ACRF does not mandate specific technologies.** The control objectives are technology-neutral. mTLS, signed JWTs, and OPA-style policy engines are examples of how to meet an objective, not requirements.
- **ACRF does not replace threat modeling.** A full security program still requires threat modeling, adversarial testing, and incident response. ACRF is a lens, not a program.

## 8. Acknowledgments

ACRF was created by Kanna Sekar and Ravi Karthick Sankara Narayanan. The methodology was first presented at RSA Conference 2026 and is maintained as an open-source project at [github.com/kannasekar-alt/acrf](https://github.com/kannasekar-alt/acrf).

ACRF draws on and credits prior work including OWASP Agentic Top 10, OWASP MCP Top 10, OWASP Top 10 for LLM Applications, MITRE ATLAS, NIST AI RMF, Google's Secure AI Framework (SAIF), and the broader zero-trust literature. A detailed mapping is maintained in [`related-work.md`](related-work.md).
