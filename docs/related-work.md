# Related Work

ACRF is designed to sit alongside, not replace, existing bodies of work on AI and agent security. This document (a) states the specific gap that ACRF fills and that no adjacent framework fills, (b) maps ACRF's ten risk dimensions to the nearest equivalents in adjacent frameworks, and (c) identifies the constructs within ACRF that are not present in any framework surveyed.

## What no existing framework does  - the gap ACRF fills

**No existing framework cross-maps the agent-to-agent communication layer across both the OWASP Agentic Top 10 (ASI) and the OWASP MCP Top 10, with per-dimension severity scoring calibrated to autonomous multi-agent deployments.**

This is the precise claim. To be concrete about what it means:

- **OWASP Agentic Top 10 (ASI)** covers risks introduced by agentic AI systems  - goal hijacking, identity failures, memory manipulation, cascading failures. Its unit of analysis is the *agent* and its security posture.
- **OWASP MCP Top 10** covers risks in the Model Context Protocol  - token mismanagement, tool poisoning, shadow servers, privilege escalation. Its unit of analysis is the *agent-to-tool boundary*.
- **ACRF's unit of analysis is the agent-to-agent communication channel**  - the layer between these two bodies of work. ACRF identifies that cross-boundary agent communication creates a distinct attack surface not fully addressed by either framework alone, maps each risk dimension to both simultaneously, and provides severity scores (AIVSS) and maturity-scaled control objectives.

No other published framework  - including MITRE ATLAS, NIST AI RMF, NIST SP 800-53, OWASP Top 10 for LLMs, or Google SAIF  - performs this cross-mapping or addresses the agent communication layer as a first-class risk surface. The specific combinations of (cross-framework mapping) × (A2A communication scope) × (AIVSS severity scoring) × (evidence-backed maturity model) does not appear elsewhere in the public AI security literature as of the date of first publication (April 2026).

## The broader gap ACRF addresses

Existing frameworks cover two well-defined surfaces:

- **The model surface**  - adversarial inputs, prompt injection, data poisoning, model theft, membership inference. Well-covered by MITRE ATLAS, NIST AI 100-2, and OWASP Top 10 for LLM Applications.
- **The application surface**  - the APIs, identities, network paths, and data stores on which agents run. Well-covered by traditional AppSec, OWASP API Top 10, and zero-trust architectures.

Agent-to-agent communication falls between them. It is not a model-internal problem  - the model isn't under attack, and no adversarial input is necessarily present. It is not a conventional API problem  - the caller is itself an autonomous decision-maker, not a deterministic client, so the risk profile is different. **ACRF names this space and provides structure for it.**

The MCP protocol defines the agent-to-tool boundary; the A2A protocol defines agent-to-agent messaging. Neither alone addresses all the trust failures that emerge when agents communicate. ACRF identifies that gap and cross-maps it to two existing OWASP bodies of work  - the Agentic Top 10 and the MCP Top 10  - so that practitioners get one coherent view across all three.

## Cross-framework mapping

Each ACRF risk dimension is cross-mapped to the OWASP Agentic Top 10 (ASI) and OWASP MCP Top 10 in the [methodology](methodology.md). The table below extends that mapping to additional adjacent frameworks.

### ACRF-01 Implicit Trust Between Agents (AIVSS 9.2)

| Framework | Nearest equivalent | Relationship |
|-----------|---------------------|---------------|
| NIST AI RMF | "Govern" function  - accountability structures | ACRF specializes to inter-agent trust delegation |
| Zero Trust (NIST SP 800-207) | PE.1  - Identity for every subject | ACRF treats the agent as a first-class subject, not a proxy for its user |
| Google SAIF | Element: "Expand strong security foundations" | ACRF provides operational specificity for the agent case |

### ACRF-02 No Standard Agent Identity (AIVSS 9.0)

| Framework | Nearest equivalent | Relationship |
|-----------|---------------------|---------------|
| MITRE ATLAS | Initial Access techniques | ACRF covers the defense side: per-agent cryptographic identity |
| OWASP Top 10 for LLMs | LLM05: Supply Chain Vulnerabilities (partial) | ACRF covers runtime identity, not build-time supply chain |
| Zero Trust (NIST SP 800-207) | PE.1  - Identity for every subject | Direct alignment; ACRF extends to agent-vs-user identity distinction |

### ACRF-03 MCP Server Sprawl (AIVSS 8.4)

| Framework | Nearest equivalent | Relationship |
|-----------|---------------------|---------------|
| NIST SP 800-53 | CM family  - Configuration Management | ACRF applies inventory and drift-detection specifically to MCP tool endpoints |
| OWASP Top 10 for LLMs | LLM05: Supply Chain Vulnerabilities | ACRF narrows to the runtime tool-server inventory problem |

### ACRF-04 Memory Poisoning (AIVSS 9.1)

| Framework | Nearest equivalent | Relationship |
|-----------|---------------------|---------------|
| OWASP Top 10 for LLMs | LLM02: Sensitive Information Disclosure; LLM01: Prompt Injection | ACRF addresses persistent memory corruption across agent interactions |
| MITRE ATLAS | Persistence techniques | ACRF provides defensive controls for agent-context integrity |

### ACRF-05 Supply Chain Toxicity (AIVSS 9.3)

| Framework | Nearest equivalent | Relationship |
|-----------|---------------------|---------------|
| NIST SP 800-161 | Software supply chain risk management | ACRF applies to the agent-specific supply chain: skills, tools, plugins |
| OWASP Top 10 for LLMs | LLM05: Supply Chain Vulnerabilities | Direct overlap; ACRF adds agent-specific tool-poisoning and rug-pull patterns |

### ACRF-06 Config Files = Execution Vectors (AIVSS 8.7)

| Framework | Nearest equivalent | Relationship |
|-----------|---------------------|---------------|
| NIST SP 800-53 | CM-5, CM-6  - Access restrictions for change, Configuration settings | ACRF extends to agent configs that control behavior via prompts and tool endpoints |
| OWASP API Top 10 | API8: Security Misconfiguration | ACRF identifies that agent configs are execution vectors, not just settings |

### ACRF-07 Multi-Turn Defense Collapse (AIVSS 9.4)

| Framework | Nearest equivalent | Relationship |
|-----------|---------------------|---------------|
| OWASP Top 10 for LLMs | LLM01: Prompt Injection | ACRF extends to the multi-turn erosion pattern unique to agentic systems |
| MITRE ATLAS | Evasion techniques | ACRF provides deterministic-intermediary defense pattern |

### ACRF-08 Cascading Failure Blindness (AIVSS 8.5)

| Framework | Nearest equivalent | Relationship |
|-----------|---------------------|---------------|
| NIST SP 800-53 | AU family  - Audit and accountability | ACRF specializes to cascade-aware log linkage across agent hops |
| NIST AI RMF | "Manage"  - documentation and traceability | ACRF provides measurable MTTR targets for cause-chain reconstruction |

### ACRF-09 Semantic Bypass (AIVSS 8.6)

| Framework | Nearest equivalent | Relationship |
|-----------|---------------------|---------------|
| OWASP Top 10 for LLMs | LLM01: Prompt Injection; LLM08: Excessive Agency | ACRF addresses the inter-agent channel: semantic manipulation between agents |
| Google SAIF | Element: "Automate defenses" | Partial alignment; ACRF provides guardian-agent defense pattern |

### ACRF-10 Safety Controls Not Self-Protecting (AIVSS 9.5)

| Framework | Nearest equivalent | Relationship |
|-----------|---------------------|---------------|
| OWASP Top 10 for LLMs | LLM08: Excessive Agency | ACRF extends to the guardrail-integrity problem: controls that agents can disable |
| NIST SP 800-53 | AC-6  - Least privilege | ACRF applies least-agency principle specifically to autonomous agent capabilities |
| MITRE ATLAS | Impact techniques | ACRF provides defense: immutable guardrails in a separate trust domain |

## What ACRF contributes that is not present in any adjacent framework

The cross-framework mapping above demonstrates significant overlap between ACRF dimensions and existing bodies of work. This is by design  - ACRF is meant to complement, not replace. The four constructs below are **not present in any of the frameworks surveyed above** and represent ACRF's original contributions to the field:

1. **Cross-framework A2A risk mapping.** No existing framework systematically cross-maps the OWASP Agentic Top 10 and the OWASP MCP Top 10 through the agent communication layer. OWASP Agentic Top 10 and OWASP MCP Top 10 are maintained independently, with overlapping but inconsistent coverage of the same underlying risks. ACRF provides the bridge: each of the ten risk dimensions maps to a named entry in *both* frameworks simultaneously, giving practitioners a single artifact that replaces the manual reconciliation of two bodies of work.

2. **AIVSS severity scoring for A2A risk dimensions.** CVSS scores vulnerabilities in software components. OWASP frameworks describe risk categories qualitatively. MITRE ATLAS describes attacker techniques without severity ratings. NIST AI RMF provides a governance structure without risk scores. **No existing AI security framework provides per-dimension severity scores calibrated to autonomous multi-agent deployments.** AIVSS fills this gap: each ACRF dimension carries a fixed score anchored to three factors  - worst-case blast radius in a multi-agent chain, reversibility of the resulting harm, and attacker accessibility without privileged access. This gives organizations a quantitative basis for prioritizing remediation that does not exist elsewhere.

3. **Least agency as a distinct principle from least privilege.** Traditional least-privilege controls (NIST SP 800-53 AC-6, zero-trust identity) restrict what an identity can *access*. ACRF-10 introduces *least agency*  - restricting the autonomous *capabilities* an agent is granted, independent of the data it can access. An agent may legitimately have read access to a record (privilege) but should not have the autonomous capability to decide to delete it (agency). The privilege-vs-agency distinction does not appear in NIST SP 800-53, OWASP Top 10 for LLMs, MITRE ATLAS, or NIST AI RMF.

4. **Deterministic intermediaries as a named defense for multi-turn erosion.** ACRF-07 names the failure mode where safety controls that hold on a single interaction erode across multiple turns of agent dialogue  - through gradual context manipulation, incremental permission escalation, or goal drift  - and prescribes a specific defense: a non-LLM deterministic intermediary that enforces invariants across turns, independent of the agent's context window. OWASP Agentic Top 10 ASI01 names the attack (goal hijacking via prompt injection) but does not prescribe this defense. MITRE ATLAS covers evasion techniques without prescribing multi-turn-specific countermeasures. This defense pattern first appears in the public AI security literature in ACRF.

## Choosing between ACRF and adjacent frameworks

Use **ACRF** when the question is: *"Are the conversations between our agents themselves safe, and can we prove it?"*

Use **OWASP Top 10 for LLMs** when the question is: *"Are the individual LLM-backed components in our system protected against known attack classes?"*

Use **MITRE ATLAS** when the question is: *"What does the attacker lifecycle against ML systems look like, and where are we exposed in that lifecycle?"*

Use **NIST AI RMF** when the question is: *"What is our organizational AI risk management program, and how do we govern it?"*

Use **Google SAIF** when the question is: *"What principles should guide our secure AI development across the full stack?"*

In practice, a mature program will use several of these together. ACRF is intended to be the specific, narrow, operationalizable piece that covers the A2A communication layer  - and uniquely, it cross-maps every risk dimension to both the OWASP Agentic Top 10 and the OWASP MCP Top 10 so practitioners don't have to bridge those bodies of work themselves.
