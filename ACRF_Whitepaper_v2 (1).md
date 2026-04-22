# ACRF: Mapping the Security Gap Between Agent Protocols

**A whitepaper introducing the Agent Communication Risk Framework (ACRF) v0.1**

*Kanna Sekar, Senior Security Customer Engineer, Google*
*Ravi Karthick Sankara Narayanan, Senior Security Consultant, Deloitte*

---

## Abstract

As autonomous AI agents proliferate across enterprise environments, two protocol standards have emerged to govern their security: MCP (Model Context Protocol) for the agent-to-tool boundary, and A2A (Agent-to-Agent Protocol) for inter-agent communication. Neither protocol validates the other's trust decisions. The Agent Communication Risk Framework (ACRF) identifies 10 risk dimensions that exploit this gap, cross-maps each to both the OWASP Agentic Top 10 and OWASP MCP Top 10, integrates AIVSS severity scoring, and pairs each risk with a concrete defense pattern. This paper presents the framework, its methodology, and practical guidance for operationalizing it.

---

## 1. Introduction: The Protocol Gap

### 1.1 The Agentic Explosion

The agentic AI landscape has moved from experimental to production in less than 18 months. Perplexity Computer orchestrates 19 models with multi-agent delegation. Anthropic's Claude Cowork manages sub-agent teams with a 14.5-hour autonomous horizon. Google's Agent Development Kit ships with the A2A protocol and Agent Cards for discovery. OpenAI's Codex and Operator enable autonomous coding and web browsing. Enterprise platforms from ServiceNow, Salesforce, and Microsoft embed agents in every workflow.

These agents don't operate in isolation. They call each other. They delegate tasks. They negotiate, execute transactions, and make decisions - often with no human in the loop.

### 1.2 MCP and A2A: Complementary but Incomplete

**MCP** (Anthropic-originated, now an industry standard) secures what agents *can do*. It defines capability whitelists, schemas, authentication, and sandboxing at the agent-to-tool boundary. It is used by Claude, Cursor, Windsurf, and a growing ecosystem of tools.

**A2A** (Google-led open standard) secures how agents *talk*. It uses JSON-RPC 2.0 and Agent Cards for capability discovery, enabling multi-agent coordination through the Agent Development Kit.

The gap between them is where trust fails. When Agent A delegates a task to Agent B via A2A, and Agent B executes it through an MCP tool, neither protocol checks whether the original delegation was legitimate. A spoofed Agent Card can inject malicious instructions that flow through the entire pipeline. A compromised research agent can issue instructions consumed by a financial agent, resulting in unintended trades. The attack surface is not in either protocol - it is in the space between them.

### 1.3 Why ACRF Exists

Before ACRF, a security team evaluating their agentic infrastructure had three separate lenses: the OWASP Agentic Top 10 for agent-level risks, the OWASP MCP Top 10 for tool-level risks, and AIVSS for severity scoring. No published framework connected them. ACRF provides that single view - 10 risk dimensions, each cross-mapped to both OWASP standards, scored for severity, and paired with a defense pattern.

---

## 2. Methodology

### 2.1 Risk Identification

The 10 ACRF risk dimensions were identified through analysis of real-world incidents, CVE disclosures, and threat research from 2025–2026, including:

- **CVE-2026-25253**: Safety APIs that became attack APIs - the same API controlling sandbox/safety was accessible to attackers with a stolen token. Guardrails could not protect themselves.
- **1,184 malicious skills** confirmed across ClawHub by Antiy CERT, including Trojan payloads, hidden MCP servers, and base64-encoded downloaders in legitimate packages.
- **Session smuggling attacks**: Spoofed Agent Cards injecting malicious JSON-RPC messages into agent pipelines, with a compromised research agent issuing hidden instructions consumed by a financial agent.
- **MCP Inspector CVEs**: CVE-2025-49596 (CVSS 9.4, unauthenticated access) and CVE-2025-6514 (CVSS 9.6, command injection), both exploitable on default installations.
- **China-linked APT activity**: A threat group automated 80–90% of a cyberattack chain by jailbreaking an AI coding assistant, demonstrating agent weaponization at nation-state scale.
- **Pynt Research finding**: Deploying just 10 MCP plugins yields a 92% exploitation probability.

Each incident was analyzed for which protocol boundary failed and which existing OWASP category it mapped to, revealing where the cross-protocol gap created the exploit path.

### 2.2 Cross-Framework Mapping

Each ACRF risk dimension was mapped to the most specific matching entry in both the OWASP Agentic Top 10 (ASI01–ASI10, December 2025) and the OWASP MCP Top 10 (MCP01–MCP10, 2025). Mappings were verified against the official OWASP source documents.

Some OWASP entries appear multiple times across the matrix. ASI04 (Supply Chain Vulnerabilities) appears in risks 03 and 05 because supply chain risk manifests as two distinct failure modes: uncontrolled server proliferation and poisoned packages. Similarly, ASI07 (Insecure Inter-Agent Communications) appears in risks 01 and 04 because implicit trust failures operate differently at the authentication layer versus the session layer. This is a finding, not a flaw - it reveals which risk surfaces are most overloaded.

### 2.3 AIVSS Integration

Severity scoring uses the Agentic Intelligence Vulnerability Scoring System (AIVSS) v0.8 (Ken Huang et al.), which extends CVSS v4.0 with Agentic Risk Amplification Factors (ARAFs) scored at 0.0, 0.5, or 1.0. The relevant amplifiers for ACRF risks include autonomy level, tool use scope, non-determinism, persistent memory, self-modification, dynamic identity, and multi-agent interactions.

AIVSS scores in the ACRF matrix reflect worst-case deployment scenarios (autonomous agents with full tool access and no guardrails) to provide a baseline for prioritization.

---

## 3. The ACRF Cross-Framework Matrix

| # | Risk Dimension | OWASP Agentic | OWASP MCP | AIVSS | Defense Pattern |
|---|---|---|---|---|---|
| 01 | Implicit Trust Between Agents | ASI07 Insecure Inter-Agent | MCP07 Insufficient Auth | Critical (9.2) | Warrant delegation, mTLS, signed Agent Cards |
| 02 | No Standard Agent Identity | ASI03 Identity & Privilege | MCP01 Token Mismanagement | Critical (9.0) | Agent Naming Service, OAuth 2.1, scoped tokens |
| 03 | MCP Server Sprawl | ASI04 Supply Chain Vulns | MCP09 Shadow MCP Servers | High (8.4) | Agent inventory, mcp-scan, AIBOM |
| 04 | Memory Poisoning | ASI06 Memory & Context | MCP06 Intent Flow Subversion | Critical (9.1) | Namespace isolation, contextual integrity |
| 05 | Supply Chain Toxicity | ASI04 Supply Chain Vulns | MCP03, MCP04 Tool Poisoning | Critical (9.3) | Lock dependency versions, skill-scanner |
| 06 | Config Files = Execution Vectors | ASI05 Unexpected Code Exec | MCP05 Command Injection | High (8.7) | Sandboxing, read-only configs |
| 07 | Multi-Turn Defense Collapse | ASI01 Goal Hijack | MCP06 Intent Flow Subversion | Critical (9.4) | Deterministic intermediaries, session limits |
| 08 | Cascading Failure Blindness | ASI08 Cascading Failures | MCP08 Lack of Audit | High (8.5) | Circuit breakers, agent-aware SIEM |
| 09 | Semantic Bypass | ASI09 Human-Agent Trust | MCP10 Context Over-Sharing | High (8.6) | Guardian agents, intent validation |
| 10 | Safety Controls Not Self-Protecting | ASI10 Rogue Agents | MCP02 Privilege Escalation | Critical (9.5) | Least agency, immutable guardrails |

---

## 4. The 10 Risk Dimensions in Detail

### 4.1 Implicit Trust Between Agents
**AIVSS: Critical (9.2) | ASI07 | MCP07**

When Agent A calls Agent B, there is no cryptographic verification. Agent B accepts the message because it arrived, not because the sender proved its identity. With an 82:1 machine-to-human ratio in typical agentic systems, there is no human watching each handshake. Spoofed Agent Cards exploit this by injecting malicious JSON-RPC messages into agent pipelines. In documented incidents, a compromised research agent injected hidden instructions that were consumed by a financial agent, resulting in unintended trades.

The defense pattern is **warrant delegation with mTLS and cryptographically signed Agent Cards** - mutual authentication before any communication occurs, with every message carrying verifiable proof of origin.

### 4.2 No Standard Agent Identity
**AIVSS: Critical (9.0) | ASI03 | MCP01**

There is no universal agent IAM. Agents identify themselves through self-declared metadata that can be trivially forged. OAuth tokens designed for human authentication are repurposed for agent identity, making those tokens the most valuable thing an attacker can steal. Leaked credentials allow agents to operate beyond their intended scope.

The defense is an **Agent Naming Service** (as proposed by Ken Huang et al. at OWASP) combined with **OAuth 2.1 with scoped, short-lived tokens** that are bound to specific agent-action pairs rather than inheriting a human user's full permission set.

### 4.3 MCP Server Sprawl
**AIVSS: High (8.4) | ASI04 | MCP09**

492 MCP servers have been found internet-exposed with zero authentication. Shadow servers with backdoors proliferate outside governance. Every unmanaged MCP server is an entry point into the agent communication fabric that no one is monitoring.

The defense is **agent inventory** - map every MCP server and tool integration, treat them as first-class assets, and run **mcp-scan** and generate **AIBOMs** (AI Bills of Materials) before any deployment.

### 4.4 Memory Poisoning
**AIVSS: Critical (9.1) | ASI06 | MCP06**

Corrupted context injected into an agent's memory persists across sessions and reshapes long-term behavior. Sleeper payloads can activate weeks after initial injection. Unlike hallucinations (a reliability problem that stays isolated), memory poisoning is an adversarial security problem - the corrupted context propagates across agents through inter-agent messages.

The defense is **namespace isolation and contextual integrity** - agent memory is scoped to a single session and not persisted without explicit validation. Context from external agents is treated as untrusted input.

### 4.5 Supply Chain Toxicity
**AIVSS: Critical (9.3) | ASI04 | MCP03, MCP04**

12% of the OpenClaw ecosystem has been confirmed compromised. Antiy CERT identified 1,184 malicious skills across ClawHub, including Trojan payloads, hidden MCP servers, and base64-encoded downloaders in legitimate packages. The first wild MCP malware - postmark-mcp (September 2025) - silently BCC'd every message to an attacker.

The defense is **locked dependency versions, skill-scanner, and supply chain hardening** - audit all packages, pin versions, and scan for known-malicious patterns before deployment.

### 4.6 Config Files = Execution Vectors
**AIVSS: High (8.7) | ASI05 | MCP05**

`.mcp.json` config files have become de facto installers. Three RCE CVEs in Claude Code alone were traced to config file exploitation. Agents construct system commands from untrusted input embedded in configuration, turning what should be a static declaration into an execution path.

The defense is **sandboxing and read-only configs** - configuration files must not be executable, and any command construction from config values must be validated against a strict allowlist.

### 4.7 Multi-Turn Defense Collapse
**AIVSS: Critical (9.4) | ASI01 | MCP06**

Single-turn prompt injection defenses fail in long-running agent sessions. Research by Pynt demonstrates a 92% success rate for multi-turn attacks. Each individual request appears benign; the cumulative effect across 20+ turns is complete goal hijack. Persistent memory compounds the problem - the poison from turn 3 is still active at turn 20.

The defense is **deterministic intermediaries and session limits** - structured validation layers between agents that enforce schema compliance at each turn, combined with mandatory session resets and re-authorization after a bounded number of interactions.

### 4.8 Cascading Failure Blindness
**AIVSS: High (8.5) | ASI08 | MCP08**

When something goes wrong in an agent chain, existing SIEM infrastructure cannot tell you which agent started the cascade. Agent A calls B calls C calls D; when D takes an unauthorized action, there is no practical way to reconstruct whose intent initiated the chain. Without agent-aware observability, cascading failures compound silently.

The defense is **circuit breakers and agent-aware SIEM** - automated kill switches that halt agent chains when anomalous behavior is detected, combined with observability infrastructure that traces causality across agent delegation chains.

### 4.9 Semantic Bypass
**AIVSS: High (8.6) | ASI09 | MCP10**

Traditional firewalls cannot distinguish legitimate agent queries from malicious ones because both look like well-formed natural language. An agent asking "summarize the customer's financial history" and an agent exfiltrating that data use syntactically identical requests. The semantic layer - where meaning determines intent - is invisible to conventional security tooling.

The defense is **guardian agents and intent validation** - dedicated monitoring agents that validate the semantic intent of inter-agent messages against declared policy, catching what network-layer controls miss.

### 4.10 Safety Controls Not Self-Protecting
**AIVSS: Critical (9.5) | ASI10 | MCP02**

The highest-severity risk in the ACRF matrix. CVE-2026-25253 demonstrated that the same API controlling sandbox and safety controls was accessible to attackers with a stolen token. If your safety layer can be disabled through the same interface it's supposed to protect, you don't have a safety layer. Every other defense in this framework becomes moot if the safety controls themselves are compromised.

The defense is **least agency and immutable guardrails** - safety control APIs must be architecturally separated from the interfaces they protect, with immutable configurations that cannot be modified at runtime by the agents or tools they govern.

---

## 5. Emergent Patterns

Three structural patterns emerge from the ACRF matrix:

**Identity and privilege are the most overloaded risk surfaces.** ASI03 and ASI04 each appear twice; ASI07 appears twice. If an organization can only harden one area first, identity management and supply chain integrity across agent chains are the highest-leverage investments.

**Agentic amplifiers fundamentally change severity math.** A prompt injection in a chatbot is a bounded risk. The same injection in an autonomous agent with persistent memory, tool access, and delegation authority is a fundamentally different calculation. AIVSS captures this through amplifiers that traditional CVSS cannot model. Six of the ten ACRF risks score Critical.

**No single vendor closes all 10 risks.** Analysis of the current defense ecosystem - including products from Palo Alto (Prisma AIRS 2.0), Cisco (AI Defense), F5 (AI Guardrails), Lakera (Guard), Straiker, Zscaler (AI Security), Gravitee (Agent Gateway), and Cequence (AI Gateway) - shows that Cisco AI Defense covers the most (~9 of 10 ACRF risks), followed by Palo Alto Prisma AIRS 2.0 (~7 of 10). Key persistent gaps across all vendors: self-protecting safety controls and the MCP/A2A protocol gap itself. Defense-in-depth across multiple layers remains necessary.

---

## 6. Operationalizing ACRF

### 6.1 The 6-Point Action Plan

1. **Inventory Your Agents** - Map every AI agent, MCP server, and tool integration. Treat agents as first-class identities.
2. **Kill Implicit Trust** - Enforce mutual authentication between all agents. Cryptographically sign Agent Cards. No default trust.
3. **Apply Least Agency** - Minimum autonomy for bounded tasks. Scope permissions tightly. Human approval for high-impact actions.
4. **Harden the Supply Chain** - Audit all MCP servers. Pin dependencies. Generate AIBOMs. Run mcp-scan before deployment.
5. **Deploy Runtime Guardrails** - Real-time monitoring at every agent boundary. Anomaly detection. Circuit breakers for cascading failures.
6. **Red Team Continuously** - Multi-turn adversarial testing. Memory poisoning probes. Test the full workflow, not just the model.

### 6.2 Using the Matrix

When evaluating a new agent integration, run it against the 10 ACRF rows:

- Which risk dimensions does this integration introduce?
- What is the AIVSS severity for our specific deployment profile?
- Which defense patterns are already in place?
- Which gaps remain?

This transforms ACRF from a reference table into a security review checklist.

---

## 7. Roadmap

**ACRF v2.0** will add product-level implementation mappings - connecting each defense pattern to specific vendor capabilities and open-source tools. The goal is to bridge the gap between "what to defend" (v0.1) and "how to defend it with available products" (v2.0).

The broader landscape continues to evolve. The OWASP Agentic Skills Top 10 (AST10) is an adjacent framework scoped differently from ACRF but relevant to the overall security surface. ACRF will monitor and incorporate relevant developments.

---

## 8. Acknowledgments

- **Ken Huang and co-authors** - AIVSS v0.8 (Agentic Intelligence Vulnerability Scoring System) and OWASP Agent Naming Service (ANS)
- **Niki Niyikiza** - Tenuo open-source work, agent delegation and trust boundary research
- **OWASP Foundation** - The Agentic Top 10 and MCP Top 10 communities
- **RSAC** - For hosting the virtual seminar where ACRF was first presented

---

## 9. References

- OWASP Agentic Top 10 (ASI01–ASI10), December 2025. https://owasp.org/www-project-agentic-ai-threats/
- OWASP MCP Top 10 (MCP01–MCP10), 2025. https://owasp.org/www-project-mcp-top-10/
- AIVSS v0.8 - Agentic Intelligence Vulnerability Scoring System. Ken Huang et al.
- Google A2A Protocol. https://github.com/google/A2A
- Anthropic MCP Specification. https://modelcontextprotocol.io/
- Pynt Research - MCP Plugin Exploitation Probability Study, 2025.
- Antiy CERT - ClawHub Malicious Skills Report, 2025.
- RSAC 2026 Virtual Seminar: "My AI Will Call Your AI: Securing Agent-to-Agent Communication." Sekar & Sankara Narayanan. https://www.rsaconference.com/library/virtual-seminar/hds-22-agentic-ai-challenges-increased-autonomy

---

## Citation

```
Sekar, K. & Sankara Narayanan, R.K. (2026). Agent Communication Risk Framework (ACRF) v0.1:
Mapping the Security Gap Between Agent Protocols. Presented at RSAC 2026 Virtual Seminar.
https://github.com/kannasekar-alt/acrf
```

---

*Licensed under Creative Commons Attribution 4.0 International (CC BY 4.0).*
