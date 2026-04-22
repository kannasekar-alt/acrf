# ACRF Assessment  - Travel Booking Multi-Agent System

- **Methodology version:** 0.1
- **Assessment date:** 2026-04-20
- **Overall mean level:** 1.70

## Risk dimension scores

| # | Risk Dimension | AIVSS | Claimed | Awarded |
|---|----------------|-------|---------|---------|
| ACRF-01 | Implicit Trust Between Agents | 9.2 (Critical) | 3 | 3 |
| ACRF-02 | No Standard Agent Identity | 9.0 (Critical) | 3 | 3 |
| ACRF-03 | MCP Server Sprawl | 8.4 (High) | 1 | 1 |
| ACRF-04 | Memory Poisoning | 9.1 (Critical) | 1 | 1 |
| ACRF-05 | Supply Chain Toxicity | 9.3 (Critical) | 2 | 2 |
| ACRF-06 | Config Files = Execution Vectors | 8.7 (High) | 2 | 2 |
| ACRF-07 | Multi-Turn Defense Collapse | 9.4 (Critical) | 1 | 1 |
| ACRF-08 | Cascading Failure Blindness | 8.5 (High) | 2 | 2 |
| ACRF-09 | Semantic Bypass | 8.6 (High) | 1 | 1 |
| ACRF-10 | Safety Controls Not Self-Protecting | 9.5 (Critical) | 1 | 1 |

## Per-dimension findings

### ACRF-01  - Implicit Trust Between Agents

- **OWASP Agentic:** ASI07 Insecure Inter-Agent
- **OWASP MCP:** MCP07 Insufficient Auth
- **AIVSS:** 9.2 (Critical)
- **Defense pattern:** Warrant delegation, mTLS, signed Agent Cards
- Claimed level: **3**
- Awarded level: **3**

**Notes:**
- System has cross-boundary channels; verify that IT-2 evidence covers external as well as internal trust delegation.

**Evidence gaps:**
- Level 4 requires evidence for IT-1, IT-2, IT-3, IT-4; missing: IT-4

### ACRF-02  - No Standard Agent Identity

- **OWASP Agentic:** ASI03 Identity & Privilege
- **OWASP MCP:** MCP01 Token Mismanagement
- **AIVSS:** 9.0 (Critical)
- **Defense pattern:** Agent Naming Service, OAuth 2.1, scoped tokens
- Claimed level: **3**
- Awarded level: **3**

**Evidence gaps:**
- Level 4 requires evidence for SI-1, SI-2, SI-3, SI-4; missing: SI-4

### ACRF-03  - MCP Server Sprawl

- **OWASP Agentic:** ASI04 Supply Chain Vulns
- **OWASP MCP:** MCP09 Shadow MCP Servers
- **AIVSS:** 8.4 (High)
- **Defense pattern:** Agent inventory, mcp-scan, AIBOM
- Claimed level: **1**
- Awarded level: **1**

**Evidence gaps:**
- Level 2 requires evidence for SS-1, SS-2; missing: SS-2

### ACRF-04  - Memory Poisoning

- **OWASP Agentic:** ASI06 Memory & Context
- **OWASP MCP:** MCP06 Intent Flow Subversion
- **AIVSS:** 9.1 (Critical)
- **Defense pattern:** Namespace isolation, contextual integrity
- Claimed level: **1**
- Awarded level: **1**

**Evidence gaps:**
- Level 2 requires evidence for MP-1, MP-2; missing: MP-2

### ACRF-05  - Supply Chain Toxicity

- **OWASP Agentic:** ASI04 Supply Chain Vulns
- **OWASP MCP:** MCP03, MCP04 Tool Poisoning
- **AIVSS:** 9.3 (Critical)
- **Defense pattern:** Lock dependency versions, skill-scanner
- Claimed level: **2**
- Awarded level: **2**

**Evidence gaps:**
- Level 3 requires evidence for SC-1, SC-2, SC-3; missing: SC-3

### ACRF-06  - Config Files = Execution Vectors

- **OWASP Agentic:** ASI05 Unexpected Code Exec
- **OWASP MCP:** MCP05 Command Injection
- **AIVSS:** 8.7 (High)
- **Defense pattern:** Sandboxing, read-only configs
- Claimed level: **2**
- Awarded level: **2**

**Evidence gaps:**
- Level 3 requires evidence for CE-1, CE-2, CE-3; missing: CE-3

### ACRF-07  - Multi-Turn Defense Collapse

- **OWASP Agentic:** ASI01 Goal Hijack
- **OWASP MCP:** MCP06 Intent Flow Subversion
- **AIVSS:** 9.4 (Critical)
- **Defense pattern:** Deterministic intermediaries, session limits
- Claimed level: **1**
- Awarded level: **1**

**Evidence gaps:**
- Level 2 requires evidence for MT-1, MT-2; missing: MT-2

### ACRF-08  - Cascading Failure Blindness

- **OWASP Agentic:** ASI08 Cascading Failures
- **OWASP MCP:** MCP08 Lack of Audit
- **AIVSS:** 8.5 (High)
- **Defense pattern:** Circuit breakers, agent-aware SIEM
- Claimed level: **2**
- Awarded level: **2**

**Notes:**
- System has multiple agent channels; verify that CF-1 evidence includes circuit-breaker coverage across all hops.

**Evidence gaps:**
- Level 3 requires evidence for CF-1, CF-2, CF-3; missing: CF-3

### ACRF-09  - Semantic Bypass

- **OWASP Agentic:** ASI09 Human-Agent Trust
- **OWASP MCP:** MCP10 Context Over-Sharing
- **AIVSS:** 8.6 (High)
- **Defense pattern:** Guardian agents, intent validation
- Claimed level: **1**
- Awarded level: **1**

**Evidence gaps:**
- Level 2 requires evidence for SB-1, SB-2; missing: SB-2

### ACRF-10  - Safety Controls Not Self-Protecting

- **OWASP Agentic:** ASI10 Rogue Agents
- **OWASP MCP:** MCP02 Privilege Escalation
- **AIVSS:** 9.5 (Critical)
- **Defense pattern:** Least agency, immutable guardrails
- Claimed level: **1**
- Awarded level: **1**

**Evidence gaps:**
- Level 2 requires evidence for SP-1, SP-2; missing: SP-2

## Remediation backlog

1. ACRF-10 Safety Controls Not Self-Protecting: advance from level 1 to 2 by providing evidence for SP-2 (priority score 6.2)
2. ACRF-07 Multi-Turn Defense Collapse: advance from level 1 to 2 by providing evidence for MT-2 (priority score 4.6)
3. ACRF-09 Semantic Bypass: advance from level 1 to 2 by providing evidence for SB-2 (priority score 3.8)
4. ACRF-05 Supply Chain Toxicity: advance from level 2 to 3 by providing evidence for SC-3 (priority score 3.1)
5. ACRF-04 Memory Poisoning: advance from level 1 to 2 by providing evidence for MP-2 (priority score 3.0)
6. ACRF-03 MCP Server Sprawl: advance from level 1 to 2 by providing evidence for SS-2 (priority score 2.8)
7. ACRF-08 Cascading Failure Blindness: advance from level 2 to 3 by providing evidence for CF-3 (priority score 2.5)
8. ACRF-06 Config Files = Execution Vectors: advance from level 2 to 3 by providing evidence for CE-3 (priority score 1.9)
9. ACRF-01 Implicit Trust Between Agents: advance from level 3 to 4 by providing evidence for IT-4 (priority score 1.5)
10. ACRF-02 No Standard Agent Identity: advance from level 3 to 4 by providing evidence for SI-4 (priority score 1.5)

---

_Generated by the ACRF reference tool. The methodology is described at [https://github.com/kannasekar-alt/acrf](https://github.com/kannasekar-alt/acrf)._