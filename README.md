# ACRF - Agent Communication Risk Framework

**A structured risk methodology for securing agent-to-agent (A2A) communications. Ten risk dimensions, severity-scored and defense-paired, covering the trust failures that emerge when autonomous AI agents talk to each other.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## Origin

ACRF was introduced at **RSA Conference 2026** in the virtual seminar *"My AI Will Call Your AI: Securing Agent-to-Agent Communication"* by **Kanna Sekar** (Google) and **Ravi Karthick Sankara Narayanan** (Deloitte). [RSAC session listing](https://www.rsaconference.com/Library/virtual-seminar/hds-22-agentic-ai-challenges-increased-autonomy)

## What is ACRF?

As autonomous AI agents begin communicating with other agents - placing orders, negotiating, sharing context, invoking tools - the attack surface shifts. Existing AI security work focuses on *model* risks (prompt injection, jailbreaks, data leakage) or *infrastructure* risks (the stack that runs the model). Neither addresses what happens when the agents themselves become the callers. **ACRF covers that gap: the communication layer where agents talk to each other.**

ACRF defines **10 risk dimensions** for agent-to-agent communication security. Each dimension identifies a specific failure mode, assigns an AIVSS (AI Vulnerability Severity Scoring) severity score, and prescribes a concrete defense pattern. Dimensions are also cross-mapped to the OWASP Agentic Top 10 and OWASP MCP Top 10 so practitioners can trace coverage across existing bodies of work.

It is designed to be:

- **Narrow enough to adopt tomorrow.** Ten risk dimensions, a scoring rubric, a CLI, and machine-readable reports.
- **Evidence-producing.** Assessments generate reports suitable for audits, procurement, and regulatory evidence.
- **Traceable to existing standards.** Each dimension maps to OWASP Agentic Top 10 and OWASP MCP Top 10 entries, so ACRF plugs into security programs that already reference those frameworks.

## The 10 ACRF Risk Dimensions

| # | Risk Dimension | OWASP Agentic | OWASP MCP | AIVSS | Defense Pattern |
|---|----------------|---------------|-----------|-------|-----------------|
| 01 | **Implicit Trust Between Agents** | ASI07 Insecure Inter-Agent | MCP07 Insufficient Auth | Critical (9.4) | Warrant delegation, mTLS, signed Agent Cards |
| 02 | **No Standard Agent Identity** | ASI03 Identity & Privilege | MCP01 Token Mismanagement | High (8.2) | Agent Naming Service, OAuth 2.1, scoped tokens |
| 03 | **MCP Server Sprawl** | ASI04 Supply Chain Vulns | MCP09 Shadow MCP Servers | High (7.2) | Agent inventory, mcp-scan, AIBOM |
| 04 | **Memory Poisoning** | ASI06 Memory & Context | MCP06 Intent Flow Subversion | High (8.6) | Namespace isolation, contextual integrity |
| 05 | **Supply Chain Toxicity** | ASI04 Supply Chain Vulns | MCP03, MCP04 Tool Poisoning | Critical (9.2) | Lock dependency versions, skill-scanner |
| 06 | **Config Files = Execution Vectors** | ASI05 Unexpected Code Exec | MCP05 Command Injection | High (7.8) | Sandboxing, read-only configs |
| 07 | **Multi-Turn Defense Collapse** | ASI01 Goal Hijack | MCP06 Intent Flow Subversion | Critical (9.6) | Deterministic intermediaries, session limits |
| 08 | **Cascading Failure Blindness** | ASI08 Cascading Failures | MCP08 Lack of Audit | High (7.4) | Circuit breakers, agent-aware SIEM |
| 09 | **Semantic Bypass** | ASI09 Human-Agent Trust | MCP10 Context Over-Sharing | High (8.0) | Guardian agents, intent validation |
| 10 | **Safety Controls Not Self-Protecting** | ASI10 Rogue Agents | MCP02 Privilege Escalation | Critical (9.8) | Least agency, immutable guardrails |

See [`docs/methodology.md`](docs/methodology.md) for the full rubric, evidence requirements, and maturity scales.

## Quickstart

```bash
pip install acrf

# Run an assessment against a declarative system description
acrf assess examples/travel-booking-agents.yaml

# Generate a human-readable report
acrf report examples/travel-booking-agents.yaml --format markdown -o report.md

# Validate that a system description conforms to the ACRF schema
acrf validate examples/travel-booking-agents.yaml
```

Or in Python:

```python
from acrf import Assessment, load_system

system = load_system("examples/travel-booking-agents.yaml")
result = Assessment(system).run()
print(result.summary())
```

## Assess Your Own System

The examples in this repo show pre-built scenarios. To evaluate **your own** agent architecture, you describe it in a YAML file and run the CLI against it. The whole process takes about 15 minutes.

### Step 1: Start from a template

Pick the assessment template closest to your architecture:

```bash
# Customer-facing agents with delegation and high-blast-radius actions
cp acrf/assessments/implicit-trust.yaml my-system.yaml

# Agents that pull from MCP registries or third-party tool servers
cp acrf/assessments/supply-chain-toxicity.yaml my-system.yaml

# Multi-turn conversational agents with per-turn guardrails
cp acrf/assessments/multi-turn-defense-collapse.yaml my-system.yaml

# Systems where operational agents can reach the safety/policy layer
cp acrf/assessments/safety-controls-not-self-protecting.yaml my-system.yaml
```

Or start from scratch — any YAML conforming to `specs/system-description.schema.json` works.

### Step 2: Describe your agents

List every agent in the system with its role and identity scheme:

```yaml
agents:
  - id: orchestrator
    name: "Order Processing Orchestrator"
    role: orchestrator
    identity_scheme: mtls-spiffe
    operates_on_behalf_of: user

  - id: inventory
    name: "Inventory Service Agent"
    role: service_agent
    identity_scheme: oauth-client-credentials
    operates_on_behalf_of: service

  - id: payment
    name: "Payment Processing Agent"
    role: service_agent
    identity_scheme: oauth-client-credentials
    operates_on_behalf_of: service
```

Roles: `orchestrator`, `tool_user`, `service_agent`, `third_party`.

### Step 3: Map your channels

Define how agents communicate. Pay attention to trust boundary crossings and blast radius — these drive the severity weighting:

```yaml
channels:
  - id: ch-orch-payment
    sender: orchestrator
    receiver: payment
    transport: https
    message_format: json-rpc
    crosses_trust_boundary: true
    synchronous: true
    actions:
      - name: charge_customer
        blast_radius: critical
        reversible: false
      - name: lookup_balance
        blast_radius: low
        reversible: true
```

### Step 4: Claim your maturity and attach evidence

For each risk dimension you want to assess, state the level you believe you've reached (0–4) and point to the artifacts that prove it:

```yaml
evidence:
  implicit_trust:
    claimed_level: 2
    artifacts:
      - control_objective: IT-1
        artifact: "configs/agent-mtls-policy.yaml"
        description: "mTLS with SPIFFE IDs verified on every agent-to-agent call."
      - control_objective: IT-2
        artifact: "policies/action-scopes.rego"
        description: "OPA policy restricting which agents can invoke which actions."
```

Leave out dimensions you're not ready to assess — the tool will score them as Level 0.

### Step 5: Validate and run

```bash
# Check your YAML is structurally valid
acrf validate my-system.yaml

# Run the assessment — see a summary with gaps
acrf assess my-system.yaml

# Generate a full report for your security review
acrf report my-system.yaml --format markdown -o my-system-report.md
```

### What you get back

The assessment engine checks your claimed level against the evidence you provided. For each of the 10 risk dimensions, it awards the highest maturity level whose control objectives all have supporting artifacts — and tells you exactly what's missing.

A full report includes per-dimension findings, OWASP cross-references, defense pattern recommendations, evidence gaps, and a prioritized remediation backlog weighted by AIVSS severity. See `examples/sample-assessment-report.md` for a complete example.

**Or use it programmatically:**

```python
from acrf import Assessment, load_system

system = load_system("my-system.yaml")
result = Assessment(system).run()

for dr in result.dimension_results:
    if dr.awarded_level < dr.claimed_level:
        print(f"{dr.dimension.display_name}: claimed {dr.claimed_level}, "
              f"awarded {dr.awarded_level} — gaps: {dr.gaps}")
```

## Why ACRF exists

In production multi-agent deployments, three things keep going wrong:

1. **Implicit trust between agents.** Agent A trusts messages from Agent B because they share a deployment, not because B authenticated.
2. **Undifferentiated authorization.** An agent that can read a record can usually also delete it, because authorization is modeled on the human user, not on the agent-action pair.
3. **Untraceable cascades.** Agent A calls B calls C calls D; when D does something wrong, there is no practical way to reconstruct whose intent initiated the chain.

ACRF names these failure modes, provides a structured way to test for them, and produces evidence that a given multi-agent system has  - or has not  - addressed each.

## Who should use this

- **Security architects** reviewing a proposed multi-agent system before deployment.
- **Red teams** looking for a structured target surface beyond prompt injection.
- **Procurement and risk teams** evaluating vendor agents that will interact with internal agents.
- **Standards and policy authors** looking for a vocabulary to describe A2A risk.

## Status

ACRF v0.1 was presented at RSA Conference 2026. The methodology is stable; the reference tool is usable and evolving. Feedback, issues, and PRs are genuinely welcome  - see [CONTRIBUTING.md](CONTRIBUTING.md).

## Citation

If you reference ACRF in a paper, talk, blog post, or policy document, please cite it:

```bibtex
@misc{acrf2026,
  author       = {Sekar, Kanna and Sankara Narayanan, Ravi Karthick},
  title        = {ACRF: Agent Communication Risk Framework},
  year         = {2026},
  howpublished = {\url{https://github.com/kannasekar-alt/acrf}},
  note         = {Presented at RSA Conference 2026. Version 0.1}
}
```

See [CITATION.cff](CITATION.cff) for machine-readable citation metadata.

## Related work

ACRF is designed to sit alongside, not replace, existing bodies of work. See [`docs/related-work.md`](docs/related-work.md) for a mapping to MITRE ATLAS, OWASP Top 10 for LLM Applications, OWASP Agentic Top 10, OWASP MCP Top 10, NIST AI RMF, and Google SAIF.

## License

Apache License 2.0  - see [LICENSE](LICENSE).
