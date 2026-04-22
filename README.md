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
