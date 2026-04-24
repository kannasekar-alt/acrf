# ACRF Assessment Templates

Pre-built YAML templates for assessing agent-to-agent communication systems against the ACRF risk dimensions. Each template models a realistic multi-agent scenario, defines the control objectives for that dimension, and starts at maturity Level 0 so you can see exactly what gaps the framework catches.

## Available Templates

| Template | Risk Dimension | ACRF ID | AIVSS | Severity |
|----------|---------------|---------|-------|----------|
| `implicit-trust.yaml` | Implicit Trust Between Agents | ACRF-01 | 9.4 | Critical |
| `supply-chain-toxicity.yaml` | Supply Chain Toxicity | ACRF-05 | 9.2 | Critical |
| `multi-turn-defense-collapse.yaml` | Multi-Turn Defense Collapse | ACRF-07 | 9.6 | Critical |
| `safety-controls-not-self-protecting.yaml` | Safety Controls Not Self-Protecting | ACRF-10 | 9.8 | Critical |

## Quick Start

1. Copy a template that's closest to your architecture:

```bash
cp acrf/assessments/implicit-trust.yaml my-system.yaml
```

2. Edit the file — replace the example agents, channels, and trust boundaries with your own. Then set `claimed_level` and add your evidence artifacts.

3. Run the assessment:

```bash
acrf assess my-system.yaml
```

4. Review the output. The tool will compare your claimed maturity level against the evidence you provided and flag gaps.

## How Templates Are Structured

Each YAML file follows the ACRF system description schema (`specs/system-description.schema.json`) and contains:

- **System metadata** — name, description, owner, assessment date.
- **Agents** — the actors in the system with their roles and identity schemes.
- **Channels** — how agents communicate, including transport, message format, trust boundary crossings, and actions with blast radius ratings.
- **Trust boundaries** — logical boundaries between trust domains.
- **Evidence** — the dimension being assessed, the claimed maturity level (0–4), and artifacts proving each control objective.

## Control Objective Reference

Each dimension defines four control objectives (one per maturity level):

**Implicit Trust (IT-1 through IT-4):** Caller identity verification → per-action authorization → continuous re-validation → real-time violation detection.

**Supply Chain Toxicity (SC-1 through SC-4):** Tool inventory → integrity/provenance verification → runtime behavior monitoring → supply chain attestation.

**Multi-Turn Defense Collapse (MT-1 through MT-4):** Cross-turn action tracking → session-aware escalation thresholds → semantic drift detection → adversarial red-team verification.

**Safety Controls Not Self-Protecting (SP-1 through SP-4):** Prevent policy modification by governed agents → trust domain isolation → tamper detection and alerting → out-of-band integrity attestation.

## Contributing New Templates

We welcome templates for the remaining six ACRF dimensions. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines. A good template should:

- Model a realistic, recognizable architecture (not a toy example).
- Include at least two trust boundaries and one cross-boundary channel.
- Have at least one `critical` or `high` blast-radius action.
- Start at `claimed_level: 0` with empty artifacts, plus commented examples showing what Level 1–2 evidence looks like.
