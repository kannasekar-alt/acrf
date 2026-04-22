# Adopting ACRF

This guide describes how to apply ACRF to a real multi-agent system. It's written for the practitioner doing the assessment, not for a standards committee.

## Who should do the assessment

An ACRF assessment is best done by someone who (a) understands the system under assessment well enough to describe every A2A hop, and (b) is independent enough from the team that built it to push back on "we do that" claims that aren't evidenced.

A typical setup is a security architect or detection engineer, paired with an engineer from the team that owns the system. The engineer provides access to the design; the assessor provides the pressure to produce evidence rather than assertions.

## Time investment

A first assessment of a small system (2–5 agents, a handful of A2A calls) takes roughly:

- 2–4 hours to write the system description.
- 4–8 hours to collect evidence across the ten risk dimensions.
- 1–2 hours to score, write up, and circulate the report.

Subsequent re-assessments are much faster  - typically a half-day  - because the system description and most evidence carries forward.

## Step-by-step

### Step 1  - Scope the assessment

Write down:

- Every agent in the system (give each a stable name).
- Every A2A communication channel between those agents  - what message format, what transport, what trust boundary it crosses.
- The human user(s) whose authority flows through the system, and where that authority is attenuated or scoped.

Use the [system description schema](../specs/system-description.schema.json) to capture this in a machine-readable form. An [example](../examples/travel-booking-agents.yaml) is provided.

If you cannot describe the system in this form, the assessment has already revealed something: you don't have a shared model of your own agent topology. Fix that first.

### Step 2  - Collect evidence

For each of the ten risk dimensions, the evidence requirements are listed in the [methodology document](methodology.md). The critical discipline here is: **evidence is an artifact, not an assertion.**

Good evidence for ACRF-01 (Implicit Trust Between Agents) at level 3:

- A configuration file showing mTLS required on every A2A channel.
- A log excerpt showing a failed authentication attempt being rejected.
- An explicit trust-delegation policy document with scoped warrant definitions.
- A runbook entry describing the last credential rotation, with a date.

Not-good evidence:

- "We use mTLS."
- "The platform team handles identity."
- "It's in the design doc."

The difference is that the first list could be shown to an auditor, a regulator, or a future version of yourself, and the second list could not.

### Step 3  - Score

For each risk dimension, assign the highest maturity level for which you have full evidence for all control objectives at that level and below. If you have full evidence for levels 0–2 and partial evidence for level 3, score 2  - not 2.5, not "almost 3." The methodology is intentionally coarse because it is used to drive action, not to produce rankings.

The reference tool's `acrf assess` command applies this scoring rule given a system description and an evidence file.

### Step 4  - Prioritize remediation

Not every gap is worth fixing immediately. Order the remediation backlog by:

1. **AIVSS severity of the dimension.** Dimensions scored Critical (9.0+) generally warrant attention before High (7.0–8.9) dimensions, unless the system's specific profile changes the calculus.
2. **Size of the gap.** A jump from level 0 to level 2 is lower-effort-per-level than a jump from level 3 to level 4.
3. **Dependencies.** Implicit Trust (ACRF-01) and Standard Identity (ACRF-02) often unlock progress on other dimensions. Cascading Failure Blindness (ACRF-08) often unlocks the ability to detect whether other dimensions are working as claimed.
4. **System-specific criticality.** A system that makes financial transactions weights ACRF-10 (Safety Controls) and ACRF-07 (Multi-Turn Defense Collapse) heavily. A system that processes regulated data weights ACRF-04 (Memory Poisoning) and ACRF-09 (Semantic Bypass) heavily.

The reference tool emits a prioritized backlog using AIVSS severity and system-specific signals, but the human judgment about criticality still belongs to the assessor.

### Step 5  - Re-assess on a cadence

Set a re-assessment cadence  - quarterly is typical. Keep the system description and evidence in version control alongside the system itself; this turns the assessment into a diff over time rather than a reinvention.

## Common failure modes

**Failure mode 1: scoring before evidence is collected.** The team "knows" they're at level 3 and writes the report accordingly. The assessment becomes a status report, not a risk-reduction tool. Counter by enforcing: no level above 0 without a specific evidence artifact.

**Failure mode 2: conflating the user's authority with the agent's.** Most legacy authorization systems were designed for humans. A naive integration gives the agent whatever authority the user had. Catch this in ACRF-01 and ACRF-02 by asking: "What could the agent do that the user, in this moment, did not intend it to do?"

**Failure mode 3: assuming network position equals trust.** Two agents on the same VPC, same cluster, same namespace  - therefore "inside the trust boundary." This was the unit of trust in pre-agent systems. Agents invert the assumption: adjacency is not authorization. Catch this in ACRF-01.

**Failure mode 4: reporting without a remediation plan.** A report that says "we are at level 1" and stops is useful to exactly nobody. Every assessment output should include the specific next step for each dimension.

**Failure mode 5: treating configs as inert.** Agent config files specify tool endpoints, system prompts, and allowed actions. A change to a config can change agent behavior as much as a code change. Catch this in ACRF-06.

## Integrating ACRF into an existing program

ACRF is designed to slot into an existing security program rather than replace anything. Good integration points:

- **Architecture review.** ACRF scoring gate on new multi-agent designs.
- **Incident post-mortem.** After an agent-related incident, re-run the affected dimensions and check whether the score was accurate.
- **Vendor/procurement review.** Require third-party agents that will communicate with your agents to provide an ACRF assessment of their side.
- **Red team exercises.** Use the dimension structure to scope exercises  - a red team focused on ACRF-07 (Multi-Turn Defense Collapse) looks different from one focused on ACRF-09 (Semantic Bypass).

## Reporting outward

When publishing an ACRF assessment outside your organization (to a customer, a regulator, a partner), include:

- The methodology version used.
- The scope  - which agents, which communication channels.
- Per-dimension scores with AIVSS severity context and a one-line justification each.
- The OWASP cross-mappings for traceability.
- The date of the assessment.
- Known exclusions and future-dated remediations.

Do not include the underlying evidence artifacts unless the receiver has a legitimate need and appropriate protections  - the evidence often contains sensitive configuration detail.
