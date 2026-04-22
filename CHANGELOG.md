# Changelog

All notable changes to ACRF  - both the methodology and the reference tool  - will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) applied to the methodology (see [docs/governance.md](docs/governance.md) for details).

## [Unreleased]

### Fixed

- **`acrf validate` now runs JSON Schema validation** against `specs/system-description.schema.json` in addition
  to the loader's cross-reference checks. Schema violations (e.g. invalid `role` enum values) are now caught
  and reported with a clear error message. `jsonschema>=4.0` is an optional dependency (`pip install acrf[validate]`)
  and is included in the `dev` extra.
- **Loader now validates `agent.role` and `agent.operates_on_behalf_of`** against the enum values defined in the
  JSON Schema, raising `SystemDescriptionError` on invalid values instead of silently accepting arbitrary strings.
- **`acrf.assessments` sub-package** is now documented as an intentional extension point for future custom
  assessment logic rather than an unexplained empty stub.
- **Public API surface completed**: `Action`, `BlastRadius`, `EvidenceArtifact`, and `TrustBoundary` are now
  exported from the top-level `acrf` package so programmatic users do not need to import from `acrf.core.models`
  directly.

## [0.1.0]  - 2026-04-20

### Added

- **Methodology v0.1.** Ten risk dimensions for agent-to-agent communication security, each cross-mapped to OWASP Agentic Top 10 (ASI) and OWASP MCP Top 10, scored with AIVSS (AI Vulnerability Severity Scoring), and paired with a concrete defense pattern:
  - ACRF-01: Implicit Trust Between Agents (Critical, 9.2)
  - ACRF-02: No Standard Agent Identity (Critical, 9.0)
  - ACRF-03: MCP Server Sprawl (High, 8.4)
  - ACRF-04: Memory Poisoning (Critical, 9.1)
  - ACRF-05: Supply Chain Toxicity (Critical, 9.3)
  - ACRF-06: Config Files = Execution Vectors (High, 8.7)
  - ACRF-07: Multi-Turn Defense Collapse (Critical, 9.4)
  - ACRF-08: Cascading Failure Blindness (High, 8.5)
  - ACRF-09: Semantic Bypass (High, 8.6)
  - ACRF-10: Safety Controls Not Self-Protecting (Critical, 9.5)
- **Reference tool v0.1.0.** Python package with CLI (`acrf validate`, `acrf assess`, `acrf report`) and programmatic API (`Assessment`, `load_system`).
- **System description schema** (JSON Schema, draft 2020-12) for machine-readable system descriptions.
- **Examples**  - `travel-booking-agents.yaml`, `trading-research-agents.yaml`, `prior-auth-agents.yaml`, `minimal-two-agent.yaml`, plus a generated sample report.
- **Documentation**  - methodology specification, adoption guide, governance model, related-work mapping.

### Notes

This is the initial public release of ACRF, first presented at RSA Conference 2026 in the virtual seminar "My AI Will Call Your AI: Securing Agent-to-Agent Communication." The methodology is stable at v0.1 but expected to evolve based on practitioner feedback. Breaking changes to risk dimension definitions, AIVSS scores, or maturity scales will be released under a new major version (see [docs/governance.md](docs/governance.md)).
