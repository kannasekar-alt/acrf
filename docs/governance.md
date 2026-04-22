# ACRF Governance

This document describes how the ACRF methodology and reference tool are maintained.

## Versioning

ACRF uses semantic versioning applied to the **methodology**, not only the software.

- **Patch (0.1.x)**  - clarifications, additional examples, improved evidence-requirement wording. No change to domain structure or scoring. Safe to adopt without re-assessment.
- **Minor (0.x.0)**  - non-breaking additions: new evidence suggestions, new optional control objectives, new reference tool features. Existing assessments remain valid.
- **Major (x.0.0)**  - breaking changes to risk dimension definitions, the number of dimensions, AIVSS scores, or maturity scale interpretation. Existing assessments should be re-scored against the new version.

The reference tool's version follows the methodology version for the major and minor components.

## Proposing changes

All changes to the methodology are proposed through GitHub issues labeled `methodology-change`. A change proposal should include:

- The motivation  - what problem does this solve?
- The proposed text change (diff-style is welcome).
- The expected impact on existing assessments.

Proposals remain open for a minimum comment period (30 days for major, 14 days for minor, 7 days for patch) before merge.

## Decision process

In this early phase, decisions on methodology changes are made by the project maintainer after considering comments on the proposal. This will transition to a multi-maintainer model as the project grows. The current maintainer is listed in [MAINTAINERS.md](../MAINTAINERS.md).

The decision process is expected to become more formal as the project grows. Options under consideration include a small steering committee drawn from independent adopters, and rotating maintainership.

## Backwards compatibility commitments

- **System description schema:** additive changes are non-breaking; existing description files remain valid. Field removals or semantic changes are breaking.
- **Assessment output format:** the human-readable report is expected to evolve. The machine-readable output (JSON) is versioned and will maintain backward-compatible fields within a major version.
- **Maturity levels:** the numeric scale (0–4) is not expected to change. The interpretation of each level within a risk dimension may be clarified but will not be substantively redefined without a major version bump.
- **AIVSS scores:** scores are fixed per dimension within a major version. Re-scoring requires a major version bump.

## Independent assessments

ACRF is deliberately designed so that anyone can perform an assessment without permission, certification, or accreditation from the project. There is no "ACRF auditor" designation, and the project will not create one. An assessment is valid if the methodology is followed and the evidence supports the claims made  - it does not require project endorsement.

This is intentional: the goal is broad adoption of a consistent way of thinking, not control over who applies it.

## Trademarks and naming

The name "ACRF" and "Agent Communication Risk Framework" may be used freely to refer to this methodology and to describe work that applies it. The project does not claim trademark rights over the methodology name and does not restrict its use in titles of assessments, papers, products, or talks.

## Contact

Methodology questions and proposals: open a GitHub issue.
Security concerns with the reference tool: see [SECURITY.md](../SECURITY.md).
