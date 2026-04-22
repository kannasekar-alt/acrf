# Security Policy

## Reporting a vulnerability

If you find a security vulnerability in the ACRF reference tool  - for example, a way to make the CLI execute unintended code when parsing a malicious system description file, or a way to cause denial of service  - please report it privately rather than opening a public issue.

**How to report:**

- Open a [private security advisory](https://github.com/kannasekar-alt/acrf/security/advisories/new) on GitHub, or
- Email the maintainer (see [MAINTAINERS.md](MAINTAINERS.md)) with the subject line `ACRF Security Report`.

Please include:

- A description of the issue and its potential impact.
- Steps to reproduce, including the exact input that triggers the behavior.
- Any suggested remediation.

## Response expectations

- **Acknowledgment:** within 5 business days.
- **Initial assessment:** within 10 business days.
- **Fix or mitigation timeline:** communicated after initial assessment.

Reporters who prefer public credit will be named in the advisory and release notes. Reporters who prefer anonymity will be honored.

## Scope

**In scope:**

- The `acrf` Python package and CLI.
- The JSON Schema and other specifications in `specs/`.
- Supply-chain issues with the release artifacts on PyPI.

**Out of scope:**

- Vulnerabilities in systems *assessed by* ACRF  - those belong to the system's owner, not to this project.
- Vulnerabilities in third-party dependencies  - please report those upstream first; we will track and update accordingly.
- The methodology itself being "wrong" or incomplete  - that is a methodology question, not a security issue. Please open a normal issue with label `methodology-change`.

## Supported versions

Only the latest minor version receives security fixes. Earlier versions will be patched only where the fix is straightforward and low-risk.
