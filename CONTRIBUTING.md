# Contributing to ACRF

Thank you for your interest in ACRF. This project welcomes two kinds of contributions:

1. **Methodology contributions**  - proposals to add, clarify, or refine the ACRF methodology itself (the ten risk dimensions, their control objectives, their OWASP cross-mappings, their AIVSS scores, their maturity scales).
2. **Reference tool contributions**  - bug fixes, new features, better error messages, additional output formats, and anything else that makes the Python package more useful to practitioners.

Both are valuable. Both are reviewed against the bar "does this make ACRF more useful to someone actually doing an assessment?"

## Getting started

1. Fork the repository and clone your fork.
2. Install in editable mode with dev extras:

   ```bash
   pip install -e ".[dev]"
   ```

3. Run the tests:

   ```bash
   pytest
   ```

4. Run the linter:

   ```bash
   ruff check .
   ```

## Proposing a methodology change

Open a GitHub issue with the label `methodology-change`. The issue should include:

- **Motivation**  - what problem does the change solve? A real-world scenario or a specific ambiguity is ideal.
- **Proposed change**  - the text as you would have it read, ideally as a diff.
- **Impact on existing assessments**  - would anyone scoring a system today need to rescore?

Methodology changes go through a public comment period before being merged. See [docs/governance.md](docs/governance.md) for the timeline and process.

## Proposing a reference tool change

For bug fixes and small improvements, open a PR directly. For larger changes (new commands, new output formats, new scoring logic), open an issue first to discuss the approach. This avoids you doing work that doesn't end up merging.

## PR checklist

- [ ] Tests pass (`pytest`).
- [ ] Lint passes (`ruff check .`).
- [ ] New behavior has new tests.
- [ ] If the methodology is affected, `docs/methodology.md` is updated and the change is noted in `CHANGELOG.md`.
- [ ] If the public API of the tool changes, the `README.md` quickstart still works.

## Code style

- Python 3.10+.
- Type hints on all public functions and dataclasses.
- No runtime dependencies beyond PyYAML. Dev dependencies are fine.
- Error messages should tell the user what to do, not just what went wrong. "Field `agents` must be a list" is fine. "Field `agents` must be a list; got a string, did you forget to indent?" is better.

## Scope discipline

ACRF is deliberately narrow. Contributions that expand scope  - to cover the model adversarial surface, the application infrastructure surface, or generic AI governance  - are likely to be declined, with thanks. The discipline of staying narrow is what makes the methodology adoptable; broadening it is a step away from that.

## Code of Conduct

All participants are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
