"""ACRF command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Literal

import yaml

from acrf import __version__
from acrf.core.assessment import Assessment
from acrf.core.loader import SystemDescriptionError, load_system
from acrf.core.report import render

# Path to the bundled JSON Schema, relative to this file.
_SCHEMA_PATH = Path(__file__).parent.parent.parent / "specs" / "system-description.schema.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="acrf",
        description=(
            "ACRF - Agent Communication Risk Framework. Assess the security "
            "risk posture of agent-to-agent communications in a multi-agent "
            "system."
        ),
    )
    parser.add_argument("--version", action="version", version=f"acrf {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_validate = subparsers.add_parser(
        "validate",
        help="Validate that a system description conforms to the ACRF schema.",
    )
    p_validate.add_argument("path", type=Path)

    p_assess = subparsers.add_parser(
        "assess",
        help="Run an ACRF assessment and print a summary.",
    )
    p_assess.add_argument("path", type=Path)

    p_report = subparsers.add_parser(
        "report",
        help="Run an ACRF assessment and emit a full report.",
    )
    p_report.add_argument("path", type=Path)
    p_report.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
    )
    p_report.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write to file instead of stdout.",
    )

    args = parser.parse_args(argv)

    try:
        if args.command == "validate":
            return _cmd_validate(args.path)
        if args.command == "assess":
            return _cmd_assess(args.path)
        if args.command == "report":
            return _cmd_report(args.path, args.format, args.output)
    except SystemDescriptionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 1


def _cmd_validate(path: Path) -> int:
    """Validate a system description at two levels:

    1. JSON Schema validation (specs/system-description.schema.json)  - catches
       structural / enum errors that the schema defines.
    2. Loader validation  - catches cross-reference errors (e.g. unknown agent IDs
       in channels) that a schema cannot express.
    """
    # --- Level 1: JSON Schema ---
    try:
        import jsonschema  # noqa: PLC0415
    except ImportError:
        print(
            "warning: jsonschema is not installed; skipping schema validation.\n"
            "         Install it with: pip install jsonschema",
            file=sys.stderr,
        )
    else:
        if not _SCHEMA_PATH.exists():
            print(
                f"warning: schema file not found at {_SCHEMA_PATH}; skipping schema validation.",
                file=sys.stderr,
            )
        else:
            schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
            raw_text = path.read_text(encoding="utf-8")
            # Use yaml.safe_load so the same file works as both YAML and JSON input.
            try:
                instance = yaml.safe_load(raw_text)
            except Exception as exc:
                print(f"error: could not parse {path}: {exc}", file=sys.stderr)
                return 2
            try:
                jsonschema.validate(instance=instance, schema=schema)
            except jsonschema.ValidationError as exc:
                print(f"error: schema validation failed: {exc.message}", file=sys.stderr)
                return 2

    # --- Level 2: Loader (cross-reference) validation ---
    load_system(path)  # raises SystemDescriptionError on failure
    print(f"{path}: valid ACRF system description")
    return 0


def _cmd_assess(path: Path) -> int:
    system = load_system(path)
    result = Assessment(system).run()
    print(result.summary())
    if result.remediation_backlog:
        print()
        print("Remediation backlog (prioritized):")
        for i, item in enumerate(result.remediation_backlog, 1):
            print(f"  {i}. {item}")
    return 0


def _cmd_report(path: Path, fmt: Literal["markdown", "json"], output: Path | None) -> int:
    system = load_system(path)
    result = Assessment(system).run()
    text = render(result, format=fmt)
    if output:
        output.write_text(text, encoding="utf-8")
        print(f"wrote {output}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
