"""
acrf-semantic-guard CLI

Commands:
    acrf-semantic-guard inspect "<text>"
        Check a single instruction for semantic threats.

    acrf-semantic-guard scan-file <path>
        Scan a file containing one instruction per line.

    acrf-semantic-guard rules
        List all detection rules currently loaded.
"""
import argparse
import sys
from pathlib import Path

from acrf_semantic_guard.detector import SemanticGuard


def cmd_inspect(args: argparse.Namespace) -> int:
    guard = SemanticGuard()
    threats = guard.detect(args.text)
    if not threats:
        print("OK: no threats detected")
        return 0

    print(f"FAIL: {len(threats)} threat(s) detected")
    for threat in threats:
        print(
            f"  [{threat.severity.upper()}] {threat.category}/{threat.rule}: "
            f"{threat.detail} (matched={threat.matched})"
        )
    return 1


def cmd_scan_file(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        print(f"ERROR: file not found: {args.path}", file=sys.stderr)
        return 1

    guard = SemanticGuard()
    lines = [line.rstrip("\n") for line in path.read_text().splitlines() if line.strip()]
    total = len(lines)
    flagged = 0

    for i, line in enumerate(lines, start=1):
        threats = guard.detect(line)
        if not threats:
            continue
        flagged += 1
        print(f"line {i}: {line}")
        for threat in threats:
            print(
                f"  [{threat.severity.upper()}] {threat.category}/{threat.rule}: "
                f"{threat.detail} (matched={threat.matched})"
            )

    print()
    print(f"Scanned {total} line(s). {flagged} flagged.")
    return 1 if flagged else 0


def cmd_rules(args: argparse.Namespace) -> int:
    guard = SemanticGuard()
    print(f"Loaded rules ({len(guard.rules)}):")
    for rule in guard.rules:
        print(
            f"  {rule.name:30s}  category={rule.category:25s}  severity={rule.severity}"
        )
        print(f"      detail: {rule.detail}")
        for i, group in enumerate(rule.groups, start=1):
            preview = ", ".join(group[:5])
            extra = f" (+{len(group) - 5} more)" if len(group) > 5 else ""
            print(f"      group {i}: {preview}{extra}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acrf-semantic-guard",
        description="Semantic intent analyzer for AI agent communication (ACRF-09).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_ins = sub.add_parser("inspect", help="Check a single instruction")
    p_ins.add_argument("text")
    p_ins.set_defaults(func=cmd_inspect)

    p_scan = sub.add_parser("scan-file", help="Scan a file of instructions")
    p_scan.add_argument("path")
    p_scan.set_defaults(func=cmd_scan_file)

    p_rules = sub.add_parser("rules", help="List loaded detection rules")
    p_rules.set_defaults(func=cmd_rules)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
