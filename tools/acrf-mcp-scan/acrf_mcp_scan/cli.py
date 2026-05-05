"""
acrf-mcp-scan CLI

Commands:
    acrf-mcp-scan inventory <path> [--out PATH]
        Scan a config file or directory and produce an inventory.

    acrf-mcp-scan check <path>
        Scan a config file or directory and print findings to stdout.

    acrf-mcp-scan compare <current.json> <trusted.json>
        Compare current inventory against a trusted inventory.
"""
import argparse
import json
import sys
from pathlib import Path

from acrf_mcp_scan.exceptions import InvalidConfigError, InventoryError
from acrf_mcp_scan.inventory import MCPServerInventory
from acrf_mcp_scan.scanner import MCPScanner, ScannerOptions


def _scan(path: Path) -> MCPServerInventory:
    scanner = MCPScanner(ScannerOptions())
    if path.is_dir():
        return scanner.scan_directory(path)
    return scanner.scan_config_file(path)


def cmd_inventory(args: argparse.Namespace) -> int:
    target = Path(args.path)
    try:
        inventory = _scan(target)
    except InvalidConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.out:
        out_path = Path(args.out)
        inventory.save(out_path)
        print(f"Wrote inventory to {out_path}")
    else:
        print(json.dumps(inventory.to_dict(), indent=2, sort_keys=True))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    target = Path(args.path)
    try:
        inventory = _scan(target)
    except InvalidConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    suspicious = inventory.suspicious_servers()
    print(f"Scanned {len(inventory.servers)} server(s) at {target}")

    stats = inventory.server_count_by_risk()
    print(
        f"Risk: critical={stats['critical']} high={stats['high']} "
        f"medium={stats['medium']} low={stats['low']} none={stats['none']}"
    )

    if not suspicious:
        print("OK: no suspicious servers")
        return 0

    print()
    print(f"Suspicious ({len(suspicious)}):")
    for server in suspicious:
        print(f"  [{server.risk_level().upper()}] {server.name}")
        for finding in server.findings:
            print(f"      - {finding.severity}: {finding.rule} ({finding.detail})")
    return 1


def cmd_compare(args: argparse.Namespace) -> int:
    try:
        current = MCPServerInventory.load(args.current)
        trusted = MCPServerInventory.load(args.trusted)
    except (InventoryError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    diff = current.diff(trusted)
    print(f"Diff: {diff.summary()}")

    if diff.is_empty():
        print("OK: current matches trusted inventory")
        return 0

    if diff.added:
        print()
        print(f"Unauthorized servers ({len(diff.added)}):")
        for server in diff.added:
            print(f"  + {server.name}  command={server.command} version={server.version}")

    if diff.removed:
        print()
        print(f"Missing trusted servers ({len(diff.removed)}):")
        for server in diff.removed:
            print(f"  - {server.name}  expected version={server.version}")

    if diff.changed:
        print()
        print(f"Changed servers ({len(diff.changed)}):")
        for current_server, trusted_server in diff.changed:
            print(f"  ~ {current_server.name}")
            if current_server.command != trusted_server.command:
                print(
                    f"      command: {trusted_server.command!r} -> {current_server.command!r}"
                )
            if current_server.args != trusted_server.args:
                print(
                    f"      args:    {trusted_server.args} -> {current_server.args}"
                )
            if current_server.version != trusted_server.version:
                print(
                    f"      version: {trusted_server.version!r} -> {current_server.version!r}"
                )
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acrf-mcp-scan",
        description="MCP server inventory and risk scanner (ACRF-03).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_inv = sub.add_parser("inventory", help="Build an inventory from a config or directory")
    p_inv.add_argument("path")
    p_inv.add_argument("--out", default=None, help="Write inventory JSON to this path")
    p_inv.set_defaults(func=cmd_inventory)

    p_chk = sub.add_parser("check", help="Scan and report suspicious servers")
    p_chk.add_argument("path")
    p_chk.set_defaults(func=cmd_check)

    p_cmp = sub.add_parser("compare", help="Compare current inventory to a trusted inventory")
    p_cmp.add_argument("current")
    p_cmp.add_argument("trusted")
    p_cmp.set_defaults(func=cmd_compare)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
