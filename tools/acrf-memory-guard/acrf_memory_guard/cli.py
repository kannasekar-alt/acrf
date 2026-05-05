"""
acrf-memory-guard CLI

Commands:
    acrf-memory-guard verify-store <store_path>   Verify all entries in a JSON memory store

The store file is expected to be a JSON object where keys are entry IDs
and values are signed entry dicts.
"""
import argparse
import json
import os
import sys

from acrf_memory_guard.core import verify_entry

SECRET_ENV_VAR = "ACRF_MEMORY_SECRET"


def _get_secret() -> str:
    secret = os.environ.get(SECRET_ENV_VAR)
    if not secret:
        print(f"ERROR: Environment variable {SECRET_ENV_VAR} not set.", file=sys.stderr)
        print(f"Set it with: export {SECRET_ENV_VAR}='your-secret-key'", file=sys.stderr)
        sys.exit(2)
    return secret


def cmd_verify_store(args: argparse.Namespace) -> int:
    secret = _get_secret()

    try:
        with open(args.store_path) as f:
            store = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Store file not found: {args.store_path}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"ERROR: Store file is not valid JSON: {exc}", file=sys.stderr)
        return 1

    if not isinstance(store, dict):
        print("ERROR: Store file must be a JSON object (dict)", file=sys.stderr)
        return 1

    total = len(store)
    failed = []

    for entry_id, entry in store.items():
        valid, reason = verify_entry(entry, secret)
        if not valid:
            failed.append((entry_id, reason))

    if failed:
        print(f"FAIL: {len(failed)} of {total} entries failed integrity check", file=sys.stderr)
        for entry_id, reason in failed:
            print(f"  {entry_id}: {reason}", file=sys.stderr)
        return 1

    print(f"OK: {total} entries verified")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acrf-memory-guard",
        description="Memory integrity verification for AI agents (ACRF-04)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    verify_parser = sub.add_parser(
        "verify-store",
        help="Verify all entries in a JSON memory store"
    )
    verify_parser.add_argument("store_path", help="Path to the JSON memory store file")
    verify_parser.set_defaults(func=cmd_verify_store)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
