"""
acrf-skill-verify CLI

Commands:
    acrf-skill-verify hash <path>                          Compute hash of a skill file or directory
    acrf-skill-verify register <name> <path>               Register a skill in the registry
    acrf-skill-verify block <name>                         Block a skill name
    acrf-skill-verify verify <name> <path>                 Verify a skill against the registry
    acrf-skill-verify list                                 List approved and blocked skills

Set the registry path via env var:
    export ACRF_SKILL_REGISTRY=/path/to/trusted_skills.json
"""
import argparse
import os
import sys
from pathlib import Path

from acrf_skill_verify.core import (
    SkillRegistry,
    hash_directory,
    hash_file,
    verify_skill,
)

REGISTRY_ENV_VAR = "ACRF_SKILL_REGISTRY"


def _get_registry_path() -> Path:
    path = os.environ.get(REGISTRY_ENV_VAR)
    if not path:
        print(f"ERROR: Environment variable {REGISTRY_ENV_VAR} not set.", file=sys.stderr)
        print(f"Set it with: export {REGISTRY_ENV_VAR}=/path/to/trusted_skills.json", file=sys.stderr)
        sys.exit(2)
    return Path(path)


def _load_or_create_registry(path: Path) -> SkillRegistry:
    if path.exists():
        return SkillRegistry.load(path)
    return SkillRegistry()


def cmd_hash(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        print(f"ERROR: Path not found: {args.path}", file=sys.stderr)
        return 1
    digest = hash_directory(path) if path.is_dir() else hash_file(path)
    print(digest)
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    registry_path = _get_registry_path()
    registry = _load_or_create_registry(registry_path)

    skill_path = Path(args.path)
    if not skill_path.exists():
        print(f"ERROR: Skill path not found: {args.path}", file=sys.stderr)
        return 1

    digest = hash_directory(skill_path) if skill_path.is_dir() else hash_file(skill_path)

    try:
        registry.register(args.name, digest)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    registry.save(registry_path)
    print(f"Registered: {args.name}")
    print(f"Hash: {digest}")
    print(f"Registry: {registry_path}")
    return 0


def cmd_block(args: argparse.Namespace) -> int:
    registry_path = _get_registry_path()
    registry = _load_or_create_registry(registry_path)
    registry.block(args.name)
    registry.save(registry_path)
    print(f"Blocked: {args.name}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    registry_path = _get_registry_path()
    if not registry_path.exists():
        print(f"ERROR: Registry not found: {registry_path}", file=sys.stderr)
        return 1
    registry = SkillRegistry.load(registry_path)

    skill_path = Path(args.path)
    if not skill_path.exists():
        print(f"ERROR: Skill path not found: {args.path}", file=sys.stderr)
        return 1

    valid, reason = verify_skill(args.name, skill_path, registry)
    if valid:
        print(f"OK: {args.name} integrity verified")
        return 0

    print(f"FAIL: {args.name}", file=sys.stderr)
    print(f"  {reason}", file=sys.stderr)
    return 1


def cmd_list(args: argparse.Namespace) -> int:
    registry_path = _get_registry_path()
    if not registry_path.exists():
        print(f"Registry is empty (no file at {registry_path})")
        return 0
    registry = SkillRegistry.load(registry_path)
    data = registry.to_dict()

    print(f"Registry: {registry_path}")
    print()
    print(f"Approved skills ({len(data['approved'])}):")
    for name, digest in sorted(data["approved"].items()):
        print(f"  {name}  {digest[:48]}...")
    print()
    print(f"Blocklist ({len(data['blocklist'])}):")
    for name in data["blocklist"]:
        print(f"  {name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acrf-skill-verify",
        description="Skill integrity verification for AI agents (ACRF-05)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_hash = sub.add_parser("hash", help="Compute hash of a skill file or directory")
    p_hash.add_argument("path", help="Path to skill file or directory")
    p_hash.set_defaults(func=cmd_hash)

    p_register = sub.add_parser("register", help="Register a skill in the registry")
    p_register.add_argument("name", help="Skill name")
    p_register.add_argument("path", help="Path to skill file or directory")
    p_register.set_defaults(func=cmd_register)

    p_block = sub.add_parser("block", help="Add a skill name to the blocklist")
    p_block.add_argument("name", help="Skill name to block")
    p_block.set_defaults(func=cmd_block)

    p_verify = sub.add_parser("verify", help="Verify a skill against the registry")
    p_verify.add_argument("name", help="Skill name")
    p_verify.add_argument("path", help="Path to skill file or directory")
    p_verify.set_defaults(func=cmd_verify)

    p_list = sub.add_parser("list", help="List approved skills and blocklist")
    p_list.set_defaults(func=cmd_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
