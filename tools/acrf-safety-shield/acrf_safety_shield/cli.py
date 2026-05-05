"""
acrf-safety-shield CLI

Commands:
    acrf-safety-shield generate-admin <admin-name> [--out PATH] [--public-out PATH]
        Generate a new admin credential.

    acrf-safety-shield init [--out PATH]
        Initialize a new shield state file.

    acrf-safety-shield trust-admin <admin-public.json>
        Add an admin public card to the shield trust set.

    acrf-safety-shield set <key> <value> --admin <admin-private.json>
        Set a guardrail value (admin only).

    acrf-safety-shield delete <key> --admin <admin-private.json>
        Delete a guardrail (admin only).

    acrf-safety-shield get <key> [--actor agent|admin] [--name NAME]
        Read a guardrail.

    acrf-safety-shield list
        List all guardrails.

    acrf-safety-shield audit
        Print the audit log.

Set the shield state path once:
    export ACRF_SAFETY_SHIELD=/etc/acrf/safety_shield.json
"""
import argparse
import json
import os
import sys
from pathlib import Path

from acrf_safety_shield.credentials import (
    AdminCredential,
    AgentCredential,
    PublicAdminCard,
)
from acrf_safety_shield.exceptions import SafetyShieldError
from acrf_safety_shield.shield import SafetyShield

SHIELD_ENV_VAR = "ACRF_SAFETY_SHIELD"


def _require_shield_path() -> Path:
    path = os.environ.get(SHIELD_ENV_VAR)
    if not path:
        print(f"ERROR: Environment variable {SHIELD_ENV_VAR} not set.", file=sys.stderr)
        print(f"Set it with: export {SHIELD_ENV_VAR}=/path/to/safety_shield.json", file=sys.stderr)
        sys.exit(2)
    return Path(path)


def _load_shield(path: Path) -> SafetyShield:
    if path.exists():
        return SafetyShield.load(path)
    return SafetyShield()


def _save_shield(shield: SafetyShield, path: Path) -> None:
    shield.save(path)


def cmd_generate_admin(args: argparse.Namespace) -> int:
    admin = AdminCredential.generate(admin_name=args.admin_name)
    private_path = Path(args.out or f"{args.admin_name}_admin_private.json")
    public_path = Path(args.public_out or f"{args.admin_name}_admin_public.json")
    admin.save_private(private_path)
    admin.public_card().save_to(public_path)
    print(f"Generated admin: {args.admin_name}")
    print(f"  admin_id: {admin.admin_id}")
    print(f"  private:  {private_path} (KEEP OFFLINE)")
    print(f"  public:   {public_path} (load into shield)")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.out) if args.out else _require_shield_path()
    if path.exists():
        print(f"ERROR: shield already initialized at {path}", file=sys.stderr)
        return 1
    SafetyShield().save(path)
    print(f"Initialized shield at {path}")
    return 0


def cmd_trust_admin(args: argparse.Namespace) -> int:
    path = _require_shield_path()
    shield = _load_shield(path)
    try:
        card = PublicAdminCard.load(args.admin_public)
    except FileNotFoundError:
        print(f"ERROR: admin public card not found: {args.admin_public}", file=sys.stderr)
        return 1
    shield.trust_admin(card)
    _save_shield(shield, path)
    print(f"Trusted admin: {card.admin_name} (id={card.admin_id})")
    return 0


def _parse_value(raw: str) -> object:
    raw_stripped = raw.strip()
    try:
        return json.loads(raw_stripped)
    except json.JSONDecodeError:
        return raw_stripped


def cmd_set(args: argparse.Namespace) -> int:
    path = _require_shield_path()
    shield = _load_shield(path)
    try:
        admin = AdminCredential.load_private(args.admin)
    except FileNotFoundError:
        print(f"ERROR: admin private file not found: {args.admin}", file=sys.stderr)
        return 1
    value = _parse_value(args.value)
    try:
        change_id = shield.set_guardrail(args.key, value, signer=admin)
    except SafetyShieldError as exc:
        print(f"FAIL: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1
    _save_shield(shield, path)
    if change_id is None:
        print(f"OK: {args.key} = {args.value}")
    else:
        print(f"PENDING: change_id={change_id}")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    path = _require_shield_path()
    shield = _load_shield(path)
    try:
        admin = AdminCredential.load_private(args.admin)
    except FileNotFoundError:
        print(f"ERROR: admin private file not found: {args.admin}", file=sys.stderr)
        return 1
    try:
        change_id = shield.delete_guardrail(args.key, signer=admin)
    except SafetyShieldError as exc:
        print(f"FAIL: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1
    _save_shield(shield, path)
    if change_id is None:
        print(f"OK: deleted {args.key}")
    else:
        print(f"PENDING: change_id={change_id}")
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    path = _require_shield_path()
    shield = _load_shield(path)
    actor: AdminCredential | AgentCredential
    if args.actor == "admin":
        if not args.admin:
            print("ERROR: admin actor requires --admin <private.json>", file=sys.stderr)
            return 1
        actor = AdminCredential.load_private(args.admin)
    else:
        actor = AgentCredential(agent_name=args.name or "agent", token="cli-token")
    value = shield.get_guardrail(args.key, actor)
    _save_shield(shield, path)
    if value is None:
        print(f"(no value for {args.key})")
        return 1
    print(json.dumps(value, indent=2, sort_keys=True, default=str))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    path = _require_shield_path()
    shield = _load_shield(path)
    actor: AdminCredential | AgentCredential
    if args.actor == "admin":
        if not args.admin:
            print("ERROR: admin actor requires --admin <private.json>", file=sys.stderr)
            return 1
        actor = AdminCredential.load_private(args.admin)
    else:
        actor = AgentCredential(agent_name=args.name or "agent", token="cli-token")
    state = shield.list_guardrails(actor)
    _save_shield(shield, path)
    print(json.dumps(state, indent=2, sort_keys=True, default=str))
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    path = _require_shield_path()
    shield = _load_shield(path)
    print(json.dumps(shield.audit_log(), indent=2, sort_keys=True, default=str))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acrf-safety-shield",
        description="Safety control credential isolation for AI agents (ACRF-10).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate-admin", help="Generate a new admin credential")
    p_gen.add_argument("admin_name")
    p_gen.add_argument("--out", default=None)
    p_gen.add_argument("--public-out", dest="public_out", default=None)
    p_gen.set_defaults(func=cmd_generate_admin)

    p_init = sub.add_parser("init", help="Initialize a new shield state file")
    p_init.add_argument("--out", default=None)
    p_init.set_defaults(func=cmd_init)

    p_trust = sub.add_parser("trust-admin", help="Trust an admin public card")
    p_trust.add_argument("admin_public")
    p_trust.set_defaults(func=cmd_trust_admin)

    p_set = sub.add_parser("set", help="Set a guardrail (admin only)")
    p_set.add_argument("key")
    p_set.add_argument("value")
    p_set.add_argument("--admin", required=True, help="Path to admin private file")
    p_set.set_defaults(func=cmd_set)

    p_del = sub.add_parser("delete", help="Delete a guardrail (admin only)")
    p_del.add_argument("key")
    p_del.add_argument("--admin", required=True, help="Path to admin private file")
    p_del.set_defaults(func=cmd_delete)

    p_get = sub.add_parser("get", help="Read a guardrail")
    p_get.add_argument("key")
    p_get.add_argument("--actor", choices=["admin", "agent"], default="agent")
    p_get.add_argument("--admin", default=None)
    p_get.add_argument("--name", default=None, help="Agent name to record in audit log")
    p_get.set_defaults(func=cmd_get)

    p_list = sub.add_parser("list", help="List all guardrails")
    p_list.add_argument("--actor", choices=["admin", "agent"], default="agent")
    p_list.add_argument("--admin", default=None)
    p_list.add_argument("--name", default=None)
    p_list.set_defaults(func=cmd_list)

    p_audit = sub.add_parser("audit", help="Print the audit log")
    p_audit.set_defaults(func=cmd_audit)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
