"""
acrf-identity CLI

Commands:
    acrf-identity generate <agent-name> [--organization ORG] [--out PATH]
        Generate a new agent identity (private + public keys).

    acrf-identity public <private-card>
        Print the public-only card extracted from a private card.

    acrf-identity trust add <public-card>
        Add an agent to the trust store.

    acrf-identity trust revoke <agent-name>
        Revoke an agent.

    acrf-identity trust rotate <public-card>
        Rotate the key for an existing agent.

    acrf-identity trust list
        List trusted and revoked agents.

    acrf-identity verify <envelope-file>
        Verify a message envelope against the trust store.

Set the trust store path via env var:
    export ACRF_TRUST_STORE=/path/to/trusted_agents.json
"""
import argparse
import json
import os
import sys
from pathlib import Path

from acrf_identity.card import AgentCard, PublicAgentCard
from acrf_identity.envelope import MessageEnvelope
from acrf_identity.exceptions import AgentIdentityError
from acrf_identity.trust_store import TrustStore

TRUST_STORE_ENV_VAR = "ACRF_TRUST_STORE"


def _get_trust_store_path() -> Path:
    path = os.environ.get(TRUST_STORE_ENV_VAR)
    if not path:
        print(f"ERROR: Environment variable {TRUST_STORE_ENV_VAR} not set.", file=sys.stderr)
        print(f"Set it with: export {TRUST_STORE_ENV_VAR}=/path/to/trusted_agents.json", file=sys.stderr)
        sys.exit(2)
    return Path(path)


def _load_or_create_store(path: Path) -> TrustStore:
    if path.exists():
        return TrustStore.load(path)
    return TrustStore()


def cmd_generate(args: argparse.Namespace) -> int:
    metadata = {}
    if args.metadata:
        try:
            metadata = json.loads(args.metadata)
        except json.JSONDecodeError as exc:
            print(f"ERROR: --metadata is not valid JSON: {exc}", file=sys.stderr)
            return 1

    card = AgentCard.generate(
        agent_name=args.agent_name,
        organization=args.organization or "",
        metadata=metadata,
    )

    out_path = Path(args.out or f"{args.agent_name}_private.json")
    card.save(out_path)

    public_path = Path(args.public_out or f"{args.agent_name}_public.json")
    card.public_only().save(public_path)

    print(f"Generated agent identity for {args.agent_name}")
    print(f"  agent_id: {card.agent_id}")
    print(f"  private card: {out_path} (KEEP SECRET)")
    print(f"  public card:  {public_path} (safe to share)")
    return 0


def cmd_public(args: argparse.Namespace) -> int:
    try:
        card = AgentCard.load(args.private_card)
    except FileNotFoundError:
        print(f"ERROR: Private card not found: {args.private_card}", file=sys.stderr)
        return 1
    public = card.public_only()
    print(json.dumps(public.to_dict(), indent=2, sort_keys=True))
    return 0


def cmd_trust_add(args: argparse.Namespace) -> int:
    store_path = _get_trust_store_path()
    store = _load_or_create_store(store_path)
    try:
        card = PublicAgentCard.load(args.public_card)
    except FileNotFoundError:
        print(f"ERROR: Public card not found: {args.public_card}", file=sys.stderr)
        return 1
    try:
        store.add(card)
    except AgentIdentityError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    store.save(store_path)
    print(f"Added to trust store: {card.agent_name} (id={card.agent_id})")
    return 0


def cmd_trust_revoke(args: argparse.Namespace) -> int:
    store_path = _get_trust_store_path()
    store = _load_or_create_store(store_path)
    store.revoke(args.agent_name)
    store.save(store_path)
    print(f"Revoked: {args.agent_name}")
    return 0


def cmd_trust_rotate(args: argparse.Namespace) -> int:
    store_path = _get_trust_store_path()
    store = _load_or_create_store(store_path)
    try:
        card = PublicAgentCard.load(args.public_card)
    except FileNotFoundError:
        print(f"ERROR: Public card not found: {args.public_card}", file=sys.stderr)
        return 1
    try:
        store.rotate_key(card)
    except AgentIdentityError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    store.save(store_path)
    print(f"Rotated key for: {card.agent_name} (new id={card.agent_id})")
    return 0


def cmd_trust_list(args: argparse.Namespace) -> int:
    store_path = _get_trust_store_path()
    if not store_path.exists():
        print(f"Trust store is empty (no file at {store_path})")
        return 0
    store = TrustStore.load(store_path)
    print(f"Trust store: {store_path}")
    print()
    trusted = store.trusted_agent_names()
    print(f"Trusted agents ({len(trusted)}):")
    for name in trusted:
        card = store.lookup(name)
        org = f" [{card.organization}]" if card and card.organization else ""
        print(f"  {name}{org}  id={card.agent_id if card else '?'}")
    print()
    revoked = store.revoked_agent_names()
    print(f"Revoked agents ({len(revoked)}):")
    for name in revoked:
        print(f"  {name}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    store_path = _get_trust_store_path()
    if not store_path.exists():
        print(f"ERROR: Trust store not found: {store_path}", file=sys.stderr)
        return 1
    store = TrustStore.load(store_path)

    try:
        raw = Path(args.envelope_file).read_text()
    except FileNotFoundError:
        print(f"ERROR: Envelope file not found: {args.envelope_file}", file=sys.stderr)
        return 1

    try:
        envelope = MessageEnvelope.from_json(raw)
    except (json.JSONDecodeError, KeyError) as exc:
        print(f"ERROR: Envelope file is not a valid envelope: {exc}", file=sys.stderr)
        return 1

    try:
        payload = store.verify(envelope)
    except AgentIdentityError as exc:
        print(f"FAIL: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1

    print(f"OK: envelope from {envelope.sender_name} verified")
    print(f"Payload: {json.dumps(payload, indent=2, sort_keys=True, default=str)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acrf-identity",
        description="Production-grade agent identity (ACRF-01)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate", help="Generate a new agent identity")
    p_gen.add_argument("agent_name")
    p_gen.add_argument("--organization", default="")
    p_gen.add_argument("--metadata", help="JSON string of metadata", default=None)
    p_gen.add_argument("--out", help="Path to write private card", default=None)
    p_gen.add_argument("--public-out", dest="public_out", help="Path to write public card", default=None)
    p_gen.set_defaults(func=cmd_generate)

    p_pub = sub.add_parser("public", help="Print public-only card from a private card")
    p_pub.add_argument("private_card")
    p_pub.set_defaults(func=cmd_public)

    p_trust = sub.add_parser("trust", help="Manage the trust store")
    trust_sub = p_trust.add_subparsers(dest="trust_command", required=True)

    p_add = trust_sub.add_parser("add", help="Add an agent to the trust store")
    p_add.add_argument("public_card")
    p_add.set_defaults(func=cmd_trust_add)

    p_rev = trust_sub.add_parser("revoke", help="Revoke an agent")
    p_rev.add_argument("agent_name")
    p_rev.set_defaults(func=cmd_trust_revoke)

    p_rot = trust_sub.add_parser("rotate", help="Rotate the key for an existing agent")
    p_rot.add_argument("public_card")
    p_rot.set_defaults(func=cmd_trust_rotate)

    p_list = trust_sub.add_parser("list", help="List trusted and revoked agents")
    p_list.set_defaults(func=cmd_trust_list)

    p_verify = sub.add_parser("verify", help="Verify a message envelope")
    p_verify.add_argument("envelope_file")
    p_verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
