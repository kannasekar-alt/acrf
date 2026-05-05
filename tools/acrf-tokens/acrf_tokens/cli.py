"""
acrf-tokens CLI

Commands:
    acrf-tokens generate-issuer <issuer-name> [--out PATH] [--public-out PATH]
        Generate a new issuer keypair.

    acrf-tokens issue --issuer <private.json> --agent <name> --scopes a,b,c [--ttl SECONDS]
        Mint a new scoped token.

    acrf-tokens validate <token-string>
        Validate a token against the issuer public card and revocation list.

    acrf-tokens revoke <token-id>
        Add a token id to the revocation list.

    acrf-tokens list
        Show currently revoked token ids.

Set the issuer public card and revocation list paths via env vars:
    export ACRF_TOKENS_PUBLIC=/etc/acrf/issuer_public.json
    export ACRF_TOKENS_REVOCATIONS=/etc/acrf/revocations.json
"""
import argparse
import json
import os
import sys
from pathlib import Path

from acrf_tokens.exceptions import TokenError
from acrf_tokens.issuer import TokenIssuer
from acrf_tokens.validator import TokenValidator

PUBLIC_CARD_ENV = "ACRF_TOKENS_PUBLIC"
REVOCATIONS_ENV = "ACRF_TOKENS_REVOCATIONS"


def _require_env(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        print(f"ERROR: Environment variable {name} not set.", file=sys.stderr)
        sys.exit(2)
    return Path(value)


def _load_validator() -> TokenValidator:
    public_path = _require_env(PUBLIC_CARD_ENV)
    revocations_path = _require_env(REVOCATIONS_ENV)
    if not public_path.exists():
        print(f"ERROR: Issuer public card not found: {public_path}", file=sys.stderr)
        sys.exit(1)
    return TokenValidator.load_with_revocations(public_path, revocations_path)


def _save_revocations(validator: TokenValidator) -> None:
    revocations_path = _require_env(REVOCATIONS_ENV)
    validator.save_revocations(revocations_path)


def cmd_generate_issuer(args: argparse.Namespace) -> int:
    issuer = TokenIssuer.generate(issuer_name=args.issuer_name)

    private_path = Path(args.out or f"{args.issuer_name}_private.json")
    public_path = Path(args.public_out or f"{args.issuer_name}_public.json")

    issuer.save(private_path)
    issuer.save_public(public_path)

    print(f"Generated issuer: {args.issuer_name}")
    print(f"  issuer_id: {issuer.issuer_id}")
    print(f"  private:   {private_path} (KEEP SECRET)")
    print(f"  public:    {public_path} (give to validators)")
    return 0


def cmd_issue(args: argparse.Namespace) -> int:
    issuer_path = Path(args.issuer)
    if not issuer_path.exists():
        print(f"ERROR: Issuer private file not found: {issuer_path}", file=sys.stderr)
        return 1
    issuer = TokenIssuer.load(issuer_path)

    scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
    if not scopes:
        print("ERROR: at least one scope is required", file=sys.stderr)
        return 1

    metadata = {}
    if args.metadata:
        try:
            metadata = json.loads(args.metadata)
        except json.JSONDecodeError as exc:
            print(f"ERROR: --metadata is not valid JSON: {exc}", file=sys.stderr)
            return 1

    token_string = issuer.issue(
        agent_name=args.agent,
        scopes=scopes,
        ttl_seconds=args.ttl,
        metadata=metadata,
    )

    print(token_string)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    validator = _load_validator()
    try:
        agent_token = validator.validate(token_string=args.token, required_scope=args.scope)
    except TokenError as exc:
        print(f"FAIL: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1

    print("OK: token valid")
    print(json.dumps(agent_token.claims(), indent=2, sort_keys=True))
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    validator = _load_validator()
    validator.revoke(args.token_id)
    _save_revocations(validator)
    print(f"Revoked: {args.token_id}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    validator = _load_validator()
    revoked = validator.revoked_token_ids()
    print(f"Revoked tokens ({len(revoked)}):")
    for token_id in revoked:
        print(f"  {token_id}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acrf-tokens",
        description="Per-agent scoped tokens with revocation (ACRF-02).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate-issuer", help="Generate a new issuer keypair")
    p_gen.add_argument("issuer_name")
    p_gen.add_argument("--out", default=None)
    p_gen.add_argument("--public-out", dest="public_out", default=None)
    p_gen.set_defaults(func=cmd_generate_issuer)

    p_issue = sub.add_parser("issue", help="Mint a new token")
    p_issue.add_argument("--issuer", required=True, help="Path to issuer private file")
    p_issue.add_argument("--agent", required=True, help="Agent name")
    p_issue.add_argument("--scopes", required=True, help="Comma-separated list of scopes")
    p_issue.add_argument("--ttl", type=float, default=3600.0, help="Token TTL in seconds (default 3600)")
    p_issue.add_argument("--metadata", default=None, help="JSON string of metadata")
    p_issue.set_defaults(func=cmd_issue)

    p_val = sub.add_parser("validate", help="Validate a token string")
    p_val.add_argument("token")
    p_val.add_argument("--scope", default=None, help="Optional required scope")
    p_val.set_defaults(func=cmd_validate)

    p_rev = sub.add_parser("revoke", help="Revoke a token id")
    p_rev.add_argument("token_id")
    p_rev.set_defaults(func=cmd_revoke)

    p_list = sub.add_parser("list", help="List revoked token ids")
    p_list.set_defaults(func=cmd_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
