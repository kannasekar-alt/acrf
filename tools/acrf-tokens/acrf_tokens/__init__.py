"""
acrf-tokens
===========

Per-agent scoped tokens with revocation.
Implements the ACRF-02 (No Standard Agent Identity) defense pattern.

Quick start:

    from acrf_tokens import TokenIssuer, TokenValidator

    # Issuer side (one time)
    issuer = TokenIssuer.generate(issuer_name="acme-auth")
    issuer.save("issuer_private.json")

    # Mint a scoped token for an agent
    token_string = issuer.issue(
        agent_name="PricingAgent",
        scopes=["pricing:read", "trades:propose"],
        ttl_seconds=3600,
    )

    # Validator side
    validator = TokenValidator.load("issuer_public.json")
    agent_token = validator.validate(token_string)

    if agent_token.has_scope("trades:propose"):
        # allowed
        pass

    # Revoke a compromised token by token_id
    validator.revoke(agent_token.token_id)

Security features:

    - Ed25519 signed tokens
    - Per-agent identity, no shared credentials
    - Explicit scope list per token
    - Short-lived tokens (expires_at)
    - Instant revocation by token id
    - Public-key validation (no shared secret)
    - Full audit trail

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
"""
from acrf_tokens.exceptions import (
    InvalidTokenError,
    TokenError,
    TokenExpiredError,
    TokenRevokedError,
    TokenScopeError,
)
from acrf_tokens.issuer import TokenIssuer
from acrf_tokens.token import AgentToken
from acrf_tokens.validator import TokenValidator

__version__ = "0.1.0"
__all__ = [
    "AgentToken",
    "TokenIssuer",
    "TokenValidator",
    "TokenError",
    "InvalidTokenError",
    "TokenExpiredError",
    "TokenRevokedError",
    "TokenScopeError",
]
