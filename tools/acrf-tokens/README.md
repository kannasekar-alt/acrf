# acrf-tokens

Per-agent scoped tokens with revocation.
Implements the ACRF-02 (No Standard Agent Identity) defense pattern.

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
PyPI: https://pypi.org/project/acrf-tokens/
Presented at RSA Conference 2026.

---

## Try it in your environment right now

No Docker. No setup. Just Python 3.10+.

**Step 1 - Install:**

    pip install acrf-tokens

**Step 2 - Generate an issuer (one-time setup):**

    from acrf_tokens import TokenIssuer

    issuer = TokenIssuer.generate(issuer_name="acme-auth")
    issuer.save("issuer_private.json")             # KEEP SECRET
    issuer.save_public("issuer_public.json")       # share with validators

**Step 3 - Mint a token for each agent:**

    from acrf_tokens import TokenIssuer

    issuer = TokenIssuer.load("issuer_private.json")
    token = issuer.issue(
        agent_name="PricingAgent",
        scopes=["pricing:read", "trades:propose"],
        ttl_seconds=3600,
    )
    # token is a string - send it to the agent

**Step 4 - Validate before allowing any action:**

    from acrf_tokens import TokenValidator

    validator = TokenValidator.load("issuer_public.json")
    agent_token = validator.validate(token, required_scope="trades:propose")
    # raises TokenError subclass if invalid, expired, revoked, or missing scope

**Step 5 - Revoke compromised tokens instantly:**

    validator.revoke(agent_token.token_id)
    validator.save_revocations("revocations.json")

---

## The problem this solves

Most agent platforms today share a single API token across many agents.
There is no per-agent identity, no scope, no expiration, no revocation.
When that token leaks, every agent in the system is compromised.

This is ACRF-02: no standard agent identity.

acrf-tokens gives every agent its own short-lived, scoped, revocable token
signed by a central issuer using Ed25519. Compromised tokens are revoked
instantly. Stolen tokens expire on their own. No more shared secrets.

---

## Security features built in

**Ed25519 signed tokens**
Industry-standard cryptography. Issuer signs with private key, validator
verifies with public key. No shared secret between issuer and validator.

**Per-agent identity**
Every token names exactly one agent. No more "one key for all agents."

**Explicit scope list**
Every token carries the exact set of permissions it grants. The validator
enforces that the required scope is present before allowing the action.

**Short-lived tokens**
Every token has an expires_at. Stolen tokens become useless on their own.

**Instant revocation**
Compromised tokens can be revoked by token id (jti). Future validations
fail immediately, regardless of expiration.

**Public-key validation**
Validators only need the issuer public card. They never see the private
key. You can have hundreds of validators with zero shared secrets.

**Audit trail**
Every validation produces an audit record (success or failure) with token
id, agent name, issuer, timestamp, and outcome.

---

## CLI

Set the validator paths once:

    export ACRF_TOKENS_PUBLIC=/etc/acrf/issuer_public.json
    export ACRF_TOKENS_REVOCATIONS=/etc/acrf/revocations.json

Generate an issuer:

    acrf-tokens generate-issuer acme-auth

Mint a scoped token:

    acrf-tokens issue \
        --issuer acme-auth_private.json \
        --agent PricingAgent \
        --scopes pricing:read,trades:propose \
        --ttl 3600

Validate a token:

    acrf-tokens validate <token-string> --scope trades:propose

Revoke a token:

    acrf-tokens revoke <token-id>

List revoked tokens:

    acrf-tokens list

---

## How it works

1. The issuer generates an Ed25519 keypair (one time)
2. The public part is distributed to validators
3. To mint a token, the issuer signs JSON claims (token_id, agent_name,
   scopes, issued_at, expires_at) with the private key
4. The wire format is: BASE64(claims).BASE64(signature)
5. Validators verify the signature with the public key
6. Validators check expiration and revocation list
7. If a required scope is requested, validators check it is present
8. Only then is the token accepted and the AgentToken returned

---

## What goes in the issuer private file

The issuer private file contains the Ed25519 private key.
Treat it like any other production secret:

- AWS Secrets Manager / Azure Key Vault / GCP Secret Manager
- HashiCorp Vault
- Kubernetes secrets mounted at runtime

What NOT to do:

- Commit the issuer private file to source control
- Bake it into Docker images
- Distribute it to validators (only the public file goes there)

---

## Real-world use

Wrap your agent action handler with one validation call:

    from acrf_tokens import TokenValidator
    from acrf_tokens.exceptions import TokenError
    import os

    VALIDATOR = TokenValidator.load_with_revocations(
        os.environ["ACRF_TOKENS_PUBLIC"],
        os.environ["ACRF_TOKENS_REVOCATIONS"],
    )

    def handle_request(request):
        token_string = request.headers["X-Agent-Token"]
        try:
            agent_token = VALIDATOR.validate(token_string, required_scope=request.required_scope)
        except TokenError as exc:
            return {"error": "unauthorized", "reason": str(exc)}, 401

        # request authorized; proceed using agent_token.agent_name and agent_token.scopes
        return process(request, agent_token)

That is it. Every action handler is now per-agent authorized with
revocation, expiration, and scope enforcement.

---

## ACRF-02 control objectives addressed

    SI-1  Every agent has a cryptographically verifiable identity distinct from user identity
    SI-2  Tokens scoped per agent and per endpoint
    SI-3  Identity material rotatable and revocable without impacting other agents

---

## What this library does NOT do

- It does not handle user authentication (use OAuth/SSO)
- It does not encrypt the token contents (claims are visible in the token)
- It does not enforce rate limits (use a separate gateway)

It only ensures that an agent action is authorized by a token that was
issued by a trusted issuer, names a specific agent, has not expired,
has not been revoked, and contains the required scope. That is the
ACRF-02 defense pattern.

---

## Works with any Python AI agent framework

LangChain, CrewAI, AutoGen, MCP-based systems, custom agents.
If your agents call APIs or each other, you can use this library.

---

## Authors

Ravi Karthick Sankara Narayanan, Kanna Sekar

## License

Apache 2.0
