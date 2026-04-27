"""
Agent Registry - VULNERABLE VERSION (ACRF-02 demo)

All agents share a single token. No per-agent identity.
No token expiry. No scope restrictions. No revocation.
This is service account sprawl for AI agents.
"""

# One shared token for ALL agents - like a shared service account
SHARED_TOKEN = "shared-service-token-acrf02-2026"

# All agents use the same token - no individual identity
AGENTS = {
    "orchestrator-agent": {"token": SHARED_TOKEN, "status": "active"},
    "pricing-agent":      {"token": SHARED_TOKEN, "status": "active"},
    "trade-agent":        {"token": SHARED_TOKEN, "status": "active"},
    "data-agent":         {"token": SHARED_TOKEN, "status": "retired"},
}

def get_token(agent_id: str) -> str | None:
    agent = AGENTS.get(agent_id)
    return agent["token"] if agent else None

def is_valid_token(token: str) -> bool:
    return token == SHARED_TOKEN
