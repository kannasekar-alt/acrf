"""
Agent Registry - PROTECTED VERSION (ACRF-02 demo)

Each agent has its own scoped token with expiry.
Tokens are revocable. Retired agents are immediately deactivated.
This is per-agent identity - like individual service accounts in SailPoint.
"""
import time

# Each agent has its own token - scoped to specific endpoints
# Short-lived - expires after task window
# Revocable - retired agents are immediately deactivated

AGENT_TOKENS = {
    "orchestrator-agent": {
        "token": "orch-token-x9k2m-2026",
        "scopes": ["pricing:read", "trade:execute"],
        "status": "active",
        "expires_at": time.time() + 3600,
    },
    "pricing-agent": {
        "token": "price-token-j7n4p-2026",
        "scopes": ["pricing:read"],
        "status": "active",
        "expires_at": time.time() + 3600,
    },
    "trade-agent": {
        "token": "trade-token-q8r5s-2026",
        "scopes": ["pricing:read", "trade:execute"],
        "status": "active",
        "expires_at": time.time() + 3600,
    },
    "data-agent": {
        "token": "data-token-w3t6u-2026",
        "scopes": ["pricing:read"],
        "status": "revoked",
        "expires_at": 0,
        "revoked_reason": "Agent decommissioned 90 days ago",
    },
}

TOKEN_INDEX = {v["token"]: k for k, v in AGENT_TOKENS.items()}

def validate_token(token: str, required_scope: str) -> tuple[bool, str, str]:
    agent_id = TOKEN_INDEX.get(token)
    if not agent_id:
        return False, "unknown", "Token not recognized"

    agent = AGENT_TOKENS[agent_id]

    if agent["status"] == "revoked":
        return False, agent_id, f"Token revoked: {agent.get('revoked_reason', 'No reason given')}"

    if time.time() > agent["expires_at"]:
        return False, agent_id, "Token expired"

    if required_scope not in agent["scopes"]:
        return False, agent_id, f"Insufficient scope. Required: {required_scope}, Agent has: {agent['scopes']}"

    return True, agent_id, "OK"
