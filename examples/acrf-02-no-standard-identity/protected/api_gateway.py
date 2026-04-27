"""
API Gateway - PROTECTED VERSION (ACRF-02 demo)

Validates every request against:
- Per-agent token (no shared tokens)
- Scope (can this agent call this endpoint?)
- Expiry (is the token still valid?)
- Revocation (has this agent been decommissioned?)
"""
from agent_registry import validate_token
from flask import Flask, jsonify, request

app = Flask(__name__)
audit_log = []

@app.route("/api/pricing", methods=["GET"])
def get_pricing():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    valid, agent_id, reason = validate_token(token, "pricing:read")

    entry = {
        "agent_id": agent_id,
        "endpoint": "/api/pricing",
        "decision": "GRANTED" if valid else "DENIED",
        "reason": reason
    }
    audit_log.append(entry)

    if not valid:
        print(f"[Gateway] /api/pricing DENIED for {agent_id}: {reason}")
        return jsonify({"error": "access denied", "reason": reason}), 403

    print(f"[Gateway] /api/pricing GRANTED for {agent_id} (scope verified)")
    return jsonify({"AAPL": 189.50, "TSLA": 245.30, "MSFT": 415.20}), 200

@app.route("/api/execute-trade", methods=["POST"])
def execute_trade():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    valid, agent_id, reason = validate_token(token, "trade:execute")

    entry = {
        "agent_id": agent_id,
        "endpoint": "/api/execute-trade",
        "decision": "GRANTED" if valid else "DENIED",
        "reason": reason
    }
    audit_log.append(entry)

    if not valid:
        print(f"[Gateway] /api/execute-trade DENIED for {agent_id}: {reason}")
        return jsonify({"error": "access denied", "reason": reason}), 403

    data = request.get_json()
    print(f"[Gateway] /api/execute-trade GRANTED for {agent_id} (scope verified)")
    return jsonify({"status": "executed", "order": data, "authorized_by": agent_id}), 200

@app.route("/audit", methods=["GET"])
def audit():
    return jsonify({"log": audit_log}), 200

if __name__ == "__main__":
    print("[Gateway] Starting PROTECTED API gateway.")
    print("[Gateway] Per-agent tokens. Scoped access. Revocation enforced.")
    app.run(host="0.0.0.0", port=8000)
