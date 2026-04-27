"""
API Gateway - VULNERABLE VERSION (ACRF-02 demo)

Accepts any request with the shared token.
No scope check. No expiry. No per-agent identity.
Cannot tell which agent made which call.
"""
from agent_registry import is_valid_token
from flask import Flask, jsonify, request

app = Flask(__name__)
audit_log = []

@app.route("/api/pricing", methods=["GET"])
def get_pricing():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not is_valid_token(token):
        return jsonify({"error": "invalid token"}), 401

    # No scope check - any token can call any endpoint
    # No agent identity - cannot tell who is calling
    caller = request.headers.get("X-Agent-Id", "unknown")
    audit_log.append({"caller": caller, "endpoint": "/api/pricing", "token": token[:8] + "..."})
    print(f"[Gateway] /api/pricing called by {caller} - GRANTED (no scope check)")
    return jsonify({"AAPL": 189.50, "TSLA": 245.30, "MSFT": 415.20}), 200

@app.route("/api/execute-trade", methods=["POST"])
def execute_trade():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not is_valid_token(token):
        return jsonify({"error": "invalid token"}), 401

    caller = request.headers.get("X-Agent-Id", "unknown")
    data = request.get_json()
    audit_log.append({"caller": caller, "endpoint": "/api/execute-trade", "token": token[:8] + "..."})
    print(f"[Gateway] /api/execute-trade called by {caller} - GRANTED (no scope check)")
    return jsonify({"status": "executed", "order": data}), 200

@app.route("/audit", methods=["GET"])
def audit():
    return jsonify({"log": audit_log}), 200

if __name__ == "__main__":
    print("[Gateway] Starting VULNERABLE API gateway.")
    print("[Gateway] WARNING: Shared token, no scope, no expiry, no revocation.")
    app.run(host="0.0.0.0", port=8000)
