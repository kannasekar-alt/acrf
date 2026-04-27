"""
CustomerServiceAgent - VULNERABLE VERSION (ACRF-07 demo)

Handles laptop orders over multiple conversation turns.
VULNERABILITY: Security check happens only at Turn 1.
No drift detection. Attacker gradually shifts shipping address
across multiple turns. Agent never notices.
"""
from flask import Flask, jsonify, request

app = Flask(__name__)

session = {
    "turn": 0,
    "customer": None,
    "shipping_address": None,
    "order": None,
    "verified_at_turn": None,
    "conversation": []
}

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    message = data.get("message", "")
    actor = data.get("actor", "customer")

    session["turn"] += 1
    turn = session["turn"]

    session["conversation"].append({
        "turn": turn,
        "actor": actor,
        "message": message
    })

    print(f"[Agent] Turn {turn} | {actor}: {message}")

    # Security check ONLY at turn 1
    if turn == 1:
        session["customer"] = data.get("customer_id", "unknown")
        session["verified_at_turn"] = 1
        print("[Agent] Turn 1: Customer verified. No further checks.")
        return jsonify({"response": "Hello! How can I help you today?", "turn": turn}), 200

    # Process subsequent turns without re-verification
    if "shipping address" in message.lower() or "ship to" in message.lower():
        new_address = data.get("address")
        if new_address:
            session["shipping_address"]
            session["shipping_address"] = new_address
            print(f"[Agent] Turn {turn}: Shipping address updated to: {new_address}")
            return jsonify({
                "response": f"Shipping address updated to: {new_address}",
                "turn": turn
            }), 200

    if "place order" in message.lower() or "buy" in message.lower():
        session["order"] = {
            "product": "MacBook Pro 16",
            "price": 3499,
            "shipping_to": session["shipping_address"],
            "customer": session["customer"]
        }
        print(f"[Agent] Turn {turn}: Order placed. Shipping to: {session['shipping_address']}")
        return jsonify({
            "response": f"Order placed! MacBook Pro 16 shipping to: {session['shipping_address']}",
            "order": session["order"],
            "turn": turn
        }), 200

    return jsonify({"response": "I can help you with that.", "turn": turn}), 200

@app.route("/session", methods=["GET"])
def get_session():
    return jsonify(session), 200

if __name__ == "__main__":
    print("[Agent] Starting VULNERABLE customer service agent.")
    print("[Agent] WARNING: Security check only at Turn 1. No drift detection.")
    app.run(host="0.0.0.0", port=8000)
