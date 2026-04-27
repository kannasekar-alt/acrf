"""
CustomerServiceAgent - PROTECTED VERSION (ACRF-07 demo)

Handles laptop orders over multiple conversation turns.
DEFENSE: Guardian agent monitors every turn for intent drift.
Shipping address changes mid-session require re-verification.
Session limits enforced.
"""
from flask import Flask, jsonify, request
from guardian import check_turn, get_session_summary

app = Flask(__name__)

session = {
    "turn": 0,
    "customer": None,
    "shipping_address": None,
    "original_address": None,
    "order": None,
    "verified_at_turn": None,
    "address_change_verified": False,
    "drift_flags": [],
    "conversation": []
}

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    message = data.get("message", "")
    actor = data.get("actor", "customer")
    new_address = data.get("address")

    session["turn"] += 1
    turn = session["turn"]

    session["conversation"].append({
        "turn": turn,
        "actor": actor,
        "message": message
    })

    # Guardian checks EVERY turn
    allowed, reason = check_turn(session, message, new_address)

    if not allowed:
        flag = {"turn": turn, "reason": reason}
        session["drift_flags"].append(flag)
        print(f"[Guardian] Turn {turn} BLOCKED: {reason}")
        return jsonify({
            "response": f"Action blocked: {reason}",
            "blocked": True,
            "turn": turn
        }), 403

    print(f"[Agent] Turn {turn} | {actor}: {message}")

    if turn == 1:
        session["customer"] = data.get("customer_id", "unknown")
        session["verified_at_turn"] = 1
        print("[Agent] Turn 1: Customer verified.")
        return jsonify({"response": "Hello! How can I help you today?", "turn": turn}), 200

    if new_address and not session["shipping_address"]:
        session["shipping_address"] = new_address
        session["original_address"] = new_address
        print(f"[Agent] Turn {turn}: Shipping address set to: {new_address}")
        return jsonify({
            "response": f"Shipping address set to: {new_address}",
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
    return jsonify(get_session_summary(session)), 200

if __name__ == "__main__":
    print("[Agent] Starting PROTECTED customer service agent.")
    print("[Agent] Guardian monitoring every turn for intent drift.")
    app.run(host="0.0.0.0", port=8000)
