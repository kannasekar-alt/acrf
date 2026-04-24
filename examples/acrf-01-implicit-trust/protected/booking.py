"""BookingExecutor Agent — PROTECTED VERSION (verifies signatures before processing)."""
import base64
import json
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from flask import Flask, jsonify, request
from keygen import ensure_keys_exist

app = Flask(__name__)
AGENT_CARDS_DIR = Path("/app/agent-cards")

trust_store = {}
bookings = []
total_charges = {}
rejected_attempts = []

def load_trust_store():
    for card_path in AGENT_CARDS_DIR.glob("*.json"):
        card = json.loads(card_path.read_text())
        trust_store[card["agent_id"]] = card
    print(f"[BookingExecutor] Loaded {len(trust_store)} Agent Cards into trust store.")

def canonicalize(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

def verify_signature(envelope):
    sender = envelope.get("sender")
    signature_b64 = envelope.get("signature")
    payload = envelope.get("payload")

    if not sender or not signature_b64 or not payload:
        return False, "Malformed envelope (missing sender, signature, or payload)"

    card = trust_store.get(sender)
    if not card:
        return False, f"Sender '{sender}' not found in trust store — no Agent Card registered"

    try:
        public_key = serialization.load_pem_public_key(card["public_key_pem"].encode())
        signature = base64.b64decode(signature_b64)
        canonical = canonicalize(payload)
        public_key.verify(signature, canonical)
        return True, "Signature valid"
    except InvalidSignature:
        return False, "Signature verification FAILED — message was tampered with or forged"
    except Exception as e:
        return False, f"Verification error: {e}"

@app.route("/book", methods=["POST"])
def book_flight():
    envelope = request.get_json()
    is_valid, verification_msg = verify_signature(envelope)

    if not is_valid:
        rejected_attempts.append({
            "timestamp": time.time(),
            "claimed_sender": envelope.get("sender", "unknown"),
            "reason": verification_msg,
            "payload": envelope.get("payload", {}),
        })
        print(f"[BookingExecutor] REJECTED request claiming to be '{envelope.get('sender')}' — {verification_msg}")
        payload = envelope.get("payload", {})
        print(f"[BookingExecutor] Audit log: attempted booking for '{payload.get('user')}'")
        return jsonify({"error": "signature_verification_failed", "reason": verification_msg}), 403

    payload = envelope["payload"]
    sender = envelope["sender"]
    booking_id = len(bookings) + 1
    bookings.append({
        "id": booking_id, "user": payload.get("user"), "route": payload.get("route"),
        "amount": payload.get("amount"), "card_owner": payload.get("card_owner"),
        "verified_sender": sender, "timestamp": time.time(),
    })
    card_owner = payload.get("card_owner")
    total_charges[card_owner] = total_charges.get(card_owner, 0) + payload.get("amount", 0)

    message = f"OK: Signature verified. Booking #{booking_id} confirmed. Charged ${payload.get('amount'):.2f} to {card_owner}."
    print(f"[BookingExecutor] {message}")
    return jsonify({"status": "confirmed", "booking_id": booking_id, "message": message}), 200

@app.route("/audit", methods=["GET"])
def get_audit():
    return jsonify({
        "confirmed_bookings": len(bookings),
        "rejected_attempts": len(rejected_attempts),
        "charges_by_card_owner": total_charges,
        "bookings": bookings,
        "rejection_log": rejected_attempts,
    }), 200

if __name__ == "__main__":
    ensure_keys_exist()
    load_trust_store()
    print("[BookingExecutor] Starting PROTECTED booking service.")
    print("[BookingExecutor] Every request will be signature-verified against Agent Cards.")
    app.run(host="0.0.0.0", port=8000)
