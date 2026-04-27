"""
Semantic Firewall - PROTECTED VERSION (ACRF-09 demo)

Two layers of defense:
1. Traditional firewall rules (IPs, domains, signatures)
2. Semantic guardian analyzes INTENT of every message

Traditional firewalls cannot read English.
Semantic guardian can.
"""
from flask import Flask, jsonify, request
from semantic_guardian import analyze_intent

app = Flask(__name__)
traffic_log = []

BLOCKED_IPS = ["192.168.99.99", "10.0.0.evil"]
BLOCKED_DOMAINS = ["malware.com", "known-attack.net"]
MALWARE_SIGNATURES = ["<script>", "DROP TABLE", "rm -rf", "eval(base64"]

def check_traditional_rules(data: dict) -> tuple[bool, str]:
    destination = data.get("destination", "")
    payload = str(data.get("payload", ""))
    source_ip = data.get("source_ip", "")

    if source_ip in BLOCKED_IPS:
        return False, f"Blocked IP: {source_ip}"

    for domain in BLOCKED_DOMAINS:
        if domain in destination:
            return False, f"Blocked domain: {domain}"

    for sig in MALWARE_SIGNATURES:
        if sig.lower() in payload.lower():
            return False, f"Malware signature detected: {sig}"

    return True, "Traditional rules passed"

@app.route("/forward", methods=["POST"])
def forward():
    data = request.get_json()
    destination = data.get("destination", "")
    payload = data.get("payload", "")

    # Layer 1: Traditional firewall rules
    trad_allowed, trad_reason = check_traditional_rules(data)
    if not trad_allowed:
        entry = {"destination": destination, "allowed": False,
                 "layer": "traditional", "reason": trad_reason}
        traffic_log.append(entry)
        print(f"[Firewall] BLOCKED by traditional rules: {trad_reason}")
        return jsonify({"status": "blocked", "layer": "traditional", "reason": trad_reason}), 403

    # Layer 2: Semantic guardian analyzes intent
    sem_allowed, sem_reason = analyze_intent(destination, payload)
    if not sem_allowed:
        entry = {"destination": destination, "allowed": False,
                 "layer": "semantic", "reason": sem_reason}
        traffic_log.append(entry)
        print(f"[Guardian] BLOCKED by semantic analysis: {sem_reason}")
        return jsonify({"status": "blocked", "layer": "semantic", "reason": sem_reason}), 403

    entry = {"destination": destination, "allowed": True, "reason": sem_reason}
    traffic_log.append(entry)
    print(f"[Firewall] ALLOWED: {destination}")
    return jsonify({"status": "allowed", "forwarded_to": destination}), 200

@app.route("/log", methods=["GET"])
def get_log():
    return jsonify({"traffic": traffic_log}), 200

if __name__ == "__main__":
    print("[Firewall] Starting PROTECTED semantic firewall.")
    print("[Firewall] Layer 1: Traditional rules (IPs, domains, signatures)")
    print("[Firewall] Layer 2: Semantic guardian (intent analysis)")
    app.run(host="0.0.0.0", port=8001)
