"""
Traditional Firewall - VULNERABLE VERSION (ACRF-09 demo)

Blocks known attack patterns:
- Malware signatures
- Blocked IP addresses
- Known bad domains

VULNERABILITY: Cannot read English.
Semantic attacks pass through because they look like normal HTTPS traffic.
"""
from flask import Flask, jsonify, request

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

    return True, "PASSED - No known attack patterns detected"

@app.route("/forward", methods=["POST"])
def forward():
    data = request.get_json()
    allowed, reason = check_traditional_rules(data)

    entry = {
        "destination": data.get("destination"),
        "allowed": allowed,
        "reason": reason,
        "payload_preview": str(data.get("payload", ""))[:80]
    }
    traffic_log.append(entry)

    if not allowed:
        print(f"[Firewall] BLOCKED: {reason}")
        return jsonify({"status": "blocked", "reason": reason}), 403

    print(f"[Firewall] ALLOWED: {data.get('destination')} - {reason}")
    return jsonify({"status": "allowed", "forwarded_to": data.get("destination")}), 200

@app.route("/log", methods=["GET"])
def get_log():
    return jsonify({"traffic": traffic_log}), 200

if __name__ == "__main__":
    print("[Firewall] Traditional firewall running.")
    print("[Firewall] Checking IPs, domains, malware signatures.")
    print("[Firewall] Cannot read English. Semantic attacks will pass.")
    app.run(host="0.0.0.0", port=8001)
