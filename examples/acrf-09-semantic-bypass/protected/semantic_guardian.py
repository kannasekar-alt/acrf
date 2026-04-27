"""
Semantic Guardian - ACRF-09 defense layer.

Reads the MEANING of every agent message before forwarding.
Traditional firewalls check IPs, domains, signatures.
Semantic guardian checks INTENT.

This implements ACRF-09 control objectives:
  SB-1: Guardian agents monitor communication paths
  SB-2: Intent validation checks what agent is trying to DO
  SB-3: Semantic analysis detects attacks invisible to perimeter tools
"""

EXFILTRATION_PATTERNS = [
    "send to external",
    "forward to external",
    "export to external",
    "send the complete",
    "forward all",
    "export all",
    "send all",
    "collection endpoint",
    "attacker",
    "external-collector",
    "analytics platform",
]

SENSITIVE_DATA_PATTERNS = [
    "ssn",
    "social security",
    "credit card",
    "password",
    "credentials",
    "api key",
    "private key",
    "salary",
    "home address",
    "date of birth",
    "all customer records",
    "all employee records",
    "all user credentials",
    "complete dataset",
]

SUSPICIOUS_DESTINATIONS = [
    ".io",
    ".net",
    "external",
    "attacker",
    "collector",
    "analytics",
]

def analyze_intent(destination: str, payload: str) -> tuple[bool, str]:
    payload_lower = payload.lower()
    destination_lower = destination.lower()

    # Check for exfiltration intent
    exfil_matches = [p for p in EXFILTRATION_PATTERNS if p in payload_lower]
    if exfil_matches:
        return False, f"Exfiltration intent detected: {exfil_matches[0]}"

    # Check for sensitive data references combined with external destination
    sensitive_matches = [p for p in SENSITIVE_DATA_PATTERNS if p in payload_lower]
    suspicious_dest = any(p in destination_lower for p in SUSPICIOUS_DESTINATIONS)

    if sensitive_matches and suspicious_dest:
        return False, (
            f"Sensitive data ({sensitive_matches[0]}) being sent to "
            f"suspicious destination ({destination})"
        )

    # Check for credential harvesting
    if ("credentials" in payload_lower or "api key" in payload_lower) and (
        "retrieve" in payload_lower or "export" in payload_lower or "forward" in payload_lower
    ):
        return False, "Credential harvesting intent detected"

    return True, "Intent analysis passed - request appears legitimate"
