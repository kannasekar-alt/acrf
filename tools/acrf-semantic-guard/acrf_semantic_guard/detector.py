"""
SemanticGuard module.

Detects semantic threats in natural-language instructions sent to or
between AI agents. Uses deterministic keyword-and-pattern rules - no ML,
no external services required.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from acrf_semantic_guard.exceptions import SemanticThreatError

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"

SEVERITY_RANK = {SEVERITY_LOW: 1, SEVERITY_MEDIUM: 2, SEVERITY_HIGH: 3}


# ----------------------------------------------------------------------
# Threat record
# ----------------------------------------------------------------------

@dataclass
class Threat:
    """A single semantic threat finding."""
    category: str
    severity: str
    rule: str
    detail: str
    matched: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "rule": self.rule,
            "detail": self.detail,
            "matched": list(self.matched),
        }


# ----------------------------------------------------------------------
# Rule definition
# ----------------------------------------------------------------------

@dataclass
class SemanticRule:
    """
    A rule that fires when ALL keyword groups match the instruction.

    Each group is a list of synonyms; the rule fires only if at least one
    synonym from each group is present (i.e. groups are AND-ed, synonyms
    inside a group are OR-ed).
    """
    name: str
    category: str
    severity: str
    detail: str
    groups: list[list[str]]

    def evaluate(self, text_lower: str) -> Threat | None:
        matched: list[str] = []
        for group in self.groups:
            hit = None
            for keyword in group:
                if re.search(rf"\b{re.escape(keyword)}\b", text_lower):
                    hit = keyword
                    break
            if hit is None:
                return None
            matched.append(hit)
        return Threat(
            category=self.category,
            severity=self.severity,
            rule=self.name,
            detail=self.detail,
            matched=matched,
        )


# ----------------------------------------------------------------------
# Built-in rules
# ----------------------------------------------------------------------

# Outbound channel verbs
SEND_VERBS = ["email", "send", "post", "upload", "transfer", "transmit", "push", "publish", "share", "leak", "exfiltrate", "forward"]

# Sensitive data nouns
SENSITIVE_DATA_NOUNS = ["password", "passwords", "credential", "credentials", "secret", "secrets", "token", "tokens", "api_key", "apikey", "private_key", "ssn", "pii", "customer", "customers", "user_data", "userdata", "credit_card", "creditcard", "database", "dump"]

# Tokens that strongly imply external/non-internal destination
EXTERNAL_HINT = ["external", "third-party", "outside", "public", "untrusted", "@", "http://", "https://", ".com", ".net", ".org", ".io", ".co"]

# Dangerous code primitives
CODE_VERBS = ["eval", "exec", "spawn", "system", "shell", "subprocess", "compile", "run"]
CODE_TARGETS = ["code", "script", "command", "shell", "binary", "payload", "instruction", "input"]

# Bypass / disable
BYPASS_VERBS = ["bypass", "disable", "ignore", "override", "skip", "circumvent", "evade", "turn off", "switch off"]
SAFETY_NOUNS = ["safety", "security", "policy", "guardrail", "guardrails", "control", "controls", "filter", "filters", "moderation", "approval"]

# Privilege escalation
ESCALATE_VERBS = ["promote", "grant", "escalate", "elevate", "assign", "give"]
PRIVILEGED_ROLES = ["admin", "administrator", "root", "superuser", "super_user", "sysadmin", "owner", "god mode", "godmode", "privileged"]

# Data destruction
DESTRUCT_VERBS = ["delete", "drop", "purge", "wipe", "destroy", "remove", "truncate"]
DESTRUCT_SCOPES = ["all", "everything", "production", "prod", "database", "table", "tables", "users", "logs", "history", "backup", "backups"]

# Credential extraction
REVEAL_VERBS = ["show", "reveal", "print", "expose", "leak", "echo", "display", "dump", "list"]
CREDENTIAL_NOUNS = ["password", "passwords", "secret", "secrets", "key", "keys", "token", "tokens", "credential", "credentials", "private_key", "api_key", "apikey"]


DEFAULT_RULES: list[SemanticRule] = [
    SemanticRule(
        name="exfiltration_external",
        category="exfiltration",
        severity=SEVERITY_HIGH,
        detail="instruction sends sensitive data to an external destination",
        groups=[SEND_VERBS, SENSITIVE_DATA_NOUNS, EXTERNAL_HINT],
    ),
    SemanticRule(
        name="exfiltration_no_destination",
        category="exfiltration",
        severity=SEVERITY_MEDIUM,
        detail="instruction sends sensitive data without specifying internal destination",
        groups=[SEND_VERBS, SENSITIVE_DATA_NOUNS],
    ),
    SemanticRule(
        name="bypass_safety",
        category="bypass",
        severity=SEVERITY_HIGH,
        detail="instruction asks the agent to bypass or disable a safety control",
        groups=[BYPASS_VERBS, SAFETY_NOUNS],
    ),
    SemanticRule(
        name="privilege_escalation",
        category="privilege_escalation",
        severity=SEVERITY_HIGH,
        detail="instruction grants or escalates privileged role",
        groups=[ESCALATE_VERBS, PRIVILEGED_ROLES],
    ),
    SemanticRule(
        name="data_destruction",
        category="data_destruction",
        severity=SEVERITY_HIGH,
        detail="instruction destroys data at scope production/all/database",
        groups=[DESTRUCT_VERBS, DESTRUCT_SCOPES],
    ),
    SemanticRule(
        name="credential_extraction",
        category="credential_extraction",
        severity=SEVERITY_HIGH,
        detail="instruction asks the agent to reveal credentials",
        groups=[REVEAL_VERBS, CREDENTIAL_NOUNS],
    ),
    SemanticRule(
        name="code_execution",
        category="code_execution",
        severity=SEVERITY_HIGH,
        detail="instruction asks for arbitrary code or shell execution",
        groups=[CODE_VERBS, CODE_TARGETS],
    ),
]


# ----------------------------------------------------------------------
# SemanticGuard
# ----------------------------------------------------------------------

@dataclass
class SemanticGuard:
    """
    Inspect text for semantic threats using a configurable rule set.
    """
    rules: list[SemanticRule] = field(default_factory=lambda: list(DEFAULT_RULES))

    def detect(self, text: str) -> list[Threat]:
        """
        Return all threats triggered by the given text. Empty list if clean.
        """
        if not text:
            return []
        text_lower = text.lower()
        threats: list[Threat] = []
        for rule in self.rules:
            threat = rule.evaluate(text_lower)
            if threat is not None:
                threats.append(threat)
        return threats

    def inspect(self, text: str) -> None:
        """
        Detect threats and raise SemanticThreatError if any are found.

        Raises:
            SemanticThreatError: with .threats attribute containing all findings.
        """
        threats = self.detect(text)
        if not threats:
            return
        worst = max(threats, key=lambda t: SEVERITY_RANK.get(t.severity, 0))
        raise SemanticThreatError(
            f"semantic threat detected ({worst.severity}): "
            f"{worst.category}/{worst.rule} - {worst.detail}",
            threats=[t.to_dict() for t in threats],
        )

    def add_rule(self, rule: SemanticRule) -> None:
        self.rules.append(rule)

    def remove_rule(self, name: str) -> None:
        self.rules = [r for r in self.rules if r.name != name]

    def rule_names(self) -> list[str]:
        return [r.name for r in self.rules]
