"""
MCP Server Inventory module.

Defines MCPServer (a single discovered server with risk findings) and
MCPServerInventory (a collection with comparison and persistence support).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acrf_mcp_scan.exceptions import InventoryError

INVENTORY_FORMAT_VERSION = "1.0"


# Risk levels
RISK_NONE = "none"
RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
RISK_CRITICAL = "critical"

RISK_RANK = {
    RISK_NONE: 0,
    RISK_LOW: 1,
    RISK_MEDIUM: 2,
    RISK_HIGH: 3,
    RISK_CRITICAL: 4,
}


@dataclass
class RiskFinding:
    """A single risk finding for an MCP server."""
    rule: str
    severity: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "severity": self.severity, "detail": self.detail}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskFinding:
        return cls(
            rule=data["rule"],
            severity=data["severity"],
            detail=data.get("detail", ""),
        )


@dataclass
class MCPServer:
    """
    A single discovered MCP server with risk findings.
    """
    name: str
    source: str  # path or URL where the server was discovered
    command: str = ""
    args: list[str] = field(default_factory=list)
    publisher: str = ""
    version: str = ""
    has_signature: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    findings: list[RiskFinding] = field(default_factory=list)

    def add_finding(self, rule: str, severity: str, detail: str = "") -> None:
        self.findings.append(RiskFinding(rule=rule, severity=severity, detail=detail))

    def risk_level(self) -> str:
        if not self.findings:
            return RISK_NONE
        return max(self.findings, key=lambda f: RISK_RANK.get(f.severity, 0)).severity

    def is_suspicious(self) -> bool:
        return RISK_RANK.get(self.risk_level(), 0) >= RISK_RANK[RISK_MEDIUM]

    def risk_summary(self) -> str:
        if not self.findings:
            return "no findings"
        parts = [f"[{f.severity}] {f.rule}: {f.detail}" for f in self.findings]
        return "; ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "command": self.command,
            "args": list(self.args),
            "publisher": self.publisher,
            "version": self.version,
            "has_signature": self.has_signature,
            "metadata": dict(self.metadata),
            "findings": [f.to_dict() for f in self.findings],
            "risk_level": self.risk_level(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MCPServer:
        return cls(
            name=data["name"],
            source=data.get("source", ""),
            command=data.get("command", ""),
            args=list(data.get("args", [])),
            publisher=data.get("publisher", ""),
            version=data.get("version", ""),
            has_signature=bool(data.get("has_signature", False)),
            metadata=dict(data.get("metadata", {})),
            findings=[RiskFinding.from_dict(f) for f in data.get("findings", [])],
        )


@dataclass
class InventoryDiff:
    """Result of comparing two MCP inventories."""
    added: list[MCPServer] = field(default_factory=list)
    removed: list[MCPServer] = field(default_factory=list)
    changed: list[tuple[MCPServer, MCPServer]] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.changed)

    def summary(self) -> str:
        return (
            f"added={len(self.added)} removed={len(self.removed)} changed={len(self.changed)}"
        )


@dataclass
class MCPServerInventory:
    """
    A collection of discovered MCP servers.

    Supports persistence to JSON and diffing against another inventory
    to detect unauthorized servers or version drift.
    """
    servers: list[MCPServer] = field(default_factory=list)
    format_version: str = INVENTORY_FORMAT_VERSION

    def add(self, server: MCPServer) -> None:
        self.servers.append(server)

    def by_name(self) -> dict[str, MCPServer]:
        return {s.name: s for s in self.servers}

    def suspicious_servers(self) -> list[MCPServer]:
        return [s for s in self.servers if s.is_suspicious()]

    def server_count_by_risk(self) -> dict[str, int]:
        counts = {RISK_NONE: 0, RISK_LOW: 0, RISK_MEDIUM: 0, RISK_HIGH: 0, RISK_CRITICAL: 0}
        for server in self.servers:
            counts[server.risk_level()] += 1
        return counts

    def diff(self, other: MCPServerInventory) -> InventoryDiff:
        """
        Compare self to other.

        added   = servers in self not in other (e.g. discovered but not approved)
        removed = servers in other not in self (e.g. approved but not present)
        changed = servers in both but with different command/args/version
        """
        my_map = self.by_name()
        other_map = other.by_name()

        added = [s for name, s in my_map.items() if name not in other_map]
        removed = [s for name, s in other_map.items() if name not in my_map]

        changed = []
        for name, mine in my_map.items():
            theirs = other_map.get(name)
            if theirs is None:
                continue
            if (
                mine.command != theirs.command
                or mine.args != theirs.args
                or mine.version != theirs.version
            ):
                changed.append((mine, theirs))

        return InventoryDiff(added=added, removed=removed, changed=changed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "servers": [s.to_dict() for s in self.servers],
            "stats": self.server_count_by_risk(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MCPServerInventory:
        if "servers" not in data:
            raise InventoryError("inventory data missing \"servers\" field")
        return cls(
            servers=[MCPServer.from_dict(s) for s in data["servers"]],
            format_version=data.get("format_version", INVENTORY_FORMAT_VERSION),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> MCPServerInventory:
        try:
            data = json.loads(Path(path).read_text())
        except json.JSONDecodeError as exc:
            raise InventoryError(f"inventory file is not valid JSON: {exc}") from exc
        return cls.from_dict(data)
