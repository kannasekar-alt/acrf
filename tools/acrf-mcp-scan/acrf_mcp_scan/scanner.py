"""
MCP Scanner module.

Scans MCP config files and server directories to build an inventory and
flag suspicious servers using a configurable rule set.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acrf_mcp_scan.exceptions import InvalidConfigError
from acrf_mcp_scan.inventory import (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    MCPServer,
    MCPServerInventory,
)

DANGEROUS_IMPORTS = {
    "subprocess",
    "socket",
    "ftplib",
    "telnetlib",
    "smtplib",
    "ctypes",
    "pickle",
    "marshal",
}

DANGEROUS_PATTERNS = [
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\beval\s*\("),
    re.compile(r"\bexec\s*\("),
    re.compile(r"\b__import__\s*\("),
    re.compile(r"\bcompile\s*\("),
]

NETWORK_HINT_PATTERN = re.compile(
    r"(https?://|wss?://|tcp://|udp://)([a-zA-Z0-9._-]+)",
    re.IGNORECASE,
)


@dataclass
class ScannerOptions:
    allowed_publishers: set[str] = field(default_factory=set)
    allowed_network_hosts: set[str] = field(default_factory=set)
    require_signature: bool = True
    scan_source_files: bool = True
    source_file_extensions: tuple[str, ...] = (".py", ".js", ".ts", ".mjs")


class MCPScanner:
    def __init__(self, options: ScannerOptions | None = None) -> None:
        self.options = options or ScannerOptions()

    def scan_config_file(self, path: str | Path) -> MCPServerInventory:
        config_path = Path(path)
        if not config_path.exists():
            raise InvalidConfigError(f"config file not found: {path}")
        try:
            data = json.loads(config_path.read_text())
        except json.JSONDecodeError as exc:
            raise InvalidConfigError(f"config file is not valid JSON: {exc}") from exc
        servers_block = data.get("mcpServers")
        if not isinstance(servers_block, dict):
            raise InvalidConfigError("config file does not contain an mcpServers object")

        inventory = MCPServerInventory()
        for name, raw in servers_block.items():
            server = self._parse_config_entry(name, raw, source=str(config_path))
            self._apply_config_rules(server, raw)
            if self.options.scan_source_files and server.command:
                self._scan_referenced_files(server)
            inventory.add(server)
        return inventory

    def scan_directory(self, path: str | Path) -> MCPServerInventory:
        root = Path(path)
        if not root.is_dir():
            raise InvalidConfigError(f"not a directory: {path}")
        inventory = MCPServerInventory()
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            server = self._parse_directory(child)
            self._apply_metadata_rules(server)
            if self.options.scan_source_files:
                self._scan_directory_source(server, child)
            inventory.add(server)
        return inventory

    def _parse_config_entry(self, name: str, raw: Any, source: str) -> MCPServer:
        if not isinstance(raw, dict):
            server = MCPServer(name=name, source=source)
            server.add_finding(
                rule="invalid_config_entry",
                severity=RISK_HIGH,
                detail="server config entry is not an object",
            )
            return server
        return MCPServer(
            name=name,
            source=source,
            command=str(raw.get("command", "")),
            args=[str(a) for a in raw.get("args", [])],
            publisher=str(raw.get("publisher", "")),
            version=str(raw.get("version", "")),
            has_signature=bool(raw.get("signature")),
            metadata=dict(raw.get("metadata", {})),
        )

    def _apply_config_rules(self, server: MCPServer, raw: Any) -> None:
        if isinstance(raw, dict):
            auto_approve = raw.get("autoApprove", [])
            if isinstance(auto_approve, list) and len(auto_approve) > 0:
                destructive = [a for a in auto_approve if self._is_destructive(str(a))]
                if destructive:
                    server.add_finding(
                        rule="auto_approve_destructive",
                        severity=RISK_CRITICAL,
                        detail=f"autoApprove contains destructive ops: {destructive}",
                    )
                else:
                    server.add_finding(
                        rule="auto_approve_present",
                        severity=RISK_MEDIUM,
                        detail=f"autoApprove list has {len(auto_approve)} entries",
                    )
        if not server.command:
            server.add_finding(
                rule="missing_command",
                severity=RISK_HIGH,
                detail="MCP server has no command",
            )
        self._apply_publisher_rules(server)
        self._apply_signature_rules(server)

    def _apply_metadata_rules(self, server: MCPServer) -> None:
        if not server.metadata.get("description") and not server.metadata.get("readme"):
            server.add_finding(
                rule="missing_description",
                severity=RISK_LOW,
                detail="server has no description or README",
            )
        self._apply_publisher_rules(server)
        self._apply_signature_rules(server)

    def _apply_publisher_rules(self, server: MCPServer) -> None:
        if not server.publisher:
            server.add_finding(
                rule="unknown_publisher",
                severity=RISK_HIGH,
                detail="no publisher metadata declared",
            )
            return
        if (
            self.options.allowed_publishers
            and server.publisher not in self.options.allowed_publishers
        ):
            server.add_finding(
                rule="publisher_not_allowed",
                severity=RISK_HIGH,
                detail=f"publisher {server.publisher!r} is not in allowed list",
            )

    def _apply_signature_rules(self, server: MCPServer) -> None:
        if self.options.require_signature and not server.has_signature:
            server.add_finding(
                rule="missing_signature",
                severity=RISK_HIGH,
                detail="server is not cryptographically signed",
            )

    def _parse_directory(self, dir_path: Path) -> MCPServer:
        server = MCPServer(name=dir_path.name, source=str(dir_path))
        for fname in ("package.json", "pyproject.toml", "mcp.json"):
            fpath = dir_path / fname
            if fpath.exists():
                self._enrich_from_manifest(server, fpath)
                break
        return server

    def _enrich_from_manifest(self, server: MCPServer, manifest_path: Path) -> None:
        try:
            text = manifest_path.read_text()
        except OSError:
            return
        if manifest_path.name == "package.json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                server.add_finding(
                    rule="malformed_manifest",
                    severity=RISK_MEDIUM,
                    detail="package.json is not valid JSON",
                )
                return
            server.publisher = str(data.get("author", "") or data.get("publisher", ""))
            server.version = str(data.get("version", ""))
            server.metadata = {
                "description": data.get("description", ""),
                "license": data.get("license", ""),
            }
        elif manifest_path.name == "pyproject.toml":
            for line in text.splitlines():
                if line.startswith("name "):
                    server.metadata["pyproject_name"] = line.split("=", 1)[-1].strip().strip("\"")
                if line.startswith("version "):
                    server.version = line.split("=", 1)[-1].strip().strip("\"")
        elif manifest_path.name == "mcp.json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                server.add_finding(
                    rule="malformed_manifest",
                    severity=RISK_MEDIUM,
                    detail="mcp.json is not valid JSON",
                )
                return
            server.publisher = str(data.get("publisher", ""))
            server.version = str(data.get("version", ""))
            server.has_signature = bool(data.get("signature"))
            server.metadata = dict(data.get("metadata", {}))

    def _scan_referenced_files(self, server: MCPServer) -> None:
        for candidate in [server.command, *server.args]:
            path = Path(candidate)
            if path.exists() and path.is_file():
                self._scan_source_file(server, path)
            elif path.exists() and path.is_dir():
                self._scan_directory_source(server, path)

    def _scan_directory_source(self, server: MCPServer, dir_path: Path) -> None:
        for ext in self.options.source_file_extensions:
            for src_file in dir_path.rglob(f"*{ext}"):
                self._scan_source_file(server, src_file)

    def _scan_source_file(self, server: MCPServer, path: Path) -> None:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return
        for module in DANGEROUS_IMPORTS:
            if re.search(rf"\b(?:import\s+{module}|from\s+{module}\s+import)\b", text):
                server.add_finding(
                    rule=f"dangerous_import:{module}",
                    severity=RISK_MEDIUM,
                    detail=f"source file {path.name} imports {module}",
                )
        for pattern in DANGEROUS_PATTERNS:
            match = pattern.search(text)
            if match:
                server.add_finding(
                    rule=f"dangerous_call:{match.group(0)}",
                    severity=RISK_HIGH,
                    detail=f"source file {path.name} uses {match.group(0)}",
                )
        for match in NETWORK_HINT_PATTERN.finditer(text):
            host = match.group(2).lower()
            if host in {"localhost", "127.0.0.1"}:
                continue
            if (
                self.options.allowed_network_hosts
                and host in self.options.allowed_network_hosts
            ):
                continue
            server.add_finding(
                rule="network_endpoint",
                severity=RISK_MEDIUM,
                detail=f"source file {path.name} references {match.group(0)}",
            )

    @staticmethod
    def _is_destructive(action: str) -> bool:
        lowered = action.lower()
        destructive_keywords = (
            "delete",
            "remove",
            "drop",
            "purge",
            "wipe",
            "destroy",
            "refund_all",
            "transfer",
            "shutdown",
        )
        return any(k in lowered for k in destructive_keywords)
