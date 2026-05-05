"""
acrf-mcp-scan
=============

MCP server inventory and risk scanner.
Implements the ACRF-03 (MCP Server Sprawl) defense pattern.

Quick start:

    from acrf_mcp_scan import MCPScanner, MCPServerInventory

    # Scan an MCP config file
    scanner = MCPScanner()
    inventory = scanner.scan_config_file("mcp_config.json")

    # Print findings
    for server in inventory.servers:
        if server.is_suspicious():
            print(f"WARNING {server.name}: {server.risk_summary()}")

    # Compare against approved list
    trusted = MCPServerInventory.load("trusted_mcp.json")
    diff = inventory.diff(trusted)
    for unauthorized in diff.added:
        print(f"UNAUTHORIZED: {unauthorized.name}")

Detection rules:

    - Unknown publisher (no signature, no metadata)
    - Outbound network calls to non-allowlisted destinations
    - Use of dangerous modules (subprocess, socket, os.system)
    - File system writes outside expected paths
    - Missing README or version
    - Servers not in the approved inventory

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
"""
from acrf_mcp_scan.exceptions import (
    InvalidConfigError,
    InventoryError,
    MCPScanError,
)
from acrf_mcp_scan.inventory import (
    InventoryDiff,
    MCPServer,
    MCPServerInventory,
)
from acrf_mcp_scan.scanner import MCPScanner

__version__ = "0.1.0"
__all__ = [
    "MCPScanner",
    "MCPServer",
    "MCPServerInventory",
    "InventoryDiff",
    "MCPScanError",
    "InvalidConfigError",
    "InventoryError",
]
