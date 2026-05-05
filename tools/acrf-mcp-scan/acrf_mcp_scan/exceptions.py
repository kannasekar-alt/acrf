"""Exceptions raised by acrf-mcp-scan."""


class MCPScanError(Exception):
    """Base exception for all MCP scan errors."""


class InvalidConfigError(MCPScanError):
    """Raised when an MCP config file cannot be parsed."""


class InventoryError(MCPScanError):
    """Raised when an inventory file is malformed."""
