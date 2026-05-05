# acrf-mcp-scan

MCP server inventory and risk scanner.
Implements the ACRF-03 (MCP Server Sprawl) defense pattern.

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
PyPI: https://pypi.org/project/acrf-mcp-scan/
Presented at RSA Conference 2026.

---

## Try it in your environment right now

No Docker. No setup. Just Python 3.10+.

**Step 1 - Install:**

    pip install acrf-mcp-scan

**Step 2 - Scan your MCP config file:**

    from acrf_mcp_scan import MCPScanner

    scanner = MCPScanner()
    inventory = scanner.scan_config_file("mcp_config.json")

    for server in inventory.suspicious_servers():
        print(f"WARNING {server.name}: {server.risk_summary()}")

**Step 3 - Scan a directory of MCP servers:**

    inventory = scanner.scan_directory("/opt/mcp-servers")

**Step 4 - Compare against your approved inventory:**

    from acrf_mcp_scan import MCPServerInventory

    trusted = MCPServerInventory.load("approved_mcp.json")
    diff = inventory.diff(trusted)

    for unauthorized in diff.added:
        print(f"UNAUTHORIZED: {unauthorized.name}")
    for missing in diff.removed:
        print(f"MISSING APPROVED: {missing.name}")

If anything is unauthorized or anything has changed in command/args/version,
your application can fail closed and refuse to start.

---

## The problem this solves

MCP server registries make it trivial to install third-party agent capabilities.
That trivial install is also an unbounded attack surface. Antiy CERT 2025
documented over 1,000 malicious MCP servers in public registries, including
postmark-mcp which silently exfiltrated email content for months before
being noticed.

This is ACRF-03: MCP server sprawl.

acrf-mcp-scan inventories every MCP server in your environment, flags
suspicious ones with a configurable rule set, and lets you compare your
running inventory against an approved baseline.

---

## What gets flagged

The scanner checks each MCP server for:

**Configuration risks**
- Missing publisher metadata (unknown_publisher)
- Publisher not in your allowed list (publisher_not_allowed)
- Missing or no cryptographic signature (missing_signature)
- autoApprove list present (auto_approve_present)
- autoApprove contains destructive operations (auto_approve_destructive) - critical

**Source code risks**
- Imports of dangerous modules (subprocess, socket, ftplib, ctypes, pickle, etc.)
- Use of os.system, eval, exec, __import__, compile
- Hard-coded URLs to external hosts not in your allowlist

**Manifest risks**
- Malformed package.json, pyproject.toml, or mcp.json
- Missing description or README

Each finding has a severity (low, medium, high, critical) and the server
risk_level is the maximum severity of its findings.

---

## CLI

Build an inventory:

    acrf-mcp-scan inventory mcp_config.json --out current_inventory.json

Check what is suspicious without writing anywhere:

    acrf-mcp-scan check mcp_config.json

Compare current state against an approved baseline:

    acrf-mcp-scan compare current_inventory.json approved_mcp.json

Output when clean:

    Scanned 4 server(s) at mcp_config.json
    Risk: critical=0 high=0 medium=0 low=0 none=4
    OK: no suspicious servers

Output when risky:

    Scanned 5 server(s) at mcp_config.json
    Risk: critical=1 high=0 medium=2 low=0 none=2

    Suspicious (3):
      [CRITICAL] TicketApp
          - critical: auto_approve_destructive (autoApprove contains destructive ops: ["refund_all"])
      [MEDIUM] EmailServer
          - medium: auto_approve_present (autoApprove list has 3 entries)
      [MEDIUM] Insights
          - medium: dangerous_import:socket (source file main.py imports socket)

---

## Configurable rules

The scanner accepts a ScannerOptions object:

    from acrf_mcp_scan import MCPScanner
    from acrf_mcp_scan.scanner import ScannerOptions

    scanner = MCPScanner(ScannerOptions(
        allowed_publishers={"trusted-vendor", "internal-team"},
        allowed_network_hosts={"api.acme-corp.com"},
        require_signature=True,
        scan_source_files=True,
    ))

When require_signature is true, an MCP server with no signature gets a
high-severity finding. When you provide allowed_publishers, any server
whose publisher is not in that set is flagged.

---

## Real-world use

In CI for your AI platform:

    from acrf_mcp_scan import MCPScanner, MCPServerInventory
    from acrf_mcp_scan.scanner import ScannerOptions
    import sys

    scanner = MCPScanner(ScannerOptions(
        allowed_publishers={"acme-internal"},
        require_signature=True,
    ))
    current = scanner.scan_config_file("config/mcp_config.json")
    trusted = MCPServerInventory.load("config/approved_mcp.json")

    if current.suspicious_servers():
        for server in current.suspicious_servers():
            print(f"FAIL {server.name}: {server.risk_summary()}")
        sys.exit(1)

    diff = current.diff(trusted)
    if not diff.is_empty():
        print(f"DRIFT: {diff.summary()}")
        sys.exit(1)

    print("OK: MCP inventory matches approved baseline")

Run that on every deployment. Block any release that introduces a new
unapproved MCP server or a server with risky configuration.

---

## ACRF-03 control objectives addressed

    SS-1  All installed MCP servers cataloged in an inventory
    SS-2  Cryptographic verification of MCP server packages before installation
            (acrf-mcp-scan flags missing signatures; pair with acrf-skill-verify
             to actually enforce hash verification)

Out of scope (your runtime stack):

    SS-3  Runtime monitoring of MCP server behavior for unexpected network calls

Runtime behavioral monitoring belongs in your observability stack, not in
a static scanner.

---

## What this library does NOT do

- It does not execute or sandbox MCP servers
- It does not block servers at runtime - it produces findings; your CI/CD enforces
- It does not replace dynamic monitoring or sandboxing

It only ensures that you know exactly what MCP servers exist in your
environment and that none of them have configuration or source code
patterns commonly seen in malicious skills. That is the ACRF-03 defense
pattern.

---

## Works with any Python AI agent framework

LangChain, CrewAI, AutoGen, MCP-based systems, custom agents.
Anywhere you load third-party agent capabilities, you can use this scanner.

---

## Authors

Ravi Karthick Sankara Narayanan, Kanna Sekar

## License

Apache 2.0
