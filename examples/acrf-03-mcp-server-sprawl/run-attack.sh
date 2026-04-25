#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo ""
echo "ACRF-03 MCP Server Sprawl Demo - VULNERABLE"
echo "   Expected: Shadow server exfiltrates data. No inventory check."
echo ""
docker compose --profile vulnerable down --remove-orphans 2>/dev/null || true
docker compose --profile vulnerable up --build --abort-on-container-exit
