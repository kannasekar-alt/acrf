#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo ""
echo "ACRF-03 MCP Server Sprawl Demo - PROTECTED"
echo "   Expected: Shadow server blocked by inventory check."
echo ""
docker compose --profile protected down --remove-orphans 2>/dev/null || true
docker compose --profile protected up --build --abort-on-container-exit
