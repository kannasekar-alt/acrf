#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo ""
echo "ACRF-06 Config Files = Execution Vectors Demo - VULNERABLE"
echo "   Expected: Attacker edits config. Agent auto-refunds all tickets."
echo ""
docker compose --profile vulnerable down --remove-orphans 2>/dev/null || true
docker compose --profile vulnerable up --build -d
sleep 12
docker logs ticket-agent
docker compose --profile vulnerable down
