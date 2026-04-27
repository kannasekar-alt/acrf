#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo ""
echo "ACRF-07 Multi-Turn Defense Collapse Demo - VULNERABLE"
echo "   Expected: Attacker shifts shipping address across turns. Laptop ships to attacker."
echo ""
docker compose --profile vulnerable down --remove-orphans 2>/dev/null || true
docker compose --profile vulnerable up --build --abort-on-container-exit
