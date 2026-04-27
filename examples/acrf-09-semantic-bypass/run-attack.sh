#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo ""
echo "ACRF-09 Semantic Layer Bypass Demo - VULNERABLE"
echo "   Expected: Semantic attacks pass through traditional firewall."
echo ""
docker compose --profile vulnerable down --remove-orphans 2>/dev/null || true
docker compose --profile vulnerable up --build --abort-on-container-exit
