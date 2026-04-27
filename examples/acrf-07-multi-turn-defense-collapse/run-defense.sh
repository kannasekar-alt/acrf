#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo ""
echo "ACRF-07 Multi-Turn Defense Collapse Demo - PROTECTED"
echo "   Expected: Guardian detects drift. Address change blocked. Laptop ships to Alice."
echo ""
docker compose --profile protected down --remove-orphans 2>/dev/null || true
docker compose --profile protected up --build --abort-on-container-exit
