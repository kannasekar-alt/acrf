#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo ""
echo "ACRF-02 No Standard Agent Identity Demo - PROTECTED"
echo "   Expected: Retired token revoked. Per-agent scoped tokens enforced."
echo ""
docker compose --profile protected down --remove-orphans 2>/dev/null || true
docker compose --profile protected up --build --abort-on-container-exit
