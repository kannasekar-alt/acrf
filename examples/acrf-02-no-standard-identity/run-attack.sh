#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo ""
echo "ACRF-02 No Standard Agent Identity Demo - VULNERABLE"
echo "   Expected: Retired agent token still works. No per-agent identity."
echo ""
docker compose --profile vulnerable down --remove-orphans 2>/dev/null || true
docker compose --profile vulnerable up --build --abort-on-container-exit
