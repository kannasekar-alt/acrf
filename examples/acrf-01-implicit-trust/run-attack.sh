#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo ""
echo "ACRF-01 Implicit Trust Demo — VULNERABLE"
echo "   Expected outcome: Attack succeeds. No authentication between agents."
echo ""
docker compose --profile vulnerable down --remove-orphans 2>/dev/null || true
docker compose --profile vulnerable up --build --abort-on-container-exit
echo ""
echo "Demo complete. To see the defense: ./run-defense.sh"
