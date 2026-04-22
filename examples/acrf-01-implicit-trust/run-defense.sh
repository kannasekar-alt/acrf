#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo ""
echo "ACRF-01 Implicit Trust Demo — PROTECTED"
echo "   Expected outcome: Attack blocked. mTLS + signed Agent Cards prevent impersonation."
echo ""
docker compose --profile protected down --remove-orphans 2>/dev/null || true
docker compose --profile protected up --build --abort-on-container-exit
echo ""
echo "Demo complete. Check audit log to see rejected attempts."
