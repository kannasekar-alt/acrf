#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo ""
echo "ACRF-06 Config Files = Execution Vectors Demo - PROTECTED"
echo "   Expected: Config tamper detected. Agent refuses to start."
echo ""
docker compose --profile protected down --remove-orphans 2>/dev/null || true
docker compose --profile protected up --build -d
sleep 12
docker logs ticket-agent
docker compose --profile protected down
