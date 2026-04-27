#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo ""
echo "ACRF-09 Semantic Layer Bypass Demo - PROTECTED"
echo "   Expected: Semantic guardian reads intent and blocks attacks."
echo ""
docker compose --profile protected down --remove-orphans 2>/dev/null || true
docker compose --profile protected up --build --abort-on-container-exit
