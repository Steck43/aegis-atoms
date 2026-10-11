#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/lande/Engineering_and_Development/aegis-atoms-public
export ANTHROPIC_API_KEY
ANTHROPIC_API_KEY="$(grep ^ANTHROPIC_API_KEY= ~/.hermes/profiles/aegis/.env | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'")"
mkdir -p receipts/raw/judge-spec
python3 scripts/j7_smoke_temp_top_p.py receipts/raw/judge-spec/JUDGE-J7-SMOKE-2026-10-11.json
