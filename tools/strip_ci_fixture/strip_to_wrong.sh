#!/usr/bin/env bash
# Restore the wrong-answer stub so strip-check expects a red pytest.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cat > "$ROOT/tools/strip_ci_fixture/add.py" <<'EOF'
"""GIT-5 fixture: intentional wrong stub for strip-check."""


def add(a: int, b: int) -> int:
    return a - b
EOF
