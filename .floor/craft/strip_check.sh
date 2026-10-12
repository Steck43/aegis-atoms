#!/usr/bin/env bash
# strip-check: each recipe must fail under strip and pass on the restored head.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
TSV=".floor/strip.tsv"
if [[ ! -f "$TSV" ]]; then
  echo "strip_check: missing $TSV" >&2
  exit 2
fi

TARGET=tools/strip_ci_fixture/add.py
FIXTURE_PYTEST=(
  -q --noconftest --import-mode=importlib
  -c tools/strip_ci_fixture/pytest.ini
)
while IFS=$'\t' read -r package strip_cmd nodeid expect_sub; do
  expect_sub="${expect_sub%$'\r'}"
  package="${package%$'\r'}"
  [[ -z "${package:-}" || "$package" =~ ^# ]] && continue
  echo "strip_check: recipe package=$package"
  backup=$(mktemp)
  cp "$TARGET" "$backup"
  # shellcheck disable=SC2086
  eval "$strip_cmd"
  PY=python3
  command -v "$PY" >/dev/null || PY=python
  set +e
  out="$($PY -m pytest "${FIXTURE_PYTEST[@]}" "$nodeid" 2>&1)"
  rc=$?
  set -e
  cp "$backup" "$TARGET"
  rm -f "$backup"
  if [[ $rc -eq 0 ]]; then
    echo "strip_check FAIL: expected red under strip for $package" >&2
    echo "$out" >&2
    exit 1
  fi
  if ! grep -F "$expect_sub" <<<"$out" >/dev/null; then
    echo "strip_check FAIL: missing expect substring for $package: $expect_sub" >&2
    echo "$out" >&2
    exit 1
  fi
  echo "strip_check: strip red OK for $package"
  $PY -m pytest "${FIXTURE_PYTEST[@]}" "$nodeid"
  echo "strip_check: head green OK for $package"
done < "$TSV"

echo "strip_check: all recipes OK"
