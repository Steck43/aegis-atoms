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

backup=""
target=""
restore_target() {
  if [[ -n "${backup:-}" && -f "${backup}" && -n "${target:-}" ]]; then
    cp "$backup" "$target"
    rm -f "$backup"
  fi
  backup=""
  target=""
}
trap restore_target EXIT

ran=0
# fd 3, so a strip command or pytest that reads stdin cannot eat later rows.
# The || test keeps a final row that has no trailing newline.
while IFS=$'\t' read -r package strip_target strip_cmd nodeid expect_sub <&3 || [[ -n "${package:-}" ]]; do
  expect_sub="${expect_sub%$'\r'}"
  package="${package%$'\r'}"
  strip_target="${strip_target%$'\r'}"
  [[ -z "${package:-}" || "$package" =~ ^# ]] && continue
  if [[ -z "${strip_target:-}" || -z "${strip_cmd:-}" || -z "${nodeid:-}" || -z "${expect_sub:-}" ]]; then
    echo "strip_check FAIL: incomplete recipe for package=$package" >&2
    exit 2
  fi
  if [[ ! -f "$strip_target" ]]; then
    echo "strip_check FAIL: strip target missing: $strip_target" >&2
    exit 2
  fi
  ran=$((ran + 1))
  echo "strip_check: recipe package=$package target=$strip_target"
  target="$strip_target"
  backup=$(mktemp)
  cp "$target" "$backup"
  # shellcheck disable=SC2086
  eval "$strip_cmd"
  PY=python3
  command -v "$PY" >/dev/null || PY=python
  # Fixture job installs pytest only; isolate from repo pytest.ini / plugin root.
  local_pytest=( -q --noconftest --import-mode=importlib )
  if [[ -f tools/strip_ci_fixture/pytest.ini && "$nodeid" == tools/strip_ci_fixture/* ]]; then
    local_pytest+=( -c tools/strip_ci_fixture/pytest.ini )
  fi
  set +e
  out="$($PY -m pytest "${local_pytest[@]}" "$nodeid" 2>&1)"
  rc=$?
  set -e
  restore_target
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
  $PY -m pytest "${local_pytest[@]}" "$nodeid"
  echo "strip_check: head green OK for $package"
done 3< "$TSV"

if [[ $ran -eq 0 ]]; then
  echo "strip_check FAIL: no recipes in $TSV" >&2
  exit 2
fi

echo "strip_check: all recipes OK ($ran)"
