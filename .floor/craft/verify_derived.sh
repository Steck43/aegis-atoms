#!/usr/bin/env bash
# verify_derived.sh — a generated file must be derived, not maintained.
#
# Reads `.floor/derived.tsv`, one `artifact<TAB>command` per line, runs each
# generator, and fails if the committed artifact is not what the generator
# produces. An absent registry is a no-op, so this is safe on any roof.
#
# Why this exists: SHA256SUMS on this repository claimed to list the bytes of
# the tree and, for anyone who cloned it, 81 of its 110 rows were wrong. It was
# hand-written once from a Windows checkout and nothing ever read it again. The
# defect was not the wrong hashes. It was that a file which is a function of
# other files was being maintained by hand.
#
# The command must be plain argv: no pipes, redirects, or shell operators. The
# nightly readiness probe runs the same registry without a shell, and a command
# that only works under one of them is a check that disagrees with itself.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

REG=.floor/derived.tsv
if [ ! -f "$REG" ]; then
    echo "verify_derived: no $REG in this roof, nothing to verify"
    exit 0
fi

rc=0
rows=0

while IFS=$'\t' read -r artifact cmd <&3 || [ -n "${artifact:-}" ]; do
    case "${artifact:-}" in
        '' | \#*) continue ;;
    esac
    [ -n "${cmd:-}" ] || continue

    if ! git ls-files --error-unmatch "$artifact" >/dev/null 2>&1; then
        echo "verify_derived: FAIL $artifact is listed but not tracked by git"
        rc=1
        continue
    fi

    rows=$((rows + 1))
    echo "verify_derived: $artifact <- $cmd"

    # shellcheck disable=SC2086
    if ! $cmd </dev/null; then
        echo "verify_derived: FAIL generator for $artifact exited nonzero"
        rc=1
        continue
    fi

    if ! git diff --quiet -- "$artifact"; then
        echo "verify_derived: FAIL $artifact is not what its generator produces"
        git --no-pager diff --stat -- "$artifact"
        rc=1
    fi
done 3< "$REG"

if [ "$rc" -eq 0 ]; then
    echo "verify_derived: $rows artifact(s) reproduce from their generator"
fi

exit "$rc"
