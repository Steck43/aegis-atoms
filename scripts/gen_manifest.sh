#!/usr/bin/env bash
# gen_manifest.sh — write SHA256SUMS from the bytes git stores, not the bytes
# this host happens to hold.
#
# A worktree on Windows can carry CRLF for a file whose blob is LF. Hashing the
# worktree bakes that host's line endings into a public integrity claim, and the
# claim then fails for every consumer who clones it. The manifest published
# before this script was written that way: 81 of its 110 rows did not match the
# repository, while all but 8 matched the Windows checkout it was generated on.
#
# Each path is read from the index (":path"), which is always the normalized
# form, so the output is byte-identical on every platform. `git ls-files` emits
# paths in sorted order, so the row order is stable too.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

while IFS= read -r -d '' path; do
    if [ "$path" != "SHA256SUMS" ]; then
        printf '%s  %s\n' "$(git cat-file blob ":$path" | sha256sum | cut -d' ' -f1)" "$path" >> "$tmp"
    fi
done < <(git ls-files -z)

mv "$tmp" SHA256SUMS
trap - EXIT
