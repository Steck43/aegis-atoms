"""GIT-3 helper: before branch delete, record red sha and refs/pull/N/head."""

from __future__ import annotations

import argparse
import subprocess
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True, help="owner/name")
    ap.add_argument("--pr", type=int, required=True)
    ap.add_argument("--red-sha", required=True, help="failing-first / red tip sha")
    args = ap.parse_args()
    ref = f"refs/pull/{args.pr}/head"
    out = subprocess.check_output(
        ["git", "ls-remote", f"https://github.com/{args.repo}.git", ref],
        text=True,
    ).strip()
    if not out:
        print(f"FAIL: {ref} does not resolve", file=sys.stderr)
        return 1
    remote_sha = out.split()[0]
    print(f"red_sha={args.red_sha}")
    print(f"refs_pull={ref}")
    print(f"remote_sha={remote_sha}")
    # Containing check: red sha is ancestor of or equal to remote tip.
    rc = subprocess.call(
        ["git", "merge-base", "--is-ancestor", args.red_sha, remote_sha]
    )
    if rc != 0 and args.red_sha != remote_sha:
        print(
            "FAIL: red sha is not contained in refs/pull tip "
            "(fetch the PR ref locally if needed)",
            file=sys.stderr,
        )
        return 2
    print("OK: red sha contained in refs/pull tip")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
