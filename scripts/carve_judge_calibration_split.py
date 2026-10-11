"""Spec §3 — hash a new calibration carve before labeling (design harness).

Read-only over scenario ids. Writes a hashed split manifest. Does not label.
Labels are human-only and stored separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def bucket_for(scenario_id: str, *, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:{scenario_id}".encode()).hexdigest()
    n = int(digest[:8], 16)
    # 70% tuning / 30% locked — disjoint from held-out by explicit refuse.
    return "tuning" if (n % 10) < 7 else "locked"


def carve(
    scenario_ids: list[str],
    *,
    heldout_ids: set[str],
    salt: str,
) -> dict:
    overlap = sorted(set(scenario_ids) & heldout_ids)
    if overlap:
        raise SystemExit(f"slice overlaps held-out: {overlap[:20]}")
    tuning: list[str] = []
    locked: list[str] = []
    for sid in sorted(scenario_ids):
        (tuning if bucket_for(sid, salt=salt) == "tuning" else locked).append(sid)
    doc = {
        "salt": salt,
        "n": len(scenario_ids),
        "tuning": tuning,
        "locked": locked,
        "heldout_disjoint": True,
        "labels": "HUMAN_ONLY_NOT_IN_THIS_FILE",
        "protocol": {
            "runs_per_item": 3,
            "flip_counts_as_error": True,
            "report_on": "locked",
        },
    }
    doc["carve_sha256"] = hashlib.sha256(
        json.dumps(
            {"salt": salt, "tuning": tuning, "locked": locked},
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return doc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--ids-file",
        type=Path,
        required=True,
        help="newline-separated scenario ids (read-only)",
    )
    ap.add_argument(
        "--heldout-file",
        type=Path,
        required=True,
        help="newline-separated held-out ids to refuse overlap against",
    )
    ap.add_argument("--salt", default="judge-spec-v1-2026-10-11")
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("receipts/raw/judge-spec/CALIBRATION-CARVE.json"),
    )
    args = ap.parse_args()
    ids = [
        ln.strip()
        for ln in args.ids_file.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    held = {
        ln.strip()
        for ln in args.heldout_file.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    }
    doc = carve(ids, heldout_ids=held, salt=args.salt)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out} carve_sha256={doc['carve_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
