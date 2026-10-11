"""Spec section 3: hash a new calibration carve before labeling (design harness).

Read-only over scenario ids and optional body texts. Writes a hashed split
manifest. Does not label. Labels are out-of-path (LBL lane) and stored separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def body_content_hash(body: str) -> str:
    return hashlib.sha256(body.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def family_of(scenario_id: str) -> str:
    """Tool/track family prefix before first underscore or slash."""
    for sep in ("/", "_"):
        if sep in scenario_id:
            return scenario_id.split(sep, 1)[0]
    return scenario_id


def bucket_for(scenario_id: str, *, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:{scenario_id}".encode()).hexdigest()
    n = int(digest[:8], 16)
    # 70% tuning / 30% locked; disjoint from held-out by explicit refuse.
    return "tuning" if (n % 10) < 7 else "locked"


def carve(
    scenario_ids: list[str],
    *,
    heldout_ids: set[str],
    salt: str,
    forbidden_body_hashes: set[str] | None = None,
    forbidden_families: set[str] | None = None,
    id_to_body: dict[str, str] | None = None,
) -> dict:
    overlap = sorted(set(scenario_ids) & heldout_ids)
    if overlap:
        raise SystemExit(f"slice overlaps held-out: {overlap[:20]}")
    forbidden_body_hashes = forbidden_body_hashes or set()
    forbidden_families = forbidden_families or set()
    id_to_body = id_to_body or {}
    for sid in scenario_ids:
        fam = family_of(sid)
        if fam in forbidden_families:
            raise SystemExit(f"carve refuses family overlap: id={sid!r} family={fam!r}")
        body = id_to_body.get(sid)
        if body is None:
            continue
        digest = body_content_hash(body)
        if digest in forbidden_body_hashes:
            raise SystemExit(
                f"carve refuses content overlap new id: id={sid!r} hash={digest[:12]}"
            )
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
        "content_hash_disjoint": True,
        "family_disjoint": True,
        "labels": "OUT_OF_PATH_MODELED_NOT_IN_THIS_FILE",
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


def _load_lines(path: Path) -> list[str]:
    return [
        ln.strip()
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]


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
    ap.add_argument(
        "--forbidden-body-hashes-file",
        type=Path,
        default=None,
        help="newline-separated sha256 of bodies already used (pilot/anchors/canary/J-1)",
    )
    ap.add_argument(
        "--forbidden-families-file",
        type=Path,
        default=None,
        help="newline-separated families reserved by other slices",
    )
    ap.add_argument(
        "--bodies-json",
        type=Path,
        default=None,
        help='optional JSON object {"id": "body text", ...} for content-hash checks',
    )
    ap.add_argument("--salt", default="judge-spec-v1-2026-10-11")
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("receipts/raw/judge-spec/CALIBRATION-CARVE.json"),
    )
    args = ap.parse_args()
    ids = _load_lines(args.ids_file)
    held = set(_load_lines(args.heldout_file))
    forbidden_hashes: set[str] = set()
    if args.forbidden_body_hashes_file and args.forbidden_body_hashes_file.is_file():
        forbidden_hashes = set(_load_lines(args.forbidden_body_hashes_file))
    forbidden_families: set[str] = set()
    if args.forbidden_families_file and args.forbidden_families_file.is_file():
        forbidden_families = set(_load_lines(args.forbidden_families_file))
    id_to_body: dict[str, str] = {}
    if args.bodies_json and args.bodies_json.is_file():
        id_to_body = json.loads(args.bodies_json.read_text(encoding="utf-8"))
    doc = carve(
        ids,
        heldout_ids=held,
        salt=args.salt,
        forbidden_body_hashes=forbidden_hashes,
        forbidden_families=forbidden_families,
        id_to_body=id_to_body,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out} carve_sha256={doc['carve_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
