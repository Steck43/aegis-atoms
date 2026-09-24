"""catalog/REGISTRY.tsv must match a fresh harvest of this repo, and never carry a fenced id.

Local columns only (atom_id..source). The `copies` column and cross-copy drift
depend on the vault and WSL, so they belong to `tools/build_registry.py --check`,
not to a suite that must pass on a clean clone.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import build_registry as br  # noqa: E402


def test_registry_tsv_matches_a_fresh_local_harvest():
    cats, codes, _ = br.load_copies(local_only=True)
    fresh = br.render(br.build_rows(cats, codes))
    on_disk = br.TSV.read_text(encoding="utf-8")
    assert br._local_cols(on_disk) == br._local_cols(fresh), (
        "REGISTRY.tsv is stale: run `python tools/build_registry.py`"
    )


def test_registry_never_carries_a_fenced_id():
    assert not br.fence_skip().search(br.TSV.read_text(encoding="utf-8"))


def test_fence_pattern_is_not_tracked_in_git():
    tracked = br.subprocess.check_output(
        ["git", "ls-files", "--", "catalog/.fence"],
        cwd=br.ROOT,
        text=True,
    ).strip()
    assert tracked == ""


def test_every_code_atom_constant_is_a_row():
    cats, codes, _ = br.load_copies(local_only=True)
    ids = {r["atom_id"] for r in br.build_rows(cats, codes)}
    assert set(codes["pub_code"]) <= ids
    assert len(codes["pub_code"]) >= 11
