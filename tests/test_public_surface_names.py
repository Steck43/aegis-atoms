"""The public tree does not name the retired seat, and the catalog marker stays generic.

The names live outside the tree: the LEAK_DENYLIST secret in CI, or an
untracked leak-denylist file under the repository's common git dir locally.
A missing or short list fails in CI and skips with a reason elsewhere, so an
absent list can never read as a clean tree.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GENERIC_MARKERS = {
    "catalog/Aegis-Atoms-v0.yaml": ["CONFIDENTIAL", "NDA", "client name"],
    "Aegis-Atoms-v0.bundle.yaml": ["CONFIDENTIAL", "NDA"],
}
SEAT_ROW = 9
_ARGS = {
    "tool_call_id": "call-synthetic-1",
    "gate_decision_sha256": "a" * 64,
    "atoms_result_sha256": "b" * 64,
}


def _git(*args: str, cwd: Path = ROOT) -> str:
    out = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)
    return out.stdout.decode("utf-8")


def _tracked(root: Path = ROOT) -> list[str]:
    return [p for p in _git("ls-files", "-z", cwd=root).split("\0") if p]


def _local_denylist() -> Path:
    # A linked worktree has a .git file, not a directory, so ask git for the
    # shared dir instead of joining ROOT / ".git".
    common = Path(_git("rev-parse", "--git-common-dir").strip())
    if not common.is_absolute():
        common = ROOT / common
    return common / "info" / "leak-denylist"


def _denylist_rows() -> list[str]:
    text = os.environ.get("LEAK_DENYLIST", "").strip()
    if not text:
        local = _local_denylist()
        text = local.read_text(encoding="utf-8") if local.is_file() else ""
    rows = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if len(rows) > SEAT_ROW:
        return rows
    reason = f"leak denylist has {len(rows)} rows; need more than {SEAT_ROW}"
    if os.environ.get("CI"):
        pytest.fail(f"{reason}; set the LEAK_DENYLIST secret")
    pytest.skip(reason)


def _pattern(row: str) -> re.Pattern[str]:
    if row.lower().startswith("re:"):
        return re.compile(row[3:], re.IGNORECASE)
    return re.compile(re.escape(row), re.IGNORECASE)


def _scan(root: Path, paths: list[str], seat: re.Pattern[str]) -> list[str]:
    hits = [path for path in paths if seat.search(path)]
    for path in paths:
        file = root / path
        if not file.is_file():
            continue
        try:
            text = file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if seat.search(text):
            hits.append(path)
    return hits


def test_tracked_tree_does_not_name_the_retired_seat() -> None:
    seat = _pattern(_denylist_rows()[SEAT_ROW])
    assert _scan(ROOT, _tracked(), seat) == []


def test_scan_fails_when_the_retired_seat_is_planted(tmp_path: Path) -> None:
    row = _denylist_rows()[SEAT_ROW]
    if row.lower().startswith("re:"):
        pytest.fail("seat row is a regex; the planted canary needs a literal row")
    _git("init", "-q", cwd=tmp_path)
    (tmp_path / "clean.md").write_text("generic labels\n", encoding="utf-8")
    (tmp_path / "leak.md").write_text(f"see {row.upper()} notes\n", encoding="utf-8")
    _git("add", "clean.md", "leak.md", cwd=tmp_path)
    hits = _scan(tmp_path, _tracked(tmp_path), _pattern(row))
    assert hits == ["leak.md"]


def test_bound_prove_refuses_at_runtime_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import __init__ as atoms

    monkeypatch.delenv("AEGISBOX_BOUND_PROVE", raising=False)
    monkeypatch.setattr(atoms.Path, "is_file", lambda self: True)
    calls: list[object] = []
    monkeypatch.setattr(atoms.subprocess, "run", lambda *a, **k: calls.append(a))
    prove, code, err = atoms._bound_prove_on_aegisbox(**_ARGS)
    assert (prove, code, calls) == (None, 2, [])
    assert err is not None and "AEGISBOX_BOUND_PROVE" in err


def test_catalog_markers_stay_generic() -> None:
    rows = _denylist_rows()
    paths = [
        ROOT / "catalog" / "Aegis-Atoms-v0.yaml",
        ROOT / "Aegis-Atoms-v0.bundle.yaml",
    ]
    for path in paths:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        atoms = doc["atoms"] if isinstance(doc, dict) and "atoms" in doc else doc
        found = None
        for atom in atoms:
            det = (atom.get("detector") or {}) if isinstance(atom, dict) else {}
            if det.get("kind") == "write_content_to_clean_path":
                found = det.get("confidentiality_markers")
        rel = path.relative_to(ROOT).as_posix()
        assert found == GENERIC_MARKERS[rel], rel
        blob = "\n".join(found).casefold()
        for token in rows:
            if len(token) < 4 or token.lower().startswith("re:"):
                continue
            assert token.casefold() not in blob
