"""The public tree does not name the retired seat, and the catalog marker stays generic.

The names live outside the tree: the LEAK_DENYLIST secret in CI, or an
untracked leak-denylist file under the repository's common git dir locally.
The seat is the literal row whose casefolded SHA-256 is SEAT_SHA256. It is
chosen by content, not position, so a row added or removed elsewhere in the
list cannot move the scan onto another name. A list that is missing, empty or
without that row fails in CI and skips with a reason elsewhere, so an absent
list can never read as a clean tree. A tracked file that is not UTF-8 counts
as a hit: a scan that cannot read a file cannot clear it.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GENERIC_MARKERS = {
    "catalog/Aegis-Atoms-v0.yaml": ["CONFIDENTIAL", "NDA", "client name"],
    "Aegis-Atoms-v0.bundle.yaml": ["CONFIDENTIAL", "NDA"],
}
SEAT_SHA256 = "5b8046ceca24242118123b520b55a8fc235ee4fbb6ce4a0506a7c02ccadbd9c2"
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


def _missing(reason: str) -> NoReturn:
    if os.environ.get("CI"):
        pytest.fail(f"{reason}; set the LEAK_DENYLIST secret")
    pytest.skip(reason)


def _denylist_rows(local: Path | None = None) -> list[str]:
    text = os.environ.get("LEAK_DENYLIST", "").strip()
    if not text:
        local = local or _local_denylist()
        text = local.read_text(encoding="utf-8") if local.is_file() else ""
    rows = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if not rows:
        _missing("leak denylist is missing or empty")
    return rows


def _digest(row: str) -> str:
    return hashlib.sha256(row.casefold().encode("utf-8")).hexdigest()


def _seat_row(rows: list[str], digest: str = SEAT_SHA256) -> str:
    for row in rows:
        if _digest(row) == digest:
            return row
    _missing(f"no row of the {len(rows)}-row leak denylist hashes to the seat")


def _pattern(row: str) -> re.Pattern[str]:
    if row.lower().startswith("re:"):
        return re.compile(row[3:], re.IGNORECASE)
    return re.compile(re.escape(row), re.IGNORECASE)


def _scan(root: Path, paths: list[str], seat: re.Pattern[str]) -> list[str]:
    hits = []
    for path in paths:
        file = root / path
        text = ""
        if file.is_file():
            try:
                text = file.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                hits.append(path)
                continue
        if seat.search(path) or seat.search(text):
            hits.append(path)
    return hits


def _outcome(call: Callable[[], object]) -> str:
    try:
        call()
    except pytest.fail.Exception:
        return "fail"
    except pytest.skip.Exception:
        return "skip"
    return "pass"


def _planted_repo(tmp_path: Path, leak: bytes) -> list[str]:
    _git("init", "-q", cwd=tmp_path)
    (tmp_path / "clean.md").write_text("generic labels\n", encoding="utf-8")
    (tmp_path / "leak.txt").write_bytes(leak)
    _git("add", "clean.md", "leak.txt", cwd=tmp_path)
    return _tracked(tmp_path)


def test_tracked_tree_does_not_name_the_retired_seat() -> None:
    seat = _pattern(_seat_row(_denylist_rows()))
    assert _scan(ROOT, _tracked(), seat) == []


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "cp1252"])
def test_scan_fails_when_the_retired_seat_is_planted(
    tmp_path: Path, encoding: str
) -> None:
    row = _seat_row(_denylist_rows())
    leak = f"caf\u00e9, see {row.upper()} notes\n".encode(encoding)
    hits = _scan(tmp_path, _planted_repo(tmp_path, leak), _pattern(row))
    assert hits == ["leak.txt"]


@pytest.mark.parametrize("encoding", ["utf-16", "cp1252"])
def test_scan_fails_closed_on_a_file_it_cannot_decode(
    tmp_path: Path, encoding: str
) -> None:
    leak = "caf\u00e9 menu\n".encode(encoding)
    hits = _scan(tmp_path, _planted_repo(tmp_path, leak), re.compile("absent"))
    assert hits == ["leak.txt"]


def test_seat_row_is_chosen_by_content_not_position() -> None:
    digest = _digest("Synthetic-Seat")
    for rows in (
        ["synthetic-seat"],
        ["decoy-a", "re:decoy", "decoy-b", "SYNTHETIC-SEAT", "decoy-c"],
        ["synthetic-seat", *(f"decoy-{n}" for n in range(12))],
    ):
        assert _seat_row(rows, digest).casefold() == "synthetic-seat"


def test_missing_list_or_seat_fails_in_ci_and_skips_elsewhere(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    absent = tmp_path / "leak-denylist"
    digest = _digest("synthetic-seat")
    monkeypatch.delenv("LEAK_DENYLIST", raising=False)
    monkeypatch.setenv("CI", "1")
    assert _outcome(lambda: _denylist_rows(absent)) == "fail"
    assert _outcome(lambda: _seat_row(["decoy-a", "decoy-b"], digest)) == "fail"
    monkeypatch.delenv("CI")
    assert _outcome(lambda: _denylist_rows(absent)) == "skip"
    assert _outcome(lambda: _seat_row(["decoy-a", "decoy-b"], digest)) == "skip"


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
