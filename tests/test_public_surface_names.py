"""The public tree does not name the retired seat, and the catalog marker stays generic."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
GENERIC_MARKERS = {
    "catalog/Aegis-Atoms-v0.yaml": ["CONFIDENTIAL", "NDA", "client name"],
    "Aegis-Atoms-v0.bundle.yaml": ["CONFIDENTIAL", "NDA"],
}


def _tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [p for p in out.stdout.decode("utf-8").split("\0") if p]


def _denylist_text() -> str | None:
    env = os.environ.get("LEAK_DENYLIST", "").strip()
    if env:
        return env
    local = ROOT / ".git" / "info" / "leak-denylist"
    if local.is_file():
        return local.read_text(encoding="utf-8")
    return None


def _retired_seat() -> re.Pattern[str] | None:
    """One denylist row. The spelling stays in that file, not in this source."""
    text = _denylist_text()
    if text is None:
        return None
    rows = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if len(rows) < 10:
        return None
    row = rows[9]
    if row.lower().startswith("re:"):
        return re.compile(row[3:], re.IGNORECASE)
    return re.compile(re.escape(row), re.IGNORECASE)


def test_tracked_tree_does_not_name_the_retired_seat() -> None:
    seat = _retired_seat()
    if seat is None:
        return
    hits = [path for path in _tracked() if seat.search(path)]
    for path in _tracked():
        file = ROOT / path
        if not file.is_file():
            continue
        try:
            text = file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if seat.search(text):
            hits.append(path)
    assert hits == []


def test_bound_prove_path_comes_from_the_environment() -> None:
    source = (ROOT / "__init__.py").read_text(encoding="utf-8")
    start = source.index("def _bound_prove")
    end = source.index("\ndef ", start + 1)
    body = source[start:end]
    assert "environ.get" in body
    assert "Users" not in body
    assert "/home/" not in body
    assert "/mnt/" not in body


def test_catalog_markers_stay_generic() -> None:
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
        names = _denylist_text()
        if names is None:
            continue
        blob = "\n".join(found).casefold()
        for raw in names.splitlines():
            token = raw.strip()
            if not token or token.startswith("#") or len(token) < 4:
                continue
            assert token.casefold() not in blob
