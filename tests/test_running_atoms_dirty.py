"""J0-8: dirty tree flag; no .git fails closed."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import judge_slot_sonnet as slot


def test_dirty_tree_flagged(monkeypatch):
    def fake_run(cmd, cwd=None, capture_output=True, text=True, check=False):
        class R:
            returncode = 0
            stdout = " M judge_slot_sonnet.py\n"
            stderr = ""

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert slot.running_atoms_dirty() is True


def test_clean_tree_not_dirty(monkeypatch):
    def fake_run(cmd, cwd=None, capture_output=True, text=True, check=False):
        class R:
            returncode = 0
            stdout = ""
            stderr = ""

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert slot.running_atoms_dirty() is False


def test_no_git_fails_closed(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(slot, "__file__", str(tmp_path / "judge_slot_sonnet.py"))
    with pytest.raises(ValueError, match="no .git"):
        slot.running_atoms_dirty()
    with pytest.raises(ValueError, match="no .git"):
        slot.running_atoms_commit()
