"""strip_check.sh: every recipe row is run, and a failed run leaves no strip.

Failure class: `while read` drops a final row that has no trailing newline.
With two recipes, the second one is never run, the script still prints
"all recipes OK", and a strip that no longer goes red passes the gate. A file
saved by an editor that trims the last newline is enough to cause it.

Each test copies the script and the fixture into a scratch git repo, so the
real tree is never stripped.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".floor" / "craft" / "strip_check.sh"
FIXTURE = ROOT / "tools" / "strip_ci_fixture"

HEADER = "# package\tstrip_target\tstrip_cmd\tpytest_nodeid\texpect_fail_substring\n"
GOOD = (
    "strip_ci_fixture\ttools/strip_ci_fixture/add.py\t"
    "bash tools/strip_ci_fixture/strip_to_wrong.sh\t"
    "tools/strip_ci_fixture/test_add.py::test_add_one_plus_one_is_two\t"
    "assert 0 == 2"
)
# A strip that changes nothing: pytest stays green, so the recipe must fail.
NOOP = (
    "noop_strip\ttools/strip_ci_fixture/add.py\ttrue\t"
    "tools/strip_ci_fixture/test_add.py::test_add_one_plus_one_is_two\t"
    "assert 0 == 2"
)

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def _repo(tmp_path: Path, tsv: str) -> Path:
    repo = tmp_path / "repo"
    (repo / ".floor" / "craft").mkdir(parents=True)
    shutil.copy2(SCRIPT, repo / ".floor" / "craft" / "strip_check.sh")
    shutil.copytree(
        FIXTURE,
        repo / "tools" / "strip_ci_fixture",
        ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"),
    )
    (repo / ".floor" / "strip.tsv").write_bytes(tsv.encode("utf-8"))
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    return repo


def _run(repo: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    # strip_check.sh calls python3 -m pytest; point it at this interpreter.
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    env.pop("PYTEST_ADDOPTS", None)
    return subprocess.run(
        ["bash", ".floor/craft/strip_check.sh"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _add_bytes(repo: Path) -> bytes:
    return (repo / "tools" / "strip_ci_fixture" / "add.py").read_bytes()


def test_good_recipe_passes_and_restores(tmp_path):
    repo = _repo(tmp_path, HEADER + GOOD + "\n")
    before = _add_bytes(repo)
    r = _run(repo)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "all recipes OK (1)" in r.stdout
    assert _add_bytes(repo) == before


def test_last_row_without_newline_is_still_run(tmp_path):
    repo = _repo(tmp_path, HEADER + GOOD + "\n" + NOOP)
    before = _add_bytes(repo)
    r = _run(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "expected red under strip for noop_strip" in r.stderr
    assert _add_bytes(repo) == before


def test_only_row_without_newline_is_counted(tmp_path):
    repo = _repo(tmp_path, HEADER + GOOD)
    r = _run(repo)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "all recipes OK (1)" in r.stdout


def test_crlf_rows_are_read(tmp_path):
    tsv = (HEADER + GOOD + "\n" + NOOP + "\n").replace("\n", "\r\n")
    repo = _repo(tmp_path, tsv)
    r = _run(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "expected red under strip for noop_strip" in r.stderr


def test_empty_recipe_list_fails(tmp_path):
    repo = _repo(tmp_path, HEADER)
    r = _run(repo)
    assert r.returncode == 2
    assert "no recipes" in r.stderr


def test_incomplete_row_fails(tmp_path):
    repo = _repo(tmp_path, HEADER + "strip_ci_fixture\ttools/strip_ci_fixture/add.py\n")
    r = _run(repo)
    assert r.returncode == 2
    assert "incomplete recipe" in r.stderr


def test_missing_target_fails(tmp_path):
    row = GOOD.replace(
        "tools/strip_ci_fixture/add.py", "tools/strip_ci_fixture/gone.py", 1
    )
    repo = _repo(tmp_path, HEADER + row + "\n")
    r = _run(repo)
    assert r.returncode == 2
    assert "strip target missing" in r.stderr


def test_wrong_expect_substring_fails(tmp_path):
    row = GOOD.replace("assert 0 == 2", "this text is not in the output")
    repo = _repo(tmp_path, HEADER + row + "\n")
    before = _add_bytes(repo)
    r = _run(repo)
    assert r.returncode == 1
    assert "missing expect substring" in r.stderr
    assert _add_bytes(repo) == before


def test_failing_strip_command_restores_target(tmp_path):
    row = GOOD.replace(
        "bash tools/strip_ci_fixture/strip_to_wrong.sh",
        "bash tools/strip_ci_fixture/strip_to_wrong.sh && false",
    )
    repo = _repo(tmp_path, HEADER + row + "\n")
    before = _add_bytes(repo)
    r = _run(repo)
    assert r.returncode != 0
    assert _add_bytes(repo) == before


def test_strip_command_cannot_swallow_later_rows(tmp_path):
    # A strip command that reads stdin must not eat the rows after it.
    row = GOOD.replace(
        "bash tools/strip_ci_fixture/strip_to_wrong.sh",
        "bash tools/strip_ci_fixture/strip_to_wrong.sh; cat >/dev/null",
    )
    repo = _repo(tmp_path, HEADER + row + "\n" + NOOP + "\n")
    r = _run(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "expected red under strip for noop_strip" in r.stderr
