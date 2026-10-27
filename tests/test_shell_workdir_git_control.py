"""A covered shell row needs a bounded working dir and no reach into .git.

A git row bounds the argv, not the repo it runs in. git status in a repo whose
config sets core.fsmonitor runs that program, so a row is COVERED only when the
working dir is absent or resolves inside allowed_roots, no positional or working
dir names a .git part, and path tool writes into .git are denied by C1.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path

import pytest

import action_gating
from engine import COVERAGE_UNKNOWN_CONTROL, evaluate_tool_call, load_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog" / "Aegis-Atoms-v0.yaml"
SHELL_ATOM = f"atom:{action_gating.ATOM_SHELL_UNSANITIZED}"
PATH_ATOM = action_gating.ATOM_PATH_OUTSIDE


def _roots(tmp_path: Path) -> tuple[dict[str, str], list[str]]:
    env = {
        "HERMES_HOME": str(tmp_path / "h"),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "v"),
    }
    for v in env.values():
        Path(v).mkdir(parents=True, exist_ok=True)
    return env, [env["HERMES_HOME"], env["OBSIDIAN_VAULT_PATH"]]


def _eval(tmp_path: Path, tool: str, args, **kw):
    env, roots = _roots(tmp_path)
    kw.setdefault("action_gating_enabled", True)
    kw.setdefault("allowed_roots", roots)
    kw.setdefault("plugin_mode", "enforce")
    catalog = load_catalog(CATALOG, env)
    return evaluate_tool_call(catalog, tool, args, env=env, **kw)


def _assert_not_covered(r):
    assert r.coverage == "UNKNOWN", r.coverage_sources
    assert SHELL_ATOM not in r.coverage_sources
    assert r.block_message is not None
    assert COVERAGE_UNKNOWN_CONTROL in r.block_message
    assert not r.box_ticket


def _outside_dirs(tmp_path: Path) -> list[str]:
    evil = tmp_path / "evilrepo"
    (evil / ".git").mkdir(parents=True, exist_ok=True)
    link = tmp_path / "h" / "link_out"
    link.parent.mkdir(parents=True, exist_ok=True)
    if not link.exists():
        os.symlink(evil, link)
    return [
        str(evil),
        "/root",
        "/tmp",
        "/",
        str(tmp_path / "h" / ".." / "evilrepo"),
        str(link),
        str(tmp_path / "hh"),
    ]


@pytest.mark.parametrize("cmd", ["git status", "ls -la", "git log --oneline -5"])
@pytest.mark.parametrize("form", ["command", "argv"])
def test_workdir_outside_roots_is_unknown(tmp_path, cmd, form):
    for wd in _outside_dirs(tmp_path):
        surface = {"command": cmd} if form == "command" else {"argv": shlex.split(cmd)}
        r = _eval(tmp_path, "terminal", {**surface, "workdir": wd})
        _assert_not_covered(r)


@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_workdir_outside_roots_gets_no_ticket_in_either_mode(tmp_path, mode):
    r = _eval(
        tmp_path,
        "terminal",
        {"command": "git status", "workdir": str(tmp_path / "evilrepo")},
        plugin_mode=mode,
    )
    assert r.coverage == "UNKNOWN"
    assert not r.box_ticket
    assert r.coverage_record()["final_effect"] != "allow"


@pytest.mark.parametrize(
    "wd",
    [".", "src", "./h", "~", "~/h", "", "   ", None, 42, ["/tmp"], "h/../h"],
)
def test_workdir_not_absolute_or_not_str_is_unknown(tmp_path, wd):
    r = _eval(tmp_path, "terminal", {"command": "git status", "workdir": wd})
    _assert_not_covered(r)


def test_workdir_without_roots_is_unknown():
    f = action_gating.shell_call_coverage
    assert f({"command": "ls", "workdir": "/tmp"}) == (None, "workdir_no_roots")
    assert f({"command": "ls", "workdir": "/tmp"}, allowed_roots=[]) == (
        None,
        "workdir_no_roots",
    )


@pytest.mark.parametrize("sub", ["", "src", "src/deep"])
@pytest.mark.parametrize("cmd,row", [("git status", "git.status"), ("ls -la", "ls")])
def test_workdir_inside_roots_covers(tmp_path, sub, cmd, row):
    env, roots = _roots(tmp_path)
    wd = Path(roots[0], sub) if sub else Path(roots[0])
    wd.mkdir(parents=True, exist_ok=True)
    r = _eval(tmp_path, "terminal", {"command": cmd, "workdir": str(wd)})
    assert r.coverage == "COVERED", r.coverage_sources
    assert f"shell_table:{row}" in r.coverage_sources
    assert r.block_message is None
    assert r.box_ticket


def test_workdir_absent_still_covers(tmp_path):
    r = _eval(tmp_path, "terminal", {"command": "git status"})
    assert r.coverage == "COVERED"
    assert r.box_ticket


@pytest.mark.parametrize(
    "rel", [".git", ".git/hooks", "a/.git", ".GIT", ".git.", ".Git/hooks"]
)
def test_workdir_inside_git_dir_is_unknown(tmp_path, rel):
    _env, roots = _roots(tmp_path)
    wd = Path(roots[0], rel)
    r = _eval(tmp_path, "terminal", {"command": "git status", "workdir": str(wd)})
    _assert_not_covered(r)


@pytest.mark.parametrize(
    "cmd",
    [
        "ls .git",
        "ls .git/hooks",
        "ls -la .git/config",
        "ls a/.git/hooks",
        "ls .GIT/hooks",
        "git status .git/config",
        "git log .git",
        "git diff --stat .git/config",
    ],
)
@pytest.mark.parametrize("form", ["command", "argv"])
def test_positional_naming_git_dir_is_unknown(tmp_path, cmd, form):
    surface = {"command": cmd} if form == "command" else {"argv": shlex.split(cmd)}
    r = _eval(tmp_path, "terminal", surface)
    assert r.coverage == "UNKNOWN", (cmd, r.coverage_sources)
    assert not r.box_ticket


@pytest.mark.parametrize(
    "rel",
    [
        ".git/config",
        ".git/config.worktree",
        ".git/hooks/pre-commit",
        ".git/hooks/fsmonitor-watchman",
        ".git/info/attributes",
        ".git",
        "sub/.git",
        "sub/.git/config",
        ".GIT/config",
        ".Git/Hooks/post-checkout",
        ".git./config",
        ".git /config",
        "a/../.git/config",
    ],
)
@pytest.mark.parametrize("tool", ["write_file", "patch"])
def test_c1_denies_writes_into_git_inside_roots(tmp_path, rel, tool):
    _env, roots = _roots(tmp_path)
    path = f"{roots[0]}/{rel}"
    r = _eval(tmp_path, tool, {"path": path, "content": "[core]\n"})
    assert r.block_message is not None, (tool, rel)
    assert any(f.fired and f.atom_id == PATH_ATOM for f in r.firings), r.firings
    assert not r.box_ticket


def test_c1_denies_write_through_symlink_into_git(tmp_path):
    _env, roots = _roots(tmp_path)
    repo = Path(roots[0], "repo")
    (repo / ".git").mkdir(parents=True)
    alias = Path(roots[0], "cfg")
    os.symlink(repo / ".git" / "config", alias)
    r = _eval(tmp_path, "write_file", {"path": str(alias), "content": "x"})
    assert r.block_message is not None
    assert any(f.fired and f.atom_id == PATH_ATOM for f in r.firings)


@pytest.mark.parametrize(
    "rel", ["notes.md", "src/x.py", ".gitignore", ".github/x.yml", "git/config"]
)
def test_c1_allows_ordinary_writes_inside_roots(tmp_path, rel):
    _env, roots = _roots(tmp_path)
    r = _eval(tmp_path, "write_file", {"path": f"{roots[0]}/{rel}", "content": "x"})
    assert not any(f.fired and f.atom_id == PATH_ATOM for f in r.firings), rel
    assert r.block_message is None


def test_c1_reads_of_git_are_not_denied_by_the_git_rule(tmp_path):
    _env, roots = _roots(tmp_path)
    r = _eval(tmp_path, "read_file", {"path": f"{roots[0]}/.git/config"})
    assert not any(f.fired and f.atom_id == PATH_ATOM for f in r.firings)


def test_planted_fsmonitor_chain_is_held(tmp_path):
    """The BH-W1 chain: plant config, then git status. Each hop is held."""
    _env, roots = _roots(tmp_path)
    repo = Path(roots[0], "repo")
    plant = _eval(
        tmp_path,
        "write_file",
        {"path": str(repo / ".git" / "config"), "content": "[core]\nfsmonitor=x\n"},
    )
    assert plant.block_message is not None
    hook = _eval(
        tmp_path,
        "write_file",
        {"path": str(repo / ".git" / "hooks" / "pre-commit"), "content": "id\n"},
    )
    assert hook.block_message is not None
    outside = _eval(
        tmp_path,
        "terminal",
        {"command": "git status", "workdir": str(tmp_path / "evilrepo")},
    )
    _assert_not_covered(outside)
