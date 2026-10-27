"""A directory git reads as a repository counts even with no .git part.

git takes a dir that holds HEAD, objects and refs as a repository when it walks
up from its working dir, and reads config from it. A config with core.bare
false, core.worktree and core.fsmonitor then runs a program on git status. So
C1 denies a path tool write of HEAD, of config beside HEAD, and of anything
under a gitdir shaped dir; a terminal call is not COVERED in or under a gitdir
shaped dir; and the plugin pins safe.bareRepository=explicit for the harness.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

import action_gating
from engine import COVERAGE_UNKNOWN_CONTROL, evaluate_tool_call, load_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog" / "Aegis-Atoms-v0.yaml"
SHELL_ATOM = f"atom:{action_gating.ATOM_SHELL_UNSANITIZED}"
PATH_ATOM = action_gating.ATOM_PATH_OUTSIDE
GIT_ROWS = ["git status", "git log --oneline -5", "git diff --stat"]


def _roots(tmp_path: Path) -> tuple[dict[str, str], list[str]]:
    env = {
        "HERMES_HOME": str(tmp_path / "h"),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "v"),
    }
    for v in env.values():
        Path(v).mkdir(parents=True, exist_ok=True)
    return env, [env["HERMES_HOME"], env["OBSIDIAN_VAULT_PATH"]]


_LAST_CALL: dict[str, object] = {}


def _eval(tmp_path: Path, tool: str, args, **kw):
    env, roots = _roots(tmp_path)
    _LAST_CALL.update(tool=tool, args=args, roots=kw.get("allowed_roots", roots))
    kw.setdefault("action_gating_enabled", True)
    kw.setdefault("allowed_roots", roots)
    kw.setdefault("plugin_mode", "enforce")
    catalog = load_catalog(CATALOG, env)
    return evaluate_tool_call(catalog, tool, args, env=env, **kw)


def _vault(tmp_path: Path) -> Path:
    return Path(_roots(tmp_path)[1][1])


def _config_text(worktree: Path, marker_cmd: str) -> str:
    return (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tbare = false\n"
        f"\tworktree = {worktree}\n"
        f"\tfsmonitor = {marker_cmd}\n"
    )


def _plant_on_disk(base: Path, marker_cmd: str = "/bin/false") -> Path:
    """Lay out the plant by hand, as a route other than a path tool would."""
    planted = base / "planted"
    wt = base / "planted-wt"
    (planted / "refs" / "heads").mkdir(parents=True, exist_ok=True)
    (planted / "objects").mkdir(parents=True, exist_ok=True)
    wt.mkdir(parents=True, exist_ok=True)
    (wt / "readme.txt").write_text("hi\n")
    (planted / "HEAD").write_text("ref: refs/heads/main\n")
    (planted / "config").write_text(_config_text(wt, marker_cmd))
    return planted


def _git_reasons() -> set[str]:
    """git_reason coords C1 gives the last _eval call."""
    firings, _rollups, _rank = action_gating.evaluate_action_gating(
        _LAST_CALL["tool"], _LAST_CALL["args"], allowed_roots=_LAST_CALL["roots"]
    )
    return {
        f.source_coordinates.get("git_reason")
        for f in firings
        if f.atom_id == PATH_ATOM
    } - {None}


def _assert_denied(r, reason: str | None = None):
    assert r.block_message is not None
    assert any(f.fired and f.atom_id == PATH_ATOM for f in r.firings)
    assert not r.box_ticket
    if reason is not None:
        assert _git_reasons() == {reason}


def _assert_not_covered(r):
    assert r.coverage == "UNKNOWN", r.coverage_sources
    assert SHELL_ATOM not in r.coverage_sources
    assert r.block_message is not None
    assert COVERAGE_UNKNOWN_CONTROL in r.block_message
    assert not r.box_ticket


# Adversary chain, through the gate.


def test_adversary_plant_write_of_head_is_denied(tmp_path):
    v = _vault(tmp_path)
    r = _eval(
        tmp_path,
        "write_file",
        {"path": str(v / "planted" / "HEAD"), "content": "ref: refs/heads/main\n"},
    )
    _assert_denied(r, "gitdir_head")


def test_adversary_plant_config_beside_head_is_denied(tmp_path):
    v = _vault(tmp_path)
    planted = v / "planted"
    planted.mkdir()
    (planted / "HEAD").write_text("ref: refs/heads/main\n")
    r = _eval(
        tmp_path,
        "write_file",
        {
            "path": str(planted / "config"),
            "content": _config_text(v / "planted-wt", "/tmp/m.sh"),
        },
    )
    _assert_denied(r, "gitdir_sibling")


@pytest.mark.parametrize("cmd", GIT_ROWS)
@pytest.mark.parametrize("form", ["command", "argv"])
@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_adversary_git_in_planted_workdir_is_not_covered(tmp_path, cmd, form, mode):
    planted = _plant_on_disk(_vault(tmp_path))
    args = {"command": cmd} if form == "command" else {"argv": cmd.split()}
    args["workdir"] = str(planted)
    r = _eval(tmp_path, "terminal", args, plugin_mode=mode)
    assert r.coverage == "UNKNOWN", r.coverage_sources
    assert not r.box_ticket
    if mode == "enforce":
        _assert_not_covered(r)


def test_adversary_full_chain_is_held_at_each_hop(tmp_path):
    """Write HEAD, config, refs, objects, a hook, then git status in planted."""
    v = _vault(tmp_path)
    planted = v / "planted"
    head = _eval(
        tmp_path,
        "write_file",
        {"path": str(planted / "HEAD"), "content": "ref: refs/heads/main\n"},
    )
    _assert_denied(head)
    # The plant lands anyway by some other route; every later hop still holds.
    _plant_on_disk(v)
    for rel in ("config", "hooks/pre-commit", "refs/heads/main", "objects/x"):
        r = _eval(tmp_path, "write_file", {"path": str(planted / rel), "content": "x"})
        _assert_denied(r)
    status = _eval(
        tmp_path, "terminal", {"command": "git status", "workdir": str(planted)}
    )
    _assert_not_covered(status)


# Write side.


@pytest.mark.parametrize("name", ["HEAD", "head", "Head", "HEAD.", "HEAD "])
@pytest.mark.parametrize("tool", ["write_file", "patch"])
def test_write_named_head_is_denied_anywhere_in_roots(tmp_path, name, tool):
    v = _vault(tmp_path)
    r = _eval(tmp_path, tool, {"path": str(v / "any" / "dir" / name), "content": "x"})
    _assert_denied(r, "gitdir_head")


def test_write_through_symlink_to_head_is_denied(tmp_path):
    v = _vault(tmp_path)
    (v / "d").mkdir()
    os.symlink(v / "d" / "HEAD", v / "alias")
    r = _eval(tmp_path, "write_file", {"path": str(v / "alias"), "content": "x"})
    _assert_denied(r, "gitdir_head")


@pytest.mark.parametrize(
    "name", ["config", "CONFIG", "config.", "commondir", "gitdir", "packed-refs"]
)
@pytest.mark.parametrize("layout", ["head", "objects_refs"])
def test_write_beside_gitdir_marker_is_denied(tmp_path, name, layout):
    d = _vault(tmp_path) / "repoish"
    d.mkdir()
    if layout == "head":
        (d / "HEAD").write_text("ref: refs/heads/main\n")
    else:
        (d / "objects").mkdir()
        (d / "refs").mkdir()
    r = _eval(tmp_path, "write_file", {"path": str(d / name), "content": "x"})
    _assert_denied(r, "gitdir_sibling")


@pytest.mark.parametrize(
    "rel", ["hooks/pre-commit", "info/attributes", "refs/heads/main", "a/b/c.txt"]
)
def test_write_under_gitdir_shaped_dir_is_denied(tmp_path, rel):
    planted = _plant_on_disk(_vault(tmp_path))
    r = _eval(tmp_path, "write_file", {"path": str(planted / rel), "content": "x"})
    _assert_denied(r, "gitdir_inside")


@pytest.mark.parametrize("rel", ["planted/config", "config", "x/packed-refs"])
def test_relative_config_name_is_denied(tmp_path, monkeypatch, rel):
    # cwd inside the roots, so only the git rule can fire on the relative path.
    monkeypatch.chdir(_vault(tmp_path))
    r = _eval(tmp_path, "write_file", {"path": rel, "content": "x"})
    _assert_denied(r, "gitdir_relative")


@pytest.mark.parametrize(
    "rel",
    [
        "git/config",
        "proj/config",
        "notes/head.md",
        "notes/HEADER.md",
        "proj/refs/x.md",
        "proj/objects/x.md",
    ],
)
def test_ordinary_writes_inside_roots_still_allowed(tmp_path, rel):
    v = _vault(tmp_path)
    r = _eval(tmp_path, "write_file", {"path": str(v / rel), "content": "x"})
    assert not any(f.fired and f.atom_id == PATH_ATOM for f in r.firings), rel
    assert r.block_message is None


def test_config_beside_only_objects_is_allowed(tmp_path):
    d = _vault(tmp_path) / "proj"
    (d / "objects").mkdir(parents=True)
    r = _eval(tmp_path, "write_file", {"path": str(d / "config"), "content": "x"})
    assert r.block_message is None


def test_read_of_planted_config_is_not_denied_by_the_git_rule(tmp_path):
    planted = _plant_on_disk(_vault(tmp_path))
    r = _eval(tmp_path, "read_file", {"path": str(planted / "config")})
    assert not any(f.fired and f.atom_id == PATH_ATOM for f in r.firings)


# V4A patch bodies name files in the patch, not in path.


@pytest.mark.parametrize("header", ["Add File", "Update File", "Move to"])
@pytest.mark.parametrize("target", ["planted/HEAD", "repo/.git/config"])
def test_v4a_patch_header_naming_git_control_is_denied(tmp_path, header, target):
    v = _vault(tmp_path)
    body = f"*** Begin Patch\n*** {header}: {v / target}\n+x\n*** End Patch\n"
    r = _eval(tmp_path, "patch", {"mode": "patch", "patch": body})
    _assert_denied(r, "gitdir_head" if target.endswith("HEAD") else "git_control")


def test_v4a_patch_of_ordinary_file_is_not_denied_by_the_git_rule(tmp_path):
    v = _vault(tmp_path)
    body = f"*** Begin Patch\n*** Add File: {v / 'notes.md'}\n+x\n*** End Patch\n"
    r = _eval(tmp_path, "patch", {"mode": "patch", "patch": body})
    assert _git_reasons() == set()
    # A V4A patch with no path is not bounded by any family, so it is held as
    # UNKNOWN; the git rule only adds a deny on top.
    assert r.coverage == "UNKNOWN"


# Workdir side.


@pytest.mark.parametrize(
    "rel", ["planted", "planted/refs", "planted/refs/heads", "planted/objects"]
)
@pytest.mark.parametrize("cmd", ["git status", "ls -la"])
def test_workdir_in_or_under_gitdir_shape_is_unknown(tmp_path, rel, cmd):
    v = _vault(tmp_path)
    _plant_on_disk(v)
    r = _eval(tmp_path, "terminal", {"command": cmd, "workdir": str(v / rel)})
    _assert_not_covered(r)


def test_workdir_with_partial_plant_head_and_config_is_unknown(tmp_path):
    d = _vault(tmp_path) / "partial"
    d.mkdir()
    (d / "HEAD").write_text("ref: refs/heads/main\n")
    (d / "config").write_text("[core]\n")
    r = _eval(tmp_path, "terminal", {"command": "git status", "workdir": str(d)})
    _assert_not_covered(r)


def test_workdir_symlink_into_gitdir_shape_is_unknown(tmp_path):
    v = _vault(tmp_path)
    planted = _plant_on_disk(v)
    os.symlink(planted, v / "innocent")
    r = _eval(
        tmp_path, "terminal", {"command": "git status", "workdir": str(v / "innocent")}
    )
    _assert_not_covered(r)


def test_workdir_symlink_to_a_dir_under_gitdir_shape_is_unknown(tmp_path):
    """git walks up from the real dir, so parents of the resolved path count."""
    v = _vault(tmp_path)
    planted = _plant_on_disk(v)
    os.symlink(planted / "refs" / "heads", v / "innocent")
    r = _eval(
        tmp_path, "terminal", {"command": "git status", "workdir": str(v / "innocent")}
    )
    _assert_not_covered(r)


def test_workdir_of_ordinary_repo_still_covers(tmp_path):
    v = _vault(tmp_path)
    git = v / ".git"
    (git / "objects").mkdir(parents=True)
    (git / "refs").mkdir()
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    (v / "src").mkdir()
    for wd in (v, v / "src"):
        r = _eval(tmp_path, "terminal", {"command": "git status", "workdir": str(wd)})
        assert r.coverage == "COVERED", r.coverage_sources
        assert "shell_table:git.status" in r.coverage_sources


def test_workdir_beside_lone_head_file_still_covers(tmp_path):
    d = _vault(tmp_path) / "docs"
    d.mkdir()
    (d / "HEAD").write_text("x\n")
    r = _eval(tmp_path, "terminal", {"command": "ls -la", "workdir": str(d)})
    assert r.coverage == "COVERED", r.coverage_sources


# Harness pin.


def test_pin_sets_safe_bare_repository_explicit():
    env: dict[str, str] = {}
    action_gating.pin_git_harness_env(env)
    assert env == {
        "GIT_CONFIG_COUNT": "4",
        "GIT_CONFIG_KEY_0": "safe.bareRepository",
        "GIT_CONFIG_VALUE_0": "explicit",
        "GIT_CONFIG_KEY_1": "core.fsmonitor",
        "GIT_CONFIG_VALUE_1": "false",
        "GIT_CONFIG_KEY_2": "core.hooksPath",
        "GIT_CONFIG_VALUE_2": "/dev/null",
        "GIT_CONFIG_KEY_3": "core.pager",
        "GIT_CONFIG_VALUE_3": "cat",
        "GIT_CONFIG_PARAMETERS": (
            "'safe.bareRepository'='explicit' 'core.fsmonitor'='false'"
            " 'core.hooksPath'='/dev/null' 'core.pager'='cat'"
        ),
    }
    assert action_gating.git_pin_effective(env)


def test_pin_keeps_existing_entries_and_is_idempotent():
    env = {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.pager",
        "GIT_CONFIG_VALUE_0": "cat",
    }
    action_gating.pin_git_harness_env(env)
    once = dict(env)
    action_gating.pin_git_harness_env(env)
    assert env == once
    # core.pager cat is already the last value, so it is not added again.
    assert env["GIT_CONFIG_COUNT"] == "4"
    assert env["GIT_CONFIG_KEY_0"] == "core.pager"
    assert env["GIT_CONFIG_KEY_1"] == "safe.bareRepository"
    assert env["GIT_CONFIG_VALUE_1"] == "explicit"


@pytest.mark.parametrize("value", ["all", "EXPLICIT", ""])
def test_pin_overrides_a_weaker_earlier_value(value):
    env = {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.bareRepository",
        "GIT_CONFIG_VALUE_0": value,
    }
    action_gating.pin_git_harness_env(env)
    assert env["GIT_CONFIG_COUNT"] == "5"
    assert env["GIT_CONFIG_VALUE_1"] == "explicit"


@pytest.mark.parametrize("count", ["x", "-3", ""])
def test_pin_with_bad_count_starts_at_zero(count):
    env = {"GIT_CONFIG_COUNT": count}
    action_gating.pin_git_harness_env(env)
    assert env["GIT_CONFIG_COUNT"] == "4"
    assert env["GIT_CONFIG_VALUE_0"] == "explicit"


def test_register_pins_the_host_env(monkeypatch, tmp_path):
    import importlib
    from types import SimpleNamespace

    atoms = importlib.import_module("__init__")
    for k in [k for k in os.environ if k.startswith("GIT_CONFIG_")]:
        monkeypatch.delenv(k)
    monkeypatch.setattr(atoms, "_assert_live_plugin_path", lambda: tmp_path)
    monkeypatch.setattr(atoms, "_write_load_heartbeat", lambda _root: None)
    atoms.register(SimpleNamespace(register_hook=lambda *a, **k: None))
    assert os.environ.get("GIT_CONFIG_COUNT") == "4"
    assert os.environ.get("GIT_CONFIG_KEY_0") == "safe.bareRepository"
    assert os.environ.get("GIT_CONFIG_VALUE_0") == "explicit"
    assert action_gating.git_pin_effective(os.environ)


def test_suite_runs_git_with_the_pin():
    assert os.environ.get("GIT_CONFIG_COUNT")
    n = int(os.environ["GIT_CONFIG_COUNT"])
    pairs = [
        (os.environ.get(f"GIT_CONFIG_KEY_{i}"), os.environ.get(f"GIT_CONFIG_VALUE_{i}"))
        for i in range(n)
    ]
    assert ("safe.bareRepository", "explicit") in pairs


# Live git: the pin makes the complete plant fail closed.


def _git_env(home: Path, *, pinned: bool) -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("GIT_") or k == "GIT_EXEC_PATH"
    }
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_NOSYSTEM="1")
    if pinned:
        action_gating.pin_git_harness_env(env)
    return env


def _live_plant(tmp_path: Path) -> tuple[Path, Path]:
    marker = tmp_path / "fsmonitor.ran"
    script = tmp_path / "fsmonitor.sh"
    script.write_text(f'#!/bin/sh\necho ran > "{marker}"\n')
    script.chmod(0o755)
    planted = _plant_on_disk(tmp_path / "live", str(script))
    return planted, marker


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_live_pinned_git_refuses_the_complete_plant(tmp_path):
    planted, marker = _live_plant(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    r = subprocess.run(
        ["git", "status"],
        cwd=planted,
        env=_git_env(home, pinned=True),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode != 0
    assert "safe.bareRepository" in r.stderr
    assert not marker.exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_live_unpinned_git_runs_the_plant_so_the_pin_matters(tmp_path):
    planted, marker = _live_plant(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    subprocess.run(
        ["git", "status"],
        cwd=planted,
        env=_git_env(home, pinned=False),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert marker.exists()
