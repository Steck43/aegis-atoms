"""git user config and shell init files in an in-root HOME are control.

Hermes runs the terminal with HOME at {HERMES_HOME}/home, inside the roots. A
write_file of HOME/.gitconfig with core.fsmonitor was COVERED with a ticket,
and a covered git status then ran the program. C1 now denies a path tool write
to .gitconfig, a .config/git config or attributes file, shell init files and
anything under .ssh, and the plugin pins core.fsmonitor, core.hooksPath and
core.pager in the git env, so a config file that lands by another route does
not run its program.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

import action_gating
from engine import evaluate_tool_call, load_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog" / "Aegis-Atoms-v0.yaml"
PATH_ATOM = action_gating.ATOM_PATH_OUTSIDE


def _roots(tmp_path: Path) -> tuple[dict[str, str], list[str]]:
    env = {
        "HERMES_HOME": str(tmp_path / "h"),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "v"),
    }
    for v in env.values():
        Path(v).mkdir(parents=True, exist_ok=True)
    return env, [env["HERMES_HOME"], env["OBSIDIAN_VAULT_PATH"]]


def _eval(tmp_path: Path, tool: str, args, mode: str = "enforce"):
    env, roots = _roots(tmp_path)
    catalog = load_catalog(CATALOG, env)
    return evaluate_tool_call(
        catalog,
        tool,
        args,
        env=env,
        action_gating_enabled=True,
        allowed_roots=roots,
        plugin_mode=mode,
    )


def _home(tmp_path: Path) -> Path:
    return tmp_path / "h" / "home"


def _fired(r) -> bool:
    return any(f.fired and f.atom_id == PATH_ATOM for f in r.firings)


_CFG = "[core]\n\tfsmonitor = /tmp/x.sh\n"

HOME_CONTROL = [
    ".gitconfig",
    ".GITCONFIG",
    ".gitconfig.",
    ".gitconfig ",
    ".config/git/config",
    ".config/git/attributes",
    ".config/GIT/Config",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".ssh/config",
    ".ssh/rc",
    ".ssh/authorized_keys",
    ".SSH./config",
]


@pytest.mark.parametrize("rel", HOME_CONTROL)
def test_write_to_home_control_is_denied(tmp_path, rel):
    r = _eval(
        tmp_path, "write_file", {"path": f"{_home(tmp_path)}/{rel}", "content": _CFG}
    )
    assert _fired(r), rel
    assert r.block_message, rel
    assert not r.box_ticket, rel


@pytest.mark.parametrize("rel", [".gitconfig", ".bashrc", ".config/git/config"])
def test_home_control_denied_anywhere_in_the_roots(tmp_path, rel):
    v = Path(_roots(tmp_path)[1][1])
    r = _eval(tmp_path, "write_file", {"path": f"{v}/sub/{rel}", "content": _CFG})
    assert _fired(r) and r.block_message and not r.box_ticket


def test_plain_patch_of_home_gitconfig_is_denied(tmp_path):
    args = {
        "path": f"{_home(tmp_path)}/.gitconfig",
        "old_string": "a",
        "new_string": "b",
    }
    r = _eval(tmp_path, "patch", args)
    assert _fired(r) and r.block_message and not r.box_ticket


@pytest.mark.parametrize(
    "header",
    ["*** Add File: {t}", "*** Update  File: {t}", "*** Move File: {v}/n.md -> {t}"],
)
def test_v4a_header_to_home_gitconfig_is_denied(tmp_path, header):
    v = Path(_roots(tmp_path)[1][1])
    target = f"{_home(tmp_path)}/.gitconfig"
    body = "*** Begin Patch\n" + header.format(t=target, v=v) + "\n+x\n*** End Patch\n"
    args = {"mode": "patch", "path": f"{v}/n.md", "patch": body}
    r = _eval(tmp_path, "patch", args)
    assert _fired(r) and r.block_message and not r.box_ticket


def test_link_in_roots_to_home_gitconfig_is_denied(tmp_path):
    _roots(tmp_path)
    _home(tmp_path).mkdir(parents=True)
    link = tmp_path / "v" / "notes.cfg"
    link.symlink_to(_home(tmp_path) / ".gitconfig")
    r = _eval(tmp_path, "write_file", {"path": str(link), "content": _CFG})
    assert _fired(r) and r.block_message and not r.box_ticket


def test_git_config_under_host_xdg_config_home_is_denied(tmp_path, monkeypatch):
    v = Path(_roots(tmp_path)[1][1])
    monkeypatch.setenv("XDG_CONFIG_HOME", str(v / "xdg"))
    r = _eval(tmp_path, "write_file", {"path": f"{v}/xdg/git/config", "content": _CFG})
    assert _fired(r) and r.block_message


@pytest.mark.parametrize(
    "rel",
    [
        "notes.md",
        "gitconfig-notes.md",
        ".gitattributes",
        ".gitignore",
        "git/config",
        "docs/.config/git/notes.md",
        "profile.md",
        ".bashrc.md",
        "ssh-notes.md",
    ],
)
def test_ordinary_writes_stay_allowed(tmp_path, rel):
    v = Path(_roots(tmp_path)[1][1])
    r = _eval(tmp_path, "write_file", {"path": f"{v}/{rel}", "content": "x"})
    assert not _fired(r), rel
    assert not r.block_message, rel


@pytest.mark.parametrize(
    "raw,reason",
    [
        ("/r/hh/.gitconfig", "home_git_config"),
        ("/r/hh/.bashrc", "shell_init"),
        ("/r/hh/.config/git/config", "xdg_git_config"),
        ("/r/hh/.ssh/config", "ssh_control"),
        ("/r/hh/a\x00b", "home_control_not_inspectable"),
        ("/r/hh/notes.md", None),
    ],
)
def test_home_control_reason_names_the_file_kind(raw, reason):
    assert action_gating.home_control_reason(raw) == reason


# Env pins: every key a config file could point at a program for, on the rows.


@pytest.mark.parametrize(
    "key,value",
    [
        ("safe.bareRepository", "explicit"),
        ("core.fsmonitor", "false"),
        ("core.hooksPath", "/dev/null"),
        ("core.pager", "cat"),
    ],
)
def test_pin_carries_each_key_in_count_and_parameters(key, value):
    env: dict[str, str] = {}
    action_gating.pin_git_harness_env(env)
    count = int(env["GIT_CONFIG_COUNT"])
    pairs = [
        (env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"]) for i in range(count)
    ]
    assert (key, value) in pairs
    assert f"'{key}'='{value}'" in env["GIT_CONFIG_PARAMETERS"]
    assert action_gating.git_pin_effective(env)


@pytest.mark.parametrize(
    "override",
    [
        "'core.fsmonitor'='/tmp/x.sh'",
        "'core.FSMonitor'='true'",
        "'core.hooksPath'='/tmp/hooks'",
        "'core.pager'='sh /tmp/x.sh'",
    ],
)
def test_later_override_of_any_pin_is_not_effective(override):
    env: dict[str, str] = {}
    action_gating.pin_git_harness_env(env)
    env["GIT_CONFIG_PARAMETERS"] += f" {override}"
    assert not action_gating.git_pin_effective(env)
    row, why = action_gating.shell_call_coverage({"command": "git status"}, environ=env)
    assert row is None and why == "git_pin_not_effective"
    action_gating.pin_git_harness_env(env)
    assert action_gating.git_pin_effective(env)


def test_safe_bare_only_env_is_not_effective():
    env = {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.bareRepository",
        "GIT_CONFIG_VALUE_0": "explicit",
    }
    assert not action_gating.git_pin_effective(env)


def test_unsplit_parameters_is_not_effective_with_every_count_pin():
    env: dict[str, str] = {}
    action_gating.pin_git_harness_env(env)
    env["GIT_CONFIG_PARAMETERS"] = "'unbalanced"
    assert not action_gating.git_pin_effective(env)


# Live git: a planted HOME/.gitconfig fsmonitor runs without the pin and not with it.


def _live(tmp_path: Path, *, pinned: bool) -> bool:
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    marker = tmp_path / "fsmonitor.ran"
    script = tmp_path / "fsmonitor.sh"
    home.mkdir()
    script.write_text(f'#!/bin/sh\necho ran > "{marker}"\nexit 1\n')
    script.chmod(0o755)
    (home / ".gitconfig").write_text(
        f"[core]\n\tfsmonitor = {script}\n\thooksPath = {tmp_path}/hooks\n"
    )
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("GIT_") or k == "GIT_EXEC_PATH"
    }
    env.pop("XDG_CONFIG_HOME", None)
    env.update(HOME=str(home), GIT_CONFIG_NOSYSTEM="1")
    if pinned:
        action_gating.pin_git_harness_env(env)
    subprocess.run(["git", "init", "-q", str(repo)], env=env, check=True)
    (repo / "f.txt").write_text("x")
    subprocess.run(["git", "status"], cwd=repo, env=env, capture_output=True)
    return marker.exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_live_home_gitconfig_fsmonitor_runs_without_pin(tmp_path):
    assert _live(tmp_path, pinned=False)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_live_home_gitconfig_fsmonitor_does_not_run_with_pin(tmp_path):
    assert not _live(tmp_path, pinned=True)
