"""A V4A patch is read with the header grammar Hermes applies.

Hermes tools/patch_parser.py takes any whitespace run after the stars and
between the words, and Move File names a source and a destination. The atoms
read the same headers, run full C1 on every file a body names, read an
unparsed *** line as UNKNOWN, judge a gitdir plant across every file in one
patch, and keep the safe.bareRepository pin when the host env tries to undo it.
"""

from __future__ import annotations

import os
import random
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import action_gating
from engine import COVERAGE_UNKNOWN_CONTROL, evaluate_tool_call, load_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog" / "Aegis-Atoms-v0.yaml"
PATH_ATOM = action_gating.ATOM_PATH_OUTSIDE
SHELL_ATOM = f"atom:{action_gating.ATOM_SHELL_UNSANITIZED}"

# The Hermes reference grammar, copied from tools/patch_parser.py.
HERMES = {
    "update": re.compile(r"\*\*\*\s*Update\s+File:\s*(.+)"),
    "add": re.compile(r"\*\*\*\s*Add\s+File:\s*(.+)"),
    "delete": re.compile(r"\*\*\*\s*Delete\s+File:\s*(.+)"),
    "move": re.compile(r"\*\*\*\s*Move\s+File:\s*(.+?)\s*->\s*(.+)"),
}


def _setup(tmp_path: Path):
    env = {
        "HERMES_HOME": str(tmp_path / "h"),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "v"),
    }
    for v in env.values():
        Path(v).mkdir(parents=True, exist_ok=True)
    h = Path(env["HERMES_HOME"])
    (h / "repo" / ".git" / "hooks").mkdir(parents=True, exist_ok=True)
    (h / "repo" / ".git" / "config").write_text("[core]\n")
    (h / "plain").mkdir(exist_ok=True)
    return env, list(env.values()), h


def _eval(tmp_path: Path, tool: str, args, **kw):
    env, roots, _h = _setup(tmp_path)
    kw.setdefault("action_gating_enabled", True)
    kw.setdefault("allowed_roots", roots)
    kw.setdefault("plugin_mode", "enforce")
    return evaluate_tool_call(load_catalog(CATALOG, env), tool, args, env=env, **kw)


def _held(r):
    assert r.block_message is not None, r.coverage_sources
    assert not r.box_ticket


def _denied(r):
    _held(r)
    assert any(f.fired and f.atom_id == PATH_ATOM for f in r.firings)


def _patch(h: Path, body: str) -> dict:
    return {"mode": "patch", "path": str(h / "plain" / "ok.md"), "patch": body}


def _wrap(*lines: str) -> str:
    return "*** Begin Patch\n" + "\n".join(lines) + "\n*** End Patch\n"


HEADER_FORMS = [
    "*** Update  File: {t}\n@@\n [core]\n+x",
    "*** Update\tFile: {t}\n@@\n [core]\n+x",
    "***Update File: {t}\n@@\n [core]\n+x",
    "*** Add\tFile: {t}\n+x",
    "*** Add   File:{t}\n+x",
    "*** Delete   File: {t}",
    "*** Move File: {src} -> {t}",
    "*** Move\tFile:{src}->{t}",
    "*** Move File: {t} -> {src2}",
    "*** Move to: {t}",
]


@pytest.mark.parametrize("form", HEADER_FORMS)
@pytest.mark.parametrize(
    "target", ["dotgit_config", "dotgit_hook", "plant_head", "outside"]
)
def test_hermes_header_forms_with_decoy_path_are_denied(tmp_path, form, target):
    _env, _roots, h = _setup(tmp_path)
    t = {
        "dotgit_config": h / "repo" / ".git" / "config",
        "dotgit_hook": h / "repo" / ".git" / "hooks" / "post-checkout",
        "plant_head": h / "plant" / "HEAD",
        "outside": tmp_path / "outside" / "note.txt",
    }[target]
    line = form.format(t=t, src=h / "plain" / "h.txt", src2=h / "plain" / "h2.txt")
    body = _wrap(f"*** Add File: {h / 'plain' / 'h.txt'}\n+x", line)
    _denied(_eval(tmp_path, "patch", _patch(h, body)))


@pytest.mark.parametrize("crlf", [False, True])
def test_bad_header_after_clean_headers_is_denied(tmp_path, crlf):
    _env, _roots, h = _setup(tmp_path)
    body = _wrap(
        f"*** Add File: {h / 'plain' / 'a.md'}\n+a",
        f"*** Update File: {h / 'plain' / 'b.md'}\n@@\n b\n+c",
        f"*** Update  File: {h / 'repo' / '.git' / 'config'}\n@@\n [core]\n+x",
    )
    if crlf:
        body = body.replace("\n", "\r\n")
    _denied(_eval(tmp_path, "patch", _patch(h, body)))


def test_move_source_outside_roots_is_denied(tmp_path):
    _env, _roots, h = _setup(tmp_path)
    body = _wrap(f"*** Move File: {tmp_path / 'outside' / 'x'} -> {h / 'plain' / 'x'}")
    _denied(_eval(tmp_path, "patch", _patch(h, body)))


@pytest.mark.parametrize(
    "line",
    [
        "*** Rename File: a.md -> b.md",
        "*** Update Files: a.md",
        "*** Copy File: a.md",
        "*** Add File:   ",
        "*** Move File: a.md",
        "***",
    ],
)
@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_unparsed_star_line_is_unknown_even_with_path(tmp_path, line, mode):
    _env, _roots, h = _setup(tmp_path)
    body = _wrap(f"*** Add File: {h / 'plain' / 'a.md'}\n+a", line)
    r = _eval(tmp_path, "patch", _patch(h, body), plugin_mode=mode)
    assert r.coverage == "UNKNOWN", r.coverage_sources
    assert not r.box_ticket
    if mode == "enforce":
        assert r.block_message is not None
        assert COVERAGE_UNKNOWN_CONTROL in r.block_message


@pytest.mark.parametrize("body", [None, 7, "", "just text\n"])
def test_v4a_call_with_no_readable_header_is_unknown(tmp_path, body):
    _env, _roots, h = _setup(tmp_path)
    args = {"mode": "patch", "path": str(h / "plain" / "ok.md")}
    if body is not None:
        args["patch"] = body
    r = _eval(tmp_path, "patch", args)
    assert r.coverage == "UNKNOWN"
    _held(r)


def test_clean_in_root_v4a_patch_still_covers(tmp_path):
    _env, _roots, h = _setup(tmp_path)
    (h / "plain" / "b.md").write_text("b\n")
    body = _wrap(
        f"*** Add File: {h / 'plain' / 'a.md'}\n+a",
        f"*** Update File: {h / 'plain' / 'b.md'}\n@@\n b\n+c",
        f"*** Move File: {h / 'plain' / 'a.md'} -> {h / 'plain' / 'c.md'}",
        f"*** Delete File: {h / 'plain' / 'old.md'}",
    )
    r = _eval(tmp_path, "patch", _patch(h, body))
    assert r.coverage == "COVERED", r.coverage_sources
    assert r.block_message is None


def test_content_lines_that_quote_headers_do_not_count(tmp_path):
    _env, _roots, h = _setup(tmp_path)
    body = _wrap(
        f"*** Add File: {h / 'plain' / 'doc.md'}",
        f"+*** Update File: {h / 'repo' / '.git' / 'config'}",
        " *** End Patch",
    )
    r = _eval(tmp_path, "patch", _patch(h, body))
    assert r.coverage == "COVERED", r.coverage_sources
    assert r.block_message is None


# One patch that lays out a whole plant, into a dir that is empty at decide time.


def test_one_patch_full_plant_is_denied(tmp_path):
    _env, _roots, h = _setup(tmp_path)
    p = h / "plant"
    body = _wrap(
        f"*** Add File: {p}/objects/keep\n+",
        f"*** Add File: {p}/refs/heads/keep\n+",
        f"*** Add File: {p}/config\n+[core]\n+\tbare = false",
        f"*** Add File: {h}/plain/tmp.txt\n+ref: refs/heads/main",
        f"*** Move File: {h}/plain/tmp.txt -> {p}/HEAD",
    )
    _denied(_eval(tmp_path, "patch", _patch(h, body)))


@pytest.mark.parametrize(
    "name", ["config", "commondir", "packed-refs", "config.worktree"]
)
def test_one_patch_objects_refs_and_sibling_is_denied(tmp_path, name):
    _env, _roots, h = _setup(tmp_path)
    p = h / "plant"
    body = _wrap(
        f"*** Add File: {p}/objects/keep\n+",
        f"*** Add File: {p}/refs/heads/keep\n+",
        f"*** Add File: {p}/{name}\n+x",
    )
    _denied(_eval(tmp_path, "patch", _patch(h, body)))
    reasons = {
        f.source_coordinates.get("git_reason")
        for f in action_gating.evaluate_action_gating(
            "patch", _patch(h, body), allowed_roots=_roots
        )[0]
    }
    assert "gitdir_sibling" in reasons


def test_one_patch_objects_and_refs_alone_still_allowed(tmp_path):
    _env, _roots, h = _setup(tmp_path)
    p = h / "proj"
    body = _wrap(
        f"*** Add File: {p}/objects/a.md\n+", f"*** Add File: {p}/refs/b.md\n+"
    )
    assert _eval(tmp_path, "patch", _patch(h, body)).block_message is None


def test_head_and_commondir_dir_is_gitdir_shaped(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "HEAD").write_text("ref: refs/heads/main\n")
    assert not action_gating.is_gitdir_shaped(d)
    (d / "commondir").write_text("../x\n")
    assert action_gating.is_gitdir_shaped(d)


def test_config_worktree_beside_lone_head_is_denied(tmp_path):
    _env, roots, h = _setup(tmp_path)
    d = h / "lone"
    d.mkdir()
    (d / "HEAD").write_text("ref: refs/heads/main\n")
    r = _eval(
        tmp_path, "write_file", {"path": str(d / "config.worktree"), "content": "x"}
    )
    _denied(r)


# Parity fuzz: every file the Hermes grammar names, the atoms name too.


def _hermes_paths(body: str) -> list[str]:
    out: list[str] = []
    for raw in body.split("\n"):
        line = raw[:-1] if raw.endswith("\r") else raw
        for kind, rx in HERMES.items():
            m = rx.match(line)
            if m:
                out.extend(g.strip() for g in m.groups())
                break
    return out


def test_fuzz_atoms_read_every_file_hermes_reads():
    rng = random.Random(20261026)
    ws = [" ", "  ", "\t", " \t ", ""]
    for _ in range(3000):
        lines = []
        for _ in range(rng.randint(1, 5)):
            a, b = rng.choice(ws), rng.choice(ws[:-1])
            kind = rng.choice(["Update", "Add", "Delete", "Move"])
            p1 = f"/r/{rng.randint(0, 99)}/f"
            if kind == "Move":
                lines.append(
                    f"***{a}Move{b}File:{rng.choice(ws)}{p1}{rng.choice(ws)}->{rng.choice(ws)}/r/x"
                )
            else:
                lines.append(
                    f"***{a}{kind}{b}File:{rng.choice(ws)}{p1}{rng.choice(ws)}"
                )
            lines.append("+x")
        body = "\n".join(lines)
        if rng.random() < 0.3:
            body = body.replace("\n", "\r\n")
        want = _hermes_paths(body)
        got = action_gating.parse_v4a_headers(body)
        assert set(want) <= set(got.paths), body
        assert not got.unparsed, body


# Pin against a host env that tries to undo it.


def test_pin_wins_over_host_parameters_all():
    env = {"GIT_CONFIG_PARAMETERS": "'safe.bareRepository'='all'"}
    assert not action_gating.git_pin_effective(env)
    action_gating.pin_git_harness_env(env)
    assert env["GIT_CONFIG_PARAMETERS"].endswith("'safe.bareRepository'='explicit'")
    assert action_gating.git_pin_effective(env)
    action_gating.pin_git_harness_env(env)
    assert env["GIT_CONFIG_PARAMETERS"].count("explicit") == 1


@pytest.mark.parametrize(
    "env",
    [
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.bareRepository",
            "GIT_CONFIG_VALUE_0": "explicit",
            "GIT_CONFIG_PARAMETERS": "'safe.bareRepository'='all'",
        },
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.bareRepository",
            "GIT_CONFIG_VALUE_0": "explicit",
            "GIT_CONFIG_PARAMETERS": "'safe.barerepository=all'",
        },
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.bareRepository",
            "GIT_CONFIG_VALUE_0": "explicit",
            "GIT_CONFIG_PARAMETERS": "'unbalanced",
        },
        {"GIT_CONFIG_COUNT": "0"},
        {},
    ],
)
def test_git_row_not_covered_when_pin_not_effective(tmp_path, env):
    _e, roots, h = _setup(tmp_path)
    row, why = action_gating.shell_call_coverage(
        {"command": "git status", "workdir": str(h)}, allowed_roots=roots, environ=env
    )
    assert row is None and why == "git_pin_not_effective"
    row, _ = action_gating.shell_call_coverage(
        {"command": "ls -la", "workdir": str(h)}, allowed_roots=roots, environ=env
    )
    assert row is not None


def test_git_row_held_through_the_gate_when_host_env_overrides_pin(
    tmp_path, monkeypatch
):
    _e, _roots, h = _setup(tmp_path)
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'safe.bareRepository'='all'")
    r = _eval(tmp_path, "terminal", {"command": "git status", "workdir": str(h)})
    assert r.coverage == "UNKNOWN"
    assert SHELL_ATOM not in r.coverage_sources
    _held(r)
    r = _eval(tmp_path, "terminal", {"command": "git status"})
    assert r.coverage == "UNKNOWN"
    _held(r)


def _live_plant(tmp_path: Path) -> Path:
    p = tmp_path / "plant"
    (p / "objects").mkdir(parents=True)
    (p / "refs" / "heads").mkdir(parents=True)
    (p / "HEAD").write_text("ref: refs/heads/main\n")
    (p / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
        f"\tworktree = {tmp_path}\n[rta]\n\tmarker = benign\n"
    )
    return p


def _base_env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_NOSYSTEM="1")
    return env


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
@pytest.mark.parametrize("child", ["host_params_all", "child_count_reset"])
def test_live_pinned_git_refuses_plant_against_env_overrides(tmp_path, child):
    p = _live_plant(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    env = _base_env(home)
    if child == "host_params_all":
        env["GIT_CONFIG_PARAMETERS"] = "'safe.bareRepository'='all'"
    action_gating.pin_git_harness_env(env)
    if child == "child_count_reset":
        env["GIT_CONFIG_COUNT"] = "0"
    r = subprocess.run(
        ["git", "config", "rta.marker"],
        cwd=p,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "benign" not in r.stdout
    assert r.returncode != 0


@pytest.mark.parametrize(
    "form", ["*** Update  File: {t}\n@@\n a\n+b", "*** Move File: {s} -> {t}"]
)
def test_resource_atom_reads_v4a_header_paths(tmp_path, form):
    _env, _roots, h = _setup(tmp_path)
    body = _wrap(form.format(t=h / ".env", s=h / "plain" / "x"))
    r = _eval(tmp_path, "patch", _patch(h, body))
    _held(r)
    assert any(
        f.fired and f.atom_id == "atom.resource.write_hermes_secrets" for f in r.firings
    )


def test_clean_v4a_with_no_path_arg_stays_unknown(tmp_path):
    _env, _roots, h = _setup(tmp_path)
    body = _wrap(f"*** Add File: {h / 'plain' / 'a.md'}\n+a")
    r = _eval(tmp_path, "patch", {"mode": "patch", "patch": body})
    assert r.coverage == "UNKNOWN"
    _held(r)


def test_move_destination_counts_toward_the_plant_shape(tmp_path):
    _env, _roots, h = _setup(tmp_path)
    p = h / "plant"
    (h / "plain" / "a").write_text("x\n")
    body = _wrap(
        f"*** Move File: {h / 'plain' / 'a'} -> {p}/objects/keep",
        f"*** Add File: {p}/refs/keep\n+",
        f"*** Add File: {p}/config\n+x",
    )
    _denied(_eval(tmp_path, "patch", _patch(h, body)))


def test_clean_crlf_v4a_patch_still_covers(tmp_path):
    _env, _roots, h = _setup(tmp_path)
    body = _wrap(f"*** Add File: {h / 'plain' / 'a.md'}\n+a").replace("\n", "\r\n")
    r = _eval(tmp_path, "patch", _patch(h, body))
    assert r.coverage == "COVERED", r.coverage_sources
    assert r.block_message is None
