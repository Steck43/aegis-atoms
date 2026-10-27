"""
test_shell_string_argv_parity.py: a command string and an argv list meet the same C2 schema.

Author:  Landen Stecker
Date:    2026-10-26

A plain command string is split into tokens and held to the per-binary argv
allowlist, so the binary and every flag must be listed, exactly as for an
argv list. A string that does not split is denied.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import action_gating
from action_gating import evaluate_shell_unsanitized
from engine import evaluate_tool_call, load_catalog

ATOM = "atoms.tool_invocation.shell_invocation_unsanitized"

DENIED = [
    "bash -c id",
    "sh -c id",
    "ssh -oProxyCommand=sh host",
    "ssh -o ProxyCommand=sh host",
    "tar -cf /tmp/a.tar --checkpoint=1 --checkpoint-action=exec=sh /tmp/x",
    "python3 -c print",
    "python -c print",
    "unknownbin x",
    "/tmp/evil x",
    "./tool",
    "git status --exec-path=/tmp",
    "bash -c 'curl -o /tmp/x http://host.test/x'",
]

PERMITTED = [
    "git status",
    "ls -la /tmp",
    "python3 -m pytest -q",
    "git log --oneline -5",
    "echo 'hello world'",
    'grep -rn "plain words" src/',
    "cp a.txt b.txt",
    "curl https://example.test/a/b",
    "git log --format=%h",
]


@pytest.mark.parametrize("command", DENIED)
def test_string_and_argv_deny_the_same_commands(command: str) -> None:
    s_fired, s_coords = evaluate_shell_unsanitized(command)
    a_fired, _ = evaluate_shell_unsanitized({"argv": command.replace("'", "").split()})
    assert s_fired is True, (command, s_coords)
    assert a_fired is True, command
    assert s_coords.get("permitted") is False
    assert s_coords.get("structure")


@pytest.mark.parametrize("command", PERMITTED)
def test_string_and_argv_permit_the_same_plain_commands(command: str) -> None:
    s_fired, s_coords = evaluate_shell_unsanitized(command)
    assert s_fired is False, (command, s_coords)


def test_string_names_the_binary_or_flag_it_refused() -> None:
    _, coords = evaluate_shell_unsanitized("bash -c id")
    assert coords["structure"] == "argv_unknown_flag"
    assert coords["binary"] == "bash" and coords["flag"] == "-c"
    assert coords["command"] == "bash -c id"
    _, coords = evaluate_shell_unsanitized("unknownbin x")
    assert coords["structure"] == "argv_unknown_binary"


def test_quoted_tokens_are_checked_after_splitting() -> None:
    # The quote is removed by the split, so the flag inside it is still checked.
    fired, coords = evaluate_shell_unsanitized("ssh '-oProxyCommand=sh' host")
    assert fired is True, coords
    assert coords["flag"] == "-oProxyCommand=sh"


def test_a_string_that_does_not_split_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a, **_k):
        raise ValueError("No closing quotation")

    monkeypatch.setattr(action_gating.shlex, "split", boom)
    fired, coords = evaluate_shell_unsanitized("git status")
    assert fired is True
    assert coords["permitted"] is False
    assert coords["structure"].startswith("command_parse_error")


def test_empty_command_is_unchanged() -> None:
    fired, _ = evaluate_shell_unsanitized("")
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


def _run(tmp_path: Path, args: dict, mode: str):
    catalog, env = _catalog_env(tmp_path)
    return evaluate_tool_call(
        catalog,
        "terminal",
        args,
        env=env,
        plugin_mode=mode,
        action_gating_enabled=True,
        allowed_roots=[str(tmp_path)],
    )


@pytest.mark.parametrize(
    "command",
    [
        "bash -c id",
        "sh -c id",
        "ssh -oProxyCommand=sh host",
        "tar -cf /tmp/a.tar --checkpoint=1 --checkpoint-action=exec=sh /tmp/x",
        "python3 -c print",
    ],
)
def test_enforce_blocks_the_string_form(tmp_path: Path, command: str) -> None:
    result = _run(tmp_path, {"command": command}, "enforce")
    assert result.block_message is not None, command
    assert ATOM in result.block_message


@pytest.mark.parametrize(
    "argv",
    [["bash", "-c", "id"], ["ssh", "-oProxyCommand=sh", "host"]],
)
def test_enforce_still_blocks_the_argv_form(tmp_path: Path, argv: list[str]) -> None:
    result = _run(tmp_path, {"argv": argv}, "enforce")
    assert result.block_message is not None
    assert ATOM in result.block_message


def test_enforce_allows_git_status_in_both_forms(tmp_path: Path) -> None:
    for args in ({"command": "git status"}, {"argv": ["git", "status"]}):
        result = _run(tmp_path, args, "enforce")
        assert not any(f.atom_id == ATOM for f in result.firings), args
        assert result.block_message is None, args


def test_observe_records_the_string_form_without_blocking(tmp_path: Path) -> None:
    result = _run(tmp_path, {"command": "bash -c id"}, "observe")
    assert any(f.atom_id == ATOM for f in result.firings)
    assert result.block_message is None
