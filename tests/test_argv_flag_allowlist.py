"""
test_argv_flag_allowlist.py: C2 argv is a per-binary flag allowlist.

Author:  Landen Stecker
Date:    2026-10-09

Joining argv tokens and scanning for shell punctuation missed flag-shaped
escapes. The detector now allows only bare basenames on a closed map, and
only the flags listed for that binary. Unknown binary, path-form binary,
unknown flag, or shell punctuation inside a token means deny.
"""

from __future__ import annotations

import pytest

from action_gating import evaluate_shell_unsanitized


@pytest.mark.parametrize(
    "argv",
    [
        ["tar", "--checkpoint-action=exec=id"],
        ["ssh", "-oProxyCommand=bash"],
        ["ssh", "-o", "ProxyCommand=bash"],
        ["bash", "-c", "id"],
        ["sh", "-c", "id"],
        ["python", "-c", "print(1)"],
        ["python3", "-c", "print(1)"],
        ["/tmp/evil", "x"],
        ["./tool"],
        ["C:\\Windows\\evil.exe", "x"],
        ["unknownbin", "x"],
        ["cat", "a;rm"],
        ["echo", "$(id)"],
        ["ls", "<(id)"],
    ],
)
def test_argv_denies_flag_escapes_and_off_list_binaries(argv: list[str]) -> None:
    fired, coords = evaluate_shell_unsanitized({"argv": argv})
    assert fired is True, (argv, coords)
    assert coords.get("permitted") is False


@pytest.mark.parametrize(
    "argv",
    [
        ["git", "log", "--oneline", "-5"],
        ["cat", "/allowed/readme.md"],
        ["ls", "-la"],
        ["python3", "-m", "pytest", "-q"],
        ["tar", "-tzf", "archive.tar.gz"],
        ["ssh", "-p", "22", "host"],
    ],
)
def test_argv_allows_listed_binaries_and_flags(argv: list[str]) -> None:
    fired, coords = evaluate_shell_unsanitized({"argv": argv})
    assert fired is False, (argv, coords)
    assert coords.get("permitted") is True
