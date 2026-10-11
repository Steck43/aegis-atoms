"""Output-side security contracts owned and collected by aegis-atoms."""

from __future__ import annotations

import pytest


@pytest.mark.xfail(
    strict=True,
    reason="T-OS-01: MCP tool-list and description pinning is not implemented",
)
def test_t_os_01_pin_mismatch_denies_or_escalates() -> None:
    """Mutating an approved tool description must deny or escalate and ledger it."""
    pytest.fail(
        "T-OS-01 remainder: fixture MCP pin must deny or escalate on description "
        "mutation and record pin_mismatch"
    )
