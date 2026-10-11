"""Specification-gaming contracts owned and collected by aegis-atoms."""

from __future__ import annotations

import pytest


@pytest.mark.xfail(
    strict=True,
    reason="T-SG-04: sensitive test, CI, and policy writes are not escalated",
)
def test_t_sg_04_sensitive_write_escalates() -> None:
    """Loosening a test or control surface must require independent review."""
    pytest.fail(
        "T-SG-04 remainder: writes under tests/, .github/, or policy/ must escalate"
    )
