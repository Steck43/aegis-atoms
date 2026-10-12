"""Refuse paid runs that would exceed a SPEND-LEDGER line cap or the $50 total.

Ledger path SoT (spaces and ampersand):
C:\\Users\\lande\\Engineering & Development\\Grok-Bot-Hub\\burn-queue\\2026-10-09-paper-claims-ledger\\SPEND-LEDGER.md
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_LEDGER = Path(
    r"C:\Users\lande\Engineering & Development\Grok-Bot-Hub"
    r"\burn-queue\2026-10-09-paper-claims-ledger\SPEND-LEDGER.md"
)
TOTAL_CEILING = 50.0

_LINE_RE = re.compile(
    r"^\| (BUD-\d+) \| .+ \| ([\d.]+) \| ([\d.]+) \| ([\d.]+) \|",
    re.MULTILINE,
)
_TOTAL_RE = re.compile(
    r"^\| \| \*\*Total\*\* \| \*\*([\d.]+)\*\* \| \*\*([\d.]+)\*\*",
    re.MULTILINE,
)


@dataclass(frozen=True)
class LedgerView:
    caps: dict[str, float]
    spent: dict[str, float]
    running_total: float
    path: Path


class SpendGuardRefuse(RuntimeError):
    """Paid run refused: line cap or total ceiling would be exceeded."""


def parse_ledger(text: str, *, path: Path) -> LedgerView:
    caps: dict[str, float] = {}
    spent: dict[str, float] = {}
    for match in _LINE_RE.finditer(text):
        line_id, cap_s, spent_s, _rem = match.groups()
        caps[line_id] = float(cap_s)
        spent[line_id] = float(spent_s)
    if not caps:
        raise SpendGuardRefuse(f"SPEND-LEDGER parse refused: zero BUD rows at {path}")
    total_match = _TOTAL_RE.search(text)
    if total_match:
        running = float(total_match.group(2))
    else:
        running = sum(spent.values())
    return LedgerView(caps=caps, spent=spent, running_total=running, path=path)


def load_ledger(path: Path | None = None) -> LedgerView:
    ledger_path = Path(path) if path is not None else DEFAULT_LEDGER
    if not ledger_path.is_file():
        raise SpendGuardRefuse(f"SPEND-LEDGER missing: {ledger_path}")
    return parse_ledger(ledger_path.read_text(encoding="utf-8"), path=ledger_path)


def check_affordable(
    line_id: str,
    amount_usd: float,
    *,
    ledger: LedgerView | None = None,
    path: Path | None = None,
) -> None:
    """Raise SpendGuardRefuse if amount would exceed line cap or $50 total."""
    view = ledger if ledger is not None else load_ledger(path)
    if line_id not in view.caps:
        raise SpendGuardRefuse(f"unknown spend line: {line_id}")
    if amount_usd < 0:
        raise SpendGuardRefuse(f"negative spend refused: {amount_usd}")
    proposed_line = view.spent[line_id] + amount_usd
    if proposed_line > view.caps[line_id] + 1e-9:
        raise SpendGuardRefuse(
            f"over line cap: {line_id} spent={view.spent[line_id]} "
            f"+ {amount_usd} > cap={view.caps[line_id]}"
        )
    proposed_total = view.running_total + amount_usd
    if proposed_total > TOTAL_CEILING + 1e-9:
        raise SpendGuardRefuse(
            f"over total ceiling: running={view.running_total} "
            f"+ {amount_usd} > {TOTAL_CEILING}"
        )
