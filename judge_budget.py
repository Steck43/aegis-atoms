"""
Judge budget guard — lives outside the judge (J1a).

Author:  Landen Stecker
Date:    2026-07-13
Version: 1.0.0
Summary: Pre-call cost authorization. The judge cannot read or modify this
         state. Crossing a ceiling refuses the call before it is issued.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any

from judge_audit import PriceTable, SONNET5_PRICE_TABLE


class BudgetExhausted(Exception):
    """Ceiling would be crossed — call must not be issued."""

    def __init__(self, message: str, *, spent_usd: float, ceiling_usd: float) -> None:
        super().__init__(message)
        self.spent_usd = spent_usd
        self.ceiling_usd = ceiling_usd


@dataclass
class CallEstimate:
    tokens_in: int
    tokens_out_cap: int
    thinking_tokens_est: int
    estimated_cost_usd: float


@dataclass
class DriftSample:
    estimated_usd: float
    actual_usd: float

    @property
    def delta_usd(self) -> float:
        return self.actual_usd - self.estimated_usd


@dataclass
class BudgetGuard:
    """Absolute spend ceiling. Retries count. Outside the judge."""

    ceiling_usd: float
    price_table: PriceTable = field(default_factory=lambda: SONNET5_PRICE_TABLE)
    wall_usd: float = 20.0
    spent_usd: float = 0.0
    calls_authorized: int = 0
    calls_issued: int = 0
    calls_refused: int = 0
    drifts: list[DriftSample] = field(default_factory=list)
    stage_name: str = "unset"

    def __post_init__(self) -> None:
        if self.ceiling_usd > self.wall_usd:
            raise ValueError(
                f"ceiling ${self.ceiling_usd} exceeds absolute wall ${self.wall_usd}"
            )
        if self.ceiling_usd < 0:
            raise ValueError("ceiling must be non-negative")

    def estimate(
        self,
        *,
        tokens_in: int,
        tokens_out_cap: int,
        thinking_tokens_est: int = 0,
        when: date | None = None,
    ) -> CallEstimate:
        # Authorize against the output cap. Thinking bills as output and counts
        # toward max_tokens — do not add thinking on top of the cap (double-count).
        # thinking_tokens_est is retained for audit / drift reporting only.
        cost = self.price_table.cost_usd(
            tokens_in=tokens_in,
            tokens_out=tokens_out_cap,
            thinking_tokens=0,
            when=when,
        )
        return CallEstimate(
            tokens_in=tokens_in,
            tokens_out_cap=tokens_out_cap,
            thinking_tokens_est=thinking_tokens_est,
            estimated_cost_usd=cost,
        )

    def authorize(self, estimate: CallEstimate) -> None:
        """Refuse before issue if estimate would cross the ceiling."""
        projected = self.spent_usd + estimate.estimated_cost_usd
        if projected > self.ceiling_usd + 1e-12:
            self.calls_refused += 1
            raise BudgetExhausted(
                f"budget_exhausted: spent=${self.spent_usd:.6f} + "
                f"est=${estimate.estimated_cost_usd:.6f} > ceiling=${self.ceiling_usd:.2f} "
                f"(stage={self.stage_name})",
                spent_usd=self.spent_usd,
                ceiling_usd=self.ceiling_usd,
            )
        self.calls_authorized += 1

    def record_issue(self, actual_cost_usd: float, estimate: CallEstimate) -> None:
        self.calls_issued += 1
        self.spent_usd += actual_cost_usd
        self.drifts.append(
            DriftSample(
                estimated_usd=estimate.estimated_cost_usd,
                actual_usd=actual_cost_usd,
            )
        )
        if self.spent_usd > self.wall_usd + 1e-12:
            raise RuntimeError(
                f"absolute wall ${self.wall_usd} breached (spent=${self.spent_usd:.6f})"
            )

    def cumulative_drift_usd(self) -> float:
        return sum(d.delta_usd for d in self.drifts)

    def mean_actual_usd(self) -> float | None:
        if not self.drifts:
            return None
        return sum(d.actual_usd for d in self.drifts) / len(self.drifts)

    def status(self) -> dict[str, Any]:
        pct = (self.spent_usd / self.ceiling_usd * 100.0) if self.ceiling_usd else 0.0
        mean = self.mean_actual_usd()
        remaining = max(0.0, self.ceiling_usd - self.spent_usd)
        calls_left = None if not mean or mean <= 0 else int(remaining // mean)
        bands = [b for b in (50, 80, 95, 100) if pct >= b]
        return {
            "stage": self.stage_name,
            "spent_usd": round(self.spent_usd, 6),
            "ceiling_usd": self.ceiling_usd,
            "wall_usd": self.wall_usd,
            "percent_of_ceiling": round(pct, 2),
            "bands_crossed": bands,
            "calls_issued": self.calls_issued,
            "calls_refused": self.calls_refused,
            "cumulative_drift_usd": round(self.cumulative_drift_usd(), 6),
            "mean_actual_usd": None if mean is None else round(mean, 6),
            "calls_remaining_at_mean": calls_left,
            "last_call": None
            if not self.drifts
            else {
                "estimated_usd": self.drifts[-1].estimated_usd,
                "actual_usd": self.drifts[-1].actual_usd,
                "delta_usd": self.drifts[-1].delta_usd,
            },
        }
