"""
Judge audit spine — append-only cycle records (B1).

Author:  Landen Stecker
Date:    2026-07-13
Version: 1.0.0
Summary: Typed audit spine for the bounded judge. Every evaluation cycle
         appends one record. A model-call block without a model identity
         cannot be constructed. Dollars are recomputable from raw tokens
         and the pinned price table (source + 2026-08-31 expiry recorded).
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Literal

AUDIT_RECORD_TYPE = "judge_cycle_audit"
DEFAULT_AUDIT_REL = Path("logs") / "judge-audit.jsonl"

VerdictLiteral = Literal[
    "concur",
    "flag_for_review",
    "add_nuance",
    "judge_unavailable",
    "budget_exhausted",
    "refusal",
    "malformed",
    "skipped",
    "none",
]
EffectLiteral = Literal[
    "none",
    "floor_stands",
    "hitl",
    "nuance_recorded",
    "flag_recorded",
]
OutcomeLiteral = Literal[
    "completed",
    "escalated_hitl",
    "judge_unavailable",
    "budget_exhausted",
    "skipped_not_ambiguous",
]


# ---------------------------------------------------------------------------
# Price table — pinned 2026-07-13. Source + expiry are load-bearing.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PriceTable:
    """Dollars per million tokens. Recompute cost from raw counts; do not trust a cached dollar field alone."""

    model_id: str
    input_usd_per_mtok: float
    output_usd_per_mtok: float
    # Thinking tokens bill as output (Anthropic Sonnet 5).
    thinking_bills_as: Literal["output"]
    introductory_through: date
    post_intro_input_usd_per_mtok: float
    post_intro_output_usd_per_mtok: float
    source: str
    pinned_on: date

    def rates_on(self, when: date | None = None) -> tuple[float, float]:
        """Return (input_per_mtok, output_per_mtok) for the given calendar day."""
        day = when or date.today()
        if day <= self.introductory_through:
            return self.input_usd_per_mtok, self.output_usd_per_mtok
        return self.post_intro_input_usd_per_mtok, self.post_intro_output_usd_per_mtok

    def cost_usd(
        self,
        *,
        tokens_in: int,
        tokens_out: int,
        thinking_tokens: int,
        when: date | None = None,
    ) -> float:
        inp, out = self.rates_on(when)
        # Thinking bills as output.
        billed_out = tokens_out + thinking_tokens
        return (tokens_in / 1_000_000.0) * inp + (billed_out / 1_000_000.0) * out


# Verified 2026-07-13 against Anthropic docs / platform.claude.com (directive pin).
SONNET5_PRICE_TABLE = PriceTable(
    model_id="claude-sonnet-5",
    input_usd_per_mtok=2.00,
    output_usd_per_mtok=10.00,
    thinking_bills_as="output",
    introductory_through=date(2026, 8, 31),
    post_intro_input_usd_per_mtok=3.00,
    post_intro_output_usd_per_mtok=15.00,
    source=(
        "platform.claude.com pricing + Anthropic Sonnet 5 launch post; "
        "directive pin 2026-07-13 (intro through 2026-08-31)"
    ),
    pinned_on=date(2026, 7, 13),
)


# ---------------------------------------------------------------------------
# Typed records — ModelCallUsage requires model_identity at construction.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelCallUsage:
    """One paid (or stubbed) model invocation. model_identity is mandatory."""

    model_identity: str  # precise string from the API response `model` field
    tokens_in: int
    tokens_out: int
    thinking_tokens: int
    latency_ms: float
    estimated_cost_usd: float
    actual_cost_usd: float | None
    stop_reason: str | None = None
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    dry_run: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.model_identity, str) or not self.model_identity.strip():
            raise TypeError(
                "ModelCallUsage.model_identity is required "
                "(API response model field; a model-call record without it must not compile)"
            )
        for name in ("tokens_in", "tokens_out", "thinking_tokens"):
            val = getattr(self, name)
            if not isinstance(val, int) or val < 0:
                raise ValueError(f"{name} must be a non-negative int")


@dataclass
class CycleAuditRecord:
    """One evaluation cycle. Append-only."""

    cycle_id: str
    timestamp: str
    agent_identity: str
    atoms_fired: list[str]
    rollup: str
    floor_verdict: str
    judge_verdict: VerdictLiteral
    effect: EffectLiteral
    outcome: OutcomeLiteral
    model_call: ModelCallUsage | None = None
    escalation_reason: str | None = None
    retries_used: int = 0
    locked_atoms: list[str] = field(default_factory=list)
    notes: dict[str, Any] = field(default_factory=dict)
    record_type: str = AUDIT_RECORD_TYPE

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def new_cycle_id() -> str:
    return (
        f"jc_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_"
        f"{uuid.uuid4().hex[:8]}"
    )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class AuditStore:
    """Append-only JSONL. Never rewrite prior lines."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def append(self, record: CycleAuditRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        out: list[dict[str, Any]] = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def summarize(self) -> dict[str, Any]:
        rows = self.read_all()
        spend = 0.0
        tokens_in = tokens_out = thinking = 0
        calls = 0
        cache_reads = cache_creates = 0
        for r in rows:
            mc = r.get("model_call")
            if not mc:
                continue
            calls += 1
            tokens_in += int(mc.get("tokens_in") or 0)
            tokens_out += int(mc.get("tokens_out") or 0)
            thinking += int(mc.get("thinking_tokens") or 0)
            cache_reads += int(mc.get("cache_read_tokens") or 0)
            cache_creates += int(mc.get("cache_creation_tokens") or 0)
            actual = mc.get("actual_cost_usd")
            if actual is None:
                actual = mc.get("estimated_cost_usd") or 0.0
            spend += float(actual)
        promptish = tokens_in + cache_creates
        hit_rate = (
            (cache_reads / (cache_reads + promptish))
            if (cache_reads + promptish)
            else None
        )
        return {
            "records": len(rows),
            "model_calls": calls,
            "spend_usd": round(spend, 6),
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "thinking_tokens": thinking,
            "cache_read_tokens": cache_reads,
            "cache_creation_tokens": cache_creates,
            "cache_hit_rate": None if hit_rate is None else round(hit_rate, 4),
        }


# ---------------------------------------------------------------------------
# Sample / helpers
# ---------------------------------------------------------------------------


def sample_record(*, dry_run: bool = True) -> CycleAuditRecord:
    """Deterministic sample for B1 presentation (no network)."""
    usage = ModelCallUsage(
        model_identity="claude-sonnet-5",  # placeholder until first live response
        tokens_in=1200,
        tokens_out=180,
        thinking_tokens=90,
        latency_ms=412.0,
        estimated_cost_usd=SONNET5_PRICE_TABLE.cost_usd(
            tokens_in=1200, tokens_out=180, thinking_tokens=90
        ),
        actual_cost_usd=None
        if dry_run
        else SONNET5_PRICE_TABLE.cost_usd(
            tokens_in=1200, tokens_out=180, thinking_tokens=90
        ),
        stop_reason="end_turn",
        dry_run=dry_run,
    )
    return CycleAuditRecord(
        cycle_id="jc_sample_b1_00000001",
        timestamp="2026-07-13T16:00:00+00:00",
        agent_identity="aegis",
        atoms_fired=["atoms.tool_invocation.path_resolves_outside_allowed_root"],
        rollup="CONFLICTING",
        floor_verdict="DENY",
        judge_verdict="concur",
        effect="floor_stands",
        outcome="completed",
        model_call=usage,
        retries_used=1,
        locked_atoms=["atoms.tool_invocation.path_resolves_outside_allowed_root"],
        notes={"b1_sample": True, "price_table_model": SONNET5_PRICE_TABLE.model_id},
    )


# ---------------------------------------------------------------------------
# CLI (cli-for-agents: non-interactive, --json, dry-run, actionable errors)
# ---------------------------------------------------------------------------


def _die(msg: str, code: int = 2) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegis-judge-audit",
        description=(
            "Read or append the judge-lane audit spine. "
            "Non-interactive. Use --json for machine output."
        ),
    )
    p.add_argument(
        "--path",
        type=Path,
        default=None,
        help="Audit JSONL path (default: ./logs/judge-audit.jsonl or $AEGIS_JUDGE_AUDIT)",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON on stdout")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("summary", help="Summarize spend and token totals")
    s.add_argument(
        "--dry-run", action="store_true", help="No side effects (default for summary)"
    )

    s = sub.add_parser("tail", help="Show last N records")
    s.add_argument("-n", type=int, default=5)

    s = sub.add_parser(
        "sample", help="Write the B1 sample record (or print with --dry-run)"
    )
    s.add_argument(
        "--dry-run",
        action="store_true",
        help="Print sample JSON; do not append",
    )

    s = sub.add_parser("price-table", help="Show the pinned Sonnet 5 price table")

    s = sub.add_parser(
        "budget-status",
        help="Live spend bands from a BudgetGuard status JSON file",
    )
    s.add_argument(
        "--status-file",
        type=Path,
        required=True,
        help="JSON written by a runner (BudgetGuard.status())",
    )
    return p


def _resolve_path(arg: Path | None) -> Path:
    import os

    if arg is not None:
        return arg
    env = os.environ.get("AEGIS_JUDGE_AUDIT")
    if env:
        return Path(env)
    return Path.cwd() / DEFAULT_AUDIT_REL


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    path = _resolve_path(args.path)
    store = AuditStore(path)

    if args.cmd == "price-table":
        pt = SONNET5_PRICE_TABLE
        payload = {
            "model_id": pt.model_id,
            "input_usd_per_mtok": pt.input_usd_per_mtok,
            "output_usd_per_mtok": pt.output_usd_per_mtok,
            "thinking_bills_as": pt.thinking_bills_as,
            "introductory_through": pt.introductory_through.isoformat(),
            "post_intro_input_usd_per_mtok": pt.post_intro_input_usd_per_mtok,
            "post_intro_output_usd_per_mtok": pt.post_intro_output_usd_per_mtok,
            "source": pt.source,
            "pinned_on": pt.pinned_on.isoformat(),
        }
        print(
            json.dumps(payload, indent=2)
            if args.json
            else json.dumps(payload, indent=2)
        )
        return 0

    if args.cmd == "summary":
        if not path.is_file():
            _die(
                f"audit file not found: {path} (run sample --dry-run first, or set --path)"
            )
        summary = store.summarize()
        summary["path"] = str(path)
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(f"path={path}")
            for k, v in summary.items():
                if k == "path":
                    continue
                print(f"{k}={v}")
        return 0

    if args.cmd == "tail":
        if not path.is_file():
            _die(f"audit file not found: {path}")
        rows = store.read_all()
        n = max(0, int(args.n))
        chunk = rows[-n:]
        if args.json:
            print(json.dumps(chunk, indent=2))
        else:
            for r in chunk:
                print(json.dumps(r, ensure_ascii=False))
        return 0

    if args.cmd == "sample":
        rec = sample_record(dry_run=True)
        if args.dry_run:
            print(json.dumps(rec.to_dict(), indent=2, ensure_ascii=False))
            return 0
        store.append(rec)
        if args.json:
            print(
                json.dumps(
                    {"appended": True, "path": str(path), "cycle_id": rec.cycle_id}
                )
            )
        else:
            print(f"appended {rec.cycle_id} -> {path}")
        return 0

    if args.cmd == "budget-status":
        if not args.status_file.is_file():
            _die(f"status file not found: {args.status_file}")
        try:
            payload = json.loads(args.status_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            _die(f"invalid JSON in {args.status_file}: {exc}")
        # Accept either bare status or a report wrapping budget_status.
        status = payload.get("budget_status", payload)
        required = ("spent_usd", "ceiling_usd", "percent_of_ceiling", "bands_crossed")
        missing = [k for k in required if k not in status]
        if missing:
            _die(f"status missing keys {missing}; pass BudgetGuard.status() JSON")
        if args.json:
            print(json.dumps(status, indent=2))
        else:
            print(
                f"stage={status.get('stage')} spent=${status['spent_usd']:.6f} "
                f"ceiling=${status['ceiling_usd']:.2f} "
                f"pct={status['percent_of_ceiling']}% "
                f"bands={status['bands_crossed']} "
                f"issued={status.get('calls_issued')} "
                f"refused={status.get('calls_refused')} "
                f"drift=${status.get('cumulative_drift_usd')} "
                f"remaining_calls={status.get('calls_remaining_at_mean')}"
            )
            last = status.get("last_call") or {}
            if last:
                print(
                    f"last estimated=${last.get('estimated_usd')} "
                    f"actual=${last.get('actual_usd')} "
                    f"delta=${last.get('delta_usd')}"
                )
        return 0

    _die(f"unknown command: {args.cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
