"""
Sonnet 5 judge slot — drops into the bounded cage without changing its types (J1).

Author:  Landen Stecker
Date:    2026-07-13
Version: 1.0.0
Summary: Real Anthropic Messages API call returning JudgeOpinion via structured
         outputs. Effort floor is ``low`` (thinking cannot be disabled per pack
         pin). max_tokens=2000. Budget guard authorizes before issue. Prefill
         is never used (400 on Sonnet 5).
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Callable

from bounded_judge import JudgeOpinion, JudgeRecommendation
from judge_audit import (
    SONNET5_PRICE_TABLE,
    AuditStore,
    CycleAuditRecord,
    ModelCallUsage,
    new_cycle_id,
    utc_now_iso,
)
from judge_budget import BudgetGuard
from triad_types import EffectRank

MODEL_ID = "claude-sonnet-5"
EFFORT_FLOOR = "low"  # lowest selectable; adaptive thinking stays on (pack pin)
MAX_OUTPUT_TOKENS = 2000
JUDGE_SCHEMA_NAME = "aegis_judge_opinion"

SYSTEM_POLICY = """You are the Aegis bounded judge. You are advisory only.
You may return exactly one recommendation:
  - concur
  - flag_for_review
  - add_nuance
You must NEVER return allow, block, deny, or any other verdict.
The floor verdict is authoritative and immutable. You cannot widen what the floor allows.
Respond only through the structured schema."""


class JudgeUnavailable(Exception):
    """Timeout, transport failure, or dark judge — must escalate to HITL."""


class JudgeRefusal(Exception):
    """stop_reason == refusal — distinct class, not malformed and not a verdict."""

    def __init__(self, message: str, *, stop_reason: str = "refusal") -> None:
        super().__init__(message)
        self.stop_reason = stop_reason


class MalformedJudgeOutput(Exception):
    """Schema-violating or out-of-set recommendation."""


_REC_MAP = {
    "concur": JudgeRecommendation.CONCUR,
    "flag": JudgeRecommendation.FLAG_FOR_REVIEW,
    "flag_for_review": JudgeRecommendation.FLAG_FOR_REVIEW,
    "nuance": JudgeRecommendation.ADD_NUANCE,
    "add_nuance": JudgeRecommendation.ADD_NUANCE,
}


def _opinion_from_structured(data: dict[str, Any]) -> JudgeOpinion:
    rec_raw = str(data.get("recommendation", "")).strip().lower()
    if rec_raw in {"allow", "block", "deny"}:
        raise MalformedJudgeOutput(
            f"forbidden recommendation {rec_raw!r} — cage rejects allow/block"
        )
    if rec_raw not in _REC_MAP:
        raise MalformedJudgeOutput(f"unknown recommendation {rec_raw!r}")
    conf = float(data.get("confidence", 0.0))
    if conf < 0.0 or conf > 1.0:
        raise MalformedJudgeOutput(f"confidence out of range: {conf}")
    reason = str(data.get("reason", "")).strip() or "no reason"
    return JudgeOpinion(
        recommendation=_REC_MAP[rec_raw],
        confidence=conf,
        reason=reason,
        advisory=True,
    )


def _structured_format() -> dict[str, Any]:
    # Anthropic output_config.format: {"type":"json_schema","schema":{...}}
    # Note: number min/max not supported on this endpoint — reject out of range in code.
    return {
        "type": "json_schema",
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "recommendation": {
                    "type": "string",
                    "enum": ["concur", "flag_for_review", "add_nuance"],
                },
                "confidence": {"type": "number"},
                "reason": {"type": "string"},
            },
            "required": ["recommendation", "confidence", "reason"],
        },
    }


def estimate_input_tokens(text: str) -> int:
    """Conservative Sonnet-5-aware estimate (~1.2× prior heuristic). Not the tokenizer."""
    # Pack: count with Sonnet 5 tokenizer when available; until then use
    # chars/3 * 1.2 as a ceiling-biased estimate (prefer refuse over under-estimate).
    return max(1, int(len(text) / 3.0 * 1.2))


@dataclass
class SonnetJudgeConfig:
    api_key: str | None = None
    dry_run: bool = False
    effort: str = EFFORT_FLOOR
    max_tokens: int = MAX_OUTPUT_TOKENS
    audit_store: AuditStore | None = None
    agent_identity: str = "aegis"


def make_sonnet_judge_slot(
    budget: BudgetGuard,
    *,
    config: SonnetJudgeConfig | None = None,
    client: Any | None = None,
) -> Callable[[dict[str, Any], EffectRank], JudgeOpinion]:
    """Return a JudgeSlot. Cage types unchanged."""
    cfg = config or SonnetJudgeConfig()
    key = (
        cfg.api_key
        or os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("ANTHROPIC_API_KEY".lower())
    )

    def slot(case: dict[str, Any], floor_verdict: EffectRank) -> JudgeOpinion:
        user_blob = json.dumps(
            {
                "floor_verdict": floor_verdict.name,
                "rollup_status": case.get("rollup_status"),
                "ambiguous": case.get("ambiguous"),
                "atoms_for_adjudication": case.get("atoms_for_adjudication"),
                "locked_atoms": case.get("locked_atoms"),
                "content_for_judge": case.get("content_for_judge"),
                "evaluation_id": case.get("evaluation_id"),
            },
            ensure_ascii=False,
        )
        prompt_text = SYSTEM_POLICY + "\n" + user_blob
        tokens_in_est = estimate_input_tokens(prompt_text)
        # Residual thinking at effort=low: recorded for audit; authorize uses out cap.
        thinking_est = min(400, cfg.max_tokens // 4)
        estimate = budget.estimate(
            tokens_in=tokens_in_est,
            tokens_out_cap=cfg.max_tokens,
            thinking_tokens_est=thinking_est,
        )
        budget.authorize(estimate)  # may raise BudgetExhausted — before issue

        if cfg.dry_run:
            usage = ModelCallUsage(
                model_identity=MODEL_ID + "#dry-run",
                tokens_in=tokens_in_est,
                tokens_out=0,
                thinking_tokens=thinking_est,
                latency_ms=0.0,
                estimated_cost_usd=estimate.estimated_cost_usd,
                actual_cost_usd=0.0,
                stop_reason="dry_run",
                dry_run=True,
            )
            # Dry-run does not spend, but records the would-be cost on the audit.
            _maybe_audit(
                cfg,
                case,
                floor_verdict,
                usage,
                "skipped",
                "none",
                "skipped_not_ambiguous",
            )
            return JudgeOpinion(
                recommendation=JudgeRecommendation.CONCUR,
                confidence=1.0,
                reason=f"dry_run concur floor={floor_verdict.name} est=${estimate.estimated_cost_usd:.6f}",
                advisory=True,
            )

        if not key and client is None:
            raise JudgeUnavailable("ANTHROPIC_API_KEY not set")

        t0 = time.monotonic()
        try:
            resp = _call_anthropic(
                client=client,
                api_key=key or "",
                user_blob=user_blob,
                effort=cfg.effort,
                max_tokens=cfg.max_tokens,
            )
        except JudgeRefusal:
            raise
        except JudgeUnavailable:
            raise
        except Exception as exc:
            raise JudgeUnavailable(f"transport:{type(exc).__name__}:{exc}") from exc
        latency_ms = (time.monotonic() - t0) * 1000.0

        stop_reason = getattr(resp, "stop_reason", None) or (
            resp.get("stop_reason") if isinstance(resp, dict) else None
        )
        model_identity = (
            getattr(resp, "model", None)
            or (resp.get("model") if isinstance(resp, dict) else None)
            or MODEL_ID
        )
        usage = _usage_from_response(resp)
        tokens_in = usage["tokens_in"]
        tokens_out = usage["tokens_out"]
        thinking_tokens = usage["thinking_tokens"]
        cache_read = usage["cache_read_tokens"]
        cache_create = usage["cache_creation_tokens"]
        # API output_tokens already includes thinking; do not double-bill.
        actual = SONNET5_PRICE_TABLE.cost_usd(
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            thinking_tokens=0,
        )
        mc = ModelCallUsage(
            model_identity=str(model_identity),
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            thinking_tokens=thinking_tokens,
            latency_ms=latency_ms,
            estimated_cost_usd=estimate.estimated_cost_usd,
            actual_cost_usd=actual,
            stop_reason=str(stop_reason) if stop_reason else None,
            cache_read_tokens=cache_read,
            cache_creation_tokens=cache_create,
            dry_run=False,
        )
        # Every issued response meters — including refusal (paid decline).
        budget.record_issue(actual, estimate)

        if stop_reason == "refusal":
            _maybe_audit(
                cfg,
                case,
                floor_verdict,
                mc,
                "refusal",
                "hitl",
                "judge_unavailable",
            )
            raise JudgeRefusal("model refused", stop_reason="refusal")

        try:
            opinion = _parse_response_opinion(resp)
        except MalformedJudgeOutput:
            _maybe_audit(
                cfg,
                case,
                floor_verdict,
                mc,
                "malformed",
                "hitl",
                "escalated_hitl",
            )
            raise

        _maybe_audit(
            cfg,
            case,
            floor_verdict,
            mc,
            opinion.recommendation.value,  # type: ignore[arg-type]
            "floor_stands",
            "completed",
        )
        return opinion

    return slot


def _maybe_audit(
    cfg: SonnetJudgeConfig,
    case: dict[str, Any],
    floor_verdict: EffectRank,
    mc: ModelCallUsage,
    judge_verdict: str,
    effect: str,
    outcome: str,
) -> None:
    if cfg.audit_store is None:
        return
    rec = CycleAuditRecord(
        cycle_id=str(case.get("evaluation_id") or new_cycle_id()),
        timestamp=utc_now_iso(),
        agent_identity=cfg.agent_identity,
        atoms_fired=[str(a) for a in (case.get("atoms_for_adjudication") or [])],
        rollup=str(case.get("rollup_status") or ""),
        floor_verdict=floor_verdict.name,
        judge_verdict=judge_verdict,  # type: ignore[arg-type]
        effect=effect,  # type: ignore[arg-type]
        outcome=outcome,  # type: ignore[arg-type]
        model_call=mc,
        locked_atoms=[str(a) for a in (case.get("locked_atoms") or [])],
        notes={"effort": cfg.effort, "max_tokens": cfg.max_tokens},
    )
    cfg.audit_store.append(rec)


def _call_anthropic(
    *,
    client: Any | None,
    api_key: str,
    user_blob: str,
    effort: str,
    max_tokens: int,
) -> Any:
    if client is None:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
    # Cache stable system prefix (byte-identical every call).
    return client.messages.create(
        model=MODEL_ID,
        max_tokens=max_tokens,
        system=[
            {
                "type": "text",
                "text": SYSTEM_POLICY,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": user_blob}],
        thinking={"type": "adaptive"},
        output_config={
            "effort": effort,
            "format": _structured_format(),
        },
    )


def _usage_from_response(resp: Any) -> dict[str, int]:
    usage = (
        getattr(resp, "usage", None)
        or (resp.get("usage") if isinstance(resp, dict) else {})
        or {}
    )
    if not isinstance(usage, dict):
        # SDK object
        tokens_in = int(getattr(usage, "input_tokens", 0) or 0)
        tokens_out = int(getattr(usage, "output_tokens", 0) or 0)
        cache_read = int(getattr(usage, "cache_read_input_tokens", 0) or 0)
        cache_create = int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
    else:
        tokens_in = int(usage.get("input_tokens") or 0)
        tokens_out = int(usage.get("output_tokens") or 0)
        cache_read = int(usage.get("cache_read_input_tokens") or 0)
        cache_create = int(usage.get("cache_creation_input_tokens") or 0)
    # Thinking tokens: prefer explicit field; else 0 (billed inside output on some paths).
    thinking = 0
    if not isinstance(usage, dict):
        thinking = int(getattr(usage, "thinking_tokens", 0) or 0)
    else:
        thinking = int(usage.get("thinking_tokens") or 0)
    # Also scan content blocks for thinking type lengths if present.
    content = getattr(resp, "content", None) or (
        resp.get("content") if isinstance(resp, dict) else []
    )
    if content and thinking == 0:
        for block in content:
            btype = getattr(block, "type", None) or (
                block.get("type") if isinstance(block, dict) else None
            )
            if btype == "thinking":
                text = getattr(block, "thinking", None) or (
                    block.get("thinking") if isinstance(block, dict) else ""
                )
                thinking += estimate_input_tokens(str(text or ""))
    return {
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "thinking_tokens": thinking,
        "cache_read_tokens": cache_read,
        "cache_creation_tokens": cache_create,
    }


def _parse_response_opinion(resp: Any) -> JudgeOpinion:
    content = getattr(resp, "content", None) or (
        resp.get("content") if isinstance(resp, dict) else []
    )
    text_parts: list[str] = []
    for block in content or []:
        btype = getattr(block, "type", None) or (
            block.get("type") if isinstance(block, dict) else None
        )
        if btype == "text":
            text_parts.append(
                str(
                    getattr(block, "text", None)
                    or (block.get("text") if isinstance(block, dict) else "")
                )
            )
        elif btype == "output_json" or btype == "json":
            data = getattr(block, "json", None) or (
                block.get("json") if isinstance(block, dict) else None
            )
            if isinstance(data, dict):
                return _opinion_from_structured(data)
    blob = "".join(text_parts).strip()
    if not blob:
        raise MalformedJudgeOutput("empty response content")
    try:
        data = json.loads(blob)
    except json.JSONDecodeError as exc:
        raise MalformedJudgeOutput(f"non-json content: {exc}") from exc
    if not isinstance(data, dict):
        raise MalformedJudgeOutput("json root must be object")
    return _opinion_from_structured(data)
