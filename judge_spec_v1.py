"""Judge Spec v1 harness contracts (CURSOR-JUDGE-SPEC.md).

Model answers yes / no / cannot_determine only. Code maps to outcomes.
Apply stays False until a passing calibration receipt pins current hashes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from judge_reason_codes import JudgeReasonCode
from judge_rubric_v1 import RUBRIC_ATOMS_COMMIT_PIN, rubric_sha256

REQUIRED_G6_PINS = (
    "model_snapshot",
    "rubric_sha",
    "prompt_sha",
    "atoms_commit",
    "sampling",
    "effort",
    "sdk",
)


def map_model_answer_to_outcome(raw: Any) -> str:
    """Map model payload to CONCUR / SUBTRACT / ESCALATE / HUMAN.

    Only exact single answers yes/no/cannot_determine are accepted.
    Everything else escalates (never silently becomes a flag).
    """
    if not isinstance(raw, dict):
        return "ESCALATE"
    answer = raw.get("answer")
    if not isinstance(answer, str):
        return "ESCALATE"
    key = answer.strip().lower()
    if key == "yes":
        # yes = violates → subtract path (code maps; model never says flag)
        return "SUBTRACT"
    if key == "no":
        return "CONCUR"
    if key == "cannot_determine":
        return "HUMAN"
    return "ESCALATE"


def assert_rubric_tracks_atoms(
    *, atoms_commit: str, rubric_atoms_commit_pin: str | None = None
) -> None:
    pin = rubric_atoms_commit_pin or RUBRIC_ATOMS_COMMIT_PIN
    if atoms_commit != pin:
        raise AssertionError(
            f"atom change {atoms_commit!r} without rubric bump (pin {pin!r})"
        )


def current_rubric_sha() -> str:
    return rubric_sha256()


def require_g6_pins(row: dict[str, Any]) -> None:
    missing = [k for k in REQUIRED_G6_PINS if not row.get(k)]
    if missing:
        raise ValueError(f"missing pinned hash fields: {missing}")


def refuse_heldout_overlap(*, slice_ids: list[str], heldout_ids: set[str]) -> None:
    overlap = set(slice_ids) & set(heldout_ids)
    if overlap:
        raise ValueError(f"slice overlaps held-out: {sorted(overlap)}")


def assert_agent_invoked_every_item(rows: list[dict[str, Any]]) -> None:
    missing = [r.get("id") for r in rows if not r.get("agent_invoked")]
    if missing:
        raise AssertionError(f"agent not invoked on items: {missing}")


def apply_arm_allowed(
    *,
    calibration_receipt_path: Path | str | None,
    rubric_sha: str,
    prompt_sha: str,
    atoms_commit: str,
) -> bool:
    if not calibration_receipt_path:
        return False
    path = Path(calibration_receipt_path)
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
        return False
    if data.get("status") != "PASS":
        return False
    pins = data.get("pins") or {}
    return (
        pins.get("rubric_sha") == rubric_sha
        and pins.get("prompt_sha") == prompt_sha
        and pins.get("atoms_commit") == atoms_commit
    )


def reason_code_for_escalate(kind: str) -> JudgeReasonCode:
    return {
        "refusal": JudgeReasonCode.REFUSAL,
        "timeout": JudgeReasonCode.TIMEOUT,
        "malformed": JudgeReasonCode.MALFORMED,
        "unknown": JudgeReasonCode.UNKNOWN,
        "multi_code": JudgeReasonCode.MULTI_CODE,
        "empty": JudgeReasonCode.EMPTY,
    }.get(kind, JudgeReasonCode.UNKNOWN)
