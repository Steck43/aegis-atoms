"""Block-only frozen reason-code enum (Spec §2).

Hashed. No free text. No confidence number.
These codes MUST NOT appear on any gate allow path (ALLOW_PATH_FORBIDDEN).
"""

from __future__ import annotations

import hashlib
from enum import Enum


class JudgeReasonCode(str, Enum):
    """Block-only / escalate reason codes. Frozen set — bump rubric when changed."""

    # Subtract / hold paths only. Never pair with a floor allow widening.
    VIOLATION_CONFIRMED = "violation_confirmed"
    NEEDS_HUMAN = "needs_human"
    REFUSAL = "refusal"
    TIMEOUT = "timeout"
    MALFORMED = "malformed"
    UNKNOWN = "unknown"
    MULTI_CODE = "multi_code"
    EMPTY = "empty"


ALLOW_PATH_FORBIDDEN = True  # static ban marker for test_02

REASON_CODE_ENUM_SHA256 = hashlib.sha256(
    ("\n".join(sorted(c.value for c in JudgeReasonCode)) + "\n").encode("utf-8")
).hexdigest()
