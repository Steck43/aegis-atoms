"""SYNTHETIC CONFLICTING probe for observe-tune.

Label: SYNTHETIC. Do not claim organic CONFLICTING.
Production ACTION_GATING_EDGES is CONTRADICTS-only (SUPPORTS retract 2026-09-24).
This fixture keeps an ad-hoc SUPPORTS peer so the dry door can be exercised.
"""

from __future__ import annotations

from action_gating import (
    ATOM_SHELL_UNSANITIZED,
    CTRL_SHELL,
    conflicting_handoff_dry,
    rollup_denial_message,
)
from triad_types import (
    Control,
    Edge,
    EffectRank,
    EnforcementMode,
    MappingMethod,
    Polarity,
    RollupStatus,
    Severity,
    Strength,
    rollup_control,
)

# Synthetic support atom id. Not in production ACTION_GATING_ATOMS.
SYNTH_SUPPORT_ATOM = "atoms.tool_invocation.SYNTHETIC_shell_schema_valid_for_probe"


def synthetic_conflicting_rollups():
    """Dual-polarity fixture on CTRL_SHELL: SUPPORTS + CONTRADICTS both fired."""
    ctrl = Control(
        control_id=CTRL_SHELL,
        effect=EffectRank.BLOCK,
        severity=Severity.HIGH,
        precedence=100,
        enforcement_mode=EnforcementMode.MONITOR,
        framework_mappings=[],
    )
    edges = [
        Edge(
            atom_id=ATOM_SHELL_UNSANITIZED,
            control_id=CTRL_SHELL,
            polarity=Polarity.CONTRADICTS,
            strength=Strength.STRONG,
            mapping_method=MappingMethod.RULE,
        ),
        Edge(
            atom_id=SYNTH_SUPPORT_ATOM,
            control_id=CTRL_SHELL,
            polarity=Polarity.SUPPORTS,
            strength=Strength.MODERATE,
            mapping_method=MappingMethod.RULE,
        ),
    ]
    fired = {ATOM_SHELL_UNSANITIZED, SYNTH_SUPPORT_ATOM}
    return [rollup_control(ctrl, edges, fired)]


def main() -> int:
    rollups = synthetic_conflicting_rollups()
    assert rollups[0].status is RollupStatus.CONFLICTING, rollups[0].status
    msg = rollup_denial_message(rollups)
    door = conflicting_handoff_dry()
    print("GRADE=SYNTHETIC")
    print(f"rollup_status={rollups[0].status.value}")
    print(f"door={door}")
    print(f"denial={msg}")
    if msg is None or "CONFLICTING" not in msg:
        return 1
    if f"[{door}]" not in (msg or ""):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
