# Extract named exceptions

Author: Landen Stecker. Date: 2026-08-19.

Re-derived from `git ls-files` on the public extract (not the 2026-08-19 false-done receipt).

`publish_gate` HOST_PATH worktree scan: **empty** on this tip after the 2026-08-19 scrub.

Environment **variable names** (no values) remain in:

- `__init__.py`
- `judge_slot_sonnet.py`
- `tests/test_j4_sonnet_observe.py`
- `scripts/j1_live_model_pin.py`
- `scripts/j3_live_sample.py`

Client catalog atoms and the ingest lane stay in the Hermes-fork tree. This copy uses `restricted-ingest`. CIE sibling tests are not in this extract (`tests/test_cie_observation_aggregate.py` dropped — `parents[2]/aegis-compounding` cannot collect here).
