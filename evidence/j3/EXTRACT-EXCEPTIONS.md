# Extract named exceptions

Author: Landen Stecker. Date: 2026-08-19.

Staging `rg` for client-name / host-home / LAN IP / paid-model env-var name is empty except the **environment variable name** (no values) in:

- `__init__.py`
- `judge_slot_sonnet.py`
- `tests/test_j4_sonnet_observe.py`
- `scripts/j1_live_model_pin.py`
- `scripts/j3_live_sample.py`

Client catalog atoms and the ingest lane stay in the Hermes-fork tree. This copy uses `restricted-ingest`.
