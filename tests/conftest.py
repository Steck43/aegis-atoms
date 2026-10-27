"""
conftest.py: shared pytest setup.

Author:  Landen Stecker
Date:    2026-07-11
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import os  # noqa: E402

import action_gating  # noqa: E402

# Every git the suite runs refuses a bare repo it finds by discovery, the same
# pin the plugin sets at register.
action_gating.pin_git_harness_env(os.environ)
