"""Shared fixtures and fake-credential factories.

Every secret used in tests is assembled at runtime from parts, so no
secret-shaped literal is ever committed to the repository — and so that
scrubcast's own test suite would pass a secret scan of the source tree.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Zero runtime dependencies means the suite can run straight from a checkout:
# fall back to src/ when the package is not pip-installed.
_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# --- fake credentials (constructed, never valid) -------------------------

FAKE_GITHUB = "ghp_" + "Ab3" * 12  # 36-char body
FAKE_AWS_ID = "AKIA" + "IOSFODNN7EXAMPLE"  # the canonical AWS docs example
FAKE_SLACK = "xoxb-" + "1234567890-abcDEF"
FAKE_STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1"
FAKE_JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxIn0" + "." + "c2lnbmF0dXJl"
FAKE_HIGH_ENTROPY = "Zq3xVb9TkLm2Pw8RsYd4Jf6Hn1Cg5Wt7"  # mixed case + digits


def make_cast(events, header=None):
    """Build asciicast v2 text from a list of [time, code, data] events."""
    head = {"version": 2, "width": 80, "height": 24}
    if header:
        head.update(header)
    lines = [json.dumps(head)]
    lines.extend(json.dumps(e) for e in events)
    return "\n".join(lines) + "\n"


@pytest.fixture()
def default_ruleset():
    from scrubcast import default_ruleset as make

    return make()
