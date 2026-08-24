"""Test package bootstrap: make ``src`` and the fixture builder importable.

Keeps ``python -m unittest discover`` and ``pytest`` working without an install
step, which matters because the tool is meant to run offline from a checkout.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for entry in (ROOT / "src", ROOT / "tests"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))
