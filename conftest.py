"""Make the checkout importable under pytest without installing it."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for entry in (ROOT / "src", ROOT / "tests", ROOT):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))
