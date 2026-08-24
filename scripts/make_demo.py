#!/usr/bin/env python3
"""Build a synthetic five-player match so the reports can be looked at.

Everything here is generated. No real archive is involved, and no real person.
Run ``make demo`` rather than this directly.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from fixtures.synth import Synth  # noqa: E402

PLAYERS = [
    ("clean", {"start_local": datetime(2024, 3, 28, 21, 0, 0), "captures": 68}),
    (
        "late-start",
        {"start_local": datetime(2024, 3, 28, 21, 26, 0), "captures": 42},
    ),
    (
        "edited-archive",
        {
            "start_local": datetime(2024, 3, 28, 21, 1, 0),
            "captures": 66,
            "tamper_capture": "005.JPG",
        },
    ),
    (
        "moved-clock",
        {
            "start_local": datetime(2024, 3, 28, 21, 0, 30),
            "captures": 65,
            "clock_skew_minutes": 41,
        },
    ),
    (
        "busy-machine",
        {
            "start_local": datetime(2024, 3, 28, 21, 2, 0),
            "captures": 64,
            "blank_frames": (11, 12, 13),
            "fast_double_click": True,
            "vulkan_layers": "VK_LAYER_OW_OVERLAY;VK_LAYER_ZZ_hook",
            "processes": [
                (r"C:\Windows\System32\lsass.exe", "Microsoft Windows Publisher"),
                (r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", "philandro Software GmbH"),
                (r"C:\Users\busy\Downloads\loader.exe", None),
                (r"C:\Program Files\LGHUB\lghub.exe", "Logitech Inc"),
            ],
        },
    ),
]


def main(directory: str = "demo") -> int:
    out = Path(directory)
    archives = out / "archives"
    archives.mkdir(parents=True, exist_ok=True)

    built = {}
    for index, (name, options) in enumerate(PLAYERS):
        built[name] = Synth(
            directory=archives, user=name, seed=7 + index, nonce=str(100000000 + index), **options
        ).build()
        print(f"built {name:15} {built[name].name}")

    schedule = {
        "match_id": "DEMO-QF1",
        "start": "2024-03-28T21:05:00+03:00",
        "end": "2024-03-28T22:05:00+03:00",
        "rounds": [
            {
                "number": n,
                "start": f"2024-03-28T21:{5 + (n - 1) * 7:02d}:00+03:00",
                "end": f"2024-03-28T21:{5 + (n - 1) * 7 + 5:02d}:00+03:00",
            }
            for n in range(1, 8)
        ],
        "players": [
            {"name": name, "team": "Ash" if i < 3 else "Thermite", "archive": path.name}
            for i, (name, path) in enumerate(built.items())
        ]
        + [{"name": "never-submitted", "team": "Thermite", "archive": "missing.zip"}],
    }
    (out / "schedule.json").write_text(json.dumps(schedule, indent=2), encoding="utf-8")
    print(f"schedule written to {out / 'schedule.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
