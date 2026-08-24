"""Match schedules — the one piece of ground truth the archive cannot supply.

"Do the dates match the data?" needs a second date to match against. DECISIONS
D2 items 2 and 4 are blocked without it, so the format is deliberately trivial
to produce: a JSON (or YAML) file a league admin can export from a spreadsheet,
a bracket platform, or type by hand.

Times must carry a UTC offset. A schedule without one is rejected rather than
guessed at — the whole point of this module is that it is the reference.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class ScheduleError(Exception):
    """The schedule file is missing, malformed, or ambiguous about time."""


def parse_iso_utc(value: str, *, field_name: str) -> datetime:
    """Parse an offset-aware ISO-8601 timestamp into a naive UTC datetime."""
    text = str(value).strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ScheduleError(f"{field_name}: not an ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ScheduleError(
            f"{field_name}: {value!r} has no UTC offset. Schedules are the reference clock, "
            "so the offset must be explicit (e.g. 2024-03-28T21:00:00+03:00)."
        )
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


@dataclass
class Round:
    number: int
    start_utc: datetime
    end_utc: datetime | None = None

    @property
    def label(self) -> str:
        return f"Round {self.number}"


@dataclass
class PlayerEntry:
    name: str
    team: str | None = None
    archive: str | None = None  # filename or SHA-256 of the submitted archive
    notes: str | None = None


@dataclass
class MatchSchedule:
    match_id: str
    start_utc: datetime
    end_utc: datetime
    rounds: list[Round] = field(default_factory=list)
    players: list[PlayerEntry] = field(default_factory=list)
    source: str = ""

    @property
    def duration_s(self) -> float:
        return (self.end_utc - self.start_utc).total_seconds()

    def entry_for(self, *, filename: str, sha256: str, label: str | None = None) -> PlayerEntry | None:
        """Match an archive to a scheduled player by hash, filename, or label."""
        for player in self.players:
            ref = (player.archive or "").strip()
            if not ref:
                continue
            if ref.lower() in (filename.lower(), sha256.lower()):
                return player
            if sha256 and ref.lower() == sha256[: len(ref)].lower() and len(ref) >= 8:
                return player
        if label:
            for player in self.players:
                if player.name.lower() == label.lower():
                    return player
        return None

    def rounds_overlapping(self, start: datetime, end: datetime) -> list[Round]:
        result = []
        for rnd in self.rounds:
            rnd_end = rnd.end_utc or rnd.start_utc
            if rnd.start_utc <= end and rnd_end >= start:
                result.append(rnd)
        return result

    def to_json(self) -> dict[str, Any]:
        return {
            "match_id": self.match_id,
            "start_utc": self.start_utc.isoformat(sep=" "),
            "end_utc": self.end_utc.isoformat(sep=" "),
            "rounds": [
                {
                    "number": r.number,
                    "start_utc": r.start_utc.isoformat(sep=" "),
                    "end_utc": r.end_utc.isoformat(sep=" ") if r.end_utc else None,
                }
                for r in self.rounds
            ],
            "players": [
                {"name": p.name, "team": p.team, "archive": p.archive, "notes": p.notes}
                for p in self.players
            ],
            "source": self.source,
        }


def _load_mapping(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]  # noqa: PLC0415 (optional dependency)
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise ScheduleError(
                f"{path} is YAML but PyYAML is not installed (pip install 'samireader[yaml]')"
            ) from exc
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ScheduleError(f"{path}: schedule must be a mapping at the top level")
    return data


def load_schedule(path: str | Path) -> MatchSchedule:
    path = Path(path)
    if not path.is_file():
        raise ScheduleError(f"schedule not found: {path}")
    data = _load_mapping(path)

    for required in ("match_id", "start"):
        if required not in data:
            raise ScheduleError(f"{path}: missing required field {required!r}")

    start = parse_iso_utc(data["start"], field_name="start")
    if "end" in data:
        end = parse_iso_utc(data["end"], field_name="end")
    elif "duration_minutes" in data:
        end = start + timedelta(minutes=float(data["duration_minutes"]))
    else:
        raise ScheduleError(f"{path}: needs either 'end' or 'duration_minutes'")
    if end <= start:
        raise ScheduleError(f"{path}: match end is not after match start")

    rounds = []
    for index, raw in enumerate(data.get("rounds") or [], start=1):
        if not isinstance(raw, dict):
            raise ScheduleError(f"{path}: rounds[{index}] must be a mapping")
        rounds.append(
            Round(
                number=int(raw.get("number", index)),
                start_utc=parse_iso_utc(raw["start"], field_name=f"rounds[{index}].start"),
                end_utc=parse_iso_utc(raw["end"], field_name=f"rounds[{index}].end")
                if raw.get("end")
                else None,
            )
        )

    players = []
    for index, raw in enumerate(data.get("players") or [], start=1):
        if not isinstance(raw, dict) or "name" not in raw:
            raise ScheduleError(f"{path}: players[{index}] needs at least a 'name'")
        players.append(
            PlayerEntry(
                name=str(raw["name"]),
                team=raw.get("team"),
                archive=raw.get("archive"),
                notes=raw.get("notes"),
            )
        )

    return MatchSchedule(
        match_id=str(data["match_id"]),
        start_utc=start,
        end_utc=end,
        rounds=sorted(rounds, key=lambda r: r.start_utc),
        players=players,
        source=str(path),
    )
