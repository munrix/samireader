"""Clock arithmetic shared by the parser and the clock analyzers.

MOSS emits several wall-clock strings in different formats and different
zones. This module does the mechanical part — parsing, formatting, offset
classification — and takes no view on what a mismatch means.
"""

from __future__ import annotations

from datetime import datetime, timedelta

#: Formats seen across the corpus. Order matters: most specific first.
DATETIME_FORMATS = (
    "%Y/%m/%d %H:%M:%S",   # Monitor Started, screenshot `at`, FileCheck
    "%Y-%m-%d %H:%M:%S",   # SHAS2 mode started
    "%Y/%m/%d %H:%M",
    "%Y-%m-%d %H:%M",
)

#: Real-world UTC offsets are whole hours, or :30 / :45 in a handful of zones.
VALID_OFFSET_MINUTES = tuple(
    m
    for m in range(-12 * 60, 14 * 60 + 1, 15)
    if m % 60 in (0, 30, 45)
)


def parse_datetime(text: str | None) -> datetime | None:
    """Parse a MOSS timestamp, or return ``None``. Never raises."""
    if not text:
        return None
    text = text.strip().rstrip(":").strip()
    for fmt in DATETIME_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def parse_running_time(text: str) -> int | None:
    """``DD:HH:MM:SS`` or ``HH:MM:SS`` (or ``MM:SS``) -> seconds. ``None`` if unparseable."""
    parts = text.strip().split(":")
    if not 2 <= len(parts) <= 4:
        return None
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if any(n < 0 for n in nums):
        return None
    weights = {4: (86400, 3600, 60, 1), 3: (3600, 60, 1), 2: (60, 1)}[len(nums)]
    return sum(n * w for n, w in zip(nums, weights, strict=True))


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    seconds = int(round(seconds))
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{sign}{days}d {hours:02d}h {minutes:02d}m"
    if hours:
        return f"{sign}{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{sign}{minutes}m {secs:02d}s"
    return f"{sign}{secs}s"


def format_offset(minutes: float | None) -> str:
    """Minutes -> ``UTC+03:00``-style label."""
    if minutes is None:
        return "—"
    total = int(round(minutes))
    sign = "+" if total >= 0 else "-"
    hours, mins = divmod(abs(total), 60)
    return f"UTC{sign}{hours:02d}:{mins:02d}"


def offset_minutes(local: datetime, reference: datetime) -> float:
    """Signed minutes ``local - reference``."""
    return (local - reference).total_seconds() / 60.0


def is_valid_utc_offset(minutes: float, tolerance_minutes: float = 3.0) -> bool:
    """True when ``minutes`` sits within tolerance of a real-world UTC offset."""
    return any(abs(minutes - candidate) <= tolerance_minutes for candidate in VALID_OFFSET_MINUTES)


def nearest_valid_offset(minutes: float) -> int:
    return min(VALID_OFFSET_MINUTES, key=lambda c: abs(minutes - c))


def to_utc(local: datetime, offset_min: float) -> datetime:
    """Convert a host-local wall clock to UTC given the host's offset in minutes."""
    return local - timedelta(minutes=offset_min)


def from_utc(utc: datetime, offset_min: float) -> datetime:
    return utc + timedelta(minutes=offset_min)


def median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2
