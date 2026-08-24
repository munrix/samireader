"""Reconciling the clocks in one archive.

An archive carries six independent clocks plus a derived seventh (RESEARCH §4).
This module measures the relationships between them and takes no view on what a
mismatch means; :mod:`sami.analyzers.clocks` turns measurements into findings.

The clocks, and what each is believed to be:

======  ===============================  ==================
Clock   Source                           Zone
======  ===============================  ==================
1       ZIP filename                     UTC
2       ``SHAS2 mode started``           MOSS network time
3       ``Monitor Started``              host local
4       per-screenshot ``at``            host local
5       ZIP entry mtimes                 UTC
6       taskbar clock inside the JPEG    host local (not read in P0)
7       boot time = capture − uptime     derived, host local
======  ===============================  ==================

The load-bearing relationship is 5↔4: it yields the host's UTC offset from the
archive alone, with no external reference. Everything else is checked against it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from mosslib.model import Session
from mosslib.timeutil import (
    format_offset,
    is_valid_utc_offset,
    median,
    nearest_valid_offset,
    offset_minutes,
    to_utc,
)


@dataclass
class OffsetSample:
    """One screenshot's local timestamp against its ZIP entry mtime."""

    file: str
    local: datetime
    zip_mtime: datetime
    delta_minutes: float
    line: int = 0


@dataclass
class ClockModel:
    samples: list[OffsetSample] = field(default_factory=list)
    host_offset_minutes: float | None = None
    offset_spread_minutes: float | None = None
    offset_is_valid: bool = False
    nearest_offset_minutes: int | None = None

    #: ``Monitor Started`` − ``SHAS2 mode started``. Under the observed model
    #: this equals ``host_offset − 60`` on an unmanipulated host.
    network_to_local_minutes: float | None = None
    implied_network_offset_minutes: float | None = None

    #: ZIP filename (UTC) against the header clock.
    name_to_header_minutes: float | None = None
    #: ZIP filename (UTC) against the session start converted to UTC.
    name_to_session_minutes: float | None = None

    boot_time_local: datetime | None = None
    uptime_source: str | None = None
    uptime_seconds: int | None = None

    session_start_local: datetime | None = None
    session_end_local: datetime | None = None

    @property
    def resolved(self) -> bool:
        return self.host_offset_minutes is not None

    @property
    def offset_label(self) -> str:
        return format_offset(self.host_offset_minutes)

    def to_utc(self, local: datetime | None) -> datetime | None:
        if local is None or self.host_offset_minutes is None:
            return None
        return to_utc(local, self.host_offset_minutes)

    @property
    def session_start_utc(self) -> datetime | None:
        return self.to_utc(self.session_start_local)

    @property
    def session_end_utc(self) -> datetime | None:
        return self.to_utc(self.session_end_local)

    def to_json(self) -> dict[str, object]:
        return {
            "host_offset_minutes": self.host_offset_minutes,
            "host_offset_label": self.offset_label,
            "offset_spread_minutes": self.offset_spread_minutes,
            "offset_is_valid": self.offset_is_valid,
            "samples": len(self.samples),
            "network_to_local_minutes": self.network_to_local_minutes,
            "implied_network_offset_minutes": self.implied_network_offset_minutes,
            "name_to_header_minutes": self.name_to_header_minutes,
            "name_to_session_minutes": self.name_to_session_minutes,
            "boot_time_local": self.boot_time_local.isoformat(sep=" ")
            if self.boot_time_local
            else None,
            "uptime_seconds": self.uptime_seconds,
            "uptime_source": self.uptime_source,
            "session_start_utc": self.session_start_utc.isoformat(sep=" ")
            if self.session_start_utc
            else None,
            "session_end_utc": self.session_end_utc.isoformat(sep=" ")
            if self.session_end_utc
            else None,
        }


#: Processes whose running time is the host's uptime. ``lsass`` and ``winlogon``
#: start during boot and never restart on a healthy Windows host.
UPTIME_PROCESSES = ("lsass.exe", "winlogon.exe", "services.exe", "csrss.exe")


def build_clock_model(session: Session, *, network_offset_minutes: float = 60.0) -> ClockModel:
    """Measure every clock relationship the archive supports."""
    model = ClockModel(
        session_start_local=session.session_start,
        session_end_local=session.session_end,
    )

    # --- clock 4 vs clock 5: the host's UTC offset, from the archive alone ---
    for shot in session.screenshots:
        entry = session.archive.entry(shot.file)
        if shot.at is None or entry is None or entry.mtime is None:
            continue
        model.samples.append(
            OffsetSample(
                file=shot.file,
                local=shot.at,
                zip_mtime=entry.mtime,
                delta_minutes=offset_minutes(shot.at, entry.mtime),
                line=shot.line,
            )
        )

    deltas = [s.delta_minutes for s in model.samples]
    offset = median(deltas)
    if offset is not None:
        model.host_offset_minutes = offset
        model.offset_spread_minutes = max(deltas) - min(deltas)
        model.offset_is_valid = is_valid_utc_offset(offset)
        model.nearest_offset_minutes = nearest_valid_offset(offset)

    # --- clock 2 vs clock 3: MOSS's network clock against the host's own ---
    if session.header_started_at and session.monitor_started_at:
        delta = offset_minutes(session.monitor_started_at, session.header_started_at)
        model.network_to_local_minutes = delta
        model.implied_network_offset_minutes = (
            (model.host_offset_minutes - delta) if model.host_offset_minutes is not None else None
        )

    # --- clock 1: the filename, which MOSS writes in UTC ---
    name_ts = session.archive.name_timestamp
    if name_ts and session.header_started_at:
        model.name_to_header_minutes = offset_minutes(session.header_started_at, name_ts)
    if name_ts and model.session_start_utc:
        model.name_to_session_minutes = offset_minutes(model.session_start_utc, name_ts)

    # --- clock 7: boot time from a process that starts at boot ---
    stats_time = model.session_end_local or model.session_start_local
    if stats_time:
        for name in UPTIME_PROCESSES:
            stat = session.stat(name)
            if stat and stat.running_time_s:
                model.uptime_seconds = stat.running_time_s
                model.uptime_source = stat.name
                model.boot_time_local = stats_time - timedelta(seconds=stat.running_time_s)
                break

    return model


def screenshot_gaps(session: Session) -> list[tuple[datetime, datetime, float]]:
    """Consecutive capture gaps as (from, to, seconds), in chronological order."""
    times = sorted(session.screenshot_times)
    return [
        (a, b, (b - a).total_seconds())
        for a, b in zip(times, times[1:], strict=False)
    ]
