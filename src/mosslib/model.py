"""Typed representation of a parsed MOSS session.

Everything here is a plain dataclass with JSON round-tripping. Times are
timezone-naive on purpose: MOSS writes wall-clock strings with no zone, and
inventing one at parse time would destroy the very evidence the clock
analyzers exist to weigh. Which clock a field came from is recorded in the
field name and in :data:`CLOCK_ZONES`.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

#: What each parsed clock is believed to be measured in, per RESEARCH §4.
#: These are *observations from five archives*, not vendor documentation, and
#: the clock analyzer treats them as hypotheses to test rather than as truth.
CLOCK_ZONES = {
    "archive_name": "utc",
    "header_started_at": "moss-network",
    "monitor_started_at": "host-local",
    "screenshot_at": "host-local",
    "zip_mtime": "utc",
    "filecheck_at": "host-local",
}


def _dt(value: datetime | None) -> str | None:
    return value.isoformat(sep=" ") if value else None


def _undt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


@dataclass(frozen=True)
class ParseWarning:
    """A line the parser could not fully understand, kept rather than dropped."""

    line: int
    code: str
    message: str
    raw: str = ""

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> ParseWarning:
        return cls(**data)


@dataclass(frozen=True)
class LogLine:
    """One physical line of ``Logfile.log`` with the grammar rule that claimed it."""

    number: int
    raw: str
    kind: str = "unknown"

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> LogLine:
        return cls(**data)


@dataclass
class ProcessEntry:
    """A ``SHAS2:`` process record — the snapshot MOSS takes at game start."""

    sha256: str
    path: str
    author: str | None = None
    starred: bool = False
    line: int = 0

    @property
    def signed(self) -> bool:
        """An absent ``Author:`` means MOSS found no Authenticode signer."""
        return bool(self.author)

    @property
    def name(self) -> str:
        return self.path.replace("/", "\\").rsplit("\\", 1)[-1]

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> ProcessEntry:
        return cls(**data)


@dataclass
class Screenshot:
    """A capture record from the log. ``crc`` is the SHA-256 of the JPEG bytes."""

    file: str
    at: datetime | None
    crc: str | None = None
    monitor: int | None = None
    backend: str | None = None
    api: str | None = None
    nominal_interval_s: int | None = None
    counters: tuple[int, ...] = ()
    line: int = 0

    @property
    def index(self) -> int | None:
        """``010.JPG`` -> 10. ``None`` when the name is not the NNN.JPG convention."""
        stem = self.file.rsplit(".", 1)[0]
        return int(stem) if stem.isdigit() else None

    def to_json(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["at"] = _dt(self.at)
        data["counters"] = list(self.counters)
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Screenshot:
        data = dict(data)
        data["at"] = _undt(data.get("at"))
        data["counters"] = tuple(data.get("counters") or ())
        return cls(**data)


@dataclass
class CapturedFile:
    """A ``captured:`` record — a game config MOSS copied into the archive."""

    source_path: str
    file: str
    crc: str | None = None
    line: int = 0

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> CapturedFile:
        return cls(**data)


@dataclass
class FileCheck:
    """A ``FileCheck start/end`` block over one captured directory."""

    path: str
    started_at: datetime | None = None
    ended_at: datetime | None = None
    line: int = 0

    def to_json(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["started_at"] = _dt(self.started_at)
        data["ended_at"] = _dt(self.ended_at)
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> FileCheck:
        data = dict(data)
        data["started_at"] = _undt(data.get("started_at"))
        data["ended_at"] = _undt(data.get("ended_at"))
        return cls(**data)


@dataclass
class ProcessStat:
    """A row of the ``Processes statistics`` table. Times are seconds."""

    pid: int
    name: str
    running_time_s: int | None = None
    kernel_time_s: int | None = None
    user_time_s: int | None = None
    line: int = 0

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> ProcessStat:
        return cls(**data)


@dataclass
class Monitor:
    description: str
    serial: str | None = None

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Monitor:
        return cls(**data)


@dataclass
class Device:
    """A PCI / USB / video / drive line, kept as text plus whatever parsed out."""

    description: str
    vendor_id: str | None = None
    product_id: str | None = None
    serial: str | None = None
    driver: str | None = None

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Device:
        return cls(**data)


@dataclass
class Hardware:
    """The host inventory block. Every field is optional — MOSS omits plenty."""

    sign_id1: str | None = None
    user: str | None = None
    hostname: str | None = None
    memory_mb: int | None = None
    physical: str | None = None
    processor: str | None = None
    processor_mhz: int | None = None
    lan_ip: str | None = None
    public_ip: str | None = None
    steam_id: str | None = None
    windows_defender: str | None = None
    os_version: str | None = None
    real_os: str | None = None
    directx: str | None = None
    pci: list[Device] = field(default_factory=list)
    video: list[Device] = field(default_factory=list)
    drives: list[Device] = field(default_factory=list)
    usb: list[Device] = field(default_factory=list)
    monitors: list[Monitor] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            **{
                k: getattr(self, k)
                for k in (
                    "sign_id1", "user", "hostname", "memory_mb", "physical", "processor",
                    "processor_mhz", "lan_ip", "public_ip", "steam_id", "windows_defender",
                    "os_version", "real_os", "directx",
                )
            },
            "pci": [d.to_json() for d in self.pci],
            "video": [d.to_json() for d in self.video],
            "drives": [d.to_json() for d in self.drives],
            "usb": [d.to_json() for d in self.usb],
            "monitors": [m.to_json() for m in self.monitors],
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Hardware:
        data = dict(data)
        for key in ("pci", "video", "drives", "usb"):
            data[key] = [Device.from_json(d) for d in data.get(key) or []]
        data["monitors"] = [Monitor.from_json(m) for m in data.get("monitors") or []]
        return cls(**data)


@dataclass
class HistogramBucket:
    """One column of a MOSS ASCII histogram, reconstructed into numbers."""

    lower: float
    upper: float | None
    count: int

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> HistogramBucket:
        return cls(**data)


@dataclass
class Histogram:
    """A reconstructed ASCII histogram (RESEARCH §3.8).

    ``reconstruction`` records how much of the drawing the parser could read;
    findings derived from a partial reconstruction must say so.
    """

    kind: str  # "interval" | "no_recoil" | "unknown"
    label: str
    keys: list[str] = field(default_factory=list)
    unit: str = "ms"
    total_events: int | None = None
    buckets: list[HistogramBucket] = field(default_factory=list)
    reconstruction: str = "full"  # full | partial | failed
    line: int = 0

    @property
    def counts(self) -> list[int]:
        return [b.count for b in self.buckets]

    def to_json(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["buckets"] = [b.to_json() for b in self.buckets]
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Histogram:
        data = dict(data)
        data["buckets"] = [HistogramBucket.from_json(b) for b in data.get("buckets") or []]
        return cls(**data)


@dataclass
class ArchiveEntry:
    """ZIP-level metadata for one member, independent of anything in the log."""

    name: str
    size: int
    compressed_size: int
    compress_type: int
    crc32: int
    mtime: datetime | None
    order: int
    sha256: str | None = None
    external_attr: int = 0
    create_system: int = 0
    flag_bits: int = 0
    comment: str = ""

    def to_json(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["mtime"] = _dt(self.mtime)
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> ArchiveEntry:
        data = dict(data)
        data["mtime"] = _undt(data.get("mtime"))
        return cls(**data)


@dataclass
class ArchiveInfo:
    """Identity of the submitted file. ``sha256`` is the evidence ID (D1)."""

    filename: str = ""
    sha256: str = ""
    size: int = 0
    name_timestamp: datetime | None = None  # UTC per RESEARCH §2
    name_sign_id: str | None = None
    name_nonce: str | None = None
    entries: list[ArchiveEntry] = field(default_factory=list)

    def entry(self, name: str) -> ArchiveEntry | None:
        for e in self.entries:
            if e.name == name:
                return e
        return None

    def to_json(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "sha256": self.sha256,
            "size": self.size,
            "name_timestamp": _dt(self.name_timestamp),
            "name_sign_id": self.name_sign_id,
            "name_nonce": self.name_nonce,
            "entries": [e.to_json() for e in self.entries],
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> ArchiveInfo:
        data = dict(data)
        data["name_timestamp"] = _undt(data.get("name_timestamp"))
        data["entries"] = [ArchiveEntry.from_json(e) for e in data.get("entries") or []]
        return cls(**data)


@dataclass
class Session:
    """A parsed MOSS session: the log, the ZIP metadata, and nothing inferred."""

    archive: ArchiveInfo = field(default_factory=ArchiveInfo)
    moss_version: str | None = None
    game: str | None = None
    arch: str | None = None
    header_started_at: datetime | None = None
    monitor_started_at: datetime | None = None
    ping_ms: int | None = None
    update: str | None = None
    game_detected: bool = False
    game_process: str | None = None
    hardware: Hardware = field(default_factory=Hardware)
    processes: list[ProcessEntry] = field(default_factory=list)
    screenshots: list[Screenshot] = field(default_factory=list)
    captured_files: list[CapturedFile] = field(default_factory=list)
    file_checks: list[FileCheck] = field(default_factory=list)
    process_stats: list[ProcessStat] = field(default_factory=list)
    stats_ping_ms: int | None = None
    histograms: list[Histogram] = field(default_factory=list)
    global_log_crc: str | None = None
    log_sha256: str | None = None
    log_line_count: int = 0
    lines: list[LogLine] = field(default_factory=list)
    warnings: list[ParseWarning] = field(default_factory=list)
    grammar_version: int = 0
    parser_version: str = ""

    # ------------------------------------------------------------------ views

    @property
    def unknown_lines(self) -> list[LogLine]:
        return [ln for ln in self.lines if ln.kind == "unknown"]

    @property
    def screenshot_times(self) -> list[datetime]:
        return [s.at for s in self.screenshots if s.at]

    @property
    def session_start(self) -> datetime | None:
        """Earliest host-local timestamp: ``Monitor Started`` or first capture."""
        candidates = [t for t in (self.monitor_started_at, *self.screenshot_times) if t]
        return min(candidates) if candidates else None

    @property
    def session_end(self) -> datetime | None:
        times = self.screenshot_times
        return max(times) if times else None

    @property
    def duration_s(self) -> float | None:
        start, end = self.session_start, self.session_end
        return (end - start).total_seconds() if start and end else None

    def line(self, number: int) -> LogLine | None:
        idx = number - 1
        if 0 <= idx < len(self.lines) and self.lines[idx].number == number:
            return self.lines[idx]
        return next((ln for ln in self.lines if ln.number == number), None)

    def stat(self, process_name: str) -> ProcessStat | None:
        low = process_name.lower()
        return next((s for s in self.process_stats if s.name.lower() == low), None)

    # ------------------------------------------------------------------- json

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": "samireader/session/1",
            "parser_version": self.parser_version,
            "grammar_version": self.grammar_version,
            "archive": self.archive.to_json(),
            "moss_version": self.moss_version,
            "game": self.game,
            "arch": self.arch,
            "header_started_at": _dt(self.header_started_at),
            "monitor_started_at": _dt(self.monitor_started_at),
            "ping_ms": self.ping_ms,
            "update": self.update,
            "game_detected": self.game_detected,
            "game_process": self.game_process,
            "hardware": self.hardware.to_json(),
            "processes": [p.to_json() for p in self.processes],
            "screenshots": [s.to_json() for s in self.screenshots],
            "captured_files": [c.to_json() for c in self.captured_files],
            "file_checks": [f.to_json() for f in self.file_checks],
            "process_stats": [p.to_json() for p in self.process_stats],
            "stats_ping_ms": self.stats_ping_ms,
            "histograms": [h.to_json() for h in self.histograms],
            "global_log_crc": self.global_log_crc,
            "log_sha256": self.log_sha256,
            "log_line_count": self.log_line_count,
            "lines": [ln.to_json() for ln in self.lines],
            "warnings": [w.to_json() for w in self.warnings],
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Session:
        return cls(
            archive=ArchiveInfo.from_json(data.get("archive") or {}),
            moss_version=data.get("moss_version"),
            game=data.get("game"),
            arch=data.get("arch"),
            header_started_at=_undt(data.get("header_started_at")),
            monitor_started_at=_undt(data.get("monitor_started_at")),
            ping_ms=data.get("ping_ms"),
            update=data.get("update"),
            game_detected=bool(data.get("game_detected")),
            game_process=data.get("game_process"),
            hardware=Hardware.from_json(data.get("hardware") or {}),
            processes=[ProcessEntry.from_json(p) for p in data.get("processes") or []],
            screenshots=[Screenshot.from_json(s) for s in data.get("screenshots") or []],
            captured_files=[CapturedFile.from_json(c) for c in data.get("captured_files") or []],
            file_checks=[FileCheck.from_json(f) for f in data.get("file_checks") or []],
            process_stats=[ProcessStat.from_json(p) for p in data.get("process_stats") or []],
            stats_ping_ms=data.get("stats_ping_ms"),
            histograms=[Histogram.from_json(h) for h in data.get("histograms") or []],
            global_log_crc=data.get("global_log_crc"),
            log_sha256=data.get("log_sha256"),
            log_line_count=data.get("log_line_count", 0),
            lines=[LogLine.from_json(ln) for ln in data.get("lines") or []],
            warnings=[ParseWarning.from_json(w) for w in data.get("warnings") or []],
            grammar_version=data.get("grammar_version", 0),
            parser_version=data.get("parser_version", ""),
        )
