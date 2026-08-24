"""The tolerant MOSS log parser.

One pass over the log, first-matching-rule-wins, with two small state machines
(the process-statistics table and the ASCII histograms). Unrecognised lines are
kept with their line numbers and surfaced in the report appendix, because an
undocumented format that drifts between versions makes silence dangerous: a
rule that stops firing because MOSS renamed a field must be *visible*.
"""

from __future__ import annotations

from pathlib import Path

from mosslib import grammar as g
from mosslib.archive import MossArchive, open_archive
from mosslib.hashing import sha256_bytes
from mosslib.histogram import NO_RECOIL_RE, SEQUENCE_RE, is_histogram_body, reconstruct
from mosslib.model import (
    CapturedFile,
    Device,
    FileCheck,
    Hardware,
    LogLine,
    Monitor,
    ParseWarning,
    ProcessEntry,
    ProcessStat,
    Screenshot,
    Session,
)
from mosslib.timeutil import parse_datetime, parse_running_time
from mosslib.version import GRAMMAR_VERSION, __version__


def decode_log(data: bytes) -> tuple[str, str]:
    """Decode log bytes, returning (text, encoding-actually-used)."""
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace"), "latin-1/replace"


class _Parser:
    def __init__(self, session: Session):
        self.s = session
        self.hw: Hardware = session.hardware
        self.in_stats = False
        self._last_filecheck: FileCheck | None = None

    # ---------------------------------------------------------------- helpers

    def warn(self, number: int, code: str, message: str, raw: str = "") -> None:
        self.s.warnings.append(ParseWarning(line=number, code=code, message=message, raw=raw))

    def _time(self, number: int, text: str, field: str):
        value = parse_datetime(text)
        if value is None:
            self.warn(number, "bad-timestamp", f"unparseable {field}: {text!r}", text)
        return value

    # ------------------------------------------------------------------- main

    def feed(self, lines: list[str]) -> None:
        index = 0
        while index < len(lines):
            number = index + 1
            raw = lines[index].rstrip("\n").rstrip("\r")

            if SEQUENCE_RE.match(raw) or NO_RECOIL_RE.match(raw):
                consumed = self._histogram(lines, index)
                for offset in range(consumed):
                    body = lines[index + offset].rstrip("\n").rstrip("\r")
                    self.s.lines.append(
                        LogLine(number=index + offset + 1, raw=body, kind="histogram")
                    )
                index += consumed
                continue

            kind = self._line(number, raw)
            self.s.lines.append(LogLine(number=number, raw=raw, kind=kind))
            index += 1

        self.s.log_line_count = len(self.s.lines)

    # -------------------------------------------------------------- histogram

    def _histogram(self, lines: list[str], start: int) -> int:
        block = [lines[start].rstrip("\n").rstrip("\r")]
        cursor = start + 1
        blanks = 0
        while cursor < len(lines):
            candidate = lines[cursor].rstrip("\n").rstrip("\r")
            if SEQUENCE_RE.match(candidate) or NO_RECOIL_RE.match(candidate):
                break
            if not candidate.strip():
                blanks += 1
                if blanks > 1:
                    break
                block.append(candidate)
                cursor += 1
                continue
            if not is_histogram_body(candidate):
                break
            blanks = 0
            block.append(candidate)
            cursor += 1

        while block and not block[-1].strip():
            block.pop()
        hist = reconstruct(block, line_number=start + 1)
        self.s.histograms.append(hist)
        if hist.reconstruction == "failed":
            self.warn(
                start + 1,
                "histogram-unreadable",
                f"could not reconstruct histogram {hist.label!r}",
                block[0],
            )
        return max(len(block), 1)

    # ------------------------------------------------------------- line rules

    def _line(self, number: int, raw: str) -> str:  # noqa: C901 - a grammar dispatch table
        s = self.s

        if not raw.strip():
            return "blank"

        # The statistics table runs until a line stops looking like a row.
        if self.in_stats:
            row = g.STATS_ROW_RE.match(raw)
            if row:
                s.process_stats.append(
                    ProcessStat(
                        pid=int(row.group("pid")),
                        name=row.group("name"),
                        running_time_s=parse_running_time(row.group("running")),
                        kernel_time_s=parse_running_time(row.group("kernel")),
                        user_time_s=parse_running_time(row.group("user")),
                        line=number,
                    )
                )
                return "stats_row"
            if g.STATS_COLUMNS_RE.match(raw):
                return "stats_columns"
            self.in_stats = False

        m = g.HEADER_RE.match(raw)
        if m:
            s.header_started_at = self._time(number, m.group("ts"), "SHAS2 mode started")
            s.game = m.group("game")
            s.arch = m.group("arch")
            return "header"

        m = g.PROCESS_RE.match(raw)
        if m:
            s.processes.append(
                ProcessEntry(
                    sha256=m.group("sha").lower(),
                    path=m.group("path"),
                    author=(m.group("author") or None),
                    starred=bool(m.group("star")),
                    line=number,
                )
            )
            return "process"

        m = g.FILE_RECORD_RE.match(raw)
        if m:
            return self._file_record(number, raw, m)

        m = g.STATS_HEADER_RE.match(raw)
        if m:
            self.in_stats = True
            if m.group("ping"):
                s.stats_ping_ms = int(m.group("ping"))
            return "stats_header"

        m = g.MONITOR_STARTED_RE.match(raw)
        if m:
            s.monitor_started_at = self._time(number, m.group("ts"), "Monitor Started")
            return "monitor_started"

        m = g.FILECHECK_START_RE.match(raw)
        if m:
            check = FileCheck(
                path=m.group("path"),
                started_at=self._time(number, m.group("ts"), "FileCheck start"),
                line=number,
            )
            s.file_checks.append(check)
            self._last_filecheck = check
            return "filecheck_start"

        m = g.FILECHECK_END_RE.match(raw)
        if m:
            ended = self._time(number, m.group("ts"), "FileCheck end")
            target = next(
                (c for c in reversed(s.file_checks) if c.path == m.group("path") and not c.ended_at),
                self._last_filecheck,
            )
            if target is not None:
                target.ended_at = ended
            else:
                self.warn(number, "orphan-filecheck-end", "FileCheck end without a start", raw)
            return "filecheck_end"

        if g.GAME_DETECTED_RE.match(raw):
            s.game_detected = True
            if s.processes:
                s.game_process = s.processes[-1].path
            return "game_detected"

        m = g.GLOBAL_CRC_RE.match(raw)
        if m:
            s.global_log_crc = m.group("crc").lower()
            return "global_crc"

        return self._inventory(number, raw)

    def _file_record(self, number: int, raw: str, m) -> str:
        s = self.s
        prefix = m.group("prefix")
        name = m.group("file").strip()
        crc = m.group("crc").lower()

        captured = g.CAPTURED_PREFIX_RE.match(prefix)
        if captured:
            s.captured_files.append(
                CapturedFile(
                    source_path=captured.group("path"), file=name, crc=crc, line=number
                )
            )
            return "captured_file"

        at = g.AT_TIME_RE.search(prefix)
        if not at:
            self.warn(number, "file-record-no-time", "file record without a timestamp", raw)
        mon = g.MONITOR_INDEX_RE.search(prefix)
        each = g.EACH_RE.search(prefix)
        backend = g.BACKEND_RE.match(prefix)
        api = g.API_RE.search(prefix)
        s.screenshots.append(
            Screenshot(
                file=name,
                at=self._time(number, at.group("ts"), "screenshot time") if at else None,
                crc=crc,
                monitor=int(mon.group("index")) if mon else None,
                backend=backend.group("backend") if backend else None,
                api=api.group("api") if api else None,
                nominal_interval_s=int(each.group("seconds")) if each else None,
                counters=tuple(int(c.group("n")) for c in g.COUNTER_RE.finditer(prefix)),
                line=number,
            )
        )
        return "screenshot"

    def _inventory(self, number: int, raw: str) -> str:  # noqa: C901 - flat dispatch
        s, hw = self.s, self.hw

        m = g.PING_RE.match(raw)
        if m:
            s.ping_ms = int(m.group("ms"))
            return "ping"

        m = g.VERSION_RE.match(raw)
        if m:
            s.moss_version = m.group("version").replace(",", ".").strip()
            return "version"

        m = g.UPDATE_RE.match(raw)
        if m:
            s.update = m.group("value")
            return "update"

        m = g.DIRECTX_RE.match(raw)
        if m:
            hw.directx = m.group("value")
            return "directx"

        m = g.OS_RE.match(raw)
        if m:
            hw.os_version = m.group("value")
            return "os"

        m = g.REAL_OS_RE.match(raw)
        if m:
            hw.real_os = m.group("value")
            return "real_os"

        m = g.PCI_RE.match(raw)
        if m:
            hw.pci.append(
                Device(
                    description=m.group("desc"),
                    vendor_id=m.group("vid"),
                    product_id=m.group("did"),
                )
            )
            return "pci"

        m = g.MEMORY_RE.match(raw)
        if m:
            hw.memory_mb = int(m.group("mb"))
            return "memory"

        m = g.PHYSICAL_RE.match(raw)
        if m:
            hw.physical = m.group("value")
            return "physical"

        m = g.SIGN_ID_RE.match(raw)
        if m:
            hw.sign_id1 = m.group("value")
            return "sign_id"

        m = g.USER_RE.match(raw)
        if m:
            hw.user = (m.group("user") or "").strip() or None
            hw.hostname = (m.group("host") or "").strip() or None
            return "user"

        m = g.DRIVE_RE.match(raw)
        if m:
            hw.drives.append(
                Device(description=m.group("desc"), serial=m.group("serial") or None)
            )
            return "drive"

        m = g.NET_RE.match(raw)
        if m:
            hw.lan_ip = m.group("lan")
            hw.public_ip = m.group("wan")
            return "net"

        m = g.VIDEO_RE.match(raw)
        if m:
            hw.video.append(
                Device(description=m.group("desc"), driver=m.group("driver") or None)
            )
            return "video"

        m = g.MONITOR_RE.match(raw)
        if m:
            hw.monitors.append(
                Monitor(description=m.group("desc"), serial=m.group("serial") or None)
            )
            return "monitor"

        m = g.USB_RE.match(raw)
        if m:
            hw.usb.append(
                Device(
                    description=m.group("desc"),
                    serial=m.group("serial"),
                    vendor_id=m.group("vid"),
                    product_id=m.group("did"),
                )
            )
            return "usb"

        m = g.PROCESSOR_RE.match(raw)
        if m:
            hw.processor = m.group("name")
            hw.processor_mhz = int(m.group("mhz"))
            return "processor"

        m = g.DEFENDER_RE.match(raw)
        if m:
            hw.windows_defender = m.group("value")
            return "defender"

        m = g.STEAM_ID_RE.match(raw)
        if m:
            hw.steam_id = m.group("value") or None
            return "steam_id"

        if g.SEARCH_FILES_RE.match(raw):
            return "search_files"

        return "unknown"


def parse_log_text(text: str, session: Session | None = None) -> Session:
    """Parse the contents of ``Logfile.log``. Never raises on malformed input."""
    s = session or Session()
    s.parser_version = __version__
    s.grammar_version = GRAMMAR_VERSION
    _Parser(s).feed(text.splitlines())
    return s


def parse_log(path: str | Path) -> Session:
    """Parse a bare log file that is not inside an archive."""
    data = Path(path).read_bytes()
    text, encoding = decode_log(data)
    session = Session()
    session.log_sha256 = sha256_bytes(data)
    parse_log_text(text, session)
    if encoding not in ("utf-8-sig",):
        session.warnings.append(
            ParseWarning(line=0, code="encoding-fallback", message=f"log decoded as {encoding}")
        )
    return session


def parse_open_archive(archive: MossArchive) -> Session:
    """Parse a already-open archive, attaching its identity and ZIP structure."""
    session = Session(archive=archive.info)
    log_name = archive.find_log()
    if log_name is None:
        session.parser_version = __version__
        session.grammar_version = GRAMMAR_VERSION
        session.warnings.append(
            ParseWarning(line=0, code="no-log", message="archive contains no Logfile.log")
        )
        return session

    data = archive.read(log_name)
    text, encoding = decode_log(data)
    session.log_sha256 = sha256_bytes(data)
    parse_log_text(text, session)
    if encoding != "utf-8-sig":
        session.warnings.append(
            ParseWarning(line=0, code="encoding-fallback", message=f"log decoded as {encoding}")
        )
    if log_name.lower() != "logfile.log":
        session.warnings.append(
            ParseWarning(
                line=0,
                code="unexpected-log-name",
                message=f"log found as {log_name!r}, expected 'Logfile.log'",
            )
        )
    return session


def parse_archive(path: str | Path) -> Session:
    """Open a MOSS ZIP and parse it into a :class:`Session`."""
    with open_archive(path) as archive:
        return parse_open_archive(archive)
