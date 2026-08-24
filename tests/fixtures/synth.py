"""Build synthetic MOSS archives for tests.

There are no real archives in this repository and there never will be: they are
personal data (RESEARCH §8). The corpus is instead *reconstructed* from the log
grammar documented in RESEARCH §3, which means the tests prove the parser
matches the documented format — not that it matches an undocumented reality.
That distinction is stated in the README, and closing it needs privacy-scrubbed
real archives.

The builder produces internally consistent archives by default and takes
explicit switches for each way an archive can be wrong, so every analyzer has a
positive and a negative case.
"""

from __future__ import annotations

import hashlib
import random
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

# --------------------------------------------------------------------- JPEGs


def jpeg_bytes(width: int, height: int, size: int, seed: int, *, truncated: bool = False) -> bytes:
    """A structurally valid JPEG of an approximate size. No pixels are encoded."""
    header = bytearray(b"\xff\xd8")
    header += b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    header += b"\xff\xc0\x00\x11\x08"
    header += height.to_bytes(2, "big") + width.to_bytes(2, "big")
    header += b"\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01"
    header += b"\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00"
    rng = random.Random(seed)
    payload_len = max(size - len(header) - 2, 16)
    payload = bytes(rng.randrange(0, 0xFE) for _ in range(payload_len))
    if truncated:
        return bytes(header) + payload
    return bytes(header) + payload + b"\xff\xd9"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- histograms


def render_histogram(keys: list[str], buckets: dict[int, int], *, unit: str = "ms",
                     step: int = 5, span: int = 140) -> list[str]:
    """Draw a distribution the way MOSS draws it (RESEARCH §3.8)."""
    columns = span // step
    counts = [buckets.get(i * step, 0) for i in range(columns)]
    total = sum(counts)
    peak = max(counts) if counts else 0

    if keys:
        title = " sequence " + " ".join(f"[{k}]" for k in keys) + " : interval distribution"
    else:
        title = " Mouse down moves ( no recoil )"
    lines = [title, f"    ^  {total} events"]
    for level in range(peak, 0, -1):
        row = [" "] * (5 + columns * 5)
        for index, count in enumerate(counts):
            if count >= level:
                row[5 + index * 5] = "X"
        lines.append(f"{level:3d} |" + "".join(row[5:]).rstrip())
    axis = "  " + "--+" + " -- +" * (columns - 1) + f"  > {span} {unit}"
    lines.append(axis)
    labels = [" "] * (5 + columns * 5)
    for index in range(columns):
        text = str(index * step)
        labels[5 + index * 5 : 5 + index * 5 + len(text)] = list(text)
    lines.append("".join(labels).rstrip())
    return lines


# -------------------------------------------------------------------- options


@dataclass
class Capture:
    name: str
    at: datetime
    data: bytes


@dataclass
class Synth:
    """One archive to build. Defaults produce a clean, internally consistent one."""

    directory: Path
    user: str = "szazi"
    hostname: str = "NESKIN"
    sign_id: str = "1434136903"
    nonce: str = "369969994"
    game: str = "Rainbow Six"
    moss_version: str = "6,6,9,0"
    start_local: datetime = datetime(2024, 3, 28, 21, 0, 18)
    host_offset_minutes: int = 180
    network_offset_minutes: int = 60
    captures: int = 20
    interval_s: int = 60
    interval_jitter_s: int = 25
    width: int = 3840
    height: int = 1089
    median_size: int = 150_000
    seed: int = 7

    # --- deliberate defects -------------------------------------------------
    tamper_capture: str | None = None      # rewrite this capture's bytes after hashing
    remove_capture: str | None = None      # log it but leave it out of the ZIP
    remove_log_record: str | None = None   # keep the file but delete its log line
    extra_member: str | None = None        # add a member the log never mentions
    drop_footer: bool = False              # no 'Global log CRC' line
    drop_header: bool = False              # no 'SHAS2 mode started' line
    uniform_mtimes: bool = False           # re-zip signature
    stored_compression: bool = False
    #: The host's system clock is wrong. Everything the OS stamps moves with it —
    #: log-local times, ZIP entry times and the archive filename — while MOSS's
    #: network-synced header does not. That asymmetry is the detection (RESEARCH §4).
    clock_skew_minutes: int = 0
    #: The log alone was edited after the fact; ZIP entry times still say otherwise.
    log_time_shift_minutes: int = 0
    mid_session_shift_minutes: int = 0     # move the clock partway through
    late_members: tuple[str, ...] = ()     # these members are stamped after the session
    blank_frames: tuple[int, ...] = ()     # indices rendered far below median size
    duplicate_frames: tuple[int, ...] = () # indices byte-identical to their predecessor
    truncated_frames: tuple[int, ...] = ()
    resolution_change_at: int | None = None
    reverse_zip_order: bool = False
    entries_after_session_minutes: int = 0
    uptime_hours: float = 12.0
    include_histograms: bool = True
    #: MOSS's footer digest algorithm is undocumented (RESEARCH §3.9). By default
    #: the builder writes a value no candidate algorithm can reproduce, because
    #: that is the situation on a real archive. Set this to exercise the path
    #: where a candidate *does* match — it asserts the mechanism works, never
    #: that this is how MOSS actually computes it.
    footer_is_sha256_of_body: bool = False
    fast_double_click: bool = False
    processes: list[tuple[str, str | None]] = field(default_factory=list)
    configs: dict[str, str] = field(default_factory=dict)
    vulkan_layers: str = "VK_LAYER_OW_OBS_HOOK;VK_LAYER_OW_OVERLAY"
    profiles: int = 1
    game_detected: bool = True
    defender: str = "enabled"

    # ------------------------------------------------------------------ build

    def _capture_times(self) -> list[datetime]:
        rng = random.Random(self.seed)
        times, moment = [], self.start_local + timedelta(seconds=32)
        for index in range(self.captures):
            times.append(moment)
            step = self.interval_s + rng.randint(-self.interval_jitter_s, self.interval_jitter_s)
            moment += timedelta(seconds=max(step, 2))
            if self.mid_session_shift_minutes and index == self.captures // 2:
                moment += timedelta(minutes=self.mid_session_shift_minutes)
        return times

    def build(self) -> Path:
        rng = random.Random(self.seed)
        times = self._capture_times()

        captures: list[Capture] = []
        previous: bytes | None = None
        for index, at in enumerate(times, start=1):
            name = f"{index:03d}.JPG"
            width, height = self.width, self.height
            if self.resolution_change_at is not None and index >= self.resolution_change_at:
                width, height = 1920, 1080
            size = self.median_size + rng.randint(-20_000, 20_000)
            if index in self.blank_frames:
                size = 40_000
            data = jpeg_bytes(
                width, height, size, seed=self.seed * 1000 + index,
                truncated=index in self.truncated_frames,
            )
            if index in self.duplicate_frames and previous is not None:
                data = previous
            captures.append(Capture(name=name, at=at, data=data))
            previous = data

        configs: dict[str, bytes] = {}
        for profile in range(1, self.profiles + 1):
            name = f"GameSettings.ini.{profile:03d}"
            text = self.configs.get(name) or (
                "[DISPLAY]\n"
                "RefreshRate=240\n"
                "DefaultFOV=74\n"
                "[INPUT]\n"
                "MouseSensitivityMultiplierUnit=0.020000\n"
                f"VulkanWhitelistedLayers={self.vulkan_layers}\n"
                "Console=0\n"
                f"GPUAdapterInfo=NVIDIA GeForce RTX 3080\n"
            )
            configs[name] = text.encode("utf-8")

        log = self._log(captures, configs)
        log_bytes = log.encode("utf-8")

        utc_start = (
            self.start_local
            - timedelta(minutes=self.host_offset_minutes)
            + timedelta(minutes=self.clock_skew_minutes)
        )
        archive_name = (
            f"{utc_start.strftime('%Y%m%d_%H%M%S')}_{self.sign_id}_{self.nonce}.zip"
        )
        path = self.directory / archive_name
        path.parent.mkdir(parents=True, exist_ok=True)

        members: list[tuple[str, bytes, datetime]] = []
        for capture in captures:
            if capture.name == self.remove_capture:
                continue
            data = capture.data
            if capture.name == self.tamper_capture:
                data = data[:-3] + b"\x01\x02\xff\xd9"
            mtime = (
                capture.at
                - timedelta(minutes=self.host_offset_minutes)
                + timedelta(minutes=self.clock_skew_minutes)
            )
            members.append((capture.name, data, mtime))
        for name, data in configs.items():
            members.append((name, data, utc_start))
        log_mtime = (
            (times[-1] if times else self.start_local)
            - timedelta(minutes=self.host_offset_minutes)
            + timedelta(minutes=self.clock_skew_minutes)
            + timedelta(seconds=5)
        )
        members.append(("Logfile.log", log_bytes, log_mtime))
        if self.extra_member:
            members.append((self.extra_member, b"added after the fact\n", log_mtime))

        if self.uniform_mtimes:
            members = [(n, d, log_mtime) for n, d, _ in members]
        if self.entries_after_session_minutes:
            shift = timedelta(minutes=self.entries_after_session_minutes)
            members = [
                (n, d, (m + shift) if n.endswith(".JPG") else m) for n, d, m in members
            ]
        if self.late_members:
            members = [
                (n, d, m + timedelta(hours=2) if n in self.late_members else m)
                for n, d, m in members
            ]
        if self.reverse_zip_order:
            members.reverse()

        method = zipfile.ZIP_STORED if self.stored_compression else zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(path, "w", compression=method) as zf:
            for name, data, mtime in members:
                info = zipfile.ZipInfo(name, date_time=mtime.timetuple()[:6])
                info.compress_type = method
                zf.writestr(info, data)
        return path

    # -------------------------------------------------------------------- log

    def _log(self, captures: list[Capture], configs: dict[str, bytes]) -> str:
        log_shift = self.clock_skew_minutes + self.log_time_shift_minutes
        local_start = self.start_local + timedelta(minutes=log_shift)
        header_time = (
            self.start_local
            - timedelta(minutes=self.host_offset_minutes)
            + timedelta(minutes=self.network_offset_minutes)
            - timedelta(seconds=6)
        )
        lines: list[str] = []
        if not self.drop_header:
            lines.append(
                f"SHAS2 mode started at {header_time:%Y-%m-%d %H:%M:%S} for {self.game} on x64"
            )
        lines += [
            " ping:68ms",
            "update 6",
            "DirectX version is 12.0( )",
            "OS is 10.0 64 bit build 19045",
            "Real OS Windows 10 or 11",
            "PCI: NVIDIA GeForce RTX 3080 (0x10DE-0x220A)",
            "memory: 16237 MB",
            f"version: MOSS {self.moss_version}",
            "Physical: Micro-Star International Co., Ltd.MS-7D24PRO B660M-P DDR4 WIFI (MS-7D24)",
            f"Sign ID1: {self.sign_id}",
            f"User: {self.user}@{self.hostname}",
            "Drive: WD_BLACK SN770 1TB serial: 21492H803129",
            "Net: 192.168.100.33 Public: 90.148.144.xxx",
            "Video: NVIDIA GeForce RTX 3080 driver : 31.0.15.3742",
            "Monitor: ZOWIE XL LCD serial: EBB9N00443SL0",
            "Usb: Logitech PRO Gaming Keyboard (0C6832703832) (0x46D-0xC339)",
            "processor BIOS details 2500 MHz by 25.00*100. 13th Gen Intel(R) Core(TM) i5-13400F",
            f"Monitor Started at {local_start:%Y/%m/%d %H:%M:%S}",
            f"Windows Defender: {self.defender}",
            "SteamId: 0",
        ]

        processes = self.processes or [
            (r"C:\Windows\System32\lsass.exe", "Microsoft Windows Publisher"),
            (r"C:\Windows\explorer.exe", "Microsoft Windows"),
            (rf"C:\Users\{self.user}\AppData\Local\Discord\app-1.0.9\Discord.exe", "Discord Inc."),
            (r"C:\Program Files\Ubisoft\Ubisoft Game Launcher\upc.exe", "UBISOFT ENTERTAINMENT INC."),
        ]
        for index, (path, author) in enumerate(processes):
            digest = sha256(f"{path}{index}".encode())
            author_part = f"Author: {author} " if author else ""
            lines.append(f"SHAS2: {digest} {author_part}process: {path}")

        game_path = r"C:\Program Files\Ubisoft\Rainbow Six Siege\RainbowSix_Vulkan.exe"
        lines.append(
            f"SHAS2: {sha256(game_path.encode())} Author: UBISOFT ENTERTAINMENT INC. "
            f"process: {game_path}"
        )
        if self.game_detected:
            lines.append("Game Detected")

        check_time = self.start_local + timedelta(minutes=log_shift) - timedelta(minutes=9)
        source = rf"C:\USERS\{self.user.upper()}\APPDATA\LOCAL\UBISOFT\R6SIEGE"
        lines.append(f"FileCheck start for {source} at {check_time:%Y/%m/%d %H:%M:%S}:")
        lines.append("Search for files")
        for name, data in configs.items():
            lines.append(
                rf"captured: C:\Users\{self.user}\Documents\My Games\Rainbow Six - Siege"
                rf"\GameSettings.ini file: {name}- Zip CRC: {sha256(data)}"
            )
        lines.append(f"FileCheck end for {source} at {check_time:%Y/%m/%d %H:%M:%S}:")

        for index, capture in enumerate(captures, start=1):
            if capture.name == self.remove_log_record:
                continue
            at = capture.at + timedelta(minutes=log_shift)
            lines.append(
                f" Dxgi ...({60 + index})(Mon 1) DX11({300 + index}) : Each {self.interval_s} "
                f"at {at:%Y/%m/%d %H:%M:%S} file: {capture.name}- Zip CRC: {sha256(capture.data)}"
            )

        if self.include_histograms:
            if self.fast_double_click:
                buckets = {0: 1, 5: 3, 10: 9, 15: 12, 20: 6, 25: 2}
            else:
                buckets = {80: 2, 85: 4, 90: 5, 95: 6, 100: 5, 105: 4, 110: 3, 115: 2, 120: 1}
            lines += render_histogram(["LEFT CLICK", "LEFT CLICK"], buckets)
            lines.append("")
            lines += render_histogram([], {0: 2, 5: 4, 10: 3, 15: 2, 20: 1}, unit="px", span=150, step=5)
            lines.append("")

        lines.append("Processes statistics  ping:274")
        lines.append("PID\tRunning Time\tKernel Time\tUser Time\tName")
        uptime = timedelta(hours=self.uptime_hours)
        days = uptime.days
        hours, rem = divmod(uptime.seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        lines.append(
            f"896\t{days:02d}:{hours:02d}:{minutes:02d}:{seconds:02d} \t00:02:52 \t00:02:44 \tlsass.exe"
        )
        lines.append("1204\t00:01:12:11 \t00:00:31 \t00:04:02 \texplorer.exe")

        if not self.drop_footer:
            body = "\n".join(lines)
            digest = (
                sha256(body.encode())
                if self.footer_is_sha256_of_body
                else sha256(b"unknown-algorithm:" + body.encode())
            )
            lines.append(f"Global log CRC: {digest}")
        return "\n".join(lines) + "\n"


def clean_archive(directory: Path, **overrides) -> Path:
    return Synth(directory=directory, **overrides).build()
