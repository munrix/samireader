"""Safe access to a MOSS ZIP.

Every archive is treated as hostile input (PLAN §4): it was produced on a
machine controlled by the person it may incriminate. Nothing is executed,
nothing is written outside a caller-supplied directory, and expansion is
capped in both total bytes and member count.

The reader also captures ZIP *structure* — entry order, compression method,
mtimes, flag bits — because a rebuilt archive rarely reproduces MOSS's own
write pattern, and that structure is evidence in its own right.
"""

from __future__ import annotations

import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from mosslib.hashing import sha256_file, sha256_stream
from mosslib.model import ArchiveEntry, ArchiveInfo

#: Defaults sized generously against the observed corpus (48–77 JPEGs, up to
#: 60 configs, one log) with two orders of magnitude of headroom.
MAX_TOTAL_BYTES = 8 * 1024**3
MAX_ENTRIES = 20_000
MAX_MEMBER_BYTES = 512 * 1024**2
MAX_COMPRESSION_RATIO = 1000


class ArchiveError(Exception):
    """The file is not usable as a MOSS archive, or is unsafe to expand."""


@dataclass
class ArchiveMember:
    """A member the caller may read. Bytes are only materialised on demand."""

    entry: ArchiveEntry
    _zip: zipfile.ZipFile

    def read(self, limit: int = MAX_MEMBER_BYTES) -> bytes:
        with self._zip.open(self.entry.name) as fh:
            data = fh.read(limit + 1)
        if len(data) > limit:
            raise ArchiveError(f"member {self.entry.name!r} exceeds {limit} bytes")
        return data

    def sha256(self, limit: int = MAX_MEMBER_BYTES) -> str:
        with self._zip.open(self.entry.name) as fh:
            digest, size = sha256_stream(fh, limit=limit)
        if size > limit:
            raise ArchiveError(f"member {self.entry.name!r} exceeds {limit} bytes")
        return digest


def _entry_mtime(info: zipfile.ZipInfo) -> datetime | None:
    try:
        return datetime(*info.date_time)
    except (ValueError, TypeError):
        return None


def _safe_name(name: str) -> bool:
    """Reject absolute paths, drive letters, traversal and NUL — zip-slip guard."""
    if not name or "\x00" in name:
        return False
    if name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":"):
        return False
    parts = name.replace("\\", "/").split("/")
    return ".." not in parts


class MossArchive:
    """Read-only view over a MOSS ZIP, with structure captured at open time."""

    def __init__(self, path: str | Path, zf: zipfile.ZipFile, info: ArchiveInfo):
        self.path = Path(path)
        self._zip = zf
        self.info = info

    # ------------------------------------------------------------------ dunder

    def __enter__(self) -> MossArchive:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._zip.close()

    # ------------------------------------------------------------------ access

    @property
    def names(self) -> list[str]:
        return [e.name for e in self.info.entries]

    def member(self, name: str) -> ArchiveMember:
        entry = self.info.entry(name)
        if entry is None:
            raise ArchiveError(f"no such member: {name!r}")
        return ArchiveMember(entry, self._zip)

    def read(self, name: str, limit: int = MAX_MEMBER_BYTES) -> bytes:
        return self.member(name).read(limit=limit)

    def sha256(self, name: str) -> str:
        return self.member(name).sha256()

    def find_log(self) -> str | None:
        """MOSS writes ``Logfile.log``; match case-insensitively and tolerate a prefix dir."""
        candidates = [n for n in self.names if n.lower().replace("\\", "/").endswith("logfile.log")]
        if not candidates:
            candidates = [n for n in self.names if n.lower().endswith(".log")]
        return sorted(candidates, key=len)[0] if candidates else None

    def hash_all(self) -> dict[str, str]:
        """SHA-256 every member. This is the per-file tamper check's raw input."""
        return {e.name: self.member(e.name).sha256() for e in self.info.entries}


def parse_archive_name(filename: str) -> tuple[datetime | None, str | None, str | None]:
    """``20240328_180012_1434136903_369969994.zip`` -> (utc time, sign id, nonce)."""
    stem = Path(filename).name
    if stem.lower().endswith(".zip"):
        stem = stem[:-4]
    parts = stem.split("_")
    if len(parts) < 2:
        return None, None, None
    stamp: datetime | None = None
    if len(parts[0]) == 8 and len(parts[1]) == 6 and parts[0].isdigit() and parts[1].isdigit():
        try:
            stamp = datetime.strptime(parts[0] + parts[1], "%Y%m%d%H%M%S")
        except ValueError:
            stamp = None
    sign = parts[2] if len(parts) > 2 else None
    nonce = parts[3] if len(parts) > 3 else None
    return stamp, sign, nonce


@contextmanager
def open_archive(
    path: str | Path,
    *,
    max_entries: int = MAX_ENTRIES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> Iterator[MossArchive]:
    """Open a MOSS archive, capturing its identity and structure.

    Raises :class:`ArchiveError` for anything that is not a readable ZIP or that
    trips a resource guard. Nothing is extracted to disk.
    """
    path = Path(path)
    if not path.is_file():
        raise ArchiveError(f"not a file: {path}")
    if not zipfile.is_zipfile(path):
        raise ArchiveError(f"not a ZIP archive: {path}")

    zf = zipfile.ZipFile(path)
    try:
        infolist = zf.infolist()
        if len(infolist) > max_entries:
            raise ArchiveError(f"archive has {len(infolist)} entries (limit {max_entries})")

        entries: list[ArchiveEntry] = []
        total = 0
        for order, zi in enumerate(infolist):
            if not _safe_name(zi.filename):
                raise ArchiveError(f"unsafe member path: {zi.filename!r}")
            if zi.is_dir():
                continue
            total += zi.file_size
            if total > max_total_bytes:
                raise ArchiveError(f"expanded size exceeds {max_total_bytes} bytes")
            if zi.compress_size and zi.file_size / max(zi.compress_size, 1) > MAX_COMPRESSION_RATIO:
                raise ArchiveError(f"member {zi.filename!r} has an implausible compression ratio")
            entries.append(
                ArchiveEntry(
                    name=zi.filename,
                    size=zi.file_size,
                    compressed_size=zi.compress_size,
                    compress_type=zi.compress_type,
                    crc32=zi.CRC,
                    mtime=_entry_mtime(zi),
                    order=order,
                    external_attr=zi.external_attr,
                    create_system=zi.create_system,
                    flag_bits=zi.flag_bits,
                    comment=(zi.comment or b"").decode("utf-8", "replace"),
                )
            )

        stamp, sign, nonce = parse_archive_name(path.name)
        info = ArchiveInfo(
            filename=path.name,
            sha256=sha256_file(path),
            size=path.stat().st_size,
            name_timestamp=stamp,
            name_sign_id=sign,
            name_nonce=nonce,
            entries=entries,
        )
        archive = MossArchive(path, zf, info)
        yield archive
    finally:
        zf.close()
