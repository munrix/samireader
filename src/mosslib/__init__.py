"""mosslib — a tolerant, versioned parser for MOSS anti-cheat session archives.

The library is deliberately dependency-free and side-effect-free: it reads an
archive (or a raw log) and returns a typed :class:`~mosslib.model.Session`.
All judgement about what the data *means* lives in :mod:`sami`, never here.

Design rules, in priority order:

1. **Never drop a line.** Every log line ends up in ``Session.lines`` with a
   ``kind``; unrecognised lines are kept as ``unknown`` with their line number.
   MOSS's format is undocumented and drifts between versions.
2. **Never guess a value.** A field that cannot be parsed stays ``None`` and a
   :class:`~mosslib.model.ParseWarning` records why.
3. **Round-trip.** ``Session`` serialises to JSON and back without loss.
"""

from mosslib.archive import ArchiveError, ArchiveMember, MossArchive, open_archive
from mosslib.model import (
    CapturedFile,
    FileCheck,
    Hardware,
    Histogram,
    LogLine,
    ParseWarning,
    ProcessEntry,
    ProcessStat,
    Screenshot,
    Session,
)
from mosslib.parser import parse_archive, parse_log, parse_log_text
from mosslib.version import __version__

__all__ = [
    "ArchiveError",
    "ArchiveMember",
    "CapturedFile",
    "FileCheck",
    "Hardware",
    "Histogram",
    "LogLine",
    "MossArchive",
    "ParseWarning",
    "ProcessEntry",
    "ProcessStat",
    "Screenshot",
    "Session",
    "__version__",
    "open_archive",
    "parse_archive",
    "parse_log",
    "parse_log_text",
]
