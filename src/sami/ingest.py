"""Ingest: turn a submitted file into evidence with an identity and a paper trail.

Per DECISIONS D1 the output feeds disciplinary proceedings, so chain of custody
is P0, not a later feature. Ingest does three things and nothing else:

1. hashes the submitted file — the SHA-256 *is* the evidence ID;
2. reads everything the analyzers will need in one pass (member hashes, JPEG
   headers, config text), so no analyzer ever re-opens attacker-controlled input;
3. appends an immutable custody record describing what was ingested, by whom,
   with which tool and rule versions.
"""

from __future__ import annotations

import getpass
import json
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mosslib.archive import ArchiveError, open_archive
from mosslib.jpeg import JpegInfo, inspect
from mosslib.model import Session
from mosslib.parser import decode_log, parse_open_archive
from sami.version import RULESET_VERSION, __version__

MAX_CONFIG_BYTES = 4 * 1024 * 1024
CUSTODY_FILENAME = "chain-of-custody.jsonl"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def default_actor() -> str:
    """Who is running the tool. Recorded, never used for access control."""
    try:
        user = getpass.getuser()
    except Exception:  # pragma: no cover - getpass can fail on odd hosts
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    try:
        host = socket.gethostname()
    except Exception:  # pragma: no cover
        host = "unknown"
    return f"{user}@{host}"


@dataclass
class ArchiveScan:
    """Everything read out of one archive, in one pass, before analysis starts."""

    path: Path
    session: Session
    member_sha256: dict[str, str] = field(default_factory=dict)
    jpegs: dict[str, JpegInfo] = field(default_factory=dict)
    configs: dict[str, str] = field(default_factory=dict)
    #: Raw log text, kept so the undocumented footer digest can be tested
    #: against candidate algorithms (:mod:`mosslib.logcrc`). Logs are ~1000 lines.
    log_text: str = ""
    ingested_at: datetime = field(default_factory=utcnow)
    label: str | None = None  # player/team label supplied by the operator

    @property
    def evidence_id(self) -> str:
        return self.session.archive.sha256

    @property
    def short_id(self) -> str:
        return self.evidence_id[:12] if self.evidence_id else "unknown"

    @property
    def display_name(self) -> str:
        return self.label or self.session.hardware.user or self.path.name


def _is_config(name: str, prefixes: list[str]) -> bool:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    return any(base.lower().startswith(p.lower()) for p in prefixes)


def scan_archive(
    path: str | Path,
    *,
    config_prefixes: list[str] | None = None,
    label: str | None = None,
) -> ArchiveScan:
    """Open, hash and parse an archive. Raises :class:`ArchiveError` if unusable."""
    path = Path(path)
    prefixes = config_prefixes or ["GameSettings.ini"]
    with open_archive(path) as archive:
        session = parse_open_archive(archive)
        scan = ArchiveScan(path=path, session=session, label=label)
        log_name = archive.find_log()
        if log_name:
            scan.log_text = decode_log(archive.read(log_name))[0]
        for entry in session.archive.entries:
            digest = archive.member(entry.name).sha256()
            entry.sha256 = digest
            scan.member_sha256[entry.name] = digest
            lower = entry.name.lower()
            if lower.endswith((".jpg", ".jpeg")):
                scan.jpegs[entry.name] = inspect(archive.read(entry.name))
            elif _is_config(entry.name, prefixes) and entry.name != log_name:
                raw = archive.read(entry.name, limit=MAX_CONFIG_BYTES)
                scan.configs[entry.name] = raw.decode("utf-8-sig", errors="replace")
    return scan


class CustodyLog:
    """Append-only JSONL record of everything done to a piece of evidence.

    Deliberately a flat file: it must survive without a database, be readable by
    a league admin with no tooling, and be diffable in a dispute. Each record
    carries the hash of the record before it, so removing or editing any record
    but the most recent one leaves a visible break.

    What this does **not** do, stated plainly because a custody log that is
    trusted further than it deserves is worse than none: anyone who can write
    to this file can rewrite it wholesale and recompute the chain. It is
    tamper-*evident* against partial edits and accidental truncation, not
    tamper-proof. For a log that has to survive a motivated party, keep it on
    storage the submitter cannot reach, or countersign it externally.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _last_hash(self) -> str | None:
        if not self.path.is_file():
            return None
        previous = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    previous = line.strip()
        if previous is None:
            return None
        import hashlib

        return hashlib.sha256(previous.encode("utf-8")).hexdigest()

    def append(
        self,
        action: str,
        *,
        evidence_id: str = "",
        actor: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = {
            "at": utcnow().isoformat(),
            "action": action,
            "evidence_id": evidence_id,
            "actor": actor or default_actor(),
            "tool": f"samireader {__version__}",
            "ruleset_version": RULESET_VERSION,
            "previous": self._last_hash(),
            "details": details or {},
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def read(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        records = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    records.append(json.loads(line))
        return records

    def verify(self) -> list[str]:
        """Re-walk the hash chain. Returns a list of human-readable problems."""
        import hashlib

        problems: list[str] = []
        previous_line: str | None = None
        if not self.path.is_file():
            return ["custody log does not exist"]
        with self.path.open("r", encoding="utf-8") as fh:
            for number, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    problems.append(f"line {number}: not valid JSON")
                    previous_line = line.strip()
                    continue
                expected = (
                    hashlib.sha256(previous_line.encode("utf-8")).hexdigest()
                    if previous_line
                    else None
                )
                if record.get("previous") != expected:
                    problems.append(
                        f"line {number}: chain broken — a preceding record was altered or removed"
                    )
                previous_line = line.strip()
        return problems


__all__ = ["ArchiveError", "ArchiveScan", "CustodyLog", "default_actor", "scan_archive", "utcnow"]
