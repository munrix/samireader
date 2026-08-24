"""What an analyzer is allowed to see.

Analyzers are pure functions ``AnalysisContext -> [Finding]``. They never open
files, never touch the network and never mutate the context, which is what
makes the finding set reproducible from a stored ``ArchiveScan`` and a rule
pack version — a property the appeal process depends on.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mosslib.model import Session
from sami.clockmodel import ClockModel
from sami.ingest import ArchiveScan
from sami.rules import RulePack
from sami.schedule import MatchSchedule, PlayerEntry


@dataclass
class AnalysisContext:
    scan: ArchiveScan
    rules: RulePack
    clocks: ClockModel
    schedule: MatchSchedule | None = None
    entry: PlayerEntry | None = None
    #: Other archives from the same match, for cross-player comparison.
    peers: list[ArchiveScan] = field(default_factory=list)

    @property
    def session(self) -> Session:
        return self.scan.session

    @property
    def subject(self) -> str:
        return self.scan.display_name
