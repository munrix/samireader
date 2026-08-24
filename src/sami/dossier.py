"""Assembling one archive's findings into the thing an admin actually reads.

A dossier is the unit of review: one archive, its findings ordered by how hard
they are to argue with, the clock arithmetic behind them, and the provenance
needed to reproduce the result — tool version, ruleset version, rule pack, and
the evidence ID of the file it came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mosslib.version import KNOWN_MOSS_VERSIONS
from sami.analyzers import ANALYZER_NAMES, run_all
from sami.clockmodel import ClockModel, build_clock_model
from sami.context import AnalysisContext
from sami.findings import Finding, Severity, Tier, review_priority, severity_counts
from sami.ingest import ArchiveScan, utcnow
from sami.rules import RulePack
from sami.schedule import MatchSchedule, PlayerEntry
from sami.version import RULESET_VERSION, __version__

#: Reproduced in every report. Not a disclaimer — a statement of what the
#: evidence base can and cannot support (RESEARCH §7).
LIMITATIONS = (
    "MOSS records a session; it does not detect cheating. Everything in this report is "
    "evidence for a human decision, never a verdict.",
    "The process list is a single snapshot taken at game start. Anything launched afterwards "
    "does not appear in this archive.",
    "MOSS runs in user mode, on hardware controlled by the person it may incriminate. "
    "Screenshot-timing evasion and log editing before packaging are publicly documented.",
    "DMA cheats on a second machine, hardware input injection (KMBox, XIM-class devices) and "
    "second-device overlays leave no trace on the monitored host at all.",
    "A clean report means nothing was found in what MOSS captured. It is not a finding of "
    "innocence, and must not be reported as one.",
)


@dataclass
class Dossier:
    scan: ArchiveScan
    findings: list[Finding]
    clocks: ClockModel
    rules: RulePack
    schedule: MatchSchedule | None = None
    entry: PlayerEntry | None = None
    generated_at: datetime = field(default_factory=utcnow)
    max_tier: int = 3

    # ------------------------------------------------------------------ views

    @property
    def session(self):
        return self.scan.session

    @property
    def subject(self) -> str:
        return self.entry.name if self.entry else self.scan.display_name

    @property
    def priority(self) -> tuple[str, str]:
        return review_priority(self.findings)

    @property
    def counts(self) -> dict[str, int]:
        return severity_counts(self.findings)

    @property
    def actionable(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is not Severity.INFO]

    def by_tier(self, tier: Tier) -> list[Finding]:
        return [f for f in self.findings if f.tier is tier]

    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), key=lambda s: s.rank, default=Severity.INFO)

    @property
    def unknown_moss_version(self) -> bool:
        version = self.session.moss_version
        return bool(version) and version not in KNOWN_MOSS_VERSIONS

    # ------------------------------------------------------------------- json

    def to_json(self) -> dict[str, Any]:
        session = self.session
        return {
            "schema": "samireader/dossier/1",
            "generated_at": self.generated_at.isoformat(),
            "tool": {
                "name": "samireader",
                "version": __version__,
                "ruleset_version": RULESET_VERSION,
                "rule_pack": self.rules.describe(),
                "analyzers": list(ANALYZER_NAMES),
                "max_tier": self.max_tier,
            },
            "evidence": {
                "id": self.scan.evidence_id,
                "filename": session.archive.filename,
                "size": session.archive.size,
                "ingested_at": self.scan.ingested_at.isoformat(),
                "source_path": str(self.scan.path),
            },
            "subject": self.subject,
            "review_priority": {"band": self.priority[0], "meaning": self.priority[1]},
            "severity_counts": self.counts,
            "session": {
                "moss_version": session.moss_version,
                "game": session.game,
                "game_detected": session.game_detected,
                "header_started_at": session.header_started_at.isoformat(sep=" ")
                if session.header_started_at
                else None,
                "monitor_started_at": session.monitor_started_at.isoformat(sep=" ")
                if session.monitor_started_at
                else None,
                "start_local": session.session_start.isoformat(sep=" ")
                if session.session_start
                else None,
                "end_local": session.session_end.isoformat(sep=" ")
                if session.session_end
                else None,
                "duration_s": session.duration_s,
                "captures": len(session.screenshots),
                "processes": len(session.processes),
                "configs": len(self.scan.configs),
                "log_lines": session.log_line_count,
                "unparsed_lines": len(session.unknown_lines),
                "parse_warnings": [w.to_json() for w in session.warnings],
            },
            "clocks": self.clocks.to_json(),
            "schedule": self.schedule.to_json() if self.schedule else None,
            "findings": [f.to_json() for f in self.findings],
            "limitations": list(LIMITATIONS),
        }


def analyze_scan(
    scan: ArchiveScan,
    rules: RulePack,
    *,
    schedule: MatchSchedule | None = None,
    peers: list[ArchiveScan] | None = None,
    max_tier: int = 3,
) -> Dossier:
    """Run every analyzer over one scanned archive and assemble its dossier."""
    clocks = build_clock_model(
        scan.session,
        network_offset_minutes=rules.number("clocks.network_clock_expected_offset_minutes", 60),
    )
    entry = (
        schedule.entry_for(
            filename=scan.session.archive.filename,
            sha256=scan.evidence_id,
            label=scan.label,
        )
        if schedule
        else None
    )
    ctx = AnalysisContext(
        scan=scan,
        rules=rules,
        clocks=clocks,
        schedule=schedule,
        entry=entry,
        peers=[p for p in (peers or []) if p is not scan],
    )
    findings = run_all(ctx, max_tier=max_tier)
    return Dossier(
        scan=scan,
        findings=findings,
        clocks=clocks,
        rules=rules,
        schedule=schedule,
        entry=entry,
        max_tier=max_tier,
    )


@dataclass
class MatchDossier:
    """Every player's dossier for one match, plus the coverage question."""

    dossiers: list[Dossier]
    schedule: MatchSchedule | None = None
    generated_at: datetime = field(default_factory=utcnow)

    @property
    def missing_players(self) -> list[PlayerEntry]:
        """Scheduled players with no archive submitted."""
        if not self.schedule:
            return []
        submitted = {d.entry.name for d in self.dossiers if d.entry}
        return [p for p in self.schedule.players if p.name not in submitted]

    def ordered(self) -> list[Dossier]:
        band_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
        return sorted(
            self.dossiers,
            key=lambda d: (band_order.get(d.priority[0], 9), -d.worst().rank, d.subject.lower()),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": "samireader/match/1",
            "generated_at": self.generated_at.isoformat(),
            "schedule": self.schedule.to_json() if self.schedule else None,
            "missing_players": [
                {"name": p.name, "team": p.team} for p in self.missing_players
            ],
            "dossiers": [d.to_json() for d in self.ordered()],
        }
