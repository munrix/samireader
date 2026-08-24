"""Tier 1 — match-window correlation: "do the dates match the data?"

This is the check DECISIONS D2 items 2 and 4 are blocked on without ground
truth, so everything here is a no-op unless a schedule was supplied. When one
is, the session's own timeline is converted to UTC using the offset measured
from the archive itself (never from the reviewer's machine) and compared with
the match window.
"""

from __future__ import annotations

from datetime import timedelta

from mosslib.timeutil import format_duration, format_offset
from sami.clockmodel import screenshot_gaps
from sami.context import AnalysisContext
from sami.findings import Confidence, Evidence, EvidenceKind, Finding, Severity, Tier


def analyze(ctx: AnalysisContext) -> list[Finding]:  # noqa: C901 - sequential rules
    schedule = ctx.schedule
    if schedule is None:
        return []

    model = ctx.clocks
    rules = ctx.rules
    findings: list[Finding] = []
    # MOSS's capture cadence means the recording starts a little before the first
    # capture and continues a little after the last one — up to one nominal
    # interval either side. Margins absorb that so a 30-second shortfall does not
    # read as a player stopping early.
    nominal = next(
        (s.nominal_interval_s for s in ctx.session.screenshots if s.nominal_interval_s),
        60,
    )
    def margin(key: str) -> float:
        configured = rules.get(key)
        return float(configured) if isinstance(configured, (int, float)) else float(nominal)

    start_margin = margin("schedule.start_margin_s")
    end_margin = margin("schedule.end_margin_s")

    session_start = model.session_start_utc
    session_end = model.session_end_utc

    if session_start is None or session_end is None:
        findings.append(
            Finding(
                rule="schedule.not-comparable",
                title="Session cannot be placed against the match window",
                tier=Tier.INTEGRITY,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                summary="The host's UTC offset could not be measured, so the session has no absolute time.",
                detail=(
                    "Match-window correlation converts the session's local timestamps to UTC "
                    "using the offset derived from this archive's own ZIP entry timestamps. "
                    "Without that offset the session timeline cannot be compared to a schedule."
                ),
                benign=(
                    "This is a limitation of the archive as submitted, not a finding against the "
                    "player. The coverage question stays open rather than answered either way."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.EXTERNAL,
                        label="Match window (UTC)",
                        value=f"{schedule.start_utc} → {schedule.end_utc}",
                    )
                ],
                subject=ctx.subject,
                tags=["schedule", "coverage"],
            )
        )
        return findings

    # ------------------------------------------------------------ wrong session
    stale_days = rules.number("schedule.stale_archive_days", 1)
    day_delta = abs((session_start.date() - schedule.start_utc.date()).days)
    if day_delta >= stale_days:
        findings.append(
            Finding(
                rule="schedule.wrong-date",
                title="Session was recorded on a different day from the match",
                tier=Tier.INTEGRITY,
                severity=rules.severity("schedule.wrong-date", Severity.CRITICAL),
                confidence=Confidence.CERTAIN,
                summary=(
                    f"Session starts {session_start} UTC; match {schedule.match_id} starts "
                    f"{schedule.start_utc} UTC ({day_delta} day(s) apart)."
                ),
                detail=(
                    "The session's first capture was converted to UTC using the host offset "
                    f"measured from this archive ({format_offset(model.host_offset_minutes)}) and "
                    "compared with the scheduled match start. They fall on different days, so "
                    "this archive does not record the match it was submitted for."
                ),
                benign=(
                    "The most common cause by far is a player uploading the wrong file — an "
                    "archive from a previous match or a practice session. Ask for the correct "
                    "archive before treating a recycled upload as deception."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Session window (UTC)",
                        value=f"{session_start} → {session_end}",
                    ),
                    Evidence(
                        kind=EvidenceKind.EXTERNAL,
                        label=f"Match {schedule.match_id} (UTC)",
                        value=f"{schedule.start_utc} → {schedule.end_utc}",
                    ),
                ],
                subject=ctx.subject,
                tags=["schedule", "wrong-session"],
            )
        )
        return findings

    # --------------------------------------------------------------- late start
    late_by = (session_start - (schedule.start_utc + timedelta(seconds=start_margin))).total_seconds()
    if late_by > 0:
        uncovered = schedule.rounds_overlapping(schedule.start_utc, session_start)
        severity = Severity.HIGH if uncovered or late_by > 300 else Severity.MEDIUM
        findings.append(
            Finding(
                rule="schedule.late-start",
                title="Recording started after the match began",
                tier=Tier.INTEGRITY,
                severity=rules.severity("schedule.late-start", severity),
                confidence=Confidence.CERTAIN,
                summary=(
                    f"First capture is {format_duration(late_by)} after the scheduled start"
                    + (f", leaving {len(uncovered)} round(s) unrecorded." if uncovered else ".")
                ),
                detail=(
                    f"Match starts {schedule.start_utc} UTC. The first capture converts to "
                    f"{session_start} UTC using the measured host offset "
                    f"{format_offset(model.host_offset_minutes)}, which is "
                    f"{format_duration(late_by)} beyond the {format_duration(start_margin)} "
                    "allowed for MOSS's capture cadence. Everything before the first capture has "
                    "no visual record."
                ),
                benign=(
                    "Players routinely start MOSS a little late, and MOSS only begins capturing "
                    "once it detects the game — a player who started MOSS on time but launched "
                    "the game late produces this. The question for the admin is what happened in "
                    "the uncovered window, not that the window exists."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Match start vs first capture (UTC)",
                        value=f"{schedule.start_utc} vs {session_start}",
                    ),
                    *(
                        [
                            Evidence(
                                kind=EvidenceKind.EXTERNAL,
                                label="Rounds with no coverage",
                                value=", ".join(r.label for r in uncovered),
                            )
                        ]
                        if uncovered
                        else []
                    ),
                ],
                subject=ctx.subject,
                tags=["schedule", "coverage"],
            )
        )

    # ---------------------------------------------------------------- early stop
    early_by = ((schedule.end_utc - timedelta(seconds=end_margin)) - session_end).total_seconds()
    if early_by > 0:
        uncovered = schedule.rounds_overlapping(session_end, schedule.end_utc)
        severity = Severity.HIGH if uncovered or early_by > 300 else Severity.MEDIUM
        findings.append(
            Finding(
                rule="schedule.early-stop",
                title="Recording stopped before the match ended",
                tier=Tier.INTEGRITY,
                severity=rules.severity("schedule.early-stop", severity),
                confidence=Confidence.CERTAIN,
                summary=(
                    f"Last capture is {format_duration(early_by)} before the scheduled end"
                    + (f", leaving {len(uncovered)} round(s) unrecorded." if uncovered else ".")
                ),
                detail=(
                    f"Match ends {schedule.end_utc} UTC; the last capture converts to "
                    f"{session_end} UTC — {format_duration(early_by)} short, after allowing "
                    f"{format_duration(end_margin)} for MOSS's capture cadence. The last capture "
                    "is not the moment recording stopped, only the last moment it is evidenced."
                ),
                benign=(
                    "A match that finished early (a 7-0, a forfeit, a walkover) legitimately ends "
                    "before its scheduled window does — compare against the actual result before "
                    "reading anything into it. A crash at the end of the match does the same."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Last capture vs match end (UTC)",
                        value=f"{session_end} vs {schedule.end_utc}",
                    ),
                    *(
                        [
                            Evidence(
                                kind=EvidenceKind.EXTERNAL,
                                label="Rounds with no coverage",
                                value=", ".join(r.label for r in uncovered),
                            )
                        ]
                        if uncovered
                        else []
                    ),
                ],
                subject=ctx.subject,
                tags=["schedule", "coverage"],
            )
        )

    # ------------------------------------------------ gaps that swallow a round
    offset = model.host_offset_minutes or 0
    round_gaps: list[tuple[str, float, str]] = []
    for gap_start, gap_end, seconds in screenshot_gaps(ctx.session):
        gap_start_utc = gap_start - timedelta(minutes=offset)
        gap_end_utc = gap_end - timedelta(minutes=offset)
        covered = schedule.rounds_overlapping(gap_start_utc, gap_end_utc)
        for rnd in covered:
            round_gaps.append(
                (rnd.label, seconds, f"{gap_start_utc} → {gap_end_utc} UTC")
            )
    max_gap = rules.number("session.max_screenshot_gap_s", 300)
    notable = [g for g in round_gaps if g[1] > max_gap]
    if notable:
        findings.append(
            Finding(
                rule="schedule.round-coverage-gap",
                title="A capture gap spans a scheduled round",
                tier=Tier.INTEGRITY,
                severity=rules.severity("schedule.round-coverage-gap", Severity.HIGH),
                confidence=Confidence.HIGH,
                summary=f"{len(notable)} round(s) overlap a capture gap longer than {format_duration(max_gap)}.",
                detail=(
                    "Each capture gap was converted to UTC and intersected with the scheduled "
                    "rounds. A gap covering live play is the coverage question that matters: the "
                    "archive records the session but not that part of the match."
                ),
                benign=(
                    "MOSS randomises its cadence and skips captures it cannot take, so gaps occur "
                    "without cause. A single gap over one round is weak; a pattern of gaps that "
                    "align with rounds is not."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label=f"{label} — gap of {format_duration(seconds)}",
                        value=window,
                    )
                    for label, seconds, window in notable[:10]
                ],
                subject=ctx.subject,
                tags=["schedule", "coverage", "gap"],
            )
        )

    # ------------------------------------------------------------------- clean
    if not any(f.severity.rank >= Severity.MEDIUM.rank for f in findings):
        findings.append(
            Finding(
                rule="schedule.covers-match",
                title="Session covers the scheduled match window",
                tier=Tier.INTEGRITY,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary=(
                    f"Recording runs {session_start} → {session_end} UTC, covering "
                    f"{schedule.match_id} ({schedule.start_utc} → {schedule.end_utc})."
                ),
                detail=(
                    "The session's local timestamps were converted to UTC using the host offset "
                    f"measured from this archive ({format_offset(model.host_offset_minutes)}) and "
                    "found to start before the match and end after it, with no capture gap over "
                    "a scheduled round."
                ),
                benign=(
                    "Full coverage means the recording is complete, not that the play in it was "
                    "clean. The remaining tiers are what speak to that, and they corroborate — "
                    "they do not conclude."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Coverage margin",
                        value=(
                            f"starts {format_duration(abs(late_by))} early, ends "
                            f"{format_duration(abs(early_by))} late"
                        ),
                    )
                ],
                subject=ctx.subject,
                tags=["schedule"],
            )
        )

    return findings
