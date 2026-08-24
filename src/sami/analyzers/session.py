"""Tier 1 — session shape: does the recording cover a continuous, plausible session?

These checks need no external reference, which is what separates them from
:mod:`sami.analyzers.schedule`. They answer "is this a coherent recording?"
rather than "is it a recording of the right match?".
"""

from __future__ import annotations

from mosslib.timeutil import format_duration, median
from sami.clockmodel import screenshot_gaps
from sami.context import AnalysisContext
from sami.findings import Confidence, Evidence, EvidenceKind, Finding, Severity, Tier


def analyze(ctx: AnalysisContext) -> list[Finding]:
    session = ctx.session
    rules = ctx.rules
    findings: list[Finding] = []

    capture_times = [s.at for s in session.screenshots if s.at]
    min_shots = rules.integer("session.min_screenshots", 5)

    if len(session.screenshots) < min_shots:
        findings.append(
            Finding(
                rule="session.too-few-captures",
                title="Very few captures in the session",
                tier=Tier.INTEGRITY,
                severity=rules.severity("session.too-few-captures", Severity.MEDIUM),
                confidence=Confidence.HIGH,
                summary=f"{len(session.screenshots)} capture(s) recorded (expected at least {min_shots}).",
                detail=(
                    "MOSS captures roughly once a minute, so even a short session produces "
                    "dozens of frames. A near-empty archive covers almost nothing, whatever "
                    "else it verifies cleanly."
                ),
                benign=(
                    "A session stopped moments after starting — a mis-click, a crash, a restart "
                    "before the real recording — looks exactly like this. Ask for the archive "
                    "that covers the match."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Captures",
                        value=str(len(session.screenshots)),
                    )
                ],
                subject=ctx.subject,
                tags=["coverage"],
            )
        )

    duration = session.duration_s
    min_duration = rules.number("session.min_duration_s", 300)
    if duration is not None and duration < min_duration:
        findings.append(
            Finding(
                rule="session.too-short",
                title="Session is shorter than a match",
                tier=Tier.INTEGRITY,
                severity=rules.severity("session.too-short", Severity.MEDIUM),
                confidence=Confidence.HIGH,
                summary=f"Recording spans {format_duration(duration)}.",
                detail=(
                    f"From the first capture at {session.session_start} to the last at "
                    f"{session.session_end}. Anything below {format_duration(min_duration)} "
                    "cannot cover a competitive match."
                ),
                benign=(
                    "A player who recorded a warm-up, or who restarted MOSS after a crash, will "
                    "have a short archive plus a longer one. Check whether a second submission "
                    "exists before treating the short window as the whole story."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Session window (host local)",
                        value=f"{session.session_start} → {session.session_end}",
                    )
                ],
                subject=ctx.subject,
                tags=["coverage"],
            )
        )

    # ------------------------------------------------------------- capture gaps
    gaps = screenshot_gaps(session)
    max_gap = rules.number("session.max_screenshot_gap_s", 300)
    long_gaps = [g for g in gaps if g[2] > max_gap]
    if long_gaps:
        worst = max(long_gaps, key=lambda g: g[2])
        findings.append(
            Finding(
                rule="session.capture-gap",
                title="Long gap between captures",
                tier=Tier.INTEGRITY,
                severity=rules.severity("session.capture-gap", Severity.MEDIUM),
                confidence=Confidence.HIGH,
                summary=(
                    f"{len(long_gaps)} gap(s) over {format_duration(max_gap)}; the longest is "
                    f"{format_duration(worst[2])} from {worst[0]} to {worst[1]}."
                ),
                detail=(
                    "MOSS's nominal cadence is 60s and it randomises around it — observed "
                    "intervals in the reference corpus ranged from 2s to 138s. A gap far outside "
                    "that leaves a stretch of the session with no visual record at all."
                ),
                benign=(
                    "A capture that MOSS could not take (exclusive full-screen transitions, a "
                    "GPU driver reset, a heavily loaded machine) extends the interval without "
                    "anyone doing anything. What matters is what the gap covers: a gap over a "
                    "live round is worth a question, a gap in the pre-match lobby is not."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label=f"Gap of {format_duration(g[2])}",
                        value=f"{g[0]} → {g[1]}",
                    )
                    for g in sorted(long_gaps, key=lambda g: g[2], reverse=True)[:8]
                ],
                subject=ctx.subject,
                tags=["coverage", "gap"],
            )
        )

    # -------------------------------------------------- suspiciously regular cadence
    intervals = [g[2] for g in gaps]
    if len(intervals) >= 10:
        mid = median(intervals) or 0.0
        if mid > 0:
            spread = max(intervals) - min(intervals)
            cv_floor = rules.number("session.cadence_regularity_cv", 0.05)
            if spread / mid < cv_floor:
                findings.append(
                    Finding(
                        rule="session.cadence-too-regular",
                        title="Capture cadence is unnaturally regular",
                        tier=Tier.INTEGRITY,
                        severity=rules.severity("session.cadence-too-regular", Severity.MEDIUM),
                        confidence=Confidence.MODERATE,
                        summary=f"All {len(intervals)} intervals sit within {spread:.0f}s of each other (median {mid:.0f}s).",
                        detail=(
                            "MOSS randomises its capture interval around the nominal cadence, so "
                            "a real session shows a spread of intervals. A near-constant interval "
                            "suggests the capture records were generated rather than observed."
                        ),
                        benign=(
                            "A short session with few intervals can look regular by chance, and a "
                            "MOSS version that does not randomise would produce this legitimately. "
                            "Weigh it next to the hash results rather than on its own."
                        ),
                        evidence=[
                            Evidence(
                                kind=EvidenceKind.COMPUTED,
                                label="Interval range",
                                value=f"{min(intervals):.0f}s – {max(intervals):.0f}s (median {mid:.0f}s)",
                            )
                        ],
                        subject=ctx.subject,
                        tags=["cadence"],
                    )
                )

    # ------------------------------------------- monitor start to first capture
    lead = rules.number("session.monitor_start_to_first_shot_max_s", 900)
    if session.monitor_started_at and capture_times:
        first = min(capture_times)
        delta = (first - session.monitor_started_at).total_seconds()
        if delta > lead:
            findings.append(
                Finding(
                    rule="session.late-first-capture",
                    title="First capture is long after monitoring started",
                    tier=Tier.INTEGRITY,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    summary=f"{format_duration(delta)} between 'Monitor Started' and the first capture.",
                    detail=(
                        f"MOSS began monitoring at {session.monitor_started_at} but the first "
                        f"capture is stamped {first}. The intervening period is recorded in the "
                        "log but has no visual record."
                    ),
                    benign=(
                        "MOSS captures only once the game is detected, so a player who started "
                        "MOSS early and then queued, patched or sat in a lobby produces exactly "
                        "this. It is only interesting if the match itself falls inside the gap."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.COMPUTED,
                            label="Monitor started → first capture",
                            value=f"{session.monitor_started_at} → {first}",
                        )
                    ],
                    subject=ctx.subject,
                    tags=["coverage"],
                )
            )

    if not session.game_detected and session.screenshots:
        findings.append(
            Finding(
                rule="session.no-game-detected",
                title="MOSS never reported detecting the game",
                tier=Tier.INTEGRITY,
                severity=rules.severity("session.no-game-detected", Severity.MEDIUM),
                confidence=Confidence.HIGH,
                summary="The log has no 'Game Detected' line.",
                detail=(
                    "MOSS writes 'Game Detected' when it identifies the game process. Without it "
                    "there is no evidence the archive covers the game at all, only that something "
                    "was on screen."
                ),
                benign=(
                    "A title MOSS does not recognise, or a launcher that starts the game in a way "
                    "MOSS misses, prevents detection without preventing recording. Check whether "
                    "the game process appears in the process list anyway."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Declared game",
                        value=session.game or "(not stated in header)",
                    )
                ],
                subject=ctx.subject,
                tags=["coverage"],
            )
        )

    return findings
