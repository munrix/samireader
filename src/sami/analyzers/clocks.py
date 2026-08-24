"""Tier 1 — multi-clock reconciliation.

The measurements come from :mod:`sami.clockmodel`; this module decides which of
them are worth an admin's time. The load-bearing checks, in order of strength:

* **host offset validity** — captures against ZIP mtimes must differ by a real
  world UTC offset. 2h17m is not a timezone.
* **offset stability** — that difference must hold across the whole session. A
  step change mid-session is a clock being moved while MOSS was recording.
* **network clock agreement** — MOSS's own network-synced start time against
  the host's local clock. This is the check a player cannot defeat by setting
  their system clock, because they do not control both sides of it.
* **boot-time sanity** — a session cannot predate the boot of the machine that
  recorded it.
"""

from __future__ import annotations

from mosslib.timeutil import format_duration, format_offset, is_valid_utc_offset
from sami.context import AnalysisContext
from sami.findings import Confidence, Evidence, EvidenceKind, Finding, Severity, Tier

BENIGN_OFFSET = (
    "A host genuinely running on a non-standard offset is vanishingly rare, but a machine "
    "whose clock drifted badly without NTP, or a VM with a misconfigured RTC, produces the "
    "same reading with no intent behind it. The finding says the clocks do not reconcile — "
    "not who moved them."
)


def analyze(ctx: AnalysisContext) -> list[Finding]:  # noqa: C901 - one rule per block
    session = ctx.session
    model = ctx.clocks
    rules = ctx.rules
    findings: list[Finding] = []

    tolerance = rules.number("clocks.offset_tolerance_minutes", 3)
    drift_tolerance = rules.number("clocks.drift_tolerance_minutes", 2)

    if not model.samples:
        if session.screenshots:
            findings.append(
                Finding(
                    rule="clocks.no-offset-samples",
                    title="Host time zone could not be established",
                    tier=Tier.INTEGRITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    summary="No capture could be paired with a ZIP entry timestamp.",
                    detail=(
                        "The host's UTC offset is derived by comparing each capture's local "
                        "timestamp in the log with the same file's ZIP entry timestamp. Without "
                        "at least one pair, every clock check that depends on the offset — "
                        "including match-window correlation — cannot run."
                    ),
                    benign=(
                        "An archive rebuilt by a tool that discards entry timestamps loses this "
                        "signal without anyone targeting it. Treat the clock section as "
                        "unchecked rather than clean."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.COMPUTED,
                            label="Captures in log / entries in ZIP",
                            value=f"{len(session.screenshots)} / {len(session.archive.entries)}",
                        )
                    ],
                    subject=ctx.subject,
                    tags=["time", "coverage"],
                )
            )
        return findings

    offset = model.host_offset_minutes
    assert offset is not None

    # --------------------------------------------------- offset is a real zone
    if not is_valid_utc_offset(offset, tolerance_minutes=tolerance):
        nearest = model.nearest_offset_minutes or 0
        findings.append(
            Finding(
                rule="clocks.invalid-utc-offset",
                title="Host clock is not on a real UTC offset",
                tier=Tier.INTEGRITY,
                severity=rules.severity("clocks.invalid-utc-offset", Severity.HIGH),
                confidence=Confidence.HIGH,
                summary=(
                    f"Captures run {offset:+.1f} min ahead of the archive's UTC timestamps — "
                    f"{format_offset(offset)}, which is not a time zone."
                ),
                detail=(
                    "For each capture, the local timestamp in the log was compared with the same "
                    f"file's ZIP entry timestamp (written in UTC). The median difference is "
                    f"{offset:+.1f} minutes across {len(model.samples)} captures. Every real UTC "
                    f"offset is a whole hour, or :30/:45 in a few zones; the nearest is "
                    f"{format_offset(nearest)}, {abs(offset - nearest):.1f} min away. The host's "
                    "displayed clock is therefore not simply in a different time zone from UTC — "
                    "it has been set to something else."
                ),
                benign=BENIGN_OFFSET,
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Median capture − ZIP mtime",
                        value=f"{offset:+.1f} min over {len(model.samples)} samples",
                    ),
                    *[
                        Evidence(
                            kind=EvidenceKind.LOG_LINE,
                            label=s.file,
                            value=f"log {s.local} vs ZIP {s.zip_mtime} = {s.delta_minutes:+.1f} min",
                            line=s.line,
                            member=s.file,
                        )
                        for s in model.samples[:5]
                    ],
                ],
                subject=ctx.subject,
                tags=["time", "clock-manipulation"],
            )
        )

    # ------------------------------------------------------- offset stability
    spread = model.offset_spread_minutes or 0.0
    if spread > drift_tolerance:
        worst = max(model.samples, key=lambda s: abs(s.delta_minutes - offset))
        findings.append(
            Finding(
                rule="clocks.offset-drift",
                title="Host offset changed during the session",
                tier=Tier.INTEGRITY,
                severity=rules.severity("clocks.offset-drift", Severity.HIGH),
                confidence=Confidence.HIGH,
                summary=f"Capture-to-UTC offset varies by {spread:.1f} min across the session.",
                detail=(
                    "The difference between each capture's local timestamp and its UTC entry "
                    f"timestamp should be constant. Here it moves by {spread:.1f} min "
                    f"(tolerance {drift_tolerance:.0f} min), the largest deviation at "
                    f"{worst.file} ({worst.delta_minutes:+.1f} min against a median of "
                    f"{offset:+.1f}). A clock that moves mid-recording changes what the "
                    "timestamps in this archive mean."
                ),
                benign=(
                    "A single NTP correction on a machine whose clock had drifted produces one "
                    "step of a few seconds to a few minutes and is entirely normal. A step of a "
                    "whole hour at a DST boundary is also legitimate — check the session date "
                    "against the local DST change before reading anything into it."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Offset range",
                        value=f"{min(s.delta_minutes for s in model.samples):+.1f} … "
                        f"{max(s.delta_minutes for s in model.samples):+.1f} min",
                    ),
                    Evidence(
                        kind=EvidenceKind.LOG_LINE,
                        label=f"Largest deviation: {worst.file}",
                        value=f"log {worst.local} vs ZIP {worst.zip_mtime}",
                        line=worst.line,
                        member=worst.file,
                    ),
                ],
                subject=ctx.subject,
                tags=["time", "clock-manipulation"],
            )
        )

    # ------------------------------------------- MOSS network clock vs host
    expected_network = rules.number("clocks.network_clock_expected_offset_minutes", 60)
    network_tolerance = rules.number("clocks.network_clock_tolerance_minutes", 5)
    implied = model.implied_network_offset_minutes
    if model.network_to_local_minutes is not None and implied is not None:
        deviation = abs(implied - expected_network)
        if deviation > network_tolerance:
            findings.append(
                Finding(
                    rule="clocks.network-clock-disagrees",
                    title="MOSS's own start time disagrees with the host clock",
                    tier=Tier.INTEGRITY,
                    severity=rules.severity("clocks.network-clock-disagrees", Severity.HIGH),
                    confidence=Confidence.MODERATE,
                    summary=(
                        f"MOSS's session header sits {format_offset(implied)} from UTC; across the "
                        f"reference corpus it is always {format_offset(expected_network)}."
                    ),
                    detail=(
                        "'SHAS2 mode started' is written from a clock that tracked UTC+1 on every "
                        "host in the reference corpus regardless of the host's own time zone, "
                        "which makes it an independent reference. Here: header "
                        f"{session.header_started_at}, host local start "
                        f"{session.monitor_started_at} — a difference of "
                        f"{model.network_to_local_minutes:+.1f} min. With the host offset measured "
                        f"at {format_offset(offset)}, the header clock implies "
                        f"{format_offset(implied)}, off by {deviation:.1f} min. The host clock and "
                        "MOSS's clock do not tell the same story."
                    ),
                    benign=(
                        "The UTC+1 behaviour of this clock is an observation from five archives, "
                        "not vendor-documented: a different MOSS build, or a host that could not "
                        "reach MOSS's time source, may legitimately differ. Corroborate with the "
                        "offset and drift findings before relying on this one alone."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.COMPUTED,
                            label="Header (network) vs Monitor Started (local)",
                            value=f"{session.header_started_at} vs {session.monitor_started_at}",
                        ),
                        Evidence(
                            kind=EvidenceKind.COMPUTED,
                            label="Implied network-clock offset",
                            value=f"{format_offset(implied)} (expected {format_offset(expected_network)})",
                        ),
                    ],
                    subject=ctx.subject,
                    tags=["time", "clock-manipulation"],
                )
            )

    # --------------------------------------------- filename clock vs the rest
    name_tolerance = rules.number("clocks.archive_name_tolerance_s", 900)
    if model.name_to_session_minutes is not None:
        drift_s = model.name_to_session_minutes * 60
        if abs(drift_s) > name_tolerance:
            findings.append(
                Finding(
                    rule="clocks.filename-time-mismatch",
                    title="Archive filename time does not match the session",
                    tier=Tier.INTEGRITY,
                    severity=rules.severity("clocks.filename-time-mismatch", Severity.MEDIUM),
                    confidence=Confidence.MODERATE,
                    summary=(
                        f"The name says {session.archive.name_timestamp} UTC; the session starts "
                        f"{format_duration(abs(drift_s))} {'later' if drift_s > 0 else 'earlier'}."
                    ),
                    detail=(
                        "MOSS names the ZIP with the session start in UTC. Converting the "
                        f"session's first local timestamp using the measured host offset "
                        f"({format_offset(offset)}) gives {model.session_start_utc} UTC, against "
                        f"{session.archive.name_timestamp} in the filename — a difference of "
                        f"{drift_s / 60:+.1f} min."
                    ),
                    benign=(
                        "Renaming the file for submission is extremely common and entirely "
                        "innocent — many leagues ask for it. Treat this as a prompt to check "
                        "whether the *contents* reconcile, not as tampering in itself."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.COMPUTED,
                            label="Filename timestamp vs session start (UTC)",
                            value=f"{session.archive.name_timestamp} vs {model.session_start_utc}",
                        )
                    ],
                    subject=ctx.subject,
                    tags=["time"],
                )
            )

    # ------------------------------------------------------------ boot sanity
    boot_tolerance = rules.number("clocks.boot_time_tolerance_s", 900)
    if model.boot_time_local and model.session_start_local:
        delta = (model.session_start_local - model.boot_time_local).total_seconds()
        if delta < -boot_tolerance:
            findings.append(
                Finding(
                    rule="clocks.session-before-boot",
                    title="Session started before the machine booted",
                    tier=Tier.INTEGRITY,
                    severity=rules.severity("clocks.session-before-boot", Severity.HIGH),
                    confidence=Confidence.HIGH,
                    summary=(
                        f"Derived boot time {model.boot_time_local} is "
                        f"{format_duration(abs(delta))} after the session start."
                    ),
                    detail=(
                        f"{model.uptime_source} had been running for "
                        f"{format_duration(model.uptime_seconds)} when MOSS wrote its process "
                        "statistics at the end of the session. Subtracting that from the session "
                        f"end gives a boot time of {model.boot_time_local}, which is after the "
                        f"session's own start of {model.session_start_local}. A session cannot "
                        "predate the boot of the machine that recorded it, so at least one of "
                        "these clocks is wrong."
                    ),
                    benign=(
                        "The uptime process may have been restarted, or the statistics may have "
                        "been sampled at a different moment than assumed here (this tool assumes "
                        "the end of the session). Fast startup and hibernation also distort "
                        "uptime on Windows. Verify against the taskbar clock in the captures "
                        "before relying on this."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.COMPUTED,
                            label=f"{model.uptime_source} running time",
                            value=format_duration(model.uptime_seconds),
                        ),
                        Evidence(
                            kind=EvidenceKind.COMPUTED,
                            label="Derived boot vs session start",
                            value=f"{model.boot_time_local} vs {model.session_start_local}",
                        ),
                    ],
                    subject=ctx.subject,
                    tags=["time", "uptime"],
                )
            )

    # ------------------------------------------------------------ monotonicity
    times = [(s.file, s.at, s.line) for s in session.screenshots if s.at]
    backwards = [
        (prev_file, prev_at, file, at, line)
        for (prev_file, prev_at, _), (file, at, line) in zip(times, times[1:], strict=False)
        if at < prev_at
    ]
    if backwards:
        findings.append(
            Finding(
                rule="clocks.non-monotonic-captures",
                title="Capture timestamps go backwards",
                tier=Tier.INTEGRITY,
                severity=rules.severity("clocks.non-monotonic-captures", Severity.HIGH),
                confidence=Confidence.CERTAIN,
                summary=f"{len(backwards)} capture(s) are timestamped before the capture that precedes them.",
                detail=(
                    "Captures are written in order, so their timestamps must increase. A "
                    "backwards step means the clock moved while MOSS was recording, or the log "
                    "was reordered after the fact."
                ),
                benign=(
                    "A DST rollback or an NTP correction during the session moves the clock "
                    "backwards legitimately. The size of the step distinguishes them: an hour "
                    "at a known DST boundary is routine, a few minutes mid-match is not."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.LOG_LINE,
                        label=f"{prev_file} → {file}",
                        value=f"{prev_at} → {at} ({(at - prev_at).total_seconds():+.0f}s)",
                        line=line,
                        member=file,
                    )
                    for prev_file, prev_at, file, at, line in backwards[:10]
                ],
                subject=ctx.subject,
                tags=["time", "clock-manipulation"],
            )
        )

    # -------------------------------------------------------- clean statement
    if not any(f.tags and "time" in f.tags for f in findings):
        findings.append(
            Finding(
                rule="clocks.reconciled",
                title="Clocks reconcile",
                tier=Tier.INTEGRITY,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary=(
                    f"Host reads {format_offset(offset)}, stable to within "
                    f"{spread:.1f} min across {len(model.samples)} captures."
                ),
                detail=(
                    "Capture timestamps, ZIP entry timestamps, the session header and the "
                    "archive filename were compared against each other. Every relationship "
                    "measured is consistent with a single, unmoved host clock."
                ),
                benign=(
                    "Consistent clocks mean the archive's own timestamps can be trusted as a "
                    "timeline. They do not establish that the timeline covers the right match — "
                    "that needs a schedule to compare against."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Measured host offset",
                        value=f"{format_offset(offset)} ± {spread / 2:.1f} min",
                    )
                ],
                subject=ctx.subject,
                tags=["time"],
            )
        )

    return findings
