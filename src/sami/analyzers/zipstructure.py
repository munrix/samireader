"""Tier 1 — ZIP structure forensics.

A rebuilt archive rarely reproduces MOSS's own write pattern. MOSS writes each
capture as it takes it, so entries appear in capture order, mtimes climb across
the session, and the compression method is uniform. Re-zipping a folder
collapses all of that: mtimes bunch, order follows the directory listing, and
the tool's own defaults replace MOSS's.

None of these is proof on its own. Together with a hash mismatch they describe
*how* an archive was rebuilt; on their own they say "this file did not come
straight out of MOSS".
"""

from __future__ import annotations

from collections import Counter
from datetime import timedelta

from sami.context import AnalysisContext
from sami.findings import Confidence, Evidence, EvidenceKind, Finding, Severity, Tier


def analyze(ctx: AnalysisContext) -> list[Finding]:
    session = ctx.session
    rules = ctx.rules
    entries = [e for e in session.archive.entries if e.mtime]
    findings: list[Finding] = []

    if len(session.archive.entries) < rules.integer("zip.min_entries_for_structure_checks", 6):
        return findings

    # ------------------------------------------------------ mtime clustering
    if len(entries) >= 4:
        stamps = sorted(e.mtime for e in entries if e.mtime)
        counts = Counter(stamps)
        most_common_count = counts.most_common(1)[0][1]
        share = most_common_count / len(stamps)
        span = (stamps[-1] - stamps[0]).total_seconds()
        threshold = rules.number("zip.mtime_uniformity_ratio", 0.9)
        if share >= threshold:
            findings.append(
                Finding(
                    rule="zip.uniform-mtimes",
                    title="Archive entry timestamps are all the same",
                    tier=Tier.INTEGRITY,
                    severity=rules.severity("zip.uniform-mtimes", Severity.HIGH),
                    confidence=Confidence.HIGH,
                    summary=(
                        f"{most_common_count} of {len(stamps)} entries share the timestamp "
                        f"{counts.most_common(1)[0][0]}."
                    ),
                    detail=(
                        "MOSS writes captures across the session, so entry timestamps normally "
                        f"spread over its duration. Here they span {span:.0f}s. A single shared "
                        "timestamp is the signature of a folder being re-zipped in one operation."
                    ),
                    benign=(
                        "Some file transfer paths (cloud sync, extract-and-recompress in a chat "
                        "client, a mail gateway) rewrite timestamps without anyone intending to. "
                        "Ask how the file reached you before treating this as deliberate."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.COMPUTED,
                            label="Entry timestamp span",
                            value=f"{stamps[0]} → {stamps[-1]} ({span:.0f}s)",
                        )
                    ],
                    subject=ctx.subject,
                    tags=["rebuild"],
                )
            )

    # ------------------------------------------------- ordering vs capture order
    paired = [
        (shot.at, entry.order)
        for shot in session.screenshots
        if shot.at and (entry := session.archive.entry(shot.file)) is not None
    ]
    if len(paired) >= 4:
        positions = [order for _at, order in sorted(paired, key=lambda pair: pair[0])]
        inversions = sum(
            1 for a, b in zip(positions, positions[1:], strict=False) if b < a
        )
        if inversions > len(positions) * 0.25:
            findings.append(
                Finding(
                    rule="zip.entry-order-mismatch",
                    title="Archive entry order does not follow capture order",
                    tier=Tier.INTEGRITY,
                    severity=rules.severity("zip.entry-order-mismatch", Severity.MEDIUM),
                    confidence=Confidence.MODERATE,
                    summary=f"{inversions} of {len(positions) - 1} consecutive captures are stored out of order.",
                    detail=(
                        "MOSS appends each capture as it is taken, so ZIP entry order normally "
                        "matches capture order. Widespread inversion suggests the archive was "
                        "assembled from a directory listing rather than written by MOSS."
                    ),
                    benign=(
                        "Any re-zip sorts entries by name or by filesystem order. If the file "
                        "names are also sequential this finding is weak on its own — read it "
                        "next to the hash results, not instead of them."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.COMPUTED,
                            label="Out-of-order transitions",
                            value=f"{inversions}/{len(positions) - 1}",
                        )
                    ],
                    subject=ctx.subject,
                    tags=["rebuild"],
                )
            )

    # ------------------------------------------------- compression uniformity
    methods = Counter(e.compress_type for e in session.archive.entries)
    expected = set(rules.get("zip.expected_compress_types") or [8])
    if len(methods) > 1:
        findings.append(
            Finding(
                rule="zip.mixed-compression",
                title="Archive mixes compression methods",
                tier=Tier.INTEGRITY,
                severity=rules.severity("zip.mixed-compression", Severity.MEDIUM),
                confidence=Confidence.MODERATE,
                summary="Members were compressed with more than one method: "
                + ", ".join(f"method {m} ×{c}" for m, c in sorted(methods.items())),
                detail=(
                    "MOSS writes every member with the same compression method. A mixture "
                    "indicates members were added or replaced by a different tool."
                ),
                benign=(
                    "Archive utilities skip compression for files they judge incompressible, so "
                    "a mixture can appear from an innocent repack. It still means the file is "
                    "not the one MOSS wrote."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Compression methods",
                        value=", ".join(f"{m}: {c} entries" for m, c in sorted(methods.items())),
                    )
                ],
                subject=ctx.subject,
                tags=["rebuild"],
            )
        )
    elif methods and set(methods) - expected:
        findings.append(
            Finding(
                rule="zip.unexpected-compression",
                title="Archive uses an unexpected compression method",
                tier=Tier.INTEGRITY,
                severity=Severity.LOW,
                confidence=Confidence.MODERATE,
                summary=f"All members use compression method {next(iter(methods))}, not the expected {sorted(expected)}.",
                detail=(
                    "The reference corpus is uniformly deflate (method 8). Another method points "
                    "at a different packer, which means a different tool wrote this file."
                ),
                benign=(
                    "A newer MOSS build, or a league's own repackaging step, could legitimately "
                    "use a different method. Confirm what the submission pipeline does."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Compression method",
                        value=str(next(iter(methods))),
                    )
                ],
                subject=ctx.subject,
                tags=["rebuild"],
            )
        )

    # ------------------------------------------- entries newer than the session
    tolerance = rules.number("zip.mtime_after_log_tolerance_s", 120)
    last_local = session.session_end
    offset = ctx.clocks.host_offset_minutes
    if last_local and offset is not None and entries:
        last_utc = last_local - timedelta(minutes=offset)
        late = [
            (e, (e.mtime - last_utc).total_seconds())
            for e in entries
            if e.mtime is not None and (e.mtime - last_utc).total_seconds() > tolerance
        ]
        if late:
            worst, delta = max(late, key=lambda pair: pair[1])
            findings.append(
                Finding(
                    rule="zip.entry-written-after-session",
                    title="Files were written into the archive after the session ended",
                    tier=Tier.INTEGRITY,
                    severity=rules.severity("zip.entry-written-after-session", Severity.HIGH),
                    confidence=Confidence.HIGH,
                    summary=f"{len(late)} entry timestamp(s) postdate the last capture, the worst by {delta / 60:.1f} min.",
                    detail=(
                        "Entry timestamps were compared against the last capture time converted "
                        f"to UTC using the host offset derived from this archive "
                        f"({ctx.clocks.offset_label}). An entry stamped after the session ended "
                        "was written after MOSS had finished recording."
                    ),
                    benign=(
                        "MOSS itself writes the log last, so the log entry legitimately postdates "
                        "the final capture. Check whether the late entries are captures or just "
                        "the log before treating this as tampering."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.ARCHIVE_MEMBER,
                            label=e.name,
                            value=f"entry mtime {e.mtime} vs session end {last_utc} UTC",
                            member=e.name,
                        )
                        for e, _seconds in sorted(late, key=lambda pair: pair[1], reverse=True)[:10]
                    ],
                    subject=ctx.subject,
                    tags=["rebuild", "time"],
                )
            )

    return findings
