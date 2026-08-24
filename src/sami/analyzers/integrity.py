"""Tier 1 — per-file integrity.

The strongest evidence the tool produces, and the cheapest: MOSS writes the
SHA-256 of every file it packages into the log as ``Zip CRC:`` (RESEARCH §5G,
verified by recomputation). Recomputing those hashes answers "was this archive
edited after MOSS wrote it?" with arithmetic rather than judgement.

Three questions, in order of how hard they are to argue with:

1. does every file's content still hash to what the log says?
2. is the set of files in the ZIP the set the log describes?
3. is the log itself structurally complete?
"""

from __future__ import annotations

from mosslib import logcrc
from mosslib.hashing import looks_like_sha256
from sami.context import AnalysisContext
from sami.findings import Confidence, Evidence, EvidenceKind, Finding, Severity, Tier

BENIGN_HASH = (
    "A mismatch can be produced innocently by re-zipping the archive with a tool that "
    "rewrites files, by antivirus quarantining and restoring a capture, or by a partial "
    "upload. None of those are the player editing evidence — but all of them mean the "
    "archive is no longer the one MOSS produced, and it can no longer be relied on."
)


def _log_line_evidence(ctx: AnalysisContext, line: int, label: str) -> Evidence:
    log_line = ctx.session.line(line)
    return Evidence(
        kind=EvidenceKind.LOG_LINE,
        label=label,
        value=(log_line.raw.strip() if log_line else ""),
        line=line,
    )


def analyze(ctx: AnalysisContext) -> list[Finding]:
    session = ctx.session
    findings: list[Finding] = []
    rules = ctx.rules

    # ---------------------------------------------------------------- hashes
    logged: dict[str, tuple[str, int, str]] = {}
    for shot in session.screenshots:
        if shot.crc:
            logged[shot.file] = (shot.crc, shot.line, "screenshot")
    for cap in session.captured_files:
        if cap.crc:
            logged[cap.file] = (cap.crc, cap.line, "captured file")

    actual = {name.replace("\\", "/").rsplit("/", 1)[-1]: digest for name, digest in ctx.scan.member_sha256.items()}

    mismatched: list[tuple[str, str, str, int]] = []
    unverifiable: list[tuple[str, str, int]] = []
    verified = 0
    for name, (crc, line, _kind) in sorted(logged.items()):
        recomputed = actual.get(name)
        if recomputed is None:
            continue  # handled by the set-reconciliation rules below
        if not looks_like_sha256(crc):
            unverifiable.append((name, crc, line))
            continue
        if recomputed.lower() == crc.lower():
            verified += 1
        else:
            mismatched.append((name, crc.lower(), recomputed, line))

    if mismatched:
        evidence = [
            Evidence(
                kind=EvidenceKind.COMPUTED,
                label=f"{name}: log says / file is",
                value=f"{expected}\n{got}",
                line=line,
                member=name,
            )
            for name, expected, got, line in mismatched[:20]
        ]
        evidence.append(
            Evidence(
                kind=EvidenceKind.COMPUTED,
                label="Files verified against the log",
                value=f"{verified} matched, {len(mismatched)} did not",
            )
        )
        findings.append(
            Finding(
                rule="integrity.file-hash-mismatch",
                title="File contents do not match the hash MOSS recorded",
                tier=Tier.INTEGRITY,
                severity=rules.severity("integrity.file-hash-mismatch", Severity.CRITICAL),
                confidence=Confidence.CERTAIN,
                summary=(
                    f"{len(mismatched)} of {verified + len(mismatched)} verifiable files hash to "
                    "something other than the value in the log."
                ),
                detail=(
                    "MOSS writes the SHA-256 of each file's contents into the log as 'Zip CRC:'. "
                    "Each file in the ZIP was re-hashed and compared. A mismatch means the file "
                    "in the archive is not the file MOSS hashed. This is arithmetic on the "
                    "submitted archive: it needs no interpretation and no baseline."
                ),
                benign=BENIGN_HASH,
                evidence=evidence,
                subject=ctx.subject,
                tags=["tamper", "hash"],
            )
        )

    if unverifiable:
        findings.append(
            Finding(
                rule="integrity.unverifiable-hash",
                title="Log records a hash in an unexpected format",
                tier=Tier.INTEGRITY,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                summary=f"{len(unverifiable)} 'Zip CRC:' values are not 64 hex characters.",
                detail=(
                    "Verification assumes 'Zip CRC:' is a SHA-256 digest, which held for every "
                    "file across the reference corpus. A different length means either a "
                    "different MOSS version or an edited log; either way those files could not "
                    "be verified and must be treated as unchecked, not as clean."
                ),
                benign=(
                    "A MOSS version older or newer than the corpus may write a different digest "
                    "format. That is a gap in this tool's coverage, not evidence against anyone."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.LOG_LINE,
                        label=name,
                        value=crc,
                        line=line,
                        member=name,
                    )
                    for name, crc, line in unverifiable[:20]
                ],
                subject=ctx.subject,
                tags=["hash", "coverage"],
            )
        )

    # ------------------------------------------------------ set reconciliation
    log_name = (rules.get("integrity.expected_log_name") or "Logfile.log").lower()
    allowed_extra = {n.lower() for n in rules.strings("integrity.allow_extra_members")}
    zip_names = {name.replace("\\", "/").rsplit("/", 1)[-1] for name in ctx.scan.member_sha256}

    extra = sorted(
        n for n in zip_names
        if n.lower() != log_name and n not in logged and n.lower() not in allowed_extra
    )
    missing = sorted(n for n in logged if n not in zip_names)

    if extra:
        findings.append(
            Finding(
                rule="integrity.file-not-in-log",
                title="Archive contains files the log does not mention",
                tier=Tier.INTEGRITY,
                severity=rules.severity("integrity.file-not-in-log", Severity.HIGH),
                confidence=Confidence.CERTAIN,
                summary=f"{len(extra)} file(s) present in the ZIP but absent from the log.",
                detail=(
                    "MOSS lists every file it packages. A file in the ZIP with no corresponding "
                    "log record was added after MOSS finished, which means the archive was opened "
                    "and rebuilt."
                ),
                benign=(
                    "Some archive tools inject metadata files (Thumbs.db, .DS_Store, __MACOSX). "
                    "Check the names before treating this as deliberate: an added JPEG is a very "
                    "different matter from an added .DS_Store."
                ),
                evidence=[
                    Evidence(kind=EvidenceKind.ARCHIVE_MEMBER, label="Unlisted member", value=name, member=name)
                    for name in extra[:20]
                ],
                subject=ctx.subject,
                tags=["tamper", "set"],
            )
        )

    if missing:
        findings.append(
            Finding(
                rule="integrity.file-missing",
                title="Log records files that are not in the archive",
                tier=Tier.INTEGRITY,
                severity=rules.severity("integrity.file-missing", Severity.CRITICAL),
                confidence=Confidence.CERTAIN,
                summary=f"{len(missing)} file(s) described in the log are absent from the ZIP.",
                detail=(
                    "MOSS logged these files with their hashes, so they existed when the session "
                    "ended. They are not in the submitted archive. Removing captures is the "
                    "single most direct way to hide what was on screen, and the vendor's own "
                    "instructions to players are explicit that files must not be removed."
                ),
                benign=(
                    "A failed or truncated upload, or an archive re-saved by a tool that dropped "
                    "entries, produces the same result. Ask for a fresh copy of the original ZIP "
                    "before drawing any conclusion — a re-supplied complete archive settles it."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.LOG_LINE,
                        label=f"Missing: {name}",
                        value=_log_line_evidence(ctx, logged[name][1], name).value,
                        line=logged[name][1],
                        member=name,
                    )
                    for name in missing[:20]
                ],
                subject=ctx.subject,
                tags=["tamper", "set"],
            )
        )

    # Only claim a clean bill once the file *set* reconciles too: "every file
    # matches" next to "a file is missing" reads as reassurance it has not earned.
    if verified and not mismatched and not unverifiable and not extra and not missing:
        findings.append(
            Finding(
                rule="integrity.all-files-verified",
                title="Every file matches the hash MOSS recorded",
                tier=Tier.INTEGRITY,
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                summary=f"{verified} files re-hashed and matched the log exactly, and the file set reconciles.",
                detail=(
                    "Each file's SHA-256 was recomputed from the archive and compared against "
                    "its 'Zip CRC:' entry in the log. All matched."
                ),
                benign=(
                    "This shows the archive was not modified after MOSS wrote it. It says nothing "
                    "about whether the session itself was honest — a player can submit an "
                    "untampered recording of a session in which they cheated."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Files verified",
                        value=str(verified),
                    )
                ],
                subject=ctx.subject,
                tags=["hash"],
            )
        )

    # --------------------------------------------------- screenshot sequence
    indices = sorted(s.index for s in session.screenshots if s.index is not None)
    if indices:
        expected = set(range(indices[0], indices[-1] + 1))
        gaps = sorted(expected - set(indices))
        if gaps:
            findings.append(
                Finding(
                    rule="integrity.screenshot-sequence-gap",
                    title="Gap in the screenshot numbering",
                    tier=Tier.INTEGRITY,
                    severity=rules.severity("integrity.screenshot-sequence-gap", Severity.HIGH),
                    confidence=Confidence.HIGH,
                    summary=f"Missing capture numbers: {', '.join(str(g) for g in gaps[:12])}"
                    + (" …" if len(gaps) > 12 else ""),
                    detail=(
                        "MOSS numbers captures sequentially from the session start. A number "
                        f"absent from the log means a capture that existed was not recorded. "
                        f"Range seen: {indices[0]:03d}–{indices[-1]:03d}, {len(indices)} present, "
                        f"{len(gaps)} missing."
                    ),
                    benign=(
                        "A capture that failed at the moment MOSS tried to take it (a full-screen "
                        "exclusive mode transition, a GPU driver reset) can consume a number "
                        "without producing a file. Correlate with the timeline: a gap that also "
                        "shows a long interval is more interesting than one that does not."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.COMPUTED,
                            label="Sequence",
                            value=f"{indices[0]:03d}–{indices[-1]:03d} with {len(gaps)} missing",
                        )
                    ],
                    subject=ctx.subject,
                    tags=["sequence"],
                )
            )

    # ----------------------------------------------------- log structure
    if session.archive.entries and not any(
        e.name.lower().endswith(".log") for e in session.archive.entries
    ):
        findings.append(
            Finding(
                rule="integrity.log-missing",
                title="Archive contains no MOSS log",
                tier=Tier.INTEGRITY,
                severity=Severity.CRITICAL,
                confidence=Confidence.CERTAIN,
                summary="No Logfile.log in the archive; nothing about the session can be verified.",
                detail="Every verification this tool performs reads the log. Without it the archive is not reviewable.",
                benign="The wrong file may have been uploaded. Request the original MOSS ZIP.",
                evidence=[
                    Evidence(
                        kind=EvidenceKind.ARCHIVE_MEMBER,
                        label="Members",
                        value=", ".join(sorted(zip_names)[:10]) or "(empty archive)",
                    )
                ],
                subject=ctx.subject,
                tags=["structure"],
            )
        )
        return findings

    # ------------------------------------------------- the undocumented footer
    if session.global_log_crc and ctx.scan.log_text:
        file_crcs = [s.crc for s in session.screenshots if s.crc] + [
            c.crc for c in session.captured_files if c.crc
        ]
        matched, explanation = logcrc.verify(
            ctx.scan.log_text, session.global_log_crc, file_crcs
        )
        if matched:
            findings.append(
                Finding(
                    rule="integrity.log-crc-verified",
                    title="The whole log verifies against its own footer digest",
                    tier=Tier.INTEGRITY,
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    summary=f"'Global log CRC' reproduced as {explanation}.",
                    detail=(
                        "MOSS's footer algorithm is undocumented, so this tool tries a set of "
                        "candidate algorithms and inputs against every log it reads. One "
                        "reproduced the recorded value exactly, which means the log as a whole — "
                        "not only the files it lists — is unmodified."
                    ),
                    benign=(
                        "Whole-log verification shows the log was not edited after MOSS wrote "
                        "it. It says nothing about whether what MOSS recorded was a clean session."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.COMPUTED,
                            label="Global log CRC",
                            value=f"{session.global_log_crc} — reproduced by {explanation}",
                        )
                    ],
                    subject=ctx.subject,
                    tags=["hash", "structure"],
                )
            )
        else:
            findings.append(
                Finding(
                    rule="integrity.log-crc-unverified",
                    title="The log's own footer digest could not be checked",
                    tier=Tier.INTEGRITY,
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    summary=f"'Global log CRC' is present but {explanation}.",
                    detail=(
                        "MOSS closes each log with a digest of the whole log, computed by an "
                        "algorithm the vendor has not published. Candidate algorithms and inputs "
                        "were tried and none reproduced the recorded value, so the log as a whole "
                        "is unverified. Per-file verification is unaffected and is reported above."
                    ),
                    benign=(
                        "This is a gap in this tool's knowledge, not a finding against anyone. "
                        "Confirming the algorithm with the vendor would close it; until then, "
                        "treat whole-log integrity as unchecked rather than as failed."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.COMPUTED,
                            label="Global log CRC (algorithm unconfirmed)",
                            value=session.global_log_crc,
                        )
                    ],
                    subject=ctx.subject,
                    tags=["hash", "coverage", "limitation"],
                )
            )

    if session.log_line_count and session.global_log_crc is None:
        findings.append(
            Finding(
                rule="integrity.log-truncated",
                title="Log has no closing 'Global log CRC' line",
                tier=Tier.INTEGRITY,
                severity=rules.severity("integrity.log-truncated", Severity.HIGH),
                confidence=Confidence.HIGH,
                summary="The log ends without its footer, so it is incomplete.",
                detail=(
                    "MOSS closes every log with 'Global log CRC:'. Its absence means the log was "
                    f"truncated or edited. The log here ends at line {session.log_line_count}: "
                    f"{(session.lines[-1].raw.strip()[:80] if session.lines else '')!r}"
                ),
                benign=(
                    "A session that ended in a crash, a forced shutdown or a power loss can leave "
                    "the log unfinished through no fault of the player. That is still an "
                    "incomplete record, so the session should be re-submitted or discounted "
                    "rather than treated as evidence either way."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.LOG_LINE,
                        label="Last line of the log",
                        value=(session.lines[-1].raw.strip() if session.lines else ""),
                        line=session.log_line_count,
                    )
                ],
                subject=ctx.subject,
                tags=["structure", "tamper"],
            )
        )

    if session.header_started_at is None:
        findings.append(
            Finding(
                rule="integrity.log-header-missing",
                title="Log has no session header",
                tier=Tier.INTEGRITY,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                summary="No 'SHAS2 mode started' line, so the session's own start time is unknown.",
                detail=(
                    "The header carries MOSS's network-synced start time, the game and the "
                    "architecture. Without it the network-clock cross-check cannot run, which "
                    "removes the main defence against a manipulated system clock."
                ),
                benign=(
                    "An unrecognised MOSS version may word the header differently; check the "
                    "unparsed-lines appendix before treating this as removal."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Parsed log lines",
                        value=str(session.log_line_count),
                    )
                ],
                subject=ctx.subject,
                tags=["structure"],
            )
        )

    return findings
