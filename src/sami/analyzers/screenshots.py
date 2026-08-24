"""Tier 2 — capture-file analysis without decoding pixels.

Three things are readable from the bytes alone, and all three earned their
place from the reference corpus (RESEARCH §5E):

* **blank frames** — 39–42 KB against a ~150 KB median turned out to be bare
  desktop wallpaper: no game, no taskbar, no icons;
* **resolution changes mid-session** — a monitor swap, or a capture switching
  from the full virtual desktop to a single screen;
* **structurally broken frames** — truncated or headerless JPEGs.

Deliberately no pixel decoding: it buys perceptual hashing at the cost of a
large native attack surface fed by attacker-controlled files. Duplicate
detection here is exact-hash only, which catches a replayed identical frame and
honestly misses a re-encoded one.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from mosslib.timeutil import median
from sami.context import AnalysisContext
from sami.findings import Confidence, Evidence, EvidenceKind, Finding, Severity, Tier


def analyze(ctx: AnalysisContext) -> list[Finding]:  # noqa: C901 - sequential rules
    rules = ctx.rules
    findings: list[Finding] = []
    jpegs = ctx.scan.jpegs
    if not jpegs:
        return findings

    sizes = {name: info.size for name, info in jpegs.items()}
    mid = median([float(s) for s in sizes.values()]) or 0.0

    # ------------------------------------------------------------ blank frames
    ratio = rules.number("screenshots.blank_frame_size_ratio", 0.4)
    floor = rules.number("screenshots.blank_frame_min_median_bytes", 20000)
    if mid >= floor:
        blank = sorted(
            (name for name, size in sizes.items() if size < mid * ratio),
            key=lambda n: sizes[n],
        )
        if blank:
            findings.append(
                Finding(
                    rule="screenshots.blank-frame",
                    title="Captures far smaller than the rest of the session",
                    tier=Tier.ENVIRONMENT,
                    severity=rules.severity("screenshots.blank-frame", Severity.MEDIUM),
                    confidence=Confidence.HIGH,
                    summary=(
                        f"{len(blank)} capture(s) under {mid * ratio / 1024:.0f} KB against a "
                        f"{mid / 1024:.0f} KB median."
                    ),
                    detail=(
                        "JPEG size tracks image complexity. In the reference corpus, frames at "
                        "roughly a quarter of the median size were bare desktop wallpaper — no "
                        "game, no taskbar, no icons. A capture with nothing in it records nothing "
                        "about the match, and repeated blanks are what a capture-evasion bypass "
                        "produces."
                    ),
                    benign=(
                        "Alt-tabbing to a plain desktop, a loading screen, a black transition "
                        "between rounds, or a grab that landed while the screen was blanking all "
                        "produce small frames. Open them: the answer is immediate, and this "
                        "finding exists to tell you which ones to open."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.SCREENSHOT,
                            label=name,
                            value=f"{sizes[name] / 1024:.0f} KB (median {mid / 1024:.0f} KB)",
                            member=name,
                        )
                        for name in blank[:15]
                    ],
                    subject=ctx.subject,
                    tags=["screenshot", "blank"],
                )
            )

    # -------------------------------------------------------- identical frames
    by_hash: dict[str, list[str]] = defaultdict(list)
    for name in jpegs:
        digest = ctx.scan.member_sha256.get(name)
        if digest:
            by_hash[digest].append(name)
    duplicates = {h: sorted(names) for h, names in by_hash.items() if len(names) > 1}
    if duplicates:
        total = sum(len(names) for names in duplicates.values())
        findings.append(
            Finding(
                rule="screenshots.identical-frames",
                title="Byte-identical captures",
                tier=Tier.ENVIRONMENT,
                severity=rules.severity("screenshots.identical-frames", Severity.MEDIUM),
                confidence=Confidence.CERTAIN,
                summary=f"{total} captures across {len(duplicates)} group(s) are byte-for-byte identical.",
                detail=(
                    "Two captures taken at different moments of a live session are never "
                    "byte-identical — JPEG encoding of even a static scene varies with the "
                    "smallest change. Identical files mean the same image was written twice: a "
                    "frozen capture source, or a frame copied over another."
                ),
                benign=(
                    "A genuinely frozen screen — a hung game, a static loading screen, an idle "
                    "desktop between rounds — can produce identical grabs, as can a capture "
                    "backend that returned a cached frame."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.SCREENSHOT,
                        label=f"{len(names)} identical",
                        value=", ".join(names),
                        member=names[0],
                    )
                    for names in list(duplicates.values())[:10]
                ],
                subject=ctx.subject,
                tags=["screenshot", "duplicate"],
            )
        )

    # ---------------------------------------------------- resolution consistency
    dimensions = Counter(
        info.dimensions for info in jpegs.values() if info.dimensions is not None
    )
    if len(dimensions) > 1:
        common = dimensions.most_common()
        odd = [
            name
            for name, info in sorted(jpegs.items())
            if info.dimensions and info.dimensions != common[0][0]
        ]
        findings.append(
            Finding(
                rule="screenshots.resolution-change",
                title="Capture resolution changed during the session",
                tier=Tier.ENVIRONMENT,
                severity=rules.severity("screenshots.resolution-change", Severity.MEDIUM),
                confidence=Confidence.HIGH,
                summary=" / ".join(f"{w}×{h} ×{count}" for (w, h), count in common[:4]),
                detail=(
                    "MOSS captures the whole virtual desktop, so the frame size reflects the "
                    "desktop layout. A change mid-session means a display was attached, detached "
                    "or reconfigured while the match was being recorded — which changes what the "
                    "capture can see."
                ),
                benign=(
                    "A monitor going to sleep, a resolution change on launching the game, a "
                    "second screen switched off to reduce distraction, or a driver reset all do "
                    "this legitimately and often."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.SCREENSHOT,
                        label=name,
                        value=f"{jpegs[name].width}×{jpegs[name].height}",
                        member=name,
                    )
                    for name in odd[:10]
                ],
                subject=ctx.subject,
                tags=["screenshot", "display"],
            )
        )

    # ------------------------------------------------------ structural problems
    broken = sorted(
        name for name, info in jpegs.items() if info.error or info.truncated or not info.valid_soi
    )
    if broken:
        findings.append(
            Finding(
                rule="screenshots.corrupt-frame",
                title="Captures are structurally incomplete",
                tier=Tier.ENVIRONMENT,
                severity=rules.severity("screenshots.corrupt-frame", Severity.MEDIUM),
                confidence=Confidence.HIGH,
                summary=f"{len(broken)} capture(s) are truncated or not valid JPEG files.",
                detail=(
                    "Each capture's JPEG structure was checked without decoding it: start and end "
                    "markers, and segment lengths that stay inside the file. A file that fails "
                    "this was not written completely, or was replaced with something that is not "
                    "the capture MOSS took."
                ),
                benign=(
                    "An interrupted write, a full disk or a crash mid-capture truncates a file "
                    "with nobody's involvement. If the same files also fail their hash check, "
                    "that combination is the thing to look at."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.SCREENSHOT,
                        label=name,
                        value=jpegs[name].error or ("truncated" if jpegs[name].truncated else "invalid"),
                        member=name,
                    )
                    for name in broken[:12]
                ],
                subject=ctx.subject,
                tags=["screenshot", "corrupt"],
            )
        )

    # ------------------------------------------------------ standing limitation
    findings.append(
        Finding(
            rule="screenshots.no-content-analysis",
            title="Capture contents were not analysed",
            tier=Tier.ENVIRONMENT,
            severity=Severity.INFO,
            confidence=Confidence.CERTAIN,
            summary=f"{len(jpegs)} captures checked for size, structure and duplication only.",
            detail=(
                "This release reads JPEG headers, not pixels: no OCR of the taskbar clock, no "
                "HUD reading, no perceptual hashing, no second-monitor content classification. "
                "What is on screen still has to be looked at by a person."
            ),
            benign=(
                "The contact sheet in this report orders the frames so the flagged ones come "
                "first. Everything else is unreviewed, not cleared."
            ),
            evidence=[
                Evidence(kind=EvidenceKind.COMPUTED, label="Captures in archive", value=str(len(jpegs)))
            ],
            subject=ctx.subject,
            tags=["screenshot", "limitation"],
        )
    )

    return findings
