"""Tier 3 — behavioural statistics over MOSS's macro histograms.

MOSS already measures inter-event intervals and draws them as ASCII art nobody
reads. :mod:`mosslib.histogram` turns the drawing back into numbers; this
module scores them against the *vendor's own* published human baselines
(RESEARCH §3.8) rather than against thresholds this project invented:

* no player sustains a double-click interval below 80 ms;
* no player sustains a same-key double-press below 100 ms;
* human input spreads across the 0–140 ms range — a sharp peak does not.

Everything here is corroborating evidence and is labelled as such. A tool that
opens with a behavioural score gets dismissed the first time it flags a good
player, and rightly.
"""

from __future__ import annotations

from mosslib.histogram import recovered_events
from mosslib.model import Histogram
from sami.context import AnalysisContext
from sami.findings import Confidence, Evidence, EvidenceKind, Finding, Severity, Tier

CAVEAT = (
    "Tier 3 findings corroborate; they never conclude. High-DPI mice, sensitive switches, "
    "double-click faults in a worn switch, and rapid-fire modes built into ordinary gaming "
    "peripherals all compress intervals without any macro involved."
)


def peak_share(hist: Histogram) -> float | None:
    total = recovered_events(hist)
    if total <= 0:
        return None
    return max(b.count for b in hist.buckets) / total


def weighted_mean(hist: Histogram) -> float | None:
    total = recovered_events(hist)
    if total <= 0:
        return None
    return sum(b.lower * b.count for b in hist.buckets) / total


def coefficient_of_variation(hist: Histogram) -> float | None:
    total = recovered_events(hist)
    mean = weighted_mean(hist)
    if total <= 1 or mean is None or mean <= 0:
        return None
    variance = sum(b.count * (b.lower - mean) ** 2 for b in hist.buckets) / total
    return (variance**0.5) / mean


def _describe(hist: Histogram) -> str:
    return ", ".join(
        f"{b.lower:.0f}{hist.unit}×{b.count}" for b in hist.buckets if b.count
    )[:400]


def _is_double_click(hist: Histogram) -> bool:
    keys = [k.upper() for k in hist.keys]
    return len(keys) == 2 and keys[0] == keys[1] and "CLICK" in keys[0]


def _is_same_key(hist: Histogram) -> bool:
    keys = [k.upper() for k in hist.keys]
    return len(keys) == 2 and keys[0] == keys[1] and "CLICK" not in keys[0]


def analyze(ctx: AnalysisContext) -> list[Finding]:  # noqa: C901 - one rule per shape
    rules = ctx.rules
    findings: list[Finding] = []
    histograms = ctx.session.histograms
    if not histograms:
        return findings

    min_events = rules.integer("behaviour.min_events_for_scoring", 25)
    double_ms = rules.number("behaviour.double_click_min_interval_ms", 80)
    same_key_ms = rules.number("behaviour.same_key_min_interval_ms", 100)
    review_share = rules.number("behaviour.peak_share_review_threshold", 0.6)
    high_share = rules.number("behaviour.peak_share_high_threshold", 0.8)

    unreadable = [h for h in histograms if h.reconstruction == "failed"]
    scored = [
        h
        for h in histograms
        if h.reconstruction != "failed" and recovered_events(h) >= min_events
    ]

    # ------------------------------------------- vendor baselines: fast intervals
    for hist in scored:
        if hist.kind != "interval" or hist.unit != "ms":
            continue
        limit = (
            double_ms
            if _is_double_click(hist)
            else same_key_ms
            if _is_same_key(hist)
            else None
        )
        if limit is None:
            continue
        fast = sum(b.count for b in hist.buckets if b.lower < limit)
        total = recovered_events(hist)
        share = fast / total if total else 0.0
        if fast and share >= 0.5:
            findings.append(
                Finding(
                    rule="behaviour.below-human-interval",
                    title="Input intervals sustained below the vendor's human floor",
                    tier=Tier.BEHAVIOURAL,
                    severity=rules.severity("behaviour.below-human-interval", Severity.MEDIUM),
                    confidence=Confidence.LOW if hist.reconstruction == "partial" else Confidence.MODERATE,
                    summary=(
                        f"{hist.label}: {fast} of {total} intervals ({share:.0%}) are under "
                        f"{limit:.0f} ms."
                    ),
                    detail=(
                        "MOSS's own documentation states that no player sustains a double-click "
                        f"interval below {double_ms:.0f} ms or a same-key double-press below "
                        f"{same_key_ms:.0f} ms. This histogram was reconstructed from the log's "
                        f"ASCII drawing ({hist.reconstruction} reconstruction) and shows "
                        f"{share:.0%} of events below that floor. Distribution: {_describe(hist)}."
                    ),
                    benign=CAVEAT,
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.LOG_LINE,
                            label=hist.label,
                            value=_describe(hist),
                            line=hist.line,
                        )
                    ],
                    subject=ctx.subject,
                    tags=["behaviour", "macro"],
                )
            )

    # ------------------------------------------------------------ peak sharpness
    for hist in scored:
        if hist.kind != "interval":
            continue
        sharpness = peak_share(hist)
        if sharpness is None or sharpness < review_share:
            continue
        cv = coefficient_of_variation(hist)
        findings.append(
            Finding(
                rule="behaviour.sharp-interval-peak",
                title="Input intervals cluster far more tightly than human input does",
                tier=Tier.BEHAVIOURAL,
                severity=rules.severity(
                    "behaviour.sharp-interval-peak",
                    Severity.MEDIUM if sharpness >= high_share else Severity.LOW,
                ),
                confidence=Confidence.LOW if hist.reconstruction == "partial" else Confidence.MODERATE,
                summary=(
                    f"{hist.label}: {sharpness:.0%} of intervals fall in a single bucket"
                    + (f" (coefficient of variation {cv:.2f})." if cv is not None else ".")
                ),
                detail=(
                    "The vendor's stated reading of these graphs is that the bigger and sharper "
                    "the peak, the higher the macro suspicion, and that human input spreads "
                    f"across the whole 0–140 ms range. Here {sharpness:.0%} of "
                    f"{recovered_events(hist)} events sit in one bucket "
                    f"({hist.reconstruction} reconstruction). Distribution: {_describe(hist)}."
                ),
                benign=(
                    CAVEAT
                    + " A tight peak is also what a repeated in-game action with a fixed "
                    "animation length produces, and what a small sample looks like by chance."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.LOG_LINE,
                        label=hist.label,
                        value=_describe(hist),
                        line=hist.line,
                    )
                ],
                subject=ctx.subject,
                tags=["behaviour", "macro"],
            )
        )

    # --------------------------------------------------------------- no recoil
    small_px = rules.number("behaviour.no_recoil_small_move_px", 6)
    small_share_limit = rules.number("behaviour.no_recoil_small_move_share", 0.85)
    for hist in scored:
        if hist.kind != "no_recoil":
            continue
        total = recovered_events(hist)
        small = sum(b.count for b in hist.buckets if b.lower <= small_px)
        share = small / total if total else 0.0
        if share >= small_share_limit:
            findings.append(
                Finding(
                    rule="behaviour.no-recoil-pattern",
                    title="Downward mouse movement is dominated by tiny, uniform steps",
                    tier=Tier.BEHAVIOURAL,
                    severity=rules.severity("behaviour.no-recoil-pattern", Severity.MEDIUM),
                    confidence=Confidence.LOW,
                    summary=f"{share:.0%} of downward moves while firing are ≤{small_px:.0f} px.",
                    detail=(
                        "MOSS records downward mouse movement during sustained fire, the pattern "
                        "recoil control produces. The vendor's stated reading is that dense "
                        "clusters of tiny movements, or a few large-pixel jumps, are what "
                        f"scripted compensation looks like. Here {small} of {total} recorded "
                        f"moves are at or below {small_px:.0f} px "
                        f"({hist.reconstruction} reconstruction)."
                    ),
                    benign=(
                        CAVEAT
                        + " A player with a very high DPI, or one who has drilled a specific "
                        "weapon's pattern for years, produces small consistent corrections too. "
                        "This is the weakest class of finding in the tool and must never stand "
                        "alone."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.LOG_LINE,
                            label=hist.label,
                            value=_describe(hist),
                            line=hist.line,
                        )
                    ],
                    subject=ctx.subject,
                    tags=["behaviour", "recoil"],
                )
            )

    # ---------------------------------------------------- reconstruction quality
    partial = [h for h in histograms if h.reconstruction == "partial"]
    if unreadable or partial:
        findings.append(
            Finding(
                rule="behaviour.reconstruction-incomplete",
                title="Some input histograms could not be fully reconstructed",
                tier=Tier.BEHAVIOURAL,
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                summary=(
                    f"{len(unreadable)} unreadable, {len(partial)} partial, "
                    f"{len(histograms) - len(unreadable) - len(partial)} fully recovered."
                ),
                detail=(
                    "MOSS's histograms are ASCII drawings with no documented format. Where the "
                    "recovered bucket counts do not sum to the event total the drawing states, "
                    "the reconstruction is marked partial and any finding derived from it is "
                    "downgraded to low confidence. Read the original ASCII in the log for these."
                ),
                benign=(
                    "This is a limitation of reading undocumented ASCII art, not a property of "
                    "the player's input. Unreconstructed histograms are unchecked, not clean."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.LOG_LINE,
                        label=h.label,
                        value=f"{h.reconstruction} ({recovered_events(h)} of {h.total_events or '?'} events recovered)",
                        line=h.line,
                    )
                    for h in (unreadable + partial)[:10]
                ],
                subject=ctx.subject,
                tags=["behaviour", "limitation"],
            )
        )

    return findings
