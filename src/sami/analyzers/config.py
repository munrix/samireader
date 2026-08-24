"""Tier 2 — game configuration forensics.

MOSS captures every ``GameSettings.ini`` it finds, one per profile GUID
(RESEARCH §6.1). The highest-value key by a wide margin is
``VulkanWhitelistedLayers``: a *user-editable allowlist of code injected into
the game process*. An unrecognised layer there is a direct injection vector and
costs one string comparison to find.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict

from sami.context import AnalysisContext
from sami.findings import Confidence, Evidence, EvidenceKind, Finding, Severity, Tier

SECTION_RE = re.compile(r"^\s*\[(?P<name>[^\]]+)\]\s*$")
KEY_RE = re.compile(r"^\s*(?P<key>[^=;#\[][^=]*?)\s*=\s*(?P<value>.*?)\s*$")


def parse_ini(text: str) -> dict[str, str]:
    """Flat key→value view of an INI file. Later keys win; sections are ignored.

    MOSS's captured configs are flat enough that section-awareness buys nothing,
    and a tolerant flat read survives the malformed files real machines produce.
    """
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith((";", "#")) or SECTION_RE.match(line):
            continue
        match = KEY_RE.match(line)
        if match:
            values[match.group("key").strip()] = match.group("value").strip()
    return values


def _number(value: str) -> float | None:
    try:
        return float(value.strip())
    except (TypeError, ValueError):
        return None


def analyze(ctx: AnalysisContext) -> list[Finding]:  # noqa: C901 - sequential rules
    rules = ctx.rules
    findings: list[Finding] = []
    configs = {name: parse_ini(text) for name, text in ctx.scan.configs.items()}
    if not configs:
        return findings

    # ------------------------------------------------- vulkan injection allowlist
    allow = {layer.lower() for layer in rules.strings("config.vulkan_layer_allowlist")}
    unknown: dict[str, list[str]] = defaultdict(list)
    for name, values in configs.items():
        raw = values.get("VulkanWhitelistedLayers")
        if not raw:
            continue
        for layer in (entry.strip() for entry in raw.split(";")):
            if layer and layer.lower() not in allow:
                unknown[name].append(layer)

    if unknown:
        layers = sorted({layer for entries in unknown.values() for layer in entries})
        findings.append(
            Finding(
                rule="config.unknown-vulkan-layer",
                title="Unrecognised Vulkan layer whitelisted in the game config",
                tier=Tier.ENVIRONMENT,
                severity=rules.severity("config.unknown-vulkan-layer", Severity.HIGH),
                confidence=Confidence.HIGH,
                summary=", ".join(layers[:6]) + (" …" if len(layers) > 6 else ""),
                detail=(
                    "'VulkanWhitelistedLayers' is a player-editable list of Vulkan layers allowed "
                    "to load into the game process — that is, code permitted to run inside the "
                    "game. The rule pack's allowlist covers the layers seen on ordinary machines "
                    "(Overwolf, Steam, vendor drivers). Anything else was added by someone, and "
                    "an unrecognised layer name is worth identifying precisely."
                ),
                benign=(
                    "Capture tools, monitoring overlays and GPU vendor utilities all add layers "
                    "legitimately, and the shipped allowlist is not exhaustive. Identify the "
                    "layer's owning software first — then add it to the league's rule pack so it "
                    "stops firing."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.CONFIG,
                        label=name,
                        value=", ".join(entries),
                        member=name,
                    )
                    for name, entries in sorted(unknown.items())[:10]
                ],
                subject=ctx.subject,
                tags=["config", "injection"],
            )
        )

    # -------------------------------------------------------- out-of-range values
    ranges = rules.get("config.numeric_ranges") or {}
    out_of_range: list[tuple[str, str, str, float, float]] = []
    for name, values in configs.items():
        for key, bounds in ranges.items():
            if key not in values or not isinstance(bounds, list) or len(bounds) != 2:
                continue
            number = _number(values[key])
            if number is None:
                continue
            low, high = float(bounds[0]), float(bounds[1])
            if not low <= number <= high:
                out_of_range.append((name, key, values[key], low, high))

    if out_of_range:
        findings.append(
            Finding(
                rule="config.value-out-of-range",
                title="Config value outside the range the game's own UI allows",
                tier=Tier.ENVIRONMENT,
                severity=rules.severity("config.value-out-of-range", Severity.MEDIUM),
                confidence=Confidence.HIGH,
                summary=", ".join(f"{key}={value}" for _n, key, value, _lo, _hi in out_of_range[:6]),
                detail=(
                    "These keys were set to values the in-game settings screen cannot produce, "
                    "which means the file was edited by hand or by a tool. Editing a config is "
                    "not cheating and is usually not even against the rules — it is a reliable "
                    "indicator that the player modifies game files, which is context for "
                    "everything else in the report."
                ),
                benign=(
                    "Hand-editing sensitivity or FOV beyond the slider range is a widespread and "
                    "openly discussed practice, and the shipped ranges are approximate and "
                    "version-dependent. Check the league's own rules on config edits before "
                    "treating this as a violation."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.CONFIG,
                        label=f"{name}: {key}",
                        value=f"{value} (expected {low}–{high})",
                        member=name,
                    )
                    for name, key, value, low, high in out_of_range[:10]
                ],
                subject=ctx.subject,
                tags=["config"],
            )
        )

    # ------------------------------------------------------------------- flags
    flags = rules.get("config.flag_keys") or {}
    hits = [
        (name, key, values[key])
        for name, values in configs.items()
        for key, expected in flags.items()
        if key in values and values[key].strip() == str(expected)
    ]
    if hits:
        findings.append(
            Finding(
                rule="config.flag-enabled",
                title="Developer or debug flag enabled in the game config",
                tier=Tier.ENVIRONMENT,
                severity=rules.severity("config.flag-enabled", Severity.LOW),
                confidence=Confidence.HIGH,
                summary=", ".join(f"{key}={value}" for _n, key, value in hits[:6]),
                detail=(
                    "Flags such as Console=1 expose developer functionality that is not reachable "
                    "from the normal UI. Whether that matters depends entirely on what the flag "
                    "does in the title and season in question."
                ),
                benign=(
                    "These flags are widely enabled for entirely ordinary reasons — launch "
                    "options copied from a guide, a troubleshooting step, a leftover from an "
                    "older patch."
                ),
                evidence=[
                    Evidence(kind=EvidenceKind.CONFIG, label=f"{name}: {key}", value=value, member=name)
                    for name, key, value in hits[:10]
                ],
                subject=ctx.subject,
                tags=["config"],
            )
        )

    # ----------------------------------------------------------- profile count
    threshold = rules.integer("config.profile_count_review_threshold", 5)
    if len(configs) >= threshold:
        findings.append(
            Finding(
                rule="config.many-profiles",
                title="Many game profiles on one machine",
                tier=Tier.ENVIRONMENT,
                severity=rules.severity("config.many-profiles", Severity.LOW),
                confidence=Confidence.HIGH,
                summary=f"{len(configs)} captured game configs, one per profile.",
                detail=(
                    "MOSS captures one config per profile GUID it finds. A high count means many "
                    "game accounts have been used on this machine, which is context for smurfing "
                    "and account-sharing questions rather than for cheating."
                ),
                benign=(
                    "Shared family machines, LAN rigs, second accounts for practice, and profiles "
                    "left behind by old installs all inflate this count innocently. One archive "
                    "in the reference corpus had eleven with no suggestion of wrongdoing."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.CONFIG,
                        label="Captured configs",
                        value=", ".join(sorted(configs)[:12]),
                    )
                ],
                subject=ctx.subject,
                tags=["config", "identity"],
            )
        )

    # ---------------------------------------------- refresh rate vs the monitor
    monitors = ctx.session.hardware.monitors
    refresh_values = {
        name: values["RefreshRate"] for name, values in configs.items() if "RefreshRate" in values
    }
    if refresh_values and not monitors:
        pass  # nothing to compare against; silence beats a guess

    # ---------------------------------------------- cross-player config diffing
    if ctx.peers:
        peer_layers: Counter[str] = Counter()
        for peer in ctx.peers:
            seen: set[str] = set()
            for text in peer.configs.values():
                raw = parse_ini(text).get("VulkanWhitelistedLayers", "")
                seen.update(entry.strip() for entry in raw.split(";") if entry.strip())
            peer_layers.update(seen)
        mine = {
            layer
            for values in configs.values()
            for layer in (values.get("VulkanWhitelistedLayers", "").split(";"))
            if layer.strip()
        }
        unique = sorted(
            layer.strip()
            for layer in mine
            if layer.strip() and peer_layers.get(layer.strip(), 0) == 0
        )
        if unique and len(ctx.peers) >= 2:
            findings.append(
                Finding(
                    rule="config.layer-unique-in-match",
                    title="Vulkan layer present on this player's machine only",
                    tier=Tier.ENVIRONMENT,
                    severity=rules.severity("config.layer-unique-in-match", Severity.LOW),
                    confidence=Confidence.MODERATE,
                    summary=", ".join(unique[:6]),
                    detail=(
                        f"Compared against {len(ctx.peers)} other archive(s) from the same match. "
                        "These layers appear in this player's config and in no other player's. "
                        "Cross-player diffing is a way to see what is unusual *for this match* "
                        "rather than what is unusual in general."
                    ),
                    benign=(
                        "Players run different capture software, different GPUs and different "
                        "overlays. Being the only person in a lobby with a given overlay is "
                        "entirely ordinary and, with a small comparison group, close to expected."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.CONFIG,
                            label="Layers unique to this player",
                            value=", ".join(unique),
                        )
                    ],
                    subject=ctx.subject,
                    tags=["config", "match-diff"],
                )
            )

    return findings
