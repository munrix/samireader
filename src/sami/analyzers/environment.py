"""Tier 2 — what was running on the machine.

Strong evidence, but contextual in a way Tier 1 is not: a remote-access tool
installed on a gaming PC is a fact; whether it mattered depends on the match.
Every finding here says so.

The hard limit, restated in every report: MOSS snapshots the process list **at
game start only** (RESEARCH §7.1). A clean process list means nothing was
running at that moment — not that nothing ran during the match.
"""

from __future__ import annotations

from sami.context import AnalysisContext
from sami.findings import Confidence, Evidence, EvidenceKind, Finding, Severity, Tier

CATEGORY_TITLES = {
    "remote_access": "Remote-access software was running",
    "macro_suite": "Macro or input-remapping software was running",
    "virtual_machine": "Virtual machine or sandbox artefacts present",
    "spoofer_or_cleaner": "Hardware-ID spoofing or trace-cleaning tools present",
    "overlay_or_injector": "Overlay or injection framework running",
    "debugger_or_memory_tool": "Debugger or memory-editing tool running",
    "capture_or_share": "Capture, streaming or chat software running",
}

CATEGORY_DETAIL = {
    "remote_access": (
        "Remote-access software lets a second person drive the machine, or watch it, from "
        "elsewhere. It is under-checked by admins and is one of the few forms of assistance "
        "that leaves a clear trace in a MOSS archive."
    ),
    "macro_suite": (
        "Vendor macro suites and remapping tools can execute recorded input sequences. Their "
        "presence is not misuse — these ship with most gaming peripherals — but it is the "
        "context in which the behavioural histograms should be read."
    ),
    "virtual_machine": (
        "A session recorded inside a virtual machine is not a recording of the machine that "
        "played, and VM artefacts also indicate the sandbox setups used to isolate cheat "
        "software from anti-cheat inspection."
    ),
    "spoofer_or_cleaner": (
        "Hardware-ID spoofers and trace cleaners exist to defeat exactly the identity and "
        "history checks a ban relies on. There is no ordinary competitive use for them."
    ),
    "overlay_or_injector": (
        "Overlay frameworks inject code into the game process. That is how they draw, and it "
        "is also the mechanism a cheat overlay uses. Presence alone is very common."
    ),
    "debugger_or_memory_tool": (
        "Debuggers and memory editors read and write another process's memory — the "
        "foundation of most internal cheats. They also have entirely ordinary uses for "
        "developers, which the player's occupation may explain."
    ),
    "capture_or_share": (
        "Recording, streaming and chat clients. Listed for context — particularly for "
        "screen-sharing, which is how a coach or spectator sees a live feed."
    ),
}

CATEGORY_BENIGN = {
    "remote_access": (
        "Many people install AnyDesk, Parsec or TeamViewer for work or to help family, and "
        "leave them running at boot. Running is not connected: without a session log from the "
        "tool itself there is no evidence anyone was actually connected during the match."
    ),
    "macro_suite": (
        "Logitech G HUB, Razer Synapse and iCUE are required to configure ordinary gaming "
        "mice and keyboards, including DPI and lighting. Their presence is close to universal "
        "among competitive players and means nothing on its own."
    ),
    "virtual_machine": (
        "VM guest tools also appear on machines that merely have virtualisation software "
        "installed, and some anti-cheat and enterprise agents look similar to detectors. "
        "Confirm against the hardware inventory before treating this as a VM session."
    ),
    "spoofer_or_cleaner": (
        "Some names in this category collide with legitimate disk and BIOS utilities. Check "
        "the full path and the publisher before concluding anything."
    ),
    "overlay_or_injector": (
        "Discord, Steam, OBS, GeForce Experience and Overwolf all inject overlays as a matter "
        "of course. This is background noise on almost every gaming PC."
    ),
    "debugger_or_memory_tool": (
        "Developers, modders and QA staff run these tools for their jobs. Ask before assuming."
    ),
    "capture_or_share": (
        "Every streamer and most players run these. Purely contextual."
    ),
}


def _proc_evidence(entries) -> list[Evidence]:
    return [
        Evidence(
            kind=EvidenceKind.LOG_LINE,
            label=p.name,
            value=f"{p.path} — {'signed by ' + p.author if p.author else 'UNSIGNED'}",
            line=p.line,
            sensitive=True,
        )
        for p in entries[:15]
    ]


def analyze(ctx: AnalysisContext) -> list[Finding]:
    session = ctx.session
    rules = ctx.rules
    findings: list[Finding] = []

    if not session.processes:
        return findings

    # ------------------------------------------------------------- categories
    categories = rules.categories("environment.categories")
    severities = rules.get("environment.category_severity") or {}
    for category, names in categories.items():
        matched = [p for p in session.processes if p.name.lower() in set(names)]
        if not matched:
            continue
        severity = Severity(severities.get(category, "medium"))
        findings.append(
            Finding(
                rule=f"environment.category.{category.replace('_', '-')}",
                title=CATEGORY_TITLES.get(category, f"Process category: {category}"),
                tier=Tier.ENVIRONMENT,
                severity=rules.severity(f"environment.category.{category.replace('_', '-')}", severity),
                confidence=Confidence.HIGH,
                summary=", ".join(sorted({p.name for p in matched}))[:300],
                detail=(
                    CATEGORY_DETAIL.get(category, "")
                    + " Matched against the rule pack's name list; MOSS snapshots the process "
                    "list once, at game start, so this is what was running at that moment only."
                ),
                benign=CATEGORY_BENIGN.get(
                    category,
                    "Presence of software is not use of software. Establish whether it was used "
                    "during the match before treating this as more than context.",
                ),
                evidence=_proc_evidence(matched),
                subject=ctx.subject,
                tags=["process", category],
            )
        )

    # ---------------------------------------------------------- known-bad hashes
    bad = {h.lower() for h in rules.strings("environment.known_bad_sha256")}
    if bad:
        hits = [p for p in session.processes if p.sha256.lower() in bad]
        if hits:
            findings.append(
                Finding(
                    rule="environment.known-bad-hash",
                    title="Process matches a known-bad hash from the rule pack",
                    tier=Tier.ENVIRONMENT,
                    severity=rules.severity("environment.known-bad-hash", Severity.CRITICAL),
                    confidence=Confidence.HIGH,
                    summary=", ".join(sorted({p.name for p in hits})),
                    detail=(
                        "The SHA-256 MOSS recorded for these processes appears in the league's "
                        "known-bad list. The match is on file contents, so a renamed copy still "
                        "matches."
                    ),
                    benign=(
                        "The list is only as good as its curation — a mis-entered or over-broad "
                        "hash produces a false hit. Confirm the entry's provenance in the rule "
                        "pack before acting, and record which list version fired."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.LOG_LINE,
                            label=p.name,
                            value=f"{p.sha256} — {p.path}",
                            line=p.line,
                            sensitive=True,
                        )
                        for p in hits[:10]
                    ],
                    subject=ctx.subject,
                    tags=["process", "hash"],
                )
            )

    # ------------------------------------------------------------ unsigned code
    ignore = [f.lower() for f in rules.strings("environment.unsigned_ignore")]
    unsigned = [
        p
        for p in session.processes
        if not p.signed and not any(frag in p.path.lower() for frag in ignore)
    ]
    if unsigned:
        findings.append(
            Finding(
                rule="environment.unsigned-process",
                title="Unsigned executables were running",
                tier=Tier.ENVIRONMENT,
                severity=rules.severity("environment.unsigned-process", Severity.MEDIUM),
                confidence=Confidence.HIGH,
                summary=f"{len(unsigned)} process(es) with no Authenticode signature: "
                + ", ".join(sorted({p.name for p in unsigned})[:8]),
                detail=(
                    "MOSS records the Authenticode signer of every process it can. An absent "
                    "'Author:' means the binary is unsigned. Cheat software is almost never "
                    "signed; a great deal of ordinary software is not either, which is why this "
                    "is a list to scan rather than a conclusion."
                ),
                benign=(
                    "Indie games, hobby utilities, portable tools, self-built software and many "
                    "launchers ship unsigned. On a typical gaming PC a handful of unsigned "
                    "processes is normal. Look at the paths, not the count."
                ),
                evidence=_proc_evidence(unsigned),
                subject=ctx.subject,
                tags=["process", "signature"],
            )
        )

    # ---------------------------------------------------------- suspicious paths
    fragments = [f.lower() for f in rules.strings("environment.suspicious_path_fragments")]
    from_temp = [p for p in session.processes if any(f in p.path.lower() for f in fragments)]
    if from_temp:
        findings.append(
            Finding(
                rule="environment.executed-from-temp",
                title="Executables were running from temporary or download folders",
                tier=Tier.ENVIRONMENT,
                severity=rules.severity("environment.executed-from-temp", Severity.MEDIUM),
                confidence=Confidence.HIGH,
                summary=", ".join(sorted({p.name for p in from_temp})[:8]),
                detail=(
                    "Software installed normally runs from Program Files or a game library. "
                    "Running from %TEMP%, Downloads or the Desktop is the pattern of something "
                    "downloaded and executed directly, which is how most cheat loaders arrive."
                ),
                benign=(
                    "Installers, updaters, launchers and portable apps legitimately run from "
                    "these folders — as does anything a player downloaded and simply never "
                    "moved. Check the signature and the name together with the path."
                ),
                evidence=_proc_evidence(from_temp),
                subject=ctx.subject,
                tags=["process", "path"],
            )
        )

    # ------------------------------------------------------------ OS statements
    expect_real_os = rules.get("environment.expect_real_os")
    if expect_real_os and session.hardware.real_os and expect_real_os not in session.hardware.real_os:
        findings.append(
            Finding(
                rule="environment.real-os-mismatch",
                title="MOSS's OS check did not report a normal Windows install",
                tier=Tier.ENVIRONMENT,
                severity=rules.severity("environment.real-os-mismatch", Severity.HIGH),
                confidence=Confidence.MODERATE,
                summary=f"'Real OS' reads {session.hardware.real_os!r}, expected {expect_real_os!r}.",
                detail=(
                    "MOSS cross-checks the reported OS against what it observes, which is its own "
                    "guard against a spoofed or virtualised environment. A value other than the "
                    "expected one means that check did not come back normal."
                ),
                benign=(
                    "A Windows build MOSS does not recognise (an Insider build, a newer release "
                    "than the MOSS version, a heavily customised install) produces an unexpected "
                    "string with no deception involved."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.COMPUTED,
                        label="Real OS / OS",
                        value=f"{session.hardware.real_os} / {session.hardware.os_version}",
                    )
                ],
                subject=ctx.subject,
                tags=["os"],
            )
        )

    expect_defender = rules.get("environment.expect_defender")
    defender = session.hardware.windows_defender
    if expect_defender and defender and expect_defender.lower() not in defender.lower():
        findings.append(
            Finding(
                rule="environment.defender-disabled",
                title="Windows Defender was not enabled",
                tier=Tier.ENVIRONMENT,
                severity=rules.severity("environment.defender-disabled", Severity.LOW),
                confidence=Confidence.HIGH,
                summary=f"MOSS recorded Windows Defender as {defender!r}.",
                detail=(
                    "Cheat software is routinely detected as malware, so disabling real-time "
                    "protection is a common prerequisite for running it. This is weak on its own."
                ),
                benign=(
                    "Third-party antivirus disables Defender by design, and plenty of players "
                    "turn it off for performance or because it quarantines their games. Very "
                    "common and very weak evidence."
                ),
                evidence=[
                    Evidence(kind=EvidenceKind.COMPUTED, label="Windows Defender", value=defender)
                ],
                subject=ctx.subject,
                tags=["os"],
            )
        )

    # ------------------------------------------------------- the standing caveat
    findings.append(
        Finding(
            rule="environment.snapshot-limitation",
            title="Process list is a single snapshot, taken at game start",
            tier=Tier.ENVIRONMENT,
            severity=Severity.INFO,
            confidence=Confidence.CERTAIN,
            summary=f"{len(session.processes)} processes recorded, all at one moment.",
            detail=(
                "MOSS enumerates processes once, when it detects the game, and never again "
                "(RESEARCH §7.1). Anything started after that point — including a cheat loader "
                "launched once the match began — does not appear in this archive at all."
            ),
            benign=(
                "This is a property of MOSS, not of the player. A clean process list is not "
                "evidence of a clean session, and must never be reported as such."
            ),
            evidence=[
                Evidence(
                    kind=EvidenceKind.COMPUTED,
                    label="Processes in snapshot",
                    value=str(len(session.processes)),
                )
            ],
            subject=ctx.subject,
            tags=["process", "limitation"],
        )
    )

    return findings
