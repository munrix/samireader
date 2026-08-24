"""The analyzer registry.

Order is the order findings are computed, not the order they are shown — the
report sorts by severity. Registration is explicit rather than discovered by
import magic so that "which rules ran?" has one answer, printable in the report.
"""

from __future__ import annotations

from collections.abc import Callable

from sami.analyzers import (
    behaviour,
    clocks,
    config,
    environment,
    integrity,
    schedule,
    screenshots,
    session,
    zipstructure,
)
from sami.context import AnalysisContext
from sami.findings import Finding, sort_findings

Analyzer = Callable[[AnalysisContext], list[Finding]]

#: (name, tier, function). Tier here is the *dominant* tier of the analyzer's
#: findings; individual findings carry their own.
REGISTRY: tuple[tuple[str, int, Analyzer], ...] = (
    ("integrity", 1, integrity.analyze),
    ("zipstructure", 1, zipstructure.analyze),
    ("clocks", 1, clocks.analyze),
    ("session", 1, session.analyze),
    ("schedule", 1, schedule.analyze),
    ("environment", 2, environment.analyze),
    ("config", 2, config.analyze),
    ("screenshots", 2, screenshots.analyze),
    ("behaviour", 3, behaviour.analyze),
)

ANALYZER_NAMES = tuple(name for name, _, _ in REGISTRY)


def run_all(ctx: AnalysisContext, *, max_tier: int = 3) -> list[Finding]:
    """Run every registered analyzer up to ``max_tier`` and return sorted findings."""
    findings: list[Finding] = []
    for _name, tier, analyze in REGISTRY:
        if tier > max_tier:
            continue
        findings.extend(analyze(ctx))
    findings = [f for f in findings if ctx.rules.enabled(f.rule)]
    for finding in findings:
        finding.severity = ctx.rules.severity(finding.rule, finding.severity)
    return sort_findings(findings)


__all__ = ["ANALYZER_NAMES", "REGISTRY", "Analyzer", "run_all"]
