"""The finding model, and the invariants that keep the output defensible.

Two rules are enforced in code rather than left to reviewer discipline, because
they are what makes this tool usable in a disciplinary process at all:

* **every finding states a benign explanation** — the innocent reading of the
  same evidence, in the same font, next to the suspicious one;
* **every finding carries evidence** — a log line, an archive member, or the
  arithmetic that produced it, so the accused can check the work.

A finding that cannot satisfy both is a finding that should not be shown.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Tier(int, Enum):
    """PLAN §2. Lower is more defensible."""

    INTEGRITY = 1   # hashes and clocks: arithmetic, nearly unarguable
    ENVIRONMENT = 2  # what was on the machine: strong but contextual
    BEHAVIOURAL = 3  # statistics over input: corroborating evidence only

    @property
    def label(self) -> str:
        return {1: "Integrity & time", 2: "Environment", 3: "Behavioural"}[self.value]


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class Confidence(str, Enum):
    """How sure the *measurement* is — not how guilty anybody is."""

    CERTAIN = "certain"      # arithmetic on verified inputs; no interpretation
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"certain": 3, "high": 2, "moderate": 1, "low": 0}[self.value]


class EvidenceKind(str, Enum):
    LOG_LINE = "log_line"
    ARCHIVE_MEMBER = "archive_member"
    COMPUTED = "computed"
    CONFIG = "config"
    SCREENSHOT = "screenshot"
    EXTERNAL = "external"


@dataclass(frozen=True)
class Evidence:
    """One checkable thing. ``value`` is shown verbatim in the report."""

    kind: EvidenceKind
    label: str
    value: str = ""
    line: int | None = None
    member: str | None = None
    sensitive: bool = False  # redacted in the shareable report variant

    def to_json(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data["kind"] = self.kind.value
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Evidence:
        data = dict(data)
        data["kind"] = EvidenceKind(data["kind"])
        return cls(**data)


@dataclass
class Finding:
    rule: str
    title: str
    tier: Tier
    severity: Severity
    confidence: Confidence
    summary: str
    detail: str
    benign: str
    evidence: list[Evidence] = field(default_factory=list)
    subject: str | None = None
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.benign.strip():
            raise ValueError(f"finding {self.rule!r} has no benign explanation")
        if not self.evidence:
            raise ValueError(f"finding {self.rule!r} carries no evidence")
        if not self.detail.strip():
            raise ValueError(f"finding {self.rule!r} does not explain the rule that fired")
        self.tier = Tier(self.tier)
        self.severity = Severity(self.severity)
        self.confidence = Confidence(self.confidence)

    @property
    def sort_key(self) -> tuple[int, int, int, str]:
        """Most defensible first: severity, then tier, then confidence."""
        return (-self.severity.rank, self.tier.value, -self.confidence.rank, self.rule)

    def to_json(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "title": self.title,
            "tier": self.tier.value,
            "tier_label": self.tier.label,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "summary": self.summary,
            "detail": self.detail,
            "benign": self.benign,
            "subject": self.subject,
            "tags": list(self.tags),
            "evidence": [e.to_json() for e in self.evidence],
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Finding:
        return cls(
            rule=data["rule"],
            title=data["title"],
            tier=Tier(data["tier"]),
            severity=Severity(data["severity"]),
            confidence=Confidence(data["confidence"]),
            summary=data["summary"],
            detail=data["detail"],
            benign=data["benign"],
            evidence=[Evidence.from_json(e) for e in data.get("evidence") or []],
            subject=data.get("subject"),
            tags=list(data.get("tags") or []),
        )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.sort_key)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


#: Triage bands. Deliberately ordinal and deliberately not a percentage:
#: "P1 — open first" is a queue position, not a claim about a person.
PRIORITY_BANDS = (
    ("P1", "Open first — integrity or clock evidence does not reconcile"),
    ("P2", "Review — environment or coverage findings need a human"),
    ("P3", "Low priority — minor or informational findings only"),
    ("P4", "Nothing flagged — archive parsed clean against the current rules"),
)


def review_priority(findings: list[Finding]) -> tuple[str, str]:
    """Map a finding set onto a triage band. Never a score, never a verdict."""
    if not findings or all(f.severity is Severity.INFO for f in findings):
        return PRIORITY_BANDS[3]
    tier1 = [f for f in findings if f.tier is Tier.INTEGRITY]
    if any(f.severity.rank >= Severity.HIGH.rank for f in tier1):
        return PRIORITY_BANDS[0]
    if any(f.severity.rank >= Severity.HIGH.rank for f in findings):
        return PRIORITY_BANDS[1]
    if any(f.severity.rank >= Severity.MEDIUM.rank for f in findings):
        return PRIORITY_BANDS[1]
    return PRIORITY_BANDS[2]
