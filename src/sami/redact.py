"""Pseudonymisation for reports that leave the admin team.

A MOSS archive is personal data (RESEARCH §8): Windows usernames, hostnames,
LAN and partial WAN addresses, monitor and drive serials, Steam IDs, and full
process paths carrying real names. A report shared with an opposing team, a
tournament organiser or the accused player's own team should not carry all of
that just because the finding it supports needed one line of it.

Redaction here is **pseudonymisation, not deletion**: every sensitive value is
replaced by a stable token derived from a case salt, so ``USER-4f21`` still
reads as the same person everywhere in the report, and two reports produced
under the same salt still correlate. The salt is recorded in the chain of
custody, never in the redacted report.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field

from mosslib.model import LogLine, Session
from sami.dossier import Dossier, MatchDossier
from sami.findings import Evidence, Finding

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}(?:\d{1,3}|x{1,3})\b")
WINDOWS_USER_PATH_RE = re.compile(r"(?i)([A-Z]:\\Users\\)([^\\]+)")


def new_salt() -> str:
    """A fresh case salt. Store it with the case, not with the report."""
    return secrets.token_hex(16)


@dataclass
class Redactor:
    salt: str = field(default_factory=new_salt)
    _map: dict[str, str] = field(default_factory=dict, init=False)

    def token(self, value: str, prefix: str) -> str:
        key = value.strip()
        if not key:
            return value
        if key not in self._map:
            digest = hmac.new(self.salt.encode(), key.encode("utf-8"), hashlib.sha256).hexdigest()
            self._map[key] = f"{prefix}-{digest[:6]}"
        return self._map[key]

    # ------------------------------------------------------------- collection

    def learn(self, session: Session) -> None:
        """Register the sensitive values in one session so they can be replaced."""
        hw = session.hardware
        for value, prefix in (
            (hw.user, "USER"),
            (hw.hostname, "HOST"),
            (hw.steam_id, "STEAM"),
            (hw.lan_ip, "LAN"),
            (hw.public_ip, "WAN"),
            (hw.sign_id1, "SIGN"),
        ):
            if value and value not in ("0", "0.0.0.0"):
                self.token(value, prefix)
        for monitor in hw.monitors:
            if monitor.serial:
                self.token(monitor.serial, "MON")
        for device in (*hw.drives, *hw.usb):
            if device.serial:
                self.token(device.serial, "SERIAL")
        for process in session.processes:
            match = WINDOWS_USER_PATH_RE.search(process.path)
            if match:
                self.token(match.group(2), "USER")
        for check in session.file_checks:
            match = WINDOWS_USER_PATH_RE.search(check.path)
            if match:
                self.token(match.group(2), "USER")

    # -------------------------------------------------------------- rewriting

    def text(self, value: str | None) -> str | None:
        if not value:
            return value
        result = value
        # Longest first: a hostname can contain a username as a substring.
        for original, token in sorted(self._map.items(), key=lambda kv: -len(kv[0])):
            if original in result:
                result = result.replace(original, token)
            lowered = original.lower()
            if lowered != original and lowered in result.lower():
                result = re.sub(re.escape(original), token, result, flags=re.IGNORECASE)
        result = WINDOWS_USER_PATH_RE.sub(lambda m: m.group(1) + self.token(m.group(2), "USER"), result)
        result = IPV4_RE.sub(lambda m: self.token(m.group(0), "IP"), result)
        return result

    def evidence(self, item: Evidence) -> Evidence:
        return Evidence(
            kind=item.kind,
            label=self.text(item.label) or "",
            value=self.text(item.value) or "",
            line=item.line,
            member=item.member,
            sensitive=item.sensitive,
        )

    def finding(self, item: Finding) -> Finding:
        return Finding(
            rule=item.rule,
            title=item.title,
            tier=item.tier,
            severity=item.severity,
            confidence=item.confidence,
            summary=self.text(item.summary) or "",
            detail=self.text(item.detail) or "",
            benign=item.benign,
            evidence=[self.evidence(e) for e in item.evidence],
            subject=self.text(item.subject),
            tags=list(item.tags),
        )

    def session(self, session: Session) -> Session:
        """A copy of the session with identifiers replaced by stable tokens."""
        clone = Session.from_json(session.to_json())
        hw = clone.hardware
        clone.archive.filename = self.text(clone.archive.filename) or clone.archive.filename
        clone.archive.name_sign_id = self.text(clone.archive.name_sign_id)
        hw.sign_id1 = self.text(hw.sign_id1)
        hw.user = self.text(hw.user)
        hw.hostname = self.text(hw.hostname)
        hw.steam_id = self.text(hw.steam_id)
        hw.lan_ip = self.text(hw.lan_ip)
        hw.public_ip = self.text(hw.public_ip)
        hw.physical = self.text(hw.physical)
        for monitor in hw.monitors:
            monitor.serial = self.text(monitor.serial)
        for device in (*hw.drives, *hw.usb, *hw.video, *hw.pci):
            device.serial = self.text(device.serial)
        for process in clone.processes:
            process.path = self.text(process.path) or process.path
        for check in clone.file_checks:
            check.path = self.text(check.path) or check.path
        for captured in clone.captured_files:
            captured.source_path = self.text(captured.source_path) or captured.source_path
        clone.lines = [
            LogLine(number=line.number, raw=self.text(line.raw) or line.raw, kind=line.kind)
            for line in clone.lines
        ]
        return clone

    def dossier(self, dossier: Dossier) -> Dossier:
        self.learn(dossier.session)
        scan = dossier.scan
        redacted_scan = type(scan)(
            path=scan.path,
            session=self.session(scan.session),
            member_sha256=dict(scan.member_sha256),
            jpegs=dict(scan.jpegs),
            configs={name: self.text(text) or "" for name, text in scan.configs.items()},
            ingested_at=scan.ingested_at,
            label=self.text(scan.label),
        )
        return Dossier(
            scan=redacted_scan,
            findings=[self.finding(f) for f in dossier.findings],
            clocks=dossier.clocks,
            rules=dossier.rules,
            schedule=dossier.schedule,
            entry=dossier.entry,
            generated_at=dossier.generated_at,
            max_tier=dossier.max_tier,
        )

    def match(self, match: MatchDossier) -> MatchDossier:
        return MatchDossier(
            dossiers=[self.dossier(d) for d in match.dossiers],
            schedule=match.schedule,
            generated_at=match.generated_at,
        )
