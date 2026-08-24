"""The output contract: findings, reports, redaction, custody, CLI."""

from __future__ import annotations

import html as html_module
import json
import unittest
from datetime import datetime

from sami.dossier import LIMITATIONS, MatchDossier
from sami.findings import Confidence, Evidence, EvidenceKind, Finding, Severity, Tier
from sami.ingest import CustodyLog
from sami.redact import Redactor
from sami.report.html import render_dossier, render_match
from sami.rules import RuleError, RulePack
from tests.support import ArchiveTestCase

#: One archive that trips as many rules as possible, so the invariants below are
#: checked against real analyzer output rather than a hand-built example.
KITCHEN_SINK = {
    "tamper_capture": "005.JPG",
    "extra_member": "notes.txt",
    "blank_frames": (8, 9),
    "duplicate_frames": (12,),
    "truncated_frames": (3,),
    "resolution_change_at": 15,
    "fast_double_click": True,
    "vulkan_layers": "VK_LAYER_OW_OVERLAY;VK_LAYER_UNKNOWN_THING",
    "defender": "disabled",
    "profiles": 6,
    "processes": [
        (r"C:\Windows\System32\lsass.exe", "Microsoft Windows Publisher"),
        (r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", "philandro Software GmbH"),
        (r"C:\Users\szazi\Downloads\loader.exe", None),
        (r"C:\Program Files\LGHUB\lghub.exe", "Logitech Inc"),
        (r"C:\tools\cheatengine-x86_64.exe", None),
    ],
}


class FindingContractTest(unittest.TestCase):
    """Two invariants are enforced in code, not left to reviewer discipline."""

    def _finding(self, **overrides) -> Finding:
        base = {
            "rule": "test.rule",
            "title": "Title",
            "tier": Tier.INTEGRITY,
            "severity": Severity.HIGH,
            "confidence": Confidence.CERTAIN,
            "summary": "summary",
            "detail": "the arithmetic",
            "benign": "the innocent reading",
            "evidence": [Evidence(kind=EvidenceKind.COMPUTED, label="x", value="1")],
        }
        base.update(overrides)
        return Finding(**base)

    def test_a_finding_without_a_benign_explanation_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._finding(benign="  ")

    def test_a_finding_without_evidence_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._finding(evidence=[])

    def test_a_finding_without_its_rule_explained_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._finding(detail="")

    def test_round_trip(self) -> None:
        finding = self._finding()
        self.assertEqual(Finding.from_json(finding.to_json()).to_json(), finding.to_json())

    def test_ordering_puts_severe_and_defensible_first(self) -> None:
        from sami.findings import sort_findings

        low_tier1 = self._finding(rule="a", severity=Severity.LOW)
        high_tier3 = self._finding(rule="b", severity=Severity.HIGH, tier=Tier.BEHAVIOURAL)
        critical_tier1 = self._finding(rule="c", severity=Severity.CRITICAL)
        order = [f.rule for f in sort_findings([low_tier1, high_tier3, critical_tier1])]
        self.assertEqual(order, ["c", "b", "a"])


class AnalyzerOutputContractTest(ArchiveTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.dossier_all = self.dossier(**KITCHEN_SINK)

    def test_many_rules_fire(self) -> None:
        self.assertGreaterEqual(len(self.dossier_all.findings), 10)

    def test_every_finding_states_a_benign_explanation(self) -> None:
        for finding in self.dossier_all.findings:
            self.assertTrue(finding.benign.strip(), finding.rule)
            self.assertGreater(len(finding.benign), 40, f"{finding.rule}: benign text is a stub")

    def test_every_finding_carries_evidence_and_a_rule_explanation(self) -> None:
        for finding in self.dossier_all.findings:
            self.assertTrue(finding.evidence, finding.rule)
            self.assertTrue(finding.detail.strip(), finding.rule)

    def test_no_finding_claims_a_verdict(self) -> None:
        banned = ("cheater", "guilty", "proves", "definitely cheat", "confirmed cheat")
        for finding in self.dossier_all.findings:
            text = " ".join([finding.title, finding.summary, finding.detail]).lower()
            for word in banned:
                self.assertNotIn(word, text, f"{finding.rule} reads as a verdict")

    def test_priority_is_a_band_not_a_score(self) -> None:
        band, meaning = self.dossier_all.priority
        self.assertIn(band, ("P1", "P2", "P3", "P4"))
        self.assertNotIn("%", meaning)

    def test_json_export_round_trips(self) -> None:
        payload = json.loads(json.dumps(self.dossier_all.to_json()))
        self.assertEqual(payload["schema"], "samireader/dossier/1")
        self.assertEqual(len(payload["findings"]), len(self.dossier_all.findings))
        self.assertEqual(payload["evidence"]["id"], self.dossier_all.scan.evidence_id)


class ReportTest(ArchiveTestCase):
    def test_report_is_self_contained(self) -> None:
        html = render_dossier(self.dossier(), embed_images="none")
        for forbidden in ("http://", "https://", "<script", "src=\"/"):
            self.assertNotIn(forbidden, html, f"report must not reference {forbidden}")
        self.assertIn("<style>", html)

    def test_report_states_its_limitations(self) -> None:
        html = render_dossier(self.dossier(), embed_images="none")
        for limitation in LIMITATIONS:
            self.assertIn(limitation[:40], html)

    def test_report_shows_the_benign_explanation_of_every_finding(self) -> None:
        dossier = self.dossier(**KITCHEN_SINK)
        html = render_dossier(dossier, embed_images="none")
        for finding in dossier.findings:
            self.assertIn(html_module.escape(finding.benign[:60], quote=True), html, finding.rule)

    def test_hostile_content_is_escaped(self) -> None:
        dossier = self.dossier(
            user="<script>alert(1)</script>",
            hostname="\"><img src=x onerror=alert(2)>",
        )
        html = render_dossier(dossier, embed_images="none")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("<img src=x onerror", html)
        self.assertIn("&lt;script&gt;", html)

    def test_flagged_captures_are_embedded(self) -> None:
        html = render_dossier(self.dossier(blank_frames=(4,)), embed_images="flagged")
        self.assertIn("data:image/jpeg;base64,", html)

    def test_match_report_renders_the_coverage_grid(self) -> None:
        dossiers = [
            self.dossier(user=f"player{i}", start_local=datetime(2024, 3, 28, 21, i, 0))
            for i in range(3)
        ]
        html = render_match(MatchDossier(dossiers=dossiers))
        self.assertIn("<svg", html)
        self.assertIn("Review queue", html)


class RedactionTest(ArchiveTestCase):
    def test_identifiers_are_replaced_with_stable_tokens(self) -> None:
        dossier = self.dossier(user="alice", hostname="ALICE-PC", **KITCHEN_SINK)
        redacted = Redactor(salt="fixed-salt").dossier(dossier)
        html = render_dossier(redacted, embed_images="none", redacted=True)
        for secret in ("alice", "ALICE-PC", "192.168.100.33", "EBB9N00443SL0", "1434136903"):
            self.assertNotIn(secret.lower(), html.lower(), f"{secret} leaked into the redacted copy")
        self.assertIn("USER-", html)

    def test_the_same_value_gets_the_same_token(self) -> None:
        redactor = Redactor(salt="fixed-salt")
        first = redactor.token("alice", "USER")
        self.assertEqual(first, redactor.token("alice", "USER"))
        self.assertNotEqual(first, redactor.token("bob", "USER"))

    def test_different_salts_give_different_tokens(self) -> None:
        self.assertNotEqual(
            Redactor(salt="a").token("alice", "USER"), Redactor(salt="b").token("alice", "USER")
        )

    def test_findings_survive_redaction(self) -> None:
        dossier = self.dossier(**KITCHEN_SINK)
        redacted = Redactor(salt="fixed-salt").dossier(dossier)
        self.assertEqual(
            [f.rule for f in redacted.findings], [f.rule for f in dossier.findings]
        )


class CustodyTest(ArchiveTestCase):
    def test_chain_is_verifiable(self) -> None:
        log = CustodyLog(self.tmp / "custody.jsonl")
        for index in range(3):
            log.append("verify", evidence_id=f"{index:064d}", actor="tester")
        self.assertEqual(log.verify(), [])
        self.assertEqual(len(log.read()), 3)

    def test_deleting_a_record_breaks_the_chain(self) -> None:
        path = self.tmp / "custody.jsonl"
        log = CustodyLog(path)
        for index in range(4):
            log.append("verify", evidence_id=f"{index:064d}", actor="tester")
        lines = path.read_text().splitlines()
        path.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
        self.assertTrue(log.verify())

    def test_editing_a_record_breaks_the_chain(self) -> None:
        path = self.tmp / "custody.jsonl"
        log = CustodyLog(path)
        log.append("verify", evidence_id="a" * 64, actor="tester")
        log.append("report", evidence_id="a" * 64, actor="tester")
        text = path.read_text().replace('"actor": "tester"', '"actor": "someone-else"', 1)
        path.write_text(text)
        self.assertTrue(log.verify())


class RulePackTest(ArchiveTestCase):
    def test_overlay_merges_over_defaults(self) -> None:
        overlay = self.tmp / "league.json"
        overlay.write_text(json.dumps({"clocks": {"offset_tolerance_minutes": 30}}))
        pack = RulePack.load(overlay)
        self.assertEqual(pack.number("clocks.offset_tolerance_minutes", 0), 30)
        self.assertEqual(pack.number("behaviour.double_click_min_interval_ms", 0), 80)

    def test_rules_can_be_disabled(self) -> None:
        overlay = self.tmp / "quiet.json"
        overlay.write_text(json.dumps({"disabled_rules": ["screenshots.blank-frame"]}))
        dossier = self.dossier(blank_frames=(4, 5), rules=RulePack.load(overlay))
        self.assertNotFired(dossier, "screenshots.blank-frame")

    def test_severity_can_be_overridden(self) -> None:
        overlay = self.tmp / "sev.json"
        overlay.write_text(json.dumps({"severity": {"screenshots.blank-frame": "critical"}}))
        dossier = self.dossier(blank_frames=(4, 5), rules=RulePack.load(overlay))
        finding = next(f for f in dossier.findings if f.rule == "screenshots.blank-frame")
        self.assertEqual(finding.severity.value, "critical")

    def test_invalid_severity_is_refused(self) -> None:
        overlay = self.tmp / "bad.json"
        overlay.write_text(json.dumps({"severity": {"x": "catastrophic"}}))
        with self.assertRaises(RuleError):
            RulePack.load(overlay)

    def test_missing_pack_is_refused(self) -> None:
        with self.assertRaises(RuleError):
            RulePack.load(self.tmp / "nope.json")


class CliTest(ArchiveTestCase):
    def run_cli(self, *args: str) -> int:
        """Run the CLI with stdout captured, so a test run stays readable."""
        import contextlib
        import io

        from sami.cli import main

        self.stdout = io.StringIO()
        with contextlib.redirect_stdout(self.stdout):
            return main([*args, "--no-colour"])

    def test_verify_clean_archive_exits_zero(self) -> None:
        archive = self.build()
        self.assertEqual(self.run_cli("verify", str(archive)), 0)

    def test_verify_tampered_archive_exits_nonzero(self) -> None:
        archive = self.build(tamper_capture="005.JPG")
        self.assertEqual(self.run_cli("verify", str(archive)), 1)

    def test_fail_on_never_always_exits_zero(self) -> None:
        archive = self.build(tamper_capture="005.JPG")
        self.assertEqual(self.run_cli("verify", str(archive), "--fail-on", "never"), 0)

    def test_report_writes_html_and_redacted_copy(self) -> None:
        archive = self.build()
        output = self.tmp / "report.html"
        self.run_cli("report", str(archive), "-o", str(output), "--redacted",
                     "--embed-images", "none")
        self.assertTrue(output.is_file())
        self.assertTrue(output.with_name("report.redacted.html").is_file())

    def test_match_writes_index_and_player_reports(self) -> None:
        archives = [str(self.build(user=f"p{i}", seed=i + 1, nonce=str(i))) for i in range(3)]
        output = self.tmp / "match"
        self.run_cli("match", *archives, "-o", str(output), "--embed-images", "none")
        self.assertTrue((output / "index.html").is_file())
        self.assertEqual(len(list(output.glob("*.html"))), 4)

    def test_appeal_packet_contains_everything_needed_to_check_the_work(self) -> None:
        archive = self.build(tamper_capture="005.JPG")
        custody = self.tmp / "custody.jsonl"
        packet = self.tmp / "appeal"
        self.run_cli("verify", str(archive), "--custody", str(custody))
        self.run_cli("appeal", str(archive), "-o", str(packet), "--custody", str(custody))
        for name in ("READ-ME-FIRST.txt", "dossier.html", "findings.json",
                     "session.json", "rules.json", "custody.jsonl"):
            self.assertTrue((packet / name).is_file(), name)
        cover = (packet / "READ-ME-FIRST.txt").read_text()
        self.assertIn("HOW TO CONTEST A FINDING", cover)
        self.assertIn("No output of this tool is a verdict", cover)
        self.assertIn("queue position", cover)
        findings = json.loads((packet / "findings.json").read_text())
        self.assertTrue(all(f["benign"] for f in findings))
        self.assertTrue(any(f["rule"] == "integrity.file-hash-mismatch" for f in findings))

    def test_parse_emits_session_json(self) -> None:
        archive = self.build()
        output = self.tmp / "session.json"
        self.run_cli("parse", str(archive), "-o", str(output))
        data = json.loads(output.read_text())
        self.assertEqual(data["schema"], "samireader/session/1")

    def test_unreadable_archive_exits_with_an_error(self) -> None:
        broken = self.tmp / "broken.zip"
        broken.write_bytes(b"not a zip")
        self.assertEqual(self.run_cli("verify", str(broken)), 2)

    def test_custody_command_reports_a_broken_chain(self) -> None:
        archive = self.build()
        custody = self.tmp / "custody.jsonl"
        self.run_cli("verify", str(archive), "--custody", str(custody))
        self.run_cli("verify", str(archive), "--custody", str(custody))
        self.assertEqual(self.run_cli("custody", str(custody)), 0)
        # Editing any record but the last one breaks the forward hash chain. The
        # last record is unprotected by construction — see CustodyLog's docstring.
        custody.write_text(
            custody.read_text().replace('"action": "verify"', '"action": "edited"', 1)
        )
        self.assertEqual(self.run_cli("custody", str(custody)), 1)


if __name__ == "__main__":
    unittest.main()
