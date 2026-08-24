"""Tier 1 integrity: the findings that are arithmetic rather than judgement."""

from __future__ import annotations

import unittest
import zipfile

from tests.support import ArchiveTestCase


class IntegrityTest(ArchiveTestCase):
    def test_clean_archive_verifies(self) -> None:
        dossier = self.dossier()
        self.assertFired(dossier, "integrity.all-files-verified")
        self.assertEqual(dossier.actionable, [])
        self.assertEqual(dossier.priority[0], "P4")

    def test_edited_capture_is_caught(self) -> None:
        dossier = self.dossier(tamper_capture="005.JPG")
        self.assertFired(dossier, "integrity.file-hash-mismatch")
        finding = next(f for f in dossier.findings if f.rule == "integrity.file-hash-mismatch")
        self.assertEqual(finding.severity.value, "critical")
        self.assertEqual(finding.confidence.value, "certain")
        self.assertTrue(any("005.JPG" in e.label for e in finding.evidence))
        self.assertEqual(dossier.priority[0], "P1")

    def test_removed_capture_is_caught(self) -> None:
        dossier = self.dossier(remove_capture="007.JPG")
        self.assertFired(dossier, "integrity.file-missing")
        self.assertNotFired(dossier, "integrity.all-files-verified")

    def test_deleted_log_record_is_caught(self) -> None:
        # The other direction: the file is still in the ZIP but its log line was
        # deleted, which is what editing the log to hide a capture looks like.
        dossier = self.dossier(remove_log_record="007.JPG")
        self.assertFired(dossier, "integrity.file-not-in-log")
        self.assertFired(dossier, "integrity.screenshot-sequence-gap")

    def test_added_member_is_caught(self) -> None:
        dossier = self.dossier(extra_member="cheat-notes.txt")
        self.assertFired(dossier, "integrity.file-not-in-log")

    def test_unknown_footer_algorithm_is_reported_as_unchecked(self) -> None:
        # The real situation: the vendor has not published the algorithm, so the
        # footer must read as unverified rather than as verified or as failed.
        dossier = self.dossier()
        self.assertFired(dossier, "integrity.log-crc-unverified")
        finding = next(f for f in dossier.findings if f.rule == "integrity.log-crc-unverified")
        self.assertEqual(finding.severity.value, "info")

    def test_a_matching_footer_algorithm_is_reported(self) -> None:
        dossier = self.dossier(footer_is_sha256_of_body=True)
        self.assertFired(dossier, "integrity.log-crc-verified")

    def test_truncated_log_is_caught(self) -> None:
        self.assertFired(self.dossier(drop_footer=True), "integrity.log-truncated")

    def test_missing_header_is_caught(self) -> None:
        self.assertFired(self.dossier(drop_header=True), "integrity.log-header-missing")

    def test_verification_covers_configs_as_well_as_captures(self) -> None:
        scan = self.scan(profiles=3)
        logged = {c.file for c in scan.session.captured_files}
        self.assertEqual(len(logged), 3)
        for name in logged:
            self.assertIn(name, scan.member_sha256)


class ZipStructureTest(ArchiveTestCase):
    def test_rezipped_archive_shows_structural_signature(self) -> None:
        dossier = self.dossier(
            uniform_mtimes=True, stored_compression=True, reverse_zip_order=True
        )
        fired = self.rules_fired(dossier)
        self.assertIn("zip.uniform-mtimes", fired)
        self.assertIn("zip.unexpected-compression", fired)
        self.assertIn("zip.entry-order-mismatch", fired)

    def test_clean_archive_has_no_structural_findings(self) -> None:
        fired = self.rules_fired(self.dossier())
        self.assertFalse({r for r in fired if r.startswith("zip.")})

    def test_members_stamped_after_the_session(self) -> None:
        self.assertFired(
            self.dossier(late_members=("005.JPG",)), "zip.entry-written-after-session"
        )


class HostileArchiveTest(ArchiveTestCase):
    """Archives are attacker-controlled input (PLAN §4)."""

    def test_zip_slip_is_refused(self) -> None:
        from mosslib.archive import ArchiveError, open_archive

        path = self.tmp / "slip.zip"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("../../etc/passwd", b"nope")
        with self.assertRaises(ArchiveError), open_archive(path):
            pass

    def test_absolute_path_is_refused(self) -> None:
        from mosslib.archive import ArchiveError, open_archive

        path = self.tmp / "abs.zip"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("/etc/shadow", b"nope")
        with self.assertRaises(ArchiveError), open_archive(path):
            pass

    def test_zip_bomb_ratio_is_refused(self) -> None:
        from mosslib.archive import ArchiveError, open_archive

        path = self.tmp / "bomb.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.bin", b"\x00" * (50 * 1024 * 1024))
        with self.assertRaises(ArchiveError), open_archive(path):
            pass

    def test_not_a_zip_is_refused(self) -> None:
        from mosslib.archive import ArchiveError, open_archive

        path = self.tmp / "notazip.zip"
        path.write_bytes(b"this is not a zip file")
        with self.assertRaises(ArchiveError), open_archive(path):
            pass

    def test_archive_without_log_is_reported_not_crashed(self) -> None:
        from mosslib.parser import parse_archive

        path = self.tmp / "nolog.zip"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("001.JPG", b"\xff\xd8\xff\xd9")
        session = parse_archive(path)
        self.assertTrue(any(w.code == "no-log" for w in session.warnings))


if __name__ == "__main__":
    unittest.main()
