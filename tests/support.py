"""Shared test scaffolding."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import tests  # noqa: F401  (bootstraps sys.path)
from fixtures.synth import Synth
from sami.dossier import Dossier, analyze_scan
from sami.ingest import scan_archive
from sami.rules import RulePack


class ArchiveTestCase(unittest.TestCase):
    """Builds synthetic archives into a temporary directory per test."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.rules = RulePack.default()
        self.addCleanup(self._tmp.cleanup)

    def build(self, **options) -> Path:
        return Synth(directory=self.tmp / "archives", **options).build()

    def scan(self, **options):
        return scan_archive(self.build(**options))

    def dossier(self, *, schedule=None, rules: RulePack | None = None, **options) -> Dossier:
        return analyze_scan(
            self.scan(**options), rules or self.rules, schedule=schedule
        )

    # ------------------------------------------------------------- assertions

    def rules_fired(self, dossier: Dossier) -> set[str]:
        return {f.rule for f in dossier.findings}

    def assertFired(self, dossier: Dossier, rule: str) -> None:
        fired = self.rules_fired(dossier)
        self.assertIn(rule, fired, f"expected {rule}; fired: {sorted(fired)}")

    def assertNotFired(self, dossier: Dossier, rule: str) -> None:
        self.assertNotIn(rule, self.rules_fired(dossier))
