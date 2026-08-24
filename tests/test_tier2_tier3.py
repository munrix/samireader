"""Environment, configuration, capture and behavioural analyzers."""

from __future__ import annotations

import unittest

from mosslib.histogram import reconstruct
from mosslib.jpeg import inspect
from tests.fixtures.synth import jpeg_bytes, render_histogram
from tests.support import ArchiveTestCase

REMOTE_ACCESS = [
    (r"C:\Windows\System32\lsass.exe", "Microsoft Windows Publisher"),
    (r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", "philandro Software GmbH"),
]
FROM_DOWNLOADS = [
    (r"C:\Windows\System32\lsass.exe", "Microsoft Windows Publisher"),
    (r"C:\Users\szazi\Downloads\loader.exe", None),
]


class EnvironmentTest(ArchiveTestCase):
    def test_remote_access_tool_is_flagged(self) -> None:
        dossier = self.dossier(processes=REMOTE_ACCESS)
        self.assertFired(dossier, "environment.category.remote-access")
        finding = next(f for f in dossier.findings if f.rule == "environment.category.remote-access")
        self.assertEqual(finding.severity.value, "high")
        self.assertIn("connected", finding.benign)

    def test_unsigned_binary_from_downloads(self) -> None:
        dossier = self.dossier(processes=FROM_DOWNLOADS)
        self.assertFired(dossier, "environment.unsigned-process")
        self.assertFired(dossier, "environment.executed-from-temp")

    def test_system32_is_not_treated_as_unsigned_noise(self) -> None:
        dossier = self.dossier(
            processes=[(r"C:\Windows\System32\svchost.exe", None)]
        )
        self.assertNotFired(dossier, "environment.unsigned-process")

    def test_snapshot_limitation_is_always_stated(self) -> None:
        self.assertFired(self.dossier(), "environment.snapshot-limitation")

    def test_known_bad_hash_list(self) -> None:
        scan = self.scan(processes=FROM_DOWNLOADS)
        target = next(p for p in scan.session.processes if p.name == "loader.exe")
        from sami.dossier import analyze_scan
        from sami.rules import RulePack

        rules = RulePack.default()
        rules.data["environment"]["known_bad_sha256"] = [target.sha256]
        dossier = analyze_scan(scan, rules)
        self.assertFired(dossier, "environment.known-bad-hash")

    def test_defender_disabled(self) -> None:
        self.assertFired(self.dossier(defender="disabled"), "environment.defender-disabled")


class ConfigTest(ArchiveTestCase):
    def test_unknown_vulkan_layer(self) -> None:
        dossier = self.dossier(
            vulkan_layers="VK_LAYER_OW_OVERLAY;VK_LAYER_SOMETHING_ELSE"
        )
        self.assertFired(dossier, "config.unknown-vulkan-layer")

    def test_known_layers_are_quiet(self) -> None:
        self.assertNotFired(self.dossier(), "config.unknown-vulkan-layer")

    def test_out_of_range_sensitivity(self) -> None:
        dossier = self.dossier(
            configs={
                "GameSettings.ini.001": (
                    "[INPUT]\nMouseSensitivityMultiplierUnit=999.0\n"
                    "VulkanWhitelistedLayers=VK_LAYER_OW_OVERLAY\n"
                )
            }
        )
        self.assertFired(dossier, "config.value-out-of-range")

    def test_console_flag(self) -> None:
        dossier = self.dossier(
            configs={
                "GameSettings.ini.001": (
                    "[GAMEPLAY]\nConsole=1\nVulkanWhitelistedLayers=VK_LAYER_OW_OVERLAY\n"
                )
            }
        )
        self.assertFired(dossier, "config.flag-enabled")

    def test_many_profiles(self) -> None:
        self.assertFired(self.dossier(profiles=8), "config.many-profiles")

    def test_ini_parsing_is_tolerant(self) -> None:
        from sami.analyzers.config import parse_ini

        values = parse_ini("; comment\n[SECTION]\nA=1\nbroken line\nB = two words \n")
        self.assertEqual(values, {"A": "1", "B": "two words"})


class ScreenshotTest(ArchiveTestCase):
    def test_blank_frames(self) -> None:
        self.assertFired(self.dossier(blank_frames=(4, 5, 6)), "screenshots.blank-frame")

    def test_identical_frames(self) -> None:
        self.assertFired(self.dossier(duplicate_frames=(9, 10)), "screenshots.identical-frames")

    def test_resolution_change(self) -> None:
        self.assertFired(self.dossier(resolution_change_at=12), "screenshots.resolution-change")

    def test_truncated_frame(self) -> None:
        self.assertFired(self.dossier(truncated_frames=(3,)), "screenshots.corrupt-frame")

    def test_clean_captures_are_quiet(self) -> None:
        fired = self.rules_fired(self.dossier())
        self.assertEqual(
            {r for r in fired if r.startswith("screenshots.")},
            {"screenshots.no-content-analysis"},
        )

    def test_jpeg_dimensions_without_decoding(self) -> None:
        info = inspect(jpeg_bytes(3840, 1089, 50_000, seed=1))
        self.assertEqual(info.dimensions, (3840, 1089))
        self.assertTrue(info.valid_soi)
        self.assertFalse(info.truncated)

    def test_truncated_jpeg_is_detected(self) -> None:
        info = inspect(jpeg_bytes(1920, 1080, 20_000, seed=2, truncated=True))
        self.assertTrue(info.truncated)

    def test_non_jpeg_is_detected(self) -> None:
        info = inspect(b"not a jpeg at all")
        self.assertFalse(info.valid_soi)
        self.assertIsNotNone(info.error)


class HistogramTest(unittest.TestCase):
    def test_reconstruction_recovers_the_distribution(self) -> None:
        buckets = {0: 1, 5: 3, 10: 9, 15: 12, 20: 6, 25: 2}
        block = render_histogram(["LEFT CLICK", "LEFT CLICK"], buckets)
        hist = reconstruct(block)
        self.assertEqual(hist.kind, "interval")
        self.assertEqual(hist.keys, ["LEFT CLICK", "LEFT CLICK"])
        self.assertEqual(hist.unit, "ms")
        self.assertEqual(hist.total_events, sum(buckets.values()))
        self.assertEqual(hist.reconstruction, "full")
        self.assertEqual({b.lower: b.count for b in hist.buckets}, buckets)

    def test_no_recoil_histogram(self) -> None:
        block = render_histogram([], {0: 4, 5: 2}, unit="px", span=150)
        hist = reconstruct(block)
        self.assertEqual(hist.kind, "no_recoil")
        self.assertEqual(hist.unit, "px")

    def test_unreadable_drawing_is_reported_not_guessed(self) -> None:
        hist = reconstruct([" sequence [A] [B] : interval distribution", "    ^  10 events"])
        self.assertEqual(hist.reconstruction, "failed")
        self.assertEqual(hist.buckets, [])


class BehaviourTest(ArchiveTestCase):
    def test_sub_human_double_click_interval(self) -> None:
        dossier = self.dossier(fast_double_click=True)
        self.assertFired(dossier, "behaviour.below-human-interval")
        finding = next(f for f in dossier.findings if f.rule == "behaviour.below-human-interval")
        self.assertEqual(finding.tier.value, 3)
        self.assertIn(finding.confidence.value, ("low", "moderate"))

    def test_human_spread_is_quiet(self) -> None:
        self.assertNotFired(self.dossier(), "behaviour.below-human-interval")

    def test_tier_limit_excludes_behaviour(self) -> None:
        from sami.dossier import analyze_scan

        dossier = analyze_scan(
            self.scan(fast_double_click=True), self.rules, max_tier=1
        )
        self.assertFalse({f for f in self.rules_fired(dossier) if f.startswith("behaviour.")})
        self.assertFalse({f for f in self.rules_fired(dossier) if f.startswith("environment.")})


if __name__ == "__main__":
    unittest.main()
