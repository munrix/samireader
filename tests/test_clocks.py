"""Clock reconciliation — the four timestamp failure modes of DECISIONS D2."""

from __future__ import annotations

import json
import unittest
from datetime import datetime

from mosslib.timeutil import is_valid_utc_offset, nearest_valid_offset, parse_running_time
from sami.schedule import ScheduleError, load_schedule
from tests.support import ArchiveTestCase


class ClockArithmeticTest(unittest.TestCase):
    def test_valid_offsets(self) -> None:
        for minutes in (0, 60, -300, 180, 330, 345, 840, -720):
            self.assertTrue(is_valid_utc_offset(minutes), minutes)

    def test_invalid_offsets(self) -> None:
        for minutes in (37, 137, 217, -95, 1000):
            self.assertFalse(is_valid_utc_offset(minutes), minutes)

    def test_small_drift_is_tolerated(self) -> None:
        self.assertTrue(is_valid_utc_offset(180.9))
        self.assertEqual(nearest_valid_offset(182), 180)

    def test_running_time_formats(self) -> None:
        self.assertEqual(parse_running_time("12:10:12:48"), 12 * 86400 + 10 * 3600 + 12 * 60 + 48)
        self.assertEqual(parse_running_time("00:02:52"), 172)
        self.assertIsNone(parse_running_time("nonsense"))


class ClockFindingTest(ArchiveTestCase):
    def test_clean_archive_reconciles(self) -> None:
        dossier = self.dossier()
        self.assertFired(dossier, "clocks.reconciled")
        self.assertEqual(dossier.clocks.host_offset_minutes, 180)
        self.assertTrue(dossier.clocks.offset_is_valid)

    def test_system_clock_manipulation_shows_on_the_network_clock(self) -> None:
        # The whole OS moves with the system clock — log times, ZIP entry times
        # and the filename — but MOSS's network-synced header does not.
        dossier = self.dossier(clock_skew_minutes=41)
        self.assertFired(dossier, "clocks.network-clock-disagrees")
        self.assertTrue(
            dossier.clocks.offset_is_valid,
            "a uniformly skewed clock still yields a valid-looking offset; the network "
            "clock is what catches it",
        )

    def test_log_editing_shows_as_an_impossible_offset(self) -> None:
        dossier = self.dossier(log_time_shift_minutes=25)
        self.assertFired(dossier, "clocks.invalid-utc-offset")

    def test_clock_moved_mid_session(self) -> None:
        self.assertFired(
            self.dossier(mid_session_shift_minutes=-20), "clocks.non-monotonic-captures"
        )

    def test_boot_time_bounds_the_session(self) -> None:
        dossier = self.dossier(uptime_hours=0.05, captures=40)
        self.assertFired(dossier, "clocks.session-before-boot")
        self.assertIsNotNone(dossier.clocks.boot_time_local)
        self.assertEqual(dossier.clocks.uptime_source, "lsass.exe")

    def test_plausible_uptime_does_not_fire(self) -> None:
        self.assertNotFired(self.dossier(uptime_hours=30), "clocks.session-before-boot")

    def test_capture_gap_is_reported(self) -> None:
        self.assertFired(
            self.dossier(captures=8, interval_s=900, interval_jitter_s=0), "session.capture-gap"
        )


class ScheduleTest(ArchiveTestCase):
    MATCH = {
        "match_id": "R6-QF1",
        "start": "2024-03-28T21:05:00+03:00",
        "end": "2024-03-28T22:05:00+03:00",
        "rounds": [
            {
                "number": n,
                "start": f"2024-03-28T21:{5 + (n - 1) * 7:02d}:00+03:00",
                "end": f"2024-03-28T21:{5 + (n - 1) * 7 + 5:02d}:00+03:00",
            }
            for n in range(1, 8)
        ],
        "players": [{"name": "szazi", "team": "A", "archive": "sample.zip"}],
    }

    def schedule(self, **overrides):
        data = {**self.MATCH, **overrides}
        path = self.tmp / "schedule.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return load_schedule(path)

    def test_naive_timestamps_are_refused(self) -> None:
        path = self.tmp / "naive.json"
        path.write_text(
            json.dumps({"match_id": "x", "start": "2024-03-28T21:05:00", "end": "2024-03-28T22:00:00"})
        )
        with self.assertRaises(ScheduleError):
            load_schedule(path)

    def test_session_covering_the_match_is_clean(self) -> None:
        dossier = self.dossier(
            schedule=self.schedule(),
            start_local=datetime(2024, 3, 28, 21, 0, 0),
            captures=70,
        )
        self.assertFired(dossier, "schedule.covers-match")
        self.assertNotFired(dossier, "schedule.late-start")
        self.assertNotFired(dossier, "schedule.early-stop")

    def test_late_start_is_caught(self) -> None:
        dossier = self.dossier(
            schedule=self.schedule(),
            start_local=datetime(2024, 3, 28, 21, 25, 0),
            captures=45,
        )
        self.assertFired(dossier, "schedule.late-start")
        finding = next(f for f in dossier.findings if f.rule == "schedule.late-start")
        self.assertEqual(finding.severity.value, "high")
        self.assertTrue(any("Rounds with no coverage" in e.label for e in finding.evidence))

    def test_early_stop_is_caught(self) -> None:
        dossier = self.dossier(
            schedule=self.schedule(),
            start_local=datetime(2024, 3, 28, 21, 0, 0),
            captures=20,
        )
        self.assertFired(dossier, "schedule.early-stop")

    def test_a_capture_cadence_shortfall_is_not_an_early_stop(self) -> None:
        # The last capture is not the moment recording stopped; MOSS's ~60s
        # cadence means a small shortfall is expected and must not read as one.
        dossier = self.dossier(
            schedule=self.schedule(),
            start_local=datetime(2024, 3, 28, 21, 0, 0),
            captures=65,
            interval_s=60,
            interval_jitter_s=0,
        )
        self.assertNotFired(dossier, "schedule.early-stop")

    def test_wrong_day_is_caught(self) -> None:
        dossier = self.dossier(
            schedule=self.schedule(),
            start_local=datetime(2024, 3, 25, 21, 0, 0),
            captures=70,
        )
        self.assertFired(dossier, "schedule.wrong-date")
        self.assertEqual(dossier.priority[0], "P1")

    def test_gap_over_a_round_is_caught(self) -> None:
        dossier = self.dossier(
            schedule=self.schedule(),
            start_local=datetime(2024, 3, 28, 21, 0, 0),
            captures=8,
            interval_s=600,
            interval_jitter_s=0,
        )
        self.assertFired(dossier, "schedule.round-coverage-gap")

    def test_no_schedule_means_no_schedule_findings(self) -> None:
        fired = self.rules_fired(self.dossier())
        self.assertFalse({r for r in fired if r.startswith("schedule.")})


if __name__ == "__main__":
    unittest.main()
