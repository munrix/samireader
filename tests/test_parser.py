"""The parser against the documented grammar (RESEARCH §3)."""

from __future__ import annotations

import unittest

import tests  # noqa: F401  (bootstraps sys.path)
from mosslib.parser import parse_log_text
from mosslib.timeutil import parse_running_time
from tests.support import ArchiveTestCase

SAMPLE = """SHAS2 mode started at 2024-03-28 19:00:12 for Rainbow Six on x64
 ping:68ms
update 6
DirectX version is 12.0( )
OS is 10.0 64 bit build 19045
Real OS Windows 10 or 11
PCI: NVIDIA GeForce RTX 3080 (0x10DE-0x220A)
memory: 16237 MB
version: MOSS 6,6,9,0
Physical: Micro-Star International Co., Ltd.MS-7D24PRO B660M-P DDR4 WIFI (MS-7D24)
Sign ID1: 1434136903
User: GeeKay@DESKTOP-RLNAQE3
Drive: WD_BLACK SN770 1TB serial:
Net: 192.168.100.33 Public: 90.148.144.xxx
Video: NVIDIA GeForce RTX 3080 driver : 31.0.15.3742
Monitor: ZOWIE XL LCD serial: EBB9N00443SL0
Usb: Logitech PRO Gaming Keyboard (0C6832703832) (0x46D-0xC339)
processor BIOS details 2500 MHz by 25.00*100. 13th Gen Intel(R) Core(TM) i5-13400F
Monitor Started at 2024/03/28 21:00:18
Windows Defender: enabled
SteamId: 0
SHAS2: aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233 Author: Microsoft Windows process: C:\\Windows\\explorer.exe
*SHAS2: bb11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233 Author: Helpfeel Inc process: C:\\Users\\x\\GyazoVideoCore.exe
SHAS2: cc11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233 process: C:\\Users\\x\\Downloads\\thing.exe
SHAS2: dd11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233 Author: UBISOFT ENTERTAINMENT INC. process: C:\\Games\\RainbowSix_Vulkan.exe
Game Detected
FileCheck start for C:\\USERS\\SZAZI\\APPDATA\\LOCAL\\UBISOFT\\R6SIEGE at 2024/03/28 20:51:32:
Search for files
captured: C:\\Users\\x\\GameSettings.ini file: GameSettings.ini.001- Zip CRC: 1122334455667788990011223344556677889900112233445566778899001122
FileCheck end for C:\\USERS\\SZAZI\\APPDATA\\LOCAL\\UBISOFT\\R6SIEGE at 2024/03/28 20:51:32:
 Dxgi ...(75)(Mon 1) DX11(312) : Each 60 at 2024/03/28 21:05:52 file: 010.JPG- Zip CRC: 5f9322cb00000000000000000000000000000000000000000000000000000000
Processes statistics  ping:274
PID\tRunning Time\tKernel Time\tUser Time\tName
896\t12:10:12:48 \t00:02:52 \t00:02:44 \tlsass.exe
Global log CRC: 51863537190742710a6e241149f66441e050afd053378f43d18d60aa248b096c
"""


class ParserTest(unittest.TestCase):
    def setUp(self) -> None:
        self.session = parse_log_text(SAMPLE)

    def test_header(self) -> None:
        self.assertEqual(self.session.game, "Rainbow Six")
        self.assertEqual(self.session.arch, "x64")
        self.assertEqual(str(self.session.header_started_at), "2024-03-28 19:00:12")
        self.assertEqual(self.session.ping_ms, 68)
        self.assertEqual(self.session.moss_version, "6.6.9.0")

    def test_hardware(self) -> None:
        hw = self.session.hardware
        self.assertEqual(hw.sign_id1, "1434136903")
        self.assertEqual(hw.user, "GeeKay")
        self.assertEqual(hw.hostname, "DESKTOP-RLNAQE3")
        self.assertEqual(hw.memory_mb, 16237)
        self.assertEqual(hw.lan_ip, "192.168.100.33")
        self.assertEqual(hw.public_ip, "90.148.144.xxx")
        self.assertEqual(hw.monitors[0].serial, "EBB9N00443SL0")
        self.assertEqual(hw.video[0].driver, "31.0.15.3742")
        self.assertEqual(hw.pci[0].vendor_id, "0x10DE")
        self.assertEqual(hw.processor_mhz, 2500)
        self.assertIsNone(hw.drives[0].serial, "an empty serial must stay empty, not become a string")
        self.assertEqual(hw.real_os, "Windows 10 or 11")

    def test_processes(self) -> None:
        self.assertEqual(len(self.session.processes), 4)
        starred = [p for p in self.session.processes if p.starred]
        self.assertEqual(len(starred), 1, "the '*' prefix must be preserved, not stripped")
        unsigned = [p for p in self.session.processes if not p.signed]
        self.assertEqual([p.name for p in unsigned], ["thing.exe"])
        self.assertTrue(self.session.game_detected)
        self.assertIn("RainbowSix_Vulkan.exe", self.session.game_process or "")

    def test_screenshot_record(self) -> None:
        shot = self.session.screenshots[0]
        self.assertEqual(shot.file, "010.JPG")
        self.assertEqual(shot.monitor, 1)
        self.assertEqual(shot.nominal_interval_s, 60)
        self.assertEqual(shot.index, 10)
        self.assertEqual(str(shot.at), "2024-03-28 21:05:52")
        self.assertTrue(shot.crc.startswith("5f9322cb"))

    def test_captured_file(self) -> None:
        captured = self.session.captured_files[0]
        self.assertEqual(captured.file, "GameSettings.ini.001")
        self.assertEqual(len(captured.crc), 64)
        self.assertEqual(len(self.session.file_checks), 1)
        self.assertIsNotNone(self.session.file_checks[0].ended_at)

    def test_process_statistics(self) -> None:
        stat = self.session.stat("lsass.exe")
        self.assertIsNotNone(stat)
        self.assertEqual(stat.running_time_s, parse_running_time("12:10:12:48"))
        self.assertEqual(self.session.stats_ping_ms, 274)

    def test_footer_and_coverage(self) -> None:
        self.assertEqual(len(self.session.global_log_crc), 64)
        self.assertEqual(
            self.session.unknown_lines, [], "every documented line type must be claimed by a rule"
        )

    def test_unknown_lines_are_kept_not_dropped(self) -> None:
        session = parse_log_text("SomeFutureMossField: 42\nGlobal log CRC: ab\n")
        self.assertEqual(len(session.unknown_lines), 1)
        self.assertEqual(session.unknown_lines[0].number, 1)
        self.assertEqual(session.unknown_lines[0].raw, "SomeFutureMossField: 42")

    def test_malformed_input_does_not_raise(self) -> None:
        for text in ("", "\n\n\n", "\x00\x01garbage", "SHAS2: notahash process:", "a" * 10000):
            parse_log_text(text)

    def test_round_trip(self) -> None:
        from mosslib.model import Session

        restored = Session.from_json(self.session.to_json())
        self.assertEqual(restored.to_json(), self.session.to_json())


class ArchiveParserTest(ArchiveTestCase):
    def test_parses_synthetic_archive_without_unknown_lines(self) -> None:
        scan = self.scan()
        self.assertEqual(scan.session.unknown_lines, [])
        self.assertEqual(scan.session.warnings, [])
        self.assertEqual(len(scan.session.screenshots), 20)
        self.assertEqual(scan.session.moss_version, "6.6.9.0")

    def test_archive_name_is_parsed(self) -> None:
        info = self.scan().session.archive
        self.assertEqual(info.name_sign_id, "1434136903")
        self.assertIsNotNone(info.name_timestamp)
        self.assertEqual(len(info.sha256), 64)


if __name__ == "__main__":
    unittest.main()
