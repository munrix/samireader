"""End-to-end: drive the browser app with real archives in real Chromium.

The app runs entirely in the page — ZIP reading, SHA-256 hashing via WebCrypto,
and the rules. None of that is exercised by importing a module, so this test
starts a server, opens the page in Chromium, hands it an actual MOSS archive
built by the fixture builder, and reads the verdict off the rendered DOM.

Skipped rather than failed when Playwright or the Chromium build is missing, so
a checkout without them still runs the rest of the suite.
"""

from __future__ import annotations

import socket
import sys
import tempfile
import threading
import unittest
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import tests  # noqa: F401  (bootstraps sys.path)

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

CHROMIUM = Path("/opt/pw-browsers/chromium-1194/chrome-linux/chrome")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class WebAppTest(unittest.TestCase):
    """One built site and one browser, shared by every assertion below."""

    server = None
    thread = None
    playwright = None
    browser = None

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise unittest.SkipTest("playwright is not installed") from exc
        if not CHROMIUM.is_file():  # pragma: no cover - environment dependent
            raise unittest.SkipTest(f"chromium not found at {CHROMIUM}")

        from build_site import main as build_site

        from fixtures.synth import Synth

        cls._tmp = tempfile.TemporaryDirectory()
        cls.site = Path(cls._tmp.name) / "site"
        build_site(str(cls.site), verbose=False)

        # Archives live inside the served tree so the page can fetch them the
        # way a browser would, rather than through a file-picker shim.
        archives = cls.site / "test-archives"
        archives.mkdir()
        cls.archives = {
            "clean": Synth(directory=archives).build(),
            "tampered": Synth(directory=archives, nonce="2", tamper_capture="005.JPG").build(),
            "removed": Synth(directory=archives, nonce="3", remove_capture="007.JPG").build(),
            "rebuilt": Synth(
                directory=archives, nonce="4", uniform_mtimes=True,
                stored_compression=True, drop_footer=True,
            ).build(),
            "moved-clock": Synth(directory=archives, nonce="5", clock_skew_minutes=41).build(),
            "busy": Synth(
                directory=archives, nonce="6",
                blank_frames=(11, 12), fast_double_click=True,
                vulkan_layers="VK_LAYER_OW_OVERLAY;VK_LAYER_ZZ_hook",
                processes=[
                    (r"C:\Windows\System32\lsass.exe", "Microsoft Windows Publisher"),
                    (r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", "philandro Software GmbH"),
                    (r"C:\Users\szazi\Downloads\loader.exe", None),
                ],
            ).build(),
        }

        port = _free_port()

        class QuietHandler(SimpleHTTPRequestHandler):
            def log_message(self, *args):  # keep the test output readable
                pass

        handler = partial(QuietHandler, directory=str(cls.site))
        cls.server = ThreadingHTTPServer(("127.0.0.1", port), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{port}"

        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(executable_path=str(CHROMIUM))

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.browser:
            cls.browser.close()
        if cls.playwright:
            cls.playwright.stop()
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()
        cls._tmp.cleanup()

    # ------------------------------------------------------------------ helper

    def analyse(self, key: str) -> dict:
        """Open the app, hand it an archive, return what the page rendered."""
        page = self.browser.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)

        page.goto(f"{self.base}/index.html", wait_until="load")
        page.set_input_files("#file-input", str(self.archives[key]))
        # #results losing .hidden is the completion signal; waiting for the
        # progress card to be "visible while hidden" never resolves.
        page.wait_for_selector("#results:not(.hidden)", timeout=60_000)

        result = {
            "verdict": page.inner_text(".verdict"),
            "rules": page.evaluate(
                "[...document.querySelectorAll('.finding h3')].map(h => h.textContent)"
            ),
            "text": page.inner_text("#results"),
            "errors": errors,
        }
        page.close()
        self.assertEqual(result["errors"], [], f"{key}: page errors")
        return result

    # ------------------------------------------------------------------- tests

    def test_clean_archive_reads_clean(self) -> None:
        result = self.analyse("clean")
        self.assertIn("Clean", result["verdict"])
        self.assertIn("not a finding of innocence", result["text"])

    def test_clean_archive_verified_the_hashes_in_the_browser(self) -> None:
        # The whole point of the tool: WebCrypto really re-hashed the files.
        result = self.analyse("clean")
        self.assertRegex(result["text"], r"All \d+ files match the hash MOSS recorded")

    def test_edited_capture_is_caught(self) -> None:
        result = self.analyse("tampered")
        self.assertIn("problem", result["verdict"])
        self.assertTrue(
            any("not the file MOSS recorded" in r for r in result["rules"]),
            result["rules"],
        )
        self.assertIn("005.JPG", result["text"])

    def test_removed_capture_is_caught(self) -> None:
        result = self.analyse("removed")
        self.assertTrue(
            any("lists files that are not in the archive" in r for r in result["rules"]),
            result["rules"],
        )

    def test_rebuilt_archive_is_caught(self) -> None:
        result = self.analyse("rebuilt")
        titles = " | ".join(result["rules"])
        self.assertIn("same timestamp", titles)
        self.assertIn("no closing line", titles)

    def test_moved_system_clock_is_caught(self) -> None:
        # Everything the OS stamps moves with the clock; MOSS's network-synced
        # header does not. That asymmetry is the whole detection.
        result = self.analyse("moved-clock")
        self.assertTrue(
            any("disagrees with the host clock" in r for r in result["rules"]),
            result["rules"],
        )

    def test_environment_and_input_findings(self) -> None:
        result = self.analyse("busy")
        titles = " | ".join(result["rules"])
        self.assertIn("Remote-access software", titles)
        self.assertIn("unsigned executable", titles)
        self.assertIn("temporary or download folders", titles)
        self.assertIn("Vulkan layer", titles)
        self.assertIn("far smaller than the rest", titles)
        self.assertIn("faster than a person can sustain", titles)

    def test_every_finding_shows_its_innocent_explanation(self) -> None:
        result = self.analyse("busy")
        count = len(result["rules"])
        self.assertGreater(count, 4)
        page = self.browser.new_page()
        page.goto(f"{self.base}/index.html", wait_until="load")
        page.set_input_files("#file-input", str(self.archives["busy"]))
        page.wait_for_selector("#results:not(.hidden)", timeout=60_000)
        benign = page.evaluate("document.querySelectorAll('.finding .block.benign').length")
        page.close()
        self.assertEqual(benign, count, "every finding must carry a benign explanation")

    def test_screenshots_and_processes_are_shown(self) -> None:
        result = self.analyse("clean")
        self.assertIn("Screenshots", result["text"])
        self.assertIn("Processes running at game start", result["text"])

    def test_page_makes_no_network_calls_for_the_analysis(self) -> None:
        """No upload, no API: the only requests are the page's own assets."""
        page = self.browser.new_page()
        requests: list[str] = []
        page.on("request", lambda r: requests.append(r.url))
        page.goto(f"{self.base}/index.html", wait_until="load")
        page.set_input_files("#file-input", str(self.archives["busy"]))
        page.wait_for_selector("#results:not(.hidden)", timeout=60_000)
        page.close()
        external = [u for u in requests if not u.startswith(self.base)]
        self.assertEqual(external, [], "the app must not talk to anything off-page")

    def test_a_non_moss_zip_is_reported_not_crashed(self) -> None:
        import zipfile

        junk = self.site / "test-archives" / "not-moss.zip"
        with zipfile.ZipFile(junk, "w") as zf:
            zf.writestr("hello.txt", b"nothing to see")
        page = self.browser.new_page()
        page.goto(f"{self.base}/index.html", wait_until="load")
        page.set_input_files("#file-input", str(junk))
        page.wait_for_selector("#results:not(.hidden)", timeout=30_000)
        text = page.inner_text("#results")
        page.close()
        self.assertIn("does not look like a MOSS archive", text)


if __name__ == "__main__":
    unittest.main()
