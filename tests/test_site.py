"""The docs site: the Markdown renderer, and the built output."""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

import tests  # noqa: F401  (bootstraps sys.path)

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from site_markdown import render  # noqa: E402


class MarkdownTest(unittest.TestCase):
    def html(self, text: str) -> str:
        return render(text)[0]

    def test_headings_get_anchors(self) -> None:
        body, headings = render("## Retention and privacy\n")
        self.assertIn('<h2 id="retention-and-privacy">', body)
        self.assertEqual(headings, [(2, "Retention and privacy", "retention-and-privacy")])

    def test_table_with_alignment(self) -> None:
        html = self.html("| A | B |\n|---|---:|\n| 1 | 2 |\n")
        self.assertIn("<th>A</th>", html)
        self.assertIn('<th style="text-align:right">B</th>', html)
        self.assertIn("<td>1</td>", html)

    def test_fenced_code_is_literal(self) -> None:
        html = self.html("```python\nprint('<b>')\n```\n")
        self.assertIn("&lt;b&gt;", html)
        self.assertNotIn("<b>", html)

    def test_inline_code_is_not_reformatted(self) -> None:
        html = self.html("Use `**not bold**` here.\n")
        self.assertIn("<code>**not bold**</code>", html)
        self.assertNotIn("<strong>", html)

    def test_bold_spanning_a_line_break(self) -> None:
        # Real documents wrap. An inline span must survive the wrap.
        html = self.html("- **Per-file verification: recompute the hash and\n  compare it.** Then continue.\n")
        self.assertIn("<strong>Per-file verification: recompute the hash and compare it.</strong>", html)

    def test_nested_list(self) -> None:
        html = self.html("- outer\n  - inner\n- second\n")
        self.assertIn("<ul><li>outer<ul><li>inner</li></ul></li><li>second</li></ul>", html)

    def test_links_can_be_rewritten(self) -> None:
        html = render("See [the plan](docs/PLAN.md).", link_rewriter=lambda h: "/plan.html")[0]
        self.assertIn('<a href="/plan.html">the plan</a>', html)

    def test_html_in_prose_is_escaped(self) -> None:
        html = self.html("A <script>alert(1)</script> in prose.\n")
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_blockquote_and_rule(self) -> None:
        html = self.html("> quoted\n\n---\n")
        self.assertIn("<blockquote><p>quoted</p></blockquote>", html)
        self.assertIn("<hr>", html)

    def test_every_repository_document_renders(self) -> None:
        sources = [ROOT / "README.md", ROOT / "CHANGELOG.md", *(ROOT / "docs").glob("*.md")]
        self.assertGreaterEqual(len(sources), 6)
        for source in sources:
            body, _ = render(source.read_text(encoding="utf-8"))
            text = re.sub(r"<(pre|code)[^>]*>.*?</\1>", "", body, flags=re.S)
            text = re.sub(r"<[^>]+>", " ", text)
            self.assertNotIn("**", text, f"{source.name}: unrendered bold")
            self.assertNotRegex(text, r"\|\s*---", f"{source.name}: unrendered table")


class SiteBuildTest(unittest.TestCase):
    """Builds the whole site once; the assertions all read that output."""

    @classmethod
    def setUpClass(cls) -> None:
        from build_site import main

        cls._tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls._tmp.name) / "site"
        main(str(cls.out), verbose=False)
        cls.pages = {p.relative_to(cls.out).as_posix(): p.read_text() for p in cls.out.rglob("*.html")}

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_expected_pages_exist(self) -> None:
        for name in ("index.html", "samples/index.html", "samples/match.html",
                     "docs/index.html", "docs/research.html", "docs/operations.html"):
            self.assertIn(name, self.pages)

    def test_landing_page_states_the_no_verdict_rule(self) -> None:
        landing = self.pages["index.html"]
        self.assertIn("never outputs a verdict", landing)
        self.assertIn("benign explanation", landing)

    def test_sample_pages_are_labelled_as_synthetic(self) -> None:
        samples = [name for name in self.pages if name.startswith("samples/")]
        self.assertGreaterEqual(len(samples), 6)
        for name in samples:
            if name == "samples/index.html":
                continue
            self.assertIn("synthetic archive", self.pages[name],
                          f"{name} must say its data is synthetic")

    def test_no_page_loads_an_external_resource(self) -> None:
        for name, html in self.pages.items():
            for match in re.finditer(r'(?:src|href)="(https?://[^"]+)"', html):
                url = match.group(1)
                # Hyperlinks are fine; loaded resources are not.
                attribute = html[max(0, match.start() - 6):match.start()]
                self.assertNotIn("src", attribute, f"{name} loads {url}")

    def test_build_is_deterministic_in_page_set(self) -> None:
        from build_site import main

        with tempfile.TemporaryDirectory() as other:
            second = Path(other) / "site"
            main(str(second), verbose=False)
            self.assertEqual(
                sorted(self.pages),
                sorted(p.relative_to(second).as_posix() for p in second.rglob("*.html")),
            )

    def test_build_leaves_no_working_directory_behind(self) -> None:
        self.assertFalse((self.out / ".build").exists())
        self.assertEqual(list(self.out.rglob("*.zip")), [])


if __name__ == "__main__":
    unittest.main()
