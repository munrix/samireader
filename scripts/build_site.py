#!/usr/bin/env python3
"""Build the static site: landing page, rendered docs, and live sample reports.

samireader is a CLI that writes self-contained HTML, so its site is the same
thing at rest: no server, no framework, no build step at deploy time. Vercel (or
any static host, or a USB stick at a LAN) serves the output directory as-is.

    python3 scripts/build_site.py site

The sample reports are produced by running the real tool over archives from the
synthetic fixture builder. No real archive and no real person is involved, and
every sample page says so at the top — a forensic report that looks genuine but
is not must never be mistakable for one.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))

from make_demo import main as build_demo_archives  # noqa: E402
from site_markdown import render as render_markdown  # noqa: E402

from sami.dossier import MatchDossier, analyze_scan  # noqa: E402
from sami.ingest import scan_archive  # noqa: E402
from sami.report.html import render_dossier, render_match  # noqa: E402
from sami.report.theme import CSS  # noqa: E402
from sami.rules import RulePack  # noqa: E402
from sami.schedule import load_schedule  # noqa: E402
from sami.version import __version__  # noqa: E402

REPO_URL = "https://github.com/munrix/samireader"

DOCS = [
    ("index", "Overview", ROOT / "README.md"),
    ("research", "Research", ROOT / "docs" / "RESEARCH.md"),
    ("plan", "Plan", ROOT / "docs" / "PLAN.md"),
    ("decisions", "Decisions", ROOT / "docs" / "DECISIONS.md"),
    ("operations", "Operations", ROOT / "docs" / "OPERATIONS.md"),
    ("questions", "Open questions", ROOT / "docs" / "QUESTIONS.md"),
    ("changelog", "Changelog", ROOT / "CHANGELOG.md"),
]

#: Repository paths that become site pages, so in-document links keep working.
LINK_MAP = {
    "README.md": "/docs/index.html",
    "docs/RESEARCH.md": "/docs/research.html",
    "docs/PLAN.md": "/docs/plan.html",
    "docs/DECISIONS.md": "/docs/decisions.html",
    "docs/OPERATIONS.md": "/docs/operations.html",
    "docs/QUESTIONS.md": "/docs/questions.html",
    "CHANGELOG.md": "/docs/changelog.html",
    "LICENSE": f"{REPO_URL}/blob/main/LICENSE",
    "./RESEARCH.md": "/docs/research.html",
    "./PLAN.md": "/docs/plan.html",
    "./DECISIONS.md": "/docs/decisions.html",
    "./OPERATIONS.md": "/docs/operations.html",
    "./QUESTIONS.md": "/docs/questions.html",
}

SAMPLE_BANNER = """
<div class="sample-banner">
  <b>Sample output.</b> Every figure on this page was produced by running samireader over a
  <b>synthetic archive</b> from the project's test fixtures. No real MOSS archive, no real
  match and no real person is involved, and nothing here is a finding about anybody.
  <a href="/">What this is</a>
</div>
"""

SITE_CSS = """
.site-nav {
  position: sticky; top: 0; z-index: 20;
  background: var(--panel); border-bottom: 1px solid var(--line);
  padding: .6rem 0;
}
.site-nav .wrap { display: flex; gap: 1.1rem; align-items: baseline; flex-wrap: wrap; }
.site-nav a { color: var(--ink-2); text-decoration: none; font-size: .88rem; }
.site-nav a:hover { color: var(--accent); }
.site-nav a.brand { font-weight: 700; color: var(--ink); font-size: 1rem; letter-spacing: -.01em; }
.site-nav .spacer { flex: 1; }
.hero { padding: 3rem 0 1.5rem; }
.hero h1 { font-size: 2.1rem; line-height: 1.15; margin: 0 0 .6rem; }
.hero .lede { font-size: 1.1rem; color: var(--ink-2); max-width: 46rem; }
.hero .cta { display: flex; gap: .6rem; flex-wrap: wrap; margin-top: 1.4rem; }
.btn {
  display: inline-block; padding: .5rem .95rem; border-radius: 7px;
  border: 1px solid var(--line-2); color: var(--ink); text-decoration: none; font-size: .9rem;
}
.btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
.btn:hover { border-color: var(--accent); }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: .8rem; }
.card {
  background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 1rem 1.15rem;
}
.card h3 { margin: 0 0 .35rem; font-size: .98rem; }
.card p { color: var(--ink-2); font-size: .9rem; margin: 0; }
.card .tier { font-family: var(--mono); font-size: .72rem; color: var(--ink-3); }
.card a { text-decoration: none; }
.sample-banner {
  background: color-mix(in srgb, var(--accent) 10%, var(--panel));
  border-bottom: 1px solid var(--line-2);
  padding: .7rem 1.25rem; font-size: .86rem; color: var(--ink-2);
  text-align: center;
}
.doc { padding: 1.5rem 0 4rem; display: grid; grid-template-columns: minmax(0, 1fr); gap: 2rem; }
@media (min-width: 900px) { .doc { grid-template-columns: minmax(0, 1fr) 15rem; } }
.doc-body h1 { font-size: 1.7rem; margin-top: 0; }
.doc-body h2 { text-transform: none; letter-spacing: 0; font-size: 1.25rem; color: var(--ink); }
.doc-body h3 { font-size: 1.02rem; }
.doc-body pre.code {
  background: var(--panel-2); border: 1px solid var(--line);
  border-radius: 8px; padding: .75rem .9rem; overflow-x: auto; font-size: .82rem;
}
.doc-body code { background: var(--panel-2); padding: .08em .32em; border-radius: 4px; }
.doc-body pre.code code { background: none; padding: 0; }
.doc-body blockquote {
  margin: 1rem 0; padding: .6rem .9rem; border-left: 3px solid var(--accent);
  background: var(--panel-2); border-radius: 0 6px 6px 0; color: var(--ink-2);
}
.doc-body table { margin: .6rem 0; }
.doc-body li { margin: .2rem 0; }
.toc { font-size: .84rem; align-self: start; position: sticky; top: 4rem; }
.toc h4 { margin: 0 0 .4rem; font-size: .72rem; text-transform: uppercase;
  letter-spacing: .06em; color: var(--ink-3); }
.toc a { display: block; padding: .12rem 0; color: var(--ink-2); text-decoration: none; }
.toc a:hover { color: var(--accent); }
.toc a.level-3 { padding-left: .8rem; font-size: .8rem; }
.foot-links { display: flex; gap: 1rem; flex-wrap: wrap; }
@media print { .site-nav, .toc { display: none; } }
"""


def nav(active: str = "") -> str:
    items = [
        ("/", "Overview"),
        ("/samples/", "Sample reports"),
        ("/docs/research.html", "Research"),
        ("/docs/plan.html", "Plan"),
        ("/docs/operations.html", "Operations"),
    ]
    current = ' style="color:var(--accent)"'
    links = "".join(
        f'<a href="{href}"{current if label == active else ""}>{label}</a>'
        for href, label in items
    )
    return (
        '<nav class="site-nav"><div class="wrap">'
        '<a class="brand" href="/">samireader</a>'
        f"{links}"
        '<span class="spacer"></span>'
        f'<a href="{REPO_URL}">GitHub ↗</a>'
        "</div></nav>"
    )


def page(title: str, body: str, *, description: str = "", active: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="{description}">
<meta name="generator" content="samireader {__version__}">
<title>{title}</title>
<style>{CSS}{SITE_CSS}</style>
</head>
<body>
{nav(active)}
{body}
</body>
</html>
"""


def rewrite_link(href: str) -> str:
    if href.startswith(("http://", "https://", "#", "/")):
        return href
    cleaned = href.lstrip("./") if href.startswith("./") else href
    for key, value in LINK_MAP.items():
        if href == key or cleaned == key.lstrip("./"):
            return value
    return f"{REPO_URL}/blob/main/{cleaned}"


def build_docs(out: Path) -> None:
    (out / "docs").mkdir(parents=True, exist_ok=True)
    for slug, title, source in DOCS:
        if not source.is_file():
            continue
        body, headings = render_markdown(source.read_text(encoding="utf-8"),
                                         link_rewriter=rewrite_link)
        toc = "".join(
            f'<a class="level-{level}" href="#{anchor}">{label}</a>'
            for level, label, anchor in headings
            if 2 <= level <= 3
        )
        aside = f'<aside class="toc"><h4>On this page</h4>{toc}</aside>' if toc else ""
        other = "".join(
            f'<a href="/docs/{s}.html">{t}</a>'
            for s, t, _ in DOCS
            if s != slug
        )
        html = f"""
<main class="wrap doc">
  <article class="doc-body">{body}
    <footer class="foot"><div class="foot-links">{other}
      <a href="{REPO_URL}">Source on GitHub</a></div></footer>
  </article>
  {aside}
</main>"""
        (out / "docs" / f"{slug}.html").write_text(
            page(f"{title} — samireader", html, description=f"samireader {title.lower()}",
                 active=title),
            encoding="utf-8",
        )


def build_samples(out: Path, work: Path, *, verbose: bool = True) -> list[tuple[str, str, str, str]]:
    """Run the real tool over synthetic archives. Returns rows for the index."""
    samples = out / "samples"
    samples.mkdir(parents=True, exist_ok=True)
    build_demo_archives(str(work), verbose=verbose)

    rules = RulePack.default()
    schedule = load_schedule(work / "schedule.json")
    scans = [scan_archive(path) for path in sorted((work / "archives").glob("*.zip"))]
    dossiers = [
        analyze_scan(scan, rules, schedule=schedule, peers=scans) for scan in scans
    ]
    match = MatchDossier(dossiers=dossiers, schedule=schedule)

    links: dict[str, str] = {}
    rows: list[tuple[str, str, str, str]] = []
    for dossier in match.ordered():
        name = f"{dossier.scan.short_id}.html"
        links[dossier.scan.evidence_id] = name
        (samples / name).write_text(
            with_banner(render_dossier(dossier, embed_images="flagged")), encoding="utf-8"
        )
        leading = next(
            (f.title for f in dossier.findings if f.severity.value != "info"),
            "Nothing flagged against the current rules",
        )
        rows.append((dossier.subject, dossier.priority[0], leading, name))

    (samples / "match.html").write_text(
        with_banner(render_match(match, report_links=links)), encoding="utf-8"
    )
    (samples / "index.html").write_text(samples_index(rows), encoding="utf-8")
    return rows


def with_banner(html: str) -> str:
    return html.replace("<body>", "<body>" + SAMPLE_BANNER, 1)


def samples_index(rows: list[tuple[str, str, str, str]]) -> str:
    cards = "".join(
        f"""<a class="card" href="/samples/{name}">
             <h3>{subject} <span class="chip {'critical' if band == 'P1' else 'high' if band == 'P2' else 'low'}">{band}</span></h3>
             <p>{leading}</p></a>"""
        for subject, band, leading, name in rows
    )
    body = f"""
<main class="wrap">
  <section class="hero">
    <h1>Sample reports</h1>
    <p class="lede">One synthetic match, five submitted archives, each broken in a different
    way. These pages are the tool's real output — the same HTML <code>sami report</code>
    writes to disk — produced by running it over archives from the test fixtures.</p>
    <div class="cta">
      <a class="btn primary" href="/samples/match.html">Open the match view</a>
      <a class="btn" href="/docs/operations.html">How to run it</a>
    </div>
  </section>
  <h2>Per-player dossiers</h2>
  <div class="cards">{cards}</div>
  <section class="panel" style="margin-top:1.5rem">
    <h3 style="margin-top:0">What the fixtures broke</h3>
    <p class="sub">The synthetic builder has one switch per way an archive can be wrong, so
    every analyzer has both a positive and a negative case: an edited capture, a deleted log
    record, a re-zipped archive, a moved system clock, an edited log, a late start, an early
    stop, a session from the wrong day, blank frames, frozen frames, a monitor swap and a
    sub-human click interval.</p>
  </section>
  <footer class="foot">Sample data only. Nothing on these pages is a finding about a real
  person.</footer>
</main>"""
    return page("Sample reports — samireader", body,
                description="Live sample output from samireader, produced from synthetic archives.",
                active="Sample reports")


def landing(rows: list[tuple[str, str, str, str]]) -> str:
    tiers = [
        ("Tier 1", "Integrity &amp; time",
         "Hashes and clocks reconcile, or they do not. Per-file SHA-256 against the hash MOSS "
         "recorded, ZIP structure forensics, seven clocks cross-checked against each other, and "
         "the session placed against the match window. Arithmetic — nearly unarguable."),
        ("Tier 2", "Environment",
         "Remote-access tools, macro suites, VM artefacts, unsigned binaries running from "
         "Downloads, unrecognised Vulkan layers whitelisted into the game process, blank and "
         "frozen captures. Strong, but contextual — and it says so."),
        ("Tier 3", "Behavioural",
         "MOSS draws real input distributions as ASCII art nobody reads. The parser turns them "
         "back into numbers and scores them against the vendor's own published human limits. "
         "Corroborating evidence only, never a conclusion."),
    ]
    cards = "".join(
        f'<div class="card"><div class="tier">{tier}</div><h3>{title}</h3><p>{text}</p></div>'
        for tier, title, text in tiers
    )
    body = f"""
<main class="wrap">
  <section class="hero">
    <h1>The review layer MOSS never shipped.</h1>
    <p class="lede">A league admin gets ten MOSS archives after a match: ~600 screenshots and
    ~5,000 log lines, reviewed by hand, inconsistently, with no record of what was checked.
    samireader reads those archives and produces an evidence dossier — with timestamp
    reconciliation, <em>do the dates match the data?</em>, as the core.</p>
    <div class="cta">
      <a class="btn primary" href="/samples/match.html">See a sample report</a>
      <a class="btn" href="/docs/index.html">Read the docs</a>
      <a class="btn" href="{REPO_URL}">GitHub</a>
    </div>
  </section>

  <section class="panel limitations">
    <h3 style="margin-top:0">It never outputs a verdict</h3>
    <p>MOSS is user-mode software, run by the suspect, on their own hardware, with publicly
    documented bypasses. A tool that prints <em>“CHEATER: 87%”</em> is wrong, unusable as
    evidence, and a liability the first time it is wrong about a named person.</p>
    <p>Every finding carries the raw evidence, the arithmetic that produced it, a confidence
    level, and <b>the benign explanation stated alongside the suspicious one</b>. Two of those
    are enforced in code: a finding with no benign explanation, or no evidence, raises rather
    than rendering.</p>
  </section>

  <h2>Three tiers, in order of how hard they are to argue with</h2>
  <div class="cards">{cards}</div>

  <h2>Getting started</h2>
  <div class="panel">
    <pre class="code"><code>git clone {REPO_URL} &amp;&amp; cd samireader
pip install -e .

sami verify  match/*.zip --schedule match.json     # answer in the terminal, exit code set
sami report  player.zip -o case.html --redacted    # the case document, plus a shareable copy
sami match   match/*.zip --schedule match.json -o out/   # ten players, one coverage grid
sami appeal  player.zip -o appeal/                 # what the accused needs to check the work</code></pre>
    <p class="sub">No dependencies, Python 3.10+. No server, no network, no telemetry — it runs
    offline at a LAN, and the HTML file it writes <em>is</em> the case document.</p>
  </div>

  <h2>What it deliberately does not do</h2>
  <div class="panel">
    <p>No OCR of the taskbar clock — the highest-value thing still missing. No pixel decoding.
    No cross-archive identity graph. No network access of any kind. No Valorant, which needs a
    different evidence model entirely. No Call of Duty support is claimed until real CoD
    archives exist to check against.</p>
    <p class="sub">The test suite runs against synthetic archives reconstructed from the
    documented log grammar, not against real MOSS output — the archives that grounded the
    research are personal data. So it proves conformance to the documented format, not that the
    format is complete. <a href="/docs/index.html#validation">The README says so plainly</a>
    rather than leaving it to be discovered.</p>
  </div>

  <footer class="foot">
    samireader {__version__} · MIT · <a href="{REPO_URL}">source</a> ·
    MOSS archives are personal data; read
    <a href="/docs/operations.html#8-retention-and-privacy">retention and privacy</a> before
    running a season on this.
  </footer>
</main>"""
    return page("samireader — MOSS archive review", body,
                description="Reads MOSS anti-cheat archives and produces a defensible, "
                            "evidence-linked integrity report. Never a verdict.",
                active="Overview")


def main(destination: str = "site", *, verbose: bool = True) -> int:
    out = ROOT / destination
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    work = out / ".build"

    rows = build_samples(out, work, verbose=verbose)
    build_docs(out)
    (out / "index.html").write_text(landing(rows), encoding="utf-8")
    shutil.rmtree(work, ignore_errors=True)

    pages = sorted(p.relative_to(out).as_posix() for p in out.rglob("*.html"))
    if verbose:
        total = sum(p.stat().st_size for p in out.rglob("*"))
        print(f"built {len(pages)} pages into {out} ({total / 1024:.0f} KB)")
        for name in pages:
            print(f"  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
