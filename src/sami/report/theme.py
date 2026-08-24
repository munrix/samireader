"""Report styling, inlined into every HTML file.

Self-contained by requirement: these reports are opened offline at LAN events,
emailed, and archived as evidence years after the tool that made them. Nothing
may be fetched at open time.
"""

CSS = """
:root {
  color-scheme: light dark;
  --bg: #f6f7f9;
  --panel: #ffffff;
  --panel-2: #fbfbfd;
  --ink: #14161a;
  --ink-2: #4a5059;
  --ink-3: #6b7280;
  --line: #e2e5ea;
  --line-2: #cfd4dc;
  --accent: #1f4ed8;
  --critical: #b3261e;
  --high: #b45309;
  --medium: #8a6d12;
  --low: #4b5563;
  --info: #2f5bd0;
  --ok: #14713d;
  --benign-bg: #f0f7f2;
  --benign-line: #bcdcc8;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #101216;
    --panel: #171a20;
    --panel-2: #1c2027;
    --ink: #e8eaee;
    --ink-2: #b3b9c4;
    --ink-3: #8b94a3;
    --line: #262b34;
    --line-2: #333a45;
    --accent: #7aa2ff;
    --critical: #ff7a70;
    --high: #eaa15a;
    --medium: #d7bd63;
    --low: #9aa4b2;
    --info: #7aa2ff;
    --ok: #6cc48d;
    --benign-bg: #16211a;
    --benign-line: #2c4634;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0 0 6rem;
  background: var(--bg); color: var(--ink);
  font-family: var(--sans);
  font-size: 15px; line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 0 1.25rem; }
header.masthead {
  background: var(--panel); border-bottom: 1px solid var(--line);
  padding: 1.75rem 0 1.5rem; margin-bottom: 1.5rem;
}
h1 { font-size: 1.5rem; margin: 0 0 .35rem; letter-spacing: -.01em; }
h2 {
  font-size: 1.05rem; margin: 2.25rem 0 .75rem; letter-spacing: .02em;
  text-transform: uppercase; color: var(--ink-2);
}
h3 { font-size: 1rem; margin: 1.25rem 0 .5rem; }
p { margin: .5rem 0; }
a { color: var(--accent); }
code, .mono { font-family: var(--mono); font-size: .86em; }
.sub { color: var(--ink-3); font-size: .9rem; }
.meta { display: flex; flex-wrap: wrap; gap: .35rem 1.5rem; margin-top: .75rem; font-size: .85rem; color: var(--ink-2); }
.meta b { color: var(--ink); font-weight: 600; }

.panel {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 10px; padding: 1rem 1.15rem; margin: .75rem 0;
}
.panel.flat { background: var(--panel-2); }

.priority { display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; }
.priority .band {
  font-family: var(--mono); font-size: 1.6rem; font-weight: 700;
  padding: .35rem .75rem; border-radius: 8px; border: 2px solid currentColor;
}
.band.P1 { color: var(--critical); }
.band.P2 { color: var(--high); }
.band.P3 { color: var(--low); }
.band.P4 { color: var(--ok); }

.counts { display: flex; gap: .4rem; flex-wrap: wrap; margin-top: .6rem; }
.chip {
  display: inline-flex; align-items: center; gap: .35rem;
  border: 1px solid var(--line-2); border-radius: 999px;
  padding: .1rem .6rem; font-size: .78rem; color: var(--ink-2);
  background: var(--panel-2); white-space: nowrap;
}
.chip b { color: var(--ink); }
.chip.critical { color: var(--critical); border-color: currentColor; }
.chip.high { color: var(--high); border-color: currentColor; }
.chip.medium { color: var(--medium); border-color: currentColor; }
.chip.low { color: var(--low); }
.chip.info { color: var(--info); }

.finding {
  background: var(--panel); border: 1px solid var(--line);
  border-left: 4px solid var(--low); border-radius: 8px;
  padding: .9rem 1.1rem; margin: .6rem 0;
}
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.finding.info { border-left-color: var(--info); }
.finding h3 { margin: 0 0 .25rem; font-size: 1.02rem; }
.finding .chips { display: flex; gap: .35rem; flex-wrap: wrap; margin: .4rem 0 .6rem; }
.finding .summary { font-weight: 500; }
.finding .label {
  font-size: .72rem; text-transform: uppercase; letter-spacing: .06em;
  color: var(--ink-3); margin-top: .8rem; font-weight: 600;
}
.finding .detail { color: var(--ink-2); }
.benign {
  background: var(--benign-bg); border: 1px solid var(--benign-line);
  border-radius: 6px; padding: .55rem .75rem; margin-top: .35rem; color: var(--ink-2);
}
.rule-id { font-family: var(--mono); font-size: .75rem; color: var(--ink-3); }

table { border-collapse: collapse; width: 100%; font-size: .86rem; }
th, td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--ink-3); font-weight: 600; font-size: .74rem; text-transform: uppercase; letter-spacing: .04em; }
tbody tr:hover { background: var(--panel-2); }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
tr.flag td { background: color-mix(in srgb, var(--critical) 8%, transparent); }
.scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
.tablewrap { max-height: 26rem; overflow: auto; border: 1px solid var(--line); border-radius: 8px; }
.tablewrap table { font-size: .8rem; }
.tablewrap th { position: sticky; top: 0; background: var(--panel); z-index: 1; }

.kv { display: grid; grid-template-columns: minmax(11rem, auto) 1fr; gap: .25rem 1rem; font-size: .88rem; }
.kv dt { color: var(--ink-3); }
.kv dd { margin: 0; }

details { margin: .5rem 0; }
details > summary {
  cursor: pointer; font-weight: 600; color: var(--ink-2);
  padding: .4rem 0; list-style: none;
}
details > summary::-webkit-details-marker { display: none; }
details > summary::before { content: "▸ "; color: var(--ink-3); }
details[open] > summary::before { content: "▾ "; }

.timeline { width: 100%; height: auto; display: block; }
.limitations { border-left: 4px solid var(--accent); }
.limitations ul { margin: .4rem 0 0; padding-left: 1.1rem; color: var(--ink-2); }
.limitations li { margin: .25rem 0; }

.grid-legend { display: flex; gap: 1rem; flex-wrap: wrap; font-size: .8rem; color: var(--ink-3); margin-top: .5rem; }
.swatch { display: inline-block; width: .8rem; height: .8rem; border-radius: 2px; vertical-align: -1px; margin-right: .3rem; }

.contact { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: .5rem; }
.contact figure { margin: 0; background: var(--panel-2); border: 1px solid var(--line); border-radius: 6px; padding: .35rem; }
.contact figure.flagged { border-color: var(--critical); }
.contact img { width: 100%; height: auto; display: block; border-radius: 3px; background: #000; }
.contact figcaption { font-size: .72rem; color: var(--ink-3); margin-top: .25rem; font-family: var(--mono); }

.hist { margin: .75rem 0; }
.hist .bars { display: flex; align-items: flex-end; gap: 1px; height: 90px; border-bottom: 1px solid var(--line-2); }
.hist .bar { flex: 1 1 auto; background: var(--accent); min-height: 1px; opacity: .85; }
.hist .axis { display: flex; justify-content: space-between; font-size: .7rem; color: var(--ink-3); font-family: var(--mono); }

footer.foot { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line); color: var(--ink-3); font-size: .8rem; }

.player-row td:first-child { font-weight: 600; }
.nowrap { white-space: nowrap; }
.hash { font-family: var(--mono); font-size: .74rem; color: var(--ink-3); word-break: break-all; }
.ok { color: var(--ok); }
.bad { color: var(--critical); font-weight: 600; }

@media print {
  body { background: #fff; font-size: 11pt; }
  .panel, .finding { break-inside: avoid; border-color: #ccc; }
  details { break-inside: avoid; }
  details:not([open]) > summary::after { content: " (collapsed in this printout)"; color: #888; font-weight: normal; }
  .tablewrap { max-height: none; overflow: visible; }
  header.masthead { border-bottom: 2px solid #000; }
}
"""
