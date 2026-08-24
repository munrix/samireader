"""Self-contained HTML reports.

One file, no server, no external requests: it opens at a LAN with no network,
attaches to an email, and stays readable in an archive long after this tool is
gone. It is also the case document, so it carries its own provenance — evidence
ID, tool and ruleset versions, rule pack, and the limitations of the evidence
base — rather than relying on a covering note that gets lost.
"""

from __future__ import annotations

import base64
import html
from collections.abc import Iterable
from datetime import datetime, timedelta
from pathlib import Path

from mosslib.timeutil import format_duration, format_offset
from sami.analyzers import ANALYZER_NAMES
from sami.dossier import LIMITATIONS, Dossier, MatchDossier
from sami.findings import Finding, Severity, Tier
from sami.report.theme import CSS
from sami.version import RULESET_VERSION, __version__

MAX_EMBED_BYTES = 8 * 1024 * 1024


def e(value: object) -> str:
    """Escape for HTML text. Everything from an archive goes through here."""
    return html.escape("" if value is None else str(value), quote=True)


def _fmt(value: datetime | None) -> str:
    return value.isoformat(sep=" ") if value else "—"


def _bytes(size: float | None) -> str:
    if size is None:
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


# --------------------------------------------------------------------- pieces


def _chip(text: str, cls: str = "") -> str:
    return f'<span class="chip {cls}">{e(text)}</span>'


def _finding_html(finding: Finding) -> str:
    rows = "".join(
        f"<tr><td class='nowrap'>{e(ev.label)}</td>"
        f"<td class='mono'>{e(ev.value).replace(chr(10), '<br>')}</td>"
        f"<td class='num sub'>{('line ' + str(ev.line)) if ev.line else ''}</td></tr>"
        for ev in finding.evidence
    )
    evidence_block = (
        f"<div class='label'>Evidence</div><div class='scroll'><table>{rows}</table></div>"
        if rows
        else ""
    )
    return f"""
<article class="finding {finding.severity.value}" id="rule-{e(finding.rule)}">
  <h3>{e(finding.title)}</h3>
  <div class="chips">
    {_chip(finding.severity.value, finding.severity.value)}
    {_chip(f"Tier {finding.tier.value} · {finding.tier.label}")}
    {_chip(f"confidence: {finding.confidence.value}")}
    <span class="rule-id">{e(finding.rule)}</span>
  </div>
  <p class="summary">{e(finding.summary)}</p>
  <div class="label">How this was determined</div>
  <p class="detail">{e(finding.detail)}</p>
  <div class="label">If there is an innocent explanation, it is this</div>
  <div class="benign">{e(finding.benign)}</div>
  {evidence_block}
</article>"""


def _flagged_summary(dossier: Dossier) -> str:
    """Everything actionable, in severity order, before the tier-by-tier detail.

    The sections below are grouped by tier because that is the order of
    defensibility. This list exists so an admin sees the whole picture first,
    without having to reconstruct it from three sections.
    """
    actionable = dossier.actionable
    if not actionable:
        return (
            "<p class='sub' style='margin-top:.75rem'>Nothing was flagged against the current "
            "rules. That means nothing was found in what MOSS captured — it is not a finding "
            "of innocence.</p>"
        )
    rows = "".join(
        f"<tr><td class='nowrap'>{_chip(f.severity.value, f.severity.value)}</td>"
        f"<td><a href='#rule-{e(f.rule)}'>{e(f.title)}</a></td>"
        f"<td class='sub'>{e(f.summary)}</td>"
        f"<td class='nowrap sub'>tier {f.tier.value}</td></tr>"
        for f in actionable
    )
    return f"<div class='scroll' style='margin-top:.9rem'><table><tbody>{rows}</tbody></table></div>"


def _limitations_html() -> str:
    items = "".join(f"<li>{e(item)}</li>" for item in LIMITATIONS)
    return f"""
<section class="panel limitations">
  <h3 style="margin-top:0">What this report cannot tell you</h3>
  <ul>{items}</ul>
</section>"""


def _timeline_svg(dossier: Dossier, width: int = 1000, height: int = 96) -> str:
    """Captures across the session, with the match window overlaid if known."""
    session = dossier.session
    times = sorted(session.screenshot_times)
    if len(times) < 2:
        return "<p class='sub'>Not enough timestamped captures to draw a timeline.</p>"

    offset = dossier.clocks.host_offset_minutes
    schedule = dossier.schedule
    start, end = times[0], times[-1]
    if schedule and offset is not None:
        match_start_local = schedule.start_utc + timedelta(minutes=offset)
        match_end_local = schedule.end_utc + timedelta(minutes=offset)
        start = min(start, match_start_local)
        end = max(end, match_end_local)
    span = max((end - start).total_seconds(), 1)

    def x(moment: datetime) -> float:
        return 40 + (moment - start).total_seconds() / span * (width - 60)

    parts = [
        f'<svg class="timeline" viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Capture timeline from {_fmt(times[0])} to {_fmt(times[-1])}">'
    ]

    if schedule and offset is not None:
        ms, me = schedule.start_utc + timedelta(minutes=offset), schedule.end_utc + timedelta(minutes=offset)
        parts.append(
            f'<rect x="{x(ms):.1f}" y="14" width="{max(x(me) - x(ms), 1):.1f}" height="46" '
            f'fill="var(--accent)" opacity="0.10"/>'
            f'<text x="{x(ms):.1f}" y="10" font-size="9" fill="var(--ink-3)">match window</text>'
        )
        for rnd in schedule.rounds:
            rs = rnd.start_utc + timedelta(minutes=offset)
            re_ = (rnd.end_utc or rnd.start_utc) + timedelta(minutes=offset)
            parts.append(
                f'<rect x="{x(rs):.1f}" y="16" width="{max(x(re_) - x(rs), 1.5):.1f}" height="42" '
                f'fill="var(--accent)" opacity="0.14"/>'
            )

    parts.append(
        f'<line x1="40" y1="60" x2="{width - 20}" y2="60" stroke="var(--line-2)" stroke-width="1"/>'
    )
    parts.append(
        f'<rect x="{x(times[0]):.1f}" y="52" width="{max(x(times[-1]) - x(times[0]), 1):.1f}" '
        f'height="16" fill="var(--ok)" opacity="0.22" rx="2"/>'
    )

    max_gap = dossier.rules.number("session.max_screenshot_gap_s", 300)
    for a, b in zip(times, times[1:], strict=False):
        if (b - a).total_seconds() > max_gap:
            parts.append(
                f'<rect x="{x(a):.1f}" y="52" width="{max(x(b) - x(a), 1):.1f}" height="16" '
                f'fill="var(--critical)" opacity="0.30" rx="2"/>'
            )
    for moment in times:
        parts.append(
            f'<line x1="{x(moment):.1f}" y1="50" x2="{x(moment):.1f}" y2="70" '
            f'stroke="var(--ink-2)" stroke-width="1" opacity="0.55"/>'
        )

    parts.append(
        f'<text x="40" y="86" font-size="10" fill="var(--ink-3)">{e(_fmt(start))}</text>'
        f'<text x="{width - 20}" y="86" font-size="10" fill="var(--ink-3)" text-anchor="end">'
        f"{e(_fmt(end))}</text>"
    )
    parts.append("</svg>")
    parts.append(
        '<div class="grid-legend">'
        '<span><span class="swatch" style="background:var(--ok);opacity:.5"></span>recording</span>'
        '<span><span class="swatch" style="background:var(--critical);opacity:.5"></span>capture gap</span>'
        '<span><span class="swatch" style="background:var(--accent);opacity:.35"></span>match window</span>'
        "<span>host local time</span></div>"
    )
    return "".join(parts)


def _clock_table(dossier: Dossier) -> str:
    session, model = dossier.session, dossier.clocks
    rows = [
        ("1 · ZIP filename (UTC)", _fmt(session.archive.name_timestamp), "as written by MOSS"),
        (
            "2 · SHAS2 mode started (MOSS network clock)",
            _fmt(session.header_started_at),
            f"implies {format_offset(model.implied_network_offset_minutes)} from UTC"
            if model.implied_network_offset_minutes is not None
            else "—",
        ),
        ("3 · Monitor Started (host local)", _fmt(session.monitor_started_at), "host wall clock"),
        (
            "4 · First / last capture (host local)",
            f"{_fmt(session.session_start)} → {_fmt(session.session_end)}",
            format_duration(session.duration_s),
        ),
        (
            "5 · ZIP entry timestamps (UTC)",
            f"{len(model.samples)} paired with captures",
            f"median difference {model.host_offset_minutes:+.1f} min"
            if model.host_offset_minutes is not None
            else "—",
        ),
        ("6 · Taskbar clock inside the captures", "not read", "OCR is out of scope in this release"),
        (
            "7 · Derived boot time",
            _fmt(model.boot_time_local),
            f"from {model.uptime_source} uptime {format_duration(model.uptime_seconds)}"
            if model.uptime_source
            else "no uptime process in the statistics table",
        ),
    ]
    body = "".join(
        f"<tr><td>{e(a)}</td><td class='mono'>{e(b)}</td><td class='sub'>{e(c)}</td></tr>"
        for a, b, c in rows
    )
    verdict = (
        f"Host clock measured at <b>{e(format_offset(model.host_offset_minutes))}</b>, "
        f"stable to within {model.offset_spread_minutes:.1f} min across {len(model.samples)} captures."
        if model.resolved
        else "The host's UTC offset could not be measured from this archive."
    )
    return f"""
<div class="panel">
  <p>{verdict}</p>
  <div class="scroll"><table>
    <thead><tr><th>Clock</th><th>Reads</th><th>Cross-check</th></tr></thead>
    <tbody>{body}</tbody>
  </table></div>
</div>"""


def _verification_table(dossier: Dossier) -> str:
    session = dossier.session
    logged: dict[str, str] = {}
    for shot in session.screenshots:
        if shot.crc:
            logged[shot.file] = shot.crc.lower()
    for cap in session.captured_files:
        if cap.crc:
            logged[cap.file] = cap.crc.lower()

    rows = []
    for entry in session.archive.entries:
        base = entry.name.replace("\\", "/").rsplit("/", 1)[-1]
        expected = logged.get(base)
        actual = (entry.sha256 or dossier.scan.member_sha256.get(entry.name, "")).lower()
        if expected is None:
            status, cls = ("not listed in log", "bad") if not base.lower().endswith(".log") else ("log file", "sub")
        elif expected == actual:
            status, cls = "verified", "ok"
        else:
            status, cls = "HASH MISMATCH", "bad"
        rows.append(
            f"<tr class='{'flag' if cls == 'bad' else ''}'>"
            f"<td class='mono'>{e(entry.name)}</td>"
            f"<td class='num'>{_bytes(entry.size)}</td>"
            f"<td class='mono sub'>{e(_fmt(entry.mtime))}</td>"
            f"<td class='hash'>{e(actual[:24])}…</td>"
            f"<td class='{cls}'>{e(status)}</td></tr>"
        )
    return f"""
<div class="tablewrap"><table>
  <thead><tr><th>Member</th><th>Size</th><th>ZIP timestamp (UTC)</th><th>SHA-256</th><th>Against the log</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table></div>"""


def _process_table(dossier: Dossier) -> str:
    session = dossier.session
    if not session.processes:
        return "<p class='sub'>No process snapshot in this archive.</p>"
    flagged_paths = {
        ev.value.split(" — ")[0]
        for finding in dossier.findings
        if "process" in finding.tags
        for ev in finding.evidence
    }
    rows = []
    for process in session.processes:
        flag = process.path in flagged_paths
        rows.append(
            f"<tr class='{'flag' if flag else ''}'>"
            f"<td class='mono'>{e(process.name)}</td>"
            f"<td>{e(process.author) if process.author else '<span class=bad>unsigned</span>'}</td>"
            f"<td class='mono sub'>{e(process.path)}</td>"
            f"<td class='hash'>{e(process.sha256[:16])}…</td></tr>"
        )
    return f"""
<div class="tablewrap"><table>
  <thead><tr><th>Process</th><th>Signed by</th><th>Path</th><th>SHA-256</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table></div>"""


def _histogram_html(dossier: Dossier) -> str:
    histograms = [h for h in dossier.session.histograms if h.buckets]
    if not histograms:
        return "<p class='sub'>No input histograms in this archive.</p>"
    blocks = []
    for hist in histograms:
        peak = max((b.count for b in hist.buckets), default=1) or 1
        bars = "".join(
            f'<div class="bar" style="height:{max(b.count / peak * 100, 2):.0f}%" '
            f'title="{e(f"{b.lower:.0f} {hist.unit}: {b.count} events")}"></div>'
            for b in hist.buckets
        )
        blocks.append(
            f"""<div class="hist">
  <div class="sub"><b>{e(hist.label)}</b> — {e(hist.total_events or '?')} events,
    {e(hist.reconstruction)} reconstruction, log line {e(hist.line)}</div>
  <div class="bars">{bars}</div>
  <div class="axis"><span>{e(f"{hist.buckets[0].lower:.0f}")}</span>
    <span>{e(hist.unit)}</span>
    <span>{e(f"{hist.buckets[-1].lower:.0f}")}</span></div>
</div>"""
        )
    return "".join(blocks)


def _contact_sheet(dossier: Dossier, mode: str) -> str:
    """Embed captures as data URIs. The archive is opened once, not once per frame."""
    if mode == "none":
        return ""
    flagged = {
        ev.member
        for finding in dossier.findings
        if finding.severity is not Severity.INFO
        for ev in finding.evidence
        if ev.member and ev.member.lower().endswith((".jpg", ".jpeg"))
    }
    names = sorted(dossier.scan.jpegs)
    chosen = [n for n in names if n in flagged] if mode == "flagged" else names
    if not chosen:
        return "<p class='sub'>No captures flagged for review.</p>" if mode == "flagged" else ""

    from mosslib.archive import ArchiveError, open_archive

    figures: list[str] = []
    budget = MAX_EMBED_BYTES
    skipped = 0
    try:
        with open_archive(dossier.scan.path) as archive:
            for name in chosen:
                info = dossier.scan.jpegs.get(name)
                if info and info.size > budget:
                    skipped += 1
                    continue
                try:
                    raw = archive.read(name)
                except (ArchiveError, KeyError, OSError):
                    skipped += 1
                    continue
                budget -= len(raw)
                encoded = base64.b64encode(raw).decode("ascii")
                figures.append(
                    f"<figure class='{'flagged' if name in flagged else ''}'>"
                    f"<img src='data:image/jpeg;base64,{encoded}' alt='capture {e(name)}' loading='lazy'>"
                    f"<figcaption>{e(name)} · {_bytes(len(raw))}</figcaption></figure>"
                )
    except (ArchiveError, OSError):
        return (
            "<p class='sub'>Captures could not be embedded: the archive is no longer readable "
            "at the path it was ingested from.</p>"
        )

    note = (
        f"<p class='sub'>{skipped} capture(s) omitted to keep the report under "
        f"{_bytes(MAX_EMBED_BYTES)}.</p>"
        if skipped
        else ""
    )
    return f"<div class='contact'>{''.join(figures)}</div>{note}"


def _appendix(dossier: Dossier) -> str:
    session = dossier.session
    unknown = session.unknown_lines
    unknown_rows = "".join(
        f"<tr><td class='num sub'>{line.number}</td><td class='mono'>{e(line.raw)}</td></tr>"
        for line in unknown[:400]
    )
    warning_rows = "".join(
        f"<tr><td class='num sub'>{w.line or ''}</td><td class='mono'>{e(w.code)}</td>"
        f"<td>{e(w.message)}</td></tr>"
        for w in session.warnings
    )
    configs = "".join(
        f"<details><summary>{e(name)}</summary><pre class='mono scroll'>{e(text[:20000])}</pre></details>"
        for name, text in sorted(dossier.scan.configs.items())
    )
    return f"""
<h2>Appendix</h2>
<details>
  <summary>Unrecognised log lines ({len(unknown)})</summary>
  <p class="sub">Kept, never dropped. MOSS's format is undocumented and drifts between
  versions; a rule that stops firing because a field was renamed shows up here first.</p>
  <div class="tablewrap"><table><tbody>{unknown_rows or "<tr><td class='sub'>None.</td></tr>"}</tbody></table></div>
</details>
<details>
  <summary>Parser warnings ({len(session.warnings)})</summary>
  <div class="tablewrap"><table><tbody>{warning_rows or "<tr><td class='sub'>None.</td></tr>"}</tbody></table></div>
</details>
<details>
  <summary>Captured game configuration ({len(dossier.scan.configs)})</summary>
  {configs or "<p class='sub'>No configs captured.</p>"}
</details>
<details>
  <summary>Host inventory</summary>
  {_inventory_html(dossier)}
</details>
<details>
  <summary>Process snapshot ({len(session.processes)})</summary>
  {_process_table(dossier)}
</details>
<details>
  <summary>How this report was produced</summary>
  <dl class="kv">
    <dt>Tool</dt><dd>samireader {e(__version__)} (ruleset {e(RULESET_VERSION)}, grammar {e(session.grammar_version)})</dd>
    <dt>Rule pack</dt><dd>{e(dossier.rules.describe())}</dd>
    <dt>Analyzers</dt><dd class="mono">{e(', '.join(ANALYZER_NAMES))}</dd>
    <dt>Tiers analysed</dt><dd>1–{e(dossier.max_tier)}</dd>
    <dt>Evidence ID (SHA-256 of the submitted file)</dt><dd class="hash">{e(dossier.scan.evidence_id)}</dd>
    <dt>Ingested</dt><dd>{e(dossier.scan.ingested_at.isoformat())}</dd>
    <dt>Log SHA-256</dt><dd class="hash">{e(session.log_sha256 or '—')}</dd>
    <dt>Global log CRC (algorithm unconfirmed)</dt><dd class="hash">{e(session.global_log_crc or '—')}</dd>
  </dl>
</details>"""


def _inventory_html(dossier: Dossier) -> str:
    hw = dossier.session.hardware
    rows = [
        ("MOSS version", dossier.session.moss_version),
        ("Game (header)", dossier.session.game),
        ("User @ host", f"{hw.user or '—'} @ {hw.hostname or '—'}"),
        ("Sign ID1 (weak — collides between machines)", hw.sign_id1),
        ("Motherboard", hw.physical),
        ("Processor", hw.processor),
        ("Memory", f"{hw.memory_mb} MB" if hw.memory_mb else None),
        ("Video", "; ".join(f"{d.description} (driver {d.driver})" for d in hw.video)),
        ("Monitors", "; ".join(f"{m.description} serial {m.serial}" for m in hw.monitors)),
        ("Drives", "; ".join(f"{d.description} serial {d.serial}" for d in hw.drives)),
        ("Network", f"LAN {hw.lan_ip or '—'} · public {hw.public_ip or '—'}"),
        ("OS", f"{hw.os_version or '—'} · real OS {hw.real_os or '—'}"),
        ("Windows Defender", hw.windows_defender),
        ("SteamId", hw.steam_id),
        ("USB devices", "; ".join(d.description for d in hw.usb)),
    ]
    body = "".join(
        f"<dt>{e(label)}</dt><dd>{e(value) if value else '<span class=sub>—</span>'}</dd>"
        for label, value in rows
    )
    return f'<dl class="kv">{body}</dl>'


def _findings_section(dossier: Dossier) -> str:
    blocks = []
    for tier in (Tier.INTEGRITY, Tier.ENVIRONMENT, Tier.BEHAVIOURAL):
        items = dossier.by_tier(tier)
        if not items:
            continue
        actionable = [f for f in items if f.severity is not Severity.INFO]
        notes = [f for f in items if f.severity is Severity.INFO]
        blocks.append(f"<h2>Tier {tier.value} — {e(tier.label)}</h2>")
        blocks.extend(_finding_html(f) for f in actionable)
        if notes:
            blocks.append(
                f"<details><summary>Context and limitations ({len(notes)})</summary>"
                + "".join(_finding_html(f) for f in notes)
                + "</details>"
            )
    return "".join(blocks) or "<p class='sub'>No findings.</p>"


def _document(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="samireader {e(__version__)}">
<title>{e(title)}</title>
<style>{CSS}</style>
</head>
<body>
{body}
</body>
</html>
"""


# ---------------------------------------------------------------- entry points


def render_dossier(dossier: Dossier, *, embed_images: str = "flagged", redacted: bool = False) -> str:
    """Render one archive's dossier as a complete HTML document."""
    session = dossier.session
    band, meaning = dossier.priority
    counts = dossier.counts
    chips = "".join(
        _chip(f"{count} {name}", name)
        for name, count in counts.items()
        if count
    ) or _chip("no findings", "info")

    title = f"MOSS review — {dossier.subject}"
    schedule_line = (
        f"<dt>Match</dt><dd>{e(dossier.schedule.match_id)} · "
        f"{e(_fmt(dossier.schedule.start_utc))} → {e(_fmt(dossier.schedule.end_utc))} UTC</dd>"
        if dossier.schedule
        else ""
    )
    redaction_banner = (
        '<section class="panel flat"><b>Redacted copy.</b> Usernames, hostnames, serial '
        "numbers, addresses and account IDs have been replaced with stable pseudonyms. The same "
        "token means the same value throughout, and across other reports produced with the same "
        "case salt. The salt is held with the case record, not in this file.</section>"
        if redacted
        else ""
    )
    version_warning = (
        '<section class="panel flat"><b>Unverified MOSS version.</b> This archive was written by '
        f"MOSS {e(session.moss_version)}, which is outside the set the log grammar was built "
        "against. Parsing is tolerant, but unrecognised lines in the appendix deserve a look "
        "before relying on any finding here.</section>"
        if dossier.unknown_moss_version
        else ""
    )

    body = f"""
<header class="masthead"><div class="wrap">
  <h1>{e(title)}</h1>
  <div class="sub">{e(session.archive.filename or dossier.scan.path.name)} · evidence ID
    <span class="hash">{e(dossier.scan.short_id)}</span></div>
  <div class="meta">
    <span><b>{e(session.game or 'unknown game')}</b> · MOSS {e(session.moss_version or '?')}</span>
    <span>{e(len(session.screenshots))} captures</span>
    <span>{e(format_duration(session.duration_s))} recorded</span>
    <span>generated {e(dossier.generated_at.isoformat())}</span>
  </div>
</div></header>
<main class="wrap">
  {redaction_banner}
  {version_warning}
  <section class="panel">
    <div class="priority">
      <span class="band {e(band)}">{e(band)}</span>
      <div>
        <div><b>{e(meaning)}</b></div>
        <div class="counts">{chips}</div>
      </div>
    </div>
    <p class="sub" style="margin-top:.75rem">This is a review queue position, not a score and not
    a conclusion. Findings are ordered by how hard they are to argue with: hashes and clocks
    first, environment second, input statistics last.</p>
    {_flagged_summary(dossier)}
  </section>

  {_limitations_html()}

  <h2>Session</h2>
  <div class="panel">
    <dl class="kv">
      <dt>Subject</dt><dd>{e(dossier.subject)}</dd>
      {schedule_line}
      <dt>Recording (host local)</dt><dd>{e(_fmt(session.session_start))} → {e(_fmt(session.session_end))}</dd>
      <dt>Host clock</dt><dd>{e(format_offset(dossier.clocks.host_offset_minutes))}
        (measured from this archive)</dd>
      <dt>Session in UTC</dt><dd>{e(_fmt(dossier.clocks.session_start_utc))} →
        {e(_fmt(dossier.clocks.session_end_utc))}</dd>
      <dt>Game detected by MOSS</dt><dd>{'yes' if session.game_detected else 'no'}</dd>
    </dl>
    {_timeline_svg(dossier)}
  </div>

  {_findings_section(dossier)}

  <h2>Clock reconciliation</h2>
  {_clock_table(dossier)}

  <h2>Archive verification</h2>
  <p class="sub">Every member re-hashed and compared with the <code>Zip CRC:</code> value MOSS
  wrote in the log.</p>
  {_verification_table(dossier)}

  <h2>Input histograms</h2>
  <p class="sub">MOSS's ASCII drawings, reconstructed into numbers. Tier 3 corroborates; it never
  concludes.</p>
  <div class="panel">{_histogram_html(dossier)}</div>

  {_contact_sheet_section(dossier, embed_images)}

  {_appendix(dossier)}

  <footer class="foot">
    Produced by samireader {e(__version__)} · rule pack {e(dossier.rules.describe())} ·
    evidence ID <span class="hash">{e(dossier.scan.evidence_id)}</span><br>
    Every finding above is evidence for a human decision. This tool does not decide.
  </footer>
</main>"""
    return _document(title, body)


def _contact_sheet_section(dossier: Dossier, mode: str) -> str:
    sheet = _contact_sheet(dossier, mode)
    if not sheet:
        return ""
    label = "Flagged captures" if mode == "flagged" else "Contact sheet"
    return f"<h2>{e(label)}</h2><div class='panel'>{sheet}</div>"


def _coverage_grid(match: MatchDossier, width: int = 1000) -> str:
    """The single highest-value screen in the product: ten players, one glance."""
    schedule = match.schedule
    dossiers = match.ordered()
    if not dossiers:
        return "<p class='sub'>No archives.</p>"

    spans: list[tuple[Dossier, datetime | None, datetime | None]] = [
        (d, d.clocks.session_start_utc, d.clocks.session_end_utc) for d in dossiers
    ]
    bounds = [t for _d, a, b in spans for t in (a, b) if t]
    if schedule:
        bounds += [schedule.start_utc, schedule.end_utc]
    if not bounds:
        return "<p class='sub'>No archive could be placed on an absolute timeline.</p>"
    start, end = min(bounds), max(bounds)
    span = max((end - start).total_seconds(), 1)
    row_h, top = 26, 34
    height = top + row_h * (len(spans) + len(match.missing_players)) + 24
    label_w = 180

    def x(moment: datetime) -> float:
        return label_w + (moment - start).total_seconds() / span * (width - label_w - 24)

    parts = [f'<svg class="timeline" viewBox="0 0 {width} {height}" role="img" aria-label="Team coverage grid">']
    if schedule:
        parts.append(
            f'<rect x="{x(schedule.start_utc):.1f}" y="18" '
            f'width="{max(x(schedule.end_utc) - x(schedule.start_utc), 1):.1f}" '
            f'height="{height - 34:.0f}" fill="var(--accent)" opacity="0.08"/>'
            f'<text x="{x(schedule.start_utc):.1f}" y="13" font-size="10" fill="var(--ink-3)">'
            f"{e(schedule.match_id)} · {e(_fmt(schedule.start_utc))} → {e(_fmt(schedule.end_utc))} UTC</text>"
        )
        for rnd in schedule.rounds:
            rs = rnd.start_utc
            re_ = rnd.end_utc or rnd.start_utc
            parts.append(
                f'<rect x="{x(rs):.1f}" y="18" width="{max(x(re_) - x(rs), 1.5):.1f}" '
                f'height="{height - 34:.0f}" fill="var(--accent)" opacity="0.10"/>'
            )

    for index, (dossier, first, last) in enumerate(spans):
        y = top + index * row_h
        colour = {"P1": "var(--critical)", "P2": "var(--high)", "P3": "var(--low)"}.get(
            dossier.priority[0], "var(--ok)"
        )
        team = f" ({dossier.entry.team})" if dossier.entry and dossier.entry.team else ""
        parts.append(
            f'<text x="4" y="{y + 13}" font-size="11" fill="var(--ink)">'
            f"{e((dossier.subject + team)[:30])}</text>"
        )
        if first and last:
            parts.append(
                f'<rect x="{x(first):.1f}" y="{y + 4}" width="{max(x(last) - x(first), 2):.1f}" '
                f'height="14" fill="{colour}" opacity="0.55" rx="3"/>'
            )
            if schedule:
                if first > schedule.start_utc:
                    parts.append(
                        f'<rect x="{x(schedule.start_utc):.1f}" y="{y + 4}" '
                        f'width="{max(x(first) - x(schedule.start_utc), 1):.1f}" height="14" '
                        f'fill="var(--critical)" opacity="0.25" rx="3"/>'
                    )
                if last < schedule.end_utc:
                    parts.append(
                        f'<rect x="{x(last):.1f}" y="{y + 4}" '
                        f'width="{max(x(schedule.end_utc) - x(last), 1):.1f}" height="14" '
                        f'fill="var(--critical)" opacity="0.25" rx="3"/>'
                    )
        else:
            parts.append(
                f'<text x="{label_w}" y="{y + 15}" font-size="10" fill="var(--ink-3)">'
                "no absolute timeline (host offset unmeasurable)</text>"
            )

    for offset, player in enumerate(match.missing_players):
        y = top + (len(spans) + offset) * row_h
        parts.append(
            f'<text x="4" y="{y + 13}" font-size="11" fill="var(--critical)">'
            f"{e(player.name)}{e(' (' + player.team + ')' if player.team else '')}</text>"
            f'<text x="{label_w}" y="{y + 13}" font-size="10" fill="var(--critical)">'
            "no archive submitted</text>"
        )

    parts.append("</svg>")
    parts.append(
        '<div class="grid-legend">'
        '<span><span class="swatch" style="background:var(--ok);opacity:.6"></span>covered</span>'
        '<span><span class="swatch" style="background:var(--critical);opacity:.4"></span>match time not covered</span>'
        '<span><span class="swatch" style="background:var(--accent);opacity:.3"></span>match window / rounds</span>'
        "<span>all times UTC</span></div>"
    )
    return "".join(parts)


def render_match(
    match: MatchDossier,
    *,
    report_links: dict[str, str] | None = None,
    redacted: bool = False,
) -> str:
    """Render the per-match view: coverage grid first, then the review queue."""
    links = report_links or {}
    schedule = match.schedule
    title = f"MOSS review — {schedule.match_id}" if schedule else "MOSS review — match"

    rows = []
    for dossier in match.ordered():
        counts = dossier.counts
        link = links.get(dossier.scan.evidence_id)
        name = (
            f"<a href='{e(link)}'>{e(dossier.subject)}</a>" if link else e(dossier.subject)
        )
        top = next(
            (f for f in dossier.findings if f.severity is not Severity.INFO), None
        )
        rows.append(
            f"<tr class='player-row'><td>{name}</td>"
            f"<td>{e(dossier.entry.team if dossier.entry and dossier.entry.team else '—')}</td>"
            f"<td><span class='chip {'critical' if dossier.priority[0] == 'P1' else 'high' if dossier.priority[0] == 'P2' else 'low'}'>"
            f"{e(dossier.priority[0])}</span></td>"
            f"<td class='num'>{counts['critical'] + counts['high']}</td>"
            f"<td class='num'>{counts['medium'] + counts['low']}</td>"
            f"<td>{e(top.title) if top else '<span class=sub>nothing flagged</span>'}</td>"
            f"<td class='hash'>{e(dossier.scan.short_id)}</td></tr>"
        )

    missing_note = (
        f"<section class='panel'><b class='bad'>{len(match.missing_players)} scheduled player(s) "
        "submitted no archive:</b> "
        + e(", ".join(p.name for p in match.missing_players))
        + "</section>"
        if match.missing_players
        else ""
    )
    redaction_banner = (
        '<section class="panel flat"><b>Redacted copy.</b> Identifiers replaced with stable '
        "pseudonyms; the case salt is held with the case record.</section>"
        if redacted
        else ""
    )

    body = f"""
<header class="masthead"><div class="wrap">
  <h1>{e(title)}</h1>
  <div class="sub">{e(len(match.dossiers))} archive(s) ·
    generated {e(match.generated_at.isoformat())}</div>
</div></header>
<main class="wrap">
  {redaction_banner}
  {missing_note}
  <h2>Coverage</h2>
  <div class="panel">
    <p class="sub" style="margin-top:0">Did everyone actually record this match? Each bar is one
    player's session placed on an absolute timeline, converted to UTC using the clock offset
    measured from that player's own archive.</p>
    {_coverage_grid(match)}
  </div>

  <h2>Review queue</h2>
  <div class="panel">
    <div class="scroll"><table>
      <thead><tr><th>Player</th><th>Team</th><th>Priority</th><th class="num">Critical/high</th>
        <th class="num">Medium/low</th><th>Leading finding</th><th>Evidence ID</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table></div>
  </div>

  {_limitations_html()}

  <footer class="foot">
    Produced by samireader {e(__version__)} · ordering is a review queue, not a ranking of
    suspicion. Every archive still needs a human.
  </footer>
</main>"""
    return _document(title, body)


def write_report(path: str | Path, content: str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def iter_flagged_members(dossier: Dossier) -> Iterable[str]:
    for finding in dossier.findings:
        for ev in finding.evidence:
            if ev.member:
                yield ev.member
