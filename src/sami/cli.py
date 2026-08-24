"""``sami`` — the command line.

CLI-first is the honest MVP (DECISIONS D4): it works offline at a LAN with no
infrastructure, and the HTML file it produces *is* the case document. Five
verbs:

``sami verify``   integrity and clocks, printed to the terminal, exit code set
``sami report``   the full dossier as a self-contained HTML file
``sami match``    every player in one match, coverage grid first
``sami parse``    the parsed session as JSON, for anything downstream
``sami appeal``   the packet the accused needs to check the work (D1)
``sami custody``  read and re-verify a chain-of-custody log
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from mosslib.archive import ArchiveError
from mosslib.timeutil import format_duration, format_offset
from sami.appeal import write_packet
from sami.dossier import Dossier, MatchDossier, analyze_scan
from sami.findings import Severity
from sami.ingest import CustodyLog, default_actor, scan_archive
from sami.redact import Redactor, new_salt
from sami.report.html import render_dossier, render_match, write_report
from sami.rules import RuleError, RulePack
from sami.schedule import ScheduleError, load_schedule
from sami.version import __version__

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


# ----------------------------------------------------------------- formatting


def _use_colour(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


class Out:
    """Terminal output that stays readable when piped to a file."""

    COLOURS = {
        "critical": "\033[1;31m",
        "high": "\033[31m",
        "medium": "\033[33m",
        "low": "\033[36m",
        "info": "\033[90m",
        "ok": "\033[32m",
        "bold": "\033[1m",
        "dim": "\033[90m",
    }

    def __init__(self, stream=None, colour: bool | None = None):
        # Resolved per instance, not bound at import: tests and callers redirect
        # stdout, and a default argument would capture the original stream.
        self.stream = stream if stream is not None else sys.stdout
        self.colour = _use_colour(self.stream) if colour is None else colour

    def paint(self, text: str, style: str) -> str:
        if not self.colour or style not in self.COLOURS:
            return text
        return f"{self.COLOURS[style]}{text}\033[0m"

    def line(self, text: str = "") -> None:
        print(text, file=self.stream)


def _print_dossier(out: Out, dossier: Dossier, *, verbose: bool) -> None:
    session = dossier.session
    band, meaning = dossier.priority
    out.line()
    out.line(out.paint(f"{dossier.subject}", "bold") + f"  ({session.archive.filename})")
    out.line(f"  evidence {dossier.scan.short_id}  ·  MOSS {session.moss_version or '?'}"
             f"  ·  {session.game or 'unknown game'}")
    out.line(
        f"  session {session.session_start} → {session.session_end}"
        f"  ({format_duration(session.duration_s)}, {len(session.screenshots)} captures)"
    )
    out.line(
        f"  host clock {format_offset(dossier.clocks.host_offset_minutes)}"
        + (
            f"  ·  UTC {dossier.clocks.session_start_utc} → {dossier.clocks.session_end_utc}"
            if dossier.clocks.session_start_utc
            else "  ·  offset unmeasurable"
        )
    )
    band_style = {"P1": "critical", "P2": "high", "P3": "low"}.get(band, "ok")
    out.line(f"  {out.paint(band, band_style)}  {meaning}")
    out.line()

    shown = dossier.findings if verbose else dossier.actionable
    if not shown:
        out.line(out.paint("  nothing flagged against the current rules", "ok"))
    for finding in shown:
        marker = out.paint(f"[{finding.severity.value:>8}]", finding.severity.value)
        out.line(f"  {marker} {finding.title}")
        out.line(f"             {finding.summary}")
        out.line(out.paint(f"             tier {finding.tier.value} · {finding.confidence.value}"
                           f" confidence · {finding.rule}", "dim"))
        if verbose:
            out.line(out.paint(f"             benign: {finding.benign}", "dim"))
    out.line()
    counts = dossier.counts
    out.line("  " + "  ".join(
        out.paint(f"{counts[name]} {name}", name) for name in SEVERITY_ORDER if counts[name]
    ) or "  no findings")


# --------------------------------------------------------------------- shared


def _load_rules(args: argparse.Namespace) -> RulePack:
    return RulePack.load(getattr(args, "rules", None))


def _load_schedule(args: argparse.Namespace):
    path = getattr(args, "schedule", None)
    return load_schedule(path) if path else None


def _custody(args: argparse.Namespace) -> CustodyLog | None:
    path = getattr(args, "custody", None)
    return CustodyLog(path) if path else None


def _scan_all(paths: Sequence[str], rules: RulePack, out: Out) -> list:
    scans = []
    for raw in paths:
        path = Path(raw)
        try:
            scans.append(
                scan_archive(path, config_prefixes=rules.strings("integrity.config_prefixes") or None)
            )
        except ArchiveError as exc:
            out.line(out.paint(f"  !! {path.name}: {exc}", "critical"))
    return scans


def _threshold(name: str) -> int:
    return Severity(name).rank


def _exit_code(dossiers: list[Dossier], fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    limit = _threshold(fail_on)
    worst = max((d.worst().rank for d in dossiers), default=0)
    return EXIT_FINDINGS if worst >= limit else EXIT_OK


# ------------------------------------------------------------------- commands


def cmd_verify(args: argparse.Namespace) -> int:
    out = Out(colour=None if not args.no_colour else False)
    rules = _load_rules(args)
    schedule = _load_schedule(args)
    custody = _custody(args)
    scans = _scan_all(args.archives, rules, out)
    if not scans:
        return EXIT_ERROR

    dossiers = []
    for scan in scans:
        dossier = analyze_scan(scan, rules, schedule=schedule, peers=scans, max_tier=args.max_tier)
        dossiers.append(dossier)
        _print_dossier(out, dossier, verbose=args.verbose)
        if custody:
            custody.append(
                "verify",
                evidence_id=scan.evidence_id,
                actor=args.actor,
                details={
                    "filename": scan.session.archive.filename,
                    "priority": dossier.priority[0],
                    "counts": dossier.counts,
                    "rule_pack": rules.describe(),
                },
            )
    if args.json:
        payload = [d.to_json() for d in dossiers]
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        out.line(f"\nJSON written to {args.json}")
    return _exit_code(dossiers, args.fail_on)


def cmd_report(args: argparse.Namespace) -> int:
    out = Out(colour=None if not args.no_colour else False)
    rules = _load_rules(args)
    schedule = _load_schedule(args)
    custody = _custody(args)
    scans = _scan_all(args.archives, rules, out)
    if not scans:
        return EXIT_ERROR

    output = Path(args.output)
    multiple = len(scans) > 1
    if multiple:
        output.mkdir(parents=True, exist_ok=True)

    dossiers = []
    salt = args.salt or new_salt()
    for scan in scans:
        dossier = analyze_scan(scan, rules, schedule=schedule, peers=scans, max_tier=args.max_tier)
        dossiers.append(dossier)
        target = (
            output / f"{scan.short_id}-{Path(scan.session.archive.filename).stem}.html"
            if multiple
            else output
        )
        write_report(target, render_dossier(dossier, embed_images=args.embed_images))
        out.line(f"{dossier.priority[0]}  {dossier.subject:<28}  {target}")

        if args.redacted:
            redacted_path = target.with_name(target.stem + ".redacted.html")
            redacted = Redactor(salt=salt).dossier(dossier)
            write_report(
                redacted_path,
                render_dossier(redacted, embed_images="none", redacted=True),
            )
            out.line(f"     redacted copy           {redacted_path}")

        if custody:
            custody.append(
                "report",
                evidence_id=scan.evidence_id,
                actor=args.actor,
                details={
                    "report": str(target),
                    "redacted": bool(args.redacted),
                    "case_salt": salt if args.redacted else None,
                    "priority": dossier.priority[0],
                    "rule_pack": rules.describe(),
                },
            )

    if args.json:
        Path(args.json).write_text(
            json.dumps([d.to_json() for d in dossiers], indent=2), encoding="utf-8"
        )
        out.line(f"JSON written to {args.json}")
    return _exit_code(dossiers, args.fail_on)


def cmd_match(args: argparse.Namespace) -> int:
    out = Out(colour=None if not args.no_colour else False)
    rules = _load_rules(args)
    schedule = _load_schedule(args)
    custody = _custody(args)
    scans = _scan_all(args.archives, rules, out)
    if not scans:
        return EXIT_ERROR

    dossiers = [
        analyze_scan(scan, rules, schedule=schedule, peers=scans, max_tier=args.max_tier)
        for scan in scans
    ]
    match = MatchDossier(dossiers=dossiers, schedule=schedule)

    output = Path(args.output)
    directory = output.parent if output.suffix else output
    directory.mkdir(parents=True, exist_ok=True)
    index = output if output.suffix else output / "index.html"

    links: dict[str, str] = {}
    if not args.no_player_reports:
        for dossier in dossiers:
            name = f"{dossier.scan.short_id}-{Path(dossier.session.archive.filename).stem}.html"
            write_report(index.parent / name, render_dossier(dossier, embed_images=args.embed_images))
            links[dossier.scan.evidence_id] = name

    write_report(index, render_match(match, report_links=links))
    out.line(f"match report: {index}")
    for dossier in match.ordered():
        out.line(f"  {dossier.priority[0]}  {dossier.subject:<28}  {dossier.worst().value}")
    for player in match.missing_players:
        out.line(out.paint(f"  --  {player.name:<28}  no archive submitted", "critical"))

    if args.redacted:
        redacted = Redactor(salt=args.salt or new_salt()).match(match)
        redacted_index = index.with_name(index.stem + ".redacted.html")
        write_report(redacted_index, render_match(redacted, redacted=True))
        out.line(f"redacted match report: {redacted_index}")

    if args.json:
        Path(args.json).write_text(json.dumps(match.to_json(), indent=2), encoding="utf-8")
        out.line(f"JSON written to {args.json}")

    if custody:
        for dossier in dossiers:
            custody.append(
                "match-report",
                evidence_id=dossier.scan.evidence_id,
                actor=args.actor,
                details={
                    "match": schedule.match_id if schedule else None,
                    "report": str(index),
                    "priority": dossier.priority[0],
                },
            )
    return _exit_code(dossiers, args.fail_on)


def cmd_appeal(args: argparse.Namespace) -> int:
    out = Out(colour=None if not args.no_colour else False)
    rules = _load_rules(args)
    schedule = _load_schedule(args)
    custody = _custody(args)
    scans = _scan_all(args.archives, rules, out)
    if not scans:
        return EXIT_ERROR

    root = Path(args.output)
    dossiers = []
    for scan in scans:
        dossier = analyze_scan(scan, rules, schedule=schedule, peers=scans, max_tier=args.max_tier)
        dossiers.append(dossier)
        directory = root / scan.short_id if len(scans) > 1 else root
        write_packet(
            dossier,
            directory,
            custody=custody,
            redacted=args.redacted,
            salt=args.salt,
        )
        out.line(f"appeal packet for {dossier.subject}: {directory}")
        if custody:
            custody.append(
                "appeal-packet",
                evidence_id=scan.evidence_id,
                actor=args.actor,
                details={"packet": str(directory), "redacted": bool(args.redacted)},
            )
    return _exit_code(dossiers, args.fail_on)


def cmd_parse(args: argparse.Namespace) -> int:
    out = Out(colour=None if not args.no_colour else False)
    rules = _load_rules(args)
    scans = _scan_all(args.archives, rules, out)
    if not scans:
        return EXIT_ERROR
    payload = [scan.session.to_json() for scan in scans]
    text = json.dumps(payload if len(payload) > 1 else payload[0], indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        out.line(f"session JSON written to {args.output}")
    else:
        print(text)
    return EXIT_OK


def cmd_custody(args: argparse.Namespace) -> int:
    out = Out(colour=None if not args.no_colour else False)
    log = CustodyLog(args.path)
    records = log.read()
    if not records:
        out.line("custody log is empty or does not exist")
        return EXIT_ERROR
    for record in records:
        out.line(
            f"{record['at']}  {record['action']:<14} {record.get('evidence_id', '')[:12]:<12} "
            f"{record.get('actor', '')}"
        )
        if args.verbose and record.get("details"):
            out.line(f"    {json.dumps(record['details'], sort_keys=True)}")
    problems = log.verify()
    out.line()
    if problems:
        for problem in problems:
            out.line(out.paint(f"  !! {problem}", "critical"))
        return EXIT_FINDINGS
    out.line(out.paint(f"  chain intact across {len(records)} record(s)", "ok"))
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    rules = RulePack.load(args.rules)
    print(json.dumps(rules.data, indent=2))
    return EXIT_OK


# --------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sami",
        description=(
            "Review MOSS anti-cheat archives: verify integrity, reconcile clocks, and produce "
            "an evidence dossier. Never outputs a verdict."
        ),
        epilog="Findings are evidence for a human decision. A clean report is not a finding of innocence.",
    )
    parser.add_argument("--version", action="version", version=f"samireader {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(sub: argparse.ArgumentParser, *, archives: bool = True) -> None:
        if archives:
            sub.add_argument("archives", nargs="+", help="MOSS .zip archive(s)")
        sub.add_argument("--rules", help="rule pack layered over the built-in defaults (.json/.yaml)")
        sub.add_argument("--schedule", help="match schedule for window correlation (.json/.yaml)")
        sub.add_argument("--custody", help="append actions to this chain-of-custody log (JSONL)")
        sub.add_argument("--actor", default=default_actor(), help="who is running this review")
        sub.add_argument("--max-tier", type=int, choices=(1, 2, 3), default=3,
                         help="highest finding tier to run (1 = integrity and time only)")
        sub.add_argument("--fail-on", choices=(*SEVERITY_ORDER, "never"), default="high",
                         help="exit non-zero when a finding at or above this severity is present")
        sub.add_argument("--no-colour", action="store_true", help="disable terminal colour")

    verify = subparsers.add_parser("verify", help="check integrity and clocks, print a summary")
    common(verify)
    verify.add_argument("--json", help="also write the full dossiers as JSON")
    verify.add_argument("-v", "--verbose", action="store_true",
                        help="include informational findings and benign explanations")
    verify.set_defaults(func=cmd_verify)

    report = subparsers.add_parser("report", help="write a self-contained HTML dossier")
    common(report)
    report.add_argument("-o", "--output", required=True,
                        help="output .html file, or a directory when several archives are given")
    report.add_argument("--redacted", action="store_true",
                        help="also write a pseudonymised copy for sharing beyond admins")
    report.add_argument("--salt", help="case salt for redaction (reuse to keep tokens stable)")
    report.add_argument("--embed-images", choices=("none", "flagged", "all"), default="flagged",
                        help="embed captures in the report (default: only flagged frames)")
    report.add_argument("--json", help="also write the dossiers as JSON")
    report.set_defaults(func=cmd_report)

    match = subparsers.add_parser("match", help="review every archive from one match together")
    common(match)
    match.add_argument("-o", "--output", required=True, help="output directory or index .html")
    match.add_argument("--redacted", action="store_true", help="also write a pseudonymised copy")
    match.add_argument("--salt", help="case salt for redaction")
    match.add_argument("--embed-images", choices=("none", "flagged", "all"), default="flagged")
    match.add_argument("--no-player-reports", action="store_true",
                       help="write only the match index, not per-player dossiers")
    match.add_argument("--json", help="also write the match dossier as JSON")
    match.set_defaults(func=cmd_match)

    appeal = subparsers.add_parser(
        "appeal",
        help="write the packet the accused player needs to check the work",
    )
    common(appeal)
    appeal.add_argument("-o", "--output", required=True, help="output directory")
    appeal.add_argument("--redacted", action="store_true",
                        help="pseudonymise the packet (for onward sharing, not for the player's own copy)")
    appeal.add_argument("--salt", help="case salt, when redacting")
    appeal.set_defaults(func=cmd_appeal)

    parse = subparsers.add_parser("parse", help="dump the parsed session as JSON")
    common(parse)
    parse.add_argument("-o", "--output", help="write to this file instead of stdout")
    parse.set_defaults(func=cmd_parse)

    custody = subparsers.add_parser("custody", help="read and re-verify a chain-of-custody log")
    custody.add_argument("path", help="chain-of-custody JSONL file")
    custody.add_argument("-v", "--verbose", action="store_true", help="show record details")
    custody.add_argument("--no-colour", action="store_true")
    custody.set_defaults(func=cmd_custody)

    rules = subparsers.add_parser("rules", help="print the effective rule pack")
    rules.add_argument("--rules", help="overlay pack to merge over the defaults")
    rules.add_argument("--no-colour", action="store_true")
    rules.set_defaults(func=cmd_rules)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (RuleError, ScheduleError) as exc:
        print(f"sami: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ArchiveError as exc:
        print(f"sami: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:  # pragma: no cover - piping into head
        return EXIT_OK
    except KeyboardInterrupt:  # pragma: no cover
        print("sami: interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
