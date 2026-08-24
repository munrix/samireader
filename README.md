# samireader

Reads MOSS anti-cheat archives and produces a defensible, evidence-linked integrity
report for league admins — with timestamp reconciliation ("do the dates match the data?")
as the core.

**Status: P0 implemented and tested.** CLI, parser library, analyzers and HTML reporting
all work end to end. See [Validation](#validation) for what that does and does not prove.

```bash
sami verify  match/*.zip --schedule match.json      # answer, in the terminal, exit code set
sami report  player.zip -o case.html --redacted     # the case document, plus a shareable copy
sami match   match/*.zip --schedule match.json -o out/   # ten players, one coverage grid
```

---

## The problem

A league admin receives 10 MOSS ZIPs after a match: ~600 screenshots and ~5,000 log lines.
Reviewing them by hand takes 30–60 minutes, is done inconsistently, and leaves no record of
what was checked. MOSS ships no analyser, no API and no admin portal.

**The recording is automated. The review is not.** This is the review layer.

## What it is not

Not a verdict machine. MOSS is user-mode software, run by the suspect, on their own
hardware, with publicly documented bypasses. Any tool that prints "CHEATER: 87%" is wrong,
unusable as evidence, and a liability the first time it is wrong about a named person.

The output is a **prioritised evidence dossier**. Every finding carries the raw evidence,
the arithmetic that produced it, a confidence level, and **the benign explanation stated
alongside the suspicious one**. Two of those are enforced in code: a finding with no benign
explanation, or no evidence, raises rather than rendering.

---

## Install

No dependencies. Python 3.10+.

```bash
git clone https://github.com/munrix/samireader && cd samireader
pip install -e .                # provides the `sami` command
# or run straight from the checkout, with no install at all:
PYTHONPATH=src python3 -m sami.cli --help
```

`pip install -e '.[yaml]'` additionally allows rule packs and schedules in YAML.

## Commands

| Command | Does |
|---|---|
| `sami verify ARCHIVE…` | Integrity and clocks, summarised in the terminal. Exit code reflects the worst finding, so it drops straight into a submission pipeline. |
| `sami report ARCHIVE… -o FILE` | The self-contained HTML dossier. `--redacted` also writes a pseudonymised copy for sharing beyond admins. |
| `sami match ARCHIVE… -o DIR` | Every archive from one match: the team coverage grid, the review queue, and a dossier per player. |
| `sami appeal ARCHIVE -o DIR` | The packet the accused needs to check the work: their dossier, the findings as data, the exact rule pack that produced them, the parsed session, and the custody records for their archive. |
| `sami parse ARCHIVE…` | The parsed session as JSON, for anything downstream. |
| `sami custody LOG` | Read back a chain-of-custody log and re-verify its hash chain. |
| `sami rules` | Print the effective rule pack after overlays. |

Common flags: `--rules` (league overrides), `--schedule` (match window), `--custody`
(append to an evidence log), `--max-tier` (1 = integrity and time only), `--fail-on`
(exit-code threshold).

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `high`), `2` the
archive or configuration could not be read.

---

## What it finds

Ordered by how hard the finding is to argue with, which is also the order it is built in.

### Tier 1 — integrity and time · *arithmetic, near-unarguable*

- **Per-file tamper detection.** `Zip CRC:` in the log is the SHA-256 of the file contents;
  every member is re-hashed and compared. Files in the ZIP but not the log, and in the log
  but not the ZIP, are reconciled both ways.
- **Whole-log footer.** MOSS's `Global log CRC` algorithm is undocumented, so the tool tries
  70 candidate algorithm/input combinations on every log. If one matches, whole-log
  verification is available and the report says which. If none does, the report says
  **unverified** rather than implying the log was checked.
- **ZIP structure forensics.** Uniform entry timestamps, entry order against capture order,
  mixed compression, members stamped after the session ended — the signatures of a rebuilt
  archive.
- **Multi-clock reconciliation.** Six clocks plus a derived seventh (RESEARCH §4). The host's
  UTC offset is measured *from the archive itself* — captures against ZIP entry timestamps —
  and everything else is checked against it: is the offset a real time zone, is it stable
  across the session, does MOSS's network-synced header agree with the host's own clock,
  do capture timestamps move only forwards, and does the session fit inside the machine's
  uptime.
- **Match-window correlation.** Given a schedule: late start, early stop, capture gaps over
  scheduled rounds, and archives recorded on the wrong day entirely.
- **Session shape.** Too few captures, too short, long capture gaps, cadence too regular to
  be MOSS's randomised one, game never detected.

The four failure modes of `DECISIONS.md` D2 each map to a distinct detection:

| Failure mode | Caught by |
|---|---|
| Archive edited or rebuilt | per-file hashes, set reconciliation, ZIP structure |
| System clock manipulated | MOSS's network clock vs the host's local clock |
| Log edited after the fact | host offset that is not a real UTC offset |
| Wrong session submitted · late start · early stop | match-window correlation |

### Tier 2 — environment · *strong but contextual*

Remote-access tools, macro suites, VM artefacts, spoofers, debuggers and overlays, by
category; unsigned binaries; execution from `%TEMP%`/Downloads; league-supplied known-bad
hashes. Unrecognised `VK_LAYER_*` entries in `VulkanWhitelistedLayers` — a user-editable
allowlist for code injected into the game process. Out-of-range config values, developer
flags, profile counts, and cross-player config diffing within a match. Blank frames,
byte-identical frames, mid-session resolution changes and structurally broken captures.

### Tier 3 — behavioural · *corroborating only*

MOSS renders real interval distributions as ASCII art nobody reads. The parser reconstructs
them into numbers and scores them against **the vendor's own published human baselines** —
no sustained double-click under 80 ms, no sustained same-key press under 100 ms, human input
spread across 0–140 ms — plus peak sharpness and the no-recoil movement distribution. Every
Tier 3 finding is labelled corroborating and downgraded to low confidence when the ASCII
could only be partially reconstructed.

## What it deliberately does not do

- **No OCR.** The taskbar clock inside the captures is a genuine seventh reference and is
  left unread. It is the highest-value thing still missing.
- **No pixel decoding.** Frame size, JPEG structure and exact-hash duplicates only — feeding
  attacker-controlled images to an image decoder buys perceptual hashing at the cost of a
  large native attack surface.
- **No identity graph across archives**, no season analytics, no web app, no network access
  of any kind.
- **No Valorant.** Vanguard's ring-0 posture makes MOSS unreliable there; that needs a
  different evidence model, not a parser change (RESEARCH §6.2).
- **No Call of Duty support claimed.** The grammar is built against Rainbow Six output.
  CoD archives should parse — the parser is tolerant and keeps what it does not recognise —
  but nothing is asserted until real CoD archives exist to check against.

## Validation

**The tests run against synthetic archives, reconstructed from the log grammar documented in
`docs/RESEARCH.md` §3 — not against real MOSS output.** The five real archives that grounded
the research are personal data (RESEARCH §8) and are not in this repository.

So the suite proves the parser and the analyzers behave correctly *against the documented
format*. It does not prove the documented format is complete. Closing that gap needs a
privacy-scrubbed corpus of real archives; until then the parser is deliberately tolerant,
every unrecognised log line is preserved with its line number, and every report lists them
in an appendix so a format drift shows up as a visible gap rather than a silent one.

What would make it bulletproof, in order (PLAN §8): labelled archives from confirmed
cheaters, a clean-baseline corpus, vendor confirmation of `Global log CRC` / `Sign ID1` /
the `*` prefix, ground-truth match schedules, and a written evidentiary standard from the
league.

## Layout

```
src/mosslib/     the parser, dependency-free and side-effect-free: archive → Session
src/sami/        analyzers, rule packs, redaction, custody, reporting, CLI
tests/fixtures/  the synthetic archive builder — one switch per way an archive can be wrong
docs/            research, plan, decisions, open questions, operations
```

`mosslib` is the asset; everything else is replaceable. It never decides what anything
*means* — that lives in `sami`, where each analyzer is a pure function
`AnalysisContext → [Finding]`.

## Development

```bash
python3 -m unittest discover -s tests -t .   # 113 tests, no network, no fixtures on disk
ruff check src tests && mypy src
make check                                   # all of the above
make demo                                    # build a synthetic match and report on it
```

## Documents

| Doc | Contents |
|---|---|
| [`docs/RESEARCH.md`](docs/RESEARCH.md) | What MOSS is, the reverse-engineered log grammar, the six-clock model, per-game analysis, findings from five real archives, and MOSS's blind spots |
| [`docs/PLAN.md`](docs/PLAN.md) | Positioning, the three-tier finding model, architecture, roadmap, risks |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | Confirmed direction, and what shipped against it |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | Running it in a league: rule packs, schedules, redaction, custody, privacy |
| [`docs/QUESTIONS.md`](docs/QUESTIONS.md) | Open questions, blocking ones first |

## Privacy

MOSS archives contain, in plaintext: Windows usernames and hostnames, LAN and partial WAN
addresses, monitor EDID and drive serials, motherboard identifiers, full process paths with
personal folder names, Steam IDs, and screenshots containing chat messages and real names.
Treat them as personal data. `--redacted` produces a pseudonymised report for anything
leaving the admin team; `docs/OPERATIONS.md` covers retention and the case salt.

## Licence

MIT. See [`LICENSE`](LICENSE).
