# Operations

Running samireader in a league. Everything here assumes the posture set out in
[`PLAN.md`](./PLAN.md) §1: the tool reduces review time, it does not replace review
judgement, and its output is evidence for a human decision.

---

## 1. The submission loop

```bash
# One archive, quick answer, exit code for the pipeline
sami verify player.zip --schedule match.json --custody cases/QF1/custody.jsonl

# The case document
sami report player.zip -o cases/QF1/player.html --redacted \
    --custody cases/QF1/custody.jsonl

# The whole match: coverage grid first, then a dossier per player
sami match submissions/QF1/*.zip --schedule schedules/QF1.json \
    -o cases/QF1/ --custody cases/QF1/custody.jsonl
```

`sami match` is the one to run first. The coverage grid answers "did everyone actually
record this match?" in one glance, which is the question that most often has an answer and
almost never gets asked.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing at or above `--fail-on` (default `high`) |
| 1 | At least one finding at or above the threshold |
| 2 | An archive or a configuration file could not be read |

For an automated intake that should only stop on the unarguable findings:

```bash
sami verify "$upload" --max-tier 1 --fail-on critical || notify_admin "$upload"
```

`--max-tier 1` runs integrity and time only. It is fast, it needs no schedule, and every
finding it can produce is arithmetic.

---

## 2. Match schedules

Match-window correlation is the "dates against the data" product, and it needs a second
date to compare against. The format is deliberately trivial to produce from a spreadsheet
export or by hand:

```json
{
  "match_id": "R6-QF1",
  "start": "2024-03-28T21:05:00+03:00",
  "end":   "2024-03-28T22:05:00+03:00",
  "rounds": [
    { "number": 1, "start": "2024-03-28T21:05:00+03:00", "end": "2024-03-28T21:10:00+03:00" },
    { "number": 2, "start": "2024-03-28T21:12:00+03:00", "end": "2024-03-28T21:17:00+03:00" }
  ],
  "players": [
    { "name": "szazi",  "team": "Ash",      "archive": "20240328_180012_1434136903_369969994.zip" },
    { "name": "geekay", "team": "Ash",      "archive": "3f9a2c1b" },
    { "name": "absent", "team": "Thermite", "archive": "not-submitted.zip" }
  ]
}
```

- **Timestamps must carry a UTC offset.** A schedule without one is rejected rather than
  guessed at — it is the reference clock, so an ambiguous one is worse than none.
- `end` may be replaced by `duration_minutes`.
- `rounds` are optional. With them, coverage gaps are reported against the rounds they
  swallow, which is far more useful than a gap in the abstract.
- `archive` matches on filename, full SHA-256, or a hash prefix of 8 characters or more.
  A player whose `archive` never matches is reported as **no archive submitted**.

The session is placed on an absolute timeline using the UTC offset measured from that
player's *own archive* — never from the reviewer's machine, and never from a timezone the
player states.

---

## 3. Rule packs

Every threshold and every name list lives outside the code. A pack passed with `--rules` is
layered over the built-in defaults, so it only needs to state what it changes:

```json
{
  "name": "example-league",
  "version": "2026.1",
  "clocks":  { "offset_tolerance_minutes": 5 },
  "session": { "max_screenshot_gap_s": 240 },
  "config":  { "vulkan_layer_allowlist": ["VK_LAYER_OW_OVERLAY", "VK_LAYER_our_capture_tool"] },
  "environment": { "known_bad_sha256": ["<sha256 of a confirmed loader>"] },
  "severity": { "environment.category.macro-suite": "low" },
  "disabled_rules": ["config.many-profiles"]
}
```

- Nested objects merge; **lists replace**, so a league can shrink a list as well as extend it.
- `severity` overrides any rule's severity by rule id. Rule ids are printed next to every
  finding in the report and in `sami verify` output.
- `disabled_rules` silences a rule entirely. Prefer downgrading severity over disabling —
  a silenced rule leaves no trace in the report that it was silenced.
- `sami rules --rules league.json` prints the effective pack after merging, which is what
  should be attached to a case file.

**The shipped defaults are public, which means they are known to anyone who wants to evade
them** (PLAN §7). A league that cares should keep a private overlay pack, version it, and
not publish its thresholds or hash lists.

### YAML

Packs and schedules may be `.yaml`/`.yml` if PyYAML is installed
(`pip install 'samireader[yaml]'`). JSON works with no dependencies at all, which is why the
built-in pack ships as JSON: the tool must run at a LAN with no network and no wheels.

---

## 4. Redaction and the case salt

`--redacted` writes a second HTML file with usernames, hostnames, serial numbers, IP
addresses, Steam IDs and the MOSS hardware fingerprint replaced by stable tokens
(`USER-4f21`, `MON-9ba0`). It is **pseudonymisation, not deletion**: the same value gets the
same token everywhere, so the report still reads coherently and still supports the finding.

Tokens are derived from a **case salt**:

- Omit `--salt` and a fresh random salt is generated per run. Tokens are then stable
  *within* that report but not across runs.
- Pass `--salt` to keep tokens stable across reports — necessary when the same machine or
  the same player appears in several cases and the correlation is the point.
- When `--custody` is also given, the salt used is written into the custody record, so a
  case file can reproduce its own tokens later. **The salt is never written into the
  redacted report.** Anyone holding both the salt and the report can re-derive the mapping,
  so treat the salt with the same care as the archive.

Send the redacted copy to opposing teams, tournament organisers and the accused player's
side. Keep the unredacted one inside the admin team.

---

## 5. The appeal packet

If a finding is going to be used in a ruling, the person it is used against has to be able
to check it. That is not a courtesy; it is what makes the output evidence rather than an
assertion (DECISIONS D1).

```bash
sami appeal player.zip -o cases/QF1/appeal-player/ --custody cases/QF1/custody.jsonl
```

The packet contains their dossier, the findings as data, **the exact rule pack that produced
them**, the parsed session including every log line the tool did not recognise, the custody
records for their archive, and a plain-text cover sheet explaining how to contest each
finding.

Give it to the player unredacted — it is their own archive, and their own data. Use
`--redacted` only for a copy that will travel further than they do.

---

## 6. Chain of custody

`--custody path.jsonl` appends a record for every action taken against a piece of evidence:
what was done, when, by whom, with which tool and rule-pack versions, and the archive's
SHA-256 as its evidence ID. Each record carries the hash of the record before it.

```bash
sami custody cases/QF1/custody.jsonl -v     # read it back and re-verify the chain
```

Stated plainly, because a custody log trusted further than it deserves is worse than none:
**this is tamper-evident, not tamper-proof.** Removing or editing any record but the most
recent one leaves a visible break, and accidental truncation shows up immediately. Anyone
who can write to the file can also rewrite it wholesale and recompute the chain. For a log
that has to survive a motivated party, keep it on storage the submitter cannot reach, or
countersign it externally.

---

## 7. Handling the archives themselves

Every archive is treated as hostile input: it was produced on a machine controlled by the
person it may incriminate.

- Nothing extracted is ever executed, and nothing is written outside the paths you name.
- Zip-slip, absolute paths and traversal are refused outright.
- Expansion is capped by entry count, total size, per-member size and compression ratio.
- Images are inspected structurally, never decoded.

On your side: keep archives in a directory the tool only reads, and let the reports be the
thing that circulates.

---

## 8. Retention and privacy

MOSS archives are personal data (RESEARCH §8). Before running a season on this:

1. **Write down a retention period** and delete archives when it expires. A tournament that
   keeps ZIPs forever is holding a database of players' machines, home networks and
   screenshots.
2. **Restrict access** to the unredacted reports to the admins who decide cases.
3. **Share only the redacted variant** outside that group, including with the accused
   player's team.
4. **Record a lawful basis** for processing — for most leagues, the rules the player agreed
   to when entering. Say so in the rules rather than assuming it.
5. **Give the accused their own dossier.** The tool's output is designed to be dismissible
   on the merits: every finding carries its arithmetic and its benign explanation precisely
   so that it can be argued with. A player who cannot see the evidence against them cannot
   do that.

---

## 9. What to do with a finding

| Priority | Meaning | Reasonable first step |
|---|---|---|
| **P1** | Integrity or clock evidence does not reconcile | Ask for the original archive again, unmodified. A re-supplied clean copy settles most of these. |
| **P2** | Environment or coverage findings need a human | Open the flagged captures and the process list. Most resolve in a minute. |
| **P3** | Minor or informational findings only | Note and move on. |
| **P4** | Nothing flagged against the current rules | **Not a finding of innocence.** It means nothing was found in what MOSS captured. |

The priority band is a queue position. It is not a score, it is not a probability, and it
must never be quoted as one — least of all in a ruling about a named person.
