# Changelog

## 0.2.0 — the browser app

Drop a MOSS `.zip` into the page and it says clean or not, with no AI and no upload.

- `web/` — a dependency-free browser app: JSZip (vendored, no CDN), the log parser ported to
  plain JS, and the same checks the CLI runs. Files are hashed with WebCrypto in the page, so
  per-file tamper detection works client-side and nothing leaves the machine.
- Every finding renders as *what was found* (the measurement), *why that matters* (the rule),
  and *the innocent explanation* (the same evidence read the other way).
- The app and the CLI load the **same rule pack**, so thresholds and name lists cannot drift.
- The app is now the site root; the project overview moved to `/about.html`.
- `tests/test_webapp.py` drives the page in real Chromium with real archives, asserting the
  verdicts and that no network request is made during analysis.

## 0.1.0 — first working release

The P0 scope of [`docs/DECISIONS.md`](docs/DECISIONS.md), plus the parts of P1–P3 that need
no OCR, no network and no external data.

### The parser — `mosslib`

- Tolerant, versioned grammar for the MOSS log, reverse-engineered from `docs/RESEARCH.md` §3.
  Unrecognised lines are preserved with their line numbers, never dropped, and surfaced in
  every report.
- Typed `Session` object with lossless JSON round-tripping.
- Safe archive handling: zip-slip, absolute paths and traversal refused; entry-count, size
  and compression-ratio caps; nothing extracted is executed.
- ASCII histogram reconstruction, with an explicit `full` / `partial` / `failed` quality
  signal so findings built on a partial reconstruction can be downgraded.
- JPEG structure reading (dimensions, truncation) with no pixel decoding.
- `Global log CRC` identification: 70 candidate algorithm/input combinations tried against
  every log, so the undocumented footer is either verified or reported as unverified.

### The review layer — `sami`

- **Tier 1:** per-file SHA-256 verification against `Zip CRC:`, file-set reconciliation,
  screenshot sequence continuity, log structure, ZIP structure forensics, seven-clock
  reconciliation (host offset, offset stability, MOSS's network clock, filename clock,
  monotonicity, boot-time sanity), session shape, and match-window correlation.
- **Tier 2:** process categories, unsigned binaries, execution from temp/Downloads,
  known-bad hashes, `VK_LAYER_*` injection allowlist, config ranges and flags, profile
  counts, cross-player config diffing, blank/identical/corrupt captures, resolution changes.
- **Tier 3:** macro and no-recoil scoring against the vendor's own published human baselines.
- Findings enforce two invariants in code: every one states a benign explanation, and every
  one carries evidence.
- Rule packs: every threshold and name list outside the code, layered over the defaults.
- Chain of custody with a hash-chained JSONL log, and `sami custody` to re-verify it.
- Redaction: stable pseudonyms from a case salt, for reports leaving the admin team.
- Appeal packet export (`sami appeal`) — dossier, findings, rule pack, session and custody
  records, so the accused can check the work.
- Self-contained HTML reports: findings summary, timeline, clock table, verification table,
  histograms, contact sheet, and appendices. Per-match view with the team coverage grid.
- CLI: `verify`, `report`, `match`, `appeal`, `parse`, `custody`, `rules`.

### Testing

113 tests over synthetic archives built from the documented grammar — one fixture switch per
way an archive can be wrong. No network, no real archives (they are personal data). See the
README's *Validation* section for what this proves and what it does not.

### Known gaps

Taskbar-clock OCR, the cross-archive identity graph, season analytics, PDF export, and
everything in PLAN P5. Call of Duty support is not claimed until real CoD archives exist to
check against; Valorant needs a different evidence model entirely.
