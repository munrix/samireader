# samireader — Product & Engineering Plan

An application that ingests MOSS anti-cheat archives and produces a defensible,
evidence-linked integrity report — with timestamp reconciliation as the core.

Read [`RESEARCH.md`](./RESEARCH.md) first; this plan depends on its findings.
Open questions that could change this plan are in [`QUESTIONS.md`](./QUESTIONS.md).

---

## 1. Positioning

**The job to be done:** a league admin receives 10 MOSS ZIPs after a match and currently
spends 30–60 minutes scrolling screenshots and log lines, inconsistently, with no record
of what was checked. There is no official analyser, no API, no admin portal.

**What we build:** the review layer MOSS never shipped.

**What we explicitly do not build:** a verdict machine. Per RESEARCH §7, MOSS is
user-mode software run by the suspect on their own hardware, with publicly documented
bypasses. Any product that outputs "CHEATER: 87%" is wrong, unusable as evidence, and a
liability the first time it is wrong about a named person.

**The output is a dossier**, ordered by severity, where every finding carries:
- the raw evidence (log line number, image file, config key),
- the arithmetic or rule that produced it,
- a confidence level,
- **and the benign explanation stated alongside the suspicious one.**

Design principle, stated once and applied everywhere: **reduce review time, do not
replace review judgement.**

---

## 2. Core thesis — three tiers of finding

Order matters. Tier 1 is what makes the product credible; tiers 2 and 3 are what makes
it useful.

| Tier | Class | Nature | Defensibility |
|---|---|---|---|
| **1** | **Integrity & time** | Hashes and clocks reconcile, or they do not | **Objective.** Arithmetic. Nearly unarguable. |
| **2** | **Environment** | Unsigned binaries, injection layers, remote-access tools, blank frames | Strong but contextual |
| **3** | **Behavioural** | Macro histograms, no-recoil distribution, input timing | Statistical. **Corroborating evidence only.** |

Build strictly in this order. A tool that can prove an archive was rebuilt after the
match is immediately valuable and cannot be argued with. A tool that opens with a
behavioural score gets dismissed the first time it flags a good player.

---

## 3. Feature set

### 3.1 Tier 1 — Integrity & time (the wedge, and the requested core)

**Archive integrity**
- SHA-256 of the submitted archive as the immutable evidence ID.
- **Per-file verification: recompute SHA-256 of every extracted file and compare against
  the `Zip CRC:` value in the log.** Verified working — `Zip CRC` *is* the content SHA-256.
- Set reconciliation: files in ZIP but not in log (added), in log but not in ZIP (removed).
- Sequence continuity: gaps in `NNN.JPG` numbering.
- Structural checks: log truncated, `Global log CRC` line missing, header missing.
- ZIP-level forensics: entry order, compression method uniformity, mtime clustering — a
  rebuilt archive rarely reproduces MOSS's original write pattern.

**Multi-clock reconciliation** — the six clocks plus derived boot time (RESEARCH §4):
- Derive host UTC offset from ZIP-mtime ↔ log-local pairs; assert it is a valid whole
  or half-hour offset and constant across the session.
- Assert `SHAS2 mode started` (network-synced) ↔ `Monitor Started` (local) delta is a
  plausible timezone offset — **a mismatch here is the primary system-clock-manipulation
  signal.**
- Monotonicity: screenshot timestamps strictly increasing; no backward jumps.
- Boot-time sanity: session must fall inside `capture_time − lsass.exe running time`.
- **OCR the taskbar clock** from screenshots and add it as an independent reference.
  Verified readable in the samples (`9:05 PM 3/28/2024`).

**Match-window correlation** — "checking the dates against the data":
- Given a scheduled match window, assert the session **starts before** the first round
  and **ends after** the last.
- Flag coverage gaps overlapping rounds.
- Flag stale/recycled archives (session date ≠ match date).
- **Team coverage grid:** all 10 players on one screen, session bars against the match
  window. One glance answers "did everyone actually record this match?" — the single
  highest-value screen in the product.

### 3.2 Tier 2 — Environment

- **Process & signature analysis:** unsigned binaries (absent `Author:`), execution from
  `%TEMP%` / `%APPDATA%` / `Downloads`, known-bad hash lists, and category detection for
  **remote-access tools** (AnyDesk, Parsec, RustDesk, TeamViewer — enables a remote
  operator, and is under-checked by admins), macro suites (GHUB, Synapse, AutoHotkey,
  reWASD), VM/sandbox artifacts, spoofers, overlay frameworks.
- **Config analysis:** unknown `VK_LAYER_*` entries in `VulkanWhitelistedLayers`
  (a user-editable injection allowlist — see RESEARCH §5C); sensitivity/FOV outside
  in-game ranges; `RefreshRate` inconsistent with the declared monitor EDID; profile-GUID
  count (many accounts on one machine); **cross-player config diffing** within a match.
- **Screenshot analysis:** blank/near-uniform frame detection (file size + variance —
  catches the 39 KB wallpaper frames); perceptual-hash duplicate detection (a frozen or
  replayed frame); resolution/aspect change mid-session (monitor swap); second-monitor
  region extraction and content classification (stream open, Discord screen-share).
- **Identity graph:** composite fingerprint — monitor EDID serial + drive serial + board +
  CPU + RAM + GPU + driver + LAN/WAN IP. **`Sign ID1` is a weak hint only** — the samples
  contain a real collision between two different machines (RESEARCH §5A). Cross-archive
  matching finds shared machines, shared WAN IPs, and repeat identities across a season.
  **Every identity match must render as "review this", never as "confirmed same person".**

### 3.3 Tier 3 — Behavioural

- **Parse the ASCII histograms back into numeric distributions** — MOSS renders real data
  as ASCII art that nobody reads. Reconstructing it is cheap and unlocks the whole tier.
- Score peak sharpness / kurtosis / coefficient of variation per key-pair sequence.
- Apply the vendor's own stated human baselines as thresholds: sustained double-click
  < 80 ms, sustained same-key double-press < 100 ms, absent key-order reversal on
  simultaneous pairs (RESEARCH §3.8).
- No-recoil histogram: dense small-pixel clusters vs sparse large-pixel moves.
- **Always presented as "warrants human review", never as proof.**

### 3.4 Reporting & workflow

- **Self-contained HTML report** — single file, no server, emailable, opens anywhere.
  This matches how admins actually work and should be the v1 output.
- JSON export for machine consumption; PDF for formal proceedings.
- Screenshot contact sheet with flagged frames pinned to the top.
- Per-match view aggregating all 10 players.
- Redacted variant for sharing beyond admins (RESEARCH §8).
- Case management: reviewer queue, admin notes, decision log, chain of custody,
  appeal packet export.

---

## 4. Architecture

```
submission → ingest → parse → verify → analyse → score → report
                ↓        ↓       ↓        ↓        ↓        ↓
             quarantine  AST  integrity  rules  weighted  HTML/JSON/PDF
             + evidence       + clocks   packs  by tier
               hash                             (never a
                                                 single %)
```

**`mosslib` — the parser, as a standalone dependency-light library.**
This is the asset. Everything else is replaceable.
- Strict, versioned grammar; **tolerant by default** — unknown lines are preserved with
  line numbers, never dropped. MOSS versions differ and the format is undocumented.
- Emits a typed `Session` object. Round-trips to JSON.
- **Golden-file test corpus** seeded with the five sample archives (privacy-scrubbed).
  Every parser change runs against the corpus. This is what makes the tool trustworthy.

**Analyzers** are pure functions `Session → [Finding]`. Each `Finding` carries id,
severity, confidence, tier, evidence references, rule explanation, and benign explanation.

**Rule packs** in declarative YAML so leagues tune thresholds and hash lists without
touching code, and so rule changes are reviewable and versioned.

**Suggested stack** (open to preference — see QUESTIONS §5):
- **Python** — best imaging/OCR ecosystem, fastest path to the analyzers.
- **CLI first** (`sami parse`, `sami verify`, `sami report`, `sami match`). Works offline
  at a LAN with no infrastructure, and is the honest MVP.
- Web layer only when volume justifies it: FastAPI + a job queue + Postgres + object
  storage; React report viewer.
- OCR: Tesseract on a fixed taskbar region for digits; template matching for R6 HUD
  elements. **No heavy ML in v1** — deterministic and explainable beats accurate-but-opaque
  when the output accuses someone.

**Security posture** — treat every archive as hostile input: zip-slip protection,
extraction size and file-count limits, no execution of anything extracted, decode images
in a resource-capped sandbox.

---

## 5. Roadmap

| Phase | Scope | Outcome |
|---|---|---|
| **P0** — 1–2 wks | `mosslib` parser, archive + per-file SHA-256 verification, multi-clock reconciliation, static HTML report, CLI | **Ships against the 5 sample archives.** Already provably valuable. |
| **P1** | Process/signature, config (`VK_LAYER_*`), blank/duplicate frame detection, taskbar-clock OCR | Tier 2 environment findings |
| **P2** | Match-window correlation, team coverage grid, multi-player match view | The "dates vs data" product, complete |
| **P3** | ASCII histogram reconstruction, macro & no-recoil scoring | Tier 3 behavioural |
| **P4** | Cross-archive identity graph, season analytics, repeat-offender detection | Longitudinal value |
| **P5** | Web app, case management, Discord submission bot, league integrations | Scale & workflow |

**P0 is deliberately small and completely defensible.** It answers "is this archive
authentic and does it cover the match?" — which is the question admins cannot currently
answer at all, and which needs no ML, no OCR and no server.

---

## 6. Game rollout

1. **Rainbow Six Siege** — the wedge. All samples are R6, MOSS works well, config
   capture and HUD OCR are richest.
2. **Call of Duty** — same MOSS model; needs title/season-versioned game detection.
3. **Valorant** — **different evidence model.** Vanguard's ring-0 posture makes MOSS
   unreliable (RESEARCH §6.2). Do not promise a Valorant MOSS workflow; plan for Riot
   match IDs and VOD correlation instead.

Architectural consequence: the pipeline must be **evidence-source-agnostic** — MOSS is
the first source, not the only one. Keep `Session` general enough to admit demos, VODs
and official match records later.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| **False accusation of a named player** | Never emit verdicts. Confidence levels. Benign explanation on every finding. Human sign-off required. The `Sign ID1` collision in the samples is the cautionary case. |
| **Undocumented format drifts across MOSS versions** | Tolerant parser, version detection, golden-file corpus, unknown lines preserved not dropped. |
| **Cheaters adapt to published rules** | Keep rule packs private; version them; do not publish thresholds. |
| **`Global log CRC` algorithm unknown** | Per-file SHA-256 verification already works and covers most tampering. Seek vendor confirmation. |
| **`*` line-prefix semantics unknown** | Do not build a rule on it until confirmed. |
| **Personal data handling** | Retention policy, access control, redacted sharing variant, documented lawful basis. |
| **Over-engineering before validation** | P0 ships in two weeks against real archives before any web infrastructure exists. |

---

## 8. What would make this bulletproof

Ranked by impact on correctness:

1. **Labelled archives from confirmed cheaters.** The single most valuable asset that does
   not exist yet. Without positives, every threshold is a guess. With even 10–20 confirmed
   cases, rules can be validated instead of asserted.
2. **A clean-baseline corpus** — archives from trusted players on known-good machines, to
   measure the false-positive rate before anything reaches an admin.
3. **Vendor confirmation from Nohope** on `*`, `Global log CRC`, `Sign ID1` derivation, and
   the screenshot-cadence randomisation function.
4. **Ground-truth match schedules** to correlate against.
5. **A written evidentiary standard from the league** — what threshold justifies what
   sanction — so scoring maps onto real decisions rather than inventing its own scale.
