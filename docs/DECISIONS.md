# Decisions

Confirmed direction. Supersedes the working assumptions marked ▸ in
[`QUESTIONS.md`](./QUESTIONS.md).

---

## D1 — Output serves both triage and formal evidence

The report ranks which archives an admin opens first **and** feeds formal ban/DQ
proceedings with human sign-off.

**Consequences:**
- Chain of custody is required from P0, not deferred. Archive SHA-256 becomes the
  immutable evidence ID at ingest, and every action against it is logged.
- Reports need a **redacted variant** for anything shared beyond admins, and an
  **appeal packet** export (the accused player's own findings, evidence and the rule
  that produced each one).
- The no-verdict rule (PLAN §1) becomes non-negotiable rather than stylistic. Every
  finding ships with its confidence, the arithmetic behind it, and the benign
  explanation. A tool used in rulings must be dismissible by the accused on the merits.
- **Needed from the league:** the written evidentiary standard — what threshold of
  finding justifies what sanction. Scoring must map onto that, not invent a scale.
  (QUESTIONS §1.3, still open.)

## D2 — All four timestamp failure modes are in scope

Wrong session submitted · archive edited or rebuilt · started late / stopped early ·
system clock manipulated.

All four have been hit in practice, which makes Tier 1 the whole product core rather
than a wedge. Build order within Tier 1, cheapest-and-most-certain first:

| Order | Detection | Needs |
|---|---|---|
| 1 | **Archive edited or rebuilt** | Nothing external. Per-file SHA-256 vs `Zip CRC:` + ZIP structure forensics. Verified working. |
| 2 | **Started late / stopped early** | Match window. Session bounds vs match bounds; team coverage grid. |
| 3 | **System clock manipulated** | Nothing external. MOSS's network-synced clock vs host local vs ZIP mtimes vs OCR'd taskbar clock. |
| 4 | **Wrong session submitted** | **Ground-truth match schedule.** Session date/window vs scheduled match. |

**Immediate unblock required:** items 2 and 4 cannot run without a match schedule.
Where does it come from — spreadsheet, Toornament/Battlefy/FACEIT API, Discord,
manual entry? And is round-level timing available, or only match start?
(QUESTIONS §2.8–2.10.)

## D3 — Rainbow Six and Call of Duty in the first release; Valorant deferred

**Consequences:**
- Game detection, config capture paths and any hash baselines must be
  **title- and season-versioned from the start** — CoD churns executable names, install
  paths and anti-cheat components every season. No hardcoding.
- CoD is Windows-only under MOSS; console entries are out of scope by definition.
- CoD's cheat ecosystem skews toward DMA and hardware input injection, which MOSS
  cannot see (RESEARCH §7). Tier 1 and Tier 2 carry the weight there; Tier 3
  behavioural analysis is weaker for CoD than for R6.
- **Immediate unblock required:** there are zero CoD sample archives. The parser is
  being written against R6 MOSS 6.6.9 output only. A handful of real CoD archives is
  needed before claiming CoD support — the log grammar is undocumented and may differ.
- Valorant stays out until working Valorant MOSS archives prove it is feasible at all
  (RESEARCH §6.2).

## D4 — CLI producing a self-contained HTML report

**Consequences:**
- Confirms the P0 shape in PLAN §5: no server, no auth, no storage layer to start.
- Works offline at LAN events.
- The HTML file is the deliverable — emailable, archivable, and it *is* the case
  document, which fits D1's evidence requirement well.
- Case management, submission bots and dashboards (P5) stay deferred until volume
  justifies them. D1 raises their eventual priority but does not pull them into P0.
- Redaction ships as a CLI flag producing a second HTML file, not as a separate system.

---

## Revised P0 scope

1. `mosslib` parser — tolerant, versioned, golden-file corpus from the five R6 archives.
2. Archive ingest with evidence hashing and chain-of-custody log.
3. Per-file SHA-256 verification against `Zip CRC:`; ZIP structure forensics; file-set
   reconciliation.
4. Multi-clock reconciliation, including boot-time sanity from process running times.
5. Session-bounds reporting (match-window correlation lands once a schedule source exists).
6. Self-contained HTML report + `--redacted` variant.
7. CLI: `sami verify`, `sami report`.

Deliberately excluded from P0: OCR, macro histogram parsing, process reputation lists,
identity graph, anything requiring a network.
