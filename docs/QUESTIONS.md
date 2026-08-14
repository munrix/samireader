# Open Questions

Answers to these change the plan. Grouped by how much they change it — **§1 questions are
blocking**, the rest can proceed under stated assumptions.

Working assumptions are marked ▸. If an assumption is wrong, say so and the plan adjusts.

---

## 1. Purpose & decision authority (blocking)

1. **Who is the primary user?** League admin, tournament organiser, team manager, or a
   player self-checking before submission? The samples look like an organised event
   (EGA MENA / Geekay Esports, R6, March 2024) — is this for that organisation?
   ▸ *Assumed: league/tournament admin.*
2. **What decision does the report drive?** Is it (a) triage — deciding which of 10
   archives a human opens first, or (b) evidence in a ruling that can ban or DQ a player?
   This determines how much the tool may assert, and the legal posture of the output.
   ▸ *Assumed: (a) triage, feeding into (b) with human sign-off.*
3. **What is the league's evidentiary standard today?** What currently justifies a ban —
   and who signs off? The scoring must map onto real sanctions, not invent its own scale.
4. **Volume?** Matches per week × 10 players. 20 archives/week and 2,000/week are
   different products (CLI vs queue-backed service).
5. **Is MOSS mandatory for every match, or requested only when a dispute arises?**

## 2. The date-checking core

6. **What specifically do you want date checking to catch?** Rank these:
   - player recorded a *different* session than the match
   - player edited or rebuilt the archive
   - player started MOSS late / stopped early
   - player resubmitted an old archive
   - system-clock manipulation
7. **Have you actually been burned by one of these?** A real incident is worth more than
   any hypothesis for prioritising rules.
8. **Where does the ground-truth match schedule come from?** Spreadsheet, Toornament/
   Battlefy/FACEIT API, Discord messages, manual entry? Without it, match-window
   correlation cannot run.
9. **What timezone is authoritative for the schedule**, and do you know players' local
   timezones? The samples span UTC+1 and UTC+3 — four hosts at +3, one at +1.
10. **Do you receive round-level timing** (round start/end), or only a match start time?
    Round-level enables gap-vs-round detection; match-level only gives coverage bounds.

## 3. Scope & data

11. **Game priority.** All five samples are Rainbow Six. Is R6 first and Valorant/CoD
    later, or must all three ship together? ▸ *Assumed: R6 first.*
12. **Valorant reality check.** Vanguard's ring-0 posture makes MOSS unreliable there
    (RESEARCH §6.2). Do you already have working Valorant MOSS archives, or is Valorant
    coverage aspirational? This materially changes the roadmap.
13. **Console entries** — in scope at all? MOSS is Windows-only.
14. **MOSS versions in the wild.** Samples are all 6.6.9.0. Do submissions vary? Older
    versions have different log formats and the parser must be version-aware.
15. **Do you have archives from confirmed cheaters?** This is the highest-value asset
    named in the plan (PLAN §8). Without labelled positives every threshold is a guess.
16. **Do you have clean baselines** from trusted players, to measure false-positive rate?
17. **May the five sample archives be used as a permanent test corpus** (privacy-scrubbed)
    and committed to this repository? They contain real personal data — usernames,
    hostnames, IPs, hardware serials, Discord content with real names.

## 4. Context questions the tool cannot answer alone

18. **Was the March 2024 event a LAN or online?** Four of five hosts share public IP
    `90.148.144.xxx` and a `192.168.100.x` LAN. At a LAN that is expected; online it is
    a serious finding. **The tool must be told which**, per match.
19. **Is a second monitor permitted during matches?** One player had Discord, a screen-share
    and the tournament stream open on a second display.
20. **Is Discord screen-sharing during a match allowed?**
21. **Are macro-capable peripherals (Logitech GHUB, Razer Synapse) allowed?** They appear
    in every sample. If allowed, their mere presence must not be flagged.

## 5. Product & delivery

22. **Self-hosted CLI/desktop tool, or hosted web service?** How technical are the admins?
    ▸ *Assumed: CLI first, web later.*
23. **Offline requirement?** LAN events may have no reliable internet.
24. **Report delivery** — emailed HTML file, Discord bot post, web dashboard link?
25. **Who may see a report?** Admins only, both teams, the accused player, public?
    Drives the redaction requirement.
26. **Data retention** — how long are archives and reports kept? Any GDPR-equivalent
    obligation in your jurisdiction?
27. **Integrations wanted?** Discord submission bot, Toornament/Battlefy/FACEIT, Google
    Drive ingestion?
28. **Should the tool ingest other evidence types** — game demos/replays, OBS recordings,
    official match IDs — or MOSS-only? Affects how general `Session` must be.

## 6. Technical

29. **Stack preference?** ▸ *Assumed: Python, for the imaging/OCR ecosystem.*
30. **Hosting / existing infrastructure?**
31. **Do you know what the `*` prefix means on a `SHAS2:` line?** It appears exactly once
    per log in all five samples. Undocumented. No rule should depend on it until confirmed.
32. **Any contact with Nohope (the MOSS author)?** Vendor confirmation on `Global log CRC`,
    `Sign ID1` derivation and the screenshot-cadence randomisation would harden several rules.
33. **What is the repository name `samireader` referring to?** Naming the CLI and the
    report artifacts consistently is easier with the intent behind it.
34. **Budget/appetite for OCR and ML?** ▸ *Assumed: deterministic rules first, OCR in P1,
    no heavy ML.*

---

## Notes carried from analysis

- `Zip CRC:` in the log is confirmed to be the **SHA-256 of file contents** — verified by
  recomputation. Per-file integrity verification needs no vendor input and can ship in P0.
- `Sign ID1` **collides** between two physically different machines in the samples
  (same board + CPU model). It must never be used alone as identity.
- `VulkanWhitelistedLayers` in R6's `GameSettings.ini` is a user-editable allowlist for
  code injected into the game process. An allowlist check here is cheap and high-value.
