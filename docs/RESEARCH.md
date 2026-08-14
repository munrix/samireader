# MOSS Forensics — Research

Domain research for an application that ingests MOSS anti-cheat archives and produces
an evidence report. Grounded in five real MOSS archives from a Rainbow Six Siege event
(2024-03-28, MOSS 6.6.9.0) plus published documentation.

---

## 1. What MOSS actually is

MOSS ("Monitor System Status") is a free, **user-mode** session recorder written by
Nohope92 in 2010. It is used by ESL leagues, EMS, GO4 and a long tail of community
leagues and LANs. It supports 100+ titles including Rainbow Six, Call of Duty,
Counter-Strike, Valorant, Fortnite, Battlefield and PUBG.

The single most important property, and the one that should shape the entire product:

> **MOSS does not prevent or detect cheating. It records a session and hands a human
> a pile of evidence.** Every published description of it says the same thing — admins
> must manually inspect the ZIP for suspicious screenshots, macro graphs and process
> activity. There is no official analyser, no API, no admin portal. "MOSS Automation"
> is only a command-line launcher plus registry configuration.

That gap is the entire product opportunity: **the recording is automated, the review is not.**

### Workflow it sits in

1. Player runs `moss.exe` as admin before the match, picks the game, starts capture.
2. Player plays. MOSS screenshots, hashes processes, records input timing.
3. Player stops capture. MOSS analyses the session and emits a ZIP.
4. Player uploads the ZIP to the admin / opponent.
5. A human opens it and scrolls. For a 10-player match that is ~600 screenshots and
   ~5,000 log lines. **This step takes 30–60 minutes per match and is done inconsistently.**

The vendor's rule for players is explicit: *"Do not edit it in any way, do not remove
images or captured files, do not alter the session file."* Tamper detection is therefore
a first-class requirement, not a nice-to-have.

---

## 2. Archive anatomy (verified against the five samples)

Filename convention:

```
YYYYMMDD_HHMMSS_<SignID1>_<sessionNonce>.zip
20240328_180012_1434136903_369969994.zip
```

The leading timestamp is **UTC**, not local time (see §4). `SignID1` is MOSS's hardware
fingerprint — with an important caveat in §5.

Contents:

| File | Count in samples | Notes |
|---|---|---|
| `Logfile.log` | 1 | Flat text, 525–1100 lines. The whole record. |
| `NNN.JPG` | 48–77 | Screenshots, zero-padded, sequential. Full **virtual desktop** capture. |
| `GameSettings.ini.NNN` | 1–60 | Every game config file MOSS found, one per R6 profile GUID. |

Screenshots are the full virtual desktop, not the game window. A dual-monitor player
produced **3840×1089** JPEGs — both screens plus taskbar in one frame. This is
extremely valuable: it captures the second monitor, the taskbar clock, Discord, and
any browser window.

---

## 3. Log grammar — the parser specification

The log is one flat stream with no section delimiters; line types are identified by
prefix. Derived from the samples:

### 3.1 Session header
```
SHAS2 mode started at 2024-03-28 19:00:12 for Rainbow Six on x64
 ping:68ms
update 6
DirectX version is 12.0( )
OS is 10.0 64 bit build 19045
Real OS Windows 10 or 11              <- VM / spoofed-OS check
```

### 3.2 Hardware inventory
```
PCI: NVIDIA GeForce RTX 3080 (0x10DE-0x220A)          <- full PCI enumeration w/ VID-DID
memory: 16237 MB
version: MOSS 6,6,9,0
Physical: Micro-Star International Co., Ltd.MS-7D24PRO B660M-P DDR4 WIFI (MS-7D24)
Sign ID1: 1434136903
User: GeeKay@DESKTOP-RLNAQE3                          <- Windows user @ hostname
Drive: WD_BLACK SN770 1TB serial:
Net: 192.168.100.33 Public: 90.148.144.xxx            <- last octet deliberately masked
Video: NVIDIA GeForce RTX 3080 driver : 31.0.15.3742
Monitor: ZOWIE XL LCD serial: EBB9N00443SL0           <- EDID serial, one line per display
Usb: Logitech PRO Gaming Keyboard (0C6832703832) (0x46D-0xC339)
processor BIOS details 2500 MHz by 25.00*100. 13th Gen Intel(R) Core(TM) i5-13400F
Monitor Started at 2024/03/28 21:00:18                <- LOCAL time, unlike the header
Windows Defender: enabled
SteamId: 0
```

`processor BIOS details` is MOSS's real-clock-vs-BIOS check (multiplier × base clock).

### 3.3 Process snapshot
```
SHAS2: <sha256> Author: <Authenticode signer> process: <full path>
*SHAS2: <sha256> Author: Helpfeel Inc process: C:\...\GyazoVideoCore.exe
```
Authenticode signer is present only when signed — **an absent `Author:` means unsigned**,
which is directly actionable. The `*` prefix appears exactly once per log in all five
samples; its meaning is undocumented and must be confirmed with the vendor before any
rule depends on it (see open questions).

> **Known limitation:** the process list is snapshotted **at game start only**. Anything
> launched afterwards is invisible. This is a publicly documented bypass.

### 3.4 File capture
```
FileCheck start for C:\USERS\SZAZI\APPDATA\LOCAL\UBISOFT\R6SIEGE at 2024/03/28 20:51:32:
Search for files
captured: C:\Users\...\GameSettings.ini file: GameSettings.ini.001- Zip CRC: <sha256>
FileCheck end for ... at 2024/03/28 20:51:32:
```

### 3.5 Game detection
```
SHAS2: 2a2c...5266 Author: UBISOFT ENTERTAINMENT INC. process: C:\...\RainbowSix_Vulkan.exe
Game Detected
```

### 3.6 Screenshot records
```
 Dxgi ...(75)(Mon 1) DX11(312) : Each 60 at 2024/03/28 21:05:52 file: 010.JPG- Zip CRC: 5f9322cb...
```
- `Dxgi ...(75)` / `DX11(312)` — capture backend and timing counters.
- `(Mon 1)` — monitor index. **All 312 captures across all five archives used `Mon 1`**, even for
  dual-monitor players — because the DXGI desktop-duplication grab spans the whole virtual desktop.
- `Each 60` — the *nominal* 60 s cadence. Observed intervals were 2–138 s (median 40–111 s);
  MOSS randomises. Do not treat deviation from 60 s as an anomaly by itself.

### 3.7 Process statistics table
```
Processes statistics  ping:274
PID	Running Time	Kernel Time	User Time	Name
896	12:10:12:48 	00:02:52 	00:02:44 	lsass.exe
```
`Running Time` is `DD:HH:MM:SS`. **`lsass.exe` / `winlogon.exe` running time yields the host's
boot time** — an independent clock for cross-checking (§4).

### 3.8 Macro analysis (the part nobody reads)
```
 sequence [LEFT CLICK] [LEFT CLICK] : interval distribution
    ^  42 events
  3 |                              X
  ...
  --+ -- + -- + ... > 140 ms
    0    5    10   15  ...  135
```
An ASCII histogram of inter-event intervals, 0–140 ms, one per observed key pair,
plus a final `Mouse down moves ( no recoil )` histogram over 0–150 px of movement.

Vendor-stated human baselines, which are directly usable as rule thresholds:

| Signal | Human limit per vendor |
|---|---|
| Double-click interval | No player sustains **< 80 ms** |
| Same-key double-press | No player sustains **< 100 ms** |
| Two-key order (e.g. Q+W) | Humans occasionally reverse the order; macros never do |
| No-recoil | Dense clusters of tiny downward moves, or few large-pixel moves |

The stated interpretation rule: *"the bigger and sharper the peak on the graph, the higher
the macro suspicion"*; a spread across 0–140 ms is normal human input. This is a
**parseable numeric distribution rendered as ASCII** — reconstructing it into real numbers
and scoring peak sharpness is one of the highest-value, lowest-cost features available.

### 3.9 Footer
```
Global log CRC: 51863537190742710a6e241149f66441e050afd053378f43d18d60aa248b096c
```

---

## 4. Timestamps — "checking the dates against the data"

This is the core of the requested product, and the samples show it works.

A single archive contains **six independent clocks**:

| # | Clock | Example (archive `40477d93`) | Zone |
|---|---|---|---|
| 1 | ZIP filename | `20240328_180012` | UTC |
| 2 | `SHAS2 mode started` | `2024-03-28 19:00:13` | UTC+1 (fixed across all 5 hosts) |
| 3 | `Monitor Started` | `2024/03/28 21:00:18` | Host local |
| 4 | Per-screenshot `at` | `2024/03/28 21:05:52` | Host local |
| 5 | ZIP entry mtime | `2024-03-28 18:05` | UTC |
| 6 | Taskbar clock **inside the JPEG** | `9:05 PM 3/28/2024` | Host local (OCR-able) |

Plus a seventh, derived: host **boot time** = capture time − `lsass.exe` running time.

**Worked example, verified.** For `010.JPG` in archive `40477d93`:
- log says `at 2024/03/28 21:05:52`
- ZIP entry mtime is `2024-03-28 18:05` → exactly **+3:00**
- the taskbar in the image itself reads `9:05 PM  3/28/2024` → **21:05 local**
- all three agree; host is UTC+3.

Four of the five hosts sit at UTC+3; one (`e9c215cb`) at UTC+1. Clock #2 was **+1:00 from
UTC on every host regardless of local zone**, which means it is *not* the host's local clock —
likely MOSS's network-synced time. That makes clock #2 a genuinely independent reference:
**a host that has moved its system clock will show a #2↔#3 delta that is not a whole-hour
timezone offset**, or an offset inconsistent with the rest of the archive.

Detections this enables:
- **System-clock manipulation** — #2 vs #3 delta is not a valid UTC offset, or shifts mid-session.
- **Log editing** — screenshot `at` timestamps disagree with ZIP entry mtimes.
- **Re-zipping / archive rebuild** — ZIP entry mtimes uniform, or newer than the log.
- **Recycled archive** — session date does not match the scheduled match date.
- **Late start / early stop** — session window does not cover the match window.
- **Coverage gaps** — screenshot gap spanning a round.
- **Impossible uptime** — session sits outside the boot-time-derived uptime window.

None of this requires ML. It is arithmetic over parsed fields, and it is the single most
defensible category of finding because the numbers either reconcile or they do not.

---

## 5. What the five sample archives actually reveal

Real findings from a real event — these validate the product thesis.

**A. Hardware fingerprint collision.** `60d8009d` and `5825d46d` share
`Sign ID1: 1434136903` but are different machines:

| | `60d8009d` | `5825d46d` |
|---|---|---|
| User | `szazi@NESKIN` | `GeeKay@DESKTOP-RLNAQE3` |
| GPU | RTX 3080 **Ti**, drv 31.0.15.5186 | RTX 3080, drv 31.0.15.3742 |
| Drive | WDC WDS480G2G0C | WD_BLACK SN770 1TB |
| Monitor EDID | `EBLAM00907SL0` | `EBB9N00443SL0` |
| RAM | 16243 MB | 16237 MB |
| Board / CPU | MSI B660M-P / i5-13400F | MSI B660M-P / i5-13400F |
| SteamId | 464348805 | 0 |

Same board model and same CPU model → **`Sign ID1` collides on near-identical builds.**
This matters enormously: a naive tool would report "same PC, two accounts — ban both."
The correct conclusion is a collision. **Identity must be a composite of monitor EDID
serial + drive serial + LAN/WAN IP + RAM + GPU + driver version, with `Sign ID1` as a
weak hint only.** Getting this wrong is how an anti-cheat tool falsely bans someone.

**B. Shared network.** Four of five hosts report public IP `90.148.144.xxx` and LAN
`192.168.100.x` — same venue or same connection. Innocuous at a LAN, serious in an
online match. The fifth reports `Net: 0.0.0.0` (adapter hidden or VPN) with a different
WAN. **Context determines meaning; the tool must ask the league which it was.**

**C. Injection whitelist in the game config.** Every R6 `GameSettings.ini` contains:
```ini
VulkanWhitelistedLayers=VK_LAYER_OW_OBS_HOOK;VK_LAYER_OW_OVERLAY
```
This is a **user-editable allowlist for code injected into the game process**. `OW_*` is
Overwolf. An unrecognised `VK_LAYER_*` entry here is a direct injection vector and is
trivially checkable against an allowlist. High value, near-zero cost.

**D. Environment red flags visible in one screenshot.** A single captured frame showed:
Discord with an active screen-share, the tournament's own stream open, webcam push URLs,
and `Riot Vanguard\vgtray.exe` running in the process list during an R6 session.
Second-monitor content is a genuine integrity surface (stream-sniping, coaching) and MOSS
captures it for free.

**E. Blank captures.** Frames of 39–42 KB against a ~150 KB median turned out to be bare
desktop wallpaper — no game, no taskbar, no icons. Alt-tab, a failed grab, or a
capture-evasion bypass. File size alone flags these.

**F. Weak identity binding.** `SteamId: 0` on one archive, absent entirely on another.
The archive cannot be tied to a game account without external correlation.

**G. Integrity is fully verifiable today.** `Zip CRC:` is **the SHA-256 of the file
contents** — recomputed and matched byte-for-byte on `010.JPG`. Every screenshot and
every captured config in the log can be independently verified right now. Files present
in the ZIP but absent from the log, or vice versa, are immediately detectable.

---

## 6. Per-game analysis

### 6.1 Rainbow Six Siege — the strong case

MOSS's best fit of the three, and what all the samples are.

- **Official stack:** BattlEye, plus Ubisoft's MouseTrap (targets input manipulation
  and XIM-style device translation), plus Y9/Y10-era hardening — Secure Boot, TPM 2.0,
  VBS/Core Isolation as cryptographic enforcement of the boot chain.
- **Config forensics:** MOSS captures `GameSettings.ini` for *every* profile GUID under
  `Documents\My Games\Rainbow Six - Siege\` — one archive had 11 distinct profiles, itself
  a signal (many accounts on one machine). Fields worth checking: `VulkanWhitelistedLayers`,
  `MouseSensitivityMultiplierUnit` (players edit this beyond the in-game range — legal but
  tell-tale), `DefaultFOV`, `RefreshRate` vs the declared monitor EDID, `GPUAdapterInfo`
  vs the logged GPU, and `Console=1`.
- **Renderer nuance:** the game process was `RainbowSix_Vulkan.exe` while capture ran
  through `DX11`/DXGI desktop duplication. Vulkan-rendered frames reaching a DXGI grab is
  normal, but it is also the seam where black-frame and capture-evasion bypasses live.
- **HUD is OCR-rich:** `FPS`, `GPU`, `PING`, `VERSION: 69366124`, round timer, score,
  operator select, map name — enough to reconstruct a match timeline from images alone
  and correlate it against the official match record.

### 6.2 Valorant — MOSS is the wrong primary tool

- **Vanguard is ring-0 and loads at boot.** It refuses to run alongside a long list of
  drivers, overlays and monitoring tools, and actively blocks monitoring software.
  A user-mode screenshot grabber against a Vanguard-protected process is unreliable and
  can yield black frames.
- Vanguard now supports an on-demand mode (off when not playing), which changes when it
  is even loaded.
- **Consequence:** for Valorant the evidence base shifts to Riot's own artifacts — match
  IDs, in-client match history, observer/VOD recordings. MOSS degrades to "what else was
  running on this box," which is still useful but is not the centre of the case.
- **Design implication:** the app must be **evidence-source-agnostic per game**, not
  MOSS-only. Do not build a Valorant workflow that assumes a usable MOSS archive exists.

### 6.3 Call of Duty — viable but fragmented

- **Official stack:** RICOCHET, kernel driver since MW2 (2022), with seasonal detection
  updates and an in-game community report system.
- Community/GameBattles-style ladders do use MOSS for CoD on PC, and MOSS lists multiple
  CoD titles.
- **Complications:** heavy console and crossplay presence (MOSS is Windows-only and
  irrelevant for console entries); executable names, install paths and anti-cheat
  components change per title and per season, so game detection and any hash baseline
  must be **title- and season-versioned**, not hardcoded.
- CoD's cheat ecosystem skews toward DMA and hardware-input devices — precisely the
  category MOSS cannot see (§7).

### 6.4 Summary

| | Rainbow Six | Valorant | Call of Duty |
|---|---|---|---|
| MOSS practical? | **Yes** | Unreliable (Vanguard) | Yes, PC only |
| Official AC | BattlEye + MouseTrap | Vanguard (ring-0) | RICOCHET (kernel) |
| Config capture value | **High** (`GameSettings.ini`) | Low | Medium, version-churny |
| HUD OCR value | **High** | Medium | Medium |
| Build order | **1st — the wedge** | 3rd, different evidence model | 2nd |

---

## 7. Limitations that must be stated in every report

Publicly documented bypasses and blind spots. The product's credibility depends on
saying these out loud rather than implying coverage it does not have.

1. **Process list is a single snapshot at game start.** Anything started later is invisible.
2. **The log is written to disk, then zipped.** Hooking that window lets the log be edited
   before packaging.
3. **Screenshot-timing evasion.** Detect the capture, hide the overlay, allow the shot.
4. **DMA / second-PC cheats.** A separate machine reading memory over PCIe leaves nothing
   on the monitored host.
5. **Hardware input injection** (KMBox, Arduino, XIM-class devices) presents as a normal
   HID device; MOSS sees a mouse.
6. **Second-device ESP** — a phone or tablet is entirely out of frame.
7. **User-mode, run by the suspect, on their own machine.** Everything is attacker-controlled.

**Therefore: the application must never output a verdict.** It outputs a prioritised,
evidence-linked anomaly dossier with confidence levels and, for every finding, the
benign explanation alongside the suspicious one. A human decides. This is a legal and
reputational constraint as much as a technical one — the output of this tool will be
used to accuse named people of cheating.

---

## 8. Privacy note

These archives contain, in plaintext: Windows usernames, hostnames, LAN and partial WAN
IPs, monitor EDID serials, drive serials, motherboard identifiers, full process paths
including personal folder names, Steam IDs, and screenshots containing Discord messages,
real names and webcam URLs. Any product handling them needs a retention policy, access
control, redaction for reports shared beyond admins, and a documented lawful basis for
processing. Treat these five sample archives as personal data.

---

## Sources

- [Moss — nohope.eu](https://nohope.eu/)
- [Quick use | Moss](https://nohope.eu/quick-use/)
- [Log analysis | Moss](https://nohope.eu/log-analysis/)
- [Moss macro control | Moss](https://nohope.eu/moss-macro-control/)
- [Moss Automation | Moss](https://nohope.eu/moss-automation/)
- [MOSS Anti-Cheat for FPS — technojs](https://www.technojs.com/moss-anti-cheat-for-fps/68)
- [Download Moss, Anti Cheat Software by Nohope — coderpradip](https://coderpradip.com/blog/moss/)
- [How to Bypass MOSS Anticheat — GuidedHacking](https://guidedhacking.com/threads/how-to-bypass-moss-anticheat.19662/)
- [MOSS Screenshot bypass — MPGH](https://www.mpgh.net/forum/showthread.php?t=1195772)
- [Rainbow Six Siege anti-cheat status update: Data bans, Mousetrap — Sportskeeda](https://www.sportskeeda.com/esports/rainbow-six-siege-anti-cheat-status-update-data-bans-mousetrap)
- [R6 Siege Y9S4 Player Protection update — Sportskeeda](https://sportskeeda.com/esports/rainbow-six-siege-y9s4-player-protection-update-anti-cheat-anti-toxicity-systems-changes-explained)
- [Rainbow Six Siege Community Checkpoint: New Anti-Cheat Measures — Ubisoft](https://news.ubisoft.com/en-us/article/4CHPYPn72TtqMJoYJRUU2m/rainbow-six-siege-community-checkpoint-new-anticheat-measures-balancing-updates-more)
- [Riot Vanguard — Wikipedia](https://en.wikipedia.org/wiki/Riot_Vanguard)
- [Vanguard On-Demand — Riot Games](https://www.riotgames.com/en/news/vanguard-on-demand)
- [Kernel-Level Anti-Cheat Explained: Vanguard vs Ricochet — Game Modifier](https://gamemodifier.com/blog/kernel-anticheat-explained-vanguard-ricochet)
- [RICOCHET Anti-Cheat — Call of Duty](https://www.callofduty.com/ricochet)
- [Valorant vs. Call of Duty Anti Cheat — GGBoost](https://ggboost.com/blog/post/valorant-vs-cod-anti-cheat)
- [Overwolf Developers changelog](https://dev.overwolf.com/ow-native/getting-started/changelog/ow-changelog/)
- ['Rainbow Six Siege' Scandal Shows Cheating Still Undermines eSports — Vice](https://motherboard.vice.com/en_us/article/aek378/rainbow-six-siege-esports-cheating)
