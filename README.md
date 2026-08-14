# samireader

Reads MOSS anti-cheat archives and produces a defensible, evidence-linked integrity
report for league admins — with timestamp reconciliation ("do the dates match the data?")
as the core.

Status: **research & planning.** No code yet.

## Documents

| Doc | Contents |
|---|---|
| [`docs/RESEARCH.md`](docs/RESEARCH.md) | What MOSS is, a reverse-engineered log grammar, the six-clock timestamp model, per-game analysis (Rainbow Six / Valorant / Call of Duty), findings from five real archives, and MOSS's documented blind spots |
| [`docs/PLAN.md`](docs/PLAN.md) | Positioning, three-tier finding model, feature set, architecture, phased roadmap, risks |
| [`docs/QUESTIONS.md`](docs/QUESTIONS.md) | Open questions, blocking ones first, with working assumptions marked |

## The short version

MOSS records competitive gaming sessions and packages screenshots, a system log and
captured game configs into a ZIP. It has no official analyser — admins review these by
hand, roughly an hour per match. This project builds the review layer.

Three things established from real archives:

1. **`Zip CRC:` in the log is the SHA-256 of the file contents** — verified by
   recomputation. Complete per-file tamper detection is implementable immediately.
2. **An archive contains six independent clocks** (ZIP filename, log header, monitor
   start, per-screenshot, ZIP entry mtimes, and the taskbar clock visible inside the
   screenshots), plus host boot time derived from process running times. They either
   reconcile or they do not.
3. **MOSS's `Sign ID1` hardware fingerprint collides** between physically different
   machines. Identity must be composite. Getting this wrong is how a tool falsely
   accuses someone.

The tool outputs a prioritised evidence dossier, never a verdict — MOSS is user-mode
software run by the suspect on their own machine, with publicly documented bypasses.
See [`docs/RESEARCH.md`](docs/RESEARCH.md) §7.
