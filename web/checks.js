/**
 * The rules. Plain arithmetic and string matching — no AI, no network.
 *
 * Each check returns findings shaped:
 *   { rule, title, severity, what, why, benign }
 *
 * `what` is the evidence (what was actually measured), `why` is the rule that
 * fired, `benign` is the innocent reading of the same evidence. The benign line
 * is not politeness: this output gets used to accuse named people, and a
 * finding nobody can argue with is not evidence.
 *
 * Severity: critical > high > medium > low. Anything below `low` is context and
 * does not make an archive "not clean".
 */

import { sessionBounds } from './moss.js';

const MIN = 60000;

// Real UTC offsets are whole hours, or :30/:45 in a handful of zones.
const VALID_OFFSETS = [];
for (let m = -12 * 60; m <= 14 * 60; m += 15) {
  if (m % 60 === 0 || Math.abs(m % 60) === 30 || Math.abs(m % 60) === 45) VALID_OFFSETS.push(m);
}

const isValidOffset = (mins, tol = 3) => VALID_OFFSETS.some((c) => Math.abs(mins - c) <= tol);
const nearestOffset = (mins) => VALID_OFFSETS.reduce((a, b) => (Math.abs(mins - b) < Math.abs(mins - a) ? b : a));
const median = (xs) => {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
};

export const fmtTime = (ms) => (ms === null || ms === undefined ? '—' : new Date(ms).toISOString().replace('T', ' ').slice(0, 19));
export const fmtOffset = (mins) => {
  if (mins === null || mins === undefined) return '—';
  const t = Math.round(mins), sign = t < 0 ? '-' : '+';
  return `UTC${sign}${String(Math.floor(Math.abs(t) / 60)).padStart(2, '0')}:${String(Math.abs(t) % 60).padStart(2, '0')}`;
};
export const fmtDuration = (s) => {
  if (s === null || s === undefined) return '—';
  s = Math.round(Math.abs(s));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (d) return `${d}d ${h}h ${m}m`;
  if (h) return `${h}h ${m}m ${sec}s`;
  if (m) return `${m}m ${sec}s`;
  return `${sec}s`;
};
const fmtBytes = (b) => (b > 1024 * 1024 ? `${(b / 1048576).toFixed(1)} MB` : `${Math.round(b / 1024)} KB`);

/** Build the clock model: the host's UTC offset measured from the archive itself. */
export function buildClocks(session, entries) {
  const model = { samples: [], offsetMinutes: null, spreadMinutes: 0, offsetValid: false, bootTime: null, uptimeS: null, uptimeSource: null };
  const byName = new Map(entries.map((e) => [e.name.split('/').pop(), e]));

  for (const shot of session.screenshots) {
    const entry = byName.get(shot.file);
    if (!shot.at || !entry || entry.mtime === null) continue;
    model.samples.push({ file: shot.file, local: shot.at, zip: entry.mtime, delta: (shot.at - entry.mtime) / MIN });
  }
  const deltas = model.samples.map((s) => s.delta);
  if (deltas.length) {
    model.offsetMinutes = median(deltas);
    model.spreadMinutes = Math.max(...deltas) - Math.min(...deltas);
    model.offsetValid = isValidOffset(model.offsetMinutes);
  }
  if (session.headerStartedAt && session.monitorStartedAt) {
    model.networkToLocal = (session.monitorStartedAt - session.headerStartedAt) / MIN;
    if (model.offsetMinutes !== null) model.impliedNetworkOffset = model.offsetMinutes - model.networkToLocal;
  }
  const bounds = sessionBounds(session);
  model.start = bounds.start;
  model.end = bounds.end;
  const statsAt = bounds.end ?? bounds.start;
  if (statsAt) {
    for (const name of ['lsass.exe', 'winlogon.exe', 'services.exe', 'csrss.exe']) {
      const stat = session.processStats.find((s) => s.name.toLowerCase() === name);
      if (stat && stat.runningTimeS) {
        model.uptimeS = stat.runningTimeS;
        model.uptimeSource = stat.name;
        model.bootTime = statsAt - stat.runningTimeS * 1000;
        break;
      }
    }
  }
  return model;
}

/**
 * Run every check.
 * @param {object} ctx {session, entries, hashes, sizes, rules}
 * @returns {Array} findings
 */
export function runChecks(ctx) {
  const out = [];
  const add = (f) => out.push(f);
  integrity(ctx, add);
  clocks(ctx, add);
  zipStructure(ctx, add);
  processes(ctx, add);
  configs(ctx, add);
  captures(ctx, add);
  behaviour(ctx, add);
  return out.sort((a, b) => rank(b.severity) - rank(a.severity));
}

const rank = (s) => ({ critical: 4, high: 3, medium: 2, low: 1 }[s] ?? 0);

// ---------------------------------------------------------------- integrity

function integrity({ session, entries, hashes }, add) {
  const logged = new Map();
  for (const s of session.screenshots) if (s.crc) logged.set(s.file, { crc: s.crc, line: s.line });
  for (const c of session.capturedFiles) if (c.crc) logged.set(c.file, { crc: c.crc, line: c.line });

  const actual = new Map(entries.map((e) => [e.name.split('/').pop(), hashes.get(e.name)]));
  const mismatched = [], missing = [];
  let verified = 0;

  for (const [name, { crc }] of logged) {
    const got = actual.get(name);
    if (!got) { missing.push(name); continue; }
    if (crc.length !== 64) continue;
    if (got === crc) verified++;
    else mismatched.push({ name, expected: crc, got });
  }

  const zipNames = entries.map((e) => e.name.split('/').pop())
    .filter((n) => !/\.log$/i.test(n) && !/^(thumbs\.db|\.ds_store)$/i.test(n));
  const extra = zipNames.filter((n) => !logged.has(n));

  if (mismatched.length) {
    add({
      rule: 'file-hash-mismatch',
      title: 'A file in the archive is not the file MOSS recorded',
      severity: 'critical',
      what: mismatched.slice(0, 8).map((m) => `${m.name}\n  log says  ${m.expected}\n  file is   ${m.got}`).join('\n')
        + (mismatched.length > 8 ? `\n…and ${mismatched.length - 8} more` : ``)
        + `\n\n${verified} other file(s) verified correctly.`,
      why: 'MOSS writes the SHA-256 of every file it packages into the log as "Zip CRC:". Each file was re-hashed here and compared. A mismatch means the content changed after MOSS wrote it. This is arithmetic on the file you uploaded — it needs no interpretation.',
      benign: 'Re-zipping the archive with a tool that rewrites files, antivirus quarantining and restoring a capture, or a partial upload all produce this. None of those is the player editing evidence — but all of them mean this is no longer the archive MOSS produced, so it cannot be relied on either way.',
    });
  }
  if (missing.length) {
    add({
      rule: 'file-missing',
      title: 'The log lists files that are not in the archive',
      severity: 'critical',
      what: missing.slice(0, 20).join(', ') + (missing.length > 20 ? ` …and ${missing.length - 20} more` : ''),
      why: 'MOSS logged these files with their hashes, so they existed when the session ended. They are not in the ZIP. Removing captures is the most direct way to hide what was on screen, and MOSS\'s own instructions tell players not to remove files.',
      benign: 'A failed or truncated upload, or an archive re-saved by a tool that dropped entries, looks identical. Ask for a fresh copy of the original ZIP before concluding anything — a complete re-supply settles it.',
    });
  }
  if (extra.length) {
    add({
      rule: 'file-not-in-log',
      title: 'The archive contains files the log never mentions',
      severity: 'high',
      what: extra.slice(0, 20).join(', ') + (extra.length > 20 ? ` …and ${extra.length - 20} more` : ''),
      why: 'MOSS lists every file it packages. A file in the ZIP with no log record was added after MOSS finished, which means the archive was opened and rebuilt.',
      benign: 'Some archive tools inject metadata files. Check the names: an added JPEG is a very different matter from an added .DS_Store.',
    });
  }

  const indices = session.screenshots.map((s) => s.index).filter((i) => i !== null).sort((a, b) => a - b);
  if (indices.length > 1) {
    const gaps = [];
    for (let n = indices[0]; n <= indices[indices.length - 1]; n++) if (!indices.includes(n)) gaps.push(n);
    if (gaps.length) {
      add({
        rule: 'sequence-gap',
        title: 'Gap in the screenshot numbering',
        severity: 'high',
        what: `Missing capture numbers: ${gaps.slice(0, 15).join(', ')}${gaps.length > 15 ? ' …' : ''}\nRange ${indices[0]}–${indices[indices.length - 1]}, ${indices.length} present, ${gaps.length} missing.`,
        why: 'MOSS numbers captures sequentially from the session start. A number absent from the log means a capture record that existed is no longer there.',
        benign: 'A capture that failed at the moment MOSS tried to take it (a full-screen mode change, a driver reset) can consume a number without producing a file. Cross-check against the timeline: a gap that also shows a long time interval matters more than one that does not.',
      });
    }
  }

  if (session.lines.length && !session.globalCrc) {
    add({
      rule: 'log-truncated',
      title: 'The log has no closing line, so it is incomplete',
      severity: 'high',
      what: `The log ends at line ${session.lines.length}: "${(session.lines[session.lines.length - 1]?.raw || '').trim().slice(0, 80)}"`,
      why: 'MOSS closes every log with "Global log CRC:". Its absence means the log was truncated or edited.',
      benign: 'A session that ended in a crash, a forced shutdown or a power cut leaves the log unfinished through nobody\'s fault. That is still an incomplete record — re-submit rather than treating it as evidence either way.',
    });
  }
  if (!session.headerStartedAt) {
    add({
      rule: 'log-header-missing',
      title: 'The log has no session header',
      severity: 'high',
      what: 'No "SHAS2 mode started" line was found.',
      why: 'The header carries MOSS\'s network-synced start time. Without it the network-clock cross-check cannot run, which removes the main defence against a manipulated system clock.',
      benign: 'An unrecognised MOSS version may word the header differently. Check the unrecognised-lines list at the bottom of this report before treating it as removal.',
    });
  }
  if (verified && !mismatched.length && !missing.length && !extra.length) {
    add({
      rule: 'all-files-verified',
      title: `All ${verified} files match the hash MOSS recorded`,
      severity: 'info',
      what: `${verified} files re-hashed and compared against the log. All matched, and the file set reconciles both ways.`,
      why: 'Each file\'s SHA-256 was recomputed in your browser and compared with its "Zip CRC:" entry.',
      benign: 'This shows the archive was not modified after MOSS wrote it. It does not show the session itself was honest — a player can submit an untampered recording of a session in which they cheated.',
    });
  }
}

// ------------------------------------------------------------------- clocks

function clocks({ session, clockModel: m, rules }, add) {
  if (!m.samples.length) {
    if (session.screenshots.length) {
      add({
        rule: 'no-clock-samples', title: 'The host time zone could not be established', severity: 'medium',
        what: `${session.screenshots.length} captures in the log, but none could be paired with a ZIP entry timestamp.`,
        why: 'The host UTC offset comes from comparing each capture\'s local timestamp in the log with the same file\'s ZIP timestamp. Without a pair, every clock check is unavailable.',
        benign: 'An archive rebuilt by a tool that discards entry timestamps loses this signal without anyone targeting it. Treat the clock checks as unrun, not as passed.',
      });
    }
    return;
  }

  const offset = m.offsetMinutes;
  if (!m.offsetValid) {
    const near = nearestOffset(offset);
    add({
      rule: 'invalid-utc-offset',
      title: 'The host clock is not set to a real time zone',
      severity: 'high',
      what: `Captures run ${offset >= 0 ? '+' : ''}${offset.toFixed(1)} min from the archive's UTC timestamps — that is ${fmtOffset(offset)}.\nThe nearest real offset is ${fmtOffset(near)}, ${Math.abs(offset - near).toFixed(1)} min away.\nMeasured across ${m.samples.length} captures.`,
      why: 'Every capture\'s local timestamp was compared with the same file\'s ZIP timestamp, which MOSS writes in UTC. Every real UTC offset is a whole hour, or :30/:45 in a few zones. This one is not, so the log times and the file times cannot both be honest.',
      benign: 'A machine whose clock drifted badly with no time sync, or a VM with a misconfigured clock, reads the same way with no intent behind it. This says the clocks do not reconcile — not who moved them.',
    });
  }

  const drift = rules?.clocks?.drift_tolerance_minutes ?? 2;
  if (m.spreadMinutes > drift) {
    const worst = m.samples.reduce((a, b) => (Math.abs(b.delta - offset) > Math.abs(a.delta - offset) ? b : a));
    add({
      rule: 'offset-drift',
      title: 'The host clock changed during the session',
      severity: 'high',
      what: `The capture-to-UTC offset moves by ${m.spreadMinutes.toFixed(1)} min across the session (tolerance ${drift} min).\nLargest deviation at ${worst.file}: log ${fmtTime(worst.local)} vs ZIP ${fmtTime(worst.zip)}.`,
      why: 'The difference between a capture\'s local timestamp and its UTC file timestamp should be constant for the whole recording. A clock that moves mid-recording changes what every timestamp in this archive means.',
      benign: 'A single time-sync correction on a machine whose clock had drifted produces one step of seconds to minutes and is entirely normal. A one-hour step at a daylight-saving boundary is also legitimate — check the session date against the local DST change first.',
    });
  }

  const expected = rules?.clocks?.network_clock_expected_offset_minutes ?? 60;
  const tol = rules?.clocks?.network_clock_tolerance_minutes ?? 5;
  if (m.impliedNetworkOffset !== undefined && Math.abs(m.impliedNetworkOffset - expected) > tol) {
    add({
      rule: 'network-clock-disagrees',
      title: "MOSS's own start time disagrees with the host clock",
      severity: 'high',
      what: `Session header (MOSS network time): ${fmtTime(session.headerStartedAt)}\nMonitor Started (host local):    ${fmtTime(session.monitorStartedAt)}\nHost offset measured from this archive: ${fmtOffset(offset)}\nThat makes the header clock ${fmtOffset(m.impliedNetworkOffset)}, where it should be ${fmtOffset(expected)}.`,
      why: 'MOSS writes its session header from a network-synced clock the player does not control. Moving the system clock moves the log times, the file times and the archive filename together — but not that header. The gap between them is the signal.',
      benign: 'The UTC+1 behaviour of MOSS\'s clock is an observation from real archives, not vendor documentation: a different MOSS build, or a host that could not reach the time source, may differ legitimately. Read this alongside the offset and drift results rather than on its own.',
    });
  }

  const times = session.screenshots.filter((s) => s.at).map((s) => [s.file, s.at]);
  const back = [];
  for (let i = 1; i < times.length; i++) if (times[i][1] < times[i - 1][1]) back.push(`${times[i - 1][0]} → ${times[i][0]}: ${fmtTime(times[i - 1][1])} → ${fmtTime(times[i][1])}`);
  if (back.length) {
    add({
      rule: 'time-goes-backwards',
      title: 'Capture timestamps go backwards',
      severity: 'high',
      what: back.slice(0, 8).join('\n') + (back.length > 8 ? `\n…and ${back.length - 8} more` : ''),
      why: 'Captures are written in order, so their timestamps must increase. A backwards step means the clock moved while MOSS was recording, or the log was reordered afterwards.',
      benign: 'A daylight-saving rollback or a time-sync correction during the session moves the clock backwards legitimately. The size of the step tells them apart: an hour at a known DST boundary is routine, a few minutes mid-match is not.',
    });
  }

  const bootTol = (rules?.clocks?.boot_time_tolerance_s ?? 900) * 1000;
  if (m.bootTime && m.start && m.start - m.bootTime < -bootTol) {
    add({
      rule: 'session-before-boot',
      title: 'The session started before the machine booted',
      severity: 'high',
      what: `${m.uptimeSource} had been running ${fmtDuration(m.uptimeS)} when MOSS wrote its statistics.\nThat puts boot at ${fmtTime(m.bootTime)}, but the session starts at ${fmtTime(m.start)}.`,
      why: 'A session cannot predate the boot of the machine that recorded it, so at least one of these clocks is wrong.',
      benign: 'The uptime process may have restarted, or the statistics may have been sampled at a different moment than assumed here. Windows fast startup and hibernation also distort uptime. Check the taskbar clock visible in the captures before relying on this.',
    });
  }

  const maxGap = rules?.session?.max_screenshot_gap_s ?? 300;
  const sorted = session.screenshots.filter((s) => s.at).map((s) => s.at).sort((a, b) => a - b);
  const gaps = [];
  for (let i = 1; i < sorted.length; i++) {
    const secs = (sorted[i] - sorted[i - 1]) / 1000;
    if (secs > maxGap) gaps.push({ from: sorted[i - 1], to: sorted[i], secs });
  }
  if (gaps.length) {
    const worst = gaps.reduce((a, b) => (b.secs > a.secs ? b : a));
    add({
      rule: 'capture-gap',
      title: 'Long gap with no captures',
      severity: 'medium',
      what: `${gaps.length} gap(s) longer than ${fmtDuration(maxGap)}. Longest: ${fmtDuration(worst.secs)} from ${fmtTime(worst.from)} to ${fmtTime(worst.to)}.`,
      why: 'MOSS captures roughly once a minute and randomises around it — real intervals run from a couple of seconds to about two minutes. A gap far outside that leaves a stretch of the session with no visual record at all.',
      benign: 'A capture MOSS could not take (exclusive full-screen transitions, a driver reset, a heavily loaded machine) stretches the interval with nobody doing anything. What matters is what the gap covers: over live play it is worth a question, in the pre-match lobby it is not.',
    });
  }
}

// ------------------------------------------------------------ zip structure

function zipStructure({ entries, rules }, add) {
  const stamped = entries.filter((e) => e.mtime !== null);
  if (stamped.length < (rules?.zip?.min_entries_for_structure_checks ?? 6)) return;

  const counts = new Map();
  for (const e of stamped) counts.set(e.mtime, (counts.get(e.mtime) || 0) + 1);
  const [topTime, topCount] = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];
  if (topCount / stamped.length >= (rules?.zip?.mtime_uniformity_ratio ?? 0.9)) {
    add({
      rule: 'uniform-mtimes',
      title: 'Every file in the archive has the same timestamp',
      severity: 'high',
      what: `${topCount} of ${stamped.length} entries are all stamped ${fmtTime(topTime)}.`,
      why: 'MOSS writes captures across the whole session, so file timestamps normally spread over its duration. One shared timestamp is the signature of a folder being re-zipped in a single operation.',
      benign: 'Some transfer paths — cloud sync, extract-and-recompress in a chat client, a mail gateway — rewrite timestamps without anyone intending to. Ask how the file reached you before treating it as deliberate.',
    });
  }

  const methods = new Map();
  for (const e of entries) methods.set(e.method, (methods.get(e.method) || 0) + 1);
  if (methods.size > 1) {
    add({
      rule: 'mixed-compression',
      title: 'The archive mixes compression methods',
      severity: 'medium',
      what: [...methods.entries()].map(([m, c]) => `method ${m}: ${c} entries`).join(', '),
      why: 'MOSS writes every file with the same compression method. A mixture means files were added or replaced by a different tool.',
      benign: 'Archive utilities skip compression for files they judge incompressible, so a mixture can come from an innocent repack. It still means this is not the file MOSS wrote.',
    });
  }
}

// ---------------------------------------------------------------- processes

const CATEGORY_INFO = {
  remote_access: {
    title: 'Remote-access software was running', severity: 'high',
    why: 'Remote-access software lets a second person drive or watch this machine from elsewhere. It is one of the few forms of outside assistance that leaves a clear trace in a MOSS archive, and admins rarely check for it.',
    benign: 'Plenty of people install AnyDesk, Parsec or TeamViewer for work or to help family and leave them running at boot. Running is not connected: without a session log from the tool itself there is no evidence anyone was connected during the match.',
  },
  macro_suite: {
    title: 'Macro or input-remapping software was running', severity: 'medium',
    why: 'Vendor macro suites and remapping tools can replay recorded input sequences. Presence is not misuse, but it is the context in which the input timing below should be read.',
    benign: 'G HUB, Synapse and iCUE are required to configure ordinary gaming mice and keyboards, including DPI and lighting. This is close to universal among competitive players and means nothing on its own.',
  },
  virtual_machine: {
    title: 'Virtual machine or sandbox software was running', severity: 'high',
    why: 'A session recorded inside a virtual machine is not a recording of the machine that played, and VM artefacts also indicate the sandbox setups used to hide cheat software from inspection.',
    benign: 'Guest tools also appear on machines that merely have virtualisation software installed, and some enterprise agents look similar. Confirm against the hardware list before treating this as a VM session.',
  },
  spoofer_or_cleaner: {
    title: 'Hardware-ID spoofing or trace-cleaning tools were running', severity: 'high',
    why: 'Spoofers and trace cleaners exist to defeat exactly the identity and history checks a ban relies on. There is no ordinary competitive use for them.',
    benign: 'A few names in this category collide with legitimate disk and BIOS utilities. Check the full path and publisher before concluding anything.',
  },
  debugger_or_memory_tool: {
    title: 'A debugger or memory-editing tool was running', severity: 'high',
    why: 'These read and write another process\'s memory — the foundation of most internal cheats.',
    benign: 'Developers, modders and QA staff run these for their jobs. Ask before assuming.',
  },
  overlay_or_injector: {
    title: 'An overlay or injection framework was running', severity: 'low',
    why: 'Overlay frameworks inject code into the game process. That is how they draw, and it is also the mechanism a cheat overlay uses.',
    benign: 'Discord, Steam, OBS, GeForce Experience and Overwolf all do this as a matter of course. Background noise on almost every gaming PC.',
  },
};

function processes({ session, rules }, add) {
  if (!session.processes.length) return;
  const cats = rules?.environment?.categories ?? {};

  for (const [key, names] of Object.entries(cats)) {
    if (key === 'capture_or_share') continue; // pure context, not a finding
    const set = new Set(names.map((n) => String(n).toLowerCase()));
    const hits = session.processes.filter((p) => set.has(p.name.toLowerCase()));
    if (!hits.length) continue;
    const info = CATEGORY_INFO[key] || { title: `Flagged software: ${key}`, severity: 'medium', why: 'Matched the league rule pack\'s name list for this category.', benign: 'Presence of software is not use of software. Establish whether it was used during the match before treating this as more than context.' };
    add({
      rule: `process-${key.replace(/_/g, '-')}`,
      title: info.title,
      severity: info.severity,
      what: hits.map((p) => `${p.name}\n  ${p.path}\n  ${p.author ? 'signed by ' + p.author : 'UNSIGNED'}`).join('\n'),
      why: info.why + ' Note: MOSS snapshots the process list once, at game start — this is what was running at that moment only.',
      benign: info.benign,
    });
  }

  const bad = new Set((rules?.environment?.known_bad_sha256 ?? []).map((h) => String(h).toLowerCase()));
  const badHits = session.processes.filter((p) => bad.has(p.sha256));
  if (badHits.length) {
    add({
      rule: 'known-bad-hash', title: 'A process matches a known-bad hash', severity: 'critical',
      what: badHits.map((p) => `${p.name}\n  ${p.sha256}\n  ${p.path}`).join('\n'),
      why: 'The SHA-256 MOSS recorded for these processes appears in the configured known-bad list. The match is on file contents, so a renamed copy still matches.',
      benign: 'The list is only as good as its curation — a mis-entered or over-broad hash produces a false hit. Confirm the entry\'s provenance before acting.',
    });
  }

  const ignore = (rules?.environment?.unsigned_ignore ?? []).map((f) => String(f).toLowerCase());
  const unsigned = session.processes.filter((p) => !p.author && !ignore.some((f) => p.path.toLowerCase().includes(f)));
  if (unsigned.length) {
    add({
      rule: 'unsigned-process', title: `${unsigned.length} unsigned executable(s) were running`, severity: 'medium',
      what: unsigned.slice(0, 15).map((p) => `${p.name}  —  ${p.path}`).join('\n') + (unsigned.length > 15 ? `\n…and ${unsigned.length - 15} more` : ''),
      why: 'MOSS records the code-signing publisher of every process it can. No publisher means the binary is unsigned. Cheat software is almost never signed.',
      benign: 'A great deal of ordinary software is unsigned too — indie games, hobby utilities, portable tools, self-built software, many launchers. On a typical gaming PC a handful is normal. Look at the paths, not the count.',
    });
  }

  const frags = (rules?.environment?.suspicious_path_fragments ?? []).map((f) => String(f).toLowerCase());
  const fromTemp = session.processes.filter((p) => frags.some((f) => p.path.toLowerCase().includes(f)));
  if (fromTemp.length) {
    add({
      rule: 'executed-from-temp', title: 'Executables were running from temporary or download folders', severity: 'medium',
      what: fromTemp.slice(0, 15).map((p) => `${p.name}  —  ${p.path}`).join('\n'),
      why: 'Software installed normally runs from Program Files or a game library. Running from %TEMP%, Downloads or the Desktop is the pattern of something downloaded and executed directly, which is how most cheat loaders arrive.',
      benign: 'Installers, updaters, launchers and portable apps legitimately run from these folders — as does anything downloaded and never moved. Read the signature and the name together with the path.',
    });
  }

  // Duplicate executables: a classic way to hide a cheat behind a trusted name.
  const byName = new Map();
  for (const p of session.processes) {
    const key = p.name.toLowerCase();
    if (!byName.has(key)) byName.set(key, []);
    byName.get(key).push(p.path);
  }
  const dupes = [...byName.entries()]
    .filter(([, paths]) => new Set(paths.map((x) => x.toLowerCase())).size > 1)
    .sort((a, b) => b[1].length - a[1].length);
  if (dupes.length) {
    add({
      rule: 'duplicate-process', title: 'The same executable name is running from different paths', severity: 'medium',
      what: dupes.slice(0, 10).map(([name, paths]) => `${name} (${paths.length})\n${paths.map((p) => '  ' + p).join('\n')}`).join('\n\n'),
      why: 'Naming a cheat after trusted software and running it from somewhere else is a standard way to hide it. Two different paths for one well-known executable name is worth a look.',
      benign: 'Multiple installs of the same launcher, an updater running from a staging folder, or several copies of a runtime all do this routinely. Compare the paths: one inside Program Files and one in a user folder is more interesting than two system paths.',
    });
  }

  const expectDefender = rules?.environment?.expect_defender;
  const defender = session.hardware.windowsDefender;
  if (expectDefender && defender && !defender.toLowerCase().includes(String(expectDefender).toLowerCase())) {
    add({
      rule: 'defender-disabled', title: 'Windows Defender was not enabled', severity: 'low',
      what: `MOSS recorded Windows Defender as "${defender}".`,
      why: 'Cheat software is routinely detected as malware, so turning off real-time protection is a common prerequisite for running it.',
      benign: 'Third-party antivirus disables Defender by design, and plenty of players turn it off for performance or because it quarantines their games. Very common, very weak on its own.',
    });
  }

  const expectRealOs = rules?.environment?.expect_real_os;
  const realOs = session.hardware.realOs;
  if (expectRealOs && realOs && !realOs.includes(expectRealOs)) {
    add({
      rule: 'real-os-mismatch', title: "MOSS's OS check did not report a normal Windows install", severity: 'high',
      what: `"Real OS" reads "${realOs}", expected "${expectRealOs}". Reported OS: ${session.hardware.osVersion || 'unknown'}.`,
      why: 'MOSS cross-checks the reported OS against what it observes — its own guard against a spoofed or virtualised environment. A different value means that check did not come back normal.',
      benign: 'A Windows build MOSS does not recognise (an Insider build, a release newer than the MOSS version, a heavily customised install) produces an unexpected string with no deception involved.',
    });
  }
}

// ------------------------------------------------------------------ configs

function configs({ configs: files, rules }, add) {
  if (!files || !files.size) return;
  const allow = new Set((rules?.config?.vulkan_layer_allowlist ?? []).map((l) => String(l).toLowerCase()));
  const unknown = [];
  const ranges = rules?.config?.numeric_ranges ?? {};
  const outOfRange = [];
  const flagKeys = rules?.config?.flag_keys ?? {};
  const flagsOn = [];

  for (const [name, text] of files) {
    const values = new Map();
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(/^\s*([^=;#[][^=]*?)\s*=\s*(.*?)\s*$/);
      if (m) values.set(m[1].trim(), m[2].trim());
    }
    const layers = values.get('VulkanWhitelistedLayers');
    if (layers) {
      for (const layer of layers.split(';').map((l) => l.trim()).filter(Boolean)) {
        if (!allow.has(layer.toLowerCase())) unknown.push(`${name}: ${layer}`);
      }
    }
    for (const [key, bounds] of Object.entries(ranges)) {
      if (!values.has(key) || !Array.isArray(bounds)) continue;
      const n = parseFloat(values.get(key));
      if (Number.isFinite(n) && (n < bounds[0] || n > bounds[1])) {
        outOfRange.push(`${name}: ${key} = ${values.get(key)} (expected ${bounds[0]}–${bounds[1]})`);
      }
    }
    for (const [key, expected] of Object.entries(flagKeys)) {
      if (values.get(key) === String(expected)) flagsOn.push(`${name}: ${key} = ${values.get(key)}`);
    }
  }

  if (unknown.length) {
    add({
      rule: 'unknown-vulkan-layer', title: 'An unrecognised Vulkan layer is whitelisted into the game', severity: 'high',
      what: unknown.join('\n'),
      why: '"VulkanWhitelistedLayers" is a player-editable list of code allowed to load inside the game process. The allowlist covers what appears on ordinary machines (Overwolf, Steam, GPU vendors). Anything else was added by someone, and is worth identifying precisely.',
      benign: 'Capture tools, monitoring overlays and vendor utilities all add layers legitimately, and the shipped allowlist is not exhaustive. Identify the layer\'s owning software first — then add it to your rule pack so it stops firing.',
    });
  }
  if (outOfRange.length) {
    add({
      rule: 'config-out-of-range', title: 'A game setting is outside the range the in-game menu allows', severity: 'medium',
      what: outOfRange.join('\n'),
      why: 'These keys hold values the settings screen cannot produce, which means the file was edited by hand or by a tool.',
      benign: 'Hand-editing sensitivity or FOV beyond the slider range is widespread and openly discussed, and these ranges are approximate and version-dependent. Check your own rules on config edits before treating it as a violation.',
    });
  }
  if (flagsOn.length) {
    add({
      rule: 'config-flag-enabled', title: 'A developer or debug flag is enabled in the game config', severity: 'low',
      what: flagsOn.join('\n'),
      why: 'Flags such as Console=1 expose developer functionality not reachable from the normal UI.',
      benign: 'Widely enabled for ordinary reasons — launch options copied from a guide, a troubleshooting step, a leftover from an older patch.',
    });
  }
  const threshold = rules?.config?.profile_count_review_threshold ?? 5;
  if (files.size >= threshold) {
    add({
      rule: 'many-profiles', title: `${files.size} game profiles on this machine`, severity: 'low',
      what: [...files.keys()].slice(0, 12).join(', '),
      why: 'MOSS captures one config per game profile it finds. A high count means many game accounts have been used on this machine.',
      benign: 'Shared family machines, LAN rigs, practice accounts and profiles left by old installs all inflate this innocently. This is context for account-sharing questions, not for cheating.',
    });
  }
}

// ----------------------------------------------------------------- captures

function captures({ session, entries, hashes, sizes, rules }, add) {
  const jpgs = entries.filter((e) => /\.jpe?g$/i.test(e.name));
  if (!jpgs.length) return;

  const sizeList = jpgs.map((e) => sizes.get(e.name) || 0);
  const mid = median(sizeList) ?? 0;
  const ratio = rules?.screenshots?.blank_frame_size_ratio ?? 0.4;
  const floor = rules?.screenshots?.blank_frame_min_median_bytes ?? 20000;

  if (mid >= floor) {
    const blank = jpgs.filter((e) => (sizes.get(e.name) || 0) < mid * ratio);
    if (blank.length) {
      add({
        rule: 'blank-frame', title: `${blank.length} capture(s) are far smaller than the rest`, severity: 'medium',
        what: blank.slice(0, 15).map((e) => `${e.name.split('/').pop()} — ${fmtBytes(sizes.get(e.name))} (median ${fmtBytes(mid)})`).join('\n'),
        why: 'JPEG size tracks image complexity. Frames at a fraction of the median have almost nothing in them — in real archives these turn out to be bare desktop wallpaper: no game, no taskbar, no icons. A capture with nothing in it records nothing about the match.',
        benign: 'Alt-tabbing to a plain desktop, a loading screen, a black transition between rounds, or a grab that landed while the screen was blanking all produce small frames. Open them — the answer is immediate, and this finding exists to tell you which ones to open.',
      });
    }
  }

  const byHash = new Map();
  for (const e of jpgs) {
    const h = hashes.get(e.name);
    if (!h) continue;
    if (!byHash.has(h)) byHash.set(h, []);
    byHash.get(h).push(e.name.split('/').pop());
  }
  const dupes = [...byHash.values()].filter((names) => names.length > 1);
  if (dupes.length) {
    add({
      rule: 'identical-frames', title: 'Byte-identical captures', severity: 'medium',
      what: dupes.slice(0, 10).map((names) => `${names.length} identical: ${names.join(', ')}`).join('\n'),
      why: 'Two captures taken at different moments of a live session are never byte-identical — JPEG encoding varies with the smallest change on screen. Identical files mean the same image was written twice: a frozen capture source, or a frame copied over another.',
      benign: 'A genuinely frozen screen — a hung game, a static loading screen, an idle desktop between rounds — produces identical grabs, as can a capture backend returning a cached frame.',
    });
  }
}

// ---------------------------------------------------------------- behaviour

function behaviour({ session, rules }, add) {
  const scored = session.histograms.filter((h) => h.reconstruction !== 'failed' && h.buckets.length);
  if (!scored.length) return;

  const minEvents = rules?.behaviour?.min_events_for_scoring ?? 25;
  const doubleMs = rules?.behaviour?.double_click_min_interval_ms ?? 80;
  const sameKeyMs = rules?.behaviour?.same_key_min_interval_ms ?? 100;
  const total = (h) => h.buckets.reduce((t, b) => t + b.count, 0);

  for (const h of scored) {
    if (h.kind !== 'interval' || h.unit !== 'ms' || total(h) < minEvents) continue;
    const keys = h.keys.map((k) => k.toUpperCase());
    const same = keys.length === 2 && keys[0] === keys[1];
    if (!same) continue;
    const limit = keys[0].includes('CLICK') ? doubleMs : sameKeyMs;
    const fast = h.buckets.filter((b) => b.lower < limit).reduce((t, b) => t + b.count, 0);
    const share = fast / total(h);
    if (fast && share >= 0.5) {
      add({
        rule: 'below-human-interval',
        title: 'Input repeats faster than a person can sustain',
        severity: 'medium',
        what: `${h.label}: ${fast} of ${total(h)} intervals (${Math.round(share * 100)}%) are under ${limit} ms.\nDistribution: ${h.buckets.filter((b) => b.count).map((b) => `${Math.round(b.lower)}${h.unit}×${b.count}`).join(', ')}\nReconstructed from the log's ASCII graph (${h.reconstruction}).`,
        why: `MOSS's own documentation states no player sustains a double-click under ${doubleMs} ms or a same-key repeat under ${sameKeyMs} ms. This distribution sits mostly below that floor.`,
        benign: 'This is corroborating evidence, never a conclusion. High-DPI mice, sensitive switches, a worn switch double-firing on its own, and the rapid-fire modes built into ordinary gaming peripherals all compress intervals with no macro involved.',
      });
    }
  }

  const reviewShare = rules?.behaviour?.peak_share_review_threshold ?? 0.6;
  for (const h of scored) {
    if (h.kind !== 'interval' || total(h) < minEvents) continue;
    const peak = Math.max(...h.buckets.map((b) => b.count));
    const share = peak / total(h);
    if (share >= reviewShare) {
      add({
        rule: 'sharp-interval-peak',
        title: 'Input timing is more consistent than human input is',
        severity: share >= (rules?.behaviour?.peak_share_high_threshold ?? 0.8) ? 'medium' : 'low',
        what: `${h.label}: ${Math.round(share * 100)}% of ${total(h)} events fall in a single timing bucket.\nDistribution: ${h.buckets.filter((b) => b.count).map((b) => `${Math.round(b.lower)}${h.unit}×${b.count}`).join(', ')}`,
        why: "MOSS's stated reading of these graphs is that the sharper the peak, the higher the macro suspicion, and that human input spreads across the whole range. This one does not spread.",
        benign: 'Corroborating only. A repeated in-game action with a fixed animation length produces a tight peak, and so does a small sample by chance.',
      });
    }
  }

  const px = rules?.behaviour?.no_recoil_small_move_px ?? 6;
  const limitShare = rules?.behaviour?.no_recoil_small_move_share ?? 0.85;
  for (const h of scored) {
    if (h.kind !== 'no_recoil' || total(h) < minEvents) continue;
    const small = h.buckets.filter((b) => b.lower <= px).reduce((t, b) => t + b.count, 0);
    const share = small / total(h);
    if (share >= limitShare) {
      add({
        rule: 'no-recoil-pattern', title: 'Downward mouse movement is dominated by tiny uniform steps', severity: 'medium',
        what: `${small} of ${total(h)} downward moves while firing are ${px} px or less (${Math.round(share * 100)}%).`,
        why: "MOSS records downward mouse movement during sustained fire — the pattern recoil control produces. The vendor's stated reading is that dense clusters of tiny movements are what scripted compensation looks like.",
        benign: 'The weakest class of finding here, and it must never stand alone. A player with very high DPI, or one who has drilled a weapon\'s pattern for years, produces small consistent corrections too.',
      });
    }
  }
}
