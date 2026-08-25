/**
 * MOSS log parser — plain JavaScript, no dependencies, no network.
 *
 * Reads a MOSS Logfile.log into a structured object. It never decides what
 * anything means; that is checks.js. Unrecognised lines are kept with their
 * line numbers rather than dropped, because MOSS's format is undocumented and
 * drifts between versions — a rule that silently stops matching is worse than
 * one that visibly does not.
 *
 * Grammar reverse-engineered from real archives; see docs/RESEARCH.md §3.
 */

const TS = String.raw`\d{4}[/-]\d{2}[/-]\d{2}\s+\d{2}:\d{2}(?::\d{2})?`;

const RE = {
  header: new RegExp(String.raw`^\s*SHAS2? mode started at\s+(${TS})\s+for\s+(.+?)\s+on\s+(\S+)\s*$`, 'i'),
  ping: /^\s*ping:\s*(\d+)\s*ms\s*$/i,
  version: /^\s*version:\s*MOSS\s+([\d,.\s]+?)\s*$/i,
  os: /^\s*OS is\s+(.+?)\s*$/,
  realOs: /^\s*Real OS\s+(.+?)\s*$/,
  directx: /^\s*DirectX version is\s+(.+?)\s*$/,
  memory: /^\s*memory:\s*(\d+)\s*MB\s*$/i,
  physical: /^\s*Physical:\s*(.+?)\s*$/,
  signId: /^\s*Sign ID1:\s*(\S+)\s*$/,
  user: /^\s*User:\s*([^@]*?)(?:@(.+?))?\s*$/,
  drive: /^\s*Drive:\s*(.*?)\s*serial:\s*(.*?)\s*$/,
  net: /^\s*Net:\s*(\S+)(?:\s+Public:\s*(\S+))?\s*$/,
  video: /^\s*Video:\s*(.+?)\s*driver\s*:\s*(.*?)\s*$/,
  monitor: /^\s*Monitor:\s*(.*?)\s*serial:\s*(.*?)\s*$/,
  usb: /^\s*Usb:\s*(.+?)\s*$/,
  processor: /^\s*processor BIOS details\s+(\d+)\s*MHz\s*by\s*[\d.]+\s*\*\s*[\d.]+\.\s*(.+?)\s*$/,
  monitorStarted: new RegExp(String.raw`^\s*Monitor Started at\s+(${TS})\s*$`),
  defender: /^\s*Windows Defender:\s*(.+?)\s*$/,
  steamId: /^\s*SteamId:\s*(.*?)\s*$/,
  // MOSS writes SHAS2 in the corpus; older builds write SHA2. Accept both.
  process: /^\s*(\*)?SHAS?2:\s+([0-9a-fA-F]{32,64})\s+(?:Author:\s*(.*?)\s+)?process:\s*(.+?)\s*$/,
  gameDetected: /^\s*Game Detected\s*$/i,
  // Every record carrying a hash: screenshots and captured config files alike.
  fileRecord: /^(.*?)\bfile:\s*(.+?)\s*-\s*Zip CRC:\s*([0-9a-fA-F]{8,})\s*$/,
  captured: /^\s*captured:\s*(.*?)\s*$/,
  atTime: new RegExp(String.raw`\bat\s+(${TS})`),
  monIndex: /\(\s*Mon\s+(\d+)\s*\)/i,
  each: /\bEach\s+(\d+)\b/i,
  statsHeader: /^\s*Processes statistics\s*(?:ping:\s*(\d+))?\s*$/i,
  statsRow: /^\s*(\d+)\s*[\t ]\s*([\d:]+)\s*[\t ]\s*([\d:]+)\s*[\t ]\s*([\d:]+)\s*[\t ]\s*(.+?)\s*$/,
  globalCrc: /^\s*Global log CRC:\s*([0-9a-fA-F]+)\s*$/i,
  fileCheckStart: new RegExp(String.raw`^\s*FileCheck start for\s+(.+?)\s+at\s+(${TS})\s*:?\s*$`),
  sequence: /^\s*sequence\s+((?:\[[^\]]*\]\s*)+):\s*(.*?)\s*$/i,
  noRecoil: /^\s*Mouse down moves\s*\(\s*no recoil\s*\)\s*$/i,
  events: /(\d+)\s+events/,
  histRow: /^(\s*)(\d+)?\s*\|(.*)$/,
  labels: /^[\s\d]+$/,
  unit: />\s*(\d+)\s*(ms|px|us|s)\b/i,
};

/** Parse "2024/03/28 21:05:52" as a naive wall clock, held in UTC to avoid
 *  the reviewer's own timezone silently shifting the evidence. */
export function parseTime(text) {
  if (!text) return null;
  const m = String(text).trim().match(/^(\d{4})[/-](\d{2})[/-](\d{2})\s+(\d{2}):(\d{2})(?::(\d{2}))?/);
  if (!m) return null;
  return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
}

/** JSZip hands back a Date built in the browser's local zone. Recover the raw
 *  stored wall-clock numbers so the comparison does not depend on where the
 *  reviewer happens to be sitting. */
export function zipDateToNaive(d) {
  if (!d || isNaN(d.getTime())) return null;
  return Date.UTC(d.getFullYear(), d.getMonth(), d.getDate(),
                  d.getHours(), d.getMinutes(), d.getSeconds());
}

/** "12:10:12:48" (DD:HH:MM:SS) or "00:02:52" -> seconds. */
export function parseRunningTime(text) {
  const parts = String(text).trim().split(':');
  if (parts.length < 2 || parts.length > 4) return null;
  const nums = parts.map(Number);
  if (nums.some((n) => !Number.isFinite(n) || n < 0)) return null;
  const weights = { 4: [86400, 3600, 60, 1], 3: [3600, 60, 1], 2: [60, 1] }[nums.length];
  return nums.reduce((total, n, i) => total + n * weights[i], 0);
}

function reconstructHistogram(block, lineNumber) {
  const title = block[0] || '';
  const hist = {
    kind: 'unknown', label: title.trim(), keys: [], unit: 'ms',
    totalEvents: null, buckets: [], reconstruction: 'failed', line: lineNumber,
  };

  const seq = title.match(RE.sequence);
  if (seq) {
    hist.keys = [...seq[1].matchAll(/\[([^\]]*)\]/g)].map((m) => m[1].trim());
    hist.kind = 'interval';
    hist.label = 'sequence ' + hist.keys.map((k) => `[${k}]`).join(' ');
  } else if (RE.noRecoil.test(title)) {
    hist.kind = 'no_recoil';
    hist.label = 'Mouse down moves (no recoil)';
  }

  const rows = [];
  let labelRow = null;
  for (const line of block.slice(1)) {
    if (hist.totalEvents === null && !line.includes('|')) {
      const ev = line.match(RE.events);
      if (ev) { hist.totalEvents = +ev[1]; continue; }
    }
    const u = line.match(RE.unit);
    if (u) hist.unit = u[2].toLowerCase();
    const row = line.match(RE.histRow);
    if (row) {
      const bodyStart = row[0].indexOf('|') + 1;
      rows.push({ value: row[2] ? +row[2] : null, body: ' '.repeat(bodyStart) + row[3] });
      continue;
    }
    if (RE.labels.test(line) && line.trim()) {
      const found = [...line.matchAll(/\d+/g)].map((m) => [m.index, +m[0]]);
      if (!labelRow || found.length > labelRow.length) labelRow = found;
    }
  }

  if (!rows.length || !labelRow || labelRow.length < 2) return hist;

  // Rows are drawn top-down with descending counts; MOSS omits some labels.
  let inferred = false;
  const known = rows.map((r, i) => [i, r.value]).filter(([, v]) => v !== null);
  const levels = rows.map((r, i) => {
    if (r.value !== null) return r.value;
    inferred = true;
    const after = known.find(([j]) => j > i);
    if (after) return after[1] + (after[0] - i);
    const before = [...known].reverse().find(([j]) => j < i);
    return before ? Math.max(before[1] - (i - before[0]), 0) : 0;
  });

  const columnCounts = new Map();
  rows.forEach((row, i) => {
    for (let col = 0; col < row.body.length; col++) {
      if (row.body[col] !== ' ' && row.body[col] !== '\t') {
        columnCounts.set(col, Math.max(columnCounts.get(col) || 0, levels[i]));
      }
    }
  });
  if (!columnCounts.size) return hist;

  const spans = [];
  for (let i = 0; i < labelRow.length - 1; i++) {
    if (labelRow[i + 1][1] > labelRow[i][1]) spans.push(labelRow[i + 1][1] - labelRow[i][1]);
  }
  const step = spans.length ? Math.min(...spans) : null;

  const columnToValue = (col) => {
    for (let i = 0; i < labelRow.length - 1; i++) {
      const [c0, v0] = labelRow[i], [c1, v1] = labelRow[i + 1];
      if (col >= c0 && col <= c1) return c1 === c0 ? v0 : v0 + ((v1 - v0) * (col - c0)) / (c1 - c0);
    }
    const [cn1, vn1] = labelRow[labelRow.length - 2], [cn, vn] = labelRow[labelRow.length - 1];
    const slope = (vn - vn1) / Math.max(cn - cn1, 1);
    return vn + slope * (col - cn);
  };

  const buckets = new Map();
  for (const [col, count] of [...columnCounts.entries()].sort((a, b) => a[0] - b[0])) {
    let value = columnToValue(col);
    if (step) value = Math.round(value / step) * step;
    buckets.set(value, Math.max(buckets.get(value) || 0, count));
  }
  hist.buckets = [...buckets.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([lower, count]) => ({ lower, count }));

  const recovered = hist.buckets.reduce((t, b) => t + b.count, 0);
  const disagree = hist.totalEvents !== null && recovered !== hist.totalEvents;
  hist.reconstruction = disagree || inferred ? 'partial' : 'full';
  return hist;
}

function looksLikeHistogramBody(line) {
  if (!line.trim()) return true;
  if (line.includes('|') && RE.histRow.test(line)) return true;
  if (RE.events.test(line) && line.includes('^')) return true;
  if (RE.labels.test(line)) return true;
  return /^[\s\-+]{4,}/.test(line) && /^[-+ >0-9msuxp.]*$/.test(line.trim());
}

/** Parse the whole log. Never throws on malformed input. */
export function parseLog(text) {
  const session = {
    mossVersion: null, game: null, arch: null, headerStartedAt: null,
    monitorStartedAt: null, pingMs: null, gameDetected: false,
    hardware: { monitors: [], drives: [], video: [], usb: [] },
    processes: [], screenshots: [], capturedFiles: [], processStats: [],
    histograms: [], globalCrc: null, lines: [], unknownLines: [],
  };
  const hw = session.hardware;
  const lines = text.split(/\r?\n/);
  let inStats = false;
  let i = 0;

  const setKind = (n, raw, kind) => {
    session.lines.push({ number: n, raw, kind });
    if (kind === 'unknown') session.unknownLines.push({ number: n, raw });
  };

  while (i < lines.length) {
    const raw = lines[i];
    const n = i + 1;

    if (RE.sequence.test(raw) || RE.noRecoil.test(raw)) {
      const block = [raw];
      let j = i + 1, blanks = 0;
      while (j < lines.length) {
        const candidate = lines[j];
        if (RE.sequence.test(candidate) || RE.noRecoil.test(candidate)) break;
        if (!candidate.trim()) { if (++blanks > 1) break; block.push(candidate); j++; continue; }
        if (!looksLikeHistogramBody(candidate)) break;
        blanks = 0; block.push(candidate); j++;
      }
      while (block.length && !block[block.length - 1].trim()) block.pop();
      session.histograms.push(reconstructHistogram(block, n));
      for (let k = 0; k < Math.max(block.length, 1); k++) setKind(n + k, lines[i + k], 'histogram');
      i += Math.max(block.length, 1);
      continue;
    }

    setKind(n, raw, classify(raw, n));
    i++;
  }

  session.unknownLines = session.lines.filter((l) => l.kind === 'unknown');
  return session;

  function classify(raw, n) {
    if (!raw.trim()) return 'blank';
    let m;

    if (inStats) {
      if ((m = raw.match(RE.statsRow))) {
        session.processStats.push({
          pid: +m[1], name: m[5],
          runningTimeS: parseRunningTime(m[2]),
          kernelTimeS: parseRunningTime(m[3]),
          userTimeS: parseRunningTime(m[4]),
        });
        return 'stats_row';
      }
      if (/^\s*PID\s+Running Time/.test(raw)) return 'stats_columns';
      inStats = false;
    }

    if ((m = raw.match(RE.header))) {
      session.headerStartedAt = parseTime(m[1]);
      session.game = m[2]; session.arch = m[3];
      return 'header';
    }
    if ((m = raw.match(RE.process))) {
      session.processes.push({
        starred: !!m[1], sha256: m[2].toLowerCase(),
        author: m[3] || null, path: m[4], line: n,
        name: m[4].replace(/\//g, '\\').split('\\').pop(),
      });
      return 'process';
    }
    if ((m = raw.match(RE.fileRecord))) {
      const prefix = m[1], name = m[2].trim(), crc = m[3].toLowerCase();
      const cap = prefix.match(RE.captured);
      if (cap) {
        session.capturedFiles.push({ sourcePath: cap[1], file: name, crc, line: n });
        return 'captured_file';
      }
      const at = prefix.match(RE.atTime);
      const mon = prefix.match(RE.monIndex);
      const each = prefix.match(RE.each);
      const stem = name.replace(/\.[^.]+$/, '');
      session.screenshots.push({
        file: name, at: at ? parseTime(at[1]) : null, crc, line: n,
        monitor: mon ? +mon[1] : null,
        nominalIntervalS: each ? +each[1] : null,
        index: /^\d+$/.test(stem) ? +stem : null,
      });
      return 'screenshot';
    }
    if ((m = raw.match(RE.statsHeader))) { inStats = true; return 'stats_header'; }
    if ((m = raw.match(RE.monitorStarted))) { session.monitorStartedAt = parseTime(m[1]); return 'monitor_started'; }
    if (RE.gameDetected.test(raw)) { session.gameDetected = true; return 'game_detected'; }
    if ((m = raw.match(RE.globalCrc))) { session.globalCrc = m[1].toLowerCase(); return 'global_crc'; }
    if (RE.fileCheckStart.test(raw)) return 'filecheck';
    if (/^\s*FileCheck end for/.test(raw)) return 'filecheck';
    if (/^\s*Search for files\s*$/i.test(raw)) return 'search_files';

    if ((m = raw.match(RE.ping))) { session.pingMs = +m[1]; return 'ping'; }
    if ((m = raw.match(RE.version))) { session.mossVersion = m[1].replace(/,/g, '.').trim(); return 'version'; }
    if ((m = raw.match(RE.os))) { hw.osVersion = m[1]; return 'os'; }
    if ((m = raw.match(RE.realOs))) { hw.realOs = m[1]; return 'real_os'; }
    if ((m = raw.match(RE.directx))) { hw.directx = m[1]; return 'directx'; }
    if ((m = raw.match(RE.memory))) { hw.memoryMb = +m[1]; return 'memory'; }
    if ((m = raw.match(RE.physical))) { hw.physical = m[1]; return 'physical'; }
    if ((m = raw.match(RE.signId))) { hw.signId1 = m[1]; return 'sign_id'; }
    if ((m = raw.match(RE.drive))) { hw.drives.push({ description: m[1], serial: m[2] || null }); return 'drive'; }
    if ((m = raw.match(RE.net))) { hw.lanIp = m[1]; hw.publicIp = m[2] || null; return 'net'; }
    if ((m = raw.match(RE.video))) { hw.video.push({ description: m[1], driver: m[2] || null }); return 'video'; }
    if ((m = raw.match(RE.monitor))) { hw.monitors.push({ description: m[1], serial: m[2] || null }); return 'monitor'; }
    if ((m = raw.match(RE.usb))) { hw.usb.push(m[1]); return 'usb'; }
    if ((m = raw.match(RE.processor))) { hw.processorMhz = +m[1]; hw.processor = m[2]; return 'processor'; }
    if ((m = raw.match(RE.defender))) { hw.windowsDefender = m[1]; return 'defender'; }
    if ((m = raw.match(RE.steamId))) { hw.steamId = m[1] || null; return 'steam_id'; }
    if (/^\s*PCI:/.test(raw)) return 'pci';
    if (/^\s*update\s+\S+\s*$/.test(raw)) return 'update';
    // User must come last: its pattern is loose enough to swallow other lines.
    if ((m = raw.match(RE.user)) && /^\s*User:/.test(raw)) {
      hw.user = (m[1] || '').trim() || null;
      hw.hostname = (m[2] || '').trim() || null;
      return 'user';
    }
    return 'unknown';
  }
}

/** Session start/end in host-local wall clock, from the capture timestamps. */
export function sessionBounds(session) {
  const times = session.screenshots.map((s) => s.at).filter((t) => t !== null);
  if (!times.length) return { start: session.monitorStartedAt, end: null };
  return {
    start: Math.min(...times, session.monitorStartedAt ?? Infinity),
    end: Math.max(...times),
  };
}
