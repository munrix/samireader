/**
 * samireader — reads a MOSS archive in the browser and says whether it is clean.
 *
 * Nothing leaves your machine: no upload, no API, no AI. The ZIP is read in the
 * page, every file is hashed with the browser's own crypto, and the rules in
 * checks.js run over the result.
 */

import { parseLog, zipDateToNaive } from './moss.js';
import { buildClocks, fmtDuration, fmtOffset, fmtTime, runChecks } from './checks.js';

const el = (id) => document.getElementById(id);
const dropZone = el('drop-zone');
const fileInput = el('file-input');
const browseBtn = el('browse-btn');
const uploadCard = el('upload-card');
const progress = el('progress');
const progressText = el('progress-text');
const results = el('results');

let RULES = null;

/** Thresholds and name lists come from the shared rule pack so the browser and
 *  the CLI can never drift apart on what counts as suspicious. */
async function loadRules() {
  if (RULES) return RULES;
  try {
    const res = await fetch('rules.json', { cache: 'no-cache' });
    if (res.ok) RULES = await res.json();
  } catch { /* offline from file:// — fall back below */ }
  if (!RULES) RULES = FALLBACK_RULES;
  return RULES;
}

const FALLBACK_RULES = {
  clocks: { drift_tolerance_minutes: 2, network_clock_expected_offset_minutes: 60, network_clock_tolerance_minutes: 5, boot_time_tolerance_s: 900 },
  session: { max_screenshot_gap_s: 300 },
  zip: { mtime_uniformity_ratio: 0.9, min_entries_for_structure_checks: 6 },
  screenshots: { blank_frame_size_ratio: 0.4, blank_frame_min_median_bytes: 20000 },
  behaviour: { double_click_min_interval_ms: 80, same_key_min_interval_ms: 100, min_events_for_scoring: 25, peak_share_review_threshold: 0.6, peak_share_high_threshold: 0.8, no_recoil_small_move_px: 6, no_recoil_small_move_share: 0.85 },
  environment: {
    expect_defender: 'enabled', expect_real_os: 'Windows 10 or 11',
    known_bad_sha256: [],
    unsigned_ignore: ['system32\\', 'syswow64\\', '\\windows\\winsxs\\'],
    suspicious_path_fragments: ['\\appdata\\local\\temp\\', '\\windows\\temp\\', '\\downloads\\', '\\desktop\\'],
    categories: {
      remote_access: ['anydesk.exe', 'parsec.exe', 'parsecd.exe', 'rustdesk.exe', 'teamviewer.exe', 'winvnc.exe', 'ultravnc.exe', 'splashtop.exe', 'todesk.exe', 'sunlogin.exe', 'moonlight.exe', 'sunshine.exe'],
      macro_suite: ['autohotkey.exe', 'autohotkey64.exe', 'lghub.exe', 'lcore.exe', 'razer synapse 3.exe', 'rewasd.exe', 'joytokey.exe', 'tinytask.exe', 'icue.exe', 'gtuner.exe'],
      virtual_machine: ['vmtoolsd.exe', 'vboxservice.exe', 'vboxtray.exe', 'vmwaretray.exe', 'qemu-ga.exe', 'prl_tools.exe'],
      spoofer_or_cleaner: ['hwidspoofer.exe', 'spoofer.exe', 'tracecleaner.exe', 'amidewinx64.exe', 'volumeid.exe'],
      debugger_or_memory_tool: ['cheatengine-x86_64.exe', 'cheatengine-i386.exe', 'x64dbg.exe', 'x32dbg.exe', 'ollydbg.exe', 'ida64.exe', 'processhacker.exe', 'systeminformer.exe', 'extremeinjector.exe', 'xenos64.exe', 'artmoney.exe'],
      overlay_or_injector: ['overwolf.exe', 'obs64.exe', 'rtss.exe', 'msiafterburner.exe', 'medal.exe', 'outplayed.exe'],
    },
  },
  config: {
    vulkan_layer_allowlist: ['VK_LAYER_OW_OBS_HOOK', 'VK_LAYER_OW_OVERLAY', 'VK_LAYER_VALVE_steam_overlay', 'VK_LAYER_VALVE_steam_fossilize', 'VK_LAYER_NV_optimus', 'VK_LAYER_AMD_switchable_graphics', 'VK_LAYER_EOS_Overlay', 'VK_LAYER_OBS_HOOK', 'VK_LAYER_MESA_device_select', 'VK_LAYER_INTEL_nullhw'],
    numeric_ranges: { MouseSensitivityMultiplierUnit: [0, 100], DefaultFOV: [60, 90] },
    flag_keys: { Console: '1' },
    profile_count_review_threshold: 5,
  },
};

// ------------------------------------------------------------------ helpers

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function setProgress(text) {
  progressText.textContent = text;
}

// ---------------------------------------------------------------- the flow

async function handleFile(file) {
  if (!file.name.toLowerCase().endsWith('.zip')) {
    alert('Please choose a MOSS .zip archive.');
    return;
  }
  if (!crypto?.subtle) {
    alert('This browser cannot hash files (crypto.subtle unavailable). Open the page over https:// or localhost.');
    return;
  }

  uploadCard.classList.add('hidden');
  progress.classList.remove('hidden');
  results.innerHTML = '';
  results.classList.add('hidden');

  try {
    const rules = await loadRules();
    setProgress('Reading the archive…');
    const zip = await window.JSZip.loadAsync(file);

    const entries = [];
    zip.forEach((path, f) => { if (!f.dir) entries.push({ name: path, file: f }); });
    if (!entries.length) throw new Error('The ZIP is empty.');

    const logEntry = entries.find((e) => /(^|\/)logfile\.log$/i.test(e.name))
      || entries.find((e) => /\.log$/i.test(e.name));
    if (!logEntry) throw new Error('No Logfile.log inside the ZIP — this does not look like a MOSS archive.');

    setProgress('Reading the log…');
    const logText = await logEntry.file.async('string');
    const session = parseLog(logText);

    const hashes = new Map();
    const sizes = new Map();
    const configs = new Map();
    const screenshots = [];
    const meta = [];

    for (let i = 0; i < entries.length; i++) {
      const { name, file: zf } = entries[i];
      if (i % 10 === 0) setProgress(`Verifying files… ${i}/${entries.length}`);
      const bytes = await zf.async('uint8array');
      hashes.set(name, await sha256Hex(bytes));
      sizes.set(name, bytes.length);
      const base = name.split('/').pop();
      if (/\.jpe?g$/i.test(name)) {
        screenshots.push({ name: base, blobUrl: URL.createObjectURL(new Blob([bytes], { type: 'image/jpeg' })) });
      } else if (/^GameSettings\.ini/i.test(base)) {
        configs.set(base, new TextDecoder('utf-8').decode(bytes));
      }
      meta.push({
        name,
        size: bytes.length,
        method: zf._data?.compressionMethod ?? (zf.options?.compression === 'STORE' ? 0 : 8),
        mtime: zipDateToNaive(zf.date),
      });
    }
    screenshots.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));

    setProgress('Checking…');
    const clockModel = buildClocks(session, meta);
    const findings = runChecks({ session, entries: meta, hashes, sizes, configs, clockModel, rules });

    render({ file, session, findings, clockModel, screenshots, logText, sizes, meta });
  } catch (err) {
    console.error(err);
    results.innerHTML = `<section class="card"><h2 class="verdict bad">Could not read this archive</h2><p>${esc(err.message)}</p></section>`;
    results.classList.remove('hidden');
  } finally {
    progress.classList.add('hidden');
    uploadCard.classList.remove('hidden');
  }
}

// ------------------------------------------------------------------ render

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

function render({ file, session, findings, clockModel, screenshots, logText, sizes, meta }) {
  const real = findings.filter((f) => f.severity !== 'info');
  const notes = findings.filter((f) => f.severity === 'info');
  const worst = SEVERITY_ORDER.find((s) => real.some((f) => f.severity === s));
  const clean = real.length === 0;

  const counts = SEVERITY_ORDER
    .map((s) => [s, real.filter((f) => f.severity === s).length])
    .filter(([, n]) => n > 0);

  const verdict = clean
    ? `<section class="card verdict-card clean">
         <h2 class="verdict good">✓ Clean</h2>
         <p class="verdict-line">Nothing suspicious found in <code>${esc(file.name)}</code>.</p>
         <p class="caveat">This means nothing was found <em>in what MOSS captured</em>. MOSS records a session — it does not detect cheating, and it cannot see DMA cheats, hardware input devices, or anything launched after the game started. A clean result is not a finding of innocence.</p>
       </section>`
    : `<section class="card verdict-card ${worst}">
         <h2 class="verdict bad">${real.length} problem${real.length === 1 ? '' : 's'} found</h2>
         <p class="verdict-line">In <code>${esc(file.name)}</code>.</p>
         <div class="chips">${counts.map(([s, n]) => `<span class="chip ${s}">${n} ${s}</span>`).join('')}</div>
         <p class="caveat">Each item below says what was measured, why it matters, and the innocent explanation for the same evidence. This tool never decides that someone cheated — you do.</p>
       </section>`;

  const findingCards = real.map(card).join('') + (notes.length ? `
    <details class="card notes"${clean ? ' open' : ''}>
      <summary>What checked out (${notes.length})</summary>
      ${notes.map(card).join('')}
    </details>` : '');

  const bounds = clockModel;
  const durationS = bounds.start && bounds.end ? (bounds.end - bounds.start) / 1000 : null;
  const info = [
    ['Game', session.game],
    ['MOSS version', session.mossVersion],
    ['Player', session.hardware.user && session.hardware.hostname ? `${session.hardware.user} @ ${session.hardware.hostname}` : session.hardware.user],
    ['Session start', fmtTime(bounds.start)],
    ['Session end', fmtTime(bounds.end)],
    ['Duration', fmtDuration(durationS)],
    ['Captures', String(session.screenshots.length)],
    ['Host clock', clockModel.offsetMinutes !== null ? `${fmtOffset(clockModel.offsetMinutes)} (measured from this archive)` : 'could not be measured'],
    ['Machine', session.hardware.physical],
    ['CPU', session.hardware.processor],
    ['GPU', session.hardware.video.map((v) => v.description).join('; ')],
    ['Monitors', session.hardware.monitors.map((m) => m.description).join('; ')],
    ['Network', session.hardware.lanIp ? `${session.hardware.lanIp}${session.hardware.publicIp ? ' · public ' + session.hardware.publicIp : ''}` : null],
    ['Windows Defender', session.hardware.windowsDefender],
    ['Processes at game start', String(session.processes.length)],
  ].filter(([, v]) => v);

  const infoCard = `
    <section class="card">
      <h3>Session</h3>
      <dl class="kv">${info.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>
    </section>`;

  const processCard = session.processes.length ? `
    <details class="card">
      <summary>Processes running at game start (${session.processes.length})</summary>
      <table class="tbl">
        <thead><tr><th>Name</th><th>Signed by</th><th>Path</th></tr></thead>
        <tbody>${session.processes.map((p) => `<tr>
          <td><code>${esc(p.name)}</code></td>
          <td>${p.author ? esc(p.author) : '<span class="unsigned">unsigned</span>'}</td>
          <td class="path">${esc(p.path)}</td></tr>`).join('')}</tbody>
      </table>
      <p class="caveat">MOSS takes this list once, when the game starts. Anything launched afterwards is not here.</p>
    </details>` : '';

  const shotsCard = screenshots.length ? `
    <details class="card" open>
      <summary>Screenshots (${screenshots.length})</summary>
      <div class="gallery">${screenshots.map((s, i) => `<img src="${s.blobUrl}" alt="${esc(s.name)}" title="${esc(s.name)}" loading="lazy" data-index="${i}">`).join('')}</div>
    </details>` : '';

  const logCard = `
    <details class="card">
      <summary>Raw log (${session.lines.length} lines${session.unknownLines.length ? `, ${session.unknownLines.length} not recognised` : ''})</summary>
      ${session.unknownLines.length ? `<p class="caveat">These lines did not match any known MOSS format. They are listed first so a format change shows up rather than being silently ignored.</p>
        <pre class="log small">${session.unknownLines.slice(0, 100).map((l) => esc(`${l.number}: ${l.raw}`)).join('\n')}</pre>` : ''}
      <pre class="log">${esc(logText)}</pre>
    </details>`;

  results.innerHTML = verdict + findingCards + infoCard + processCard + shotsCard + logCard;
  results.classList.remove('hidden');
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });

  wireGallery(screenshots);
}

function card(f) {
  return `
    <section class="card finding ${f.severity}">
      <div class="finding-head">
        <span class="chip ${f.severity}">${f.severity}</span>
        <h3>${esc(f.title)}</h3>
      </div>
      <div class="block">
        <h4>What was found</h4>
        <pre class="evidence">${esc(f.what)}</pre>
      </div>
      <div class="block">
        <h4>Why that matters</h4>
        <p>${esc(f.why)}</p>
      </div>
      <div class="block benign">
        <h4>The innocent explanation</h4>
        <p>${esc(f.benign)}</p>
      </div>
    </section>`;
}

// ------------------------------------------------------------------- modal

function wireGallery(screenshots) {
  const imgs = [...results.querySelectorAll('.gallery img')];
  if (!imgs.length) return;
  let index = 0;
  let modal = null;

  const show = () => {
    modal.querySelector('img').src = screenshots[index].blobUrl;
    modal.querySelector('.modal-caption').textContent = `${screenshots[index].name}  ·  ${index + 1} / ${screenshots.length}`;
  };
  const move = (d) => { index = (index + d + screenshots.length) % screenshots.length; show(); };
  const close = () => { modal?.remove(); modal = null; document.removeEventListener('keydown', onKey); };
  const onKey = (e) => {
    if (e.key === 'Escape') close();
    else if (e.key === 'ArrowRight') move(1);
    else if (e.key === 'ArrowLeft') move(-1);
  };

  imgs.forEach((img) => img.addEventListener('click', () => {
    index = +img.dataset.index;
    modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `<button class="modal-nav prev" aria-label="Previous">‹</button>
      <img alt="Screenshot">
      <button class="modal-nav next" aria-label="Next">›</button>
      <div class="modal-caption"></div>`;
    modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
    modal.querySelector('.prev').addEventListener('click', (e) => { e.stopPropagation(); move(-1); });
    modal.querySelector('.next').addEventListener('click', (e) => { e.stopPropagation(); move(1); });
    document.body.appendChild(modal);
    document.addEventListener('keydown', onKey);
    show();
  }));
}

// ------------------------------------------------------------------- wiring

browseBtn.addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });
dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => { if (e.target.files?.length) handleFile(e.target.files[0]); });
['dragenter', 'dragover'].forEach((ev) => dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.add('over'); }));
['dragleave', 'drop'].forEach((ev) => dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.remove('over'); }));
dropZone.addEventListener('drop', (e) => { if (e.dataTransfer?.files?.length) handleFile(e.dataTransfer.files[0]); });

// Exposed for the end-to-end test, which drives the page with a real archive.
window.__samireader = { handleFile, parseLog, runChecks };
