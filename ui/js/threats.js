// Threats: what Sentinel found on this Mac and on the network, how bad each would be, and how sure it is.
// docs/CONTRACT.md "Version 3" is the data; docs/DESIGN.md section 14 is the design.
//
// Two rules run through this file.
// 1. Unchecked is never shown as safe. A server without Sentinel, scans that stopped, a scanner with
//    ok: false: each is said in words, and the level is not green.
// 2. Every string in a finding was chosen by somebody else (a download names itself). It goes on screen as
//    text nodes through safe.js, never as HTML, a link or a style.
import { h, fill, isPhone } from './dom.js';
import { icon } from './icons.js';
import { get, set, on, go, select, clearSelection } from './store.js';
import { api } from './api.js';
import * as G from './graph.js';
import { tip, toast, dialog, callout, skeleton, errorState, section, copyBtn } from './ui.js';
import { relTime, absTime, plural, toMs, duration } from './fmt.js';
import { safeNodes, safeText, hasHidden, midTrunc } from './safe.js';

export const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const CONF_N = { confirmed: 4, high: 3, medium: 2, low: 1 };
const CONF_LABEL = { confirmed: 'confirmed', high: 'high confidence', medium: 'medium confidence', low: 'low confidence' };
const CONF_WHY = { confirmed: 'A signature engine named it, or the fact was measured directly.', high: 'Several signs agree. No signature engine named it.', medium: 'A heuristic: it has the marks of a problem and could be harmless.', low: 'A weak sign. More often harmless than not.' };
const STATES = ['open', 'acknowledged', 'trusted', 'quarantined', 'resolved'];
const STATE_LABEL = { open: 'Open', acknowledged: 'Acknowledged', trusted: 'Trusted', quarantined: 'In quarantine', resolved: 'Resolved' };
const CATEGORY = { malware: 'Malware', download: 'Downloads', persistence: 'Starts by itself', plugin: 'Plugins and extensions', process: 'Running programs', exposure: 'Open to the network',
  secrets: 'Secret stores', posture: 'Mac settings', network: 'Router', device: 'Devices', integrity: 'Home Observability Hub itself' };
const SUBJECT = { file: 'File', app: 'App', process: 'Program', port: 'Port', 'launch-item': 'Launch item', extension: 'Extension', package: 'Package', setting: 'Setting', device: 'Device', router: 'Router' };
const ACT = {
  quarantine: { label: 'Quarantine', icon: 'lock', doing: 'Moving it…', hint: 'Move the file where it cannot run. Asks first.' },
  restore: { label: 'Restore', icon: 'restore', doing: 'Putting it back…', hint: 'Put the file back where it was. Asks first.' },
  trust: { label: 'Trust', icon: 'check', doing: 'Adding it to the baseline…', hint: 'You know what this is: stop raising it unless it changes. Asks first.' },
  acknowledge: { label: 'Acknowledge', icon: 'eye', doing: 'Saving…', hint: 'You have seen it. It stays on the list and is still watched.' },
  reopen: { label: 'Reopen', icon: 'undo', doing: 'Reopening…', hint: 'Put it back on the open list.' },
  rescan: { label: 'Scan again', icon: 'scan', doing: 'Scanning…', hint: 'Check this one thing again now.' },
};
const ACT_ORDER = ['quarantine', 'restore', 'trust', 'acknowledge', 'reopen', 'rescan'];
const NEEDS_CONFIRM = new Set(['trust', 'quarantine', 'restore']);
const BULK_ORDER = ['acknowledge', 'trust', 'reopen'];
const PAST = { acknowledge: 'acknowledged', trust: 'trusted', reopen: 'reopened' };

const num = n => (typeof n === 'number' ? n.toLocaleString('en') : '0');
const sevKey = s => (SEV.includes(s) ? s : 'info');
export const isFindingId = id => typeof id === 'string' && /^f-[0-9a-f]{4,40}$/.test(id) && !G.isDeviceId(id);

// ---------------------------------------------------------------- data

let busy = false, lastTry = 0, known = null, chasing = 0;
const pendingRun = new Map();   // scanner → ms until which "Scan now" shows it as running, before the server says so
const scanBusy = new Set();
const details = new Map();      // id → { data, at, error, loading }
let allDoc = null, allBusy = false;

export async function loadThreats() {
  if (busy) return;
  busy = true; lastTry = Date.now();
  try {
    const doc = await api.threats();
    if (!doc || !Array.isArray(doc.findings) || !doc.summary) throw new Error('The server sent no findings list.');
    announce(doc);
    set({ threats: doc, threatsAt: Date.now(), threatsError: null });
  } catch (e) {
    if (e.status === 404) { known = null; set({ threats: null, threatsError: 'missing' }); }
    else set({ threatsError: e.message || 'The findings could not be loaded.' });
  } finally { busy = false; }
}

/** A new critical or high finding since the last reading: one toast with a way to open it. Not on the first load. */
function announce(doc) {
  const open = doc.findings.filter(f => f.state === 'open');
  if (known) {
    const fresh = open.filter(f => !known.has(f.id) && (f.severity === 'critical' || f.severity === 'high'));
    if (fresh.length === 1) {
      const f = fresh[0];
      toast(h('span', null, h('b', null, 'New ' + f.severity + ' finding. '), safeNodes(f.title)), { intent: f.severity === 'critical' ? 'danger' : 'caution', action: { label: 'Open', fn: () => go({ view: 'threats', sel: [f.id], panel: null }) } });
    } else if (fresh.length > 1) {
      const crit = fresh.filter(f => f.severity === 'critical').length;
      toast(h('span', null, h('b', null, fresh.length + ' new findings. '), crit ? plural(crit, 'is', 'are') + ' critical.' : 'All high.'), { intent: crit ? 'danger' : 'caution', action: { label: 'Open', fn: () => go({ view: 'threats', sel: [], panel: null }) } });
    }
  }
  known = new Set(doc.findings.map(f => f.id));
}

async function loadAll() {
  if (allBusy) return;
  allBusy = true;
  try { allDoc = await api.threats({ state: 'all' }); } catch (e) { allDoc = { error: e.message, findings: [] }; }
  allBusy = false;
  set({ threatTick: Date.now() });
}

// The findings ride on the live poll: at once when the live summary disagrees with what is loaded or a scan
// is running, every poll while the view is open, and about once a minute otherwise.
on(['live', 'reloadAt'], (st, keys) => {
  if (keys.has('reloadAt')) { details.clear(); loadThreats(); return; }
  const since = Date.now() - lastTry;
  if (st.threatsError === 'missing') { if (since > 60000) loadThreats(); return; }
  const lt = st.live && st.live.summary && st.live.summary.threats, s = st.threats && st.threats.summary;
  const differs = !!(lt && s && (lt.open !== s.open || lt.level !== s.level));
  const running = !!st.threats && Object.values(st.threats.scanners || {}).some(x => x && x.running);
  if (!st.threats || differs || running || (st.route.view === 'threats' && since > 8000) || since > 45000) loadThreats();
});

export function findingById(id) {
  const st = get();
  return (st.threats && st.threats.findings.find(f => f.id === id)) || (allDoc && (allDoc.findings || []).find(f => f.id === id)) || (details.get(id) || {}).data || null;
}

function loadDetail(id, force) {
  const c = details.get(id) || {};
  if (c.loading || (!force && (c.data || c.error) && Date.now() - c.at < 20000)) return;
  details.set(id, { ...c, loading: true });
  api.threat(id).then(data => details.set(id, { data, at: Date.now() }), e => details.set(id, { data: c.data, error: e.message, missing: e.status === 404, at: Date.now() }))
    .then(() => set({ threatTick: Date.now() }));
}

/** Open findings about one device, for the device inspector and the Security rows. */
export function findingsFor(deviceId) {
  const doc = get().threats;
  return doc ? doc.findings.filter(f => f.state === 'open' && f.subject && f.subject.deviceId === deviceId) : [];
}

// ---------------------------------------------------------------- what the data lets us say

/** How much of the scanning is working. `ok` is the only state in which "no findings" means something. */
export function threatHealth(st = get()) {
  const doc = st.threats;
  if (st.threatsError === 'missing') return { state: 'missing' };
  if (!doc) return st.threatsError ? { state: 'error', error: st.threatsError } : { state: 'loading' };
  const now = st.now || Date.now();
  const list = Object.entries(doc.scanners || {}).filter(([, x]) => x && typeof x === 'object').map(([name, x]) => ({ name, ...x }));
  const failing = list.filter(x => x.ok === false);
  const never = list.filter(x => x.ok !== false && !x.lastRun && !x.running);
  const overdue = list.filter(x => x.ok !== false && x.lastRun && !x.running && now - toMs(x.lastRun) > (3 * (x.intervalSec || 600) + 120) * 1000);
  const last = toMs(doc.summary.lastScan);
  const unreachable = !!st.threatsError && Date.now() - st.threatsAt > 90000;
  const stopped = !list.length || !last || now - last > 20 * 60000 || never.length + overdue.length + failing.length === list.length;
  const e = doc.engines || {};
  const noSignatures = !(e.clamav && e.clamav.installed) && !(e.yara && e.yara.installed);
  return { state: unreachable || stopped ? 'stale' : failing.length || never.length || overdue.length ? 'partial' : 'ok', list, failing, never, overdue, last, unreachable, firstRun: !last && !unreachable, noSignatures, error: st.threatsError };
}

/** The one level, with the words and the colour it may have. `rank` orders it against the device verdict. */
export function threatLevel(st = get()) {
  const hl = threatHealth(st);
  const lt = st.live && st.live.summary && st.live.summary.threats;
  if (hl.state === 'loading' && !lt) return { key: 'loading', cls: 'none', label: 'Loading', pill: 'Loading', icon: 'shield', rank: -1, health: hl };
  if (hl.state === 'missing') return { key: 'missing', cls: 'none', label: 'Not scanning', pill: 'Threats not scanned', icon: 'shield', rank: 1, health: hl };
  const s = st.threats ? st.threats.summary : { level: lt && lt.level, open: lt && lt.open, bySeverity: { critical: lt && lt.critical, high: lt && lt.high } };
  if (hl.state === 'error' && !lt) return { key: 'error', cls: 'none', label: 'No reading', pill: 'Threats: no reading', icon: 'shield', rank: 1, health: hl };
  const by = s.bySeverity || {};
  const serious = (by.critical || 0) + (by.high || 0);
  switch (s.level) {
    case 'compromised': return { key: 'compromised', cls: 'danger', label: 'Compromised', pill: 'Compromised', icon: 'warning', rank: 5, health: hl };
    case 'at-risk': return { key: 'at-risk', cls: 'risk', label: 'At risk', pill: serious ? plural(serious, 'serious finding') : 'At risk', icon: 'warning', rank: 4, health: hl };
    case 'watch': return { key: 'watch', cls: 'caution', label: 'Worth a look', pill: by.medium ? plural(by.medium, 'finding') + ' to check' : 'Worth a look', icon: 'eye', rank: 2, health: hl };
    case 'secure':
      if (hl.state === 'stale' || hl.state === 'error') return { key: 'stale', cls: 'none', label: hl.firstRun ? 'First scan running' : 'Not current', pill: hl.firstRun ? 'First threat scan running' : 'Threat scan stopped', icon: 'shield', rank: 1, health: hl };
      if (hl.state === 'partial') return { key: 'partial', cls: 'caution', label: 'Partly checked', pill: 'Threat scan incomplete', icon: 'shield', rank: 1.5, health: hl };
      return { key: 'secure', cls: 'ok', label: s.open ? 'Low findings only' : 'No open findings', pill: 'No findings', icon: 'security', rank: 0, health: hl };
    default: return { key: 'error', cls: 'none', label: 'Not assessed', pill: 'Threats not assessed', icon: 'shield', rank: 1, health: hl };
  }
}

// ---------------------------------------------------------------- the two signals

/** Severity: how bad it would be if true. A coloured chip with its word; the two worst also carry a mark. */
export function sevChip(sev) {
  const k = sevKey(sev);
  return h('span', { class: 'sevc s-' + k }, k === 'critical' || k === 'high' ? icon('warning', 12) : null, h('span', { class: 'sr-only' }, 'Severity: '), SEV_LABEL[k]);
}

/** Confidence: how sure the scanner is. Never a colour: four bars and the word, so it cannot be read as severity. */
export function confMeter(f, { pct = false } = {}) {
  const n = CONF_N[f.confidence] || 0;
  const word = CONF_LABEL[f.confidence] || 'confidence not given';
  return h('span', { class: 'confw' }, h('span', { class: 'meter', 'aria-hidden': 'true' }, [1, 2, 3, 4].map(i => h('i', { class: i <= n ? 'on' : null }))),
    h('span', null, f.confidence === 'confirmed' ? h('span', { class: 'sr-only' }, 'Confidence: ') : null, word, pct && typeof f.confidencePct === 'number' && f.confidence !== 'confirmed' ? ' · ' + Math.round(f.confidencePct) + '%' : null));
}

const tilde = p => String(p || '').replace(/^\/Users\/[^/]+(?=\/|$)/, '~');
function subjectName(f) {
  const s = f.subject || {};
  if (s.deviceId && G.isDeviceId(s.deviceId)) return G.deviceName(s.deviceId);
  return s.name || (s.path ? String(s.path).split('/').filter(Boolean).pop() : '') || '';
}
function subjectLine(f, { place = true } = {}) {
  const s = f.subject || {};
  const name = subjectName(f);
  const where = s.path ? tilde(s.path).replace(/\/[^/]*\/?$/, '') : '';
  return h('span', { class: 'f-subj' }, h('span', { class: 'f-type' }, SUBJECT[s.type] || 'Item'), name ? midTrunc(name, { keep: 14, cls: 'f-name' }) : null,
    s.port && s.type !== 'port' ? h('span', { class: 'f-type' }, 'port ' + Number(s.port)) : s.type === 'port' && s.port ? h('span', { class: 'f-type' }, String(Number(s.port))) : null,
    place && where ? midTrunc('in ' + where, { cls: 'f-where' }) : null);
}

// ---------------------------------------------------------------- actions

function applyFinding(f) {
  const doc = get().threats;
  if (!f || !doc) return;
  const i = doc.findings.findIndex(x => x.id === f.id);
  const findings = doc.findings.slice();
  if (i >= 0) findings[i] = f; else findings.push(f);
  set({ threats: { ...doc, findings } });
}

async function act(id, action, btn) {
  const f = findingById(id);
  if (!f) return;
  if (NEEDS_CONFIRM.has(action)) return confirmFinding(f, action);
  if (btn.disabled) return;
  const a = ACT[action] || { label: action, doing: 'Working…', icon: 'chevron' };
  btn.disabled = true; fill(btn, h('span', { class: 'spinner' }), h('span', null, a.doing));
  try {
    const res = await api.threatAction(id, { action });
    if (!res || res.ok === false) throw new Error((res && res.error) || 'The server gave no reason.');
    details.delete(id); applyFinding(res.finding);
    if (action === 'rescan') toast(res.result && res.result.message ? safeText(res.result.message) : res.finding && res.finding.state === 'resolved' ? 'Scanned again: it is gone.' : 'Scanned again: it is still there.', { intent: 'info' });
  } catch (e) {
    btn.disabled = false; fill(btn, icon(a.icon, 14), h('span', null, a.label));
    toast(h('span', null, h('b', null, a.label + ' did not happen. '), safeText(e.message)), { intent: 'caution' });
    return;
  }
  loadThreats(); if (allDoc) loadAll();
}

/** trust, quarantine, restore: one dialog that says exactly what will happen and how to undo it. Cancel has the focus. */
function confirmFinding(f, action) {
  const s = f.subject || {};
  const name = subjectName(f) || 'this item';
  const kind = (SUBJECT[s.type] || 'item').toLowerCase();
  const pathNode = s.path ? h('span', { class: 'mono fd-path' }, safeNodes(s.path)) : null;
  const serious = f.severity === 'critical' || f.severity === 'high';
  const T = {
    trust: {
      title: 'Trust this ' + kind + '?', verb: 'Trust it', risk: 'change',
      effect: [s.path ? ['Adds ', pathNode, s.sha256 ? ' and its hash' : '', ' to the baseline.'] : 'Adds this ' + kind + ', as it is now, to the baseline.', ' The finding leaves the open list and is raised again only if the ' + kind + ' changes.'],
      undo: 'Open it under Trusted and choose Reopen. It goes back on the open list.',
      warn: serious ? 'This is a ' + f.severity + ' finding. Trust it only if you know what it is and where it came from.' : null,
    },
    quarantine: {
      title: 'Move this ' + kind + ' to quarantine?', verb: 'Move to quarantine', risk: 'change',
      effect: ['Moves ', pathNode || name, ' into Home Observability Hub’s quarantine folder and takes away every permission, so it cannot be opened or run. Nothing is deleted.'],
      undo: 'Restore puts it back where it was.',
    },
    restore: {
      title: 'Put this ' + kind + ' back?', verb: 'Put it back', risk: 'change',
      effect: ['Moves it out of quarantine, back to ', pathNode || 'where it was', ', with its permissions. It can be opened and run again, and the finding reopens.'],
      undo: 'Quarantine it again.',
      warn: serious ? 'This is a ' + f.severity + ' finding. Put it back only if you are sure it is harmless.' : null,
    },
  }[action];
  const a = ACT[action];
  const note = h('div', { class: 'cf-note' });
  let dlg = null, running = false;
  const cancel = h('button', { class: 'btn', type: 'button', onClick: () => dlg.close() }, 'Cancel');
  const ok = h('button', { class: 'btn primary', type: 'button', onClick: run }, icon(a.icon, 14), T.verb);
  const body = h('div', { class: 'body confirm-act' },
    h('div', { class: 'cf-target fd-target' }, sevChip(f.severity), h('span', { class: 'grow' }, h('b', null, safeNodes(f.title)), h('span', { class: 'muted' }, (SUBJECT[s.type] || 'Item') + ' · ', safeNodes(name)))),
    h('dl', { class: 'cf-dl' }, h('dt', null, 'What happens'), h('dd', null, T.effect), h('dt', null, 'Undo'), h('dd', null, T.undo)),
    T.warn ? callout('caution', T.warn) : null, note,
    h('div', { class: 'cf-foot' }, h('span', { class: 'grow muted small' }, 'Written to the audit log.'), cancel, ok));
  async function run() {
    if (running) return;
    running = true; ok.disabled = true; cancel.disabled = true;
    fill(ok, h('span', { class: 'spinner' }), a.doing); fill(note);
    try {
      const res = await api.threatAction(f.id, { action, confirm: true });
      if (!res || res.ok === false) throw new Error((res && res.error) || 'The server gave no reason.');
      details.delete(f.id); applyFinding(res.finding);
      dlg.close();
      toast(res.result && res.result.message ? safeText(res.result.message) : ({ trust: safeText(name) + ' is trusted. It leaves the open list.', quarantine: safeText(name) + ' is in quarantine.', restore: safeText(name) + ' is back where it was.' }[action] || a.label + ': done.'), { intent: 'success' });
      loadThreats(); if (allDoc) loadAll();
    } catch (e) {
      running = false; ok.disabled = false; cancel.disabled = false;
      fill(ok, icon(a.icon, 14), 'Try again');
      fill(note, callout('danger', h('b', null, a.label + ' did not happen. '), safeText(e.message)));
    }
  }
  dlg = dialog({ title: T.title, body, cls: 'cf r-' + T.risk });
  cancel.focus({ preventScroll: true });
  return dlg;
}

function actionButtons(f) {
  const list = (Array.isArray(f.actions) ? f.actions : []).filter(a => ACT[a]).sort((a, b) => ACT_ORDER.indexOf(a) - ACT_ORDER.indexOf(b));
  if (!list.length) return null;
  return h('div', { class: 'actbar fd-acts', role: 'group', 'aria-label': 'Actions for this finding' }, list.map(a => {
    const b = h('button', { class: 'act', type: 'button', dataset: { faction: a, fk: 'act-' + a }, onClick: () => act(f.id, a, b) }, icon(ACT[a].icon, 14), h('span', null, ACT[a].label));
    tip(b, ACT[a].hint);
    return b;
  }));
}

export async function scanNow(name) {
  const key = name || '*';
  if (scanBusy.has(key)) return;
  scanBusy.add(key); set({ threatTick: Date.now() });
  try {
    const r = await api.threatScan(name ? { scanner: name } : {});
    if (!r || r.ok === false) throw new Error((r && r.error) || 'The server did not start the scan.');
    for (const n of Array.isArray(r.started) ? r.started : name ? [name] : []) pendingRun.set(n, Date.now() + 4000);
    chase(40);
  } catch (e) {
    toast(h('span', null, h('b', null, 'The scan did not start. '), safeText(e.status === 404 ? 'This server cannot scan on request yet.' : e.message)), { intent: 'caution' });
  } finally { scanBusy.delete(key); set({ threatTick: Date.now() }); }
}
function chase(n) {
  const mine = ++chasing;
  const step = async left => {
    if (mine !== chasing || left <= 0) return;
    await loadThreats();
    const doc = get().threats, now = Date.now();
    const going = (doc && Object.values(doc.scanners || {}).some(x => x && x.running)) || [...pendingRun.values()].some(t => t > now);
    set({ threatTick: now });
    if (going) setTimeout(() => step(left - 1), 1500);
  };
  setTimeout(() => step(n), 900);
}

// ---------------------------------------------------------------- the detail (in the inspector panel; a full sheet on a phone)

function copyIcon(text, what) {
  const b = copyBtn(text, '', { cls: 'btn minimal icon sm cp' });
  b.setAttribute('aria-label', 'Copy ' + what);
  return b;
}

function commandBlock(fix) {
  // What is copied is exactly the text shown: fix.command with any hidden character written out. Nothing is built from a file name here.
  const shown = safeText(fix.command, { multiline: true });
  const hidden = hasHidden(fix.command, { multiline: true });
  return h('div', { class: 'fd-cmd' + (fix.needsSudo ? ' sudo' : '') },
    h('pre', { tabIndex: 0, 'aria-label': 'Command' }, safeNodes(fix.command, { multiline: true })),
    h('div', { class: 'fd-cmd-f' },
      fix.needsSudo ? h('span', { class: 'tag caution' }, icon('key', 12), 'needs sudo') : null,
      h('span', { class: 'grow muted small' }, fix.needsSudo ? 'Run it yourself in Terminal; it asks for your password. Home Observability Hub never runs it.' : 'Home Observability Hub does not run this. Paste it into Terminal.'),
      copyBtn(shown, 'Copy command', { cls: 'btn sm' })),
    hidden ? callout('caution', 'This command contains hidden characters, shown as their codes. Do not run it as it is.') : null);
}

function evidenceRows(f) {
  const ev = Array.isArray(f.evidence) ? f.evidence : [];
  if (!ev.length) return h('p', { class: 'muted small' }, 'The scanner recorded no evidence rows.');
  return h('div', { class: 'fd-ev' }, ev.map(e => h('div', { class: 'fd-evr' },
    h('div', { class: 'k' }, safeNodes(e.label)),
    h('div', { class: 'v mono' }, safeNodes(e.value)),
    copyIcon(safeText(e.value), safeText(e.label)),
    e.source ? h('div', { class: 's mono' }, safeNodes(e.source)) : null)));
}

function aboutRows(f) {
  const s = f.subject || {}, st = get();
  const scanner = st.threats && st.threats.scanners && st.threats.scanners[f.scanner];
  const row = (k, v, { mono = false, copy = null } = {}) => (v == null || v === '' ? null : h('div', { class: 'fd-evr' }, h('div', { class: 'k' }, k), h('div', { class: 'v' + (mono ? ' mono' : '') }, v), copy ? copyIcon(copy, k.toLowerCase()) : h('span')));
  const when = ts => (ts ? [relTime(ts, st.now), toMs(ts) && st.now - toMs(ts) < 86400000 ? h('span', { class: 'muted' }, ' · ' + absTime(ts)) : null] : null);
  const dev = s.deviceId && G.isDeviceId(s.deviceId) ? h('button', { class: 'linkbtn', type: 'button', onClick: () => select(s.deviceId) }, G.deviceName(s.deviceId)) : s.deviceId ? safeNodes(s.deviceId) : null;
  return h('div', { class: 'fd-ev' },
    row(SUBJECT[s.type] || 'Item', s.name ? safeNodes(s.name) : null, { copy: s.name ? safeText(s.name) : null }),
    s.name && hasHidden(s.name) ? h('p', { class: 'fd-warn' }, icon('warning', 14), 'The name contains hidden characters that can disguise what it is. They are shown as their codes.') : null,
    row('Path', s.path ? safeNodes(s.path) : null, { mono: true, copy: s.path ? safeText(s.path) : null }),
    row('SHA-256', s.sha256 ? safeNodes(s.sha256) : null, { mono: true, copy: s.sha256 ? safeText(s.sha256) : null }),
    row('Device', dev), row('Port', s.port ? String(Number(s.port)) : null, { mono: true }), row('Process ID', s.pid ? String(Number(s.pid)) : null, { mono: true }),
    row('Found by', scanner && scanner.label ? safeNodes(scanner.label) : safeNodes(f.scanner)), row('Kind', CATEGORY[f.category] || (f.category ? safeNodes(f.category) : null)),
    row('First seen', when(f.firstSeen)), row('Last seen', when(f.lastSeen)), f.resolvedAt ? row('Resolved', when(f.resolvedAt)) : null,
    row('Finding ID', safeNodes(f.id), { mono: true, copy: safeText(f.id) }));
}

function historyRows(id) {
  const c = details.get(id) || {};
  const hist = c.data && Array.isArray(c.data.history) ? c.data.history : null;
  if (!hist) return c.error ? h('p', { class: 'muted small' }, 'The history could not be loaded: ', safeText(c.error)) : h('div', { class: 'skel-rows', style: { padding: 0 } }, h('span', { class: 'skel w60' }), h('span', { class: 'skel w40' }));
  if (!hist.length) return h('p', { class: 'muted small' }, 'Nothing has happened to it yet.');
  const who = a => (a === 'person' ? 'You' : a === 'sentinel' || a === 'scanner' ? 'Scanner' : safeText(a || ''));
  return h('ol', { class: 'fd-hist' }, hist.map(x => { const t = h('span', { class: 't' }, relTime(x.ts, get().now)); tip(t, absTime(x.ts)); return h('li', null, t, h('span', { class: 'w' }, who(x.actor)), h('span', { class: 'c' }, safeNodes(x.change))); }));
}

function findingNodes(id) {
  const f = findingById(id);
  const phone = isPhone();
  const back = phone ? h('button', { class: 'btn minimal icon', type: 'button', 'aria-label': 'Back to the list', dataset: { fk: 'back' }, onClick: () => clearSelection() }, icon('back')) : null;
  const close = phone ? null : h('button', { class: 'btn minimal icon insp-close', type: 'button', 'aria-label': 'Close', dataset: { fk: 'close' }, onClick: () => clearSelection() }, icon('close'));
  if (!f) {
    const c = details.get(id) || {};
    return [h('header', { class: 'insp-h' }, h('div', { class: 'row' }, back, h('h2', { class: 'grow' }, 'Finding'), close)),
      c.loading || (!c.error && !get().threats && get().threatsError !== 'missing') ? skeleton(8)
        : h('div', { class: 'state' }, h('p', null, c.missing || !c.error ? 'This finding is not on the list any more. It may have been resolved and aged out.' : ['It could not be loaded: ', safeText(c.error)]),
          h('button', { class: 'btn sm', type: 'button', onClick: () => go({ view: 'threats', sel: [], panel: null }) }, 'Show all findings'))];
  }
  const fix = f.fix || {};
  const sk = sevKey(f.severity);
  const st = f.state && f.state !== 'open' ? h('span', { class: 'tag st-' + (STATES.includes(f.state) ? f.state : 'open') }, (STATE_LABEL[f.state] || safeText(f.state)).toLowerCase()) : null;
  const reasons = Array.isArray(f.reasons) ? f.reasons.filter(r => r && r.text) : [];
  const onOtherView = get().route.view !== 'threats';
  return [
    h('header', { class: 'insp-h fd-h s-' + sk },
      h('div', { class: 'row fd-top' }, back, h('span', { class: 'grow' }), close),
      h('h2', { class: 'fd-title' }, safeNodes(f.title)),
      h('div', { class: 'fd-sub' }, subjectLine(f, { place: false }), st, f.isNew && f.state === 'open' ? h('span', { class: 'newtag' }, 'new') : null)),
    h('div', { class: 'insp-b scroll fd-b' },
      h('dl', { class: 'fd-sc' },
        h('div', null, h('dt', null, 'Severity'), h('dd', null, sevChip(f.severity)), h('dd', { class: 'cap' }, 'How bad it would be if true.')),
        h('div', null, h('dt', null, 'Confidence'), h('dd', null, confMeter(f, { pct: true })), h('dd', { class: 'cap' }, CONF_WHY[f.confidence] || 'How sure the scanner is that it is true.'))),
      f.detail ? h('p', { class: 'fd-detail' }, safeNodes(f.detail, { multiline: true })) : null,
      fix.text || fix.command ? h('div', { class: 'fd-fix' }, h('h3', null, 'What to do'), fix.text ? h('p', null, safeNodes(fix.text, { multiline: true })) : null, fix.command ? commandBlock(fix) : null) : null,
      actionButtons(f),
      onOtherView ? h('button', { class: 'linkbtn fd-all', type: 'button', onClick: () => go({ view: 'threats', panel: null }) }, 'Show it in the Threats list') : null,
      reasons.length ? h('div', { class: 'fd-why' }, h('h3', null, 'Why it was raised'), h('ul', { class: 'reasons' }, reasons.map(r => h('li', null, icon('chevron', 14), h('span', null, safeNodes(r.text)))))) : null,
      section('fd-evidence', 'Evidence', evidenceRows(f), { meta: (f.evidence || []).length ? plural(f.evidence.length, 'row') : null }),
      section('fd-about', 'Details', aboutRows(f)),
      section('fd-history', 'History', historyRows(id), { open: false })),
  ];
}

const panelScroll = new Map();
let panelShown = null;
/** Draws one finding into the inspector element. Redraws only when what it would show has changed, so a selection or the focus survives the polls. */
export function renderFinding(el, id) {
  const f = findingById(id);
  const c = details.get(id) || {};
  if (!c.loading && (!c.data || (f && c.data.state !== f.state) || Date.now() - c.at > 30000)) loadDetail(id, !!(f && c.data && c.data.state !== f.state));
  const tmp = el.cloneNode(false);
  fill(tmp, findingNodes(id));
  const body = el.querySelector('.fd-b');
  if (body && panelShown) panelScroll.set(panelShown, body.scrollTop);
  if (tmp.isEqualNode(el) && panelShown === id) return;
  const active = document.activeElement, key = active && el.contains(active) ? ((active.closest('[data-fk]') || {}).dataset || {}).fk : null;
  el.replaceChildren(...tmp.childNodes);
  const nb = el.querySelector('.fd-b');
  if (nb) nb.scrollTop = panelShown === id ? panelScroll.get(id) || 0 : 0;
  if (key && panelShown === id) { const n = [...el.querySelectorAll('[data-fk]')].find(x => x.dataset.fk === key); n && n.focus({ preventScroll: true }); }
  panelShown = id;
}
export function leaveFinding() { panelShown = null; }

/** In the device inspector: the open findings about this device, each opening its detail. */
export function deviceFindings(deviceId) {
  const list = findingsFor(deviceId);
  if (!list.length) return null;
  return h('div', { class: 'dev-findings' }, h('div', { class: 'sub-h' }, plural(list.length, 'open finding') + ' about this device'),
    list.map(f => h('button', { class: 'dfrow', type: 'button', onClick: () => go({ view: 'threats', sel: [f.id], panel: null }) }, sevChip(f.severity), h('span', { class: 'grow t' }, safeNodes(f.title)), icon('chevron', 14, 'go'))));
}
/** On a Security row: how many open findings the device has. */
export function findingChip(deviceId) {
  const list = findingsFor(deviceId);
  if (!list.length) return null;
  const worst = SEV.find(s => list.some(f => f.severity === s)) || 'info';
  const el = h('span', { class: 'sevc s-' + worst }, plural(list.length, 'finding'));
  tip(el, list.map(f => safeText(f.title)).join(' · '));
  return el;
}

// ---------------------------------------------------------------- the view

function swap(host, ...kids) {
  const tmp = host.cloneNode(false);
  fill(tmp, ...kids);
  if (tmp.isEqualNode(host)) return false;
  const active = document.activeElement, key = active && host.contains(active) ? ((active.closest('[data-fk]') || {}).dataset || {}).fk : null;
  host.replaceChildren(...tmp.childNodes);
  if (key) { const n = [...host.querySelectorAll('[data-fk]')].find(x => x.dataset.fk === key); n && n.focus({ preventScroll: true }); }
  return true;
}

export function createThreats() {
  const head = h('div', { class: 'sec-head th-head' });
  const tools = h('div', { class: 'th-tools' });
  const listEl = h('div', { class: 'th-list' });
  const cover = h('div', { class: 'th-cover' });
  const body = h('div', { class: 'sec-body th-body scroll grow' }, tools, listEl, cover);
  const el = h('div', { class: 'view secview thview' }, head, body);
  const flt = { sev: null, cat: null, scanner: null, state: 'open' };
  const dflt = () => !flt.sev && !flt.cat && !flt.scanner && flt.state === 'open';
  let rendered = null;   // ids drawn last time, to mark the ones that arrive
  let picking = false, lastPick = null, bulkBusy = false;
  const picked = new Set();   // ids ticked in select mode; only ever ones on screen
  let shownIds = [];
  const stopPicking = () => { picking = false; picked.clear(); lastPick = null; render(); };
  el.addEventListener('keydown', e => { if (e.key === 'Escape' && picking && !bulkBusy) { e.stopPropagation(); stopPicking(); } });

  function setFlt(patch) {
    Object.assign(flt, patch);
    if (flt.state === 'resolved' && !allDoc) loadAll();
    render(); body.scrollTop = 0; el.scrollTop = 0;
  }
  const clearFlt = () => setFlt({ sev: null, cat: null, scanner: null, state: 'open' });

  function ageText(ts, st) { return ts ? relTime(ts, st.now) : null; }

  function renderHead(st, lv) {
    const hl = lv.health, doc = st.threats;
    const title = pill => h('div', { class: 'sec-title' }, h('h1', null, 'Threats'), pill, h('span', { class: 'grow' }));
    if (lv.key === 'loading') return swap(head, title(null));
    if (lv.key === 'missing' || !doc) return swap(head, title(h('span', { class: 'verdict-btn static v-none' }, icon('shield', 14), lv.label)));
    const s = doc.summary, by = s.bySeverity || {};
    const scan = h('span', { class: 'muted scan' + (hl.state === 'stale' ? ' stale' : '') }, hl.last ? 'scanned ' + ageText(s.lastScan, st) : 'no scan yet');
    if (hl.last) tip(scan, 'The most recent run of any scanner: ' + absTime(s.lastScan));
    const lead = { compromised: 'A critical finding is confirmed or very likely. Open it and follow what it says to do.', 'at-risk': 'Something serious is open. Start at the top.',
      watch: 'Nothing serious is open. Look at these when you have a minute.', secure: s.open ? 'Only low findings are open.' : null }[lv.key] || null;
    const tiles = s.open > 0 ? h('div', { class: 'tsev', role: 'group', 'aria-label': 'Open findings by severity' }, SEV.map(k => {
      const n = by[k] || 0;
      return h('button', { class: 'tsev-b s-' + k + (n ? '' : ' zero'), type: 'button', 'aria-pressed': String(flt.sev === k), dataset: { fk: 'sev-' + k }, onClick: () => setFlt({ sev: flt.sev === k ? null : k, state: 'open' }) }, h('b', null, String(n)), h('span', null, SEV_LABEL[k]));
    })) : null;
    const jump = () => { const t = cover.querySelector('.sgroup'); t && t.scrollIntoView({ block: 'start', behavior: 'smooth' }); };
    const names = list => list.map(x => safeText(x.label || x.name)).join(', ');
    const notes = [
      hl.unreachable ? h('p', { class: 'sec-note bad' }, icon('warning', 14), h('span', null, 'The findings could not be refreshed: ', safeText(hl.error), '. This is what was loaded ' + relTime(st.threatsAt, st.now) + '.')) : null,
      hl.state === 'stale' && !hl.unreachable ? h('p', { class: 'sec-note warn' }, icon('warning', 14), h('span', null, hl.firstRun ? 'The first scan has not finished, so nothing has been checked yet. ' : hl.last ? 'Scanning has stopped: nothing has run since ' + absTime(s.lastScan) + ', so this page is not current. ' : 'No scanner has reported a run. ',
        h('button', { class: 'linkbtn', type: 'button', dataset: { fk: 'scan-stale' }, onClick: () => scanNow() }, 'Scan now'))) : null,
      hl.state !== 'stale' && hl.failing.length ? h('p', { class: 'sec-note warn' }, icon('warning', 14), h('span', null, plural(hl.failing.length, 'scanner is', 'scanners are') + ' failing: ' + names(hl.failing) + '. What ' + (hl.failing.length === 1 ? 'it watches' : 'they watch') + ' is not being checked. ',
        h('button', { class: 'linkbtn', type: 'button', dataset: { fk: 'jump-f' }, onClick: jump }, 'See why'))) : null,
      hl.state !== 'stale' && (hl.overdue.length || hl.never.length) ? h('p', { class: 'sec-note warn' }, icon('warning', 14), h('span', null, names([...hl.overdue, ...hl.never]) + ': ' + (hl.overdue.length + hl.never.length === 1 ? 'this scanner has' : 'these scanners have') + ' not run when due. ',
        h('button', { class: 'linkbtn', type: 'button', dataset: { fk: 'jump-o' }, onClick: jump }, 'See the scanners'))) : null,
      hl.noSignatures && hl.state !== 'stale' ? h('p', { class: 'sec-note' }, icon('info', 14), h('span', null, 'No signature engine is installed (ClamAV or YARA). Files are judged by Apple’s checks and by heuristics only.')) : null,
    ];
    return swap(head,
      h('div', { class: 'sec-title' }, h('h1', null, 'Threats'), h('span', { class: 'verdict-btn static v-' + lv.cls }, icon(lv.icon, 14), lv.label), h('span', { class: 'grow' }), scan),
      lead ? h('p', { class: 'th-lead' }, lead) : null, tiles, notes);
  }

  function pickRow(f, st) {
    const sk = sevKey(f.severity);
    const on_ = picked.has(f.id);
    const cb = h('input', { type: 'checkbox', class: 'f-cb', checked: on_, 'aria-label': 'Select: ' + safeText(f.title), dataset: { fk: 'pick-' + f.id },
      onClick: e => {
        const want = e.target.checked;
        const i = shownIds.indexOf(f.id), j = e.shiftKey && lastPick ? shownIds.indexOf(lastPick) : -1;
        const range = j >= 0 ? shownIds.slice(Math.min(i, j), Math.max(i, j) + 1) : [f.id];
        range.forEach(id => (want ? picked.add(id) : picked.delete(id)));
        lastPick = f.id; render();
      } });
    return h('li', null, h('label', { class: 'frow pick s-' + sk + (on_ ? ' picked' : ''), dataset: { id: f.id } },
      cb, sevChip(f.severity),
      h('span', { class: 'f-what' }, h('span', { class: 'f-title' }, safeNodes(f.title), f.isNew && f.state === 'open' ? h('span', { class: 'newtag' }, 'new') : null), subjectLine(f)),
      confMeter(f),
      h('span', { class: 'f-end' }, f.state !== 'open' ? h('span', { class: 'tag' }, (STATE_LABEL[f.state] || safeText(f.state)).toLowerCase()) : null)));
  }

  function row(f, st, fresh) {
    if (picking) return pickRow(f, st);
    const sk = sevKey(f.severity);
    const sel = st.route.sel.includes(f.id);
    const seen = f.state === 'resolved' && f.resolvedAt ? h('span', { class: 'seen' }, 'resolved ' + relTime(f.resolvedAt, st.now)) : f.firstSeen ? h('span', { class: 'seen' }, 'first seen ' + relTime(f.firstSeen, st.now)) : null;
    if (seen) tip(seen, absTime(f.state === 'resolved' && f.resolvedAt ? f.resolvedAt : f.firstSeen));
    return h('li', null, h('button', { class: 'frow s-' + sk + (sel ? ' sel' : '') + (fresh ? ' enter' : ''), type: 'button', 'aria-current': sel ? 'true' : null, dataset: { id: f.id, fk: 'f-' + f.id }, onClick: () => select(f.id) },
      sevChip(f.severity),
      h('span', { class: 'f-what' }, h('span', { class: 'f-title' }, safeNodes(f.title), f.isNew && f.state === 'open' ? h('span', { class: 'newtag' }, 'new') : null), subjectLine(f)),
      confMeter(f),
      h('span', { class: 'f-end' }, f.state !== 'open' ? h('span', { class: 'tag' }, (STATE_LABEL[f.state] || safeText(f.state)).toLowerCase()) : null, seen)));
  }

  function renderList(st, lv) {
    const doc = st.threats, hl = lv.health;
    if (lv.key === 'loading') { swap(tools); return swap(listEl, skeleton(8)); }
    if (lv.key === 'missing') {
      swap(tools);
      return swap(listEl, h('div', { class: 'th-quiet' }, h('h2', null, 'Threat scanning is not running on this server yet.'),
        h('p', null, 'Nothing on this Mac has been checked from here, so this page cannot say it is safe. The device checks on the Security page still run.'),
        h('p', { class: 'muted small' }, 'This page looks again every minute.'),
        h('button', { class: 'btn sm', type: 'button', onClick: () => go({ view: 'security', sel: [], panel: null }) }, 'Open Security')));
    }
    if (!doc) { swap(tools); return swap(listEl, errorState(st.threatsError || 'no detail', () => loadThreats(), 'The findings could not be loaded.')); }

    const all = doc.findings;
    const count = s => all.filter(f => f.state === s).length;
    const pool = flt.state === 'resolved' ? (allDoc ? (allDoc.findings || []).filter(f => f.state === 'resolved') : null) : all.filter(f => f.state === flt.state);
    const shown = pool && pool.filter(f => (!flt.sev || f.severity === flt.sev) && (!flt.cat || f.category === flt.cat) && (!flt.scanner || f.scanner === flt.scanner));
    const cats = [...new Set((pool || []).map(f => f.category).filter(Boolean))];
    shownIds = shown ? shown.map(f => f.id) : [];
    const onScreen = new Set(shownIds);
    [...picked].forEach(id => { if (!onScreen.has(id)) picked.delete(id); });
    const canPick = flt.state !== 'resolved' && flt.state !== 'quarantined' && shown && shown.length > 1;
    if (picking && !canPick && !bulkBusy) { picking = false; picked.clear(); }
    const others = STATES.filter(s => s !== 'open' && s !== 'resolved' && count(s) > 0);

    // filters: shown when there is something to filter, or a filter is on
    const showTools = !dflt() || (pool && pool.length > 1);
    swap(tools, showTools ? [
      h('select', { class: 'select', 'aria-label': 'State', dataset: { fk: 'f-state', v: flt.state }, onChange: e => setFlt({ state: e.target.value, sev: null }) },
        STATES.map(s => h('option', { value: s, selected: flt.state === s }, STATE_LABEL[s] + (s === 'resolved' ? '' : ' (' + count(s) + ')')))),
      cats.length > 1 || flt.cat ? h('select', { class: 'select', 'aria-label': 'Kind', dataset: { fk: 'f-cat', v: flt.cat || '' }, onChange: e => setFlt({ cat: e.target.value || null }) },
        h('option', { value: '' }, 'Every kind'), [...new Set([...cats, flt.cat].filter(Boolean))].map(c => h('option', { value: c, selected: flt.cat === c }, CATEGORY[c] || safeText(c)))) : null,
      flt.sev ? h('span', { class: 'tag' }, SEV_LABEL[flt.sev] + ' only', h('button', { type: 'button', 'aria-label': 'Show every severity', dataset: { fk: 'x-sev' }, onClick: () => setFlt({ sev: null }) }, icon('close', 12))) : null,
      flt.scanner ? h('span', { class: 'tag' }, safeText(((doc.scanners || {})[flt.scanner] || {}).label || flt.scanner), h('button', { type: 'button', 'aria-label': 'Show every scanner', dataset: { fk: 'x-scn' }, onClick: () => setFlt({ scanner: null }) }, icon('close', 12))) : null,
      !dflt() ? h('button', { class: 'linkbtn', type: 'button', dataset: { fk: 'clear' }, onClick: clearFlt }, 'Clear') : null,
      h('span', { class: 'grow' }),
      shown && pool && shown.length !== pool.length ? h('span', { class: 'muted small' }, shown.length + ' of ' + pool.length) : null,
      canPick ? h('button', { class: 'btn sm', type: 'button', 'aria-pressed': String(picking), dataset: { fk: 'pick' }, disabled: bulkBusy,
        onClick: () => { if (picking) stopPicking(); else { picking = true; render(); } } }, picking ? 'Done' : 'Select') : null,
    ] : null);

    const out = [];
    if (!pool) out.push(skeleton(5));
    else if (allDoc && allDoc.error && flt.state === 'resolved') out.push(errorState(allDoc.error, () => { allDoc = null; loadAll(); render(); }, 'The resolved findings could not be loaded.'));
    else if (shown.length) {
      const ids = new Set(shown.map(f => f.id));
      if (picking) out.push(bulkBar(shown));
      out.push(h('ul', { class: 'frows', 'aria-label': STATE_LABEL[flt.state] + ' findings' }, shown.map(f => row(f, st, !!rendered && !rendered.has(f.id) && f.isNew))));
      rendered = flt.state === 'open' && dflt() ? ids : rendered;
    } else if (!dflt() && (flt.sev || flt.cat || flt.scanner || flt.state !== 'open')) {
      out.push(h('div', { class: 'th-quiet' }, h('p', null, flt.state === 'resolved' && !flt.sev && !flt.cat && !flt.scanner ? 'Nothing has been resolved yet.' : 'No ' + (flt.state === 'open' ? 'open' : STATE_LABEL[flt.state].toLowerCase()) + ' finding matches.'),
        h('button', { class: 'btn sm', type: 'button', dataset: { fk: 'clear2' }, onClick: clearFlt }, 'Show open findings')));
    } else {
      // nothing open: say what was looked at and when, and no more than the scans support
      rendered = new Set();
      const items = hl.list.reduce((n, x) => n + (x.ok === false ? 0 : x.itemsScanned || 0), 0);
      const working = hl.list.length - hl.failing.length - hl.never.length - hl.overdue.length;
      const line = hl.state === 'ok' ? plural(hl.list.length, 'scanner') + ' looked at ' + num(items) + ' items. The last one ran ' + relTime(doc.summary.lastScan, st.now) + '.'
        : hl.state === 'partial' ? working + ' of ' + plural(hl.list.length, 'scanner') + ' looked at ' + num(items) + ' items. What the ' + (hl.list.length - working === 1 ? 'other watches' : 'others watch') + ' has not been checked.'
          : hl.firstRun ? 'The first scan has not finished.' : hl.last ? 'That was true at the last scan, ' + relTime(doc.summary.lastScan, st.now) + '. Nothing has been checked since.' : 'No scan has run.';
      out.push(h('div', { class: 'th-quiet' + (hl.state === 'ok' ? ' ok' : '') }, h('h2', null, hl.state === 'ok' ? 'Nothing is open.' : hl.state === 'partial' ? 'Nothing is open in what was checked.' : hl.firstRun ? 'Nothing has been checked yet.' : 'Nothing was open.'), h('p', null, line)));
    }
    if (flt.state === 'open' && others.length) out.push(h('p', { class: 'th-others' }, others.map((s, i) => [i ? ' · ' : null,
      h('button', { class: 'linkbtn', type: 'button', dataset: { fk: 'o-' + s }, onClick: () => setFlt({ state: s, sev: null }) }, count(s) + ' ' + STATE_LABEL[s].toLowerCase())]),
      ' · ', h('button', { class: 'linkbtn', type: 'button', dataset: { fk: 'o-res' }, onClick: () => setFlt({ state: 'resolved', sev: null }) }, 'resolved')));
    else if (flt.state === 'open' && dflt()) out.push(h('p', { class: 'th-others' }, h('button', { class: 'linkbtn', type: 'button', dataset: { fk: 'o-res' }, onClick: () => setFlt({ state: 'resolved' }) }, 'Resolved findings')));
    swap(listEl, out);
  }

  function bulkBar(shown) {
    const sel = shown.filter(f => picked.has(f.id));
    const all = sel.length === shown.length;
    const allCb = h('input', { type: 'checkbox', checked: all && sel.length > 0, 'aria-label': all ? 'Select none' : 'Select every finding shown', dataset: { fk: 'pick-all' },
      onChange: () => { if (all) picked.clear(); else shown.forEach(f => picked.add(f.id)); render(); } });
    allCb.indeterminate = sel.length > 0 && !all;
    const btns = BULK_ORDER.map(a => {
      const fits = sel.filter(f => Array.isArray(f.actions) && f.actions.includes(a));
      const b = h('button', { class: 'act', type: 'button', disabled: bulkBusy || !fits.length, dataset: { fk: 'bulk-' + a },
        onClick: () => (NEEDS_CONFIRM.has(a) ? confirmBulk(a, fits) : runBulk(a, fits, b)) },
        icon(ACT[a].icon, 14), h('span', null, ACT[a].label + (fits.length ? ' ' + fits.length : '')));
      if (fits.length && fits.length < sel.length) tip(b, plural(sel.length - fits.length, 'selected finding') + ' cannot be ' + PAST[a] + ' and will be left as ' + (sel.length - fits.length === 1 ? 'it is' : 'they are') + '.');
      return b;
    });
    return h('div', { class: 'th-bulk', role: 'toolbar', 'aria-label': 'Act on the selected findings' },
      h('label', { class: 'check' }, allCb, h('span', { 'aria-live': 'polite' }, sel.length ? sel.length + ' selected' : 'Select findings')),
      h('span', { class: 'grow' }), btns,
      h('button', { class: 'btn sm', type: 'button', disabled: bulkBusy, dataset: { fk: 'pick-cancel' }, onClick: stopPicking }, 'Cancel'));
  }

  async function runBulk(action, list, btn, confirm) {
    if (bulkBusy || !list.length) return false;
    bulkBusy = true;
    if (btn) { btn.disabled = true; fill(btn, h('span', { class: 'spinner' }), h('span', null, ACT[action].doing)); }
    let res;
    try {
      res = await api.threatBulk({ action, ids: list.map(f => f.id), confirm: !!confirm });
      if (!res || !Array.isArray(res.done)) throw new Error((res && res.error) || 'The server gave no reason.');
    } catch (e) {
      bulkBusy = false; render();
      toast(h('span', null, h('b', null, ACT[action].label + ' did not happen. '), safeText(e.message)), { intent: 'caution' });
      return false;
    }
    bulkBusy = false;
    res.done.forEach(f => { details.delete(f.id); applyFinding(f); });
    const failed = res.failed || [];
    failed.forEach(x => picked.delete(x.id));
    picking = false; picked.clear(); lastPick = null;
    const word = PAST[action][0].toUpperCase() + PAST[action].slice(1);
    toast(failed.length
      ? h('span', null, h('b', null, word + ': ' + res.done.length + '. '), plural(failed.length, 'finding') + ' could not be: ', safeText(failed[0].error) + (failed.length > 1 ? ' and more.' : '.'))
      : word + ': ' + plural(res.done.length, 'finding') + '.', { intent: failed.length ? 'caution' : 'success' });
    loadThreats(); if (allDoc) loadAll();
    render();
    return true;
  }

  /** Trust for many: what is in the set, how bad the worst is, and how to undo it. Cancel has the focus. */
  function confirmBulk(action, list) {
    const a = ACT[action];
    const serious = list.filter(f => f.severity === 'critical' || f.severity === 'high');
    const by = SEV.map(k => [k, list.filter(f => sevKey(f.severity) === k).length]).filter(x => x[1]);
    const note = h('div', { class: 'cf-note' });
    let dlg = null;
    const cancel = h('button', { class: 'btn', type: 'button', onClick: () => dlg.close() }, 'Cancel');
    const ok = h('button', { class: 'btn primary', type: 'button', onClick: async () => {
      cancel.disabled = true; ok.disabled = true; fill(ok, h('span', { class: 'spinner' }), a.doing);
      if (await runBulk(action, list, null, true)) dlg.close();
      else { cancel.disabled = false; ok.disabled = false; fill(ok, icon(a.icon, 14), 'Try again'); }
    } }, icon(a.icon, 14), 'Trust ' + plural(list.length, 'finding'));
    const body = h('div', { class: 'body confirm-act' },
      h('div', { class: 'cf-target' }, by.map(([k, n]) => h('span', { class: 'cf-sev' }, sevChip(k), h('span', null, '× ' + n)))),
      h('ul', { class: 'cf-list' }, list.slice(0, 8).map(f => h('li', null, safeNodes(f.title))), list.length > 8 ? h('li', { class: 'muted' }, 'and ' + (list.length - 8) + ' more') : null),
      h('dl', { class: 'cf-dl' }, h('dt', null, 'What happens'), h('dd', null, 'Each one is added, as it is now, to the baseline. They leave the open list, and each is raised again only if it changes.'),
        h('dt', null, 'Undo'), h('dd', null, 'Open any of them under Trusted and choose Reopen.')),
      serious.length ? callout('caution', plural(serious.length, 'of these is', 'of these are') + ' high or critical. Trust them only if you know what each one is.') : null, note,
      h('div', { class: 'cf-foot' }, h('span', { class: 'grow muted small' }, 'Each one is written to the audit log.'), cancel, ok));
    dlg = dialog({ title: 'Trust ' + plural(list.length, 'finding') + '?', body, cls: 'cf r-change' });
    cancel.focus({ preventScroll: true });
  }

  function renderCover(st, lv) {
    const doc = st.threats, hl = lv.health;
    if (!doc || lv.key === 'missing' || lv.key === 'loading') return swap(cover);
    const now = st.now;
    const allBusyNow = scanBusy.has('*');
    const scn = x => {
      const running = x.running || scanBusy.has(x.name) || allBusyNow || pendingRun.get(x.name) > Date.now();
      const failing = x.ok === false;
      const overdue = hl.overdue.some(o => o.name === x.name);
      const never = !x.lastRun && !failing;
      const state = running ? h('span', { class: 'spinner', role: 'img', 'aria-label': 'Scanning' }) : failing ? icon('warning', 14) : never || overdue ? icon('dash', 14) : icon('check', 14);
      const when = x.lastRun ? relTime(x.lastRun, now) : null;
      const line = running ? 'Scanning…'
        : failing ? ['Failing', when ? ' · last tried ' + when : '']
          : never ? 'Has not run yet'
            : [h('span', { class: 'sr-only' }, 'Ok. '), 'Ran ' + when, ' · ' + plural(x.itemsScanned || 0, 'item').replace(/^\d+/, num(x.itemsScanned || 0)), overdue ? ' · overdue, runs every ' + duration(x.intervalSec || 0) : ''];
      const whenEl = h('span', { class: 'scn-run' }, line);
      if (x.lastRun) tip(whenEl, absTime(x.lastRun) + (x.durationMs != null ? ' · took ' + (x.durationMs < 1000 ? x.durationMs + ' ms' : (x.durationMs / 1000).toFixed(1) + ' s') : '') + (x.intervalSec ? ' · runs every ' + duration(x.intervalSec) : ''));
      const go2 = h('button', { class: 'act', type: 'button', disabled: !!running, dataset: { fk: 'scan-' + x.name }, 'aria-label': 'Scan now: ' + safeText(x.label || x.name), onClick: () => scanNow(x.name) }, icon('scan', 14), h('span', null, 'Scan now'));
      return h('div', { class: 'scn' + (failing ? ' bad' : overdue || never ? ' late' : '') + (running ? ' running' : ''), role: 'listitem' },
        h('span', { class: 'scn-st' }, state),
        h('div', { class: 'scn-what' }, h('b', null, safeNodes(x.label || x.name)), x.description ? h('span', { class: 'm' }, safeNodes(x.description)) : null,
          failing ? h('span', { class: 'scn-err' }, safeNodes(x.error || 'The scanner gave no reason.')) : null),
        h('div', { class: 'scn-meta' }, whenEl, x.open ? h('button', { class: 'linkbtn', type: 'button', dataset: { fk: 'so-' + x.name }, onClick: () => setFlt({ scanner: x.name, state: 'open', sev: null, cat: null }) }, x.open + ' open') : null),
        go2);
    };
    const e = doc.engines || {};
    const daysOld = ts => (toMs(ts) ? Math.floor((now - toMs(ts)) / 86400000) : null);
    const old = d => (d == null ? '' : d < 1 ? ' · signatures from today' : ' · signatures ' + plural(d, 'day') + ' old');
    const eng = (bad, text, hint) => { const n = h('span', { class: 'pst ' + (bad === null ? 'unk' : bad ? 'bad' : 'ok') }, icon(bad === null ? 'dash' : bad ? 'warning' : 'check', 12), text); if (hint) tip(n, hint); return n; };
    const ca = e.clamav, ya = e.yara, xp = e.xprotect, gk = e.gatekeeper;
    const caAge = ca && ca.installed ? daysOld(ca.signaturesAt) : null;
    const engines = [
      !ca ? eng(null, 'ClamAV: not reported') : !ca.installed ? eng(true, 'ClamAV is not installed', 'Without it no file is checked against known malware signatures. brew install clamav adds it.')
        : eng(caAge != null && caAge > 7, ['ClamAV ', safeText(ca.version || ''), ca.signaturesAt ? old(caAge) : ' · signature age not known'], ca.signaturesAt ? 'Signatures updated ' + absTime(ca.signaturesAt) + (caAge > 7 ? '. Run freshclam to update them.' : '') : null),
      !ya ? eng(null, 'YARA: not reported') : !ya.installed ? eng(true, 'YARA is not installed', 'Without it the rule files are not used.') : eng(!ya.rules, 'YARA · ' + plural(Number(ya.rules) || 0, 'rule')),
      !xp || !xp.version ? eng(null, 'XProtect: version not known') : eng(false, ['XProtect ', safeText(xp.version), xp.updatedAt ? ' · updated ' + relTime(xp.updatedAt, now) : ''], xp.updatedAt ? 'Apple’s built-in malware definitions, updated ' + absTime(xp.updatedAt) : null),
      !gk || gk.enabled == null ? eng(null, 'Gatekeeper: not reported') : eng(!gk.enabled, gk.enabled ? 'Gatekeeper is on' : 'Gatekeeper is off', 'Gatekeeper checks that an app is signed and notarized before it first opens.'),
    ];
    const allBtn = h('button', { class: 'btn sm', type: 'button', disabled: allBusyNow, dataset: { fk: 'scan-all' }, onClick: () => scanNow() }, allBusyNow ? h('span', { class: 'spinner' }) : icon('scan', 14), 'Scan everything now');
    swap(cover,
      h('h2', { class: 'sgroup' }, 'What is scanned', h('span', { class: 'grow' }), allBtn),
      h('div', { class: 'scns', role: 'list' }, hl.list.length ? hl.list.map(scn) : h('p', { class: 'muted pad' }, 'The server lists no scanners.')),
      h('h2', { class: 'sgroup' }, 'What does the scanning'),
      h('div', { class: 'engs' }, engines));
  }

  function render() {
    const st = get();
    const lv = threatLevel(st);
    renderHead(st, lv); renderList(st, lv); renderCover(st, lv);
  }
  on(['threats', 'threatsError', 'threatTick', 'now', 'route', 'inventory'], () => { if (get().route.view === 'threats') render(); });
  window.matchMedia('(max-width: 767px)').addEventListener('change', () => { if (get().route.view === 'threats') render(); });
  return { el, show() { render(); if (Date.now() - lastTry > 4000) loadThreats(); } };
}
