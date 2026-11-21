// Activity: events (status changes, new hosts) and the audit log (everything the agent did, who decided what).
// The same content appears in the bottom drawer on the other views.
import { h, fill, tablist } from './dom.js';
import { icon } from './icons.js';
import { get, set, on, go, select } from './store.js';
import { api } from './api.js';
import * as G from './graph.js';
import { deviceChip, seg, tip, skeleton, errorState, emptyState, toast } from './ui.js';
import { relTime, absTime, clock, cableName, plural } from './fmt.js';

export async function loadEvents() {
  try { set({ events: await api.events(300), eventsError: null }); } catch (e) { set({ eventsError: e.message }); }
}
export async function loadAudit() {
  try { set({ audit: await api.audit(500), auditError: null }); } catch (e) { set({ auditError: e.message }); }
}

const KIND = { device: ['status', ''], link: ['link', 'info'], stranger: ['new host', 'caution'], security: ['security', 'danger'] };
const isPerson = a => a === 'person' || a === 'you';
const ACTOR = a => (isPerson(a) ? 'you' : a || 'system');
const TYPE = { 'device-action': 'device action', router: 'router', ask: 'question', tool: 'tool', proposal: 'proposed', decision: 'decided', refused: 'refused', 'action-result': 'ran', 'run-end': 'run ended', cancel: 'cancel', settings: 'settings' };

function timeCell(ts) {
  const el = h('span', { class: 'mono muted tm' }, relTime(ts, get().now));
  tip(el, absTime(ts));
  return el;
}

function eventRow(ev, dense) {
  const [word, cls] = KIND[ev.kind] || [ev.kind || 'event', ''];
  const l = ev.link && G.link(ev.link);
  const subject = ev.device && G.isDeviceId(ev.device) ? deviceChip(ev.device)
    : l ? h('button', { class: 'chip', title: cableName(l.cable) + ' · ' + G.deviceName(l.a.dev) + ' → ' + G.deviceName(l.b.dev), onClick: () => select(l.id) }, h('span', { class: 'ellipsis' }, cableName(l.cable) + ' · ' + G.deviceName(l.a.dev) + ' → ' + G.deviceName(l.b.dev)))
      : ev.ip ? h('span', { class: 'mono' }, ev.ip) : null;
  return h('div', { class: 'ev-row' + (dense ? ' dense' : '') }, timeCell(ev.ts), h('span', { class: 'tag ' + cls }, word), h('span', { class: 'subj' }, subject), h('span', { class: 'txt' }, ev.text || `${ev.from || '?'} → ${ev.to || '?'}`));
}

function eventsBody(opts = {}) {
  const st = get();
  if (!st.events) return st.eventsError ? errorState(st.eventsError, loadEvents, 'The events could not be loaded.') : skeleton(8);
  let evs = st.events;
  if (opts.kind) evs = evs.filter(e => e.kind === opts.kind);
  if (opts.device) evs = evs.filter(e => e.device === opts.device || (e.link && G.link(e.link) && [G.link(e.link).a.dev, G.link(e.link).b.dev].includes(opts.device)));
  if (opts.range) { const min = st.now - opts.range * 3600e3; evs = evs.filter(e => Date.parse(e.ts) >= min); }
  if (!evs.length) return emptyState(st.events.length ? 'No events match these filters.' : 'Nothing has changed since the monitor started. Status changes and new hosts appear here.');
  return h('div', { class: 'ev-list' }, evs.map(e => eventRow(e, opts.dense)));
}

function auditBody(opts = {}) {
  const st = get();
  if (!st.audit) return st.auditError ? errorState(st.auditError, loadAudit, 'The audit log could not be loaded.') : skeleton(8);
  if (!st.audit.length) return emptyState('Nothing has been logged yet.');
  // group by run, newest group first; rows without a run stand alone
  const groups = [];
  const byRun = new Map();
  for (const r of st.audit) {
    if (r.runId) {
      if (!byRun.has(r.runId)) { const g = { runId: r.runId, rows: [] }; byRun.set(r.runId, g); groups.push(g); }
      byRun.get(r.runId).rows.push(r);
    } else groups.push({ runId: null, rows: [r] });
  }
  const row = r => {
    const decision = r.type === 'decision';
    const typeWord = decision ? (r.decision === 'approve' ? 'approved' : 'rejected') : (TYPE[r.type] || r.type);
    const cls = r.type === 'refused' || (r.type === 'action-result' && r.exitCode) ? 'danger' : decision && r.decision === 'approve' ? 'info' : r.type === 'proposal' ? 'caution' : '';
    return h('div', { class: 'au-row' + (decision || isPerson(r.actor) ? ' you' : '') }, timeCell(r.ts), h('span', { class: 'actor' }, ACTOR(r.actor)), h('span', { class: 'tag ' + cls }, typeWord),
      h('div', { class: 'txt' }, r.summary ? h('span', null, r.summary) : null, r.command ? h('code', { class: 'mono cmd' }, r.command) : null),
      h('span', { class: 'mono muted exit' }, r.exitCode != null ? 'exit ' + r.exitCode : ''));
  };
  const focus = opts.run;
  return h('div', { class: 'au-list' }, groups.map(g => {
    if (!g.runId) return h('div', { class: 'au-group solo' }, g.rows.map(row));
    const q = g.rows.find(r => r.type === 'ask');
    const rows = [...g.rows].reverse();
    return h('div', { class: 'au-group' + (focus === g.runId ? ' focus' : ''), dataset: { run: g.runId } },
      h('div', { class: 'au-h' }, h('span', { class: 'grow q' }, q ? q.summary : 'Run ' + g.runId), h('span', { class: 'mono muted' }, clock(rows[0].ts)),
        h('button', { class: 'btn sm', onClick: () => go({ view: 'agent', run: g.runId, panel: null }) }, 'Open run')),
      rows.filter(r => r.type !== 'ask').map(row));
  }));
}

function exportAudit() {
  const rows = get().audit || [];
  const blob = new Blob([rows.map(r => JSON.stringify(r)).join('\n') + '\n'], { type: 'application/x-ndjson' });
  const a = h('a', { href: URL.createObjectURL(blob), download: 'home-observability-hub-audit.jsonl' });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  toast(`Exported ${plural(rows.length, 'audit row')}, as the server returned them.`, { intent: 'success' });
}

export function createActivity() {
  let kind = '', device = '', range = 0;
  const tabs = h('div', { class: 'tabs' });
  const bar = h('div', { class: 'view-h' });
  const body = h('div', { class: 'scroll grow' });
  const el = h('div', { class: 'view' }, tabs, bar, body);

  function render() {
    const st = get();
    const at = st.route.at;
    const tab = (id, label, n) => h('button', { type: 'button', role: 'tab', 'aria-selected': String(at === id), onClick: () => go({ at: id }) }, label, n != null ? h('span', { class: 'count' }, String(n)) : null);
    fill(tabs, tablist('Activity', [tab('events', 'Events', st.events ? st.events.length : null), tab('audit', 'Audit', st.audit ? st.audit.length : null)]),
      h('span', { class: 'end' }, h('button', { class: 'btn sm minimal', onClick: () => { loadEvents(); loadAudit(); } }, 'Refresh')));
    if (at === 'events') {
      const devs = st.events ? [...new Set(st.events.map(e => e.device).filter(G.isDeviceId))] : [];
      fill(bar,
        h('select', { class: 'select', 'aria-label': 'Kind of event', onChange: e => { kind = e.target.value; render(); } }, [['', 'Kind: all'], ['security', 'Security'], ['device', 'Status'], ['link', 'Link'], ['stranger', 'New host']].map(([v, t]) => h('option', { value: v, selected: v === kind }, t))),
        h('select', { class: 'select', 'aria-label': 'Device', onChange: e => { device = e.target.value; render(); } }, h('option', { value: '' }, 'Device: all'), devs.map(d => h('option', { value: d, selected: d === device }, G.deviceName(d)))),
        seg([{ value: 0, label: 'All' }, { value: 1, label: '1 h' }, { value: 24, label: '24 h' }, { value: 168, label: '7 d' }], range, v => { range = v; render(); }, { label: 'Time range' }));
      const top = body.scrollTop; fill(body, eventsBody({ kind, device, range })); body.scrollTop = top;
    } else {
      fill(bar, h('span', { class: 'muted grow view-lede' }, 'Every question, tool use, proposal and decision, grouped by run. Decisions made by you are bold.'),
        h('button', { class: 'btn sm', disabled: !(st.audit && st.audit.length), onClick: exportAudit }, icon('download', 14), 'Export as JSONL'));
      const top = body.scrollTop; fill(body, auditBody({ run: st.route.run })); body.scrollTop = top;
      const f = body.querySelector('.au-group.focus'); if (f && !render.scrolled) { render.scrolled = true; f.scrollIntoView({ block: 'start' }); }
    }
  }
  on(['events', 'eventsError', 'audit', 'auditError', 'route', 'inventory'], () => { if (get().route.view === 'activity') render(); });
  return { el, show() { render.scrolled = false; loadEvents(); loadAudit(); render(); } };
}

/** The bottom drawer: a one-line ticker when closed, events or audit when open. */
export function createDrawer() {
  const ticker = h('span', { class: 'ticker ellipsis grow' });
  const toggle = h('button', { class: 'toggle', type: 'button', 'aria-expanded': 'false', onClick: () => toggleDrawer() }, icon('activity', 14), h('span', null, 'Activity'), ticker);
  tip(toggle, h('span', null, 'Open or close the activity drawer', h('kbd', null, '`')));
  const segHost = h('span');
  const body = h('div', { class: 'd-b scroll' });
  const resizer = h('div', { class: 'resizer h', role: 'separator', 'aria-orientation': 'horizontal', 'aria-label': 'Resize the activity drawer' });
  const said = h('div', { class: 'sr-only', role: 'status' });
  let lastSaid = null;
  const el = h('div', { class: 'view' }, said, resizer, h('div', { class: 'd-h' }, toggle, segHost, h('button', { class: 'btn sm minimal', onClick: () => go({ view: 'activity' }) }, 'Open Activity')), body);
  resizer.addEventListener('pointerdown', e => {
    e.preventDefault(); resizer.classList.add('dragging'); resizer.setPointerCapture(e.pointerId);
    const app = document.querySelector('.app');
    const move = ev => { const hgt = Math.min(480, Math.max(160, window.innerHeight - ev.clientY)); app.style.setProperty('--drawer-h', hgt + 'px'); };
    const up = () => { resizer.classList.remove('dragging'); resizer.removeEventListener('pointermove', move); resizer.removeEventListener('pointerup', up); };
    resizer.addEventListener('pointermove', move); resizer.addEventListener('pointerup', up);
  });
  function render() {
    const st = get();
    const open = st.ui.drawer === 'open';
    toggle.setAttribute('aria-expanded', String(open));
    const newest = st.events && st.events[0];
    const key = newest ? newest.ts + '|' + (newest.text || '') : null;
    if (key && lastSaid && key !== lastSaid) said.textContent = 'New event: ' + (newest.text || '');
    if (key) lastSaid = key;
    ticker.textContent = newest ? ' · ' + relTime(newest.ts, st.now) + ' · ' + (newest.text || '') : st.eventsError ? ' · events could not be loaded' : st.events ? ' · nothing has changed since the monitor started' : '';
    if (!open) return;
    fill(segHost, seg([{ value: 'events', label: 'Events' }, { value: 'audit', label: 'Audit' }], st.ui.drawerTab, v => { set({ ui: { ...get().ui, drawerTab: v } }); if (v === 'audit') loadAudit(); }, { cls: 'sm', label: 'Drawer content' }));
    const top = body.scrollTop;
    fill(body, st.ui.drawerTab === 'audit' ? auditBody() : eventsBody({ dense: true }));
    body.scrollTop = top;
  }
  on(['events', 'eventsError', 'audit', 'auditError', 'ui', 'now'], render);
  render();
  return { el };
}

export function toggleDrawer() {
  const ui = get().ui;
  const open = ui.drawer !== 'open';
  set({ ui: { ...ui, drawer: open ? 'open' : 'closed' } });
  if (open) { loadEvents(); if (ui.drawerTab === 'audit') loadAudit(); }
}
