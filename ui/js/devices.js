// Devices view: the inventory as a sortable, filterable table. It is the accessible equivalent of the map.
import { h, fill } from './dom.js';
import { icon } from './icons.js';
import { get, set, on, select, pref, setPref } from './store.js';
import * as G from './graph.js';
import { statusGlyph, trustEl, callout, skeleton, errorState, emptyState, tip } from './ui.js';
import { statusLabel, kindLabel, cableName, relTime, absTime, plural } from './fmt.js';
import { matches } from './objectlist.js';
import { idChip, secChip } from './security.js';

function via(d) {
  const ls = G.linksOf(d.id);
  if (ls.length) {
    const l = ls.find(x => (x.carries || []).includes('network')) || ls[0];
    const o = G.peer(l, d.id).other;
    return `${cableName(l.cable)}${l.speed ? ' ' + l.speed : ''} → ${G.deviceName(o.dev)}`;
  }
  return G.connText(d);
}
const MED_RANK = { wired: 0, wifi: 1, bluetooth: 2, lan: 3, tunnel: 4, cable: 5, none: 6 };
const ID_RANK = { unidentified: 0, likely: 1, confirmed: 2 };
const SEC_RANK = { suspicious: 0, blocked: 1, watch: 2, ok: 3 };
function apText(d) { const c = G.conn(d); const w = c.medium === 'wifi' ? c : null; return w ? (w.ap ? G.shortName(w.ap) + (w.band ? ' · ' + w.band : '') : 'not known') : ''; }

const COLS = [
  { id: 'status', label: 'Status', get: d => G.statusRank(G.statusOf(d.id)) },
  { id: 'name', label: 'Name', get: d => d.name.toLowerCase() },
  { id: 'kind', label: 'Kind', get: d => kindLabel(d.kind) },
  { id: 'model', label: 'Make and model', get: d => G.brandOf(d).toLowerCase() || '~' },
  { id: 'ident', label: 'Identity', get: d => { const s = G.identityOf(d).state; return s in ID_RANK ? ID_RANK[s] : 3; } },
  { id: 'sec', label: 'Security', get: d => { const l = G.secLevel(d.id); return l in SEC_RANK ? SEC_RANK[l] : 4; } },
  { id: 'zone', label: 'Room', get: d => G.groups().findIndex(g => g.id === d.zone) },
  { id: 'ip', label: 'Address', get: d => (G.primaryIp(d) || '').split('.').map(x => x.padStart(3, '0')).join('.') || '~' },
  { id: 'medium', label: 'Connection', get: d => MED_RANK[G.conn(d).medium] },
  { id: 'ap', label: 'Access point', get: d => apText(d) || '~' },
  { id: 'trust', label: 'Trust', get: d => d.verified },
  { id: 'seen', label: 'Last seen', get: d => -(Date.parse((G.liveOf(d.id) || {}).lastSeen || 0) || 0) },
  { id: 'latency', label: 'Latency', get: d => { const v = (G.liveOf(d.id) || {}).latencyMs; return v == null ? Infinity : v; }, cls: 'num' },
];

export function createDevices() {
  let q = '', sort = pref('dev.sort', { col: 'status', dir: 1 }), group = pref('dev.groupRoom', true), compact = pref('dev.compact', false);
  let fKind = '', fZone = '', fTrust = '';
  const search = h('input', { class: 'input', type: 'search', placeholder: 'Search devices', 'aria-label': 'Search devices', onInput: e => { q = e.target.value; render(); },
    onKeydown: e => { if (e.key === 'ArrowDown') { const r = body.querySelector('tbody tr[tabindex]'); r && r.focus(); e.preventDefault(); } } });
  const filters = h('div', { class: 'view-f' });
  const count = h('span', { class: 'view-count' });
  const strangersEl = h('div');
  const body = h('div', { class: 'scroll grow dev-body' });
  const el = h('div', { class: 'view devview' }, h('div', { class: 'view-h' }, h('div', { class: 'view-t' }, h('h1', { class: 'hide-sm' }, 'Devices'), count), h('div', { class: 'filter-input dev-search' }, icon('search'), search), filters), strangersEl, body);

  const sel = (label, value, opts, fn) => h('select', { class: 'select', 'aria-label': label, onChange: e => fn(e.target.value) }, h('option', { value: '' }, label + ': all'), opts.map(([v, t]) => h('option', { value: v, selected: v === value }, t)));
  const toggle = (label, on_, fn) => h('label', { class: 'check hide-sm' }, h('input', { type: 'checkbox', checked: on_, onChange: e => fn(e.target.checked) }), label);

  function renderFilters() {
    const st = get();
    const stt = st.filters.status || '';
    const kinds = [...new Set(G.devices().map(d => d.kind))].sort().map(k => [k, kindLabel(k)]);
    fill(filters,
      sel('Status', stt, ['online', 'degraded', 'offline', 'unknown', 'unmonitored'].map(s => [s, statusLabel(s)]), v => set({ filters: { ...get().filters, status: v || null } })),
      sel('Kind', fKind, kinds, v => { fKind = v; render(); }),
      sel('Room', fZone, G.groups().map(g => [g.id, g.label]), v => { fZone = v; render(); }),
      sel('Trust', fTrust, [['live', 'live'], ['plan', 'plan'], ['reported', 'reported']], v => { fTrust = v; render(); }),
      toggle('Group by room', group, v => { group = v; setPref('dev.groupRoom', v); render(); }),
      toggle('Compact', compact, v => { compact = v; setPref('dev.compact', v); render(); }));
  }

  function renderStrangers() {
    const st = get();
    const xs = ((st.live && st.live.strangers) || []).filter(x => !G.isDeviceId('host-' + String(x.ip).replace(/\./g, '-')));
    if (!xs.length) return fill(strangersEl);
    fill(strangersEl, h('div', { class: 'strangers' }, callout('caution',
      h('b', null, xs.length === 1 ? 'New on the network: 1 host is not in the inventory' : `New on the network: ${xs.length} hosts are not in the inventory`),
      h('div', { class: 'stranger-list' }, xs.map(x => { const t = h('span', { class: 'muted' }, 'first seen ' + relTime(x.firstSeen, st.now)); tip(t, absTime(x.firstSeen)); return h('span', { class: 'stranger' }, h('span', { class: 'mono' }, x.ip), x.name ? h('span', null, x.name) : h('span', { class: 'nc' }, 'no name'), t); })),
      h('span', { class: 'muted' }, xs.length === 1 ? 'To track it, add it to ' : 'To track them, add them to ', h('code', null, 'data/inventory.json'), '.'))));
  }

  function rowsFor() {
    const st = get();
    const f = st.filters.status;
    let ds = G.things().filter(d => matches(d, q) && G.matchesFocus(d, st.filters.focus) && (!f || G.statusOf(d.id) === f || (f === 'unknown' && G.statusOf(d.id) === 'inferred')) && (!fKind || d.kind === fKind) && (!fZone || d.zone === fZone) && (!fTrust || d.verified === fTrust));
    const col = COLS.find(c => c.id === sort.col) || COLS[0];
    ds = ds.map((d, i) => ({ d, k: col.get(d), i })).sort((a, b) => (a.k < b.k ? -1 : a.k > b.k ? 1 : a.i - b.i) * sort.dir).map(x => x.d);
    return ds;
  }

  function tr(d) {
    const st = get();
    const status = G.statusOf(d.id), lv = G.liveOf(d.id) || {};
    const ip = G.primaryIp(d);
    const model = G.brandOf(d);
    const c = G.conn(d);
    const lvl = G.secLevel(d.id);
    const seen = h('span', null, lv.lastSeen ? relTime(lv.lastSeen, st.now) : status === 'unmonitored' ? 'not monitored' : 'never');
    if (lv.lastSeen) tip(seen, absTime(lv.lastSeen));
    return h('tr', { tabIndex: -1, dataset: { id: d.id }, 'aria-selected': String(st.route.sel.includes(d.id)),
      onClick: e => select(d.id, { add: e.shiftKey }),
      onMouseenter: () => set({ hover: d.id }), onMouseleave: () => get().hover === d.id && set({ hover: null }) },
      h('td', { class: 'c-status', title: statusLabel(status) }, h('span', { class: 'st' }, statusGlyph(status), h('span', { class: 'st-l' }, statusLabel(status)))),
      h('td', { class: 'c-name', title: d.name }, d.name),
      h('td', { class: 'c-kind muted' }, kindLabel(d.kind)),
      h('td', { class: 'c-model muted', title: model || null }, model || h('span', { class: 'nc' }, G.bestGuess(d) ? 'maybe ' + G.bestGuess(d) : 'not known')),
      h('td', { class: 'c-ident' }, idChip(d)),
      h('td', { class: 'c-sec' }, secChip(d.id, { showOk: true })),
      h('td', { class: 'c-zone', title: G.groupLabel(d.zone) }, group ? (G.groupLabel(d.zone).split(' › ')[1] || G.groupLabel(d.zone)) : G.groupLabel(d.zone)),
      h('td', { class: 'c-ip mono' }, ip || h('span', { class: 'muted' }, 'none')),
      h('td', { class: 'c-medium', title: via(d) }, h('span', { class: 'medc m-' + c.medium }, h('i'), G.MEDIUM[c.medium] || c.medium), ' ', c.medium === 'wired' || c.medium === 'cable' || c.medium === 'bluetooth' ? h('span', { class: 'muted' }, via(d).replace(/^[^→]*/, '')) : c.medium === 'wifi' ? (c.ap ? h('span', { class: 'muted' }, '→ ' + G.shortName(c.ap)) : h('span', { class: 'nc' }, 'access point not known')) : null),
      h('td', { class: 'c-ap muted' }, c.medium === 'wifi' ? (c.ap ? apText(d) : h('span', { class: 'nc' }, 'not known')) : ''),
      h('td', { class: 'c-trust' }, trustEl(d.verified)),
      h('td', { class: 'c-seen muted' }, seen),
      h('td', { class: 'c-latency num mono' }, lv.latencyMs != null ? lv.latencyMs + ' ms' : h('span', { class: 'muted' }, '–')));
  }

  function render() {
    const st = get();
    if (!st.inventory) { fill(body, st.invError ? errorState(st.invError, () => window.__hmReload && window.__hmReload(), 'The inventory could not be loaded.') : skeleton(14)); count.textContent = ''; return; }
    renderFilters(); renderStrangers();
    const ds = rowsFor();
    count.textContent = ds.length === G.things().length ? plural(ds.length, 'device') : `${ds.length} of ${G.things().length} devices`;
    if (!ds.length) {
      fill(body, emptyState('No devices match these filters.', { label: 'Clear filters', fn: () => { q = ''; search.value = ''; fKind = fZone = fTrust = ''; set({ filters: { ...get().filters, status: null, focus: null } }); render(); } }));
      return;
    }
    const focusId = body.contains(document.activeElement) ? document.activeElement.dataset.id : null;
    const head = h('thead', null, h('tr', null, COLS.map(c => {
      const active = sort.col === c.id;
      return h('th', { class: 'c-' + c.id + ' ' + (c.cls || ''), scope: 'col', 'aria-sort': active ? (sort.dir === 1 ? 'ascending' : 'descending') : 'none' },
        h('button', { type: 'button', 'aria-label': 'Sort by ' + c.label, onClick: () => { sort = { col: c.id, dir: active ? -sort.dir : 1 }; setPref('dev.sort', sort); render(); } }, c.id === 'status' ? h('span', { class: 'hide-sm' }, c.label) : c.label, c.id === 'status' ? h('span', { class: 'show-sm' }, statusGlyph('online', 8)) : null, active ? icon(sort.dir === 1 ? 'up' : 'down', 12) : null));
    })));
    const tb = h('tbody');
    if (group) {
      for (const g of G.groups()) {
        const zs = ds.filter(d => d.zone === g.id);
        if (!zs.length) continue;
        tb.appendChild(h('tr', { class: 'group' }, h('td', { colspan: COLS.length }, g.label + ' · ' + zs.length + (g.zone.note ? ' · ' + g.zone.note : ''))));
        zs.forEach(d => tb.appendChild(tr(d)));
      }
    } else ds.forEach(d => tb.appendChild(tr(d)));
    const top = body.scrollTop;
    const cols = h('colgroup', null, COLS.map(c => h('col', { class: 'c-' + c.id })));   // the widths live here, so a hidden column takes no room
    fill(body, h('table', { class: 'table devtable' + (compact ? ' compact' : '') + (group ? ' grouped' : ''), 'aria-label': 'Devices' }, cols, head, tb));
    body.scrollTop = top;
    const rows = [...tb.querySelectorAll('tr[data-id]')];
    const f = rows.find(r => r.dataset.id === focusId);
    (f || rows.find(r => r.getAttribute('aria-selected') === 'true') || rows[0]).tabIndex = 0;
    if (f) f.focus({ preventScroll: true });
  }

  body.addEventListener('keydown', e => {
    const row = e.target.closest && e.target.closest('tr[data-id]');
    if (!row) return;
    const rows = [...body.querySelectorAll('tr[data-id]')];
    const i = rows.indexOf(row);
    let n = null;
    if (e.key === 'ArrowDown') n = rows[i + 1]; else if (e.key === 'ArrowUp') n = rows[i - 1];
    else if (e.key === 'Home') n = rows[0]; else if (e.key === 'End') n = rows[rows.length - 1];
    else if (e.key === 'Enter' || e.key === ' ') { select(row.dataset.id, { add: e.shiftKey }); e.preventDefault(); return; }
    if (e.key === 'ArrowUp' && !n) { search.focus(); e.preventDefault(); return; }
    if (n) { row.tabIndex = -1; n.tabIndex = 0; n.focus(); e.preventDefault(); }
  });

  let dirty = true;
  on(['inventory', 'invError', 'live', 'filters'], () => { if (get().route.view === 'devices') render(); else dirty = true; });
  on(['route'], st => {
    if (st.route.view !== 'devices') return;
    if (dirty) { dirty = false; return render(); }
    for (const r of body.querySelectorAll('tr[data-id]')) r.setAttribute('aria-selected', String(st.route.sel.includes(r.dataset.id)));
  });
  return { el, show() { dirty = false; render(); }, focusSearch: () => { search.focus(); search.select(); } };
}
