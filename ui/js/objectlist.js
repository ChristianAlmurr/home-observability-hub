// The object list: needs attention, a filter, and the devices grouped by zone.
import { h, fill } from './dom.js';
import { icon } from './icons.js';
import { get, set, on, select, go } from './store.js';
import * as G from './graph.js';
import { theMap } from './mapview.js';
import { statusGlyph, tip, skeleton, errorState, emptyState } from './ui.js';
import { statusLabel, kindLabel } from './fmt.js';
import { watchList } from './security.js';

export function matches(d, q) {
  if (!q) return true;
  const idn = G.identityOf(d);
  const hay = [d.name, d.id, d.kind, kindLabel(d.kind), d.vendor, d.model, idn.vendor, idn.model, G.ID_WORD[idn.state], G.secLevel(d.id), G.MEDIUM[G.conn(d).medium], idn.mac, ...(d.net || []).map(n => n.mac), (G.zone(d.zone) || {}).name, G.groupLabel(d.zone), ...(d.net || []).flatMap(n => [n.ip, n.name])].filter(Boolean).join(' ').toLowerCase();
  return q.toLowerCase().split(/\s+/).every(w => hay.includes(w));
}

export function createObjectList() {
  let q = '';
  const input = h('input', { class: 'input', type: 'search', placeholder: 'Filter devices', 'aria-label': 'Filter devices', onInput: e => { q = e.target.value; renderTree(); },
    onKeydown: e => { if (e.key === 'Escape' && q) { e.stopPropagation(); q = ''; input.value = ''; renderTree(); } else if (e.key === 'ArrowDown') { const f = tree.querySelector('.orow'); f && f.focus(); e.preventDefault(); } } });
  const closeBtn = h('button', { class: 'btn minimal icon show-md', 'aria-label': 'Close the device list', onClick: () => set({ ui: { ...get().ui, list: 'closed' } }) }, icon('close'));
  const attn = h('div', { class: 'attn' });
  const tree = h('div', { class: 'tree scroll grow', role: 'group', 'aria-label': 'Devices by room' });
  const el = h('div', { class: 'view' }, h('div', { class: 'list-h' }, h('div', { class: 'filter-input' }, icon('search'), input), closeBtn), attn, tree);

  tree.addEventListener('keydown', e => {
    if (!['ArrowDown', 'ArrowUp'].includes(e.key)) return;
    const rows = [...tree.querySelectorAll('.orow')];
    const i = rows.indexOf(document.activeElement);
    const n = rows[i + (e.key === 'ArrowDown' ? 1 : -1)];
    if (n) n.focus(); else if (e.key === 'ArrowUp') input.focus();
    e.preventDefault();
  });

  function renderAttn() {
    const st = get();
    if (!st.inventory) { fill(attn); attn.hidden = true; return; }
    attn.hidden = false;
    fill(attn, watchList({ limit: 5 }));
  }

  function row(d) {
    const st = G.statusOf(d.id);
    const state = get();
    const ip = G.primaryIp(d);
    const lvl = G.secLevel(d.id), ids = G.identityOf(d).state;
    const mk = lvl === 'suspicious' ? ['sus', '!', 'suspicious'] : lvl === 'blocked' ? ['blk', '×', 'blocked'] : ids === 'unidentified' ? ['unk', '?', 'not identified'] : null;
    const b = h('button', { class: 'orow' + (st === 'offline' ? ' offline' : '') + (state.hover === d.id ? ' hover' : ''), type: 'button', dataset: { id: d.id },
      'aria-current': state.route.sel.includes(d.id) ? 'true' : null,
      onClick: e => select(d.id, { add: e.shiftKey }),
      onMouseenter: () => set({ hover: d.id }), onMouseleave: () => get().hover === d.id && set({ hover: null }) },
      statusGlyph(st, 10), h('span', { class: 'name ellipsis' }, d.name), mk ? h('span', { class: 'omark ' + mk[0] }, h('span', { 'aria-hidden': 'true' }, mk[1]), h('span', { class: 'sr-only' }, ', ' + mk[2])) : null, h('span', { class: 'meta' }, ip || kindLabel(d.kind).toLowerCase()));
    tip(b, () => d.name + ' · ' + statusLabel(G.statusOf(d.id)));
    return b;
  }

  function renderTree() {
    const st = get();
    if (!st.inventory) { fill(tree, st.invError ? errorState(st.invError, () => window.__hmReload && window.__hmReload(), 'The inventory could not be loaded.') : skeleton(12)); return; }
    const f = st.filters.status;
    const out = [];
    let total = 0;
    for (const g of G.groups()) {
      const z = g.zone;
      const ds = G.things().filter(d => d.zone === z.id && matches(d, q) && (!f || G.statusOf(d.id) === f) && G.matchesFocus(d, st.filters.focus));
      if (!ds.length) continue;
      total += ds.length;
      const head = h('button', { type: 'button', onClick: () => { if (get().route.view !== 'map') go({ view: 'map' }); requestAnimationFrame(() => theMap() && theMap().showZone(z.id)); } }, g.label);
      tip(head, 'Centre ' + g.label + ' on the map' + (z.note ? ' · ' + z.note : ''));
      out.push(h('div', { class: 'zone' }, h('h3', null, head, h('span', { class: 'count' }, String(ds.length))), ds.map(row)));
    }
    if (!total) out.push(emptyState('No devices match these filters.', { label: 'Clear filters', fn: () => { q = ''; input.value = ''; set({ filters: { ...get().filters, status: null, focus: null } }); renderTree(); } }));
    const top = tree.scrollTop;
    fill(tree, out);
    tree.scrollTop = top;
  }

  on(['inventory', 'invError', 'live', 'filters'], () => { renderAttn(); renderTree(); });
  on(['route'], () => {
    const sel = get().route.sel;
    for (const r of el.querySelectorAll('.orow[data-id]')) { if (sel.includes(r.dataset.id)) r.setAttribute('aria-current', 'true'); else r.removeAttribute('aria-current'); }
  });
  on(['hover'], () => { const hv = get().hover; for (const r of tree.querySelectorAll('.orow')) r.classList.toggle('hover', r.dataset.id === hv); });
  renderAttn(); renderTree();
  return { el, focusFilter: () => { input.focus(); input.select(); } };
}
