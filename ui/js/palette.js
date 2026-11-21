// Command palette (⌘K) and the keyboard shortcuts sheet.
import { h, fill } from './dom.js';
import { icon, kindIcon } from './icons.js';
import { get, set, go, select } from './store.js';
import * as G from './graph.js';
import { dialog } from './ui.js';
import { cableName, kindLabel } from './fmt.js';

let open = null;

function score(q, text) {
  if (!q) return 1;
  const t = text.toLowerCase();
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.every(w => t.includes(w))) return 100 - t.indexOf(words[0]) - t.length / 100;
  // subsequence match
  let i = 0;
  for (const ch of t) if (ch === q[i]) i++;
  return i === q.length ? 10 - t.length / 100 : 0;
}

/** commands: [{ group, name, meta, icon, key, run }] supplied by main.js */
export function openPalette(commands) {
  if (open) return;
  const input = h('input', { type: 'text', placeholder: 'Search devices, cables, views and commands', 'aria-label': 'Search devices, cables, views and commands', role: 'combobox', 'aria-expanded': 'true', 'aria-controls': 'pal-list', autocomplete: 'off', spellcheck: 'false' });
  const list = h('div', { class: 'p-list', id: 'pal-list', role: 'listbox' });
  const body = h('div', { class: 'palette', style: { display: 'flex', flexDirection: 'column', minHeight: 0 } }, h('div', { class: 'p-input' }, icon('search'), input, h('kbd', { 'aria-hidden': 'true' }, 'Esc')), list);
  let rows = [], idx = 0;

  function items() {
    const out = [];
    for (const d of G.devices()) out.push({ group: 'Devices', name: d.name, meta: G.primaryIp(d) || kindLabel(d.kind), icon: kindIcon(d.kind), hay: [d.name, d.id, G.primaryIp(d), d.model, d.vendor, d.kind, G.brandOf(d), G.ID_WORD[G.identityOf(d).state], G.secLevel(d.id)].join(' '),
      run: () => select(d.id) });
    for (const l of G.links()) out.push({ group: 'Cables', name: `${G.deviceName(l.a.dev)} → ${l.b.dev ? G.deviceName(l.b.dev) : 'the mesh'}`, meta: cableName(l.cable) + (l.speed ? ' ' + l.speed : ''), icon: icon('trace'), hay: [l.id, l.label, cableName(l.cable), G.deviceName(l.a.dev), l.b.dev ? G.deviceName(l.b.dev) : 'mesh'].join(' '),
      run: () => { if (get().route.view !== 'map') go({ view: 'map', sel: [l.id] }); else select(l.id); } });
    for (const c of commands()) out.push({ ...c, hay: c.name + ' ' + (c.meta || '') });
    for (const r of (get().agent.list || []).slice(0, 8)) out.push({ group: 'Recent runs', name: r.title || r.question || 'Run', meta: r.status, icon: icon('agent'), hay: (r.title || '') + ' ' + (r.question || ''), run: () => go({ view: 'agent', run: r.runId }) });
    return out;
  }
  const all = items();

  function draw() {
    const q = input.value.trim();
    let res;
    if (!q) res = all.filter(x => x.group === 'Views' || x.group === 'Recent runs');
    else res = all.map(x => ({ x, s: score(q, x.hay) })).filter(r => r.s > 0).sort((a, b) => b.s - a.s).slice(0, 40).map(r => r.x);
    const order = ['Devices', 'Cables', 'Views', 'Commands', 'Recent runs'];
    res.sort((a, b) => order.indexOf(a.group) - order.indexOf(b.group));
    rows = res; idx = Math.min(idx, Math.max(0, rows.length - 1));
    if (!rows.length) { fill(list, h('div', { class: 'state' }, `No device or command matches “${q}”.`)); return; }
    const kids = []; let g = null;
    rows.forEach((r, i) => {
      if (r.group !== g) { g = r.group; kids.push(h('div', { class: 'p-group', role: 'presentation' }, g)); }
      kids.push(h('button', { class: 'p-row', role: 'option', id: 'pal-' + i, 'aria-selected': String(i === idx), type: 'button', tabIndex: -1, onClick: () => pick(i), onMousemove: () => { if (idx !== i) { idx = i; mark(); } } },
        r.icon || icon('chevron'), h('span', { class: 'ellipsis' }, r.name), h('span', { class: 'meta' }, r.meta || '', r.key ? h('kbd', { style: { marginLeft: '8px' } }, r.key) : null)));
    });
    fill(list, kids);
    input.setAttribute('aria-activedescendant', 'pal-' + idx);
  }
  function mark() {
    list.querySelectorAll('.p-row').forEach((el, i) => el.setAttribute('aria-selected', String(i === idx)));
    const cur = list.querySelector('#pal-' + idx); cur && cur.scrollIntoView({ block: 'nearest' });
    input.setAttribute('aria-activedescendant', 'pal-' + idx);
  }
  function pick(i) { const r = rows[i]; if (!r) return; d.close(); r.run(); }
  input.addEventListener('input', () => { idx = 0; draw(); });
  input.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown') { idx = Math.min(rows.length - 1, idx + 1); mark(); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { idx = Math.max(0, idx - 1); mark(); e.preventDefault(); }
    else if (e.key === 'Enter') { pick(idx); e.preventDefault(); }
  });
  const d = dialog({ body, cls: 'pal', top: true, onClose: () => { open = null; } });
  d.el.setAttribute('aria-label', 'Command palette');
  open = d;
  draw(); input.focus();
}

export const KEYS = [
  ['⌘K / Ctrl K', 'Command palette'], ['/', 'Focus the device filter (or the table search on Devices)'], ['Esc', 'Close the topmost layer, unpin a path, clear the selection, close the panel'],
  ['G then M / T / X / D / A / Y / Q / S', 'Go to Map / Threats / Security / Devices / Agent / Activity / Questions / Settings'], ['Arrow keys (map)', 'Move the selection to the nearest device in that direction'],
  ['Home / End (map)', 'First / last device in reading order'], ['Tab (map)', 'Leave the map'], ['Enter (map)', 'Open the inspector for the selection'], ['[ / ]', 'Toggle the device list / the right panel'],
  ['`', 'Toggle the activity drawer'], ['1 2', 'Map: the network / the desk wiring'], ['Right-click a device', 'Its actions: identify, scan, investigate, block, remove'], ['T', 'Trace cables from the selection (desk wiring)'], ['K', 'Cycle the KVM input view (desk wiring)'],
  ['F / 0 / + / -', 'Fit / 100% / zoom in / zoom out'], ['A', 'Ask the agent about the selection'], ['⌘↵', 'Send in the ask box'], ['⌘.', 'Stop: cancel the run and pause the agent'], ['?', 'This sheet'],
];

export function openKeys() {
  dialog({ title: 'Keyboard shortcuts', body: h('div', { class: 'body' }, h('dl', { class: 'keys' }, KEYS.flatMap(([k, t]) => [h('dt', null, h('kbd', null, k)), h('dd', null, t)])),
    h('p', { class: 'muted', style: { marginTop: '16px' } }, 'Single-letter shortcuts are off while you are typing. No shortcut approves an action.')) });
}

export { set };
