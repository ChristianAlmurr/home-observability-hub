// The Map view. Two drawings of the same house share one selection:
//   net     the living network: every device, how it reaches the internet, what moves (the default)
//   wiring  the desk schematic: ports, KVM inputs, cable types
import { h, s, fill, isPhone } from './dom.js';
import { icon, kindIcon } from './icons.js';
import { get, set, on, go, select, clearSelection, setMapView, pref, setPref } from './store.js';
import * as G from './graph.js';
import { createMap } from './map.js';
import { createNetMap } from './netmap.js';
import { wiring } from './layout.js';
import { ownerName } from './site.js';
import { welcomePanel } from './welcome.js';
import { seg, tip, popover, statusGlyph, pathStrip, internetPath, trustLine, skeleton, errorState } from './ui.js';
import { cableName, cableCls, statusLabel, plural, kindLabel } from './fmt.js';
import { actionBar, openDeviceMenu } from './actions.js';
import { idChip, secChip } from './security.js';
import { askAbout } from './agent.js';

let net = null, wire = null;
/** The drawing that is showing. Both answer the same calls (fitAll, zoomBy, targets, show…). */
export const theMap = () => (get().layer === 'wiring' ? wire || net : net);

export function setKvm(v) { setMapView({ kvm: v }); }
export function cycleKvm() { if (!G.kvmDevice()) return; const order = [...Object.keys(G.kvmInputs()).sort(), 'both']; setKvm(order[(order.indexOf(G.kvmView()) + 1) % order.length]); }
export function setLayer(v) { setMapView({ layer: v === 'wiring' ? 'wiring' : 'net' }); }
export function toggleTrace() {
  const st = get();
  if (!st.route.sel.length || st.layer !== 'wiring') return false;
  go({ trace: !st.route.trace }, { replace: true });
  return true;
}

const sample = (cls, extra) => s('svg', { class: 'lsample ' + cls, width: 44, height: 12, viewBox: '0 0 44 12', 'aria-hidden': 'true' }, s('path', { d: 'M2 6H42' }), extra || null);
const mark = (cls, text) => h('span', { class: 'lmark ' + cls }, text || '');
const tile = cls => s('svg', { class: 'ltile nn ' + cls, width: 18, height: 18, viewBox: '-9 -9 18 18', 'aria-hidden': 'true' }, s('rect', { class: 'body', x: -8, y: -8, width: 16, height: 16 }), s('rect', { class: 'ring', x: -7.5, y: -7.5, width: 15, height: 15 }), s('path', { class: 'kind', d: 'M-3 0H3' }));

export function legendContent() {
  if (get().layer === 'wiring') {
    const cab = ['usb-c', 'hdmi', 'usb', 'ethernet', 'mesh', 'bluetooth'];
    return h('div', { class: 'legend' },
      h('h3', null, 'Cable type (colour)'),
      h('div', { class: 'lg' }, cab.map(c => [h('span', { class: `sw c-${cableCls(c)}` + (c === 'mesh' ? ' mesh' : '') }), h('span', null, c === 'usb' ? 'USB (type A)' : c === 'mesh' ? 'Mesh backhaul (radio)' : cableName(c))])),
      h('h3', null, 'How sure we are (line style)'),
      h('div', { class: 'lg' },
        h('span', { class: 'sw' }), h('span', null, 'live: measured by a probe'),
        h('span', { class: 'sw dashed' }), h('span', null, 'plan: drawn, not confirmed'),
        h('span', { class: 'sw dotted' }), h('span', null, 'reported: ' + (ownerName() || 'you') + ' said so, or an order email')),
      h('h3', null, 'Status (shape and colour)'),
      h('div', { class: 'lg' }, ['online', 'degraded', 'offline', 'unknown', 'unmonitored', 'inferred'].map(st => [h('span', { class: 'g' }, statusGlyph(st)), h('span', null, statusLabel(st))])),
      h('p', null, 'A grey shape is never good news by default: it means the device is not probed or did not say.'));
  }
  return h('div', { class: 'legend' },
    h('h3', null, 'What a connection is made of'),
    h('div', { class: 'lg' },
      sample('k-wired'), h('span', null, 'Cable carrying the network (Ethernet)'),
      sample('k-coax'), h('span', null, 'Coax: the line in from the provider'),
      sample('k-wifi'), h('span', null, 'Wi-Fi to a named access point'),
      sample('k-wifi to-hull'), h('span', null, G.accessPoints().length > 1 ? 'Wi-Fi, access point not known: drawn to the mesh as a whole' : 'Wi-Fi or the LAN, the way in not known: drawn to the Wi-Fi zone'),
      G.accessPoints().length > 1 ? [sample('k-mesh'), h('span', null, 'Mesh backhaul between the router and its nodes')] : null,
      sample('k-bt'), h('span', null, 'Bluetooth to its host (fainter when only paired)'),
      sample('k-desk'), h('span', null, 'Desk cable: video or USB, no network'),
      sample('k-lan'), h('span', null, 'On the LAN, cable or Wi-Fi not known')),
    h('h3', null, 'How sure we are'),
    h('div', { class: 'lg' },
      sample('k-wired'), h('span', null, 'live: measured by a probe'),
      sample('k-wired t-plan'), h('span', null, 'plan: drawn, not confirmed'),
      sample('k-wired t-reported'), h('span', null, 'reported: ' + (ownerName() || 'you') + ', an order email, or an earlier router reading')),
    h('h3', null, 'Flags on a device (one, worst first)'),
    h('div', { class: 'lg' },
      mark('b-suspicious', '!'), h('span', null, 'Suspicious: rose edge, and the edge pulses'),
      mark('b-blocked', ''), h('span', null, 'Blocked at the router: its link is cut'),
      mark('b-unidentified', '?'), h('span', null, 'Not identified: amber edge; nothing names the product yet'),
      mark('b-watch', ''), h('span', null, 'Worth a look'),
      mark('b-new', ''), h('span', null, 'First seen in the last 24 hours')),
    h('h3', null, 'Status (the tile)'),
    h('div', { class: 'lg' },
      tile(''), h('span', null, 'Answering, or nothing to say: healthy is quiet'),
      tile('s-degraded'), h('span', null, 'Degraded: amber edge'),
      tile('s-offline'), h('span', null, 'Offline or asleep: hollow, dashed edge'),
      tile('s-unknown'), h('span', null, 'Not probed or no answer: grey icon')),
    h('p', null, 'Hover or select a device for its make and model, status, address and first finding. “Likely” means a good guess that is not confirmed; the label and the inspector say so.'),
    h('h3', null, 'What moves'),
    h('p', null, 'Small squares travel a link towards the internet; on Wi-Fi they are short wavefronts. When the router reports traffic they run both ways and their number follows the measured rate. Without it they only show that the link is up. A link speed shows when you hover or select the link.'));
}

function filterContent() {
  const upd = patch => set({ filters: { ...get().filters, ...patch } });
  const f = get().filters;
  const cb = (label, checked, fn) => h('label', { class: 'check' }, h('input', { type: 'checkbox', checked, onChange: e => fn(e.target.checked) }), label);
  const wiring = get().layer === 'wiring';
  return h('div', { style: { display: 'flex', flexDirection: 'column', gap: '2px', minWidth: '220px' } },
    h('h3', null, 'How sure we are'),
    ['live', 'plan', 'reported'].map(t => cb(h('span', { class: 'row' }, trustLine(t), t), f.trust[t], v => upd({ trust: { ...get().filters.trust, [t]: v } }))),
    h('h3', null, 'Show'),
    cb('Only what needs attention', f.problems, v => upd({ problems: v })),
    wiring ? [h('h3', null, 'Carries'),
      ['video', 'usb', 'network', 'power'].map(c => cb(h('span', { class: 'row' }, icon(c, 14), c === 'usb' ? 'USB' : c[0].toUpperCase() + c.slice(1)), !!f.carries[c], v => upd({ carries: { ...get().filters.carries, [c]: v } })))] : null);
}

export function resetFilters() { set({ filters: { trust: { live: true, plan: true, reported: true }, problems: false, carries: {}, status: null, focus: null } }); }

const FOCUS_WORD = { unidentified: 'not identified', suspicious: 'suspicious', blocked: 'blocked', new: 'new today', offline: 'offline' };

export function createMapView() {
  const netHost = h('div', { class: 'net-host' });
  const wireHost = h('div', { class: 'wire-host', hidden: true });
  const tools = h('div', { class: 'map-tools', role: 'toolbar', 'aria-label': 'Map tools' });
  const zoomPct = h('span', { class: 'pct' }, '100%');
  const zoomer = h('div', { class: 'zoomer' });
  const foot = h('div', { class: 'map-foot' });
  const wrap = h('div', { class: 'mapwrap' }, netHost, wireHost, tools, zoomer, foot);
  const el = h('div', { class: 'view' }, wrap);
  net = createNetMap(netHost);
  const onZoom = k => { zoomPct.textContent = Math.round(k * 100) + '%'; };
  net.onZoom = onZoom;
  net.onMenu = (id, x, y) => openDeviceMenu(id, x, y, menuExtras(id));
  const cur = () => theMap();
  const ensureWire = () => { if (!wire) { wire = createMap(wireHost); wire.onZoom = onZoom; wire.padTop = net.padTop; } return wire; };

  function menuExtras(id) {
    const d = G.device(id); const ip = d && G.primaryIp(d);
    return [
      { label: 'Ask the agent about this', icon: 'agent', run: () => askAbout([id]) },
      wiring().NODES[id] ? { label: 'Show on the wiring map', icon: 'map', run: () => { setLayer('wiring'); select(id); } } : null,
      ip ? { label: 'Copy ' + ip, icon: 'copy', run: () => navigator.clipboard && navigator.clipboard.writeText(ip) } : null,
    ].filter(Boolean);
  }

  const zb = (ic, label, fn, key) => { const b = h('button', { type: 'button', 'aria-label': label, onClick: fn }, icon(ic)); tip(b, h('span', null, label, key ? h('kbd', null, key) : null)); return b; };
  zoomer.append(zb('minus', 'Zoom out', () => cur().zoomBy(1 / 1.25), '-'), zoomPct, zb('plus', 'Zoom in', () => cur().zoomBy(1.25), '+'), zb('fit', 'Fit everything', () => cur().fitAll(), 'F'));

  function renderTools() {
    const st = get();
    const f = st.filters;
    const wiring = st.layer === 'wiring';
    const mode = seg([
      { value: 'net', label: 'Network', tip: h('span', null, 'Every device and its path to the internet', h('kbd', null, '1')) },
      { value: 'wiring', label: 'Wiring', short: 'Wiring', tip: h('span', null, 'Every cable: ports, cable types and where each one goes, then the rooms', h('kbd', null, '2')) },
    ], st.layer, setLayer, { label: 'Map' });
    let kvm = null, traceBtn = null;
    if (wiring && G.kvmDevice()) {
      const belief = G.kvmBelief();
      const kvmTip = 'Shows which computer the desk is connected to. It does not switch the KVM.';
      const ins = G.kvmInputs();
      const opt = k => ({ value: k, label: G.kvmInputLabel(k), short: k.toUpperCase(), dot: belief.input === k,
        tip: kvmTip + (belief.input === k ? ' ' + k.toUpperCase() + ' is ' + (belief.basis === 'live' ? 'live.' : 'inferred: the KVM hub is on the USB bus of the ' + G.shortName(ins[k].dev) + '.') : '') });
      kvm = seg([...Object.keys(ins).sort().map(opt), { value: 'both', label: 'Both', tip: kvmTip }], G.kvmView(), setKvm, { label: 'KVM input view' });
      const sel = st.route.sel;
      traceBtn = sel.length && (G.isLinkId(sel[0]) || G.linksOf(sel[0]).length)
        ? h('button', { class: 'btn' + (st.route.trace ? ' primary' : ''), type: 'button', 'aria-pressed': String(!!st.route.trace), onClick: toggleTrace }, icon('trace'), h('span', { class: 'hide-md' }, st.route.trace ? 'Tracing' : 'Trace path')) : null;
      if (traceBtn) tip(traceBtn, h('span', null, 'Follow the cables from the selection to where each branch ends', h('kbd', null, 'T')));
    }
    const filterBtn = h('button', { class: 'btn', type: 'button', 'aria-haspopup': 'dialog', 'aria-label': 'Filter', onClick: () => popover(filterBtn, filterContent()) }, icon('filter'), h('span', { class: 'hide-md' }, 'Filter'));
    tip(filterBtn, 'Filter by how sure we are and by what needs attention');
    const legendBtn = h('button', { class: 'btn', type: 'button', 'aria-haspopup': 'dialog', 'aria-label': 'Legend', dataset: { legend: '1' }, onClick: () => popover(legendBtn, legendContent()) }, icon('legend'), h('span', { class: 'hide-md' }, 'Legend'));
    tip(legendBtn, 'What the lines, marks and moving dots mean');
    const tags = [];
    const tag = (text, clearFn, cls) => tags.push(h('span', { class: 'tag ' + (cls || '') }, text, h('button', { 'aria-label': 'Remove filter: ' + text, onClick: clearFn }, icon('close', 12))));
    if (f.focus) tag('only ' + FOCUS_WORD[f.focus], () => set({ filters: { ...get().filters, focus: null } }), 'focus');
    for (const t of ['live', 'plan', 'reported']) if (!f.trust[t]) tag('hiding ' + t, () => set({ filters: { ...get().filters, trust: { ...get().filters.trust, [t]: true } } }));
    if (f.problems) tag('only what needs attention', () => set({ filters: { ...get().filters, problems: false } }));
    if (f.status) tag('status: ' + statusLabel(f.status).toLowerCase(), () => set({ filters: { ...get().filters, status: null } }));
    for (const c of Object.keys(f.carries)) if (f.carries[c] && wiring) tag('carries ' + c, () => set({ filters: { ...get().filters, carries: { ...get().filters.carries, [c]: false } } }));
    const rt = G.routerState();
    const note = !wiring && rt && rt.configured === false ? h('button', { class: 'tool-note', type: 'button', onClick: () => go({ view: 'settings', sel: [], panel: null }) }, icon('key', 14), h('span', null, 'No router login: live access points and traffic are not read')) : null;
    if (note) tip(note, 'Wi-Fi devices are drawn to the access point the inventory records, or to the mesh as a whole. Open Settings to add the router login.');
    fill(tools, mode, kvm ? h('span', { class: 'seg-label hide-md' }, 'KVM input') : null, kvm, filterBtn, legendBtn, traceBtn, tags, note);
    const ph = tools.offsetHeight;
    if (ph && ph !== net.padTop) { const firstTime = !net.padTop; net.padTop = ph; if (wire) wire.padTop = ph; if (firstTime) cur().home(); }
  }

  function selBar(id) {
    const st = get();
    const d = G.device(id);
    const status = G.statusOf(id);
    const phone = isPhone();
    const close = h('button', { class: 'btn minimal icon sm', 'aria-label': 'Clear the selection', onClick: () => clearSelection() }, icon('close', 14));
    const brand = G.brandOf(d);
    return h('div', { class: 'selbar l-' + (G.secLevel(id) || 'none'), role: 'region', 'aria-label': 'Selected device' },
      h('div', { class: 'sb-h' }, h('span', { class: 'ki' }, kindIcon(d.kind, 18)),
        h('div', { class: 'grow who' }, h('b', { class: 'ellipsis' }, d.name), h('span', { class: 'm ellipsis' }, [brand || kindLabel(d.kind), G.primaryIp(d)].filter(Boolean).join(' · '))),
        h('span', { class: 'chipsr' }, secChip(id), idChip(d, { showConfirmed: !phone })),
        h('span', { class: 'stt' }, statusGlyph(status, 8), h('span', { class: 'hide-sm' }, statusLabel(status))),
        phone ? h('button', { class: 'btn sm primary', onClick: () => go({ panel: 'inspector' }) }, 'Details') : null, close),
      internetPath(id),
      actionBar(id, { labels: !phone || true, cls: 'wide' }));
    void st;
  }

  function renderFoot() {
    const st = get();
    const kids = [];
    const sel = st.route.sel;
    if (st.pin) {
      const hops = G.orderPath(st.pin.links || []);
      kids.push(h('div', { class: 'pathbar' },
        h('div', { class: 'ph' }, h('b', null, 'Answer path'), st.pin.title ? h('span', { class: 'ellipsis' }, st.pin.title) : null, h('span', { class: 'grow' }),
          st.pin.runId ? h('button', { class: 'btn sm minimal', onClick: () => go({ view: 'agent', run: st.pin.runId }) }, 'Open answer') : null,
          h('button', { class: 'btn sm', onClick: () => set({ pin: null }) }, 'Unpin')),
        hops.length ? pathStrip(hops, { suspect: new Set(st.pin.suspect || []) }) : h('span', { class: 'muted' }, 'The answer names devices but no cable path.'),
        st.pin.note ? h('div', { class: 'ph', style: { marginTop: '4px', marginBottom: 0 } }, 'Why this hop: ' + st.pin.note) : null));
    } else if (st.layer === 'wiring') {
      if (st.route.trace && sel.length) {
        const id = sel[0];
        const tr = G.trace(id);
        const name = G.isLinkId(id) ? 'this cable' : G.deviceName(id);
        kids.push(h('div', { class: 'pathbar' },
          h('div', { class: 'ph' }, h('b', null, 'Path from ' + name), h('span', null, tr.chains.length ? plural(tr.chains.length, 'branch', 'branches') : 'no cables to follow'), h('span', { class: 'grow' }),
            h('button', { class: 'btn sm', onClick: toggleTrace }, 'Clear')),
          tr.chains.map(c => pathStrip(c, { slow: tr.slow }))));
      } else if (sel.length === 1 && G.isDeviceId(sel[0]) && !wiring().NODES[sel[0]]) {
        kids.push(h('div', { class: 'pathbar' }, h('div', { class: 'ph', style: { margin: 0 } }, h('b', null, G.deviceName(sel[0])), h('span', null, 'has no cable to draw here.'), h('span', { class: 'grow' }),
          h('button', { class: 'btn sm primary', onClick: () => setLayer('net') }, 'Show on the network map'))));
      }
    } else if (sel.length === 1 && G.isDeviceId(sel[0])) kids.push(selBar(sel[0]));
    fill(foot, kids);
    net.padBottom = foot.offsetHeight;
  }

  // ---------------------------------------------------------------- wiring it up

  let overlayState = null, lastLayer = null, lastScan = null, welcome = null;
  function renderAll() {
    const st = get();
    const wiring = st.layer === 'wiring';
    netHost.hidden = wiring; wireHost.hidden = !wiring;
    wrap.dataset.layer = st.layer;
    if (!st.inventory) {
      if (!overlayState) { overlayState = h('div', { class: 'map-state' }); wrap.appendChild(overlayState); }
      fill(overlayState, st.invError ? errorState(st.invError, () => window.__hmReload && window.__hmReload(), 'The inventory could not be loaded.') : skeleton(8));
    } else if (overlayState) { overlayState.remove(); overlayState = null; }
    // the first run: no devices yet, so a welcome and the setup checklist instead of an empty map
    const empty = !!st.inventory && !G.things().length;
    wrap.dataset.empty = empty ? '1' : '';
    if (empty) {
      const had = !!welcome;
      if (!welcome) { welcome = h('div', { class: 'welcome-host' }); wrap.appendChild(welcome); }
      fill(welcome, welcomePanel());
      if (!had) requestAnimationFrame(() => { const t = welcome && welcome.querySelector('h2'); if (t && document.activeElement === document.body) t.focus({ preventScroll: true }); });
    } else if (welcome) { welcome.remove(); welcome = null; }
    if (wiring) { ensureWire().render(); net.stop(); } else net.render();
    renderTools(); renderFoot();
    if (lastLayer !== st.layer) { lastLayer = st.layer; onZoom(cur().zoom()); if (wiring) wire.applyFocus(); }
  }
  on(['inventory', 'invError', 'live', 'layer', 'kvm', 'filters', 'setup', 'layout', 'site'], (st, keys) => {
    if (st.route.view !== 'map') { dirty = true; return; }
    renderAll();
    // a new reading: the sweep runs out from the router
    const ts = st.live && st.live.ts;
    if (keys.has('live') && ts && lastScan && ts !== lastScan && st.layer !== 'wiring') net.sweep();
    if (ts) lastScan = ts;
  });
  let dirty = true, lastSel = '';
  on(['route', 'hover', 'pin'], (st, keys) => {
    if (st.route.view !== 'map') return;
    if (dirty) { dirty = false; renderAll(); }
    cur().applyFocus();
    if (keys.has('route') || keys.has('pin')) {
      renderTools(); renderFoot();
      const sel = st.route.sel.join(',');
      if (sel !== lastSel) { lastSel = sel; cur().announce(); if (st.route.sel[0]) requestAnimationFrame(() => cur().show(st.route.sel[0])); }
    }
  });
  window.matchMedia('(max-width: 767px)').addEventListener('change', () => { if (get().route.view === 'map') renderAll(); });

  // first visit: show the legend once
  setTimeout(() => {
    if (pref('legendSeen2', false) || isPhone() || get().route.view !== 'map' || navigator.webdriver || get().route.sel.length || !G.things().length) return;
    const legendBtn = tools.querySelector('[data-legend]');
    if (legendBtn) { popover(legendBtn, legendContent()); setPref('legendSeen2', true); }
  }, 1600);

  return { el, show() { dirty = false; renderAll(); cur().applyFocus(); if (get().layer !== 'wiring') net.start(); } };
}

export { kindLabel };
