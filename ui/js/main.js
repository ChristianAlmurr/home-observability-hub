// Boot, shell, polling and the keyboard map.
import { h, s, fill, $, isTyping, isPhone, isWide, tablist } from './dom.js';
import { icon } from './icons.js';
import { get, set, on, go, initRoute, select, clearSelection, pref, setPref } from './store.js';
import { api } from './api.js';
import * as G from './graph.js';
import { initTips, tip, seg, toast, closeTopLayer, hasLayer, statusGlyph, dialog, liveAge, hideTip } from './ui.js';
import { createMapView, theMap, cycleKvm, setKvm, setLayer, toggleTrace, resetFilters } from './mapview.js';
import { createMap } from './map.js';
import { createObjectList } from './objectlist.js';
import { createInspector } from './inspector.js';
import { createDevices } from './devices.js';
import { createAgent, createRunList, refreshRuns, askAbout, activeRun, stopEverything } from './agent.js';
import { createActivity, createDrawer, loadEvents, toggleDrawer } from './activity.js';
import { createSettings, createQuestions, applyTheme, toggleTheme, setMode, modeOptions, MODES } from './settings.js';
import { openPalette, openKeys } from './palette.js';
import { clock, statusLabel, plural } from './fmt.js';
import { createSecurity, topSummary, overallVerdict } from './security.js';
import { createThreats, threatLevel, scanNow } from './threats.js';
import { invalidateActions } from './actions.js';
import { demoMode } from './api.js';

const VIEWS = [
  { id: 'map', label: 'Map', key: 'M' }, { id: 'threats', label: 'Threats', key: 'T' }, { id: 'security', label: 'Security', key: 'X' }, { id: 'devices', label: 'Devices', key: 'D' }, { id: 'agent', label: 'Agent', key: 'A' },
  { id: 'activity', label: 'Activity', key: 'Y' }, { id: 'questions', label: 'Questions', key: 'Q' }, { id: 'settings', label: 'Settings', key: 'S' },
];

// ---------------------------------------------------------------- data

async function loadInventory() {
  try {
    // the layout and the site shape how the inventory is drawn, so all three arrive together (no jump on load);
    // both are optional routes and answer {} from a server that does not have them
    const [inv, layout, site] = await Promise.all([api.inventory(), api.layout(), api.site()]);
    set({ site: site || {}, layout: layout || {} });
    G.index(inv);
    set({ inventory: inv, invError: null });
  } catch (e) { set({ invError: e.message }); }
}
/** The setup checklist. While the home has no devices it is read again every 10 s, so the welcome panel follows /setup. */
let setupTimer = 0;
async function loadSetup() {
  clearTimeout(setupTimer);
  const before = get().setup;
  const setup = await api.setup();
  set({ setup, setupAt: Date.now() });
  const empty = get().inventory && !G.things().length;
  if (empty && before && setup.inventoryDevices > 0) loadInventory();
  if (empty || !get().inventory) setupTimer = setTimeout(() => { if (!document.hidden) loadSetup(); else setupTimer = setTimeout(loadSetup, 10000); }, 10000);
}
async function loadSettings() {
  try { set({ settings: await api.settings(), settingsError: null }); } catch (e) { set({ settingsError: e.message }); }
}
async function loadRouter() {
  try { set({ router: await api.router(), routerError: null }); } catch (e) { set({ router: null, routerError: e.status === 404 ? 'missing' : e.message }); }
}
window.__hmRouter = loadRouter;
async function loadHealth() {
  try { set({ health: await api.health() }); } catch { /* the live poll reports reachability */ }
}
let liveTimer = 0, liveBusy = false, wiringRev = null;
async function pollLive() {
  clearTimeout(liveTimer);
  if (document.hidden) return;
  if (!liveBusy) {
    liveBusy = true;
    try {
      const live = await api.live();
      const was = get().serverDown;
      // a cable moved (the server re-read the sockets): the wiring itself changed, so load it again
      const rev = live && live.wiring ? live.wiring.rev : null;
      if (rev != null && wiringRev != null && rev !== wiringRev && get().inventory) loadInventory();
      wiringRev = rev;
      set({ live, liveAt: Date.now(), liveError: null, serverDown: false, now: Date.now() });
      if (was) { toast('The server is reachable again.', { intent: 'success' }); if (!get().inventory) loadInventory(); loadSettings(); loadHealth(); refreshRuns(); }
    } catch (e) { set({ liveError: e.message, serverDown: !!e.unreachable }); }
    finally { liveBusy = false; }
  }
  liveTimer = setTimeout(pollLive, 5000);
}
function reloadAll() { invalidateActions(); set({ reloadAt: Date.now() });   // threats.js reloads the findings on reloadAt
  loadInventory(); loadSetup(); loadSettings(); loadRouter(); loadHealth(); pollLive(); loadEvents(); refreshRuns(); }
window.__hmReload = reloadAll;

// ---------------------------------------------------------------- shell

const app = $('#app');
const topbar = h('header', { class: 'topbar' });
const offline = h('div', { class: 'offline-bar', role: 'status', hidden: true });
const rail = h('nav', { class: 'rail', 'aria-label': 'Views' });
const list = h('aside', { class: 'list', 'aria-label': 'Devices' });
const main = h('main', { class: 'main', id: 'main' });
const right = h('aside', { class: 'right', 'aria-label': 'Details' });
const drawer = h('section', { class: 'drawer', 'aria-label': 'Activity' });
const tabbar = h('nav', { class: 'tabbar', 'aria-label': 'Views' });
const skip = h('a', { class: 'skip-link', href: '#main', onClick: e => { e.preventDefault(); const t = main.querySelector('.view:not([hidden]) h1') || main; if (t !== main) t.tabIndex = -1; t.focus(); } }, 'Skip to the content');
main.tabIndex = -1;
app.append(skip, topbar, offline, rail, list, main, right, drawer, tabbar);

const views = {
  map: createMapView(), threats: createThreats(), security: createSecurity(), devices: createDevices(), activity: createActivity(), questions: createQuestions(), settings: createSettings(),
};
const agent = createAgent();
const agentHost = h('div', { class: 'view', hidden: true });
const objectList = createObjectList();
const runList = createRunList();
const inspector = createInspector();
for (const v of Object.values(views)) { v.el.hidden = true; main.appendChild(v.el); }
main.appendChild(agentHost);
// Map, Activity and Agent show no title of their own: give each a heading for screen readers.
for (const [host, label] of [[views.map.el, 'Map'], [views.activity.el, 'Activity'], [agentHost, 'Agent']]) host.prepend(h('h1', { class: 'sr-only', tabIndex: -1 }, label));
const listResizer = h('div', { class: 'resizer v', role: 'separator', 'aria-orientation': 'vertical', 'aria-label': 'Resize the device list' });
list.append(objectList.el, runList.el, listResizer);
drawer.appendChild(createDrawer().el);

// right panel: tabs + bodies
const rightTabs = h('div', { class: 'tabs' });
const rightBody = h('div', { class: 'view' });
const miniHost = h('div', { class: 'mapwrap mini-host' });
const miniWrap = h('div', { class: 'view', hidden: true }, h('div', { class: 'mini-h' }, h('span', { class: 'grow' }, 'Map'), h('button', { class: 'btn sm', onClick: () => go({ view: 'map' }) }, icon('map', 14), 'Open the map')), miniHost,
  h('p', { class: 'mini-note muted' }, 'The answer’s path is highlighted. Click the map to open it with the path kept.'));
const rightResizer = h('div', { class: 'resizer v', role: 'separator', 'aria-orientation': 'vertical', 'aria-label': 'Resize the panel' });
right.append(rightResizer, rightTabs, rightBody, miniWrap);
let mini = null;

function dragResize(handle, cssVar, min, max, fromRight, prefKey) {
  const saved = pref(prefKey, null);
  if (saved) app.style.setProperty(cssVar, saved + 'px');
  handle.addEventListener('pointerdown', e => {
    e.preventDefault(); handle.classList.add('dragging'); handle.setPointerCapture(e.pointerId);
    const move = ev => {
      const railW = 48;
      const w = Math.min(max, Math.max(min, fromRight ? window.innerWidth - ev.clientX : ev.clientX - railW));
      app.style.setProperty(cssVar, w + 'px'); setPref(prefKey, w);
    };
    const up = () => { handle.classList.remove('dragging'); handle.removeEventListener('pointermove', move); handle.removeEventListener('pointerup', up); };
    handle.addEventListener('pointermove', move); handle.addEventListener('pointerup', up);
  });
}
dragResize(listResizer, '--list-w', 220, 400, false, 'listW');
dragResize(rightResizer, '--panel-w', 360, 560, true, 'panelW');

// ---------------------------------------------------------------- top bar

function renderTopbar() {
  const st = get();
  const v = VIEWS.find(x => x.id === st.route.view);
  const summary = topSummary();
  const search = h('button', { class: 'search-btn', type: 'button', 'aria-label': 'Search devices and commands', 'aria-keyshortcuts': 'Meta+K', onClick: () => openPalette(commands) }, icon('search'), h('span', null, 'Search'), h('kbd', { 'aria-hidden': 'true' }, '⌘K'));
  const mode = (st.settings || {}).agentMode;
  const modeSeg = seg(MODES.map(m => ({ value: m.value, label: m.label, icon: m.value === 'paused' ? 'pause' : null, tip: m.text, disabled: !st.settings })), mode, setMode, { cls: 'mode', label: 'Agent mode' });
  const act = activeRun();
  const stop = act ? h('button', { class: 'btn danger', type: 'button', onClick: stopEverything }, icon('stop', 14), 'Stop') : null;
  if (stop) tip(stop, h('span', null, 'Cancel the run and pause the agent', h('kbd', null, '⌘.')));
  const toLight = document.documentElement.dataset.theme !== 'light';
  const theme = h('button', { class: 'btn minimal icon hide-sm', type: 'button', 'aria-label': toLight ? 'Switch to the light theme' : 'Switch to the dark theme', onClick: toggleTheme }, icon(toLight ? 'sun' : 'moon'));
  tip(theme, toLight ? 'Switch to the light theme' : 'Switch to the dark theme');
  // phone: the verdict as one pill, and a mode pill
  const vd = overallVerdict();
  app.dataset.verdict = vd.view;
  const pill = h('button', { class: 'status-pill show-sm v-' + vd.cls, type: 'button', onClick: () => go({ view: vd.view, sel: [], panel: null }) }, icon(vd.icon, 14), h('span', { class: 'ellipsis' }, vd.text));
  const demo = demoMode() ? h('span', { class: 'demo-chip' }, 'Sample data') : null;
  if (demo) tip(demo, 'Sample devices, findings and router state are laid over the real inventory so every state can be seen. Actions change this copy only. Remove demo= from the address to leave.');
  const modePill = h('button', { class: 'mode-pill show-sm', type: 'button', dataset: { v: mode || '' }, 'aria-label': 'Agent mode: ' + (mode || 'not loaded'), onClick: () => {
    const d = dialog({ title: 'Agent mode', body: h('div', { class: 'body' }, modeOptions(() => d.close()), h('p', { class: 'muted', style: { marginTop: '12px' } }, 'There is no auto-run mode.')) });
  } }, mode === 'paused' ? icon('pause', 12) : null, mode ? MODES.find(m => m.value === mode).label : 'Mode');
  fill(topbar, h('div', { class: 'brand' }, brandMark(st.live && !st.liveError), h('span', { class: 'wordmark' }, 'Home Observability Hub')), h('span', { class: 'view-title' }, v ? v.label : ''),
    summary, demo, h('span', { class: 'grow' }), pill, search, modeSeg, modePill, stop, theme);
}

/** The Home Observability Hub mark. Its node is green while live readings arrive; the words say so for screen readers. */
function brandMark(live) {
  const mark = s('svg', { class: 'hm-mark' + (live ? ' live' : ''), viewBox: '0 0 32 32', width: 20, height: 20, 'aria-hidden': 'true', focusable: 'false' },
    s('path', { fill: 'currentColor', d: 'M16 4 24 12v12H8V12z' }),
    s('rect', { x: 14, y: 16, width: 4, height: 4, style: 'fill: var(--hm-node)' }));
  return h('span', { class: 'brand-mark', title: live ? 'Live readings' : 'Not receiving live readings' }, mark, h('span', { class: 'sr-only' }, live ? 'Live readings arriving.' : 'No live readings.'));
}

/** The name of the computer the hub runs on, when the site says which one it is. */
function hostName() { const id = G.hostDeviceId(); return id ? G.deviceName(id) : null; }
function renderOffline() {
  const st = get();
  offline.hidden = !st.serverDown;
  const where = hostName() ? 'on the ' + hostName() : 'on the computer it runs on';
  if (st.serverDown) fill(offline, icon('warning', 14), h('span', null, st.liveAt ? `Can't reach Home Observability Hub ${where}. Showing what was loaded at ${clock(st.liveAt)}; actions are off until it answers. Check that the computer is on and the hub is running, then retry.` : `Can't reach Home Observability Hub ${where}, so nothing has loaded. Check that the computer is on and the hub is running, then retry.`),
    h('span', { class: 'grow' }), h('button', { class: 'btn sm', onClick: reloadAll }, 'Retry'));
}

/** A dot on the Threats button while something serious is open. The count and the words are on the page itself. */
function threatBadge() {
  const lv = threatLevel();
  return lv.rank >= 4 ? h('span', { class: 'badge', role: 'img', 'aria-label': lv.label }) : null;
}
function renderRail() {
  const st = get();
  const btn = v => {
    const extra = v.id === 'threats' && threatLevel().rank >= 4 ? ', ' + threatLevel().label : v.id === 'agent' && activeRun() ? ', a run is going' : '';
    const b = h('button', { type: 'button', 'aria-label': v.label + extra, 'aria-current': st.route.view === v.id ? 'page' : null, onClick: () => go({ view: v.id, panel: null }) }, icon(v.id, 18),
      v.id === 'agent' && activeRun() ? h('span', { class: 'badge', style: { background: 'var(--selection)' } }) : null, v.id === 'threats' ? threatBadge() : null);
    tip(b, h('span', null, v.label, h('kbd', null, 'G ' + v.key)));
    return b;
  };
  const listBtn = h('button', { type: 'button', class: 'show-md', 'aria-label': 'Toggle the device list', onClick: toggleList }, icon('list', 18));
  tip(listBtn, h('span', null, 'Device list', h('kbd', null, '[')));
  const keys = h('button', { type: 'button', 'aria-label': 'Keyboard shortcuts', onClick: openKeys }, h('span', { class: 'mono', style: { fontSize: '14px' } }, '?'));
  tip(keys, h('span', null, 'Keyboard shortcuts', h('kbd', null, '?')));
  fill(rail, listBtn, VIEWS.map(btn), h('span', { class: 'spacer' }), keys);
  const tabs = ['map', 'threats', 'security', 'agent'].map(id => VIEWS.find(v => v.id === id));
  const moreIds = ['devices', 'activity', 'questions', 'settings'];
  const more = moreIds.includes(st.route.view);
  fill(tabbar, tabs.map(v => h('button', { type: 'button', 'aria-current': st.route.view === v.id ? 'page' : null, onClick: () => go({ view: v.id, sel: [], panel: null }) }, icon(v.id, 20), v.label, v.id === 'threats' ? threatBadge() : null)),
    h('button', { type: 'button', 'aria-current': more ? 'page' : null, 'aria-haspopup': 'dialog', onClick: () => {
      const d = dialog({ title: 'More', body: h('div', { class: 'body menu' }, moreIds.map(id => h('button', { class: 'touch', style: { minHeight: '44px' }, onClick: () => { d.close(); go({ view: id, sel: [], panel: null }); } }, icon(id), VIEWS.find(v => v.id === id).label)),
        h('button', { style: { minHeight: '44px' }, onClick: () => { d.close(); toggleTheme(); } }, icon('sun'), document.documentElement.dataset.theme === 'light' ? 'Switch to the dark theme' : 'Switch to the light theme')) });
    } }, icon('more', 20), 'More'));
}

// ---------------------------------------------------------------- layout state

function toggleList() {
  const ui = get().ui;
  const shown = isWide() ? ui.list !== 'closed' : ui.list === 'open';
  set({ ui: { ...ui, list: shown ? 'closed' : 'open' } });
}
function toggleRight() {
  const st = get();
  if (rightOpen()) go({ panel: null, sel: [] });
  else go({ panel: 'agent' });
}
function rightOpen() {
  const st = get(), r = st.route;
  if (isPhone()) return r.sel.length > 0 && (r.view !== 'map' || r.panel === 'inspector' || st.layer === 'wiring');
  if (r.view === 'agent') return true;
  return r.sel.length > 0 || r.panel === 'agent';
}

let currentView = null;
function layout() {
  const st = get(), r = st.route;
  const phone = isPhone();
  app.dataset.view = r.view;
  app.dataset.list = st.ui.list === 'closed' ? 'closed' : st.ui.list === 'open' ? 'open' : 'auto';
  app.dataset.drawer = st.ui.drawer;
  app.dataset.right = rightOpen() ? 'open' : 'closed';
  // main view
  for (const [id, v] of Object.entries(views)) v.el.hidden = id !== r.view;
  agentHost.hidden = r.view !== 'agent';
  if (r.view !== currentView) { currentView = r.view; if (views[r.view] && views[r.view].show) views[r.view].show(); document.title = (VIEWS.find(v => v.id === r.view) || {}).label + ' · Home Observability Hub'; }
  // list column: devices, or run history on the Agent view
  objectList.el.hidden = r.view === 'agent';
  app.dataset.layer = st.layer;
  runList.el.hidden = r.view !== 'agent';
  // right panel
  const showAgentInPanel = !phone && r.view !== 'agent' && r.panel === 'agent';
  const onAgentView = r.view === 'agent';
  const showMini = !phone && onAgentView && !r.sel.length;
  let rb;
  if (phone) rb = inspector.el;
  else if (onAgentView) rb = r.sel.length ? inspector.el : null;
  else rb = showAgentInPanel ? agent.el : inspector.el;
  if (onAgentView && agent.el.parentNode !== agentHost) agentHost.appendChild(agent.el);
  if (rb && rb.parentNode !== rightBody) fill(rightBody, rb);
  miniWrap.hidden = !showMini; rightBody.hidden = showMini; rightTabs.hidden = showMini || phone || onAgentView;
  if (showMini) { if (!mini) { mini = createMap(miniHost, { mini: true }); } mini.render(); mini.home(); }
  if (!rightTabs.hidden) {
    const tab = (id, label) => h('button', { type: 'button', role: 'tab', 'aria-selected': String((id === 'agent') === showAgentInPanel), onClick: () => go({ panel: id === 'agent' ? 'agent' : null }) }, label);
    const close = h('button', { class: 'btn minimal icon sm', 'aria-label': 'Close the panel', onClick: () => go({ panel: null, sel: [] }) }, icon('close'));
    tip(close, h('span', null, 'Close the panel', h('kbd', null, ']')));
    fill(rightTabs, tablist('Panel', [tab('inspector', 'Inspector'), tab('agent', 'Agent')]), h('span', { class: 'end' }, close));
  }
}

on(['route', 'ui', 'layer'], layout);
on(['route', 'live', 'liveError', 'settings', 'health', 'filters', 'agent', 'now', 'inventory', 'threats', 'threatsError'], renderTopbar);
on(['route', 'agent', 'threats', 'threatsError'], renderRail);
on(['serverDown', 'liveAt'], renderOffline);
on(['inventory', 'live', 'pin', 'route'], () => { if (mini && !miniWrap.hidden) { mini.render(); } });
window.matchMedia('(max-width: 767px)').addEventListener('change', () => { layout(); renderTopbar(); });
window.matchMedia('(min-width: 1440px)').addEventListener('change', layout);
// a narrow overlay list closes when something is picked from it
on(['route'], () => { if (!isWide() && get().ui.list === 'open' && get().route.sel.length) set({ ui: { ...get().ui, list: 'auto' } }); });
on(['route'], () => { applyTheme(); hideTip(); });

// ---------------------------------------------------------------- commands and keys

function commands() {
  const st = get();
  const sel = st.route.sel[0];
  const out = VIEWS.map(v => ({ group: 'Views', name: 'Go to ' + v.label, icon: icon(v.id), key: 'G ' + v.key, run: () => go({ view: v.id, panel: null }) }));
  const c = (name, run, key, meta) => out.push({ group: 'Commands', name, run, key, meta, icon: icon('chevron') });
  for (const m of MODES) c('Set agent mode to ' + m.label.toLowerCase(), () => setMode(m.value), null, m.text);
  if (G.kvmDevice()) {
    const ins = G.kvmInputs();
    for (const k of ['pc1', 'pc2']) if (ins[k]) c('Show KVM input ' + k.toUpperCase() + ' (' + G.shortName(ins[k].dev) + ')', () => { go({ view: 'map' }); setLayer('wiring'); setKvm(k); }, 'K');
    c('Show both KVM inputs', () => { go({ view: 'map' }); setLayer('wiring'); setKvm('both'); }, 'K');
  }
  c('Map: the network', () => { go({ view: 'map' }); setLayer('net'); }, '1');
  c('Map: wiring', () => { go({ view: 'map' }); setLayer('wiring'); }, '2');
  c('Scan for threats now', () => { go({ view: 'threats', sel: [], panel: null }); scanNow(); });
  c('Add or change the router login', () => go({ view: 'settings', sel: [], panel: null }));
  c('Fit the map to the screen', () => { go({ view: 'map' }); requestAnimationFrame(() => theMap().fitAll()); }, 'F');
  c('Clear map filters', resetFilters);
  for (const d of G.devices().filter(x => G.linksOf(x.id).some(l => l.cable !== 'bluetooth'))) c('Trace cables from ' + d.name, () => { setLayer('wiring'); go({ view: 'map', sel: [d.id], trace: true }); });
  if (sel && G.isDeviceId(sel)) c('Ask the agent about ' + G.deviceName(sel), () => askAbout(st.route.sel.filter(G.isDeviceId)), 'A');
  c('Ask the agent a new question', () => askAbout([]));
  c('Toggle the activity drawer', toggleDrawer, '`');
  c('Switch theme', toggleTheme);
  c('Keyboard shortcuts', openKeys, '?');
  if (activeRun()) c('Stop: cancel the run and pause the agent', stopEverything, '⌘.');
  return out;
}

function moveSelection(dx, dy) {
  const map = theMap(); if (!map) return;
  const ts = map.targets(); if (!ts.length) return;
  const cur = ts.find(t => t.id === get().route.sel[0]);
  if (!cur) return select(ts[0].id);
  let best = null;
  for (const t of ts) {
    if (t === cur) continue;
    const vx = t.cx - cur.cx, vy = t.cy - cur.cy;
    const along = vx * dx + vy * dy, across = Math.abs(vx * dy) + Math.abs(vy * dx);
    if (along <= 0 || across > along) continue;   // within a 90° cone
    const dist = Math.hypot(vx, vy);
    if (!best || dist < best.dist) best = { t, dist };
  }
  if (best) return select(best.t.id);
  // Nothing in that direction: step through reading order, so every device stays reachable from the keyboard.
  const n = ts[ts.indexOf(cur) + (dx + dy > 0 ? 1 : -1)];
  if (n) select(n.id);
}

let gPending = 0;
document.addEventListener('keydown', e => {
  const st = get();
  const mod = e.metaKey || e.ctrlKey;
  if (mod && e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(commands); return; }
  if (mod && e.key === '.') { e.preventDefault(); if (activeRun()) stopEverything(); return; }
  if (e.key === 'Escape') {
    if (closeTopLayer()) { e.preventDefault(); return; }
    if (isTyping(e)) { e.target.blur(); return; }
    if (st.pin) return set({ pin: null });
    if (st.route.trace) return go({ trace: false }, { replace: true });
    if (st.route.sel.length) return clearSelection();
    if (st.route.panel) return go({ panel: null });
    if (!isWide() && st.ui.list === 'open') return set({ ui: { ...st.ui, list: 'auto' } });
    return;
  }
  if (isTyping(e) || mod || e.altKey || hasLayer()) return;
  const k = e.key;
  if (gPending && Date.now() - gPending < 1200) {
    gPending = 0;
    const v = VIEWS.find(x => x.key.toLowerCase() === k.toLowerCase());
    if (v) { e.preventDefault(); go({ view: v.id, panel: null }); return; }
  }
  const onMap = st.route.view === 'map';
  const map = theMap();
  switch (k) {
    case 'g': case 'G': gPending = Date.now(); return;
    case '/': e.preventDefault(); if (st.route.view === 'devices') views.devices.focusSearch(); else if (!isPhone()) { if (!isWide() || st.ui.list === 'closed') set({ ui: { ...st.ui, list: 'open' } }); setTimeout(() => objectList.focusFilter(), 0); } return;
    case '?': openKeys(); return;
    case '[': toggleList(); return;
    case ']': toggleRight(); return;
    case '`': toggleDrawer(); return;
    case 'a': case 'A': if (st.route.sel.length) askAbout(st.route.sel.flatMap(id => (G.isDeviceId(id) ? [id] : G.isLinkId(id) ? [G.link(id).a.dev, G.link(id).b.dev] : []))); else askAbout([]); e.preventDefault(); return;
    default: break;
  }
  if (!onMap) return;
  switch (k) {
    case 't': case 'T': if (!toggleTrace()) toast(st.layer === 'wiring' ? 'Select a device or a cable first, then press T to trace its path.' : 'The network map shows the path to the internet as soon as you select a device. T traces cables on the desk wiring.'); return;
    case 'k': case 'K': if (st.layer === 'wiring') cycleKvm(); return;
    case '1': setLayer('net'); return;
    case '2': setLayer('wiring'); return;
    case 'f': case 'F': map.fitAll(); return;
    case '0': map.reset(); return;
    case '+': case '=': map.zoomBy(1.25); return;
    case '-': case '_': map.zoomBy(1 / 1.25); return;
    default: break;
  }
  if (document.activeElement !== map.el && document.activeElement !== document.body) return;
  switch (k) {
    case 'ArrowLeft': e.preventDefault(); moveSelection(-1, 0); return;
    case 'ArrowRight': e.preventDefault(); moveSelection(1, 0); return;
    case 'ArrowUp': e.preventDefault(); moveSelection(0, -1); return;
    case 'ArrowDown': e.preventDefault(); moveSelection(0, 1); return;
    case 'Enter': if (st.route.sel.length) { e.preventDefault(); const f = right.querySelector('.insp-h button, .insp-b'); f && f.focus(); } return;
    case 'Home': case 'End': { e.preventDefault(); const ts = map.targets(); if (ts.length) select(ts[k === 'Home' ? 0 : ts.length - 1].id); return; }
    default: break;
  }
});

// ---------------------------------------------------------------- boot

applyTheme();
initTips();
initRoute();
layout(); renderTopbar(); renderRail(); renderOffline();
reloadAll();
setInterval(() => { if (!document.hidden) { loadHealth(); loadEvents(); } }, 30000);
setInterval(() => { if (!document.hidden && !get().serverDown) refreshRuns(); }, 60000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) pollLive(); else clearTimeout(liveTimer); });
window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', applyTheme);
// Development aid: #/map?dev=palette|keys|legend|filter opens that layer on load, for screenshots.
if (get().route.dev) setTimeout(() => {
  const d = get().route.dev;
  if (d === 'palette') openPalette(commands);
  else if (d === 'keys') openKeys();
  else if (d === 'legend' || d === 'filter') { const b = [...document.querySelectorAll('.map-tools .btn')].find(x => (x.getAttribute('aria-label') || '').toLowerCase() === d); b && b.click(); }
}, 1800);
document.documentElement.dataset.ready = '1';

export { statusLabel, plural };
