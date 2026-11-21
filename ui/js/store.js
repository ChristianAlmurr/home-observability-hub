// One store, one selection model, one URL.
// Views read state with get(), change it with set(), and re-render from on().

const VIEWS = ['map', 'threats', 'security', 'devices', 'agent', 'activity', 'questions', 'settings'];

const state = {
  inventory: null, invError: null,
  layout: {},             // data/layout.json as served by /api/layout ({} when there is none): authored places on the two maps
  site: {}, setup: null,  // /api/site and /api/setup ({} from an older server)
  live: null, liveAt: 0, liveError: null, serverDown: false,
  health: null, settings: null, settingsError: null, router: null, routerError: null,
  threats: null, threatsAt: 0, threatsError: null,   // the Sentinel document; threatsError is 'missing' when the server has no such route
  events: null, eventsError: null, audit: null, auditError: null,
  route: { view: 'map', sel: [], panel: null, run: null, at: 'events', fixture: false, trace: false, mapMode: null, demo: null, threats: null },
  hover: null,            // id of a device or link hovered anywhere
  pin: null,              // { runId, links:[], suspect:[], devices:[], note } an answer path pinned on the map
  kvm: null,              // 'pc1' | 'pc2' | 'both' | null (null = what the system believes)
  layer: 'net',           // net (the living network) | wiring (the desk schematic)
  filters: { trust: { live: true, plan: true, reported: true }, problems: false, carries: {}, status: null, focus: null },
  scanAt: 0,              // when the last new live reading arrived (drives the scan sweep)
  ui: { list: 'auto', drawer: 'closed', drawerTab: 'events' },
  agent: { runs: {}, list: null, listError: null, scope: [], threadId: null, draft: '' },
  now: Date.now(), reloadAt: 0,
};

const subs = new Set();
let pending = null;

export function get() { return state; }

export function set(patch) {
  for (const k of Object.keys(patch)) state[k] = patch[k];
  if (!pending) {
    pending = new Set();
    queueMicrotask(flush);
  }
  for (const k of Object.keys(patch)) pending.add(k);
}

function flush() {
  const keys = pending; pending = null;
  for (const sub of [...subs]) {
    if (!sub.keys || sub.keys.some(k => keys.has(k))) {
      try { sub.fn(state, keys); } catch (e) { console.error(e); window.__hmError && window.__hmError(e); }
    }
  }
}

/** on(['route','live'], fn) → unsubscribe */
export function on(keys, fn) {
  const sub = { keys: typeof keys === 'string' ? [keys] : keys, fn };
  subs.add(sub);
  return () => subs.delete(sub);
}

// ---------------------------------------------------------------- route

export function parseHash(hash) {
  const raw = (hash || '').replace(/^#\/?/, '');
  const [path, query = ''] = raw.split('?');
  const q = new URLSearchParams(query);
  const view = VIEWS.includes(path) ? path : 'map';
  const sel = (q.get('sel') || '').split(',').map(x => x.trim()).filter(x => /^[a-z0-9][a-z0-9-]{0,63}$/.test(x));
  const panel = ['inspector', 'agent'].includes(q.get('tab')) ? q.get('tab') : null;
  const run = /^r[0-9a-f]{12}$/.test(q.get('run') || '') ? q.get('run') : null;
  return {
    view, sel, panel, run,
    at: q.get('at') === 'audit' ? 'audit' : 'events',
    fixture: q.get('fixture') === '1',
    trace: q.get('trace') === '1',
    mapMode: q.get('mode') === 'canvas' ? 'canvas' : null,
    theme: ['dark', 'light'].includes(q.get('theme')) ? q.get('theme') : null,
    dev: q.get('dev') || null,   // development aid: open a floating layer on load (palette, keys, legend, filter, mode)
    kvm: ['pc1', 'pc2', 'both'].includes(q.get('kvm')) ? q.get('kvm') : null,
    layer: q.get('layer') === 'wiring' ? 'wiring' : null,
    demo: ['1', '2'].includes(q.get('demo')) ? q.get('demo') : null,
    threats: /^[a-z0-9]{1,8}$/.test(q.get('threats') || '') ? q.get('threats') : null,   // development aid: which sample findings (see threats-fixture.js)
  };
}

export function buildHash(r) {
  const q = new URLSearchParams();
  if (r.sel && r.sel.length) q.set('sel', r.sel.join(','));
  if (r.panel) q.set('tab', r.panel);
  if (r.run) q.set('run', r.run);
  if (r.view === 'activity' && r.at === 'audit') q.set('at', 'audit');
  if (r.fixture) q.set('fixture', '1');
  if (r.trace) q.set('trace', '1');
  if (r.mapMode) q.set('mode', r.mapMode);
  if (r.theme) q.set('theme', r.theme);
  if (r.kvm) q.set('kvm', r.kvm);
  if (r.layer) q.set('layer', r.layer);
  if (r.demo) q.set('demo', r.demo);
  if (r.threats) q.set('threats', r.threats);
  const qs = q.toString().replace(/%2C/g, ',');
  return '#/' + r.view + (qs ? '?' + qs : '');
}

/** Change the route. Pushes history unless replace is set. */
export function go(patch, { replace = false } = {}) {
  const next = { ...state.route, ...patch };
  next.kvm = state.kvm;
  next.layer = state.layer === 'wiring' ? 'wiring' : null;
  if (patch.view && patch.view !== state.route.view && !('fixture' in patch)) next.fixture = false;
  if ('sel' in patch && !('trace' in patch)) next.trace = false;
  const hash = buildHash(next);
  if (hash === location.hash) { set({ route: { ...next } }); return; }
  if (replace) history.replaceState(null, '', hash); else history.pushState(null, '', hash);
  set({ route: next });
}

export function initRoute() {
  const read = () => {
    const r = parseHash(location.hash);
    set({ route: r, kvm: r.kvm, layer: r.layer || 'net' });
  };
  window.addEventListener('hashchange', read);
  window.addEventListener('popstate', read);
  read();
}

/** Change a map view setting that lives in the URL (kvm, layer). */
export function setMapView(patch) { set(patch); go({}, { replace: true }); }

// ---------------------------------------------------------------- selection

export function select(id, { add = false, panel } = {}) {
  let sel;
  if (!id) sel = [];
  else if (add) sel = state.route.sel.includes(id) ? state.route.sel.filter(x => x !== id) : [...state.route.sel, id];
  else sel = [id];
  const patch = { sel };
  if (panel !== undefined) patch.panel = panel;
  else if (sel.length && state.route.panel !== 'agent') patch.panel = null;
  go(patch);
}

export function clearSelection() { go({ sel: [], panel: state.route.panel === 'agent' ? 'agent' : null }); }
export function selected() { return state.route.sel; }
export function isSelected(id) { return state.route.sel.includes(id); }

// ---------------------------------------------------------------- local prefs

export function pref(key, fallback) {
  try { const v = localStorage.getItem('hm.' + key); return v == null ? fallback : JSON.parse(v); } catch { return fallback; }
}
export function setPref(key, value) {
  try { localStorage.setItem('hm.' + key, JSON.stringify(value)); } catch { /* private mode: not kept */ }
}

setInterval(() => { if (!document.hidden) set({ now: Date.now() }); }, 5000);
