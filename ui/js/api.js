// The only module that talks to the server. Same origin, JSON, every POST carries X-House-Monitor: 1.

export class ApiError extends Error {
  constructor(message, status, unreachable = false) {
    super(message); this.status = status; this.unreachable = unreachable;
  }
}

async function request(path, { method = 'GET', body, timeout = 12000 } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeout);
  let res;
  try {
    res = await fetch(path, {
      method, signal: ctl.signal, cache: 'no-store',
      headers: method === 'POST' ? { 'Content-Type': 'application/json', 'X-House-Monitor': '1' } : undefined,
      body: method === 'POST' ? JSON.stringify(body || {}) : undefined,
    });
  } catch (e) {
    throw new ApiError(e && e.name === 'AbortError' ? 'The server took too long to answer.' : 'The server could not be reached.', 0, true);
  } finally { clearTimeout(timer); }
  let data = null;
  const text = await res.text();
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (!res.ok) throw new ApiError((data && data.error) || ('The server answered ' + res.status + '.'), res.status);
  return data;
}

const get = path => request(path);
/** A route a newer server adds: a 404 or no answer is an empty object, so the UI never breaks on an older server. */
const optional = path => request(path).then(d => (d && typeof d === 'object' ? d : {}), () => ({}));
const post = (path, body) => request(path, { method: 'POST', body });
const enc = encodeURIComponent;

import { createDemo } from './fixture.js';

const real = {
  health: () => get('/api/health'),
  inventory: () => get('/api/inventory'),
  // the house's own files: where things sit on the maps, the site (owner, router, hands-off devices), the setup checklist
  layout: () => optional('/api/layout'),
  site: () => optional('/api/site'),
  setup: () => optional('/api/setup'),
  device: id => get('/api/device/' + enc(id)),
  live: () => get('/api/live'),
  events: (limit = 200) => get('/api/events?limit=' + limit),
  audit: (limit = 300) => get('/api/audit?limit=' + limit),
  settings: () => get('/api/settings'),
  saveSettings: patch => post('/api/settings', patch),
  reporters: () => get('/api/reporters'),
  addReporter: device => post('/api/reporters', { device }),
  removeReporter: device => post('/api/reporters', { device, remove: true }),
  ask: (message, deviceIds, threadId) => post('/api/agent/ask', threadId ? { message, deviceIds, threadId } : { message, deviceIds }),
  run: id => get('/api/agent/run/' + enc(id)),
  runs: (limit = 50) => get('/api/agent/runs?limit=' + limit),
  cancel: id => post('/api/agent/run/' + enc(id) + '/cancel'),
  decide: (actionId, decision) => post('/api/agent/action/' + enc(actionId) + '/decide', { decision }),
  streamUrl: id => '/api/agent/run/' + enc(id) + '/stream',
  // version 2: what the person does to a device, and the router login
  deviceActions: id => get('/api/device/' + enc(id) + '/actions'),
  deviceAction: (id, body) => request('/api/device/' + enc(id) + '/action', { method: 'POST', body, timeout: 90000 }),
  router: () => get('/api/router'),
  routerLogin: creds => request('/api/router/login', { method: 'POST', body: creds, timeout: 30000 }),
  routerLogout: () => post('/api/router/logout'),
  // version 3: Sentinel findings, what the person does to one, and scanning now
  threats: (params = {}) => { const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString(); return get('/api/threats' + (q ? '?' + q : '')); },
  threat: id => get('/api/threats/' + enc(id)),
  threatAction: (id, body) => request('/api/threats/' + enc(id) + '/action', { method: 'POST', body, timeout: 60000 }),
  threatScan: (body = {}) => post('/api/threats/scan', body),
  routerUnblock: mac => request('/api/router/unblock', { method: 'POST', body: { mac, confirm: true }, timeout: 30000 }),
};

/** 0 = the server's data. 1 or 2 = sample data laid over it (#/…?demo=1 without, ?demo=2 with a router login). */
export function demoMode() { const m = /[?&]demo=([12])\b/.exec(location.hash); return m ? Number(m[1]) : 0; }
let demo = null;
export const api = new Proxy(real, {
  get(target, key) {
    if (demoMode()) {
      if (!demo) demo = createDemo(real, demoMode() === 2);
      if (key in demo) return demo[key];
    }
    return target[key];
  },
});
