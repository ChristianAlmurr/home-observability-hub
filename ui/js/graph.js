// Read-only views over the inventory and the live document: lookups, status, tracing.
import { get } from './store.js';
import { speedGbps } from './fmt.js';

let G = { inv: null, dev: new Map(), link: new Map(), zone: new Map(), byDev: new Map(), wifi: new Map() };

export function parseEnd(end) {
  const [dev, port] = String(end || '').split(':');
  return { dev, port: port || null };
}

const NETCABLE = new Set(['ethernet', 'coax', 'mesh', 'wifi']);
export const carriesNet = l => NETCABLE.has(l.cable) || (l.carries || []).includes('network');

export function index(inv) {
  const g = { inv, dev: new Map(), link: new Map(), zone: new Map(), byDev: new Map(), wifi: new Map() };
  for (const z of inv.zones || []) g.zone.set(z.id, z);
  for (const d of inv.devices || []) { g.dev.set(d.id, d); g.byDev.set(d.id, []); }
  for (const l of inv.links || []) {
    const a = parseEnd(l.from), b = parseEnd(l.to);
    const link = { ...l, a, b };
    g.link.set(l.id, link);
    // A Wi-Fi link is radio, not a cable: it is kept apart so the wiring views keep meaning "cables".
    if (l.cable === 'wifi') { if (g.dev.has(a.dev)) g.wifi.set(a.dev, link); continue; }
    if (g.byDev.has(a.dev)) g.byDev.get(a.dev).push(link);
    if (g.byDev.has(b.dev) && b.dev !== a.dev) g.byDev.get(b.dev).push(link);
  }
  // An older server names no Wi-Fi links. A device whose only way onto the network is a Wi-Fi interface
  // still gets one, to the mesh as a whole: the access point is not known.
  for (const d of inv.devices || []) {
    if (g.wifi.has(d.id) || !(d.net || []).some(n => n.medium === 'wifi')) continue;
    const n = d.net.find(x => x.medium === 'wifi' && x.ap) || d.net.find(x => x.medium === 'wifi');
    const ap = n.ap && g.dev.has(n.ap) ? n.ap : null;
    const read = inv.router && inv.router.readAt ? ' on ' + inv.router.readAt : '';
    const link = { id: 'w-' + d.id, from: d.id, to: ap, cable: 'wifi', carries: ['network'], synthetic: true, ap: ap ? 'known' : 'unknown', band: n.band || null, rssi: n.rssi != null ? n.rssi : null,
      ssid: (inv.site && inv.site.ssid) || null, verified: ap ? (n.verified || 'reported') : 'plan',
      evidence: ap ? 'The inventory records the access point, as read from the router' + read + '. It is not a live reading: the device may have moved since.' : 'The inventory lists a Wi-Fi interface for this device. Which access point it uses is not known.',
      a: { dev: d.id, port: null }, b: { dev: ap || '', port: null } };
    g.link.set(link.id, link); g.wifi.set(d.id, link);
  }
  G = g;
  return g;
}

export const devices = () => (G.inv ? G.inv.devices : []);
export const links = () => [...G.link.values()];
export const zones = () => (G.inv ? G.inv.zones : []);
export const device = id => G.dev.get(id) || null;
export const link = id => G.link.get(id) || null;
export const zone = id => G.zone.get(id) || null;
export const rooms = () => (G.inv && G.inv.rooms) || [];
export const room = id => rooms().find(r => r.id === id) || null;
export const roomOf = d => { const z = G.zone.get(d.zone); return (z && z.room) || null; };

/**
 * Zones in reading order, grouped by room first: Home Office › Desk, Home Office › Network shelf, …
 * then the other rooms in the home's order, then what has no room.
 */
export function groups() {
  if (!G.inv) return [];
  const zs = G.inv.zones || [];
  const order = ['office', ...rooms().map(r => r.id).filter(r => r !== 'office')];
  const out = [];
  for (const rid of order) {
    const r = room(rid); if (!r) continue;
    const mine = zs.filter(z => z.room === rid);
    for (const z of mine) {
      const same = z.name.toLowerCase() === r.name.toLowerCase();
      out.push({ id: z.id, room: rid, roomName: r.name, zone: z, label: mine.length > 1 ? r.name + ' › ' + (same ? 'Elsewhere' : z.name) : r.name });
    }
  }
  for (const z of zs) if (!z.room || !room(z.room)) out.push({ id: z.id, room: null, roomName: null, zone: z, label: z.id === 'unplaced' ? 'Room not known' : z.name });
  return out;
}
export function groupLabel(zoneId) { const g = groups().find(x => x.id === zoneId); return g ? g.label : (zoneId || 'Room not known'); }
export const linksOf = id => G.byDev.get(id) || [];
export const isLinkId = id => G.link.has(id);
export const isDeviceId = id => G.dev.has(id);
export const deviceName = id => (G.dev.get(id) ? G.dev.get(id).name : id);

export function port(devId, portId) {
  const d = G.dev.get(devId);
  return (d && (d.ports || []).find(p => p.id === portId)) || null;
}
export function portLabel(devId, portId) {
  if (!portId) return 'port not confirmed';
  const p = port(devId, portId);
  return p ? p.label : portId;
}
/** Short label for the map: drops the parenthetical. */
export function portShort(devId, portId) {
  const p = port(devId, portId);
  if (!p) return portId || '?';
  return p.label.replace(/\s*\(.*\)\s*$/, '').trim() || p.label;
}
export function linkOnPort(devId, portId) {
  return linksOf(devId).find(l => (l.a.dev === devId && l.a.port === portId) || (l.b.dev === devId && l.b.port === portId)) || null;
}
export function peer(l, devId) {
  return l.a.dev === devId ? { self: l.a, other: l.b } : { self: l.b, other: l.a };
}

export function primaryIp(d) {
  const nets = d.net || [];
  const lan = nets.find(n => n.ip && n.if !== 'tailscale');
  if (lan) return lan.ip;
  const any = nets.find(n => n.ip);
  return any ? any.ip : null;
}
export function isWifi(d) { return conn(d).medium === 'wifi'; }
export function isRemote(d) { return !linksOf(d.id).length && !G.wifi.has(d.id) && (d.net || []).length > 0 && (d.net || []).every(n => n.if === 'tailscale'); }

// ---------------------------------------------------------------- live

export function liveOf(id) {
  const live = get().live;
  return (live && live.devices && live.devices[id]) || null;
}
export function linkLive(id) {
  const live = get().live;
  return (live && live.links && live.links[id]) || null;
}

/** The status to show. Never green for something that is not probed. */
export function statusOf(id) {
  const d = G.dev.get(id);
  const lv = liveOf(id);
  const probe = d && d.probe ? d.probe.type : null;
  if (lv && lv.status === 'unknown' && linksOf(id).some(l => l.cable === 'bluetooth' && l.a.dev === id && l.state === 'paired')) return 'asleep';
  if (!lv || !lv.status) return probe === 'none' || !probe ? 'unmonitored' : 'unknown';
  if (probe === 'none') return 'unmonitored';
  if (probe === 'inferred' && lv.status === 'online') return 'inferred';
  return ['online', 'degraded', 'offline', 'unknown', 'unmonitored'].includes(lv.status) ? lv.status : 'unknown';
}

const RANK = { offline: 0, degraded: 1, unknown: 2, inferred: 3, unmonitored: 4, asleep: 4, online: 5 };
export const statusRank = st => (st in RANK ? RANK[st] : 2);

/** The KVM switch whose inputs the wiring map can show: the first device of kind kvm with an input cable. */
export function kvmDevice() {
  return devices().find(d => d.kind === 'kvm' && linksOf(d.id).some(l => l.kvmInput)) || null;
}
/**
 * The computer behind each KVM input: { pc1: { dev, name }, pc2: … }. The cable may reach the KVM through a dock,
 * so the nearest computer upstream of the input cable is named; failing that, the device at the cable's other end.
 */
export function kvmInputs() {
  const k = kvmDevice();
  const out = {};
  if (!k) return out;
  for (const l of linksOf(k.id)) {
    if (!l.kvmInput || out[l.kvmInput]) continue;
    const first = peer(l, k.id).other.dev;
    const seen = new Set([k.id, first]);
    const q = [first];
    let found = null;
    while (q.length && !found) {
      const cur = q.shift();
      const d = G.dev.get(cur);
      if (d && ['computer', 'laptop', 'console'].includes(d.kind)) { found = cur; break; }
      for (const x of linksOf(cur)) { if (x.cable === 'bluetooth') continue; const o = peer(x, cur).other.dev; if (!seen.has(o)) { seen.add(o); q.push(o); } }
    }
    const id = found || first;
    out[l.kvmInput] = { dev: id, name: G.dev.get(id) ? G.dev.get(id).name : id };
  }
  return out;
}
/** Words for one KVM input: "PC1 Desktop", or just "PC1". */
export const kvmInputLabel = (input, short = false) => { const x = kvmInputs()[input]; return input.toUpperCase() + (x && !short ? ' ' + shortName(x.dev) : ''); };

/**
 * Which KVM input the desk is on: live if the server says, otherwise inferred, otherwise not known.
 * The inference: the KVM is read over USB by the computer this hub runs on, so when it answers, the input
 * cabled to that computer is the one in use.
 */
export function kvmBelief() {
  const k = kvmDevice();
  if (!k) return { input: null, basis: 'unknown' };
  const lv = liveOf(k.id);
  const f = (lv && lv.facts) || {};
  const said = f.activeInput || f.input || f.kvmInput;
  if (said === 'pc1' || said === 'pc2') return { input: said, basis: 'live' };
  const host = hostDeviceId();
  const mine = Object.entries(kvmInputs()).find(([, v]) => host && v.dev === host);
  if (lv && lv.status === 'online' && mine) return { input: mine[0], basis: 'inferred' };
  return { input: null, basis: 'unknown' };
}
export function kvmView() {
  const s = get();
  if (s.kvm) return s.kvm;
  return kvmBelief().input || 'both';
}
/** The id of the computer this hub runs on, from the site (or the inventory's self-probed device). */
export function hostDeviceId() {
  const h = (get().site || {}).host;
  const id = h ? (typeof h === 'string' ? h : h.deviceId || h.id) : null;
  if (id && G.dev.has(id)) return id;
  const self = devices().find(d => d.probe && d.probe.type === 'self');
  return self ? self.id : null;
}

// ---------------------------------------------------------------- tracing

const PASS = new Set(['adapter', 'hub', 'kvm', 'switch']);
const shares = (a, b) => (a.carries || []).some(c => (b.carries || []).includes(c));

/**
 * Follow cables from a device (or one link) through pass-through devices until each branch ends.
 * A branch continues through an adapter, dock, KVM or switch only along cables that carry the same
 * kind of signal. Through the KVM it goes from an input to the outputs, or from an output back to
 * the input(s) the KVM view is on.
 * Returns { links:Set, devices:Set, chains:[ [ {link, from, to} ] ], slow:Set }.
 */
export function trace(startId) {
  const out = { links: new Set(), devices: new Set(), chains: [], slow: new Set() };
  const view = kvmView();
  const walk = (devId, viaLink, chain, seen) => {
    out.devices.add(devId);
    const d = G.dev.get(devId);
    const here = linksOf(devId).filter(l => l !== viaLink && !seen.has(l.id));
    let next = here;
    if (viaLink) {
      if (!d || !PASS.has(d.kind)) next = [];
      else {
        next = here.filter(l => shares(l, viaLink));
        if (d.kind === 'kvm') {
          const cameIn = !!viaLink.kvmInput;
          next = next.filter(l => (cameIn ? !l.kvmInput : !!l.kvmInput && (view === 'both' || l.kvmInput === view)));
        }
      }
    }
    if (!next.length) { if (chain.length) out.chains.push(chain); return; }
    for (const l of next) {
      const { self, other } = peer(l, devId);
      out.links.add(l.id);
      const s2 = new Set(seen); s2.add(l.id);
      walk(other.dev, l, [...chain, { link: l, from: self, to: other }], s2);
    }
  };
  if (G.link.has(startId)) {
    const l = G.link.get(startId);
    out.links.add(l.id);
    const left = { links: new Set(), chains: [] };
    // walk both ways from the link and join the two halves
    const half = (end, otherEnd) => {
      const sub = [];
      const keep = out.chains; out.chains = sub;
      walk(end.dev, l, [], new Set([l.id]));
      out.chains = keep;
      return sub.length ? sub : [[]];
    };
    const aSide = half(l.a, l.b), bSide = half(l.b, l.a);
    for (const a of aSide) for (const b of bSide) {
      const back = [...a].reverse().map(h => ({ link: h.link, from: h.to, to: h.from }));
      out.chains.push([...back, { link: l, from: l.a, to: l.b }, ...b]);
    }
    void left;
  } else if (G.dev.has(startId)) {
    walk(startId, null, [], new Set());
  }
  for (const chain of out.chains) {
    const sp = chain.map(h => ({ id: h.link.id, v: speedGbps(h.link.speed) })).filter(x => x.v != null);
    if (sp.length < 2) continue;
    const min = Math.min(...sp.map(x => x.v)), max = Math.max(...sp.map(x => x.v));
    if (min === max) continue;
    for (const x of sp) if (x.v === min) out.slow.add(x.id);
  }
  return out;
}

/** Order an answer's path links into a chain of hops where they connect; unconnected ones follow. */
export function orderPath(linkIds) {
  const ls = linkIds.map(id => G.link.get(id)).filter(Boolean);
  if (!ls.length) return [];
  const count = new Map();
  for (const l of ls) for (const e of [l.a.dev, l.b.dev]) count.set(e, (count.get(e) || 0) + 1);
  const left = new Set(ls);
  const hops = [];
  let cur = null;
  const first = ls.find(l => count.get(l.a.dev) === 1) || ls.find(l => count.get(l.b.dev) === 1) || ls[0];
  cur = count.get(first.a.dev) === 1 || count.get(first.b.dev) !== 1 ? first.a.dev : first.b.dev;
  while (left.size) {
    let l = [...left].find(x => x.a.dev === cur || x.b.dev === cur);
    let gap = false;
    if (!l) { l = [...left][0]; cur = l.a.dev; gap = hops.length > 0; }
    left.delete(l);
    const { self, other } = peer(l, cur);
    hops.push({ link: l, from: self, to: other, gap });
    cur = other.dev;
  }
  return hops;
}

// ---------------------------------------------------------------- identity, security, how it connects

const NO_MODEL = /^(not identified|answers ping|reports the hostname|unknown|an? |something )/i;

export function shortModel(model) {
  const m = String(model || '').trim();
  return !m || NO_MODEL.test(m) ? '' : m.split(/ \(|,|;|:/)[0].trim();
}

/** The identity record, or the closest an older server allows. `assessed` is false when the server sent none. */
export function identityOf(d) {
  if (!d) return { state: null, evidence: [], candidates: [], assessed: false };
  const i = d.identity;
  if (i && i.state) return { ...i, evidence: i.evidence || [], candidates: i.candidates || [], assessed: true };
  const k = (d.knowledge && d.knowledge.identity) || {};
  const model = shortModel(d.model);
  let state = null;
  if (d.kind === 'unknown' || (!model && !d.vendor)) state = 'unidentified';
  else if (k.confidence === 'confirmed') state = 'confirmed';
  else if (k.confidence === 'likely') state = 'likely';
  else if (k.confidence === 'unknown') state = 'unidentified';
  return { state, vendor: d.vendor || k.vendor || null, model: model || null, type: null, basis: k.basis || null, evidence: [], candidates: [], assessed: false };
}
export const ID_WORD = { confirmed: 'confirmed', likely: 'likely', unidentified: 'not identified' };

/** "Vendor Model" for a label, without repeating the vendor. Empty when neither is known. */
export function brandOf(d) {
  const i = identityOf(d);
  const vendor = (i.vendor || d.vendor || '').trim();
  let model = shortModel(i.model || d.model);
  if (vendor && model.toLowerCase().startsWith(vendor.toLowerCase() + ' ')) model = model.slice(vendor.length + 1);
  return [vendor, model].filter(Boolean).join(' ');
}
/** The best guess for something that is not identified, in plain words, or ''. */
export function bestGuess(d) {
  const c = identityOf(d).candidates[0];
  return c ? [c.vendor, c.model || c.type].filter(Boolean).join(' ') : '';
}

export function securityOf(id) {
  const lv = liveOf(id);
  return (lv && lv.security) || null;
}
export const secLevel = id => { const s = securityOf(id); return s ? (s.blocked ? 'blocked' : s.level || 'ok') : null; };
export const SEC_WORD = { ok: 'no findings', watch: 'worth a look', suspicious: 'suspicious', blocked: 'blocked at the router' };

/** First seen within the last 24 hours. */
export function isNew(id, now = Date.now()) {
  const s = securityOf(id);
  const t = s && s.firstSeen ? Date.parse(s.firstSeen) : NaN;
  return !Number.isNaN(t) && now - t < 86400e3 && now - t >= 0;
}

/** Things in the house. The `internet` object stands for the outside world and is not counted. */
export const things = () => devices().filter(d => d.kind !== 'internet');

const SEC_RANK = { suspicious: 0, blocked: 2, watch: 3, ok: 6 };
/** Lower is worse. Suspicious first, then not identified, blocked, watch, new, likely, the rest. */
export function concernRank(d) {
  const lvl = secLevel(d.id), idn = identityOf(d).state;
  if (lvl === 'suspicious') return 0;
  if (idn === 'unidentified') return 1;
  if (lvl === 'blocked') return 2;
  if (lvl === 'watch') return 3;
  if (isNew(d.id, get().now)) return 4;
  if (statusOf(d.id) === 'offline') return 4.5;
  if (idn === 'likely') return 5;
  return lvl in SEC_RANK ? 6 : 7;
}
export function concerns() {
  return things().map((d, i) => ({ d, r: concernRank(d), sc: (securityOf(d.id) || {}).score || 0, i })).filter(x => x.r < 6)
    .sort((a, b) => a.r - b.r || b.sc - a.sc || a.i - b.i).map(x => x.d);
}
export function secSummary() {
  const now = get().now;
  const out = { total: 0, unidentified: 0, likely: 0, suspicious: 0, blocked: 0, watch: 0, fresh: 0, offline: 0, online: 0, assessed: false };
  for (const d of things()) {
    out.total++;
    const idn = identityOf(d), lvl = secLevel(d.id), st = statusOf(d.id);
    if (idn.state === 'unidentified') out.unidentified++;
    if (idn.state === 'likely') out.likely++;
    if (lvl) out.assessed = true;
    if (lvl === 'suspicious') out.suspicious++;
    if (lvl === 'blocked') out.blocked++;
    if (lvl === 'watch') out.watch++;
    if (isNew(d.id, now)) out.fresh++;
    if (st === 'offline') out.offline++;
    if (st === 'online' || st === 'inferred') out.online++;
  }
  return out;
}
/** Does the device match a top-bar focus (unidentified, suspicious, blocked, new, offline)? */
export function matchesFocus(d, focus) {
  if (!focus) return true;
  if (focus === 'unidentified') return identityOf(d).state === 'unidentified';
  if (focus === 'suspicious') return secLevel(d.id) === 'suspicious';
  if (focus === 'blocked') return secLevel(d.id) === 'blocked';
  if (focus === 'new') return isNew(d.id, get().now);
  if (focus === 'offline') return statusOf(d.id) === 'offline';
  return true;
}

export const wifiLink = id => G.wifi.get(id) || null;
export const routerState = () => { const l = get().live; return (l && l.router) || null; };
export const AP_KINDS = new Set(['router', 'access-point']);

/**
 * How a device reaches the network, from the data only.
 * medium: wired | wifi | bluetooth | tunnel (seen over Tailscale) | lan (on the LAN, medium not known) | none
 */
export function conn(d) {
  if (!d) return { medium: 'none' };
  const ls = linksOf(d.id);
  const bt = ls.find(l => l.cable === 'bluetooth' && l.a.dev === d.id);
  if (bt) return { medium: 'bluetooth', link: bt, to: bt.b.dev };
  const wired = ls.filter(l => l.cable !== 'bluetooth' && carriesNet(l));
  const w = G.wifi.get(d.id);
  const lw = ((get().live || {}).wireless || {})[d.id] || null;
  if (w || lw) {
    const ap = (lw && lw.ap) || (w && w.b.dev) || null;
    const wifi = { link: w, ap: ap && G.dev.has(ap) ? ap : null, band: (lw && lw.band) || (w && w.band) || null, rssi: lw && lw.rssi != null ? lw.rssi : (w && w.rssi != null ? w.rssi : null),
      ssid: (lw && lw.ssid) || (w && w.ssid) || null, source: (lw && lw.source) || null };
    if (!wired.length) return { medium: 'wifi', ...wifi, to: wifi.ap };
    return { medium: 'wired', link: wired[0], wifi };
  }
  if (wired.length) return { medium: 'wired', link: wired[0] };
  const hasIp = (d.net || []).some(n => n.ip && n.if !== 'tailscale');
  if (ls.length && hasIp) return { medium: 'lan', link: ls[0] };   // desk cables, and on the LAN by a way the inventory does not record
  if (ls.length) return { medium: 'cable', link: ls[0] };   // a desk cable: video or USB, no network of its own
  const nets = (d.net || []).filter(n => n.ip);
  if (nets.length && nets.every(n => n.if === 'tailscale')) return { medium: 'tunnel' };
  if (nets.some(n => n.medium === 'bluetooth') || (d.net || []).some(n => n.medium === 'bluetooth')) return { medium: 'bluetooth', to: null };
  if (nets.length) return { medium: 'lan' };
  return { medium: 'none' };
}
export const MEDIUM = { wired: 'Wired', wifi: 'Wi-Fi', bluetooth: 'Bluetooth', tunnel: 'Tailscale', lan: 'On the LAN', cable: 'Desk cable', none: 'Not connected' };
export function connText(d) {
  const c = conn(d);
  if (c.medium === 'wifi') return 'Wi-Fi' + (c.band ? ' ' + c.band : '') + (c.ap ? ' → ' + shortName(c.ap) : ' · access point not known');
  if (c.medium === 'wired') { const o = peer(c.link, d.id).other; return (c.link.cable === 'ethernet' ? 'Ethernet' : c.link.cable === 'coax' ? 'Coax' : c.link.cable === 'mesh' ? 'Mesh backhaul' : c.link.cable.toUpperCase()) + (c.link.speed ? ' ' + c.link.speed : '') + ' → ' + shortName(o.dev); }
  if (c.medium === 'bluetooth') return 'Bluetooth' + (c.to ? ' → ' + shortName(c.to) : ' · host not known');
  if (c.medium === 'cable') { const o = peer(c.link, d.id).other; return 'Cable → ' + shortName(o.dev); }
  if (c.medium === 'tunnel') return 'Tailscale · not on the LAN';
  if (c.medium === 'lan') return 'On the LAN · wired or Wi-Fi not known';
  return d.zone === 'spares' ? 'Not wired in' : 'No connection recorded';
}
const GEAR = new Set(['router', 'access-point', 'switch', 'modem']);
/** A shorter name for tight places: "Vendor Model X (router)" → "X router", a leading vendor dropped: "TP-Link 2.5G switch" → "2.5G switch". */
export function shortName(id) {
  const d = G.dev.get(id);
  if (!d) return id;
  const n = String(d.name || id);
  const m = /^(.*\S)\s+\(([^)]+)\)$/.exec(n);
  if (m && GEAR.has(d.kind) && m[1].includes(' ')) return m[1].split(' ').pop() + ' ' + m[2];
  const v = (d.vendor || '').trim();
  if (v && n.toLowerCase().startsWith(v.toLowerCase() + ' ') && n.length - v.length > 7) return n.slice(v.length + 1);
  return n;
}
/** Access points in the inventory (the main router counts). More than one makes a mesh. */
/** Access points in use (the main router counts): cabled, or with an address. A spare router on a shelf is not one. More than one makes a mesh. */
export const accessPoints = () => devices().filter(d => AP_KINDS.has(d.kind) && (linksOf(d.id).length || (d.net || []).some(n => n.ip) || d.id === (meshRoot() || {}).id));
/** "the mesh" when there is more than one access point, else the router's own name, else "the network". */
export function meshWord() {
  const aps = accessPoints();
  if (aps.length > 1) return 'the mesh';
  return aps.length ? shortName(aps[0].id) : 'the network';
}

const FORWARDS = new Set(['router', 'access-point', 'switch', 'modem', 'adapter', 'hub', 'internet']);
/** Where the path to the internet ends: the internet object, else the modem, else the router. */
export function gateway() {
  const ds = devices();
  return ds.find(d => d.kind === 'internet') || ds.find(d => d.kind === 'modem') || ds.find(d => d.kind === 'router') || null;
}
/** The main router: the one the site names, else the router nearest the internet, else the first router. */
export function meshRoot() {
  const named = ((get().site || {}).router || {}).deviceId;
  if (named && G.dev.has(named)) return G.dev.get(named);
  const routers = devices().filter(d => d.kind === 'router');
  if (routers.length < 2) return routers[0] || null;
  const start = devices().find(d => d.kind === 'internet') || devices().find(d => d.kind === 'modem');
  if (!start) return routers[0];
  const dist = new Map([[start.id, 0]]); const q = [start.id];
  while (q.length) { const cur = q.shift(); for (const l of linksOf(cur)) { if (l.cable === 'bluetooth' || !carriesNet(l)) continue; const o = peer(l, cur).other.dev; if (!dist.has(o)) { dist.set(o, dist.get(cur) + 1); q.push(o); } } }
  return [...routers].sort((a, b) => (dist.has(a.id) ? dist.get(a.id) : 1e9) - (dist.has(b.id) ? dist.get(b.id) : 1e9))[0];
}

/**
 * The hops from a device to the internet: [{ link, from, to, mesh? }]. A Wi-Fi hop whose access point is not
 * known goes to the mesh as a whole (`mesh: true`) and continues from the main router. null when there is none.
 */
export function upstream(id, useSpareWifi = false) {
  const goal = gateway();
  const start = G.dev.get(id);
  if (!goal || !start) return null;
  if (id === goal.id) return [];
  const c0 = conn(start);
  if (c0.medium === 'bluetooth') {
    const rest = c0.to ? upstream(c0.to) : null;
    return rest ? [{ link: c0.link, from: { dev: id }, to: { dev: c0.to } }, ...rest] : null;
  }
  const prev = new Map([[id, null]]);
  const queue = [id];
  while (queue.length) {
    const cur = queue.shift();
    if (cur === goal.id) break;
    const d = G.dev.get(cur);
    if (cur !== id && !(d && FORWARDS.has(d.kind))) continue;
    const edges = [];
    for (const l of linksOf(cur)) {
      if (l.cable === 'bluetooth' || !carriesNet(l)) continue;
      edges.push({ link: l, to: peer(l, cur).other.dev });
    }
    if (cur === id) {
      const c = conn(d);
      // a device that is wired first and also on Wi-Fi takes the wire; its Wi-Fi is the fallback
      if (c.medium === 'wifi' || (c.wifi && useSpareWifi)) {
        const w = c.medium === 'wifi' ? c : c.wifi;
        const root = meshRoot();
        const link = w.link || { id: 'w-' + id, cable: 'wifi', a: { dev: id }, b: { dev: w.ap || '' }, verified: 'live', synthetic: true };
        if (w.ap) edges.push({ link, to: w.ap });
        else if (root) edges.push({ link, to: root.id, mesh: true });
      } else if (c.medium === 'tunnel') return [{ link: { id: 't-' + id, cable: 'tunnel', a: { dev: id }, b: { dev: goal.id }, verified: 'live', synthetic: true }, from: { dev: id }, to: { dev: goal.id }, tunnel: true }];
    }
    for (const e of edges) {
      if (!e.to || prev.has(e.to) || !G.dev.has(e.to)) continue;
      prev.set(e.to, { from: cur, ...e });
      queue.push(e.to);
    }
  }
  if (!prev.has(goal.id)) return useSpareWifi ? null : upstream(id, true);
  const hops = [];
  for (let cur = goal.id; prev.get(cur); cur = prev.get(cur).from) { const p = prev.get(cur); hops.unshift({ link: p.link, from: { dev: p.from }, to: { dev: cur }, mesh: !!p.mesh }); }
  return hops;
}

/** Items for "Needs attention": at most 3, worst first. */
export function attention() {
  const s = get();
  const items = [];
  if (!G.inv) return items;
  const down = devices().filter(d => statusOf(d.id) === 'offline');
  for (const d of down) {
    const lv = liveOf(d.id);
    const bad = lv && (lv.checks || []).find(c => c.ok === false);
    items.push({ status: 'offline', text: d.name + ' is not answering' + (bad ? ' (' + bad.name + ')' : ''), ids: [d.id] });
  }
  const deg = devices().filter(d => statusOf(d.id) === 'degraded');
  for (const d of deg) items.push({ status: 'degraded', text: d.name + ' is degraded', ids: [d.id] });
  const strangers = (s.live && s.live.strangers) || [];
  if (strangers.length) items.push({ status: 'unknown', text: strangers.length === 1 ? '1 host on the network is not in the inventory' : strangers.length + ' hosts on the network are not in the inventory', strangers: true, ids: [] });
  const unk = devices().filter(d => d.kind === 'unknown');
  if (unk.length) items.push({ status: 'unknown', text: unk.length === 1 ? '1 device is not identified' : unk.length + ' devices are not identified', ids: unk.map(d => d.id) });
  const planned = links().filter(l => l.verified === 'plan' && l.cable !== 'wifi');
  if (planned.length) {
    // when every unconfirmed cable touches one device, name it: that chain is what to check
    const ends = planned.map(l => new Set([l.a.dev, l.b.dev]));
    const shared = [...ends[0]].find(id => ends.every(e => e.has(id)));
    if (shared && planned.length > 1) items.push({ status: 'plan', text: 'The cables at ' + deviceName(shared) + ' are drawn but not confirmed', ids: [shared], links: planned.map(l => l.id) });
    else items.push({ status: 'plan', text: planned.length === 1 ? '1 cable is drawn but not confirmed' : planned.length + ' cables are drawn but not confirmed', ids: [], links: planned.map(l => l.id) });
  }
  return items;
}
