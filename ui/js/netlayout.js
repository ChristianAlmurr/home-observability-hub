// Where everything sits on the network map.
//
// Places come from two sources. `network` in data/layout.json (served by /api/layout) pins what a person
// placed by hand; everything else is placed here, from the inventory alone:
//
//   the spine   one horizontal line, read left to right: internet → modem → the main router → the other access
//               points (and any switch that leads to one), found by following the cables that carry the network.
//   the hull    a quiet zone around the access points: "the mesh" when there is more than one, else the router's.
//   below       every device a cable reaches from the spine hangs under what it is plugged into, as a tree;
//               a crowd of leaves becomes a small grid fed by a bus, so no line runs through a device.
//   islands     cabled groups that reach no spine device (a desk behind a Wi-Fi laptop) sit to the right of the
//               trees, rooted at the device that brings them onto the network.
//   the air     Wi-Fi clients (and hosts on the LAN by an unknown medium) take places in rows above the hull,
//               each as near its access point as a free place allows. A place, once given, is remembered in this
//               browser (hm.slots), so a refresh or another device joining does not shuffle the rest.
//   the side    things seen only over Tailscale stand left of the internet; Bluetooth things beside their host;
//               things with no connection on a shelf at the bottom.
//
// The same inventory always gives the same picture: every order here is by kind and id, never by arrival.
import * as G from './graph.js';
import { get, pref, setPref } from './store.js';

const CORE = new Set(['internet', 'modem', 'router', 'access-point', 'switch']);
const COMPUTERS = new Set(['computer', 'laptop', 'server', 'console', 'nas']);
const PITCH = 120, STAGGER = [0, 60, 30, 90];   // the air: across, and the stagger of each ring of rows
const ROW = 116;                                 // the air and the leaf grids: down
const SLOT = 120;                                // the width one node takes in a row (its label is at most 112)
const FIRST = 170, LEVEL = 150;                  // spine to the first row of cables, then each level below
const TRUNK = 40;                                // the margin a leaf grid keeps on its left for its bus
const GRID_COLS = 6;                             // leaves per grid row
const HULL_MIN = 320, HULL_PAD = 74, HULL_HALF = 64;

const num = (v, d) => (typeof v === 'number' && Number.isFinite(v) ? v : d);
const isPt = p => Array.isArray(p) && p.length >= 2 && Number.isFinite(p[0]) && Number.isFinite(p[1]);
const byId = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function authored() {
  const n = (get().layout || {}).network;
  return n && typeof n === 'object' ? n : {};
}

function curve(p, q, bend) {
  if (!bend) return [p, q];
  const mx = (p[0] + q[0]) / 2, my = (p[1] + q[1]) / 2, dx = q[0] - p[0], dy = q[1] - p[1];
  const cx = mx - dy * bend, cy = my + dx * bend;
  const out = [];
  for (let i = 0; i <= 14; i++) { const t = i / 14, u = 1 - t; out.push([u * u * p[0] + 2 * u * t * cx + t * t * q[0], u * u * p[1] + 2 * u * t * cy + t * t * q[1]]); }
  return out;
}
const trim = (from, to, r) => { const dx = to[0] - from[0], dy = to[1] - from[1], len = Math.hypot(dx, dy) || 1; return [from[0] + (dx / len) * r, from[1] + (dy / len) * r]; };

/** Where a link from (px, py) meets the hull's edge: straight up or down onto it, or onto the nearer end. */
export function hullDock(hull, px, py, pad = 0) {
  const x0 = hull.x + 16, x1 = hull.x + hull.w - 16;
  if (py < hull.y) return [Math.max(x0, Math.min(x1, px)), hull.y - pad];
  if (py > hull.y + hull.h) return [Math.max(x0, Math.min(x1, px)), hull.y + hull.h + pad];
  return [px < hull.x + hull.w / 2 ? hull.x - pad : hull.x + hull.w + pad, Math.max(hull.y + 16, Math.min(hull.y + hull.h - 16, py))];
}

let memo = null;
function slots() { if (!memo) memo = pref('slots', {}); return memo; }

const netLinks = id => G.linksOf(id).filter(l => l.cable !== 'bluetooth' && G.carriesNet(l));
const other = (l, id) => G.peer(l, id).other.dev;

/**
 * The spine, left to right. `pre` leads to the main router (internet, modem…), `chain` is the main router and
 * every access point, with a switch only where it leads to one.
 */
function spineOf(devs) {
  const has = id => G.isDeviceId(id);
  const root = G.meshRoot() || [...devs].filter(d => d.kind === 'access-point').sort((a, b) => byId(a.id, b.id))[0] || null;
  const gw = G.gateway();
  let pre = [];
  const outside = devs.filter(d => d.kind === 'internet' || d.kind === 'modem').sort((a, b) => (a.kind === 'internet' ? 0 : 1) - (b.kind === 'internet' ? 0 : 1) || byId(a.id, b.id));
  if (gw && root && gw.id !== root.id) {
    const prev = new Map([[gw.id, null]]);
    const q = [gw.id];
    while (q.length) {
      const cur = q.shift();
      if (cur === root.id) break;
      for (const l of netLinks(cur)) { const o = other(l, cur); if (has(o) && !prev.has(o)) { prev.set(o, cur); q.push(o); } }
    }
    if (prev.has(root.id)) { for (let c = prev.get(root.id); c; c = prev.get(c)) pre.unshift(c); }
    else pre = outside.filter(d => d.id !== root.id).slice(0, 2).map(d => d.id);
  } else if (!root) pre = outside.slice(0, 2).map(d => d.id);
  else if (gw && gw.id === root.id) pre = [];
  const chain = [];
  if (root) {
    const INFRA = new Set(['router', 'access-point', 'switch']);
    const inPre = new Set(pre);
    const parent = new Map([[root.id, null]]), kids = new Map([[root.id, []]]);
    const q = [root.id];
    while (q.length) {
      const cur = q.shift();
      const next = netLinks(cur).map(l => other(l, cur)).filter(o => has(o) && !parent.has(o) && !inPre.has(o) && INFRA.has(G.device(o).kind)).sort(byId);
      for (const o of [...new Set(next)]) { parent.set(o, cur); kids.set(o, []); kids.get(cur).push(o); q.push(o); }
    }
    const isAp = id => G.AP_KINDS.has(G.device(id).kind);
    const leads = new Map();
    const lead = id => { if (leads.has(id)) return leads.get(id); const v = isAp(id) || kids.get(id).some(lead); leads.set(id, v); return v; };
    // how a child hangs off its parent: by cable, or by radio (a mesh backhaul)
    const radio = (p, k) => netLinks(p).some(l => other(l, p) === k && l.cable === 'mesh');
    const walk = id => {
      chain.push(id);
      const ks = kids.get(id).filter(k => isAp(k) || lead(k));
      // cabled children straight after their parent, radio ones after them: a mesh hop that has to reach past
      // something on the spine is drawn as an arc, which reads as radio; a cable drawn that way would not
      ks.sort((a, b) => (radio(id, a) ? 1 : 0) - (radio(id, b) ? 1 : 0) || (isAp(a) ? 0 : 1) - (isAp(b) ? 0 : 1) || byId(a, b));
      for (const k of ks) walk(k);
    };
    walk(root.id);
    // access points with no recorded cable still belong to the Wi-Fi: beside the main router
    const inUse = new Set(G.accessPoints().map(d => d.id));
    const loose = devs.filter(d => inUse.has(d.id) && !parent.has(d.id) && !inPre.has(d.id)).map(d => d.id).sort(byId);
    chain.splice(1, 0, ...loose);
  }
  return { pre, chain, root: root ? root.id : null };
}

export function layout() {
  const devs = G.devices();
  const A = authored();
  const pos = A.pos && typeof A.pos === 'object' ? A.pos : {};
  const S = num(A.spineY, 440);
  const nodes = new Map();
  const roleOf = d => (CORE.has(d.kind) ? 'core' : d.kind === 'peripheral' || d.kind === 'adapter' ? 'peri' : 'end');
  const place = (d, x, y, role, group) => nodes.set(d.id, { id: d.id, x, y, role, group, r: role === 'core' ? 24 : role === 'end' ? 18 : 14, lw: role === 'core' ? 110 : role === 'end' ? 112 : 104 });
  const free = (x, y) => { for (const n of nodes.values()) if (Math.abs(n.x - x) < 100 && Math.abs(n.y - y) < 84) return false; return true; };
  const routes = new Map();   // link id → orthogonal points, for links drawn as a tree's bus
  const pool = { hull: [], remote: [], shelf: [], auto: [] };

  // ------------------------------------------------------------ 1. what a person placed
  for (const d of devs) if (isPt(pos[d.id])) place(d, pos[d.id][0], pos[d.id][1], roleOf(d), 'fixed');
  const fixed = new Set(nodes.keys());

  // ------------------------------------------------------------ 2. the spine and what hangs below it
  const { pre, chain } = spineOf(devs);
  const spine = [...pre, ...chain];
  const onSpine = new Set(spine);
  const parent = new Map(), kids = new Map();
  const reached = new Set(spine);
  const tiers = [l => l.cable !== 'bluetooth' && G.carriesNet(l), l => l.cable !== 'bluetooth', l => l.cable === 'bluetooth'];
  const grow = (from, tier, scope) => {
    // a computer claims what hangs off it before a dock or a switch does (the KVM belongs under the desk's computer)
    const q = tier === tiers[1] ? [...from].sort((a, b) => (COMPUTERS.has(G.device(a).kind) ? 0 : 1) - (COMPUTERS.has(G.device(b).kind) ? 0 : 1)) : [...from];
    while (q.length) {
      const cur = q.shift();
      const ls = G.linksOf(cur).filter(tier).sort((a, b) => byId(other(a, cur), other(b, cur)));
      for (const l of ls) {
        const o = other(l, cur);
        if (!G.isDeviceId(o) || reached.has(o) || (scope && !scope.has(o))) continue;
        if (l.cable === 'bluetooth' && l.a.dev !== o) continue;   // a Bluetooth thing hangs off its host, never the other way
        reached.add(o); parent.set(o, { p: cur, l }); (kids.get(cur) || kids.set(cur, []).get(cur)).push(o);
        q.push(o);
      }
    }
  };
  grow(spine, tiers[0]);
  grow([...reached], tiers[1]);
  grow([...reached], tiers[2]);

  // cabled groups that reach no spine device
  const islands = [];
  const cabled = d => G.linksOf(d.id).some(l => l.cable !== 'bluetooth' && G.isDeviceId(other(l, d.id)));
  const stray = devs.filter(d => !reached.has(d.id) && cabled(d)).sort((a, b) => byId(a.id, b.id));
  const inIsland = new Set();
  for (const d of stray) {
    if (inIsland.has(d.id)) continue;
    const comp = new Set([d.id]); const q = [d.id];
    while (q.length) { const cur = q.shift(); for (const l of G.linksOf(cur)) { if (l.cable === 'bluetooth') continue; const o = other(l, cur); if (G.isDeviceId(o) && !comp.has(o) && !reached.has(o)) { comp.add(o); q.push(o); } } }
    comp.forEach(x => inIsland.add(x));
    // the root: what brings the group onto the network (Wi-Fi, the LAN), else the most connected
    const score = id => { const c = G.conn(G.device(id)); const net = c.medium === 'wifi' || (c.wifi && true) || c.medium === 'lan' || c.medium === 'tunnel' ? 100 : 0; return net + G.linksOf(id).length; };
    const root = [...comp].sort((a, b) => score(b) - score(a) || byId(a, b))[0];
    const scope = new Set([...comp, ...devs.filter(x => !reached.has(x.id)).map(x => x.id)]);
    reached.add(root);
    grow([root], tiers[0], scope);
    grow([...comp].filter(x => reached.has(x)), tiers[1], scope);
    grow([...scope].filter(x => reached.has(x)), tiers[2], scope);
    islands.push(root);
  }

  // measure each subtree: branches side by side, then the leaves as one row or a grid
  const kidsOf = id => (kids.get(id) || []).filter(k => !fixed.has(k));
  const shape = new Map();
  const measure = id => {
    const ks = kidsOf(id);
    const branches = ks.filter(k => kidsOf(k).length).sort(byId);
    const leaves = ks.filter(k => !kidsOf(k).length).sort((a, b) => (roleOf(G.device(a)) === 'peri' ? 1 : 0) - (roleOf(G.device(b)) === 'peri' ? 1 : 0) || byId(a, b));
    let w = 0;
    for (const b of branches) w += measure(b);
    let grid = null;
    if (leaves.length) {
      const cols = leaves.length <= GRID_COLS ? leaves.length : Math.min(GRID_COLS, Math.max(3, Math.ceil(Math.sqrt(leaves.length * 1.5))));
      const rows = Math.ceil(leaves.length / cols);
      grid = { cols, rows, w: cols * SLOT + (rows > 1 ? TRUNK : 0) };
      w += grid.w;
    }
    const total = Math.max(SLOT, w);
    shape.set(id, { branches, leaves, grid, w: total });
    return total;
  };
  const route = (pid, cid, pts) => { const pl = parent.get(cid); if (pl && pl.p === pid) routes.set(pl.l.id, pts); };
  const r0 = id => (CORE.has(G.device(id).kind) ? 24 : roleOf(G.device(id)) === 'end' ? 18 : 14);
  const lay = (id, x, y, below, nth = 0) => {
    const sh = shape.get(id); if (!sh) return;
    // neighbouring families at one depth put their bus at a slightly different height, so two never read as one line
    const cy = y + below, bus = cy - 44 + (nth % 2) * 10;
    let bx = x - sh.w / 2 + (sh.w - (sh.branches.reduce((a, b) => a + shape.get(b).w, 0) + (sh.grid ? sh.grid.w : 0))) / 2;
    const top = [x, y + r0(id)];
    const drop = (cx, yy, cid) => {
      if (Math.abs(cx - x) < 1) route(id, cid, [top, [cx, yy - r0(cid)]]);
      else route(id, cid, [top, [x, bus], [cx, bus], [cx, yy - r0(cid)]]);
    };
    sh.branches.forEach((b, bi) => {
      const w = shape.get(b).w, cx = bx + w / 2;
      settle(b, cx, cy, 'tree');
      drop(cx, cy, b);
      lay(b, nodes.get(b).x, nodes.get(b).y, LEVEL, bi);
      bx += w;
    });
    if (sh.grid) {
      const g = sh.grid, x0 = bx + (g.rows > 1 ? TRUNK : 0), trunk = bx + TRUNK / 2;
      sh.leaves.forEach((lid, i) => {
        const col = i % g.cols, row = Math.floor(i / g.cols);
        const lx = x0 + SLOT / 2 + col * SLOT, ly = cy + row * ROW;
        settle(lid, lx, ly, 'tree');
        if (row === 0) drop(lx, ly, lid);
        else route(id, lid, [top, [x, bus], [trunk, bus], [trunk, ly - 44], [lx, ly - 44], [lx, ly - r0(lid)]]);
      });
    }
  };
  // a computed place that a hand-placed device already holds: the nearest free place instead
  const settle = (id, x, y, group) => {
    if (nodes.has(id)) return;
    const d = G.device(id);
    if (free(x, y)) { place(d, x, y, roleOf(d), group); return; }
    const spot = near(x, y);
    place(d, spot[0], spot[1], roleOf(d), group);
    const pl = parent.get(id); if (pl) routes.delete(pl.l.id);
  };
  const near = (x, y) => {
    for (let ring = 1; ring < 40; ring++) {
      for (let k = -ring; k <= ring; k++) for (const [dx, dy] of [[k, ring], [k, -ring], [ring, k], [-ring, k]]) {
        const px = x + dx * 105, py = y + dy * ROW;
        if (free(px, py)) return [px, py];
      }
    }
    return [x, y];
  };

  // spine places: room for each subtree, and a hull wide enough to read
  for (const id of spine) measure(id);
  const aps = chain.filter(id => G.AP_KINDS.has(G.device(id).kind));
  const sx = new Map();
  const gapAfter = i => {
    const a = spine[i], b = spine[i + 1];
    const base = i < pre.length - 1 ? 115 : 150;
    return Math.max(base, shape.get(a).w / 2 + shape.get(b).w / 2 + 10);
  };
  let x = 60;
  spine.forEach((id, i) => {
    if (fixed.has(id)) x = nodes.get(id).x;
    else if (i > 0) x += gapAfter(i - 1);
    sx.set(id, x);
  });
  // widen the hull to its minimum by moving what stands left of it left, and what stands right of it right
  if (aps.length && !A.hull) {
    const xs = aps.map(id => sx.get(id));
    const span = Math.max(...xs) - Math.min(...xs) + 2 * HULL_PAD;
    if (span < HULL_MIN) {
      const extra = (HULL_MIN - span) / 2, lo = Math.min(...xs), hi = Math.max(...xs);
      for (const id of spine) if (!fixed.has(id)) { const v = sx.get(id); if (v < lo) sx.set(id, v - extra - 30); else if (v > hi) sx.set(id, v + extra + 30); }
    }
    const minX = Math.min(...spine.map(id => sx.get(id) - shape.get(id).w / 2));
    if (minX < 0 && !spine.some(id => fixed.has(id))) for (const id of spine) sx.set(id, sx.get(id) - minX);
  }
  for (const id of spine) if (!nodes.has(id)) { const d = G.device(id); if (free(sx.get(id), S)) place(d, sx.get(id), S, roleOf(d), 'spine'); else { const p = near(sx.get(id), S); place(d, p[0], p[1], roleOf(d), 'spine'); } }

  // the hull: around the access points, or a stand-in when the inventory has none
  let hull = A.hull && ['x', 'y', 'w', 'h'].every(k => Number.isFinite(A.hull[k])) ? { x: A.hull.x, y: A.hull.y, w: A.hull.w, h: A.hull.h } : null;
  const hullNodes = aps.filter(id => nodes.has(id));
  if (!hull && hullNodes.length) {
    const xs = hullNodes.map(id => nodes.get(id).x);
    let x0 = Math.min(...xs) - HULL_PAD, x1 = Math.max(...xs) + HULL_PAD;
    if (x1 - x0 < HULL_MIN) { const c = (x0 + x1) / 2; x0 = c - HULL_MIN / 2; x1 = c + HULL_MIN / 2; }
    hull = { x: x0, y: S - HULL_HALF, w: x1 - x0, h: 2 * HULL_HALF };
  }

  // trees under the spine, then the islands to their right
  for (const id of spine) { const n = nodes.get(id); if (!fixed.has(id)) lay(id, n.x, n.y, FIRST); }
  for (const id of [...fixed].sort(byId)) besideAll(id);
  let right = -Infinity;
  for (const n of nodes.values()) right = Math.max(right, n.x + 60);
  if (hull) right = Math.max(right, hull.x + hull.w + 20);
  if (!Number.isFinite(right)) right = 0;
  if (!hull) {
    // no access point is recorded: a stand-in zone where the Wi-Fi and the LAN are drawn as a whole
    const last = spine.length ? nodes.get(spine[spine.length - 1]) : null;
    const cx = last ? last.x + 60 + HULL_MIN / 2 + 40 : 60 + HULL_MIN / 2;
    hull = { x: cx - HULL_MIN / 2, y: S - HULL_HALF, w: HULL_MIN, h: 2 * HULL_HALF, virtual: true };
    right = Math.max(right, hull.x + hull.w + 20);
  }
  for (const root of islands) {
    if (nodes.has(root)) { besideAll(root); continue; }
    const w = measure(root);
    const cx = right + w / 2 + 20;
    settle(root, cx, S + FIRST, 'island');
    lay(root, nodes.get(root).x, nodes.get(root).y, LEVEL);
    right = Math.max(right, cx + w / 2 + 20);
  }

  // children of a hand-placed device: beside it, as the first build did, nearest place first
  function besideAll(id) {
    const q = [id];
    while (q.length) {
      const cur = q.shift();
      for (const k of kids.get(cur) || []) {
        if (!nodes.has(k)) {
          const host = nodes.get(cur);
          let spot = null;
          for (const [dx, dy] of [[0, -135], [105, -135], [-105, -135], [210, -135], [0, -245], [105, -245], [-105, -245], [210, -245], [-210, -245], [0, 120], [210, 0]]) if (free(host.x + dx, host.y + dy)) { spot = [host.x + dx, host.y + dy]; break; }
          if (spot) { const d = G.device(k); const c = G.conn(d); place(d, spot[0], spot[1], roleOf(d) === 'core' ? 'core' : c.medium === 'wired' ? roleOf(d) : 'peri', 'beside'); }
          else pool.auto.push({ d: G.device(k), group: 'auto' });
        }
        if (nodes.has(k)) q.push(k);
      }
    }
  }

  // ------------------------------------------------------------ 3. the air, the side, the shelf
  const rest = devs.filter(d => !nodes.has(d.id) && !pool.auto.some(it => it.d.id === d.id)).sort((a, b) => byId(a.id, b.id));
  const later = [];
  for (const d of rest) {
    const c = G.conn(d);
    // automatic places lean upwards: the air is above the hull, the cables below it
    const ay = A.hull ? S : hull.y - 40;
    if (c.medium === 'wifi') pool.hull.push({ d, group: c.ap ? 'ap:' + c.ap : 'mesh', anchor: c.ap && nodes.get(c.ap) ? [nodes.get(c.ap).x, A.hull ? nodes.get(c.ap).y : ay] : [hull.x + hull.w / 2, ay] });
    else if (c.medium === 'lan') pool.hull.push({ d, group: 'lan', anchor: [hull.x + hull.w / 2, ay] });
    else if (c.medium === 'tunnel') pool.remote.push({ d, group: 'remote' });
    else if (c.medium === 'bluetooth' && c.to) later.push({ d, c });
    else pool.shelf.push({ d, group: 'shelf' });
  }
  // the air: rows above the hull, and below it too when no cables hang there (the first build's rows)
  const nAir = pool.hull.length;
  const belowFree = !!A.hull || ![...nodes.values()].some(n => n.y > hull.y + hull.h && n.y < hull.y + hull.h + 360 && n.x > hull.x - 60 && n.x < hull.x + hull.w + 60);
  const cols = A.hull ? 5 : Math.max(5, Math.floor(hull.w / PITCH), Math.ceil(Math.sqrt((nAir * 1.6) / (belowFree ? 2 : 1))));
  const hcx = hull.x + hull.w / 2;
  const hullSlot = i => {
    const col = i % cols, band = Math.floor(i / cols);
    const ring = belowFree ? Math.floor(band / 2) : band, below = belowFree && band % 2 === 1;
    return [hcx - (cols - 1) * PITCH / 2 - 45 + PITCH * col + STAGGER[ring % 4], below ? hull.y + hull.h + 76 + ROW * ring : hull.y - 100 - ROW * ring];
  };
  const leftX = spine.length && nodes.get(spine[0]) ? nodes.get(spine[0]).x : hull.x;
  const REMOTE = Array.isArray(A.remote) ? A.remote.filter(isPt) : null;
  const remoteSlot = i => (REMOTE && REMOTE[i] ? REMOTE[i] : REMOTE ? [REMOTE[0][0] + 115 * (i % 2), REMOTE[REMOTE.length - 1][1] - 110 * (Math.floor((i - REMOTE.length) / 2) + 1)]
    : [leftX - 170 - 120 * Math.floor(i / 5), S + [0, -ROW, ROW, -2 * ROW, 2 * ROW][i % 5]]);
  const saved = slots(), taken = new Map(), now = Date.now();
  let dirty = false;
  const assign = (name, posOf, items, roleFn, key) => {
    const used = taken.get(name) || new Set(); taken.set(name, used);
    const todo = [];
    for (const it of items) {
      const s = saved[it.d.id];
      if (s && s.p === name && s.g === it.group && (s.k || '') === key && !used.has(s.s) && free(...posOf(s.s))) { used.add(s.s); s.t = now; const [px, py] = posOf(s.s); place(it.d, px, py, roleFn(it.d), it.group); }
      else todo.push(it);
    }
    for (const it of todo) {
      let best = -1, bd = Infinity;
      for (let i = 0; i < 2000 && (best < 0 || i < (A.hull ? 60 : 60 + cols * 4)); i++) {
        if (used.has(i)) continue;
        const [px, py] = posOf(i);
        if (!free(px, py)) continue;
        const dd = it.anchor ? Math.hypot(px - it.anchor[0], (py - it.anchor[1]) * 1.25) : i;
        if (dd < bd) { bd = dd; best = i; }
        if (!it.anchor) break;
      }
      if (best < 0) best = 1999;
      used.add(best); saved[it.d.id] = { p: name, g: it.group, s: best, t: now, k: key || undefined }; dirty = true;
      const [px, py] = posOf(best); place(it.d, px, py, roleFn(it.d), it.group);
    }
  };
  assign('hull', hullSlot, pool.hull, () => 'end', A.hull ? '' : cols + (belowFree ? 'b' : 'a'));
  assign('remote', remoteSlot, pool.remote, () => 'end', '');
  // Bluetooth things whose host is in the air or at the side: beside the host
  const btAir = [];
  for (const { d, c } of later) {
    const host = nodes.get(c.to);
    let spot = null;
    if (host) for (const [dx, dy] of [[0, -110], [105, -110], [-105, -110], [105, 0], [-105, 0], [0, 110], [210, -110], [-210, -110], [0, -220]]) if (free(host.x + dx, host.y + dy)) { spot = [host.x + dx, host.y + dy]; break; }
    if (spot) place(d, spot[0], spot[1], 'peri', 'beside');
    else if (host && (String(host.group).startsWith('ap:') || ['mesh', 'lan', 'bt'].some(g => String(host.group).startsWith(g)))) btAir.push({ d, group: 'bt:' + c.to, anchor: [host.x, host.y] });
    else pool.auto.push({ d, group: 'auto' });
  }
  // the host is in a crowd of Wi-Fi devices: the nearest free place in that crowd
  assign('hull', hullSlot, btAir, () => 'peri', A.hull ? '' : cols + (belowFree ? 'b' : 'a'));
  // what is left goes under everything: first what could not be put beside its host, then the shelf
  let y1 = -Infinity, x0 = Infinity;
  for (const n of nodes.values()) { y1 = Math.max(y1, n.y); x0 = Math.min(x0, n.x); }
  if (!Number.isFinite(y1)) { y1 = S; x0 = 60; }
  const AUTO = Array.isArray(A.auto) ? A.auto.filter(isPt) : null;
  const SH = A.shelf && Array.isArray(A.shelf.x) && A.shelf.x.length && Number.isFinite(A.shelf.y) ? A.shelf : null;
  const wide = Math.max(4, Math.min(10, Math.ceil(Math.sqrt(Math.max(pool.shelf.length, pool.auto.length) * 2))));
  const autoSlot = i => (AUTO && AUTO[i] ? AUTO[i] : AUTO && SH ? [SH.x[i % SH.x.length], SH.y + num(SH.dy, 96) * (2 + Math.floor(i / SH.x.length))] : [x0 + 115 * (i % wide), y1 + 150 + ROW * Math.floor(i / wide)]);
  assign('auto', autoSlot, pool.auto, roleOf, AUTO ? '' : 'w' + wide);
  if (!SH) { for (const n of nodes.values()) y1 = Math.max(y1, n.y); }
  const shelfSlot = i => (SH ? [SH.x[i % SH.x.length], SH.y + num(SH.dy, 96) * Math.floor(i / SH.x.length)] : [x0 + 115 * (i % wide), y1 + 170 + 96 * Math.floor(i / wide)]);
  assign('shelf', shelfSlot, pool.shelf, () => 'shelf', SH ? '' : 'w' + wide);
  // forget places of things not seen for a week, so the table does not grow for ever
  for (const [id, s] of Object.entries(saved)) if (!nodes.has(id) && now - (s.t || 0) > 7 * 86400e3) { delete saved[id]; dirty = true; }
  if (dirty) setPref('slots', saved);

  // ------------------------------------------------------------ 4. links
  const gw = G.gateway(), root = G.meshRoot();
  const depth = new Map();
  if (gw) {
    depth.set(gw.id, 0);
    const q = [gw.id];
    while (q.length) {
      const cur = q.shift();
      for (const l of G.linksOf(cur)) {
        if (l.cable === 'bluetooth' || !G.carriesNet(l)) continue;
        const o = other(l, cur);
        if (!depth.has(o)) { depth.set(o, depth.get(cur) + 1); q.push(o); }
      }
    }
  }
  const links = [], docks = [];
  let bridges = 0;
  const xy = id => { const n = nodes.get(id); return n ? [n.x, n.y] : null; };
  const all = [...nodes.values()];
  // a line that would run through a device bends around it: the smallest bend that clears every tile
  const clear = (pts, skip) => {
    let bad = 0;
    const xs = pts.map(p => p[0]), ys = pts.map(p => p[1]);
    const bx0 = Math.min(...xs) - 40, bx1 = Math.max(...xs) + 40, by0 = Math.min(...ys) - 40, by1 = Math.max(...ys) + 40;
    for (const n of all) {
      if (skip.has(n.id) || n.x < bx0 || n.x > bx1 || n.y < by0 || n.y > by1) continue;
      const rr = n.r + 6;
      for (let i = 1; i < pts.length; i++) {
        const [ax, ay] = pts[i - 1], [cx2, cy2] = pts[i];
        const dx = cx2 - ax, dy = cy2 - ay, len2 = dx * dx + dy * dy || 1;
        const t = Math.max(0, Math.min(1, ((n.x - ax) * dx + (n.y - ay) * dy) / len2));
        if (Math.hypot(ax + t * dx - n.x, ay + t * dy - n.y) < rr) { bad++; break; }
      }
    }
    return bad;
  };
  const seg = (a, b, bend, avoid, radioArc) => {
    const A2 = nodes.get(a), B = nodes.get(b);
    const mk = k => curve(trim([A2.x, A2.y], [B.x, B.y], A2.r + 3), trim([B.x, B.y], [A2.x, A2.y], B.r + 3), k);
    if (!avoid) return mk(bend);
    const skip = new Set([a, b]);
    let best = null;
    const up = A2.x < B.x ? -1 : 1;   // a negative bend from left to right arcs upwards
    const order = radioArc ? [bend, up * 0.15, -up * 0.15, up * 0.25, -up * 0.25, up * 0.35, -up * 0.35, up * 0.5, -up * 0.5] : [bend, bend + 0.15, bend - 0.15, bend + 0.25, bend - 0.25, bend + 0.35, bend - 0.35, bend + 0.5, bend - 0.5];
    for (const k of order) {
      const pts = mk(k), bad = clear(pts, skip);
      if (!best || bad < best.bad) best = { pts, bad };
      if (!bad) break;
    }
    return best.pts;
  };
  for (const l of G.links()) {
    if (l.cable === 'wifi') continue;
    if (!nodes.has(l.a.dev) || !nodes.has(l.b.dev)) continue;
    const kind = l.cable === 'bluetooth' ? 'bt' : l.cable === 'mesh' ? 'mesh' : l.cable === 'coax' ? 'coax' : G.carriesNet(l) ? 'wired' : 'desk';
    const da = depth.get(l.a.dev), db = depth.get(l.b.dev);
    const dir = kind === 'bt' ? 1 : kind === 'desk' || da == null || db == null || da === db ? 0 : db < da ? 1 : -1;
    const tree = routes.get(l.id);
    // a tree's bus is drawn from the parent down; flip it when the link is recorded the other way round
    let pts = tree ? (parent.get(l.a.dev) && parent.get(l.a.dev).l.id === l.id ? [...tree].reverse() : tree) : null;
    if (!pts) {
      // two spine devices with others between them: a bridge just above the hull, under the Wi-Fi rows
      const A2 = nodes.get(l.a.dev), B2 = nodes.get(l.b.dev);
      const between = onSpine.has(l.a.dev) && onSpine.has(l.b.dev) && A2.y === B2.y && spine.some(id => id !== l.a.dev && id !== l.b.dev && nodes.has(id) && nodes.get(id).y === A2.y && (nodes.get(id).x - A2.x) * (nodes.get(id).x - B2.x) < 0);
      if (between && !(fixed.has(l.a.dev) && fixed.has(l.b.dev))) {
        const yb = Math.min(A2.y, hull.y) - 22 - 10 * (bridges++ % 3);
        pts = [[A2.x, A2.y - A2.r - 3], [A2.x, yb], [B2.x, yb], [B2.x, B2.y - B2.r - 3]];
      } else pts = seg(l.a.dev, l.b.dev, kind === 'bt' ? 0.16 : 0, !(fixed.has(l.a.dev) && fixed.has(l.b.dev)), kind === 'mesh');
    }
    links.push({ id: l.id, kind, a: l.a.dev, b: l.b.dev, pts, dir, trust: l.verified, link: l, paired: kind === 'bt' && l.state === 'paired', bus: !!tree });
  }
  let unknownAp = 0, wifiN = 0;
  for (const d of devs) {
    const n = nodes.get(d.id); if (!n) continue;
    const c = G.conn(d);
    const w = c.medium === 'wifi' ? c : G.AP_KINDS.has(d.kind) ? null : c.wifi;   // a mesh node's own radio link is the backhaul, already drawn
    if (w) {
      wifiN++;
      const id = (w.link && w.link.id) || 'w-' + d.id;
      const second = c.medium !== 'wifi';
      if (w.ap && nodes.has(w.ap)) links.push({ id, kind: 'wifi', a: d.id, b: w.ap, pts: seg(d.id, w.ap, second ? -0.22 : 0.1), dir: 1, trust: (w.link && w.link.verified) || 'live', link: w.link, second });
      else {
        unknownAp++;
        const dock = hullDock(hull, n.x, n.y);
        links.push({ id, kind: 'wifi', a: d.id, b: null, hull: true, pts: curve(trim([n.x, n.y], dock, n.r + 3), dock, second ? -0.2 : 0), dir: 1, trust: (w.link && w.link.verified) || 'plan', link: w.link, second });
        docks.push({ id, x: dock[0], y: dock[1], kind: 'wifi' });
      }
    } else if (c.medium === 'lan') {
      const dock = hullDock(hull, n.x, n.y);
      links.push({ id: 'u-' + d.id, kind: 'lan', a: d.id, b: null, hull: true, pts: [trim([n.x, n.y], dock, n.r + 3), dock], dir: 1, trust: 'live', synthetic: true });
      docks.push({ id: 'u-' + d.id, x: dock[0], y: dock[1], kind: 'lan' });
    } else if (c.medium === 'tunnel' && gw && nodes.has(gw.id)) {
      links.push({ id: 't-' + d.id, kind: 'tunnel', a: d.id, b: gw.id, pts: seg(d.id, gw.id, 0.12), dir: 1, trust: 'live', synthetic: true });
    }
  }

  // ------------------------------------------------------------ 5. the frame around it all
  const showHull = !hull.virtual || wifiN > 0 || docks.length > 0;
  let bx0 = showHull ? hull.x : Infinity, by0 = showHull ? hull.y : Infinity, bx1 = showHull ? hull.x + hull.w : -Infinity, by1 = showHull ? hull.y + hull.h + 24 : -Infinity;
  for (const n of nodes.values()) { bx0 = Math.min(bx0, n.x - n.lw / 2 - 4); bx1 = Math.max(bx1, n.x + n.lw / 2 + 4); by0 = Math.min(by0, n.y - n.r - 14); by1 = Math.max(by1, n.y + n.r + 46); }
  if (!Number.isFinite(bx0)) { bx0 = 0; by0 = 0; bx1 = 800; by1 = 600; }
  const shelf = [...nodes.values()].filter(n => n.group === 'shelf');
  if (shelf.length) by1 = Math.max(by1, Math.max(...shelf.map(n => n.y)) + 72);
  const inet = devs.find(d => d.kind === 'internet');
  const inetN = inet && nodes.get(inet.id);
  // the line between outside and the home: half way from the internet to the next thing on the spine
  let outside = null;
  if (inetN) {
    const nextId = spine[spine.indexOf(inet.id) + 1];
    let nx = nextId && nodes.get(nextId) ? nodes.get(nextId).x : inetN.x + 115;
    if (showHull && nx > hull.x && hull.x > inetN.x) nx = hull.x;   // the next thing stands in the hull: the line falls before it
    outside = { x: (inetN.x + nx) / 2, y: inetN.y };
  }
  const nAps = G.accessPoints().length;
  const rootDev = root || (aps[0] ? G.device(aps[0]) : null);
  const hullTitle = hull.virtual ? 'The home network: no router recorded' : nAps > 1 ? 'The mesh: Wi-Fi for the whole home' : 'Wi-Fi' + (rootDev ? ': ' + G.shortName(rootDev.id) : '');
  return { nodes, links, docks, hull: { ...hull, show: showHull, title: hullTitle }, spineY: S, outside, root: root ? xy(root.id) : null, gw: gw ? xy(gw.id) : null, unknownAp, wifiN,
    shelf: shelf.length ? { x: Math.min(...shelf.map(n => n.x)) - 56, y: Math.min(...shelf.map(n => n.y)) - 52, w: Math.max(...shelf.map(n => n.x)) - Math.min(...shelf.map(n => n.x)) + 112, h: Math.max(...shelf.map(n => n.y)) - Math.min(...shelf.map(n => n.y)) + 124 } : null,
    bounds: { x: bx0, y: by0, w: bx1 - bx0, h: by1 - by0 } };
}

/** Bounds of the part worth opening on when the whole map would be too small to read: the hull and its clients. */
export function coreBounds(model) {
  const H = model.hull;
  let y0 = H.y - 40, y1 = H.y + H.h + 40;
  for (const n of model.nodes.values()) if (['mesh', 'lan'].includes(n.group) || String(n.group).startsWith('ap:')) { y0 = Math.min(y0, n.y - 40); y1 = Math.max(y1, n.y + 70); }
  return { x: H.x - 30, y: y0, w: H.w + 60, h: y1 - y0 };
}
