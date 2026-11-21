// Where everything sits on the wiring map.
//
// `wiring` in data/layout.json (served by /api/layout) pins what a person drew by hand: frames, boxes with their
// port stubs, cable waypoints, label spots and the room plan. Everything it leaves out is laid out here, from the
// inventory alone, and an authored entry always wins over an automatic one for the same id:
//
//   boxes    every device with a cable (anything but Wi-Fi and Bluetooth) to another device.
//   columns  signal flows left to right: towards the internet is upstream for cables that carry the network, a
//            computer is upstream of what it drives, then a dock, a KVM, a screen. Boxes are grouped in one frame
//            per zone (titled "Room › Zone"), the frames ordered by how close they are to the internet, and each
//            frame holds its boxes in columns by that flow.
//   ports    one stub per cable end, on the side that faces the cable's other end, ordered by where that end
//            is so cables cross as little as they can; unused ports collapse into a "+3 free" chip.
//   cables   orthogonal, through the channels between columns and frames, never through a box.
//   rooms    a grid of cards, one per room (then the devices whose room is not known, remote ones, spares), with
//            the devices that are not boxes as rows.
//
// The units are SVG pixels on a 10 px grid. A node is { x, y, w, rows, ports, free }: height 48 with no port
// rows, else 54 + 20 * rows. A port on the left or right sits on a row (centre y = y + 60 + 20 * row); one on
// the top or bottom sits at an absolute x.
import * as G from './graph.js';
import { get } from './store.js';

export const GRID = 10;
export function nodeHeight(n) { return n.rows ? 54 + 20 * n.rows : 48; }
export function rowY(n, row) { return n.y + 60 + 20 * row; }

/** Absolute position of a port stub's outer end, and the direction the cable leaves in. */
export function anchor(n, spec) {
  const h = nodeHeight(n);
  if (spec.side === 'l') return { x: n.x, y: rowY(n, spec.row), dx: -1, dy: 0 };
  if (spec.side === 'r') return { x: n.x + n.w, y: rowY(n, spec.row), dx: 1, dy: 0 };
  if (spec.side === 't') return { x: spec.x, y: n.y, dx: 0, dy: -1 };
  return { x: spec.x, y: n.y + h, dx: 0, dy: 1 };
}

let cache = { inv: undefined, lay: undefined, model: null };
/** The whole wiring layout for the inventory and layout.json as loaded: { WORLD, HOME, ZONES, NODES, PLAN, LOOSE_ENDS, ROUTES, LABEL_AT, auto }. */
export function wiring() {
  const st = get();
  if (cache.model && cache.inv === st.inventory && cache.lay === st.layout) return cache.model;
  cache = { inv: st.inventory, lay: st.layout, model: build() };
  return cache.model;
}
export function nodeBox(id) {
  const n = wiring().NODES[id];
  return n ? { x: n.x, y: n.y, w: n.w, h: nodeHeight(n) } : null;
}

// ---------------------------------------------------------------- helpers

const MONO = 6.62;                    // advance of the 11px mono face used by port labels
const CH = 120;                       // channel between two columns: room for the vertical runs of cables
const FRAME_GAP = 80, FRAME_PAD = 30, FRAME_TOP = 44, BOX_GAP = 34, WRAP = 2600;
const clone = v => (v == null ? v : JSON.parse(JSON.stringify(v)));
const obj = v => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const up10 = v => Math.ceil(v / 10) * 10;
const byId = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const other = (l, id) => G.peer(l, id).other.dev;
const isCable = l => l.cable !== 'wifi' && l.cable !== 'bluetooth';
const COMPUTERS = new Set(['computer', 'laptop', 'console', 'nas', 'server']);
const INFRA = new Set(['internet', 'modem', 'router', 'access-point', 'switch']);
const KIND_RANK = { internet: 0, modem: 1, router: 2, 'access-point': 3, switch: 4, nas: 5, computer: 5, laptop: 5, server: 5, console: 5, adapter: 6, hub: 6, dock: 6, kvm: 7 };
const kindRank = d => (d && d.kind in KIND_RANK ? KIND_RANK[d.kind] : 8);

function build() {
  const W = obj((get().layout || {}).wiring);
  const has = id => G.isDeviceId(id);
  // authored parts, minus ids the inventory does not have (bin/layout_check.py reports those)
  const NODES = {};
  for (const [id, n] of Object.entries(obj(W.nodes))) if (has(id) && n && Number.isFinite(n.x) && Number.isFinite(n.y)) NODES[id] = { w: 200, rows: 0, ports: {}, ...clone(n), ports: { ...obj(clone(n.ports)) } };
  const LOOSE_ENDS = {}, ROUTES = {}, LABEL_AT = {};
  for (const [id, v] of Object.entries(obj(W.looseEnds))) if (G.isLinkId(id)) LOOSE_ENDS[id] = clone(v);
  for (const [id, v] of Object.entries(obj(W.routes))) if (G.isLinkId(id) && Array.isArray(v)) ROUTES[id] = clone(v);
  for (const [id, v] of Object.entries(obj(W.labelAt))) if (G.isLinkId(id)) LABEL_AT[id] = clone(v);
  const ZONES = Array.isArray(W.zones) ? clone(W.zones).filter(z => z && Number.isFinite(z.x)) : [];
  const authored = new Set(Object.keys(NODES));
  const autoRoutes = new Set();

  // ------------------------------------------------------------ which devices are boxes
  const cables = G.links().filter(l => isCable(l) && has(l.a.dev) && has(l.b.dev) && l.a.dev !== l.b.dev);
  const boxIds = [...new Set(cables.flatMap(l => [l.a.dev, l.b.dev]))].sort(byId);
  const autoIds = boxIds.filter(id => !authored.has(id));

  // ------------------------------------------------------------ flow: which end of each cable is upstream
  const gw = G.gateway();
  const dist = new Map();
  if (gw) {
    dist.set(gw.id, 0); const q = [gw.id];
    while (q.length) { const cur = q.shift(); for (const l of G.linksOf(cur)) { if (!isCable(l) || !G.carriesNet(l)) continue; const o = other(l, cur); if (!dist.has(o)) { dist.set(o, dist.get(cur) + 1); q.push(o); } } }
  }
  const upstream = l => {
    const a = l.a.dev, b = l.b.dev, da = G.device(a), db = G.device(b);
    const infra = INFRA.has(da.kind) || INFRA.has(db.kind);
    // a computer drives what hangs off it (a dock, a screen), unless the other end is network gear
    if (!infra && COMPUTERS.has(da.kind) !== COMPUTERS.has(db.kind)) return COMPUTERS.has(da.kind) ? a : b;
    if (G.carriesNet(l) && dist.has(a) && dist.has(b) && dist.get(a) !== dist.get(b)) return dist.get(a) < dist.get(b) ? a : b;
    const ka = kindRank(da), kb = kindRank(db);
    if (ka !== kb) return ka < kb ? a : b;
    return a;   // as recorded: from → to
  };
  const preds = new Map(boxIds.map(id => [id, []]));
  for (const l of cables) { const u = upstream(l), v = u === l.a.dev ? l.b.dev : l.a.dev; preds.get(v).push(u); }
  // longest path from a source, ignoring the edge that would close a loop
  const rank = new Map(), onStack = new Set();
  const rankOf = id => {
    if (rank.has(id)) return rank.get(id);
    if (onStack.has(id)) return 0;
    onStack.add(id);
    let r = 0;
    for (const p of preds.get(id)) if (!onStack.has(p)) r = Math.max(r, rankOf(p) + 1);
    onStack.delete(id); rank.set(id, r);
    return r;
  };
  boxIds.forEach(rankOf);

  // ------------------------------------------------------------ frames: one per zone, in flow order
  const zoneKey = id => { const d = G.device(id); const z = d.zone && G.zone(d.zone) ? d.zone : 'unplaced'; return z; };
  const frames = new Map();
  for (const id of autoIds) { const k = zoneKey(id); if (!frames.has(k)) frames.set(k, { id: k, ids: [] }); frames.get(k).ids.push(id); }
  const groupOrder = G.groups().map(g => g.id);
  const fr = [...frames.values()];
  for (const f of fr) {
    f.near = Math.min(...f.ids.map(id => (dist.has(id) ? dist.get(id) : 99)));
    f.minRank = Math.min(...f.ids.map(id => rank.get(id)));
    const ranks = [...new Set(f.ids.map(id => rank.get(id)))].sort((a, b) => a - b);
    f.cols = ranks.map(r => f.ids.filter(id => rank.get(id) === r).sort(byId));
  }
  fr.sort((a, b) => a.near - b.near || a.minRank - b.minRank || groupOrder.indexOf(a.id) - groupOrder.indexOf(b.id) || byId(a.id, b.id));
  const frameIx = new Map(), colIx = new Map();
  fr.forEach((f, i) => f.cols.forEach((c, j) => c.forEach(id => { frameIx.set(id, i); colIx.set(id, j); })));

  // ------------------------------------------------------------ ports: which side each cable end takes
  const ends = new Map(boxIds.map(id => [id, []]));   // id → [{ l, key, peer, port, side }]
  const centreX = id => (NODES[id] ? NODES[id].x + NODES[id].w / 2 : null);
  const sideFor = (id, peer) => {
    if (!authored.has(id) && !authored.has(peer)) {
      const fa = frameIx.get(id), fb = frameIx.get(peer);
      if (fa !== fb) return fb > fa ? 'r' : 'l';
      const ca = colIx.get(id), cb = colIx.get(peer);
      return cb < ca ? 'l' : 'r';
    }
    return null;   // decided once places are known
  };
  for (const l of cables) for (const key of ['a', 'b']) {
    const end = l[key], id = end.dev, peer = l[key === 'a' ? 'b' : 'a'].dev;
    ends.get(id).push({ l, key, peer, port: end.port, side: sideFor(id, peer) });
  }

  // ------------------------------------------------------------ automatic boxes: size
  const portLabel = (id, pid) => (pid ? G.portShort(id, pid) : 'port ?');
  const free = id => { const d = G.device(id); const used = new Set(ends.get(id).filter(e => e.port).map(e => e.port)); return (d.ports || []).filter(p => !used.has(p.id)); };
  for (const id of autoIds) {
    const es = ends.get(id);
    const L = es.filter(e => e.side === 'l'), R = es.filter(e => e.side === 'r');
    const lw = Math.max(0, ...L.map(e => portLabel(id, e.port).length + 2)) * MONO, rw = Math.max(0, ...R.map(e => portLabel(id, e.port).length + 2)) * MONO;
    const nameW = String(G.device(id).name).length * 7.2 + 64;
    const w = Math.min(320, Math.max(200, up10(Math.max(lw + rw + 56, Math.min(nameW, 300)))));
    let rows = Math.max(L.length, R.length);
    const fr2 = free(id);
    let freeSpec = null;
    if (fr2.length) {
      if (L.length < rows) freeSpec = { side: 'l', row: L.length };
      else if (R.length < rows) freeSpec = { side: 'r', row: R.length };
      else { freeSpec = { side: L.length <= R.length ? 'l' : 'r', row: rows }; rows += 1; }
    }
    const kvm = G.device(id).kind === 'kvm' && es.some(e => e.l.kvmInput);
    if (kvm) rows += 3;   // room inside for what the input view shows
    NODES[id] = { x: 0, y: 0, w, rows, ports: {}, free: freeSpec || undefined, auto: true };
  }

  // ------------------------------------------------------------ automatic boxes: frames, columns, order
  const colW = f => f.cols.map(c => Math.max(...c.map(id => NODES[id].w)));
  // frames wrap into rows so the whole drawing keeps roughly the shape of a screen
  const sizes = fr.map(f => { const ws = colW(f); return { w: FRAME_PAD * 2 + ws.reduce((a, b) => a + b, 0) + CH * Math.max(0, ws.length - 1), h: FRAME_TOP + Math.max(...f.cols.map(c => c.reduce((a, id) => a + nodeHeight(NODES[id]) + BOX_GAP, -BOX_GAP))) + 26 }; });
  const area = sizes.reduce((a, z) => a + (z.w + FRAME_GAP) * (z.h + FRAME_GAP), 0);
  const wrapAt = Math.max(...sizes.map(z => z.w), 900, Math.min(WRAP, Math.sqrt(area * 3)));
  const placeFrames = () => {
    let x = 20, y = 20, bottom = 20;
    // with a pinned drawing, the automatic boxes stand to its right, clear of its frames, boxes and room plan
    if (authored.size || ZONES.length) {
      const P0 = obj(W.plan);
      const rights = [...Object.keys(NODES).filter(id => authored.has(id)).map(id => NODES[id].x + NODES[id].w), ...ZONES.map(z => z.x + z.w)];
      if (Number.isFinite(P0.x)) { rights.push(P0.x + (P0.w || 0)); for (const c of [...Object.values(obj(P0.cards)), obj(P0.extra)]) if (Number.isFinite(c.x)) rights.push(c.x + (c.w || 0) + (c === P0.extra ? (c.w || 0) + 20 : 0)); }
      if (W.world && Number.isFinite(W.world.w)) rights.push(W.world.w);
      x = up10(Math.max(0, ...rights) + 80); y = 20; bottom = y;
    }
    const x0 = x;
    for (const f of fr) {
      const ws = colW(f);
      const w = FRAME_PAD * 2 + ws.reduce((a, b) => a + b, 0) + CH * Math.max(0, ws.length - 1);
      const hs = f.cols.map(c => c.reduce((a, id) => a + nodeHeight(NODES[id]) + BOX_GAP, -BOX_GAP));
      const h = FRAME_TOP + Math.max(...hs) + 26;
      if (x > x0 && x + w > x0 + wrapAt) { x = x0; y = bottom + FRAME_GAP; }
      f.x = x; f.y = y; f.w = w; f.h = h; f.colX = [];
      let cx = x + FRAME_PAD;
      ws.forEach((cw, j) => { f.colX.push(cx); cx += cw + CH; });
      f.colW = ws;
      x += w + FRAME_GAP; bottom = Math.max(bottom, y + h);
    }
  };
  const stack = () => {
    for (const f of fr) f.cols.forEach((c, j) => {
      let y = f.y + FRAME_TOP;
      for (const id of c) { const n = NODES[id]; n.x = f.colX[j]; n.y = y; n.colL = f.colX[j]; n.colR = f.colX[j] + f.colW[j]; y += nodeHeight(n) + BOX_GAP; }
    });
  };
  placeFrames(); stack();
  // order each column by where its cables go (the mean height of the other ends), a few sweeps
  const cyOf = id => (NODES[id] ? NODES[id].y + nodeHeight(NODES[id]) / 2 : 0);
  for (let pass = 0; pass < 4; pass++) {
    for (const f of fr) for (const c of f.cols) {
      const bary = new Map(c.map((id, i) => { const ps = (ends.get(id) || []).map(e => e.peer); return [id, ps.length ? ps.reduce((a, p) => a + cyOf(p), 0) / ps.length : cyOf(id) + i * 0.01]; }));
      c.sort((a, b) => bary.get(a) - bary.get(b) || byId(a, b));
    }
    stack();
  }

  // ------------------------------------------------------------ ports: rows, in the order of their other ends
  for (const id of boxIds) {
    const n = NODES[id];
    for (const e of ends.get(id)) if (!e.side) {
      const px = centreX(e.peer), mx = n.x + n.w / 2;
      e.side = px == null || Math.abs(px - mx) < 1 ? 'r' : px > mx ? 'r' : 'l';
    }
  }
  const peerY = e => cyOf(e.peer);
  for (const id of autoIds) {
    const n = NODES[id];
    for (const side of ['l', 'r']) {
      const es = ends.get(id).filter(e => e.side === side).sort((a, b) => peerY(a) - peerY(b) || byId(a.l.id, b.l.id));
      es.forEach((e, row) => addEnd(id, e, { side, row }));
    }
  }
  // an authored box missing a stub for one of its cables gets one, on the side facing the other end
  for (const id of authored) {
    const n = NODES[id];
    for (const e of ends.get(id) || []) {
      const spec = (e.port && n.ports[e.port]) || (LOOSE_ENDS[e.l.id] && LOOSE_ENDS[e.l.id][e.key]);
      if (spec) continue;
      const used = new Set(Object.values(n.ports).filter(p => p.side === e.side).map(p => p.row));
      for (const [lid, le] of Object.entries(LOOSE_ENDS)) { const L2 = G.link(lid); for (const k of ['a', 'b']) if (le[k] && L2 && L2[k].dev === id && le[k].side === e.side) used.add(le[k].row); }
      if (n.free && n.free.side === e.side) used.add(n.free.row);
      let row = 0; while (used.has(row)) row++;
      if (row >= n.rows) n.rows = row + 1;
      addEnd(id, e, { side: e.side, row });
    }
  }
  function addEnd(id, e, spec) {
    const n = NODES[id];
    if (e.port && !n.ports[e.port]) n.ports[e.port] = spec;
    else if (!e.port) {
      const d = G.device(id);
      const bare = !(d.ports || []).length || e.l.cable === 'mesh';
      LOOSE_ENDS[e.l.id] = { ...(LOOSE_ENDS[e.l.id] || {}), [e.key]: { ...spec, ...(bare ? { bare: true } : { unknown: true }) } };
    }
    if (!authored.has(id) || !authored.has(e.peer)) autoRoutes.add(e.l.id);
  }

  // ------------------------------------------------------------ cables: orthogonal, around the boxes
  const boxes = boxIds.map(id => ({ id, x: NODES[id].x, y: NODES[id].y, w: NODES[id].w, h: nodeHeight(NODES[id]) }));
  // the cards of a pinned room plan are in the way too
  const P1 = obj(W.plan);
  if (Number.isFinite(P1.x)) {
    const ox = Number.isFinite(P1.ox) ? P1.ox : P1.x + 20, oy = Number.isFinite(P1.oy) ? P1.oy : P1.y + 36, rowH = P1.rowH || 22, headH = P1.headH || 28;
    for (const g of planGroups(NODES)) {
      const r = obj(P1.rooms)[g.id], c = obj(P1.cards)[g.id];
      if (g.room && r && Number.isFinite(r.x)) boxes.push({ id: 'card:' + g.id, x: ox + r.x, y: oy + r.y, w: r.w, h: r.h });
      else if (c && Number.isFinite(c.x)) boxes.push({ id: 'card:' + g.id, x: c.x, y: c.y, w: c.w, h: headH + Math.max(1, g.devices.length) * rowH + 6 });
    }
  }
  // parallel vertical runs in one channel take lanes 10 apart, centred on the channel; cables are routed from the
  // lowest stub up, so in a fan of cables going down the top stub takes the outermost lane and none cross
  const lanes = new Map(), laneN = new Map();
  const lane = key => { const k = lanes.get(key) || 0; lanes.set(key, k + 1); const n = laneN.get(key) || 1; return Math.round((k - (n - 1) / 2) * Math.min(10, 100 / n)); };
  const hits = (pts, skipA, skipB) => {
    for (let i = 1; i < pts.length; i++) {
      const [x0, y0] = pts[i - 1], [x1, y1] = pts[i];
      const lx = Math.min(x0, x1), hx = Math.max(x0, x1), ly = Math.min(y0, y1), hy = Math.max(y0, y1);
      for (const b of boxes) {
        if ((i === 1 && b.id === skipA) || (i === pts.length - 1 && b.id === skipB)) continue;
        if (hx > b.x - 8 && lx < b.x + b.w + 8 && hy > b.y - 8 && ly < b.y + b.h + 8) return true;
      }
    }
    return false;
  };
  const specOf = (l, key) => { const end = l[key], n = NODES[end.dev]; return (end.port && n.ports[end.port]) || (LOOSE_ENDS[l.id] && LOOSE_ENDS[l.id][key]) || null; };
  const exitX = (id, a) => { const n = NODES[id]; const edge = a.dx > 0 ? (n.colR != null ? n.colR : n.x + n.w) : (n.colL != null ? n.colL : n.x); return edge + a.dx * (n.colR != null ? CH / 2 : 30); };
  // a cable that would run on top of another cable, or along a frame's edge, costs more than a detour
  const drawn = [];
  const edges = [];
  const overlap = pts => {
    let c = 0;
    for (let i = 1; i < pts.length; i++) {
      const [a0, a1] = [pts[i - 1], pts[i]];
      const horiz = a0[1] === a1[1];
      const lo = Math.min(horiz ? a0[0] : a0[1], horiz ? a1[0] : a1[1]), hi = Math.max(horiz ? a0[0] : a0[1], horiz ? a1[0] : a1[1]);
      if (hi - lo < 2) continue;
      for (const [b0, b1, gap] of [...drawn, ...edges]) {
        const bh = b0[1] === b1[1];
        if (bh !== horiz) continue;
        if (Math.abs((horiz ? a0[1] : a0[0]) - (horiz ? b0[1] : b0[0])) > (gap || 6)) continue;
        const blo = Math.min(bh ? b0[0] : b0[1], bh ? b1[0] : b1[1]), bhi = Math.max(bh ? b0[0] : b0[1], bh ? b1[0] : b1[1]);
        if (Math.min(hi, bhi) - Math.max(lo, blo) > 4) { c += 400; break; }
      }
    }
    // nor through a frame's title band
    for (let i = 1; i < pts.length; i++) {
      const [a0, a1] = [pts[i - 1], pts[i]];
      if (a0[1] !== a1[1]) continue;
      const lo = Math.min(a0[0], a1[0]), hi = Math.max(a0[0], a1[0]);
      for (const z of [...fr, ...ZONES]) if (a0[1] > z.y - 6 && a0[1] < z.y + 30 && Math.min(hi, z.x + z.w) - Math.max(lo, z.x) > 4) { c += 400; break; }
    }
    return c;
  };
  for (const f of [...fr, ...ZONES]) edges.push([[f.x, f.y], [f.x + f.w, f.y], 12], [[f.x, f.y + f.h], [f.x + f.w, f.y + f.h], 12], [[f.x, f.y], [f.x, f.y + f.h], 12], [[f.x + f.w, f.y], [f.x + f.w, f.y + f.h], 12]);
  const len = pts => pts.reduce((s, p, i) => (i ? s + Math.abs(p[0] - pts[i - 1][0]) + Math.abs(p[1] - pts[i - 1][1]) : 0), 0);
  const todo = [];
  for (const l of cables) {
    if (!autoRoutes.has(l.id) || ROUTES[l.id]) continue;
    const sa = specOf(l, 'a'), sb = specOf(l, 'b');
    if (!sa || !sb) continue;
    const A = l.a.dev, B = l.b.dev;
    const p = anchor(NODES[A], sa), q = anchor(NODES[B], sb);
    if (!p.dx || !q.dx) continue;   // a top or bottom stub on an authored box: the default route
    const kp = 'x' + Math.round(exitX(A, p)), kq = 'x' + Math.round(exitX(B, q));
    laneN.set(kp, (laneN.get(kp) || 0) + 1); if (kq !== kp) laneN.set(kq, (laneN.get(kq) || 0) + 1);
    todo.push({ l, A, B, p, q, kp, kq });
  }
  todo.sort((u, v) => v.p.y - u.p.y || v.q.y - u.q.y || byId(u.l.id, v.l.id));
  for (const { l, A, B, p, q, kp, kq } of todo) {
    const lp = lane(kp), ex = exitX(A, p) + lp, ix = kq === kp ? ex : exitX(B, q) + lane(kq);
    const cands = [];
    if (p.y === q.y && p.dx === -q.dx && (q.x - p.x) * p.dx > 0) cands.push([]);
    cands.push([[ex, p.y], [ex, q.y]], [[ix, p.y], [ix, q.y]]);
    const ys = new Set([p.y, q.y, Math.round((p.y + q.y) / 20) * 10]);
    const lo = Math.min(ex, ix), hi = Math.max(ex, ix);
    for (const b of boxes) if (b.x + b.w > lo - 10 && b.x < hi + 10) { ys.add(b.y - 17); ys.add(b.y + b.h + 17); }
    for (const f of [...fr, ...ZONES]) { ys.add(f.y - 40); ys.add(f.y + f.h + 20); ys.add(f.y + f.h + 40); ys.add(f.y + 26); }
    for (const y of [...ys]) { ys.add(y + 10); ys.add(y - 10); }
    // where the vertical runs may go: the channel, or past the nearest boxes on the way out (a few, nearest first)
    const outX = (a, base) => [base, ...boxes.map(b => (a.dx > 0 ? b.x + b.w + 17 : b.x - 17)).filter(x => (x - a.x) * a.dx > 8 && Math.abs(x - base) > 4)
      .sort((u, v) => Math.abs(u - a.x) - Math.abs(v - a.x)).slice(0, 4)];
    const X1 = outX(p, ex), X2 = outX(q, ix);
    for (const y of ys) for (const x1 of X1) for (const x2 of X2) cands.push([[x1, p.y], [x1, y], [x2, y], [x2, q.y]]);
    let best = null, least = null;
    for (const mid of cands) {
      const pts = [[p.x, p.y], ...mid, [q.x, q.y]];
      let cost = len(pts) + mid.length * 30;
      // the cable leaves each stub outwards, never back across its own box
      if ((pts[1][0] - p.x) * p.dx < 0 || (pts[pts.length - 2][0] - q.x) * q.dx < 0) continue;
      if (best && cost >= best.cost) continue;
      if (hits(pts, A, B)) { if (!best && (!least || cost < least.cost)) least = { mid, cost, pts }; continue; }
      cost += overlap(pts);
      if (best && cost >= best.cost) continue;
      best = { mid, cost, pts };
    }
    best = best || least;   // nothing is clear (a pinned drawing boxed it in): the shortest, rather than none
    if (best) {
      ROUTES[l.id] = best.mid.filter((pt, i, arr) => !(i && pt[0] === arr[i - 1][0] && pt[1] === arr[i - 1][1]));
      for (let i = 1; i < best.pts.length; i++) drawn.push([best.pts[i - 1], best.pts[i]]);
    }
  }

  // ------------------------------------------------------------ frames for the automatic boxes
  for (const f of fr) {
    ZONES.push({ id: f.id, x: f.x, y: f.y, w: f.w, h: f.h, title: G.groupLabel(f.id), level: 0, zones: [f.id], auto: true });
  }

  // ------------------------------------------------------------ the room plan
  let PLAN = null;
  const P = obj(W.plan);
  const boxBottom = Math.max(0, ...Object.values(NODES).map(n => n.y + nodeHeight(n)), ...ZONES.map(z => z.y + z.h));
  const boxRight = Math.max(0, ...Object.values(NODES).map(n => n.x + n.w), ...ZONES.map(z => z.x + z.w));
  if (Number.isFinite(P.x) && Number.isFinite(P.y)) {
    PLAN = { rowH: 22, headH: 28, rooms: {}, cards: {}, extra: { x: P.x, y: P.y + (P.h || 0) + 20, w: 310 }, ...clone(P) };
    PLAN.ox = Number.isFinite(PLAN.ox) ? PLAN.ox : PLAN.x + 20; PLAN.oy = Number.isFinite(PLAN.oy) ? PLAN.oy : PLAN.y + 36;
  } else {
    // a grid of cards under the boxes: rooms first, in the home's order, then what has no room
    const groups = planGroups(NODES);
    const cardW = 300, gap = 20, rowH = 22, headH = 28, perCol = 14;
    const width = Math.max(cardW * 3 + gap * 2, Math.min(boxRight - 20, 6 * (cardW + gap)));
    const cols = Math.max(3, Math.floor((width + gap) / (cardW + gap)));
    const x0 = 40, y0 = up10(boxBottom + (boxIds.length ? 100 : 60)) + 36;
    const cards = {};
    let cx = 0, cy = 0, lineH = 0;
    for (const g of groups) {
      if (g.room && !g.devices.length && groups.length > 8) continue;
      const span = Math.min(cols, Math.max(1, Math.ceil(g.devices.length / perCol)));
      const per = Math.max(1, Math.ceil(g.devices.length / span));
      const w = span * cardW + (span - 1) * gap, h = headH + Math.max(1, per) * rowH + 6;
      if (cx + span > cols) { cx = 0; cy += lineH + gap; lineH = 0; }
      cards[g.id] = { x: x0 + cx * (cardW + gap), y: y0 + cy, w, h, span };
      cx += span; lineH = Math.max(lineH, h);
    }
    const ch = cy + lineH;
    PLAN = { x: 20, y: y0 - 36, w: cols * (cardW + gap) + 20, h: ch + 56, ox: x0, oy: y0, rowH, headH, rooms: {}, cards: {}, auto: cards };
  }

  // ------------------------------------------------------------ bounds
  const xs = [], ys2 = [];
  const add = (x, y, w, h) => { xs.push(x, x + w); ys2.push(y, y + h); };
  for (const n of Object.values(NODES)) add(n.x - 40, n.y - 30, n.w + 80, nodeHeight(n) + 60);
  for (const z of ZONES) add(z.x, z.y, z.w, z.h);
  const boxesBounds = xs.length ? { x: Math.min(...xs) - 20, y: Math.min(...ys2) - 20, w: Math.max(...xs) - Math.min(...xs) + 40, h: Math.max(...ys2) - Math.min(...ys2) + 40 } : null;
  if (PLAN) {
    add(PLAN.x, PLAN.y, PLAN.w, PLAN.h);
    for (const c of Object.values(PLAN.auto || {})) add(c.x, c.y, c.w, c.h);
  }
  const all = xs.length ? { x: Math.min(0, Math.min(...xs) - 20), y: Math.min(0, Math.min(...ys2) - 20), w: 0, h: 0 } : { x: 0, y: 0, w: 1000, h: 700 };
  if (xs.length) { all.w = Math.max(...xs) + 20 - all.x; all.h = Math.max(...ys2) + 20 - all.y; }
  // a pinned world, grown to take in what the automatic layout put beyond it
  const WORLD = W.world && Number.isFinite(W.world.w) ? { w: W.world.w, h: W.world.h } : { x: all.x, y: all.y, w: all.w, h: all.h };
  if (W.world && Number.isFinite(W.world.w) && autoIds.length) { WORLD.w = Math.max(WORLD.w, all.x + all.w); WORLD.h = Math.max(WORLD.h, all.y + all.h); }
  const HOME = W.home && Number.isFinite(W.home.w) ? clone(W.home) : boxesBounds || { x: all.x, y: all.y, w: all.w, h: all.h };
  return { WORLD, HOME, ZONES, NODES, PLAN, LOOSE_ENDS, ROUTES, LABEL_AT, auto: autoIds.length > 0, boxes: boxIds.length };
}

/**
 * Devices that are not drawn as boxes, grouped by room (then the other zones, unplaced, remote, spares).
 * Every device lands somewhere, with or without an address.
 */
export function planGroups(NODES) {
  const groups = new Map();
  for (const d of G.devices()) {
    if (NODES[d.id] || d.kind === 'internet') continue;
    const key = d.zone === 'spares' ? 'spares' : G.isRemote(d) ? 'remote' : G.roomOf(d) || (d.zone && G.zone(d.zone) ? d.zone : 'unplaced');
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(d);
  }
  const out = [];
  for (const r of G.rooms()) out.push({ id: r.id, title: r.name, room: true, devices: groups.get(r.id) || [] });
  for (const [k, v] of groups) if (!['remote', 'spares', 'unplaced'].includes(k) && !G.room(k)) out.push({ id: k, title: (G.zone(k) || { name: k }).name, devices: v });
  if (groups.has('unplaced')) out.push({ id: 'unplaced', title: 'Room not known', note: 'On the network, room not known', devices: groups.get('unplaced') });
  if (groups.has('remote')) out.push({ id: 'remote', title: 'Remote', note: 'Seen over Tailscale, not on the LAN', devices: groups.get('remote') });
  if (groups.has('spares')) out.push({ id: 'spares', title: 'Spares', note: 'Owned, not wired in', devices: groups.get('spares') });
  for (const g of out) g.devices.sort((a, b) => a.name.localeCompare(b.name));
  return out;
}
