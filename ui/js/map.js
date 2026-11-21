// The wiring schematic: SVG drawn in code from the inventory, the authored layout and the live document.
import { h, s, isPhone, reducedMotion } from './dom.js';
import { iconPath } from './icons.js';
import { get, set, select, clearSelection, go } from './store.js';
import * as G from './graph.js';
import { wiring, planGroups, nodeHeight, anchor } from './layout.js';
import { statusShape, showTip, hideTip, tipLater, DASH, liveAge } from './ui.js';
import { statusLabel, cableName, cableCls, relTime, kindLabel, plural, TRUST, LINK_STATUS } from './fmt.js';

const MONO_W = 6.62;   // advance of the 11px mono face, close enough for pill sizing
const mw = t => Math.ceil(String(t).length * MONO_W);

// ---------------------------------------------------------------- shared derivations

/** Devices that are not drawn as boxes, grouped by room (then the other zones, unplaced, remote, spares). */
export const wifiGroups = () => planGroups(wiring().NODES);

function endSpec(l, key) {
  const { NODES, LOOSE_ENDS } = wiring();
  const end = l[key];
  const n = NODES[end.dev];
  if (!n) return null;
  const sp = (end.port && n.ports[end.port]) || (LOOSE_ENDS[l.id] && LOOSE_ENDS[l.id][key]);
  return sp ? { n, sp } : null;
}

export function linkPoints(l) {
  const A = endSpec(l, 'a'), B = endSpec(l, 'b');
  if (!A || !B) return null;
  const p = anchor(A.n, A.sp), q = anchor(B.n, B.sp);
  let mid = wiring().ROUTES[l.id];
  if (!mid) {
    if (p.x === q.x || p.y === q.y) mid = [];
    else if (p.dx && q.dx) { const mx = Math.round((p.x + q.x) / 20) * 10; mid = [[mx, p.y], [mx, q.y]]; }
    else if (p.dy && q.dy) { const my = Math.round((p.y + q.y) / 20) * 10; mid = [[p.x, my], [q.x, my]]; }
    else mid = p.dx ? [[q.x, p.y]] : [[p.x, q.y]];
  }
  return [[p.x, p.y], ...mid, [q.x, q.y]];
}

function roundedPath(pts, r = 6) {
  let d = `M${pts[0][0]} ${pts[0][1]}`;
  for (let i = 1; i < pts.length - 1; i++) {
    const [x0, y0] = pts[i - 1], [x1, y1] = pts[i], [x2, y2] = pts[i + 1];
    const l1 = Math.hypot(x1 - x0, y1 - y0), l2 = Math.hypot(x2 - x1, y2 - y1);
    const rr = Math.min(r, l1 / 2, l2 / 2);
    const ax = x1 - ((x1 - x0) / l1) * rr, ay = y1 - ((y1 - y0) / l1) * rr;
    const bx = x1 + ((x2 - x1) / l2) * rr, by = y1 + ((y2 - y1) / l2) * rr;
    d += ` L${ax} ${ay} Q${x1} ${y1} ${bx} ${by}`;
  }
  const last = pts[pts.length - 1];
  return d + ` L${last[0]} ${last[1]}`;
}

function labelSpot(pts) {
  let best = null;
  for (let i = 0; i < pts.length - 1; i++) {
    const [x0, y0] = pts[i], [x1, y1] = pts[i + 1];
    const horiz = y0 === y1, len = Math.abs(horiz ? x1 - x0 : y1 - y0);
    const score = len + (horiz ? 10000 : 0);
    if (!best || score > best.score) best = { score, horiz, len, x: (x0 + x1) / 2, y: (y0 + y1) / 2 };
  }
  return best;
}

/** Does this cable's evidence say the port at this end is a guess? */
function portUncertain(l, key) {
  const end = l[key];
  if (!end.port) return true;
  const p = G.port(end.dev, end.port);
  if (p && /not confirmed/i.test(p.label)) return true;
  const ev = l.evidence || '';
  const d = G.device(end.dev);
  if (/port numbers? (is|are) from the plan/i.test(ev) && d && d.kind === 'switch') return true;
  if (/which (\w+ )?port (is used )?is not confirmed/i.test(ev)) {
    if (/rear/i.test(ev)) return p ? /rear/i.test(p.label) : false;
    if (/front/i.test(ev)) return p ? /front/i.test(p.label) : false;
    return key === 'a';
  }
  return false;
}

function shortModel(d) {
  const raw = (d.model || '').trim();
  if (!raw || /^(not identified|answers ping|reports the hostname)/i.test(raw)) return 'not identified';
  let m = raw.split(/ \(|,|;|:/)[0].trim();
  const name = d.name.toLowerCase();
  if (d.vendor && m.toLowerCase().startsWith(d.vendor.toLowerCase() + ' ')) m = m.slice(d.vendor.length + 1);
  if (m.toLowerCase().startsWith(name)) m = m.slice(name.length).trim();
  else if (name.includes(m.toLowerCase())) m = '';
  const vendorWord = (d.vendor || '').split(' ').pop().toLowerCase();
  const vendor = d.vendor && !name.includes(vendorWord) ? d.vendor : '';
  return [vendor, m].filter(Boolean).join(' ');
}

function subLine(d, w) {
  const budget = Math.floor((w - 24) / MONO_W);
  const ip = G.primaryIp(d);
  const m = shortModel(d);
  if (!ip) return m.length > budget ? m.slice(0, budget - 1) + '…' : m;
  if (m && m.length + ip.length + 3 <= budget) return m + ' · ' + ip;
  return ip;
}

function fitText(el, max) {
  let len = 0;
  try { len = el.getComputedTextLength(); } catch { return; }
  if (!len || len <= max) return;
  const full = el.textContent;
  let lo = 1, hi = full.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    el.textContent = full.slice(0, mid).trimEnd() + '…';
    if (el.getComputedTextLength() <= max) lo = mid; else hi = mid - 1;
  }
  el.textContent = full.slice(0, lo).trimEnd() + '…';
}

// ---------------------------------------------------------------- the map

export function createMap(host, { mini = false } = {}) {
  const world = s('g', { class: 'world' });
  const svg = s('svg', { class: 'map' + (mini ? ' mini' : ''), width: '100%', height: '100%', tabindex: mini ? -1 : 0,
    role: mini ? 'img' : 'application', 'aria-label': mini ? 'Map of the house wiring with the answer path highlighted' : 'Desk wiring map. Arrow keys move between devices, Home and End jump to the first and last, Enter opens the inspector, Tab leaves the map. The Devices view lists the same devices as a table.' }, world);
  const live = h('div', { class: 'sr-only', 'aria-live': 'polite' });
  host.append(svg, live);

  const t = { k: 1, x: 0, y: 0 };
  let userMoved = false, lastBounds = null, built = false, lastFit = false;
  const prevStatus = new Map();
  let targets = [];

  const size = () => ({ w: host.clientWidth, h: host.clientHeight });
  const pad = () => {
    const p = basePad();
    // On a tablet the inspector is a sheet over the canvas: keep the selection clear of it.
    if (!mini && !isPhone() && window.matchMedia('(max-width: 1023px)').matches && document.querySelector('.app').dataset.right === 'open') p.r += 360;
    return p;
  };
  const basePad = () => (mini ? { t: 8, r: 8, b: 8, l: 8 } : isPhone() ? { t: (api.padTop || 44) + 8, r: 8, b: 12, l: 8 } : { t: (api.padTop || 44) + 20, r: 20, b: 56, l: 20 });   // the bottom keeps clear of the zoom control

  function applyT() {
    world.setAttribute('transform', `translate(${t.x} ${t.y}) scale(${t.k})`);
    svg.dataset.detail = t.k < 0.6 ? 'low' : t.k >= 1.25 ? 'high' : 'mid';
    api.onZoom && api.onZoom(t.k);
  }
  function fit(b, { user = false } = {}) {
    const { w, h: hh } = size();
    lastBounds = b; userMoved = user;
    if (!w || !hh) return;
    const p = pad();
    const k = Math.max(mini ? 0.05 : 0.2, Math.min(3, Math.min((w - p.l - p.r) / b.w, (hh - p.t - p.b) / b.h)));
    t.k = k;
    t.x = p.l + (w - p.l - p.r - b.w * k) / 2 - b.x * k;
    t.y = p.t + (mini ? (hh - p.t - p.b - b.h * k) / 2 : Math.min(24, (hh - p.t - p.b - b.h * k) / 2)) - b.y * k;
    lastFit = true;
    applyT();
  }
  function zoomAt(k, cx, cy) {
    k = Math.max(Math.min(0.4, t.k), Math.min(3, k));
    const wx = (cx - t.x) / t.k, wy = (cy - t.y) / t.k;
    t.k = k; t.x = cx - wx * k; t.y = cy - wy * k; userMoved = true;
    applyT();
  }
  function ensureVisible(box) {
    const { w, h: hh } = size();
    if (!w) return;
    const p = pad();
    const x0 = box.x * t.k + t.x, y0 = box.y * t.k + t.y, x1 = x0 + box.w * t.k, y1 = y0 + box.h * t.k;
    let dx = 0, dy = 0;
    if (x0 < p.l) dx = p.l - x0; else if (x1 > w - p.r) dx = w - p.r - x1;
    if (y0 < p.t) dy = p.t - y0; else if (y1 > hh - p.b) dy = hh - p.b - y1;
    if (dx || dy) { t.x += dx; t.y += dy; userMoved = true; applyT(); }
  }

  // ------------------------------------------------------------ build

  function render() {
    const st = get();
    if (!st.inventory) { world.replaceChildren(); built = false; return; }
    const { ZONES, PLAN, NODES, LOOSE_ENDS, LABEL_AT } = wiring();
    const view = G.kvmView();
    const f = st.filters;
    const carriesOn = Object.keys(f.carries).filter(k => f.carries[k]);
    targets = [];

    const defs = s('defs', null,
      s('pattern', { id: mini ? 'hm-dots-m' : 'hm-dots', width: 10, height: 10, patternUnits: 'userSpaceOnUse' }, s('circle', { cx: 0.5, cy: 0.5, r: 0.6, class: 'grid-dot' })),
      s('pattern', { id: mini ? 'hm-lines-m' : 'hm-lines', width: 50, height: 50, patternUnits: 'userSpaceOnUse' }, s('path', { d: 'M50 0H0V50', class: 'grid-line' })));
    const bg = s('g', { class: 'bg' },
      s('rect', { x: -3000, y: -3000, width: 8000, height: 8000, fill: `url(#${mini ? 'hm-dots-m' : 'hm-dots'})` }),
      s('rect', { x: -3000, y: -3000, width: 8000, height: 8000, fill: `url(#${mini ? 'hm-lines-m' : 'hm-lines'})` }));

    // frames: the Home Office with its areas, and the room that is not known
    const zones = s('g', { class: 'zones' });
    for (const z of ZONES) {
      const zi = z.title ? {} : (G.zone(z.id) || {});
      const title = z.title || zi.name || z.id, note = z.note || zi.note;
      const g = s('g', { class: 'zone lv' + (z.level || 0), dataset: { zone: z.id } },
        s('rect', { x: z.x, y: z.y, width: z.w, height: z.h }),
        s('text', { x: z.x + 12, y: z.y + 19, class: 'zone-label' }, s('tspan', { class: 'zt' }, title), note ? s('tspan', null, '  ·  ' + note) : null));
      if (z.tip) g.appendChild(s('title', null, z.tip));
      zones.appendChild(g);
    }

    // links
    const linkLayer = s('g', { class: 'links' });
    // every cable's labels sit above every cable, so a crossing cable never runs through a label; each set is wrapped in
    // a group that carries its link's id and classes, so hover, dimming and clicks treat it as part of the link
    const badgeLayer = s('g', { class: 'link-badges' });
    const stubClass = new Map();   // "dev:port" → { cls, linkId }
    const visibleLinks = new Set();
    for (const l of G.links()) {
      const pts = linkPoints(l);
      if (!pts) continue;
      const cls = cableCls(l.cable);
      const lv = G.linkLive(l.id) || {};
      const isNet = (l.carries || []).includes('network') || l.cable === 'ethernet' || l.cable === 'mesh';
      let off = false;
      void isNet;
      if (!f.trust[l.verified]) off = true;
      if (carriesOn.length && !carriesOn.some(c => (l.carries || []).includes(c))) off = true;
      const problem = lv.status === 'down' || lv.status === 'unknown' || !!l.risk;
      const faded = f.problems && !problem;
      const inactive = !!l.kvmInput && view !== 'both' && l.kvmInput !== view;
      if (!off) visibleLinks.add(l.id);
      const d = roundedPath(pts);
      const g = s('g', { class: `link c-${cls} t-${l.verified}` + (off ? ' off' : '') + (faded ? ' faded' : '') + (inactive ? ' inactive' : '') + (lv.status === 'down' ? ' down' : ''),
        dataset: { id: l.id, kind: 'link' } });
      g.appendChild(s('path', { d, class: 'halo' }));
      if (l.cable === 'mesh') g.append(s('path', { d, class: 'cable mesh-a' }), s('path', { d, class: 'cable mesh-b' }));
      else g.appendChild(s('path', { d, class: 'cable', 'stroke-dasharray': l.verified === 'plan' ? '6 4' : l.verified === 'reported' ? '1 4' : null }));
      g.appendChild(s('path', { d, class: 'hit' }));

      // badges: marker, label, speed
      const spot = LABEL_AT[l.id] ? { ...labelSpot(pts), ...LABEL_AT[l.id] } : labelSpot(pts);
      const marker = lv.status === 'down' ? 'down' : l.risk ? 'risk' : lv.status === 'unknown' ? 'unknown' : null;
      const label = l.label || cableName(l.cable), custom = !!l.label;
      const room = spot.horiz ? spot.len - 20 : 400;
      const mwid = marker ? 20 : 0;
      const wl = mw(label) + 8, ws = l.speed ? mw(l.speed) + 8 : 0;
      let parts = [];
      const options = l.speed ? (custom ? [['l', 's'], ['l'], ['s'], []] : [['l', 's'], ['s'], ['l'], []]) : [['l'], []];
      for (const o of options) {
        const wsum = o.reduce((a, k) => a + (k === 'l' ? wl : ws) + 4, 0) + mwid;
        if (wsum <= room && (spot.horiz || spot.len >= 60)) { parts = o; break; }
      }
      const widths = [...(marker ? [16] : []), ...parts.map(k => (k === 'l' ? wl : ws))];
      const total = widths.reduce((x, y) => x + y, 0) + 4 * Math.max(0, widths.length - 1);
      if (parts.length || marker) {
        const bg2 = s('g', { class: 'badges', transform: `translate(${Math.round(spot.x - total / 2)} ${spot.y})` });
        let x = 0;
        if (marker) {
          const m = s('g', { class: 'marker ' + marker, transform: `translate(${x + 8} 0)` }, s('rect', { x: -8, y: -8, width: 16, height: 16, class: 'm-bg' }));
          if (marker === 'down') m.appendChild(s('path', { d: 'M-3.5 -3.5L3.5 3.5M3.5 -3.5L-3.5 3.5' }));
          else if (marker === 'risk') m.append(s('path', { d: 'M0 -5.5L6 5H-6z', class: 'tri' }), s('path', { d: 'M0 -1.6V1.6M0 3.3v.1' }));
          else m.appendChild(s('text', { y: 4, 'text-anchor': 'middle' }, '?'));
          bg2.appendChild(m); x += 20;
        }
        for (const k of parts) {
          const txt = k === 'l' ? label : l.speed, wdt = k === 'l' ? wl : ws;
          bg2.appendChild(s('g', { class: 'pill ' + (k === 'l' ? 'p-label' : 'p-speed'), transform: `translate(${x} 0)` },
            s('rect', { x: 0, y: -8, width: wdt, height: 16 }), s('text', { x: wdt / 2, y: 4, 'text-anchor': 'middle' }, txt)));
          x += wdt + 4;
        }
        badgeLayer.appendChild(s('g', { class: g.getAttribute('class'), dataset: { id: l.id, kind: 'link' } }, bg2));
      }
      linkLayer.appendChild(g);
      for (const key of ['a', 'b']) if (l[key].port) stubClass.set(l[key].dev + ':' + l[key].port, { cls, id: l.id, off, q: portUncertain(l, key) });
    }

    // The rooms: a card per room with the devices that are not boxes as rows, then the cards that are not rooms.
    const groups = PLAN ? wifiGroups() : [];
    const fixedRooms = groups.filter(g => g.room && PLAN.rooms && PLAN.rooms[g.id]);
    const wifiCount = G.devices().filter(d => G.isWifi(d)).length;
    const online = G.devices().filter(d => G.isWifi(d) && G.statusOf(d.id) === 'online').length;
    const aps = G.accessPoints();
    const wifi = s('g', { class: 'wifi' });
    if (groups.length) wifi.appendChild(s('g', { class: 'zone lv0', dataset: { zone: 'plan' } }, s('rect', { x: PLAN.x, y: PLAN.y, width: PLAN.w, height: st.wifiCollapsed ? 36 : PLAN.h })));
    if (groups.length) wifi.appendChild(s('text', { x: PLAN.x + 12, y: PLAN.y + 19, class: 'zone-label' },
      s('tspan', { class: 'zt' }, 'Rooms'),
      s('tspan', null, st.wifiCollapsed ? `  ·  ${plural(wifiCount, 'device')} on Wi-Fi · ${online} online` : `  ·  what has no cable, by room  ·  ${plural(wifiCount, 'device')} on Wi-Fi` + (aps.length > 1 ? ', through the mesh' : aps.length ? ' from ' + G.shortName(aps[0].id) : ''))));
    if (groups.length && PLAN.trunk && aps.filter(d => NODES[d.id]).length > 1) {
      // one mesh trunk from the backhaul line to the plan: never a line per device to a guessed node
      const T = PLAN.trunk;
      const lbl = 'Wi-Fi · node not known', wl = mw(lbl) + 8;
      wifi.appendChild(s('g', { class: 'link c-mesh trunk' }, s('path', { d: roundedPath([[T.fromX, T.y], [T.toX, T.y], [T.toX, PLAN.y]]), class: 'cable mesh-a' }), s('path', { d: roundedPath([[T.fromX, T.y], [T.toX, T.y], [T.toX, PLAN.y]]), class: 'cable mesh-b' }),
        s('rect', { x: T.fromX - 3.5, y: T.y - 3.5, width: 7, height: 7, class: 'junction' }),
        s('g', { class: 'pill p-label', transform: `translate(${Math.round((T.fromX + T.toX) / 2 - wl / 2)} ${T.y})` }, s('rect', { y: -8, width: wl, height: 16 }), s('text', { x: wl / 2, y: 4, 'text-anchor': 'middle' }, lbl)),
        s('title', null, (st.inventory.wireless && st.inventory.wireless.note) || 'Which mesh node each Wi-Fi device uses is not known.')));
    }
    const wifiPos = new Map();
    const subnet = ((st.inventory.site && st.inventory.site.subnet) || '').replace(/\.0\/24$/, '.');
    // a card is as tall as its rows, or as the plan draws it; rows that do not fit run on in a second column
    const drawCard = (g, cx, cy, cw, chFixed, isRoom, span = 1) => {
      const n = g.devices.length;
      let per = Math.max(1, Math.ceil(n / span));
      if (chFixed) per = Math.max(1, Math.floor((chFixed - PLAN.headH - 4) / PLAN.rowH));
      const cols = Math.max(1, Math.ceil(n / per));
      const ch = Math.max(chFixed || 0, PLAN.headH + Math.max(1, Math.min(n, per)) * PLAN.rowH + 6);
      const colW = (cw - 12 * (cols - 1)) / cols;
      const card = s('g', { class: 'card' + (isRoom ? ' room' : ''), transform: `translate(${cx} ${cy})` },
        s('rect', { class: 'card-body', width: cw, height: ch }),
        s('text', { x: 10, y: 18, class: 'card-title' }, g.title),
        s('text', { x: cw - 10, y: 18, class: 'card-count', 'text-anchor': 'end' }, n ? String(n) : ''));
      card.querySelector('.card-title')._fit = cw - 50;
      if (g.note) card.appendChild(s('title', null, g.note));
      if (!n) card.appendChild(s('text', { x: 10, y: PLAN.headH + 14, class: 'card-empty' }, 'no devices recorded here'));
      g.devices.forEach((d, j) => {
        const col = Math.floor(j / per), rx = col * (colW + 12);
        const y = PLAN.headH + (j % per) * PLAN.rowH - 2;
        const status = G.statusOf(d.id);
        const ip = G.primaryIp(d);
        const tail = !ip ? (g.id === 'spares' ? '' : 'no address') : subnet && ip.startsWith(subnet) ? '.' + ip.slice(subnet.length) : g.id === 'remote' ? 'tailscale' : ip;
        const fadedRow = (f.status && status !== f.status) || (f.problems && !['offline', 'degraded', 'unknown'].includes(status)) || !f.trust[d.verified];
        const row = s('g', { class: 'wrow' + (fadedRow ? ' faded' : '') + (status === 'offline' ? ' offline' : ''), dataset: { id: d.id, kind: 'wifi' }, transform: `translate(${rx} ${y})` },
          s('rect', { class: 'wrow-bg', x: 1, width: colW - 2, height: PLAN.rowH }),
          s('g', { transform: 'translate(9 6)', class: 'st' }, statusShape(status)),
          s('text', { x: 26, y: 15, class: 'wname' }, d.name),
          s('text', { x: colW - 9, y: 15, class: 'wip', 'text-anchor': 'end' }, tail));
        row.querySelector('.wname')._fit = colW - 26 - 16 - mw(tail);
        card.appendChild(row);
        wifiPos.set(d.id, { x: cx + rx, y: cy + y, w: colW, h: PLAN.rowH });
        targets.push({ id: d.id, cx: cx + rx + colW / 2, cy: cy + y + 11, box: { x: cx + rx, y: cy + y, w: colW, h: PLAN.rowH } });
      });
      if (isRoom && g.note && cols === 1 && ch - (PLAN.headH + n * PLAN.rowH) > 20) card.appendChild(s('text', { x: 10, y: ch - 9, class: 'card-empty' }, g.note));
      return card;
    };
    if (!st.wifiCollapsed && groups.length) {
      let extraN = 0;
      for (const g of groups) {
        if (PLAN.auto) { const c = PLAN.auto[g.id]; if (c) wifi.appendChild(drawCard(g, c.x, c.y, c.w, 0, !!g.room, c.span)); continue; }
        if (fixedRooms.includes(g)) { const r = PLAN.rooms[g.id]; wifi.appendChild(drawCard(g, PLAN.ox + r.x, PLAN.oy + r.y, r.w, r.h, true)); continue; }
        if (g.room && !g.devices.length) continue;
        const c = (PLAN.cards && PLAN.cards[g.id]) || { x: PLAN.extra.x + (extraN % 2) * (PLAN.extra.w + 20), y: PLAN.extra.y + Math.floor(extraN++ / 2) * 110, w: PLAN.extra.w };
        wifi.appendChild(drawCard(g, c.x, c.y, c.w, 0, false));
      }
    }

    // nodes
    const nodeLayer = s('g', { class: 'nodes' });
    const nodeTargets = [];
    for (const [id, n] of Object.entries(NODES)) {
      const d = G.device(id);
      if (!d) continue;
      const hh = nodeHeight(n);
      const status = G.statusOf(id);
      const myLinks = G.linksOf(id);
      const anyVisible = myLinks.some(l => visibleLinks.has(l.id));
      void anyVisible;
      const faded = (f.status && status !== f.status) || (f.problems && !['offline', 'degraded', 'unknown'].includes(status)) || !f.trust[d.verified];
      const g = s('g', { class: `node k-${d.kind} t-${d.verified} s-${status}` + (faded ? ' faded' : ''), dataset: { id, kind: 'node' }, transform: `translate(${n.x} ${n.y})` });
      g.appendChild(s('rect', { class: 'sel-ring', x: -4, y: -4, width: n.w + 8, height: hh + 8 }));
      g.appendChild(s('rect', { class: 'body', width: n.w, height: hh, 'stroke-dasharray': d.verified === 'plan' ? '4 3' : d.verified === 'reported' ? '1 3' : null }));
      const stg = s('g', { transform: 'translate(10 10)', class: 'st' }, statusShape(status));
      if (prevStatus.has(id) && prevStatus.get(id) !== status && !reducedMotion()) stg.appendChild(s('rect', { x: 0, y: 0, width: 10, height: 10, class: 'pulse' }));
      prevStatus.set(id, status);
      g.appendChild(stg);
      const name = s('text', { x: 28, y: 20, class: 'name' }, d.name);
      name._fit = n.w - 28 - 28;   // up to 4px short of the kind icon
      g.appendChild(name);
      g.appendChild(s('path', { d: iconPath(d.kind), class: 'kind', transform: `translate(${n.w - 24} 7)` }));
      g.appendChild(s('text', { x: 12, y: 39, class: 'sub' }, subLine(d, n.w)));
      if (n.rows) g.appendChild(s('path', { d: `M0 46.5H${n.w}`, class: 'divider' }));

      const drawPort = (pid, sp, loose) => {
        const meta = pid ? stubClass.get(id + ':' + pid) : loose;
        const lbl = pid ? G.portShort(id, pid) : 'port ?';
        const q = meta && meta.q ? ' ?' : '';
        const pg = s('g', { class: 'port' + (meta ? ' on c-' + meta.cls : '') + (meta && meta.off ? ' off' : ''), dataset: meta ? { link: meta.id } : {} });
        if (sp.bare) return;
        if (sp.side === 'l' || sp.side === 'r') {
          const cy = 60 + 20 * sp.row, left = sp.side === 'l';
          pg.appendChild(s('rect', { class: 'stub', x: left ? -4 : n.w - 4, y: cy - 5, width: 8, height: 10 }));
          pg.appendChild(s('text', { class: 'plabel', x: left ? 12 : n.w - 12, y: cy + 4, 'text-anchor': left ? 'start' : 'end' }, lbl + q));
        } else {
          const px = sp.x - n.x, top = sp.side === 't';
          pg.appendChild(s('rect', { class: 'stub', x: px - 5, y: top ? -4 : hh - 4, width: 10, height: 8 }));
          if (top) pg.appendChild(s('text', { class: 'plabel out', x: sp.end ? px - 9 : px + 9, y: -8, 'text-anchor': sp.end ? 'end' : 'start' }, lbl + q));
          else pg.appendChild(s('text', { class: 'plabel', x: px, y: 60 + 20 * (n.rows - 1) + 4, 'text-anchor': 'middle' }, lbl + q));
        }
        g.appendChild(pg);
      };
      for (const [pid, sp] of Object.entries(n.ports || {})) drawPort(pid, sp);
      for (const l of myLinks) {
        const le = LOOSE_ENDS[l.id];
        if (!le) continue;
        for (const key of ['a', 'b']) if (l[key].dev === id && !l[key].port && le[key]) drawPort(null, le[key], { cls: cableCls(l.cable), id: l.id, off: !visibleLinks.has(l.id), q: false });
      }
      // free ports collapse into a chip
      const used = new Set(myLinks.flatMap(l => [l.a, l.b]).filter(e => e.dev === id && e.port).map(e => e.port));
      const free = (d.ports || []).filter(p => !used.has(p.id) && !(n.line && n.line.port === p.id));
      if (free.length && n.free) {
        const cy = 60 + 20 * n.free.row;
        const x = n.free.side === 'l' ? 12 : n.free.side === 'r' ? n.w - 12 : n.w / 2;
        const chip = s('text', { class: 'free', x, y: cy + 4, 'text-anchor': n.free.side === 'l' ? 'start' : n.free.side === 'r' ? 'end' : 'middle' }, `+${free.length} free`);
        chip.appendChild(s('title', null, 'Free ports: ' + free.map(p => p.label).join(', ')));
        g.appendChild(chip);
      }
      for (const l of myLinks) if (l.cable === 'bluetooth' && l.a.dev === id) {   // radio, not a cable: a flag naming the host, never a line across the desk
        const my = hh / 2, txt = 'Bluetooth' + (l.state === 'paired' ? ', paired' : '') + ' · ' + G.shortName(l.b.dev);
        g.appendChild(s('g', { class: 'link c-bluetooth btflag t-' + l.verified, dataset: { id: l.id, kind: 'link' } }, s('path', { class: 'cable', d: `M0 ${my}H-26` }), s('rect', { class: 'dot', x: -32, y: my - 3, width: 6, height: 6 }), s('rect', { class: 'hitbox', x: -40 - mw(txt), y: my - 10, width: mw(txt) + 40, height: 20 }), s('text', { class: 'plabel', x: -38, y: my + 4, 'text-anchor': 'end' }, txt)));
      }
      if (d.kind === 'kvm' && G.kvmDevice() && G.kvmDevice().id === id) drawKvmInside(g, n, view, id, pid => G.portShort(id, pid) + ((stubClass.get(id + ':' + pid) || {}).q ? ' ?' : ''));
      if (n.line) {   // where the outside world comes in: a stub that leaves the frame, not a modelled cable
        const px = n.line.x - n.x;
        g.appendChild(s('g', { class: 'wan' }, s('path', { d: `M${px} ${hh}V${hh + 22}` }), s('rect', { class: 'stub', x: px - 5, y: hh - 4, width: 10, height: 8 }),
          s('text', { x: px + 9, y: hh + 20, class: 'plabel out' }, n.line.label)));
      }
      nodeLayer.appendChild(g);
      nodeTargets.push({ id, cx: n.x + n.w / 2, cy: n.y + hh / 2, box: { x: n.x, y: n.y, w: n.w, h: hh } });
    }
    targets = [...nodeTargets.sort((a, b) => zoneRank(a.id) - zoneRank(b.id) || a.box.x - b.box.x || a.box.y - b.box.y), ...targets];

    const overlay = s('g', { class: 'overlay' });
    world.replaceChildren(defs, bg, zones, wifi, linkLayer, badgeLayer, nodeLayer, overlay);
    api._wifiPos = wifiPos;
    for (const el of world.querySelectorAll('text')) if (el._fit) fitText(el, el._fit);
    svg.dataset.layer = st.layer;
    if (!built) { built = true; home(); if (!mini && lastFit && st.route.sel[0]) api.show(st.route.sel[0], true); }
    applyFocus();
  }

  function zoneRank(id) { const d = G.device(id); const i = G.groups().findIndex(g => g.id === (d && d.zone)); return i < 0 ? 99 : i; }

  /** Inside the KVM: each input joined to the outputs it feeds (same kind of signal), bright for the input in view. */
  function drawKvmInside(g, n, view, id, labelOf) {
    const ins = [], outs = [], used = new Set();
    for (const l of G.linksOf(id)) {
      if (l.cable === 'bluetooth') continue;
      const me = l.a.dev === id ? l.a : l.b;
      const sp = me.port ? n.ports[me.port] : null;
      if (!sp || (sp.side !== 'l' && sp.side !== 'r')) continue;
      used.add(sp.row);
      (l.kvmInput ? ins : outs).push({ pid: me.port, row: sp.row, side: sp.side, input: l.kvmInput, carries: l.carries || [] });
    }
    if (n.free && (n.free.side === 'l' || n.free.side === 'r')) used.add(n.free.row);
    if (!ins.length || !outs.length || ins.some(x => x.side !== 'l') || outs.some(x => x.side !== 'r')) return;
    // each line starts just after its own port label and ends just before the output's
    for (const x of ins) x.at = 12 + mw(labelOf(x.pid)) + 6;
    for (const x of outs) x.at = n.w - 12 - mw(labelOf(x.pid)) - 6;
    const lx = Math.max(...ins.map(x => x.at)), rx = Math.min(...outs.map(x => x.at));
    if (rx - lx < 12) return;
    const bus = Math.round((lx + rx) / 2 / 2) * 2;
    const y = row => 60 + 20 * row;
    const inner = s('g', { class: 'kvm-inside' });
    const draw = (from, active) => {
      for (const to of outs) {
        if (from.carries.length && to.carries.length && !from.carries.some(c => to.carries.includes(c))) continue;
        inner.appendChild(s('path', { class: active ? 'on' : '', d: `M${from.at} ${y(from.row)}H${bus}V${y(to.row)}H${to.at}` }));
      }
    };
    const on = x => view === 'both' || x.input === view;
    for (const x of ins) if (!on(x)) draw(x, false);
    for (const x of ins) if (on(x)) draw(x, true);
    // what the view shows, in words, in the longest run of empty rows
    let best = null;
    for (let r = 0, run = 0; r <= n.rows; r++) {
      if (r < n.rows && !used.has(r)) { run++; continue; }
      if (run >= 3 && (!best || run > best.len)) best = { start: r - run, len: run };
      run = 0;
    }
    if (best) {
      const belief = G.kvmBelief();
      const st = get();
      const y0 = 60 + 20 * best.start + (best.len >= 5 ? 20 : 4);
      const l1 = view === 'both' ? 'Showing both' : 'Showing ' + view.toUpperCase();
      const host = belief.input && G.kvmInputs()[belief.input] ? G.shortName(G.kvmInputs()[belief.input].dev) : 'this computer';
      const l2 = st.kvm && st.kvm !== belief.input ? 'your view,' : belief.basis === 'inferred' ? 'inferred: its hub' : belief.basis === 'live' ? 'live' : 'active input';
      const l3 = st.kvm && st.kvm !== belief.input ? 'not measured' : belief.basis === 'inferred' ? 'is on the ' + host : belief.basis === 'live' ? '' : 'not known';
      inner.append(s('text', { x: 12, y: y0, class: 'kvm-note strong' }, l1), s('text', { x: 12, y: y0 + 15, class: 'kvm-note' }, l2), s('text', { x: 12, y: y0 + 30, class: 'kvm-note' }, l3));
    }
    g.appendChild(inner);
  }

  // ------------------------------------------------------------ focus: hover, selection, trace, pinned path

  function focusSets() {
    const st = get();
    const sel = st.route.sel;
    const res = { mode: null, links: new Set(), devices: new Set(), suspect: new Set(), slow: new Set() };
    const hov = mini ? null : st.hover;
    if (hov && (G.isLinkId(hov) || (wiring().NODES[hov] && G.linksOf(hov).length))) {
      res.mode = 'hover';
      if (G.isLinkId(hov)) { const l = G.link(hov); res.links.add(hov); res.devices.add(l.a.dev); res.devices.add(l.b.dev); }
      else { res.devices.add(hov); for (const l of G.linksOf(hov)) { res.links.add(l.id); res.devices.add(l.a.dev); res.devices.add(l.b.dev); } }
    } else if (st.pin) {
      res.mode = 'strong';
      for (const id of st.pin.links || []) { const l = G.link(id); if (l) { res.links.add(id); res.devices.add(l.a.dev); res.devices.add(l.b.dev); } }
      for (const id of st.pin.devices || []) res.devices.add(id);
      for (const id of st.pin.suspect || []) res.suspect.add(id);
    } else if (!mini && sel.length) {
      let any = false;
      for (const id of sel) {
        if (!G.isLinkId(id) && !G.linksOf(id).length) { res.devices.add(id); continue; }
        const tr = G.trace(id);
        any = true;
        tr.links.forEach(x => res.links.add(x)); tr.devices.forEach(x => res.devices.add(x)); tr.slow.forEach(x => res.slow.add(x));
        if (G.isLinkId(id)) { const l = G.link(id); res.devices.add(l.a.dev); res.devices.add(l.b.dev); }
      }
      if (any) res.mode = st.route.trace ? 'strong' : 'sel';
    }
    return res;
  }

  function applyFocus() {
    if (!built) return;
    const st = get();
    const fs = focusSets();
    svg.dataset.dim = fs.mode || '';
    const sel = new Set(mini ? [] : st.route.sel);
    for (const el of world.querySelectorAll('[data-id]')) {
      const id = el.dataset.id, kind = el.dataset.kind;
      const inSet = kind === 'link' ? fs.links.has(id) : fs.devices.has(id);
      el.classList.toggle('dim', !!fs.mode && !inSet);
      el.classList.toggle('lit', !!fs.mode && inSet && kind === 'link');
      el.classList.toggle('sel', sel.has(id));
      el.classList.toggle('hov', st.hover === id);
      if (kind === 'link') { el.classList.toggle('suspect', fs.suspect.has(id)); el.classList.toggle('slow', fs.slow.has(id) && fs.mode !== 'hover'); }
    }
    for (const el of world.querySelectorAll('.port[data-link]')) el.classList.toggle('hl', st.hover === el.dataset.link || sel.has(el.dataset.link));
    for (const el of world.querySelectorAll('.zone, .trunk')) el.classList.toggle('dim', fs.mode === 'strong');
    // a selected Wi-Fi device lights the one mesh trunk: never a line to a guessed node
    const onWifi = !mini && st.route.sel.some(id => { const d = G.device(id); return d && G.isWifi(d); });
    for (const el of world.querySelectorAll('.trunk')) { el.classList.toggle('lit', onWifi); if (onWifi) el.classList.remove('dim'); }
  }

  function announce() {
    const st = get(); const id = st.route.sel[0];
    if (!id) { live.textContent = ''; return; }
    if (G.isLinkId(id)) { const l = G.link(id); live.textContent = `${cableName(l.cable)} cable, ${G.deviceName(l.a.dev)} to ${G.deviceName(l.b.dev)}, ${l.verified}`; return; }
    const d = G.device(id); if (!d) return;
    live.textContent = `${d.name}, ${statusLabel(G.statusOf(id))}, ${plural(G.linksOf(id).length, 'connection')}`;
  }

  // ------------------------------------------------------------ tooltips

  function line(text, cls) { return h('span', { class: 't-line' + (cls ? ' ' + cls : '') }, text); }
  function tooltipFor(id, kind) {
    if (kind === 'link') {
      const l = G.link(id); if (!l) return null;
      const lv = G.linkLive(id) || {};
      const view = G.kvmView();
      const box = h('div', null, h('span', { class: 't-title' }, `${G.deviceName(l.a.dev)} · ${G.portLabel(l.a.dev, l.a.port)} → ${G.deviceName(l.b.dev)} · ${G.portLabel(l.b.dev, l.b.port)}`),
        line([cableName(l.cable), l.speed, (l.carries || []).length ? 'carries ' + l.carries.join(', ') : null].filter(Boolean).join(' · ')),
        line(`${TRUST[l.verified] ? TRUST[l.verified].word : l.verified}: ${l.evidence || (TRUST[l.verified] || {}).meaning || ''}`));
      if (lv.status) box.appendChild(line('Link status: ' + (LINK_STATUS[lv.status] || lv.status) + (lv.detail ? ' · ' + lv.detail : '')));
      if (l.kvmInput && view !== 'both' && l.kvmInput !== view) box.appendChild(line('Inactive KVM input in this view'));
      if (l.risk) box.appendChild(line('Risk: ' + l.risk));
      return box;
    }
    const d = G.device(id); if (!d) return null;
    const lv = G.liveOf(id) || {};
    const status = G.statusOf(id);
    const seen = lv.lastSeen ? ' · seen ' + relTime(lv.lastSeen, get().now) : '';
    const box = h('div', null, h('span', { class: 't-title' }, d.name), line(statusLabel(status) + (status === 'unmonitored' ? ': no probe is possible' : seen)));
    const ip = G.primaryIp(d);
    if (ip) box.appendChild(line(ip));
    box.appendChild(line(kindLabel(d.kind) + ' · ' + d.verified + ': ' + (TRUST[d.verified] || {}).meaning));
    const kvm = G.kvmDevice();
    if (kvm && id === kvm.id) box.appendChild(line('The input toggle shows which computer the desk is connected to. It does not switch the KVM.'));
    else if (kvm && G.linksOf(kvm.id).some(l => !l.kvmInput && l.cable !== 'bluetooth' && G.peer(l, kvm.id).other.dev === id)) {
      const v = G.kvmView(), x = G.kvmInputs()[v];
      box.appendChild(line(v === 'both' || !x ? 'Reaches whichever computer the KVM is on' : 'In this view it reaches the ' + G.shortName(x.dev)));
    }
    return box;
  }

  // ------------------------------------------------------------ interaction

  const hit = e => { const el = e.target.closest && e.target.closest('[data-id]'); return el && world.contains(el) ? el : null; };

  if (!mini) {
    const pointers = new Map();
    let drag = null, pinch = null, suppressClick = false, space = false;
    svg.addEventListener('pointerdown', e => {
      if (e.button !== 0 && e.pointerType === 'mouse') return;
      pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      hideTip();
      if (pointers.size === 1) { drag = { id: e.pointerId, sx: e.clientX, sy: e.clientY, tx: t.x, ty: t.y, moved: false }; suppressClick = false; }
      else if (pointers.size === 2) {
        const [a, b] = [...pointers.values()];
        pinch = { d: Math.hypot(a.x - b.x, a.y - b.y), k: t.k }; drag = null; suppressClick = true;
      }
    });
    svg.addEventListener('pointermove', e => {
      if (!pointers.has(e.pointerId)) return;
      pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      const r = svg.getBoundingClientRect();
      if (pinch && pointers.size >= 2) {
        const [a, b] = [...pointers.values()];
        const dd = Math.hypot(a.x - b.x, a.y - b.y);
        zoomAt(pinch.k * dd / pinch.d, (a.x + b.x) / 2 - r.left, (a.y + b.y) / 2 - r.top);
        return;
      }
      if (!drag || drag.id !== e.pointerId) return;
      const dx = e.clientX - drag.sx, dy = e.clientY - drag.sy;
      if (!drag.moved && Math.hypot(dx, dy) > 4) { drag.moved = true; suppressClick = true; svg.classList.add('panning'); try { svg.setPointerCapture(e.pointerId); } catch { /* fine */ } }
      if (drag.moved) { t.x = drag.tx + dx; t.y = drag.ty + dy; userMoved = true; applyT(); }
    });
    const up = e => {
      pointers.delete(e.pointerId);
      if (pointers.size < 2) pinch = null;
      if (drag && drag.id === e.pointerId) { drag = null; svg.classList.remove('panning'); }
    };
    svg.addEventListener('pointerup', up); svg.addEventListener('pointercancel', up);
    svg.addEventListener('click', e => {
      if (suppressClick) { suppressClick = false; return; }
      const el = hit(e);
      if (!el) { if (get().route.sel.length && !get().route.trace) clearSelection(); return; }
      if (el.classList.contains('inactive') && el.dataset.kind === 'link') { /* still selectable: the cable exists */ }
      select(el.dataset.id, { add: e.shiftKey });
    });
    svg.addEventListener('wheel', e => {
      e.preventDefault();
      const r = svg.getBoundingClientRect();
      if (e.ctrlKey || e.metaKey) zoomAt(t.k * Math.exp(-e.deltaY * 0.01), e.clientX - r.left, e.clientY - r.top);
      else { t.x -= e.deltaX; t.y -= e.deltaY; userMoved = true; applyT(); }
    }, { passive: false });
    svg.addEventListener('gesturestart', e => e.preventDefault());
    svg.addEventListener('pointerover', e => {
      if (e.pointerType === 'touch' || drag && drag.moved) return;
      const el = hit(e);
      const id = el ? el.dataset.id : null;
      if (id !== get().hover) set({ hover: id });
      if (el) tipLater(() => tooltipFor(el.dataset.id, el.dataset.kind), e.clientX, e.clientY + 8);
      else hideTip();
    });
    svg.addEventListener('pointerleave', () => { if (get().hover) set({ hover: null }); hideTip(); });
    window.addEventListener('keydown', e => { if (e.code === 'Space' && document.activeElement === svg) { space = true; svg.classList.add('grab'); e.preventDefault(); } });
    window.addEventListener('keyup', e => { if (e.code === 'Space') { space = false; svg.classList.remove('grab'); } });
    void space;
  } else {
    svg.addEventListener('click', () => go({ view: 'map' }));
  }

  // Keep the viewport stable when a panel opens beside the map: refit only when nothing is selected.
  let lastW = 0;
  const ro = new ResizeObserver(() => {
    const { w } = size();
    const first = !lastW && w > 0;
    lastW = w;
    if (!built) return;
    if (first && !lastFit) { home(); if (!mini && get().route.sel[0]) api.show(get().route.sel[0], true); return; }
    if (userMoved || !lastBounds) return;
    if (!mini && get().route.sel.length) { if (get().route.sel[0]) api.show(get().route.sel[0], true); return; }
    home();
  });
  ro.observe(host);

  /** Everything on the wiring map. */
  function world_() { const W = wiring().WORLD; return { x: W.x || 0, y: W.y || 0, w: W.w, h: W.h }; }

  function home() {
    const st = get();
    const { HOME } = wiring();
    if (mini) return fit(world_());
    fit(HOME);
    // On a narrow canvas a full fit would drop below the zoom where labels are drawn: keep them readable and pan instead.
    if (t.k < 0.6) { const p = pad(); t.k = 0.6; t.x = p.l - HOME.x * 0.6; t.y = p.t - HOME.y * 0.6; applyT(); }
  }

  const api = {
    el: svg, render, applyFocus, announce,
    home, fit,
    fitAll: () => fit(world_(), { user: true }),
    reset: () => { const { w, h: hh } = size(); zoomAt(1, w / 2, hh / 2); },
    zoomBy: f => { const { w, h: hh } = size(); zoomAt(t.k * f, w / 2, hh / 2); },
    zoom: () => t.k,
    targets: () => targets,
    show(id, keepAuto) {
      const was = userMoved;
      const done = () => { if (keepAuto) userMoved = was; };
      const tg = targets.find(x => x.id === id);
      if (tg) { ensureVisible({ x: tg.box.x - 10, y: tg.box.y - 10, w: tg.box.w + 20, h: tg.box.h + 20 }); return done(); }
      const l = G.link(id); const pts = l && linkPoints(l);
      if (pts) { const xs = pts.map(p => p[0]), ys = pts.map(p => p[1]); ensureVisible({ x: Math.min(...xs) - 20, y: Math.min(...ys) - 20, w: Math.max(...xs) - Math.min(...xs) + 40, h: Math.max(...ys) - Math.min(...ys) + 40 }); }
      done();
    },
    showZone(zid) {
      const { ZONES } = wiring();
      const z = ZONES.find(x => x.id === zid) || ZONES.find(x => (x.zones || []).includes(zid));
      if (z && z.level !== 0) return fit({ x: z.x - 20, y: z.y - 20, w: z.w + 40, h: z.h + 40 }, { user: true });
      if (z && (z.zones || []).length <= 1) return fit({ x: z.x - 20, y: z.y - 20, w: z.w + 40, h: z.h + 40 }, { user: true });
      fit(world_(), { user: true });
    },
    destroy() { ro.disconnect(); svg.remove(); live.remove(); },
    onZoom: null,
  };
  return api;
}
