// The network map: every device as a node with its path to the internet, drawn in SVG, with a canvas
// layer on top for what moves along the links. Nodes and links are kept between renders (keyed by id),
// so a status change, a device moving to another access point or a new host animates instead of blinking.
import { h, s, isPhone, reducedMotion } from './dom.js';
import { iconPath } from './icons.js';
import { get, set, select, clearSelection } from './store.js';
import * as G from './graph.js';
import { layout, coreBounds } from './netlayout.js';
import { hideTip, tipLater } from './ui.js';
import { statusLabel, kindLabel, cableName, relTime, TRUST, rate, plural } from './fmt.js';

const pathD = pts => 'M' + pts.map(p => p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join('L');
const hash = str => { let x = 2166136261; for (const c of String(str)) x = Math.imul(x ^ c.charCodeAt(0), 16777619); return (x >>> 0) / 4294967295; };

function measure(pts) {
  const cum = [0];
  for (let i = 1; i < pts.length; i++) cum.push(cum[i - 1] + Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]));
  return cum;
}
function pointAt(pts, cum, dist) {
  let i = 1;
  while (i < cum.length - 1 && cum[i] < dist) i++;
  const seg = cum[i] - cum[i - 1] || 1, t = (dist - cum[i - 1]) / seg;
  const a = pts[i - 1], b = pts[i];
  return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, Math.atan2(b[1] - a[1], b[0] - a[0])];
}

/** A name in balanced lines: one when it fits, else two, and a third only so the name is not cut. Breaks fall
 *  after a space, a hyphen or an underscore; an ellipsis is the last resort (one word wider than the label, or more than 3 lines). */
function fitName(el, max, sub) {
  const full = el._full || '';
  const probe = t => { el.textContent = t; try { return el.getComputedTextLength(); } catch { return 0; } };
  const words = full.split(/(?<=[ \-_])/);
  // SVG drops a trailing space when measuring, so words are measured bare and the gap is added between them
  const widths = words.map(w => probe(w.trimEnd())), space = probe('a a') - probe('aa');
  const wrap = w => {
    const out = []; let cur = [], cw = 0;
    words.forEach((word, i) => {
      const gap = cur.length && words[i - 1].endsWith(' ') ? space : 0;
      if (cur.length && cw + gap + widths[i] > w) { out.push(cur); cur = []; cw = 0; }
      else cw += gap;
      cur.push(word); cw += widths[i];
    });
    if (cur.length) out.push(cur);
    return out;
  };
  let lines = wrap(max);
  if (lines.length > 1 && lines.length <= 3) {
    // balance: the narrowest width that still gives the same number of lines
    let lo = Math.max(...widths) - 1, hi = max;
    while (hi - lo > 1) { const mid = (lo + hi) / 2; if (wrap(mid).length <= lines.length) hi = mid; else lo = mid; }
    lines = wrap(hi);
  }
  if (lines.length === 1 || lines.length > 3) {
    if (lines.length > 3) lines = [lines[0], lines[1], lines.slice(2).flat()];
    else { fitText(el, max); sub.setAttribute('y', 15); return; }
  }
  const spans = lines.map((ws, i) => { const t = s('tspan', { x: 0, dy: i ? 14 : 0 }, ws.join('').trimEnd()); t._full = t.textContent; return t; });
  el.replaceChildren(...spans);
  spans.forEach(t => fitText(t, max));
  sub.setAttribute('y', 15 + 14 * (lines.length - 1));
}

function fitText(el, max) {
  const full = el._full || '';
  el.textContent = full;
  let len = 0;
  try { len = el.getComputedTextLength(); } catch { return; }
  if (!len || len <= max) return;
  let lo = 1, hi = full.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    el.textContent = full.slice(0, mid).trimEnd() + '…';
    if (el.getComputedTextLength() <= max) lo = mid; else hi = mid - 1;
  }
  el.textContent = full.slice(0, lo).trimEnd() + '…';
}

/** What the second line under a node says: the make and model, with how sure we are. */
export function subLabel(d) {
  const idn = G.identityOf(d);
  const brand = G.brandOf(d);
  if (idn.state === 'unidentified') { const g = G.bestGuess(d); return { text: g ? 'maybe ' + g : 'not identified', cls: 'q' }; }
  const repeats = brand && d.name.toLowerCase().includes(brand.toLowerCase());
  const text = !brand || repeats ? kindLabel(d.kind) : brand;
  return idn.state === 'likely' ? { text: 'likely ' + (brand || kindLabel(d.kind).toLowerCase()), cls: 'l' } : { text, cls: '' };
}

export function createNetMap(host) {
  const deco = s('g', { class: 'deco' }), linkLayer = s('g', { class: 'links' }), nodeLayer = s('g', { class: 'nodes' }), fxLayer = s('g', { class: 'fx' });
  const capLayer = s('g', { class: 'caps' });   // captions that sit above the lines (the hull's count)
  const world = s('g', { class: 'world' }, deco, linkLayer, capLayer, fxLayer, nodeLayer);
  const svg = s('svg', { class: 'net', width: '100%', height: '100%', tabindex: 0, role: 'application',
    'aria-label': 'Network map. Arrow keys move between devices, Home and End jump to the first and last, Enter opens the inspector, Tab leaves the map. The Devices view lists the same devices as a table.' },
    s('defs', null,
      s('pattern', { id: 'net-dots', width: 28, height: 28, patternUnits: 'userSpaceOnUse' }, s('rect', { x: 0.5, y: 0.5, width: 1.2, height: 1.2, class: 'grid-dot' }))),
    s('rect', { class: 'bgdots', x: -4000, y: -4000, width: 9000, height: 9000, fill: 'url(#net-dots)' }), world);
  const canvas = h('canvas', { class: 'net-fx', 'aria-hidden': 'true' });
  const live = h('div', { class: 'sr-only', 'aria-live': 'polite' });
  host.append(svg, canvas, live);
  const ctx = canvas.getContext('2d');

  const t = { k: 1, x: 0, y: 0 };
  let userMoved = false, lastBounds = null, built = false, model = null, targets = [], tween = 0, lstep = 0;
  const nodeEls = new Map(), linkEls = new Map(), prevStatus = new Map();
  let flows = [], colors = {};

  const size = () => ({ w: host.clientWidth, h: host.clientHeight });
  const pad = () => {
    const phone = isPhone();
    const p = phone ? { t: (api.padTop || 44) + 10, r: 10, b: (api.padBottom || 0) + 14, l: 10 } : { t: (api.padTop || 44) + 22, r: 24, b: 60, l: 24 };   // the bottom keeps clear of the zoom control
    if (!phone && window.matchMedia('(max-width: 1023px)').matches && document.querySelector('.app').dataset.right === 'open') p.r += 360;
    return p;
  };

  function applyT() {
    world.setAttribute('transform', `translate(${t.x} ${t.y}) scale(${t.k})`);
    svg.querySelector('.bgdots').setAttribute('transform', `translate(${t.x} ${t.y}) scale(${t.k})`);
    svg.dataset.detail = t.k < 0.34 ? 'dots' : t.k < 0.5 ? 'low' : t.k >= 1.3 ? 'high' : 'mid';
    // labels keep a readable size when the map is small: a 12px name stays at 11px or more on screen down to 66%
    const ls = Math.max(1, Math.min(1.375, 0.92 / t.k));
    const step = Math.round(ls * 8) / 8;
    if (step !== lstep) { lstep = step; svg.style.setProperty('--ls', step); refit(); }
    // and lines, captions and speed tags keep their screen size below 100% (--lk, used in net.css), up to 2x
    const lk = Math.round(Math.max(1, Math.min(2, 1 / t.k)) * 16) / 16;
    if (lk !== svg._lk) { svg._lk = lk; svg.style.setProperty('--lk', lk); }
    api.onZoom && api.onZoom(t.k);
    if (!running) drawFx(performance.now());
  }
  function refit() {
    for (const [id, e] of nodeEls) { const n = model && model.nodes.get(id); if (!n) continue; fitText(e.sub, n.lw / lstep); fitName(e.name, n.lw / lstep, e.sub); plate(e); }
  }
  function plate(e) {
    let b = null;
    try { b = e.name.getBBox(); } catch { b = null; }
    if (!b || !b.width) { e.plate.setAttribute('width', 0); return; }
    e.plate.setAttribute('x', b.x - 3); e.plate.setAttribute('y', b.y - 1); e.plate.setAttribute('width', b.width + 6); e.plate.setAttribute('height', b.height + 2);
  }
  function moveTo(nt, animate) {
    cancelAnimationFrame(tween);
    if (!animate || reducedMotion() || !built) { Object.assign(t, nt); applyT(); return; }
    const from = { ...t }, t0 = performance.now(), dur = 420;
    const step = now => {
      const p = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - p, 3);
      t.k = from.k + (nt.k - from.k) * e; t.x = from.x + (nt.x - from.x) * e; t.y = from.y + (nt.y - from.y) * e;
      applyT();
      if (p < 1) tween = requestAnimationFrame(step);
    };
    tween = requestAnimationFrame(step);
  }
  function fit(b, { user = false, animate = false, maxK = 1.35, minK = 0.12 } = {}) {
    const { w, h: hh } = size();
    lastBounds = b; userMoved = user;
    if (!w || !hh) return;
    const p = pad();
    const k = Math.max(minK, Math.min(maxK, Math.min((w - p.l - p.r) / b.w, (hh - p.t - p.b) / b.h)));
    moveTo({ k, x: p.l + (w - p.l - p.r - b.w * k) / 2 - b.x * k, y: p.t + (hh - p.t - p.b - b.h * k) / 2 - b.y * k }, animate);
  }
  function zoomAt(k, cx, cy) {
    cancelAnimationFrame(tween);
    k = Math.max(Math.min(0.2, t.k), Math.min(3, k));
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
    if (dx || dy) { userMoved = true; moveTo({ k: t.k, x: t.x + dx, y: t.y + dy }, true); }
  }

  // ------------------------------------------------------------ build

  /** What does not move between renders: the hull, the outside line, the shelf. Rebuilt only when its place changes. */
  function buildDeco(m) {
    const H = m.hull, O = m.outside;
    const key = [H.x, H.y, H.w, H.h, H.show, H.title, O ? O.x + ',' + O.y : ''].join('|');
    if (deco._key === key) return;
    deco._key = key;
    const hull = s('g', { class: 'hull', style: H.show ? null : 'display:none' },
      s('rect', { class: 'hull-body', x: H.x, y: H.y, width: H.w, height: H.h }),
      s('rect', { class: 'hull-edge', x: H.x + 0.5, y: H.y + 0.5, width: H.w - 1, height: H.h - 1 }),
      s('text', { class: 'hull-t', x: H.x + H.w / 2, y: H.y + 22, 'text-anchor': 'middle' }, H.title));
    // the count just under the zone (inside, it ran into the spine's tiles and labels), on a plate above the lines
    capLayer.replaceChildren(s('g', { class: 'hull-cap', style: H.show ? null : 'display:none' }, s('rect', { class: 'hull-n-bg', width: 0, height: 0 }),
      s('text', { class: 'hull-n', x: H.x + H.w / 2, y: H.y + H.h + 6, dy: '1em', 'text-anchor': 'middle' }, '')));
    const outside = O ? s('g', { class: 'outside' },
      s('path', { d: `M${O.x} ${O.y - 90}V${O.y + 110}` }),
      s('text', { x: O.x - 8, y: O.y + 104, 'text-anchor': 'end' }, 'outside'), s('text', { x: O.x + 8, y: O.y + 104 }, 'at home')) : s('g', { class: 'outside' });
    const shelf = s('g', { class: 'shelf-cap' }, s('rect', { class: 'shelf-zone' }),
      s('text', { class: 'cap', x: 12, y: 20 }, 'Not on the network', s('tspan', { class: 'cap2' }, '  ·  owned or recorded, no connection to draw')));
    deco.replaceChildren(outside, hull, s('g', { class: 'ripples' }), s('g', { class: 'docks' }), shelf);
  }

  function nodeEl(d, n) {
    const g = s('g', { class: 'nn', dataset: { id: d.id, kind: 'node' } });
    const pod = s('g', { class: 'pod' });
    // every node is a square tile, like every surface in the family; the ring is its 1px edge, drawn inside
    const shape = (cls, grow) => s('rect', { class: cls, x: -n.r - grow, y: -n.r - grow, width: 2 * (n.r + grow), height: 2 * (n.r + grow) });
    const ring = s('rect', { class: 'ring', x: -n.r + 0.5, y: -n.r + 0.5, width: 2 * n.r - 1, height: 2 * n.r - 1 });
    const e = { g, pod, threat: shape('threat', 4), selRing: shape('sel-ring', 4), body: shape('body', 0), ring,
      icon: s('path', { class: 'kind' }), badge: s('g', { class: 'badge' }), fresh: s('g', { class: 'fresh' }),
      name: s('text', { class: 'name', 'text-anchor': 'middle', y: 0 }), sub: s('text', { class: 'sub', 'text-anchor': 'middle', y: 15 }) };
    const sc = n.r >= 24 ? 1.5 : n.r >= 18 ? 1.25 : 1;   // the kind icon fills about half its tile: 24 / 20 / 16px
    e.icon.setAttribute('transform', `translate(${-8 * sc} ${-8 * sc}) scale(${sc})`);
    // the one flag sits on the top-right corner; the new mark on the top-left
    e.badge.setAttribute('transform', `translate(${n.r} ${-n.r})`);
    e.fresh.setAttribute('transform', `translate(${-n.r} ${-n.r})`);
    e.fresh.append(s('rect', { x: -3, y: -3, width: 6, height: 6 }), s('title', null, 'First seen in the last 24 hours'));
    // a plate the colour of the canvas behind the name, so a cable passing under a label never runs through its letters
    e.plate = s('rect', { class: 'lbl-bg', x: 0, y: 0, width: 0, height: 0 });
    e.lbl = s('g', { class: 'lbl', transform: `translate(0 ${n.r + 16})` }, s('g', { class: 'lbl-s' }, e.plate, e.name, e.sub));
    pod.append(e.threat, e.selRing, e.body, e.ring, e.icon, e.badge, e.fresh);
    g.append(pod, e.lbl);
    return e;
  }

  function badgeFor(e, kind) {
    if (e._badge === kind) return;
    e._badge = kind;
    e.badge.replaceChildren();
    if (!kind) return;
    e.badge.setAttribute('class', 'badge b-' + kind);
    e.badge.appendChild(s('rect', { x: -7, y: -7, width: 14, height: 14 }));
    if (kind === 'blocked') e.badge.appendChild(s('path', { d: 'M-3.5 3.5L3.5 -3.5' }));
    else if (kind === 'watch') e.badge.appendChild(s('rect', { class: 'pip', x: -2, y: -2, width: 4, height: 4 }));
    else e.badge.appendChild(s('text', { y: 3.6, 'text-anchor': 'middle' }, kind === 'suspicious' ? '!' : '?'));
    e.badge.appendChild(s('title', null, { suspicious: 'Suspicious', blocked: 'Blocked at the router', unidentified: 'Not identified', watch: 'Worth a look' }[kind]));
  }

  function render() {
    const st = get();
    if (!st.inventory) { linkLayer.replaceChildren(); nodeLayer.replaceChildren(); nodeEls.clear(); linkEls.clear(); built = false; flows = []; return; }
    model = layout();
    buildDeco(model);
    const f = st.filters;
    const first = !built;

    // nodes
    const seen = new Set();
    targets = [];
    for (const d of G.devices()) {
      const n = model.nodes.get(d.id); if (!n) continue;
      seen.add(d.id);
      let e = nodeEls.get(d.id);
      if (e && e.role !== n.role) { e.g.remove(); nodeEls.delete(d.id); e = null; }
      const fresh = !e;
      if (!e) { e = nodeEl(d, n); e.role = n.role; nodeEls.set(d.id, e); nodeLayer.appendChild(e.g); if (!first && !reducedMotion()) { e.g.classList.add('enter'); setTimeout(() => e.g.classList.remove('enter'), 700); } }
      const status = G.statusOf(d.id), idn = G.identityOf(d), lvl = G.secLevel(d.id), isNew = G.isNew(d.id, st.now);
      const faded = (f.status && status !== f.status) || (f.focus && !G.matchesFocus(d, f.focus)) || (f.problems && !(G.concernRank(d) < 5));
      e.g.setAttribute('class', `nn role-${n.role} k-${d.kind} s-${status}` + (idn.state ? ' id-' + idn.state : '') + (lvl ? ' sec-' + lvl : '') + (isNew ? ' new' : '') + (faded ? ' faded' : '') + (d.dynamic ? ' dyn' : '') + (e.g.classList.contains('enter') ? ' enter' : ''));
      e.g.style.transform = `translate(${n.x}px, ${n.y}px)`;
      if (fresh) e.g.style.transition = 'none'; else e.g.style.transition = '';
      if (e._kind !== d.kind) { e._kind = d.kind; e.icon.setAttribute('d', iconPath(d.kind)); }
      if (e._status !== status) {
        if (e._status && !reducedMotion()) { const p = s('rect', { class: 'pulse', x: -n.r, y: -n.r, width: 2 * n.r, height: 2 * n.r }); e.pod.appendChild(p); setTimeout(() => p.remove(), 900); }
        e._status = status;
      }
      // one flag, worst first; "likely" carries none on the map (it is in the label on hover, the tooltip and the inspector)
      badgeFor(e, lvl === 'blocked' ? 'blocked' : lvl === 'suspicious' ? 'suspicious' : idn.state === 'unidentified' ? 'unidentified' : lvl === 'watch' ? 'watch' : null);
      const sub = subLabel(d);
      if (e._nm !== d.name || e.sub._full !== sub.text || fresh) { e.name._full = n.role === 'core' ? G.shortName(d.id) : d.name; e.sub._full = sub.text; e._nm = d.name; fitText(e.sub, n.lw / (lstep || 1)); fitName(e.name, n.lw / (lstep || 1), e.sub); plate(e); }
      e.sub.setAttribute('class', 'sub ' + sub.cls);
      targets.push({ id: d.id, cx: n.x, cy: n.y, box: { x: n.x - n.r - 6, y: n.y - n.r - 6, w: 2 * n.r + 12, h: 2 * n.r + 48 } });
    }
    for (const [id, e] of nodeEls) if (!seen.has(id)) { nodeEls.delete(id); e.g.classList.add('leave'); setTimeout(() => e.g.remove(), reducedMotion() ? 0 : 260); }
    targets.sort((a, b) => a.cx - b.cx || a.cy - b.cy);

    // links
    const seenL = new Set();
    const blockedDev = id => G.secLevel(id) === 'blocked';
    for (const l of model.links) {
      seenL.add(l.id);
      let e = linkEls.get(l.id);
      if (!e) {
        const g = s('g', { dataset: { id: l.id, kind: 'link' } });
        e = { g, halo: s('path', { class: 'halo' }), ln: s('path', { class: 'ln' }), ln2: s('path', { class: 'ln2' }), flow: s('path', { class: 'flow' }), hit: s('path', { class: 'hit' }), cut: s('g', { class: 'cut' }, s('path', { class: 'gap', d: 'M-4 0H4' }), s('path', { class: 'bars', d: 'M-4 -7V7M4 -7V7' })), tag: s('g', { class: 'tag' }) };
        g.append(e.halo, e.ln, e.ln2, e.flow, e.cut, e.tag, e.hit);
        linkEls.set(l.id, e); linkLayer.appendChild(g);
        if (!first && !reducedMotion()) { g.classList.add('enter'); setTimeout(() => g.classList.remove('enter'), 700); }
      }
      const d = pathD(l.pts);
      if (e._d !== d) { e._d = d; for (const p of [e.halo, e.ln, e.ln2, e.flow, e.hit]) p.setAttribute('d', d); }
      const cut = blockedDev(l.a) || (l.b && blockedDev(l.b) && l.kind !== 'wired');
      const lv = G.linkLive(l.id) || {};
      const sa = G.statusOf(l.a);
      const dead = lv.status === 'down' || sa === 'offline';
      const faded = (f.focus && !(G.matchesFocus(G.device(l.a), f.focus) || (l.b && G.matchesFocus(G.device(l.b), f.focus)))) || (l.trust && !f.trust[l.trust]);
      e.g.setAttribute('class', `nl k-${l.kind} t-${l.trust || 'live'}` + (l.hull ? ' to-hull' : '') + (l.second ? ' second' : '') + (l.paired ? ' paired' : '') + (l.link && l.link.medium === 'wireless' ? ' radio' : '') + (cut ? ' cutlink' : '') + (dead ? ' dead' : '') + (l.dir < 0 ? ' rev' : '') + (faded ? ' faded' : '') + (e.g.classList.contains('enter') ? ' enter' : ''));
      const cum = measure(l.pts), mid = pointAt(l.pts, cum, cum[cum.length - 1] / 2);
      e.cut.setAttribute('transform', `translate(${mid[0]} ${mid[1]}) rotate(${(mid[2] * 180) / Math.PI})`);
      const speed = l.link && l.link.speed && (l.kind === 'wired' || l.kind === 'coax') ? String(l.link.speed).replace(/ USB$/, '') : null;
      if (e._tag !== speed) {
        e._tag = speed; e.tag.replaceChildren();
        if (speed) { const w = speed.length * 6.7 + 10; e.tag.append(s('g', { class: 'tag-s' }, s('rect', { x: -w / 2, y: -8, width: w, height: 16 }), s('text', { y: 4, 'text-anchor': 'middle' }, speed))); }
      }
      e.tag.setAttribute('transform', `translate(${mid[0]} ${mid[1]})`);
      l.cum = cum; l.cut = cut; l.dead = dead;
    }
    for (const [id, e] of linkEls) if (!seenL.has(id)) { linkEls.delete(id); e.g.remove(); }

    // the mesh: its caption, where the unknown-access-point links land, and the radio rings of each access point
    const hn = capLayer.querySelector('.hull-n');
    const ap = model.wifiN - model.unknownAp;
    const many = G.accessPoints().length > 1;
    hn.textContent = !model.wifiN ? '' : !many ? plural(model.wifiN, 'device') + ' on Wi-Fi' : model.unknownAp === 0 ? `access point known for all ${model.wifiN} Wi-Fi devices`
      : ap === 0 ? `${model.wifiN} devices on Wi-Fi · which access point each one uses is not known` : `${model.unknownAp} of ${model.wifiN} Wi-Fi devices: access point not known`;
    const hb = capLayer.querySelector('.hull-n-bg');
    let bb = null; try { bb = hn.textContent ? hn.getBBox() : null; } catch { bb = null; }
    if (bb && bb.width) { hb.setAttribute('x', bb.x - 4); hb.setAttribute('y', bb.y - 1); hb.setAttribute('width', bb.width + 8); hb.setAttribute('height', bb.height + 2); } else hb.setAttribute('width', 0);
    deco.querySelector('.docks').replaceChildren(...model.docks.map(k => s('rect', { class: 'dock k-' + k.kind, x: k.x - 2.5, y: k.y - 2.5, width: 5, height: 5 })));
    const rip = deco.querySelector('.ripples');
    const aps = G.devices().filter(d => G.AP_KINDS.has(d.kind) && model.nodes.has(d.id) && G.statusOf(d.id) !== 'offline');
    if (rip._key !== aps.map(d => d.id).join()) {
      rip._key = aps.map(d => d.id).join();
      rip.replaceChildren(...aps.map(d => { const n = model.nodes.get(d.id); return s('rect', { class: 'ripple', x: n.x - n.r, y: n.y - n.r, width: 2 * n.r, height: 2 * n.r, style: `animation-delay:${-hash(d.id) * 6}s` }); }));
    }
    const sc = deco.querySelector('.shelf-cap');
    sc.style.display = model.shelf ? '' : 'none';
    if (model.shelf) { sc.setAttribute('transform', `translate(${model.shelf.x} ${model.shelf.y})`); const z = sc.querySelector('.shelf-zone'); z.setAttribute('width', model.shelf.w); z.setAttribute('height', model.shelf.h); }

    if (host.clientWidth) for (const e of nodeEls.values()) if (!Number(e.plate.getAttribute('width'))) plate(e);
    buildFlows();
    if (!built) { built = true; home(); if (st.route.sel[0]) api.show(st.route.sel[0], true); }
    applyFocus();
    start();
  }

  // ------------------------------------------------------------ focus: hover, selection, the path to the internet

  function pathSets(id) {
    const out = { links: new Set(), devices: new Set([id]) };
    const hops = G.upstream(id) || [];
    for (const hop of hops) { out.links.add(hop.link.id); out.devices.add(hop.from.dev); out.devices.add(hop.to.dev); }
    const c = G.conn(G.device(id));
    if (c.medium === 'lan') out.links.add('u-' + id);
    if (c.medium === 'cable' && c.link) { out.links.add(c.link.id); out.devices.add(G.peer(c.link, id).other.dev); }
    return out;
  }
  function focusSets() {
    const st = get();
    const res = { mode: null, links: new Set(), devices: new Set(), suspect: new Set() };
    const add = (id, deep) => {
      const ml = model.links.find(l => l.id === id);
      if (ml || G.isLinkId(id)) {
        res.links.add(id);
        const a = ml ? ml.a : G.link(id).a.dev, b = ml ? ml.b : G.link(id).b.dev;
        res.devices.add(a); if (b) res.devices.add(b);
        return;
      }
      if (!G.isDeviceId(id)) return;
      const p = pathSets(id);
      p.links.forEach(x => res.links.add(x)); p.devices.forEach(x => res.devices.add(x));
      if (deep) for (const l of model.links) if (l.a === id || l.b === id) { res.links.add(l.id); res.devices.add(l.a); if (l.b) res.devices.add(l.b); }
    };
    if (st.pin) {
      res.mode = 'strong';
      for (const id of st.pin.links || []) add(id);
      for (const id of st.pin.devices || []) res.devices.add(id);
      for (const id of st.pin.suspect || []) res.suspect.add(id);
    } else if (st.route.sel.length) { res.mode = 'sel'; for (const id of st.route.sel) add(id, true); }
    else if (st.hover && (nodeEls.has(st.hover) || linkEls.has(st.hover))) { res.mode = 'hover'; add(st.hover, true); }
    return res;
  }
  let focus = { mode: null, links: new Set(), devices: new Set() };
  function applyFocus() {
    if (!built || !model) return;
    const st = get();
    focus = focusSets();
    svg.dataset.dim = focus.mode || '';
    const sel = new Set(st.route.sel);
    for (const [id, e] of nodeEls) {
      const c = e.g.classList;
      c.toggle('dim', !!focus.mode && !focus.devices.has(id)); c.toggle('sel', sel.has(id)); c.toggle('hov', st.hover === id); c.toggle('lit', !!focus.mode && focus.devices.has(id));
    }
    for (const [id, e] of linkEls) {
      const c = e.g.classList;
      c.toggle('dim', !!focus.mode && !focus.links.has(id)); c.toggle('lit', !!focus.mode && focus.links.has(id)); c.toggle('sel', sel.has(id)); c.toggle('hov', st.hover === id);
      c.toggle('suspect', !!(focus.suspect && focus.suspect.has(id)));
    }
    deco.querySelector('.hull').classList.toggle('lit', [...focus.links].some(id => { const l = model.links.find(x => x.id === id); return l && l.hull; }));
    buildFlows();
  }

  function announce() {
    const st = get(); const id = st.route.sel[0];
    if (!id) { live.textContent = ''; return; }
    const d = G.device(id);
    if (d) {
      // the flags the map shows by colour and mark, said in words too
      const lvl = G.secLevel(id), flags = [lvl === 'suspicious' ? 'suspicious' : lvl === 'blocked' ? 'blocked at the router' : lvl === 'watch' ? 'worth a look' : null, G.identityOf(d).state === 'unidentified' ? 'not identified' : null, G.isNew(id, get().now) ? 'new today' : null].filter(Boolean);
      const hops = G.upstream(id); live.textContent = `${d.name}, ${statusLabel(G.statusOf(id))}${flags.length ? ', ' + flags.join(', ') : ''}, ${G.connText(d)}${hops ? ', ' + plural(hops.length, 'hop') + ' to the internet' : ''}`; return;
    }
    const l = G.link(id); if (l) live.textContent = `${cableName(l.cable)} link, ${G.deviceName(l.a.dev)} to ${l.b.dev ? G.deviceName(l.b.dev) : G.meshWord()}`;
  }

  // ------------------------------------------------------------ what moves: the canvas layer

  function readColors() {
    const cs = getComputedStyle(svg);
    const v = n => cs.getPropertyValue(n).trim();
    colors = { wired: v('--m-wired'), wifi: v('--m-wifi'), bt: v('--m-bt'), coax: v('--m-coax'), mesh: v('--m-wifi'), lan: v('--m-none'), tunnel: v('--m-desk'), light: document.documentElement.dataset.theme === 'light' };
  }
  function buildFlows() {
    if (!model) return;
    const st = get();
    // measured traffic, summed along each device's path to the internet
    const tx = new Map(), rx = new Map();
    let measured = false;
    for (const d of G.devices()) {
      const tr = (G.liveOf(d.id) || {}).traffic;
      if (!tr) continue;
      measured = true;
      const hops = G.upstream(d.id) || [];
      for (const hop of hops) { tx.set(hop.link.id, (tx.get(hop.link.id) || 0) + (tr.txBps || 0)); rx.set(hop.link.id, (rx.get(hop.link.id) || 0) + (tr.rxBps || 0)); }
    }
    api.measured = measured;
    const out = [];
    const level = bps => Math.max(0, Math.min(6, Math.log10(Math.max(1, bps)) - 2.2));   // 160 b/s → 0, 16 Mb/s → 5
    for (const l of model.links) {
      if (l.kind === 'desk' || l.cut || l.dead || !l.dir || l.paired) continue;
      const sa = G.statusOf(l.a);
      if (l.kind !== 'wired' && l.kind !== 'coax' && l.kind !== 'mesh' && !['online', 'degraded', 'inferred'].includes(sa)) continue;
      const len = l.cum[l.cum.length - 1];
      if (len < 12) continue;
      const lit = focus.mode && focus.links.has(l.id), dim = focus.mode && !lit;
      if (l.second && !lit) continue;   // a second way onto the network stays quiet until it is asked about
      const base = { l, len, lit, dim, kind: l.kind, color: colors[l.kind] || colors.wired };
      const has = tx.has(l.id) || rx.has(l.id);
      if (measured && has) {
        const up = level(tx.get(l.id) || 0), down = level(rx.get(l.id) || 0);
        if (up > 0) out.push({ ...base, sign: l.dir, n: Math.max(1, Math.round((len / 150) * (0.5 + up * 0.5))), speed: 34 + up * 16 });
        if (down > 0) out.push({ ...base, sign: -l.dir, n: Math.max(1, Math.round((len / 150) * (0.5 + down * 0.5))), speed: 34 + down * 16, down: true });
      } else if (!has) {   // nothing measured for this link (the router counts Wi-Fi clients only): show that it is up, no more
        out.push({ ...base, sign: l.dir, n: Math.max(1, Math.round(len / 190)), speed: l.kind === 'bt' ? 18 : 30, calm: true });
      }
    }
    flows = out;
    void st;
  }

  let running = false, raf = 0;
  function resizeCanvas() {
    const { w, h: hh } = size();
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(hh * dpr)) { canvas.width = Math.round(w * dpr); canvas.height = Math.round(hh * dpr); canvas.style.width = w + 'px'; canvas.style.height = hh + 'px'; }
    return dpr;
  }
  function drawFx(now) {
    const dpr = resizeCanvas();
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    if (reducedMotion() || !flows.length) return;
    ctx.setTransform(dpr * t.k, 0, 0, dpr * t.k, dpr * t.x, dpr * t.y);
    const { w, h: hh } = size();
    const vx0 = -t.x / t.k - 20, vy0 = -t.y / t.k - 20, vx1 = (w - t.x) / t.k + 20, vy1 = (hh - t.y) / t.k + 20;
    const sec = now / 1000;
    const small = t.k < 0.5 ? 1.5 : 1;
    for (const f of flows) {
      const { l } = f;
      ctx.fillStyle = ctx.strokeStyle = f.color;
      const a = f.dim ? 0.1 : f.lit ? 1 : f.calm ? 0.4 : 0.7;
      for (let i = 0; i < f.n; i++) {
        let u = (hash(l.id + i + (f.down ? 'd' : '')) + (sec * f.speed) / f.len) % 1;
        if (f.sign < 0) u = 1 - u;
        const p = pointAt(l.pts, l.cum, u * f.len);
        if (p[0] < vx0 || p[0] > vx1 || p[1] < vy0 || p[1] > vy1) continue;
        const edge = Math.min(1, Math.min(u, 1 - u) * f.len / 14);   // fade in and out at the ends
        ctx.globalAlpha = a * edge;
        if (f.kind === 'wifi') {
          // a wavefront: a short arc across the direction of travel
          const dir = p[2] + (f.sign < 0 ? Math.PI : 0), r = 4.5 * small;
          ctx.lineWidth = 1.2 * small; ctx.lineCap = 'butt';
          ctx.beginPath(); ctx.arc(p[0] - Math.cos(dir) * r, p[1] - Math.sin(dir) * r, r, dir - 0.75, dir + 0.75); ctx.stroke();
        } else {
          // a small square, no glow: the family draws marks, not light
          const r = (f.kind === 'bt' ? 1 : f.kind === 'coax' || f.kind === 'mesh' ? 1.8 : 1.4) * small * (f.lit ? 1.25 : 1);
          ctx.fillRect(p[0] - r, p[1] - r, 2 * r, 2 * r);
        }
      }
    }
    ctx.globalAlpha = 1;
  }
  function frame(now) {
    if (!running) return;
    if (document.hidden || !host.clientWidth || reducedMotion()) { running = false; svg.classList.remove('animating'); drawFx(now); return; }
    drawFx(now);
    raf = requestAnimationFrame(frame);
  }
  function start() {
    readColors();
    const ok = !document.hidden && host.clientWidth > 0 && !reducedMotion();
    svg.classList.toggle('animating', ok);
    if (running || !ok) { if (!ok) drawFx(performance.now()); return; }
    running = true; raf = requestAnimationFrame(frame);
  }
  function stop() { running = false; cancelAnimationFrame(raf); svg.classList.remove('animating'); }
  document.addEventListener('visibilitychange', () => (document.hidden ? stop() : start()));
  window.matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change', () => { stop(); start(); });
  new MutationObserver(() => { readColors(); buildFlows(); }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

  /** A new reading has arrived: one ring runs out from the router and each node answers as it passes. */
  function sweep() {
    if (!built || !model || reducedMotion() || document.hidden || !host.clientWidth) return;
    const o = model.root || [model.hull.x + model.hull.w / 2, model.spineY];
    let max = 0;
    // a square wave, like the tiles and the access points' ripples: distance is the larger of the two offsets
    const far = n => Math.max(Math.abs(n.x - o[0]), Math.abs(n.y - o[1]));
    for (const n of model.nodes.values()) max = Math.max(max, far(n));
    max += 40;
    const ring = s('rect', { class: 'sweep', x: o[0] - max, y: o[1] - max, width: 2 * max, height: 2 * max });
    fxLayer.appendChild(ring);
    setTimeout(() => ring.remove(), 1900);
    for (const [id, e] of nodeEls) {
      const n = model.nodes.get(id); if (!n) continue;
      const delay = Math.round((far(n) / max) * 1500);
      e.pod.style.setProperty('--d', delay + 'ms');
      e.g.classList.remove('tick'); e.g.getBoundingClientRect(); e.g.classList.add('tick');
      setTimeout(() => e.g.classList.remove('tick'), delay + 700);
    }
  }

  // ------------------------------------------------------------ tooltips

  const line = (text, cls) => h('span', { class: 't-line' + (cls ? ' ' + cls : '') }, text);
  function tooltipFor(id, kind) {
    const st = get();
    if (kind === 'link') {
      const ml = model.links.find(l => l.id === id); if (!ml) return null;
      const a = G.deviceName(ml.a), b = ml.b ? G.deviceName(ml.b) : (G.accessPoints().length > 1 ? 'the mesh (access point not known)' : G.accessPoints().length ? G.meshWord() : 'the network (no router recorded)');
      const box = h('div', null, h('span', { class: 't-title' }, a + ' → ' + b));
      const l = ml.link;
      if (ml.kind === 'wifi') { const c = G.conn(G.device(ml.a)); const w = c.medium === 'wifi' ? c : c.wifi || {}; box.appendChild(line(['Wi-Fi', w.band, w.rssi != null ? w.rssi + ' dBm' : null, w.ssid].filter(Boolean).join(' · '))); }
      else if (ml.kind === 'lan') box.appendChild(line('On the LAN: whether by cable or Wi-Fi is not known'));
      else if (ml.kind === 'tunnel') box.appendChild(line('Seen over Tailscale: it reaches the house through the internet, not the LAN'));
      else if (l) box.appendChild(line([cableName(l.cable), l.speed, (l.carries || []).length ? 'carries ' + l.carries.join(', ') : null].filter(Boolean).join(' · ')));
      if (l && l.verified) box.appendChild(line(`${(TRUST[l.verified] || {}).word || l.verified}: ${l.evidence || (TRUST[l.verified] || {}).meaning || ''}`));
      const lv = G.linkLive(id);
      if (lv && lv.status) box.appendChild(line('Link ' + lv.status + (lv.detail ? ' · ' + lv.detail : '')));
      if (ml.cut) box.appendChild(line('Cut: the device is blocked at the router'));
      return box;
    }
    const d = G.device(id); if (!d) return null;
    const lv = G.liveOf(id) || {}, status = G.statusOf(id), idn = G.identityOf(d), sec = G.securityOf(id), lvl = G.secLevel(id);
    const brand = G.brandOf(d);
    const box = h('div', null, h('span', { class: 't-title' }, d.name));
    box.appendChild(line(idn.state === 'unidentified' ? 'Not identified' + (G.bestGuess(d) ? ' · maybe ' + G.bestGuess(d) : '') : (brand || kindLabel(d.kind)) + (idn.state ? ' · ' + G.ID_WORD[idn.state] : '')));
    box.appendChild(line(statusLabel(status) + (status === 'unmonitored' ? ': no probe is possible' : lv.lastSeen ? ' · seen ' + relTime(lv.lastSeen, st.now) : '')));
    box.appendChild(line(G.connText(d) + (G.conn(d).rssi != null ? ' · ' + G.conn(d).rssi + ' dBm' : '')));
    const ip = G.primaryIp(d); if (ip) box.appendChild(line(ip));
    if (lv.traffic) box.appendChild(line('↓ ' + rate(lv.traffic.rxBps) + ' · ↑ ' + rate(lv.traffic.txBps)));
    if (lvl && lvl !== 'ok') box.appendChild(line((lvl === 'blocked' ? 'Blocked at the router' : lvl === 'suspicious' ? 'Suspicious' : 'Worth a look') + (sec.reasons && sec.reasons[0] ? ': ' + sec.reasons[0].text : ''), 't-' + lvl));
    if (G.isNew(id, st.now)) box.appendChild(line('First seen ' + relTime(sec.firstSeen, st.now)));
    return box;
  }

  // ------------------------------------------------------------ interaction

  const hit = e => { const el = e.target.closest && e.target.closest('[data-id]'); return el && world.contains(el) ? el : null; };
  const pointers = new Map();
  let drag = null, pinch = null, suppressClick = false;
  svg.addEventListener('pointerdown', e => {
    if (e.button !== 0 && e.pointerType === 'mouse') return;
    pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    hideTip(); cancelAnimationFrame(tween);
    if (pointers.size === 1) { drag = { id: e.pointerId, sx: e.clientX, sy: e.clientY, tx: t.x, ty: t.y, moved: false }; suppressClick = false; }
    else if (pointers.size === 2) { const [a, b] = [...pointers.values()]; pinch = { d: Math.hypot(a.x - b.x, a.y - b.y), k: t.k }; drag = null; suppressClick = true; }
  });
  svg.addEventListener('pointermove', e => {
    if (!pointers.has(e.pointerId)) return;
    pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    const r = svg.getBoundingClientRect();
    if (pinch && pointers.size >= 2) { const [a, b] = [...pointers.values()]; zoomAt(pinch.k * Math.hypot(a.x - b.x, a.y - b.y) / pinch.d, (a.x + b.x) / 2 - r.left, (a.y + b.y) / 2 - r.top); return; }
    if (!drag || drag.id !== e.pointerId) return;
    const dx = e.clientX - drag.sx, dy = e.clientY - drag.sy;
    if (!drag.moved && Math.hypot(dx, dy) > 4) { drag.moved = true; suppressClick = true; svg.classList.add('panning'); try { svg.setPointerCapture(e.pointerId); } catch { /* fine */ } }
    if (drag.moved) { t.x = drag.tx + dx; t.y = drag.ty + dy; userMoved = true; applyT(); }
  });
  const up = e => { pointers.delete(e.pointerId); if (pointers.size < 2) pinch = null; if (drag && drag.id === e.pointerId) { drag = null; svg.classList.remove('panning'); } };
  svg.addEventListener('pointerup', up); svg.addEventListener('pointercancel', up);
  svg.addEventListener('click', e => {
    if (suppressClick) { suppressClick = false; return; }
    const el = hit(e);
    if (!el) { if (get().route.sel.length) clearSelection(); return; }
    select(el.dataset.id, { add: e.shiftKey });
  });
  svg.addEventListener('contextmenu', e => {
    const el = hit(e);
    if (!el || el.dataset.kind !== 'node') return;
    e.preventDefault(); hideTip();
    if (!get().route.sel.includes(el.dataset.id)) select(el.dataset.id);
    api.onMenu && api.onMenu(el.dataset.id, e.clientX, e.clientY);
  });
  svg.addEventListener('wheel', e => {
    e.preventDefault();
    const r = svg.getBoundingClientRect();
    if (e.ctrlKey || e.metaKey) zoomAt(t.k * Math.exp(-e.deltaY * 0.01), e.clientX - r.left, e.clientY - r.top);
    else { cancelAnimationFrame(tween); t.x -= e.deltaX; t.y -= e.deltaY; userMoved = true; applyT(); }
  }, { passive: false });
  svg.addEventListener('gesturestart', e => e.preventDefault());
  svg.addEventListener('pointerover', e => {
    if (e.pointerType === 'touch' || (drag && drag.moved)) return;
    const el = hit(e);
    const id = el ? el.dataset.id : null;
    if (id !== get().hover) set({ hover: id });
    if (el) tipLater(() => tooltipFor(el.dataset.id, el.dataset.kind), e.clientX, e.clientY + 10);
    else hideTip();
  });
  svg.addEventListener('pointerleave', () => { if (get().hover) set({ hover: null }); hideTip(); });

  let lastW = 0;
  const ro = new ResizeObserver(() => {
    const { w } = size();
    const first = !lastW && w > 0;
    lastW = w;
    if (!built) return;
    if (first) { home(); if (get().route.sel[0]) api.show(get().route.sel[0], true); start(); return; }
    if (!running) drawFx(performance.now());
    if (userMoved || !lastBounds) return;
    if (get().route.sel.length) { api.show(get().route.sel[0], true); return; }
    home();
  });
  ro.observe(host);

  function home(animate) {
    if (!model) return;
    const { w } = size();
    // a narrow screen opens on the mesh and its clients at a readable size; Fit shows everything
    if (w && w < 700) return fit(coreBounds(model), { animate, minK: 0.42 });
    fit(model.bounds, { animate });
  }

  const api = {
    el: svg, render, applyFocus, announce, home, fit, sweep, start, stop,
    fitAll: () => model && fit(model.bounds, { user: true, animate: true }),
    reset: () => { const { w, h: hh } = size(); zoomAt(1, w / 2, hh / 2); },
    zoomBy: f => { const { w, h: hh } = size(); zoomAt(t.k * f, w / 2, hh / 2); },
    zoom: () => t.k,
    targets: () => targets,
    model: () => model,
    /** Screen position of a node's centre, for anchoring a menu. */
    screenOf(id) { const n = model && model.nodes.get(id); if (!n) return null; const r = svg.getBoundingClientRect(); return { x: r.left + n.x * t.k + t.x, y: r.top + n.y * t.k + t.y, r: n.r * t.k }; },
    show(id, keepAuto) {
      const was = userMoved;
      const tg = targets.find(x => x.id === id);
      if (tg) ensureVisible({ x: tg.box.x - 50, y: tg.box.y - 14, w: tg.box.w + 100, h: tg.box.h + 28 });
      else { const l = model && model.links.find(x => x.id === id); if (l) { const xs = l.pts.map(p => p[0]), ys = l.pts.map(p => p[1]); ensureVisible({ x: Math.min(...xs) - 30, y: Math.min(...ys) - 30, w: Math.max(...xs) - Math.min(...xs) + 60, h: Math.max(...ys) - Math.min(...ys) + 60 }); } }
      if (keepAuto) userMoved = was;
    },
    showZone(zid) {
      if (!model) return;
      const ns = [...model.nodes.values()].filter(n => (G.device(n.id) || {}).zone === zid);
      if (!ns.length) return;
      const x0 = Math.min(...ns.map(n => n.x)) - 90, x1 = Math.max(...ns.map(n => n.x)) + 90, y0 = Math.min(...ns.map(n => n.y)) - 70, y1 = Math.max(...ns.map(n => n.y)) + 90;
      fit({ x: x0, y: y0, w: x1 - x0, h: y1 - y0 }, { user: true, animate: true, maxK: 1.2 });
    },
    destroy() { ro.disconnect(); stop(); svg.remove(); canvas.remove(); live.remove(); },
    onZoom: null, onMenu: null, padTop: 0, padBottom: 0, measured: false,
  };
  return api;
}
