// Shared components: glyphs, chips, tooltips, popovers, toasts, dialogs, sections, property rows, path strip.
import { h, s, copyText, isPhone } from './dom.js';
import { icon } from './icons.js';
import { get, set, select, pref, setPref } from './store.js';
import * as G from './graph.js';
import { statusLabel, TRUST, cableName, cableCls, age as ageOf, absTime } from './fmt.js';

// ---------------------------------------------------------------- status and trust glyphs

/** SVG children for a 10px status shape. Shape plus colour, so it survives greyscale. Square-cornered like the map's
 *  tiles, and every state still has its own outline: filled square (online), triangle (degraded), diamond (offline),
 *  half-filled square (asleep), dashed square (unmonitored), square with a centre (inferred), square with ? (unknown),
 *  two dashes (plan). */
export function statusShape(status) {
  const c = `var(--status-${['inferred', 'plan', 'asleep'].includes(status) ? 'unknown' : status})`;
  const box = extra => s('rect', { x: 1.1, y: 1.1, width: 7.8, height: 7.8, fill: 'none', stroke: c, 'stroke-width': 1.2, ...extra });
  switch (status) {
    case 'online': return [s('rect', { x: 1, y: 1, width: 8, height: 8, fill: c })];
    case 'degraded': return [s('path', { d: 'M5 0.8L9.6 9H0.4z', fill: c })];
    case 'offline': return [s('path', { d: 'M5 0.4L9.6 5L5 9.6L0.4 5z', fill: c })];
    case 'asleep': return [box(), s('rect', { x: 1, y: 5, width: 8, height: 4, fill: c })];
    case 'unmonitored': return [box({ 'stroke-dasharray': '2 1.9' })];
    case 'inferred': return [box(), s('rect', { x: 3.5, y: 3.5, width: 3, height: 3, fill: c })];
    case 'plan': return [s('path', { d: 'M0.5 5h3M6.5 5h3', stroke: c, 'stroke-width': 1.6, fill: 'none' })];
    default: return [box(),
      s('path', { d: 'M3.9 4.1a1.15 1.15 0 1 1 1.7 1c-.4.2-.6.4-.6.8M5 7.2v.1', fill: 'none', stroke: c, 'stroke-width': 1, 'stroke-linecap': 'round' })];
  }
}

export function statusGlyph(status, size = 10) {
  return s('svg', { class: 'glyph', width: size, height: size, viewBox: '0 0 10 10', role: 'img', 'aria-label': status === 'plan' ? 'Plan, not confirmed' : statusLabel(status) }, statusShape(status));
}

export const DASH = { live: null, plan: '4 3', reported: '1 3' };

export function trustLine(trust, w = 14) {
  return s('svg', { width: w, height: 6, viewBox: `0 0 ${w} 6`, 'aria-hidden': 'true' },
    s('path', { d: `M1 3H${w - 1}`, stroke: 'currentColor', 'stroke-width': 2, 'stroke-dasharray': DASH[trust] || null, 'stroke-linecap': trust === 'reported' ? 'round' : 'butt', fill: 'none' }));
}

/** The trust glyph: a line in the trust's style, the word, then the age or basis. */
export function trustEl(trust, extra, { stale = false } = {}) {
  const t = TRUST[trust] ? trust : 'reported';
  const el = h('span', { class: 'trust' + (stale ? ' stale' : '') }, trustLine(t), h('span', null, TRUST[t].word + (extra ? ' · ' + extra : '')));
  tip(el, TRUST[t].word + ': ' + TRUST[t].meaning);
  return el;
}

/** Age of the live document, and whether it is old enough to say so in caution colour. */
export function liveAge() {
  const st = get();
  const ts = st.live && st.live.ts;
  if (!ts) return { text: null, stale: true };
  const interval = (st.settings && st.settings.scanIntervalSec) || 30;
  const sec = (st.now - Date.parse(ts)) / 1000;
  return { text: ageOf(ts, st.now) || absTime(ts), stale: sec > interval * 3 };
}
export function liveTrust() {
  const a = liveAge();
  return trustEl('live', a.text || 'no reading yet', { stale: a.stale });
}

// ---------------------------------------------------------------- text with "not confirmed"

const NC = /(not (?:yet )?confirmed|not identified|not known|not otherwise confirmed|unverified)/gi;

export function valueNodes(text, hint) {
  const str = String(text == null ? '' : text);
  const parts = str.split(NC);
  if (parts.length === 1) return [str];
  return parts.map((p, i) => {
    if (i % 2 === 0) return p;
    const el = h('span', { class: 'nc' }, p);
    tip(el, hint || 'Not confirmed by a probe or a document. The value is shown as it was reported.');
    return el;
  });
}

// ---------------------------------------------------------------- chips

export function deviceChip(id, { removable = false, onRemove, selectable = true } = {}) {
  const d = G.device(id);
  const name = d ? d.name : id;
  const body = [statusGlyph(d ? G.statusOf(id) : 'unknown', 8), h('span', { class: 'ellipsis' }, name)];
  const hover = { onMouseenter: () => set({ hover: id }), onMouseleave: () => get().hover === id && set({ hover: null }) };
  if (removable) {
    return h('span', { class: 'chip', ...hover }, body,
      h('button', { class: 'x', 'aria-label': 'Remove ' + name, onClick: e => { e.stopPropagation(); onRemove && onRemove(id); } }, icon('close', 12)));
  }
  if (!selectable || !d) return h('span', { class: 'chip', ...hover }, body);
  const el = h('button', { class: 'chip', type: 'button', ...hover, onClick: e => { e.stopPropagation(); select(id); } }, body);
  tip(el, () => name + ' · ' + statusLabel(G.statusOf(id)));
  return el;
}

// ---------------------------------------------------------------- tooltips

let tipEl = null, tipTimer = 0, lastHide = 0, tipFor = null;
const tips = new WeakMap();

/** Attach a tooltip. content: string, Node, or a function returning either. */
export function tip(el, content) { tips.set(el, content); return el; }

function tipContent(c) {
  const v = typeof c === 'function' ? c() : c;
  if (v == null || v === '') return null;
  return v instanceof Node ? v : document.createTextNode(String(v));
}

export function showTip(content, x, y, { below = true } = {}) {
  hideTip(true);
  const node = tipContent(content);
  if (!node) return;
  tipEl = h('div', { class: 'tooltip', role: 'tooltip' }, node);
  document.body.appendChild(tipEl);
  const r = tipEl.getBoundingClientRect();
  let left = Math.min(Math.max(8, x - r.width / 2), window.innerWidth - r.width - 8);
  let top = below ? y + 10 : y - r.height - 10;
  if (top + r.height > window.innerHeight - 8) top = y - r.height - 10;
  if (top < 8) top = 8;
  tipEl.style.left = left + 'px'; tipEl.style.top = top + 'px';
}

export function hideTip(quiet) {
  clearTimeout(tipTimer);
  if (tipEl) { tipEl.remove(); tipEl = null; if (!quiet) lastHide = Date.now(); }
  if (!quiet) tipFor = null;
}

export function tipLater(content, x, y, opts) {
  clearTimeout(tipTimer);
  const delay = Date.now() - lastHide < 300 ? 0 : 400;
  tipTimer = setTimeout(() => showTip(content, x, y, opts), delay);
}

function findTip(t) {
  while (t && t !== document.body) {
    if (tips.has(t)) return t;
    t = t.parentNode;
  }
  return null;
}

export function initTips() {
  ensureToasts();
  let touch = false;
  document.addEventListener('pointerdown', e => { touch = e.pointerType === 'touch'; hideTip(); }, true);
  document.addEventListener('mouseover', e => {
    if (touch) return;
    const el = findTip(e.target);
    if (el === tipFor) return;
    hideTip(); tipFor = el;
    if (!el) return;
    const r = el.getBoundingClientRect();
    tipLater(tips.get(el), r.left + r.width / 2, r.bottom, { below: true });
  });
  document.addEventListener('focusin', e => {
    const el = findTip(e.target);
    if (!el || !e.target.matches(':focus-visible')) return;
    const r = el.getBoundingClientRect();
    tipFor = el; tipLater(tips.get(el), r.left + r.width / 2, r.bottom);
  });
  document.addEventListener('focusout', () => hideTip());
  document.addEventListener('scroll', () => hideTip(), true);
  document.addEventListener('keydown', () => hideTip(), true);
}

// ---------------------------------------------------------------- layers (Esc closes the topmost)

const layers = [];
export function pushLayer(close) { const l = { close }; layers.push(l); return () => { const i = layers.indexOf(l); if (i >= 0) layers.splice(i, 1); }; }
export function closeTopLayer() {
  const l = layers.pop();
  if (!l) return false;
  l.close();
  return true;
}
export const hasLayer = () => layers.length > 0;

export function popover(anchor, content, { cls = '', align = 'left', label } = {}) {
  const el = h('div', { class: 'popover ' + cls, role: 'dialog', 'aria-label': label || anchor.getAttribute('aria-label') || (anchor.textContent || '').trim() || null }, content);
  document.body.appendChild(el);
  const place = () => {
    const a = anchor.getBoundingClientRect(), r = el.getBoundingClientRect();
    let left = align === 'right' ? a.right - r.width : a.left;
    left = Math.min(Math.max(8, left), window.innerWidth - r.width - 8);
    let top = a.bottom + 6;
    if (top + r.height > window.innerHeight - 8) top = Math.max(8, a.top - r.height - 6);
    el.style.left = left + 'px'; el.style.top = top + 'px';
  };
  place();
  let pop;
  const close = () => { el.remove(); document.removeEventListener('pointerdown', outside, true); window.removeEventListener('resize', close); pop && pop(); anchor.setAttribute('aria-expanded', 'false'); };
  const outside = e => { if (!el.contains(e.target) && !anchor.contains(e.target)) close(); };
  pop = pushLayer(() => { el.remove(); document.removeEventListener('pointerdown', outside, true); anchor.setAttribute('aria-expanded', 'false'); anchor.focus && anchor.focus(); });
  setTimeout(() => document.addEventListener('pointerdown', outside, true), 0);
  window.addEventListener('resize', close, { once: true });
  anchor.setAttribute('aria-expanded', 'true');
  const f = el.querySelector('button, input, a, select');
  if (f) f.focus({ preventScroll: true });
  return { el, close, place };
}

export function dialog({ title, body, cls = '', top = false, onClose }) {
  const closeBtn = h('button', { class: 'btn minimal icon sm', 'aria-label': 'Close', onClick: () => close() }, icon('close'));
  const box = h('div', { class: 'dialog ' + cls, role: 'dialog', 'aria-modal': 'true', 'aria-label': title || 'Dialog' },
    title ? h('header', null, h('span', { class: 'grow' }, title), closeBtn) : null, body);
  const scrim = h('div', { class: 'scrim' + (top ? ' top' : ''), onPointerdown: e => { if (e.target === scrim) close(); } }, box);
  const prev = document.activeElement;
  document.body.appendChild(scrim);
  // everything behind the dialog is out of reach for keyboard and screen reader until it closes; toasts stay audible
  const inerted = [...document.body.children].filter(n => n !== scrim && !n.inert && n.tagName !== 'SCRIPT' && !n.classList.contains('toasts'));
  for (const n of inerted) n.inert = true;
  const release = () => { for (const n of inerted) n.inert = false; };
  let pop;
  function close() { scrim.remove(); release(); pop && pop(); onClose && onClose(); prev && prev.focus && prev.focus({ preventScroll: true }); }
  pop = pushLayer(() => { scrim.remove(); release(); onClose && onClose(); prev && prev.focus && prev.focus({ preventScroll: true }); });
  scrim.addEventListener('keydown', e => {
    if (e.key !== 'Tab') return;
    const f = [...box.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex="0"]')].filter(x => x.tabIndex >= 0 && x.offsetParent !== null);
    if (!f.includes(document.activeElement) && f.length) { e.preventDefault(); (e.shiftKey ? f[f.length - 1] : f[0]).focus(); return; }
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });
  const f = box.querySelector('input, textarea') || box.querySelector('.body button, .body a') || closeBtn;
  f && f.focus({ preventScroll: true });
  return { el: box, close };
}

// ---------------------------------------------------------------- toasts

let toastHost = null;
/** The toast region is put on the page empty, before any message, so screen readers announce the first one too. */
export function ensureToasts() { if (!toastHost) { toastHost = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' }); document.body.appendChild(toastHost); } return toastHost; }
export function toast(text, { intent = 'info', action, sticky = false } = {}) {
  ensureToasts();
  while (toastHost.children.length >= 3) toastHost.firstChild.remove();
  const el = h('div', { class: 'toast ' + intent },
    h('div', { class: 'grow' }, text),
    action ? h('button', { class: 'btn sm', onClick: () => { action.fn(); el.remove(); } }, action.label) : null,
    h('button', { class: 'btn minimal icon sm', 'aria-label': 'Dismiss notification', onClick: () => el.remove() }, icon('close', 14)));
  toastHost.appendChild(el);
  if (!(sticky || action || intent === 'danger')) {
    let timer = setTimeout(() => el.remove(), 5000);
    el.addEventListener('mouseenter', () => clearTimeout(timer));
    el.addEventListener('mouseleave', () => { timer = setTimeout(() => el.remove(), 2500); });
    el.addEventListener('focusin', () => clearTimeout(timer));
    el.addEventListener('focusout', () => { timer = setTimeout(() => el.remove(), 2500); });
  }
  return el;
}

// ---------------------------------------------------------------- small controls

export function seg(options, value, onChange, { cls = '', label } = {}) {
  const el = h('div', { class: 'seg ' + cls, role: 'radiogroup', 'aria-label': label });
  const btns = options.map(o => {
    const b = h('button', { type: 'button', role: 'radio', 'aria-checked': String(o.value === value), dataset: { v: o.value }, disabled: !!o.disabled,
      tabIndex: o.value === value ? 0 : -1, onClick: () => onChange(o.value) }, o.icon ? icon(o.icon, 14) : null, o.dot ? h('span', { class: 'live-dot' }) : null,
      o.short ? [h('span', { class: 'hide-md' }, o.label), h('span', { class: 'show-md' }, o.short)] : o.label);
    if (o.tip) tip(b, o.tip);
    return b;
  });
  el.append(...btns);
  if (!btns.some(b => b.tabIndex === 0)) { const f = btns.find(b => !b.disabled); if (f) f.tabIndex = 0; }
  el.addEventListener('keydown', e => {
    if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(e.key)) return;
    const on = btns.filter(b => !b.disabled);
    if (!on.length) return;
    const i = on.indexOf(document.activeElement);
    const fwd = e.key === 'ArrowRight' || e.key === 'ArrowDown';
    const n = e.key === 'Home' ? on[0] : e.key === 'End' ? on[on.length - 1] : on[(i + (fwd ? 1 : -1) + on.length) % on.length];
    const host = el.parentNode;
    n.focus(); n.click(); e.preventDefault(); e.stopPropagation();
    // choosing may redraw the control: keep focus on the chosen option in the new one
    requestAnimationFrame(() => { if (n.isConnected || !host) return; const g = [...host.querySelectorAll('[role="radiogroup"]')].find(x => x.getAttribute('aria-label') === label); const c = g && g.querySelector('[aria-checked="true"]'); if (c) c.focus(); });
  });
  return el;
}

export function copyBtn(text, label = 'Copy', { cls = 'btn sm' } = {}) {
  const b = h('button', { class: cls, type: 'button', onClick: async e => {
    e.stopPropagation();
    const ok = await copyText(typeof text === 'function' ? text() : text);
    toast(ok ? 'Copied.' : 'Could not copy. Select the text and copy it by hand.', { intent: ok ? 'success' : 'caution' });
  } }, icon('copy', 14), label);
  return b;
}

export function callout(intent, ...body) {
  const ic = { info: 'info', caution: 'warning', danger: 'warning', success: 'check' }[intent] || 'info';
  return h('div', { class: 'callout ' + intent, role: intent === 'danger' ? 'alert' : null }, icon(ic), h('div', { class: 'body' }, body));
}

export function errorState(message, retry, lead = 'This could not be loaded.') {
  return h('div', { class: 'state' }, callout('danger', lead, h('span', { class: 'mono' }, message)),
    retry ? h('button', { class: 'btn sm', onClick: retry }, 'Retry') : null);
}
export function emptyState(text, action) {
  return h('div', { class: 'state' }, h('p', null, text), action ? h('button', { class: 'btn sm', onClick: action.fn }, action.label) : null);
}
export function skeleton(rows = 6) {
  const w = ['w60', 'w80', 'w40', 'w60', 'w30', 'w80'];
  const el = h('div', { class: 'skel-rows', role: 'status' }, h('span', { class: 'sr-only' }, 'Loading'), Array.from({ length: rows }, (_, i) => h('span', { class: 'skel ' + w[i % w.length] })));
  const late = setTimeout(() => { if (el.isConnected) el.appendChild(h('p', { class: 'muted', style: { marginTop: '12px' } }, 'Still loading from the server…')); }, 10000);
  void late;
  return el;
}

/** Collapsible section. Open state is kept per section name, not per device. */
export function section(name, title, body, { meta, open = true } = {}) {
  const key = 'sec.' + name;
  const isOpen = pref(key, open);
  const el = h('section', { class: 'section', dataset: { open: String(isOpen) } });
  const btn = h('button', { class: 'sec-h', type: 'button', 'aria-expanded': String(isOpen), onClick: () => {
    const now = el.dataset.open !== 'true';
    el.dataset.open = String(now); btn.setAttribute('aria-expanded', String(now)); setPref(key, now);
  } }, icon('chevron', 16, 'chev'), h('span', null, title), meta ? h('span', { class: 'meta' }, meta) : null);
  el.append(btn, h('div', { class: 'sec-b' }, body));
  return el;
}

/** Property row: label, value, provenance. */
export function prop(label, value, { mono = false, trust, extra, stale, trustNode, hint, copy = true, raw } = {}) {
  const text = raw != null ? raw : (typeof value === 'string' || typeof value === 'number' ? String(value) : null);
  const v = h('div', { class: 'v' + (mono ? ' mono' : '') }, typeof value === 'string' ? valueNodes(value, hint) : value);
  const t = trustNode || (trust ? trustEl(trust, extra, { stale }) : null);
  const canCopy = copy && text && !isPhone();
  return h('div', { class: 'prop' + (canCopy ? '' : ' no-copy') }, h('div', { class: 'k' }, label), v, h('div', { class: 't' }, t),
    canCopy ? copyBtn(text, '', { cls: 'btn minimal icon sm copy' }) : null);
}

// ---------------------------------------------------------------- path strip

const short = id => G.shortName(id);

/**
 * A chain of hops: device names joined by connectors in the cable's colour and trust style.
 * hops: [{ link, from:{dev,port}, to:{dev,port}, gap? }]
 */
export function pathStrip(hops, { suspect = new Set(), slow = new Set(), vertical = false } = {}) {
  const el = h('div', { class: 'strip' + (vertical ? ' vertical' : ''), role: 'group', 'aria-label': 'Path' });
  const devBtn = (end, first) => {
    const b = h('button', { class: 'strip-dev', type: 'button', onClick: () => select(end.dev),
      onMouseenter: () => set({ hover: end.dev }), onMouseleave: () => set({ hover: null }) },
      statusGlyph(G.statusOf(end.dev), 8), h('span', null, short(end.dev)));
    void first;
    return b;
  };
  hops.forEach((hop, i) => {
    if (i === 0 || hop.gap) { if (hop.gap) el.appendChild(h('span', { class: 'strip-gap' }, '·')); el.appendChild(devBtn(hop.from, true)); }
    const l = hop.link;
    const isSus = suspect.has(l.id), isSlow = slow.has(l.id);
    const label = [hop.from.port ? G.portShort(hop.from.dev, hop.from.port) : null, cableName(l.cable) + (l.speed ? ' ' + l.speed : ''), hop.to.port ? G.portShort(hop.to.dev, hop.to.port) : null];
    const c = h('button', { class: `strip-hop c-${cableCls(l.cable)} t-${l.verified}` + (isSus ? ' suspect' : '') + (isSlow ? ' slow' : ''), type: 'button',
      onClick: () => select(l.id), onMouseenter: () => set({ hover: l.id }), onMouseleave: () => set({ hover: null }) },
      h('span', { class: 'p' }, label[0] || ''), h('span', { class: 'line' }, isSus ? icon('warning', 12) : null, h('em', null, label[1])), h('span', { class: 'p' }, label[2] || ''),
      h('span', { class: 'sr-only' }, ` cable, ${l.verified}${isSus ? ', the agent suspects this hop' : ''}${isSlow ? ', slowest hop on this path' : ''}`));
    if (isSlow) tip(c, 'Slowest hop on this path');
    if (isSus) tip(c, 'The agent suspects this hop');
    el.append(c, devBtn(hop.to));
  });
  return el;
}

const HOP = {
  wifi: l => 'Wi-Fi' + (l.band ? ' ' + l.band : ''), bluetooth: () => 'Bluetooth', mesh: () => 'mesh backhaul', coax: () => 'coax', tunnel: () => 'Tailscale',
  ethernet: l => 'Ethernet' + (l.speed ? ' ' + l.speed : ''),
};
const hopKind = l => ({ wifi: 'wifi', bluetooth: 'bt', mesh: 'mesh', coax: 'coax', tunnel: 'tunnel' }[l.cable] || 'wired');

/**
 * The way from a device to the internet, hop by hop, each connector in the colour and style of what it is made of.
 * A Wi-Fi hop whose access point is not known lands on "the mesh", never on a guessed node.
 */
export function internetPath(id, { vertical = false } = {}) {
  const d = G.device(id);
  const hops = G.upstream(id);
  const el = h('div', { class: 'npath' + (vertical ? ' vertical' : ''), role: 'group', 'aria-label': 'Path to the internet' });
  if (!d) return el;
  if (!hops) {
    const c = G.conn(d);
    el.classList.add('none');
    el.append(h('span', { class: 'np-none' }, c.medium === 'none' ? (d.zone === 'spares' ? 'In the spares drawer: not connected to anything.' : 'No connection is recorded, so there is no path to draw.')
      : c.medium === 'cable' ? G.connText(d) + '. It carries video or USB, not the network.' : G.connText(d) + '. No path from there to the internet is known.'));
    return el;
  }
  if (!hops.length) { el.classList.add('none'); el.append(h('span', { class: 'np-none' }, 'The path to the internet ends here.')); return el; }
  const dev = devId => h('button', { class: 'np-dev', type: 'button', onClick: () => select(devId), onMouseenter: () => set({ hover: devId }), onMouseleave: () => get().hover === devId && set({ hover: null }) },
    statusGlyph(G.statusOf(devId), 8), h('span', null, G.shortName(devId)));
  el.appendChild(dev(hops[0].from.dev));
  for (const hop of hops) {
    const l = hop.link, kind = hopKind(l);
    const label = (HOP[l.cable] || (x => cableName(x.cable) + (x.speed ? ' ' + x.speed : '')))(l.cable === 'wifi' ? { ...l, band: G.conn(G.device(hop.from.dev)).band || l.band } : l);
    const c = h(l.synthetic && !G.isLinkId(l.id) ? 'span' : 'button', { class: `np-hop k-${kind} t-${l.verified || 'live'}`, type: 'button', onClick: () => G.isLinkId(l.id) && select(l.id),
      onMouseenter: () => set({ hover: l.id }), onMouseleave: () => get().hover === l.id && set({ hover: null }) }, h('i'), h('em', null, label), h('i'));
    tip(c, (TRUST[l.verified] ? TRUST[l.verified].word + ': ' : '') + (l.evidence || (TRUST[l.verified] || {}).meaning || label));
    el.appendChild(c);
    if (hop.mesh) {
      const m = h('span', { class: 'np-mesh' }, 'the mesh', h('span', { class: 'nc' }, 'access point not known'));
      tip(m, 'The device is on Wi-Fi. Which access point it is talking to is not known, so the line stops at the mesh as a whole. From there the way out is the main router.');
      el.append(m, h('span', { class: 'np-hop k-mesh', 'aria-hidden': 'true' }, h('i'), h('i')));
    }
    el.appendChild(dev(hop.to.dev));
  }
  return el;
}

export function carriesIcons(carries) {
  const order = ['video', 'usb', 'network', 'power'];
  const names = { video: 'Video', usb: 'USB', network: 'Network', power: 'Power' };
  return h('span', { class: 'carries' }, order.filter(c => (carries || []).includes(c)).map(c => h('span', { class: 'tag' }, icon(c, 12), names[c])));
}
