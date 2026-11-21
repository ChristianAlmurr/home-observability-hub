// DOM helpers. Everything from the API goes in as text nodes, never as HTML.

const SVG_NS = 'http://www.w3.org/2000/svg';

function apply(el, props, isSvg) {
  if (!props) return;
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') { if (isSvg) el.setAttribute('class', v); else el.className = v; }
    else if (k === 'dataset') { for (const [dk, dv] of Object.entries(v)) if (dv != null) el.dataset[dk] = dv; }
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'text') el.textContent = v;
    else if (!isSvg && (k === 'value' || k === 'checked' || k === 'disabled' || k === 'hidden' || k === 'selected' || k === 'tabIndex' || k === 'htmlFor' || k === 'readOnly')) el[k] = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
}

function add(el, kids) {
  for (const k of kids) {
    if (k == null || k === false || k === '') continue;
    if (Array.isArray(k)) add(el, k);
    else if (k instanceof Node) el.appendChild(k);
    else el.appendChild(document.createTextNode(String(k)));
  }
}

/** h('div', {class:'x', onClick}, child, 'text', [more]) */
export function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  apply(el, props, false);
  add(el, kids);
  return el;
}

export function s(tag, props, ...kids) {
  const el = document.createElementNS(SVG_NS, tag);
  apply(el, props, true);
  add(el, kids);
  return el;
}

export function clear(el) { el.replaceChildren(); return el; }
export function fill(el, ...kids) { el.replaceChildren(); add(el, kids); return el; }

export function $(sel, root = document) { return root.querySelector(sel); }
export function $$(sel, root = document) { return [...root.querySelectorAll(sel)]; }

export function isTyping(e) {
  const t = e.target;
  if (!t || !t.tagName) return false;
  return t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName);
}

export async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch {
    const ta = h('textarea', { value: text, style: { position: 'fixed', opacity: '0' } });
    document.body.appendChild(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    return ok;
  }
}

export const isPhone = () => window.matchMedia('(max-width: 767px)').matches;
export const isNarrow = () => window.matchMedia('(max-width: 1023px)').matches;
export const isWide = () => window.matchMedia('(min-width: 1440px)').matches;
export const reducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/**
 * A row of role="tab" buttons: one Tab stop (the selected tab), arrow keys and Home/End move and select.
 * Returns the tablist element. Tabs here switch what a region shows; the route keeps which one is open.
 */
export function tablist(label, tabs) {
  const el = h('div', { class: 'tablist', role: 'tablist', 'aria-label': label }, tabs);
  const sel = tabs.find(t => t.getAttribute('aria-selected') === 'true') || tabs[0];
  for (const t of tabs) t.tabIndex = t === sel ? 0 : -1;
  el.addEventListener('keydown', e => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
    const i = tabs.indexOf(document.activeElement);
    const n = e.key === 'Home' ? tabs[0] : e.key === 'End' ? tabs[tabs.length - 1] : tabs[(i + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
    e.preventDefault(); e.stopPropagation();
    const host = el.parentNode;
    n.click();
    // the click may redraw the tabs: focus the selected tab of whatever is there now
    requestAnimationFrame(() => { const now = host && host.querySelector('[role="tab"][aria-selected="true"]'); (now && now.isConnected ? now : n).focus(); });
  });
  return el;
}
