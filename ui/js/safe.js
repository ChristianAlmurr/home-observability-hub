// Text that somebody else chose: a download picks its own file name, an extension its own title.
// Everything from a finding is shown through here. Characters that hide or reorder text (bidirectional
// overrides, zero-width marks, control codes) are shown as what they are, so "invoice\u202Efdp.app" cannot
// read as "invoiceppa.pdf".
import { h } from './dom.js';

// C0 and C1 controls, DEL, soft hyphen, Arabic letter mark, zero-width and directional marks, line and
// paragraph separators, bidirectional embeddings, overrides and isolates, word joiner and invisible
// operators, byte-order mark, interlinear annotation marks, the tag block.
const HIDDEN = /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF\uFFF9-\uFFFB]|\uDB40[\uDC00-\uDC7F]/g;
const KEEP_MULTILINE = new Set(['\n', '\t']);

const code = ch => 'U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0');

function parts(value, multiline) {
  const str = value == null ? '' : String(value);
  const out = [];
  let last = 0;
  HIDDEN.lastIndex = 0;
  for (let m; (m = HIDDEN.exec(str));) {
    if (multiline && KEEP_MULTILINE.has(m[0])) continue;
    if (m.index > last) out.push({ text: str.slice(last, m.index) });
    out.push({ esc: code(m[0]) });
    last = m.index + m[0].length;
  }
  if (last < str.length) out.push({ text: str.slice(last) });
  return out;
}

/** True when the text carries characters that would not be seen. */
export function hasHidden(value, { multiline = false } = {}) { return parts(value, multiline).some(p => p.esc); }

/** The text as one plain string, hidden characters written out as ⟨U+202E⟩. For labels, tooltips and the clipboard. */
export function safeText(value, { multiline = false } = {}) {
  return parts(value, multiline).map(p => (p.esc ? '⟨' + p.esc + '⟩' : p.text)).join('');
}

/** The text as DOM nodes: text nodes, and a marked span for each hidden character. Never HTML. */
export function safeNodes(value, { multiline = false } = {}) {
  return parts(value, multiline).map(p => (p.esc ? h('span', { class: 'esc', title: 'A hidden character, shown as its code' }, p.esc) : document.createTextNode(p.text)));
}

/**
 * One line that gives way in the middle: the start shrinks with an ellipsis and the end stays, so the file
 * name and its extension, or the last characters of a hash, are always on screen.
 */
export function midTrunc(value, { keep = 0, cls = '' } = {}) {
  const ps = parts(value, false);
  const plain = ps.map(p => (p.esc ? '⟨' + p.esc + '⟩' : p.text)).join('');
  let tail = keep;
  if (!tail) {
    const slash = plain.lastIndexOf('/', plain.length - 2);
    tail = slash > 0 ? plain.length - slash : 10;
  }
  tail = Math.min(tail, 30, Math.floor(plain.length / 2));
  if (plain.length <= 24 || tail < 4) return h('span', { class: 'mid ' + cls }, h('span', { class: 'mid-a' }, nodesOf(ps)));
  // split the parts at the tail boundary without cutting an escape in two
  const headParts = [], tailParts = [];
  let left = plain.length - tail;
  for (const p of ps) {
    const len = p.esc ? p.esc.length + 2 : p.text.length;
    if (left >= len) { headParts.push(p); left -= len; }
    else if (left <= 0 || p.esc) { tailParts.push(p); left = 0; }
    else { headParts.push({ text: p.text.slice(0, left) }); tailParts.push({ text: p.text.slice(left) }); left = 0; }
  }
  return h('span', { class: 'mid ' + cls }, h('span', { class: 'mid-a' }, nodesOf(headParts)), h('span', { class: 'mid-b' }, nodesOf(tailParts)));
}

function nodesOf(ps) { return ps.map(p => (p.esc ? h('span', { class: 'esc' }, p.esc) : document.createTextNode(p.text))); }
