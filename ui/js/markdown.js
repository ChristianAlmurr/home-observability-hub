// A small, safe markdown renderer. It builds DOM nodes; nothing is ever parsed as HTML.
// Supported: headings, paragraphs, bullet and numbered lists (one level of nesting), bold, italic,
// inline code, fenced code blocks, links (http and https only), bare URLs, simple pipe tables, rules.
import { h } from './dom.js';
import { isHttpUrl } from './fmt.js';

const INLINE = /(`[^`\n]+`)|(\[[^\]\n]+\]\([^)\s]+\))|(\*\*[^*\n][^\n]*?\*\*)|(__[^_\n]+__)|(\*[^*\s][^*\n]*?\*)|(\b_[^_\n]+_\b)|(https?:\/\/[^\s<>()]+(?:\([^\s<>()]*\))?[^\s<>().,;:!?'"\]]*)/;

function link(text, url) {
  if (!isHttpUrl(url)) return document.createTextNode(text);
  return h('a', { href: url, target: '_blank', rel: 'noopener noreferrer' }, text);
}

export function inline(text, depth = 0) {
  const out = [];
  let rest = String(text);
  while (rest) {
    const m = depth > 4 ? null : INLINE.exec(rest);
    if (!m) { out.push(rest); break; }
    if (m.index) out.push(rest.slice(0, m.index));
    const tok = m[0];
    if (m[1]) out.push(h('code', null, tok.slice(1, -1)));
    else if (m[2]) { const mm = /^\[([^\]]+)\]\(([^)\s]+)\)$/.exec(tok); out.push(mm ? link(mm[1], mm[2]) : tok); }
    else if (m[3] || m[4]) out.push(h('strong', null, inline(tok.slice(2, -2), depth + 1)));
    else if (m[5] || m[6]) out.push(h('em', null, inline(tok.slice(1, -1), depth + 1)));
    else if (m[7]) out.push(link(tok, tok));
    rest = rest.slice(m.index + tok.length);
  }
  return out;
}

const isRow = l => /^\s*\|.*\|\s*$/.test(l);
const cells = l => l.trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim());

/**
 * render(markdown, { minHeading }) → DocumentFragment-like array wrapped in a div.md
 * minHeading: the highest heading level to emit (answers never go above h4).
 */
export function render(src, { minHeading = 3 } = {}) {
  const root = h('div', { class: 'md' });
  const lines = String(src == null ? '' : src).replace(/\r\n?/g, '\n').split('\n');
  let i = 0, para = [];
  const flush = () => { if (para.length) { root.appendChild(h('p', null, inline(para.join(' ')))); para = []; } };
  while (i < lines.length) {
    const line = lines[i];
    if (/^\s*```/.test(line)) {
      flush();
      const buf = [];
      i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      root.appendChild(h('pre', null, h('code', null, buf.join('\n'))));
      continue;
    }
    if (!line.trim()) { flush(); i++; continue; }
    const hd = /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line);
    if (hd) {
      flush();
      const level = Math.min(6, Math.max(minHeading, hd[1].length + (minHeading - 1)));
      root.appendChild(h('h' + level, { class: 'md-h md-h' + hd[1].length }, inline(hd[2])));
      i++; continue;
    }
    if (/^\s*([-*_])\s*\1\s*\1[\s\-*_]*$/.test(line)) { flush(); root.appendChild(h('hr')); i++; continue; }
    if (isRow(line) && i + 1 < lines.length && /^\s*\|?[\s:|-]+\|[\s:|-]*$/.test(lines[i + 1])) {
      flush();
      const head = cells(line);
      i += 2;
      const body = [];
      while (i < lines.length && isRow(lines[i])) body.push(cells(lines[i++]));
      root.appendChild(h('div', { class: 'md-table' }, h('table', null,
        h('thead', null, h('tr', null, head.map(c => h('th', null, inline(c))))),
        h('tbody', null, body.map(r => h('tr', null, r.map(c => h('td', null, inline(c)))))))));
      continue;
    }
    const li = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/.exec(line);
    if (li) {
      flush();
      const ordered = /\d/.test(li[2]);
      const list = h(ordered ? 'ol' : 'ul');
      let last = null, sub = null;
      const base = li[1].length;
      while (i < lines.length) {
        const m = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/.exec(lines[i]);
        if (m) {
          if (m[1].length > base + 1 && last) {
            if (!sub) { sub = h(/\d/.test(m[2]) ? 'ol' : 'ul'); last.appendChild(sub); }
            sub.appendChild(h('li', null, inline(m[3])));
          } else { last = h('li', null, inline(m[3])); list.appendChild(last); sub = null; }
          i++;
        } else if (lines[i].trim() && /^\s{2,}/.test(lines[i]) && last) { last.append(' ', ...inline(lines[i].trim())); i++; }
        else break;
      }
      root.appendChild(list);
      continue;
    }
    const bq = /^\s*>\s?(.*)$/.exec(line);
    para.push(bq ? bq[1] : line.trim());
    i++;
  }
  flush();
  return root;
}

/** Headings in a guide, for the collapsed preview. */
export function headings(src) {
  return String(src || '').split('\n').map(l => /^(#{1,6})\s+(.*?)\s*$/.exec(l)).filter(Boolean).map(m => ({ level: m[1].length, text: m[2] }));
}
