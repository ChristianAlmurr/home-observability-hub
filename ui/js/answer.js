// Renders the agent's answer document and its action cards. The document is data: every string
// goes in as text, markdown goes through the safe renderer, and nothing here can approve by itself.
import { h, fill, isPhone } from './dom.js';
import { icon } from './icons.js';
import { get, set, go, select } from './store.js';
import * as G from './graph.js';
import { deviceChip, callout, copyBtn, pathStrip, tip, statusGlyph } from './ui.js';
import { render as md, inline } from './markdown.js';
import { hostOf, isHttpUrl, clock, plural } from './fmt.js';
import { isHandsOff } from './site.js';

const ticked = new Set();   // step checkboxes: local only, never sent to the agent

export function pinFor(run) {
  const a = run.answer;
  if (!a) return null;
  const p = a.path || {};
  if (!(p.links || []).length && !(a.subjects || []).length) return null;
  return { runId: run.runId, links: p.links || [], suspect: p.suspect || [], devices: a.subjects || [], note: p.note || '', title: a.title || '' };
}

function confidence(c) {
  const n = c === 'high' ? 3 : c === 'medium' ? 2 : 1;
  const word = { high: 'High confidence', medium: 'Medium confidence', low: 'Low confidence' }[c] || 'Low confidence';
  return h('span', { class: 'conf' + (n === 1 ? ' low' : ''), role: 'img', 'aria-label': word }, h('span', { class: 'meter' }, [1, 2, 3].map(i => h('i', { class: i <= n ? 'on' : '' }))), h('span', null, word));
}

function blockTitle(text, meta) { return h('h4', { class: 'b-title' }, text, meta ? h('span', { class: 'b-meta' }, meta) : null); }

function sourceIndex(answer) {
  const list = (answer.sources || []).map(s => ({ ...s }));
  const find = src => {
    if (!src) return -1;
    let i = list.findIndex(s => s.url === src || s.title === src);
    if (i < 0 && isHttpUrl(src)) { list.push({ title: hostOf(src) || src, url: src }); i = list.length - 1; }
    return i;
  };
  // register fact sources up front so numbers are stable
  for (const b of answer.blocks || []) if (b.type === 'facts') for (const it of b.items || []) find(it.source);
  return { list, find };
}

function renderBlock(b, bi, run, src) {
  const key = (i) => `${run.runId}:${bi}:${i}`;
  switch (b.type) {
    case 'text': return h('div', { class: 'b b-text' }, md(b.markdown || '', { minHeading: 4 }));
    case 'steps': return h('div', { class: 'b b-steps' }, blockTitle(b.title || 'Do this'),
      h('ol', null, (b.items || []).map((it, i) => {
        const id = 'st-' + key(i).replace(/[^a-z0-9]/gi, '-');
        const cb = h('input', { type: 'checkbox', id, checked: ticked.has(key(i)), 'aria-label': 'Done: step ' + (i + 1), onChange: e => { if (e.target.checked) ticked.add(key(i)); else ticked.delete(key(i)); li.classList.toggle('done', e.target.checked); } });
        const li = h('li', { class: ticked.has(key(i)) ? 'done' : '' }, h('span', { class: 'num' }, String(i + 1)),
          h('div', { class: 'grow' }, h('div', { class: 'st-text' }, inline(it.text || '')), it.device && G.isDeviceId(it.device) ? h('div', { class: 'st-dev' }, deviceChip(it.device)) : null,
            it.detail ? h('div', { class: 'st-detail' }, inline(it.detail)) : null,
            it.expect ? h('div', { class: 'st-expect' }, h('b', null, 'You should see: '), inline(it.expect)) : null), cb);
        return li;
      })));
    case 'checks': {
      const items = b.items || [];
      const pass = items.filter(x => x.ok === true).length, fail = items.filter(x => x.ok === false).length;
      return h('div', { class: 'b b-checks' }, blockTitle(b.title || 'What I checked', `${pass} passed${fail ? ' · ' + fail + ' failed' : ''}${items.length - pass - fail ? ' · ' + (items.length - pass - fail) + ' not judged' : ''}`),
        h('div', { class: 'ck', role: 'table', 'aria-label': b.title || 'What I checked' }, items.map(it => h('div', { class: 'ck-row', role: 'row' },
          h('span', { class: 'r ' + (it.ok === true ? 'ok' : it.ok === false ? 'bad' : 'na'), role: 'cell' }, icon(it.ok === true ? 'check' : it.ok === false ? 'cross' : 'dash', 14), h('span', { class: 'sr-only' }, it.ok === true ? 'Passed' : it.ok === false ? 'Failed' : 'Not judged')),
          h('span', { class: 'l', role: 'cell' }, it.label || ''), h('span', { class: 'v mono', role: 'cell' }, it.value == null ? '' : String(it.value)),
          it.source ? h('span', { class: 's mono', role: 'cell' }, it.source) : null))));
    }
    case 'facts': return h('div', { class: 'b b-facts' }, blockTitle(b.title || 'From the manual'),
      h('div', { class: 'props' }, (b.items || []).map(it => {
        const i = src.find(it.source);
        const cite = i >= 0 ? h('a', { class: 'cite', href: '#src-' + run.runId + '-' + (i + 1), 'aria-label': 'Source ' + (i + 1), onClick: e => { e.preventDefault(); const t = document.getElementById('src-' + run.runId + '-' + (i + 1)); t && t.scrollIntoView({ block: 'center' }); t && t.classList.add('flash'); setTimeout(() => t && t.classList.remove('flash'), 1200); } }, '[' + (i + 1) + ']')
          : it.source ? h('span', { class: 'mono muted src' }, it.source) : null;
        return h('div', { class: 'prop no-copy' }, h('div', { class: 'k' }, it.label || ''),
          h('div', { class: 'v' }, inline(it.value == null ? '' : String(it.value)), it.device && G.isDeviceId(it.device) ? h('div', { style: { marginTop: '4px' } }, deviceChip(it.device)) : null),
          h('div', { class: 't' }, cite));
      })));
    case 'compare': {
      const cols = b.columns || [], rec = Number.isInteger(b.recommended) ? b.recommended : -1;
      return h('div', { class: 'b b-compare' }, blockTitle(b.title || 'Options'),
        h('div', { class: 'cmp-wrap scroll', tabIndex: 0, role: 'region', 'aria-label': b.title || 'Options' }, h('table', { class: 'cmp' },
          h('thead', null, h('tr', null, h('th', null, h('span', { class: 'sr-only' }, 'Compared on')), cols.map((c, i) => h('th', { class: i === rec ? 'rec' : '', scope: 'col' }, c, i === rec ? h('span', { class: 'tag info' }, 'Recommended') : null)))),
          h('tbody', null, (b.rows || []).map(r => h('tr', null, h('th', { scope: 'row' }, r.label || ''), cols.map((_, i) => h('td', { class: i === rec ? 'rec' : '' }, inline((r.values || [])[i] == null ? '' : String(r.values[i]))))))))));
    }
    case 'warning': return h('div', { class: 'b' }, callout(['info', 'caution', 'danger'].includes(b.level) ? b.level : 'info', inline(b.text || '')));
    default: return null;
  }
}

/** The answer without its action cards. Re-rendered whole when the document is re-sent. */
export function renderAnswer(run, { onShowMap } = {}) {
  const a = run.answer;
  const src = sourceIndex(a);
  const out = h('article', { class: 'answer' });
  out.appendChild(h('header', { class: 'a-h' }, h('h3', null, a.title || 'Answer'), confidence(a.confidence)));
  if (a.parsed === false) out.appendChild(callout('caution', 'The agent did not answer in the expected format, so its reply is shown as plain text and nothing in it is linked to the map.'));
  if (a.verdict) out.appendChild(h('p', { class: 'verdict' }, inline(a.verdict)));
  if ((a.subjects || []).length) out.appendChild(h('div', { class: 'chips' }, a.subjects.filter(G.isDeviceId).map(id => deviceChip(id))));
  const pin = pinFor(run);
  const p = a.path || {};
  if ((p.links || []).length) {
    const hops = G.orderPath(p.links);
    const pinned = get().pin && get().pin.runId === run.runId;
    out.appendChild(h('div', { class: 'a-path' },
      h('div', { class: 'row' }, h('span', { class: 'b-title', style: { margin: 0 } }, 'Path'), h('span', { class: 'grow' }),
        h('button', { class: 'btn sm', 'aria-pressed': String(!!pinned), onClick: () => onShowMap && onShowMap(pin) }, icon('map', 14), 'Show on map')),
      pathStrip(hops, { suspect: new Set(p.suspect || []), vertical: isPhone() }),
      p.note ? h('p', { class: 'muted note' }, 'Why this hop: ', inline(p.note)) : null));
  } else if (pin) {
    out.appendChild(h('div', { class: 'a-path row' }, h('span', { class: 'muted grow' }, 'This answer names devices but no cable path.'), h('button', { class: 'btn sm', onClick: () => onShowMap && onShowMap(pin) }, icon('map', 14), 'Show on map')));
  }
  (a.blocks || []).forEach((b, i) => { const el = renderBlock(b, i, run, src); if (el) out.appendChild(el); });
  const actionsSlot = h('div', { class: 'a-actions' });
  out.appendChild(actionsSlot);
  if (src.list.length) out.appendChild(h('div', { class: 'b b-sources' }, blockTitle('Sources'),
    h('ol', null, src.list.map((s, i) => h('li', { id: 'src-' + run.runId + '-' + (i + 1) },
      isHttpUrl(s.url) ? h('a', { href: s.url, target: '_blank', rel: 'noopener noreferrer' }, s.title || s.url) : h('span', null, s.title || s.url || ''),
      isHttpUrl(s.url) ? h('span', { class: 'mono muted host' }, hostOf(s.url)) : null, s.device && G.isDeviceId(s.device) ? deviceChip(s.device) : null)))));
  if ((a.unknowns || []).length) out.appendChild(h('div', { class: 'b b-unknowns' }, blockTitle('Not established'),
    h('ul', null, a.unknowns.map(u => h('li', null, h('span', { class: 'q', 'aria-hidden': 'true' }, '?'), h('span', null, inline(String(u))))))));
  return { el: out, actionsSlot };
}

// ---------------------------------------------------------------- action cards

const RISK = { read: { cls: '', word: 'READ' }, change: { cls: 'caution', word: 'CHANGE' }, destructive: { cls: 'danger', word: 'DESTRUCTIVE' } };
const FINAL = ['done', 'failed', 'rejected', 'refused', 'copy-only', 'interrupted', 'superseded'];

/** What the card should show, from the server's state, the mode and the hard refusals. */
export function cardState(action, st, mode, otherRunning) {
  const s0 = st.state || action.state || 'proposed';
  if (s0 === 'proposed') {
    if (action.needsSudo) return 'copy-only';
    if (isHandsOff(action.target)) return 'refused';
    if (mode === 'advise') return 'advise';
    if (mode === 'paused') return 'paused';
    return otherRunning ? 'blocked' : 'proposed';
  }
  if (s0 === 'approved') return 'running';
  return s0;
}

/**
 * One action card with its own update(), so streamed output and typed confirmations survive re-renders.
 * ctx: { decide(action, decision) → Promise, stop(), undo(action), fixture }
 */
export function createActionCard(run, action, ctx) {
  const el = h('section', { class: 'action', 'aria-label': 'Proposed action: ' + (action.label || '') });
  const outEl = h('pre', { class: 'out', tabIndex: 0, 'aria-label': 'Command output' });
  let sig = '', lines = 0, typed = '', busy = false, showCmd = false, showAllOut = false, follow = true;
  outEl.addEventListener('scroll', () => { follow = outEl.scrollTop + outEl.clientHeight >= outEl.scrollHeight - 8; });
  const risk = RISK[action.risk] || RISK.change;

  function cmdBlock() {
    return h('div', { class: 'cmd' }, h('pre', { class: 'mono' }, action.command || '(no command)'), copyBtn(action.command || '', 'Copy command'));
  }
  function details() {
    const target = G.device(action.target);
    return [
      action.why ? h('div', { class: 'a-row' }, h('span', { class: 'k' }, 'Why'), h('div', { class: 'v' }, inline(action.why))) : null,
      h('div', { class: 'a-row' }, h('span', { class: 'k' }, 'Target'), h('div', { class: 'v' }, target ? deviceChip(action.target) : h('span', { class: 'mono' }, action.target || 'not given'))),
      h('div', { class: 'a-row' }, h('span', { class: 'k' }, 'Command'), h('div', { class: 'v' }, cmdBlock())),
      h('div', { class: 'a-row' }, h('span', { class: 'k' }, 'Undo'), h('div', { class: 'v' }, action.undo ? h('pre', { class: 'mono undo' }, action.undo) : h('span', { class: 'danger-text' }, 'No undo. This cannot be reversed.'))),
    ];
  }
  const auditLink = () => h('button', { class: 'linkbtn', onClick: () => go({ view: 'activity', at: 'audit', run: run.runId }) }, 'See in audit');

  async function decide(decision) {
    if (busy) return;
    busy = true; update(true);
    try { await ctx.decide(action, decision); } finally { busy = false; update(true); }
  }

  function render(state, st, mode) {
    const head = h('header', null,
      state === 'running' ? h('span', { class: 'spinner', role: 'img', 'aria-label': 'Running' }) : null,
      h('h4', { class: 'grow' }, action.label || 'Action'),
      h('span', { class: 'tag risk ' + risk.cls }, risk.word),
      h('span', { class: action.reversible ? 'muted rev' : 'danger-text rev' }, action.reversible ? 'reversible' : 'not reversible'));
    el.className = 'action s-' + state + (action.risk === 'destructive' ? ' destructive' : '');
    const kids = [head];
    const foot = (...x) => h('div', { class: 'a-foot' }, x);
    switch (state) {
      case 'proposed': case 'blocked': {
        kids.push(...details());
        const needType = action.risk === 'destructive';
        const target = G.device(action.target);
        const name = target ? target.name : (action.target || '');
        const ok = () => !busy && !get().serverDown && state === 'proposed' && (!needType || typed.trim().toLowerCase() === name.toLowerCase());
        const approve = h('button', { class: 'btn ' + (needType ? 'danger' : 'primary'), type: 'button', disabled: !ok(), onClick: () => decide('approve') },
          busy ? h('span', { class: 'spinner' }) : null, needType ? 'Approve and run, not reversible' : 'Approve and run');
        if (needType && action.reversible) approve.lastChild.textContent = 'Approve and run, destructive';
        const reject = h('button', { class: 'btn', type: 'button', disabled: busy, onClick: () => decide('reject') }, 'Reject');
        if (needType) kids.push(h('div', { class: 'a-row confirm' }, h('span', { class: 'k' }, 'Confirm'), h('div', { class: 'v' },
          h('label', { for: 'cf-' + action.id }, 'Type the target’s name, ', h('b', null, name), ', to enable approval.'),
          h('input', { class: 'input', id: 'cf-' + action.id, value: typed, autocomplete: 'off', spellcheck: 'false', placeholder: name, onInput: e => { typed = e.target.value; approve.disabled = !ok(); } }))));
        kids.push(foot(get().serverDown ? h('span', { class: 'muted grow' }, 'The server cannot be reached, so nothing can be run.') : state === 'blocked' ? h('span', { class: 'muted grow' }, 'Another action is running.') : h('span', { class: 'muted grow hint' }, 'Runs exactly as shown, on this computer, only when you approve.'), reject, approve));
        break;
      }
      case 'advise':
        kids.push(...details(), foot(h('span', { class: 'grow' }, 'Advise only: copy the command to run it yourself. Switch the mode to Approve to run it from here.'), copyBtn(action.command || '', 'Copy command', { cls: 'btn' })));
        break;
      case 'paused':
        kids.push(...details(), foot(h('span', { class: 'grow' }, 'The agent is paused.'), h('button', { class: 'btn', disabled: true }, 'Reject'), h('button', { class: 'btn primary', disabled: true }, 'Approve and run')));
        break;
      case 'copy-only': case 'refused':
        kids.push(...details(), foot(h('span', { class: 'grow' }, icon('lock', 14), h('span', null,
          state === 'copy-only' ? 'This runs only if you type it yourself in Terminal.' : 'Refused in code: the agent cannot run this.',
          (st.refusal || action.refusal) ? h('span', { class: 'muted' }, ' ' + (st.refusal || action.refusal)) : null)),
          copyBtn(action.command || '', 'Copy command', { cls: 'btn' })));
        break;
      case 'running':
        kids.push(...details(), outEl, foot(h('span', { class: 'grow' }, 'Running…'), h('button', { class: 'linkbtn', onClick: () => ctx.stop && ctx.stop(run) }, 'Stop'), auditLink()));
        break;
      case 'done': case 'failed': {
        const okk = state === 'done';
        const tm = st.finishedAt || st.decidedAt;
        kids.push(h('div', { class: 'a-result ' + (okk ? 'ok' : 'bad') }, icon(okk ? 'check' : 'cross', 14),
          h('span', null, okk ? `Ran${tm ? ' at ' + clock(tm) : ''} · exit ${st.exitCode == null ? 0 : st.exitCode}` : `Failed · exit ${st.exitCode == null ? 'not known' : st.exitCode}`)));
        kids.push(...details());
        const n = (st.output || []).length;
        if (n) {
          outEl.classList.toggle('tail', okk && !showAllOut && n > 6);
          kids.push(outEl);
          if (okk && n > 6) kids.push(h('button', { class: 'linkbtn', style: { margin: '0 12px 8px' }, onClick: () => { showAllOut = !showAllOut; update(true); } }, showAllOut ? 'Show the last 6 lines' : `Show all ${n} lines`));
        } else kids.push(h('p', { class: 'muted', style: { padding: '0 12px 8px', fontSize: '12px' } }, 'The command printed nothing.'));
        kids.push(foot(h('span', { class: 'grow' }), okk && action.reversible && action.undo ? h('button', { class: 'btn sm', onClick: () => ctx.undo && ctx.undo(action) }, icon('undo', 14), 'Undo') : null, auditLink()));
        break;
      }
      case 'interrupted':
        kids.push(callout('caution', 'The server stopped while this was running. Whether the command finished is not known. Check the device before trying again.'), ...details(), foot(h('span', { class: 'grow' }), auditLink()));
        break;
      case 'rejected': {
        el.className += ' line';
        fill(el, h('div', { class: 'one' }, icon('cross', 14), h('span', { class: 'grow ellipsis' }, `Rejected by you${st.decidedAt ? ' at ' + clock(st.decidedAt) : ''} · ${action.label || ''}`),
          h('button', { class: 'linkbtn', 'aria-expanded': String(showCmd), onClick: () => { showCmd = !showCmd; update(true); } }, showCmd ? 'Hide command' : 'Show command'), auditLink()), showCmd ? cmdBlock() : null);
        return;
      }
      case 'superseded':
        el.className += ' line';
        fill(el, h('div', { class: 'one muted' }, h('span', { class: 'grow ellipsis' }, 'No longer proposed · ' + (action.label || ''))));
        return;
      default:
        kids.push(...details());
    }
    const hadFocus = el.contains(document.activeElement) && document.activeElement.id;
    fill(el, kids);
    if (hadFocus) { const f = document.getElementById(hadFocus); f && f.focus(); }
  }

  function update(force) {
    const st = (run.actions && run.actions[action.id]) || {};
    const mode = ctx.fixture ? (action._mode || 'approve') : ((get().settings || {}).agentMode || 'advise');
    const otherRunning = ctx.anyRunning ? ctx.anyRunning(action.id) : false;
    const state = cardState(action, st, mode, otherRunning);
    const nsig = [state, st.exitCode, st.refusal, st.decidedAt, get().serverDown].join('|');
    if (force || nsig !== sig) { sig = nsig; render(state, st, mode); lines = -1; }
    const out = st.output || [];
    if (lines === -1) { outEl.replaceChildren(); lines = 0; }
    for (; lines < out.length; lines++) outEl.appendChild(h('span', { class: out[lines].stream === 'stderr' ? 'err' : '' }, out[lines].text + '\n'));
    if (follow && outEl.isConnected) outEl.scrollTop = outEl.scrollHeight;
  }
  update(true);
  return { el, update, id: action.id };
}

export { FINAL, statusGlyph, set, select, plural, tip };
