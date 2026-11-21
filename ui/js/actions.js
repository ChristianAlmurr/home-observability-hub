// What the person can do to a device: say what it is, scan it, have the agent look, block or unblock it at the
// router, remove it. The list comes from the server (GET /api/device/<id>/actions) with, for each action, whether
// it is available and what it will do. Nothing here runs without one confirmation that states the effect and the undo.
import { h, fill, isPhone } from './dom.js';
import { icon, kindIcon } from './icons.js';
import { get, go, clearSelection } from './store.js';
import { api, demoMode } from './api.js';
import * as G from './graph.js';
import { dialog, popover, tip, toast, callout, statusGlyph, hideTip } from './ui.js';
import { KIND, kindLabel, flatten } from './fmt.js';

const ORDER = ['identify', 'scan', 'investigate', 'block', 'unblock', 'forget'];
const ICON = { identify: 'identify', scan: 'scan', investigate: 'investigate', block: 'block', unblock: 'unblock', forget: 'forget' };
const SHORT = { identify: 'Identify', scan: 'Deep scan', investigate: 'Investigate', block: 'Block', unblock: 'Unblock', forget: 'Remove' };
const RISK = { read: ['reads only', ''], change: ['changes something', 'caution'], destructive: ['destructive', 'danger'] };
/** What happened, named: used when the server sends no message of its own. */
const DONE = { identify: n => 'Saved what ' + n + ' is.', scan: n => 'Deep scan of ' + n + ' finished.', investigate: n => 'The agent is investigating ' + n + '.', block: n => n + ' is blocked at the router.', unblock: n => n + ' is unblocked at the router.', forget: n => n + ' was removed from the inventory.' };
const FAILED = { identify: () => 'Not saved.', scan: () => 'The scan did not run.', investigate: () => 'The agent did not start.', block: n => n + ' was not blocked.', unblock: n => n + ' was not unblocked.', forget: n => n + ' was not removed.' };
function doneText(a, name, r) {
  if ((a.id === 'block' || a.id === 'unblock') && r && r.verified === false) return (SHORT[a.id] || a.label) + ' sent for ' + name + ', but the router did not confirm it. Check it on the map.';
  return DONE[a.id] ? DONE[a.id](name) : (SHORT[a.id] || a.label) + ': done.';
}
const DOING = { identify: 'Saving…', scan: 'Scanning… this can take a minute', investigate: 'Starting the agent…', block: 'Asking the router…', unblock: 'Asking the router…', forget: 'Removing…' };

const cache = new Map();   // id → { list, error, at, promise, missing }
const waiting = new Map(); // id → Set of callbacks to run when the list arrives

/** What to show when the server has no actions route yet: the same six, all unavailable, saying why. */
function unavailableList(id, why) {
  const name = G.deviceName(id);
  const mk = (aid, label, risk, reversible) => ({ id: aid, label, risk, reversible, available: false, unavailableReason: why, confirm: { title: label + ': ' + name, effect: '', undo: '' } });
  return [mk('identify', 'Say what it is', 'change', true), mk('scan', 'Deep scan', 'read', true), mk('investigate', 'Ask the agent to investigate', 'read', true),
    mk('block', 'Block at the router', 'change', true), mk('forget', 'Remove from the inventory', 'destructive', false)];
}

export function loadActions(id, force) {
  const c = cache.get(id) || {};
  if (c.promise) return c.promise;
  if (!force && c.list && Date.now() - c.at < 8000) return Promise.resolve(c.list);
  const promise = api.deviceActions(id).then(list => {
    const sorted = (Array.isArray(list) ? list : []).slice().sort((a, b) => (ORDER.indexOf(a.id) + 99) % 99 - (ORDER.indexOf(b.id) + 99) % 99);
    cache.set(id, { list: sorted, at: Date.now() });
    return sorted;
  }).catch(e => {
    const missing = e.status === 404;
    const list = unavailableList(id, missing ? 'This server does not offer device actions yet.' : 'The list of actions could not be loaded: ' + e.message);
    cache.set(id, { list, at: Date.now() - (missing ? 0 : 6000), error: e.message, missing });
    return list;
  }).then(list => { for (const fn of waiting.get(id) || []) fn(list); waiting.delete(id); return list; });
  cache.set(id, { ...c, promise });
  return promise;
}
export function invalidateActions(id) { if (id) cache.delete(id); else cache.clear(); }
const cached = id => (cache.get(id) || {}).list || null;

function whenLoaded(id, el, draw) {
  loadActions(id).then(list => { if (el.isConnected || !el._drawn) { el._drawn = true; draw(list); } });
}

function reasonNode(a) {
  const text = a.unavailableReason || 'Not available for this device.';
  if (/router login/i.test(text)) return h('span', null, text.replace(/\s*Add it in Settings\.?$/i, '') + ' ', h('button', { class: 'linkbtn', type: 'button', onClick: e => { e.stopPropagation(); go({ view: 'settings', sel: [], panel: null }); } }, 'Add it in Settings'));
  return h('span', null, text);
}

function press(id, a, anchor) {
  hideTip();
  if (!a.available) {
    if (anchor && !isPhone()) { popover(anchor, h('div', { class: 'why' }, h('b', null, a.label + ' is not available'), h('p', null, reasonNode(a))), { cls: 'why-pop' }); return; }
    toast(h('span', null, h('b', null, a.label + ': '), reasonNode(a)), { intent: 'caution' });
    return;
  }
  confirmAction(id, a);
}

/** A row of buttons: every action is there; one that cannot be used says why instead of hiding. */
export function actionBar(id, { labels = true, only = null, cls = '' } = {}) {
  const el = h('div', { class: 'actbar ' + cls, role: 'group', 'aria-label': 'Actions for ' + G.deviceName(id) });
  const draw = list => {
    const items = only ? list.filter(a => only.includes(a.id)) : list;
    fill(el, items.map(a => {
      const b = h('button', { class: 'act r-' + a.risk + (a.available ? '' : ' off'), type: 'button', 'aria-disabled': a.available ? null : 'true', dataset: { action: a.id },
        // with a visible word the name starts with it (WCAG 2.5.3); icon-only buttons carry the server's full label
        'aria-label': (labels ? SHORT[a.id] || a.label : a.label) + (a.available ? '' : ' (not available: ' + (a.unavailableReason || '') + ')'), onClick: e => { e.stopPropagation(); press(id, a, b); } },
        icon(ICON[a.id] || 'chevron', 14), labels ? h('span', null, SHORT[a.id] || a.label) : null);
      tip(b, a.available ? a.label : h('span', null, h('span', { class: 't-title' }, a.label + ': not available'), h('span', { class: 't-line' }, a.unavailableReason || '')));
      return b;
    }));
  };
  if (cached(id)) draw(cached(id)); else fill(el, h('span', { class: 'act ghost' }, h('span', { class: 'spinner' }), labels ? 'Loading actions' : null));
  whenLoaded(id, el, draw);
  return el;
}

/** The full list for the inspector: label, what kind of change it is, and the reason when it cannot be used. */
export function actionRows(id) {
  const el = h('div', { class: 'actrows' });
  const draw = list => fill(el, list.map(a => {
    const [word, rcls] = RISK[a.risk] || RISK.change;
    const row = h('button', { class: 'actrow r-' + a.risk + (a.available ? '' : ' off'), type: 'button', 'aria-disabled': a.available ? null : 'true', dataset: { action: a.id }, onClick: () => press(id, a, null) },
      h('span', { class: 'ic-w' }, icon(ICON[a.id] || 'chevron')),
      h('span', { class: 'grow' }, h('span', { class: 'l' }, h('span', null, a.label), h('span', { class: 'rk ' + rcls }, word)), a.available ? null : h('span', { class: 'why' }, reasonNode(a))),
      a.available ? icon('chevron', 14, 'go') : icon('lock', 14, 'go'));
    return row;
  }));
  if (cached(id)) draw(cached(id)); else fill(el, h('div', { class: 'skel-rows', style: { padding: 0 } }, [0, 1, 2].map(() => h('span', { class: 'skel w60' }))));
  whenLoaded(id, el, draw);
  return el;
}

/** Right-click on a node: the same actions, as a menu at the pointer. */
export function openDeviceMenu(id, x, y, extra = []) {
  const d = G.device(id); if (!d) return;
  const anchor = h('span', { style: { position: 'fixed', left: x + 'px', top: y + 'px', width: '1px', height: '1px' } });
  document.body.appendChild(anchor);
  const list = h('div', { class: 'menu devmenu', role: 'menu' });
  let p = null;
  const draw = acts => {
    fill(list, h('div', { class: 'mh' }, h('span', { class: 'k' }, kindIcon(d.kind, 14)), h('span', { class: 'ellipsis' }, d.name)),
      acts.map(a => h('button', { class: 'r-' + a.risk + (a.available ? '' : ' off'), role: 'menuitem', type: 'button', 'aria-disabled': a.available ? null : 'true', onClick: () => { p && p.close(); if (a.available) confirmAction(id, a); else toast(h('span', null, h('b', null, a.label + ': '), reasonNode(a)), { intent: 'caution' }); } },
        icon(ICON[a.id] || 'chevron'), h('span', { class: 'grow' }, h('span', null, a.label), a.available ? null : h('span', { class: 'why' }, a.unavailableReason || ''))),
      ), extra.length ? h('div', { class: 'sep' }) : null,
      extra.map(x2 => h('button', { role: 'menuitem', type: 'button', onClick: () => { p && p.close(); x2.run(); } }, icon(x2.icon || 'chevron'), h('span', { class: 'grow' }, x2.label))));
    p && p.place();
  };
  list.addEventListener('keydown', e => {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) return;
    const items = [...list.querySelectorAll('[role="menuitem"]')];
    const i = items.indexOf(document.activeElement);
    const n = e.key === 'Home' ? items[0] : e.key === 'End' ? items[items.length - 1] : items[(i + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length];
    if (n) { n.focus(); e.preventDefault(); }
  });
  draw(cached(id) || []);
  p = popover(anchor, list, { cls: 'menu-pop', label: 'Actions for ' + d.name });
  const close = p.close;
  p.close = () => { close(); anchor.remove(); };
  loadActions(id).then(acts => { if (list.isConnected) draw(acts); });
  const mo = new MutationObserver(() => { if (!list.isConnected) { anchor.remove(); mo.disconnect(); } });
  mo.observe(document.body, { childList: true });
}

// ---------------------------------------------------------------- confirmation

function identifyForm(d) {
  const idn = G.identityOf(d);
  const cand = idn.candidates[0] || {};
  const kinds = Object.keys(KIND).filter(k => k !== 'unknown' && k !== 'internet').sort((a, b) => kindLabel(a).localeCompare(kindLabel(b)));
  const guessKind = d.kind !== 'unknown' ? d.kind : kinds.find(k => (cand.type || idn.type || '').toLowerCase().includes(kindLabel(k).toLowerCase())) || '';
  const f = {
    name: h('input', { class: 'input', type: 'text', name: 'name', value: d.dynamic && /^host /i.test(d.name) ? '' : d.name, placeholder: 'What you call it, for example “Hallway plug”', required: true, autocomplete: 'off' }),
    vendor: h('input', { class: 'input', type: 'text', name: 'vendor', value: idn.vendor || d.vendor || '', placeholder: 'Maker', autocomplete: 'off' }),
    model: h('input', { class: 'input', type: 'text', name: 'model', value: idn.model || G.shortModel(d.model) || '', placeholder: 'Model', autocomplete: 'off' }),
    kind: h('select', { class: 'select', name: 'kind' }, h('option', { value: '' }, 'Choose a kind'), kinds.map(k => h('option', { value: k, selected: k === guessKind }, kindLabel(k)))),
    zone: h('select', { class: 'select', name: 'zone' }, G.groups().filter(g => g.id !== 'outside').map(g => h('option', { value: g.id, selected: g.id === d.zone }, g.label))),
  };
  const field = (label, input, hint) => h('label', { class: 'field' }, h('span', { class: 'fl' }, label), input, hint ? h('span', { class: 'fh' }, hint) : null);
  const cands = idn.candidates.filter(c => c.vendor || c.model);
  const el = h('div', { class: 'idform' },
    cands.length ? h('div', { class: 'cands' }, h('span', { class: 'fl' }, 'Fill in from a guess'), h('div', { class: 'chips' }, cands.map(c => {
      const b = h('button', { class: 'chip', type: 'button', onClick: () => { f.vendor.value = c.vendor || ''; f.model.value = c.model || ''; const k = kinds.find(x => (c.type || '').toLowerCase().includes(kindLabel(x).toLowerCase())); if (k) f.kind.value = k; if (!f.name.value) f.name.focus(); } },
        [c.vendor, c.model].filter(Boolean).join(' '), h('span', { class: 'muted' }, c.confidence || ''));
      tip(b, c.basis || '');
      return b;
    }))) : null,
    field('Name', f.name), h('div', { class: 'two' }, field('Maker', f.vendor), field('Model', f.model)), h('div', { class: 'two' }, field('Kind', f.kind), field('Room', f.zone)));
  return { el, values: () => ({ name: f.name.value.trim(), vendor: f.vendor.value.trim(), model: f.model.value.trim(), kind: f.kind.value, zone: f.zone.value }), valid: () => f.name.value.trim().length > 0, focus: () => f.name.focus(),
    invalid: id => { f.name.setAttribute('aria-invalid', 'true'); f.name.setAttribute('aria-describedby', id); f.name.addEventListener('input', () => f.name.removeAttribute('aria-invalid'), { once: true }); f.name.focus(); } };
}

function resultView(a, res, name) {
  const r = res.result;
  const out = [];
  const msg = r && typeof r === 'object' ? r.message : typeof r === 'string' ? r : null;
  const pre = (label, v) => (v && (Array.isArray(v) ? v.length : true) ? h('div', { class: 'cmds' }, h('span', { class: 'fl' }, label), h('pre', null, Array.isArray(v) ? v.map(x => (typeof x === 'string' ? x : JSON.stringify(x))).join('\n') : String(v))) : null);
  if (r && r.dryRun) {
    out.push(h('div', { class: 'res dry' }, icon('info'), h('span', null, h('b', null, 'Rehearsal: nothing was changed. '), r.rehearsal || 'Changes at the router are switched off in Settings.')),
      pre('What would be sent to the router', r.commands), pre('What would undo it', r.undo));
    return out;
  }
  out.push(h('div', { class: 'res ok' }, icon('check'), h('span', null, msg || doneText(a, name, r) + (r && r.verified === true ? ' The router confirms it.' : ''))));
  if (r && (r.commands || r.backup)) out.push(pre('Sent to the router', r.commands), pre('How to undo', r.undo), r.backup ? h('p', { class: 'muted small' }, 'Backup: ' + r.backup) : null);
  const evs = r && (Array.isArray(r.newEvidence) && r.newEvidence.length ? r.newEvidence : r.evidence);
  if (r && r.newEvidence && !r.newEvidence.length) out.push(h('p', { class: 'muted small' }, 'The scan found nothing new.'));
  if (r && Array.isArray(evs) && evs.length) out.push(h('div', { class: 'ev-list2' }, evs.slice(0, 12).map(e => h('div', { class: 'evi' }, h('span', { class: 'src' }, e.source || 'probe'), h('span', { class: 'grow' }, h('b', null, e.label || ''), ' ', e.value || '')))));
  else if (r && typeof r === 'object') {
    const rows = flatten(Object.fromEntries(Object.entries(r).filter(([k]) => !['message', 'runId', 'evidence', 'device', 'deviceId', 'commands', 'undo', 'backup', 'dryRun', 'changed', 'verified', 'identity', 'newEvidence', 'rehearsal'].includes(k))));
    if (rows.length) out.push(h('div', { class: 'props' }, rows.map(([k, v]) => h('div', { class: 'prop no-copy' }, h('div', { class: 'k' }, k), h('div', { class: 'v mono' }, v), h('div', { class: 't' })))));
  }
  return out;
}

export function confirmAction(id, a) {
  const d = G.device(id);
  if (!d) return;
  const [riskWord, riskCls] = RISK[a.risk] || RISK.change;
  const form = a.id === 'identify' ? identifyForm(d) : null;
  const c = a.confirm || {};
  const ip = G.primaryIp(d);
  const rehearse = (a.id === 'block' || a.id === 'unblock') && (get().settings || {}).routerWrites === false && !demoMode();
  const foot = h('div', { class: 'cf-foot' });
  const note = h('div', { class: 'cf-note' });
  const body = h('div', { class: 'body confirm-act r-' + a.risk },
    h('div', { class: 'cf-target' }, h('span', { class: 'k' }, kindIcon(d.kind)), h('span', { class: 'grow' }, h('b', null, d.name), h('span', { class: 'muted' }, [G.brandOf(d) || G.ID_WORD[G.identityOf(d).state] || '', ip].filter(Boolean).join(' · '))), statusGlyph(G.statusOf(id)),
      rehearse ? h('span', { class: 'tag dry' }, 'rehearsal only') : h('span', { class: 'tag ' + riskCls }, riskWord)),
    h('dl', { class: 'cf-dl' },
      h('dt', null, 'What happens'), h('dd', null, c.effect || 'The server did not describe this action.'),
      h('dt', null, 'Undo'), h('dd', { class: a.reversible ? '' : 'no-undo' }, c.undo || (a.reversible ? 'It can be reversed.' : 'It cannot be undone from the app.'))),
    form ? form.el : null, note, foot);
  let dlg = null, busy = false;
  const cancel = h('button', { class: 'btn', type: 'button', onClick: () => dlg.close() }, 'Cancel');
  const okBtn = h('button', { class: 'btn ' + (a.risk === 'destructive' ? 'danger' : 'primary'), type: 'button', onClick: run }, icon(ICON[a.id] || 'check', 14), a.id === 'identify' ? 'Save what it is' : rehearse ? (a.id === 'block' ? 'Rehearse the block' : 'Rehearse the unblock') : a.label);
  fill(foot, rehearse ? h('span', { class: 'grow muted small' }, 'Changes at the router are off in Settings: this shows what would be sent.') : a.risk === 'destructive' || !a.reversible ? h('span', { class: 'grow warn' }, icon('warning', 14), 'This cannot be undone from the app.') : h('span', { class: 'grow' }), cancel, okBtn);

  async function run() {
    if (busy) return;
    if (form && !form.valid()) { fill(note, callout('caution', h('span', { id: 'cf-name-err' }, 'Give it a name first, for example “Hallway plug”.'))); form.invalid('cf-name-err'); return; }
    busy = true;
    okBtn.disabled = true; cancel.disabled = true;
    fill(okBtn, h('span', { class: 'spinner' }), DOING[a.id] || 'Working…');
    fill(note);
    let res;
    try { res = await api.deviceAction(id, { action: a.id, params: form ? form.values() : {}, confirm: true }); }
    catch (e) { res = { ok: false, error: e.message }; }
    busy = false;
    invalidateActions(id);
    if (!res || res.ok === false) {
      okBtn.disabled = false; cancel.disabled = false;
      fill(okBtn, icon(ICON[a.id] || 'check', 14), 'Try again');
      fill(note, callout('danger', h('b', null, (FAILED[a.id] ? FAILED[a.id](d.name) : (SHORT[a.id] || a.label) + ' did not happen.') + ' '), (res && res.error) || 'The server gave no reason.'));
      return;
    }
    const runId = res.result && res.result.runId;
    const dry = !!(res.result && res.result.dryRun);
    const done = h('button', { class: 'btn primary', type: 'button', onClick: () => { dlg.close(); if (runId) go({ view: 'agent', run: runId, sel: [], panel: null, fixture: demoMode() > 0 }); } }, runId ? 'Open the run' : 'Done');
    fill(body, body.querySelector('.cf-target'), h('div', { class: 'cf-result' }, resultView(a, res, a.id === 'identify' && form ? form.values().name || d.name : d.name)), h('div', { class: 'cf-foot' }, h('span', { class: 'grow muted' }, dry ? 'The rehearsal is in the audit log.' : 'Written to the audit log.'), runId ? h('button', { class: 'btn', onClick: () => dlg.close() }, 'Stay here') : null, done));
    done.focus();
    toast(dry ? (SHORT[a.id] || a.label) + ' of ' + d.name + ' was rehearsed. Nothing was changed at the router.' : (res.result && res.result.message) || doneText(a, a.id === 'identify' && form ? form.values().name || d.name : d.name, res.result), { intent: dry ? 'caution' : 'success' });
    if (a.id === 'forget' && get().route.sel.includes(id)) clearSelection();
    window.__hmReload && window.__hmReload();
  }
  dlg = dialog({ title: c.title || a.label, body, cls: 'cf r-' + a.risk });
  if (form) form.focus();
  return dlg;
}
