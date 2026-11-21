// The agent surface: ask box with scope, the live trace from the stream, the answer, action
// decisions, threads and run history. The agent only proposes; this module never approves by itself.
import { h, fill, isPhone, isTyping } from './dom.js';
import { icon } from './icons.js';
import { get, set, on, go } from './store.js';
import { api } from './api.js';
import * as G from './graph.js';
import { deviceChip, callout, toast, tip, popover, dialog, skeleton, errorState, emptyState, statusGlyph } from './ui.js';
import { renderAnswer, createActionCard, pinFor } from './answer.js';
import { relTime, absTime, clock, duration, hostOf, plural, toMs } from './fmt.js';
import { fixtureRuns } from './fixture.js';

const PHASES = [['identify', 'Identify'], ['read-docs', 'Read docs'], ['inspect', 'Inspect'], ['research', 'Research'], ['answer', 'Answer']];
const streams = new Map();   // runId → EventSource
const loading = new Set();
let bumpQueued = false;

const A = () => get().agent;
const runOf = id => A().runs[id] || null;
const mode = () => (get().settings || {}).agentMode || 'advise';

function bump() {
  if (bumpQueued) return;
  bumpQueued = true;
  requestAnimationFrame(() => { bumpQueued = false; set({ agent: { ...A() } }); });
}

function newRun(base) {
  return { runId: base.runId, threadId: base.threadId || null, question: base.question || '', deviceIds: base.deviceIds || [], status: base.status || 'running',
    startedAt: base.startedAt || new Date().toISOString(), endedAt: base.endedAt || null, error: base.error || null, model: base.model || null,
    phase: null, phases: [], activities: [], answer: null, answerV: 0, actions: {}, errors: [], lastSeq: 0, stream: 'idle', loaded: false, fixture: !!base.fixture };
}

function applyEvent(run, type, data, ts, seq) {
  if (seq) { if (seq <= run.lastSeq) return; run.lastSeq = seq; }
  data = data || {};
  switch (type) {
    case 'phase':
      run.phase = data.phase; if (!run.phases.includes(data.phase)) run.phases.push(data.phase); run.phaseText = data.text || '';
      break;
    case 'activity': run.activities.push({ tool: data.tool, text: data.text || data.tool || 'Working', detail: data.detail || null, ts: ts || new Date().toISOString() }); break;
    case 'answer': {
      const prev = run.answer;
      run.answer = data; run.answerV++;
      const ids = new Set((data.actions || []).map(a => a.id));
      for (const a of data.actions || []) {
        const cur = run.actions[a.id] || { output: [] };
        if (!cur.state || cur.state === 'proposed' || cur.state === 'superseded') cur.state = a.state || 'proposed';
        if (a.refusal) cur.refusal = a.refusal;
        cur.def = a;
        run.actions[a.id] = cur;
      }
      if (prev) for (const a of prev.actions || []) if (!ids.has(a.id) && run.actions[a.id] && ['proposed', 'refused', 'copy-only'].includes(run.actions[a.id].state)) run.actions[a.id].state = 'superseded';
      break;
    }
    case 'action-output': {
      const a = run.actions[data.actionId] || (run.actions[data.actionId] = { output: [] });
      a.output.push({ stream: data.stream === 'stderr' ? 'stderr' : 'stdout', text: String(data.text == null ? '' : data.text) });
      if (!['done', 'failed'].includes(a.state)) a.state = 'running';
      break;
    }
    case 'action-result': {
      const a = run.actions[data.actionId] || (run.actions[data.actionId] = { output: [] });
      a.state = data.ok ? 'done' : 'failed'; a.exitCode = data.exitCode; a.finishedAt = ts || new Date().toISOString();
      break;
    }
    case 'error': run.errors.push(String(data.text || 'The agent reported an error.')); break;
    case 'done':
      run.doneSeen = true;
      if (run.status === 'running') run.status = data.ok ? 'done' : 'error';
      run.endedAt = run.endedAt || ts || new Date().toISOString();
      break;
    default: break;
  }
}

function fromRecord(rec) {
  const run = runOf(rec.runId) || newRun(rec);
  for (const ev of rec.events || []) applyEvent(run, ev.type, ev.data, ev.ts, ev.seq);
  Object.assign(run, { threadId: rec.threadId, question: rec.question, deviceIds: rec.deviceIds || [], status: rec.status, startedAt: rec.startedAt, endedAt: rec.endedAt, error: rec.error, model: rec.model, loaded: true });
  if (rec.answer && !run.answer) applyEvent(run, 'answer', rec.answer);
  for (const [id, a] of Object.entries(rec.actions || {})) {
    const cur = run.actions[id] || (run.actions[id] = { output: [] });
    if (cur.state !== 'superseded') cur.state = a.state || cur.state;
    cur.exitCode = a.exitCode != null ? a.exitCode : cur.exitCode; cur.decidedAt = a.decidedAt || cur.decidedAt; cur.refusal = a.refusal || cur.refusal;
  }
  A().runs[run.runId] = run;
  return run;
}

function wantsStream(run) {
  if (run.fixture) return false;
  if (run.status === 'running') return true;
  const acts = Object.values(run.actions);
  if (acts.some(a => a.state === 'running' || a.state === 'approved')) return true;
  return false;
}

function openStream(runId) {
  if (streams.has(runId)) return;
  const run = runOf(runId);
  if (!run || run.fixture) return;
  let es;
  try { es = new EventSource(api.streamUrl(runId)); } catch { run.stream = 'lost'; bump(); return; }
  streams.set(runId, es);
  run.stream = 'connecting'; bump();
  const handle = type => e => {
    let data = null;
    try { data = JSON.parse(e.data); } catch { return; }
    const seq = parseInt(e.lastEventId, 10) || 0;
    applyEvent(run, type, data, null, seq);
    if (type === 'answer' && isCurrent(runId)) autoPin(run);
    if (type === 'done') refreshRuns();
    if (type === 'action-result' || type === 'done') { if (!wantsStream(run)) closeStream(runId); }
    bump();
  };
  for (const t of ['phase', 'activity', 'answer', 'action-output', 'action-result', 'error', 'done']) es.addEventListener(t, handle(t));
  es.onopen = () => { run.stream = 'open'; bump(); };
  es.onerror = () => {
    // The server closes the stream when nothing more can come; the browser would retry forever.
    if (!wantsStream(run)) { closeStream(runId); bump(); return; }
    run.stream = 'reconnecting'; bump();
    if (es.readyState === 2) { streams.delete(runId); setTimeout(() => { if (wantsStream(run)) openStream(runId); }, 3000); }
    // if the run ended while we were away, the record says so
    api.run(runId).then(rec => { fromRecord(rec); if (!wantsStream(runOf(runId))) closeStream(runId); bump(); }).catch(() => {});
  };
}
function closeStream(runId) {
  const es = streams.get(runId);
  if (es) { es.close(); streams.delete(runId); }
  const run = runOf(runId);
  if (run) run.stream = 'idle';
}

export async function loadRun(runId, force) {
  if (!runId || loading.has(runId)) return;
  const have = runOf(runId);
  if (have && have.fixture) return;
  if (have && have.loaded && !force) { if (wantsStream(have)) openStream(runId); return; }
  loading.add(runId);
  try {
    const rec = await api.run(runId);
    const run = fromRecord(rec);
    run.loadError = null;
    if (wantsStream(run)) openStream(runId);
  } catch (e) {
    const run = have || newRun({ runId, status: 'error' });
    run.loadError = e.message; run.loaded = false; A().runs[runId] = run;
  } finally { loading.delete(runId); bump(); }
}

export async function refreshRuns() {
  try { const list = await api.runs(50); set({ agent: { ...A(), list, listError: null } }); }
  catch (e) { set({ agent: { ...A(), listError: e.message } }); }
}

function isCurrent(runId) { return get().route.run === runId; }
function autoPin(run) { const p = pinFor(run); if (p) set({ pin: p }); }

export function threadRuns(threadId) {
  if (!threadId) return [];
  const ids = new Set();
  for (const r of Object.values(A().runs)) if (r.threadId === threadId) ids.add(r.runId);
  for (const r of A().list || []) if (r.threadId === threadId) ids.add(r.runId);
  return [...ids].map(id => runOf(id) || newRun((A().list || []).find(x => x.runId === id))).sort((a, b) => (toMs(a.startedAt) || 0) - (toMs(b.startedAt) || 0));
}

export function activeRun() {
  return Object.values(A().runs).find(r => !r.fixture && (r.status === 'running' || Object.values(r.actions).some(a => a.state === 'running'))) || null;
}

/** Open the agent with these devices in scope (and optionally a draft question). */
export function askAbout(ids, text) {
  const a = A();
  set({ agent: { ...a, scope: [...new Set(ids.filter(G.isDeviceId))], draft: text != null ? text : a.draft, focusAsk: Date.now(), fresh: true } });
  if (isPhone() || get().route.view === 'agent') go({ view: 'agent', run: null, sel: isPhone() ? [] : get().route.sel });
  else go({ panel: 'agent', run: null });
}

export async function ask(message, deviceIds, threadId) {
  const res = await api.ask(message, deviceIds, threadId);
  const run = newRun({ runId: res.runId, threadId: res.threadId, question: message, deviceIds });
  A().runs[run.runId] = run;
  set({ agent: { ...A(), draft: '', fresh: false }, pin: null });
  go({ run: run.runId });
  openStream(run.runId);
  refreshRuns();
  return run;
}

export async function stopEverything() {
  const run = activeRun();
  let stopped = false;
  if (run) { try { await api.cancel(run.runId); stopped = true; } catch (e) { toast('Could not stop the run: ' + e.message, { intent: 'danger' }); } }
  try { const s = await api.saveSettings({ agentMode: 'paused' }); set({ settings: s }); toast(stopped ? 'Stopped. The agent is paused.' : 'The agent is paused. Nothing was running.', { intent: 'caution' }); }
  catch (e) { toast('Could not pause the agent: ' + e.message, { intent: 'danger' }); }
  if (run) loadRun(run.runId, true);
}

async function cancelRun(run) {
  try { await api.cancel(run.runId); toast('Cancel requested.', { intent: 'info' }); loadRun(run.runId, true); }
  catch (e) { toast('Could not cancel: ' + e.message, { intent: 'danger' }); }
}

// ---------------------------------------------------------------- the thread view

function toolIcon(tool) {
  if (/^(Read|Glob|Grep)$/i.test(tool || '')) return 'file';
  if (/^Web/i.test(tool || '')) return 'web';
  if (/^Bash$/i.test(tool || '')) return 'terminal';
  return 'chip';
}

function traceSummary(run) {
  const n = run.activities.length;
  const docs = run.activities.filter(a => /guide|specs/i.test(a.text) && /^Read$/i.test(a.tool || '')).length;
  const cmds = run.activities.filter(a => /^Bash$/i.test(a.tool || '')).length;
  const web = run.activities.filter(a => /^Web/i.test(a.tool || '')).length;
  const secs = run.endedAt && run.startedAt ? (toMs(run.endedAt) - toMs(run.startedAt)) / 1000 : null;
  return [secs != null ? 'Worked for ' + duration(secs) : 'Worked', plural(n, 'step'), docs ? 'read ' + plural(docs, 'knowledge file') : null,
    cmds ? 'ran ' + plural(cmds, 'read-only command') : null, web ? plural(web, 'web lookup') : null].filter(Boolean).join(' · ');
}

function createRunView(run0, ctx) {
  const el = h('section', { class: 'run', dataset: { run: run0.runId } });
  const qEl = h('div', { class: 'run-q' });
  const traceEl = h('div', { class: 'trace' });
  const railEl = h('div', { class: 'rail-row' });
  const rowsEl = h('div', { class: 'act-rows' });
  const noteEl = h('div', { class: 'run-notes' });
  const ansEl = h('div', { class: 'run-a' });
  el.append(qEl, traceEl, noteEl, ansEl);
  let rows = 0, answerV = -1, cards = new Map(), traceOpen = null, lastSig = '', qSig = '';

  function update(run) {
    const sigQ = run.question + '|' + run.deviceIds.join(',') + '|' + run.startedAt;
    if (sigQ !== qSig) {
      qSig = sigQ;
      const tm = h('span', { class: 'muted mono' }, clock(run.startedAt)); tip(tm, absTime(run.startedAt));
      fill(qEl, h('div', { class: 'row q-h' }, h('span', { class: 'muted' }, 'You asked'), tm),
        h('p', { class: 'q-text' }, run.question || (run.loaded ? '' : 'Loading this run…')),
        run.deviceIds.length ? h('div', { class: 'chips' }, run.deviceIds.map(id => deviceChip(id))) : null);
    }
    const running = run.status === 'running';
    const collapsed = !running && run.answer && run.status === 'done';
    if (traceOpen === null) traceOpen = !collapsed;
    const sig = [run.status, run.phase, run.phases.length, run.stream, traceOpen, collapsed, run.activities.length === 0].join('|');
    if (sig !== lastSig) {
      lastSig = sig;
      const rail = h('ol', { class: 'phases', 'aria-label': 'Progress' }, PHASES.map(([id, label]) => {
        const cur = running && run.phase === id;
        const done = run.phases.includes(id) && !cur;
        return h('li', { class: cur ? 'cur' : done ? 'done' : '', 'aria-current': cur ? 'step' : null }, done ? icon('check', 12) : null, label);
      }));
      const cancel = running ? h('button', { class: 'btn sm', onClick: () => cancelRun(run) }, 'Cancel') : null;
      fill(railEl, rail, running && run.stream === 'reconnecting' ? h('span', { class: 'tag caution' }, 'Reconnecting…') : null, cancel);
      if (collapsed) {
        const btn = h('button', { class: 'trace-sum', 'aria-expanded': String(traceOpen), onClick: () => { traceOpen = !traceOpen; lastSig = ''; update(runOf(run.runId) || run); } },
          icon('chevron', 14, traceOpen ? 'open' : ''), h('span', null, traceSummary(run)));
        fill(traceEl, btn, traceOpen ? [railEl, rowsEl] : null);
      } else fill(traceEl, railEl, rowsEl, running && !run.activities.length ? h('div', { class: 'act-row muted' }, h('span', { class: 'spinner' }), run.phaseText || 'Starting the agent…') : null);
    }
    const t0 = toMs(run.startedAt) || Date.now();
    for (; rows < run.activities.length; rows++) {
      const a = run.activities[rows];
      const el2 = h('div', { class: 'act-row new' }, icon(toolIcon(a.tool), 14),
        a.detail ? h('details', { class: 'grow' }, h('summary', null, a.text, /^https?:/.test(a.detail) ? h('span', { class: 'muted host' }, ' ' + hostOf(a.detail)) : null), h('pre', { class: 'mono' }, a.detail)) : h('span', { class: 'grow' }, a.text),
        h('span', { class: 'el mono muted' }, duration(Math.max(0, (toMs(a.ts) - t0) / 1000))));
      rowsEl.appendChild(el2);
    }
    // notes: errors, endings, load failures
    const notes = [];
    if (run.loadError) notes.push(errorState(run.loadError, () => loadRun(run.runId, true), 'This run could not be loaded.'));
    for (const e of run.errors) notes.push(callout('danger', e));
    if (run.error && !run.errors.includes(run.error)) notes.push(callout(run.status === 'cancelled' ? 'caution' : 'danger', run.error));
    if (run.status === 'cancelled' && !run.error) notes.push(callout('caution', 'This run was cancelled before it answered.'));
    if (run.status === 'timeout') notes.push(callout('caution', 'The agent ran out of time before it answered.'));
    if (run.status === 'interrupted' && !run.error) notes.push(callout('caution', 'The server stopped while this run was going. Ask again to retry.'));
    if (!running && !run.answer && !notes.length && run.loaded) notes.push(callout('caution', 'This run ended without an answer.'));
    const nsig = notes.length + '|' + run.status + '|' + run.errors.length + '|' + (run.loadError || '');
    if (noteEl.dataset.sig !== nsig) { noteEl.dataset.sig = nsig; fill(noteEl, notes); }

    if (run.answer && run.answerV !== answerV) {
      answerV = run.answerV;
      const { el: aEl, actionsSlot } = renderAnswer(run, { onShowMap: ctx.showOnMap });
      const defs = run.answer.actions || [];
      const gone = Object.entries(run.actions).filter(([id, a]) => a.state === 'superseded' && a.def && !defs.find(d => d.id === id)).map(([, a]) => a.def);
      const all = [...defs, ...gone];
      if (all.length) {
        actionsSlot.appendChild(h('h4', { class: 'b-title' }, 'Proposed actions', h('span', { class: 'b-meta' }, mode() === 'approve' ? 'each one runs only if you approve it' : mode() === 'advise' ? 'advise mode: nothing can be run from here' : 'the agent is paused')));
        const next = new Map();
        for (const def of all) {
          const card = cards.get(def.id) || createActionCard(run, def, run.fixture ? { ...ctx, anyRunning: () => !!def._blocked } : { ...ctx, anyRunning: id => Object.entries(run.actions).some(([k, a]) => k !== id && a.state === 'running') || !!(activeRun() && activeRun().runId !== run.runId && Object.values(activeRun().actions).some(a => a.state === 'running')) });
          next.set(def.id, card); actionsSlot.appendChild(card.el);
        }
        cards = next;
      }
      const first = !ansEl.firstChild;
      fill(ansEl, aEl);
      if (first && ctx.onFirstAnswer && run.stream !== 'idle') ctx.onFirstAnswer(ansEl);
    }
    for (const c of cards.values()) c.update();
    const meta = ansEl.querySelector('.a-actions .b-meta');
    if (meta) meta.textContent = mode() === 'approve' ? 'each one runs only if you approve it' : mode() === 'advise' ? 'advise mode: nothing can be run from here' : 'the agent is paused';
  }
  update(run0);
  return { el, update, runId: run0.runId };
}

export function createAgent() {
  const titleEl = h('h2', { class: 'grow ellipsis' }, 'Agent');
  const head = h('div', { class: 'agent-h' });
  const thread = h('div', { class: 'agent-thread scroll', tabIndex: -1 });
  const jump = h('button', { class: 'jump', hidden: true, onClick: () => { stick = true; thread.scrollTop = thread.scrollHeight; jump.hidden = true; } }, icon('down', 14), 'Jump to latest');
  const chips = h('div', { class: 'scope' });
  const ta = h('textarea', { class: 'textarea', rows: 3, 'aria-label': 'Question for the agent', placeholder: 'Describe the problem, for example: the MacBook picture is soft through the KVM.' });
  const sendBtn = h('button', { class: 'btn primary', type: 'button' }, 'Ask');
  const hint = h('span', { class: 'muted grow hint' });
  const askEl = h('div', { class: 'ask' }, chips, ta, h('div', { class: 'row' }, hint, sendBtn));
  const el = h('div', { class: 'agent view' }, head, h('div', { class: 'thread-wrap' }, thread, jump), askEl);
  const views = new Map();
  let stick = true, sending = false, shownThread = undefined, lastFocus = 0;

  thread.addEventListener('scroll', () => { stick = thread.scrollTop + thread.clientHeight >= thread.scrollHeight - 40; if (stick) jump.hidden = true; });
  const grow = () => { ta.style.height = 'auto'; const lh = 20.3; ta.style.height = Math.min(Math.max(ta.scrollHeight + 2, lh * (isPhone() ? 2 : 3) + 18), lh * 10 + 18) + 'px'; };
  ta.addEventListener('input', () => { A().draft = ta.value; grow(); sendBtn.disabled = !canSend(); });
  ta.addEventListener('keydown', e => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); send(); } });
  sendBtn.addEventListener('click', () => send());

  const current = () => { const r = get().route.run; return r ? runOf(r) : null; };
  const curThread = () => { const r = current(); return r ? r.threadId : null; };
  const busyRun = () => threadRuns(curThread()).find(r => r.status === 'running');
  function canSend() { return !sending && mode() !== 'paused' && ta.value.trim().length > 0 && !busyRun() && !get().serverDown && !(get().route.fixture); }

  async function send(text) {
    const msg = (text != null ? text : ta.value).trim();
    if (!msg) return;
    if (text == null && !canSend()) return;
    sending = true; renderAsk();
    try {
      const fresh = A().fresh || !curThread();
      await ask(msg, A().scope, fresh ? undefined : curThread());
      ta.value = ''; grow(); stick = true;
    } catch (e) {
      toast(e.status === 409 || e.status === 429 || e.status === 400 || e.status === 404 ? e.message : 'The question could not be sent. ' + e.message, { intent: 'danger' });
    } finally { sending = false; renderAsk(); }
  }

  const ctx = {
    // The answer first: when it arrives, bring its top into view instead of staying at the end of the trace.
    onFirstAnswer(node) { stick = false; requestAnimationFrame(() => { const run = node.closest('.run'); thread.scrollTop = Math.max(0, node.offsetTop + (run ? run.offsetTop : 0) - 48); }); },
    showOnMap(pin) {
      if (!pin) return;
      const same = get().pin && get().pin.runId === pin.runId;
      if (get().route.view === 'agent' || isPhone()) { set({ pin }); go({ view: 'map', sel: [], run: pin.runId, panel: isPhone() ? null : 'agent' }); }
      else set({ pin: same ? null : pin });
    },
    async decide(action, decision) {
      const run = Object.values(A().runs).find(r => r.actions[action.id]);
      if (!run) return;
      if (run.fixture) return fixtureDecide(run, action, decision);
      try {
        const res = await api.decide(action.id, decision);
        const a = run.actions[action.id];
        a.state = res.state || (decision === 'reject' ? 'rejected' : 'running'); a.decidedAt = new Date().toISOString();
        if (decision === 'approve') openStream(run.runId);
      } catch (e) {
        const a = run.actions[action.id];
        if (e.status === 403) { a.state = /sudo|root/i.test(e.message) ? 'copy-only' : 'refused'; a.refusal = e.message.replace(/^Refused:\s*/, ''); toast(e.message, { intent: 'caution' }); }
        else { toast(e.message, { intent: 'danger' }); loadRun(run.runId, true); }
      }
      bump();
    },
    stop(run) { cancelRun(run); },
    undo(action) {
      if (mode() === 'paused') return toast('The agent is paused. Switch the mode to Advise or Approve to ask for the undo.', { intent: 'caution' });
      send(`Propose the undo for “${action.label}” as a new action. The undo command recorded for it is: ${action.undo}`);
    },
  };

  function fixtureDecide(run, action, decision) {
    const a = run.actions[action.id];
    a.decidedAt = new Date().toISOString();
    if (decision === 'reject') { a.state = 'rejected'; bump(); return; }
    a.state = 'running'; a.output = []; bump();
    const lines = ['fixture: nothing is run on this machine', '$ ' + action.command, 'ok'];
    lines.forEach((t, i) => setTimeout(() => { a.output.push({ stream: 'stdout', text: t }); if (i === lines.length - 1) { a.state = 'done'; a.exitCode = 0; a.finishedAt = new Date().toISOString(); } bump(); }, 500 * (i + 1)));
  }

  function historyList(onPick) {
    const list = A().list;
    if (!list) return A().listError ? errorState(A().listError, refreshRuns, 'The run history could not be loaded.') : skeleton(5);
    if (!list.length) return emptyState('No runs yet. Ask about a problem to start.');
    return h('div', { class: 'runlist' }, list.map(r => runRow(r, onPick)));
  }

  function renderHead() {
    const st = get();
    const r = current();
    const inView = st.route.view === 'agent';
    const title = st.route.fixture ? 'Development fixture' : r ? (r.answer && r.answer.title) || r.question || 'Run' : 'Ask the agent';
    titleEl.textContent = title;
    const newBtn = (r || st.route.fixture) ? h('button', { class: 'btn sm', onClick: () => { set({ agent: { ...A(), fresh: true }, pin: null }); go({ run: null, fixture: false }); setTimeout(() => ta.focus(), 0); } }, icon('plus', 14), 'New question') : null;
    const histBtn = (!inView || !window.matchMedia('(min-width: 1440px)').matches) ? h('button', { class: 'btn sm icon', 'aria-label': 'Run history', onClick: () => {
      if (isPhone()) { const d = dialog({ title: 'Run history', body: h('div', { class: 'body', style: { padding: 0 } }, historyList(() => d.close())) }); }
      else { const p = popover(histBtn, h('div', { style: { width: '320px', margin: '-12px' } }, historyList(() => p.close())), { align: 'right' }); }
    } }, icon('history')) : null;
    if (histBtn) tip(histBtn, 'Run history');
    const full = !inView && !isPhone() ? h('button', { class: 'btn sm icon', 'aria-label': 'Open the Agent view', onClick: () => go({ view: 'agent', panel: null }) }, icon('external')) : null;
    if (full) tip(full, 'Open the Agent view');
    fill(head, titleEl, newBtn, histBtn, full);
  }

  function renderThread() {
    const st = get();
    let runs;
    if (st.route.fixture) runs = fixtureRuns(A());
    else { const r = current(); runs = r ? threadRuns(r.threadId || '__none').filter(x => x) : []; if (r && !runs.length) runs = [r]; if (!r && st.route.run) runs = []; }
    if (!st.inventory) { shownThread = undefined; views.clear(); fill(thread, st.invError ? errorState(st.invError, null, 'The inventory could not be loaded.') : skeleton(6)); return; }
    const key = st.route.fixture ? 'fixture' : (current() ? current().threadId || current().runId : 'new:' + (st.route.run || ''));
    let fresh = false;
    if (key !== shownThread) { shownThread = key; views.clear(); thread.replaceChildren(); stick = runs.some(r => r.status === 'running'); fresh = true; }
    if (!runs.length) {
      views.clear();
      if (st.route.run && !current()) { fill(thread, skeleton(6)); return; }
      const qs = (st.inventory && st.inventory.openQuestions) || [];
      fill(thread, h('div', { class: 'intro' },
        h('p', null, 'The agent reads the device guides, inspects the live system with read-only checks, then answers with its findings tied to the map. It can only propose changes: each one is an exact command that you approve, one at a time.'),
        mode() === 'paused' ? callout('caution', 'The agent is paused. Switch the mode to Advise or Approve to ask.') : null,
        qs.length ? [h('h3', null, 'Open questions from the inventory'), h('div', { class: 'suggest' }, qs.map(q => h('button', { type: 'button', onClick: () => {
          set({ agent: { ...A(), scope: (q.devices || []).filter(G.isDeviceId), draft: q.text } }); ta.value = q.text; grow(); renderAsk(); ta.focus();
        } }, h('span', { class: 'grow' }, q.text), h('span', { class: 'muted mono' }, plural((q.devices || []).length, 'device')))))] : null));
      return;
    }
    if (thread.querySelector('.intro, .skel-rows')) thread.replaceChildren();
    if (st.route.fixture && !thread.querySelector('.fx-note')) thread.prepend(h('div', { class: 'fx-note' }, callout('info', 'Development fixture: a built-in sample answer that exercises every block type and action state. Nothing here was asked or run, and its buttons only simulate.')));
    for (const run of runs) {
      let v = views.get(run.runId);
      if (!v) {
        v = createRunView(run, { ...ctx, fixture: run.fixture, mode: 'approve' }); views.set(run.runId, v); thread.appendChild(v.el);
        if (!run.loaded && !run.fixture && run.status !== 'running') loadRun(run.runId);
      } else v.update(run);
    }
    if (fresh && !stick) { const lastRun = views.get(runs[runs.length - 1].runId); thread.scrollTop = runs.length > 1 && lastRun ? lastRun.el.offsetTop - 12 : 0; }
    else if (stick) thread.scrollTop = thread.scrollHeight; else if (runs.some(r => r.status === 'running')) jump.hidden = false;
  }

  function renderAsk() {
    const st = get();
    const a = A();
    const scope = a.scope.filter(G.isDeviceId);
    const addBtn = h('button', { class: 'chip add', type: 'button', onClick: () => picker(addBtn) }, icon('plus', 12), 'Add device');
    fill(chips, scope.length ? scope.map(id => deviceChip(id, { removable: true, onRemove: x => { set({ agent: { ...A(), scope: A().scope.filter(y => y !== x) } }); } })) : h('span', { class: 'muted none' }, 'No devices added: the agent works out which are involved'), addBtn);
    const paused = mode() === 'paused';
    const followUp = !!curThread() && !a.fresh && !st.route.fixture;
    ta.disabled = paused || st.route.fixture;
    ta.placeholder = paused ? 'The agent is paused. Switch the mode to Advise or Approve to ask.' : followUp ? 'Ask a follow-up in this thread.' : 'Describe the problem, for example: the MacBook picture is soft through the KVM.';
    if (document.activeElement !== ta && ta.value !== a.draft) { ta.value = a.draft || ''; grow(); }
    sendBtn.disabled = !canSend();
    fill(sendBtn, sending ? h('span', { class: 'spinner' }) : null, followUp ? 'Ask follow-up' : 'Ask');
    hint.textContent = st.route.fixture ? 'The fixture does not send questions.' : paused ? 'The agent is paused. Switch the mode to Advise or Approve to ask.' : st.serverDown ? "Can't reach the server, so nothing can be sent." : busyRun() ? 'Wait for the current run, or cancel it.' : isPhone() ? '' : '⌘↵ to send · ↵ for a new line';
    if (a.focusAsk && a.focusAsk !== lastFocus) { lastFocus = a.focusAsk; setTimeout(() => { if (!ta.disabled) ta.focus(); }, 30); }
  }

  function picker(anchor) {
    const input = h('input', { class: 'input', type: 'search', placeholder: 'Find a device', 'aria-label': 'Find a device' });
    const list = h('div', { class: 'scroll', style: { maxHeight: '260px', margin: '8px -12px -12px' } });
    const draw = () => {
      const q = input.value.toLowerCase();
      const ds = G.devices().filter(d => !A().scope.includes(d.id) && (d.name + ' ' + d.id + ' ' + (G.primaryIp(d) || '')).toLowerCase().includes(q)).slice(0, 40);
      fill(list, ds.length ? ds.map(d => h('button', { class: 'orow', onClick: () => { set({ agent: { ...A(), scope: [...A().scope, d.id] } }); p.close(); } }, statusGlyph(G.statusOf(d.id)), h('span', { class: 'name ellipsis' }, d.name), h('span', { class: 'meta' }, G.primaryIp(d) || d.kind))) : h('div', { class: 'state' }, 'No device matches.'));
    };
    input.addEventListener('input', draw);
    const p = popover(anchor, h('div', { style: { width: '280px' } }, input, list));
    draw(); input.focus();
  }

  const said = h('div', { class: 'sr-only', role: 'status' });
  el.appendChild(said);
  const lastStatus = new Map();
  function announceRuns() {
    for (const r of Object.values(A().runs || {})) {
      const was = lastStatus.get(r.runId); lastStatus.set(r.runId, r.status);
      if (was !== 'running' || r.status === 'running' || r.fixture) continue;
      said.textContent = r.status === 'done' ? 'The agent has answered' + (r.answer && r.answer.title ? ': ' + r.answer.title : '.') : r.status === 'cancelled' ? 'The run was cancelled.' : r.status === 'timeout' ? 'The agent ran out of time before it answered.' : 'The run ended without an answer.';
    }
  }
  on(['agent', 'settings', 'inventory', 'invError', 'live', 'serverDown'], () => { renderHead(); renderThread(); renderAsk(); announceRuns(); });
  on(['route'], st => {
    const rid = st.route.run;
    if (rid && !st.route.fixture) {
      const r = runOf(rid);
      if (!r || !r.loaded) loadRun(rid).then(() => { const rr = runOf(rid); if (rr && rr.answer && isCurrent(rid) && !get().pin && st.route.view === 'agent') autoPin(rr); });
      else if (st.route.view === 'agent' && r.answer && (!get().pin || get().pin.runId !== rid)) autoPin(r);
      if (r && r.threadId) for (const x of threadRuns(r.threadId)) if (!x.loaded) loadRun(x.runId);
    }
    if (st.route.fixture && st.route.view === 'agent') { const fr = fixtureRuns(A()); if (!get().pin) autoPin(fr[fr.length - 1]); }
    renderHead(); renderThread(); renderAsk();
  });
  on(['pin'], () => { for (const b of thread.querySelectorAll('.a-path [aria-pressed]')) { const sec = b.closest('.run'); b.setAttribute('aria-pressed', String(!!(get().pin && sec && get().pin.runId === sec.dataset.run))); } });
  renderHead(); renderThread(); renderAsk();
  return { el, focusAsk: () => { if (!ta.disabled) ta.focus(); } };
}

function runRow(r, onPick) {
  const cur = get().route.run === r.runId;
  const stt = r.status === 'running' ? h('span', { class: 'tag info' }, h('span', { class: 'spinner' }), 'running') : r.status === 'done' ? null
    : h('span', { class: 'tag ' + (r.status === 'cancelled' ? '' : 'caution') }, r.status === 'error' ? 'failed' : r.status);
  const tm = h('span', { class: 'mono muted tm' }, relTime(r.startedAt, get().now));
  return h('button', { class: 'runrow', type: 'button', 'aria-current': String(cur), onClick: () => { set({ agent: { ...A(), fresh: false } }); go({ run: r.runId, fixture: false }); onPick && onPick(); } },
    h('div', { class: 'row' }, h('span', { class: 't grow ellipsis' }, r.title || r.question || 'Run'), stt),
    h('div', { class: 'v' }, r.verdict || (r.title ? r.question : r.error) || ''),
    h('div', { class: 'row' }, tm, (r.deviceIds || []).length ? h('span', { class: 'muted mono tm' }, '· ' + plural(r.deviceIds.length, 'device')) : null));
}

/** Run history for the list column on the Agent view. */
export function createRunList() {
  const body = h('div', { class: 'scroll grow' });
  const el = h('div', { class: 'view' }, h('div', { class: 'list-h runs-h' }, h('h2', { class: 'grow' }, 'Runs'),
    h('button', { class: 'btn sm', onClick: () => { set({ agent: { ...A(), fresh: true }, pin: null }); go({ run: null, fixture: false }); } }, icon('plus', 14), 'New')), body);
  const render = () => {
    const list = A().list;
    if (!list) return fill(body, A().listError ? errorState(A().listError, refreshRuns, 'The run history could not be loaded.') : skeleton(6));
    if (!list.length) return fill(body, emptyState('No runs yet. Ask about a problem to start.'));
    const top = body.scrollTop; fill(body, h('div', { class: 'runlist' }, list.map(r => runRow(r)))); body.scrollTop = top;
  };
  on(['agent', 'route', 'now'], render);
  render();
  return { el };
}

export function initAgentKeys() { return isTyping; }
