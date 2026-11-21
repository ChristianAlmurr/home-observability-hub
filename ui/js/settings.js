// Questions and Settings views, and the agent mode control shared with the top bar.
import { h, fill } from './dom.js';
import { icon } from './icons.js';
import { get, set, on, go, pref, setPref } from './store.js';
import { api } from './api.js';
import * as G from './graph.js';
import { deviceChip, seg, callout, toast, skeleton, errorState, emptyState, statusGlyph, dialog } from './ui.js';
import { relTime, absTime, plural } from './fmt.js';
import { askAbout } from './agent.js';
import { ownerName, homeName, handsOff, secretDirs, hostId, routerInfo } from './site.js';

export const MODES = [
  { value: 'advise', label: 'Advise', text: 'The agent can look and suggest. Nothing runs.' },
  { value: 'approve', label: 'Approve', text: 'Each proposed action runs only when you approve it.' },
  { value: 'paused', label: 'Paused', text: 'The agent will not start.' },
];

export async function setMode(v) {
  const cur = (get().settings || {}).agentMode;
  if (v === cur) return;
  try {
    const s = await api.saveSettings({ agentMode: v });
    set({ settings: s });
    toast('Agent mode: ' + MODES.find(m => m.value === v).label.toLowerCase() + '. ' + MODES.find(m => m.value === v).text, { intent: v === 'paused' ? 'caution' : 'info' });
  } catch (e) { toast('The mode was not changed. ' + e.message, { intent: 'danger' }); }
}

export function modeOptions(onPick) {
  const cur = (get().settings || {}).agentMode;
  const btns = MODES.map(m => h('button', { class: 'opt', type: 'button', role: 'radio', 'aria-checked': String(m.value === cur), disabled: !get().settings, tabIndex: m.value === (cur || MODES[0].value) ? 0 : -1,
    onClick: async () => { await setMode(m.value); onPick && onPick(); } }, h('span', { class: 'radio' }), h('span', null, h('b', null, m.label), h('span', { class: 'd' }, m.text))));
  const el = h('div', { class: 'opt-list', role: 'radiogroup', 'aria-label': 'Agent mode' }, btns);
  // a radio group is one Tab stop; the arrow keys move between modes (focus only: Enter or Space sets it, since that saves)
  el.addEventListener('keydown', e => {
    if (!['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight'].includes(e.key)) return;
    const i = btns.indexOf(document.activeElement);
    const n = btns[(i + (e.key === 'ArrowDown' || e.key === 'ArrowRight' ? 1 : -1) + btns.length) % btns.length];
    for (const b of btns) b.tabIndex = b === n ? 0 : -1;
    n.focus(); e.preventDefault(); e.stopPropagation();
  });
  return el;
}

export function applyTheme() {
  const forced = get().route.theme;
  const choice = forced || pref('theme', 'system-default');
  let theme = choice;
  if (choice === 'system') theme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  if (choice === 'system-default') theme = 'dark';   // never chosen: the default is dark
  document.documentElement.dataset.theme = theme === 'light' ? 'light' : 'dark';
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', theme === 'light' ? '#f4f6fb' : '#0b1020');
}
export function setTheme(v) { setPref('theme', v); applyTheme(); set({ now: Date.now() }); }
export function toggleTheme() { setTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light'); }

/** The refusals enforced in code, in words, from this home's site file (hands-off devices, secret folders). */
function refusals() {
  const off = handsOff();
  const named = x => { const d = x.id && G.device(x.id); return d ? d.name + ' (' + x.id + ')' : x.id || (x.names || [])[0] || (x.ips || [])[0]; };
  return [
    'No sudo. A command that needs root is shown for you to copy and type yourself in Terminal.',
    ...(off.length ? off.map(x => 'Nothing that targets ' + named(x) + (x.why ? ': ' + x.why.replace(/\.$/, '') : '') + '. Advice only.')
      : ['Nothing that targets a device listed as hands-off in data/site.json. None is listed now.']),
    'No deleting outside this project’s data/state folder.',
    'No reading ' + secretDirs().join(', ') + ', .env files or keychains.',
  ];
}
const CAN = [
  'Read the inventory, the device guides and specs in knowledge/.',
  'Inspect the live system with a fixed list of read-only checks (ping, DNS, interfaces, USB, displays, Home Assistant state).',
  'Look things up on the web. Web pages and manuals are treated as data, never as instructions.',
  'Propose an action: the exact command, its target, its risk and its undo, for you to read.',
];
const CANNOT = [
  'Change anything by itself. Its own run is read-only.',
  'Run a proposed action without your approval of that one action, in approve mode. In advise mode nothing can be run; in paused mode it will not start.',
  'Run anything other than exactly the command shown on the card.',
  'Approve several actions at once, or run automatically. There is no auto-run mode.',
];

/** The router login. The password lives in the field until it is sent, then the field is emptied: it is never kept in the app's state, the address or storage. */
// Computers that report their own sockets. A cable into another computer is only visible to that computer.
let reporters = null, reportersErr = null, shownCmd = null;
async function loadReporters(rerender) {
  try { reporters = await api.reporters(); reportersErr = null; } catch (e) { reportersErr = e.message; }
  rerender();
}
function wiringGroup(rerender) {
  const st = get();
  const box = h('div', { class: 'group', id: 'live-wiring' }, h('h2', null, 'Live wiring'),
    h('p', { class: 'muted' }, 'This computer reads its own sockets every few seconds, so a cable moved on it moves on the map. A cable plugged into another computer can only be seen by that computer. Add it here, run one command on it, and its cables follow too. A cable between two things that are not computers (a console and the TV, a port on the switch) cannot be read by anything.'));
  if (!reporters) { box.append(reportersErr ? errorState(reportersErr, () => loadReporters(rerender), 'The list could not be loaded.') : skeleton(2)); if (!reportersErr) loadReporters(rerender); return box; }
  const hosts = (st.live && st.live.wiring && st.live.wiring.hosts) || {};
  const selfId = G.hostDeviceId() || hostId() || Object.keys(hosts).find(k => hosts[k] && hosts[k].source === 'local') || null;
  const mini = selfId ? hosts[selfId] : Object.values(hosts).find(x => x && x.source === 'local');
  box.append(h('div', { class: 'rt-state s-' + (mini ? 'online' : 'unmonitored') }, statusGlyph(mini ? 'online' : 'unmonitored'), h('div', { class: 'grow' }, h('b', null, selfId ? G.deviceName(selfId) + ' (this computer)' : 'This computer'),
    h('span', { class: 'm' }, mini ? 'sockets read ' + relTime(mini.ts, st.now) : 'no reading yet'))));
  for (const r of reporters.reporters) {
    const ok = r.ageSec != null && r.ageSec < 180;
    box.append(h('div', { class: 'rt-state s-' + (ok ? 'online' : r.lastReport ? 'offline' : 'unmonitored') }, statusGlyph(ok ? 'online' : r.lastReport ? 'offline' : 'unmonitored'), h('div', { class: 'grow' }, h('b', null, r.name),
      h('span', { class: 'm' }, r.lastReport ? 'last report ' + relTime(r.lastReport, st.now) + (ok ? '' : ' · the command is not running on it now, so its cables are shown where they were last seen') : 'added, no report yet: run the command on it')),
      h('button', { class: 'btn', onClick: async () => { try { await api.removeReporter(r.device); if (shownCmd && shownCmd.device === r.device) shownCmd = null; toast('Removed. Its cables go back to what the inventory says.', { intent: 'success' }); } catch (e) { toast('Not removed. ' + e.message, { intent: 'danger' }); } loadReporters(rerender); } }, 'Remove')));
  }
  if (shownCmd) box.append(callout('info', h('b', null, 'Run this in Terminal on ' + shownCmd.name + '. '), 'It is shown once. It only reads what is plugged in and sends that to this Mac over your home network; it changes nothing on that computer. Leave the Terminal window open: it keeps reporting, and sends at once when a cable moves.',
    h('pre', { class: 'mono', style: { whiteSpace: 'pre-wrap', wordBreak: 'break-all', userSelect: 'all', margin: '8px 0 0' } }, shownCmd.command)));
  if (reporters.candidates.length) {
    const sel = h('select', { class: 'select', 'aria-label': 'Computer to add' }, reporters.candidates.map(c => h('option', { value: c.device }, c.name)));
    const note = h('p', { class: 'muted' });
    const sync = () => { const c = reporters.candidates.find(x => x.device === sel.value); note.textContent = c && c.work ? 'This is a work laptop. The command only reads its sockets and sends the list to this Mac, but running anything on an employer-managed machine is your call.' : ''; };
    sel.addEventListener('change', sync); sync();
    box.append(h('div', { class: 'rt-form' }, sel, h('button', { class: 'btn primary', onClick: async () => {
      const c = reporters.candidates.find(x => x.device === sel.value);
      try { const out = await api.addReporter(sel.value); shownCmd = { device: sel.value, name: c ? c.name : sel.value, command: out.command }; } catch (e) { toast('Not added. ' + e.message, { intent: 'danger' }); }
      loadReporters(rerender);
    } }, 'Add this computer')), note);
  }
  return box;
}

function routerGroup(rerender) {
  const st = get();
  const r = st.router;
  const live = (st.live && st.live.router) || null;
  const box = h('div', { class: 'group', id: 'router-login' }, h('h2', null, 'Router login'));
  if (routerInfo().type === 'none') {
    box.append(h('div', { class: 'rt-state s-unmonitored' }, statusGlyph('unmonitored'), h('div', { class: 'grow' }, h('b', null, 'No router connection is set up.'),
      h('span', { class: 'm' }, 'The router type is none in data/site.json. Devices are found by ping, mDNS, SSDP and the ARP table. Which access point each Wi-Fi device uses, traffic, and blocking a device at the router need a supported router: run /setup again to add one.'))));
    return box;
  }
  if (st.routerError === 'missing') { box.append(h('p', { class: 'muted' }, 'This server has no router connection yet. Blocking a device and reading which access point each Wi-Fi device uses need it.')); return box; }
  if (!r) { box.append(st.routerError ? errorState(st.routerError, () => window.__hmRouter && window.__hmRouter(), 'The router state could not be loaded.') : skeleton(3)); return box; }
  const how = r.transport === 'ssh' || (r.sshKey && !r.webLogin) ? 'over SSH, with the household key' : r.webLogin ? 'with the web login stored in the Keychain' : 'with a stored login';
  const state = r.configured ? (r.ok === false ? ['offline', 'The app has a way in, but the router did not accept it' + (r.error ? ': ' + r.error : '.')] : ['online', 'The app reads the router ' + how + '.']) : ['unmonitored', 'No login is stored.'];
  const nClients = Array.isArray(r.clients) ? r.clients.length : r.clients;
  box.append(h('div', { class: 'rt-state s-' + state[0] }, statusGlyph(state[0]), h('div', { class: 'grow' }, h('b', null, state[1]),
    h('span', { class: 'm' }, r.configured ? [r.model, r.firmware ? 'firmware ' + r.firmware : null, nClients != null ? plural(nClients, 'client') + ' in its list' : null, r.lastRun || (live && live.lastRun) ? 'read ' + relTime(r.lastRun || live.lastRun, st.now) : null, r.stale ? 'the reading is stale' : null].filter(Boolean).join(' · ')
      : 'Without it the app cannot read the router\'s client list (which access point each device uses, traffic) and cannot block or unblock a device.'))));
  // Changes at the router: off unless the person turns them on
  if (st.settings && 'routerWrites' in st.settings) {
    const on = !!st.settings.routerWrites;
    const cb = h('input', { type: 'checkbox', checked: on, 'aria-describedby': 'rw-d', onChange: e => {
      const want = e.target.checked;
      const apply = async () => { try { set({ settings: await api.saveSettings({ routerWrites: want }) }); toast(want ? 'Block and unblock now change the router.' : 'Block and unblock are rehearsals again. Nothing is sent to the router.', { intent: want ? 'caution' : 'success' }); } catch (err) { toast('Not saved. ' + err.message, { intent: 'danger' }); } rerender(); };
      if (!want) return apply();
      e.target.checked = false;
      const d = dialog({ title: 'Let the app change the router', body: h('div', { class: 'body confirm-act' },
        h('dl', { class: 'cf-dl' }, h('dt', null, 'What happens'), h('dd', null, 'From now on, confirming Block or Unblock on a device edits the router\'s block list and reloads its firewall. Each one still asks first and shows what it will do.'),
          h('dt', null, 'Undo'), h('dd', null, 'Turn this off again here. Devices already blocked stay blocked until you unblock them.')),
        h('div', { class: 'cf-foot' }, h('span', { class: 'grow' }), h('button', { class: 'btn', onClick: () => d.close() }, 'Cancel'), h('button', { class: 'btn danger', onClick: () => { d.close(); apply(); } }, 'Allow changes at the router'))) });
    } });
    box.append(h('label', { class: 'switch-row' + (on ? ' on' : '') }, cb, h('span', null, h('b', null, 'Allow the app to change the router'),
      h('span', { class: 'm', id: 'rw-d' }, on ? 'On: Block and Unblock edit the router\'s block list, each after its own confirmation.' : 'Off: Block and Unblock are rehearsals. You see the exact commands that would be sent, and nothing is changed.'))));
  }
  const user = h('input', { class: 'input', type: 'text', name: 'router-user', value: 'admin', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', 'aria-label': 'Router user name' });
  const pass = h('input', { class: 'input', type: 'password', name: 'router-pass', autocomplete: 'off', placeholder: r.webLogin || (r.configured && r.webLogin == null) ? 'New password' : 'Router admin password', 'aria-label': 'Router password' });
  const msg = h('div', { class: 'rt-msg', role: 'status' });
  const save = h('button', { class: 'btn primary', type: 'submit' }, icon('key', 14), r.webLogin ? 'Test and replace' : 'Test and save');
  const form = h('form', { class: 'rt-form', autocomplete: 'off', onSubmit: async e => {
    e.preventDefault();
    if (!user.value.trim() || !pass.value) { fill(msg, callout('caution', 'Enter the user name and the password.')); return; }
    save.disabled = true; fill(save, h('span', { class: 'spinner' }), 'Testing the login…');
    const creds = { username: user.value.trim(), password: pass.value };
    pass.value = '';   // gone from the page before the answer comes back
    let res;
    try { res = await api.routerLogin(creds); } catch (err) { res = { ok: false, error: err.message }; }
    creds.password = '';
    save.disabled = false; fill(save, icon('key', 14), 'Test and save');
    if (!res || res.ok === false) { fill(msg, callout('danger', h('b', null, 'Not saved. '), (res && res.error) || 'The router did not accept the login.', ' Nothing was stored.')); pass.focus(); return; }
    toast('The router accepted the login. It is stored in the macOS Keychain.', { intent: 'success' });
    window.__hmReload && window.__hmReload();
  } },
    h('label', { class: 'field' }, h('span', { class: 'fl' }, 'User name'), user),
    h('label', { class: 'field' }, h('span', { class: 'fl' }, 'Password'), pass),
    h('div', { class: 'row' }, save, (r.webLogin == null ? r.configured : r.webLogin) ? h('button', { class: 'btn', type: 'button', onClick: () => {
      const d = dialog({ title: 'Remove the router login', body: h('div', { class: 'body confirm-act' },
        h('dl', { class: 'cf-dl' }, h('dt', null, 'What happens'), h('dd', { class: 'no-undo' }, 'Deletes the router login from the macOS Keychain. That Keychain item is shared: other tools on this Mac that use it to reach the router lose it too. ' + (r.sshKey ? 'The app keeps reading the router over SSH.' : 'The app stops reading the router\'s client list, and blocking stops working.') + ' Devices that are blocked stay blocked.'),
          h('dt', null, 'Undo'), h('dd', null, 'Enter the login again here. The other tools pick it up from the Keychain again.')),
        h('div', { class: 'cf-foot' }, h('span', { class: 'grow' }), h('button', { class: 'btn', onClick: () => d.close() }, 'Cancel'), h('button', { class: 'btn danger', onClick: async () => {
          d.close();
          try { await api.routerLogout(); toast('The router login was removed.', { intent: 'success' }); } catch (err) { toast('Not removed. ' + err.message, { intent: 'danger' }); }
          window.__hmReload && window.__hmReload();
        } }, 'Remove the login'))) });
    } }, 'Remove the login') : null),
    msg);
  box.append(h('h3', { class: 'sub-h' }, r.sshKey ? 'Web login (optional: the app already has SSH)' : 'Web login'), form, h('p', { class: 'muted' }, 'The password goes to this Mac only, is tested against the router, and is stored in the macOS Keychain (service ', h('code', null, 'home-observability-hub-router'), '). It is not written to a file or a log, the agent never sees it, and this page cannot show it again.'));
  void rerender;
  return box;
}

export function createSettings() {
  const page = h('div', { class: 'page' });
  const el = h('div', { class: 'view' }, h('div', { class: 'scroll grow' }, page));
  let saving = false;

  async function save(patch) {
    saving = true;
    try { set({ settings: await api.saveSettings(patch) }); toast('Saved.', { intent: 'success' }); }
    catch (e) { toast('Not saved. ' + e.message, { intent: 'danger' }); render(); }
    finally { saving = false; }
  }

  function render() {
    const st = get();
    const s = st.settings;
    const hl = st.health;
    const themeChoice = pref('theme', 'system-default');
    const intervals = [[30, '30 s'], [60, '60 s'], [300, '5 min']];
    if (s && !intervals.find(i => i[0] === s.scanIntervalSec)) intervals.push([s.scanIntervalSec, s.scanIntervalSec + ' s']);
    fill(page,
      h('h1', { class: 'page-title hide-sm' }, 'Settings'),
      h('div', { class: 'group' }, h('h2', null, 'Agent mode'),
        !s ? (st.settingsError ? errorState(st.settingsError, () => window.__hmReload && window.__hmReload(), 'The settings could not be loaded.') : skeleton(3)) : modeOptions(),
        h('p', { class: 'muted' }, 'There is no auto-run mode. The Stop control in the top bar cancels a run and sets the mode to paused.')),
      routerGroup(render),
      wiringGroup(render),
      h('div', { class: 'group' }, h('h2', null, 'What the agent can and cannot do'),
        h('div', { class: 'cando' }, h('div', null, h('h3', null, 'It can'), h('ul', null, CAN.map(t => h('li', null, h('span', { class: 'r ok' }, icon('check', 14)), h('span', null, t))))),
          h('div', null, h('h3', null, 'It cannot'), h('ul', null, CANNOT.map(t => h('li', null, h('span', { class: 'r bad' }, icon('cross', 14)), h('span', null, t)))))),
        h('h3', { class: 'refusals-h' }, 'Hard refusals'),
        h('ul', { class: 'refusals' }, refusals().map(t => h('li', null, icon('lock', 14), h('span', null, t)))),
        h('p', { class: 'muted' }, 'These are enforced in code. They cannot be changed here.'),
        h('p', { class: 'muted' }, 'Everything is written to the audit log: the question, the tools used, the actions proposed, who decided what, and exit codes. ',
          h('button', { class: 'linkbtn', onClick: () => go({ view: 'activity', at: 'audit' }) }, 'Open the audit log'))),
      h('div', { class: 'group' }, h('h2', null, 'Scanning'),
        !s ? skeleton(2) : [
          h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: !!s.scanning, disabled: saving, onChange: e => save({ scanning: e.target.checked }) }), 'Look for hosts that are not in the inventory'),
          h('p', { class: 'muted' }, 'Turning this off stops only the sweep for hosts that are not in the inventory. Devices in the inventory are still probed.'),
          h('label', { class: 'row' }, h('span', null, 'Probe every'), h('select', { class: 'select', disabled: saving, onChange: e => save({ scanIntervalSec: parseInt(e.target.value, 10) }) }, intervals.map(([v, t]) => h('option', { value: v, selected: v === s.scanIntervalSec }, t)))),
          s.agentModel ? h('p', { class: 'muted' }, 'Agent model: ', h('span', { class: 'mono' }, s.agentModel)) : null]),
      h('div', { class: 'group' }, h('h2', null, 'Collectors'),
        !hl ? skeleton(3) : Object.keys(hl.collectors || {}).length ? h('div', { class: 'scroll' }, h('table', { class: 'table' }, h('thead', null, h('tr', null, ['Collector', 'Last run', 'Result', 'Error'].map(t => h('th', { scope: 'col' }, t)))),
          h('tbody', null, Object.entries(hl.collectors).map(([name, c]) => h('tr', null, h('td', { class: 'mono' }, name), h('td', { title: absTime(c.lastRun) }, c.lastRun ? relTime(c.lastRun, st.now) : 'not yet'),
            h('td', null, h('span', { class: 'row' }, statusGlyph(c.ok ? 'online' : c.ok === false ? 'offline' : 'unknown'), c.ok ? 'ok' : c.ok === false ? 'failing' : 'no result yet')), h('td', { class: 'mono wrap' }, c.error || '')))))) : emptyState('No collector has reported yet.')),
      h('div', { class: 'group' }, h('h2', null, 'Theme'),
        seg([{ value: 'dark', label: 'Dark' }, { value: 'light', label: 'Light' }, { value: 'system', label: 'System' }], themeChoice === 'system-default' ? 'dark' : themeChoice, v => { setTheme(v); render(); }, { label: 'Theme' }),
        h('p', { class: 'muted' }, 'Kept in this browser only. It is a view preference, not house state.')),
      h('div', { class: 'group' }, h('h2', null, 'About'), h('p', { class: 'muted' }, 'Home Observability Hub ', h('span', { class: 'mono' }, hl && hl.version ? hl.version : 'version not known'),
        homeName() || (st.inventory && st.inventory.site && st.inventory.site.name) ? [' · ', homeName() || st.inventory.site.name] : null,
        ownerName() ? [' · kept by ', ownerName()] : null,
        st.inventory && st.inventory.site && st.inventory.site.surveyedAt ? [' · surveyed ', st.inventory.site.surveyedAt] : null),
        h('p', { class: 'muted' }, 'The inventory is kept in ', h('code', null, 'data/inventory.json'), '. The app changes it only when you identify or remove a device, and keeps a copy from before each change in ', h('code', null, 'data/state/backups/'), '.')));
  }
  on(['settings', 'settingsError', 'health', 'inventory', 'router', 'routerError', 'site'], () => { if (get().route.view === 'settings' && !(document.activeElement && document.activeElement.closest && document.activeElement.closest('.rt-form'))) render(); });
  return { el, show: render };
}

export function createQuestions() {
  const page = h('div', { class: 'page' });
  const el = h('div', { class: 'view' }, h('div', { class: 'scroll grow' }, page));
  function render() {
    const st = get();
    if (!st.inventory) return fill(page, st.invError ? errorState(st.invError, () => window.__hmReload && window.__hmReload(), 'The inventory could not be loaded.') : skeleton(8));
    const qs = st.inventory.openQuestions || [];
    fill(page, h('div', { class: 'page-head' }, h('div', { class: 'view-t' }, h('h1', { class: 'page-title hide-sm' }, 'Open questions'), qs.length ? h('span', { class: 'view-count' }, plural(qs.length, 'question')) : null),
      h('p', { class: 'muted' }, 'What the survey could not settle. This list comes from the inventory file.')),
      qs.length ? h('div', { class: 'qcards' }, qs.map(q => {
        const ids = (q.devices || []).filter(G.isDeviceId);
        return h('div', { class: 'qcard' }, h('p', null, q.text), h('div', { class: 'chips' }, ids.map(id => deviceChip(id))),
          h('div', { class: 'row' }, h('button', { class: 'btn sm primary', onClick: () => askAbout(ids, q.text) }, 'Ask the agent'),
            h('button', { class: 'btn sm', onClick: () => go({ view: 'map', sel: ids, mapMode: null }) }, icon('map', 14), 'Show on map'), h('span', { class: 'grow' }), h('span', { class: 'qmeta' }, plural(ids.length, 'device'))));
      })) : emptyState('The inventory lists no open questions.'));
  }
  on(['inventory', 'invError', 'live'], () => { if (get().route.view === 'questions') render(); });
  return { el, show: render };
}

export { callout };
