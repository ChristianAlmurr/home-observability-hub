// The security overview: how many devices, how many are not identified, suspicious, blocked or new,
// and the list of them, worst first. The same counts sit in the top bar on every view.
import { h, fill } from './dom.js';
import { icon, kindIcon } from './icons.js';
import { get, set, on, go, select } from './store.js';
import * as G from './graph.js';
import { statusGlyph, tip, skeleton, errorState, liveAge } from './ui.js';
import { relTime, absTime, plural, kindLabel } from './fmt.js';
import { actionBar } from './actions.js';
import { api } from './api.js';
import { dialog, toast, callout } from './ui.js';
import { threatLevel, findingChip } from './threats.js';

/** "confirmed", "likely", "not identified": with what it rests on in the tooltip. */
export function idChip(d, { showConfirmed = true } = {}) {
  const idn = G.identityOf(d);
  if (!idn.state) { const el = h('span', { class: 'idc none' }, 'identity not assessed'); tip(el, 'This server did not send an identity record for the device.'); return el; }
  if (idn.state === 'confirmed' && !showConfirmed) return null;
  const el = h('span', { class: 'idc ' + idn.state }, idn.state === 'confirmed' ? icon('check', 12) : h('i', null, idn.state === 'likely' ? '~' : '?'), G.ID_WORD[idn.state]);
  tip(el, idn.state === 'confirmed' ? 'Confirmed: ' + (idn.basis || 'a probe names the product, or someone in the home said so') : idn.state === 'likely' ? 'Likely, not confirmed: ' + (idn.basis || 'no probe has named the product')
    : 'Not identified.' + (G.bestGuess(d) ? ' Best guess: ' + G.bestGuess(d) + ' (' + (idn.candidates[0].confidence || 'low') + ').' : ' Nothing names it yet.'));
  return el;
}

export function secChip(id, { showOk = false } = {}) {
  const lvl = G.secLevel(id), sec = G.securityOf(id);
  if (!lvl) return showOk ? h('span', { class: 'secc none' }, 'not assessed') : null;
  if (lvl === 'ok' && !showOk) return null;
  const el = h('span', { class: 'secc ' + lvl }, icon(lvl === 'blocked' ? 'block' : lvl === 'ok' ? 'check' : lvl === 'suspicious' ? 'warning' : 'eye', 12), lvl === 'ok' ? 'no findings' : lvl === 'watch' ? 'worth a look' : lvl);
  if (sec && (sec.reasons || []).length) tip(el, sec.reasons.map(r => r.text).join(' · '));
  return el;
}

export function setFocus(key) { const f = get().filters; set({ filters: { ...f, focus: f.focus === key ? null : key } }); }

/** The one-line verdict: the worst thing that is true right now. */
export function verdict() {
  const st = get();
  if (!st.inventory || !st.live) return { cls: 'none', text: 'No reading yet', icon: 'shield' };
  const s = G.secSummary();
  if (s.suspicious) return { cls: 'danger', text: plural(s.suspicious, 'suspicious device'), icon: 'warning' };
  if (s.unidentified) return { cls: 'caution', text: s.unidentified + ' not identified', icon: 'shield' };
  if (!s.assessed) return { cls: 'none', text: 'Security not assessed', icon: 'shield' };
  if (s.fresh) return { cls: 'info', text: s.fresh + ' new today', icon: 'shield' };
  return { cls: 'ok', text: 'No findings', icon: 'security' };
}

/** The verdict for the whole house: the worse of the devices' and the threat scan's. `view` is where it leads. */
export function overallVerdict() {
  const d = verdict(), t = threatLevel();
  const dr = { danger: 4, caution: 2, none: 1, info: 0.5, ok: 0 }[d.cls] || 0;
  if (t.rank > 0 && t.rank >= dr) return { cls: t.cls, text: t.pill, icon: t.icon, view: 'threats' };
  return { ...d, view: 'security' };
}

/** Top bar: the verdict, then the counts. A count filters the map and the lists to those devices. */
export function topSummary() {
  const st = get();
  const el = h('div', { class: 'summary full', role: 'group', 'aria-label': 'Security summary' });
  const v = overallVerdict();
  const vb = h('button', { class: 'verdict-btn v-' + v.cls, type: 'button', onClick: () => go({ view: v.view, panel: null }) }, icon(v.icon, 14), h('span', null, v.text));
  tip(vb, v.view === 'threats' ? h('span', null, 'Open the threats', h('kbd', null, 'G T')) : h('span', null, 'Open the security overview', h('kbd', null, 'G X')));
  el.appendChild(vb);
  if (!st.live || !st.inventory) { el.appendChild(h('span', { class: 'age' + (st.liveError ? ' stale' : '') }, st.liveError ? 'No live reading: ' + st.liveError : 'Waiting for the first scan…')); return el; }
  const s = G.secSummary(), f = st.filters.focus;
  const cnt = (key, n, label, cls, hint) => {
    const b = h('button', { class: 'cnt ' + (cls || '') + (n ? '' : ' zero'), type: 'button', 'aria-pressed': String(f === key && !!key), onClick: () => (key ? setFocus(key) : set({ filters: { ...get().filters, focus: null, status: null } })) }, h('b', null, String(n)), h('span', null, label));
    tip(b, key ? (f === key ? 'Showing only these. Click to show everything.' : hint) : 'Everything in the inventory and every host the scan has found. Click to clear filters.');
    return b;
  };
  el.append(cnt(null, s.total, 'devices'), cnt('unidentified', s.unidentified, 'not identified', 'c-caution', 'Dim everything except devices that are not identified'),
    cnt('suspicious', s.suspicious, 'suspicious', 'c-danger', 'Dim everything except suspicious devices'), cnt('blocked', s.blocked, 'blocked', 'c-muted', 'Dim everything except devices blocked at the router'),
    cnt('new', s.fresh, 'new today', 'c-info', 'Dim everything except devices first seen in the last 24 hours'));
  if (s.offline) el.appendChild(cnt('offline', s.offline, 'offline', 'c-danger', 'Dim everything except devices that stopped answering'));
  const a = liveAge();
  const age = h('span', { class: 'age' + (a.stale ? ' stale' : '') }, h('i', { class: 'beat' }), st.live.ts ? 'scanned ' + a.text + ' ago' : 'no scan yet');
  tip(age, a.stale ? 'The last scan is older than three scan intervals. Live values may be out of date.' : 'Age of the last scan by the server');
  el.appendChild(age);
  const failing = st.health && Object.entries(st.health.collectors || {}).filter(([, c]) => c.ok === false);
  if (failing && failing.length) { const fl = h('span', { class: 'age failing' }, 'Scan failing: ' + failing.map(([n]) => n).join(', ')); tip(fl, failing.map(([n, c]) => n + ': ' + (c.error || 'no detail')).join(' · ')); el.appendChild(fl); }
  return el;
}

function why(d) {
  const sec = G.securityOf(d.id), idn = G.identityOf(d), lvl = G.secLevel(d.id);
  if (sec && (sec.reasons || []).length && lvl !== 'ok') return sec.reasons[0].text + (sec.reasons.length > 1 ? ' (+' + (sec.reasons.length - 1) + ' more)' : '');
  if (idn.state === 'unidentified') return G.bestGuess(d) ? 'Not identified. Best guess: ' + G.bestGuess(d) : 'Not identified: nothing names it yet';
  if (G.statusOf(d.id) === 'offline') return 'Stopped answering';
  if (sec && (sec.reasons || []).length) return sec.reasons[0].text;
  if (idn.state === 'likely') return 'Likely ' + (G.brandOf(d) || kindLabel(d.kind)) + ': ' + (idn.basis || 'not confirmed by a probe');
  return '';
}

function row(d, { actions = true } = {}) {
  const st = get();
  const lvl = G.secLevel(d.id), sec = G.securityOf(d.id);
  const brand = G.brandOf(d);
  const seen = sec && sec.firstSeen ? h('span', { class: 'seen' }, 'first seen ' + relTime(sec.firstSeen, st.now)) : null;
  if (seen) tip(seen, absTime(sec.firstSeen));
  const el = h('div', { class: 'srow l-' + (lvl || 'none') + (st.route.sel.includes(d.id) ? ' sel' : ''), dataset: { id: d.id },
    onMouseenter: () => set({ hover: d.id }), onMouseleave: () => get().hover === d.id && set({ hover: null }) },
    h('button', { class: 'srow-main', type: 'button', onClick: e => select(d.id, { add: e.shiftKey }) },
      h('span', { class: 'ki' }, kindIcon(d.kind, 18)),
      h('span', { class: 'who' }, h('span', { class: 'n' }, statusGlyph(G.statusOf(d.id), 8), h('b', { class: 'ellipsis' }, d.name), G.isNew(d.id, st.now) ? h('span', { class: 'newtag' }, 'new') : null),
        h('span', { class: 'm ellipsis' }, [brand || (G.identityOf(d).state === 'unidentified' ? '' : kindLabel(d.kind)), G.primaryIp(d), G.connText(d)].filter(Boolean).join(' · '))),
      h('span', { class: 'chipsr' }, findingChip(d.id), secChip(d.id), idChip(d, { showConfirmed: false })),
      h('span', { class: 'why' }, why(d), seen)),
    actions ? actionBar(d.id, { labels: false, cls: 'mini' }) : null);
  return el;
}

/** The compact list for the side panel: the few things that need a decision, worst first. */
export function watchList({ limit = 5 } = {}) {
  const st = get();
  if (!st.inventory) return [];
  const items = G.concerns().filter(d => G.concernRank(d) < 5);
  const head = h('h2', null, h('span', null, 'Watch list'), h('button', { class: 'linkbtn', type: 'button', onClick: () => go({ view: 'security', panel: null }) }, items.length > limit ? 'All ' + items.length : 'Open'));
  if (!items.length) return [head, h('div', { class: 'orow quiet' }, st.live ? (G.secSummary().assessed ? 'Nothing needs a decision.' : 'Nothing is reported down. This server sends no security findings yet.') : 'No live reading yet.')];
  return [head, ...items.slice(0, limit).map(d => {
    const lvl = G.secLevel(d.id);
    const b = h('button', { class: 'orow wl l-' + (lvl || 'none'), type: 'button', dataset: { id: d.id }, 'aria-current': st.route.sel.includes(d.id) ? 'true' : null, onClick: () => select(d.id),
      onMouseenter: () => set({ hover: d.id }), onMouseleave: () => get().hover === d.id && set({ hover: null }) },
      h('span', { class: 'mark' }), h('span', { class: 'grow' }, h('span', { class: 'name ellipsis' }, d.name), h('span', { class: 'wr' }, why(d))));
    return b;
  })];
}

export function createSecurity() {
  const head = h('div', { class: 'sec-head' });
  const body = h('div', { class: 'sec-body scroll grow' });
  const el = h('div', { class: 'view secview' }, head, body);
  let showRest = false;

  /** Addresses the router blocks that match no device here: they still deserve a row, and a way to unblock. */
  function orphans() {
    const st = get();
    const macs = new Set(G.devices().flatMap(d => [G.identityOf(d).mac, ...(d.net || []).map(n => n.mac)]).filter(Boolean).map(m => String(m).toUpperCase()));
    const rl = st.router && (st.router.blockList || st.router.blocked);
    const fromRouter = Array.isArray(rl) ? rl.filter(b => b.active !== false) : null;
    const list = (fromRouter || (st.inventory.router && st.inventory.router.blocked) || []).filter(b => b && b.mac && !b.deviceId && !macs.has(String(b.mac).toUpperCase()));
    if (!list.length) return [];
    const trustNote = fromRouter ? 'read from the router now' : 'as read from the router' + (st.inventory.router && st.inventory.router.readAt ? ' on ' + st.inventory.router.readAt : '') + ', not a live reading';
    return [h('h2', { class: 'sgroup' }, 'Blocked at the router, not on the network', h('span', { class: 'count' }, String(list.length))),
      h('p', { class: 'muted pad' }, 'The router blocks these addresses and no device here matches them (' + trustNote + ').'),
      ...list.map(b => h('div', { class: 'srow l-blocked orphan' },
        h('div', { class: 'srow-main' }, h('span', { class: 'ki' }, icon('block', 18)),
          h('span', { class: 'who' }, h('span', { class: 'n' }, h('b', { class: 'ellipsis' }, b.name || 'No name')), h('span', { class: 'm mono' }, b.mac + (b.randomizedMac ? ' · randomized' : ''))),
          h('span', { class: 'chipsr' }, h('span', { class: 'secc blocked' }, icon('block', 12), 'blocked')),
          h('span', { class: 'why' }, b.note || '')),
        h('div', { class: 'actbar mini' }, h('button', { class: 'act r-change', type: 'button', onClick: () => unblockMac(b) }, icon('unblock', 14), h('span', null, 'Unblock')))))];
  }
  /** The router's own settings, as findings: what is open that need not be. */
  function routerCard() {
    const r = get().router;
    if (!r || !r.posture) return [];
    const p = r.posture;
    const item = (bad, badText, okText) => (bad == null ? null : h('span', { class: 'pst ' + (bad ? 'bad' : 'ok') }, icon(bad ? 'warning' : 'check', 12), bad ? badText : okText));
    const rid = (G.meshRoot() || {}).id;
    const items = [
      item(p.wanAdmin, 'Its admin page can be reached from the internet', 'Admin page not reachable from the internet'),
      item(p.wps, 'WPS is on: a push-button way onto the Wi-Fi', 'WPS is off'),
      item(p.upnp, 'UPnP is on: devices can open ports to the internet by themselves', 'UPnP is off'),
      item(p.telnet, 'Telnet is on', 'Telnet is off'),
      p.ssh != null ? item(p.ssh === 'wan' || p.ssh === 'lan+wan' || p.ssh === true, 'SSH is open to the internet', p.ssh ? 'SSH from the LAN only' : 'SSH is off') : null,
      item(p.firmwareUpdate, 'A firmware update is waiting', 'Firmware is up to date'),
    ].filter(Boolean);
    const bad = items.filter(x => x.classList.contains('bad')).length;
    return [h('h2', { class: 'sgroup' }, 'The router itself', h('span', { class: 'count' }, bad ? plural(bad, 'finding') : 'no findings')),
      h('div', { class: 'rt-card' }, h('span', { class: 'ki' }, kindIcon('router', 18)),
        h('button', { class: 'who', type: 'button', onClick: () => rid && select(rid) }, h('b', null, rid ? G.deviceName(rid) : 'Router'),
          h('span', { class: 'm' }, [r.model, r.firmware ? 'firmware ' + r.firmware : null, Array.isArray(r.clients) ? plural(r.clients.length, 'client') : null, r.transport ? 'read over ' + (r.transport === 'ssh' ? 'SSH' : 'its web login') : null, r.stale ? 'reading is stale' : null].filter(Boolean).join(' · '))),
        h('div', { class: 'posture' }, items))];
  }
  function unblockMac(b) {
    const rt = G.routerState() || get().router || {};
    const note = h('div');
    const go2 = h('button', { class: 'btn primary', type: 'button' }, icon('unblock', 14), 'Unblock at the router');
    const d = dialog({ title: 'Unblock ' + (b.name || b.mac), body: h('div', { class: 'body confirm-act' },
      h('dl', { class: 'cf-dl' }, h('dt', null, 'What happens'), h('dd', null, 'Removes ' + b.mac + (b.name ? ' (' + b.name + ')' : '') + ' from the router\'s block list. If that device comes back it can join the network and reach the internet.'),
        h('dt', null, 'Undo'), h('dd', null, 'When it joins it shows up on the map as a new host, and you can block it again from there.')),
      rt.configured === false ? callout('caution', 'No router login is stored, so this cannot be done yet. Add it in Settings.') : null, note,
      h('div', { class: 'cf-foot' }, h('span', { class: 'grow' }), h('button', { class: 'btn', type: 'button', onClick: () => d.close() }, 'Cancel'), go2)) });
    go2.onclick = async () => {
      go2.disabled = true; fill(go2, h('span', { class: 'spinner' }), 'Asking the router…');
      let res;
      try { res = await api.routerUnblock(b.mac); } catch (e) { res = { ok: false, error: e.status === 404 ? 'This server cannot unblock by address yet.' : e.message }; }
      if (!res || res.ok === false) { go2.disabled = false; fill(go2, icon('unblock', 14), 'Try again'); fill(note, callout('danger', h('b', null, 'Not unblocked. '), (res && res.error) || 'The server gave no reason.')); return; }
      d.close(); toast((b.name || b.mac) + ' is off the router\'s block list.', { intent: 'success' }); window.__hmReload && window.__hmReload();
    };
  }

  function render() {
    const st = get();
    if (!st.inventory) { fill(head); fill(body, st.invError ? errorState(st.invError, () => window.__hmReload && window.__hmReload(), 'The inventory could not be loaded.') : skeleton(10)); return; }
    const s = G.secSummary(), v = verdict(), rt = G.routerState();
    const big = (n, label, cls, key) => {
      const b = h('button', { class: 'big ' + (cls || '') + (n ? '' : ' zero'), type: 'button', 'aria-pressed': String(st.filters.focus === key && !!key), onClick: () => (key ? setFocus(key) : set({ filters: { ...get().filters, focus: null } })) }, h('b', null, String(n)), h('span', null, label));
      return b;
    };
    const a = liveAge();
    fill(head,
      h('div', { class: 'sec-title' }, h('h1', null, 'Security'), h('span', { class: 'verdict-btn static v-' + v.cls }, icon(v.icon, 14), v.text),
        h('span', { class: 'grow' }), h('span', { class: 'muted scan' + (a.stale ? ' stale' : '') }, st.live && st.live.ts ? 'scanned ' + a.text + ' ago' : 'no scan yet')),
      h('div', { class: 'bigs', role: 'group', 'aria-label': 'Counts' }, big(s.total, 'devices', '', null), big(s.unidentified, 'not identified', 'c-caution', 'unidentified'), big(s.suspicious, 'suspicious', 'c-danger', 'suspicious'),
        big(s.blocked, 'blocked', 'c-muted', 'blocked'), big(s.fresh, 'new today', 'c-info', 'new'), big(s.offline, 'offline', s.offline ? 'c-danger' : '', 'offline')),
      !s.assessed ? h('p', { class: 'sec-note' }, icon('info', 14), 'This server sends no security findings yet, so nothing can be called suspicious or blocked. Identity comes from the inventory.') : null,
      rt && rt.configured === false ? h('p', { class: 'sec-note' }, icon('key', 14), h('span', null, 'No router login is stored, so the app cannot read which access point each device uses, or block a device. '),
        h('button', { class: 'linkbtn', type: 'button', onClick: () => go({ view: 'settings', sel: [], panel: null }) }, 'Add the router login')) : null,
      rt && rt.configured && rt.ok === false ? h('p', { class: 'sec-note bad' }, icon('warning', 14), 'The router login is stored but the router did not accept it: ' + (rt.error || 'no detail') + '.') : null);

    const f = st.filters.focus;
    const all = G.things();
    const concerns = G.concerns();
    const pick = fn => concerns.filter(fn);
    const groups = f ? [[{ unidentified: 'Not identified', suspicious: 'Suspicious', blocked: 'Blocked at the router', new: 'New today', offline: 'Offline' }[f], all.filter(d => G.matchesFocus(d, f)).sort((x, y) => G.concernRank(x) - G.concernRank(y)), 'No devices match. Select the count again to show everything.']] : [
      ['Needs a decision', pick(d => G.concernRank(d) < 2), null],
      ['Blocked at the router', pick(d => G.concernRank(d) === 2), null],
      ['Worth a look', pick(d => { const r = G.concernRank(d); return r > 2 && r < 5; }), null],
      ['Likely, not confirmed', pick(d => G.concernRank(d) === 5), null],
    ];
    const out = [];
    let routerShown = !!f;
    for (const [title, ds, empty] of groups) {
      if (!routerShown && title === 'Likely, not confirmed') { routerShown = true; out.push(...routerCard()); }
      if (!ds.length && !empty) continue;
      out.push(h('h2', { class: 'sgroup' }, title, h('span', { class: 'count' }, String(ds.length))));
      if (!ds.length) out.push(h('p', { class: 'muted pad' }, empty)); else out.push(...ds.map(d => row(d)));
    }
    if (!f) {
      const rest = all.filter(d => !concerns.includes(d));
      if (!concerns.length) out.push(h('p', { class: 'allclear' }, icon('security', 18), s.assessed ? 'Every device is identified and none has a finding.' : 'Every device in the inventory is identified.'));
      if (rest.length) {
        out.push(h('h2', { class: 'sgroup' }, h('button', { class: 'linkbtn', type: 'button', 'aria-expanded': String(showRest), onClick: () => { showRest = !showRest; render(); } }, icon('chevron', 14, showRest ? 'open' : ''), 'Identified, no findings'), h('span', { class: 'count' }, String(rest.length))));
        if (showRest) out.push(...rest.map(d => row(d, { actions: false })));
      }
    }
    if (!routerShown) out.push(...routerCard());
    out.push(...orphans());
    const top = body.scrollTop;
    fill(body, out);
    body.scrollTop = top;
  }
  let dirty = true;
  on(['inventory', 'invError', 'live', 'filters', 'router', 'threats'], () => { if (get().route.view === 'security') render(); else dirty = true; });
  on(['route'], st => {
    if (st.route.view !== 'security') return;
    if (dirty) { dirty = false; return render(); }
    for (const r of body.querySelectorAll('.srow')) r.classList.toggle('sel', st.route.sel.includes(r.dataset.id));
  });
  on(['hover'], () => { if (get().route.view !== 'security') return; const hv = get().hover; for (const r of body.querySelectorAll('.srow')) r.classList.toggle('hov', r.dataset.id === hv); });
  return { el, show() { dirty = false; render(); } };
}
