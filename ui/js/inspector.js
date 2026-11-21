// The inspector: one device or one cable, with provenance on every value.
import { h, fill, isPhone } from './dom.js';
import { icon, kindIcon } from './icons.js';
import { get, on, select, clearSelection, go } from './store.js';
import { api } from './api.js';
import * as G from './graph.js';
import { statusGlyph, trustEl, liveTrust, liveAge, section, prop, callout, deviceChip, copyBtn, popover, tip, skeleton, errorState, valueNodes, carriesIcons, pathStrip, internetPath, toast } from './ui.js';
import { actionRows, actionBar } from './actions.js';
import { idChip, secChip } from './security.js';
import { isFindingId, renderFinding, leaveFinding, deviceFindings } from './threats.js';
import { statusLabel, kindLabel, cableName, cableCls, relTime, absTime, flatten, hostOf, isHttpUrl, PORT_TYPE, LINK_STATUS, TRUST, plural, clock, rate } from './fmt.js';
import { render as md, headings } from './markdown.js';
import { askAbout } from './agent.js';
import { setLayer } from './mapview.js';
import { copyText } from './dom.js';

const openEvidence = new Set(), guideOpen = new Set();   // kept across live re-renders
const cache = new Map();   // id → { data, error, at, loading }

function load(id, force) {
  const c = cache.get(id) || {};
  if (c.loading || (!force && c.data && Date.now() - c.at < 30000)) return;
  cache.set(id, { ...c, loading: true });
  api.device(id).then(data => { cache.set(id, { data, at: Date.now() }); rerender(id); })
    .catch(e => { cache.set(id, { data: c.data, error: e.message, at: Date.now() }); rerender(id); });
}
let rerender = () => {};

function hintFor(d) {
  const inv = get().inventory;
  const q = (inv.openQuestions || []).find(x => (x.devices || []).includes(d.id));
  return q ? 'Open question: ' + q.text : null;
}

function statusStrip(d) {
  const st = G.statusOf(d.id), lv = G.liveOf(d.id) || {};
  const now = get().now;
  let text;
  if (st === 'unmonitored') {
    const why = (lv.checks || []).find(c => c.name === 'probe');
    text = 'Not monitored: no probe is possible for this device' + (why && why.detail ? ' (' + why.detail.replace(/\.\s*Shown as.*$/i, '').replace(/^Nothing to probe:\s*/i, '') + ').' : '.');
  } else if (st === 'inferred') text = 'Inferred from links: this device has no address and cannot be probed. It is shown as working because a cable through it is up.';
  else if (!get().live) text = 'Unknown: no live reading has arrived from the server yet.';
  else {
    const seen = lv.lastSeen ? (st === 'online' || st === 'degraded' ? 'seen ' : 'last seen ') + relTime(lv.lastSeen, now) : 'never seen by this monitor';
    text = statusLabel(st) + ' · ' + seen;
  }
  const bits = [];
  if (lv.latencyMs != null && st !== 'unmonitored') bits.push(h('span', { class: 'mono' }, lv.latencyMs + ' ms'));
  if (lv.lastChange) { const c = h('span', null, 'changed ' + relTime(lv.lastChange, now)); tip(c, absTime(lv.lastChange)); bits.push(c); }
  return h('div', { class: 'status-strip s-' + st }, h('div', { class: 'row', style: { alignItems: 'flex-start' } }, h('span', { style: { marginTop: '4px' } }, statusGlyph(st)), h('div', { class: 'grow' }, h('div', null, text),
    bits.length ? h('div', { class: 'row muted', style: { fontSize: '12px', marginTop: '2px', flexWrap: 'wrap' } }, bits.flatMap((b, i) => (i ? ['·', b] : [b]))) : null)));
}

function connectionRow(l, devId) {
  const { self, other } = G.peer(l, devId);
  const lv = G.linkLive(l.id) || {};
  const view = G.kvmView();
  const inactive = !!l.kvmInput && view !== 'both' && l.kvmInput !== view;
  const peerBtn = h('button', { class: 'linkbtn', type: 'button', onClick: () => select(other.dev) }, G.deviceName(other.dev));
  const cable = h('button', { class: 'linkbtn cab', type: 'button', onClick: () => select(l.id) }, (l.label || cableName(l.cable)) + (l.speed && !(l.label || '').includes(l.speed) ? ' · ' + l.speed : ''));
  tip(cable, 'Open this cable');
  const more = (l.evidence || l.risk) ? h('details', { open: openEvidence.has(l.id), onToggle: e => { if (e.target.open) openEvidence.add(l.id); else openEvidence.delete(l.id); } }, h('summary', null, 'evidence'), l.evidence ? h('p', null, valueNodes(l.evidence)) : null, l.risk ? h('p', { class: 'risk' }, 'Risk: ', valueNodes(l.risk)) : null) : null;
  return h('div', { class: `conn c-${cableCls(l.cable)} t-${l.verified}` },
    h('span', { class: 'sw' }),
    h('div', { class: 'grow' },
      h('div', { class: 'l1' }, self.port ? h('span', { class: 'mono' }, G.portShort(devId, self.port)) : h('span', { class: 'nc' }, 'port not confirmed'), h('span', { class: 'arrow' }, '→'), cable, h('span', { class: 'arrow' }, '→'),
        peerBtn, other.port ? h('span', { class: 'mono muted' }, '· ' + G.portShort(other.dev, other.port)) : h('span', { class: 'nc' }, '· port not confirmed')),
      h('div', { class: 'l2' }, carriesIcons(l.carries), lv.status ? h('span', { class: 'tag' + (lv.status === 'down' ? ' danger' : '') }, LINK_STATUS[lv.status] || lv.status) : null,
        inactive ? h('span', { class: 'tag' }, 'inactive KVM input') : null, l.risk ? h('span', { class: 'tag caution' }, icon('warning', 12), 'risk') : null),
      more),
    h('div', { class: 't' }, trustEl(l.verified)));
}

function portsGrid(d, specs) {
  const specOf = id => ((specs && specs.ports) || []).find(p => p.id === id);
  return h('div', { class: 'ports' }, (d.ports || []).map(p => {
    const l = G.linkOnPort(d.id, p.id);
    const sp = specOf(p.id);
    const lv = l ? G.linkLive(l.id) || {} : {};
    const peer = l ? G.peer(l, d.id).other : null;
    const row = h('div', { class: 'port-row' + (l ? '' : ' free') },
      h('span', { class: 'mono pl' }, valueNodes(p.label)), h('span', { class: 'tag' }, PORT_TYPE[p.type] || p.type || 'port'),
      l ? h('button', { class: 'linkbtn ellipsis', onClick: () => select(peer.dev) }, G.deviceName(peer.dev)) : h('span', { class: 'muted' }, 'free'),
      l ? h('span', { class: `dot c-${cableCls(l.cable)}` + (lv.status === 'down' ? ' down' : ''), role: 'img', 'aria-label': 'Link ' + (LINK_STATUS[lv.status] || 'status not known') }) : h('span'));
    if (sp && sp.spec) tip(row, sp.spec);
    return row;
  }));
}

function guideBlock(guide, id) {
  const hs = headings(guide);
  const wrap = h('div', { class: 'guide' });
  let open = guideOpen.has(id);
  const draw = () => {
    if (open || hs.length <= 3) { fill(wrap, md(guide, { minHeading: 4 }), hs.length > 3 ? h('button', { class: 'btn sm', onClick: () => { open = false; guideOpen.delete(id); draw(); } }, 'Show less') : null); return; }
    // collapsed: everything up to the 4th heading
    const lines = guide.split('\n'); let n = 0, cut = lines.length;
    for (let i = 0; i < lines.length; i++) if (/^#{1,6}\s/.test(lines[i]) && ++n === 4) { cut = i; break; }
    fill(wrap, md(lines.slice(0, cut).join('\n'), { minHeading: 4 }), h('button', { class: 'btn sm', onClick: () => { open = true; guideOpen.add(id); draw(); } }, `Show full guide (${hs.length - 3} more sections)`));
  };
  draw();
  return wrap;
}

function identitySection(d) {
  const idn = G.identityOf(d);
  const now = get().now;
  const brand = G.brandOf(d);
  const head = h('div', { class: 'id-head s-' + (idn.state || 'none') }, idChip(d),
    h('div', { class: 'grow' }, h('b', null, idn.state === 'unidentified' ? 'Nothing names this device yet' : brand || kindLabel(d.kind)),
      idn.basis ? h('span', { class: 'basis' }, 'Rests on: ', valueNodes(idn.basis)) : idn.state === 'unidentified' ? h('span', { class: 'basis' }, 'The app keeps looking each scan. You can run a deep scan, ask the agent, or say what it is.') : null));
  const out = [head];
  const mac = idn.mac || (d.net || []).map(n => n.mac).find(Boolean);
  if (mac || idn.macVendor || idn.randomizedMac) out.push(h('div', { class: 'props' },
    mac ? prop('MAC address', mac, { mono: true, trust: 'live' }) : null,
    idn.randomizedMac ? prop('MAC maker', 'none: the address is randomized (private), so it says nothing about who made the device', { copy: false, trust: 'live' })
      : idn.macVendor ? prop('MAC maker', idn.macVendor, { trust: 'live', extra: 'prefix' }) : null));
  if (idn.candidates.length) out.push(h('div', { class: 'sub-h' }, idn.state === 'confirmed' ? 'Other candidates considered' : 'Candidates'), h('div', { class: 'cands-l' }, idn.candidates.map(c => h('div', { class: 'cand c-' + (c.confidence || 'low') },
    h('div', { class: 'row' }, h('b', { class: 'grow' }, [c.vendor, c.model].filter(Boolean).join(' ') || c.type || 'Unnamed candidate'), h('span', { class: 'conf-w' }, h('span', { class: 'meter' }, [0, 1, 2].map(i => h('i', { class: i < ({ high: 3, medium: 2, low: 1 }[c.confidence] || 1) ? 'on' : '' }))), (c.confidence || 'low') + ' confidence')),
    c.type && (c.vendor || c.model) ? h('div', { class: 'ty' }, c.type) : null,
    c.basis ? h('div', { class: 'ba' }, 'Rests on: ', valueNodes(c.basis)) : null))));
  if (idn.evidence.length) out.push(h('div', { class: 'sub-h' }, 'Evidence'), h('div', { class: 'ev-list2' }, idn.evidence.map(e => {
    const t = e.ts ? h('span', { class: 'tm mono muted' }, relTime(e.ts, now)) : null; if (t) tip(t, absTime(e.ts));
    return h('div', { class: 'evi' }, h('span', { class: 'src' }, e.source || 'probe'), h('span', { class: 'grow' }, h('b', null, e.label || ''), ' ', h('span', { class: 'val' }, e.value == null ? '' : String(e.value))), t);
  })));
  else if (idn.assessed) out.push(h('p', { class: 'muted small' }, 'No evidence is recorded.'));
  else out.push(h('p', { class: 'muted small' }, 'This server sent no identity record. What is shown comes from the inventory and the documentation notes.'));
  out.push(actionBar(d.id, { only: ['identify', 'scan', 'investigate'], cls: 'inline' }));
  return section('identity', 'Identity', out, { meta: idn.state ? G.ID_WORD[idn.state] : 'not assessed' });
}

function securitySection(d) {
  const sec = G.securityOf(d.id), lvl = G.secLevel(d.id), lv = G.liveOf(d.id) || {};
  const now = get().now;
  if (!sec) return section('security', 'Security', [deviceFindings(d.id), h('p', { class: 'muted small' }, 'This server sends no security findings for the device yet.')], { meta: 'not assessed' });
  const out = [h('div', { class: 'sec-headline l-' + lvl }, secChip(d.id, { showOk: true }), sec.score != null ? h('span', { class: 'score' }, h('span', { class: 'bar' }, h('i', { style: { width: Math.max(2, Math.min(100, sec.score)) + '%' } })), h('span', { class: 'mono' }, sec.score + ' / 100')) : null)];
  out.push(deviceFindings(d.id));
  if ((sec.reasons || []).length) out.push(h('ul', { class: 'reasons' }, sec.reasons.map(r => h('li', null, icon(lvl === 'ok' ? 'info' : 'warning', 14), h('span', null, r.text)))));
  else out.push(h('p', { class: 'muted small' }, 'Nothing was found that needs a look.'));
  const ports = sec.openPorts || [];
  out.push(h('div', { class: 'sub-h' }, 'Open ports'), ports.length ? h('div', { class: 'ports-l' }, ports.map(p => h('span', { class: 'port-c' + (p.risky ? ' risky' : '') }, h('b', { class: 'mono' }, String(p.port)), p.service || 'unknown', p.risky ? h('span', { class: 'rk' }, 'risky') : null)))
    : h('p', { class: 'muted small' }, 'None of the scanned ports answered.'));
  out.push(h('div', { class: 'props' },
    sec.firstSeen ? prop('First seen', relTime(sec.firstSeen, now) + (G.isNew(d.id, now) ? ' (new)' : ''), { trustNode: liveTrust(), raw: absTime(sec.firstSeen) }) : null,
    lv.traffic ? prop('Traffic now', '↓ ' + rate(lv.traffic.rxBps) + '  ↑ ' + rate(lv.traffic.txBps), { mono: true, trustNode: trustEl('live', 'router') }) : null));
  return section('security', 'Security', out, { meta: lvl === 'ok' ? 'no findings' : lvl === 'watch' ? 'worth a look' : lvl });
}

function pathSection(d) {
  const c = G.conn(d);
  const w = c.medium === 'wifi' ? c : c.wifi;
  const out = [internetPath(d.id, { vertical: true })];
  if (w) {
    const t = (w.link && w.link.verified) || 'plan';
    out.push(h('div', { class: 'sub-h' }, 'Wi-Fi'), h('div', { class: 'props' },
      prop('Access point', w.ap ? h('button', { class: 'linkbtn', onClick: () => select(w.ap) }, G.deviceName(w.ap)) : h('span', { class: 'nc' }, 'not known'), { trust: w.source ? 'live' : t, extra: w.source || null, copy: false,
        hint: 'Known only when the router\'s client list or a matching BSSID says so.' }),
      w.band ? prop('Band', w.band, { trust: w.source ? 'live' : t }) : null,
      w.rssi != null ? prop('Signal', w.rssi + ' dBm', { mono: true, trust: w.source ? 'live' : t }) : null,
      w.ssid ? prop('Network name', w.ssid, { trust: w.source ? 'live' : t }) : null),
      w.link && w.link.evidence ? h('p', { class: 'muted small' }, valueNodes(w.link.evidence)) : null);
  }
  const hops = G.upstream(d.id);
  return section('path', 'Path to the internet', out, { meta: hops ? (hops.length ? plural(hops.length, 'hop') : null) : G.MEDIUM[c.medium] || null });
}

/** What is in each socket of a computer that reports them, read from the machine itself. */
function socketsSection(d) {
  const inv = get().inventory, live = get().live;
  const hs = ((live && live.wiring && live.wiring.hosts) || (inv && inv.wiring && inv.wiring.hosts) || {})[d.id];
  if (!hs || !(hs.ports || []).length) return null;
  return section('sockets', 'Sockets', h('div', { class: 'props' }, hs.ports.map(p =>
    prop(p.label, p.what && p.what.length ? p.what.join(' + ') : p.active ? 'something is plugged in, it does not say what' : h('span', { class: 'nc' }, 'empty'), { trust: 'live', copy: false }))),
    { meta: 'read from the machine ' + relTime(hs.ts, get().now) });
}

function deviceBody(d) {
  const st = get();
  const c = cache.get(d.id) || {};
  const data = c.data || {};
  const specs = (data.knowledge && data.knowledge.specs) || d.knowledge || null;
  const guide = data.knowledge ? data.knowledge.guideMarkdown : null;
  const lv = G.liveOf(d.id) || {};
  const hint = hintFor(d);
  const out = [];

  out.push(statusStrip(d));
  out.push(section('actions', 'Actions', actionRows(d.id), { meta: 'each asks before it runs' }));
  out.push(identitySection(d), securitySection(d), pathSection(d));
  const sockets = socketsSection(d);
  if (sockets) out.push(sockets);
  if (d.role) out.push(h('p', { class: 'role' }, d.role));
  // Location: the room and area, with where that knowledge comes from
  const pl = d.placement;
  const where = G.groupLabel(d.zone);
  const plTrust = !pl ? h('span', { class: 'trust' }, 'no basis recorded') : ['live', 'plan', 'reported'].includes(pl.verified) ? trustEl(pl.verified) : h('span', { class: 'trust' }, 'not known');
  out.push(h('div', { class: 'loc' }, h('div', { class: 'props' }, prop('Location', h('span', null, valueNodes(where), pl && pl.basis ? h('span', { class: 'basis' }, valueNodes(pl.basis)) : null), { trustNode: plTrust, raw: where }))));
  if ((d.constraints || []).length || (d.rules || []).length)
    out.push(h('div', { class: 'pad' }, [...(d.constraints || []), ...(d.rules || [])].map(t => callout('caution', t))));

  const checks = lv.checks || [];
  if (checks.length) out.push(section('checks', 'Live checks', h('div', { class: 'checks' }, checks.map(ck => h('div', { class: 'check-row' },
    h('span', { class: 'r ' + (ck.ok === true ? 'ok' : ck.ok === false ? 'bad' : 'na'), role: 'img', 'aria-label': ck.ok === true ? 'Passed' : ck.ok === false ? 'Failed' : 'Not applicable' }, icon(ck.ok === true ? 'check' : ck.ok === false ? 'cross' : 'dash', 14)),
    h('span', { class: 'n' }, ck.name), h('span', { class: 'd mono' }, ck.detail || '')))), { meta: liveAge().text ? 'checked ' + liveAge().text + ' ago' : null }));

  const ls = G.linksOf(d.id);
  out.push(section('connections', 'Cables', ls.length ? h('div', null, ls.map(l => connectionRow(l, d.id)))
    : h('p', { class: 'muted' }, G.isWifi(d) ? 'No cable: it is on Wi-Fi. See the path above.' : G.isRemote(d) ? 'Seen over Tailscale, not on the LAN. No cable is modelled.' : d.zone === 'spares' ? 'In the spares drawer: owned, not wired in.' : 'No cable is recorded for this device.'), { meta: ls.length ? String(ls.length) : null, open: ls.length > 0 }));

  if ((d.ports || []).length) out.push(section('ports', 'Ports', portsGrid(d, specs), { meta: `${(d.ports || []).filter(p => G.linkOnPort(d.id, p.id)).length} of ${d.ports.length} in use` }));

  if ((d.net || []).length) out.push(section('network', 'Network', h('div', null, d.net.map(n => h('div', { class: 'netcard' },
    n.ip ? prop('IP address', n.ip, { mono: true, trust: n.verified || d.verified }) : null,
    n.if ? prop('Interface', n.if, { mono: true, trust: n.verified || d.verified }) : null,
    n.name ? prop('Name', n.name, { mono: true, trust: n.verified || d.verified }) : null,
    n.medium ? prop('Medium', n.medium === 'wifi' ? 'Wi-Fi' : n.medium, { trust: n.verified || d.verified }) : null,
    n.linkSpeed ? prop('Link speed', n.linkSpeed, { mono: true, trust: n.verified || d.verified }) : null,
    n.via ? prop('Through', h('button', { class: 'linkbtn', onClick: () => select(n.via) }, G.deviceName(n.via)), { trust: n.verified || d.verified, copy: false }) : null,
    n.note ? prop('Note', n.note, { trust: n.verified || d.verified, hint }) : null)))));

  const liveFacts = flatten(lv.facts || {});
  if (liveFacts.length) out.push(section('livefacts', 'Measured now', h('div', { class: 'props' }, liveFacts.map(([k, v]) => prop(k, v, { mono: /^[\d.:x@ a-f]+$/i.test(v) || /\d/.test(v), trustNode: liveTrust() })))));

  const facts = [['Vendor', d.vendor], ['Model', d.model], ...flatten(d.facts || {}), d.ha ? ['Home Assistant entity', d.ha] : null].filter(x => x && x[1]);
  if (facts.length) out.push(section('facts', 'Facts', h('div', { class: 'props' }, facts.map(([k, v]) => {
    const isUrl = isHttpUrl(v);
    return prop(k, isUrl ? h('a', { href: v, target: '_blank', rel: 'noopener noreferrer' }, v) : v, { trust: d.verified, hint, raw: v, mono: isUrl });
  })), { meta: 'from the inventory' }));

  if (specs) {
    const groups = new Map();
    for (const sp of specs.specs || []) { if (!groups.has(sp.group || 'General')) groups.set(sp.group || 'General', []); groups.get(sp.group || 'General').push(sp); }
    const id = specs.identity || {};
    out.push(section('specs', 'Specs', h('div', null,
      specs.summary ? h('p', { style: { lineHeight: 1.45, marginBottom: '8px' } }, valueNodes(specs.summary)) : null,
      id.confidence ? h('p', { class: 'identity' }, 'Identity: ', h('b', null, id.confidence), id.basis ? [' · basis: ', valueNodes(id.basis)] : null) : null,
      [...groups].map(([g, rows]) => [h('div', { class: 'sub-h' }, g), h('div', { class: 'props' }, rows.map(sp => prop(sp.label, sp.value, { trust: 'reported', extra: 'docs' })))]),
      (specs.limits || []).length ? [h('div', { class: 'sub-h' }, 'Limits'), h('ul', { class: 'bullets' }, specs.limits.map(t => h('li', null, valueNodes(t))))] : null),
      { meta: specs.researchedAt ? 'researched ' + specs.researchedAt : 'from documentation' }));
  }

  const docs = (specs && specs.docs) || [];
  const docBody = [];
  if (docs.length) docBody.push(h('ul', { class: 'doclist' }, docs.map(doc => h('li', null, h('span', { class: 'tag' }, doc.kind || 'doc'),
    isHttpUrl(doc.url) ? h('a', { href: doc.url, target: '_blank', rel: 'noopener noreferrer' }, doc.title || doc.url) : h('span', null, doc.title || ''), h('span', { class: 'mono muted host' }, hostOf(doc.url))))));
  if (guide) docBody.push(h('div', { class: 'sub-h' }, 'Guide'), guideBlock(guide, d.id));
  else if (c.loading && !c.data) docBody.push(skeleton(4));
  else if (c.error && !c.data) docBody.push(errorState(c.error, () => load(d.id, true), 'The guide and history could not be loaded.'));
  else if (!docs.length) docBody.push(h('p', { class: 'muted' }, 'No documentation has been researched for this device yet.'));
  else if (d.hasGuide === false) docBody.push(h('p', { class: 'muted' }, 'No troubleshooting guide has been written for this device.'));
  out.push(section('docs', 'Documentation', docBody, { meta: docs.length ? plural(docs.length, 'link') : null }));

  const events = data.events;
  out.push(section('history', 'History', !events ? (c.error ? h('p', { class: 'muted' }, 'History could not be loaded.') : skeleton(3))
    : events.length ? h('div', { class: 'hist' }, events.map(ev => { const t = h('span', { class: 'mono muted tm' }, relTime(ev.ts, st.now)); tip(t, absTime(ev.ts)); return h('div', { class: 'hist-row' }, t, h('span', null, ev.text || `${ev.from || '?'} → ${ev.to || '?'}`)); }))
      : h('p', { class: 'muted' }, 'No status changes have been recorded for this device.'), { open: true, meta: events && events.length ? String(events.length) : null }));

  const raw = { ...d }; delete raw.knowledge;
  out.push(section('raw', 'Raw', h('pre', { class: 'raw' }, JSON.stringify(raw, null, 2)), { open: false, meta: 'inventory record' }));
  return out;
}

function header(title, sub, glyph, trust, actions) {
  const back = isPhone() ? h('button', { class: 'btn minimal icon', 'aria-label': 'Back', onClick: () => (get().route.view === 'map' && get().route.panel === 'inspector' ? go({ panel: null }) : clearSelection()) }, icon('back')) : null;
  const close = isPhone() ? null : h('button', { class: 'btn minimal icon insp-close', 'aria-label': 'Close the inspector', onClick: () => clearSelection() }, icon('close'));
  if (close) tip(close, h('span', null, 'Close', h('kbd', null, 'Esc')));
  return h('header', { class: 'insp-h' },
    h('div', { class: 'row' }, back, glyph, h('h2', { class: 'grow ellipsis' }, title), close),
    h('div', { class: 'row meta' }, h('span', { class: 'grow ellipsis muted' }, sub), trust),
    h('div', { class: 'row acts' }, actions));
}

function deviceView(d) {
  const ip = G.primaryIp(d);
  const admin = d.facts && isHttpUrl(d.facts.admin) ? d.facts.admin : null;
  const moreBtn = h('button', { class: 'btn sm icon', 'aria-label': 'More actions for ' + d.name, 'aria-haspopup': 'menu', onClick: () => {
    const p = popover(moreBtn, h('div', { class: 'menu', role: 'menu' },
      h('button', { role: 'menuitem', onClick: async () => { await copyText(d.id); toast('Copied the device ID.', { intent: 'success' }); p.close(); } }, icon('copy'), 'Copy ID'),
      ip ? h('button', { role: 'menuitem', onClick: async () => { await copyText(ip); toast('Copied ' + ip + '.', { intent: 'success' }); p.close(); } }, icon('copy'), 'Copy IP address') : null,
      admin ? h('a', { role: 'menuitem', href: admin, target: '_blank', rel: 'noopener noreferrer' }, icon('external'), 'Open admin page') : null,
      get().route.view !== 'map' ? h('button', { role: 'menuitem', onClick: () => { p.close(); go({ view: 'map' }); } }, icon('map'), 'Show on map') : null), { cls: 'menu-pop', align: 'right' });
  } }, icon('dots'));
  const canTrace = G.linksOf(d.id).some(l => l.cable !== 'bluetooth');
  const acts = [
    h('button', { class: 'btn sm primary', onClick: () => askAbout([d.id]) }, 'Ask agent about this'),
    canTrace ? h('button', { class: 'btn sm', 'aria-pressed': String(!!get().route.trace), onClick: () => { setLayer('wiring'); go({ view: 'map', trace: true }); } }, icon('trace', 14), 'Trace cables') : null,
    h('span', { class: 'grow' }), moreBtn];
  const brand = G.brandOf(d);
  return [header(d.name, kindLabel(d.kind) + (brand ? ' · ' + brand : ''), h('span', { class: 'kind-ic' }, kindIcon(d.kind)), trustEl(d.verified), acts), h('div', { class: 'insp-b scroll' }, deviceBody(d))];
}

function linkView(l) {
  const lv = G.linkLive(l.id) || {};
  const view = G.kvmView();
  const end = (e, label) => (!e.dev ? prop(label, h('span', null, 'The mesh as a whole · ', h('span', { class: 'nc' }, 'access point not known')), { trust: l.verified, copy: false }) : l.cable === 'wifi' || l.cable === 'bluetooth' ? prop(label, h('button', { class: 'linkbtn', onClick: () => select(e.dev) }, G.deviceName(e.dev)), { trust: l.verified, copy: false }) : prop(label, h('span', null, h('button', { class: 'linkbtn', onClick: () => select(e.dev) }, G.deviceName(e.dev)), ' · ', e.port ? h('span', { class: 'mono' }, valueNodes(G.portLabel(e.dev, e.port))) : h('span', { class: 'nc' }, 'port not confirmed')), { trust: l.verified, copy: false }));
  const radio = l.cable === 'wifi' || l.cable === 'bluetooth';
  const tr = radio ? { chains: [], slow: new Set() } : G.trace(l.id);
  const body = [
    h('div', { class: 'pad' }, h('div', { class: `cable-sample c-${cableCls(l.cable)} t-${l.verified}` }, h('span')),
      l.risk ? callout('caution', 'Risk: ', valueNodes(l.risk)) : null),
    section('link', 'Cable', h('div', { class: 'props' },
      end(l.a, 'From'), end(l.b, 'To'),
      prop(radio ? 'Link' : 'Cable type', cableName(l.cable) + (l.state ? ' · ' + l.state : ''), { trust: l.verified }),
      l.band ? prop('Band', l.band, { trust: l.verified }) : null,
      l.rssi != null ? prop('Signal', l.rssi + ' dBm', { mono: true, trust: l.verified }) : null,
      prop('Carries', carriesIcons(l.carries), { trust: l.verified, copy: false }),
      l.speed ? prop('Speed', l.speed, { mono: true, trust: l.verified }) : prop('Speed', 'not recorded', { trust: l.verified, copy: false }),
      l.label ? prop('Label', l.label, { trust: l.verified }) : null,
      l.kvmInput ? prop('KVM input', l.kvmInput.toUpperCase() + (view !== 'both' && view !== l.kvmInput ? ' (inactive in this view)' : ''), { trust: l.verified }) : null,
      l.declared && (l.moved || l.corrected) ? prop(l.moved ? 'Moved from' : 'Inventory said', (() => { const side = e => { const [dv, pt] = String(e || '').split(':'); return G.deviceName(dv) + (pt ? ' (' + G.portLabel(dv, pt) + ')' : ''); }; return side(l.declared.from) + ' to ' + side(l.declared.to); })(), { trust: 'plan' }) : null,
      l.observed ? prop('Last seen', G.deviceName(l.observed.by) + ' read its sockets ' + relTime(l.observed.ts, get().now) + (l.observed.present ? '' : ' · not plugged in now'), { trust: 'live', copy: false }) : null,
      prop('Evidence', l.evidence || (TRUST[l.verified] || {}).meaning || 'none recorded', { trust: l.verified }))),
    section('linklive', 'Live status', h('div', { class: 'props' },
      prop('Status', lv.status ? (LINK_STATUS[lv.status] || lv.status) : 'no reading yet', { trustNode: lv.status === 'planned' ? trustEl('plan') : liveTrust(), copy: false }),
      lv.speed ? prop('Measured speed', String(lv.speed), { mono: true, trustNode: liveTrust() }) : null,
      lv.detail ? prop('Detail', lv.detail, { trustNode: lv.status === 'planned' ? trustEl('plan') : liveTrust() }) : null)),
    radio ? null : section('linktrace', 'Trace from this cable', tr.chains.length ? h('div', null, tr.chains.map(c => pathStrip(c, { slow: tr.slow, vertical: true }))) : h('p', { class: 'muted' }, 'This cable does not continue through another device.')),
    section('raw', 'Raw', h('pre', { class: 'raw' }, JSON.stringify({ id: l.id, from: l.from, to: l.to, cable: l.cable, carries: l.carries, speed: l.speed, label: l.label, kvmInput: l.kvmInput, verified: l.verified, evidence: l.evidence, risk: l.risk }, null, 2)), { open: false, meta: 'inventory record' }),
  ];
  const acts = [h('button', { class: 'btn sm primary', onClick: () => askAbout([l.a.dev, l.b.dev].filter(Boolean)) }, 'Ask agent about this'),
    l.cable !== 'wifi' ? h('button', { class: 'btn sm', onClick: () => { setLayer('wiring'); go({ view: 'map', trace: true }); } }, icon('trace', 14), 'Trace cables') : null, h('span', { class: 'grow' }), copyBtn(l.id, 'Copy ID')];
  return [header(`${cableName(l.cable)} · ${G.deviceName(l.a.dev)} → ${l.b.dev ? G.deviceName(l.b.dev) : 'the mesh'}`, (radio ? 'Radio link' : 'Cable') + (l.label ? ' · ' + l.label : ''), h('span', { class: `cable-dot c-${cableCls(l.cable)}` }), trustEl(l.verified), acts),
    h('div', { class: 'insp-b scroll' }, body)];
}

function multiView(ids) {
  const devs = ids.filter(G.isDeviceId);
  return [header(plural(ids.length, 'object') + ' selected', 'Shift-click adds or removes', null, null, [
    devs.length ? h('button', { class: 'btn sm primary', onClick: () => askAbout(devs) }, 'Ask agent about these') : null,
    h('button', { class: 'btn sm', onClick: () => clearSelection() }, 'Clear selection')]),
    h('div', { class: 'insp-b scroll' }, h('div', { class: 'pad' }, h('div', { class: 'chips' }, ids.map(id => (G.isDeviceId(id) ? deviceChip(id) : h('button', { class: 'chip', onClick: () => select(id) }, 'Cable: ' + id)))),
      h('p', { class: 'muted', style: { marginTop: '12px', lineHeight: 1.45 } }, 'The map traces the connections of everything selected. Select one object to see its details.')))];
}

export function createInspector() {
  const el = h('div', { class: 'insp view', 'aria-label': 'Inspector' });
  let shown = null, scrollTops = new Map();

  function render() {
    const st = get();
    const sel = st.route.sel;
    const body = el.querySelector('.insp-b');
    if (sel.length === 1 && isFindingId(sel[0])) { if (body && shown && shown !== sel[0]) scrollTops.set(shown, body.scrollTop); shown = sel[0]; renderFinding(el, sel[0]); return; }
    leaveFinding();
    if (body && shown) scrollTops.set(shown, body.scrollTop);
    if (!st.inventory) { fill(el, st.invError ? errorState(st.invError, null, 'The inventory could not be loaded.') : skeleton(10)); return; }
    if (!sel.length) { shown = null; fill(el, h('div', { class: 'state' }, h('p', null, 'Nothing is selected. Click a device or a cable on the map, or a row in the device table.'))); return; }
    const key = sel.join(',');
    if (sel.length > 1) fill(el, multiView(sel));
    else if (G.isLinkId(sel[0])) fill(el, linkView(G.link(sel[0])));
    else if (G.isDeviceId(sel[0])) { load(sel[0]); fill(el, deviceView(G.device(sel[0]))); }
    else fill(el, header('Not in the inventory', sel[0], null, null, [h('button', { class: 'btn sm', onClick: () => clearSelection() }, 'Clear selection')]),
      h('div', { class: 'state' }, h('p', null, `Nothing in the inventory has the id “${sel[0]}”. It may have been renamed in data/inventory.json.`)));
    const nb = el.querySelector('.insp-b');
    if (nb) nb.scrollTop = shown === key ? (scrollTops.get(key) || 0) : 0;
    shown = key;
  }
  rerender = id => { if (get().route.sel.length === 1 && get().route.sel[0] === id) render(); };
  let lastKey = '';
  on(['reloadAt'], () => { cache.clear(); const sl = get().route.sel; if (sl.length === 1 && G.isDeviceId(sl[0])) load(sl[0], true); });
  on(['threats', 'threatTick'], st => { const sl = st.route.sel; if (sl.length === 1 && (isFindingId(sl[0]) || G.isDeviceId(sl[0]))) render(); });
  on(['route', 'inventory', 'invError', 'live', 'kvm'], (st, keys) => {
    if (st.route.sel.length === 1 && isFindingId(st.route.sel[0]) && !keys.has('route') && !keys.has('inventory')) return;   // a finding does not change with the live poll
    const key = st.route.sel.join(',') + '|' + st.route.trace + '|' + st.route.view;
    if (keys.has('route') && !keys.has('live') && !keys.has('inventory') && key === lastKey) return;
    lastKey = key;
    if (keys.has('live') && st.route.sel.length === 1 && G.isDeviceId(st.route.sel[0])) load(st.route.sel[0]);
    render();
  });
  render();
  return { el };
}

export { clock };
