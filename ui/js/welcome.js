// The first run: the home has no devices yet. Instead of an empty map, a calm panel says what the hub is and
// how to set it up, with the server's own checklist (/api/setup). It is read again every few seconds while the
// inventory is empty (main.js), so the list fills in as /setup goes.
import { h } from './dom.js';
import { get } from './store.js';
import { statusGlyph, copyBtn } from './ui.js';
import { clock } from './fmt.js';

const ROUTERS = { asuswrt: 'ASUS (AsusWRT)', none: 'none' };

/** One checklist row: state is done | todo | optional | unknown. */
function item(state, label, detail) {
  const glyph = state === 'done' ? 'online' : state === 'todo' ? 'degraded' : 'unmonitored';
  const word = { done: 'Done', todo: 'Not yet', optional: 'Optional', unknown: 'Not reported' }[state];
  return h('li', { class: 'wl-item s-' + state },
    h('span', { class: 'wl-g' }, statusGlyph(glyph, 10)),
    h('span', { class: 'wl-k' }, label),
    h('span', { class: 'wl-v' }, h('span', { class: 'sr-only' }, word + ': '), detail));
}

function checklist(su) {
  if (!su || !Object.keys(su).length) {
    return h('p', { class: 'wl-note' }, 'This server does not report its setup yet. Once ', h('code', null, '/setup'), ' has run, the map appears here by itself.');
  }
  const n = Number(su.inventoryDevices) || 0;
  const rt = su.routerType || null;
  const cli = su.claudeCli;
  const rows = [
    item(su.siteConfigured ? 'done' : 'todo', 'Site', su.siteConfigured ? 'data/site.json is written' : 'the network, the router and who the hub belongs to'),
    item(n > 0 ? 'done' : 'todo', 'Devices', n > 0 ? n + (n === 1 ? ' device' : ' devices') + ' in the inventory' : 'none found yet'),
    item(su.layoutPresent ? 'done' : 'optional', 'Map layout', su.layoutPresent ? 'data/layout.json pins some places' : 'everything is placed automatically'),
    item(!rt ? 'unknown' : rt === 'none' ? 'optional' : su.routerReachable ? 'done' : 'todo', 'Router',
      !rt ? 'not set' : rt === 'none' ? 'none: devices are found by ping, mDNS and the ARP table' : (ROUTERS[rt] || rt) + (su.routerReachable ? ', reachable' : ', not reachable yet')),
    item(su.haConfigured ? 'done' : 'optional', 'Home Assistant', su.haConfigured ? 'connected' : 'not connected'),
    item(cli ? 'done' : cli === false ? 'todo' : 'unknown', 'Claude CLI', cli ? (typeof cli === 'string' ? cli : 'found') : cli === false ? 'not found: install Claude Code first' : 'not reported'),
  ];
  if (su.knowledgeFiles != null) rows.splice(2, 0, item(su.knowledgeFiles > 0 ? 'done' : 'optional', 'Device guides', su.knowledgeFiles > 0 ? su.knowledgeFiles + ' in knowledge/' : 'written during setup, per device'));
  return h('ul', { class: 'wl-list', 'aria-label': 'Setup checklist' }, rows);
}

/** The panel. `setup` is /api/setup ({} from a server that does not have it, null while loading). */
export function welcomePanel() {
  const st = get();
  const su = st.setup;
  const step = (n, ...body) => h('li', null, h('span', { class: 'wl-n', 'aria-hidden': 'true' }, String(n)), h('span', { class: 'wl-s' }, body));
  return h('section', { class: 'welcome', 'aria-labelledby': 'wl-title' },
    h('div', { class: 'wl-inner' },
      h('p', { class: 'wl-eyebrow' }, 'Home Observability Hub'),
      h('h2', { id: 'wl-title', tabIndex: -1 }, 'Nothing on the map yet'),
      h('p', { class: 'wl-lead' }, 'This hub keeps a map of every device in your home: how each one is connected, whether it answers, and anything on the network that should not be there. It reads and reports. It changes nothing unless you approve that one change.'),
      h('h3', null, 'Set it up from Terminal'),
      h('ol', { class: 'wl-steps' },
        step(1, 'Open Terminal in this hub’s folder.'),
        step(2, 'Run ', h('code', null, 'claude'), copyBtn('claude', '', { cls: 'btn minimal icon sm' })),
        step(3, 'Type ', h('code', null, '/setup'), ' and answer its questions.')),
      h('p', { class: 'wl-note' }, 'Setup looks at your network with you, names what it finds and writes the files under data/. This page follows along and shows the map when the first devices are in.'),
      h('div', { class: 'wl-check' },
        h('div', { class: 'wl-ch' }, h('h3', null, 'Checklist'), su && Object.keys(su).length && st.setupAt ? h('span', { class: 'wl-at mono' }, 'checked ' + clock(st.setupAt)) : null),
        su ? checklist(su) : h('p', { class: 'wl-note' }, 'Reading the setup state…'))));
}
