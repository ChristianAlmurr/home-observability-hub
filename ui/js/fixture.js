// Development fixture: #/agent?fixture=1 renders this sample run. It exercises every block type in
// the contract and every action state. Nothing here comes from the server and nothing is run.

import { createThreatDemo, variant as threatVariant } from './threats-fixture.js';
import { isHandsOff, handsOffWhy, protectedIds, hostId as siteHost } from './site.js';

const iso = s => new Date(Date.now() - s * 1000).toISOString();

function build() {
  const id = 'r00000000f1c5';
  const act = (n, extra) => ({ id: `${id}-a${n}`, risk: 'change', reversible: true, needsSudo: false, refusal: null, state: 'proposed', ...extra });
  const actions = [
    act(1, { label: 'Turn Wi-Fi off on the Mac mini', why: 'Ethernet already carries everything; Wi-Fi is a second route to the same network.', command: 'networksetup -setairportpower en1 off', target: 'mac-mini', undo: 'networksetup -setairportpower en1 on' }),
    act(2, { label: 'Read the display mode again', why: 'Confirms what the Mac mini is sending after the KVM switches back.', command: 'python3 bin/probe.py displays', target: 'mac-mini', risk: 'read', undo: null, reversible: true, _mode: 'advise' }),
    act(3, { label: 'Check the NAS on SMB', why: 'A second look at TCP 445 while you watch the lights.', command: 'python3 bin/probe.py nas', target: 'nas-f4423', risk: 'read', state: 'running' }),
    act(4, { label: 'Read the service order', why: 'Shows which interface macOS prefers.', command: 'networksetup -listnetworkserviceorder', target: 'mac-mini', risk: 'read', state: 'done' }),
    act(5, { label: 'Renew the DHCP lease on en8', why: 'Would pick up a new address reservation.', command: 'ipconfig set en8 DHCP', target: 'mac-mini', state: 'failed', undo: null, reversible: false }),
    act(6, { label: 'Turn Wi-Fi back on', why: 'Offered as the opposite of the first action.', command: 'networksetup -setairportpower en1 on', target: 'mac-mini', state: 'rejected', undo: 'networksetup -setairportpower en1 off' }),
    act(7, { label: 'Flush the DNS cache', why: 'Clears a stale HomeNAS address.', command: 'sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder', target: 'mac-mini', needsSudo: true, state: 'copy-only', refusal: 'needs root: you type this yourself in a terminal', undo: null, reversible: false }),
    act(8, { label: 'Reset the MacBook display settings', why: 'Would clear the saved scaling for the Odyssey.', command: 'defaults delete com.apple.windowserver.displays', target: 'macbook-work', state: 'refused', refusal: 'macbook-work is a managed laptop: nothing may target it', undo: null, reversible: false }),
    act(9, { label: 'Delete the saved live readings', why: 'Starts the status history from scratch.', command: 'rm data/state/live.json data/state/events.jsonl', target: 'mac-mini', risk: 'destructive', undo: null, reversible: false }),
    act(10, { label: 'Read the USB tree', why: 'Shown while another action runs.', command: 'python3 bin/probe.py usb', target: 'mac-mini', risk: 'read', _blocked: true }),
  ];
  const answer = {
    parsed: true,
    title: 'MacBook picture is soft through the KVM',
    verdict: 'The MacBook is most likely sending a scaled 1440p picture through the dock’s HDMI, and the KVM passes it on untouched. Set the MacBook to the panel’s native 3840 × 2160 at 60 Hz; the dock to KVM hop is the one to prove first.',
    confidence: 'medium',
    subjects: ['macbook-work', 'hub-arcdock', 'kvm-ugreen', 'monitor-g70b'],
    path: { links: ['l-macbook-hub', 'l-hub-kvm-hdmi', 'l-kvm-monitor'], suspect: ['l-hub-kvm-hdmi'], note: 'It is the only hop that is drawn from the plan and never measured, and UGREEN warns about docks in front of some of its KVMs.' },
    blocks: [
      { type: 'text', markdown: 'The Mac mini drives the Odyssey at **3840 × 2160 @ 60 Hz** through the same KVM, so the KVM, the HDMI cable to the monitor and the panel are fine. What differs for the MacBook is the *dock* and its HDMI output.\n\n- The work MacBook is managed, so nothing below runs on it: those are steps for you.\n- `EDID` emulation on this KVM is not confirmed. Without it macOS forgets the display on every switch. See the [UGREEN manual](https://m.media-amazon.com/images/I/91v-ngN1uKL.pdf).' },
      { type: 'steps', title: 'Do this', items: [
        { text: 'Switch the KVM to PC2 and open System Settings → Displays on the MacBook.', device: 'macbook-work', detail: 'Hold Option and click “Scaled” to list every resolution.', expect: 'A list that includes 3840 × 2160.' },
        { text: 'Pick 3840 × 2160 and 60 Hz, then choose “Looks like 1920 × 1080”.', device: 'monitor-g70b', expect: 'Text that is as sharp as on the Mac mini.' },
        { text: 'If 3840 × 2160 is missing, plug the dock’s HDMI straight into the monitor’s second HDMI input.', device: 'hub-arcdock', detail: 'This takes the KVM out of the path.', expect: 'If the picture is sharp now, the KVM’s PC2 input is the limit.' },
      ] },
      { type: 'checks', title: 'What I checked', items: [
        { label: 'Mac mini display mode', value: '3840x2160 @ 60 Hz, HiDPI', ok: true, source: 'python3 bin/probe.py displays' },
        { label: 'KVM hub on the Mac mini USB bus', value: '05e3:0610 at 480 Mb/s', ok: true, source: 'python3 bin/probe.py usb' },
        { label: 'ArcDock on any bus', value: 'not seen (it hangs off the MacBook)', ok: false, source: 'python3 bin/probe.py usb' },
        { label: 'MacBook display mode', value: 'cannot be read: managed device', source: 'inventory constraint' },
      ] },
      { type: 'facts', title: 'From the manual', items: [
        { label: 'KVM video limit', value: '4K at 60 Hz on the HDMI output', device: 'kvm-ugreen', source: 'https://m.media-amazon.com/images/I/91v-ngN1uKL.pdf' },
        { label: 'Dock HDMI', value: 'HDMI out, 4K60 according to the listing; **not confirmed** for this unit', device: 'hub-arcdock', source: 'knowledge/hub-arcdock.specs.json' },
        { label: 'Panel', value: '3840 × 2160, 144 Hz native, HDMI 2.1', device: 'monitor-g70b', source: 'https://forum.level1techs.com/t/kvm-edid-emulation-solutions-for-macos/251631' },
      ] },
      { type: 'compare', title: 'Options if the dock cannot do 4K60 through the KVM', columns: ['Keep the chain', 'HDMI straight to the monitor', 'USB-C to the KVM'], recommended: 1, rows: [
        { label: 'Cables to move', values: ['none', 'one HDMI cable', 'one USB-C cable'] },
        { label: 'One-button switch', values: ['yes', 'no: change the monitor input too', 'yes'] },
        { label: 'Charging through the dock', values: ['yes', 'yes', 'no, needs its own charger'] },
        { label: 'Cost', values: ['nothing', 'nothing', 'nothing'] },
      ] },
      { type: 'warning', level: 'info', text: 'The KVM caps the picture at 60 Hz for both computers; the panel’s 144 Hz is not available through it.' },
      { type: 'warning', level: 'caution', text: 'Display settings can revert each time the KVM switches, because EDID emulation is not confirmed for this model.' },
      { type: 'warning', level: 'danger', text: 'Do not route Ethernet through the KVM: the network would drop on every switch.' },
    ],
    actions,
    sources: [
      { title: 'UGREEN KVM manual (HDMI KVM, EDID re-read note)', url: 'https://m.media-amazon.com/images/I/91v-ngN1uKL.pdf', device: 'kvm-ugreen' },
      { title: 'Level1Techs: KVM EDID emulation for macOS', url: 'https://forum.level1techs.com/t/kvm-edid-emulation-solutions-for-macos/251631' },
    ],
    unknowns: [
      'Whether the ArcDock’s HDMI output reaches 4K at 60 Hz through the KVM’s PC2 input. Step 3 settles it.',
      'Which resolution the MacBook is sending now. It is a managed laptop, so only you can read it in System Settings.',
    ],
  };
  const run = {
    runId: id, threadId: 't00000000f1c5', fixture: true, loaded: true, status: 'done', model: 'fixture',
    question: 'The MacBook picture is not crisp through the KVM, and the display settings revert after switching.',
    deviceIds: ['macbook-work', 'hub-arcdock', 'kvm-ugreen', 'monitor-g70b'],
    startedAt: iso(240), endedAt: iso(192), error: null, phase: 'answer', phases: ['identify', 'read-docs', 'inspect', 'research', 'answer'],
    activities: [
      { tool: 'Read', text: 'Reading the inventory', detail: 'data/inventory.json', ts: iso(238) },
      { tool: 'Read', text: 'Reading the UGREEN KVM’s guide', detail: 'knowledge/kvm-ugreen.md', ts: iso(233) },
      { tool: 'Read', text: 'Reading the Spigen ArcDock Pro’s specs', detail: 'knowledge/hub-arcdock.specs.json', ts: iso(229) },
      { tool: 'Bash', text: 'Reading the display modes', detail: 'python3 bin/probe.py displays', ts: iso(221) },
      { tool: 'Bash', text: 'Reading the USB tree', detail: 'python3 bin/probe.py usb', ts: iso(214) },
      { tool: 'WebFetch', text: 'Reading forum.level1techs.com', detail: 'https://forum.level1techs.com/t/kvm-edid-emulation-solutions-for-macos/251631', ts: iso(203) },
    ],
    answer, answerV: 1, errors: [], lastSeq: 0, stream: 'idle',
    actions: {},
  };
  for (const a of actions) run.actions[a.id] = { state: a.state, def: a, refusal: a.refusal, output: [] };
  run.actions[`${id}-a3`].output = [{ stream: 'stdout', text: 'resolve HomeNAS → 10.20.0.192' }, { stream: 'stdout', text: 'tcp 10.20.0.192:445 …' }];
  Object.assign(run.actions[`${id}-a4`], { exitCode: 0, decidedAt: iso(150), finishedAt: iso(149), output: ['An asterisk (*) denotes that a network service is disabled.', '(1) Ethernet', '(Hardware Port: Ethernet, Device: en0)', '(2) USB 10/100/1G/2.5G LAN', '(Hardware Port: USB 10/100/1G/2.5G LAN, Device: en8)', '(3) Thunderbolt Bridge', '(Hardware Port: Thunderbolt Bridge, Device: bridge0)', '(4) Wi-Fi', '(Hardware Port: Wi-Fi, Device: en1)'].map(text => ({ stream: 'stdout', text })) });
  Object.assign(run.actions[`${id}-a5`], { exitCode: 1, decidedAt: iso(120), finishedAt: iso(119), output: [{ stream: 'stderr', text: 'ipconfig: failed to set DHCP on en8: operation not permitted' }] });
  Object.assign(run.actions[`${id}-a6`], { decidedAt: iso(100) });
  return run;
}

let cached = null;
/** The fixture thread, registered in the agent's run map so decisions can be simulated. */
export function fixtureRuns(agent) {
  if (!cached) cached = build();
  agent.runs[cached.runId] = cached;
  return [cached];
}

// ---------------------------------------------------------------------------------------------
// Sample data for the version 2 API: #/map?demo=1 (no router login) or ?demo=2 (router login stored).
// It wraps the real API: the inventory and live readings come from the server when it answers (a small
// built-in house is used when it does not), and everything version 2 adds is laid over them so each
// state can be seen: hosts that are not in the inventory, identity states, security levels, Wi-Fi links
// with and without a known access point, a blocked device, a suspicious one. Actions change this copy
// only. Nothing is sent to the server and nothing is run. The top bar says "Sample data" while it is on.

const ago = s => new Date(Date.now() - s * 1000).toISOString();
const hash = str => { let x = 2166136261; for (const c of String(str)) x = Math.imul(x ^ c.charCodeAt(0), 16777619); return (x >>> 0) / 4294967295; };

const dev = (id, name, kind, zone, vendor, model, verified, ip, medium, extra) => ({ id, name, kind, zone, vendor, model, verified, net: ip ? [{ ip, ...(medium ? { medium } : {}) }] : [], ports: [], ...extra });
const BASE = {
  schema: 2, site: { name: 'Sample house', subnet: '10.20.0.0/24', gateway: '10.20.0.1', surveyedAt: '2026-11-20' },
  rooms: [{ id: 'bedroom', name: 'Bedroom' }, { id: 'office', name: 'Home Office' }, { id: 'hallway', name: 'Hallway' }, { id: 'bathroom', name: 'Bathroom' }, { id: 'living', name: 'Living Room' }, { id: 'kitchen', name: 'Kitchen' }],
  zones: [{ id: 'desk', name: 'Desk', room: 'office' }, { id: 'rack', name: 'Network shelf', room: 'office' }, { id: 'spares', name: 'Spares drawer', room: 'office' }, { id: 'office', name: 'Home office', room: 'office' },
    { id: 'living-wired', name: 'TV corner', room: 'living' }, { id: 'living', name: 'Living room', room: 'living' }, { id: 'kitchen', name: 'Kitchen', room: 'kitchen' }, { id: 'bedroom', name: 'Bedroom', room: 'bedroom' },
    { id: 'bathroom', name: 'Bathroom', room: 'bathroom' }, { id: 'hallway', name: 'Hallway', room: 'hallway' }, { id: 'unplaced', name: 'Unplaced', note: 'On the network, room not known' }],
  openQuestions: [],
  devices: [
    dev('mac-mini', 'Mac mini', 'computer', 'desk', 'Apple', 'Mac mini M4 Pro', 'live', '10.20.0.140', 'ethernet', { probe: { type: 'self' } }),
    dev('macbook-work', 'Work MacBook Pro', 'computer', 'desk', 'Apple', 'MacBook Pro', 'reported', '10.20.0.98', null, { probe: { type: 'mdns' } }),
    dev('monitor-g70b', 'Odyssey G70B', 'display', 'desk', 'Samsung', 'Odyssey G70B 4K', 'live', null, null, { probe: { type: 'display' } }),
    dev('kvm-ugreen', 'UGREEN KVM', 'kvm', 'desk', 'UGREEN', 'USB-C + HDMI KVM', 'live', null, null, { probe: { type: 'usb' } }),
    dev('hub-arcdock', 'Spigen ArcDock Pro', 'hub', 'desk', 'Spigen', 'ArcDock Pro 6-in-1', 'reported'),
    dev('streamdeck-neo', 'Stream Deck Neo', 'peripheral', 'desk', 'Elgato', 'Stream Deck Neo', 'live', null, null, { probe: { type: 'usb' } }),
    dev('usb-audio', 'USB audio adapter', 'peripheral', 'desk', 'C-Media', 'USB PnP Sound Device', 'live', null, null, { probe: { type: 'usb' } }),
    dev('adapter-ugreen-25g', 'UGREEN 2.5G adapter', 'adapter', 'desk', 'UGREEN', 'USB-C to 2.5G Ethernet', 'live', null, null, { probe: { type: 'interface' } }),
    dev('keyboard', 'Keyboard', 'peripheral', 'desk', 'Logitech', 'MX Keys', 'live', null, null, { probe: { type: 'bluetooth' } }),
    dev('mouse', 'Mouse', 'peripheral', 'desk', 'Logitech', 'MX Master 3', 'live', null, null, { probe: { type: 'bluetooth' } }),
    dev('switch-sg105m2', 'TP-Link 2.5G switch', 'switch', 'rack', 'TP-Link', 'TL-SG105-M2', 'reported', null, null, { probe: { type: 'inferred' } }),
    dev('nas-f4423', 'HomeNAS', 'nas', 'rack', 'TerraMaster', 'F4-423', 'reported', '10.20.0.192', null, { probe: { type: 'tcp' } }),
    dev('node-xt8', 'ASUS ZenWiFi XT8 (mesh node)', 'access-point', 'rack', 'ASUS', 'ZenWiFi AX XT8', 'live', '10.20.0.45', null, { probe: { type: 'ping' } }),
    dev('router-xt8', 'ASUS ZenWiFi XT8 (router)', 'router', 'living-wired', 'ASUS', 'ZenWiFi AX XT8', 'live', '10.20.0.1', null, { probe: { type: 'ping' } }),
    dev('modem-cableco', 'CableCo modem', 'modem', 'living-wired', 'CableCo', 'Cable modem', 'live', '192.168.100.1', null, { probe: { type: 'ping' } }),
    dev('hue-bridge', 'Hue Bridge', 'bridge', 'living-wired', 'Philips Hue', 'Hue Bridge v2', 'live', '10.20.0.4', 'ethernet', { probe: { type: 'http' } }),
    dev('tv-philips', 'Living Room TV', 'tv', 'living-wired', 'Philips', 'Google TV', 'live', '10.20.0.119', 'wifi', { probe: { type: 'cast' } }),
    dev('speaker-living-display', 'Living Room Display', 'speaker', 'living', 'Google', 'Nest Hub', 'live', '10.20.0.109', 'wifi', { probe: { type: 'cast' } }),
    dev('speaker-living', 'Living Room speaker', 'speaker', 'living', 'Google', 'Nest Audio', 'live', '10.20.0.214', 'wifi', { probe: { type: 'cast' } }),
    dev('speaker-office-1', 'Office speaker', 'speaker', 'office', 'JBL', 'Link Music', 'live', '10.20.0.122', 'wifi', { probe: { type: 'cast' } }),
    dev('speaker-office-2', 'Office speaker 2', 'speaker', 'office', 'JBL', 'Link Music', 'live', '10.20.0.152', 'wifi', { probe: { type: 'cast' } }),
    dev('speaker-bathroom', 'Bathroom speaker', 'speaker', 'bathroom', 'Google', 'Home Mini', 'live', '10.20.0.207', 'wifi', { probe: { type: 'cast' } }),
    dev('speaker-bedroom', 'Bedroom speaker', 'speaker', 'bedroom', 'Google', 'Google Home', 'live', '10.20.0.211', 'wifi', { probe: { type: 'cast' } }),
    dev('cam-indoor', 'Living room camera', 'camera', 'living', 'eufy', 'IndoorCam Pan 2K', 'live', '10.20.0.213', 'wifi', { probe: { type: 'ping' } }),
    dev('cam-garage', 'Garage monitor', 'camera', 'bedroom', 'eufy', 'Garage Monitor E21', 'live', '10.20.0.15', 'wifi', { probe: { type: 'ping' } }),
    dev('vacuum-omni-e28', 'Omni E28', 'vacuum', 'hallway', 'eufy', 'Robot Vacuum Omni E28', 'live', '10.20.0.129', 'wifi', { probe: { type: 'ping' } }),
    dev('dishwasher-bosch', 'Bosch dishwasher', 'appliance', 'kitchen', 'Bosch', 'SBV4EVX08E', 'live', '10.20.0.218', 'wifi', { probe: { type: 'ping' } }),
    dev('unknown-lwip0', 'Tuya smart device (lwip0)', 'unknown', 'unplaced', 'Tuya', '', 'live', '10.20.0.53', 'wifi', { probe: { type: 'ping' } }),
    dev('streamdeck-mini', 'Stream Deck Mini', 'peripheral', 'spares', 'Elgato', 'Stream Deck Mini', 'reported', null, null, { probe: { type: 'none' } }),
    dev('adapter-belkin-inc012', 'Belkin USB-C Ethernet adapter', 'adapter', 'spares', 'Belkin', 'INC012btBK', 'reported', null, null, { probe: { type: 'none' } }),
    { ...dev('phone-alex', 'Alex\'s iPhone', 'phone', 'unplaced', 'Apple', 'iPhone', 'live'), net: [{ ip: '100.64.0.11', if: 'tailscale' }], probe: { type: 'ha' } },
  ],
  links: [
    { id: 'l-mini-kvm', from: 'mac-mini', to: 'kvm-ugreen', cable: 'usb-c', carries: ['video', 'usb'], verified: 'live', kvmInput: 'pc1' },
    { id: 'l-kvm-monitor', from: 'kvm-ugreen', to: 'monitor-g70b', cable: 'hdmi', carries: ['video'], verified: 'live' },
    { id: 'l-kvm-streamdeck', from: 'kvm-ugreen', to: 'streamdeck-neo', cable: 'usb', carries: ['usb'], verified: 'live' },
    { id: 'l-mini-audio', from: 'mac-mini', to: 'usb-audio', cable: 'usb', carries: ['usb'], verified: 'live' },
    { id: 'l-mini-adapter', from: 'mac-mini', to: 'adapter-ugreen-25g', cable: 'usb-c', speed: '5 Gb/s USB', carries: ['network'], verified: 'live' },
    { id: 'l-adapter-switch', from: 'adapter-ugreen-25g', to: 'switch-sg105m2', cable: 'ethernet', speed: '2.5G', carries: ['network'], verified: 'live' },
    { id: 'l-nas-switch', from: 'nas-f4423', to: 'switch-sg105m2', cable: 'ethernet', speed: '2.5G', carries: ['network'], verified: 'plan' },
    { id: 'l-node-switch', from: 'node-xt8', to: 'switch-sg105m2', cable: 'ethernet', speed: '1G', carries: ['network'], verified: 'plan' },
    { id: 'l-macbook-hub', from: 'macbook-work', to: 'hub-arcdock', cable: 'usb-c', carries: ['video', 'usb', 'network', 'power'], verified: 'plan' },
    { id: 'l-hub-kvm-hdmi', from: 'hub-arcdock', to: 'kvm-ugreen', cable: 'hdmi', carries: ['video'], verified: 'plan', kvmInput: 'pc2' },
    { id: 'l-hub-switch', from: 'hub-arcdock', to: 'switch-sg105m2', cable: 'ethernet', speed: '2.5G', carries: ['network'], verified: 'plan' },
    { id: 'l-router-node', from: 'router-xt8', to: 'node-xt8', cable: 'mesh', carries: ['network'], verified: 'live' },
    { id: 'l-router-hue', from: 'router-xt8', to: 'hue-bridge', cable: 'ethernet', carries: ['network'], verified: 'plan' },
    { id: 'l-modem-router', from: 'modem-cableco', to: 'router-xt8', cable: 'ethernet', carries: ['network'], verified: 'plan' },
  ],
};

const HOSTS = [
  { ip: '10.20.0.201', name: null, medium: 'wifi', mac: '9A:2C:11:CE:E8:69', randomizedMac: true, firstSeen: 6.2 * 3600,
    identity: { state: 'unidentified', vendor: null, model: null, type: null, basis: null, macVendor: null,
      evidence: [{ source: 'router', label: 'Client list', value: 'no hostname', ts: 400 }, { source: 'mac', label: 'MAC prefix', value: 'locally administered (randomized): no maker', ts: 400 }, { source: 'ports', label: 'Open ports', value: '23 (telnet), 8080 (http)', ts: 380 }, { source: 'banner', label: 'Telnet banner', value: 'BusyBox v1.19.4 login:', ts: 380 }],
      candidates: [{ vendor: null, model: null, type: 'Embedded Linux device (camera, DVR or cheap IoT)', confidence: 'low', basis: 'BusyBox telnet banner; nothing names a product' }] },
    security: { level: 'suspicious', score: 86, reasons: [{ code: 'new-host', text: 'First seen at 02:13 last night, while nobody was adding devices' }, { code: 'telnet-open', text: 'Telnet (port 23) is open: a remote login with no encryption' }, { code: 'lan-sweep', text: 'It tried 14 other addresses on the LAN within five minutes' }, { code: 'random-mac', text: 'Uses a randomized MAC address, so its maker cannot be read' }],
      openPorts: [{ port: 23, service: 'telnet', risky: true }, { port: 8080, service: 'http', risky: false }] }, traffic: [42000, 310000] },
  { ip: '10.20.0.77', name: 'espressif', medium: 'wifi', mac: '24:6F:28:77:46:3A', firstSeen: 3.1 * 86400,
    identity: { state: 'unidentified', vendor: null, model: null, type: null, basis: null, macVendor: 'Espressif Inc.',
      evidence: [{ source: 'mac', label: 'MAC prefix', value: '24:6F:28 → Espressif Inc.', ts: 900 }, { source: 'router', label: 'Hostname', value: 'espressif', ts: 900 }, { source: 'ports', label: 'Open ports', value: '80 (http)', ts: 860 }, { source: 'http', label: 'Page title', value: 'Shelly Web Admin', ts: 860 }],
      candidates: [{ vendor: 'Shelly', model: 'Plug S', type: 'smart plug', confidence: 'medium', basis: 'The page on port 80 is titled Shelly Web Admin, and Shelly plugs use Espressif chips' }, { vendor: 'Espressif', model: null, type: 'ESP32 module (a DIY sensor or another maker\'s product)', confidence: 'low', basis: 'MAC prefix and hostname only' }] },
    security: { level: 'watch', score: 38, reasons: [{ code: 'unidentified', text: 'Not identified yet' }, { code: 'open-admin', text: 'Its admin page on port 80 asks for no password' }], openPorts: [{ port: 80, service: 'http', risky: true }] }, traffic: [900, 1400] },
  { ip: '10.20.0.166', name: 'android-7f3a', medium: 'wifi', mac: 'D4:8A:3B:BE:97:16', firstSeen: 5 * 86400, blocked: true, status: 'offline',
    identity: { state: 'likely', vendor: 'Samsung', model: 'Galaxy phone', type: 'phone', basis: 'MAC prefix is Samsung Electronics and the hostname follows the Android pattern', macVendor: 'Samsung Electronics',
      evidence: [{ source: 'mac', label: 'MAC prefix', value: 'D4:8A:3B → Samsung Electronics', ts: 5 * 86400 }, { source: 'router', label: 'Hostname', value: 'android-7f3a', ts: 5 * 86400 }], candidates: [{ vendor: 'Samsung', model: 'Galaxy phone', type: 'phone', confidence: 'medium', basis: 'MAC prefix and hostname' }] },
    security: { level: 'blocked', score: 55, reasons: [{ code: 'blocked', text: 'You blocked it at the router 2 days ago' }, { code: 'unknown-owner', text: 'Nobody in the house recognised it' }], openPorts: [] } },
  { ip: '10.20.0.60', name: 'iPad', medium: 'wifi', mac: '6E:19:C4:F1:6A:FB', randomizedMac: true, firstSeen: 2.2 * 3600,
    identity: { state: 'likely', vendor: 'Apple', model: 'iPad', type: 'tablet', basis: 'mDNS announces _companion-link with model iPad13,18; the MAC is randomized so it proves nothing', macVendor: null,
      evidence: [{ source: 'mdns', label: 'mDNS', value: '_companion-link._tcp, rpMd=iPad13,18', ts: 7000 }, { source: 'router', label: 'Hostname', value: 'iPad', ts: 7000 }, { source: 'mac', label: 'MAC prefix', value: 'locally administered (randomized)', ts: 7000 }], candidates: [{ vendor: 'Apple', model: 'iPad (10th generation)', type: 'tablet', confidence: 'high', basis: 'Model code iPad13,18 in its mDNS record' }] },
    security: { level: 'ok', score: 12, reasons: [{ code: 'new-host', text: 'New today' }], openPorts: [] }, traffic: [180000, 2400000] },
  { ip: '10.20.0.33', name: null, medium: null, mac: null, firstSeen: 9 * 86400,
    identity: { state: 'unidentified', vendor: null, model: null, type: null, basis: null, macVendor: null, evidence: [{ source: 'ping', label: 'Ping', value: 'answers, 3 ms', ts: 30 }, { source: 'ports', label: 'Open ports', value: 'none of the common ones', ts: 3000 }], candidates: [] },
    security: { level: 'watch', score: 30, reasons: [{ code: 'unidentified', text: 'Not identified: it answers ping and says nothing else' }], openPorts: [] } },
];
const hostId = ip => 'host-' + ip.replace(/\./g, '-');
// what the demo may not block or remove: network gear, the hub's own computer, and what the site protects
const GEAR = new Set(['internet', 'modem', 'router', 'access-point', 'switch']);
const isProtected = (inv, id) => { const d = inv.devices.find(x => x.id === id); return !!d && (GEAR.has(d.kind) || protectedIds().has(id) || id === hostOf(inv)); };
/** The computer the hub runs on: the site's, else the device that probes itself. */
const hostOf = inv => { const h = siteHost(); if (h && inv.devices.some(d => d.id === h)) return h; const d = inv.devices.find(x => x.probe && x.probe.type === 'self'); return d ? d.id : null; };
const SEC_FOR = {
  'cam-indoor': { level: 'watch', score: 28, reasons: [{ code: 'rtsp-open', text: 'RTSP (port 554) is open on the LAN: anything in the house can ask for the video stream' }], openPorts: [{ port: 554, service: 'rtsp', risky: true }] },
  'nas-f4423': { level: 'ok', score: 8, reasons: [], openPorts: [{ port: 445, service: 'smb', risky: false }, { port: 5443, service: 'https', risky: false }] },
};
const ID_FOR = {
  'macbook-work': { state: 'likely', vendor: 'Apple', model: 'MacBook Pro', type: 'computer', basis: 'Reported by its owner; the exact model is not confirmed and the laptop may not be probed', evidence: [{ source: 'mdns', label: 'mDNS', value: 'announces a MacBook Pro', ts: 9000 }], candidates: [] },
  'modem-cableco': { state: 'likely', vendor: 'CableCo', model: 'Cable modem', type: 'modem', basis: 'It answers on 192.168.100.1 like a CableCo modem in bridge mode; the model was not read', evidence: [{ source: 'ping', label: 'Ping', value: '192.168.100.1 answers', ts: 30 }], candidates: [{ vendor: 'CableCo', model: 'ConnectBox (Arris TG2492)', type: 'modem', confidence: 'low', basis: 'The most common CableCo modem; nothing confirms it here' }] },
};

function idOf(d) {
  if (ID_FOR[d.id]) return ID_FOR[d.id];
  if (d.identity && d.identity.state) return d.identity;
  const k = (d.knowledge && d.knowledge.identity) || {};
  const known = d.vendor && d.model && !/^not identified/i.test(d.model);
  const state = d.kind === 'unknown' || !known ? 'unidentified' : k.confidence === 'likely' ? 'likely' : d.verified === 'live' || k.confidence === 'confirmed' ? 'confirmed' : 'likely';
  const how = { cast: 'The device names itself over the cast API', usb: 'It names itself on the USB bus', bluetooth: 'It names itself over Bluetooth', self: 'Read from this Mac', display: 'The display names itself (EDID)', http: 'Its local API names the model', interface: 'macOS names the adapter\'s chip' }[(d.probe || {}).type];
  return { state, vendor: d.vendor || null, model: (d.model || '').split(/ \(|;/)[0] || null, type: d.kind, basis: k.basis || (state === 'confirmed' ? how || 'A probe names the product' : 'Reported by someone in the home or an order email; no probe has named it'),
    evidence: state === 'confirmed' ? [{ source: (d.probe || {}).type || 'probe', label: 'Probe', value: how || 'names the product', ts: 600 }] : [], candidates: [] };
}

export function createDemo(real, startConfigured) {
  const threatDemo = createThreatDemo();
  const s = { configured: !!startConfigured, forgotten: new Set(), named: new Map(), blocked: new Map(HOSTS.filter(x => x.blocked).map(x => [hostId(x.ip), true])), scanned: new Map(), unblockedMacs: new Set(), base: null, baseLive: null };
  const wait = ms => new Promise(r => setTimeout(r, ms));
  const tsOf = sec => ago(sec);

  async function inventory() {
    let inv;
    try { inv = await real.inventory(); } catch { inv = JSON.parse(JSON.stringify(BASE)); }
    inv = JSON.parse(JSON.stringify(inv));
    inv.schema = 2;
    const has = id => inv.devices.some(d => d.id === id);
    if (!(inv.zones || []).some(z => z.id === 'outside')) inv.zones = [...(inv.zones || []), { id: 'outside', name: 'Outside', note: 'Beyond the modem' }];
    const modem = inv.devices.find(d => d.kind === 'modem');
    if (!has('internet') && modem) inv.devices.unshift({ id: 'internet', name: 'Internet', kind: 'internet', zone: 'outside', vendor: '', model: 'Internet', verified: 'reported', net: [], ports: [], probe: { type: 'ping' } });
    if (modem && has('internet') && !inv.links.some(l => String(l.from).split(':')[0] === 'internet' || String(l.to).split(':')[0] === 'internet')) inv.links.push({ id: 'l-internet-modem', from: 'internet', to: modem.id, cable: 'coax', carries: ['network'], verified: 'reported', evidence: 'Sample data: the line in from the provider.' });
    const me = hostOf(inv);
    for (const [id, name, model] of [['keyboard', 'MX Keys', 'MX Keys'], ['mouse', 'MX Master 3', 'MX Master 3']]) {
      const d = inv.devices.find(x => x.id === id); if (!d || !me) continue;
      if (!inv.links.some(l => l.cable === 'bluetooth' && String(l.from).split(':')[0] === id)) {
        inv.links = inv.links.filter(l => !(String(l.to).split(':')[0] === id && l.cable === 'usb'));
        inv.links.push({ id: 'l-' + id + '-bt', from: id, to: me, cable: 'bluetooth', carries: ['usb'], verified: 'live', evidence: 'Listed as connected in this computer\'s Bluetooth devices.' });
        Object.assign(d, { name: 'Logitech ' + name, vendor: 'Logitech', model, verified: 'live', net: [{ medium: 'bluetooth', mac: id === 'keyboard' ? 'F4:73:35:47:56:3B' : 'D2:5B:77:0D:97:64' }], probe: { type: 'bluetooth' } });
      }
    }
    for (const x of HOSTS) {
      const id = hostId(x.ip);
      if (!has(id)) inv.devices.push({ id, name: x.name || 'Host .' + x.ip.split('.').pop(), kind: 'unknown', zone: 'unplaced', dynamic: true, verified: 'live', vendor: '', model: '', ports: [],
        net: [{ ip: x.ip, ...(x.mac ? { mac: x.mac } : {}), ...(x.medium ? { medium: x.medium } : {}) }], probe: { type: 'ping' } });
    }
    inv.devices = inv.devices.filter(d => !s.forgotten.has(d.id));
    inv.links = inv.links.filter(l => l.cable !== 'wifi' && !s.forgotten.has(String(l.from).split(':')[0]) && !s.forgotten.has(String(l.to || '').split(':')[0]));
    const wired = new Set(inv.links.filter(l => l.cable !== 'bluetooth' && (['ethernet', 'coax', 'mesh'].includes(l.cable) || (l.carries || []).includes('network'))).flatMap(l => [String(l.from).split(':')[0], String(l.to).split(':')[0]]));
    for (const d of inv.devices) {
      const host = HOSTS.find(x => hostId(x.ip) === d.id);
      d.identity = { mac: (d.net || []).map(n => n.mac).find(Boolean) || null, macVendor: null, randomizedMac: false, ...(host ? host.identity : idOf(d)), ...(host && host.randomizedMac ? { randomizedMac: true } : {}) };
      d.identity.evidence = (d.identity.evidence || []).map(e => ({ ...e, ts: typeof e.ts === 'number' ? tsOf(e.ts) : e.ts }));
      if (s.scanned.has(d.id)) d.identity.evidence = [...s.scanned.get(d.id), ...d.identity.evidence];
      const n = s.named.get(d.id);
      if (n) { Object.assign(d, { name: n.name || d.name, vendor: n.vendor || d.vendor, model: n.model || d.model, kind: n.kind || d.kind, zone: n.zone || d.zone, verified: 'reported', dynamic: false });
        d.identity = { ...d.identity, state: 'confirmed', vendor: d.vendor, model: d.model, type: d.kind, basis: 'You said so', evidence: [{ source: 'person', label: 'You', value: 'identified it in Home Observability Hub', ts: n.at }, ...d.identity.evidence] }; }
      if (!(d.net || []).some(x => x.medium === 'wifi') || (wired.has(d.id) && d.id !== me)) continue;
      // which access point: with a router login, the recorded one or one picked by the id; without one, a few cast devices report theirs
      const aps = inv.devices.filter(x => x.kind === 'router' || x.kind === 'access-point').map(x => x.id).sort();
      const cast = aps.length > 1 && /^speaker/.test(d.id) && hash(d.id) > 0.5;
      const wn = d.net.find(x => x.medium === 'wifi') || {};
      const pick = aps.length ? aps[Math.floor(hash(d.id) * aps.length) % aps.length] : null;
      const ap = s.configured ? (wn.ap || pick) : cast ? pick : null;
      if (d.id === me && !s.configured) continue;
      const band = ap || cast ? wn.band || (hash(d.id + 'b') > 0.45 ? '5 GHz' : '2.4 GHz') : null;
      inv.links.push({ id: 'w-' + d.id, from: d.id, to: ap, cable: 'wifi', carries: ['network'], synthetic: true, ap: ap ? 'known' : 'unknown', band, rssi: ap ? (wn.rssi != null ? wn.rssi : -38 - Math.round(hash(d.id + 'r') * 36)) : null, ssid: ap ? 'Example' : null,
        verified: ap ? 'live' : 'plan', evidence: ap ? (s.configured ? 'The router\'s client list places it on this node.' : 'The cast API reports a BSSID that matches the mesh node\'s 5 GHz radio.') : 'The device is on Wi-Fi; which access point it uses is not known without the router\'s client list.' });
    }
    s.base = inv;
    return inv;
  }

  async function live() {
    let lv;
    try { lv = JSON.parse(JSON.stringify(await real.live())); } catch { lv = { ts: new Date().toISOString(), devices: {}, links: {}, strangers: [] }; }
    const inv = s.base || await inventory();
    const t = Date.now() / 1000;
    lv.wireless = {}; lv.devices = lv.devices || {};
    for (const d of inv.devices) {
      const host = HOSTS.find(x => hostId(x.ip) === d.id);
      const cur = lv.devices[d.id] || (lv.devices[d.id] = { status: (d.probe || {}).type === 'none' || !(d.probe || host) ? 'unmonitored' : 'online', latencyMs: host || (d.net || []).some(n => n.ip) ? Math.round(2 + hash(d.id) * 30) : null, lastSeen: ago(8), checks: [], facts: {} });
      const blocked = s.blocked.has(d.id);
      if (host && (host.status || blocked)) Object.assign(cur, { status: 'offline', lastSeen: ago(2 * 86400), latencyMs: null, checks: [{ name: 'ping ' + host.ip, ok: false, detail: 'no answer: blocked at the router' }] });
      else if (blocked) Object.assign(cur, { status: 'offline', checks: [{ name: 'ping', ok: false, detail: 'no answer: blocked at the router' }] });
      const base = host ? host.security : SEC_FOR[d.id] || { level: 'ok', score: Math.round(hash(d.id + 's') * 9), reasons: [], openPorts: [] };
      cur.security = { ...base, firstSeen: host ? ago(host.firstSeen) : ago(86400 * (20 + Math.round(hash(d.id) * 200))), blocked,
        level: blocked ? 'blocked' : base.level === 'blocked' ? 'watch' : s.named.has(d.id) && base.level === 'watch' ? 'ok' : base.level,
        reasons: blocked && base.level !== 'blocked' ? [{ code: 'blocked', text: 'You blocked it at the router just now' }, ...base.reasons] : s.named.has(d.id) ? base.reasons.filter(r => r.code !== 'unidentified') : base.reasons };
      const w = inv.links.find(l => l.id === 'w-' + d.id);
      if (w) lv.wireless[d.id] = { ap: w.to, band: w.band, rssi: w.rssi, ssid: w.ssid, source: s.configured ? 'router' : w.to ? 'cast' : null };
      if (s.configured && cur.status === 'online' && (w || host || ['tv', 'nas', 'computer', 'bridge'].includes(d.kind))) {
        const big = { tv: 9e6, computer: 2.4e6, nas: 6e5, camera: 8e5 }[d.kind] || (host && host.traffic ? host.traffic[1] : 2e3 + hash(d.id + 't') * 6e4);
        const wob = 0.6 + 0.4 * Math.sin(t / 7 + hash(d.id) * 6);
        cur.traffic = { rxBps: Math.round(big * wob), txBps: Math.round((host && host.traffic ? host.traffic[0] : big * (d.kind === 'camera' ? 6 : 0.08)) * wob) };
      }
    }
    for (const id of Object.keys(lv.devices)) if (s.forgotten.has(id)) delete lv.devices[id];
    const clients = Object.keys(lv.wireless).length + 6;
    lv.router = { configured: s.configured, ok: s.configured ? true : null, error: null, lastRun: s.configured ? ago(12) : null, clients: s.configured ? clients : null };
    lv.strangers = HOSTS.filter(x => !s.forgotten.has(hostId(x.ip)) && !s.named.has(hostId(x.ip))).map(x => ({ ip: x.ip, name: x.name, firstSeen: ago(x.firstSeen), lastSeen: ago(20) }));
    const ds = inv.devices.filter(d => d.kind !== 'internet');
    const count = st => ds.filter(d => (lv.devices[d.id] || {}).status === st).length;
    lv.summary = { online: count('online'), offline: count('offline'), unknown: count('unknown'), degraded: count('degraded'), unmonitored: count('unmonitored'),
      unidentified: ds.filter(d => d.identity.state === 'unidentified').length, suspicious: ds.filter(d => lv.devices[d.id].security.level === 'suspicious').length, blocked: ds.filter(d => lv.devices[d.id].security.level === 'blocked').length };
    if (threatVariant() === 'missing') delete lv.summary.threats;
    else { const t = threatDemo.summary(); lv.summary.threats = { open: t.open, critical: t.bySeverity.critical, high: t.bySeverity.high, level: t.level }; }
    lv.ts = new Date().toISOString();
    s.baseLive = lv;
    return lv;
  }

  const log = [];
  async function events(limit) {
    let evs = [];
    try { evs = await real.events(limit); } catch { evs = []; }
    const sample = [
      { ts: ago(6.2 * 3600), kind: 'security', device: hostId('10.20.0.201'), text: 'New host 10.20.0.201 joined the Wi-Fi with a randomized MAC address' },
      { ts: ago(6.1 * 3600), kind: 'security', device: hostId('10.20.0.201'), from: 'watch', to: 'suspicious', text: 'Host .201 became suspicious: telnet is open and it probed 14 addresses on the LAN' },
      { ts: ago(2.2 * 3600), kind: 'security', device: hostId('10.20.0.60'), text: 'New host iPad (10.20.0.60): likely an Apple iPad' },
      { ts: ago(2 * 86400), kind: 'security', device: hostId('10.20.0.166'), text: 'android-7f3a was blocked at the router by you' },
      { ts: ago(3.1 * 86400), kind: 'security', device: hostId('10.20.0.77'), text: 'New host espressif (10.20.0.77): not identified' },
    ].filter(e => !s.forgotten.has(e.device));
    return [...log, ...sample, ...evs].sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts)).slice(0, limit || 300);
  }

  async function device(id) {
    const inv = s.base || await inventory();
    const d = inv.devices.find(x => x.id === id);
    let data;
    try { if (HOSTS.some(x => hostId(x.ip) === id)) throw new Error('sample host'); data = await real.device(id); } catch { data = { device: d, knowledge: { specs: null, guideMarkdown: null }, live: null, links: [], events: [] }; }
    if (!d) throw new Error('No device has the id ' + id + '.');
    const evs = (await events(300)).filter(e => e.device === id);
    return { ...data, device: { ...(data.device || {}), ...d }, events: [...evs, ...(data.events || []).filter(e => e.kind !== 'security')].slice(0, 50) };
  }

  async function deviceActions(id) {
    const inv = s.base || await inventory();
    const d = inv.devices.find(x => x.id === id);
    if (!d) throw new Error('No device has the id ' + id + '.');
    const name = d.name, ip = (d.net || []).map(n => n.ip).find(Boolean), onLan = !!ip && !(d.net || []).every(n => n.if === 'tailscale');
    const managed = isHandsOff(id), prot = isProtected(inv, id), blocked = s.blocked.has(id);
    const no = why => ({ available: false, unavailableReason: why });
    const managedNo = no(name + ' is hands-off' + (handsOffWhy(id) ? ' (' + handsOffWhy(id) + ')' : '') + ': nothing may be changed for it from here.');
    const A = (aid, label, risk, reversible, confirm, avail) => ({ id: aid, label, risk, reversible, available: true, unavailableReason: null, confirm, ...(avail || {}) });
    const out = [
      A('identify', 'Say what it is', 'change', true, { title: 'Say what ' + name + ' is', effect: 'Writes the name, maker, model, kind and room you give to data/inventory.json, marked as reported by you.' + (d.dynamic ? ' The host becomes a device in the inventory.' : ''), undo: 'Identify it again with other values, or remove it. The inventory before this change is kept in data/state/backups/.' }, managed ? managedNo : id === 'internet' ? no('This stands for the outside world, not a device.') : null),
      A('scan', 'Deep scan', 'read', true, { title: 'Deep scan ' + name, effect: 'Probes ' + (ip || 'the device') + ' now: common ports and their banners, mDNS, SSDP and the MAC prefix. It reads; it changes nothing on the device. It takes up to a minute and the device may log the connection attempts.', undo: 'Nothing to undo: nothing is changed.' }, !onLan ? no('It has no address on the LAN, so there is nothing to probe.') : null),
      A('investigate', 'Ask the agent to investigate', 'read', true, { title: 'Investigate ' + name, effect: 'Starts an agent run about this device. The agent reads what is known, looks things up and reports what it most likely is and whether it is a concern. Its run is read-only.', undo: 'Cancel the run from the Agent view.' }, managed ? managedNo : null),
      blocked
        ? A('unblock', 'Unblock at the router', 'change', true, { title: 'Unblock ' + name, effect: 'Removes ' + name + ' from the router\'s block list. It can join the network and reach the internet again.', undo: 'Block it again.' }, !s.configured ? no('Needs the router login. Add it in Settings.') : null)
        : A('block', 'Block at the router', 'change', true, { title: 'Block ' + name + ' at the router', effect: 'Adds ' + name + (ip ? ' (' + ip + ')' : '') + ' to the router\'s block list. It loses its connection to the internet and to the rest of the house within a few seconds. Anything it was doing stops.', undo: 'Unblock it here. The router keeps the entry until you do.' },
          managed ? managedNo : prot ? no('The network depends on this device: it cannot be blocked from here.') : !onLan ? no('It is not on the LAN, so the router has nothing to block.') : !s.configured ? no('Needs the router login. Add it in Settings.') : null),
      A('forget', 'Remove from the inventory', 'destructive', false, { title: 'Remove ' + name, effect: 'Deletes ' + name + ' and its cables from data/inventory.json. Its history stays in the event log.' + (d.dynamic || onLan ? ' If it is still on the network it will show up again as a new host.' : ''), undo: 'No undo in the app. A copy of the inventory from before the change is kept in data/state/backups/ and can be put back by hand.' },
        managed ? managedNo : prot ? no('The map is built around this device: it cannot be removed from here.') : null),
    ];
    return out;
  }

  async function deviceAction(id, body) {
    if (!body || body.confirm !== true) throw Object.assign(new Error('The action was not confirmed.'), { status: 400 });
    const acts = await deviceActions(id);
    const a = acts.find(x => x.id === body.action);
    if (!a) throw Object.assign(new Error('No such action.'), { status: 400 });
    if (!a.available) throw Object.assign(new Error(a.unavailableReason), { status: 403 });
    const d = s.base.devices.find(x => x.id === id);
    await wait(body.action === 'scan' ? 1800 : 700);
    const ev = text => log.unshift({ ts: new Date().toISOString(), kind: 'security', device: id, text });
    switch (body.action) {
      case 'identify': { const p = body.params || {}; s.named.set(id, { ...p, at: new Date().toISOString() }); ev((p.name || d.name) + ' was identified by you as ' + [p.vendor, p.model].filter(Boolean).join(' ')); return { ok: true, result: { message: 'Saved to the inventory as reported by you.', device: id } }; }
      case 'scan': { const evd = [{ source: 'ports', label: 'Open ports', value: id.endsWith('201') ? '23 (telnet), 8080 (http), 37215 (unknown)' : 'none of the common ones answer', ts: new Date().toISOString() }, { source: 'ssdp', label: 'SSDP / UPnP', value: 'no answer', ts: new Date().toISOString() }];
        s.scanned.set(id, evd); return { ok: true, result: { message: 'Scan finished: ' + evd.length + ' new findings.', evidence: evd } }; }
      case 'investigate': return { ok: true, result: { runId: 'r00000000f1c5', message: 'The agent run has started.' } };
      case 'block': s.blocked.set(id, true); ev(d.name + ' was blocked at the router by you'); return { ok: true, result: { message: d.name + ' is on the router\'s block list.' } };
      case 'unblock': s.blocked.delete(id); ev(d.name + ' was unblocked at the router by you'); return { ok: true, result: { message: d.name + ' is off the block list.' } };
      case 'forget': s.forgotten.add(id); ev(d.name + ' was removed from the inventory by you'); return { ok: true, result: { message: d.name + ' was removed. Backup: data/state/backups/inventory-sample.json' } };
      default: return { ok: false, error: 'No such action.' };
    }
  }

  const orphan = [{ mac: 'C2:EF:E0:55:B0:72', name: 'android-dhcp-12', randomizedMac: true, note: 'An Android 12 device, by the name it sent. Not in the router\'s current client list.' }, { mac: 'D2:6C:C3:BB:B4:F5', name: 'HUAWEI_P30_Pro-0a1b2c3d4e', randomizedMac: true, note: 'A Huawei P30 Pro, by the name it sent.' }];
  const routerDoc = () => ({ blocked: orphan.filter(b => !s.unblockedMacs.has(b.mac)), configured: s.configured, ok: s.configured ? true : null, error: null, model: s.configured ? ((s.base && (s.base.devices.find(d => d.kind === 'router') || {}).model) || 'Router') : null, firmware: s.configured ? '3.0.0.4.388_24621' : null, clients: s.configured ? 27 : null });
  return {
    demo: true, inventory, live, events, device, deviceActions, deviceAction,
    threats: threatDemo.threats, threat: threatDemo.threat, threatAction: threatDemo.threatAction, threatScan: threatDemo.threatScan,
    router: async () => routerDoc(),
    routerLogin: async ({ username, password }) => { await wait(900); if (!username || !password || password === 'wrong') return { ok: false, error: 'The router refused that user name and password.' }; s.configured = true; s.base = null; return { ok: true }; },
    routerUnblock: async mac => { await wait(700); if (!s.configured) return { ok: false, error: 'Needs the router login. Add it in Settings.' }; s.unblockedMacs.add(mac); return { ok: true }; },
    routerLogout: async () => { await wait(300); s.configured = false; s.base = null; return { ok: true }; },
  };
}
