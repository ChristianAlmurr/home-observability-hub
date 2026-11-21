// Sample Sentinel data for #/threats?demo=1, shaped exactly like docs/CONTRACT.md "Version 3".
// `&threats=0|1|3|40` picks how many findings are open; `missing` answers 404 (a server without Sentinel),
// `failing` has a scanner and an engine down, `stale` has scans that stopped three hours ago, `arrive` adds a
// critical finding nine seconds after the page opens.
// The strings are deliberately awkward: a 130-character path, 64-hex hashes, a 90-character title, and a
// file name with a right-to-left override in it. Nothing here is run and nothing leaves the page.

const ago = s => new Date(Date.now() - s * 1000).toISOString();
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const CONF = ['confirmed', 'high', 'medium', 'low'];
const HOME = '/Users/you';
const sha = seed => { let x = 2166136261, out = ''; for (let i = 0; out.length < 64; i++) { for (const c of seed + i) x = Math.imul(x ^ c.charCodeAt(0), 16777619); out += (x >>> 0).toString(16).padStart(8, '0'); } return out.slice(0, 64); };

export function variant() { const m = /[?&]threats=([a-z0-9]+)/.exec(location.hash); return m ? m[1] : ''; }

const SCANNERS = [
  ['posture', 'This Mac’s settings', 'System Integrity Protection, Gatekeeper, FileVault, the firewall, automatic updates, remote login, screen and file sharing, admin accounts, screen lock', 600, 31],
  ['downloads', 'Downloads and apps', 'New or changed files in Downloads, Desktop, Applications and mounted disk images: hash, signature, notarization, ClamAV and YARA', 60, 1284],
  ['persistence', 'Things that start by themselves', 'Launch agents and daemons, login items, cron, shell startup files, /etc/hosts, sudoers, SSH authorized keys, system extensions, profiles', 300, 212],
  ['plugins', 'Plugins and extensions', 'Claude Code plugins, skills, hooks and MCP servers; browser, VS Code and Stream Deck extensions; Homebrew, npm and pip packages', 600, 947],
  ['processes', 'Running programs', 'Ports open to the network, programs running from temporary or download folders, unsigned long-running programs, screen and disk access', 120, 418],
  ['secrets', 'Secret stores', 'Permissions of ~/.ssh, ~/.aws, ~/.config/gh, the folders listed in data/site.json and .env files in projects. Never their contents', 1800, 46],
  ['network', 'Router and devices', 'The router’s settings and changes to them, every new device, devices with risky ports, a known device changing its address', 300, 58],
  ['integrity', 'Home Observability Hub itself', 'Hashes of this app’s code, its launchd job and ~/.claude/settings.json', 600, 164],
];

function base() {
  const f = (n, o) => ({
    id: 'f-' + sha('id' + n).slice(0, 12), confidencePct: { confirmed: 100, high: 85, medium: 60, low: 30 }[o.confidence], state: 'open', isNew: false,
    firstSeen: ago(86400 * 2), lastSeen: ago(40), resolvedAt: null, evidence: [], reasons: [], fix: { text: '', command: null, needsSudo: false },
    actions: ['acknowledge', 'trust', 'rescan'], ...o,
  });
  const longDir = HOME + '/Downloads/Bank statements and invoices 2026 (shared with the accountant)/November/unpacked attachments';
  return [
    f(1, { scanner: 'downloads', category: 'malware', title: 'ClamAV names a file in Downloads as a password stealer', severity: 'critical', confidence: 'confirmed', isNew: true, firstSeen: ago(190),
      detail: 'A disk image that arrived in Downloads three minutes ago matches a ClamAV signature for Atomic Stealer, a program that copies saved passwords, browser cookies and keychain items. It has not been opened from this Mac’s account as far as the scan can tell.',
      subject: { type: 'file', name: 'Zoom-Installer-6.2.11.dmg', path: HOME + '/Downloads/Zoom-Installer-6.2.11.dmg', sha256: sha('amos') },
      evidence: [{ label: 'ClamAV', value: 'Osx.Infostealer.AtomicStealer-10021873-0 FOUND', source: 'clamscan --no-summary' }, { label: 'SHA-256', value: sha('amos'), source: 'shasum -a 256' },
        { label: 'Downloaded from', value: 'hxxps://zoom-download[.]app/mac/latest', source: 'com.apple.quarantine' }, { label: 'Signature', value: 'not signed', source: 'codesign -dv' }, { label: 'Size', value: '14.2 MB', source: 'stat' }],
      reasons: [{ code: 'clamav', text: 'A signature engine names it: this is not a guess.' }, { code: 'unsigned', text: 'It is not signed, and the real Zoom installer is.' }, { code: 'lookalike-domain', text: 'It came from a site that is not zoom.us.' }],
      fix: { text: 'Do not open it. Quarantine it from here. If it was opened, change the passwords used on this Mac from another device, starting with email and banking.', command: null, needsSudo: false },
      actions: ['acknowledge', 'quarantine', 'trust', 'rescan'] }),
    f(2, { scanner: 'persistence', category: 'persistence', title: 'A new launch agent runs a script from a temporary folder at every login', severity: 'critical', confidence: 'high', isNew: true, firstSeen: ago(2400),
      detail: 'A launch agent that did not exist at the last scan now starts a shell script kept in /private/tmp. It uses an Apple-looking name, and Apple does not install launch agents in your own Library folder.',
      subject: { type: 'launch-item', name: 'com.apple.softwareupdate.helper', path: HOME + '/Library/LaunchAgents/com.apple.softwareupdate.helper.plist', sha256: sha('agent') },
      evidence: [{ label: 'Program', value: '/bin/sh /private/tmp/.cache-7f3a/update.sh', source: 'plutil -p' }, { label: 'RunAtLoad', value: 'true', source: 'plutil -p' }, { label: 'Created', value: '40 min ago', source: 'stat' },
        { label: 'SHA-256', value: sha('agent'), source: 'shasum -a 256' }],
      reasons: [{ code: 'new-launch-item', text: 'It is new since the baseline.' }, { code: 'runs-from-tmp', text: 'It runs a program from a temporary folder.' }, { code: 'apple-lookalike', text: 'Its name imitates Apple’s.' }],
      fix: { text: 'Stop it and move the file away, then look at what the script does before deleting anything.', command: 'launchctl bootout gui/501 ' + HOME + '/Library/LaunchAgents/com.apple.softwareupdate.helper.plist', needsSudo: false } }),
    f(3, { scanner: 'downloads', category: 'download', title: 'Unsigned app in Downloads is not notarized and asks for Accessibility and Full Disk Access', severity: 'high', confidence: 'medium', isNew: true, firstSeen: ago(3 * 3600),
      detail: 'An app bundle unpacked from a zip has no signature and no notarization ticket, and its Info.plist asks for access that lets it read every file and control the keyboard. Its name contains a hidden right-to-left mark, so Finder shows it as a picture.',
      subject: { type: 'app', name: 'Invoice_2026_11\u202Egpj.app', path: longDir + '/Invoice_2026_11\u202Egpj.app', sha256: sha('invoice') },
      evidence: [{ label: 'Gatekeeper', value: 'rejected: no usable signature', source: 'spctl --assess --type execute' }, { label: 'Signature', value: 'code object is not signed at all', source: 'codesign -dv' },
        { label: 'Asks for', value: 'NSAppleEventsUsageDescription, kTCCServiceAccessibility, kTCCServiceSystemPolicyAllFiles', source: 'Info.plist' }, { label: 'SHA-256', value: sha('invoice'), source: 'shasum -a 256' },
        { label: 'Path', value: longDir + '/Invoice_2026_11\u202Egpj.app', source: 'downloads scan' }],
      reasons: [{ code: 'unsigned', text: 'It is not signed.' }, { code: 'not-notarized', text: 'Apple has not checked it.' }, { code: 'bidi-name', text: 'Its name hides its real ending.' }, { code: 'broad-permissions', text: 'It asks for more access than an invoice needs.' }],
      fix: { text: 'Do not open it. If you were not expecting it, quarantine it. If it is something you built or know, trust it.', command: null, needsSudo: false },
      actions: ['acknowledge', 'quarantine', 'trust', 'rescan'] }),
    f(4, { scanner: 'posture', category: 'posture', title: 'The firewall is off', severity: 'high', confidence: 'confirmed', firstSeen: ago(86400 * 3),
      detail: 'macOS is accepting incoming connections on every port a program opens. On the home network that is every device in the house; on another Wi-Fi it is everyone there.',
      subject: { type: 'setting', name: 'Application Firewall' },
      evidence: [{ label: 'Global state', value: 'Firewall is disabled. (State = 0)', source: 'socketfilterfw --getglobalstate' }, { label: 'Stealth mode', value: 'off', source: 'socketfilterfw --getstealthmode' }],
      reasons: [{ code: 'firewall-off', text: 'The setting was read directly.' }],
      fix: { text: 'Turn it on in System Settings, Network, Firewall, or run this in Terminal.', command: 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on', needsSudo: true }, actions: ['acknowledge', 'rescan'] }),
    f(5, { scanner: 'network', category: 'device', title: 'A device on the Wi-Fi has telnet open', severity: 'medium', confidence: 'confirmed', firstSeen: ago(6.1 * 3600),
      detail: 'Telnet sends its password in the clear and is the first thing network worms try. The device joined six hours ago with a randomized address and is not identified.',
      subject: { type: 'device', name: 'Host .201', deviceId: 'host-10-20-0-201', port: 23 },
      evidence: [{ label: 'Open port', value: '23/tcp telnet', source: 'port scan' }, { label: 'Banner', value: 'BusyBox v1.19.4 login:', source: 'port scan' }, { label: 'Address', value: '10.20.0.201', source: 'router client list' }],
      reasons: [{ code: 'port-telnet', text: 'Telnet answered.' }, { code: 'unidentified', text: 'Nothing names the device.' }],
      fix: { text: 'Find out what it is. If nobody in the house knows it, block it at the router from its device page.', command: null, needsSudo: false }, actions: ['acknowledge', 'rescan'] }),
    f(6, { scanner: 'plugins', category: 'plugin', title: 'Browser extension can read and change every page you visit', severity: 'medium', confidence: 'medium', firstSeen: ago(86400 * 5),
      detail: 'A Chrome extension installed five days ago has permission for all sites. That is what a password or session thief needs, and also what many honest extensions ask for.',
      subject: { type: 'extension', name: 'PDF Toolbox – Convert & Merge', path: HOME + '/Library/Application Support/Google/Chrome/Default/Extensions/kbfnbcaeplbcioakkpcpgfkobkghlhen/3.1.4_0' },
      evidence: [{ label: 'Permissions', value: '<all_urls>, cookies, webRequest, scripting', source: 'manifest.json' }, { label: 'Installed', value: '15 Nov, 21:14', source: 'Chrome Preferences' }, { label: 'From the store', value: 'yes', source: 'Chrome Preferences' }],
      reasons: [{ code: 'all-urls', text: 'It can read every page.' }, { code: 'new-extension', text: 'It is new since the baseline.' }],
      fix: { text: 'If you do not use it, remove it in Chrome under Extensions. If you do, trust it here.', command: null, needsSudo: false } }),
    f(7, { scanner: 'secrets', category: 'secrets', title: 'A .env file can be read by every account on this Mac', severity: 'low', confidence: 'confirmed', firstSeen: ago(86400 * 9),
      detail: 'The file holds settings that usually include keys. Its permissions let any account on this Mac read it. The scan read the permissions only, not the file.',
      subject: { type: 'file', name: '.env', path: HOME + '/projects/shop/.env' },
      evidence: [{ label: 'Mode', value: '-rw-r--r-- (644)', source: 'stat' }, { label: 'Owner', value: 'you:staff', source: 'stat' }, { label: 'Tracked by git', value: 'no', source: 'git ls-files' }],
      reasons: [{ code: 'world-readable', text: 'Others can read it.' }],
      fix: { text: 'Make it readable by you only.', command: 'chmod 600 ' + HOME + '/projects/shop/.env', needsSudo: false }, actions: ['acknowledge', 'trust', 'rescan'] }),
    f(8, { scanner: 'integrity', category: 'integrity', title: 'Claude Code settings changed outside git', severity: 'info', confidence: 'confirmed', firstSeen: ago(86400),
      detail: 'The file’s hash differs from the baseline. Claude Code rewrites this file when you change a permission, so this is usually you.',
      subject: { type: 'file', name: 'settings.json', path: HOME + '/.claude/settings.json', sha256: sha('settings') },
      evidence: [{ label: 'SHA-256 now', value: sha('settings'), source: 'shasum -a 256' }, { label: 'SHA-256 baseline', value: sha('settings-old'), source: 'baseline.json' }, { label: 'Changed', value: '19 Nov, 22:40', source: 'stat' }],
      reasons: [{ code: 'hash-changed', text: 'The hash changed.' }], fix: { text: 'Look at the file. If the change is yours, trust it so the new version becomes the baseline.', command: null, needsSudo: false } }),
    f(9, { scanner: 'processes', category: 'exposure', title: 'A program listens on every network interface', severity: 'medium', confidence: 'high', state: 'acknowledged', firstSeen: ago(86400 * 12), actions: ['reopen', 'trust', 'rescan'],
      detail: 'whisper-server accepts connections from any device on the network, not only from this Mac.', subject: { type: 'port', name: 'whisper-server', port: 8790, pid: 61422, path: '/opt/homebrew/bin/whisper-server' },
      evidence: [{ label: 'Listening on', value: '*:8790 (TCP)', source: 'lsof -iTCP -sTCP:LISTEN' }, { label: 'Signature', value: 'ad-hoc', source: 'codesign -dv' }],
      reasons: [{ code: 'listen-any', text: 'It is not bound to loopback.' }], fix: { text: 'Start it with --host 127.0.0.1 if only this Mac uses it.', command: null, needsSudo: false } }),
    f(10, { scanner: 'plugins', category: 'plugin', title: 'Stream Deck plugin is not signed', severity: 'low', confidence: 'high', state: 'trusted', firstSeen: ago(86400 * 20), actions: ['reopen', 'rescan'],
      detail: 'The plugin’s binary has no signature. You trusted it on 2 Nov.', subject: { type: 'extension', name: 'com.example.house.sdPlugin', path: HOME + '/Library/Application Support/com.elgato.StreamDeck/Plugins/com.example.house.sdPlugin' },
      evidence: [{ label: 'Signature', value: 'not signed', source: 'codesign -dv' }], reasons: [{ code: 'unsigned', text: 'It is not signed.' }], fix: { text: 'Nothing to do while it stays as it is.', command: null, needsSudo: false } }),
    f(11, { scanner: 'downloads', category: 'download', title: 'Script pipes a download straight into a shell', severity: 'high', confidence: 'medium', state: 'quarantined', firstSeen: ago(86400 * 4), actions: ['restore', 'rescan'],
      detail: 'The script fetches a file from the internet and runs it without looking at it. It is in quarantine and cannot run.', subject: { type: 'file', name: 'install.command', path: HOME + '/Desktop/install.command', sha256: sha('pipe') },
      evidence: [{ label: 'Line 3', value: 'curl -fsSL https://get.example.sh | sh', source: 'heuristic: pipe-to-shell' }, { label: 'SHA-256', value: sha('pipe'), source: 'shasum -a 256' }, { label: 'Quarantined to', value: 'data/state/sentinel/quarantine/' + sha('pipe').slice(0, 16), source: 'sentinel' }],
      reasons: [{ code: 'pipe-to-shell', text: 'It runs whatever the server sends.' }], fix: { text: 'Leave it in quarantine unless you wrote it.', command: null, needsSudo: false } }),
    f(12, { scanner: 'posture', category: 'posture', title: 'Remote Login (SSH) was on', severity: 'medium', confidence: 'confirmed', state: 'resolved', firstSeen: ago(86400 * 6), resolvedAt: ago(86400 * 5), actions: ['rescan'],
      detail: 'Remote Login let anyone on the network try passwords against this Mac. It is off now.', subject: { type: 'setting', name: 'Remote Login' },
      evidence: [{ label: 'Remote Login', value: 'Off', source: 'systemsetup -getremotelogin' }], reasons: [{ code: 'ssh-on', text: 'The setting was read directly.' }], fix: { text: 'Nothing to do.', command: null, needsSudo: false } }),
  ];
}

function many(list) {
  const kinds = [['plugins', 'plugin', 'package', 'Global npm package runs a script when it is installed', 'low', 'medium'], ['downloads', 'download', 'file', 'File in Downloads has two extensions', 'medium', 'low'],
    ['processes', 'process', 'process', 'Unsigned program has been running for two days', 'medium', 'medium'], ['persistence', 'persistence', 'launch-item', 'Login item was added outside System Settings', 'high', 'low'],
    ['plugins', 'plugin', 'extension', 'VS Code extension is not from the marketplace', 'low', 'high'], ['secrets', 'secrets', 'file', 'SSH private key is readable by the group', 'high', 'confirmed']];
  const names = ['left-pad-cli', 'holiday-photos.jpg.command', 'node', 'com.updater.agent', 'theme-nord-plus', 'id_ed25519_old', 'esbuild-wasm', 'receipt.pdf.app', 'python3.9', 'com.dropbox.helper'];
  const out = list.slice();
  for (let i = 0; out.filter(x => x.state === 'open').length < 40; i++) {
    const [scanner, category, type, title, severity, confidence] = kinds[i % kinds.length];
    const name = names[i % names.length] + (i >= names.length ? '-' + i : '');
    out.push({ id: 'f-' + sha('gen' + i).slice(0, 12), scanner, category, title, severity, confidence, confidencePct: { confirmed: 100, high: 85, medium: 60, low: 30 }[confidence], state: 'open', isNew: i % 9 === 0,
      detail: 'Sample finding ' + (i + 1) + ' of a long list.', subject: { type, name, path: HOME + '/Library/Sample/' + name, sha256: type === 'file' ? sha(name) : undefined },
      evidence: [{ label: 'Seen', value: name, source: scanner + ' scan' }], reasons: [{ code: 'sample', text: 'Generated to test a long list.' }], fix: { text: 'Look at it, then trust it or remove it.', command: null, needsSudo: false },
      firstSeen: ago(3600 * (i + 2)), lastSeen: ago(50), resolvedAt: null, actions: ['acknowledge', 'trust', 'rescan'] });
  }
  return out;
}

export function createThreatDemo() {
  const v = variant();
  const wait = ms => new Promise(r => setTimeout(r, ms));
  let list = base();
  if (v === '0' || v === 'failing' || v === 'stale') list = list.filter(f => f.state === 'resolved' || f.state === 'trusted');
  else if (v === '1') list = list.filter((f, i) => i === 3 || f.state === 'resolved');
  else if (v === '3') list = list.filter((f, i) => [0, 2, 4].includes(i) || f.state === 'resolved');
  else if (v === '40') list = many(list);
  const history = new Map();
  const running = new Map();   // scanner → until (ms)
  const ranAt = new Map();     // scanner → iso
  // &threats=arrive: the worst finding turns up nine seconds after the page opens, to see how a new one is announced
  const t0 = Date.now();
  let pending = null;
  if (v === 'arrive') { pending = list[0]; list = list.slice(1); }

  const rank = f => SEV.indexOf(f.severity) * 1e15 + CONF.indexOf(f.confidence) * 1e13 - Date.parse(f.firstSeen) / 1e3;
  const sorted = () => list.slice().sort((a, b) => rank(a) - rank(b));
  const arrive = () => { if (pending && Date.now() - t0 > 9000) { pending.firstSeen = ago(3); list.push(pending); pending = null; } };
  function summary() {
    arrive();
    const open = list.filter(f => f.state === 'open');
    const bySeverity = Object.fromEntries(SEV.map(s => [s, open.filter(f => f.severity === s).length]));
    const worst = SEV.find(s => bySeverity[s]) || 'none';
    const level = open.some(f => f.severity === 'critical' && ['confirmed', 'high'].includes(f.confidence)) ? 'compromised' : bySeverity.critical || bySeverity.high ? 'at-risk' : bySeverity.medium ? 'watch' : 'secure';
    return { open: open.length, new: open.filter(f => f.isNew).length, bySeverity, worst, level, lastScan: v === 'stale' ? ago(3 * 3600 + 240) : ago(22) };
  }
  function scanners() {
    const now = Date.now();
    return Object.fromEntries(SCANNERS.map(([name, label, description, intervalSec, itemsScanned], i) => {
      const run = running.get(name) > now;
      const failing = v === 'failing' && name === 'downloads';
      return [name, { label, description, intervalSec, lastRun: ranAt.get(name) || (v === 'stale' ? ago(3 * 3600 + 240 + i * 31) : failing ? ago(52 * 60) : ago(Math.min(intervalSec - 5, 22 + i * 37))), durationMs: 180 + i * 240,
        ok: !failing, error: failing ? 'Operation not permitted: ' + HOME + '/Downloads. Give python3 Full Disk Access in System Settings, Privacy & Security.' : null,
        itemsScanned: failing ? 0 : itemsScanned, open: list.filter(f => f.scanner === name && f.state === 'open').length, running: run }];
    }));
  }
  const engines = () => ({ clamav: v === 'failing' ? { installed: false, version: null, signaturesAt: null } : { installed: true, version: '1.4.1', signaturesAt: ago(86400 * 2) }, yara: { installed: false, rules: 0 },
    xprotect: { version: '5281', updatedAt: ago(86400 * 6) }, gatekeeper: { enabled: true } });
  const find = id => { const f = list.find(x => x.id === id); if (!f) throw Object.assign(new Error('No finding has the id ' + id + '.'), { status: 404 }); return f; };
  const hist = f => history.get(f.id) || [{ ts: f.firstSeen, actor: 'sentinel', change: 'Found by the ' + f.scanner + ' scan' },
    ...(f.state === 'acknowledged' ? [{ ts: ago(86400 * 11), actor: 'person', change: 'Acknowledged' }] : f.state === 'trusted' ? [{ ts: ago(86400 * 18), actor: 'person', change: 'Trusted: added to the baseline' }]
      : f.state === 'quarantined' ? [{ ts: ago(86400 * 4 - 600), actor: 'person', change: 'Quarantined from ' + f.subject.path }] : f.state === 'resolved' ? [{ ts: f.resolvedAt, actor: 'sentinel', change: 'Resolved: the cause is gone' }] : [])];

  return {
    summary,
    async threats(params = {}) {
      await wait(160);
      if (v === 'missing') throw Object.assign(new Error('The server answered 404.'), { status: 404 });
      arrive();
      let fs = sorted();
      fs = params.state === 'all' ? fs : params.state ? fs.filter(f => f.state === params.state) : fs.filter(f => f.state !== 'resolved');
      if (params.severity) fs = fs.filter(f => f.severity === params.severity);
      if (params.scanner) fs = fs.filter(f => f.scanner === params.scanner);
      return JSON.parse(JSON.stringify({ ts: new Date().toISOString(), summary: summary(), findings: fs, scanners: scanners(), engines: engines() }));
    },
    async threat(id) { await wait(220); const f = find(id); return JSON.parse(JSON.stringify({ ...f, history: hist(f).slice().sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts)) })); },
    async threatAction(id, body) {
      await wait(body.action === 'rescan' ? 1400 : 600);
      const f = find(id), a = body && body.action;
      if (!f.actions.includes(a)) throw Object.assign(new Error('That cannot be done to this finding now.'), { status: 409 });
      if (['trust', 'quarantine', 'restore'].includes(a) && body.confirm !== true) throw Object.assign(new Error('The action was not confirmed.'), { status: 400 });
      const log = change => history.set(f.id, [...hist(f), { ts: new Date().toISOString(), actor: a === 'rescan' ? 'sentinel' : 'person', change }]);
      const canQ = ['file', 'app'].includes(f.subject.type) && f.subject.path && !/\/Library\//.test(f.subject.path);
      let message;
      switch (a) {
        case 'acknowledge': log('Acknowledged'); f.state = 'acknowledged'; f.isNew = false; f.actions = ['reopen', 'trust', ...(canQ ? ['quarantine'] : []), 'rescan']; message = 'Acknowledged. It stays on the list and is still watched.'; break;
        case 'trust': log('Trusted: added to the baseline'); f.state = 'trusted'; f.isNew = false; f.actions = ['reopen', 'rescan']; message = 'Trusted. It will be raised again only if it changes.'; break;
        case 'quarantine': log('Quarantined from ' + f.subject.path); f.state = 'quarantined'; f.isNew = false; f.actions = ['restore', 'rescan']; message = 'Moved to quarantine. It cannot run.'; break;
        case 'restore': log('Restored to ' + f.subject.path); f.state = 'open'; f.actions = ['acknowledge', 'quarantine', 'trust', 'rescan']; message = 'Put back at ' + f.subject.path + '.'; break;
        case 'reopen': log('Reopened'); f.state = 'open'; f.actions = ['acknowledge', 'trust', ...(canQ ? ['quarantine'] : []), 'rescan']; message = 'Reopened.'; break;
        case 'rescan': log('Scanned again: still there'); f.lastSeen = new Date().toISOString(); message = 'Scanned again. It is still there.'; break;
        default: throw Object.assign(new Error('No such action.'), { status: 400 });
      }
      return JSON.parse(JSON.stringify({ ok: true, finding: f, result: { message } }));
    },
    async threatScan(body = {}) {
      await wait(200);
      const names = body.scanner ? [body.scanner] : SCANNERS.map(s => s[0]);
      names.forEach((n, i) => { const until = Date.now() + 2400 + i * 500; running.set(n, until); setTimeout(() => ranAt.set(n, new Date().toISOString()), 2400 + i * 500); });
      return { ok: true, started: names };
    },
  };
}
