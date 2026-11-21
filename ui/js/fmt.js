// Words and numbers, per the copy rules in docs/DESIGN.md section 10.

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const p2 = n => String(n).padStart(2, '0');

export function toMs(ts) {
  if (ts == null) return null;
  if (typeof ts === 'number') return ts < 1e12 ? ts * 1000 : ts;
  const t = Date.parse(ts);
  return Number.isNaN(t) ? null : t;
}

export function clock(ts) {
  const t = toMs(ts); if (t == null) return '';
  const d = new Date(t);
  return p2(d.getHours()) + ':' + p2(d.getMinutes());
}

export function absTime(ts) {
  const t = toMs(ts); if (t == null) return 'not known';
  const d = new Date(t);
  return d.getDate() + ' ' + MONTHS[d.getMonth()] + ', ' + p2(d.getHours()) + ':' + p2(d.getMinutes());
}

export function duration(sec) {
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return sec + ' s';
  if (sec < 3600) return Math.floor(sec / 60) + ' min' + (sec < 600 && sec % 60 ? ' ' + (sec % 60) + ' s' : '');
  if (sec < 86400) return Math.floor(sec / 3600) + ' h' + (Math.floor((sec % 3600) / 60) ? ' ' + Math.floor((sec % 3600) / 60) + ' min' : '');
  return Math.floor(sec / 86400) + ' days';
}

/** "40 s", "3 min", "2 h" under a day; absolute after. */
export function age(ts, now = Date.now()) {
  const t = toMs(ts); if (t == null) return null;
  const sec = Math.max(0, Math.round((now - t) / 1000));
  if (sec < 60) return sec + ' s';
  if (sec < 3600) return Math.floor(sec / 60) + ' min';
  if (sec < 86400) return Math.floor(sec / 3600) + ' h';
  return null;
}

export function relTime(ts, now = Date.now()) {
  const a = age(ts, now);
  if (a) return a + ' ago';
  return absTime(ts);
}

export function hostOf(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return ''; }
}

export function isHttpUrl(url) { return typeof url === 'string' && /^https?:\/\//i.test(url); }

export const STATUS = {
  online: { label: 'Online' },
  degraded: { label: 'Degraded' },
  offline: { label: 'Offline' },
  unknown: { label: 'Unknown' },
  unmonitored: { label: 'Not monitored' },
  inferred: { label: 'Inferred from links' },
  asleep: { label: 'Paired, not connected' },
};
export const statusLabel = st => (STATUS[st] || STATUS.unknown).label;

export const TRUST = {
  live: { word: 'live', meaning: 'measured by a probe' },
  plan: { word: 'plan', meaning: 'drawn, not confirmed' },
  reported: { word: 'reported', meaning: 'someone in the home said so, or an order email' },
};

export const CABLE = {
  'usb-c': { name: 'USB-C', cls: 'usbc' },
  hdmi: { name: 'HDMI', cls: 'hdmi' },
  usb: { name: 'USB', cls: 'usb' },
  video: { name: 'Video', cls: 'hdmi' },
  ethernet: { name: 'Ethernet', cls: 'ethernet' },
  mesh: { name: 'Mesh', cls: 'mesh' },
  wifi: { name: 'Wi-Fi', cls: 'mesh' },
  bluetooth: { name: 'Bluetooth', cls: 'bluetooth' },
  coax: { name: 'Coax', cls: 'coax' },
  tunnel: { name: 'Tailscale', cls: 'mesh' },
};
export const cableName = c => (CABLE[c] || { name: c || 'Cable' }).name;
export const cableCls = c => (CABLE[c] || { cls: 'mesh' }).cls;

export const LINK_STATUS = { up: 'Up', down: 'Down', unknown: 'Unknown', planned: 'Planned, not confirmed' };

export const KIND = {
  computer: 'Computer', display: 'Display', kvm: 'KVM switch', hub: 'Dock', peripheral: 'Peripheral', adapter: 'Adapter',
  switch: 'Network switch', router: 'Router', 'access-point': 'Mesh node', nas: 'NAS', bridge: 'Bridge', speaker: 'Speaker',
  camera: 'Camera', vacuum: 'Robot vacuum', appliance: 'Appliance', phone: 'Phone', modem: 'Modem', tv: 'TV', unknown: 'Not identified',
  internet: 'Internet', tablet: 'Tablet', plug: 'Smart plug', light: 'Light', sensor: 'Sensor', printer: 'Printer', console: 'Games console', watch: 'Watch', wearable: 'Watch', headphones: 'Headphones',
};
export const kindLabel = k => KIND[k] || (k ? k[0].toUpperCase() + k.slice(1) : 'Not identified');

export const PORT_TYPE = { 'usb-c': 'USB-C', 'usb-a': 'USB-A', 'usb-b': 'USB-B', rj45: 'RJ45', hdmi: 'HDMI', dp: 'DisplayPort' };

/** camelCase or snake_case key → "Sentence case" */
export function humanKey(k) {
  const t = String(k).replace(/[_-]+/g, ' ').replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().trim();
  const fixed = t.replace(/\bip\b/g, 'IP').replace(/\busb\b/g, 'USB').replace(/\bha\b/g, 'Home Assistant').replace(/\bssid\b/g, 'SSID')
    .replace(/\bmdns\b/g, 'mDNS').replace(/\bipv4\b/g, 'IPv4').replace(/\bipv6\b/g, 'IPv6').replace(/\bhidpi\b/g, 'HiDPI').replace(/\bhz\b/g, 'Hz').replace(/\bid\b/g, 'id');
  return fixed.charAt(0).toUpperCase() + fixed.slice(1);
}

export function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }

/** Flatten nested fact objects into [label, value] rows. */
export function flatten(obj, prefix = '') {
  const out = [];
  for (const [k, v] of Object.entries(obj || {})) {
    const label = prefix ? prefix + ' · ' + humanKey(k).toLowerCase() : humanKey(k);
    if (v == null || v === '') continue;
    if (Array.isArray(v)) out.push([label, v.map(x => (typeof x === 'object' ? JSON.stringify(x) : String(x))).join(', ')]);
    else if (typeof v === 'object') out.push(...flatten(v, humanKey(k)));
    else if (typeof v === 'boolean') out.push([label, v ? 'yes' : 'no']);
    else out.push([label, String(v)]);
  }
  return out;
}

/** "2.5G" → 2.5, "5 Gb/s USB" → 5, "480 Mb/s" → 0.48. null when it is not a data rate. */
export function speedGbps(sp) {
  if (!sp) return null;
  const m = String(sp).match(/([\d.]+)\s*(G|M)(?:b\/s|bps|\b)/i);
  if (!m) return null;
  const n = parseFloat(m[1]);
  return m[2].toUpperCase() === 'G' ? n : n / 1000;
}

/** Bits per second in plain units: "340 kb/s", "2.4 Mb/s". */
export function rate(bps) {
  const n = Number(bps) || 0;
  if (n >= 1e9) return (n / 1e9).toFixed(1) + ' Gb/s';
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + ' Mb/s';
  if (n >= 1e3) return Math.round(n / 1e3) + ' kb/s';
  return Math.round(n) + ' b/s';
}
