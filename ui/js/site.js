// What makes this house this house, as /api/site serves it (data/site.json, resolved by the server).
// Every helper copes with an older server that has no /api/site: the answer is then {} and each one
// falls back to plain, generic words. Nothing here names a particular house.
import { get } from './store.js';

const site = () => get().site || {};

/** The person the app speaks to ("you" in the copy); their name only where a name reads better. */
export function ownerName() {
  const s = site();
  const o = (s.home && s.home.owner) || s.owner;
  return typeof o === 'string' && o.trim() ? o.trim() : null;
}
export const homeName = () => { const s = site(); return (s.home && s.home.name) || null; };

/** The computer this hub runs on, as an inventory id, or null. */
export function hostId() {
  const h = site().host;
  if (!h) return null;
  if (typeof h === 'string') return h;
  return h.deviceId || h.id || null;
}

/** Devices the agent never touches: [{ id, ips, names, why }]. */
export function handsOff() {
  const list = site().handsOff;
  return Array.isArray(list) ? list.filter(x => x && (x.id || (x.ips || []).length || (x.names || []).length)) : [];
}
export const isHandsOff = id => !!id && handsOff().some(x => x.id === id);
export const handsOffWhy = id => { const x = handsOff().find(y => y.id === id); return (x && x.why) || null; };

/** Inventory ids never offered for blocking or removal (the server also adds network gear and the host). */
export const protectedIds = () => new Set([...(Array.isArray(site().protected) ? site().protected : []), hostId()].filter(Boolean));

export function routerInfo() {
  const r = site().router || {};
  return { type: r.type || null, deviceId: r.deviceId || null, writes: !!r.writes };
}

/** Folders whose contents the agent may never read. Always ~/.ssh; the rest come from the site file. */
export function secretDirs() {
  const s = site();
  const extra = Array.isArray(s.secretDirs) ? s.secretDirs : [];
  return [...new Set(['~/.ssh', ...extra])];
}
