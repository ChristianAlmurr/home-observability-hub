"""Live wiring: the cables as the computers themselves see them.

inventory.json says how things were wired when someone last wrote it down. A Mac knows what is in each of its
sockets right now (portscan.py). This module turns those readings into facts ("the Stream Deck is on the KVM",
"the Odyssey is on the MacBook's HDMI socket"), remembers them in data/state/wiring.json, and lays them over
the inventory: a cable the inventory has in the wrong place is drawn where it was seen, marked as moved, and
goes back by itself when the reading says so. inventory.json is never written from here.

Only a computer that reports can be read. A cable between two things that are not computers (a console and a
TV, a port on the unmanaged switch) is seen by nobody, and stays as the inventory has it.
"""
import copy
import json
import os
import re
import threading
import time

USBISH = ("usb", "usb-c", "thunderbolt")
VIDEOISH = ("hdmi", "dp", "video", "usb-c", "thunderbolt")
WIRED = ("usb", "usb-c", "thunderbolt", "hdmi", "dp", "video")
HUB_KINDS = ("kvm", "hub", "dock")
PORT_LABEL = {"usb-c": "USB-C", "hdmi": "HDMI", "usb-a": "USB-A", "sd": "SD card", "magsafe": "MagSafe"}
LOCK = threading.Lock()


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")[:-2] + ":" + time.strftime("%z")[-2:]


def parse_end(end):
    if not end:
        return None, None
    a, _, b = str(end).partition(":")
    return a, (b or None)


def _hex(v):
    v = str(v or "").lower().strip()
    return v[2:] if v.startswith("0x") else v


def state_path(state_dir):
    return os.path.join(state_dir, "wiring.json")


def load_state(state_dir):
    try:
        with open(state_path(state_dir)) as f:
            d = json.load(f)
        if isinstance(d, dict):
            d.setdefault("hosts", {})
            d.setdefault("learned", {})
            d.setdefault("applied", {})
            d.setdefault("rev", 0)
            return d
    except (OSError, ValueError):
        pass
    return {"rev": 0, "hosts": {}, "learned": {}, "applied": {}}


def save_state(state_dir, state):
    tmp = state_path(state_dir) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, state_path(state_dir))


# ---------------------------------------------------------------- reading one computer

def usb_index(inv, learned=None):
    """(vendorId, productId) -> device id, from each device's usb probe, its usb list, and what was learned."""
    idx = {}
    for d in inv.get("devices") or []:
        p = d.get("probe") or {}
        if p.get("type") == "usb" and (p.get("vendorId") or p.get("productId")):
            idx[(_hex(p.get("vendorId")), _hex(p.get("productId")))] = d["id"]
        for u in d.get("usb") or []:
            idx[(_hex(u.get("vendorId")), _hex(u.get("productId")))] = d["id"]
    for did, pairs in (learned or {}).items():
        for vid, pid in pairs:
            idx.setdefault((vid, pid), did)
    return idx


def port_id(host_dev, typ, n):
    raw = "%s-%s" % (typ, n)
    return ((host_dev or {}).get("portMap") or {}).get(raw, raw)


def port_label(host_dev, pid, typ=None, n=None):
    for p in (host_dev or {}).get("ports") or []:
        if p.get("id") == pid:
            return p.get("label") or pid
    if typ:
        return "%s %s" % (PORT_LABEL.get(typ, typ), n)
    m = re.match(r"^(.*)-(\d+)$", pid or "")
    return "%s %s" % (PORT_LABEL.get(m.group(1), m.group(1)), m.group(2)) if m else pid


def match_display(inv, name):
    if not name:
        return None
    low = name.lower()
    for d in inv.get("devices") or []:
        p = d.get("probe") or {}
        if p.get("type") == "display" and (p.get("match") or "").lower() and (p.get("match") or "").lower() in low:
            return d["id"]
    for d in inv.get("devices") or []:
        if d.get("kind") in ("display", "tv") and low in ("%s %s" % (d.get("name") or "", d.get("model") or "")).lower():
            return d["id"]
    return None


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", str(s or "").lower()).strip("-")[:40] or "unnamed"


def read_host(inv, host_id, obs, learned=None):
    """One computer's reading as facts. Returns {ts, computer, model, ports, attach, video, dynamic, learned}."""
    devs = {d["id"]: d for d in inv.get("devices") or []}
    host = devs.get(host_id) or {}
    learned = {k: [tuple(p) for p in v] for k, v in (learned or {}).items()}
    idx = usb_index(inv, learned)
    ts = now_iso()
    out = {"ts": ts, "computer": obs.get("computer"), "model": obs.get("model"), "ports": [],
           "attach": {}, "video": {}, "dynamic": {}, "learned": {}}
    ports = [p for p in obs.get("ports") or [] if isinstance(p, dict)]
    usb = [u for u in obs.get("usb") or [] if isinstance(u, dict)]
    have_ports = bool(ports)

    # which socket each top-level USB device is in
    where = {}
    for p in ports:
        for u in p.get("usb") or []:
            where[(_hex(u.get("vendorId")), _hex(u.get("productId")))] = p

    # devices the inventory links to this computer that cannot be recognised by a USB id (a dock with no id on file)
    def unrecognised_neighbours():
        res = []
        known = set(idx.values())
        for l in inv.get("links") or []:
            a, b = parse_end(l.get("from"))[0], parse_end(l.get("to"))[0]
            if host_id in (a, b) and l.get("cable") in USBISH:
                o = b if a == host_id else a
                if o in devs and o not in known and devs[o].get("kind") in HUB_KINDS:
                    res.append(o)
        return res

    resolved = {}       # index in usb -> device id (or None for built-in)
    dyn = {}

    def resolve(i):
        if i in resolved:
            return resolved[i]
        u = usb[i]
        key = (_hex(u.get("vendorId")), _hex(u.get("productId")))
        if u.get("builtIn"):
            resolved[i] = None
            return None
        did = idx.get(key)
        is_hub = "hub" in (u.get("name") or "").lower()
        if did is None and is_hub:
            # the other half of a hub the inventory knows (USB 2 and USB 3 halves have different ids)
            for j, v in enumerate(usb):
                if j == i or v.get("parent") != u.get("parent") or _hex(v.get("vendorId")) != key[0]:
                    continue
                if u.get("parent") is None and have_ports and where.get((_hex(v.get("vendorId")), _hex(v.get("productId")))) is not where.get(key):
                    continue
                sib = idx.get((_hex(v.get("vendorId")), _hex(v.get("productId"))))
                if sib:
                    did = sib
                    break
        if did is None and is_hub and u.get("parent") is None:
            nb = unrecognised_neighbours()
            if len(nb) == 1:
                did = nb[0]
                out["learned"].setdefault(did, []).append(list(key))
                idx[key] = did
        if did is None:
            did = "usb-%s-%s" % (key[0] or "0000", key[1] or "0000")
            dyn[did] = {"id": did, "name": u.get("name") or "USB device %s:%s" % key,
                        "kind": "hub" if is_hub else "peripheral", "vendor": u.get("vendor"),
                        "model": u.get("name"), "zone": host.get("zone") or "unplaced", "dynamic": True, "verified": "live",
                        "probe": {"type": "none"}, "net": None,
                        "ports": [{"id": "usb", "label": "USB", "type": "usb"}],
                        "usbSeen": {"vendorId": key[0], "productId": key[1], "vendor": u.get("vendor"),
                                    "name": u.get("name"), "serial": u.get("serial"), "by": host_id, "firstSeen": ts}}
        resolved[i] = did
        return did

    for i, u in enumerate(usb):
        did = resolve(i)
        if did is None or did == host_id:
            continue
        key = (_hex(u.get("vendorId")), _hex(u.get("productId")))
        par = u.get("parent")
        # climb past built-in hubs and the other half of the same device
        pdev, sock = None, None
        while par is not None:
            pd = resolve(par)
            if pd is not None and pd != did:
                pdev = pd
                break
            par = usb[par].get("parent")
        if pdev is None:
            pdev = host_id
            p = where.get(key)
            if p is None:
                # a child of a companion half: use the socket of any entry that resolved to the same device
                for j, v in enumerate(usb):
                    if resolved.get(j) == did and where.get((_hex(v.get("vendorId")), _hex(v.get("productId")))):
                        p = where[(_hex(v.get("vendorId")), _hex(v.get("productId")))]
                        break
            if p is not None:
                sock = port_id(host, p.get("type"), p.get("n"))
        cur = out["attach"].get(did)
        fact = {"parent": pdev, "port": sock, "present": True, "seen": ts, "name": u.get("name"),
                "usbId": "%s:%s" % key, "speed": u.get("speed")}
        if cur is None or (cur.get("port") is None and sock):
            out["attach"][did] = fact
    out["dynamic"] = {k: v for k, v in dyn.items() if k in out["attach"]}

    # displays, socket by socket
    for p in ports:
        sock = port_id(host, p.get("type"), p.get("n"))
        tops = [idx.get((_hex(u.get("vendorId")), _hex(u.get("productId")))) for u in p.get("usb") or []]
        tops = [t for t in tops if t]
        what = []
        for t in dict.fromkeys(tops):
            what.append((devs.get(t) or {}).get("name", t))
        for u in p.get("usb") or []:
            if not idx.get((_hex(u.get("vendorId")), _hex(u.get("productId")))) and u.get("name") and not (tops and u.get("hub")):
                what.append(u["name"])
        disp = p.get("display")
        if disp and disp.get("name"):
            did = match_display(inv, disp["name"])
            if did is None:
                did = "display-" + slug(disp["name"])
                out["dynamic"][did] = {"id": did, "name": disp["name"], "kind": "display", "vendor": disp.get("vendor"),
                                       "model": disp["name"], "zone": host.get("zone") or "unplaced", "dynamic": True,
                                       "verified": "live", "probe": {"type": "none"}, "net": None,
                                       "ports": [{"id": "in", "label": "Video in", "type": "video"}],
                                       "displaySeen": {"name": disp["name"], "vendor": disp.get("vendor"), "by": host_id, "firstSeen": ts}}
            via = next((t for t in tops if (devs.get(t) or {}).get("kind") in HUB_KINDS), None)
            out["video"][did] = {"via": via, "port": sock, "portType": p.get("type"), "present": True, "seen": ts,
                                 "name": disp["name"], "rate": disp.get("rate")}
            what.append("%s (video)" % (devs.get(did) or {}).get("name", disp["name"]))
        out["ports"].append({"id": sock, "label": port_label(host, sock, p.get("type"), p.get("n")), "type": p.get("type"),
                             "active": bool(p.get("active")), "what": list(dict.fromkeys(what))})
    if not have_ports:
        for d in obs.get("displays") or []:
            if isinstance(d, dict) and d.get("name") and not d.get("builtIn"):
                did = match_display(inv, d["name"])
                if did:
                    out["video"][did] = {"via": None, "port": None, "portType": None, "present": True, "seen": ts,
                                         "name": d["name"], "rate": None, "socketUnknown": True}
    return out


def update_host(state, inv, host_id, obs, source):
    """Fold one reading into the state. What an inventory device was last plugged into is remembered while it is
    unplugged; a device the inventory does not know is forgotten when it goes."""
    devs = {d["id"] for d in inv.get("devices") or []}
    new = read_host(inv, host_id, obs, state.get("learned"))
    old = (state.get("hosts") or {}).get(host_id) or {}
    for kind in ("attach", "video"):
        for cid, f in (old.get(kind) or {}).items():
            if cid not in new[kind] and cid in devs:
                new[kind][cid] = dict(f, present=False)
    for did, pairs in new.pop("learned").items():
        cur = state.setdefault("learned", {}).setdefault(did, [])
        for p in pairs:
            if p not in cur:
                cur.append(p)
    new["source"] = source
    new["epoch"] = time.time()
    state.setdefault("hosts", {})[host_id] = new
    return new


# ---------------------------------------------------------------- laying the facts over the inventory

def apply(inv, state):
    """inventory + facts -> the inventory as wired right now. Pure: returns a copy."""
    inv = copy.deepcopy(inv)
    if not state or not state.get("hosts"):
        return inv
    devices = inv.setdefault("devices", [])
    links = inv.setdefault("links", [])
    devs = {d["id"]: d for d in devices}
    hosts = {h: hs for h, hs in state["hosts"].items() if h in devs}

    for h, hs in hosts.items():
        for did, d in (hs.get("dynamic") or {}).items():
            if did not in devs:
                d = copy.deepcopy(d)
                devices.append(d)
                devs[did] = d

    def ends(l):
        return parse_end(l.get("from"))[0], parse_end(l.get("to"))[0]

    def other(l, x):
        a, b = ends(l)
        return b if a == x else a

    def between(x, y, cables=WIRED):
        res = [l for l in links if set(ends(l)) == {x, y} and l.get("cable") in cables]
        return res[0] if res else None

    def linked(x, y):
        return any(set(ends(l)) == {x, y} for l in links)

    def name(x):
        return (devs.get(x) or {}).get("name", x)

    def ensure_port(did, pid, typ=None):
        if not pid or did not in devs:
            return
        d = devs[did]
        if not any(p.get("id") == pid for p in d.get("ports") or []):
            m = re.match(r"^(.*)-(\d+)$", pid)
            lab = "%s %s" % (PORT_LABEL.get(m.group(1), m.group(1)), m.group(2)) if m else pid
            d["ports"] = list(d.get("ports") or []) + [{"id": pid, "label": lab, "type": typ or (m.group(1) if m else "usb"), "observed": True}]

    def set_end(l, side_dev, new_dev, new_port, keep_port=False):
        """Point the end of l that is on side_dev at new_dev[:new_port]; remember what the inventory said."""
        a = parse_end(l.get("from"))
        key = "from" if a[0] == side_dev else "to"
        cur_dev, cur_port = parse_end(l.get(key))
        port = new_port if (new_port or not keep_port) else cur_port
        new = "%s:%s" % (new_dev, port) if port else new_dev
        if new != l.get(key):
            l.setdefault("declared", {"from": l.get("from"), "to": l.get("to")})
            l[key] = new
            if cur_dev != new_dev:
                l["moved"] = True
            else:
                l["corrected"] = True
        ensure_port(new_dev, port)

    def mark(l, host, fact, text):
        l["observed"] = {"by": host, "ts": fact.get("seen"), "present": bool(fact.get("present"))}
        l["verified"] = "live"
        l["evidence"] = text
        claimed.add(l["id"])

    def synth(lid, frm, to, cable, carries, label):
        l = {"id": lid, "from": frm, "to": to, "cable": cable, "carries": carries, "label": label, "synthetic": True}
        links.append(l)
        return l

    claimed = set()

    # 1. USB: every device under the computer or hub it was seen on
    best = {}
    for h, hs in hosts.items():
        for cid, f in (hs.get("attach") or {}).items():
            cur = best.get(cid)
            rank = (bool(f.get("present")), f.get("seen") or "")
            if cur is None or rank > cur[2]:
                best[cid] = (h, f, rank)
    for cid, (h, f, _) in sorted(best.items(), key=lambda kv: kv[1][1].get("parent") != kv[1][0]):
        par = f.get("parent")
        if cid not in devs or par not in devs:
            continue
        sock = f.get("port")
        if par == h:
            where = "in its own %s" % (port_label(devs[par], sock) if sock else "USB")
        else:
            where = "on %s" % name(par)
        seen = "Seen by %s %s%s." % (name(h), where, "" if f.get("present") else " when it was last plugged in")
        cands = [l for l in links if cid in ends(l) and l.get("cable") in WIRED and l["id"] not in claimed]
        direct = [l for l in cands if par in ends(l)]
        direct.sort(key=lambda l: l.get("cable") not in USBISH)
        if direct:
            l = direct[0]
            set_end(l, par, par, sock, keep_port=True)
        else:
            up = [l for l in cands if ends(l)[1] == cid and l.get("cable") in USBISH]
            if len(up) != 1:
                only = [l for l in cands if l.get("cable") in USBISH]
                up = only if len(only) == 1 else []
            if up:
                l = up[0]
                was = other(l, cid)
                set_end(l, was, par, sock)
                seen += " The inventory had it on %s." % name(was)
            else:
                ensure_port(par, sock)
                l = synth("o-" + cid, "%s:%s" % (par, sock) if sock else par, cid, "usb", ["usb"], "USB")
        if f.get("speed") and not l.get("speed"):
            l["observedSpeed"] = f["speed"]
        mark(l, h, f, seen)

    # 2. Video. First the displays seen through a dock or KVM, then the ones seen on a socket directly.
    def kvm_of(d):
        for l in links:
            if d in ends(l) and (devs.get(other(l, d)) or {}).get("kind") == "kvm":
                return other(l, d)
        return None

    vids = [(h, d, f) for h, hs in hosts.items() for d, f in (hs.get("video") or {}).items() if d in devs]
    vids.sort(key=lambda t: (t[2].get("via") is None, not t[2].get("present")))
    for h, d, f in vids:
        sock = f.get("port")
        via = f.get("via") if f.get("via") in devs else None
        cable = "hdmi" if f.get("portType") == "hdmi" else "video"
        tail = "" if f.get("present") else " when it was last connected"
        if via:
            l = between(via, d, VIDEOISH)
            x = kvm_of(d)
            if l is None and x and x != via:
                l = between(via, x, VIDEOISH)
            if l is None:
                l = synth("o-%s-%s" % (via, d), via, d, "video", ["video"], "Video")
            if l["id"] not in claimed or not l.get("observed"):
                mark(l, h, f, "%s shows on %s through %s%s." % (name(d), name(h), name(via), tail))
            continue
        where = port_label(devs[h], sock) if sock else "a socket it does not name"
        text = "%s shows on %s, straight into its %s%s." % (name(d), name(h), where, tail)
        l = between(h, d, VIDEOISH)
        if l is not None:
            set_end(l, h, h, sock, keep_port=True)
            mark(l, h, f, text)
            continue
        x = kvm_of(d)
        if x:
            ins = [l for l in links if x in ends(l) and other(l, x) != d and
                   ("video" in (l.get("carries") or []) or l.get("cable") in ("hdmi", "dp"))]
            mine = [l for l in ins if other(l, x) == h]
            if mine:
                l = mine[0]
                set_end(l, h, h, sock, keep_port=True)
            else:
                free = [l for l in ins if l["id"] not in claimed]
                cand = [l for l in free if linked(h, other(l, x))] or \
                       [l for l in free if ((devs.get(other(l, x)) or {}).get("probe") or {}).get("type", "none") == "none"]
                if cand:
                    l = cand[0]
                    was = other(l, x)
                    set_end(l, was, h, sock)
                    text += " It reaches the screen through %s. The inventory had this cable on %s." % (name(x), name(was))
                else:
                    ensure_port(h, sock)
                    l = synth("o-%s-%s" % (h, x), "%s:%s" % (h, sock) if sock else h, x, cable, ["video"], "Video")
                    text += " It reaches the screen through %s." % name(x)
            mark(l, h, f, text)
            continue
        loose = [l for l in links if d in ends(l) and l.get("cable") in VIDEOISH and l["id"] not in claimed]
        if len(loose) == 1:
            l = loose[0]
            was = other(l, d)
            set_end(l, was, h, sock)
            text += " The inventory had it on %s." % name(was)
        else:
            ensure_port(h, sock)
            l = synth("o-%s-%s" % (h, d), "%s:%s" % (h, sock) if sock else h, d, cable, ["video"], "Video")
        mark(l, h, f, text)

    inv["wiring"] = summary(state, devs)
    return inv


def summary(state, devs=None):
    """What live.json and the inventory carry about the readings."""
    out = {"rev": state.get("rev", 0), "hosts": {}}
    for h, hs in (state.get("hosts") or {}).items():
        if devs is not None and h not in devs:
            continue
        out["hosts"][h] = {"ts": hs.get("ts"), "source": hs.get("source"), "computer": hs.get("computer"),
                           "model": hs.get("model"), "ports": hs.get("ports") or [],
                           "ageSec": int(max(0, time.time() - (hs.get("epoch") or 0)))}
    return out


def diff_events(inv_before, inv_after, state):
    """Cables that changed place since the last look: [(link id, text, code)]. Updates state['applied'] and rev."""
    devs = {d["id"]: d for d in inv_after.get("devices") or []}
    declared = {l["id"]: (l.get("from"), l.get("to")) for l in inv_before.get("links") or []}

    def side(end):
        d, p = parse_end(end)
        dev = devs.get(d) or {}
        return dev.get("name", d) + ((" (%s)" % port_label(dev, p)) if p else "")
    applied = state.setdefault("applied", {})
    now, events = {}, []
    for l in inv_after.get("links") or []:
        if not (l.get("observed") or l.get("synthetic") and l["id"].startswith("o-")):
            continue
        now[l["id"]] = [l.get("from"), l.get("to")]
        prev = applied.get(l["id"]) or list(declared.get(l["id"]) or [])
        if not prev:
            events.append((l["id"], "New cable seen: %s to %s." % (side(l["from"]), side(l["to"])), "wiring-new"))
        elif prev != now[l["id"]]:
            events.append((l["id"], "Cable moved: %s to %s. Before: %s to %s." % (
                side(l["from"]), side(l["to"]), side(prev[0]), side(prev[1])), "wiring-moved"))
    for lid, prev in applied.items():
        if lid not in now and lid.startswith("o-"):
            events.append((lid, "Unplugged: %s from %s." % (side(prev[1]), side(prev[0])), "wiring-gone"))
        elif lid not in now and lid in declared and list(declared[lid]) != prev:
            events.append((lid, "Cable back where the inventory has it: %s to %s." % (side(declared[lid][0]), side(declared[lid][1])), "wiring-moved"))
    if now != applied:
        state["applied"] = now
        state["rev"] = int(state.get("rev", 0)) + 1
    return events
