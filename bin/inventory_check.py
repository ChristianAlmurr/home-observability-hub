#!/usr/bin/env python3
"""Check data/inventory.json against the shape the hub expects (docs/CONTRACT.md).

    python3 bin/inventory_check.py                       data/inventory.json (or $HM_INVENTORY)
    python3 bin/inventory_check.py path/to/inventory.json
    python3 bin/inventory_check.py --json                machine-readable
    python3 bin/inventory_check.py --strict              warnings count as errors

Exit 0 when there are no errors (warnings are printed), 1 when there are, 2 when the file cannot be read.
Standard library only, Python 3.9+. Reads only.
"""
import ipaddress
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
PORT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,47}$")
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
VERIFIED = ("live", "plan", "reported")
KINDS = {"computer", "laptop", "phone", "tablet", "display", "tv", "speaker", "headphones", "peripheral", "keyboard", "mouse",
         "adapter", "hub", "dock", "kvm", "switch", "router", "access-point", "modem", "internet", "nas", "bridge", "camera",
         "doorbell", "vacuum", "appliance", "console", "wearable", "printer", "scanner", "light", "plug", "sensor",
         "thermostat", "media-player", "streamer", "storage", "server", "ups", "iot", "unknown", "other"}
PROBES = {
    "none": [], "inferred": ["from"], "self": [], "ping": ["ip"], "tcp": ["tcp"], "http": ["url"], "cast": ["ip"],
    "usb": ["vendorId", "productId"], "display": ["match"], "interface": ["if"], "mdns": ["name"], "ha": ["entity"],
    "bluetooth": [],
}
CABLES = {"ethernet", "usb", "usb-c", "thunderbolt", "hdmi", "dp", "displayport", "video", "bluetooth", "coax", "mesh", "fiber",
          "dsl", "phone", "power", "audio", "optical", "powerline", "moca", "serial", "other"}
CARRIES = {"network", "video", "usb", "audio", "power", "input", "data", "storage", "charging"}
MEDIA = {"ethernet", "wifi", "bluetooth", "thread", "zigbee", "usb", "thunderbolt", "bridge", "other"}
IDENTITY_STATES = ("confirmed", "likely", "unidentified")


class Report:
    def __init__(self):
        self.errors, self.warnings = [], []

    def err(self, where, text):
        self.errors.append({"where": where, "text": text})

    def warn(self, where, text):
        self.warnings.append({"where": where, "text": text})


def _where(kind, i, x):
    xid = x.get("id") if isinstance(x, dict) else None
    return "%s[%d]%s" % (kind, i, (" %r" % xid) if xid else "")


def allowed_nets(site_path=None):
    """The LAN, loopback, Tailscale and extra nets from site.json (site_config resolves "auto")."""
    if site_path:
        os.environ["HM_SITE"] = site_path
    try:
        import site_config as S
        S.reset_cache()
        return S.allowed_nets(), S.get()
    except Exception as e:      # site_config broken: check without address limits
        return None, {"_error": str(e)}


def ip_in(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if nets is None:
        return True
    return any(a in n for n in nets)


def check(inv, nets=None, site=None):
    """Validate an inventory dict. Returns a Report."""
    r = Report()
    if not isinstance(inv, dict):
        r.err("top", "the file must hold one JSON object")
        return r
    if not isinstance(inv.get("schema"), int):
        r.warn("schema", "no integer `schema`; the current inventory schema is 2")
    devices = inv.get("devices")
    if not isinstance(devices, list):
        r.err("devices", "`devices` must be a list")
        devices = []
    links = inv.get("links") if inv.get("links") is not None else []
    if not isinstance(links, list):
        r.err("links", "`links` must be a list")
        links = []
    rooms = inv.get("rooms") or []
    zones = inv.get("zones") or []
    room_ids, zone_ids = set(), set()
    for i, rm in enumerate(rooms if isinstance(rooms, list) else []):
        w = _where("rooms", i, rm)
        if not isinstance(rm, dict) or not ID_RE.match(str(rm.get("id") or "")):
            r.err(w, "a room needs a slug-like `id` (lower-case letters, digits and dashes)")
            continue
        if rm["id"] in room_ids:
            r.err(w, "room id %r is used twice" % rm["id"])
        room_ids.add(rm["id"])
        if not rm.get("name"):
            r.warn(w, "room has no `name`")
    for i, z in enumerate(zones if isinstance(zones, list) else []):
        w = _where("zones", i, z)
        if not isinstance(z, dict) or not ID_RE.match(str(z.get("id") or "")):
            r.err(w, "a zone needs a slug-like `id`")
            continue
        if z["id"] in zone_ids:
            r.err(w, "zone id %r is used twice" % z["id"])
        zone_ids.add(z["id"])
        if z.get("room") and room_ids and z["room"] not in room_ids:
            r.err(w, "zone refers to room %r, which is not in `rooms`" % z["room"])
        elif z.get("room") and not room_ids:
            r.warn(w, "zone refers to room %r but the inventory has no `rooms`" % z["room"])

    dev_ids, ports_of = set(), {}
    link_ids = {l.get("id") for l in links if isinstance(l, dict)}
    for i, d in enumerate(devices):
        w = _where("devices", i, d)
        if not isinstance(d, dict):
            r.err(w, "each device must be an object")
            continue
        did = d.get("id")
        if not isinstance(did, str) or not ID_RE.match(did):
            r.err(w, "`id` %r is not slug-like: use lower-case letters, digits and dashes, starting with a letter or digit, "
                     "at most 64 characters" % (did,))
        elif did in dev_ids:
            r.err(w, "device id %r is used twice" % did)
        dev_ids.add(did)
        if not d.get("name"):
            r.err(w, "no `name`")
        if not d.get("kind"):
            r.err(w, "no `kind`")
        elif d["kind"] not in KINDS:
            r.warn(w, "kind %r is not one the maps draw specially; known kinds: %s" % (d["kind"], ", ".join(sorted(KINDS))))
        if d.get("verified") not in VERIFIED:
            r.err(w, "`verified` must be one of live, plan, reported (got %r)" % (d.get("verified"),))
        if d.get("zone") is not None and zone_ids and d["zone"] not in zone_ids:
            r.err(w, "zone %r is not in `zones`" % d["zone"])
        elif d.get("zone") is None:
            r.warn(w, "no `zone`: the maps will put it under unplaced")
        if d.get("room") is not None and room_ids and d["room"] not in room_ids:
            r.err(w, "room %r is not in `rooms`" % d["room"])
        pids = set()
        for j, p in enumerate(d.get("ports") or []):
            pw = "%s.ports[%d]" % (w, j)
            if not isinstance(p, dict) or not isinstance(p.get("id"), str) or not PORT_ID_RE.match(p["id"]):
                r.err(pw, "a port needs an `id` of lower-case letters, digits, dots, dashes or underscores")
                continue
            if p["id"] in pids:
                r.err(pw, "port id %r is used twice on this device" % p["id"])
            pids.add(p["id"])
            if not p.get("type"):
                r.warn(pw, "port %r has no `type` (rj45, usb-c, hdmi, …)" % p["id"])
        if isinstance(did, str):
            ports_of[did] = pids
        for j, n in enumerate(d.get("net") or []):
            nw = "%s.net[%d]" % (w, j)
            if not isinstance(n, dict):
                r.err(nw, "each net entry must be an object")
                continue
            if n.get("ip") is not None:
                ok = ip_in(n["ip"], nets)
                if ok is None:
                    r.err(nw, "%r is not an IP address" % n["ip"])
                elif not ok:
                    r.err(nw, "%s is outside the allowed nets (the home subnet, loopback, 100.64.0.0/10 and site.json "
                              "network.extraNets)" % n["ip"])
            if n.get("mac") is not None and not MAC_RE.match(str(n["mac"])):
                r.err(nw, "mac %r is not written AA:BB:CC:DD:EE:FF" % n["mac"])
            if n.get("verified") is not None and n["verified"] not in VERIFIED:
                r.err(nw, "`verified` must be one of live, plan, reported")
            if n.get("medium") is not None and n["medium"] not in MEDIA:
                r.warn(nw, "medium %r is unusual; expected one of %s" % (n["medium"], ", ".join(sorted(MEDIA))))
            if n.get("ap") is not None and n["ap"] not in [x.get("id") for x in devices if isinstance(x, dict)]:
                r.err(nw, "ap %r is not a device id" % n["ap"])
            if n.get("via") is not None and n["via"] not in [x.get("id") for x in devices if isinstance(x, dict)]:
                r.err(nw, "via %r is not a device id" % n["via"])
        p = d.get("probe")
        if p is not None:
            if not isinstance(p, dict):
                r.err(w, "`probe` must be an object")
            else:
                t = p.get("type") or "none"
                if t not in PROBES:
                    r.err(w, "probe type %r is not one the collectors know: %s" % (t, ", ".join(sorted(PROBES))))
                else:
                    for k in PROBES[t]:
                        if p.get(k) in (None, "", []):
                            r.err(w, "probe type %s needs `%s`" % (t, k))
                    if t == "tcp" and not (p.get("host") or p.get("fallbackIps")):
                        r.err(w, "probe type tcp needs `host` or `fallbackIps`")
                    if t == "bluetooth" and not (p.get("mac") or p.get("name")):
                        r.warn(w, "probe type bluetooth works best with `mac` (the Bluetooth address)")
                    if t == "inferred":
                        for lid in p.get("from") or []:
                            if lid not in link_ids:
                                r.err(w, "probe inferred from link %r, which does not exist" % lid)
                    if t == "usb":
                        for k in ("vendorId", "productId"):
                            if p.get(k) and not re.match(r"^0x[0-9a-f]{4}$", str(p[k])):
                                r.err(w, "probe %s %r must be written like 0x05e3 (lower-case hex)" % (k, p[k]))
                    ips = [p.get("ip")] + list(p.get("fallbackIps") or [])
                    m = re.match(r"^https?://(\d+\.\d+\.\d+\.\d+)", str(p.get("url") or ""))
                    if m:
                        ips.append(m.group(1))
                    for ip in ips:
                        if ip is None:
                            continue
                        ok = ip_in(ip, nets)
                        if ok is None:
                            r.err(w, "probe address %r is not an IP address" % ip)
                        elif not ok:
                            r.err(w, "probe address %s is outside the allowed nets" % ip)
        idn = d.get("identity")
        if idn is not None:
            if not isinstance(idn, dict):
                r.err(w, "`identity` must be an object")
            else:
                if idn.get("state") not in IDENTITY_STATES:
                    r.err(w, "identity.state must be confirmed, likely or unidentified")
                if idn.get("state") == "confirmed" and not idn.get("basis"):
                    r.err(w, "identity is confirmed but has no `basis`: say which probe or who confirmed it")
                if idn.get("state") != "confirmed" and idn.get("model") and not idn.get("basis"):
                    r.warn(w, "identity names a model without a `basis`")
                for c in idn.get("candidates") or []:
                    if isinstance(c, dict) and c.get("confidence") not in (None, "high", "medium", "low"):
                        r.err(w, "identity candidate confidence must be high, medium or low")

    def endpoint(lw, ref, side):
        if not isinstance(ref, str) or not ref:
            r.err(lw, "`%s` is missing" % side)
            return None
        did, _, pid = ref.partition(":")
        if did not in dev_ids:
            r.err(lw, "`%s` refers to device %r, which does not exist" % (side, did))
            return did
        if pid and pid not in ports_of.get(did, set()):
            r.err(lw, "`%s` refers to port %r on %r, which is not in that device's `ports`" % (side, pid, did))
        return did

    seen_links = set()
    for i, l in enumerate(links):
        lw = _where("links", i, l)
        if not isinstance(l, dict):
            r.err(lw, "each link must be an object")
            continue
        lid = l.get("id")
        if not isinstance(lid, str) or not ID_RE.match(lid):
            r.err(lw, "link `id` %r is not slug-like" % (lid,))
        elif lid in seen_links:
            r.err(lw, "link id %r is used twice" % lid)
        elif lid in dev_ids:
            r.warn(lw, "link id %r is also a device id" % lid)
        seen_links.add(lid)
        a = endpoint(lw, l.get("from"), "from")
        b = endpoint(lw, l.get("to"), "to")
        if a and a == b:
            r.err(lw, "a link must join two different devices")
        cab = l.get("cable")
        if cab == "wifi":
            r.err(lw, "hand-kept links never describe Wi-Fi: put the access point on the device's net entry (`ap`) instead")
        elif not cab:
            r.err(lw, "no `cable`")
        elif cab not in CABLES:
            r.warn(lw, "cable %r is not one the maps know: %s" % (cab, ", ".join(sorted(CABLES))))
        car = l.get("carries")
        if car is None:
            r.warn(lw, "no `carries` (network, video, usb, audio, power, input)")
        elif not isinstance(car, list):
            r.err(lw, "`carries` must be a list")
        else:
            for c in car:
                if c not in CARRIES:
                    r.warn(lw, "carries %r is unusual; known: %s" % (c, ", ".join(sorted(CARRIES))))
        if l.get("verified") not in VERIFIED:
            r.err(lw, "`verified` must be one of live, plan, reported (got %r)" % (l.get("verified"),))
        if l.get("verified") == "live" and not l.get("evidence"):
            r.warn(lw, "a live link should say how it was seen in `evidence`")

    qids = set()
    for i, q in enumerate(inv.get("openQuestions") or []):
        qw = _where("openQuestions", i, q)
        if not isinstance(q, dict):
            r.err(qw, "each open question must be an object")
            continue
        if not q.get("id") or not ID_RE.match(str(q["id"])):
            r.err(qw, "an open question needs a slug-like `id`")
        elif q["id"] in qids:
            r.err(qw, "question id %r is used twice" % q["id"])
        qids.add(q.get("id"))
        if not q.get("text"):
            r.err(qw, "an open question needs `text`")
        for did in q.get("devices") or []:
            if did not in dev_ids:
                r.err(qw, "refers to device %r, which does not exist" % did)

    if site and not site.get("_error"):
        rt = site.get("router") or {}
        if rt.get("deviceId") and rt["deviceId"] not in dev_ids:
            r.err("site.json router.deviceId", "%r is not a device in the inventory" % rt["deviceId"])
        h = (site.get("host") or {}).get("deviceId")
        if h and h != "auto" and h not in dev_ids:
            r.err("site.json host.deviceId", "%r is not a device in the inventory" % h)
        for pid in site.get("protected") or []:
            if pid not in dev_ids:
                r.warn("site.json protected", "%r is not a device in the inventory" % pid)
        for x in site.get("handsOff") or []:
            hid = x.get("id") if isinstance(x, dict) else x
            if hid and hid not in dev_ids:
                r.warn("site.json handsOff", "%r is not a device in the inventory" % hid)
        selfs = [d.get("id") for d in devices if isinstance(d, dict) and (d.get("probe") or {}).get("type") == "self"]
        if len(selfs) > 1:
            r.err("devices", "more than one device has probe type self: %s" % ", ".join(map(str, selfs)))
    return r


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Validate data/inventory.json.")
    ap.add_argument("path", nargs="?", help="inventory file (default data/inventory.json or $HM_INVENTORY)")
    ap.add_argument("--site", help="site.json to read the allowed nets from (default data/site.json or $HM_SITE)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    ap.add_argument("--quiet", action="store_true", help="print errors only")
    a = ap.parse_args(argv)
    path = a.path or os.environ.get("HM_INVENTORY") or os.path.join(ROOT, "data", "inventory.json")
    try:
        with open(path) as f:
            inv = json.load(f)
    except OSError as e:
        msg = "cannot read %s: %s" % (path, e.strerror or e)
        print(json.dumps({"ok": False, "path": path, "errors": [{"where": "file", "text": msg}], "warnings": []})
              if a.json else "FAIL " + msg)
        return 2
    except ValueError as e:
        msg = "%s is not valid JSON: %s" % (path, e)
        print(json.dumps({"ok": False, "path": path, "errors": [{"where": "file", "text": msg}], "warnings": []})
              if a.json else "FAIL " + msg)
        return 1
    nets, site = allowed_nets(a.site)
    r = check(inv, nets, site)
    errors = r.errors + (r.warnings if a.strict else [])
    ok = not errors
    if a.json:
        print(json.dumps({"ok": ok, "path": path, "devices": len(inv.get("devices") or []) if isinstance(inv, dict) else 0,
                          "links": len(inv.get("links") or []) if isinstance(inv, dict) else 0,
                          "allowedNets": [str(n) for n in nets] if nets else None,
                          "errors": r.errors, "warnings": r.warnings}, indent=1))
    else:
        for e in r.errors:
            print("ERROR %s: %s" % (e["where"], e["text"]))
        if not a.quiet:
            for w in r.warnings:
                print("warn  %s: %s" % (w["where"], w["text"]))
        print("%s %s: %d devices, %d links, %d errors, %d warnings" % (
            "OK  " if ok else "FAIL", path, len(inv.get("devices") or []) if isinstance(inv, dict) else 0,
            len(inv.get("links") or []) if isinstance(inv, dict) else 0, len(r.errors), len(r.warnings)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
