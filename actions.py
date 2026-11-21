"""What the person can do to a device from the map: identify, scan, investigate, block, unblock, forget.

These are the person's own clicks, not agent proposals. Each needs `confirm: true`, each is written
to audit.jsonl with actor `person`, and the refusals below are in code, whatever the UI sends.
"""
import datetime
import json
import os
import re
import shutil
import threading
import time

import collectors as C
import identify as I
import oui
import router as R
import site_config as SITE

# Which devices are protected (never blocked or removed) and which are hands-off (looked at, never touched)
# comes from data/site.json and the inventory's kinds: see site_config.protected_ids and hands_off.
ACTIONS = ("identify", "scan", "investigate", "block", "unblock", "forget")
KIND_RE = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
_inv_lock = threading.Lock()


class ActionError(Exception):
    def __init__(self, status, text):
        Exception.__init__(self, text)
        self.status, self.text = status, text


def backups_dir():
    return os.path.join(C.state_dir(), "backups")


def _text(v, n=80):
    if v is None:
        return None
    if not isinstance(v, str):
        raise ActionError(400, "name, vendor, model, kind and zone must be text")
    return re.sub(r"[\x00-\x1f\x7f]", " ", v).strip()[:n]


def is_protected(dev, inv=None):
    """data/site.json's protected list, the router, network gear (by kind), and the computer this server runs on."""
    if dev.get("kind") in ("router", "access-point", "modem", "switch", "internet"):
        return True
    if (dev.get("probe") or {}).get("type") == "self":
        return True
    if inv is None:
        try:
            inv = C.load_inventory()
        except Exception:
            inv = {}
    return dev["id"] in SITE.protected_ids(inv)


def hands_off(dev):
    """The handsOff entry in data/site.json for this device, else None."""
    return SITE.hands_off_match(target=dev["id"])


def refusal(dev, action, inv=None):
    """Plain words when the action is refused for this device in code, else None."""
    h = hands_off(dev)
    if h and action != "scan":
        return "This device is hands-off (%s). The hub only looks at it; it never changes, blocks or removes it." % h["why"]
    if action in ("block", "forget") and is_protected(dev, inv):
        return "%s is part of what keeps the house online or runs this monitor, so it cannot be %s from here." % (
            dev.get("name") or dev["id"], "blocked" if action == "block" else "removed")
    return None


class Context:
    """What an action needs from the running server. Tests build one with fakes."""

    def __init__(self, monitor, runs=None, audit=None, settings=None):
        self.monitor, self.runs, self.audit, self.settings = monitor, runs, audit or (lambda **k: None), settings or (lambda: {})

    def device(self, did):
        inv = I.served_inventory()
        return next((d for d in inv.get("devices") or [] if d["id"] == did), None), inv

    def addresses(self, did):
        return (I.load_picture().get("addresses") or {}).get(did) or {"ips": [], "macs": [], "names": []}

    def router_snapshot(self):
        return self.monitor.router.snapshot or {}

    def blocked_macs(self):
        return {b["mac"] for b in self.router_snapshot().get("blockList") or [] if b.get("mode") == "block"}

    def self_macs(self):
        """This Mac's own interface addresses: never blocked, whichever device they show up under."""
        macs = set()
        rc, out, _ = C.run(["/sbin/ifconfig"], timeout=5)
        for m in re.finditer(r"ether ([0-9a-f:]{17})", out or ""):
            macs.add(m.group(1).upper())
        return macs


def target_mac(ctx, did):
    """The address a block would act on: the one the router sees connected, else the first known."""
    a = ctx.addresses(did)
    online = {c["mac"] for c in ctx.router_snapshot().get("clients") or [] if c.get("online")}
    macs = [m for m in a.get("macs") or [] if oui.normalize(m)]
    return next((m for m in macs if m in online), macs[0] if macs else None)


def describe(ctx, dev, inv):
    """The list for GET /api/device/<id>/actions."""
    did, name = dev["id"], dev.get("name") or dev["id"]
    a = ctx.addresses(did)
    ips = [ip for ip in a.get("ips") or [] if C.ip_allowed(ip)]
    mac = target_mac(ctx, did)
    rstat = ctx.monitor.router.status()
    blocked = bool(set(a.get("macs") or []) & ctx.blocked_macs())
    dynamic = bool(dev.get("dynamic"))
    nlinks = len([l for l in inv.get("links") or [] if not l.get("synthetic") and did in (C.parse_end(l.get("from"))[0], C.parse_end(l.get("to"))[0])])
    out = []

    def add(aid, label, risk, reversible, title, effect, undo, why=None):
        why = refusal(dev, aid, inv) or why
        out.append({"id": aid, "label": label, "risk": risk, "reversible": reversible, "available": why is None,
                    "unavailableReason": why, "confirm": {"title": title, "effect": effect, "undo": undo}})

    add("identify", "Say what this is", "change", True, "Record what %s is" % name,
        ("Adds it to the inventory as a device you named, marked as reported by you." if dynamic else
         "Writes the name, maker, model, kind and place you give into the inventory, marked as reported by you.") +
        " A copy of the inventory is saved first.",
        "Restore the copy from data/state/backups/, or use Remove on the device.")
    add("scan", "Scan it now", "read", True, "Scan %s" % name,
        "Tries about %d common ports on %s, reads web page titles, certificates and greetings, and asks again on Bonjour and UPnP. "
        "It only connects and reads; nothing is changed on the device." % (len(I.PORTS), ", ".join(ips) or "its address"),
        "Nothing to undo.",
        None if ips else "It has no address on the house network to scan.")
    add("investigate", "Ask the agent to investigate", "read", True, "Investigate %s" % name,
        "Starts an agent run that reads the evidence, probes the device read-only and reports what it most likely is and how to confirm it.",
        "Cancel the run from the agent panel.",
        "The agent is paused in settings." if (ctx.settings() or {}).get("agentMode") == "paused" else None)
    rand = oui.is_randomized(mac) if mac else False
    rehearse = "" if writes_allowed(ctx) else \
        " Changes at the router are switched off %s, so for now this only shows the commands it would send." % (
            "in settings" if SITE.router_writes() else "in data/site.json (router.writes)")
    why = None
    if not R.enabled():
        why = "Router reading is not set up."
    elif not rstat.get("configured"):
        why = "Router access is not set up."
    elif not mac:
        why = "Its hardware address is not known, and the router blocks by that address."
    elif blocked:
        why = "It is already blocked."
    add("block", "Block at the router", "change", True, "Block %s at the router" % name,
        "Adds %s to the router's block list (the list behind “Block Internet Access”) and reloads the router's firewall. "
        "The device stays on the Wi-Fi but loses the internet. Other entries on the list are not touched.%s" % (
            mac or "its address", " It uses a private (randomised) address: if it rejoins under a new one, the block no longer applies." if rand else "") + rehearse,
        "Unblock it here, or remove it under Parental Controls in the router's own page.", why)
    add("unblock", "Unblock", "change", True, "Unblock %s" % name,
        "Removes %s from the router's block list and reloads the router's firewall. Other entries are not touched." % (mac or "its address") + rehearse,
        "Block it again.",
        None if blocked and rstat.get("configured") else ("Router reading is not set up." if not R.enabled() else
                                                          "Router access is not set up." if not rstat.get("configured") else "It is not blocked."))
    add("forget", "Remove", "destructive", True, "Remove %s" % name,
        ("Drops it from the list of devices seen on the network and forgets what was learned about it. If it shows up again it comes back as new."
         if dynamic else
         "Removes it%s from the inventory. A copy of the inventory is saved first. Its knowledge files stay." % (
             (" and its %d link%s" % (nlinks, "" if nlinks == 1 else "s")) if nlinks else "")),
        "It reappears by itself when it is next seen." if dynamic else "Restore the copy from data/state/backups/.")
    return out


def writes_allowed(ctx):
    """A block or unblock is sent only when both switches are on: routerWrites in settings and router.writes in data/site.json."""
    return (ctx.settings() or {}).get("routerWrites") is True and SITE.router_writes()


# ---------------------------------------------------------------- inventory writes

def _write_inventory(mutate):
    """Backup, change, atomic write. `mutate(inv)` returns the result to hand back.
    With no inventory yet, the first write creates it (there is nothing to back up)."""
    with _inv_lock:
        path = C.inventory_path()
        backup = None
        if os.path.exists(path):
            try:
                with open(path) as f:
                    inv = json.load(f)
            except ValueError:
                raise ActionError(409, "data/inventory.json is not valid JSON, so nothing was written to it. Fix the file first.")
            if not isinstance(inv, dict):
                raise ActionError(409, "data/inventory.json is not a JSON object, so nothing was written to it.")
            os.makedirs(backups_dir(), exist_ok=True)
            backup = os.path.join(backups_dir(), "inventory-%s-%03d.json" % (time.strftime("%Y%m%d-%H%M%S"), int(time.time() * 1000) % 1000))
            shutil.copy2(path, backup)
        else:
            inv = C.empty_inventory()
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        res = mutate(inv)
        tmp = "%s.%d.tmp" % (path, os.getpid())
        with open(tmp, "w") as f:
            json.dump(inv, f, indent=2, ensure_ascii=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return res, backup


def _slug(name, taken, fallback):
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")[:40] or fallback
    if s.startswith("host-") or s in SITE.protected_ids() or s in SITE.hands_off_ids():
        s = fallback
    base, n = s, 2
    while s in taken:
        s = "%s-%d" % (base, n)
        n += 1
    return s


def do_identify(ctx, dev, inv, params):
    vals = {k: _text(params.get(k)) for k in ("name", "vendor", "model", "kind", "zone")}
    if not any(vals.values()):
        raise ActionError(400, "Say at least one of: name, vendor, model, kind, zone.")
    if vals["kind"] and not KIND_RE.match(vals["kind"]):
        raise ActionError(400, "kind must be one short word, like phone, camera or plug.")
    zones = {z["id"] for z in inv.get("zones") or []}
    if vals["zone"] and vals["zone"] not in zones:
        raise ActionError(400, "There is no place called %s in the inventory." % vals["zone"])
    stamp = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    a = ctx.addresses(dev["id"])

    def mutate(raw):
        devices = raw.setdefault("devices", [])
        cur = next((d for d in devices if d["id"] == dev["id"]), None)
        if cur is None:
            if not dev.get("dynamic"):
                raise ActionError(404, "no such device")
            n0 = (dev.get("net") or [{}])[0]
            ip, mac = n0.get("ip"), n0.get("mac")
            new_id = _slug(vals["name"], {d["id"] for d in devices}, "device-" + (ip.split(".")[-1] if ip else (mac or "x").replace(":", "").lower()[-6:]))
            net = {k: v for k, v in (("ip", ip), ("mac", mac), ("medium", n0.get("medium")), ("name", n0.get("name"))) if v}
            net["verified"] = "live"
            cur = {"id": new_id, "name": vals["name"] or dev.get("name") or new_id, "kind": vals["kind"] or "unknown",
                   "vendor": vals["vendor"] or "", "model": vals["model"] or "", "zone": vals["zone"] or "unplaced",
                   "verified": "reported", "net": [net],
                   # With the router's client list its presence is read there; without it, ping is all there is.
                   "probe": {"type": "none"} if (mac and ctx.monitor.router.configured()) or not ip else {"type": "ping", "ip": ip}}
            if "unplaced" not in {z["id"] for z in raw.get("zones") or []} and cur["zone"] == "unplaced":
                raw.setdefault("zones", []).append({"id": "unplaced", "name": "Not placed yet"})
            devices.append(cur)
        else:
            for k, v in vals.items():
                if v:
                    cur[k] = v
            cur["verified"] = "reported"
        cur["identifiedBy"], cur["identifiedAt"] = "person", stamp
        return cur["id"]
    new_id, backup = _write_inventory(mutate)
    said = ", ".join("%s %s" % (k, v) for k, v in vals.items() if v)
    ctx.monitor.event("security", new_id, None, None, "identified", "%s was identified by hand: %s." % (dev.get("name") or dev["id"], said), code="identified")
    return {"deviceId": new_id, "was": dev["id"], "backup": os.path.basename(backup) if backup else None, "addresses": a}, said


def do_forget(ctx, dev, inv, params):
    did = dev["id"]
    if dev.get("dynamic"):
        n0 = (dev.get("net") or [{}])[0]
        ip, mac = n0.get("ip"), n0.get("mac")
        mon = ctx.monitor
        with mon.cycle_lock:
            for key, s in list(mon.strangers.items()):
                if (ip and s.get("ip") == ip) or (mac and s.get("mac") == mac):
                    del mon.strangers[key]
            mon.ident.forget(ip, mac)
            if mon.prev:
                mon.prev["devices"].pop(did, None)
        res = {"removed": did, "note": "It will come back as a new device if it is seen on the network again."}
    else:
        def mutate(raw):
            before = len(raw.get("devices") or [])
            raw["devices"] = [d for d in raw.get("devices") or [] if d["id"] != did]
            if len(raw["devices"]) == before:
                raise ActionError(404, "no such device")
            gone = [l["id"] for l in raw.get("links") or [] if did in (C.parse_end(l.get("from"))[0], C.parse_end(l.get("to"))[0])]
            raw["links"] = [l for l in raw.get("links") or [] if l["id"] not in gone]
            return gone
        gone, backup = _write_inventory(mutate)
        res = {"removed": did, "removedLinks": gone, "backup": os.path.basename(backup) if backup else None}
    ctx.monitor.event("security", did, None, None, "removed", "%s was removed%s." % (
        dev.get("name") or did, " from the inventory" if not dev.get("dynamic") else " from the list of devices seen"), code="removed")
    return res, "removed %s" % did


def do_scan(ctx, dev, inv, params):
    a = ctx.addresses(dev["id"])
    ips = [ip for ip in a.get("ips") or [] if C.ip_allowed(ip) and C.ipaddress.ip_address(ip) in C.subnet()]
    if not ips:
        raise ActionError(409, "It has no address on the house network to scan.")
    before = {(e["source"], e["label"], e["value"]) for e in (dev.get("identity") or {}).get("evidence") or []}
    scans = {}
    for ip in ips[:3]:
        scans[ip] = ctx.monitor.ident.scan_now(ip)
    ctx.monitor.refresh_picture()
    pic = I.load_picture()
    ident = (pic.get("identities") or {}).get(dev["id"]) or {}
    new = [e for e in ident.get("evidence") or [] if (e["source"], e["label"], e["value"]) not in before]
    ports = sorted({p["port"]: p for s in scans.values() for p in s.get("ports") or []}.values(), key=lambda p: p["port"])
    return ({"scanned": list(scans), "openPorts": ports, "newEvidence": new, "evidence": ident.get("evidence") or [],
             "identity": {k: ident.get(k) for k in ("state", "vendor", "model", "type", "basis", "candidates")}},
            "scanned %s: %d open port(s), %d new finding(s)" % (", ".join(scans), len(ports), len(new)))


def investigate_question(dev, addresses):
    ident = dev.get("identity") or {}
    lines = ["Work out what this device is and whether it belongs in this house: %s (id %s)." % (dev.get("name") or dev["id"], dev["id"])]
    if addresses.get("ips"):
        lines.append("Address: %s." % ", ".join(addresses["ips"]))
    if addresses.get("macs"):
        lines.append("Hardware address: %s." % ", ".join(addresses["macs"]))
    lines.append("The identification engine currently says: %s%s." % (
        ident.get("state") or "unidentified", (" (%s %s)" % (ident.get("vendor") or "", ident.get("model") or "")).rstrip() if ident.get("vendor") or ident.get("model") else ""))
    for c in (ident.get("candidates") or [])[:4]:
        lines.append("Lead (%s): %s" % (c.get("confidence"), c.get("basis")))
    lines.append("Start with `python3 bin/probe.py identity %s`, then use ports, ssdp, mdns and bluetooth as needed. "
                 "Say what it most likely is and how sure you are, never naming a product the evidence does not show; "
                 "say whether anything about it is a security worry; and give %s the quickest way to confirm it by hand "
                 "(for example what to unplug or which app to open). Do not propose blocking it unless the evidence points to a device that does not belong." % (
                     dev["id"], SITE.owner_or("the person")))
    return "\n".join(lines)


def do_investigate(ctx, dev, inv, params):
    if ctx.runs is None:
        raise ActionError(409, "The agent is not available.")
    run_id, thread_id = ctx.runs.ask(investigate_question(dev, ctx.addresses(dev["id"])), [dev["id"]])
    return {"runId": run_id, "threadId": thread_id}, "agent run %s" % run_id


def do_router(ctx, dev, inv, params, action):
    mon = ctx.monitor
    if not R.enabled():
        raise ActionError(409, "Router reading is not set up (router.type in data/site.json).")
    if not mon.router.configured():
        raise ActionError(409, "Router access is not set up.")
    a = ctx.addresses(dev["id"])
    if action == "unblock":
        macs = [m for m in a.get("macs") or [] if m in ctx.blocked_macs()]
        if not macs:
            raise ActionError(409, "It is not on the router's block list.")
        mac = macs[0]
    else:
        mac = target_mac(ctx, dev["id"])
        if not mac:
            raise ActionError(409, "Its hardware address is not known, and the router blocks by that address.")
    protected = set(ctx.self_macs())
    pic_addr = I.load_picture().get("addresses") or {}
    for d in inv.get("devices") or []:
        if is_protected(d, inv) or hands_off(d):
            protected.update((pic_addr.get(d["id"]) or {}).get("macs") or [])
    settings_on = (ctx.settings() or {}).get("routerWrites") is True
    writes_on = settings_on and SITE.router_writes()
    dry = bool(params.get("dryRun")) or not writes_on
    try:
        res = mon.router.change(action, mac, name=dev.get("name"), dry_run=dry, protected=protected if action == "block" else (),
                                backup_dir=backups_dir())
    except R.RouterError as e:
        raise ActionError(409, str(e))
    for k in ("before", "after"):
        res.pop(k, None)
    if res["dryRun"] and not params.get("dryRun"):
        res["rehearsal"] = ("Nothing was sent. Changes at the router are switched off"
                            + (" in settings (routerWrites)." if not settings_on else
                               " in data/site.json (router.writes)." if not SITE.router_writes() else " on this server (HM_ROUTER_DRY_RUN)."))
    if res.get("backup"):
        res["backup"] = os.path.basename(res["backup"])
    if not res["dryRun"] and res.get("changed"):
        mon.event("security", dev["id"], None, None, "blocked" if action == "block" else "unblocked",
                  "%s was %s at the router (%s)." % (dev.get("name") or dev["id"], "blocked" if action == "block" else "unblocked", mac),
                  code="blocked" if action == "block" else "unblocked")
        try:
            mon.router.poll(force=True)
            mon.refresh_picture()
        except Exception:
            pass
    summary = "%s%s %s: %s" % ("dry run, " if res["dryRun"] else "", action, mac,
                              "; ".join(res.get("commands") or []) or (res.get("note") or "nothing to change"))
    return res, summary


def perform(ctx, did, body):
    """POST /api/device/<id>/action. Returns {ok, result}. Raises ActionError(status, plain words)."""
    action, params = body.get("action"), body.get("params")
    if action not in ACTIONS:
        raise ActionError(400, "action must be one of: %s" % ", ".join(ACTIONS))
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ActionError(400, "params must be an object")
    if body.get("confirm") is not True:
        raise ActionError(400, "This needs confirm: true. Show the person what will happen first.")
    dev, inv = ctx.device(did)
    if dev is None:
        raise ActionError(404, "no such device")
    why = refusal(dev, action, inv)
    if why:
        ctx.audit(actor="person", type="device-action", command="%s %s" % (action, did), decision="refused", summary=why)
        raise ActionError(403, why)
    fn = {"identify": do_identify, "forget": do_forget, "scan": do_scan, "investigate": do_investigate}.get(action)
    try:
        if fn:
            result, summary = fn(ctx, dev, inv, params)
        else:
            result, summary = do_router(ctx, dev, inv, params, action)
    except ActionError as e:
        ctx.audit(actor="person", type="device-action", command="%s %s" % (action, did), decision="confirmed", exitCode=1, summary=e.text[:300])
        raise
    ok = result.get("ok", True) is not False
    ctx.audit(actor="person", type="device-action", command="%s %s" % (action, did), decision="confirmed",
              exitCode=0 if ok else 1, summary=summary[:500], runId=result.get("runId"))
    if action in ("identify", "forget"):
        try:
            ctx.monitor.refresh_picture()
        except Exception:
            pass
        ctx.monitor.wake.set()
    out = {"ok": ok, "result": result}
    if not ok:
        out["error"] = result.get("error") or "The action did not complete."
    return out
