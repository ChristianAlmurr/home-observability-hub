#!/usr/bin/env python3
"""Home Observability Hub probe: the fix agent's only way to look at the live system.

Read-only by construction: fixed argv lists (no shell), validated arguments,
addresses limited to the house subnet in data/site.json (plus its extraNets),
127.0.0.1 and 100.64.0.0/10, a timeout on everything, nothing sent to a
hands-off device, and the Home Assistant token is never printed.

    python3 bin/probe.py --list
    python3 bin/probe.py <subcommand> [args]
"""
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import collectors as C  # noqa: E402
import identify as I  # noqa: E402
import site_config as SITE  # noqa: E402

HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*\.?$")
IF_RE = re.compile(r"^(en|bridge|utun|lo|awdl|llw|anpi|ap|gif|stf)\d{0,3}$")
SVC_RE = re.compile(r"^_[a-z0-9][a-z0-9-]{0,30}\._(tcp|udp)$")
ENTITY_RE = re.compile(r"^[a-z_]{1,40}\.[a-z0-9_]{1,120}$")
DOMAIN_RE = re.compile(r"^[a-z_]{1,40}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class Bad(Exception):
    pass


# ---------------------------------------------------------------- validation

def v_ip(s):
    try:
        ipaddress.ip_address(s)
    except ValueError:
        raise Bad("not an IP address: %r" % s)
    if not C.ip_allowed(s):
        raise Bad("%s is outside the allowed ranges (%s)" % (s, ", ".join(str(n) for n in C.allowed_nets())))
    hands_off_refusal(ip=s)
    return s


def hands_off_refusal(ip=None, name=None):
    """Probes never reach a device data/site.json lists as hands-off (by address, host name or recorded address)."""
    ids, ips, names = SITE.hands_off_all(C.load_inventory())
    addr = I.load_picture().get("addresses") or {}
    for did in ids:
        ips.update((addr.get(did) or {}).get("ips") or [])
    low = {n.lower() for n in names}
    if ip and ip in ips:
        raise Bad("%s belongs to a hands-off device: probes never reach it" % ip)
    if name and name.lower().rstrip(".").replace(".local", "") in low:
        raise Bad("%s is a hands-off device: probes never reach it" % name)


def v_host(s):
    """An allowed IP, or a hostname that resolves only to allowed IPs. Returns (host, ip)."""
    try:
        ipaddress.ip_address(s)
        return s, v_ip(s)
    except ValueError:
        pass
    if not HOST_RE.match(s or ""):
        raise Bad("not a valid host name: %r" % s)
    hands_off_refusal(name=s)
    ips = C.resolve(s)
    if not ips:
        raise Bad("%s does not resolve" % s)
    bad = [ip for ip in ips if not C.ip_allowed(ip)]
    if bad:
        raise Bad("%s resolves to %s, outside the allowed ranges" % (s, ", ".join(bad)))
    return s, ips[0]


def v_port(s):
    if not re.match(r"^\d{1,5}$", s or "") or not 1 <= int(s) <= 65535:
        raise Bad("not a port: %r" % s)
    return int(s)


def v_re(rx, what):
    def f(s):
        if not rx.match(s or ""):
            raise Bad("not a valid %s: %r" % (what, s))
        return s
    return f


def v_url(s):
    u = urllib.parse.urlsplit(s or "")
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise Bad("only plain http(s) URLs to local hosts: %r" % s)
    if re.search(r"[\s<>\"'`;|&$\\]", s):
        raise Bad("URL contains characters that are not allowed")
    v_host(u.hostname)
    return s


def v_device(s):
    if not ID_RE.match(s or ""):
        raise Bad("not a device id: %r" % s)
    inv = I.served_inventory()          # the inventory plus the hosts seen on the network that are not in it
    for d in inv.get("devices") or []:
        if d["id"] == s:
            return d
    raise Bad("no device with id %r in the inventory" % s)


def v_subnet_ip(s):
    v_ip(s)         # refuses hands-off devices too
    if ipaddress.ip_address(s) not in C.subnet():
        raise Bad("%s is not on the house network %s" % (s, C.subnet()))
    return s


# ---------------------------------------------------------------- subcommands

def cmd_live():
    try:
        with open(os.path.join(C.state_dir(), "live.json")) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"ts": None, "devices": {}, "links": {}, "strangers": [], "note": "the collectors have not written live.json yet"}


def cmd_device(dev):
    live = {}
    try:
        live = (cmd_live().get("devices") or {}).get(dev["id"]) or {}
    except Exception:
        pass
    inv = C.load_inventory()
    links = [l for l in inv.get("links") or []
             if C.parse_end(l.get("from"))[0] == dev["id"] or C.parse_end(l.get("to"))[0] == dev["id"]]
    return {"device": dev, "live": live, "links": links}


def cmd_ping(host):
    h, ip = host
    ok, ms = C.ping(ip, attempts=3)
    return {"host": h, "ip": ip, "reply": ok, "latencyMs": ms}


def cmd_tcp(host, port):
    h, ip = host
    ok, ms, det = C.tcp_check(ip, port, timeout=2.0)
    return {"host": h, "ip": ip, "port": port, "open": ok, "latencyMs": ms, "detail": det}


def cmd_dns(name):
    if not HOST_RE.match(name):
        raise Bad("not a valid host name: %r" % name)
    router = [x for x in C.dig([name, "@" + C.router_ip()])]
    system = C._getaddrinfo(name)
    return {"name": name, "router": router, "system": system}


def cmd_rdns(ip):
    return {"ip": ip, "name": C.rdns(ip)}


def cmd_route(host):
    h, ip = host
    return dict({"host": h, "ip": ip}, **C.route_to(ip))


def cmd_interfaces():
    rc, out, _ = C.run(["/sbin/ifconfig", "-l"], timeout=5)
    res = {}
    for n in out.split():
        if re.match(r"^(en|bridge)\d+$", n):
            i = C.interface(n)
            res[n] = {k: i.get(k) for k in ("status", "speed", "speedRaw", "duplex", "media", "ipv4", "mtu")}
    return {"interfaces": res, "defaultRouteInterface": C.default_route_if()}


def cmd_interface(ifn):
    return C.interface(ifn)


def cmd_service_order():
    return {"serviceOrder": C.service_order(), "defaultRouteInterface": C.default_route_if()}


def cmd_wifi():
    wif = C.wifi_interface()
    res = {"interface": wif, "power": C.wifi_power(wif), "ifconfig": C.interface(wif)}
    try:
        d = C._sp("SPAirPortDataType", timeout=30)
        for x in d.get("SPAirPortDataType") or []:
            for i in x.get("spairport_airport_interfaces") or []:
                if i.get("_name") == wif:
                    cur = i.get("spairport_current_network_information") or {}
                    res["current"] = {k.replace("spairport_", ""): v for k, v in cur.items()
                                      if k in ("_name", "spairport_network_phymode", "spairport_network_channel",
                                               "spairport_signal_noise", "spairport_network_rate",
                                               "spairport_security_mode")}
                    res["status"] = i.get("spairport_status_information")
    except Exception as e:
        res["airportError"] = str(e)[:200]
    return res


def cmd_usb():
    return {"usb": C.usb_devices(fresh=True)}


def cmd_displays():
    return {"displays": C.displays(fresh=True)}


def cmd_thunderbolt():
    return C._sp("SPThunderboltDataType", timeout=30)


def cmd_mdns(svc):
    names = C.mdns_browse(svc, seconds=4)
    return {"serviceType": svc, "instances": names}


def cmd_cast(ip):
    info = C.cast_info(ip)
    return {"ip": ip, "answered": info is not None, "info": info}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def cmd_http_head(url):
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, method="HEAD")
    try:
        with opener.open(req, timeout=4) as r:
            return {"url": url, "status": r.status, "headers": dict(r.headers.items())}
    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "headers": dict(e.headers.items()) if e.headers else {}}
    except Exception as e:
        return {"url": url, "status": None, "error": str(e)[:200]}


def cmd_ha_state(entity):
    try:
        st = C.ha_state(entity)
    except C.HAUnavailable as e:
        return {"entity": entity, "error": str(e)}
    return {"entity": entity, "found": st is not None, "state": st}


def cmd_ha_states(domain=None):
    try:
        sts = C.ha_states(domain)
    except C.HAUnavailable as e:
        return {"error": str(e)}
    return {"count": len(sts), "states": [{"entity_id": s.get("entity_id"), "state": s.get("state"),
                                           "name": (s.get("attributes") or {}).get("friendly_name"),
                                           "last_changed": s.get("last_changed")} for s in sts]}


def cmd_sweep():
    found = C.sweep()
    inv = C.load_inventory()
    known = {}
    for d in inv.get("devices") or []:
        for n in d.get("net") or []:
            if n.get("ip"):
                known[n["ip"]] = d["id"]
    hosts = sorted(found, key=lambda ip: tuple(int(x) for x in ip.split(".")))
    return {"answered": [{"ip": ip, "latencyMs": found[ip], "device": known.get(ip), "name": C.rdns(ip)} for ip in hosts]}


def cmd_bluetooth():
    return {"bluetooth": C.bluetooth_devices(fresh=True),
            "note": "Devices this Mac knows over Bluetooth. connected=false means paired but not connected now."}


def cmd_ssdp():
    return {"ssdp": I.ssdp_discover(seconds=3.0)}


def cmd_ports(ip):
    d = I.deep_scan(ip)
    d.pop("t", None)
    return dict({"ip": ip, "scannedPorts": len(I.PORTS)}, **d)


def cmd_identity(dev):
    pic = I.load_picture()
    live = {}
    try:
        live = (cmd_live().get("devices") or {}).get(dev["id"]) or {}
    except Exception:
        pass
    return {"device": {k: dev.get(k) for k in ("id", "name", "kind", "vendor", "model", "zone", "verified", "dynamic", "net")},
            "identity": dev.get("identity"), "addresses": (pic.get("addresses") or {}).get(dev["id"]),
            "security": live.get("security"), "status": live.get("status"),
            "note": "state is confirmed only when a probe names the product or the person said so; candidates are leads, not facts."}


def cmd_nas():
    inv = C.load_inventory()
    nas = next((d for d in inv.get("devices") or [] if d.get("kind") == "nas"), None)
    if nas is None:
        raise Bad("there is no device of kind nas in the inventory")
    p = nas.get("probe") or {}
    host = p.get("host") or next((n.get("name") for n in nas.get("net") or [] if n.get("name")), None) or \
        next((n.get("ip") for n in nas.get("net") or [] if n.get("ip")), None)
    if not host:
        raise Bad("the NAS in the inventory has no host name or address")
    resolved = [host] if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else C.resolve(host)
    cands = []
    for ip in resolved + list(p.get("fallbackIps") or []):
        if ip not in cands and C.ip_allowed(ip):
            cands.append(ip)
    checks = []
    for ip in cands:
        ok, ms, det = C.tcp_check(ip, 445, timeout=2.0)
        pok, pms = C.ping(ip, attempts=1)
        checks.append({"ip": ip, "smb445": ok, "smbDetail": det, "ping": pok, "pingMs": pms})
    return {"host": host, "resolved": resolved, "checks": checks,
            "healthy": any(c["smb445"] for c in checks),
            "note": "Healthy means SMB 445 answers. Ping alone proves nothing for a NAS."}


# name: (function, [validators], optional-count, help)
COMMANDS = {
    "live": (cmd_live, [], 0, "print the monitor's live.json (all devices, links, strangers)"),
    "device": (cmd_device, [v_device], 0, "<id>: inventory entry, live status and links of one device"),
    "ping": (cmd_ping, [v_host], 0, "<host>: three single pings with a 1 s timeout"),
    "tcp": (cmd_tcp, [v_host, v_port], 0, "<host> <port>: can a TCP connection be opened"),
    "dns": (cmd_dns, [v_re(HOST_RE, "host name")], 0, "<name>: resolve through the router's DNS and the system resolver"),
    "rdns": (cmd_rdns, [v_ip], 0, "<ip>: reverse DNS at the router (the name the router gave it)"),
    "route": (cmd_route, [v_host], 0, "<host>: which interface and gateway this Mac uses to reach it"),
    "interfaces": (cmd_interfaces, [], 0, "every en*/bridge* interface: status, negotiated speed, address"),
    "interface": (cmd_interface, [v_re(IF_RE, "interface name")], 0, "<if>: one interface (e.g. en0): status, media, speed, duplex"),
    "service-order": (cmd_service_order, [], 0, "network service order and the default route interface"),
    "wifi": (cmd_wifi, [], 0, "Wi-Fi power, address, PHY mode, channel, signal/noise"),
    "usb": (cmd_usb, [], 0, "USB devices with ids, link speed, power and the hub they sit behind"),
    "displays": (cmd_displays, [], 0, "connected displays: pixels, looks-like resolution, refresh, HiDPI"),
    "thunderbolt": (cmd_thunderbolt, [], 0, "Thunderbolt/USB4 ports and what is attached"),
    "mdns": (cmd_mdns, [v_re(SVC_RE, "service type")], 0, "<_type._tcp>: instances advertising a Bonjour service (4 s browse)"),
    "cast": (cmd_cast, [v_ip], 0, "<ip>: Google Cast device info (name, firmware, Wi-Fi or Ethernet)"),
    "http-head": (cmd_http_head, [v_url], 0, "<url>: HTTP HEAD to a local host, no redirects followed"),
    "ha-state": (cmd_ha_state, [v_re(ENTITY_RE, "entity id")], 0, "<entity_id>: one Home Assistant entity (token never shown)"),
    "ha-states": (cmd_ha_states, [v_re(DOMAIN_RE, "domain")], 1, "[domain]: Home Assistant entities, optionally one domain (e.g. media_player)"),
    "sweep": (cmd_sweep, [], 0, "ping every address on the house network and name the ones that answer"),
    "bluetooth": (cmd_bluetooth, [], 0, "Bluetooth devices this Mac knows: name, address, connected or only paired, battery, firmware"),
    "ssdp": (cmd_ssdp, [], 0, "UPnP/SSDP search of the house network: who answers, with maker and model from their descriptions"),
    "ports": (cmd_ports, [v_subnet_ip], 0, "<ip>: common open TCP ports of one host, web page titles, certificate names, greetings (read-only)"),
    "identity": (cmd_identity, [v_device], 0, "<id>: what the identification engine knows about one device: evidence, candidates, security"),
    "nas": (cmd_nas, [], 0, "resolve the inventory's NAS and test SMB 445 and ping on each candidate address"),
}


def list_text():
    return "\n".join("python3 bin/probe.py %-14s %s" % (n, h) for n, (_, _, _, h) in COMMANDS.items())


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        print()
        print(list_text())
        return 0
    if argv[0] == "--list":
        print(list_text())
        return 0
    name, args = argv[0], argv[1:]
    if name not in COMMANDS:
        sys.stderr.write("unknown subcommand %r. Run: python3 bin/probe.py --list\n" % name)
        return 2
    fn, validators, optional, _ = COMMANDS[name]
    if not (len(validators) - optional <= len(args) <= len(validators)):
        sys.stderr.write("%s takes %d argument(s): %s\n" % (name, len(validators), COMMANDS[name][3]))
        return 2
    try:
        vals = [v(a) for v, a in zip(validators, args)]
    except Bad as e:
        sys.stderr.write("refused: %s\n" % e)
        return 2
    try:
        out = fn(*vals)
    except Bad as e:
        sys.stderr.write("refused: %s\n" % e)
        return 2
    except Exception as e:
        sys.stderr.write("failed: %s: %s\n" % (type(e).__name__, e))
        return 1
    print(json.dumps(out, indent=1, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
