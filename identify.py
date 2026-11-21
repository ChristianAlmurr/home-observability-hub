"""Identification engine: gathers evidence about every host and says, honestly, what it is.

Standard library only, Python 3.9+. Everything here reads: multicast queries
(mDNS, SSDP), TCP connects, HTTP GETs and TLS handshakes on the house subnet
(data/site.json), Home Assistant's template API, and state files.

The rule that shapes it: never state a product that evidence does not show. So there are two kinds of finding:

- a *claim*: a probe in which the device, or a system that talks to it, names
  the product (cast, UPnP description, Hue config, Bluetooth, the router's own
  product id, Home Assistant's registry matched by address) or the person said so;
- a *candidate*: a lead from a MAC prefix, a hostname, an open port or a name
  that matches. Candidates never make a device `confirmed`.
"""
import concurrent.futures
import datetime
import json
import os
import re
import socket
import ssl
import struct
import tempfile
import threading
import time
import urllib.request

import collectors as C
import oui

NET_TTL = 600            # mDNS, SSDP and Home Assistant registry: every 10 minutes
DEEP_TTL = 12 * 3600     # ports and banners of a known host: twice a day
DEEP_BATCH = 6           # hosts fingerprinted per background round
NET_EARLY = 60           # a new address may pull the passive round forward, at most once a minute
NEW_WINDOW = 24 * 3600

# port: (service, risky, why it is risky)
PORTS = {
    21: ("ftp", True, "FTP sends passwords and files unencrypted"),
    22: ("ssh", False, None), 23: ("telnet", True, "Telnet is an unencrypted remote login, a favourite of botnets"),
    53: ("dns", False, None), 80: ("http", False, None), 81: ("http", False, None), 139: ("netbios", False, None),
    443: ("https", False, None), 445: ("smb", False, None), 515: ("printer", False, None), 548: ("afp", False, None),
    554: ("rtsp", False, None), 631: ("ipp", False, None), 1400: ("sonos", False, None), 1883: ("mqtt", False, None),
    2323: ("telnet", True, "Telnet on a side port is an unencrypted remote login"),
    3389: ("rdp", True, "Remote Desktop is open to anything on the network"),
    5000: ("http", False, None), 5001: ("https", False, None),
    5555: ("adb", True, "Android debugging over the network gives full control without a password"),
    5900: ("vnc", True, "Screen sharing (VNC) is open to anything on the network"),
    6466: ("androidtv", False, None), 6668: ("tuya", False, None), 7000: ("airplay", False, None),
    8000: ("http", False, None), 8001: ("http", False, None), 8008: ("cast", False, None), 8009: ("cast", False, None),
    8060: ("roku", False, None), 8080: ("http", False, None), 8081: ("http", False, None), 8123: ("home-assistant", False, None),
    8443: ("https", False, None), 8883: ("mqtt-tls", False, None), 8888: ("http", False, None), 9000: ("http", False, None),
    9100: ("printer", False, None), 9999: ("iot", False, None), 32400: ("plex", False, None), 49152: ("upnp", False, None),
    49153: ("upnp", False, None), 55443: ("yeelight", False, None), 62078: ("iphone-sync", False, None),
}
HTTP_PORTS = (80, 81, 5000, 8000, 8001, 8080, 8081, 8888, 9000, 49152)
TLS_PORTS = (443, 5001, 8443)
BANNER_PORTS = (21, 22, 23, 2323)

MDNS_TYPES = [
    "_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_hap._tcp", "_homekit._tcp", "_matter._tcp", "_matterc._udp",
    "_companion-link._tcp", "_device-info._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp",
    "_scanner._tcp", "_uscan._tcp", "_http._tcp", "_https._tcp", "_ssh._tcp", "_sftp-ssh._tcp", "_smb._tcp",
    "_afpovertcp._tcp", "_workstation._tcp", "_spotify-connect._tcp", "_sonos._tcp", "_hue._tcp", "_esphomelib._tcp",
    "_shelly._tcp", "_miio._udp", "_homeconnect._tcp", "_androidtvremote2._tcp", "_amzn-wplay._tcp", "_rdlink._tcp",
    "_sleep-proxy._udp", "_apple-mobdev2._tcp", "_meshcop._udp", "_rtsp._tcp", "_daap._tcp", "_adisk._tcp",
    "_nvstream._tcp", "_axis-video._tcp", "_mqtt._tcp", "_home-assistant._tcp", "_eufy._tcp", "_tuya._tcp",
]
HAP_CATEGORY = {"2": "bridge", "5": "light", "7": "plug", "8": "switch", "9": "thermostat", "10": "sensor", "17": "camera",
                "18": "doorbell", "19": "appliance", "20": "appliance", "21": "appliance", "22": "appliance",
                "26": "speaker", "27": "speaker", "28": "appliance", "31": "tv", "32": "remote", "33": "router"}

# (regex on a hostname, vendor, type, what the name suggests)
HOSTNAME_HINTS = [
    (r"^mxchip", "MXCHIP (Wi-Fi module)", "appliance", "an appliance or gadget built on an MXCHIP Wi-Fi module"),
    (r"^lwip", None, "iot", "a small embedded device (lwIP is a network stack used in smart plugs, bulbs and sensors)"),
    (r"^esp[-_]|^espressif", "Espressif (Wi-Fi module)", "iot", "a gadget built on an Espressif (ESP) module"),
    (r"iphone", "Apple", "phone", "an iPhone"), (r"ipad", "Apple", "tablet", "an iPad"),
    (r"macbook|^imac|^mac$|^mac-|-mini$|^macm-", "Apple", "computer", "a Mac"),
    (r"watch", None, "wearable", "a watch"), (r"apple-?tv", "Apple", "tv", "an Apple TV"), (r"homepod", "Apple", "speaker", "a HomePod"),
    (r"^android|^galaxy|^pixel|^huawei|^oneplus|^redmi|^xiaomi", None, "phone", "an Android phone or tablet"),
    (r"^galaxy|^samsung", "Samsung", None, "a Samsung device"), (r"^huawei", "Huawei", "phone", "a Huawei phone"),
    (r"^pixel", "Google", "phone", "a Google Pixel"),
    (r"^google-home|^nest-|chromecast|^google-nest", "Google", "speaker", "a Google Home or Nest device"),
    (r"^audiocast", None, "speaker", "a cast-enabled speaker"),
    (r"^amazon-|^echo", "Amazon", "speaker", "an Amazon Echo"), (r"^ring-", "Ring", "camera", "a Ring device"),
    (r"^sonos", "Sonos", "speaker", "a Sonos speaker"), (r"eufy", "Anker (eufy, Soundcore)", None, "a eufy device"),
    (r"cam(era)?\b|^ipc", None, "camera", "a camera"),
    (r"^hp[0-9a-f]{6}|^npi[0-9a-f]{6}|printer|^canon|^epson|^brother|^brn", None, "printer", "a printer"),
    (r"^shelly", "Shelly (Allterco)", "plug", "a Shelly relay or plug"), (r"^tasmota|^wled", None, "iot", "a gadget with open firmware"),
    (r"^roborock|vacuum|^deebot|omni", None, "vacuum", "a robot vacuum"), (r"dishwasher|washer|dryer|oven|fridge", None, "appliance", "a kitchen or laundry appliance"),
    (r"^lgwebostv|bravia|^tv-|tizen|[-_]tv$", None, "tv", "a television"), (r"mediabox|settop|^stb", None, "tv", "a TV set-top box"),
    (r"nas$|^nas|diskstation|synology|qnap|mycloud", None, "nas", "network storage"),
    (r"phone$", None, "phone", "a phone"), (r"zenwifi|^rt-a[cx]|^gt-a[cx]", "ASUS", "router", "an ASUS router or mesh node"),
    (r"^imx\d", None, "iot", "an embedded Linux board (NXP i.MX)"),
]
PORT_HINTS = {
    62078: ("Apple", "phone", "port 62078 (iPhone sync) is open, which iPhones and iPads do"),
    8009: ("Google", None, "it answers on the Google Cast port"),
    1400: ("Sonos", "speaker", "it answers on the Sonos control port"),
    9100: (None, "printer", "it answers on the raw printing port"),
    631: (None, "printer", "it answers on the IPP printing port"),
    554: (None, "camera", "it serves RTSP video, which cameras do"),
    6668: ("Tuya (smart-home module)", "plug", "it answers on port 6668, the local control port of Tuya-based smart plugs, bulbs and sensors"),
    8060: ("Roku", "tv", "it answers on the Roku control port"),
    32400: (None, "computer", "it runs a Plex media server"),
    7000: (None, None, "it is an AirPlay receiver"),
}


def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def host_id(ip=None, mac=None):
    if ip:
        return "host-" + ip.replace(".", "-")
    return "host-mac-" + (mac or "").replace(":", "").lower()


def local_ip():
    """This Mac's address on the house subnet."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((C.router_ip(), 9))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


# ================================================================ mDNS

def _dns_name(buf, off, depth=0):
    labels = []
    jumped, end = False, off
    while True:
        if off >= len(buf) or depth > 20:
            raise ValueError("bad name")
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("bad pointer")
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            depth += 1
            continue
        off += 1
        labels.append(buf[off:off + n].decode("utf-8", "replace"))
        off += n
    return ".".join(labels), (end if jumped else off)


def parse_dns(buf):
    """[(name, type, rdata)] for PTR, TXT, SRV and A records in a DNS message. Never raises."""
    out = []
    try:
        _, flags, qd, an, ns, ar = struct.unpack("!6H", buf[:12])
        off = 12
        for _ in range(qd):
            _, off = _dns_name(buf, off)
            off += 4
        for _ in range(an + ns + ar):
            name, off = _dns_name(buf, off)
            typ, _cls, _ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
            off += 10
            rd = off
            off += rdlen
            if off > len(buf):
                break
            if typ == 12:
                out.append((name, "PTR", _dns_name(buf, rd)[0]))
            elif typ == 33 and rdlen >= 7:
                port = struct.unpack("!H", buf[rd + 4:rd + 6])[0]
                out.append((name, "SRV", (_dns_name(buf, rd + 6)[0], port)))
            elif typ == 16:
                txt, p = {}, rd
                while p < rd + rdlen:
                    n = buf[p]
                    s = buf[p + 1:p + 1 + n].decode("utf-8", "replace")
                    p += 1 + n
                    if s and len(txt) < 24:
                        k, _, v = s.partition("=")
                        txt[k[:40]] = v[:160]
                out.append((name, "TXT", txt))
            elif typ == 1 and rdlen == 4:
                out.append((name, "A", socket.inet_ntoa(buf[rd:rd + 4])))
    except Exception:
        pass
    return out


def _dns_query(questions, unicast=False):
    pkt = struct.pack("!6H", 0, 0, len(questions), 0, 0, 0)
    for name, qtype in questions:
        for lab in name.rstrip(".").split("."):
            b = lab.encode("utf-8")[:63]
            pkt += bytes([len(b)]) + b
        pkt += b"\x00" + struct.pack("!2H", qtype, 1 | (0x8000 if unicast else 0))
    return pkt


def _mdns_socket(ifip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    shared = True
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.bind(("", 5353))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton("224.0.0.251") + socket.inet_aton(ifip))
    except OSError:
        s.close()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.bind((ifip, 0))
        shared = False
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ifip))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    return s, shared


def mdns_discover(seconds=6.0, extra_types=()):
    """Browse every advertised service type. {ip: {"hostnames": [...], "services": [{type, instance, port, txt}]}}

    Raises OSError when the network will not let us send (for example inside a sandbox)."""
    ifip = local_ip()
    if not ifip:
        raise OSError("this Mac has no address on the house network")
    s, shared = _mdns_socket(ifip)
    recs = []           # (src, name, type, data)

    def send(questions):
        for i in range(0, len(questions), 12):
            s.sendto(_dns_query(questions[i:i + 12], unicast=not shared), ("224.0.0.251", 5353))

    def listen(sec):
        end = time.time() + sec
        while True:
            left = end - time.time()
            if left <= 0:
                return
            s.settimeout(left)
            try:
                data, addr = s.recvfrom(9000)
            except socket.timeout:
                return
            except OSError:
                return
            for name, typ, rd in parse_dns(data):
                recs.append((addr[0], name, typ, rd))
    try:
        send([("_services._dns-sd._udp.local", 12)])
        listen(seconds * 0.2)
        types = set(MDNS_TYPES) | set(extra_types)
        for _, name, typ, rd in recs:
            if typ == "PTR" and name.lower().startswith("_services._dns-sd._udp"):
                t = rd[:-6] if rd.lower().endswith(".local") else rd
                if re.match(r"^_[A-Za-z0-9-]{1,40}\._(tcp|udp)$", t):
                    types.add(t)
        send([(t + ".local", 12) for t in sorted(types)])
        listen(seconds * 0.5)
        inst = {}
        for src, name, typ, rd in recs:
            if typ == "PTR" and not name.lower().startswith("_services."):
                inst.setdefault(rd, {"type": name[:-6] if name.lower().endswith(".local") else name, "src": src})
        have_srv = {n for _, n, t, _ in recs if t == "SRV"}
        have_txt = {n for _, n, t, _ in recs if t == "TXT"}
        follow = []
        for n in inst:
            if n not in have_srv:
                follow.append((n, 33))
            if n not in have_txt:
                follow.append((n, 16))
        if follow:
            send(follow[:240])
            listen(seconds * 0.2)
        have_a = {n.lower() for _, n, t, _ in recs if t == "A"}
        targets = {rd[0] for _, _, t, rd in recs if t == "SRV" and rd[0].lower() not in have_a}
        if targets:
            send([(t, 1) for t in sorted(targets)][:240])
            listen(seconds * 0.1)
    finally:
        s.close()

    addr = {}
    for _, name, typ, rd in recs:
        if typ == "A" and C.ip_allowed(rd):
            addr.setdefault(name.lower(), rd)
    srv = {n: rd for _, n, t, rd in recs if t == "SRV"}
    txt = {}
    for _, n, t, rd in recs:
        if t == "TXT":
            txt.setdefault(n, {}).update(rd)
    out = {}
    for name, ip in addr.items():
        out.setdefault(ip, {"hostnames": [], "services": []})
        h = name[:-6] if name.endswith(".local") else name
        if h not in out[ip]["hostnames"]:
            out[ip]["hostnames"].append(h)
    for name, meta in inst.items():
        target, port = srv.get(name, (None, None))
        ip = addr.get((target or "").lower()) or meta["src"]
        if not C.ip_allowed(ip):
            continue
        label = name[:-(len(meta["type"]) + 7)] if name.lower().endswith("." + meta["type"].lower() + ".local") else name
        e = out.setdefault(ip, {"hostnames": [], "services": []})
        if not any(x["type"] == meta["type"] and x["instance"] == label for x in e["services"]):
            e["services"].append({"type": meta["type"], "instance": label, "port": port, "txt": txt.get(name, {})})
    return out


# ================================================================ SSDP / UPnP

def _xml_tag(body, tag):
    m = re.search(r"<%s[^>]*>\s*([^<]{1,200}?)\s*</%s>" % (tag, tag), body or "", re.I)
    return m.group(1).strip() if m else None


def parse_upnp_description(body):
    d = {k: _xml_tag(body, k) for k in ("friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription", "deviceType")}
    d = {k: v for k, v in d.items() if v}
    if re.search(r"InternetGatewayDevice|WANIPConnection|WANPPPConnection", body or ""):
        d["igd"] = True
    return d


def ssdp_discover(seconds=3.0, fetch=True):
    """{ip: {"servers": [...], "types": [...], "location": url, "description": {...}}}"""
    ifip = local_ip()
    if not ifip:
        raise OSError("this Mac has no address on the house network")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    out = {}
    try:
        s.bind((ifip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ifip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
        s.sendto(msg, ("239.255.255.250", 1900))
        time.sleep(0.2)
        s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + seconds
        while time.time() < end:
            s.settimeout(max(0.05, end - time.time()))
            try:
                data, addr = s.recvfrom(4096)
            except (socket.timeout, OSError):
                break
            ip = addr[0]
            if not C.ip_allowed(ip):
                continue
            hdr = {}
            for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
                k, _, v = line.partition(":")
                if v:
                    hdr[k.strip().lower()] = v.strip()
            e = out.setdefault(ip, {"servers": [], "types": [], "location": None, "description": {}})
            if hdr.get("server") and hdr["server"][:120] not in e["servers"] and len(e["servers"]) < 4:
                e["servers"].append(hdr["server"][:120])
            if hdr.get("st") and hdr["st"][:120] not in e["types"] and len(e["types"]) < 24:
                e["types"].append(hdr["st"][:120])
            loc = hdr.get("location")
            if loc and not e["location"]:
                m = re.match(r"^http://(\d+\.\d+\.\d+\.\d+)(?::\d+)?/[^\s<>\"']*$", loc)
                if m and m.group(1) == ip:        # only ever fetch from the host that answered
                    e["location"] = loc
    finally:
        s.close()
    if fetch:
        def get(item):
            ip, e = item
            if e["location"]:
                st, body = C.http_get(e["location"], timeout=3, limit=131072)
                if st == 200:
                    e["description"] = parse_upnp_description(body)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(get, list(out.items())))
    for e in out.values():
        if any("InternetGatewayDevice" in t or "WANIPConnection" in t for t in e["types"]):
            e["description"]["igd"] = True
    return out


# ================================================================ Home Assistant registry

HA_TEMPLATE = (
    "{% set ns = namespace(out=[]) %}"
    "{% for did in states | map(attribute='entity_id') | map('device_id') | reject('none') | unique %}"
    "{% set ns.out = ns.out + [{'name': device_attr(did,'name_by_user') or device_attr(did,'name'), "
    "'manufacturer': device_attr(did,'manufacturer'), 'model': device_attr(did,'model'), 'modelId': device_attr(did,'model_id'), "
    "'sw': device_attr(did,'sw_version'), 'connections': device_attr(did,'connections') | list, "
    "'entities': device_entities(did)}] %}{% endfor %}{{ ns.out | to_json }}")


def ha_devices(timeout=12):
    """Home Assistant's device registry through its template API: [{name, manufacturer, model, modelId, sw, macs, entities}].
    Rendering a template reads; it changes nothing. Raises C.HAUnavailable."""
    base = C.ha_url()
    if not base:
        raise C.HAUnavailable("Home Assistant is not set up (homeAssistant.url in data/site.json)")
    tok = C._ha_token()
    if not tok:
        raise C.HAUnavailable("no Home Assistant token (homeAssistant.tokenFile in data/site.json)")
    req = urllib.request.Request(base + "/api/template", data=json.dumps({"template": HA_TEMPLATE}).encode(),
                                 headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    del tok
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            rows = json.loads(r.read(4 * 1024 * 1024).decode("utf-8", "replace"))
    except Exception as e:
        raise C.HAUnavailable("Home Assistant's device registry could not be read (%s)" % type(e).__name__)
    out = []
    for d in rows if isinstance(rows, list) else []:
        if not isinstance(d, dict):
            continue
        macs = []
        for c in d.get("connections") or []:
            if isinstance(c, (list, tuple)) and len(c) == 2 and c[0] == "mac" and oui.normalize(str(c[1])):
                macs.append(oui.normalize(str(c[1])))
        out.append({"name": d.get("name"), "manufacturer": d.get("manufacturer"), "model": d.get("model"),
                    "modelId": d.get("modelId"), "sw": d.get("sw"), "macs": macs,
                    "entities": [e for e in (d.get("entities") or []) if isinstance(e, str)][:60]})
    return out


# ================================================================ one host, in depth

TAILSCALE = ("/usr/local/bin/tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale", "/opt/homebrew/bin/tailscale")


def parse_tailscale_status(doc):
    """{house IP: {name, ips}} for tailnet peers whose current direct path is on the house subnet."""
    out = {}
    for p in ((doc or {}).get("Peer") or {}).values():
        host = (p.get("CurAddr") or "").rsplit(":", 1)[0].strip("[]")
        try:
            if not host or C.ipaddress.ip_address(host) not in C.subnet():
                continue
        except ValueError:
            continue
        out[host] = {"name": (p.get("DNSName") or "").split(".")[0] or p.get("HostName"),
                     "ips": [i for i in p.get("TailscaleIPs") or [] if "." in i]}
    return out


def tailscale_lan_peers():
    """Reads the local Tailscale daemon's status; sends nothing on the network."""
    exe = next((x for x in TAILSCALE if os.path.exists(x)), None)
    if not exe:
        return {}
    rc, out, _ = C.run([exe, "status", "--json"], timeout=8)
    if rc != 0:
        return {}                       # Tailscale stopped or logged out: no peers, which is not a fault of this app
    return parse_tailscale_status(json.loads(out))


def port_scan(ip, ports=None, timeout=0.8):
    """Open TCP ports among the common ones. [{port, service, risky}]"""
    ports = sorted(ports or PORTS)

    def one(p):
        try:
            s = socket.create_connection((ip, p), timeout=timeout)
            s.close()
            return p
        except OSError:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        found = [p for p in ex.map(one, ports) if p]
    return [{"port": p, "service": PORTS.get(p, ("unknown", False, None))[0], "risky": bool(PORTS.get(p, (None, False))[1])}
            for p in found]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def http_fingerprint(ip, port, tls=False, timeout=3.0):
    """{port, status, server, title, auth, passwordField, location} or None when nothing sensible answered."""
    handlers = [_NoRedirect, urllib.request.ProxyHandler({})]
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")      # old appliances
        except ssl.SSLError:
            pass
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    url = "%s://%s:%d/" % ("https" if tls else "http", ip, port)
    try:
        try:
            r = opener.open(urllib.request.Request(url, headers={"User-Agent": "HomeObservabilityHub/2"}), timeout=timeout)
        except urllib.error.HTTPError as e:
            r = e
        status, headers = r.getcode(), r.headers
        try:
            body = r.read(16384).decode("utf-8", "replace")
        except Exception:
            body = ""
        r.close()
    except Exception:
        return None
    m = re.search(r"<title[^>]*>\s*([^<]{1,120})", body, re.I)
    auth = headers.get("WWW-Authenticate")
    return {"port": port, "tls": tls, "status": status, "server": (headers.get("Server") or "")[:100] or None,
            "title": re.sub(r"\s+", " ", m.group(1)).strip() if m else None,
            "auth": auth[:100] if auth else None,
            "passwordField": bool(re.search(r"type\s*=\s*[\"']?password", body, re.I)),
            "location": (headers.get("Location") or "")[:160] or None}


def tls_names(ip, port, timeout=3.0):
    """Names in the certificate a host presents: {port, cn, org, issuer, san}. None when there is no TLS."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw) as s:
                der = s.getpeercert(True)
    except Exception:
        return None
    if not der:
        return None
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
            path = f.name
        d = ssl._ssl._test_decode_cert(path)
    except Exception:
        return {"port": port, "cn": None, "org": None, "issuer": None, "san": []}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass

    def field(seq, key):
        for rdn in seq or ():
            for k, v in rdn:
                if k == key:
                    return v[:100]
        return None
    return {"port": port, "cn": field(d.get("subject"), "commonName"), "org": field(d.get("subject"), "organizationName"),
            "issuer": field(d.get("issuer"), "organizationName") or field(d.get("issuer"), "commonName"),
            "san": [v[:100] for k, v in (d.get("subjectAltName") or ()) if k == "DNS"][:6]}


def banner(ip, port, timeout=2.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(200)
    except OSError:
        return None
    text = "".join(ch for ch in data.decode("latin-1") if 32 <= ord(ch) < 127).strip()
    return text[:120] or None


def rtsp_server(ip, timeout=2.0):
    try:
        with socket.create_connection((ip, 554), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(("OPTIONS rtsp://%s/ RTSP/1.0\r\nCSeq: 1\r\n\r\n" % ip).encode())
            data = s.recv(600).decode("latin-1")
    except OSError:
        return None
    m = re.search(r"^Server:\s*(.+)$", data, re.I | re.M)
    return m.group(1).strip()[:100] if m else None


def cast_details(ip):
    """What a Google Cast device says about itself: {name, mac, bssid, ssid, signal, firmware, manufacturer, model}."""
    st, body = C.http_get("http://%s:8008/setup/eureka_info" % ip, timeout=3)
    if st != 200:
        return None
    try:
        d = json.loads(body)
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    out = {"name": d.get("name"), "mac": oui.normalize(d.get("mac_address") or ""), "bssid": oui.normalize(d.get("bssid") or ""),
           "ssid": d.get("ssid"), "signal": d.get("signal_level"), "firmware": d.get("cast_build_revision"),
           "ethernet": bool(d.get("ethernet_connected"))}
    st, body = C.http_get("http://%s:8008/ssdp/device-desc.xml" % ip, timeout=3)
    if st == 200:
        out["manufacturer"] = _xml_tag(body, "manufacturer")
        out["model"] = _xml_tag(body, "modelName")
    return {k: v for k, v in out.items() if v not in (None, "")}


def hue_details(ip):
    st, body = C.http_get("http://%s/api/0/config" % ip, timeout=3)
    if st != 200:
        return None
    try:
        d = json.loads(body)
    except ValueError:
        return None
    if not isinstance(d, dict) or not d.get("bridgeid"):
        return None
    return {"name": d.get("name"), "model": d.get("modelid"), "mac": oui.normalize(d.get("mac") or ""),
            "software": d.get("swversion"), "api": d.get("apiversion")}


def coap_get(ip, path, timeout=1.5):
    """One CoAP GET (UDP 5683). (code like '2.05', payload text) or None. Small appliances answer this
    where they answer nothing else."""
    pkt = struct.pack("!BBH", 0x40, 1, int.from_bytes(os.urandom(2), "big"))
    last = 0
    for seg in [x for x in path.split("/") if x]:
        b = seg.encode("ascii", "replace")[:12]
        pkt += bytes([((11 - last) << 4) | len(b)]) + b
        last = 11
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 5683))
        data, _ = s.recvfrom(2048)
    except OSError:
        return None
    finally:
        s.close()
    if len(data) < 4:
        return None
    i = data.find(b"\xff")
    return "%d.%02d" % (data[1] >> 5, data[1] & 31), (data[i + 1:].decode("utf-8", "replace") if i >= 0 else "")


def coap_device_info(ip):
    """{name, type, model, software} from /sys/dev/info, when the host speaks that."""
    r = coap_get(ip, "/sys/dev/info")
    if not r or not r[0].startswith("2."):
        return None
    try:
        d = json.loads(r[1])
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    out = {"name": d.get("name"), "type": d.get("type"), "model": d.get("modelid"), "software": d.get("swversion")}
    out = {k: str(v)[:80] for k, v in out.items() if v}
    return out or None


def deep_scan(ip):
    """Fingerprint one host. Read-only: connects, HTTP GET /, TLS handshake, greeting banners."""
    if not C.ip_allowed(ip):
        raise ValueError("%s is outside the house network" % ip)
    out = {"ts": now_iso(), "t": time.time(), "ports": port_scan(ip), "http": [], "tls": [], "banners": {}}
    open_ports = {p["port"] for p in out["ports"]}
    out["rdns"] = C.rdns(ip)
    for p in HTTP_PORTS:
        if p in open_ports:
            f = http_fingerprint(ip, p)
            if f:
                out["http"].append(f)
    for p in TLS_PORTS:
        if p in open_ports:
            n = tls_names(ip, p)
            if n:
                out["tls"].append(n)
                f = http_fingerprint(ip, p, tls=True)
                if f:
                    out["http"].append(f)
    for p in BANNER_PORTS:
        if p in open_ports:
            b = banner(ip, p)
            if b:
                out["banners"][str(p)] = b
    if 554 in open_ports:
        s = rtsp_server(ip)
        if s:
            out["banners"]["554"] = s
    if 8008 in open_ports:
        c = cast_details(ip)
        if c:
            out["cast"] = c
    if 80 in open_ports:
        h = hue_details(ip)
        if h:
            out["hue"] = h
    co = coap_device_info(ip)
    if co:
        out["coap"] = co
    return out


# ================================================================ the engine (cache + cadence)

class Engine:
    """Keeps the evidence, decides what is due and gathers it off the 30-second loop."""

    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.enabled = os.environ.get("HM_NO_IDENTIFY") != "1"
        self.net = {"t": 0, "ts": None, "mdns": {}, "ssdp": {}, "ha": [], "errors": {}}
        self.hosts = {}          # ip -> deep_scan() result
        self.seen = {}           # ip or MAC -> first-seen ISO time
        self.wanted = {}         # ip -> when it was first queued for a scan (not saved: after a restart it waits again)
        self.health = None       # set by the worker: (ok, error)
        self._load()

    @property
    def path(self):
        return os.path.join(C.state_dir(), "identity-cache.json")

    def _load(self):
        try:
            with open(self.path) as f:
                d = json.load(f)
            self.net.update(d.get("net") or {})
            self.hosts = d.get("hosts") or {}
            self.seen = d.get("seen") or {}
        except (OSError, ValueError):
            pass

    def save(self):
        with self.lock:
            doc = {"net": self.net, "hosts": self.hosts, "seen": self.seen}
        try:
            C.write_json_atomic(self.path, doc)
        except OSError:
            pass

    def first_seen(self, key, ts=None):
        with self.lock:
            if key not in self.seen:
                self.seen[key] = ts or now_iso()
            elif ts and ts < self.seen[key]:
                self.seen[key] = ts
            return self.seen[key]

    def due(self, ips):
        """(passive round due, addresses to fingerprint). An address never fingerprinted waits until a passive
        round (mDNS, SSDP, Home Assistant, Tailscale) has run since it was queued: a known device on a new
        MAC is matched by what it announces before anything probes it."""
        now = time.time()
        with self.lock:
            net_t = self.net.get("t") or 0
            for ip in list(self.wanted):
                if ip not in ips:
                    del self.wanted[ip]
            for ip in ips:
                self.wanted.setdefault(ip, now)
            fresh = [ip for ip in ips if ip not in self.hosts]
            new = [ip for ip in fresh if self.wanted[ip] < net_t]
            net_due = now - net_t >= NET_TTL or (len(new) < len(fresh) and now - net_t >= NET_EARLY)
            old = sorted((ip for ip in ips if ip in self.hosts and now - (self.hosts[ip].get("t") or 0) >= DEEP_TTL),
                         key=lambda ip: self.hosts[ip].get("t") or 0)
        return net_due, (new + old)[:DEEP_BATCH]

    def kick(self, ips, on_done=None):
        """Start a background round if something is due and none is running. Returns True when started."""
        if not self.enabled:
            return False
        net_due, todo = self.due(ips)
        with self.lock:
            if self.running or not (net_due or todo):
                return False
            self.running = True
        threading.Thread(target=self._work, args=(net_due, todo, on_done), name="identify", daemon=True).start()
        return True

    def _work(self, net_due, ips, on_done=None):
        errors = {}
        try:
            if net_due:
                self.discover(errors)
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
                for ip, res in zip(ips, ex.map(self._scan_safe, ips)):
                    if res is not None:
                        with self.lock:
                            self.hosts[ip] = res
            self.save()
            self.health = (not errors, "; ".join("%s: %s" % kv for kv in errors.items()) or None)
        except Exception as e:
            self.health = (False, "%s: %s" % (type(e).__name__, e))
        finally:
            with self.lock:
                self.running = False
            if on_done:
                try:
                    on_done()
                except Exception:
                    pass

    def discover(self, errors=None):
        errors = errors if errors is not None else {}
        net = {"t": time.time(), "ts": now_iso(), "errors": errors}
        for key, fn in (("mdns", mdns_discover), ("ssdp", ssdp_discover), ("ha", ha_devices), ("tailscale", tailscale_lan_peers)):
            try:
                net[key] = fn()
            except Exception as e:
                errors[key] = "%s" % (e if isinstance(e, C.HAUnavailable) else "%s: %s" % (type(e).__name__, e))
                net[key] = self.net.get(key) or ({} if key != "ha" else [])
        with self.lock:
            self.net = net
        return net

    @staticmethod
    def _scan_safe(ip):
        try:
            return deep_scan(ip)
        except Exception:
            return None

    def scan_now(self, ip):
        """The `scan` action: fingerprint one host right now and refresh the network-wide sources."""
        res = deep_scan(ip)
        with self.lock:
            self.hosts[ip] = res
        try:
            self.discover()
        except Exception:
            pass
        self.save()
        return res

    def forget(self, ip=None, mac=None):
        with self.lock:
            for k in (ip, mac):
                if k:
                    self.hosts.pop(k, None)
                    self.seen.pop(k, None)
        self.save()


# ================================================================ from evidence to identity

HEDGE = re.compile(r"not confirmed|not identified|unidentified|likely|probably|not known|unknown|candidate|not otherwise", re.I)


def vendor_key(v):
    v = re.sub(r"\(.*?\)", "", str(v or "")).lower()
    w = re.findall(r"[a-z0-9]+", v)
    alias = {"harman": "harman", "jbl": "harman", "signify": "philips", "philips": "philips", "anker": "anker", "eufy": "anker",
             "asustek": "asus", "bsh": "bosch", "hewlett": "hp", "tpv": "tpvision", "tp": "tp" }
    return alias.get(w[0], w[0]) if w else ""


def _ev(source, label, value, ts=None):
    return {"source": source, "label": label, "value": str(value)[:240], "ts": ts}


def base_identity(dev, specs):
    """Where an inventory device starts: what research or the inventory already established."""
    if dev is None:
        return {"state": "unidentified", "vendor": None, "model": None, "type": None, "basis": None}
    kind = dev.get("kind") if dev.get("kind") != "unknown" else None
    if dev.get("identifiedBy"):
        who = C.SITE.owner() if str(dev["identifiedBy"]).lower() in ("person", "owner", C.SITE.owner().lower()) else str(dev["identifiedBy"])
        return {"state": "confirmed", "vendor": dev.get("vendor") or None, "model": dev.get("model") or None, "type": kind,
                "basis": "Identified by hand by %s%s." % (who, (" on " + dev["identifiedAt"][:10]) if dev.get("identifiedAt") else "")}
    si = (specs or {}).get("identity") if isinstance(specs, dict) else None
    if isinstance(si, dict) and si.get("confidence") in ("confirmed", "likely", "unknown"):
        state = {"confirmed": "confirmed", "likely": "likely", "unknown": "unidentified"}[si["confidence"]]
        vendor = si.get("vendor") if state != "unidentified" else None
        model = si.get("model") if state != "unidentified" else None
        return {"state": state, "vendor": vendor or None, "model": model or None, "type": kind,
                "basis": si.get("basis") or "From the device's knowledge file."}
    vendor, model = (dev.get("vendor") or "").strip(), (dev.get("model") or "").strip()
    if not vendor:
        return {"state": "unidentified", "vendor": None, "model": None, "type": kind, "basis": "The inventory has no maker for it."}
    if not model or HEDGE.search(model):
        return {"state": "likely", "vendor": vendor, "model": model or None, "type": kind,
                "basis": "From the inventory (%s); the inventory itself says the model is not settled." % (dev.get("verified") or "plan")}
    how = {"live": "probed when the house was surveyed", "reported": "reported by %s or an order email" % C.SITE.owner()}.get(dev.get("verified"))
    if how:
        return {"state": "confirmed", "vendor": vendor, "model": model, "type": kind, "basis": "From the inventory: %s." % how}
    return {"state": "likely", "vendor": vendor, "model": model, "type": kind, "basis": "From the plan; not confirmed."}


def build_identity(dev=None, specs=None, ips=(), macs=(), names=(), router_client=None, router_node=None, mdns=None,
                   ssdp=None, deep=None, ha=None, ha_by_name=None, bluetooth=None, bt_namesake=None, live_facts=None):
    """The `identity` object of the contract. Pure: everything it needs is passed in."""
    evidence, claims, cands = [], [], []
    base = base_identity(dev, specs)
    live_facts = live_facts or {}
    deep = deep or {}
    names = [n for n in names if n]

    def cand(vendor, model, typ, confidence, basis, source):
        cands.append({"vendor": vendor, "model": model, "type": typ, "confidence": confidence, "basis": basis, "_source": source})

    def claim(vendor, model, typ, basis, source):
        claims.append({"vendor": vendor, "model": model, "type": typ, "basis": basis, "source": source})

    # --- MAC
    mac = next((m for m in macs if m), None)
    mac_vendor = oui.vendor(mac) if mac else None
    randomized = oui.is_randomized(mac) if mac else False
    if mac:
        evidence.append(_ev("mac", "Hardware address", mac + (" (private, randomised: says nothing about the maker)" if randomized else "")))
        if mac_vendor:
            evidence.append(_ev("mac", "Maker of the network chip", mac_vendor))
            module = oui.is_module_maker(mac_vendor)
            cand(mac_vendor, None, None, "low",
                 "Its network chip is registered to %s%s." % (mac_vendor, ", which makes radios for other brands" if module else ""), "mac")

    # --- router
    rc = router_client or {}
    if rc:
        ts = rc.get("_ts")
        if rc.get("nickname"):
            evidence.append(_ev("router", "Name given to it on the router", rc["nickname"], ts))
        if rc.get("hostname"):
            evidence.append(_ev("router", "Name it gave the router (DHCP)", rc["hostname"], ts))
        if rc.get("vendor"):
            evidence.append(_ev("router", "Maker according to the router", rc["vendor"], ts))
            if not re.match(r"^(dhcpcd|udhcp|android-dhcp|MSFT)", rc["vendor"]):
                cand(rc["vendor"], None, None, "low", "The router lists its maker as %s." % rc["vendor"].rstrip("."), "router")
        if rc.get("dhcpVendorClass") and rc.get("dhcpVendorClass") != rc.get("vendor"):
            evidence.append(_ev("router", "DHCP client software", rc["dhcpVendorClass"], ts))
        if rc.get("medium") == "wifi":
            evidence.append(_ev("router", "Connection", "Wi-Fi %s, signal %s dBm" % (rc.get("bandLabel") or "", rc.get("rssi")), ts))
        elif rc.get("medium") == "ethernet":
            evidence.append(_ev("router", "Connection", "Wired", ts))
    if router_node:
        evidence.append(_ev("router", "Product id it reports over SSH", router_node.get("model") or "?"))
        if router_node.get("model"):
            nm = next((n for n in names if re.search(r"zenwifi|^rt-|^gt-|^asus", n, re.I)), None)
            claim("ASUS", "%s(product id %s)" % ((nm.split("-")[0].replace("_", " ") + " ") if nm else "", router_node["model"]),
                  "router" if router_node.get("main") else "access-point",
                  "The unit itself reports product id %s%s." % (router_node["model"], (" and names itself " + nm) if nm else ""), "router")

    # --- names (reverse DNS, mDNS host names, the router's)
    for n in names:
        for rx, vendor, typ, what in HOSTNAME_HINTS:
            if re.search(rx, n, re.I):
                cand(vendor, None, typ, "low", "It calls itself %s, which suggests %s." % (n, what), "name")
                break
    if deep.get("rdns"):
        evidence.append(_ev("dns", "Name at the router's DNS", deep["rdns"], deep.get("ts")))

    # --- mDNS
    for h in (mdns or {}).get("hostnames") or []:
        evidence.append(_ev("mdns", "Bonjour host name", h))
    for s in ((mdns or {}).get("services") or [])[:16]:
        txt = s.get("txt") or {}
        shown = {k: v for k, v in txt.items() if k.lower() in ("md", "model", "am", "ty", "product", "manufacturer", "mf", "fn", "n", "ci", "usb_mfg", "usb_mdl", "vendor", "integrator", "brand", "type", "deviceid")}
        evidence.append(_ev("mdns", "Advertises %s" % s.get("type"), "%s%s" % (s.get("instance"), (" " + json.dumps(shown, ensure_ascii=False)) if shown else "")))
        st = s.get("type")
        model = {"_googlecast._tcp": txt.get("md"), "_hap._tcp": txt.get("md"), "_homeconnect._tcp": txt.get("md") or txt.get("type"),
                 "_airplay._tcp": txt.get("model"), "_raop._tcp": txt.get("am"), "_sonos._tcp": txt.get("md") or txt.get("model"),
                 "_ipp._tcp": txt.get("ty") or txt.get("usb_MDL") or txt.get("product"),
                 "_ipps._tcp": txt.get("ty") or txt.get("usb_MDL") or txt.get("product"),
                 "_printer._tcp": txt.get("ty") or txt.get("product")}.get(st)
        if model in ("Google Cast Group",):
            continue
        vendor = txt.get("manufacturer") or txt.get("mf") or txt.get("usb_MFG") or txt.get("vendor") or txt.get("brand")
        typ = {"_googlecast._tcp": None, "_ipp._tcp": "printer", "_ipps._tcp": "printer", "_printer._tcp": "printer",
               "_airplay._tcp": None, "_hap._tcp": HAP_CATEGORY.get(str(txt.get("ci"))), "_sonos._tcp": "speaker",
               "_androidtvremote2._tcp": "tv", "_homeconnect._tcp": "appliance"}.get(s.get("type"))
        if model:
            claim(vendor, model.strip("()"), typ, "It announces itself on the network (%s) as %s." % (s.get("type"), model), "mdns")
        elif typ:
            cand(vendor, None, typ, "medium", "It advertises %s." % s.get("type"), "mdns")
        if s.get("type") == "_companion-link._tcp" or s.get("type") == "_apple-mobdev2._tcp":
            cand("Apple", None, None, "medium", "It advertises %s, an Apple-only service." % s.get("type"), "mdns")

    # --- SSDP / UPnP
    if ssdp:
        d = ssdp.get("description") or {}
        for sv in ssdp.get("servers") or []:
            evidence.append(_ev("ssdp", "UPnP server software", sv))
        if d.get("friendlyName"):
            evidence.append(_ev("ssdp", "UPnP name", d["friendlyName"]))
        if d.get("manufacturer") or d.get("modelName"):
            evidence.append(_ev("ssdp", "UPnP description", "%s %s %s" % (d.get("manufacturer") or "", d.get("modelName") or "", d.get("modelNumber") or "")))
        if d.get("manufacturer") and d.get("modelName"):
            generic = bool(re.search(r"Wi-Fi Protected Setup|WPS", d["modelName"], re.I))
            model = d.get("modelNumber") if generic else d["modelName"] + (
                (" " + d["modelNumber"]) if d.get("modelNumber") and d["modelNumber"] not in d["modelName"] else "")
            typ = "tv" if re.search(r"tvdevice|MediaRenderer|dial", d.get("deviceType") or "", re.I) and not cast_like(d) else None
            if model:
                claim(d["manufacturer"], model, typ, "Its UPnP description names it: %s %s." % (d["manufacturer"], model), "ssdp")

    # --- ports, banners, web pages, certificates
    ports = deep.get("ports") or []
    if deep.get("ts"):
        evidence.append(_ev("ports", "Open ports (of %d common ones)" % len(PORTS),
                            ", ".join("%d %s" % (p["port"], p["service"]) for p in ports) or "none", deep["ts"]))
    for p in ports:
        h = PORT_HINTS.get(p["port"])
        if h:
            cand(h[0], None, h[1], "medium" if p["port"] in (62078, 6668, 1400, 8060) else "low", "%s." % (h[2][0].upper() + h[2][1:]), "ports")
    for f in deep.get("http") or []:
        bits = ["HTTP %s" % f.get("status")]
        if f.get("server"):
            bits.append("server %s" % f["server"])
        if f.get("title"):
            bits.append("title “%s”" % f["title"])
        if f.get("auth"):
            bits.append("asks for a login (%s)" % f["auth"])
        evidence.append(_ev("http", "Web page on port %s" % f.get("port"), ", ".join(bits), deep.get("ts")))
    for t in deep.get("tls") or []:
        val = ", ".join(x for x in [t.get("cn"), t.get("org"), ("issued by " + t["issuer"]) if t.get("issuer") else None] if x)
        if val:
            evidence.append(_ev("tls", "Certificate on port %s" % t.get("port"), val, deep.get("ts")))
    for port, b in (deep.get("banners") or {}).items():
        evidence.append(_ev("ports", "Greeting on port %s" % port, b, deep.get("ts")))

    # --- cast, Hue (from the deep scan or the 30-second probes)
    cast = deep.get("cast") or {}
    if cast or live_facts.get("firmware") and live_facts.get("connection"):
        nm = cast.get("name") or live_facts.get("name")
        if nm:
            evidence.append(_ev("cast", "Cast name", nm, deep.get("ts")))
        if cast.get("model"):
            evidence.append(_ev("cast", "Cast device description", "%s %s" % (cast.get("manufacturer") or "", cast["model"]), deep.get("ts")))
            claim(cast.get("manufacturer"), cast["model"], "speaker" if re.search(r"home|audio|speaker|link|mini", cast["model"], re.I) else None,
                  "Its own cast description names it %s%s." % (cast["model"], (", made by " + cast["manufacturer"]) if cast.get("manufacturer") else ""), "cast")
        if cast.get("bssid"):
            evidence.append(_ev("cast", "Wi-Fi access point it reports", "%s on %s" % (cast["bssid"], cast.get("ssid") or "?"), deep.get("ts")))
    hue = deep.get("hue") or ({"model": live_facts.get("modelid"), "name": live_facts.get("name")} if live_facts.get("bridgeid") else {})
    if hue.get("model"):
        evidence.append(_ev("hue", "Hue config", "%s, model %s" % (hue.get("name") or "Hue Bridge", hue["model"]), deep.get("ts")))
        claim("Philips Hue (Signify)", "Hue Bridge (%s)" % hue["model"], "bridge", "Its Hue API reports model %s." % hue["model"], "hue")

    co = deep.get("coap") or {}
    if co:
        evidence.append(_ev("coap", "Device info it serves (CoAP /sys/dev/info)",
                            ", ".join("%s %s" % (k, v) for k, v in co.items()), deep.get("ts")))
        if co.get("model"):
            claim(None, co["model"], "appliance", "It answers a device-info request (CoAP) with model id %s%s." % (
                co["model"], (" and the name " + co["name"]) if co.get("name") else ""), "coap")
            if re.match(r"^[A-Z]{2}\d{4}/\d{2}$", co["model"]):
                cand("Philips", None, "appliance", "medium",
                     "This device-info interface and a model id written like %s are how Philips air purifiers, fans and heaters "
                     "present themselves. The device does not state its maker." % co["model"], "coap")

    # --- Home Assistant
    for h in ha or []:
        evidence.append(_ev("home-assistant", "Home Assistant device (%s)" % h.get("_match", "matched"),
                            "%s: %s %s" % (h.get("name"), h.get("manufacturer") or "?", h.get("model") or "?")))
        if h.get("manufacturer") and h.get("model") and h.get("_match") in ("address", "entity"):
            claim(h["manufacturer"], h["model"] + ((" (" + h["modelId"] + ")") if h.get("modelId") and h["modelId"] not in h["model"] else ""), None,
                  "Home Assistant's device registry, matched by %s, lists it as %s %s." % (
                      "hardware address" if h["_match"] == "address" else "its entity in the inventory", h["manufacturer"], h["model"]), "home-assistant")
    for h in ha_by_name or []:
        evidence.append(_ev("home-assistant", "Home Assistant has a device with the same name", "%s: %s %s" % (h.get("name"), h.get("manufacturer") or "?", h.get("model") or "?")))
        cand(h.get("manufacturer"), h.get("model"), "phone" if re.search(r"iphone|pixel|galaxy|phone", str(h.get("model")), re.I) else None, "medium",
             "Home Assistant knows a device with the same name (%s) and lists it as %s %s. The name matches; the address was not compared." % (
                 h.get("name"), h.get("manufacturer") or "?", h.get("model") or "?"), "home-assistant")

    # --- Bluetooth
    if bluetooth:
        b = bluetooth
        v = oui.peripheral_vendor(b.get("vendorId")) or None
        evidence.append(_ev("bluetooth", "Bluetooth device on this Mac", "%s (%s:%s)%s%s" % (
            b.get("name"), str(b.get("vendorId") or "?").replace("0x", ""), str(b.get("productId") or "?").replace("0x", ""),
            (", firmware " + b["firmware"]) if b.get("firmware") else "", (", battery " + str(b["battery"]) + "%") if b.get("battery") is not None else "")))
        # A name with a possessive is what its owner called it ("Kim's AirPods"), not a product name.
        if b.get("name") and b.get("productId") and not re.search(r"[’']s\b", b["name"]):
            claim(v, b["name"], "peripheral", "The %s connected to this Mac over Bluetooth reports itself as %s%s." % (
                (b.get("minorType") or "device").lower(), b["name"], (" (vendor id %s: %s)" % (b.get("vendorId"), v)) if v else ""), "bluetooth")
    if bt_namesake:
        b = bt_namesake
        bv = oui.vendor(b.get("address"))
        evidence.append(_ev("bluetooth", "This Mac knows a Bluetooth device with the same name",
                            "%s (%s%s)" % (b.get("name"), b.get("address"), (", " + bv) if bv else "")))
        if bv:
            cand(bv, None, None, "low", "A Bluetooth device with the same name (%s) is known to this Mac and its address is registered to %s." % (b.get("name"), bv), "bluetooth")
    if live_facts.get("usbName"):
        evidence.append(_ev("usb", "USB device on this Mac", live_facts["usbName"]))

    # --- merge candidates: the same maker from independent sources is a stronger lead
    merged = {}
    for c in cands:
        k = (vendor_key(c["vendor"]), c["type"] or "") if c["vendor"] else ("", c["type"] or "", c["basis"])
        m = merged.setdefault(k[0] or k, {"vendor": c["vendor"], "model": None, "type": None, "sources": [], "bases": [], "best": "low"})
        if c["vendor"] and (not m["vendor"] or len(c["vendor"]) < len(m["vendor"])) and not oui.is_module_maker(c["vendor"]):
            m["vendor"] = c["vendor"]
        m["model"] = m["model"] or c["model"]
        m["type"] = m["type"] or c["type"]
        if c["_source"] not in m["sources"]:
            m["sources"].append(c["_source"])
        m["bases"].append(c["basis"])
        if c["confidence"] == "medium":
            m["best"] = "medium"
    out_cands = []
    for m in merged.values():
        module = bool(m["vendor"]) and oui.is_module_maker(m["vendor"])
        conf = m["best"]
        if m["vendor"] and len(m["sources"]) >= 2:
            conf = "medium" if module else "high"
        out_cands.append({"vendor": m["vendor"], "model": m["model"], "type": m["type"], "confidence": conf,
                          "basis": " ".join(dict.fromkeys(m["bases"])), "module": module})
    order = {"high": 0, "medium": 1, "low": 2}
    out_cands.sort(key=lambda c: (order[c["confidence"]], not c["vendor"]))
    for c in out_cands:
        if not c["type"]:
            c["type"] = next((x["type"] for x in out_cands if x["type"] and (not x["vendor"] or vendor_key(x["vendor"]) == vendor_key(c["vendor"]))), None)

    # --- the verdict
    ident = dict(base)
    rank = {"bluetooth": 0, "router": 1, "cast": 2, "hue": 3, "coap": 4, "ssdp": 5, "mdns": 6, "home-assistant": 7}
    claims.sort(key=lambda c: rank.get(c["source"], 9))
    if claims and base["state"] != "confirmed":
        c = claims[0]
        vendor = c["vendor"] or next((x["vendor"] for x in claims if x["vendor"]), None) or base.get("vendor")
        ident = {"state": "confirmed", "vendor": vendor, "model": c["model"], "type": c["type"] or base.get("type") or
                 next((x["type"] for x in claims if x["type"]), None), "basis": c["basis"]}
    elif claims and base["state"] == "confirmed":
        ident["basis"] = (base.get("basis") or "") + " Also: " + claims[0]["basis"]
        ident["type"] = base.get("type") or claims[0]["type"]
    elif base["state"] == "unidentified":
        top = next((c for c in out_cands if c["confidence"] == "high" and not c["module"]), None)
        if top:
            ident = {"state": "likely", "vendor": top["vendor"], "model": top["model"], "type": top["type"] or base.get("type"),
                     "basis": "Not confirmed. " + top["basis"]}
        else:
            ident = {"state": "unidentified", "vendor": None, "model": None, "type": base.get("type"),
                     "basis": base.get("basis") or ("Nothing on the network names it yet." if not out_cands else
                                                    "Only leads so far; nothing names the product.")}
    for c in out_cands:
        c.pop("module", None)
    ident.update({"mac": mac, "macVendor": mac_vendor, "randomizedMac": randomized, "evidence": evidence, "candidates": out_cands[:6]})
    return ident


def cast_like(desc):
    """A UPnP description served by a cast speaker also says 'dial'; only call it a TV when the name does."""
    return not re.search(r"tv|mediabox|set.?top", "%s %s" % (desc.get("modelName"), desc.get("friendlyName")), re.I)


# ================================================================ the whole picture

def _lower_set(xs):
    return {str(x).lower() for x in xs if x}


# Names that many hosts use, so they never tie a host to one device: three laptops call themselves "Mac".
GENERIC_NAME = re.compile(
    r"^(mac|macbook|macbook-?pro|macbook-?air|imac|mac-?mini|iphone|ipad|ipod|apple-?watch|watch|android(-dhcp)?|"
    r"localhost|unknown|none|device|host|google|google-home|audiocast|chromecast|esp|espressif|lwip|mxchip|"
    r"raspberrypi|ubuntu|debian|linux|windows|desktop|laptop|pc|printer|camera|tv|phone)([-_ .]?\d+)?$", re.I)
MAC_IN_TEXT = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")


def _bare(name):
    n = str(name or "").strip().lower()
    return n[:-6] if n.endswith(".local") else n


def specific_name(name):
    n = _bare(name)
    return n if len(n) >= 4 and not GENERIC_NAME.match(n) else None


def device_names(dev):
    """Every specific name an inventory device goes by: its interfaces (Tailscale included), its probe, its host name."""
    p = dev.get("probe") or {}
    raw = [n.get("name") for n in dev.get("net") or [] if n.get("medium") != "bluetooth"] + [p.get("name"), p.get("host")]
    return {s for s in (specific_name(x) for x in raw) if s}


def passive_names(ip, rc, reg, mdns, tailscale):
    """[(source, name)] a host calls itself without being probed: mDNS, its DHCP host name at the router, Tailscale."""
    out = []
    for h in ((mdns or {}).get(ip) or {}).get("hostnames") or [] if ip else []:
        out.append(("mDNS", h))
    for k in ("hostname", "nickname"):
        if (rc or {}).get(k):
            out.append(("router (DHCP host name)", rc[k]))
    if (reg or {}).get("name"):
        out.append(("router (DHCP host name)", reg["name"]))
    ts = (tailscale or {}).get(ip) if ip else None
    if ts and ts.get("name"):
        out.append(("Tailscale", ts["name"]))
    return [(s, _bare(n)) for s, n in out if _bare(n)]


def passive_match(names, ts_ips, by_name, by_ts_ip, announcers):
    """The one inventory device this evidence points to, or None.

    A name counts only when it is specific, exactly one inventory device carries it, and exactly
    one host on the network announces it right now. Two sources pointing at two devices: no match."""
    hits = {}
    for src, n in names:
        s = specific_name(n)
        if not s or len(by_name.get(s, ())) != 1 or len(announcers.get(s, ())) != 1:
            continue
        hits.setdefault(next(iter(by_name[s])), []).append("%s name %s" % (src, n))
    for t in ts_ips or ():
        if len(by_ts_ip.get(t, ())) == 1:
            hits.setdefault(next(iter(by_ts_ip[t])), []).append("Tailscale address %s" % t)
    return (next(iter(hits.items()))) if len(hits) == 1 else (None, None)


def device_addresses(dev, result):
    """(ips on the house subnet, names) an inventory device is known by."""
    ips, names = [], []
    net = C.subnet()
    p = dev.get("probe") or {}
    f = (result or {}).get("facts") or {}
    cand = [n.get("ip") for n in dev.get("net") or []] + [p.get("ip")] + list(p.get("fallbackIps") or []) + \
           [f.get("resolvedIp"), f.get("answeredIp"), f.get("ip")] + [i.get("ipv4") for i in (f.get("interfaces") or {}).values()]
    for ip in cand:
        try:
            if ip and C.ipaddress.ip_address(ip) in net and ip not in ips:
                ips.append(ip)
        except ValueError:
            pass
    for n in [x.get("name") for x in dev.get("net") or []] + [p.get("name"), p.get("host")]:
        if n and n not in names:
            names.append(n)
    return ips, names


def build_picture(inv, results, registry, router, engine, bluetooth=None, specs_fn=None, router_fresh=True, self_ips=()):
    """Join every source into what the server serves on top of the inventory.

    registry: {key: {ip, mac, name, firstSeen, lastSeen}} of hosts seen that the inventory does not list.
    Returns {identities, dynamic, wifiLinks, wireless, security, traffic, linkLive, hostLive, scanIps, addresses, rematched}.
    rematched: {device id: [{ip, mac, basis}]}, the new addresses a known device was matched to by what it announces."""
    router = router or {}
    clients = router.get("clients") or []
    nodes = router.get("nodes") or []
    by_ip = {c["ip"]: c for c in clients if c.get("ip") and c.get("online")}
    for c in clients:
        if c.get("ip"):
            by_ip.setdefault(c["ip"], c)
    by_mac = {c["mac"]: c for c in clients}
    by_name = {}
    for c in clients:
        for n in (c.get("hostname"), c.get("nickname")):
            if n:
                by_name.setdefault(n.lower(), []).append(c)
    blocked_macs = {b["mac"] for b in router.get("blockList") or [] if b.get("active")}
    sched_macs = {b["mac"] for b in router.get("blockList") or [] if b.get("mode") == "schedule"}
    with engine.lock:
        net = dict(engine.net)
        hosts = dict(engine.hosts)
    mdns, ssdp, ha = net.get("mdns") or {}, net.get("ssdp") or {}, net.get("ha") or []
    mdns_by_name = {}
    for ip, e in mdns.items():
        for h in e.get("hostnames") or []:
            mdns_by_name.setdefault(h.lower(), ip)
    bluetooth = bluetooth or []
    devices = inv.get("devices") or []
    dev_by_ip = {}
    out = {"ts": now_iso(), "identities": {}, "dynamic": [], "wifiLinks": [], "wireless": {}, "security": {}, "traffic": {},
           "linkLive": {}, "hostLive": {}, "scanIps": [], "addresses": {}}

    # which inventory device is a mesh unit
    node_dev = {}

    def ha_matches(dev, macs, names):
        hit, named = [], []
        ent = (dev or {}).get("ha") or ((dev or {}).get("probe") or {}).get("entity")
        low = _lower_set(names)
        for h in ha:
            if set(h.get("macs") or []) & set(macs):
                hit.append(dict(h, _match="address"))
            elif ent and ent in (h.get("entities") or []):
                hit.append(dict(h, _match="entity"))
            elif h.get("name") and h["name"].lower() in low:
                named.append(h)
        return hit, named

    def namesake(names, own_bt):
        low = _lower_set(names)
        for b in bluetooth:
            if b.get("name") and b["name"].lower() in low and b is not own_bt:
                return b
        return None

    def ap_for(mac_or_bssid):
        """Inventory id of the mesh unit a node MAC or a radio BSSID belongs to, with how we know."""
        m = oui.normalize(mac_or_bssid or "")
        if not m:
            return None, None
        for n in nodes:
            if n["mac"] == m or m in (n.get("radios") or {}).values():
                return node_dev.get(n["mac"]), "router"
        for d in devices:                       # no router data: the units' own host names end in their MAC's last four digits
            if d.get("kind") in ("router", "access-point"):
                for nm in [x.get("name") for x in d.get("net") or []]:
                    k = re.search(r"-([0-9A-Fa-f]{4})$", nm or "")
                    if k and (int(m.replace(":", "")[-4:], 16) & 0xFFF0) == (int(k.group(1), 16) & 0xFFF0) and oui.vendor(m) == "ASUS":
                        return d["id"], "name"
        return None, None

    per_dev = {}
    for d in devices:
        ips, names = device_addresses(d, results.get(d["id"]))
        macs = [oui.normalize(n.get("mac") or "") for n in d.get("net") or [] if n.get("medium") != "bluetooth"]
        # A name ties a host to a device only where the inventory has no hardware address for that entry,
        # and only when exactly one host uses it: three laptops all call themselves "Mac".
        loose = [n.get("name") for n in d.get("net") or [] if n.get("name") and not n.get("mac") and n.get("medium") != "bluetooth"]
        p0 = d.get("probe") or {}
        loose += [x for x in (p0.get("name") if p0.get("type") == "mdns" else None, p0.get("host")) if x]
        for n in loose:
            ip = mdns_by_name.get(n.lower())
            if ip and ip not in ips:
                ips.append(ip)
        rcs = []
        for ip in ips:
            c = by_ip.get(ip)
            if c and c not in rcs:
                rcs.append(c)
        for m in macs:
            if m and by_mac.get(m) and by_mac[m] not in rcs:
                rcs.append(by_mac[m])
        for n in loose:
            same = by_name.get(n.lower(), [])
            for c in (same if len(same) == 1 else []):
                if c not in rcs:
                    rcs.append(c)
                    if c.get("ip") and c.get("online") and c["ip"] not in ips:
                        ips.append(c["ip"])
        for ip in ips:
            dp = hosts.get(ip) or {}
            for src in (dp.get("cast"), dp.get("hue")):
                if src and src.get("mac"):
                    macs.append(src["mac"])
        macs = [m for m in macs if m] + [c["mac"] for c in rcs]
        macs = list(dict.fromkeys(macs))
        per_dev[d["id"]] = {"ips": ips, "names": names, "macs": macs, "rcs": rcs}
        for ip in ips:
            dev_by_ip.setdefault(ip, d["id"])
        for n in nodes:
            if n.get("ip") in ips or n["mac"] in macs:
                node_dev[n["mac"]] = d["id"]
    claimed_ips = set(dev_by_ip)
    claimed_macs = {m for x in per_dev.values() for m in x["macs"]}

    # --- a known device on a new address: a private Wi-Fi MAC rotates and the device takes a new lease.
    # Before it is called a stranger, and long before anything probes it, ask what it says about itself.
    entries = {}
    for key, r in (registry or {}).items():
        entries[key] = dict(r)
    for b in router.get("blockList") or []:
        if b["mac"] not in claimed_macs and not any(e.get("mac") == b["mac"] for e in entries.values()):
            entries["mac:" + b["mac"]] = {"ip": b.get("ip") if b.get("online") else None, "mac": b["mac"], "name": b.get("name"),
                                          "firstSeen": None, "lastSeen": None, "blockListOnly": True}
    tailscale = net.get("tailscale") or {}
    by_name, by_ts_ip = {}, {}
    for d in devices:
        for n in device_names(d):
            by_name.setdefault(n, set()).add(d["id"])
        for n in d.get("net") or []:
            if n.get("if") == "tailscale" and n.get("ip"):
                by_ts_ip.setdefault(n["ip"], set()).add(d["id"])
    announcers = {}                       # specific name -> the hosts announcing it right now
    for ip, e in mdns.items():
        for h in e.get("hostnames") or []:
            if specific_name(h):
                announcers.setdefault(specific_name(h), set()).add(ip)
    for c in clients:
        if c.get("online"):
            for n in (c.get("hostname"), c.get("nickname")):
                if specific_name(n):
                    announcers.setdefault(specific_name(n), set()).add(c.get("ip") or c["mac"])
    for ip, t in tailscale.items():
        if specific_name(t.get("name")):
            announcers.setdefault(specific_name(t["name"]), set()).add(ip)
    # hands-off devices (data/site.json): their names and every MAC the inventory or the site file records for them
    hands_ids, hands_ips, hands_names = C.SITE.hands_off_all(inv)
    work_names = {s for s in (specific_name(n) for n in hands_names) if s} | \
        {n for d in devices if d["id"] in hands_ids for n in device_names(d)}
    work_macs = {oui.normalize(m) for m in C.SITE.hands_off_macs()} | \
        {oui.normalize(m) for d in devices if d["id"] in hands_ids
         for m in [n.get("mac") for n in d.get("net") or []] + MAC_IN_TEXT.findall(json.dumps(d.get("facts") or {})) if m}
    guarded_ips = set()                   # looks like the work laptop, even when the match is not unique: never scanned
    out["rematched"] = {}
    for key, r in sorted(entries.items()):
        ip, mac = r.get("ip"), oui.normalize(r.get("mac") or "")
        if (ip and ip in claimed_ips) or (mac and mac in claimed_macs):
            continue
        rc = (by_mac.get(mac) if mac else None) or (by_ip.get(ip) if ip else None)
        mac = mac or (rc or {}).get("mac")
        names = passive_names(ip, rc, r, mdns, tailscale)
        if ip and (mac in work_macs or any(n in work_names for _, n in names)):
            guarded_ips.add(ip)
        did, basis = passive_match(names, (tailscale.get(ip) or {}).get("ips") if ip else None, by_name, by_ts_ip, announcers)
        if not did:
            continue
        x = per_dev[did]
        if ip and ip not in x["ips"]:
            x["ips"].append(ip)
            dev_by_ip.setdefault(ip, did)
            claimed_ips.add(ip)
        if mac and mac not in x["macs"]:
            x["macs"].append(mac)
            claimed_macs.add(mac)
        if rc and rc not in x["rcs"]:
            x["rcs"].append(rc)
        out["rematched"].setdefault(did, []).append({"ip": ip, "mac": mac, "basis": basis})

    def finish(did, dev, ips, names, macs, rcs, dynamic=False, first_seen=None, reg=None):
        rc = next((c for c in rcs if c.get("online")), rcs[0] if rcs else None)
        ip = next((i for i in ips if i in hosts), ips[0] if ips else None)
        deep = {}
        for i in ips:                        # one device, several addresses: pool what was found
            d0 = hosts.get(i) or {}
            if not deep:
                deep = dict(d0)
            else:
                deep["ports"] = sorted({p["port"]: p for p in (deep.get("ports") or []) + (d0.get("ports") or [])}.values(), key=lambda p: p["port"])
                deep["http"] = (deep.get("http") or []) + (d0.get("http") or [])
                for k in ("cast", "hue", "rdns", "coap"):
                    deep.setdefault(k, d0.get(k))
        md = {"hostnames": [], "services": []}
        for i in ips:
            e = mdns.get(i) or {}
            md["hostnames"] += [h for h in e.get("hostnames") or [] if h not in md["hostnames"]]
            md["services"] += e.get("services") or []
        sd = next((ssdp[i] for i in ips if i in ssdp), None)
        res = results.get(did) or {}
        facts = res.get("facts") or {}
        own_bt = facts.get("bluetooth")
        all_names = list(dict.fromkeys(names + [x for c in rcs for x in (c.get("nickname"), c.get("hostname")) if x] +
                                       md["hostnames"] + ([deep["rdns"]] if deep.get("rdns") else [])))
        ha_hit, ha_named = ha_matches(dev if not dynamic else None, macs, all_names)
        node = next((n for n in nodes if node_dev.get(n["mac"]) == did), None)
        ident = build_identity(dev=None if dynamic else dev, specs=specs_fn(did) if (specs_fn and not dynamic) else None,
                               ips=ips, macs=macs, names=all_names, router_client=dict(rc, _ts=router.get("ts")) if rc else None,
                               router_node=node, mdns=md, ssdp=sd, deep=deep, ha=ha_hit, ha_by_name=ha_named,
                               bluetooth=own_bt, bt_namesake=None if own_bt else namesake(all_names, own_bt), live_facts=facts)
        out["identities"][did] = ident
        blocked = any(m in blocked_macs for m in macs)
        out["security"][did] = score_security(
            ident, deep=deep, dynamic=dynamic, first_seen=first_seen, blocked=blocked,
            named=bool([n for n in all_names if n]) or not dynamic, ssdp=sd,
            posture=router.get("posture") if (node and node.get("main")) else None,
            scheduled=any(m in sched_macs for m in macs))
        out["addresses"][did] = {"ips": ips, "macs": macs, "names": all_names[:8]}
        # --- wireless
        wc = next((c for c in rcs if c.get("online") and c.get("medium") == "wifi"), None)
        w = None
        if wc and not (node and node.get("main")):
            ap, _ = ap_for(wc.get("node"))
            w = {"ap": ap, "band": wc.get("bandLabel"), "rssi": wc.get("rssi"), "ssid": wc.get("ssid"), "source": "router",
                 "rxRateMbps": wc.get("rxRateMbps"), "txRateMbps": wc.get("txRateMbps"), "channel": wc.get("channel"),
                 "evidence": "The router lists it as a Wi-Fi client of %s." % ((dev_name.get(ap) or "that unit") if ap else "a mesh unit this app cannot place")}
            if not router_fresh:
                w["stale"] = True
        elif node and not node.get("main") and (node.get("uplink") or {}).get("medium") == "wifi":
            up = node["uplink"]
            ap = node_dev.get(up.get("to"))
            w = {"ap": ap, "band": up.get("bandLabel"), "rssi": up.get("rssi"), "ssid": None, "source": "router", "backhaul": True,
                 "evidence": "The router lists this node's wireless backhaul to it."}
        elif (deep.get("cast") or {}).get("bssid") and not (deep.get("cast") or {}).get("ethernet"):
            c = deep["cast"]
            ap, how = ap_for(c["bssid"])
            w = {"ap": ap, "band": None, "rssi": c.get("signal"), "ssid": c.get("ssid"), "source": "cast",
                 "evidence": ("It reports access point %s, " % c["bssid"]) + (
                     "one of %s's radios." % dev_name.get(ap, ap) if how == "router" else
                     "which is within 16 addresses of the one in %s's host name: a strong hint, not a reading from the router." % dev_name.get(ap, ap)
                     if ap else "which this app cannot match to a mesh unit.")}
        elif not dynamic and not node and any(n.get("medium") == "wifi" for n in dev.get("net") or []) and \
                not any(n.get("medium") == "ethernet" and n.get("ip") for n in dev.get("net") or []):
            n = next(n for n in dev.get("net") or [] if n.get("medium") == "wifi")
            ap = n.get("ap") if n.get("ap") in dev_name else None
            w = {"ap": ap, "band": n.get("band"), "rssi": n.get("rssi"), "ssid": n.get("ssid"), "source": "inventory",
                 "evidence": ("Recorded in the inventory (%s); not read from the router just now." % n.get("apBasis")) if ap and n.get("apBasis")
                 else "The inventory says it is on Wi-Fi. Which mesh unit it uses is not known."}
        if w:
            out["wireless"][did] = w
            status = (res.get("status") if not dynamic else None)
            out["wifiLinks"].append({
                "id": "w-" + did, "from": did, "to": w["ap"], "cable": "wifi", "carries": ["network"], "synthetic": True,
                "ap": "known" if w["ap"] else "unknown", "band": w.get("band"), "rssi": w.get("rssi"), "ssid": w.get("ssid"),
                "verified": "live" if w["source"] in ("router", "cast") else "plan", "evidence": w["evidence"],
                **({"backhaul": True} if w.get("backhaul") else {})})
            bits = []
            if w.get("ssid"):
                bits.append("on %s" % w["ssid"])
            if w.get("ap"):
                bits.append("through %s" % dev_name.get(w["ap"], w["ap"]))
            if w.get("band"):
                bits.append(w["band"])
            if w.get("rssi") is not None:
                bits.append("signal %s dBm" % w["rssi"])
            speed = ("%g Mb/s" % w["rxRateMbps"]) if w.get("rxRateMbps") else None
            out["linkLive"]["w-" + did] = {"_status_of": did, "speed": speed,
                                           "detail": ("Wi-Fi " + ", ".join(bits)) if bits else w["evidence"]}
        if wc and wc.get("traffic"):
            out["traffic"][did] = wc["traffic"]
        return ident, rc

    dev_name = {d["id"]: d.get("name") or d["id"] for d in devices}
    work_ips = set(hands_ips)
    for d in devices:
        x = per_dev[d["id"]]
        res = results.get(d["id"]) or {}
        finish(d["id"], d, x["ips"], x["names"], x["macs"], x["rcs"])
        if d["id"] in hands_ids:
            work_ips.update(x["ips"])        # a hands-off device (data/site.json) is never port-scanned on our own initiative
        elif res.get("status") in ("online", "degraded"):
            out["scanIps"] += [ip for ip in x["ips"] if ip not in out["scanIps"]]

    # --- hosts the inventory does not list (entries, built above, less the ones matched to a device)
    for key, r in sorted(entries.items()):
        ip, mac = r.get("ip"), oui.normalize(r.get("mac") or "")
        if (ip and ip in claimed_ips) or (mac and mac in claimed_macs):
            continue
        rc = (by_mac.get(mac) if mac else None) or (by_ip.get(ip) if ip else None)
        if rc and not mac:
            mac = rc["mac"]
            if mac in claimed_macs:
                continue
        did = host_id(ip, mac)
        if did in out["identities"]:
            continue
        ips = [ip] if ip else []
        names = [r.get("name")] if r.get("name") else []
        first = r.get("firstSeen") or engine.first_seen(mac or ip)
        ident, rc = finish(did, None, ips, names, [mac] if mac else [], [rc] if rc else [], dynamic=True, first_seen=first, reg=r)
        nick = (rc or {}).get("nickname") or (rc or {}).get("hostname") or r.get("name") or \
            next((n for n in out["addresses"][did]["names"] if n), None)
        label = nick or ("Device at %s" % ip if ip else "Device %s" % mac)   # the not-identified flag says the rest
        netent = {k: v for k, v in (("ip", ip), ("mac", mac), ("medium", (rc or {}).get("medium")), ("name", (rc or {}).get("hostname") or r.get("name"))) if v}
        out["dynamic"].append({"id": did, "name": label, "kind": ident.get("type") if ident["state"] != "unidentified" and ident.get("type") else "unknown",
                               "zone": "unplaced", "dynamic": True, "verified": "live",
                               "vendor": ident.get("vendor") or "", "model": ident.get("model") or "",
                               "net": [netent] if netent else [], "firstSeen": first, "lastSeen": r.get("lastSeen")})
        online = bool(rc and rc.get("online")) if router_fresh and rc else None
        out["hostLive"][did] = {"ip": ip, "mac": mac, "routerOnline": online, "name": label,
                                "blockListOnly": bool(r.get("blockListOnly")),
                                "connection": ("Wi-Fi" if (rc or {}).get("medium") == "wifi" else "wired" if (rc or {}).get("medium") == "ethernet" else None)}
        if ip and ip not in work_ips and ip not in self_ips and ip not in guarded_ips:
            out["scanIps"].append(ip)
    out["scanIps"] = [ip for ip in dict.fromkeys(out["scanIps"]) if ip not in work_ips and ip not in guarded_ips]
    return out


def merge_inventory(inv, doc):
    """inventory.json as served: plus the hosts that are not in it, the Wi-Fi links and every device's identity."""
    doc = doc or {}
    ids = {d["id"] for d in inv.get("devices") or []}
    inv["devices"] = list(inv.get("devices") or []) + [dict(d) for d in doc.get("dynamic") or [] if d["id"] not in ids]
    ids = {d["id"] for d in inv["devices"]}
    lids = {l["id"] for l in inv.get("links") or []}
    inv["links"] = list(inv.get("links") or []) + [dict(l) for l in doc.get("wifiLinks") or []
                                                   if l["id"] not in lids and l["from"] in ids and (l["to"] is None or l["to"] in ids)]
    idents = doc.get("identities") or {}
    for d in inv["devices"]:
        d["identity"] = idents.get(d["id"]) or dict(base_identity(None if d.get("dynamic") else d, None),
                                                    mac=None, macVendor=None, randomizedMac=False, evidence=[], candidates=[])
    if not any(z.get("id") == "unplaced" for z in inv.get("zones") or []) and any(d.get("zone") == "unplaced" for d in inv["devices"]):
        inv["zones"] = list(inv.get("zones") or []) + [{"id": "unplaced", "name": "Not placed yet", "note": "Seen on the network; where it is in the house is not known."}]
    return inv


def load_picture():
    try:
        with open(os.path.join(C.state_dir(), "identity.json")) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def served_inventory():
    inv = merge_inventory(C.wired_inventory(), load_picture())
    for d in inv.get("devices") or []:
        seen = d.get("usbSeen") or d.get("displaySeen")
        if seen:        # plugged into one of the computers, not in the inventory: the device names itself
            d["identity"] = {"state": "likely", "type": d.get("kind"), "vendor": seen.get("vendor"), "model": seen.get("name"),
                             "mac": None, "macVendor": None, "randomizedMac": False, "candidates": [],
                             "evidence": [_ev("usb" if d.get("usbSeen") else "display", "Name the device gives itself",
                                               "%s%s, plugged into %s" % (seen.get("name"), (" by " + seen["vendor"]) if seen.get("vendor") else "", seen.get("by")),
                                               seen.get("firstSeen"))]}
    return inv


# ================================================================ security

def score_security(identity, deep=None, dynamic=False, first_seen=None, blocked=False, named=True, ssdp=None,
                   posture=None, scheduled=False, now=None):
    """`security` of the contract: level, score and reasons in plain words."""
    now = now or time.time()
    deep = deep or {}
    reasons, score = [], 0

    def add(code, text, pts):
        nonlocal score
        reasons.append({"code": code, "text": text})
        score += pts
    state = (identity or {}).get("state")
    if state == "unidentified":
        add("unidentified", "Nothing has established what this is yet.", 25)
    if dynamic:
        add("not-in-inventory", "It is on the network but not in the inventory.", 15)
        try:
            age = now - datetime.datetime.fromisoformat(first_seen).timestamp()
        except Exception:
            age = None
        if age is not None and age < NEW_WINDOW:
            add("new", "It is new: first seen %s." % first_seen[:16].replace("T", " at "), 15)
    if (identity or {}).get("randomizedMac") and not named and state != "confirmed":
        add("random-mac", "It uses a private (randomised) address and gives no name, so nothing ties it to a known device.", 15)
    open_ports = []
    for p in deep.get("ports") or []:
        info = PORTS.get(p["port"], ("unknown", False, None))
        open_ports.append({"port": p["port"], "service": info[0], "risky": bool(info[1])})
        if info[1]:
            add("port-" + info[0], "Port %d is open: %s." % (p["port"], info[2]), 30 if info[0] in ("telnet", "adb") else 20)
    for f in deep.get("http") or []:
        if f.get("status") == 200 and not f.get("auth") and not f.get("passwordField") and f.get("title") and \
                re.search(r"admin|config|setup|settings|control|management|camera|router|status", f["title"], re.I):
            add("open-web-page", "A web page titled “%s” on port %s opens without asking for a password." % (f["title"], f["port"]), 10)
            break
    if ssdp and (ssdp.get("description") or {}).get("igd"):
        add("upnp-gateway", "It offers UPnP port mapping: any device inside can ask it to open a port to the internet.", 10)
    for key, code, text, pts in (
            ("wanAdmin", "router-wan-admin", "The router's setting “web access from WAN” is on (misc_http_x=1): its admin page can be reached from the internet.", 20),
            ("telnet", "router-telnet", "Telnet is switched on at the router.", 30),
            ("upnp", "router-upnp", "UPnP is on at the router: devices inside can open ports to the internet by themselves.", 10),
            ("wps", "router-wps", "WPS is on at the router (wps_enable=1): a known weak way to join the Wi-Fi.", 10),
            ("firmwareUpdate", "router-firmware", "The router says newer firmware is available.", 10)):
        if (posture or {}).get(key):
            add(code, text, pts)
    if scheduled:
        add("time-limited", "The router limits its internet access by a time schedule.", 0)
    if blocked:
        reasons.insert(0, {"code": "blocked", "text": "Its internet access is blocked at the router."})
    score = min(100, score)
    level = "blocked" if blocked else "suspicious" if score >= 50 else "watch" if score >= 20 else "ok"
    return {"level": level, "score": score, "reasons": reasons, "openPorts": open_ports, "firstSeen": first_seen,
            "blocked": bool(blocked)}
