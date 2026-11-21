#!/usr/bin/env python3
"""Read-only discovery of the home network, for onboarding and rescans.

    python3 discover.py                 readable summary, writes data/state/discovery.json
    python3 discover.py --json          the whole document on stdout
    python3 discover.py --diff          also compare with the previous discovery and data/inventory.json
    python3 discover.py --force         allow a sweep larger than a /22
    python3 discover.py --no-ports      skip the TCP port check
    python3 discover.py --quick         skip the slow parts of this Mac's own reading (USB, Bluetooth, cables)

Standard library only, Python 3.9+. Everything here only reads: it pings, sends one mDNS and one SSDP query,
opens TCP connections to a short list of ports, makes HTTP GETs to landing pages and device descriptions, and
runs fixed read-only macOS commands. It never logs into anything and never writes anything except the
discovery file (`$HM_STATE_DIR/discovery.json`, default `data/state/discovery.json`).

Every fact carries the probe that produced it (`source`), because the inventory's evidence levels depend on it:
a host that answered ping is `live`; a product name is a claim only when the device itself said it (SSDP
description, mDNS TXT record, the Cast API); a MAC prefix, a hostname or an open port is only a lead.
"""
import concurrent.futures
import datetime
import ipaddress
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

import oui  # noqa: E402
import site_config as S  # noqa: E402

VERSION = 1
MAX_PREFIX_DEFAULT = 22                 # refuse to sweep more than a /22 (1022 hosts) without --force
PORTS = (22, 53, 80, 443, 445, 554, 631, 1400, 5000, 8008, 8009, 8080, 8123, 8443, 9100)
PORT_NAMES = {22: "ssh", 53: "dns", 80: "http", 443: "https", 445: "smb", 554: "rtsp", 631: "ipp", 1400: "sonos",
              5000: "http-alt", 8008: "cast", 8009: "cast-tls", 8080: "http-alt", 8123: "home-assistant",
              8443: "https-alt", 9100: "printer-raw"}
MDNS_TYPES = ("_airplay._tcp", "_googlecast._tcp", "_hap._tcp", "_hue._tcp", "_ipp._tcp", "_printer._tcp", "_smb._tcp",
              "_ssh._tcp", "_raop._tcp", "_companion-link._tcp", "_homekit._tcp", "_matter._tcp",
              "_spotify-connect._tcp", "_sonos._tcp", "_workstation._tcp")
MDNS_SECONDS = 5.0
SSDP_SECONDS = 3.0
UA = "home-observability-hub-discover/%d" % VERSION


# ================================================================ small helpers

def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def state_dir():
    return os.environ.get("HM_STATE_DIR") or os.path.join(ROOT, "data", "state")


def out_path():
    return os.path.join(state_dir(), "discovery.json")


def inventory_path():
    return os.environ.get("HM_INVENTORY") or os.path.join(ROOT, "data", "inventory.json")


def run(argv, timeout=8):
    """(rc, stdout, stderr). Never raises, never uses a shell."""
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, text=True, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except Exception as e:
        return 127, "", str(e)


def norm_mac(s):
    """'a:b:c:1:2:3' (arp drops leading zeros) or 'AA-BB-…' -> 'AA:BB:CC:01:02:03'. None when not a MAC."""
    if not isinstance(s, str):
        return None
    parts = re.split(r"[:-]", s.strip())
    if len(parts) == 6 and all(re.match(r"^[0-9A-Fa-f]{1,2}$", p) for p in parts):
        return ":".join(p.zfill(2).upper() for p in parts)
    return oui.normalize(s)


def ev(value, source, **extra):
    d = {"value": value, "source": source}
    d.update(extra)
    return d


class Budget:
    """One deadline for the whole run, so a slow network cannot hold it past ~90 s."""

    def __init__(self, seconds):
        self.end = time.time() + seconds

    def left(self, cap=None):
        x = max(0.0, self.end - time.time())
        return min(x, cap) if cap is not None else x


# ================================================================ this Mac

def parse_hardware_ports(text):
    """`networksetup -listallhardwareports` -> [{port, device, mac}]."""
    out = []
    for m in re.finditer(r"Hardware Port:\s*(.+)\nDevice:\s*(\S+)\n(?:Ethernet Address:\s*(\S+))?", text or ""):
        out.append({"port": m.group(1).strip(), "device": m.group(2).strip(), "mac": norm_mac(m.group(3) or "")})
    return out


def medium_of(port_name):
    p = (port_name or "").lower()
    if "wi-fi" in p or "airport" in p or "wlan" in p:
        return "wifi"
    if "bridge" in p:
        return "bridge"
    if "bluetooth" in p:
        return "bluetooth"
    if "thunderbolt" in p and "ethernet" not in p:
        return "thunderbolt"
    if "ethernet" in p or "lan" in p or "10/100" in p or "gigabit" in p:
        return "ethernet"
    if "iphone" in p or "usb" in p:
        return "usb"
    return "other"


def parse_ifconfig(text):
    """One interface's `ifconfig` -> {status, ipv4, netmaskPrefix, mac, media, speedRaw}."""
    d = {}
    m = re.search(r"status:\s*(\S+)", text or "")
    d["status"] = m.group(1) if m else None
    m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", text or "")
    if m:
        d["ipv4"] = m.group(1)
        d["prefix"] = bin(int(m.group(2), 16)).count("1")
    m = re.search(r"\bether ([0-9a-fA-F:]{11,17})", text or "")
    d["mac"] = norm_mac(m.group(1)) if m else None
    m = re.search(r"media:\s*(.+)", text or "")
    d["media"] = m.group(1).strip() if m else None
    sm = re.search(r"\(([^)<\s]+)\s*(?:<([^>]*)>)?\)", d["media"] or "")
    d["speedRaw"] = sm.group(1) if sm and sm.group(1) not in ("none", "autoselect") else None
    return d


def speed_label(raw):
    if not raw:
        return None
    m = re.match(r"(\d+)\s*[Bb]ase", raw)
    if not m:
        return raw
    mbps = int(m.group(1))
    return ("%gG" % (mbps / 1000.0)) if mbps >= 1000 else "%dM" % mbps


def parse_ssid(networksetup_out, summary_out):
    """The Wi-Fi network name, or (None, why). macOS hides it from tools that lack Location Services access."""
    m = re.search(r"Current Wi-Fi Network:\s*(.+)", networksetup_out or "")
    if m and m.group(1).strip() and "<redacted>" not in m.group(1):
        return m.group(1).strip(), "networksetup -getairportnetwork"
    m = re.search(r"^\s*SSID\s*:\s*(.+)$", summary_out or "", re.M)
    if m and m.group(1).strip() and "<redacted>" not in m.group(1):
        return m.group(1).strip(), "ipconfig getsummary"
    return None, None


def this_mac(quick=False, budget=None):
    """What this Mac says about itself. No serial numbers."""
    srcs = {}
    out = {"os": "macOS " + (platform.mac_ver()[0] or "?"), "python": platform.python_version()}
    rc, model, _ = run(["/usr/sbin/sysctl", "-n", "hw.model"], timeout=4)
    out["model"] = model.strip() or None
    srcs["model"] = "sysctl hw.model"
    rc, sp, _ = run(["/usr/sbin/system_profiler", "SPHardwareDataType", "-json"], timeout=20)
    try:
        hw = (json.loads(sp or "{}").get("SPHardwareDataType") or [{}])[0]
        out["modelName"] = hw.get("machine_name")
        out["chip"] = hw.get("chip_type") or hw.get("cpu_type")
        out["memory"] = hw.get("physical_memory")
        out["modelNumber"] = hw.get("model_number")
        srcs["modelName"] = "system_profiler SPHardwareDataType"
    except ValueError:
        pass
    for key, argv in (("computerName", ["/usr/sbin/scutil", "--get", "ComputerName"]),
                      ("localHostName", ["/usr/sbin/scutil", "--get", "LocalHostName"])):
        rc, t, _ = run(argv, timeout=4)
        out[key] = t.strip() or None
    out["hostname"] = socket.gethostname()
    srcs["computerName"] = "scutil --get ComputerName"

    rc, hp, _ = run(["/usr/sbin/networksetup", "-listallhardwareports"], timeout=8)
    ifaces = []
    wifi_if = None
    for h in parse_hardware_ports(hp):
        rc, t, _ = run(["/sbin/ifconfig", h["device"]], timeout=4)
        if rc != 0:
            continue
        i = parse_ifconfig(t)
        med = medium_of(h["port"])
        if med == "wifi":
            wifi_if = h["device"]
        ifaces.append({"if": h["device"], "hardwarePort": h["port"], "medium": med, "status": i.get("status"),
                       "ip": i.get("ipv4"), "mac": h["mac"] or i.get("mac"),
                       "randomizedMac": oui.is_randomized(h["mac"] or i.get("mac") or ""),
                       "macVendor": oui.vendor(h["mac"] or i.get("mac") or ""),
                       "speed": speed_label(i.get("speedRaw")) if med == "ethernet" else None,
                       "media": i.get("media"), "source": "networksetup -listallhardwareports + ifconfig"})
    # Wi-Fi uses a private address per network: ifconfig shows the one in use, the hardware port list the burned-in one.
    for i in ifaces:
        if i["medium"] == "wifi":
            rc, t, _ = run(["/sbin/ifconfig", i["if"]], timeout=4)
            cur = parse_ifconfig(t).get("mac")
            if cur and cur != i["mac"]:
                i["hardwareMac"], i["mac"] = i["mac"], cur
                i["randomizedMac"] = oui.is_randomized(cur)
                i["macVendor"] = oui.vendor(cur)
    out["interfaces"] = ifaces
    wifi = {"if": wifi_if, "ssid": None, "source": None}
    if wifi_if:
        rc1, a, _ = run(["/usr/sbin/networksetup", "-getairportnetwork", wifi_if], timeout=5)
        rc2, b, _ = run(["/usr/sbin/ipconfig", "getsummary", wifi_if], timeout=5)
        wifi["ssid"], wifi["source"] = parse_ssid(a, b)
        if not wifi["ssid"]:
            wifi["note"] = ("macOS did not give the Wi-Fi name to a command-line tool (it needs Location Services, or "
                            "the Mac is not on Wi-Fi). Ask the person, or read it in System Settings, Wi-Fi.")
    out["wifi"] = wifi
    out["sources"] = srcs

    if quick:
        out["usb"] = out["displays"] = out["bluetooth"] = out["cables"] = None
        out["skipped"] = "USB, displays, Bluetooth and cables (--quick)"
        return out
    try:
        import collectors as C
    except Exception as e:      # collectors is the server's module; discovery must not die with it
        C = None
        out["collectorsError"] = "%s: %s" % (type(e).__name__, e)

    def usb():
        rows = C.usb_devices(fresh=True)
        return [{"name": u.get("name"), "vendorId": u.get("vendorId"), "productId": u.get("productId"),
                 "vendor": u.get("vendor"), "linkSpeed": u.get("linkSpeed"), "behind": u.get("parent"),
                 "source": "system_profiler SPUSBHostDataType"} for u in rows]

    def disp():
        return [dict(d, source="system_profiler SPDisplaysDataType") for d in C.displays(fresh=True)]

    def bt():
        rows = C.bluetooth_devices(fresh=True)
        return [{"name": b.get("name"), "address": b.get("address"), "connected": b.get("connected"),
                 "minorType": b.get("minorType"), "vendor": oui.peripheral_vendor(b.get("vendorId")),
                 "vendorId": b.get("vendorId"), "productId": b.get("productId"),
                 "source": "system_profiler SPBluetoothDataType"} for b in rows]

    def cables():
        import portscan
        o = portscan.observe()
        o["source"] = "portscan.py (ioreg IOPort + USB tree)"
        return o
    jobs = {"usb": usb, "displays": disp, "bluetooth": bt, "cables": cables} if C else {"cables": cables}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futs = {k: ex.submit(f) for k, f in jobs.items()}
        for k, f in futs.items():
            try:
                out[k] = f.result(timeout=budget.left(40) if budget else 40)
            except Exception as e:
                out[k] = None
                out.setdefault("errors", {})[k] = "%s: %s" % (type(e).__name__, str(e)[:160])
    return out


# ================================================================ sweep and ARP

def ping(ip, timeout_s=1):
    rc, out, _ = run(["/sbin/ping", "-c", "1", "-t", str(timeout_s), "-n", ip], timeout=timeout_s + 2)
    if rc == 0:
        m = re.search(r"time[=<]([\d.]+)\s*ms", out)
        return True, (round(float(m.group(1)), 1) if m else None)
    return False, None


def sweep(net, workers=96):
    """{ip: latency_ms} for every address that answers one ping."""
    found = {}

    def one(ip):
        return (ip,) + ping(ip)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for ip, ok, ms in ex.map(one, [str(h) for h in net.hosts()]):
            if ok:
                found[ip] = ms
    return found


ARP_RE = re.compile(r"^\S+\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)(?:\s+on\s+(\S+))?(.*)$")


def parse_arp(text):
    """`arp -an` -> {"entries": {ip: {mac, if}}, "status": ok|empty|redacted|partial, "redacted": n, "incomplete": n}.

    Recent macOS versions print nothing, or print the neighbours with the hardware address hidden.
    Both are reported as they are; nothing is invented to fill the gap."""
    entries, redacted, incomplete = {}, 0, 0
    for line in (text or "").splitlines():
        m = ARP_RE.match(line.strip())
        if not m:
            continue
        ip, hw, ifn, rest = m.group(1), m.group(2), m.group(3), m.group(4) or ""
        if hw == "(incomplete)" or "incomplete" in hw:
            incomplete += 1
            continue
        mac = norm_mac(hw)
        if not mac:
            redacted += 1
            entries.setdefault(ip, {"mac": None, "if": ifn, "redacted": True})
            continue
        if mac in ("FF:FF:FF:FF:FF:FF",) or mac.startswith("01:00:5E"):
            continue
        entries[ip] = {"mac": mac, "if": ifn, "permanent": "permanent" in rest}
    real = sum(1 for e in entries.values() if e.get("mac"))
    if not entries:
        status = "empty"
    elif real == 0:
        status = "redacted"
    elif redacted:
        status = "partial"
    else:
        status = "ok"
    return {"entries": entries, "status": status, "redacted": redacted, "incomplete": incomplete, "withMac": real}


ARP_NOTES = {
    "empty": "arp -an printed nothing (some macOS versions do this). MAC addresses then come only from mDNS, SSDP, the "
             "Cast API or the router.",
    "redacted": "arp -an lists the neighbours but macOS hides their MAC addresses. MAC addresses then come only from "
                "mDNS, SSDP, the Cast API or the router.",
    "partial": "Some neighbours in arp -an have their MAC address hidden.",
}


# ================================================================ mDNS

def _dns_name(buf, off, depth=0):
    labels, jumped, end = [], False, off
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
            if not jumped:
                end = off + 2
            jumped = True
            off = ((n & 0x3F) << 8) | buf[off + 1]
            depth += 1
            continue
        off += 1
        labels.append(buf[off:off + n].decode("utf-8", "replace"))
        off += n
    return ".".join(labels), (end if jumped else off)


def parse_dns(buf):
    """[(name, type, rdata)] for PTR, SRV, TXT and A records of one DNS message. Never raises."""
    out = []
    try:
        _, _, qd, an, ns, ar = struct.unpack("!6H", buf[:12])
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
                out.append((name, "SRV", (_dns_name(buf, rd + 6)[0], struct.unpack("!H", buf[rd + 4:rd + 6])[0])))
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


def dns_query(questions, unicast=False):
    pkt = struct.pack("!6H", 0, 0, len(questions), 0, 0, 0)
    for name, qtype in questions:
        for lab in name.rstrip(".").split("."):
            b = lab.encode("utf-8")[:63]
            pkt += bytes([len(b)]) + b
        pkt += b"\x00" + struct.pack("!2H", qtype, 1 | (0x8000 if unicast else 0))
    return pkt


def _strip_local(n):
    return n[:-6] if n.lower().endswith(".local") else n


def assemble_mdns(records, net=None):
    """[(src_ip, name, type, rdata)] -> {ip: {hostnames, services: [{type, instance, port, txt}]}}.
    Only addresses inside `net` are kept (when given)."""
    def ok(ip):
        try:
            return net is None or ipaddress.ip_address(ip) in net
        except ValueError:
            return False
    addr = {}
    for _, name, typ, rd in records:
        if typ == "A" and ok(rd):
            addr.setdefault(name.lower(), rd)
    srv = {n: rd for _, n, t, rd in records if t == "SRV"}
    txt = {}
    for _, n, t, rd in records:
        if t == "TXT":
            txt.setdefault(n, {}).update(rd)
    inst = {}
    for src, name, typ, rd in records:
        if typ == "PTR" and not name.lower().startswith("_services.") and not name.lower().endswith(".arpa"):
            inst.setdefault(rd, {"type": _strip_local(name), "src": src})
    out = {}
    for name, ip in addr.items():
        e = out.setdefault(ip, {"hostnames": [], "services": []})
        h = _strip_local(name)
        if h not in e["hostnames"]:
            e["hostnames"].append(h)
    for name, meta in inst.items():
        target, port = srv.get(name, (None, None))
        ip = addr.get((target or "").lower()) or meta["src"]
        if not ip or not ok(ip):
            continue
        suffix = "." + meta["type"].lower() + ".local"
        label = name[:-len(suffix)] if name.lower().endswith(suffix) else name
        e = out.setdefault(ip, {"hostnames": [], "services": []})
        if not any(x["type"] == meta["type"] and x["instance"] == label for x in e["services"]):
            e["services"].append({"type": meta["type"], "instance": label, "port": port, "txt": txt.get(name, {})})
    return out


def local_ip_toward(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((ip, 9))
        a = s.getsockname()[0]
        s.close()
        return a
    except OSError:
        return None


def mdns_discover(ifip, net, types=MDNS_TYPES, seconds=MDNS_SECONDS):
    """Ask once for each service type, then for the addresses behind them. Raises OSError when the network
    will not let us send (macOS Local Network permission, or a sandbox)."""
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
    recs = []

    def send(qs):
        for i in range(0, len(qs), 12):
            s.sendto(dns_query(qs[i:i + 12], unicast=not shared), ("224.0.0.251", 5353))

    def listen(sec):
        end = time.time() + sec
        while True:
            left = end - time.time()
            if left <= 0:
                return
            s.settimeout(left)
            try:
                data, a = s.recvfrom(9000)
            except (socket.timeout, OSError):
                return
            for name, typ, rd in parse_dns(data):
                recs.append((a[0], name, typ, rd))
    try:
        send([(t + ".local", 12) for t in types])
        listen(seconds * 0.6)
        inst = {rd for _, n, t, rd in recs if t == "PTR"}
        have_srv = {n for _, n, t, _ in recs if t == "SRV"}
        follow = [(n, 33) for n in inst if n not in have_srv] + [(n, 16) for n in inst if n not in have_srv]
        if follow:
            send(follow[:200])
            listen(seconds * 0.25)
        have_a = {n.lower() for _, n, t, _ in recs if t == "A"}
        targets = sorted({rd[0] for _, _, t, rd in recs if t == "SRV" and rd[0].lower() not in have_a})
        if targets:
            send([(t, 1) for t in targets][:200])
            listen(seconds * 0.15)
    finally:
        s.close()
    return assemble_mdns(recs, net)


DNSSD_RE = re.compile(r"^\s*\S+\s+(Add|Rmv)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+?)\s*$")


def parse_dnssd_browse(text):
    """`dns-sd -B <type>` lines -> [{type, instance}] (Add rows only). No addresses: dns-sd -B does not resolve."""
    seen, out = set(), []
    for line in (text or "").splitlines():
        m = DNSSD_RE.match(line)
        if not m or m.group(1) != "Add":
            continue
        typ = m.group(5).rstrip(".")
        if typ.endswith(".local"):
            typ = typ[:-6]
        inst = m.group(6)
        if (typ, inst) not in seen:
            seen.add((typ, inst))
            out.append({"type": typ, "instance": inst})
    return out


def dnssd_browse(types=MDNS_TYPES, seconds=3.0):
    """Fallback when the raw socket is refused: one `dns-sd -B` per type in parallel, killed after `seconds`."""
    def one(t):
        try:
            p = subprocess.Popen(["/usr/bin/dns-sd", "-B", t, "local."], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, text=True, start_new_session=True)
        except Exception:
            return ""
        try:
            out, _ = p.communicate(timeout=seconds)
        except subprocess.TimeoutExpired:
            p.kill()
            out, _ = p.communicate(timeout=2)
        return out or ""
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(types)) as ex:
        return parse_dnssd_browse("\n".join(ex.map(one, types)))


# ================================================================ SSDP

def parse_ssdp_response(data):
    """One SSDP reply (bytes or str) -> {server, st, usn, location} with only the keys present."""
    if isinstance(data, bytes):
        data = data.decode("utf-8", "replace")
    lines = data.split("\r\n") if "\r\n" in data else data.split("\n")
    if not lines or not re.match(r"^(HTTP/1\.[01] 200|NOTIFY )", lines[0].strip(), re.I):
        return None
    hdr = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        if v and k.strip():
            hdr[k.strip().lower()] = v.strip()
    return {k: hdr[k][:200] for k in ("server", "st", "usn", "location") if hdr.get(k)}


def xml_tag(body, tag):
    m = re.search(r"<%s[^>]*>\s*([^<]{1,200}?)\s*</%s>" % (tag, tag), body or "", re.I)
    return m.group(1).strip() if m else None


def parse_device_description(body):
    d = {k: xml_tag(body, k) for k in ("friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription",
                                       "deviceType", "presentationURL")}
    d = {k: v for k, v in d.items() if v}
    if re.search(r"InternetGatewayDevice|WANIPConnection|WANPPPConnection", body or ""):
        d["igd"] = True
    return d


def location_ok(loc, ip):
    """Fetch a LOCATION only from the host that answered, only over plain HTTP."""
    m = re.match(r"^http://(\d+\.\d+\.\d+\.\d+)(?::\d+)?/[^\s<>\"']*$", loc or "")
    return bool(m and m.group(1) == ip)


def ssdp_discover(ifip, net, seconds=SSDP_SECONDS, fetch=True):
    """{ip: {servers, types, location, description}}"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    out = {}
    try:
        s.bind((ifip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ifip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        msg = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
        s.sendto(msg, ("239.255.255.250", 1900))
        time.sleep(0.2)
        s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + seconds
        while time.time() < end:
            s.settimeout(max(0.05, end - time.time()))
            try:
                data, a = s.recvfrom(4096)
            except (socket.timeout, OSError):
                break
            ip = a[0]
            try:
                if ipaddress.ip_address(ip) not in net:
                    continue
            except ValueError:
                continue
            r = parse_ssdp_response(data)
            if not r:
                continue
            e = out.setdefault(ip, {"servers": [], "types": [], "location": None, "description": {}})
            if r.get("server") and r["server"] not in e["servers"] and len(e["servers"]) < 4:
                e["servers"].append(r["server"])
            if r.get("st") and r["st"] not in e["types"] and len(e["types"]) < 24:
                e["types"].append(r["st"])
            if r.get("location") and not e["location"] and location_ok(r["location"], ip):
                e["location"] = r["location"]
    finally:
        s.close()
    if fetch:
        def get(item):
            ip, e = item
            if e["location"]:
                st, _, body = http_fetch(e["location"], timeout=3, limit=131072)
                if st == 200:
                    e["description"] = parse_device_description(body)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(get, list(out.items())))
    for e in out.values():
        if any("InternetGatewayDevice" in t or "WANIPConnection" in t for t in e["types"]):
            e["description"]["igd"] = True
    return out


# ================================================================ HTTP, ports, names

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def http_fetch(url, timeout=3.0, limit=65536):
    """(status, headers dict lower-case, body text). status None when nothing answered. Never follows redirects."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=ctx))
    try:
        try:
            r = opener.open(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=timeout)
        except urllib.error.HTTPError as e:
            r = e
        status = r.getcode()
        headers = {k.lower(): v for k, v in (r.headers.items() if r.headers else [])}
        try:
            body = r.read(limit).decode("utf-8", "replace")
        except Exception:
            body = ""
        r.close()
        return status, headers, body
    except Exception as e:
        return None, {}, "%s: %s" % (type(e).__name__, e)


def title_of(body):
    m = re.search(r"<title[^>]*>\s*([^<]{1,160})", body or "", re.I)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else None


def tcp_open(ip, port, timeout=0.6):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def port_check(ips, ports=PORTS, timeout=0.6, workers=96):
    """{ip: [open ports]} with a short connect timeout. Connects and closes; sends nothing."""
    pairs = [(ip, p) for ip in ips for p in ports]
    res = {ip: [] for ip in ips}

    def one(x):
        return x, tcp_open(x[0], x[1], timeout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for (ip, p), ok in ex.map(one, pairs):
            if ok:
                res[ip].append(p)
    return {ip: sorted(v) for ip, v in res.items()}


def rdns(ip, server=None, timeout=2):
    """Reverse DNS: the router's DNS first (it knows DHCP names), then the system resolver. (name, source)."""
    if server:
        rc, out, _ = run(["/usr/bin/dig", "+short", "+time=1", "+tries=1", "-x", ip, "@" + server], timeout=timeout + 1)
        names = [l.strip().rstrip(".") for l in out.splitlines() if l.strip() and not l.startswith(";")]
        if rc == 0 and names:
            return names[0], "reverse DNS at %s" % server
    box = []

    def go():
        try:
            box.append(socket.gethostbyaddr(ip)[0])
        except Exception:
            pass
    t = threading.Thread(target=go, daemon=True)
    t.start()
    t.join(timeout)
    if box and box[0] != ip:
        return box[0], "reverse DNS (system resolver)"
    return None, None


# ================================================================ the router at the gateway

# (family, brand, routerType, [(where, regex)]): where is title|server|realm|location|body|ssdp|vendor
ROUTER_RULES = [
    ("asuswrt", "ASUS", "asuswrt", [("name", r"zenwifi|^rt-a[cx]|^gt-a[cx]|^asus|^tuf-|^rog-"), ("title", r"\basus\b|asuswrt|zenwifi|rog rapture"), ("realm", r"\basus|rt-a[cx]|gt-a[cx]"),
                                    ("location", r"Main_Login\.asp"), ("body", r"Main_Login\.asp|asuswrt"),
                                    ("ssdp", r"asustek|zenwifi|\brt-a[cx]\d|\bgt-a[cx]\d"), ("vendor", r"^asustek")]),
    ("unifi", "Ubiquiti UniFi", "none", [("name", r"^unifi|^udm|^ubnt|^usg\b"), ("title", r"unifi"), ("ssdp", r"ubiquiti"), ("vendor", r"ubiquiti")]),
    ("fritzbox", "AVM FRITZ!Box", "none", [("name", r"fritz"), ("title", r"fritz!?\s*box"), ("server", r"fritz"), ("ssdp", r"\bavm\b|fritz"),
                                           ("vendor", r"^avm")]),
    ("orbi", "NETGEAR Orbi", "none", [("name", r"orbi"), ("title", r"\borbi\b"), ("realm", r"\borbi\b"), ("ssdp", r"\borbi\b|\brb[rks]\d")]),
    ("netgear", "NETGEAR", "none", [("name", r"netgear|routerlogin"), ("title", r"netgear"), ("realm", r"netgear"), ("ssdp", r"netgear"), ("vendor", r"netgear")]),
    ("tplink", "TP-Link", "none", [("name", r"tp-?link|^deco|^archer"), ("title", r"tp-?link|\bdeco\b|archer"), ("server", r"tp-?link"), ("ssdp", r"tp-?link"),
                                   ("vendor", r"tp-?link")]),
    ("linksys", "Linksys", "none", [("title", r"linksys"), ("ssdp", r"linksys"), ("vendor", r"linksys|belkin")]),
    ("mikrotik", "MikroTik", "none", [("name", r"mikrotik"), ("title", r"routeros|mikrotik"), ("server", r"mikrotik"), ("vendor", r"mikrotik|routerboard")]),
    ("openwrt", "OpenWrt", "none", [("name", r"openwrt"), ("title", r"openwrt|luci|lede"), ("body", r"luci-static|/cgi-bin/luci")]),
    ("eero", "eero", "none", [("vendor", r"\beero\b"), ("title", r"\beero\b")]),
    ("google", "Google/Nest Wifi", "none", [("vendor", r"^google"), ("title", r"google wifi|nest wifi|onhub")]),
    ("isp", None, "none", [("title", r"cableco|connect ?box|experia|\bkpn\b|livebox|freebox|bbox|\bbt\b.*hub|smart ?hub|"
                                     r"sky ?(hub|router)|vodafone|gigacube|xfinity|telekom|speedport|fritz!box 7|"
                                     r"sagemcom|technicolor|arris|zyxel|huawei|zte|nokia|sercomm|compal|vantiv|"
                                     r"proximus|swisscom|telenet|virgin|o2 ?(box|home)|orange|movistar|spectrum"),
                           ("ssdp", r"sagemcom|technicolor|arris|zyxel|compal|sercomm|huawei|zte"),
                           ("vendor", r"sagemcom|technicolor|arris|zyxel|compal|sercomm|huawei|zte|nokia|askey|hitron")]),
]


def router_fingerprint(pages, ssdp=None, mac_vendor=None, names=None):
    """Name the router family at the gateway from what it shows anyone: HTTP landing pages (title, Server header,
    auth realm, redirect), its SSDP description and its MAC prefix. Never logs in.

    pages: [{port, status, headers, body}] (headers lower-case). Returns
    {family, brand, routerType, confidence: high|medium|low|none, basis: [{field, value, source}], model, http: [...]}.
    `model` is set only when the router names it itself (SSDP modelName)."""
    fields = []         # (where, value, source)
    http = []
    for p in pages or []:
        if p.get("status") is None:
            continue
        h = p.get("headers") or {}
        src = "HTTP GET %s port %s" % (p.get("path") or "/", p.get("port"))
        t = title_of(p.get("body"))
        realm = None
        m = re.search(r'realm="?([^",]+)', h.get("www-authenticate") or "", re.I)
        if m:
            realm = m.group(1)
        http.append({"port": p.get("port"), "path": p.get("path") or "/", "status": p.get("status"), "title": t,
                     "server": (h.get("server") or "")[:100] or None, "realm": realm,
                     "location": (h.get("location") or "")[:160] or None, "source": src})
        for where, val in (("title", t), ("server", h.get("server")), ("realm", realm), ("location", h.get("location")),
                           ("body", (p.get("body") or "")[:20000])):
            if val:
                fields.append((where, val, src))
    desc = (ssdp or {}).get("description") or {}
    for k in ("manufacturer", "modelName", "friendlyName", "modelDescription"):
        if desc.get(k):
            fields.append(("ssdp", desc[k], "SSDP device description (%s)" % k))
    for sv in (ssdp or {}).get("servers") or []:
        fields.append(("ssdp", sv, "SSDP Server header"))
    if mac_vendor:
        fields.append(("vendor", mac_vendor, "MAC prefix (IEEE table)"))
    for n in names or []:
        fields.append(("name", n.get("value") or "", n.get("source") or "name"))
    best = None
    for family, brand, rtype, rules in ROUTER_RULES:
        hits = []
        for where, rx in rules:
            for fw, val, src in fields:
                if fw == where and re.search(rx, val, re.I):
                    hits.append({"field": fw, "value": (val if fw != "body" else "(page body matched %s)" % rx)[:120],
                                 "source": src})
                    break
        if hits:
            strong = [x for x in hits if x["field"] in ("title", "ssdp", "realm", "server", "location", "name")]
            score = len(strong) * 2 + (len(hits) - len(strong))
            if not best or score > best[0]:
                best = (score, family, brand, rtype, hits)
    out = {"family": "unknown", "brand": None, "routerType": "none", "confidence": "none", "basis": [], "model": None,
           "http": http}
    if best:
        score, family, brand, rtype, hits = best
        if family == "isp" and not brand:
            brand = next((x["value"] for x in hits if x["field"] in ("title", "ssdp")), None) or "an internet provider's box"
        conf = "high" if score >= 4 else "medium" if score >= 2 else "low"
        out.update(family=family, brand=brand, routerType=rtype, confidence=conf, basis=hits)
    if desc.get("modelName") and out["family"] != "unknown":
        out["model"] = {"value": " ".join(x for x in (desc.get("modelName"), desc.get("modelNumber")) if x),
                        "source": "SSDP device description"}
    if out["family"] == "asuswrt":
        out["note"] = ("AsusWRT or ZenWiFi: the hub can read the router's client list over SSH with a key "
                       "(python3 bin/hoh router setup-key).")
    elif out["family"] != "unknown":
        out["note"] = "The hub cannot read this router's client list; it finds devices by sweep, mDNS and SSDP (router.type none)."
    return out


def fingerprint_gateway(gw, ssdp=None, mac_vendor=None, names=None, timeout=3.0):
    """GET / on 80 and 443, and one same-host redirect target. Landing pages only; no login, no form posts."""
    pages = []
    for port, scheme in ((80, "http"), (443, "https")):
        url = "%s://%s%s/" % (scheme, gw, "" if port in (80, 443) else ":%d" % port)
        st, h, body = http_fetch(url, timeout=timeout)
        pages.append({"port": port, "path": "/", "status": st, "headers": h, "body": body if st else ""})
        loc = h.get("location") if st else None
        if loc and st and 300 <= st < 400:
            m = re.match(r"^(?:https?://%s(?::\d+)?)?(/[^\s?#]{0,120})" % re.escape(gw), loc)
            if m:
                st2, h2, b2 = http_fetch("%s://%s%s" % (scheme, gw, m.group(1)), timeout=timeout)
                pages.append({"port": port, "path": m.group(1), "status": st2, "headers": h2, "body": b2 if st2 else ""})
    return router_fingerprint(pages, ssdp=ssdp, mac_vendor=mac_vendor, names=names)


def home_assistant(url="http://127.0.0.1:8123", timeout=2.0):
    """Is Home Assistant answering on this Mac? Reads the public landing page and manifest only."""
    st, h, body = http_fetch(url.rstrip("/") + "/manifest.json", timeout=timeout)
    if st == 200 and "home assistant" in (body or "").lower():
        return {"url": url, "found": True, "source": "GET /manifest.json"}
    st2, h2, body2 = http_fetch(url.rstrip("/") + "/", timeout=timeout)
    if st2 and "home assistant" in (title_of(body2) or body2[:4000]).lower():
        return {"url": url, "found": True, "source": "GET /"}
    return {"url": url, "found": False, "source": "GET /manifest.json",
            "detail": ("HTTP %s" % st) if st else "nothing answered"}


# ================================================================ leads

def _hint_tables():
    try:
        import identify as I
        return I.HOSTNAME_HINTS, I.PORT_HINTS
    except Exception:
        return [], {}


MDNS_TYPE_LEADS = {
    "_googlecast._tcp": (None, "cast device", "advertises Google Cast"),
    "_airplay._tcp": ("Apple or AirPlay", None, "advertises AirPlay"),
    "_raop._tcp": (None, "speaker", "advertises AirPlay audio"),
    "_hap._tcp": (None, None, "is a HomeKit accessory"),
    "_homekit._tcp": (None, None, "is a HomeKit accessory"),
    "_matter._tcp": (None, None, "is a Matter device"),
    "_hue._tcp": ("Signify (Philips Hue)", "bridge", "advertises a Hue bridge"),
    "_ipp._tcp": (None, "printer", "advertises IPP printing"),
    "_printer._tcp": (None, "printer", "advertises a printer"),
    "_smb._tcp": (None, None, "shares files over SMB"),
    "_ssh._tcp": (None, None, "accepts SSH"),
    "_companion-link._tcp": ("Apple", None, "is an Apple device (companion link)"),
    "_workstation._tcp": (None, "computer", "advertises itself as a workstation"),
    "_spotify-connect._tcp": (None, "speaker", "is a Spotify Connect speaker"),
    "_sonos._tcp": ("Sonos", "speaker", "advertises Sonos"),
}
TXT_MODEL_KEYS = (("_googlecast._tcp", "md", "model"), ("_airplay._tcp", "model", "model identifier"),
                  ("_raop._tcp", "am", "model identifier"), ("_ipp._tcp", "ty", "printer model"),
                  ("_printer._tcp", "ty", "printer model"), ("_companion-link._tcp", "rpMd", "model identifier"),
                  ("_hap._tcp", "md", "model"))


def leads_for(h, hostname_hints=None, port_hints=None):
    """What the evidence says this host might be. A `claim` is the device naming its own product (SSDP description,
    an mDNS TXT model field, the Cast API); everything else is a `candidate` and never an identity."""
    if hostname_hints is None or port_hints is None:
        hostname_hints, port_hints = _hint_tables()
    out = []

    def add(kind, text, source, vendor=None, model=None, typ=None):
        if not any(x["text"] == text for x in out):
            out.append({"kind": kind, "text": text, "source": source, "vendor": vendor, "model": model, "type": typ})
    d = (h.get("ssdp") or {}).get("description") or {}
    if d.get("modelName") or d.get("manufacturer"):
        add("claim", "Says it is %s" % " ".join(x for x in (d.get("manufacturer"), d.get("modelName"), d.get("modelNumber")) if x),
            "SSDP device description", d.get("manufacturer"), d.get("modelName"))
    c = h.get("cast") or {}
    if c.get("model") or c.get("manufacturer"):
        add("claim", "Cast API says %s" % " ".join(x for x in (c.get("manufacturer"), c.get("model")) if x),
            "Cast API (port 8008)", c.get("manufacturer"), c.get("model"))
    for svc in (h.get("mdns") or {}).get("services") or []:
        for typ, key, what in TXT_MODEL_KEYS:
            v = (svc.get("txt") or {}).get(key)
            if svc["type"] == typ and v and v.lower() not in ("google cast group",):
                add("claim", "mDNS %s %s: %s" % (typ, what, v), "mDNS TXT %s=" % key, None, v)
        lead = MDNS_TYPE_LEADS.get(svc["type"])
        if lead:
            add("candidate", "It %s" % lead[2], "mDNS %s" % svc["type"], lead[0], None, lead[1])
    names = [n["value"] for n in h.get("names") or []]
    for n in names:
        for rx, vendor, typ, text in hostname_hints:
            if re.search(rx, n, re.I):
                add("candidate", "The name %r suggests %s" % (n, text), "hostname", vendor, None, typ)
                break
    for p in h.get("ports") or []:
        hint = port_hints.get(p)
        if hint:
            add("candidate", "Port %d: %s" % (p, hint[2]), "TCP connect", hint[0], None, hint[1])
    if h.get("macVendor"):
        mod = False
        try:
            mod = oui.is_module_maker(h["macVendor"])
        except Exception:
            pass
        add("candidate", "Network chip made by %s%s" % (h["macVendor"], " (a module maker: the brand on the box is "
                                                         "likely someone else)" if mod else ""),
            "MAC prefix (IEEE table)", None if mod else h["macVendor"])
    if h.get("randomizedMac"):
        add("candidate", "Private (randomized) MAC address: usually a phone, tablet, watch or laptop", "MAC address bit")
    return out


# ================================================================ inventory matching and diff

def inventory_index(inv, site=None):
    """{"ip": {ip: id}, "mac": {mac: id}, "name": {lower name: id}} from inventory net entries, probes and handsOff."""
    idx = {"ip": {}, "mac": {}, "name": {}}
    for d in (inv or {}).get("devices") or []:
        did = d.get("id")
        if not did:
            continue
        for n in d.get("net") or []:
            if n.get("medium") == "bluetooth":
                continue
            if n.get("ip"):
                idx["ip"].setdefault(n["ip"], did)
            m = norm_mac(n.get("mac") or "")
            if m:
                idx["mac"].setdefault(m, did)
            for k in ("name", "host"):
                if n.get(k):
                    idx["name"].setdefault(str(n[k]).lower().split(".")[0], did)
        p = d.get("probe") or {}
        if p.get("ip"):
            idx["ip"].setdefault(p["ip"], did)
        for ip in p.get("fallbackIps") or []:
            idx["ip"].setdefault(ip, did)
        if p.get("url"):
            m = re.match(r"^https?://(\d+\.\d+\.\d+\.\d+)", p["url"])
            if m:
                idx["ip"].setdefault(m.group(1), did)
        for k in ("name", "host"):
            if p.get(k) and p.get("type") in ("mdns", "tcp"):
                idx["name"].setdefault(str(p[k]).lower().split(".")[0], did)
    for h in (site or {}).get("handsOff") or []:
        if isinstance(h, dict) and h.get("id"):
            for ip in h.get("ips") or []:
                idx["ip"].setdefault(ip, h["id"])
            for n in h.get("names") or []:
                idx["name"].setdefault(str(n).lower().split(".")[0], h["id"])
    return idx


def match_host(h, idx):
    """(inventory id, how) for a discovered host, or (None, None)."""
    if h.get("mac") and not h.get("randomizedMac") and h["mac"] in idx["mac"]:
        return idx["mac"][h["mac"]], "mac"
    if h.get("mac") and h["mac"] in idx["mac"]:
        return idx["mac"][h["mac"]], "mac"
    if h.get("ip") in idx["ip"]:
        return idx["ip"][h["ip"]], "ip"
    for n in h.get("names") or []:
        k = str(n.get("value") or "").lower().split(".")[0]
        if k and k in idx["name"]:
            return idx["name"][k], "name"
    return None, None


def host_key(h):
    if h.get("mac") and not h.get("randomizedMac"):
        return "mac:" + h["mac"]
    return "ip:" + h["ip"]


def _names(h):
    return sorted({str(n.get("value")) for n in h.get("names") or [] if n.get("value")})


def diff(prev, cur, inv=None, site=None):
    """Compare two discovery documents and the inventory.

    {new: [host], gone: [host], changed: [{ip, key, changes: [{field, from, to}]}],
     notSeen: [{id, name, ips}], unexplained: [host], previousTs}"""
    prev_hosts = (prev or {}).get("hosts") or []
    cur_hosts = (cur or {}).get("hosts") or []
    pk = {host_key(h): h for h in prev_hosts}
    p_ip = {h["ip"]: h for h in prev_hosts}
    p_mac = {h["mac"]: h for h in prev_hosts if h.get("mac")}
    out = {"previousTs": (prev or {}).get("ts"), "new": [], "gone": [], "changed": [], "notSeen": [], "unexplained": []}
    matched = set()
    for h in cur_hosts:
        old = pk.get(host_key(h)) or (p_mac.get(h["mac"]) if h.get("mac") else None) or p_ip.get(h["ip"])
        if old is None:
            if prev is not None:
                out["new"].append(_brief(h))
            continue
        matched.add(host_key(old))
        ch = []
        if old.get("ip") != h.get("ip"):
            ch.append({"field": "ip", "from": old.get("ip"), "to": h.get("ip")})
        if old.get("mac") and h.get("mac") and old["mac"] != h["mac"]:
            ch.append({"field": "mac", "from": old["mac"], "to": h["mac"]})
        # mDNS and Cast add and drop names between scans; only a host that goes by none of its old names changed.
        if _names(old) and _names(h) and not set(n.lower() for n in _names(old)) & set(n.lower() for n in _names(h)):
            ch.append({"field": "names", "from": _names(old), "to": _names(h)})
        if sorted(old.get("ports") or []) != sorted(h.get("ports") or []) and cur.get("probes", {}).get("ports", {}).get("ok") \
                and (prev or {}).get("probes", {}).get("ports", {}).get("ok"):
            ch.append({"field": "ports", "from": sorted(old.get("ports") or []), "to": sorted(h.get("ports") or [])})
        if ch:
            out["changed"].append({"ip": h["ip"], "key": host_key(h), "names": _names(h), "changes": ch})
    for k, h in pk.items():
        if k not in matched:
            out["gone"].append(_brief(h))
    if inv is not None:
        idx = inventory_index(inv, site)
        seen_ids = set()
        for h in cur_hosts:
            did, how = match_host(h, idx)
            if did:
                seen_ids.add(did)
            elif not h.get("self"):
                out["unexplained"].append(_brief(h))
        for d in inv.get("devices") or []:
            ips = sorted({n["ip"] for n in d.get("net") or [] if n.get("ip") and n.get("medium") != "bluetooth"}
                         | ({(d.get("probe") or {}).get("ip")} - {None}))
            macs = sorted({n["mac"] for n in d.get("net") or [] if n.get("mac") and n.get("medium") != "bluetooth"})
            if (ips or macs) and d.get("id") not in seen_ids and (d.get("probe") or {}).get("type") != "self":
                out["notSeen"].append({"id": d.get("id"), "name": d.get("name"), "ips": ips, "macs": macs,
                                       "probe": (d.get("probe") or {}).get("type") or "none"})
    return out


def _brief(h):
    return {"ip": h.get("ip"), "mac": h.get("mac"), "macVendor": h.get("macVendor"), "names": _names(h),
            "services": sorted({s["type"] for s in (h.get("mdns") or {}).get("services") or []}),
            "leads": [l["text"] for l in (h.get("leads") or [])[:3]], "inventoryId": h.get("inventoryId")}


# ================================================================ the run

def _load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def write_atomic(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = "%s.%d.tmp" % (path, os.getpid())
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


def discover(force=False, ports=True, quick=False, subnet=None, budget_s=85):
    t0 = time.time()
    budget = Budget(budget_s)
    warnings = []
    probes = {}
    site, site_problems = S.load()
    det = S.detect()
    net_cidr = subnet or site["network"]["subnet"]
    net = ipaddress.ip_network(net_cidr, strict=False)
    gw = site["network"]["gateway"]
    doc = {"schema": 1, "tool": "discover.py", "version": VERSION, "ts": now_iso(),
           "network": {"subnet": str(net), "gateway": gw, "interface": det.get("interface"), "address": det.get("address"),
                       "source": "site.json" if site.get("configured") and site["network"].get("subnetSource") is None
                       else "route -n get default + ifconfig"},
           "warnings": warnings, "probes": probes}
    for p in site_problems:
        warnings.append("site.json: " + p)
    if not det.get("gateway"):
        warnings.append("This Mac has no default route: it is not connected to a network.")
    max_prefix = MAX_PREFIX_DEFAULT
    if net.prefixlen < max_prefix and not force:
        raise SystemExit("discover.py: the subnet %s has %d addresses, more than a /%d. Refusing to sweep it; pass "
                         "--force if this really is your home network." % (net, net.num_addresses, max_prefix))
    ifip = det.get("address") or local_ip_toward(gw)
    self_ips = set()
    results = {}

    def job_self():
        return this_mac(quick=quick, budget=budget)

    def job_sweep():
        return sweep(net)

    def job_mdns():
        if not ifip:
            raise OSError("no local address on the home network")
        try:
            return ("socket", mdns_discover(ifip, net))
        except OSError as e:
            rows = dnssd_browse()
            return ("dns-sd", {"_fallback": rows, "_error": str(e)})

    def job_ssdp():
        if not ifip:
            raise OSError("no local address on the home network")
        return ssdp_discover(ifip, net)

    def job_ha():
        return home_assistant((site.get("homeAssistant") or {}).get("url") or "http://127.0.0.1:8123")
    jobs = {"self": job_self, "sweep": job_sweep, "mdns": job_mdns, "ssdp": job_ssdp, "homeAssistant": job_ha}
    took = {}

    def timed(k, f):
        s0 = time.time()
        try:
            return f()
        finally:
            took[k] = round(time.time() - s0, 1)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs))
    futs = {k: ex.submit(timed, k, f) for k, f in jobs.items()}
    for k, f in futs.items():
        try:
            results[k] = f.result(timeout=max(1.0, budget.left(60)))
            probes[k] = {"ok": True}
        except Exception as e:
            results[k] = None
            probes[k] = {"ok": False, "error": "%s: %s" % (type(e).__name__, str(e)[:200]) if not isinstance(
                e, concurrent.futures.TimeoutError) else "did not finish in time"}
        if k in took:
            probes[k]["durationSec"] = took[k]
    ex.shutdown(wait=False)

    me = results.get("self") or {}
    doc["host"] = me
    for i in me.get("interfaces") or []:
        if i.get("ip"):
            self_ips.add(i["ip"])
    if ifip:
        self_ips.add(ifip)

    hosts = {}

    def host(ip):
        if ip not in hosts:
            hosts[ip] = {"ip": ip, "sources": [], "names": [], "mac": None, "macSource": None}
        return hosts[ip]

    def src(h, s):
        if s not in h["sources"]:
            h["sources"].append(s)

    swept = results.get("sweep") or {}
    probes.setdefault("sweep", {})["found"] = len(swept)
    probes["sweep"]["source"] = "ping, one packet, 1 s timeout, every address in %s" % net
    for ip, ms in swept.items():
        h = host(ip)
        h["latencyMs"] = ms
        src(h, "ping")

    rc, arp_out, arp_err = run(["/usr/sbin/arp", "-an"], timeout=8)
    arp = parse_arp(arp_out) if rc == 0 else {"entries": {}, "status": "failed", "redacted": 0, "incomplete": 0, "withMac": 0}
    probes["arp"] = {"ok": rc == 0, "status": arp["status"], "entries": len(arp["entries"]), "withMac": arp["withMac"],
                     "redacted": arp["redacted"], "source": "arp -an"}
    if arp["status"] in ARP_NOTES:
        probes["arp"]["note"] = ARP_NOTES[arp["status"]]
        warnings.append(ARP_NOTES[arp["status"]])
    for ip, e in arp["entries"].items():
        try:
            if ipaddress.ip_address(ip) not in net:
                continue
        except ValueError:
            continue
        h = host(ip)
        src(h, "arp")
        if e.get("mac") and not h["mac"]:
            h["mac"], h["macSource"] = e["mac"], "arp -an"

    md = results.get("mdns")
    if md:
        how, data = md
        probes["mdns"]["method"] = how
        if how == "socket":
            probes["mdns"]["hosts"] = len(data)
            probes["mdns"]["source"] = "mDNS query for %d service types" % len(MDNS_TYPES)
            for ip, e in data.items():
                h = host(ip)
                src(h, "mdns")
                h["mdns"] = e
                for n in e.get("hostnames") or []:
                    h["names"].append(ev(n, "mDNS A record"))
        else:
            probes["mdns"]["ok"] = False
            probes["mdns"]["error"] = data.get("_error")
            doc["mdnsUnresolved"] = data.get("_fallback") or []
            probes["mdns"]["note"] = ("The raw mDNS query was refused (%s); dns-sd -B found %d service names but "
                                      "cannot tie them to addresses." % (data.get("_error"), len(doc["mdnsUnresolved"])))

    sd = results.get("ssdp") or {}
    probes["ssdp"]["hosts"] = len(sd)
    probes["ssdp"]["source"] = "SSDP M-SEARCH ssdp:all to 239.255.255.250:1900, 3 s; LOCATION fetched from the same host"
    for ip, e in sd.items():
        h = host(ip)
        src(h, "ssdp")
        h["ssdp"] = {"servers": e.get("servers"), "types": e.get("types")[:8], "location": e.get("location"),
                     "description": e.get("description") or {}}
        fn = (e.get("description") or {}).get("friendlyName")
        if fn:
            h["names"].append(ev(fn, "SSDP friendlyName"))

    for ip in self_ips:
        if ip in hosts or (ipaddress.ip_address(ip) in net):
            host(ip)["self"] = True
            src(host(ip), "this Mac")
    if gw:
        try:
            if ipaddress.ip_address(gw) in net:
                host(gw)["gateway"] = True
                src(host(gw), "default route")
        except ValueError:
            pass

    # Hands-off devices: looked at, never port-checked.
    hands_off_ips = {ip for x in site.get("handsOff") or [] if isinstance(x, dict) for ip in x.get("ips") or []}
    targets = sorted((ip for ip in hosts if ip not in hands_off_ips and not hosts[ip].get("self")),
                     key=lambda x: ipaddress.ip_address(x))
    if ports and budget.left() > 8:
        s0 = time.time()
        timeout = 0.6 if len(targets) <= 120 else 0.4
        pc = port_check(targets, timeout=timeout)
        for ip, open_ in pc.items():
            hosts[ip]["ports"] = open_
            if open_:
                src(hosts[ip], "tcp")
        probes["ports"] = {"ok": True, "hosts": len(targets), "ports": list(PORTS), "timeoutSec": timeout,
                           "skippedHandsOff": sorted(hands_off_ips & set(hosts)), "durationSec": round(time.time() - s0, 1),
                           "source": "TCP connect, closed at once"}
    else:
        probes["ports"] = {"ok": False, "error": "skipped (--no-ports)" if not ports else "skipped: out of time"}

    # Names, MAC vendors, Cast, in parallel and bounded.
    def enrich(ip):
        h = hosts[ip]
        n, s = rdns(ip, server=gw if gw else None)
        if n:
            h["rdns"] = n
            h["names"].append(ev(n, s))
        if 8008 in (h.get("ports") or []) or any(x["type"] == "_googlecast._tcp" for x in (h.get("mdns") or {}).get("services") or []):
            try:
                import collectors as C
                c = C.cast_info(ip)
            except Exception:
                c = None
            if c:
                c = dict(c, source="Cast API eureka_info (port 8008)")
                st, _, body = http_fetch("http://%s:8008/ssdp/device-desc.xml" % ip, timeout=3)
                if st == 200:
                    c["manufacturer"] = xml_tag(body, "manufacturer")
                    c["model"] = xml_tag(body, "modelName")
                h["cast"] = {k: v for k, v in c.items() if v not in (None, "")}
                if c.get("name"):
                    h["names"].append(ev(c["name"], "Cast API name"))
        return ip
    if budget.left() > 4:
        s0 = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex2:
            fs = [ex2.submit(enrich, ip) for ip in hosts]
            done, notdone = concurrent.futures.wait(fs, timeout=max(2.0, budget.left(25)))
        probes["names"] = {"ok": not notdone, "hosts": len(done), "unfinished": len(notdone),
                           "durationSec": round(time.time() - s0, 1), "source": "dig -x at the gateway, then the system resolver; Cast API"}

    # Router at the gateway.
    if gw:
        gh = hosts.get(gw) or {}
        try:
            fp = fingerprint_gateway(gw, ssdp=sd.get(gw), mac_vendor=oui.vendor(gh.get("mac") or ""), names=gh.get("names"))
            fp["ip"] = gw
            doc["router"] = fp
            probes["router"] = {"ok": True, "source": "HTTP landing pages on 80/443 (no login), SSDP, MAC prefix"}
        except Exception as e:
            doc["router"] = {"ip": gw, "family": "unknown", "error": str(e)}
            probes["router"] = {"ok": False, "error": str(e)}
    doc["homeAssistant"] = results.get("homeAssistant") or {"found": False}

    # Per-host finishing: MAC facts, leads, inventory match.
    inv = _load_json(inventory_path())
    idx = inventory_index(inv, site) if inv else None
    hh, ph = _hint_tables()
    for i in me.get("interfaces") or []:
        if i.get("ip") in hosts and i.get("mac") and not hosts[i["ip"]]["mac"]:
            hosts[i["ip"]]["mac"], hosts[i["ip"]]["macSource"] = i["mac"], "ifconfig (this Mac)"
    for ip, h in hosts.items():
        if not h["mac"] and (h.get("cast") or {}).get("mac"):
            h["mac"], h["macSource"] = h["cast"]["mac"], "Cast API"
        if h["mac"]:
            h["randomizedMac"] = oui.is_randomized(h["mac"])
            h["macVendor"] = oui.vendor(h["mac"])
        # de-duplicate names, keep the first source for each
        seen, names = set(), []
        for n in h["names"]:
            k = n["value"].lower()
            if k not in seen:
                seen.add(k)
                names.append(n)
        h["names"] = names
        h["leads"] = leads_for(h, hh, ph)
        if idx:
            did, how = match_host(h, idx)
            if did:
                h["inventoryId"], h["inventoryMatch"] = did, how
    doc["hosts"] = sorted(hosts.values(), key=lambda h: ipaddress.ip_address(h["ip"]))

    # Local Network permission: a default route but a silent gateway and an empty sweep.
    gw_seen = gw in swept or (gw in hosts and len(hosts[gw]["sources"]) > 1)
    if det.get("gateway") and not swept:
        doc["localNetwork"] = {"ok": False, "detail": (
            "Nothing answered the ping sweep, not even the router at %s, although this Mac has a default route. macOS is "
            "probably blocking local network access for the app running this (System Settings > Privacy & Security > "
            "Local Network: switch it on for Terminal, iTerm or the app you run Claude Code in, then run the scan again). "
            "A sandboxed shell has the same effect." % gw)}
        warnings.append(doc["localNetwork"]["detail"])
    else:
        doc["localNetwork"] = {"ok": True, "gatewayAnswered": bool(gw_seen)}

    hs = doc["hosts"]
    doc["summary"] = {
        "hosts": len(hs),
        "answeredPing": len(swept),
        "withMac": sum(1 for h in hs if h.get("mac")),
        "randomizedMac": sum(1 for h in hs if h.get("randomizedMac")),
        "withName": sum(1 for h in hs if h.get("names")),
        "mdnsHosts": sum(1 for h in hs if h.get("mdns")),
        "mdnsServices": sum(len((h.get("mdns") or {}).get("services") or []) for h in hs),
        "ssdpHosts": sum(1 for h in hs if h.get("ssdp")),
        "castDevices": sum(1 for h in hs if h.get("cast")),
        "withOpenPorts": sum(1 for h in hs if h.get("ports")),
        "withClaim": sum(1 for h in hs if any(l["kind"] == "claim" for l in h.get("leads") or [])),
        "inInventory": sum(1 for h in hs if h.get("inventoryId")),
        "usb": len(me.get("usb") or []), "displays": len(me.get("displays") or []),
        "bluetooth": len(me.get("bluetooth") or []),
        "router": (doc.get("router") or {}).get("family"),
        "homeAssistant": bool(doc["homeAssistant"].get("found")),
        "arp": arp["status"],
    }
    doc["durationSec"] = round(time.time() - t0, 1)
    return doc


# ================================================================ output

def summary_text(doc):
    L = []
    s = doc.get("summary") or {}
    n = doc.get("network") or {}
    me = doc.get("host") or {}
    L.append("Discovery %s, %.0f s" % (doc.get("ts"), doc.get("durationSec") or 0))
    L.append("This Mac: %s (%s), %s, %s" % (me.get("modelName") or "?", me.get("model") or "?", me.get("computerName") or "?",
                                           me.get("os") or "?"))
    for i in me.get("interfaces") or []:
        if i.get("ip") or i.get("status") == "active":
            L.append("  %-6s %-9s %-15s %s%s" % (i["if"], i["medium"], i.get("ip") or "-", i.get("speed") or "",
                                                  (" Wi-Fi %s" % me["wifi"]["ssid"]) if i["medium"] == "wifi" and (me.get("wifi") or {}).get("ssid") else ""))
    L.append("  USB %s, displays %s, Bluetooth %s" % (s.get("usb"), s.get("displays"), s.get("bluetooth")))
    L.append("Network %s, gateway %s (%s)" % (n.get("subnet"), n.get("gateway"), n.get("source")))
    r = doc.get("router") or {}
    if r:
        L.append("Router: %s%s, confidence %s%s" % (r.get("brand") or r.get("family"),
                                                    (" " + r["model"]["value"]) if r.get("model") else "",
                                                    r.get("confidence"), (". " + r["note"]) if r.get("note") else ""))
    ha = doc.get("homeAssistant") or {}
    L.append("Home Assistant: %s" % ("answering at %s" % ha.get("url") if ha.get("found") else "not found on this Mac"))
    L.append("Hosts: %d (ping %d, with MAC %d, named %d, mDNS %d, SSDP %d, cast %d, open ports %d, in inventory %d); ARP %s"
             % (s.get("hosts", 0), s.get("answeredPing", 0), s.get("withMac", 0), s.get("withName", 0), s.get("mdnsHosts", 0),
                s.get("ssdpHosts", 0), s.get("castDevices", 0), s.get("withOpenPorts", 0), s.get("inInventory", 0), s.get("arp")))
    L.append("")
    for h in doc.get("hosts") or []:
        tag = "self" if h.get("self") else "gw" if h.get("gateway") else (h.get("inventoryId") or "")
        names = ", ".join(x["value"] for x in h.get("names") or [])[:60]
        mac = h.get("mac") or "-"
        if h.get("randomizedMac"):
            mac += " (private)"
        elif h.get("macVendor"):
            mac += " (%s)" % h["macVendor"][:24]
        L.append("%-15s %-12s %-40s %s" % (h["ip"], tag[:12], mac[:40], names))
        extra = []
        svcs = sorted({x["type"] for x in (h.get("mdns") or {}).get("services") or []})
        if svcs:
            extra.append("mDNS " + " ".join(svcs))
        if h.get("ports"):
            extra.append("ports " + ",".join(str(p) for p in h["ports"]))
        claims = [l["text"] for l in h.get("leads") or [] if l["kind"] == "claim"]
        if claims:
            extra.append("; ".join(claims))
        if extra:
            L.append("%-15s %s" % ("", " | ".join(extra))[:200])
    if doc.get("mdnsUnresolved"):
        L.append("")
        L.append("mDNS names without an address (dns-sd fallback): %d" % len(doc["mdnsUnresolved"]))
    d = doc.get("diff")
    if d:
        L.append("")
        L.append("Changes since %s:" % (d.get("previousTs") or "no previous scan"))
        for k, label in (("new", "new"), ("gone", "gone"), ("unexplained", "not in the inventory")):
            for h in d.get(k) or []:
                L.append("  %-20s %-15s %s %s" % (label, h["ip"], h.get("mac") or "", ", ".join(h.get("names") or [])))
        for c in d.get("changed") or []:
            L.append("  %-20s %-15s %s" % ("changed", c["ip"], "; ".join("%s %s -> %s" % (x["field"], x["from"], x["to"])
                                                                      for x in c["changes"])))
        for x in d.get("notSeen") or []:
            L.append("  %-20s %-15s %s" % ("inventory, not seen", ",".join(x["ips"]) or "-", x["id"]))
        if not any(d.get(k) for k in ("new", "gone", "unexplained", "changed", "notSeen")):
            L.append("  nothing")
    if doc.get("warnings"):
        L.append("")
        for w in doc["warnings"]:
            L.append("Note: " + w)
    L.append("")
    L.append("Written to %s" % doc.get("path", out_path()))
    return "\n".join(L)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Read-only discovery of the home network.")
    ap.add_argument("--json", action="store_true", help="print the whole document as JSON")
    ap.add_argument("--diff", action="store_true", help="compare with the previous discovery and data/inventory.json")
    ap.add_argument("--force", action="store_true", help="allow sweeping more than a /22")
    ap.add_argument("--no-ports", action="store_true", help="skip the TCP port check")
    ap.add_argument("--quick", action="store_true", help="skip USB, displays, Bluetooth and cable readings of this Mac")
    ap.add_argument("--subnet", help="sweep this CIDR instead of the one in site.json / detected")
    a = ap.parse_args(argv)
    if a.subnet:
        try:
            ipaddress.ip_network(a.subnet, strict=False)
        except ValueError:
            ap.error("--subnet %r is not a CIDR" % a.subnet)
    path = out_path()
    prev = _load_json(path)
    doc = discover(force=a.force, ports=not a.no_ports, quick=a.quick, subnet=a.subnet)
    if a.diff:
        site, _ = S.load()
        doc["diff"] = diff(prev, doc, _load_json(inventory_path()), site)
    doc["path"] = path
    write_atomic(path, doc)
    if a.json:
        json.dump(doc, sys.stdout, indent=1, ensure_ascii=False)
        print()
    else:
        print(summary_text(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
