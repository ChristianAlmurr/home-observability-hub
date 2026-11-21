"""Home Observability Hub collectors: probes for every device in data/inventory.json.

Standard library only, Python 3.9+. Every function here is read-only toward the
system: it runs fixed argv lists (never a shell), opens TCP connections and
HTTP GETs on the local network, and reads files. The only writes are the
state files the server asks `Monitor` to keep (live.json, events.jsonl).

Facts about this Mac that shape the code (macOS 27):
- `arp -an` prints nothing and neighbour MACs are redacted, so ARP is never used.
- `dns-sd -B` never exits; it is killed after a few seconds.
- `ping -t 1` is the timeout flag on macOS.
"""
import concurrent.futures
import datetime
import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request

import site_config as SITE

ROOT = os.path.dirname(os.path.abspath(__file__))
SLOW_TTL = 120          # system_profiler at most every 2 minutes
SWEEP_TTL = 300         # stranger sweep at most every 5 minutes
BT_TTL = 25             # Bluetooth list: fresh on every 30 s cycle


def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def state_dir():
    return os.environ.get("HM_STATE_DIR") or os.path.join(ROOT, "data", "state")


# Where the house is: all of it comes from data/site.json (site_config.py), read at call time.
def router_ip():
    """The router's LAN address."""
    return SITE.router_ip()


def subnet():
    return SITE.subnet()


def allowed_nets():
    return SITE.allowed_nets()


def inventory_path():
    return os.environ.get("HM_INVENTORY") or os.path.join(ROOT, "data", "inventory.json")


INVENTORY_PROBLEM = {"text": None}


def empty_inventory():
    return json.loads(json.dumps(SITE.EMPTY_INVENTORY))


def load_inventory():
    """data/inventory.json. A house that has none yet is an empty inventory; a file that cannot be read
    is one too, with the reason kept in INVENTORY_PROBLEM (nothing is ever written over it)."""
    try:
        with open(inventory_path()) as f:
            inv = json.load(f)
    except FileNotFoundError:
        INVENTORY_PROBLEM["text"] = None
        return empty_inventory()
    except (OSError, ValueError) as e:
        INVENTORY_PROBLEM["text"] = "data/inventory.json could not be read (%s)." % e
        return empty_inventory()
    if not isinstance(inv, dict):
        INVENTORY_PROBLEM["text"] = "data/inventory.json is not a JSON object."
        return empty_inventory()
    INVENTORY_PROBLEM["text"] = None
    for k in ("devices", "links", "rooms", "zones"):
        if not isinstance(inv.get(k), list):
            inv[k] = []
    inv["devices"] = [d for d in inv["devices"] if isinstance(d, dict) and d.get("id")]
    inv["links"] = [l for l in inv["links"] if isinstance(l, dict) and l.get("id")]
    return inv


def wired_inventory():
    """inventory.json with the cables where the computers last saw them (wiring.py)."""
    import wiring
    return wiring.apply(load_inventory(), wiring.load_state(state_dir()))


def write_json_atomic(path, obj):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    tmp = "%s.%d.%d.tmp" % (path, os.getpid(), threading.get_ident())
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


_append_lock = threading.Lock()


def append_jsonl(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    line = json.dumps(obj, ensure_ascii=False) + "\n"
    with _append_lock:
        with open(path, "a") as f:
            f.write(line)


# ---------------------------------------------------------------- low level

def run(argv, timeout=10):
    """(returncode, stdout, stderr). Never raises; never uses a shell."""
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, text=True)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except Exception as e:  # missing binary, etc.
        return 127, "", str(e)


def ip_allowed(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in allowed_nets())


def ping(ip, attempts=2):
    """(ok, latency_ms). Two single-packet tries with a 1 s timeout each, so one
    dropped packet on Wi-Fi is not an outage."""
    for _ in range(attempts):
        rc, out, _ = run(["/sbin/ping", "-c", "1", "-t", "1", "-n", ip], timeout=3)
        if rc == 0:
            m = re.search(r"time[=<]([\d.]+)\s*ms", out)
            return True, (round(float(m.group(1)), 1) if m else None)
    return False, None


def tcp_check(ip, port, timeout=1.5):
    """(ok, latency_ms, detail)."""
    t0 = time.time()
    try:
        s = socket.create_connection((ip, int(port)), timeout=timeout)
        s.close()
        return True, round((time.time() - t0) * 1000, 1), "open"
    except socket.timeout:
        return False, None, "no answer within %.1fs" % timeout
    except ConnectionRefusedError:
        # The host is there: it actively refused.
        return False, round((time.time() - t0) * 1000, 1), "refused"
    except OSError as e:
        return False, None, e.strerror or str(e)


def dig(args, timeout=3):
    rc, out, err = run(["/usr/bin/dig", "+short", "+time=1", "+tries=1"] + args, timeout=timeout)
    if rc != 0:
        return []
    return [l.strip().rstrip(".") for l in out.splitlines() if l.strip() and not l.startswith(";")]


def rdns(ip):
    """Name the router's DNS gives this address, or None."""
    names = dig(["-x", ip, "@" + router_ip()])
    return names[0] if names else None


def _getaddrinfo(name, timeout=2.0):
    box = []

    def go():
        try:
            box.extend({ai[4][0] for ai in socket.getaddrinfo(name, None, socket.AF_INET)})
        except Exception:
            pass
    t = threading.Thread(target=go, daemon=True)
    t.start()
    t.join(timeout)
    return sorted(box)


def resolve(name):
    """IPv4 addresses for a name: the router's DNS first, then the system resolver."""
    try:
        ipaddress.ip_address(name)
        return [name]
    except ValueError:
        pass
    ips = [x for x in dig([name, "@" + router_ip()]) if re.match(r"^\d+\.\d+\.\d+\.\d+$", x)]
    if not ips:
        ips = _getaddrinfo(name)
    return ips


def http_get(url, timeout=3.0, headers=None, limit=65536):
    """(status, body_text). status None when nothing answered."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(limit).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(limit).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:
        return None, str(e)


# ---------------------------------------------------------------- slow, cached

class _Cache:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {}

    def get(self, key, ttl, fn):
        with self.lock:
            hit = self.data.get(key)
            if hit and time.time() - hit[0] < ttl:
                return hit[1]
        val = fn()
        with self.lock:
            self.data[key] = (time.time(), val)
        return val


CACHE = _Cache()


def _sp(datatype, timeout=30):
    rc, out, err = run(["/usr/sbin/system_profiler", datatype, "-json"], timeout=timeout)
    if rc != 0:
        raise RuntimeError("system_profiler %s failed: %s" % (datatype, (err or "").strip()[:200]))
    return json.loads(out or "{}")


def usb_devices(fresh=False):
    """Flat list of USB devices: {name, vendorId, productId, vendor, linkSpeed,
    power, location, parent}. Uses SPUSBHostDataType, falls back to SPUSBDataType."""
    def load():
        out = []

        def walk(items, parent):
            for it in items or []:
                vid = it.get("USBDeviceKeyVendorID") or it.get("vendor_id") or ""
                pid = it.get("USBDeviceKeyProductID") or it.get("product_id") or ""
                vid = vid.split()[0].lower() if vid else ""
                pid = pid.split()[0].lower() if pid else ""
                if vid or pid:
                    out.append({
                        "name": it.get("_name"),
                        "vendorId": vid, "productId": pid,
                        "vendor": it.get("USBDeviceKeyVendorName") or it.get("manufacturer"),
                        "linkSpeed": it.get("USBDeviceKeyLinkSpeed") or it.get("device_speed"),
                        "power": it.get("USBDeviceKeyPowerAllocation") or it.get("bus_power_used"),
                        "location": it.get("USBKeyLocationID") or it.get("location_id"),
                        "parent": parent,
                    })
                walk(it.get("_items"), it.get("_name") if (vid or pid) else parent)
        d = _sp("SPUSBHostDataType")
        walk(d.get("SPUSBHostDataType"), None)
        if not out:
            d = _sp("SPUSBDataType")
            walk(d.get("SPUSBDataType"), None)
        return out
    return load() if fresh else CACHE.get("usb", SLOW_TTL, load)


def displays(fresh=False):
    """[{name, pixels, looksLike, refreshHz, hidpi, main, online}]"""
    def load():
        d = _sp("SPDisplaysDataType")
        out = []
        for gpu in d.get("SPDisplaysDataType") or []:
            for disp in gpu.get("spdisplays_ndrvs") or []:
                res = disp.get("_spdisplays_resolution") or disp.get("spdisplays_resolution") or ""
                pixels = (disp.get("_spdisplays_pixels") or "").replace(" ", "")
                m = re.match(r"\s*(\d+)\s*x\s*(\d+)(?:\s*@\s*([\d.]+)\s*Hz)?", res)
                looks = "%sx%s" % (m.group(1), m.group(2)) if m else None
                hz = float(m.group(3)) if m and m.group(3) else None
                out.append({
                    "name": disp.get("_name"),
                    "gpu": gpu.get("sppci_model") or gpu.get("_name"),
                    "pixels": pixels or None,
                    "looksLike": looks,
                    "refreshHz": hz,
                    "hidpi": bool(pixels and looks and pixels != looks),
                    "main": disp.get("spdisplays_main") == "spdisplays_yes",
                    "online": disp.get("spdisplays_online", "spdisplays_yes") == "spdisplays_yes",
                })
        return out
    return load() if fresh else CACHE.get("displays", SLOW_TTL, load)


def bluetooth_devices(fresh=False):
    """Bluetooth devices this Mac knows: [{name, address, connected, minorType, vendorId, productId,
    battery, firmware, rssi}]. Serial numbers are left out."""
    def load():
        d = _sp("SPBluetoothDataType")
        out = []
        for ctl in d.get("SPBluetoothDataType") or []:
            for key, connected in (("device_connected", True), ("device_not_connected", False)):
                for item in ctl.get(key) or []:
                    if not isinstance(item, dict):
                        continue
                    for name, v in item.items():
                        v = v if isinstance(v, dict) else {}
                        bat = re.match(r"(\d+)", str(v.get("device_batteryLevelMain") or ""))
                        rssi = re.match(r"(-?\d+)", str(v.get("device_rssi") or ""))
                        out.append({"name": name.replace("\u00a0", " "), "address": (v.get("device_address") or "").upper() or None,
                                    "connected": connected, "minorType": v.get("device_minorType"),
                                    "vendorId": v.get("device_vendorID"), "productId": v.get("device_productID"),
                                    "battery": int(bat.group(1)) if bat else None,
                                    "firmware": v.get("device_firmwareVersion"), "rssi": int(rssi.group(1)) if rssi else None})
        return out
    return load() if fresh else CACHE.get("bluetooth", BT_TTL, load)


BT_WORDS = (("keyboard", "Keyboard"), ("mouse", "Mouse"), ("trackpad", "Trackpad"), ("headphone", "Headphones"))


def match_bluetooth(dev, bt):
    """The Bluetooth device that is this inventory device: by address when the inventory has one,
    else by kind (the keyboard is the device whose minor type is Keyboard). Connected ones win."""
    if not bt:
        return None
    macs = {(n.get("mac") or "").upper() for n in dev.get("net") or [] if n.get("medium") == "bluetooth" and n.get("mac")}
    for k in ("mac", "address"):
        macs.add(((dev.get("probe") or {}).get(k) or "").upper())
    macs.discard("")
    hits = [b for b in bt if b.get("address") in macs]
    if not hits and not macs:
        text = ("%s %s" % (dev.get("id"), dev.get("name"))).lower()
        for word, minor in BT_WORDS:
            if word in text:
                hits = [b for b in bt if b.get("minorType") == minor]
                break
    hits.sort(key=lambda b: not b.get("connected"))
    return hits[0] if hits else None


def display_mode_text(d):
    if not d:
        return None
    s = "%s at %s" % (d.get("name"), d.get("pixels") or "?")
    if d.get("hidpi"):
        s += ", HiDPI looks like %s" % d.get("looksLike")
    if d.get("refreshHz"):
        s += " @ %g Hz" % d["refreshHz"]
    return s


# ---------------------------------------------------------------- interfaces

def interface(ifname):
    """{exists, status, active, media, speed, duplex, ipv4, mtu}"""
    rc, out, err = run(["/sbin/ifconfig", ifname], timeout=5)
    if rc != 0:
        return {"name": ifname, "exists": False, "status": "absent", "active": False}
    info = {"name": ifname, "exists": True}
    m = re.search(r"status:\s*(\S+)", out)
    info["status"] = m.group(1) if m else "unknown"
    info["active"] = info["status"] == "active"
    m = re.search(r"media:\s*(.+)", out)
    media = m.group(1).strip() if m else None
    info["media"] = media
    sm = re.search(r"\(([^)<\s]+)\s*(?:<([^>]*)>)?\)", media or "")
    info["speedRaw"] = sm.group(1) if sm and sm.group(1) != "none" else None
    info["duplex"] = sm.group(2) if sm and sm.group(2) else None
    info["speed"] = speed_label(info["speedRaw"])
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    info["ipv4"] = m.group(1) if m else None
    m = re.search(r"mtu (\d+)", out)
    info["mtu"] = int(m.group(1)) if m else None
    return info


def speed_label(raw):
    """'2500Base-T' -> '2.5G', '1000baseT' -> '1G', '100baseTX' -> '100M'."""
    if not raw:
        return None
    m = re.match(r"(\d+)\s*[Bb]ase", raw)
    if not m:
        return raw
    mbps = int(m.group(1))
    if mbps >= 1000:
        g = mbps / 1000.0
        return ("%g" % g) + "G"
    return "%dM" % mbps


def service_order():
    """[{name, device, enabled}] in priority order."""
    rc, out, _ = run(["/usr/sbin/networksetup", "-listnetworkserviceorder"], timeout=8)
    res = []
    for m in re.finditer(r"\((\d+|\*)\)\s*(.+)\n\(Hardware Port: ([^,]*), Device: ([^)]*)\)", out):
        res.append({"name": m.group(2).strip(), "device": m.group(4).strip() or None,
                    "enabled": not m.group(2).strip().startswith("*")})
    return res


def default_route_if():
    rc, out, _ = run(["/sbin/route", "-n", "get", "default"], timeout=5)
    m = re.search(r"interface:\s*(\S+)", out)
    return m.group(1) if m else None


def route_to(ip):
    rc, out, _ = run(["/sbin/route", "-n", "get", ip], timeout=5)
    info = {}
    for key in ("route to", "gateway", "interface"):
        m = re.search(r"%s:\s*(\S+)" % key, out)
        if m:
            info[key.replace("route to", "routeTo")] = m.group(1)
    return info


def wifi_power(ifname="en1"):
    rc, out, _ = run(["/usr/sbin/networksetup", "-getairportpower", ifname], timeout=5)
    m = re.search(r":\s*(On|Off)", out)
    return (m.group(1) == "On") if m else None


def wifi_interface():
    rc, out, _ = run(["/usr/sbin/networksetup", "-listallhardwareports"], timeout=5)
    m = re.search(r"Hardware Port: Wi-Fi\nDevice: (\S+)", out)
    return m.group(1) if m else "en1"


def uptime_sec():
    rc, out, _ = run(["/usr/sbin/sysctl", "-n", "kern.boottime"], timeout=3)
    m = re.search(r"sec = (\d+)", out)
    return int(time.time() - int(m.group(1))) if m else None


# ---------------------------------------------------------------- mDNS

def mdns_browse(service_type, seconds=3.0):
    """Instance names seen for a service type. dns-sd never exits, so it is killed."""
    try:
        p = subprocess.Popen(["/usr/bin/dns-sd", "-B", service_type, "local."], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                             start_new_session=True)
    except Exception:
        return None
    lines = []

    def reader():
        try:
            for l in p.stdout:
                lines.append(l)
        except Exception:
            pass
    t = threading.Thread(target=reader, daemon=True)
    t.start()
    time.sleep(seconds)
    try:
        p.kill()
    except Exception:
        pass
    try:
        p.wait(timeout=2)
    except Exception:
        pass
    t.join(1)
    names = set()
    for l in lines:
        m = re.match(r"\s*\S+\s+(Add|Rmv)\s+\d+\s+\d+\s+\S+\s+\S+\s+(.+)$", l.rstrip("\n"))
        if m:
            nm = m.group(2).strip()
            if m.group(1) == "Add":
                names.add(nm)
    return sorted(names)


# ---------------------------------------------------------------- Home Assistant

class HAUnavailable(Exception):
    pass


def _ha_token():
    """Read at call time (HM_HA_TOKEN or the token file in data/site.json), never stored, logged or returned."""
    return SITE.ha_token()


def ha_url():
    return SITE.ha_url()


def _scrub(obj):
    """Drop anything that looks like a credential from HA output."""
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items() if "token" not in k.lower() and "password" not in k.lower()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    if isinstance(obj, str) and "token=" in obj:
        return re.sub(r"token=[^&\s]+", "token=REDACTED", obj)
    return obj


def ha_get(path, timeout=4):
    base = ha_url()
    if not base:
        raise HAUnavailable("Home Assistant is not set up (homeAssistant.url in data/site.json)")
    tok = _ha_token()
    if not tok:
        raise HAUnavailable("no Home Assistant token (homeAssistant.tokenFile in data/site.json)")
    status, body = http_get(base + path, timeout=timeout,
                            headers={"Authorization": "Bearer " + tok, "Accept": "application/json"},
                            limit=4 * 1024 * 1024)
    del tok
    if status is None:
        raise HAUnavailable("Home Assistant did not answer")
    if status == 404:
        return None
    if status != 200:
        raise HAUnavailable("Home Assistant answered HTTP %s" % status)
    try:
        return _scrub(json.loads(body))
    except ValueError:
        raise HAUnavailable("Home Assistant sent something that is not JSON")


def ha_state(entity):
    return ha_get("/api/states/" + entity)


def ha_states(domain=None):
    states = ha_get("/api/states") or []
    if domain:
        states = [s for s in states if str(s.get("entity_id", "")).startswith(domain + ".")]
    return states


# ---------------------------------------------------------------- cast / http

def cast_info(ip):
    status, body = http_get("http://%s:8008/setup/eureka_info?params=name,build_info,net" % ip, timeout=3)
    if status != 200:
        return None
    try:
        d = json.loads(body)
    except ValueError:
        return None
    facts = {"name": d.get("name")}
    bi = d.get("build_info") or {}
    facts["firmware"] = d.get("cast_build_revision") or bi.get("cast_build_revision") or d.get("build_version")
    eth = d.get("ethernet_connected")
    if eth is None:
        eth = (d.get("net") or {}).get("ethernet_connected")
    facts["connection"] = "ethernet" if eth else "wifi"
    for k in ("ssid", "signal_level", "noise_level"):
        if d.get(k) is not None:
            facts[k] = d[k]
    if d.get("connected") is not None:
        facts["cloudConnected"] = d.get("connected")
    return facts


# ---------------------------------------------------------------- sweep

def sweep_network():
    """The house subnet, or for a very large one the /24 around this Mac's own address: a ping sweep stays short."""
    net = subnet()
    if net.num_addresses <= 1024:
        return net
    det = SITE.detect()
    anchor = det.get("address") if det.get("address") and ipaddress.ip_address(det["address"]) in net else router_ip()
    try:
        return ipaddress.ip_network(anchor + "/24", strict=False)
    except ValueError:
        return net


def sweep(network=None, workers=64):
    """{ip: latency_ms} for every host in the subnet that answers one ping."""
    network = network or sweep_network()
    hosts = [str(h) for h in network.hosts()]
    found = {}

    def one(ip):
        ok, ms = ping(ip, attempts=1)
        return ip, ok, ms
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for ip, ok, ms in ex.map(one, hosts):
            if ok:
                found[ip] = ms
    return found


# ================================================================ the monitor

def parse_end(end):
    dev, _, port = (end or "").partition(":")
    return dev, (port or None)


UNPROBED = ("none", "inferred")


class Monitor:
    """Runs the collectors on a schedule and keeps live.json and events.jsonl.

    `settings_fn()` returns the current settings dict (scanning, scanIntervalSec).
    Each collector is isolated: its error lands in `health`, the others go on."""

    def __init__(self, settings_fn=None, inventory_fn=None):
        import identify
        import router
        self.settings_fn = settings_fn or (lambda: {"scanning": True, "scanIntervalSec": 30})
        self.inventory_fn = inventory_fn or load_inventory
        self.health = {}
        self.lock = threading.Lock()
        self.cycle_lock = threading.RLock()
        self.identify = identify
        self.ident = identify.Engine()
        self.router = router.Router()
        self.specs_fn = None      # set by the server: device id -> knowledge specs
        self.last = None          # what the last cycle probed, for refresh_picture()
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.thread = None
        self.last_sweep = 0.0
        self.sweep_running = False
        # Live wiring: read this Mac's sockets each cycle. Off for a fixture inventory (tests) unless asked for.
        self.wiring_on = os.environ.get("HM_WIRING", "1" if inventory_fn is None else "0") == "1"
        self.wiring_events = []
        self.strangers = {}
        self.prev = None          # {"devices": {id: {...}}, "links": {...}} from the last cycle or file
        self._load_previous()

    # -- files
    @property
    def live_path(self):
        return os.path.join(state_dir(), "live.json")

    @property
    def events_path(self):
        return os.path.join(state_dir(), "events.jsonl")

    def _load_previous(self):
        try:
            with open(self.live_path) as f:
                prev = json.load(f)
            self.prev = {"devices": prev.get("devices") or {}, "links": prev.get("links") or {}}
            for s in prev.get("strangers") or []:
                if s.get("ip"):
                    self.strangers[s["ip"]] = s
            for k, s in (prev.get("registry") or {}).items():
                self.strangers.setdefault(k, s)
            self.last_sweep = 0.0
        except Exception:
            self.prev = None

    # -- scheduling
    def start(self):
        self.thread = threading.Thread(target=self._loop, name="collectors", daemon=True)
        self.thread.start()
        if self.wiring_on:
            threading.Thread(target=self._watch_ports, name="ports", daemon=True).start()

    def _watch_ports(self):
        """A cable going in or out of this Mac starts a cycle at once instead of waiting for the next one."""
        import portscan
        last = None
        while not self.stop.is_set():
            try:
                now = json.dumps(portscan.read_ports(), sort_keys=True)
                if last is not None and now != last:
                    with CACHE.lock:
                        CACHE.data.pop("usb", None)
                        CACHE.data.pop("displays", None)
                    self.wake.set()
                last = now
            except Exception:
                pass
            self.stop.wait(3)

    def scan_wiring(self, base, observe=True):
        """Read this Mac's sockets, fold the reading into wiring.json, return the inventory as wired now."""
        import portscan
        import wiring
        with wiring.LOCK:
            state = wiring.load_state(state_dir())
            host = SITE.host_device(base)
            if observe and host and any(d.get("id") == host for d in base.get("devices") or []):
                wiring.update_host(state, base, host, portscan.observe(), "local")
            inv = wiring.apply(base, state)
            self.wiring_events.extend(wiring.diff_events(base, inv, state))
            inv["wiring"] = wiring.summary(state, {d["id"] for d in inv.get("devices") or []})
            wiring.save_state(state_dir(), state)
        return inv

    def report(self, host_id, obs):
        """A reading sent in by another computer (portscan.py --post). Starts a cycle so the map follows."""
        import wiring
        base = self.inventory_fn()
        with wiring.LOCK:
            state = wiring.load_state(state_dir())
            wiring.update_host(state, base, host_id, obs, "report")
            wiring.save_state(state_dir(), state)
        self.wake.set()

    def _loop(self):
        while not self.stop.is_set():
            t0 = time.time()
            try:
                self.cycle()
            except Exception as e:  # the cycle itself should never die
                self._mark("cycle", False, e)
            try:
                interval = int(self.settings_fn().get("scanIntervalSec") or 30)
            except Exception:
                interval = 30
            wait = max(5, interval - (time.time() - t0))
            self.wake.wait(wait)
            self.wake.clear()

    def _mark(self, name, ok, err=None):
        with self.lock:
            self.health[name] = {"lastRun": now_iso(), "ok": bool(ok),
                                 "error": (str(err)[:300] if err else None)}

    def _isolated(self, name, fn, *a):
        try:
            r = fn(*a)
            self._mark(name, True)
            return r
        except Exception as e:
            self._mark(name, False, "%s: %s" % (type(e).__name__, e))
            return None

    # -- one cycle
    def cycle(self, sweep_now=None):
        with self.cycle_lock:
            return self._cycle(sweep_now)

    def _cycle(self, sweep_now=None):
        inv = self.inventory_fn()
        if self.wiring_on:
            w = self._isolated("wiring", self.scan_wiring, inv)
            inv = w or inv
        devices = inv.get("devices") or []
        results = {}

        # Shared, slow inputs, each its own collector.
        usb = self._isolated("usb", usb_devices)
        disp = self._isolated("display", displays)
        bt = self._isolated("bluetooth", bluetooth_devices)
        need_mdns = sorted({t for d in devices if (d.get("probe") or {}).get("type") == "mdns"
                            for t in ((d.get("probe") or {}).get("serviceTypes") or ["_companion-link._tcp", "_workstation._tcp"])})
        mdns = {}
        if need_mdns:
            def browse_all():
                out = {}
                with concurrent.futures.ThreadPoolExecutor(max_workers=len(need_mdns)) as ex:
                    for t, names in zip(need_mdns, ex.map(mdns_browse, need_mdns)):
                        if names is None:
                            raise RuntimeError("dns-sd could not start")
                        out[t] = names
                return out
            mdns = self._isolated("mdns", browse_all)
        ha_ok = {"value": None}

        def probe_one(dev):
            ptype = (dev.get("probe") or {}).get("type") or "none"
            try:
                r = self.probe_device(dev, usb=usb, disp=disp, mdns=mdns)
            except HAUnavailable as e:
                r = {"status": "unknown", "checks": [{"name": "home assistant", "ok": False, "detail": str(e)}], "facts": {}}
                ha_ok["value"] = str(e)
            except Exception as e:
                r = {"status": "unknown", "checks": [{"name": ptype, "ok": False,
                                                      "detail": "probe failed: %s: %s" % (type(e).__name__, e)}], "facts": {}}
                self._mark("probe:" + ptype, False, "%s: %s" % (dev.get("id"), e))
            # Attach the Home Assistant entity, if any.
            ent = dev.get("ha")
            if ent and ptype != "ha":
                try:
                    st = ha_state(ent)
                    if st:
                        r.setdefault("facts", {})["ha"] = {"entity": ent, "state": st.get("state"),
                                                           "lastChanged": st.get("last_changed")}
                except HAUnavailable as e:
                    r.setdefault("facts", {})["ha"] = {"entity": ent, "state": None, "error": str(e)}
                    ha_ok["value"] = str(e)
                except Exception as e:
                    r.setdefault("facts", {})["ha"] = {"entity": ent, "state": None, "error": str(e)[:200]}
            return dev["id"], r

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            for did, r in ex.map(probe_one, [d for d in devices if (d.get("probe") or {}).get("type") != "inferred"]):
                results[did] = r
        self._mark("devices", True)
        self.apply_bluetooth(devices, results, bt)
        if any(d.get("ha") or (d.get("probe") or {}).get("type") == "ha" for d in devices):
            self._mark("ha", ha_ok["value"] is None, ha_ok["value"])

        links = self._isolated("links", self.derive_links, inv, results) or {}
        for dev in devices:
            if (dev.get("probe") or {}).get("type") == "inferred":
                results[dev["id"]] = self.infer_device(dev, links)

        # Strangers: light sweep, at most every 5 minutes, off when scanning is false.
        settings = {}
        try:
            settings = self.settings_fn() or {}
        except Exception:
            pass
        do_sweep = sweep_now if sweep_now is not None else (
            settings.get("scanning", True) and time.time() - self.last_sweep >= SWEEP_TTL)
        if do_sweep:
            self.last_sweep = time.time()
            self._isolated("strangers", self.find_strangers, inv, results)
        elif not settings.get("scanning", True):
            with self.lock:
                self.health["strangers"] = {"lastRun": (self.health.get("strangers") or {}).get("lastRun"),
                                            "ok": True, "error": None, "note": "scanning is off"}

        snap = self.poll_router()
        self.last = {"results": results, "links": links, "bt": bt}
        self.publish(inv, results, links, bt, snap)
        return results, links

    # -- version 2: router, identity, hosts outside the inventory
    def poll_router(self):
        if not self.router.configured():
            with self.lock:
                self.health.pop("router", None)
            return None
        snap = self.router.poll()
        self._mark("router", snap.get("ok"), snap.get("error"))
        return snap

    def publish(self, inv, results, links, bt, snap):
        """Join the sources, probe the hosts the inventory does not list, write the state files."""
        fresh = bool(snap and snap.get("ok"))
        if fresh:
            self.apply_router_presence(inv, results, snap)
        self.update_registry(inv, results, snap if fresh else None)
        pic = self.identify.build_picture(inv, results, self.strangers, snap, self.ident, bluetooth=bt,
                                          specs_fn=self.specs_fn, router_fresh=fresh)
        dyn = self.probe_dynamic(pic)
        if self.ident.kick(pic["scanIps"], on_done=self.wake.set):
            pass
        if self.ident.health is not None:
            self._mark("identify", self.ident.health[0], self.ident.health[1])
        return self.finish(inv, results, links, pic=pic, dyn=dyn, snap=snap)

    def refresh_picture(self):
        """After an action: rebuild identity and live files from the last probes, without probing again."""
        with self.cycle_lock:
            if not self.last:
                return None
            inv = self.inventory_fn()
            if self.wiring_on:
                inv = self.scan_wiring(inv, observe=False)
            ids = {d["id"] for d in inv.get("devices") or []}
            results = {k: v for k, v in self.last["results"].items() if k in ids}
            links = {k: v for k, v in self.last["links"].items() if any(l["id"] == k for l in inv.get("links") or [])}
            return self.publish(inv, results, links, self.last.get("bt"), self.router.snapshot)

    def apply_router_presence(self, inv, results, snap):
        """Devices nothing else can probe, but whose address the inventory knows, get their presence
        from the router's client list. Absent means "not connected right now", which is no fault."""
        online = [c for c in snap.get("clients") or [] if c.get("online")]
        macs = {c["mac"]: c for c in online}
        ips = {c["ip"]: c for c in online if c.get("ip")}
        for dev in inv.get("devices") or []:
            if ((dev.get("probe") or {}).get("type") or "none") != "none":
                continue
            nets = [n for n in dev.get("net") or [] if n.get("medium") != "bluetooth" and (n.get("mac") or n.get("ip"))]
            if not nets:
                continue
            c = next((macs.get((n.get("mac") or "").upper()) or ips.get(n.get("ip")) for n in nets
                      if macs.get((n.get("mac") or "").upper()) or ips.get(n.get("ip"))), None)
            if c:
                how = "Wi-Fi %s, signal %s dBm" % (c.get("bandLabel"), c.get("rssi")) if c.get("medium") == "wifi" else "wired"
                results[dev["id"]] = {"status": "online", "latencyMs": None, "quiet": True,
                                      "checks": [{"name": "router client list", "ok": True, "detail": "connected, %s" % how}],
                                      "facts": {k: v for k, v in (("ip", c.get("ip")), ("mac", c["mac"]), ("connection", c.get("medium"))) if v}}
            else:
                results[dev["id"]] = {"status": "offline", "latencyMs": None, "quiet": True,
                                      "checks": [{"name": "router client list", "ok": None, "detail": "not connected right now"}],
                                      "facts": {}}

    def apply_bluetooth(self, devices, results, bt):
        """Devices with nothing else to probe get their status from the Mac's Bluetooth list."""
        for dev in devices:
            ptype = (dev.get("probe") or {}).get("type") or "none"
            if ptype not in ("none", "bluetooth"):
                continue
            if bt is None:
                if ptype == "bluetooth":
                    results[dev["id"]] = {"status": "unknown", "facts": {}, "checks": [
                        {"name": "bluetooth", "ok": False, "detail": "The Mac's Bluetooth list could not be read"}]}
                continue
            b = match_bluetooth(dev, bt)
            if b is None:
                if ptype == "bluetooth":
                    results[dev["id"]] = {"status": "offline", "facts": {}, "checks": [
                        {"name": "bluetooth", "ok": False, "detail": "Not paired with this Mac"}]}
                continue
            det = "%s %s this Mac over Bluetooth" % (b["name"], "is connected to" if b["connected"] else "is paired with, but not connected to,")
            if b.get("battery") is not None:
                det += ", battery %d%%" % b["battery"]
            # Paired but not connected is how headphones spend most of the day: not a fault, so never "offline".
            results[dev["id"]] = {
                "status": "online" if b["connected"] else "unknown", "latencyMs": None,
                "checks": [{"name": "bluetooth", "ok": True if b["connected"] else None, "detail": det}],
                "facts": {"connection": "bluetooth", "bluetooth": {k: v for k, v in b.items() if v is not None},
                          "battery": b.get("battery"), "firmware": b.get("firmware")}}

    def update_registry(self, inv, results, snap):
        """Hosts on the network that the inventory does not list: the sweep finds the ones that answer
        ping, the router knows the rest. Keyed by address, or 'mac:<MAC>' when there is none."""
        ts = now_iso()
        known = self.known_ips(inv, results)
        if snap:
            for c in snap.get("clients") or []:
                if not c.get("online"):
                    continue
                ip = c.get("ip") or None
                if ip and ip in known:
                    continue
                key = ip or ("mac:" + c["mac"])
                s = self.strangers.get(key)
                if s is None:
                    s = self.strangers[key] = {"ip": ip, "name": None, "firstSeen": self.ident.first_seen(c["mac"], ts)}
                s["mac"] = c["mac"]
                s["lastSeen"] = ts
                s["name"] = c.get("name") or s.get("name")
                if ip:
                    self.strangers.pop("mac:" + c["mac"], None)
        cutoff = time.time() - 86400
        for key, s in list(self.strangers.items()):
            if s.get("ip") and s["ip"] in known:
                del self.strangers[key]
                continue
            try:
                seen = datetime.datetime.fromisoformat(s.get("lastSeen") or s.get("firstSeen")).timestamp()
            except Exception:
                seen = time.time()
            if seen < cutoff:
                del self.strangers[key]

    def probe_dynamic(self, pic):
        """Live status of the hosts that are not in the inventory."""
        hosts = pic.get("hostLive") or {}
        ips = [h["ip"] for h in hosts.values() if h.get("ip")]
        pings = {}
        if ips:
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
                pings = dict(zip(ips, ex.map(lambda ip: ping(ip, attempts=1), ips)))
        out = {}
        ts = now_iso()
        for did, h in hosts.items():
            ok, ms = pings.get(h.get("ip"), (False, None))
            checks = []
            if h.get("ip"):
                checks.append({"name": "ping %s" % h["ip"], "ok": ok, "detail": ("%s ms" % ms) if ok else "no reply"})
            if h.get("routerOnline") is not None:
                checks.append({"name": "router client list", "ok": bool(h["routerOnline"]),
                               "detail": ("connected, %s" % h["connection"]) if h["routerOnline"] and h.get("connection")
                               else "connected" if h["routerOnline"] else "not connected right now"})
            if h.get("blockListOnly"):
                checks.append({"name": "router block list", "ok": None, "detail": "On the router's block list; not connected right now"})
            status = "online" if (ok or h.get("routerOnline")) else "offline"
            if not checks:
                status = "unknown"
            if status == "online":
                for s in self.strangers.values():
                    if (h.get("ip") and s.get("ip") == h["ip"]) or (h.get("mac") and s.get("mac") == h["mac"]):
                        s["lastSeen"] = ts
            out[did] = {"status": status, "latencyMs": ms if ok else None, "checks": checks,
                        "facts": {k: v for k, v in (("ip", h.get("ip")), ("mac", h.get("mac")), ("connection", h.get("connection"))) if v}}
        return out

    # -- device probes
    def probe_device(self, dev, usb=None, disp=None, mdns=None):
        p = dev.get("probe") or {}
        t = p.get("type") or "none"
        fn = getattr(self, "probe_" + t, None)
        if fn is None:
            return {"status": "unknown", "checks": [{"name": t, "ok": False, "detail": "no collector for probe type %r" % t}], "facts": {}}
        return fn(dev, p, usb=usb, disp=disp, mdns=mdns)

    def probe_none(self, dev, p, **_):
        seen = dev.get("usbSeen") or dev.get("displaySeen")
        if seen:
            return {"status": "online", "checks": [{"name": "plugged in", "ok": True, "detail": "%s, seen by %s. It is not in the inventory." % (
                seen.get("name") or dev.get("name"), seen.get("by"))}], "facts": dict(seen)}
        return {"status": "unmonitored", "checks": [{"name": "probe", "ok": None,
                                                     "detail": "Nothing to probe: no address, no USB id. Shown as unmonitored, never green."}],
                "facts": {}}

    def probe_self(self, dev, p, disp=None, **_):
        facts, checks = {}, []
        ifaces = {}
        for n in dev.get("net") or []:
            ifn = n.get("if")
            if not ifn or not re.match(r"^en\d+$", ifn):
                continue
            i = interface(ifn)
            ifaces[ifn] = {"status": i.get("status"), "speed": i.get("speed"), "media": i.get("media"),
                           "ipv4": i.get("ipv4"), "medium": n.get("medium")}
            want = n.get("linkSpeed")
            ok = i.get("active") and (not want or i.get("speed") == want) if n.get("ip") else None
            checks.append({"name": "%s (%s)" % (ifn, n.get("medium") or "?"), "ok": ok,
                           "detail": "%s%s%s" % (i.get("status"), (", " + i["speedRaw"]) if i.get("speedRaw") else "",
                                                 (", " + i["ipv4"]) if i.get("ipv4") else "")})
        facts["interfaces"] = ifaces
        so = service_order()
        facts["serviceOrder"] = [s["name"] for s in so]
        facts["defaultRouteInterface"] = default_route_if()
        wif = wifi_interface()
        facts["wifiOn"] = wifi_power(wif)
        if disp:
            main = [d for d in disp if d.get("main")] or disp
            facts["displayMode"] = display_mode_text(main[0]) if main else None
        facts["uptimeSec"] = uptime_sec()
        checks.append({"name": "default route", "ok": facts["defaultRouteInterface"] is not None,
                       "detail": "via %s" % facts["defaultRouteInterface"]})
        return {"status": "online", "latencyMs": 0, "checks": checks, "facts": facts}

    def probe_ping(self, dev, p, **_):
        ip = p.get("ip")
        ok, ms = ping(ip)
        checks = [{"name": "ping %s" % ip, "ok": ok, "detail": ("%s ms" % ms) if ok else "no reply"}]
        tcp_ok = None
        if p.get("tcp"):
            tcp_ok, tms, det = tcp_check(ip, p["tcp"])
            checks.append({"name": "tcp %s" % p["tcp"], "ok": tcp_ok, "detail": det})
            if ms is None and tcp_ok:
                ms = tms
        status = "online" if (ok or tcp_ok) else "offline"
        if p.get("tcp") and ok and tcp_ok is False:
            status = "degraded"
        return {"status": status, "latencyMs": ms, "checks": checks, "facts": {"ip": ip}}

    def probe_tcp(self, dev, p, **_):
        host, port = p.get("host"), int(p.get("tcp") or 0)
        resolved = resolve(host) if host else []
        cands = []
        for ip in resolved + list(p.get("fallbackIps") or []):
            if ip not in cands:
                cands.append(ip)
        checks = [{"name": "resolve %s" % host, "ok": bool(resolved),
                   "detail": ", ".join(resolved) if resolved else "name did not resolve"}]
        facts = {"resolvedIp": resolved[0] if resolved else None}
        status, latency = "offline", None
        for ip in cands:
            ok, ms, det = tcp_check(ip, port)
            checks.append({"name": "tcp %s:%d" % (ip, port), "ok": ok, "detail": det})
            if ok:
                status, latency = "online", ms
                facts["answeredIp"] = ip
                break
        if status != "online":
            # Ping is informational only (the NAS sheds ping under load).
            first = cands[0] if cands else None
            if first:
                pok, pms = ping(first, attempts=1)
                checks.append({"name": "ping %s (informational)" % first, "ok": pok,
                               "detail": ("%s ms" % pms) if pok else "no reply"})
                if pok:
                    status = "degraded"
        return {"status": status, "latencyMs": latency, "checks": checks, "facts": facts}

    def probe_http(self, dev, p, **_):
        url = p.get("url")
        t0 = time.time()
        status, body = http_get(url, timeout=3)
        ms = round((time.time() - t0) * 1000, 1)
        facts = {}
        if status is not None:
            try:
                d = json.loads(body)
                if isinstance(d, dict):
                    for k in ("name", "swversion", "apiversion", "modelid", "bridgeid"):
                        if d.get(k) is not None:
                            facts[k] = d[k]
            except ValueError:
                pass
        ok = status is not None and status < 500
        return {"status": "online" if ok else "offline", "latencyMs": ms if ok else None,
                "checks": [{"name": "GET %s" % url, "ok": ok, "detail": ("HTTP %s" % status) if status else str(body)[:120]}],
                "facts": facts}

    def probe_cast(self, dev, p, **_):
        ip = p.get("ip")
        t0 = time.time()
        info = cast_info(ip)
        ms = round((time.time() - t0) * 1000, 1)
        checks = [{"name": "cast info %s:8008" % ip, "ok": info is not None,
                   "detail": ("%s, firmware %s" % (info.get("name"), info.get("firmware"))) if info else "no answer"}]
        if info:
            return {"status": "online", "latencyMs": ms, "checks": checks, "facts": info}
        ok, pms = ping(ip)
        checks.append({"name": "ping %s" % ip, "ok": ok, "detail": ("%s ms" % pms) if ok else "no reply"})
        return {"status": "degraded" if ok else "offline", "latencyMs": pms, "checks": checks, "facts": {}}

    def probe_usb(self, dev, p, usb=None, **_):
        if usb is None:
            return {"status": "unknown", "checks": [{"name": "usb", "ok": False, "detail": "USB list unavailable (system_profiler failed)"}], "facts": {}}
        vid, pid = (p.get("vendorId") or "").lower(), (p.get("productId") or "").lower()
        hits = [u for u in usb if u["vendorId"] == vid and u["productId"] == pid]
        if not hits:
            return {"status": "offline", "checks": [{"name": "usb %s:%s" % (vid, pid), "ok": False, "detail": "not enumerated"}], "facts": {}}
        u = hits[0]
        facts = {"usbName": u["name"], "linkSpeed": u["linkSpeed"], "power": u["power"], "behind": u["parent"], "location": u["location"]}
        return {"status": "online", "latencyMs": None,
                "checks": [{"name": "usb %s:%s" % (vid, pid), "ok": True, "detail": "%s at %s" % (u["name"], u["linkSpeed"])}],
                "facts": {k: v for k, v in facts.items() if v}}

    def probe_display(self, dev, p, disp=None, **_):
        if disp is None:
            return {"status": "unknown", "checks": [{"name": "display", "ok": False, "detail": "display list unavailable"}], "facts": {}}
        hits = [d for d in disp if p.get("match", "").lower() in (d.get("name") or "").lower()]
        if not hits:
            return {"status": "offline", "checks": [{"name": "display %s" % p.get("match"), "ok": False,
                                                     "detail": "not connected to this Mac (or a KVM switch is on the other input)"}], "facts": {}}
        d = hits[0]
        facts = {"pixels": d["pixels"], "looksLike": d["looksLike"], "refreshHz": d["refreshHz"], "hidpi": d["hidpi"],
                 "mode": display_mode_text(d)}
        return {"status": "online" if d.get("online") else "degraded", "latencyMs": None,
                "checks": [{"name": "display", "ok": True, "detail": facts["mode"]}], "facts": facts}

    def probe_interface(self, dev, p, usb=None, **_):
        i = interface(p.get("if"))
        facts = {"if": i["name"], "status": i.get("status"), "media": i.get("media"), "speed": i.get("speed"),
                 "speedRaw": i.get("speedRaw"), "duplex": i.get("duplex"), "ipv4": i.get("ipv4")}
        m = re.search(r"\b([0-9a-f]{4}):([0-9a-f]{4})\b", dev.get("model") or "")
        if m and usb:
            for u in usb:
                if u["vendorId"] == "0x" + m.group(1) and u["productId"] == "0x" + m.group(2):
                    facts["usbLinkSpeed"] = u["linkSpeed"]
        checks = [{"name": "ifconfig %s" % i["name"], "ok": i.get("active"),
                   "detail": "%s%s" % (i.get("status"), (", " + i["speedRaw"] + (" " + i["duplex"] if i.get("duplex") else "")) if i.get("speedRaw") else "")}]
        status = "online" if i.get("active") else "offline"
        return {"status": status, "latencyMs": None, "checks": checks, "facts": {k: v for k, v in facts.items() if v is not None}}

    def probe_mdns(self, dev, p, mdns=None, **_):
        if mdns is None:
            return {"status": "unknown", "checks": [{"name": "mdns", "ok": False, "detail": "mDNS browse failed"}], "facts": {}}
        name = (p.get("name") or "").lower()
        seen = sorted({t for t, names in mdns.items() for n in names if n.lower().startswith(name)})
        if seen:
            return {"status": "online", "latencyMs": None,
                    "checks": [{"name": "mDNS %s" % p.get("name"), "ok": True, "detail": "advertising " + ", ".join(seen)}],
                    "facts": {"mdnsServices": seen}}
        return {"status": "offline", "latencyMs": None,
                "checks": [{"name": "mDNS %s" % p.get("name"), "ok": False, "detail": "not advertising (asleep, away or off)"}],
                "facts": {}}

    def probe_ha(self, dev, p, **_):
        ent = p.get("entity")
        st = ha_state(ent)  # raises HAUnavailable -> unknown
        if st is None:
            return {"status": "unknown", "checks": [{"name": "ha %s" % ent, "ok": False, "detail": "entity not found"}], "facts": {}}
        s = st.get("state")
        if s in ("home",) or (not ent.startswith("device_tracker.") and s not in ("unavailable", "unknown", "off")):
            status = "online"
        elif s in ("unavailable", "unknown", None):
            status = "unknown"
        elif ent.startswith("device_tracker."):
            # A phone that left the house is away, not broken: never raise it as offline.
            facts = {"ha": {"entity": ent, "state": s, "lastChanged": st.get("last_changed")}}
            return {"status": "unknown", "latencyMs": None,
                    "checks": [{"name": "presence", "ok": None, "detail": "away from home"}], "facts": facts}
        else:
            status = "offline"
        facts = {"ha": {"entity": ent, "state": s, "lastChanged": st.get("last_changed")}}
        return {"status": status, "latencyMs": None,
                "checks": [{"name": "ha %s" % ent, "ok": status == "online", "detail": "state %s" % s}], "facts": facts}

    def infer_device(self, dev, links):
        ids = (dev.get("probe") or {}).get("from") or []
        sts = [(lid, (links.get(lid) or {}).get("status", "unknown")) for lid in ids]
        if any(s == "up" for _, s in sts):
            status = "online"
        elif sts and all(s == "down" for _, s in sts):
            status = "offline"
        else:
            status = "unknown"
        return {"status": status, "latencyMs": None,
                "checks": [{"name": "inferred from %s" % lid, "ok": s == "up", "detail": "link %s" % s} for lid, s in sts],
                "facts": {"inferred": True}}

    # -- links
    def derive_links(self, inv, results):
        devs = {d["id"]: d for d in inv.get("devices") or []}
        out = {}
        for link in inv.get("links") or []:
            ends = [parse_end(link.get("from"))[0], parse_end(link.get("to"))[0]]
            probed, unprobed = [], []
            for e in ends:
                ptype = ((devs.get(e) or {}).get("probe") or {}).get("type") or "none"
                (unprobed if ptype in UNPROBED else probed).append(e)
            # Inferred ends (the switch) are transparent: their state comes from these links.
            hard_unprobed = [e for e in unprobed if ((devs.get(e) or {}).get("probe") or {}).get("type") != "inferred"]
            sts = {e: (results.get(e) or {}).get("status", "unknown") for e in probed}
            name = lambda e: (devs.get(e) or {}).get("name", e)
            if link.get("cable") == "bluetooth":
                # A Bluetooth link is as alive as its peripheral's connection to the host.
                per = next((e for e in ends if ((results.get(e) or {}).get("facts") or {}).get("bluetooth")), None)
                b = (((results.get(per) or {}).get("facts") or {}).get("bluetooth")) if per else None
                if b is None:
                    out[link["id"]] = {"status": "unknown", "speed": None,
                                       "detail": "Neither end shows up in this Mac's Bluetooth list"}
                else:
                    det = "%s %s" % (b.get("name"), "connected over Bluetooth" if b.get("connected") else "paired but not connected")
                    if b.get("battery") is not None:
                        det += ", battery %d%%" % b["battery"]
                    out[link["id"]] = {"status": "up" if b.get("connected") else "unknown", "speed": None, "detail": det,
                                       "state": "connected" if b.get("connected") else "paired"}
                continue
            off = [e for e, s in sts.items() if s == "offline"]
            speed, detail = None, None
            if off:
                status = "down"
                detail = "%s %s offline" % (" and ".join(name(e) for e in off), "is" if len(off) == 1 else "are")
            elif link.get("verified") == "plan" and hard_unprobed:
                status = "planned"
                detail = "From the plan; %s cannot be probed, so this cable is not confirmed" % " and ".join(name(e) for e in hard_unprobed)
            elif probed and all(s in ("online", "degraded") for s in sts.values()):
                status = "up"
                speed, detail = self._link_speed(link, devs, results)
                if link.get("verified") == "plan":
                    detail = (detail + "; " if detail else "") + "both ends answer, cabling from the plan"
            else:
                status = "unknown"
                unk = [e for e, s in sts.items() if s not in ("online", "degraded")]
                detail = ("%s: status unknown" % ", ".join(name(e) for e in unk)) if unk else "no end can be probed"
            if speed is None and status in ("up", "planned") and link.get("speed"):
                speed = link["speed"]
                detail = (detail + "; " if detail else "") + "speed from the inventory, not measured"
            out[link["id"]] = {"status": status, "speed": speed, "detail": detail}
        return out

    def _link_speed(self, link, devs, results):
        """Measured speed for a link, from whichever end can tell."""
        carries = link.get("carries") or []
        for end in (link.get("from"), link.get("to")):
            e = parse_end(end)[0]
            dev = devs.get(e) or {}
            p = dev.get("probe") or {}
            f = (results.get(e) or {}).get("facts") or {}
            if link.get("cable") == "ethernet" and p.get("type") == "interface" and f.get("speed"):
                return f["speed"], "%s negotiated %s%s" % (p.get("if"), f.get("speedRaw"), (" " + f["duplex"]) if f.get("duplex") else "")
            if link.get("cable") in ("usb", "usb-c") and "network" in carries and f.get("usbLinkSpeed"):
                return f["usbLinkSpeed"], "USB link of %s" % dev.get("name")
            if link.get("cable") in ("usb", "usb-c") and p.get("type") == "usb" and f.get("linkSpeed") and dev.get("kind") != "kvm":
                return f["linkSpeed"], "USB link of %s" % dev.get("name")
            if link.get("cable") == "hdmi" and p.get("type") == "display" and f.get("mode"):
                hz = f.get("refreshHz")
                return ("%s%s" % (f.get("pixels"), (" @ %g Hz" % hz) if hz else "")), f.get("mode")
        return None, None

    # -- strangers
    def known_ips(self, inv, results):
        ips = set()
        for d in inv.get("devices") or []:
            for n in d.get("net") or []:
                if n.get("ip"):
                    ips.add(n["ip"])
            p = d.get("probe") or {}
            for k in ("ip",):
                if p.get(k):
                    ips.add(p[k])
            for ip in p.get("fallbackIps") or []:
                ips.add(ip)
        for r in results.values():
            f = (r or {}).get("facts") or {}
            for k in ("resolvedIp", "answeredIp", "ip"):
                if f.get(k):
                    ips.add(f[k])
            for i in (f.get("interfaces") or {}).values():
                if i.get("ipv4"):
                    ips.add(i["ipv4"])
        return ips

    def find_strangers(self, inv, results):
        found = sweep()
        known = self.known_ips(inv, results)
        ts = now_iso()
        new = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            names = dict(zip([ip for ip in found if ip not in known],
                             ex.map(rdns, [ip for ip in found if ip not in known])))
        for ip, nm in names.items():
            s = self.strangers.get(ip)
            if s is None:
                s = {"ip": ip, "name": nm, "firstSeen": ts}
                self.strangers[ip] = s
                new.append(s)
            s["lastSeen"] = ts
            if nm:
                s["name"] = nm
        # update_registry() drops the ones that got an inventory entry or were not seen for a day.
        return found

    # -- finish: timestamps, events, file
    def finish(self, inv, results, links, pic=None, dyn=None, snap=None):
        ts = now_iso()
        pic = pic or {}
        dyn = dyn or {}
        devs = {d["id"]: d for d in inv.get("devices") or []}
        names = {d["id"]: d.get("name", d["id"]) for d in inv.get("devices") or []}
        names.update({d["id"]: d.get("name", d["id"]) for d in pic.get("dynamic") or []})
        prev = self.prev or {"devices": {}, "links": {}}
        first_run = self.prev is None
        security = pic.get("security") or {}
        identities = pic.get("identities") or {}
        out_devices = {}
        all_results = dict(results)
        all_results.update(dyn)
        for did, r in all_results.items():
            pd = prev["devices"].get(did) or {}
            status = r.get("status", "unknown")
            entry = {"status": status, "latencyMs": r.get("latencyMs"), "checks": r.get("checks") or [],
                     "facts": r.get("facts") or {}}
            entry["lastSeen"] = ts if status in ("online", "degraded") else pd.get("lastSeen")
            changed = pd.get("status") is not None and pd.get("status") != status
            entry["lastChange"] = ts if (changed or not pd.get("lastChange")) else pd.get("lastChange")
            if did in security:
                entry["security"] = security[did]
            if did in (pic.get("traffic") or {}):
                entry["traffic"] = pic["traffic"][did]
            out_devices[did] = entry
            name = names.get(did, did)
            if did in dyn:
                # Phones sleep and wake all day: their comings and goings are not events. A new one is.
                if not first_run and did not in prev["devices"]:
                    sec = security.get(did) or {}
                    h = (pic.get("hostLive") or {}).get(did) or {}
                    if not h.get("blockListOnly"):
                        self.event("security", did, None, None, sec.get("level"),
                                   "New on the network: %s%s. It is not in the inventory." % (
                                       name, (" at " + h["ip"]) if h.get("ip") and h["ip"] not in name else ""),
                                   ip=h.get("ip"), code="new-host")
            elif r.get("quiet"):
                pass        # presence read off the router: a watch or a printer coming and going is not an event
            elif changed:
                self.event("device", did, None, pd.get("status"), status, device_text(name, pd.get("status"), status, entry))
            elif pd.get("status") is None and status == "offline":
                self.event("device", did, None, None, status, "%s is offline (first check since the monitor started)." % name)
            # security transitions
            psec, sec = pd.get("security") or {}, security.get(did) or {}
            if psec and sec:
                if sec.get("blocked") and not psec.get("blocked"):
                    self.event("security", did, None, psec.get("level"), "blocked", "%s is now blocked at the router." % name, code="blocked")
                elif psec.get("blocked") and not sec.get("blocked"):
                    self.event("security", did, None, "blocked", sec.get("level"), "%s is no longer blocked at the router." % name, code="unblocked")
                elif sec.get("level") == "suspicious" and psec.get("level") in ("ok", "watch"):
                    self.event("security", did, None, psec.get("level"), "suspicious", "%s now looks suspicious: %s" % (
                        name, " ".join(x["text"] for x in sec.get("reasons") or [])[:400]), code="suspicious")
        out_links = {}
        for lid, l in links.items():
            pl = prev["links"].get(lid) or {}
            out_links[lid] = l
            link = next((x for x in inv.get("links") or [] if x["id"] == lid), {})
            a = (devs.get(parse_end(link.get("from"))[0]) or {}).get("name", link.get("from"))
            b = (devs.get(parse_end(link.get("to"))[0]) or {}).get("name", link.get("to"))
            if pl.get("status") is not None and pl.get("status") != l["status"]:
                self.event("link", None, lid, pl.get("status"), l["status"], link_text(a, b, pl.get("status"), l))
            elif pl.get("status") == "up" and l["status"] == "up" and pl.get("speed") and l.get("speed") and pl["speed"] != l["speed"]:
                self.event("link", None, lid, pl["speed"], l["speed"],
                           "The link from %s to %s changed speed: %s to %s." % (a, b, pl["speed"], l["speed"]))
            elif pl.get("status") is None and l["status"] == "down":
                self.event("link", None, lid, None, "down", "The link from %s to %s is down (%s)." % (a, b, l.get("detail") or "first check"))
        # Wi-Fi links follow their device; they make no events of their own (a phone asleep is not news).
        for lid, l in (pic.get("linkLive") or {}).items():
            st = (out_devices.get(l.get("_status_of")) or {}).get("status")
            out_links[lid] = {"status": "up" if st in ("online", "degraded") else "down" if st == "offline" else "unknown",
                              "speed": l.get("speed"), "detail": l.get("detail")}
        summary = {"online": 0, "offline": 0, "unknown": 0, "degraded": 0, "unmonitored": 0,
                   "unidentified": 0, "suspicious": 0, "blocked": 0}
        for did, e in out_devices.items():
            summary[e["status"]] = summary.get(e["status"], 0) + 1
            if (identities.get(did) or {}).get("state") == "unidentified":
                summary["unidentified"] += 1
            lvl = (e.get("security") or {}).get("level")
            if lvl in ("suspicious", "blocked"):
                summary[lvl] += 1
        dyn_ips = {(h or {}).get("ip") for h in (pic.get("hostLive") or {}).values()}
        strangers = [dict(s) for s in self.strangers.values() if s.get("ip") and (not pic or s["ip"] in dyn_ips)]
        rstat = self.router.status()
        rstat["clients"] = len([c for c in (snap or {}).get("clients") or [] if c.get("online")]) if snap else 0
        for k in ("model", "firmware", "stale"):
            if snap and snap.get(k) is not None:
                rstat[k] = snap[k]
        if snap:
            rstat["blockList"] = len(snap.get("blockList") or [])
        for lid, text, code in self.wiring_events:
            self.event("link", None, lid, None, None, text, code=code)
        self.wiring_events = []
        live = {"ts": ts, "wiring": inv.get("wiring") or {"rev": 0, "hosts": {}}, "devices": out_devices, "links": out_links,
                "strangers": sorted(strangers, key=lambda s: tuple(int(x) for x in s["ip"].split("."))),
                "summary": summary, "wireless": pic.get("wireless") or {}, "router": rstat,
                "registry": {k: v for k, v in self.strangers.items()}}
        write_json_atomic(self.live_path, live)
        if pic:
            write_json_atomic(os.path.join(state_dir(), "identity.json"),
                              {k: pic.get(k) for k in ("ts", "identities", "dynamic", "wifiLinks", "addresses")})
        write_json_atomic(os.path.join(state_dir(), "router.json"),
                          dict(snap or {}, **{k: rstat[k] for k in ("configured", "ok", "error", "lastRun", "transport")}))
        self.prev = {"devices": out_devices, "links": out_links}
        return live

    def event(self, kind, device, link, frm, to, text, **extra):
        row = {"ts": now_iso(), "kind": kind, "device": device, "link": link, "from": frm, "to": to, "text": text}
        row.update({k: v for k, v in extra.items() if v is not None})
        append_jsonl(self.events_path, row)


def device_text(name, frm, to, entry):
    ha = (entry.get("facts") or {}).get("ha") or {}
    if ha.get("state") in ("home", "not_home") and str(ha.get("entity", "")).startswith("device_tracker."):
        return "%s %s." % (name, "came home" if ha["state"] == "home" else "left home")
    if to == "offline":
        return "%s went offline." % name
    if to == "online":
        return "%s is back online." % name if frm in ("offline", "degraded", "unknown") else "%s is online." % name
    if to == "degraded":
        return "%s answers but not fully (%s)." % (name, "; ".join(c["detail"] for c in entry.get("checks") or [] if c.get("ok") is False) or "a check failed")
    if to == "unknown":
        return "%s can no longer be checked." % name
    return "%s changed from %s to %s." % (name, frm, to)


def link_text(a, b, frm, l):
    to = l["status"]
    if to == "up":
        return "The link from %s to %s is up%s." % (a, b, (" at " + l["speed"]) if l.get("speed") else "")
    if to == "down":
        return "The link from %s to %s went down%s." % (a, b, (" (" + l["detail"] + ")") if l.get("detail") else "")
    if to == "planned":
        return "The link from %s to %s is back to planned (not confirmed)." % (a, b)
    return "The link from %s to %s can no longer be checked." % (a, b)
