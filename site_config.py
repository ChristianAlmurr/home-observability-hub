"""The one place that knows which house this is.

Everything that used to be hardwired (the subnet, the router's address, the computer the hub runs
on, which devices must never be blocked, the owner's name in the agent prompt) comes from
`data/site.json`. A missing file, a missing key or a value of "auto" falls back to what can be
detected on this Mac, so a fresh install runs before onboarding has written anything.

Standard library only, Python 3.9+. Reading the site never raises: a broken file is reported
in `problems` and the defaults are used.

    import site_config as S
    S.get()["network"]["subnet"]      # "192.168.1.0/24"
    S.subnet()                         # ipaddress.IPv4Network
    S.owner()                          # "Alex", or "you"
"""
import copy
import ipaddress
import json
import os
import re
import subprocess
import threading

ROOT = os.path.dirname(os.path.abspath(__file__))
APP = "home-observability-hub"

DEFAULTS = {
    "schema": 1,
    "home": {"name": "Home", "owner": ""},
    "network": {
        "subnet": "auto",               # CIDR of the home LAN, or "auto" (from this Mac's main interface)
        "gateway": "auto",              # the router's LAN address, or "auto" (the default route)
        "extraNets": [],                # more CIDRs probes may reach, e.g. a cable modem's 192.168.100.1/32
    },
    "router": {
        "type": "none",                 # "asuswrt" (ASUS, read over SSH or the web login) or "none"
        "deviceId": None,               # inventory id of the main router
        "user": "admin",
        "sshKey": "~/.config/home-observability-hub/router_ed25519",
        "keychainService": "home-observability-hub-router",
        "writes": False,                # may the hub change the router's own block list (after one approval each)
    },
    "host": {"deviceId": "auto"},       # inventory id of the computer the hub runs on ("auto": the kind=computer device marked self)
    "protected": [],                    # ids never blocked or removed: router, mesh nodes, modem, switches, this computer
    "handsOff": [],                     # [{"id", "ips": [], "names": [], "macs": [], "why"}]: managed or someone else's devices: look, never touch
    "secretDirs": ["~/.ssh", "~/.aws", "~/.gnupg", "~/.config/gh", "~/.config/home-observability-hub", "~/.kube", "~/.docker",
                   "~/.config/gcloud", "~/.netrc"],
    "homeAssistant": {"url": "", "tokenFile": "~/.config/home-observability-hub/ha-token"},
    "server": {"port": 8799, "allowedHosts": []},
}

ROUTER_TYPES = ("asuswrt", "none")
EMPTY_INVENTORY = {"schema": 2, "devices": [], "links": [], "rooms": [], "zones": []}
# Secret folders that are always off limits, whatever data/site.json lists.
FIXED_SECRET_DIRS = ["~/.ssh", "~/.aws", "~/.gnupg", "~/.netrc", "~/Library/Keychains", "~/.config/" + APP]

_lock = threading.Lock()
_cache = {"mtime": None, "path": None, "data": None, "problems": []}
_detect = {}


def config_dir():
    """Where secrets live (router key, Home Assistant token). Never inside the repo."""
    return os.path.expanduser(os.environ.get("HOH_CONFIG_DIR") or "~/.config/" + APP)


def path():
    return os.environ.get("HM_SITE") or os.path.join(ROOT, "data", "site.json")


def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _run(argv, timeout=4):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.stdout if p.returncode == 0 else ""
    except Exception:
        return ""


def detect():
    """What this Mac says about its network: {gateway, interface, address, subnet}. Cached; never raises."""
    if _detect:
        return dict(_detect)
    out = {"gateway": None, "interface": None, "address": None, "subnet": None}
    t = _run(["/sbin/route", "-n", "get", "default"])
    m = re.search(r"gateway:\s*(\S+)", t)
    i = re.search(r"interface:\s*(\S+)", t)
    if m:
        out["gateway"] = m.group(1)
    if i:
        out["interface"] = i.group(1)
    if out["interface"]:
        t = _run(["/sbin/ifconfig", out["interface"]])
        a = re.search(r"\binet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", t)
        if a:
            out["address"] = a.group(1)
            try:
                mask = int(a.group(2), 16)
                prefix = bin(mask).count("1")
                out["subnet"] = str(ipaddress.ip_network("%s/%d" % (a.group(1), prefix), strict=False))
            except ValueError:
                pass
    if not out["subnet"] and out["gateway"]:
        try:
            out["subnet"] = str(ipaddress.ip_network(out["gateway"] + "/24", strict=False))
        except ValueError:
            pass
    _detect.update(out)
    return dict(out)


def _resolve(data):
    det = None
    net = data["network"]
    if net.get("subnet") in (None, "", "auto"):
        det = det or detect()
        net["subnet"] = det.get("subnet") or "192.168.1.0/24"
        net["subnetSource"] = "detected" if det.get("subnet") else "fallback"
    else:
        net["subnetSource"] = "site"
    if net.get("gateway") in (None, "", "auto"):
        det = det or detect()
        gw = det.get("gateway")
        net["gatewaySource"] = "detected" if gw else "fallback"
        if not gw:
            try:
                n = ipaddress.ip_network(net["subnet"], strict=False)
                gw = str(next(n.hosts()))
            except (ValueError, StopIteration):
                gw = "192.168.1.1"
        net["gateway"] = gw
    else:
        net["gatewaySource"] = "site"
    if not data["home"].get("owner"):
        data["home"]["owner"] = ""
    return data


def load(fresh=False):
    """(site dict, problems list). Cached by file mtime."""
    p = path()
    try:
        mtime = os.path.getmtime(p)
    except OSError:
        mtime = None
    with _lock:
        if not fresh and _cache["data"] is not None and _cache["mtime"] == mtime and _cache["path"] == p:
            return copy.deepcopy(_cache["data"]), list(_cache["problems"])
        problems, over = [], {}
        if mtime is not None:
            try:
                with open(p) as f:
                    over = json.load(f)
                if not isinstance(over, dict):
                    problems.append("data/site.json is not a JSON object; using defaults.")
                    over = {}
            except (OSError, ValueError) as e:
                problems.append("data/site.json could not be read (%s); using defaults." % e)
                over = {}
        merged = _merge(DEFAULTS, over)
        for k, v in DEFAULTS.items():
            # A section of the wrong type (say "router": "asus") falls back to its defaults, with a word about it.
            if isinstance(v, dict) and not isinstance(merged.get(k), dict):
                problems.append("%s in data/site.json should be an object; using the defaults for it." % k)
                merged[k] = copy.deepcopy(v)
            elif isinstance(v, list) and not isinstance(merged.get(k), list):
                problems.append("%s in data/site.json should be a list; using the defaults for it." % k)
                merged[k] = copy.deepcopy(v)
        data = _resolve(merged)
        try:
            ipaddress.ip_network(data["network"]["subnet"], strict=False)
        except ValueError:
            problems.append("network.subnet %r is not a CIDR; using 192.168.1.0/24." % data["network"]["subnet"])
            data["network"]["subnet"] = "192.168.1.0/24"
        data["configured"] = mtime is not None and not problems
        _cache.update(mtime=mtime, path=p, data=data, problems=problems)
        return copy.deepcopy(data), list(problems)


def get():
    return load()[0]


def reset_cache():
    with _lock:
        _cache.update(mtime=None, path=None, data=None, problems=[])
    _detect.clear()


# ---------------------------------------------------------------- shortcuts

def subnet():
    return ipaddress.ip_network(get()["network"]["subnet"], strict=False)


def gateway():
    return get()["network"]["gateway"]


def allowed_nets():
    """Where probes may go: the LAN, loopback, Tailscale's range and any extra nets."""
    s = get()
    nets = [subnet(), ipaddress.ip_network("127.0.0.1/32"), ipaddress.ip_network("100.64.0.0/10")]
    for c in s["network"].get("extraNets") or []:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    return nets


def ip_allowed(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in allowed_nets())


def owner():
    """The person's first name for prompts and copy, or "you"."""
    return (get()["home"].get("owner") or "").strip() or "you"


def owner_or(fallback):
    return (get()["home"].get("owner") or "").strip() or fallback


def home_name():
    return (get()["home"].get("name") or "").strip() or "Home"


def router_type():
    t = str(get()["router"].get("type") or "none").lower()
    return t if t in ROUTER_TYPES else "none"


def router_device():
    return get()["router"].get("deviceId")


def host_device(inventory=None):
    """Inventory id of the computer the hub runs on."""
    h = (get().get("host") or {}).get("deviceId")
    if h and h != "auto":
        return h
    for d in (inventory or {}).get("devices") or []:
        if d.get("kind") == "computer" and ((d.get("probe") or {}).get("type") == "self" or d.get("self")):
            return d["id"]
    return None


def protected_ids(inventory=None):
    """Never blocked, never removed: the listed ids, the router, the hub's own computer, and network gear."""
    s = get()
    out = set(s.get("protected") or [])
    if s["router"].get("deviceId"):
        out.add(s["router"]["deviceId"])
    h = host_device(inventory)
    if h:
        out.add(h)
    for d in (inventory or {}).get("devices") or []:
        if d.get("kind") in ("router", "access-point", "modem", "switch", "internet"):
            out.add(d["id"])
    return sorted(out)


def hands_off():
    """[{id, ips, names, why}] for devices the hub and its agent may look at but never act on."""
    out = []
    for h in get().get("handsOff") or []:
        if isinstance(h, str):
            h = {"id": h}
        if isinstance(h, dict) and h.get("id"):
            out.append({"id": h["id"], "ips": list(h.get("ips") or []), "names": list(h.get("names") or []),
                        "macs": [m for m in h.get("macs") or [] if isinstance(m, str)],
                        "why": h.get("why") or "someone else manages it"})
    return out


def hands_off_all(inventory=None):
    """(ids, ips, names) of every hands-off device: what data/site.json says plus the addresses and host names
    the inventory records for those ids."""
    ids, ips, names = set(), set(), set()
    entries = hands_off()
    for h in entries:
        ids.add(h["id"])
        ips.update(i for i in h["ips"] if isinstance(i, str))
        names.update(n for n in h["names"] if isinstance(n, str) and n)
    for d in (inventory or {}).get("devices") or []:
        if d.get("id") in ids:
            for n in d.get("net") or []:
                if n.get("ip"):
                    ips.add(n["ip"])
                if n.get("name") and n.get("medium") != "bluetooth":
                    names.add(n["name"])
            p = d.get("probe") or {}
            if p.get("name"):
                names.add(p["name"])
    return ids, ips, names


def hands_off_macs():
    """Every MAC data/site.json lists for hands-off devices (a laptop's built-in address behind its private ones)."""
    return [m for h in hands_off() for m in h["macs"]]


def hands_off_ids():
    return [h["id"] for h in hands_off()]


def secret_dirs():
    """Expanded paths of the secret folders: the fixed ones, then what data/site.json lists. No duplicates."""
    out = []
    for p in secret_dirs_raw():
        e = os.path.normpath(os.path.expanduser(p))
        if e not in out:
            out.append(e)
    return out


def secret_dirs_raw():
    """The same list as written ("~/.ssh"), for prompts and for scanners that work under another home folder."""
    out = []
    for p in FIXED_SECRET_DIRS + [x for x in (get().get("secretDirs") or []) if isinstance(x, str) and x.strip()]:
        p = p.strip().rstrip("/")
        if p and p not in out:
            out.append(p)
    return out


def hands_off_match(target=None, ip=None, name=None):
    """The handsOff entry a device id, address or host name belongs to, else None."""
    for h in hands_off():
        if target and target == h["id"]:
            return h
        if ip and ip in h["ips"]:
            return h
        if name and any(n.lower() == str(name).lower().rstrip(".").replace(".local", "") for n in h["names"]):
            return h
    return None


def router_ip(inventory=None):
    """The router's LAN address: the gateway written in data/site.json, else the router device's own address
    in the inventory, else the detected default gateway."""
    s = get()
    if s["network"].get("gatewaySource") == "site":
        return s["network"]["gateway"]
    rid = s["router"].get("deviceId")
    if rid:
        for d in (inventory if inventory is not None else _inventory_quiet()).get("devices") or []:
            if d.get("id") == rid:
                for ip in [n.get("ip") for n in d.get("net") or []] + [(d.get("probe") or {}).get("ip")]:
                    try:
                        if ip and ipaddress.ip_address(ip) in subnet():
                            return ip
                    except ValueError:
                        pass
    return s["network"]["gateway"]


def router_user():
    u = os.environ.get("HM_ROUTER_USER") or str(get()["router"].get("user") or "")
    u = "".join(c for c in u if c.isalnum() or c in "._-")
    return u or "admin"


def router_writes():
    """data/site.json router.writes: may the hub change the router's block list at all (each change still needs approval)."""
    return router_type() == "asuswrt" and get()["router"].get("writes") is True


def keychain_service():
    return os.environ.get("HM_KEYCHAIN_SERVICE") or str(get()["router"].get("keychainService") or "home-observability-hub-router")


def ha_configured():
    return bool(ha_url())


def layout_path():
    return os.environ.get("HM_LAYOUT") or os.path.join(ROOT, "data", "layout.json")


def load_layout():
    """(layout dict, problems). A missing file is {} with no problem; a broken one is {} with a word about it."""
    p = layout_path()
    try:
        with open(p) as f:
            d = json.load(f)
    except FileNotFoundError:
        return {}, []
    except (OSError, ValueError) as e:
        return {}, ["data/layout.json could not be read (%s); placing everything automatically." % e]
    if not isinstance(d, dict):
        return {}, ["data/layout.json is not a JSON object; placing everything automatically."]
    return d, []


def claude_cli():
    """Path of the Claude Code CLI, or None: HM_CLAUDE_BIN, then PATH, then the usual install places."""
    import shutil
    env = os.environ.get("HM_CLAUDE_BIN")
    if env:
        return env
    w = shutil.which("claude")
    if w:
        return w
    for p in ("~/.local/bin/claude", "/opt/homebrew/bin/claude", "/usr/local/bin/claude"):
        p = os.path.expanduser(p)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def router_key_path():
    return os.path.expanduser(os.environ.get("HM_ROUTER_KEY") or get()["router"].get("sshKey") or "")


def ha_url():
    return (os.environ.get("HM_HA_URL") or get()["homeAssistant"].get("url") or "").rstrip("/")


def ha_token():
    """The Home Assistant long-lived token: HM_HA_TOKEN, else the token file. Never logged."""
    t = os.environ.get("HM_HA_TOKEN")
    if t:
        return t.strip()
    p = os.path.expanduser(get()["homeAssistant"].get("tokenFile") or "")
    try:
        with open(p) as f:
            return f.read().strip() or None
    except OSError:
        return None


def public():
    """What the UI may see: names of secret folders (shown as ~/...), never their contents, keys or tokens."""
    s = get()
    inv = _inventory_quiet()
    return {"home": s["home"], "owner": owner(), "network": {k: s["network"].get(k) for k in ("subnet", "gateway", "extraNets", "subnetSource", "gatewaySource")},
            "router": {"type": router_type(), "deviceId": router_device(), "ip": router_ip(inv), "writes": router_writes()},
            "host": host_device(inv), "protected": protected_ids(inv), "handsOff": hands_off(),
            "homeAssistant": {"configured": bool(ha_url())}, "configured": s.get("configured", False),
            "secretDirs": [_tilde(p) for p in secret_dirs()]}


def _tilde(p):
    home = os.path.expanduser("~")
    return "~" + p[len(home):] if p == home or p.startswith(home + os.sep) else p


def inventory_path():
    return os.environ.get("HM_INVENTORY") or os.path.join(ROOT, "data", "inventory.json")


def _inventory_quiet():
    try:
        with open(inventory_path()) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


if __name__ == "__main__":
    s, probs = load()
    print(json.dumps({"site": s, "problems": probs, "detected": detect()}, indent=1))
