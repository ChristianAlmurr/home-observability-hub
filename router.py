"""Router client for ASUS routers running AsusWRT (written against a ZenWiFi XT8 pair, AsusWRT 3.0.0.4.388).

Used only when data/site.json says router.type "asuswrt"; with "none" nothing here runs SSH, logs in
or touches the Keychain. The router's address, SSH user, key and Keychain item all come from
data/site.json (site_config.py).

Two transports, standard library only:

- SSH (preferred): one fixed read-only script per mesh node, run with the key
  named in data/site.json (router.sshKey). It prints files the firmware
  maintains (/tmp/clientlist.json, /jffs/nmp_cl_json.js, dnsmasq leases,
  /tmp/aplist.json), a fixed list of nvram values and `wl sta_info` per
  station. Nothing in the read path writes.
- Web (fallback, and what the login route tests): login.cgi with the admin
  login from the macOS Keychain, appGet.cgi hooks for reading, applyapp.cgi
  for the one write.

The only write this module can make is the block list the router's own
"Block Internet Access" switch uses (MULTIFILTER_*). It is built as a plan
(before, after, exact commands, undo) that can be shown without being run.
Wireless MAC filters (wlN_maclist, wlN_macmode) are never read for writing
and never written.

The Keychain password and the key file's contents are never logged, returned
or put on a command line.
"""
import base64
import datetime
import json
import os
import re
import shlex
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import oui
import site_config as SITE

SSH_USER = "admin"                 # the default; ssh_user() is what gets used


def router_ip():
    """The router's LAN address, from data/site.json (site_config.router_ip)."""
    return SITE.router_ip()


def enabled():
    """Is router reading set up at all? Only an AsusWRT router is read; with router.type "none" nothing here
    tries SSH, the web login or the Keychain."""
    return SITE.router_type() == "asuswrt"


def ssh_user():
    """The router's admin name, which is also its SSH user: HM_ROUTER_USER, else router.user in data/site.json,
    else "admin"."""
    return SITE.router_user() or SSH_USER
BANDS = {"2G": "2.4 GHz", "5G": "5 GHz", "5G1": "5 GHz-2", "6G": "6 GHz", "6G1": "6 GHz-2"}
BAND_ORDER = ["2G", "5G", "5G1", "6G"]
MF_KEYS = ["MULTIFILTER_ALL", "MULTIFILTER_ENABLE", "MULTIFILTER_MAC", "MULTIFILTER_DEVICENAME",
           "MULTIFILTER_MACFILTER_DAYTIME", "MULTIFILTER_MACFILTER_DAYTIME_V2"]
NVRAM_KEYS = ["productid", "firmver", "buildno", "extendno", "lan_hwaddr", "cfg_alias", "cfg_device_list",
              "custom_clientlist", "wl_ifnames", "wl0_ssid", "wl1_ssid", "wl2_ssid",
              "misc_http_x", "wps_enable", "wan0_upnp_enable", "telnetd_enable", "sshd_enable",
              "webs_state_flag", "webs_state_info"] + MF_KEYS
# Settings Sentinel watches for a change (sentinel/network.py). Add a key here and it is read and watched;
# a row in sentinel/network.py ROUTER_WATCH gives it a label and a severity. Never add a key that holds a password.
WATCH_KEYS = ["vts_enable_x", "vts_rulelist", "autofw_enable_x", "dmz_ip", "wan0_dns", "wan_dns1_x", "wan_dns2_x", "wan0_dnsenable_x",
              "dhcp_dns1_x", "dhcp_dns2_x", "ddns_enable_x", "ddns_server_x", "misc_httpport_x", "misc_httpsport_x", "http_enable",
              "sshd_port", "sshd_pass", "enable_webdav", "enable_cloudsync", "VPNServer_enable", "pptpd_enable", "enable_samba",
              "enable_ftp", "dnspriv_enable", "fw_enable_x", "misc_ping_x", "upnp_secure", "wl0.1_bss_enabled", "wl1.1_bss_enabled",
              "wl0.1_lanaccess", "wl1.1_lanaccess", "wl2.1_bss_enabled", "wl2.1_lanaccess", "autofw_rulelist", "wgs_enable",
              "ipsec_server_enable", "webdav_aidisk", "aae_enable", "ipv6_service", "ipv6_fw_enable", "jffs2_scripts", "http_username",
              "http_client", "dnssec_enable", "dns_norebind", "wps_enable_x", "wl0_auth_mode_x", "wl1_auth_mode_x", "wl2_auth_mode_x",
              "wl0_crypto", "wl1_crypto", "wl2_crypto", "wl0_mfp", "wl1_mfp", "wl2_mfp"]
# Facts that are not nvram settings, printed as key=value into the same section. Counts and names only: never a key or a password.
# (This busybox has no uniq or paste: text is pulled over and counted on the Mac.)
WATCH_COMMANDS = [
    ("sshd_authkeys_count", "nvram get sshd_authkeys | grep -c ssh-"),
    ("jffs_scripts", "ls /jffs/scripts 2>/dev/null | tr '\\n' ' '"),
    ("cron_jobs", "cru l 2>/dev/null | awk '{print $NF}' | tr '\\n' ' '"),
    ("passwd_users", "cut -d: -f1 /etc/passwd | tr '\\n' ' '"),
    ("vserver_rules", "iptables -t nat -S VSERVER 2>/dev/null | grep -c -- '-A'"),
    ("vupnp_rules", "iptables -t nat -S VUPNP 2>/dev/null | grep -c -- '-A'"),
    ("wps_state", "grep -h '^wps_state' /tmp/wl*_hapd.conf 2>/dev/null | tr '\\n' ' '"),
]
_WATCH_CMDS = "; ".join('echo "%s=$(%s)"' % kc for kc in WATCH_COMMANDS)
# Who tried to log in to the router: the admin page ([LOGIN] lines) and SSH (dropbear).
_LOGINS = ("echo '@@logins'; grep -h '\\[LOGIN\\]' /jffs/syslog.log-1 /tmp/syslog.log 2>/dev/null | tail -n 4000; "
           "echo '@@dropbear'; grep -h dropbear /jffs/syslog.log-1 /tmp/syslog.log 2>/dev/null | grep -E 'auth succeeded|Bad password|Login attempt' | tail -n 600")
NODE_NVRAM_KEYS = ["productid", "firmver", "buildno", "extendno", "lan_hwaddr", "wl_ifnames"]

_WL = ("echo '@@wl'; for i in $(nvram get wl_ifnames) wl0.1 wl1.1 wl2.1; do "
       "for m in $(wl -i $i assoclist 2>/dev/null | awk '{print $2}'); do echo \"sta $i $m\"; "
       "wl -i $i sta_info $m 2>/dev/null | grep -E 'rate of last|smoothed rssi|tx total bytes|rx data bytes|in network|chanspec'; "
       "done; done; echo '@@end'")


def _nvram_script(keys):
    return "echo '@@nvram'; for k in %s; do echo \"$k=$(nvram get $k)\"; done" % " ".join(keys)


READ_SCRIPT = "; ".join([
    "echo '@@clientlist'; cat /tmp/clientlist.json 2>/dev/null; echo",
    "echo '@@nmp'; cat /jffs/nmp_cl_json.js 2>/dev/null; echo",
    "echo '@@leases'; cat /var/lib/misc/dnsmasq.leases 2>/dev/null",
    "echo '@@aplist'; cat /tmp/aplist.json 2>/dev/null; echo",
    _nvram_script(NVRAM_KEYS + WATCH_KEYS), _WATCH_CMDS, _LOGINS, _WL])
NODE_WATCH_KEYS = ["sshd_enable", "sshd_pass", "telnetd_enable", "jffs2_scripts", "wps_enable"]
NODE_SCRIPT = "; ".join([_nvram_script(NODE_NVRAM_KEYS + NODE_WATCH_KEYS), _WATCH_CMDS, _WL])
MF_SCRIPT = _nvram_script(MF_KEYS) + "; echo '@@end'"


class RouterError(Exception):
    """Carries plain words for the person."""


def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


# ================================================================ SSH

def ssh_key_path():
    """HM_ROUTER_KEY, else router.sshKey in data/site.json."""
    return SITE.router_key_path()


def ssh_available():
    return enabled() and os.environ.get("HM_ROUTER_SSH") != "0" and bool(ssh_key_path()) and os.path.isfile(ssh_key_path())


def ssh_argv(host):
    return ["/usr/bin/ssh", "-T", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR", "-i", ssh_key_path(),
            "%s@%s" % (ssh_user(), host)]


def ssh_error_text(host, rc, err):
    e = (err or "").strip()
    low = e.lower()
    who = "The router" if host == router_ip() else "The mesh node at %s" % host
    if "permission denied" in low:
        return "%s refused the SSH key." % who
    if "host key verification failed" in low or "remote host identification has changed" in low:
        return "%s shows a different SSH identity than last time, so nothing was sent. Check it before trusting it." % who
    if "connection refused" in low:
        return "%s has SSH switched off (port 22 refused the connection)." % who
    if "timed out" in low or rc == 124:
        return "%s did not answer on SSH within the time limit." % who
    if "no route to host" in low or "network is unreachable" in low or "host is down" in low:
        return "%s cannot be reached on the network." % who
    return "%s: SSH failed (exit %s)%s" % (who, rc, (": " + e.splitlines()[-1][:160]) if e else "")


def ssh_run(host, script, timeout=20):
    """(rc, stdout, stderr). The script is one argument: the router's shell parses it."""
    try:
        p = subprocess.run(ssh_argv(host) + [script], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout, text=True, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except Exception as e:
        return 127, "", str(e)


# ================================================================ parsing

def split_sections(text):
    """'@@name' lines start a section. {name: body}."""
    out, name, buf = {}, None, []
    for line in (text or "").splitlines():
        if line.startswith("@@"):
            if name is not None:
                out[name] = "\n".join(buf)
            name, buf = line[2:].strip(), []
        elif name is not None:
            buf.append(line)
    if name is not None:
        out[name] = "\n".join(buf)
    return out


def parse_kv(body):
    out, last = {}, None
    for line in (body or "").splitlines():
        m = re.match(r"^([A-Za-z0-9_.]+)=(.*)$", line)
        if m:
            last = m.group(1)
            out[last] = m.group(2)
        elif last is not None:              # a value that held a newline
            out[last] += "\n" + line
    return out


def _json(body):
    try:
        d = json.loads((body or "").strip() or "null")
        return d if isinstance(d, dict) else {}
    except ValueError:
        return {}


def _int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def parse_wl(body):
    """{MAC: {if, rssi, apTxKbps, apRxKbps, apTxBytes, apRxBytes, assocSec, channel}}"""
    out, cur = {}, None
    for line in (body or "").splitlines():
        m = re.match(r"^sta (\S+) ([0-9A-Fa-f:]{17})$", line.strip())
        if m:
            cur = {"if": m.group(1)}
            out[m.group(2).upper()] = cur
            continue
        if cur is None:
            continue
        s = line.strip()
        m = re.match(r"rate of last tx pkt:\s*(\d+) kbps", s)
        if m:
            cur["apTxKbps"] = int(m.group(1))
        m = re.match(r"rate of last rx pkt:\s*(\d+) kbps", s)
        if m:
            cur["apRxKbps"] = int(m.group(1))
        m = re.match(r"smoothed rssi:\s*(-?\d+)", s)
        if m:
            cur["rssi"] = int(m.group(1))
        m = re.match(r"tx total bytes:\s*(\d+)", s)
        if m:
            cur["apTxBytes"] = int(m.group(1))
        m = re.match(r"rx data bytes:\s*(\d+)", s)
        if m:
            cur["apRxBytes"] = int(m.group(1))
        m = re.match(r"in network (\d+) seconds", s)
        if m:
            cur["assocSec"] = int(m.group(1))
        m = re.match(r"chanspec (\S+)", s)
        if m:
            cur["channel"] = m.group(1)
    return out


def band_of_if(ifname, wl_ifnames):
    m = re.match(r"^wl(\d)\.\d+$", ifname or "")
    if m:
        i = int(m.group(1))
    elif ifname in wl_ifnames:
        i = wl_ifnames.index(ifname)
    else:
        return None
    return ["2G", "5G", "5G1"][i] if i < 3 else None


def parse_leases(body):
    out = {}
    for line in (body or "").splitlines():
        p = line.split()
        if len(p) >= 4 and oui.normalize(p[1]):
            out[oui.normalize(p[1])] = {"ip": p[2], "hostname": None if p[3] == "*" else p[3]}
    return out


def parse_custom(value):
    """custom_clientlist: '<name>MAC>group>type>...' entries. {MAC: name the person typed on the router}."""
    out = {}
    for ent in (value or "").split("<"):
        p = ent.split(">")
        if len(p) >= 2 and oui.normalize(p[1]) and p[0].strip():
            out[oui.normalize(p[1])] = p[0].strip()
    return out


def parse_multifilter(nv):
    """The router's per-device internet block list.

    {"on": bool, "consistent": bool, "entries": [{mac, name, enable, daytime}], "raw": {key: value}}
    enable: "2" block, "1" time schedule, "0" off (as the firmware's own pages write it)."""
    raw = {k: nv.get(k, "") or "" for k in MF_KEYS}
    macs = [m for m in raw["MULTIFILTER_MAC"].split(">")] if raw["MULTIFILTER_MAC"] else []
    n = len(macs)

    def col(key):
        v = raw[key]
        return v.split(">") if (v or n == 1) and n else []
    en, names, day = col("MULTIFILTER_ENABLE"), col("MULTIFILTER_DEVICENAME"), col("MULTIFILTER_MACFILTER_DAYTIME_V2")
    consistent = all(oui.normalize(m) for m in macs) and len(en) == n and len(names) == n and len(day) in (n, 0)
    entries = []
    for i, m in enumerate(macs):
        entries.append({"mac": oui.normalize(m) or m, "name": names[i] if i < len(names) else "",
                        "enable": en[i] if i < len(en) else "", "daytime": day[i] if i < len(day) else ""})
    return {"on": raw["MULTIFILTER_ALL"] == "1", "consistent": consistent, "entries": entries, "raw": raw}


def is_outside(ip):
    """True for an address that is neither on the house network (data/site.json, with its extraNets), loopback,
    nor the tailnet (100.64.0.0/10)."""
    return not SITE.ip_allowed(ip)


_MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}


def _log_time(line, now):
    """Epoch seconds of a syslog line (which carries no year), or None."""
    m = re.match(r"^(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)", line)
    if not m or m.group(1) not in _MONTHS:
        return None
    y = time.localtime(now).tm_year
    for year in (y, y - 1):
        try:
            t = time.mktime((year, _MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), 0, 0, -1))
        except (ValueError, OverflowError):
            return None
        if t <= now + 86400:
            return t
    return None


def parse_logins(web, ssh, now=None):
    """Who tried to log in to the router, per source address: {sources: {ip: {...}}, lines, since}.

    Web lines: `Nov 20 22:43:50 HTTPD: [LOGIN][https][APP] failed (203.0.113.77)` with the outcomes
    failed | captcha error | successed. SSH lines come from dropbear."""
    now = now or time.time()
    sources, lines, since = {}, 0, None

    def iso(t):
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)) if t else None

    def add(ip, channel, ok, t):
        s = sources.setdefault(ip, {"outside": is_outside(ip), "failed": 0, "failed24h": 0, "success": 0, "channels": [],
                                    "first": None, "last": None, "lastSuccess": None, "_t": []})
        if channel not in s["channels"]:
            s["channels"].append(channel)
        if ok:
            s["success"] += 1
            s["lastSuccess"] = max(s["lastSuccess"] or 0, t or 0) or None
        else:
            s["failed"] += 1
            if t and now - t <= 86400:
                s["failed24h"] += 1
        if t:
            s["first"] = min(s["first"] or t, t)
            s["last"] = max(s["last"] or t, t)
    for line in (web or "").splitlines():
        m = re.search(r"\[LOGIN\]\[(\w+)\](?:\[\w+\])*\s+(failed|captcha error|successed)\s+\(([0-9a-fA-F.:]+)\)", line)
        if not m:
            continue
        lines += 1
        t = _log_time(line, now)
        since = min(since or t, t) if t else since
        add(m.group(3), "web", m.group(2) == "successed", t)
    for line in (ssh or "").splitlines():
        m = re.search(r"(auth succeeded|Bad password attempt|Login attempt for nonexistent user)\b.* from ([0-9a-fA-F.:]+?):\d+\s*$", line)
        if not m:
            continue
        lines += 1
        t = _log_time(line, now)
        add(m.group(2), "ssh", m.group(1) == "auth succeeded", t)
    for s in sources.values():
        s.pop("_t", None)
        for k in ("first", "last", "lastSuccess"):
            s[k] = iso(s[k])
    # Addresses inside the house are summed up: only the outside ones are kept one by one.
    inside = [s for s in sources.values() if not s["outside"]]
    out = {ip: s for ip, s in sources.items() if s["outside"]}
    return {"sources": dict(sorted(out.items(), key=lambda kv: -kv[1]["failed"])[:50]), "lines": lines, "since": iso(since),
            "inside": {"failed": sum(s["failed"] for s in inside), "success": sum(s["success"] for s in inside), "sources": len(inside)}}


def _same_unit(a, b):
    """Two MACs that belong to one mesh unit differ only in the last hex digit or two."""
    return bool(a and b) and a[:16].upper() == b[:16].upper()


def build_snapshot(main_text, node_texts=None, node_errors=None, prev_counters=None, now=None):
    """Normalise what the scripts printed. `node_texts` is {ip: text} for the other mesh nodes.

    Returns (snapshot, counters). Pure: no I/O, so it is what the tests feed fixtures to."""
    now = now or time.time()
    sec = split_sections(main_text)
    if "nvram" not in sec:
        raise RouterError("The router answered, but not with the data that was asked for.")
    nv = parse_kv(sec.get("nvram"))
    wl_if = (nv.get("wl_ifnames") or "").split()
    clientlist = _json(sec.get("clientlist"))
    nmp = _json(sec.get("nmp"))
    leases = parse_leases(sec.get("leases"))
    custom = parse_custom(nv.get("custom_clientlist"))
    aplist = _json(sec.get("aplist"))
    mf = parse_multifilter(nv)
    main_mac = oui.normalize(nv.get("lan_hwaddr")) or ""

    # --- mesh nodes
    nodes = [{"mac": main_mac, "ip": router_ip(), "alias": nv.get("cfg_alias") or None, "main": True,
              "model": nv.get("productid") or None, "radios": {}, "uplink": None, "reachable": True, "error": None}]
    for ent in (nv.get("cfg_device_list") or "").split("<"):
        p = ent.split(">")
        if len(p) >= 3 and oui.normalize(p[2]) and oui.normalize(p[2]) != main_mac:
            nodes.append({"mac": oui.normalize(p[2]), "ip": p[1] or None, "alias": None, "main": False, "model": None,
                          "radios": {}, "uplink": None, "reachable": None, "error": None})
    for mac in clientlist:                       # a node the config list does not name
        m = oui.normalize(mac)
        if m and not any(n["mac"] == m for n in nodes):
            nodes.append({"mac": m, "ip": (leases.get(m) or {}).get("ip"), "alias": None, "main": False, "model": None,
                          "radios": {}, "uplink": None, "reachable": None, "error": None})
    for radios in aplist.values():
        if not isinstance(radios, dict):
            continue
        macs = {k[2:].upper(): oui.normalize(v) for k, v in radios.items() if k.startswith("ap") and oui.normalize(v)}
        for n in nodes:
            if any(_same_unit(n["mac"], m) for m in macs.values()):
                n["radios"] = macs
    unit_macs = [n["mac"] for n in nodes]

    def is_mesh_unit(mac):
        return any(_same_unit(mac, u) for u in unit_macs)

    # --- stations as each node's radio sees them
    wl = {}
    for mac, st in parse_wl(sec.get("wl")).items():
        wl[mac] = dict(st, node=main_mac, band=band_of_if(st.get("if"), wl_if))
    node_watch = {}
    for ip, text in (node_texts or {}).items():
        node = next((n for n in nodes if n["ip"] == ip), None)
        if node is None:
            continue
        nsec = split_sections(text)
        nnv = parse_kv(nsec.get("nvram"))
        node["reachable"] = True
        node_watch[ip] = {k: nnv[k] for k in NODE_WATCH_KEYS + [c[0] for c in WATCH_COMMANDS] if k in nnv}
        node["model"] = nnv.get("productid") or None
        node["firmware"] = _firmware(nnv)
        nif = (nnv.get("wl_ifnames") or "").split()
        for mac, st in parse_wl(nsec.get("wl")).items():
            if st.get("if") in nif:
                continue        # on a node the base interfaces carry the mesh backhaul, not clients
            wl[mac] = dict(st, node=node["mac"], band=band_of_if(st.get("if"), nif))
    for ip, err in (node_errors or {}).items():
        node = next((n for n in nodes if n["ip"] == ip), None)
        if node is not None:
            node["reachable"], node["error"] = False, err

    # --- clients
    clients = {}

    def client(mac):
        mac = oui.normalize(mac)
        if mac is None:
            return None
        if mac not in clients:
            n = nmp.get(mac) or {}
            lease = leases.get(mac) or {}
            nick = custom.get(mac)
            host = lease.get("hostname")
            nmp_name = (n.get("name") or "").strip() or None
            clients[mac] = {"mac": mac, "ip": lease.get("ip"), "name": nick or host or nmp_name,
                            "nickname": nick, "hostname": host or nmp_name,
                            "vendor": (n.get("vendor") or "").strip() or None,
                            "dhcpVendorClass": (n.get("vendorclass") or "").strip() or None,
                            "medium": None, "band": None, "bandLabel": None, "ssid": None, "rssi": None, "node": None,
                            "rxRateMbps": None, "txRateMbps": None, "channel": None, "connectedSec": None,
                            "online": False, "blocked": False, "schedule": False,
                            "randomizedMac": oui.is_randomized(mac), "macVendor": oui.vendor(mac)}
        return clients[mac]

    ssids = {"2G": nv.get("wl0_ssid") or None, "5G": nv.get("wl1_ssid") or None, "5G1": nv.get("wl2_ssid") or None}
    for node_mac, bands in clientlist.items():
        nm = oui.normalize(node_mac)
        if not isinstance(bands, dict):
            continue
        for band, members in bands.items():
            if not isinstance(members, dict):
                continue
            for mac, info in members.items():
                mac = oui.normalize(mac)
                info = info if isinstance(info, dict) else {}
                if mac is None:
                    continue
                if is_mesh_unit(mac):
                    if band != "wired_mac":
                        up = next((n for n in nodes if _same_unit(n["mac"], mac)), None)
                        if up is not None and not up["main"]:
                            rssi = _int(info.get("rssi"))
                            if up["uplink"] is None or band.startswith("5"):
                                up["uplink"] = {"medium": "wifi", "band": band, "bandLabel": BANDS.get(band, band),
                                                "rssi": rssi, "to": nm}
                    continue
                c = client(mac)
                c["online"] = True
                c["node"] = nm
                if info.get("ip"):
                    c["ip"] = info["ip"]
                if band == "wired_mac":
                    c["medium"] = "ethernet"
                else:
                    c["medium"] = "wifi"
                    c["band"], c["bandLabel"], c["ssid"] = band, BANDS.get(band, band), ssids.get(band)
                    c["rssi"] = _int(info.get("rssi"))
    # Stations a radio reports that the firmware's list has not caught up with.
    for mac, st in wl.items():
        if is_mesh_unit(mac):
            continue
        c = client(mac)
        if c is None:
            continue
        if not c["online"]:
            c.update(online=True, medium="wifi", node=st.get("node"), band=st.get("band"),
                     bandLabel=BANDS.get(st.get("band"), st.get("band")), ssid=ssids.get(st.get("band")))
        if c["medium"] == "wifi":
            if st.get("rssi") is not None:
                c["rssi"] = st["rssi"]
            # The radio's transmit side is what the device receives.
            if st.get("apTxKbps"):
                c["rxRateMbps"] = round(st["apTxKbps"] / 1000.0, 1)
            if st.get("apRxKbps"):
                c["txRateMbps"] = round(st["apRxKbps"] / 1000.0, 1)
            c["channel"] = st.get("channel")
            c["connectedSec"] = st.get("assocSec")

    # --- traffic from byte counters (device's point of view)
    counters = {}
    for mac, st in wl.items():
        if st.get("apTxBytes") is None or st.get("apRxBytes") is None or mac not in clients:
            continue
        counters[mac] = (now, st["apTxBytes"], st["apRxBytes"])
        p = (prev_counters or {}).get(mac)
        if p and now - p[0] >= 5 and st["apTxBytes"] >= p[1] and st["apRxBytes"] >= p[2]:
            dt = now - p[0]
            clients[mac]["traffic"] = {"rxBps": int((st["apTxBytes"] - p[1]) * 8 / dt),
                                       "txBps": int((st["apRxBytes"] - p[2]) * 8 / dt)}

    # --- the block list
    block_list = []
    for e in mf["entries"]:
        mode = {"2": "block", "1": "schedule", "0": "off"}.get(e["enable"], "unknown")
        active = mf["on"] and mode == "block"
        nm = e["name"] or None
        if e["mac"] in clients:
            clients[e["mac"]]["blocked"] = active
            clients[e["mac"]]["schedule"] = mf["on"] and mode == "schedule"
            nm = clients[e["mac"]]["name"] or nm
        block_list.append({"mac": e["mac"], "name": nm, "mode": mode, "active": active,
                           "online": bool((clients.get(e["mac"]) or {}).get("online")),
                           "ip": (clients.get(e["mac"]) or {}).get("ip") or (leases.get(e["mac"]) or {}).get("ip"),
                           "randomizedMac": oui.is_randomized(e["mac"]), "macVendor": oui.vendor(e["mac"])})

    ssh = nv.get("sshd_enable")
    posture = {"wanAdmin": nv.get("misc_http_x") == "1", "wps": nv.get("wps_enable") == "1",
               "upnp": nv.get("wan0_upnp_enable") == "1", "telnet": nv.get("telnetd_enable") == "1",
               "ssh": {"0": "off", "1": "lan+wan", "2": "lan"}.get(ssh, ssh),
               "firmwareUpdate": nv.get("webs_state_flag") in ("1", "2"),
               "newFirmware": nv.get("webs_state_info") or None}
    snap = {"ok": True, "error": None, "ts": now_iso(), "transport": "ssh",
            "model": nv.get("productid") or None, "firmware": _firmware(nv),
            "nodes": nodes, "ssids": ssids,
            "clients": sorted(clients.values(), key=lambda c: (not c["online"], _ipkey(c.get("ip")), c["mac"])),
            "blockList": block_list, "filterOn": mf["on"], "filterConsistent": mf["consistent"], "posture": posture,
            # raw values of the watched settings, only for the keys the router answered
            "watch": {k: nv[k] for k in WATCH_KEYS + [c[0] for c in WATCH_COMMANDS] + ["misc_http_x", "sshd_enable", "telnetd_enable",
                                                                                      "wps_enable", "wan0_upnp_enable"] if k in nv},
            "nodeWatch": node_watch}
    if "logins" in sec:
        snap["logins"] = parse_logins(sec.get("logins"), sec.get("dropbear"), now)
    return snap, counters


def _ipkey(ip):
    try:
        return tuple(int(x) for x in (ip or "").split("."))
    except ValueError:
        return (999,)


def _firmware(nv):
    if not nv.get("firmver"):
        return None
    fw = nv["firmver"]
    if nv.get("buildno"):
        fw += "." + nv["buildno"]
    if nv.get("extendno"):
        fw += "_" + nv["extendno"]
    return fw


# ================================================================ block list changes

SAFE_VALUE = re.compile(r"^[^\x00-\x1f\x7f]*$")


def clean_name(name):
    """A device name the router's list format can hold: no separators, quotes or control characters."""
    s = re.sub(r"[<>\"'`\\$;&|\x00-\x1f\x7f]", "", str(name or "")).strip()
    return s[:32]


def plan_change(mf, action, mac, name=None, protected=()):
    """Work out the new MULTIFILTER_* values for blocking or unblocking one MAC.

    `mf` is parse_multifilter()'s result, read just before. Returns
    {action, mac, changed: bool, before, after, note}. Raises RouterError in plain words
    when the change must not or cannot be made. Other entries keep their place and values."""
    mac = oui.normalize(mac)
    if mac is None:
        raise RouterError("That is not a hardware (MAC) address.")
    if action not in ("block", "unblock"):
        raise RouterError("Unknown router action.")
    if action == "block" and mac in {oui.normalize(p) for p in protected if p}:
        raise RouterError("That address belongs to the router, a mesh node or this Mac. Blocking it is refused.")
    if not mf["consistent"]:
        raise RouterError("The router's block list is not in the shape this app understands "
                          "(the lists have different lengths), so it was left alone. Change it in the router's own page.")
    before = dict(mf["raw"])
    entries = [dict(e) for e in mf["entries"]]
    idx = next((i for i, e in enumerate(entries) if e["mac"] == mac), None)
    note = None
    if action == "block":
        if entries and not mf["on"]:
            raise RouterError("The router's block list holds entries but is switched off as a whole. Switching it on "
                              "would also start those, so this was not done. Sort it out in the router's Parental Controls page.")
        if idx is not None and entries[idx]["enable"] == "2":
            return {"action": action, "mac": mac, "changed": False, "before": before, "after": before,
                    "note": "It is already on the router's block list."}
        if idx is not None:
            note = "It was on the list with a time schedule; that entry now blocks all the time."
            entries[idx]["enable"], entries[idx]["daytime"] = "2", ""
        else:
            entries.append({"mac": mac, "name": clean_name(name) or mac.replace(":", ""), "enable": "2", "daytime": ""})
    else:
        if idx is None:
            return {"action": action, "mac": mac, "changed": False, "before": before, "after": before,
                    "note": "It is not on the router's block list."}
        del entries[idx]
    after = dict(before)
    after["MULTIFILTER_ENABLE"] = ">".join(e["enable"] for e in entries)
    after["MULTIFILTER_MAC"] = ">".join(e["mac"] for e in entries)
    after["MULTIFILTER_DEVICENAME"] = ">".join(e["name"] for e in entries)
    after["MULTIFILTER_MACFILTER_DAYTIME_V2"] = ">".join(e["daytime"] for e in entries)
    if action == "block":
        after["MULTIFILTER_ALL"] = "1"
    for k, v in after.items():
        if not SAFE_VALUE.match(v):
            raise RouterError("A value in the router's block list holds control characters; it was left alone.")
    return {"action": action, "mac": mac, "changed": after != before, "before": before, "after": after, "note": note}


def ssh_commands(values_from, values_to):
    """The exact shell lines that turn one set of MULTIFILTER_* values into the other."""
    cmds = ["nvram set %s=%s" % (k, shlex.quote(values_to[k])) for k in MF_KEYS if values_to.get(k) != values_from.get(k)]
    if cmds:
        cmds += ["nvram commit", "service restart_firewall"]
    return cmds


def web_apply_url(values_from, values_to):
    q = [("action_mode", "apply"), ("rc_service", "restart_firewall")]
    q += [(k, values_to[k]) for k in MF_KEYS if values_to.get(k) != values_from.get(k)]
    return "http://%s/applyapp.cgi?%s" % (router_ip(), urllib.parse.urlencode(q))


# ================================================================ Keychain (web login)

def keychain_service():
    """HM_KEYCHAIN_SERVICE, else router.keychainService in data/site.json."""
    return SITE.keychain_service()


def _security(argv, stdin=None, timeout=10):
    try:
        p = subprocess.run(["/usr/bin/security"] + argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, text=True)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 127, "", type(e).__name__


def keychain_account():
    """The stored username, or None. Does not read the password. Never asks the Keychain when router reading is off."""
    if not enabled():
        return None
    rc, out, _ = _security(["find-generic-password", "-s", keychain_service()])
    if rc != 0:
        return None
    m = re.search(r'"acct"<blob>="((?:[^"\\]|\\.)*)"', out)
    return m.group(1) if m else ""


def keychain_get():
    """(username, password) or None. The caller must not log or return the password."""
    user = keychain_account()
    if user is None:
        return None
    rc, out, _ = _security(["find-generic-password", "-s", keychain_service(), "-w"])
    if rc != 0:
        return None
    return user, out.rstrip("\n")


def _sec_quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def keychain_set(username, password):
    """Store the login. The password travels on stdin of `security -i`, never in argv."""
    if not enabled():
        raise RouterError("Router reading is not set up: router.type in data/site.json is not asuswrt.")
    for v in (username, password):
        if not isinstance(v, str) or not v or re.search(r"[\x00-\x1f\x7f]", v) or len(v) > 256:
            raise RouterError("The username or password is empty or holds characters that cannot be stored.")
    keychain_delete()
    line = "add-generic-password -U -s %s -a %s -l %s -w %s\n" % (
        _sec_quote(keychain_service()), _sec_quote(username), _sec_quote("Home Observability Hub: router login"), _sec_quote(password))
    rc, _, _ = _security(["-i"], stdin=line)
    del line
    if rc != 0 or keychain_account() != username:
        raise RouterError("macOS would not store the login in the Keychain.")
    return True


def keychain_delete():
    if not enabled():
        return False
    rc, _, _ = _security(["delete-generic-password", "-s", keychain_service()])
    return rc == 0


# ================================================================ web transport

WEB_UA = "asusrouter-Android-DUTUtil-1.0.0.245"
LOGIN_ERRORS = {
    "1": "The router said it has no connection to report this through (error 1).",
    "2": "The router rejected the login request (error 2).",
    "3": "The router says the username or password is wrong.",
    "7": "Too many wrong logins: the router has locked logins for a while. Wait five minutes before trying again.",
    "8": "The router session was logged out.",
    "9": "Someone else is logged in to the router's page from another device. Log out there and try again.",
    "10": "The router wants a captcha, which only its own page can show. Log in once in a browser first.",
    "11": "The router says its login is locked until it is reset. Use the router's own page.",
}
# Hooks escape these characters in nvram values as "&#NN" with no semicolon (httpd ej_nvram_get).
_NV_ESC = (("&#62", ">"), ("&#60", "<"), ("&#34", '"'), ("&#38", "&"))


def nv_unescape(v):
    for a, b in _NV_ESC:
        v = v.replace(a, b)
    return v



class WebClient:
    """login.cgi + appGet.cgi + applyapp.cgi, as the ASUS phone app and the open-source
    asusrouter library use them. One token per client; never stores the password."""

    def __init__(self, host=None, opener=None, timeout=8):
        self.host = host or router_ip()
        self.timeout = timeout
        self.token = None
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _request(self, path, data=None):
        headers = {"User-Agent": WEB_UA}
        if self.token:
            headers["Cookie"] = "asus_token=%s" % self.token
        req = urllib.request.Request("http://%s/%s" % (self.host, path), data=data, headers=headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.read(2 * 1024 * 1024).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            raise RouterError("The router's web page answered HTTP %s." % e.code)
        except Exception as e:
            raise RouterError("The router's web page did not answer (%s)." % type(e).__name__)

    def login(self, username, password):
        auth = base64.b64encode(("%s:%s" % (username, password)).encode("utf-8")).decode("ascii")
        body = urllib.parse.urlencode({"login_authorization": auth}).encode("ascii")
        del auth
        text = self._request("login.cgi", data=body)
        del body
        try:
            d = json.loads(text)
        except ValueError:
            raise RouterError("The router answered the login with something that is not JSON.")
        if isinstance(d, dict) and d.get("asus_token"):
            self.token = d["asus_token"]
            return True
        code = str((d or {}).get("error_status", "")) if isinstance(d, dict) else ""
        err = RouterError(LOGIN_ERRORS.get(code, "The router refused the login (error %s)." % (code or "unknown")))
        err.code = code
        err.lock_sec = _int(d.get("remaining_lock_time")) if isinstance(d, dict) else None
        raise err

    def hook(self, hooks):
        """appGet.cgi?hook=a();b(x) -> dict. Raises RouterError when the session is not accepted."""
        # ';' must travel as %3B: the firmware splits the query on '&' and ';' before unescaping.
        text = self._request("appGet.cgi?hook=" + urllib.parse.quote(hooks, safe="(),_"))
        try:
            d = json.loads(text)
        except ValueError:
            # Some firmware prints numbers with leading zeros or trailing commas; salvage nothing, say so.
            raise RouterError("The router's reply to %s was not valid JSON." % hooks.split("(")[0])
        if isinstance(d, dict) and "error_status" in d:
            code = str(d["error_status"])
            raise RouterError(LOGIN_ERRORS.get(code, "The router refused the request (error %s)." % code))
        return d if isinstance(d, dict) else {}

    def nvram(self, keys):
        d = self.hook(";".join("nvram_get(%s)" % k for k in keys))
        return {k: nv_unescape(str(d.get(k, "") or "")) for k in keys}

    def apply(self, values_from, values_to):
        url = web_apply_url(values_from, values_to)
        old, self.timeout = self.timeout, 130      # the firmware waits for the service restart before it answers
        try:
            text = self._request(url.split("/", 3)[3])
        finally:
            self.timeout = old
        try:
            d = json.loads(text)
        except ValueError:
            d = {}
        if not isinstance(d, dict) or d.get("run_service") != "restart_firewall":
            raise RouterError("The router did not confirm the change (reply: %s)." % text.strip()[:80])
        return d

    def logout(self):
        if self.token:
            try:
                self._request("Logout.asp")
            except RouterError:
                pass
            self.token = None


ISWL_BAND = {"1": "2G", "2": "5G", "3": "5G1", "4": "6G"}


def snapshot_from_web(info, clientlist, mf_nv):
    """The same snapshot shape from the web API's get_clientlist() reply (no per-node radio detail
    beyond what the reply carries). Used only when SSH is not available."""
    mf = parse_multifilter(mf_nv)
    cl = clientlist.get("get_clientlist") if isinstance(clientlist.get("get_clientlist"), dict) else clientlist
    main_mac = oui.normalize(info.get("lan_hwaddr")) or ""
    clients = []
    for mac, c in (cl or {}).items():
        m = oui.normalize(mac)
        if m is None or not isinstance(c, dict) or str(c.get("amesh_isRe", "0")) == "1":
            continue
        wl = str(c.get("isWL", "0"))
        band = ISWL_BAND.get(wl)
        mode = str(c.get("internetMode") or "")
        clients.append({
            "mac": m, "ip": c.get("ip") or None, "name": (c.get("nickName") or c.get("name") or "").strip() or None,
            "nickname": (c.get("nickName") or "").strip() or None, "hostname": (c.get("name") or "").strip() or None,
            "vendor": (c.get("vendor") or "").strip() or None, "dhcpVendorClass": None,
            "medium": "wifi" if band else "ethernet", "band": band, "bandLabel": BANDS.get(band), "ssid": None,
            "rssi": _int(c.get("rssi")) if band else None,
            "node": oui.normalize(c.get("amesh_papMac")) or main_mac or None,
            "rxRateMbps": _float(c.get("curRx")), "txRateMbps": _float(c.get("curTx")), "channel": None,
            "connectedSec": None, "online": str(c.get("isOnline", "1")) == "1",
            "blocked": mode == "block", "schedule": mode == "time",
            "randomizedMac": oui.is_randomized(m), "macVendor": oui.vendor(m)})
    block_list = [{"mac": e["mac"], "name": e["name"] or None, "mode": {"2": "block", "1": "schedule", "0": "off"}.get(e["enable"], "unknown"),
                   "active": mf["on"] and e["enable"] == "2", "online": any(c["mac"] == e["mac"] and c["online"] for c in clients),
                   "ip": next((c["ip"] for c in clients if c["mac"] == e["mac"]), None),
                   "randomizedMac": oui.is_randomized(e["mac"]), "macVendor": oui.vendor(e["mac"])} for e in mf["entries"]]
    return {"ok": True, "error": None, "ts": now_iso(), "transport": "web", "model": info.get("productid") or None,
            "firmware": _firmware(info),
            "nodes": [{"mac": main_mac, "ip": router_ip(), "alias": None, "main": True, "model": info.get("productid") or None,
                       "radios": {}, "uplink": None, "reachable": True, "error": None}],
            "ssids": {}, "clients": sorted(clients, key=lambda c: (not c["online"], _ipkey(c.get("ip")), c["mac"])),
            "blockList": block_list, "filterOn": mf["on"], "filterConsistent": mf["consistent"], "posture": {}}


def _float(v):
    try:
        f = float(str(v).strip())
        return f if f > 0 else None
    except (TypeError, ValueError):
        return None


# ================================================================ the client the monitor holds

class Router:
    """Polls the router and makes the one kind of change. Thread-safe.

    `ssh` is (host, script, timeout) -> (rc, out, err); tests pass a fake."""

    POLL_TTL = 55

    def __init__(self, ssh=None, web_factory=None, keychain=None):
        self.ssh = ssh or ssh_run
        self.web_factory = web_factory or WebClient
        self.keychain = keychain or keychain_get
        self.lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.snapshot = None
        self.counters = {}
        self.last_poll = 0.0
        self.web_blocked_until = 0.0     # after a refused web login: never hammer the router's lockout
        self.web_error = None

    # -- state
    def use_ssh(self):
        return enabled() and (self.ssh is not ssh_run or ssh_available())

    def configured(self):
        return enabled() and (self.use_ssh() or self.keychain_account_known())

    def keychain_account_known(self):
        if not enabled():
            return False
        try:
            return (keychain_account() if self.keychain is keychain_get else (self.keychain() or (None,))[0]) is not None
        except Exception:
            return False

    def status(self):
        """What live.router and /api/router start from. Never includes secrets."""
        s = self.snapshot
        on = enabled()
        base = {"configured": self.configured(), "ok": bool(s and s.get("ok")), "error": None, "lastRun": None,
                "transport": "ssh" if self.use_ssh() else ("web" if self.configured() else None),
                "type": SITE.router_type(), "enabled": on}
        if not on:
            base["ok"] = False
            base["error"] = ("Router reading is not set up. Devices are still found by ping sweep, Bonjour, UPnP and this Mac's "
                             "own tables; set router.type to asuswrt in data/site.json to read an ASUS router.")
        elif not base["configured"]:
            base["error"] = "No router access is set up: there is no SSH key for the router and no router login in the Keychain."
        elif s:
            base.update(error=s.get("error"), lastRun=s.get("ts"))
        return base

    # -- reading
    def poll(self, force=False):
        """Returns the latest snapshot (possibly cached), never raises."""
        if not enabled():
            return {"ok": False, "error": "Router reading is not set up (router.type is none in data/site.json).", "ts": now_iso()}
        with self.lock:
            if not force and self.snapshot and time.time() - self.last_poll < self.POLL_TTL:
                return self.snapshot
            self.last_poll = time.time()
            prev = self.snapshot
            try:
                snap = self._poll_ssh() if self.use_ssh() else self._poll_web()
            except RouterError as e:
                snap = {"ok": False, "error": str(e), "ts": now_iso()}
            except Exception as e:
                snap = {"ok": False, "error": "Reading the router failed (%s: %s)." % (type(e).__name__, str(e)[:120]), "ts": now_iso()}
            if not snap.get("ok") and prev and prev.get("clients") is not None:
                # Keep the last good picture, marked stale, so one missed poll does not empty the map.
                snap = dict(prev, ok=False, error=snap["error"], ts=snap["ts"], stale=True,
                            staleSince=prev.get("staleSince") or prev.get("ts"))
            self.snapshot = snap
            return snap

    def _poll_ssh(self):
        ip = router_ip()
        rc, out, err = self.ssh(ip, READ_SCRIPT, 25)
        if rc != 0 or "@@end" not in out:
            raise RouterError(ssh_error_text(ip, rc, err) if rc != 0 else "The router's answer was cut short.")
        first, _ = build_snapshot(out)
        node_texts, node_errors = {}, {}
        for n in first["nodes"]:
            if n["main"] or not n.get("ip"):
                continue
            rc2, out2, err2 = self.ssh(n["ip"], NODE_SCRIPT, 20)
            if rc2 == 0 and "@@end" in out2:
                node_texts[n["ip"]] = out2
            else:
                node_errors[n["ip"]] = ssh_error_text(n["ip"], rc2, err2)
        snap, self.counters = build_snapshot(out, node_texts, node_errors, prev_counters=self.counters)
        return snap

    def _web(self):
        if time.time() < self.web_blocked_until:
            raise RouterError(self.web_error or "The router refused the stored login; not retrying yet.")
        cred = self.keychain()
        if not cred:
            raise RouterError("There is no router login in the Keychain.")
        w = self.web_factory()
        try:
            w.login(cred[0], cred[1])
        except RouterError as e:
            # A wrong password must not be retried every 30 seconds: the router locks logins after a few.
            self.web_error = str(e)
            code = getattr(e, "code", "")
            if code == "3":
                self.web_blocked_until = float("inf")       # until a new login is saved
                self.web_error += " Not trying again until the login is saved anew."
            elif code == "7":
                self.web_blocked_until = time.time() + (getattr(e, "lock_sec", None) or 300) + 30
            else:
                self.web_blocked_until = time.time() + 300
            raise RouterError(self.web_error)
        finally:
            del cred
        return w

    def _poll_web(self):
        w = self._web()
        try:
            info = w.nvram(["productid", "firmver", "buildno", "extendno", "lan_hwaddr"])
            mf_nv = w.nvram(MF_KEYS)
            cl = w.hook("get_clientlist()")
            return snapshot_from_web(info, cl, mf_nv)
        finally:
            w.logout()

    def test_login(self, username, password):
        """Used by the login route before anything is stored. Raises RouterError in plain words."""
        w = self.web_factory()
        w.login(username, password)
        try:
            info = w.nvram(["productid", "firmver", "buildno", "extendno"])
        finally:
            w.logout()
        self.web_blocked_until, self.web_error = 0.0, None
        return {"model": info.get("productid") or None, "firmware": _firmware(info)}

    # -- the block list
    def read_multifilter(self):
        if not enabled():
            raise RouterError("Router reading is not set up (router.type is none in data/site.json).")
        if self.use_ssh():
            ip = router_ip()
            rc, out, err = self.ssh(ip, MF_SCRIPT, 15)
            if rc != 0 or "@@end" not in out:
                raise RouterError(ssh_error_text(ip, rc, err) if rc != 0 else "The router's answer was cut short.")
            return parse_multifilter(parse_kv(split_sections(out).get("nvram")))
        w = self._web()
        try:
            return parse_multifilter(w.nvram(MF_KEYS))
        finally:
            w.logout()

    def protected_macs(self):
        out = set()
        for n in (self.snapshot or {}).get("nodes") or []:
            out.add(n.get("mac"))
            out.update((n.get("radios") or {}).values())
        return {m for m in out if m}

    def change(self, action, mac, name=None, dry_run=False, protected=(), backup_dir=None):
        """Block or unblock one MAC. Reads the list fresh, changes one entry, verifies.

        Returns {ok, dryRun, changed, action, mac, transport, commands, undo, before, after, note, verified}.
        With dry_run nothing is sent beyond the read."""
        if os.environ.get("HM_ROUTER_DRY_RUN") == "1" or not SITE.router_writes():
            dry_run = True          # router.writes in data/site.json is off: rehearse only
        with self.write_lock:
            mf = self.read_multifilter()
            plan = plan_change(mf, action, mac, name=name, protected=set(protected) | self.protected_macs())
            ssh = self.use_ssh()
            before, after = plan["before"], plan["after"]
            res = {"ok": True, "dryRun": bool(dry_run), "changed": plan["changed"], "action": action, "mac": plan["mac"],
                   "transport": "ssh" if ssh else "web", "note": plan["note"],
                   "commands": ssh_commands(before, after) if ssh else ([web_apply_url(before, after)] if plan["changed"] else []),
                   "undo": ssh_commands(after, before) if ssh else ([web_apply_url(after, before)] if plan["changed"] else []),
                   "before": before, "after": after, "verified": None}
            if dry_run or not plan["changed"]:
                return res
            if backup_dir:
                os.makedirs(backup_dir, exist_ok=True)
                path = os.path.join(backup_dir, "router-blocklist-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
                with open(path, "w") as f:
                    json.dump({"ts": now_iso(), "action": action, "mac": plan["mac"], "before": before, "after": after,
                               "undo": res["undo"]}, f, indent=1)
                res["backup"] = path
            if ssh:
                ip = router_ip()
                rc, out, err = self.ssh(ip, " && ".join(res["commands"]), 30)
                if rc != 0:
                    raise RouterError("The router did not accept the change. " + ssh_error_text(ip, rc, err))
            else:
                w = self._web()
                try:
                    w.apply(before, after)
                finally:
                    w.logout()
            now = self.read_multifilter()
            res["verified"] = all(now["raw"].get(k) == after.get(k) for k in MF_KEYS)
            if not res["verified"]:
                res["ok"] = False
                res["error"] = "The change was sent, but the router's list does not read back as expected. Check the router's Parental Controls page."
            self.last_poll = 0.0
            return res


def _main(argv):
    """python3 router.py show | dry-block <MAC> [name] | dry-unblock <MAC>   (never writes)"""
    r = Router()
    if argv[:1] == ["show"]:
        s = r.poll(force=True)
        print(json.dumps(s, indent=1, ensure_ascii=False))
        return 0 if s.get("ok") else 1
    if len(argv) >= 2 and argv[0] in ("dry-block", "dry-unblock"):
        r.poll(force=True)
        try:
            res = r.change(argv[0][4:], argv[1], name=" ".join(argv[2:]) or None, dry_run=True)
        except RouterError as e:
            print("refused: %s" % e)
            return 2
        print(json.dumps({k: res[k] for k in ("dryRun", "changed", "note", "commands", "undo")}, indent=1))
        return 0
    print(_main.__doc__)
    return 2


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
