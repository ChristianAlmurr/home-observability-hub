"""network: the router's settings and changes to them, new devices, risky ports, suspicious devices.

Builds on what the collectors already gather (router.json, live.json, identity.json): nothing is
probed twice. A new device gets the existing deep scan started for it, except a hands-off device
(data/site.json handsOff), which is never port-scanned automatically.

To watch another router setting: add its nvram key to router.WATCH_KEYS (it is then read and any
change becomes a finding), and optionally a row below for a better label, a severity, or a value
that is a finding by itself.
"""
import json
import os

from . import util as U
from .util import C
import site_config as SITE


def router_subject(model):
    """The finding's subject for anything about the router: the router's inventory id from data/site.json."""
    return {"type": "router", "name": model, "deviceId": SITE.router_device()}


def router_fix():
    return "Open the router's page (http://%s) and check the setting. If you changed it, mark this trusted." % C.router_ip()

# Settings that are a finding while they have this value: (id, where, key, bad(value) -> bool, title, why, severity, fix)
ROUTER_CHECKS = (
    ("wan-admin", "posture", "wanAdmin", lambda v: v is True, "The router's admin page is reachable from the internet",
     "“Enable Web Access from WAN” is on: anyone on the internet can reach the router's login page and try passwords or firmware bugs against it.",
     "high", "Router page > Administration > System > Enable Web Access from WAN: No."),
    ("telnet", "posture", "telnet", lambda v: v is True, "Telnet is on at the router",
     "Telnet sends the router's password in clear text and is the first thing router malware looks for.", "high",
     "Router page > Administration > System > Enable Telnet: No."),
    ("ssh-wan", "posture", "ssh", lambda v: v == "lan+wan", "The router's SSH is reachable from the internet",
     "SSH is enabled for LAN and WAN: the whole internet can try to log in to the router.", "high",
     "Router page > Administration > System > Enable SSH: LAN only."),
    ("wps", "posture", "wps", lambda v: v is True, "WPS is on at the router",
     "WPS lets a device join the Wi-Fi with a button or an 8-digit PIN. The PIN method is a known weak way in; with it on, the Wi-Fi password is not the only key.",
     "medium", "Router page > Wireless > WPS > Enable WPS: OFF."),
    ("upnp", "posture", "upnp", lambda v: v is True, "UPnP is on at the router",
     "Any device inside can ask the router to open a port to the internet by itself, without anyone approving it.", "medium",
     "Router page > WAN > Internet Connection > Enable UPnP: No."),
    ("firmware", "posture", "firmwareUpdate", lambda v: v is True, "The router says newer firmware is available",
     "Router updates are mostly security fixes. This router faces the internet for the whole house.", "medium",
     "Router page > Administration > Firmware Upgrade: check and install."),
    ("firewall-off", "watch", "fw_enable_x", lambda v: v == "0", "The router's firewall is off",
     "The router is not filtering what comes in from the internet.", "high", "Router page > Firewall > General > Enable Firewall: Yes."),
    ("dmz", "watch", "dmz_ip", lambda v: bool(v and v.strip()), "A device is in the router's DMZ",
     "Everything arriving from the internet that nothing else claims is sent to one device, unfiltered.", "high",
     "Router page > WAN > DMZ: disable it unless you set it up on purpose."),
    ("port-forwards", "watch", "vts_rulelist", lambda v: bool(v and v.strip("<> ")), "The router forwards ports from the internet",
     "Port forwarding rules let the internet reach devices inside the house directly. Each rule is a door: keep only the ones you use.", "medium",
     "Router page > WAN > Virtual Server / Port Forwarding: remove rules you do not need."),
    ("ssh-password", "watch", "sshd_pass", lambda v: v == "1", "The router's SSH accepts a password",
     "SSH to the router works with the admin password, not only with a key, so a guessed or reused password is enough from any device in the house.", "low",
     "Router page > Administration > System > Allow Password Login: No (key login keeps working)."),
    ("usb-sharing", "watch", "enable_samba", lambda v: v == "1", "The router shares its USB port as a network drive",
     "The router's own file server (Samba) is on. If nothing is plugged into the router, it is an extra service with nothing to do.", "low",
     "Router page > USB Application > Network Place (Samba) Share: OFF."),
    ("router-ftp", "watch", "enable_ftp", lambda v: v == "1", "The router runs an FTP server",
     "FTP sends passwords and files in clear text.", "medium", "Router page > USB Application > FTP Share: OFF."),
    ("wan-ping", "watch", "misc_ping_x", lambda v: v == "1", "The router answers pings from the internet",
     "It makes the house easy to find for scanners. Not a hole by itself.", "low", "Router page > Firewall > General > Respond ICMP Echo Request from WAN: No."),
    ("vpn-server", "watch", "VPNServer_enable", lambda v: v == "1", "The router runs a VPN server",
     "A VPN server is a way into the house network from the internet. Fine when it is yours and has strong logins.", "low",
     "Router page > VPN > VPN Server: switch it off if you do not use it."),
    ("pptp", "watch", "pptpd_enable", lambda v: v == "1", "The router runs a PPTP VPN server",
     "PPTP's encryption has been broken for years.", "medium", "Router page > VPN > VPN Server > PPTP: OFF."),
    ("aicloud", "watch", "enable_webdav", lambda v: v == "1", "ASUS AiCloud is on at the router",
     "AiCloud publishes files through the router to the internet and has a history of serious flaws.", "medium", "Router page > AiCloud: switch Cloud Disk off."),
)
# Settings where a change is a finding: key -> (label, severity). Keys in router.WATCH_KEYS without a row use the default.
ROUTER_WATCH = {
    "vts_rulelist": ("port forwarding rules", "high"), "vts_enable_x": ("port forwarding", "high"), "dmz_ip": ("DMZ host", "high"),
    "autofw_enable_x": ("port triggering", "medium"), "wan0_dns": ("DNS servers the router uses", "high"),
    "wan_dns1_x": ("manual DNS server 1", "high"), "wan_dns2_x": ("manual DNS server 2", "high"), "wan0_dnsenable_x": ("automatic DNS from the provider", "high"),
    "dhcp_dns1_x": ("DNS server handed to devices", "high"), "dhcp_dns2_x": ("second DNS server handed to devices", "high"),
    "ddns_enable_x": ("dynamic DNS", "medium"), "ddns_server_x": ("dynamic DNS provider", "medium"),
    "misc_http_x": ("admin page from the internet", "high"), "misc_httpport_x": ("admin port from the internet", "medium"),
    "misc_httpsport_x": ("admin HTTPS port from the internet", "medium"), "http_enable": ("admin page protocol", "low"),
    "sshd_enable": ("SSH access", "high"), "sshd_port": ("SSH port", "medium"), "sshd_pass": ("SSH password login", "medium"),
    "sshd_authkeys_count": ("number of SSH keys the router accepts", "high"), "telnetd_enable": ("Telnet", "high"),
    "wps_enable": ("WPS", "medium"), "wan0_upnp_enable": ("UPnP", "medium"), "upnp_secure": ("UPnP secure mode", "medium"),
    "fw_enable_x": ("firewall", "high"), "enable_webdav": ("AiCloud", "medium"), "enable_cloudsync": ("AiCloud sync", "medium"),
    "VPNServer_enable": ("VPN server", "medium"), "pptpd_enable": ("PPTP VPN server", "medium"), "enable_samba": ("USB file sharing", "low"),
    "enable_ftp": ("FTP server", "medium"), "dnspriv_enable": ("DNS privacy (DoT)", "low"), "misc_ping_x": ("ping from the internet", "low"),
    "wl0.1_bss_enabled": ("guest network (2.4 GHz)", "medium"), "wl1.1_bss_enabled": ("guest network (5 GHz)", "medium"),
    "wl0.1_lanaccess": ("guest access to the house network (2.4 GHz)", "high"), "wl1.1_lanaccess": ("guest access to the house network (5 GHz)", "high"),
}
ROUTER_WATCH.update({
    "autofw_rulelist": ("port triggering rules", "high"), "wgs_enable": ("WireGuard VPN server", "medium"),
    "ipsec_server_enable": ("IPsec VPN server", "medium"), "webdav_aidisk": ("AiDisk over the internet", "medium"),
    "aae_enable": ("ASUS remote connection service", "medium"), "ipv6_service": ("IPv6 mode", "medium"), "ipv6_fw_enable": ("IPv6 firewall", "high"),
    "jffs2_scripts": ("custom scripts on the router", "high"), "jffs_scripts": ("script files on the router (/jffs/scripts)", "high"),
    "cron_jobs": ("scheduled jobs on the router", "high"), "passwd_users": ("user accounts on the router", "high"),
    "vserver_rules": ("live port forwarding rules (firewall)", "high"), "vupnp_rules": ("ports opened through UPnP", "medium"),
    "http_username": ("admin account name", "high"), "http_client": ("limit on who may open the admin page", "medium"),
    "dnssec_enable": ("DNSSEC", "low"), "dns_norebind": ("DNS rebind protection", "medium"), "wps_enable_x": ("WPS", "medium"),
    "wps_state": ("WPS state of the radios", "medium"), "wl2.1_bss_enabled": ("guest network (5 GHz-2)", "medium"),
    "wl2.1_lanaccess": ("guest access to the house network (5 GHz-2)", "high"),
    "wl0_auth_mode_x": ("Wi-Fi security mode (2.4 GHz)", "high"), "wl1_auth_mode_x": ("Wi-Fi security mode (5 GHz)", "high"),
    "wl2_auth_mode_x": ("Wi-Fi security mode (5 GHz-2)", "high"), "wl0_crypto": ("Wi-Fi encryption (2.4 GHz)", "high"),
    "wl1_crypto": ("Wi-Fi encryption (5 GHz)", "high"), "wl2_crypto": ("Wi-Fi encryption (5 GHz-2)", "high"),
    "wl0_mfp": ("protected management frames (2.4 GHz)", "low"), "wl1_mfp": ("protected management frames (5 GHz)", "low"),
    "wl2_mfp": ("protected management frames (5 GHz-2)", "low"),
})
# The router's own update check cannot be relied on (webs_state_flag stays 0 when the checker hangs), so the
# newest build ASUS lists is kept here by hand: (extendno, date ASUS published it). Update it when ASUS ships a new one.
LATEST_FIRMWARE = {"RT-AX95Q": (24911, "2026-10-22")}
# Settings that vary by themselves and so are not watched for change.
NO_CHANGE_WATCH = {"vupnp_rules"}


def _state(name, default=None):
    try:
        with open(os.path.join(C.state_dir(), name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def scan_router(ctx, res):
    snap = _state("router.json") or {}
    if SITE.router_type() != "asuswrt":
        res.unchecked("router settings", "router reading is not set up (router.type in data/site.json is none)", keep="router:")
        res.keep.append("router-change:")
        return
    if not snap.get("configured") and not snap.get("posture"):
        res.unchecked("router settings", "Home Observability Hub has no access to the router (no SSH key and no login in the Keychain)", keep="router:")
        return
    if not snap.get("posture"):
        res.unchecked("router settings", "the router has not been read yet (%s)" % U.clean(snap.get("error") or "no data", 120), keep="router:")
        return
    if snap.get("stale") or not snap.get("ok"):
        res.unchecked("router settings", "the last read of the router failed (%s); what is shown is from %s" % (
            U.clean(snap.get("error") or "unknown", 120), (snap.get("staleSince") or snap.get("ts") or "?")[:16]), keep="router:")
        return
    posture, watch = snap.get("posture") or {}, snap.get("watch") or {}
    first = ctx.baseline.begin("router")
    model = snap.get("model") or "router"
    for cid, where, key, bad, title, why, sev, fix in ROUTER_CHECKS:
        src = posture if where == "posture" else watch
        if key not in src:
            continue
        res.items += 1
        if not bad(src[key]):
            continue
        if cid == "wan-admin" and any(s.get("failed24h") for s in ((snap.get("logins") or {}).get("sources") or {}).values()):
            continue            # the password-guessing finding says this and more
        ev = [(key, U.clean(str(src[key]), 200), "router setting")]
        if cid == "wan-admin":
            ev.append(("admin port", U.clean(str(watch.get("misc_httpsport_x") or watch.get("misc_httpport_x") or ""), 10), "router setting"))
            ev.append(("dynamic DNS", "on" if watch.get("ddns_enable_x") == "1" else "off", "router setting"))
        if cid == "firmware":
            ev.append(("offered", U.clean(str(posture.get("newFirmware") or ""), 60), "router"))
        res.add(U.make_finding("router:" + cid, "network", title, why, router_subject(model),
                               [U.Reason("router-" + cid, why, sev, 100, measured=True)], evidence=ev, fix={"text": fix},
                               fp=U.digest(cid, src[key]), baseline=first))
    scan_logins(ctx, res, snap, model, first)
    import re
    m = re.search(r"_(\d{4,6})", snap.get("firmware") or "")
    latest = LATEST_FIRMWARE.get(snap.get("model") or "")
    if m and latest and int(m.group(1)) < latest[0] and not posture.get("firmwareUpdate"):
        why = ("The router runs firmware build %s; ASUS published build %d on %s. Router updates are mostly security fixes, and this router's admin page faces the internet. "
               "The router's own update check does not report it." % (m.group(1), latest[0], latest[1]))
        res.add(U.make_finding("router:firmware-behind", "network", "The router's firmware is behind the newest ASUS build", why,
                               router_subject(model), [U.Reason("router-firmware", why, "medium", 100, measured=True)],
                               evidence=[("running", snap.get("firmware"), "router"), ("newest known", "388_%d (%s)" % latest, "kept by hand in sentinel/network.py")],
                               fix={"text": "Router page > Administration > Firmware Upgrade: check, or download the build from the ASUS support page and upload it."},
                               fp=U.digest(m.group(1), latest[0]), baseline=first))
    elif not latest:
        res.unchecked("whether the router's firmware is the newest", "no known-latest build is recorded for the model %s" % U.clean(snap.get("model") or "?", 30))
    wps = (watch.get("wps_state") or "") + " " + " ".join((v.get("wps_state") or "") for v in (snap.get("nodeWatch") or {}).values())
    if re.search(r"wps_state=[1-9]", wps) and not posture.get("wps"):
        why = "The router's setting says WPS is off, but a Wi-Fi radio is still running it (wps_state is not 0 on the router or the mesh node). The weak way in is still open on that radio."
        res.add(U.make_finding("router:wps-radio", "network", "WPS is still active on a Wi-Fi radio", why, router_subject(model),
                               [U.Reason("router-wps", why, "medium", 100, measured=True)], evidence=[("wps_state", U.clean(wps.strip(), 200), "hostapd config on the router and node")],
                               fix={"text": "Router page > Wireless > WPS: switch it off, then restart the Wi-Fi on the mesh node (or reboot the node)."}, fp=U.digest(wps.strip()), baseline=first))
    for ip, nw in sorted((snap.get("nodeWatch") or {}).items()):
        for k, v in nw.items():
            watch["node %s: %s" % (ip, k)] = v
    if not watch:
        res.unchecked("changes to port forwards, DNS and remote access at the router",
                      "those settings are read over SSH only, and this read did not include them", keep="router-change:")
        return
    ctx.baseline.begin("router-watch")
    first_w = ctx.baseline.first("router-watch")
    for key in sorted(watch):
        res.items += 1
        value = str(watch[key])
        k = "router-change:" + key
        res.seen.add(k)
        old = ctx.baseline.get(k)
        status = ctx.baseline.status(k, value, "router-watch")
        if status not in ("new", "changed") or key.split(": ")[-1] in NO_CHANGE_WATCH:
            if status == "changed":
                ctx.baseline.accept(k, value)
            continue
        label, sev = ROUTER_WATCH.get(key.split(": ")[-1], (key, "medium"))
        if key.startswith("node "):
            label = "%s on the mesh node %s" % (label, key.split(":")[0][5:])
        text = "The router's %s changed%s. Nobody did that through Home Observability Hub: if it was not you in the router's page, someone else has changed the router." % (
            label, (" from “%s” to “%s”" % (U.clean(old, 80), U.clean(value, 80))) if old is not None else " to “%s”" % U.clean(value, 80))
        res.add(U.make_finding(k, "network", "Router setting changed: %s" % label, text, router_subject(model),
                               [U.Reason("router-changed", text, sev, 100, measured=True)],
                               evidence=[("setting", key, "nvram"), ("was", U.clean(old, 200) if old is not None else "not recorded", "baseline"),
                                         ("is now", U.clean(value, 200) or "(empty)", "router")],
                               fix={"text": router_fix()}, fp=value, baseline=first_w))


def scan_logins(ctx, res, snap, model, first):
    """Who is trying the router's login from outside the house. The same finding is updated as attempts go on."""
    logins = snap.get("logins")
    if not isinstance(logins, dict):
        res.unchecked("login attempts at the router", "the router's log is read over SSH only, and this read did not include it",
                      keep="router-login")
        return
    res.keep.append("router-login-success:")        # a successful outside login never resolves by itself when the log rolls over
    sources = logins.get("sources") or {}
    subject = router_subject(model)
    for ip, s in sorted(sources.items()):
        if not s.get("success"):
            continue
        why = ("Someone logged in to the router from %s, an address outside the house and outside the tailnet (%d successful login%s, the last at %s, over %s). "
               "Whoever that was can change DNS, open ports and read which devices are here." % (
                   ip, s["success"], "" if s["success"] == 1 else "s", (s.get("lastSuccess") or "?").replace("T", " "), " and ".join(s.get("channels") or [])))
        res.add(U.make_finding("router-login-success:%s:%s" % (ip, s.get("lastSuccess")), "network",
                               "Successful router login from outside the house: %s" % ip, why, subject,
                               [U.Reason("router-outside-login", why, "critical", 100, measured=True)],
                               evidence=[("source", ip, "router log"), ("successful logins", str(s["success"]), "router log"),
                                         ("last success", s.get("lastSuccess"), "router log"), ("failed attempts from it", str(s.get("failed") or 0), "router log"),
                                         ("over", ", ".join(s.get("channels") or []), "router log")],
                               fix={"text": "If that was not you: change the router's admin password now from inside the house, switch “Enable Web Access from WAN” off, "
                                            "check DNS, port forwarding and the SSH keys on the router, then restart it. If it was you (from another network), mark this trusted."},
                               fp=U.digest(ip, s.get("lastSuccess")), baseline=False))
    active = {ip: s for ip, s in sources.items() if s.get("failed24h")}
    if not active:
        return
    wan = bool((snap.get("posture") or {}).get("wanAdmin"))
    known = set(ctx.cache.get("loginSources") or [])
    fresh = sorted(ip for ip in active if ip not in known) if known else []
    total = sum(s["failed24h"] for s in active.values())
    prev = ctx.cache.get("loginRate")
    jump = bool(prev and total > max(prev * 2, prev + 100))
    top = sorted(active.items(), key=lambda kv: -kv[1]["failed24h"])
    counts = (total, "" if total == 1 else "s", len(active), "" if len(active) == 1 else "es", top[0][0])
    if wan:
        title = "Router admin page is open to the internet and is being password-guessed"
        why = ("The router's admin page can be reached from the internet, and it is being password-guessed: %d failed login%s in the last 24 hours from %d outside address%s (most from %s). "
               "Each attempt is a try at the admin password; one success hands over the whole network." % counts)
        fix_text = ("The sure fix is Router page > Administration > System > Enable Web Access from WAN: No, and reach the router over Tailscale instead. "
                    "If it stays on: use a long unique admin password, and restrict access under “Specified IP address” to the addresses you use.")
    else:
        # The door is closed: what is left in the log is history, and it ages out of the 24 hours by itself.
        title = "Router admin page was password-guessed before it was closed to the internet"
        why = ("The router's admin page is no longer reachable from the internet. Its log still holds %d failed login%s from the last 24 hours, from %d outside address%s (most from %s), "
               "made while it was open. None of them succeeded in the log the router keeps." % counts)
        fix_text = ("Nothing more to close. Because the password was under attack, change the router's admin password once. "
                    "This finding clears by itself when the attempts are older than 24 hours.")
    reasons = [U.Reason("router-password-guessing", why, "high" if wan else "low", 100, measured=True)]
    if fresh:
        reasons.append(U.Reason("new-source", "New since the last scan: attempts from %s." % ", ".join(fresh[:5]), "high", 100, measured=True))
    if jump:
        reasons.append(U.Reason("rate-jump", "The rate jumped: %d attempts in the last 24 hours, against %d before." % (total, prev), "high", 100, measured=True))
    ev = []
    for ip, s in top[:6]:
        span = None
        try:
            import datetime
            a, b2 = datetime.datetime.fromisoformat(s["first"]), datetime.datetime.fromisoformat(s["last"])
            if s["failed24h"] > 1:
                span = min((b2 - a).total_seconds(), 86400.0) / s["failed24h"] / 60.0
        except Exception:
            pass
        ev.append((ip, "%d failed in the last 24 h, %d in the log; first %s, last %s%s" % (
            s["failed24h"], s["failed"], (s.get("first") or "?").replace("T", " "), (s.get("last") or "?").replace("T", " "),
            ("; about one every %.1f minutes" % span) if span else ""), "router log"))
    ev.append(("web access from WAN", "on" if wan else "off", "router setting"))
    ev.append(("log covers", "since %s" % (logins.get("since") or "?").replace("T", " "), "router log"))
    res.add(U.make_finding("router-login-guessing", "network", title, why, subject, reasons,
                           evidence=ev,
                           fix={"text": fix_text},
                           fp=U.digest(*sorted(active)), baseline=first))
    ctx.cache["loginSources"] = sorted(known | set(active))[-500:]
    ctx.cache["loginRate"] = total


def rtsp_open(ip, timeout=2.5):
    """The path that answers DESCRIBE with 200 and no login challenge, or None. Reads the reply header only."""
    import socket
    for path in ("/live0", "/", "/stream1", "/live", "/h264"):
        try:
            with socket.create_connection((ip, 554), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(("DESCRIBE rtsp://%s:554%s RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n" % (ip, path)).encode())
                data = s.recv(400).decode("latin-1")
        except OSError:
            return None
        if data.startswith("RTSP/1.0 200") and "www-authenticate" not in data.lower():
            return path
        if data.startswith("RTSP/1.0 401"):
            return None
    return None


def scan_devices(ctx, res):
    live = _state("live.json")
    ident = _state("identity.json") or {}
    if not isinstance(live, dict) or not live.get("devices"):
        res.unchecked("devices on the network", "the collectors have not written a device list yet", keep="device:")
        res.keep.append("inv:")
        return
    try:
        inv = {d["id"]: d for d in C.load_inventory().get("devices") or []}
    except Exception:
        inv = {}
    names = {d.get("id"): d.get("name") for d in ident.get("dynamic") or [] if isinstance(d, dict)}
    addresses = ident.get("addresses") or {}
    identities = ident.get("identities") or {}
    ctx.baseline.begin("devices")
    first = ctx.baseline.first("devices")
    mon = ctx.monitor
    hands = set(SITE.hands_off_ids())
    for did, entry in sorted(live["devices"].items()):
        dev = inv.get(did)
        sec = entry.get("security") or {}
        addr = addresses.get(did) or {}
        macs = sorted(m for m in addr.get("macs") or [] if isinstance(m, str))
        ips = [i for i in addr.get("ips") or [] if isinstance(i, str)]
        idn = identities.get(did) or {}
        name = (dev or {}).get("name") or names.get(did) or did
        is_self = ((dev or {}).get("probe") or {}).get("type") == "self"
        res.items += 1
        if dev is not None and not sec and not macs:
            continue            # a cable, a monitor, a hub: not on the network
        key = "device:" + (macs[0] if macs and dev is None else did)
        res.seen.add(key)
        status = ctx.baseline.status(key, "seen", "devices")
        if sec.get("blocked"):
            continue            # already cut off at the router
        reasons, ev = [], []
        unidentified = idn.get("state") == "unidentified" or (not idn and dev is None)
        if status == "new":
            if unidentified:
                reasons.append(U.Reason("new-device", "A device joined the network that was not there before, and nothing has established what it is.",
                                        "medium", 100, measured=True))
            else:
                reasons.append(U.Reason("new-device", "A device joined the network that was not there before: %s." % U.clean(
                    " ".join(x for x in (idn.get("vendor"), idn.get("model")) if x) or name, 80), "low", 100, measured=True))
            scanned = None
            if mon is not None and did not in hands and ips:
                try:
                    known = set(mon.ident.hosts)
                    todo = [ip for ip in ips if ip not in known and C.ip_allowed(ip)]
                    scanned = "started" if todo and mon.ident.kick(todo, on_done=mon.wake.set) else "already done" if not todo else "queued behind a running scan"
                except Exception:
                    scanned = None
            if did in hands:
                ev.append(("deep scan", "not done: a hands-off device is never port-scanned automatically", "data/site.json"))
            elif scanned:
                ev.append(("deep scan", scanned, "identification engine"))
        risky = [p for p in sec.get("openPorts") or [] if p.get("risky")]
        if risky and not is_self:
            reasons.append(U.Reason("risky-port", "It has %s open: %s. Those services give control of a device with little or no login." % (
                "a risky port" if len(risky) == 1 else "risky ports", ", ".join("%s (%s)" % (p.get("port"), p.get("service")) for p in risky[:6])),
                "high", 100, measured=True))
        probe = getattr(ctx.cfg, "rtsp_open", None) or (None if ctx.cfg.isolated else rtsp_open)
        if probe and did not in hands and ips and any(p.get("port") == 554 for p in sec.get("openPorts") or []):
            cached = (ctx.cache.get("rtsp") or {}).get(ips[0])
            import time as _t
            if cached and _t.time() - cached[0] < 1800:
                path = cached[1]
            else:
                path = probe(ips[0])
                ctx.cache.setdefault("rtsp", {})[ips[0]] = [_t.time(), path]
            if path:
                reasons.append(U.Reason("open-camera", "Its video stream opens without a password (RTSP port 554, path %s): any device on the network, a guest's phone included, can watch it." % path,
                                        "high", 100, measured=True))
                ev.append(("RTSP", "DESCRIBE rtsp://%s:554%s answers 200 with no login challenge" % (ips[0], path), "probe"))
        if sec.get("level") == "suspicious" and not (status == "new" and unidentified):
            texts = [r.get("text") for r in sec.get("reasons") or [] if r.get("text")]
            reasons.append(U.Reason("suspicious-device", "The device check rates it suspicious (score %s): %s" % (
                sec.get("score"), U.clean(" ".join(texts), 400)), "medium", max(30, min(90, int(sec.get("score") or 50)))))
        if not reasons:
            continue
        ev += [("address", ", ".join(ips[:3]) or None, "router and probes"), ("hardware address", ", ".join(macs[:3]) or None, "router"),
               ("maker (from the address)", idn.get("macVendor"), "MAC prefix: a lead, not an identity"),
               ("identity", "%s%s" % (idn.get("state") or "unidentified", (": " + " ".join(x for x in (idn.get("vendor"), idn.get("model")) if x)) if idn.get("vendor") else ""), "identification engine"),
               ("first seen", sec.get("firstSeen"), "monitor"),
               ("open ports", ", ".join("%s %s" % (p.get("port"), p.get("service")) for p in (sec.get("openPorts") or [])[:12]) or None, "port scan")]
        lead = sorted(reasons, key=lambda r: U.SEV_RANK[r.severity], reverse=True)[0]
        if any(r.code == "open-camera" for r in reasons):
            lead = next(r for r in reasons if r.code == "open-camera")
        title = {"risky-port": "Device with a risky port open: %s", "new-device": "New device on the network: %s",
                 "suspicious-device": "Suspicious device: %s", "open-camera": "Camera stream open without a password: %s"}[lead.code] % U.clean(name, 60)
        fix_text = "Open the device on the map: say what it is if you know it, scan it, or block it at the router. Marking this trusted accepts the device as it is now."
        if lead.code == "open-camera":
            fix_text = ("Set a username and password for the camera's RTSP stream in the camera's own app, then give the same credentials to anything "
                        "that reads the stream (a recorder, Home Assistant, go2rtc): it stops working until both match.")
        res.add(U.make_finding(key, "device", title, lead.text, {"type": "device", "name": name, "deviceId": did}, reasons, evidence=ev,
                               fix={"text": fix_text},
                               fp=U.digest(did, ",".join(str(p.get("port")) for p in risky), sec.get("level") == "suspicious",
                                           any(r.code == "open-camera" for r in reasons)), baseline=first))
    # A known device that shows up with a hardware address it did not have.
    ctx.baseline.begin("inventory")
    first_i = ctx.baseline.first("inventory")
    for did, dev in sorted(inv.items()):
        macs = sorted(m for m in (addresses.get(did) or {}).get("macs") or [] if isinstance(m, str) and not _random(m))
        if not macs:
            continue
        key = "inv:" + did
        res.seen.add(key)
        cur = ",".join(macs)
        old = ctx.baseline.get(key)
        status = ctx.baseline.status(key, cur, "inventory")
        if status != "changed":
            continue
        added = [m for m in macs if m not in (old or "").split(",")]
        if not added or not old:
            ctx.baseline.accept(key, cur)
            continue
        text = "%s is now seen with a hardware address it did not have before (%s). Either its network adapter changed, or another device is using its name or address." % (
            U.clean(dev.get("name") or did, 60), ", ".join(added[:3]))
        res.add(U.make_finding(key, "device", "Known device has a new hardware address: %s" % U.clean(dev.get("name") or did, 60), text,
                               {"type": "device", "name": dev.get("name") or did, "deviceId": did},
                               [U.Reason("mac-changed", text, "medium", 100, measured=True)],
                               evidence=[("before", old, "baseline"), ("now", cur, "router")],
                               fix={"text": "If you replaced the device or its adapter, mark this trusted. If not, scan the device from the map."},
                               fp=cur, baseline=first_i))


def _random(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def scan(ctx):
    res = U.Result()
    for name, fn, prefixes in (("router settings", scan_router, ("router:", "router-change:")), ("devices", scan_devices, ("device:", "inv:"))):
        try:
            fn(ctx, res)
        except Exception as e:
            for p in prefixes:
                res.unchecked(name, "the check failed (%s)" % type(e).__name__, keep=p)
    res.detail = "%d router settings and devices" % res.items
    return res
