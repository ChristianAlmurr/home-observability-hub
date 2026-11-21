"""processes: what is listening beyond this Mac, and what runs from places programs should not run from.

`lsof` without root only shows this account's listeners, so the Mac's own network address is also
tried on a short list of risky ports: a port that answers with no visible owner belongs to a system
service (or another account) and is reported as such. Unsigned plus listening beyond loopback, or
running from a temp or download folder, is the signal; an unsigned Homebrew or Python process by
itself is not.
"""
import os
import re

from . import util as U
from .persistence import _interp

APPLE_PREFIXES = ("/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/", "/Library/Apple/")
# Ports that are trouble when they answer on the network and are not covered by a posture check.
RISKY_PORTS = ((21, "FTP", "high"), (23, "Telnet", "high"), (88, "Kerberos (a sharing service is on)", "low"), (111, "RPC portmapper", "medium"),
               (548, "AFP file sharing", "medium"), (2049, "NFS file sharing", "medium"), (3306, "MySQL", "medium"), (5432, "PostgreSQL", "medium"),
               (6379, "Redis", "high"), (27017, "MongoDB", "high"), (9200, "Elasticsearch", "medium"), (2375, "Docker API without TLS", "high"),
               (5901, "VNC", "medium"), (8080, "a web server", "low"), (8000, "a web server", "low"), (11434, "Ollama API", "medium"),
               (1883, "MQTT", "low"), (8123, "Home Assistant", "low"), (3000, "a web server", "low"), (8888, "a web server", "low"))
POSTURE_PORTS = {22, 445, 3283, 3031, 5900, 5000, 7000}        # reported by the posture scanner
TCC_SERVICES = {"kTCCServiceScreenCapture": "screen recording", "kTCCServiceAccessibility": "accessibility (control of the Mac)",
                "kTCCServiceSystemPolicyAllFiles": "full disk access", "kTCCServiceListenEvent": "keyboard monitoring",
                "kTCCServicePostEvent": "sending keystrokes"}


def parse_lsof(text):
    """[{pid, command, user, proto, addr, port}] from `lsof -F pcLPn` output; connected sockets are skipped."""
    out, pid, cmd, user, proto = [], None, None, None, None
    for line in (text or "").splitlines():
        if not line:
            continue
        t, v = line[0], line[1:]
        if t == "p":
            pid, cmd, user = int(v) if v.isdigit() else None, None, None
        elif t == "c":
            cmd = v
        elif t == "L":
            user = v
        elif t == "P":
            proto = v.lower()
        elif t == "n" and pid:
            if "->" in v:
                continue
            m = re.match(r"^(\*|\[[0-9a-fA-F:%.\w]*\]|[0-9.]+):(\d+|\*)$", v)
            if m and m.group(2) != "*":
                out.append({"pid": pid, "command": cmd, "user": user, "proto": proto or "tcp", "addr": m.group(1), "port": int(m.group(2))})
    return out


def beyond_loopback(addr):
    a = addr.strip("[]")
    return not (U.is_loopback(a) or a.lower().startswith("fe80:"))


def proc_table(cfg):
    """{pid: (uid, executable path)} for every process, or None when ps gave nothing."""
    rc, out, _ = cfg.run(["/bin/ps", "-axo", "pid=,uid=,comm="], timeout=15)
    if rc != 0 or not out:
        return None
    table = {}
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+)\s+(\d+)\s+(.+?)\s*$", line)
        if m:
            table[int(m.group(1))] = (int(m.group(2)), m.group(3))
    return table


def proc_args(cfg, pid):
    rc, out, _ = cfg.run(["/bin/ps", "-o", "command=", "-p", str(int(pid))], timeout=10)
    return out.strip() if rc == 0 else ""


def script_of(args, exe):
    """The script an interpreter is running, from its command line (best effort, never executed)."""
    parts = args.split()
    for p in parts[1:8]:
        if p.startswith("-"):
            if p == "-m":
                i = parts.index(p)
                return "module " + parts[i + 1] if i + 1 < len(parts) else None
            continue
        if p.endswith((".py", ".js", ".mjs", ".ts", ".rb", ".sh", ".pl")) or p.startswith("/"):
            return p
    return None


def signer_class(cs, path):
    if cs.get("signed") is None:
        return "unknown"
    if not cs["signed"]:
        return "unsigned"
    if cs.get("adhoc"):
        return "adhoc"
    if cs.get("apple"):
        return "apple"
    return "developer"


def scan_listeners(ctx, res, table):
    cfg = ctx.cfg
    rows = []
    for argv in (["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-FpcLPn"], ["/usr/sbin/lsof", "-nP", "-iUDP", "-FpcLPn"]):
        rc, out, err = cfg.run(argv, timeout=25)
        if rc in (124, 127) or (rc != 0 and not out):
            if rc in (124, 127):
                res.unchecked("listening ports", "lsof gave no answer", keep="listen:")
                return set()
            continue
        rows += parse_lsof(out)
    ctx.baseline.begin("listeners")
    first = ctx.baseline.first("listeners")
    groups = {}
    for r in rows:
        if not beyond_loopback(r["addr"]):
            continue
        exe = (table or {}).get(r["pid"], (None, None))[1] or r["command"]
        groups.setdefault((exe, r["pid"]), []).append(r)
    by_key, seen_ports = {}, set()
    for (exe, pid), rs in groups.items():
        for r in rs:
            if r["proto"] == "tcp":
                seen_ports.add(r["port"])
        real = os.path.realpath(exe) if exe and exe.startswith("/") else exe
        if real and real.startswith(APPLE_PREFIXES) and not _interp(real):
            cs = ctx.sigs.info(real)
            if cs.get("apple"):
                continue        # a part of macOS: the posture scanner reports the sharing services
        args = U.redact(proc_args(cfg, pid), 400) if (real and _interp(real)) else ""
        script = script_of(args, real) if args else None
        key = "listen:%s%s" % (real, (":" + script) if script else "")
        e = by_key.setdefault(key, {"exe": real, "script": script, "pids": set(), "rows": [], "args": args})
        e["pids"].add(pid)
        e["rows"] += rs
    for key, e in sorted(by_key.items()):
        real = e["exe"]
        cs = ctx.sigs.info(real) if real and real.startswith("/") else {"signed": None, "error": "the program's path is not known"}
        cls = signer_class(cs, real)
        tcp = sorted({r["port"] for r in e["rows"] if r["proto"] == "tcp"})
        udp = sorted({r["port"] for r in e["rows"] if r["proto"] == "udp"})
        fixed = [p for p in tcp if p < 49152] + ["u%d" % p for p in udp if p < 49152]
        fp = U.digest(real, e["script"], *fixed)
        name = os.path.basename(real or "?") + ((" (" + os.path.basename(e["script"]) + ")") if e["script"] else "")
        temp = len([p for p in tcp + udp if p >= 49152])
        ports_text = ", ".join(["TCP %d" % p for p in tcp if p < 49152][:8] + ["UDP %d" % p for p in udp if p < 49152][:6])
        if temp:
            ports_text = (ports_text + " and " if ports_text else "") + "%d temporary port%s" % (temp, "" if temp == 1 else "s")
        reasons = []
        status = ctx.baseline.status(key, fp, "listeners")
        if cls in ("unsigned", "adhoc") and tcp:
            reasons.append(U.Reason("unsigned-listener", "%s accepts connections from the network (%s) and is %s, so nothing says who made it. "
                                    "Every device on the Wi-Fi can talk to it." % (name, ports_text, "not signed" if cls == "unsigned" else "only ad-hoc signed"),
                                    "medium", 100, measured=True))
        elif cls in ("unsigned", "adhoc") and udp:
            reasons.append(U.Reason("unsigned-listener", "%s listens for network packets (%s) and is %s." % (
                name, ports_text, "not signed" if cls == "unsigned" else "only ad-hoc signed"), "low", 100, measured=True))
        new_sev = "low" if cls in ("developer", "apple") else "medium"
        res.seen.add(key)
        res.items += 1
        if status == "new":
            reasons.insert(0, U.Reason("new-listener", "%s started accepting connections from the network (%s). It was not doing that when the baseline was taken." % (name, ports_text),
                                       new_sev, 100, measured=True))
        elif status == "changed":
            reasons.insert(0, U.Reason("changed-listener", "%s now listens on different ports (%s)." % (name, ports_text), new_sev, 100, measured=True))
        if reasons:
            res.add(U.make_finding(
                key, "exposure", "%s is open to the network: %s" % (name, ports_text), reasons[0].text,
                {"type": "port" if len(tcp) + len(udp) == 1 else "process", "name": name, "path": real, "pid": sorted(e["pids"])[0],
                 "port": (tcp or udp or [None])[0]}, reasons,
                evidence=[("program", cfg.show(real or ""), "ps"), ("script", cfg.show(e["script"]) if e["script"] else None, "its command line"),
                          ("listens on", ", ".join(sorted({"%s %s:%d" % (r["proto"].upper(), r["addr"], r["port"]) for r in e["rows"]}))[:300], "lsof"),
                          ("signature", U.signer_text(cs), "codesign -dv"), ("process id", ", ".join(str(p) for p in sorted(e["pids"])[:6]), "lsof")],
                fix={"text": "If it only needs to serve this Mac, make it listen on 127.0.0.1 instead of every address. If you know it and it must be reachable, mark it trusted."},
                fp=fp, baseline=first))
    return seen_ports


def scan_ports(ctx, res, lsof_ports):
    """Risky ports that answer on the Mac's network address although lsof shows no owner (root's or another account's)."""
    cfg = ctx.cfg
    ip = cfg.lan_ip()
    if not ip:
        res.unchecked("ports owned by system services", "this Mac has no network address to test", keep="port:")
        return
    ctx.baseline.begin("ports")
    first = ctx.baseline.first("ports")
    for port, what, sev in RISKY_PORTS:
        res.items += 1
        if port in lsof_ports or port in POSTURE_PORTS or not cfg.tcp_open(ip, port):
            continue
        key = "port:%d" % port
        res.add(U.make_finding(key, "exposure", "Port %d (%s) answers on the network" % (port, what),
                               "Something on this Mac accepts connections on port %d (%s) from the network. It does not belong to a program of this account, "
                               "so it is a system service or another account's program." % (port, what),
                               {"type": "port", "name": what, "port": port},
                               [U.Reason("open-port", "Port %d answers on %s." % (port, ip), sev, 100, measured=True)],
                               evidence=[("port %d" % port, "answers on %s" % ip, "connect"), ("owner", "not visible without administrator rights", "lsof")],
                               fix={"text": "See what owns it, then switch that service off in System Settings > General > Sharing if you do not need it.",
                                    "command": "sudo lsof -nP -iTCP:%d -sTCP:LISTEN" % port, "needsSudo": True},
                               fp=U.digest(port), baseline=first))
    res.unchecked("listeners of other accounts and of root", "lsof only shows this account's programs without administrator rights; "
                  "only the %d risky ports on the list were tried on %s" % (len(RISKY_PORTS), ip))


def scan_locations(ctx, res, table):
    cfg = ctx.cfg
    if table is None:
        res.unchecked("where programs run from", "ps gave no answer", keep="proc:")
        return
    ctx.baseline.begin("locations")
    first = ctx.baseline.first("locations")
    spots = (("/tmp/", "a temporary folder"), ("/private/tmp/", "a temporary folder"), ("/var/tmp/", "a temporary folder"),
             ("/private/var/tmp/", "a temporary folder"), ("/Users/Shared/", "the shared folder"),
             (cfg.h("Downloads") + "/", "the downloads folder"), (cfg.h("Desktop") + "/", "the desktop"), ("/Volumes/", "a mounted disk"))
    seen = {}
    for pid, (uid, exe) in table.items():
        if not exe.startswith("/"):
            continue
        res.items += 1
        where = next((w for p, w in spots if exe.startswith(p)), None)
        if "/AppTranslocation/" in exe:
            where = "a download that was never moved out of quarantine (app translocation)"
        if where:
            seen.setdefault(exe, [where, []])[1].append(pid)
    for exe, (where, pids) in sorted(seen.items()):
        real = os.path.realpath(exe)
        cs = ctx.sigs.info(real)
        cls = signer_class(cs, real)
        if cls == "apple":
            continue
        sev, pct = ("high", 60) if cls in ("unsigned", "adhoc") else ("low", 50)
        key = "proc:" + exe
        res.add(U.make_finding(key, "process", "Program running from %s: %s" % (where.split(" (")[0], os.path.basename(exe)),
                               "%s is running from %s. Installed software does not run from there; a program that does was started straight from a download, an installer, or by something that dropped it."
                               % (os.path.basename(exe), where),
                               {"type": "process", "name": os.path.basename(exe), "path": exe, "pid": sorted(pids)[0]},
                               [U.Reason("runs-from-" + ("temp" if "temporary" in where or "shared" in where else "download"),
                                         "It runs from %s and is %s." % (where, U.signer_text(cs)), sev, pct)],
                               evidence=[("program", cfg.show(exe), "ps"), ("signature", U.signer_text(cs), "codesign -dv"),
                                         ("process id", ", ".join(str(p) for p in sorted(pids)[:6]), "ps")],
                               fix={"text": "If you started it yourself, fine: mark it trusted or move the app to Applications. If you did not, quit it in Activity Monitor and look at the file."},
                               fp=U.digest(exe, cls), baseline=first))


def scan_tcc(ctx, res):
    """Which programs hold screen recording, accessibility and full disk access. Needs Full Disk Access to read."""
    cfg = ctx.cfg
    import sqlite3
    read_any = False
    for path, scope in ((cfg.h("Library", "Application Support", "com.apple.TCC", "TCC.db"), "this account"),
                        (cfg.s("/Library/Application Support/com.apple.TCC/TCC.db"), "the whole Mac")):
        try:
            if not os.access(path, os.R_OK):
                raise OSError("not readable")
            con = sqlite3.connect("file:%s?mode=ro&immutable=1" % path.replace("?", "%3f").replace("#", "%23"), uri=True, timeout=2)
            try:
                rows = con.execute("select service, client, auth_value from access").fetchall()
            finally:
                con.close()
        except Exception:
            res.unchecked("privacy permissions for %s (screen recording, accessibility, full disk access)" % scope,
                          "macOS does not let Home Observability Hub read the permissions database; give /usr/bin/python3 Full Disk Access to include it",
                          keep="tcc:%s:" % scope)
            continue
        read_any = True
        ctx.baseline.begin("tcc:" + scope)
        first = ctx.baseline.first("tcc:" + scope)
        for service, client, auth in rows:
            if service not in TCC_SERVICES or auth != 2 or not isinstance(client, str):
                continue
            key = "tcc:%s:%s:%s" % (scope, service, client)
            res.seen.add(key)
            res.items += 1
            if ctx.baseline.status(key, "allowed", "tcc:" + scope) == "new":
                res.add(U.make_finding(key, "exposure", "%s was given %s" % (U.clean(client, 80), TCC_SERVICES[service]),
                                       "Since the baseline, %s was allowed %s. With that it can %s." % (U.clean(client, 80), TCC_SERVICES[service],
                                                                                                    "see everything on screen" if "Screen" in service else "read every file, the secrets included" if "AllFiles" in service else "watch or control what you type and click"),
                                       {"type": "setting", "name": client},
                                       [U.Reason("new-privacy-grant", "A new program holds %s." % TCC_SERVICES[service], "medium", 100, measured=True)],
                                       evidence=[("program", client, "TCC database"), ("permission", TCC_SERVICES[service], "TCC database")],
                                       fix={"text": "System Settings > Privacy & Security: switch it off there if you did not grant it."}, fp="allowed", baseline=first))
    return read_any


def scan(ctx):
    res = U.Result()
    table = proc_table(ctx.cfg)
    ports = set()
    for name, fn, prefix in (("listening ports", lambda: scan_listeners(ctx, res, table), "listen:"),
                             ("risky ports", lambda: scan_ports(ctx, res, ports), "port:"),
                             ("where programs run from", lambda: scan_locations(ctx, res, table), "proc:"),
                             ("privacy permissions", lambda: scan_tcc(ctx, res), "tcc:")):
        try:
            r = fn()
            if name == "listening ports" and isinstance(r, set):
                ports.update(r)
        except Exception as e:
            res.unchecked(name, "the check failed (%s)" % type(e).__name__, keep=prefix)
    res.detail = "%d processes and ports looked at" % res.items
    return res
