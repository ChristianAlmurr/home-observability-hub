"""posture: the Mac's own security settings. Each check that fails is one finding with the exact fix.

Every check measures a setting directly, so a failing one is `confirmed`. A check that cannot run
(the tool is missing, the answer makes no sense) is reported as not checked and never as passed.
Nothing here changes a setting: the fix is text and a command for the person to run.
"""
import os
import re
import time

from . import util as U

# Remote-control software, recognised by the launchd label or the app's bundle id.
REMOTE_TOOLS = (
    ("com.realvnc.", "RealVNC Server"), ("com.teamviewer.", "TeamViewer"), ("com.philandro.anydesk", "AnyDesk"),
    ("com.splashtop.", "Splashtop Streamer"), ("com.logmein.", "LogMeIn"), ("com.screenconnect.", "ScreenConnect"),
    ("connectwisecontrol", "ConnectWise Control"), ("com.carriez.rustdesk", "RustDesk"), ("org.chromium.chromoting", "Chrome Remote Desktop"),
    ("com.p5sys.jump.connect", "Jump Desktop Connect"), ("tv.parsec.", "Parsec"), ("com.nomachine.", "NoMachine"),
    ("net.dwservice.", "DWService"), ("com.atera.", "Atera agent"), ("com.ninjarmm.", "NinjaRMM agent"),
    ("com.kaseya.", "Kaseya agent"), ("com.zoho.assist", "Zoho Assist"), ("com.getscreen.", "Getscreen"),
    ("com.aweray.", "AweSun"), ("com.oray.sunlogin", "Sunlogin"), ("com.todesk.", "ToDesk"), ("com.tightvnc.", "TightVNC"),
)
SHARING = (
    # (check id, launchd label, port, title, why it matters, severity, how to switch it off, command)
    ("remote-login", "com.openssh.sshd", 22, "Remote Login (SSH) is on",
     "Anyone on the network who has or guesses an account password can open a shell on this Mac.", "medium",
     "System Settings > General > Sharing > Remote Login: off.", "sudo systemsetup -setremotelogin off"),
    ("screen-sharing", "com.apple.screensharing", 5900, "Screen Sharing is on",
     "The screen, keyboard and mouse of this Mac can be taken over from the network with an account password.", "medium",
     "System Settings > General > Sharing > Screen Sharing: off.", "sudo launchctl disable system/com.apple.screensharing"),
    ("remote-management", "com.apple.RemoteDesktop.agent", 3283, "Remote Management (Apple Remote Desktop) is on",
     "Remote Management allows control of this Mac, file copies and commands from the network.", "medium",
     "System Settings > General > Sharing > Remote Management: off.",
     "sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop"),
    ("file-sharing", "com.apple.smbd", 445, "File Sharing (SMB) is on",
     "Folders of this Mac are offered to the network. Whoever has an account password can read what is shared.", "low",
     "System Settings > General > Sharing > File Sharing: off.", "sudo launchctl disable system/com.apple.smbd"),
    ("remote-apple-events", "com.apple.AEServer", 3031, "Remote Apple Events are on",
     "Other computers can send this Mac scripting commands.", "medium",
     "System Settings > General > Sharing > Remote Application Scripting: off.", "sudo systemsetup -setremoteappleevents off"),
)


def _out(cfg, argv, timeout=15):
    rc, out, err = cfg.run(argv, timeout=timeout)
    return rc, ((out or "") + (err or "")).strip()


class Check:
    def __init__(self, cid, state, title=None, detail=None, severity="medium", value=None, evidence=None, fix=None,
                 command=None, sudo=False, why=None, name=None):
        self.id, self.state, self.title, self.detail, self.severity = cid, state, title, detail, severity
        self.value, self.evidence, self.fix, self.command, self.sudo, self.why, self.name = value, evidence or [], fix, command, sudo, why, name


def ok(cid):
    return Check(cid, "ok")


def unknown(cid, name, why):
    return Check(cid, "unknown", name=name, why=why)


def could_not_run(rc, text):
    return rc in (124, 127) or not text


# ---------------------------------------------------------------- the checks

def check_sip(ctx):
    rc, t = _out(ctx.cfg, ["/usr/bin/csrutil", "status"])
    if could_not_run(rc, t) or "System Integrity Protection status" not in t:
        return [unknown("sip", "System Integrity Protection", "csrutil gave no answer")]
    if re.search(r"status:\s*enabled", t) and "disabled" not in t.lower():
        return [ok("sip")]
    return [Check("sip", "fail", "System Integrity Protection is not fully on",
                  "SIP stops even an administrator's programs from changing macOS itself. With it off or partly off, malware that gets admin rights can hide in the system.",
                  "high", t, [("csrutil status", t, "csrutil status")],
                  "Restart into Recovery (hold the power button), open Terminal and run: csrutil enable. Then restart.", None, False)]


def check_gatekeeper(ctx):
    rc, t = _out(ctx.cfg, ["/usr/sbin/spctl", "--status"])
    if could_not_run(rc, t) or "assessments" not in t:
        return [unknown("gatekeeper", "Gatekeeper", "spctl gave no answer")]
    if "assessments enabled" in t:
        return [ok("gatekeeper")]
    return [Check("gatekeeper", "fail", "Gatekeeper is off",
                  "Gatekeeper is what stops an unsigned or un-notarized app from opening without a warning. With it off, anything downloaded runs.",
                  "high", t, [("spctl --status", t, "spctl --status")],
                  "Switch Gatekeeper back on.", "sudo spctl --master-enable", True)]


def check_filevault(ctx):
    rc, t = _out(ctx.cfg, ["/usr/bin/fdesetup", "status"])
    if could_not_run(rc, t) or "FileVault" not in t:
        return [unknown("filevault", "FileVault", "fdesetup gave no answer")]
    if "FileVault is On" in t:
        return [ok("filevault")]
    return [Check("filevault", "fail", "FileVault disk encryption is off",
                  "Without FileVault anyone who takes this Mac or its disk can read every file on it, the secrets included.",
                  "high", t, [("fdesetup status", t.splitlines()[0], "fdesetup status")],
                  "System Settings > Privacy & Security > FileVault: turn on, and keep the recovery key somewhere safe.", "sudo fdesetup enable", True)]


def check_firewall(ctx):
    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    out = []
    rc, t = _out(ctx.cfg, [fw, "--getglobalstate"])
    if could_not_run(rc, t) or "Firewall" not in t:
        return [unknown("firewall", "Firewall", "socketfilterfw gave no answer"),
                unknown("firewall-stealth", "Firewall stealth mode", "socketfilterfw gave no answer")]
    on = "enabled" in t.lower() and "disabled" not in t.lower()
    if on:
        out.append(ok("firewall"))
    else:
        out.append(Check("firewall", "fail", "The macOS firewall is off",
                         "Any program on this Mac that opens a port can be reached from every device on the network.",
                         "medium", t, [("firewall", t, "socketfilterfw --getglobalstate")],
                         "System Settings > Network > Firewall: on.", "sudo %s --setglobalstate on" % fw, True))
    rc, t = _out(ctx.cfg, [fw, "--getstealthmode"])
    if could_not_run(rc, t) or "stealth" not in t.lower():
        out.append(unknown("firewall-stealth", "Firewall stealth mode", "socketfilterfw gave no answer"))
    elif re.search(r"stealth mode (is )?(on|enabled)", t, re.I):
        out.append(ok("firewall-stealth"))
    else:
        out.append(Check("firewall-stealth", "fail", "Firewall stealth mode is off",
                         "This Mac answers pings and probes, so a device on the network can find it and see which ports are closed. "
                         "Stealth mode makes it stay silent. A hardening step, not a hole by itself.",
                         "low", t, [("stealth mode", t, "socketfilterfw --getstealthmode")],
                         "System Settings > Network > Firewall > Options: enable stealth mode.", "sudo %s --setstealthmode on" % fw, True))
    return out


def check_updates(ctx):
    cfg = ctx.cfg
    p = cfg.s("/Library/Preferences/com.apple.SoftwareUpdate.plist")
    d = U.load_plist(p)
    if not isinstance(d, dict):
        return [unknown("updates", "Automatic updates", "the software update settings could not be read"),
                unknown("os-beta", "macOS release channel", "the software update settings could not be read")]
    out = []
    # A key that is absent means the default, which is on.
    rows = (("AutomaticCheckEnabled", "checking for updates", "medium"), ("AutomaticDownload", "downloading updates", "low"),
            ("CriticalUpdateInstall", "installing Security Responses and system files", "medium"),
            ("ConfigDataInstall", "installing XProtect and other protection data", "medium"),
            ("AutomaticallyInstallMacOSUpdates", "installing macOS updates", "low"))
    off = [(k, label, sev) for k, label, sev in rows if d.get(k) in (False, 0)]
    if off:
        sev = "medium" if any(s == "medium" for _, _, s in off) else "low"
        out.append(Check("updates", "fail", "Automatic updates are partly off",
                         "Switched off: %s. Security fixes and malware definitions then arrive only when someone installs them by hand." % ", ".join(l for _, l, _ in off),
                         sev, ",".join(k for k, _, _ in off), [(k, "off", "com.apple.SoftwareUpdate") for k, _, _ in off],
                         "System Settings > General > Software Update > Automatic Updates: switch everything on.",
                         "; ".join("sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate %s -bool true" % k for k, _, _ in off), True))
    else:
        out.append(ok("updates"))
    rc, t = _out(cfg, ["/usr/bin/sw_vers"])
    build = re.search(r"BuildVersion:\s*(\S+)", t or "")
    ver = re.search(r"ProductVersion:\s*(\S+)", t or "")
    catalog = d.get("CatalogURL") if isinstance(d.get("CatalogURL"), str) else ""
    if not build:
        out.append(unknown("os-beta", "macOS release channel", "sw_vers gave no answer"))
    else:
        seed_build = bool(re.search(r"[a-z]$", build.group(1)))
        seed_catalog = "seed" in catalog.lower() or "beta" in catalog.lower()
        if seed_build or seed_catalog:
            ev = [("macOS", "%s (%s)" % (ver.group(1) if ver else "?", build.group(1)), "sw_vers")]
            if seed_catalog:
                ev.append(("update catalog", "a seed (beta) catalog", "com.apple.SoftwareUpdate CatalogURL"))
            out.append(Check("os-beta", "fail", "macOS is on a beta (seed) build",
                             "This Mac runs a pre-release macOS%s. Betas get security fixes later or differently and can carry unfinished protections; "
                             "the machine that holds the household's secrets is safer on the release channel." % (
                                 "" if seed_build else " update channel"),
                             "low", "%s|%s" % (build.group(1) if seed_build else "", "seed" if seed_catalog else ""), ev,
                             "System Settings > General > Software Update > Beta Updates: Off. The Mac moves to the public release when the next one passes this beta.",
                             None, False))
        else:
            out.append(ok("os-beta"))
    return out


def check_xprotect(ctx):
    xp = (ctx.engines or {}).get("xprotect") or {}
    if not xp.get("version") or not xp.get("updatedAt"):
        return [unknown("xprotect", "XProtect definitions", "the XProtect bundle could not be read")]
    import datetime
    try:
        age = (time.time() - datetime.datetime.fromisoformat(xp["updatedAt"]).timestamp()) / 86400
    except ValueError:
        return [unknown("xprotect", "XProtect definitions", "the XProtect date could not be read")]
    if age <= 45:
        return [ok("xprotect")]
    return [Check("xprotect", "fail", "XProtect malware definitions are %d days old" % age,
                  "Apple usually updates XProtect every week or two. Old definitions miss recent malware.",
                  "low", xp["version"], [("XProtect", "version %s, updated %s" % (xp["version"], xp["updatedAt"][:10]), "XProtect.bundle")],
                  "System Settings > General > Software Update > Automatic Updates: keep “Install Security Responses and system files” on, then check for updates.",
                  "sudo softwareupdate --background-critical", True)]


def _loaded(cfg, label):
    """True when launchd has the system service, False when it does not, None when launchctl could not say."""
    rc, t = _out(cfg, ["/bin/launchctl", "print", "system/" + label], timeout=10)
    if rc in (124, 127):
        return None
    if rc == 0 and label in t:
        return True
    if "Could not find service" in t or rc == 113:
        return False
    return None


def check_sharing(ctx):
    cfg, out = ctx.cfg, []
    ip = ctx.cfg.lan_ip()
    for cid, label, port, title, why, sev, fix, cmd in SHARING:
        loaded = _loaded(cfg, label)
        lan = ctx.cfg.tcp_open(ip, port) if ip else None
        local = ctx.cfg.tcp_open("127.0.0.1", port)
        if loaded is None and not (lan or local):
            out.append(unknown(cid, title.replace(" is on", "").replace(" are on", ""), "launchctl gave no answer and the port does not answer"))
            continue
        if not loaded and not lan and not local:
            out.append(ok(cid))
            continue
        ev = []
        if loaded:
            ev.append(("launchd service", "%s is loaded" % label, "launchctl print system/%s" % label))
        if lan:
            ev.append(("port %d" % port, "answers on %s (the network)" % ip, "connect"))
        elif local:
            ev.append(("port %d" % port, "answers on this Mac only", "connect"))
        if not loaded and (lan or local) and cid in ("screen-sharing", "remote-login"):
            title = "Something answers on port %d (%s)" % (port, "VNC / screen sharing" if port == 5900 else "SSH")
        if cid == "screen-sharing" and lan:
            sev = "high"        # reachable from every device on the network, not just switched on
            why += " Port 5900 answers on the network right now."
        out.append(Check(cid, "fail", title, why, sev, "%s|%s" % (bool(loaded), bool(lan)), ev, fix, cmd, True))
    return out


def check_remote_tools(ctx):
    """VNC and other remote-control servers that start by themselves."""
    cfg, found = ctx.cfg, {}
    for d, kind in ((cfg.s("/Library/LaunchDaemons"), "LaunchDaemon"), (cfg.s("/Library/LaunchAgents"), "LaunchAgent"),
                    (cfg.h("Library", "LaunchAgents"), "LaunchAgent (user)")):
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for n in names:
            if not n.endswith(".plist"):
                continue
            low = n.lower()
            for prefix, product in REMOTE_TOOLS:
                if prefix in low:
                    found.setdefault(product, []).append((kind, os.path.join(d, n)))
    out = []
    for product, items in sorted(found.items()):
        kinds = sorted({k for k, _ in items})
        daemon = "LaunchDaemon" in kinds
        cid = "remote-tool:" + re.sub(r"[^a-z0-9]+", "-", product.lower())
        out.append(Check(cid, "fail", "%s is installed as a %s" % (product, "LaunchDaemon" if daemon else "launch agent"),
                         "%s is remote-control software and starts by itself%s. Whoever has its password or account can see and control this Mac. "
                         "Keep it only if you use it, with a strong password and its own two-step sign-in." % (
                             product, " as root at boot, before anyone logs in" if daemon else " at login"),
                         "medium", "|".join(sorted(p for _, p in items)),
                         [(k, cfg.show(p), "launchd") for k, p in items],
                         "If you do not use it: remove it with the vendor's uninstaller. If you do: set a strong password and restrict who may connect.",
                         None, False))
    return out, {c.id for c in out}


def check_airplay(ctx):
    ip = ctx.cfg.lan_ip()
    if not ip:
        return [unknown("airplay-receiver", "AirPlay Receiver", "this Mac has no network address to test")]
    ports = [p for p in (7000, 5000) if ctx.cfg.tcp_open(ip, p)]
    if not ports:
        return [ok("airplay-receiver")]
    rc, t = _out(ctx.cfg, ["/usr/sbin/lsof", "-nP", "-iTCP:%d" % ports[0], "-sTCP:LISTEN", "-Fc"], timeout=10)
    owner = re.search(r"^c(.+)$", t or "", re.M)
    name = owner.group(1) if owner else None
    if name and not name.startswith("ControlCe"):
        return [ok("airplay-receiver")]      # another program owns the port: the processes scanner reports it
    return [Check("airplay-receiver", "fail", "AirPlay Receiver is on",
                  "This Mac accepts AirPlay from the network on port%s %s. Any device on the Wi-Fi can find it and, depending on the setting, send it audio or video." % (
                      "s" if len(ports) > 1 else "", " and ".join(str(p) for p in ports)),
                  "low", ",".join(str(p) for p in ports),
                  [("port %d" % p, "answers on %s" % ip, "connect") for p in ports] + ([("owner", name, "lsof")] if name else []),
                  "System Settings > General > AirDrop & Handoff > AirPlay Receiver: off (or set “Allow AirPlay for” to Current User).", None, False)]


def check_admins(ctx):
    rc, t = _out(ctx.cfg, ["/usr/bin/dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
    m = re.search(r"GroupMembership:\s*(.*)", t or "")
    if could_not_run(rc, t) or not m:
        return [unknown("admin-accounts", "Administrator accounts", "dscl gave no answer")]
    admins = sorted(a for a in m.group(1).split() if a != "root" and not a.startswith("_"))
    if len(admins) <= 1:
        return [ok("admin-accounts")]
    return [Check("admin-accounts", "fail", "%d administrator accounts on this Mac" % len(admins),
                  "Each administrator account can read every file and change every setting, so each is a way in: %s. "
                  "Keep one for administration and make the rest standard accounts, or delete the ones nobody uses." % ", ".join(admins),
                  "low", ",".join(admins), [("admin group", ", ".join(admins), "dscl . -read /Groups/admin")],
                  "System Settings > Users & Groups: turn off “Allow this user to administer this computer” for the accounts that do not need it "
                  "(the command does the same for one account; put the account's name in place of ACCOUNT).",
                  "sudo dseditgroup -o edit -d ACCOUNT -t user admin", True)]


def check_login(ctx):
    cfg = ctx.cfg
    d = U.load_plist(cfg.s("/Library/Preferences/com.apple.loginwindow.plist"))
    out = []
    if not isinstance(d, dict):
        out += [unknown("auto-login", "Automatic login", "the login window settings could not be read"),
                unknown("guest-account", "Guest account", "the login window settings could not be read")]
    else:
        user = d.get("autoLoginUser")
        if user:
            out.append(Check("auto-login", "fail", "This Mac logs in by itself at startup",
                             "Automatic login is set for an account, so whoever switches the Mac on is inside it without a password.",
                             "high", str(user), [("autoLoginUser", "set", "com.apple.loginwindow")],
                             "System Settings > Users & Groups > Automatically log in as: Off.",
                             "sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser", True))
        else:
            out.append(ok("auto-login"))
        if d.get("GuestEnabled") in (True, 1):
            out.append(Check("guest-account", "fail", "The guest account is on",
                             "Anyone at the keyboard can log in as Guest without a password and use the network from this Mac.",
                             "low", "on", [("GuestEnabled", "true", "com.apple.loginwindow")],
                             "System Settings > Users & Groups > Guest User: off.",
                             "sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false", True))
        else:
            out.append(ok("guest-account"))
        for hook in ("LoginHook", "LogoutHook"):
            if d.get(hook):
                out.append(Check("login-hook:" + hook, "fail", "A %s runs a program as root at every %s" % (hook, "login" if hook == "LoginHook" else "logout"),
                                 "Login hooks are an old way to run a script as root. Almost nothing legitimate still uses them.",
                                 "high", U.digest(str(d.get(hook))), [(hook, U.redact(d.get(hook), 200), "com.apple.loginwindow")],
                                 "If you did not set this up, remove it.",
                                 "sudo defaults delete /Library/Preferences/com.apple.loginwindow %s" % hook, True))
    rc, t = _out(cfg, ["/usr/sbin/sysadminctl", "-screenLock", "status"])
    m = re.search(r"screenLock (?:delay )?is (.+)$", t or "", re.M)
    if could_not_run(rc, t) or not m:
        out.append(unknown("screen-lock", "Screen lock", "sysadminctl gave no answer"))
    else:
        v = m.group(1).strip().rstrip(".")
        secs = re.match(r"(\d+)", v)
        if v.lower() == "off":
            out.append(Check("screen-lock", "fail", "The screen does not ask for a password when it wakes",
                             "Once the screen saver or display sleep starts, anyone can wake the Mac and use it without a password.",
                             "medium", v, [("screen lock", v, "sysadminctl -screenLock status")],
                             "System Settings > Lock Screen > Require password after screen saver begins or display is turned off: Immediately.",
                             "sysadminctl -screenLock immediate -password -", False))
        elif secs and int(secs.group(1)) > 300:
            out.append(Check("screen-lock", "fail", "The screen asks for a password only after %s" % v,
                             "For that long after the screen goes dark, anyone can wake the Mac and use it without a password.",
                             "low", v, [("screen lock", v, "sysadminctl -screenLock status")],
                             "System Settings > Lock Screen > Require password …: Immediately or after 5 seconds.",
                             "sysadminctl -screenLock immediate -password -", False))
        else:
            out.append(ok("screen-lock"))
    return out


def check_internet_sharing(ctx):
    p = ctx.cfg.s("/Library/Preferences/SystemConfiguration/com.apple.nat.plist")
    if U.lstat(p) is None:
        return [ok("internet-sharing")]      # the file only exists once Internet Sharing has been set up
    d = U.load_plist(p)
    if not isinstance(d, dict):
        return [unknown("internet-sharing", "Internet Sharing", "its settings file could not be read")]
    if ((d.get("NAT") or {}).get("Enabled")) in (1, True):
        return [Check("internet-sharing", "fail", "Internet Sharing is on",
                      "This Mac passes its network connection on to other devices, which puts them behind it and outside the router's view.",
                      "medium", "on", [("NAT.Enabled", "1", "com.apple.nat.plist")],
                      "System Settings > General > Sharing > Internet Sharing: off.", None, False)]
    return [ok("internet-sharing")]


CHECKS = (check_sip, check_gatekeeper, check_filevault, check_firewall, check_updates, check_xprotect, check_sharing,
          check_airplay, check_admins, check_login, check_internet_sharing)


def scan(ctx):
    res = U.Result()
    first = ctx.baseline.begin("posture")
    outcomes = []
    for fn in CHECKS:
        try:
            outcomes += fn(ctx)
        except Exception as e:
            name = fn.__name__.replace("check_", "").replace("_", " ")
            res.unchecked(name, "the check failed: %s" % type(e).__name__, keep="")
    try:
        tools, _ = check_remote_tools(ctx)
        outcomes += tools
    except Exception as e:
        res.unchecked("remote-control software", "the check failed: %s" % type(e).__name__, keep="remote-tool:")
    for c in outcomes:
        res.items += 1
        if c.state == "unknown":
            res.unchecked(c.name or c.id, c.why or "could not be measured", keep=c.id)
        elif c.state == "fail":
            res.add(U.make_finding(
                c.id, "exposure" if c.id in ("remote-login", "screen-sharing", "remote-management", "file-sharing", "remote-apple-events",
                                             "airplay-receiver", "internet-sharing") or c.id.startswith("remote-tool:") else "posture",
                c.title, c.detail, {"type": "setting", "name": c.title},
                [U.Reason(c.id.split(":")[0], c.detail, c.severity, 100, measured=True)],
                evidence=c.evidence, fix={"text": c.fix, "command": c.command, "needsSudo": c.sudo},
                fp=U.digest(c.id, c.value), baseline=first))
    res.detail = "%d settings measured, %d could not be" % (res.items - len(res.not_checked), len(res.not_checked))
    return res
