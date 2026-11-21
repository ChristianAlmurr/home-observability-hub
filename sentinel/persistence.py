"""persistence: everything that makes a program start by itself.

On the first run what exists is the baseline and is judged on its own merits (heuristics only). After
that any new or changed item is a finding until the person trusts it. Property lists are parsed with
plistlib; a launch item's environment is reported by variable name only, and command lines are
redacted before they are shown.
"""
import os
import re
import shlex
import stat

from . import heur as H
from . import util as U

INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "python", "python3", "node", "ruby", "perl", "osascript", "env", "nohup",
                "caffeinate", "bun", "deno", "uv", "npx", "php", "nice", "sudo", "arch", "open", "java"}
SAFE_LABEL = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SHELL_FILES = (".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout", ".bash_profile", ".bashrc", ".bash_login", ".profile",
               ".config/fish/config.fish")
HOSTS_DEFAULT = {("127.0.0.1", "localhost"), ("255.255.255.255", "broadcasthost"), ("::1", "localhost"), ("fe80::1%lo0", "localhost")}


def _interp(path):
    base = os.path.basename(path or "")
    return re.sub(r"[0-9.]+$", "", base).lower() in INTERPRETERS


def resolve_program(doc, home):
    """(program, script, inline, argv): what the item starts, the script an interpreter is given, an inline command."""
    args = doc.get("ProgramArguments")
    args = [a for a in args if isinstance(a, str)] if isinstance(args, list) else []
    prog = doc.get("Program") if isinstance(doc.get("Program"), str) else (args[0] if args else None)
    argv = args or ([prog] if prog else [])
    script = inline = None
    if prog and _interp(prog):
        rest = argv[1:]
        i = 0
        while i < len(rest):
            a = rest[i]
            if a in ("-c", "-lc", "-ic", "-e", "-lic") and i + 1 < len(rest):
                inline = rest[i + 1]
                break
            if a.startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", a):
                i += 1
                continue
            if _interp(a):          # env python3 script.py, sudo -u x bash script.sh
                i += 1
                continue
            cand = os.path.expanduser(a) if a.startswith("~") else a
            if cand.startswith("~"):
                cand = home + cand[1:]
            if cand.startswith("/"):
                script = cand
            break
    return prog, script, inline, argv


def location_reasons(cfg, path, what):
    """Where a program lives says something: temp folders, download folders and hidden places."""
    out = []
    if not path:
        return out
    real = os.path.realpath(path)
    temp = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/private/var/folders/", "/var/folders/", "/Users/Shared/")
    dl = (cfg.h("Downloads") + "/", cfg.h("Desktop") + "/")
    if any(real.startswith(t) or path.startswith(t) for t in temp) and not U.within(real, cfg.home):
        out.append(U.Reason("temp-location", "%s runs from a temporary or shared folder (%s), where any program can put a file. "
                            "Things that are meant to stay are not installed there." % (what, cfg.show(os.path.dirname(path))), "high", 70))
    elif any(real.startswith(t) for t in dl):
        out.append(U.Reason("download-location", "%s runs from %s. Something that starts by itself straight out of the downloads "
                            "folder was not installed in the usual way." % (what, cfg.show(os.path.dirname(path))), "high", 65))
    else:
        parts = [p for p in real.split(os.sep) if p]
        hidden_name = os.path.basename(real).startswith(".")
        in_library = "Library" in parts and any(p.startswith(".") for p in parts[parts.index("Library") + 1:])
        if hidden_name or in_library:
            out.append(U.Reason("hidden-location", "%s is a hidden file or sits in a hidden folder inside Library (%s)." % (
                what, cfg.show(os.path.dirname(path))), "medium", 50))
    return out


def writable_reasons(cfg, path, what, as_root):
    st = U.lstat(path)
    if st is None:
        return []
    if stat.S_ISLNK(st.st_mode):
        try:
            st = os.stat(path)
        except OSError:
            return []
    out = []
    loose = stat.S_IMODE(st.st_mode) & 0o022
    if as_root and st.st_uid != 0:
        out.append(U.Reason("root-item-user-owned", "%s runs as root but the file belongs to an ordinary account, so any program of that "
                            "account can replace it and become root." % what, "high", 100, measured=True))
    elif loose:
        out.append(U.Reason("writable-by-others", "%s can be changed by other accounts on this Mac (mode %s)%s." % (
            what, U.mode_text(st), ", and it runs as root" if as_root else ""), "high" if as_root else "medium", 100, measured=True))
    return out


def launch_dirs(cfg):
    return ((cfg.h("Library", "LaunchAgents"), "launchd-user", False), (cfg.s("/Library/LaunchAgents"), "launchd-agents", False),
            (cfg.s("/Library/LaunchDaemons"), "launchd-daemons", True))


def emit(ctx, res, key, fp, group, reasons, new_text, changed_text, sev_new="medium", sev_changed="medium", **kw):
    """Add the new/changed reason from the baseline, then the finding if there is any reason at all."""
    res.seen.add(key)
    res.items += 1
    first = ctx.baseline.first(group)
    status = ctx.baseline.status(key, fp, group)
    reasons = list(reasons)
    if status == "new":
        reasons.insert(0, U.Reason("new", new_text, sev_new, 100, measured=True))
    elif status == "changed":
        reasons.insert(0, U.Reason("changed", changed_text, sev_changed, 100, measured=True))
    if reasons:
        res.add(U.make_finding(key, kw.pop("category", "persistence"), kw.pop("title"), kw.pop("detail", None) or reasons[0].text,
                               kw.pop("subject"), reasons, fp=fp, baseline=first, **kw))
    return status


def title_for(reasons, status, name, noun="launch item"):
    lead = sorted(reasons, key=lambda r: (U.SEV_RANK[r.severity], r.pct), reverse=True)[0] if reasons else None
    words = {"temp-location": "runs from a temporary folder", "download-location": "runs from the downloads folder",
             "hidden-location": "runs from a hidden place", "missing-program": "points at a program that is not there",
             "writable-by-others": "can be changed by other accounts", "root-item-user-owned": "runs as root from a file anyone here can replace",
             "unsigned-program": "runs an unsigned program", "mimics-apple": "pretends to be Apple's",
             "pipe-to-shell": "runs code straight from the network", "base64-exec": "runs hidden code", "reverse-shell": "opens a remote shell"}
    if lead and lead.code in words and (status == "known" or U.SEV_RANK[lead.severity] > U.SEV_RANK["medium"]):
        return "%s %s: %s" % (noun.capitalize(), words[lead.code], name)
    if status == "new":
        return "New %s: %s" % (noun, name)
    if status == "changed":
        return "Changed %s: %s" % (noun, name)
    if lead:
        return "%s: %s (%s)" % (noun.capitalize(), name, lead.code.replace("-", " "))
    return "%s: %s" % (noun.capitalize(), name)


def scan_launchd(ctx, res):
    cfg = ctx.cfg
    for d, group, daemon in launch_dirs(cfg):
        try:
            names = sorted(os.listdir(d))
        except FileNotFoundError:
            ctx.baseline.begin(group)
            continue
        except OSError as e:
            res.unchecked("launch items in %s" % cfg.show(d), "cannot be listed (%s)" % (e.strerror or "error"), keep="launchd:" + d + "/")
            continue
        ctx.baseline.begin(group)
        for n in names:
            if not n.endswith(".plist"):
                continue
            path = os.path.join(d, n)
            st = U.lstat(path)
            if st is None:
                continue
            key = "launchd:" + path
            doc = U.load_plist(path)
            if not isinstance(doc, dict):
                res.seen.add(key)
                res.unchecked("launch item %s" % n, "the file could not be read as a property list", keep=key)
                continue
            label = doc.get("Label") if isinstance(doc.get("Label"), str) else n[:-6]
            prog, script, inline, argv = resolve_program(doc, cfg.home)
            fp = U.sha256_file(path) or U.digest(st.st_size, st.st_mtime_ns)
            reasons = []
            noun = "launch daemon" if daemon else "launch agent"
            as_root = daemon and not doc.get("UserName")
            target = script or prog
            if prog and prog.startswith("/") and not os.path.exists(prog):
                reasons.append(U.Reason("missing-program", "It is set to start %s, which does not exist. Whatever is put at that path later will be started automatically."
                                        % cfg.show(prog), "low", 100, measured=True))
            elif script and not os.path.exists(script):
                reasons.append(U.Reason("missing-program", "It is set to run the script %s, which does not exist. Whatever is put at that path later will be run automatically."
                                        % cfg.show(script), "low", 100, measured=True))
            reasons += location_reasons(cfg, target, "The program it starts")
            reasons += writable_reasons(cfg, path, "This launch item", as_root)
            if target and os.path.exists(target):
                reasons += writable_reasons(cfg, target, "The program it starts", as_root)
            if inline:
                reasons += H.script_reasons(inline, "command it runs")
            keeps = bool(doc.get("RunAtLoad")) or bool(doc.get("KeepAlive"))
            cs = None
            if prog and prog.startswith("/") and not _interp(prog) and os.path.isfile(prog):
                head = U.read_head(os.path.realpath(prog), 8)
                if U.is_macho(head):
                    cs = ctx.sigs.info(os.path.realpath(prog))
                    if cs.get("signed") is False and keeps:
                        reasons.append(U.Reason("unsigned-program", "It keeps an unsigned program running: nobody vouches for what %s does."
                                                % os.path.basename(prog), "medium", 50))
            apple_name = label.lower().startswith("com.apple.") or n.lower().startswith("com.apple.")
            if apple_name and not (cs and cs.get("apple")):
                reasons.append(U.Reason("mimics-apple", "It is named like a part of macOS (%s), but it is not in the system folder and what it starts is not signed by Apple. "
                                        "Malware uses Apple-looking names to be overlooked." % U.clean(label, 80), "high", 75))
            ev = [("file", cfg.show(path), "launchd"), ("runs", U.redact(" ".join(shlex.quote(a) for a in argv), 300) if argv else "nothing", "ProgramArguments")]
            flags = [k for k in ("RunAtLoad", "KeepAlive") if doc.get(k)]
            for k in ("StartInterval", "StartCalendarInterval", "WatchPaths", "QueueDirectories", "Sockets"):
                if doc.get(k):
                    flags.append(k)
            if doc.get("Disabled") is True:
                flags.append("Disabled")
            if flags:
                ev.append(("starts", ", ".join(flags), "plist keys"))
            env = doc.get("EnvironmentVariables")
            if isinstance(env, dict) and env:
                ev.append(("environment", ", ".join(sorted(str(k) for k in env)[:20]), "variable names only"))
            if cs is not None:
                ev.append(("program signature", U.signer_text(cs), "codesign -dv"))
            ev.append(("mode", "%s, owner uid %d" % (U.mode_text(st), st.st_uid), "stat"))
            status = ctx.baseline.status(key, fp, group)
            if SAFE_LABEL.match(label):
                cmd = ("sudo launchctl bootout system/%s" % label) if daemon else ("launchctl bootout gui/%d/%s" % (cfg.uid, label))
            else:
                cmd = None
            emit(ctx, res, key, fp, group, reasons,
                 "This %s was not there when the baseline was taken. It starts %s by itself." % (noun, U.redact(os.path.basename(target or "a program"), 80)),
                 "This %s changed since it was last trusted or baselined: what it runs or when may be different now." % noun,
                 title=title_for(reasons, status, U.clean(label, 100), noun),
                 subject={"type": "launch-item", "name": label, "path": path}, evidence=ev,
                 fix={"text": "If you know it, mark it trusted. If you do not: stop it with the command, then move the file %s out of that folder." % cfg.show(path),
                      "command": cmd, "needsSudo": daemon})


def scan_cron(ctx, res):
    cfg = ctx.cfg
    rc, out, err = cfg.run(["/usr/bin/crontab", "-l"], timeout=10)
    if rc in (124, 127):
        res.unchecked("cron jobs", "crontab gave no answer", keep="cron:")
        return
    ctx.baseline.begin("cron")
    lines = [] if rc != 0 else [l.strip() for l in out.splitlines() if l.strip() and not l.strip().startswith("#")]
    sys_tab = U.read_text(cfg.s("/etc/crontab"), 256 * 1024)
    for src, text_lines in (("user", lines), ("system", [l.strip() for l in (sys_tab or "").splitlines() if l.strip() and not l.strip().startswith("#")])):
        for line in text_lines:
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", line):
                continue        # an environment assignment, not a job
            key = "cron:%s:%s" % (src, U.digest(line)[:16])
            reasons = H.script_reasons(line, "cron line")
            parts = line.split(None, 5)
            cmd = parts[5] if len(parts) > 5 and not line.startswith("@") else line.split(None, 1)[-1]
            reasons += location_reasons(cfg, shlex_first(cmd), "The cron job")
            shown = U.redact(line, 240)
            status = ctx.baseline.status(key, U.digest(line), "cron")
            emit(ctx, res, key, U.digest(line), "cron", reasons,
                 "This cron job was not there when the baseline was taken.", "This cron job changed.",
                 title=title_for(reasons, status, U.redact(cmd, 60), "cron job"),
                 subject={"type": "launch-item", "name": "cron: " + U.redact(cmd, 80)},
                 evidence=[("line", shown, "crontab -l" if src == "user" else "/etc/crontab")],
                 fix={"text": "Edit the cron table and remove the line if you do not know it.", "command": "crontab -e", "needsSudo": False})
    if U.lstat(cfg.s("/var/at/tabs")) is not None and not os.access(cfg.s("/var/at/tabs"), os.R_OK):
        res.unchecked("cron jobs of other accounts", "reading them needs administrator rights (sudo ls /var/at/tabs)")


def shlex_first(cmd):
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()
    for p in parts:
        if p.startswith("/") or p.startswith("~"):
            return os.path.expanduser(p)
    return None


def scan_shell(ctx, res):
    cfg = ctx.cfg
    ctx.baseline.begin("shell")
    for rel in SHELL_FILES:
        path = cfg.h(rel)
        st = U.lstat(path)
        if st is None:
            continue
        target = os.path.realpath(path)
        key = "shell:" + path
        text = U.read_text(target, 512 * 1024) if os.path.isfile(target) else None
        if text is None:
            res.seen.add(key)
            res.unchecked("shell startup file %s" % cfg.show(path), "could not be read", keep=key)
            continue
        fp = U.digest(text)
        reasons = H.script_reasons(text, "file", strict=True)
        reasons += writable_reasons(cfg, target, "This startup file", False)
        status = ctx.baseline.status(key, fp, "shell")
        emit(ctx, res, key, fp, "shell", reasons,
             "This shell startup file was not there when the baseline was taken. Every new terminal runs it.",
             "This shell startup file changed since the baseline. Every new terminal runs it; installers add lines here, and so does malware.",
             sev_new="low", sev_changed="low",
             title=("Shell startup file %s: %s" % ("is new" if status == "new" else "changed" if status == "changed" else "looks risky", cfg.show(path))),
             subject={"type": "file", "name": os.path.basename(path), "path": path},
             evidence=[("file", cfg.show(path), "stat"), ("size", "%d bytes, mode %s" % (st.st_size, U.mode_text(st)), "stat")],
             fix={"text": "Open the file and read what was added. If every line is yours or an installer's you know, mark it trusted.",
                  "command": "less %s" % shlex.quote(path), "needsSudo": False})


def scan_hosts(ctx, res):
    cfg = ctx.cfg
    path = cfg.s("/etc/hosts")
    text = U.read_text(path, 512 * 1024)
    if text is None:
        res.unchecked("/etc/hosts", "could not be read", keep="hosts")
        return
    ctx.baseline.begin("hosts")
    redirects = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        for name in parts[1:]:
            if (ip, name) in HOSTS_DEFAULT or ip in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                continue
            redirects.append((ip, name))
    reasons = []
    public = [(ip, n) for ip, n in redirects if "." in n and not re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.|f[cde])", ip)
              and not n.endswith((".local", ".lan", ".home", ".internal", ".test", ".localhost"))]
    if public:
        reasons.append(U.Reason("hosts-redirect", "The hosts file sends %d internet name%s to an address of its own choosing (for example %s). "
                                "That overrides DNS for everything on this Mac and is how traffic is quietly redirected." % (
                                    len(public), "" if len(public) == 1 else "s", U.clean(public[0][1], 60)), "medium", 55))
    fp = U.digest(text)
    status = ctx.baseline.status("hosts", fp, "hosts")
    emit(ctx, res, "hosts", fp, "hosts", reasons, "", "The hosts file changed since the baseline. It overrides DNS for every program on this Mac.",
         title="The hosts file %s" % ("changed" if status == "changed" else "redirects internet names"),
         subject={"type": "file", "name": "hosts", "path": path},
         evidence=[("entry", "%s → %s" % (U.clean(n, 80), U.clean(ip, 45)), "/etc/hosts") for ip, n in (public or redirects)[:10]],
         fix={"text": "Open the file and check each line that is not a localhost entry.", "command": "cat /etc/hosts", "needsSudo": False})


def scan_sudoers(ctx, res):
    cfg = ctx.cfg
    ctx.baseline.begin("sudoers")
    main = cfg.s("/etc/sudoers")
    st = U.lstat(main)
    if st is not None:
        fp = U.digest(st.st_size, st.st_mtime_ns)
        emit(ctx, res, "sudoers", fp, "sudoers", [], "", "The sudoers file changed since the baseline. It decides who may become administrator, and whether a password is asked.",
             sev_changed="high", title="The sudoers file changed",
             subject={"type": "file", "name": "sudoers", "path": main},
             evidence=[("file", "/etc/sudoers, %d bytes, mode %s" % (st.st_size, U.mode_text(st)), "stat")],
             fix={"text": "Read it and look for lines with NOPASSWD or an account that should not be there.", "command": "sudo cat /etc/sudoers", "needsSudo": True})
        if not os.access(main, os.R_OK):
            res.unchecked("content of /etc/sudoers", "only root can read it: its size and date are watched, its rules are not read")
    d = cfg.s("/etc/sudoers.d")
    try:
        names = sorted(os.listdir(d))
    except OSError:
        names = []
    for n in names:
        p = os.path.join(d, n)
        s = U.lstat(p)
        if s is None:
            continue
        reasons = writable_reasons(cfg, p, "This sudoers rule file", True)
        fp = U.digest(s.st_size, s.st_mtime_ns)
        status = ctx.baseline.status("sudoers.d:" + n, fp, "sudoers")
        emit(ctx, res, "sudoers.d:" + n, fp, "sudoers", reasons,
             "A new file of sudo rules appeared. It can let a program become administrator without a password.",
             "This file of sudo rules changed.", sev_new="high", sev_changed="high",
             title="%s sudo rules file: %s" % ("New" if status == "new" else "Changed" if status == "changed" else "Loose", U.clean(n, 80)),
             subject={"type": "file", "name": n, "path": p},
             evidence=[("file", "%s, %d bytes, mode %s, owner uid %d" % (cfg.show(p), s.st_size, U.mode_text(s), s.st_uid), "stat")],
             fix={"text": "Read it. Remove it if you did not put it there.", "command": "sudo cat %s" % shlex.quote(p), "needsSudo": True})


def scan_ssh_keys(ctx, res):
    """authorized_keys: who may log in with a key. Size, date and mode only: the file is never opened."""
    cfg = ctx.cfg
    ctx.baseline.begin("ssh")
    for name in ("authorized_keys", "authorized_keys2"):
        p = cfg.h(".ssh", name)
        st = U.lstat(p)
        if st is None:
            continue
        key = "ssh:" + name
        fp = U.digest(st.st_size, st.st_mtime_ns, st.st_ino)
        first = ctx.baseline.first("ssh")
        reasons = []
        if first and st.st_size > 0:
            reasons.append(U.Reason("authorized-keys", "This account accepts SSH logins by key (%d bytes of authorised keys). Whoever holds a matching "
                                    "private key gets a shell without a password whenever Remote Login is on." % st.st_size, "low", 100, measured=True))
        if stat.S_IMODE(st.st_mode) & 0o022:
            reasons.append(U.Reason("writable-by-others", "Other accounts on this Mac can add their own key to it (mode %s)." % U.mode_text(st), "high", 100, measured=True))
        status = ctx.baseline.status(key, fp, "ssh")
        emit(ctx, res, key, fp, "ssh", reasons,
             "A file of authorised SSH keys appeared. Whoever holds a matching private key can log in to this account.",
             "The authorised SSH keys of this account changed: a key may have been added.", sev_new="high", sev_changed="high",
             title="SSH authorised keys %s" % ("are new" if status == "new" else "changed" if status == "changed" else "are in use"),
             subject={"type": "file", "name": name, "path": p},
             evidence=[("file", "%s, %d bytes, mode %s" % (cfg.show(p), st.st_size, U.mode_text(st)), "stat (contents not read)")],
             fix={"text": "Look at the keys and remove any you do not recognise.", "command": "ssh-keygen -lf %s" % shlex.quote(p), "needsSudo": False})


def scan_extensions(ctx, res):
    cfg = ctx.cfg
    rc, out, err = cfg.run(["/usr/bin/systemextensionsctl", "list"], timeout=20)
    if rc != 0 or "extension(s)" not in (out or ""):
        res.unchecked("system extensions", "systemextensionsctl gave no answer", keep="sysext:")
    else:
        ctx.baseline.begin("sysext")
        for line in out.splitlines():
            cols = line.split("\t")
            if len(cols) < 6 or "bundleID" in line:
                continue
            m = re.match(r"^(\S+)\s*\(([^)]*)\)", cols[3].strip())
            if not m or "activated" not in cols[5]:
                continue
            team, bundle, name = cols[2].strip(), m.group(1), cols[4].strip()
            key = "sysext:" + bundle
            emit(ctx, res, key, team, "sysext", [],
                 "A new system extension is active: %s (team %s). System extensions see network traffic or file activity for the whole Mac." % (U.clean(name, 60), U.clean(team, 20)),
                 "This system extension is now signed by a different team (%s)." % U.clean(team, 20), sev_changed="high",
                 title="New system extension: %s" % U.clean(name or bundle, 80),
                 subject={"type": "extension", "name": name or bundle},
                 evidence=[("bundle id", bundle, "systemextensionsctl list"), ("team id", team, "systemextensionsctl list"), ("version", m.group(2), "systemextensionsctl list")],
                 fix={"text": "System Settings > General > Login Items & Extensions > Extensions: switch it off if you do not know it, or remove its app."})
    ctx.baseline.begin("kext")
    d = cfg.s("/Library/Extensions")
    try:
        names = sorted(n for n in os.listdir(d) if n.endswith(".kext"))
    except OSError:
        names = []
    for n in names:
        info = U.load_plist(os.path.join(d, n, "Contents", "Info.plist")) or {}
        ident = info.get("CFBundleIdentifier") if isinstance(info.get("CFBundleIdentifier"), str) else n
        emit(ctx, res, "kext:" + n, U.digest(ident, info.get("CFBundleVersion")), "kext", [],
             "A new kernel extension was installed: %s. Kernel extensions run with full control of the Mac." % U.clean(ident, 80),
             "This kernel extension changed.", sev_new="high", sev_changed="high",
             title="New kernel extension: %s" % U.clean(n, 80), subject={"type": "extension", "name": n, "path": os.path.join(d, n)},
             evidence=[("bundle id", ident, "Info.plist")],
             fix={"text": "If you did not install the software it belongs to, remove that software with its uninstaller."})


def scan_profiles(ctx, res):
    cfg = ctx.cfg
    rc, out, err = cfg.run(["/usr/bin/profiles", "list"], timeout=20)
    text = (out or "") + (err or "")
    if rc in (124, 127) or not text.strip():
        res.unchecked("configuration profiles", "the profiles tool gave no answer", keep="profile:")
        return
    ctx.baseline.begin("profiles")
    ids = re.findall(r"profileIdentifier:\s*(\S+)", text)
    for pid in sorted(set(ids)):
        key = "profile:" + pid
        first = ctx.baseline.first("profiles")
        reasons = [U.Reason("profile-installed", "A configuration profile is installed (%s). A profile can add root certificates, proxies, VPNs and "
                            "management that outlast everything else on this list." % U.clean(pid, 80), "medium", 100, measured=True)] if first else []
        emit(ctx, res, key, pid, "profiles", reasons,
             "A configuration profile was installed since the baseline (%s). A profile can add root certificates, proxies and remote management." % U.clean(pid, 80),
             "", sev_new="high", title="Configuration profile installed: %s" % U.clean(pid, 80),
             subject={"type": "setting", "name": pid}, evidence=[("profile", pid, "profiles list")],
             fix={"text": "System Settings > General > Device Management: open the profile, read what it installs, remove it if you do not need it."})
    managed = cfg.s("/Library/Managed Preferences")
    try:
        entries = [n for n in os.listdir(managed) if not n.startswith(".")]
    except OSError:
        entries = []
    if entries:
        emit(ctx, res, "profile:managed-preferences", U.digest(*sorted(entries)), "profiles",
             [U.Reason("managed-preferences", "Settings on this Mac are being managed by a profile or a management server (%d managed preference file%s)." % (
                 len(entries), "" if len(entries) == 1 else "s"), "medium", 100, measured=True)],
             "", "", title="This Mac has managed settings", subject={"type": "setting", "name": "Managed Preferences"},
             evidence=[("managed", U.clean(", ".join(sorted(entries)[:8]), 200), "/Library/Managed Preferences")],
             fix={"text": "System Settings > General > Device Management shows who manages what.", "command": "sudo profiles list", "needsSudo": True})
    res.unchecked("device-wide configuration profiles", "listing them needs administrator rights (sudo profiles list); only this account's profiles and managed settings were read")


def scan_helpers(ctx, res):
    cfg = ctx.cfg
    d = cfg.s("/Library/PrivilegedHelperTools")
    ctx.baseline.begin("helpers")
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return
    for n in names:
        p = os.path.join(d, n)
        st = U.lstat(p)
        if st is None or not stat.S_ISREG(st.st_mode):
            continue
        cs = ctx.sigs.info(p)
        reasons = writable_reasons(cfg, p, "This helper", True)
        if cs.get("signed") is False or cs.get("adhoc"):
            reasons.append(U.Reason("unsigned-program", "A helper that runs as root is %s." % ("not signed" if not cs.get("signed") else "only ad-hoc signed"), "high", 70))
        fp = U.digest(st.st_size, st.st_mtime_ns, cs.get("teamId"))
        status = ctx.baseline.status("helper:" + n, fp, "helpers")
        emit(ctx, res, "helper:" + n, fp, "helpers", reasons,
             "A new privileged helper was installed. It runs as root on behalf of an app.", "This privileged helper changed.",
             title="%s privileged helper: %s" % ("New" if status == "new" else "Changed" if status == "changed" else "Risky", U.clean(n, 80)),
             subject={"type": "launch-item", "name": n, "path": p},
             evidence=[("signature", U.signer_text(cs), "codesign -dv"), ("team id", cs.get("teamId"), "codesign -dv"),
                       ("mode", "%s, owner uid %d" % (U.mode_text(st), st.st_uid), "stat")],
             fix={"text": "It belongs to an app. If you do not use that app, remove the app with its uninstaller."})


PARTS = (("launch items", scan_launchd, "launchd:"), ("cron", scan_cron, "cron:"), ("shell startup files", scan_shell, "shell:"),
         ("hosts file", scan_hosts, "hosts"), ("sudoers", scan_sudoers, "sudoers"), ("SSH authorised keys", scan_ssh_keys, "ssh:"),
         ("system and kernel extensions", scan_extensions, ("sysext:", "kext:")), ("configuration profiles", scan_profiles, "profile:"),
         ("privileged helpers", scan_helpers, "helper:"))


def scan(ctx):
    res = U.Result()
    for name, fn, prefix in PARTS:
        try:
            fn(ctx, res)
        except Exception as e:
            for p in (prefix if isinstance(prefix, tuple) else (prefix,)):
                res.unchecked(name, "the check failed (%s)" % type(e).__name__, keep=p)
    res.unchecked("login items and background items from System Settings",
                  "macOS keeps them in a database only an administrator can read (sudo sfltool dumpbtm)")
    res.unchecked("what the scripts behind launch items contain",
                  "a launch item is watched for changes to what it starts, not for edits inside the script it starts")
    res.detail = "%d items that start by themselves" % res.items
    return res
