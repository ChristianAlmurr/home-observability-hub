"""downloads: everything new or changed in Downloads, Desktop, Applications and mounted disk images.

Cheap by design: every run walks the folders with os.scandir and compares (size, mtime, inode) with
the stored index; only what is new or changed is opened, hashed, checked with codesign/spctl and
handed to ClamAV. Nothing found here is ever executed, imported, mounted or unpacked.
"""
import collections
import os
import plistlib
import re
import stat
import time
import zipfile

from . import engines as E
from . import heur as H
from . import util as U

SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", ".venv", "venv", "__pycache__", ".cache", "Caches", ".Trash", ".Trashes",
             ".Spotlight-V100", ".fseventsd", ".DocumentRevisions-V100", ".TemporaryItems", "DerivedData", ".next", ".tox"}
BUNDLE_EXT = {".app": "app", ".pkg": "pkg", ".mpkg": "pkg", ".workflow": "workflow", ".action": "workflow", ".scptd": "applescript",
              ".kext": "bundle", ".prefPane": "bundle", ".plugin": "bundle", ".saver": "bundle", ".qlgenerator": "bundle",
              ".appex": "bundle", ".framework": "bundle", ".bundle": "bundle", ".xcodeproj": "skip", ".photoslibrary": "skip"}
FILE_EXT = {".pkg": "pkg", ".mpkg": "pkg", ".dmg": "dmg", ".iso": "dmg", ".sparseimage": "dmg", ".command": "script", ".tool": "script",
            ".sh": "script", ".zsh": "script", ".bash": "script", ".py": "script", ".rb": "script", ".pl": "script",
            ".applescript": "script", ".scpt": "applescript", ".jar": "jar", ".mobileconfig": "profile", ".terminal": "terminal",
            ".crx": "extension", ".xpi": "extension", ".safariextz": "extension", ".zip": "archive", ".dylib": "macho",
            ".inetloc": "shortcut", ".webloc": "other", ".fileloc": "shortcut"}
DOC_EXT = r"(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|heic|txt|rtf|csv|mp[34]|mov|zip|html?|pages|numbers|key)"
RUN_EXT = r"(?:app|command|sh|pkg|dmg|scpt|terminal|workflow|jar|py|tool|exe|scr|bat|js)"
DOUBLE_EXT = re.compile(r"\.%s\s*\.%s$" % (DOC_EXT, RUN_EXT), re.I)
SPACED_EXT = re.compile(r"\s{4,}\.%s$" % RUN_EXT, re.I)
BYPASS_WORDS = re.compile(r"right[\s-]?click|control[\s-]?click|ctrl[\s+-]?click|open\s+anyway|drag\s+(?:it\s+)?(?:in)?to\s+terminal|"
                          r"system settings.{0,40}privacy.{0,40}open", re.I | re.S)
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-" + b"TEST-FILE!$H+H*")
MAX_ENTRIES = 20000
BUDGET_SEC = 900
PROFILE_RISK = {"com.apple.security.root": "installs a root certificate (lets someone read encrypted traffic)",
                "com.apple.security.pem": "installs a certificate", "com.apple.security.pkcs1": "installs a certificate",
                "com.apple.proxy.http.global": "routes web traffic through a proxy", "com.apple.dnsSettings.managed": "changes DNS",
                "com.apple.vpn.managed": "adds a VPN", "com.apple.webcontent-filter": "adds a content filter that sees web traffic",
                "com.apple.mdm": "enrols this Mac in remote management", "com.apple.TCC.configuration-profile-policy": "grants privacy permissions",
                "com.apple.system-extension-policy": "pre-approves system extensions", "com.apple.loginitems.managed": "adds login items"}
TITLES = {
    "malware": "Malware found", "yara": "Matches a malware rule", "test-file": "Antivirus test file",
    "revoked": "App signed with a revoked certificate", "tampered": "App changed after it was signed",
    "double-extension": "File disguised as a document", "script-executable": "App that is really a script",
    "unsigned-internet": "Unsigned program from the internet", "unsigned": "Unsigned program",
    "quarantine-stripped": "Download with its safety mark removed", "bypass-instructions": "Download that tells you to bypass macOS's warning",
    "profile": "Configuration profile", "unsigned-pkg": "Unsigned installer package", "signer-changed": "App now signed by someone else",
    "gatekeeper-rejects": "Gatekeeper would refuse this", "unnotarized": "Not notarized by Apple",
    "pipe-to-shell": "Script that runs code straight from the network", "base64-exec": "Script that runs hidden code",
    "reverse-shell": "Script that opens a remote shell", "password-prompt": "Script that asks for your password",
    "credential-check": "Script that tests passwords", "credential-files": "Script that reads stored passwords",
    "disables-protection": "Script that switches protection off", "fetch-run-temp": "Script that downloads and runs a program",
    "strips-quarantine": "Script that removes the download safety mark", "runs-on-open": "Download that runs when opened",
    "archive-disguise": "Archive with a disguised program inside", "exe-outside": "App whose program lives outside the app",
}


# ---------------------------------------------------------------- walking

def roots(ctx):
    """[(path, depth, kind)]: kind is downloads | apps | volume."""
    cfg = ctx.cfg
    out = [(cfg.h("Downloads"), 4, "downloads"), (cfg.h("Desktop"), 3, "downloads"),
           (cfg.s("/Applications"), 2, "apps"), (cfg.h("Applications"), 2, "apps")]
    out += [(p, 4, "downloads") for p in cfg.extra_roots]
    out += [(p, 3, "volume") for p in mounted_images(cfg)]
    seen, uniq = set(), []
    for p, d, k in out:
        if p not in seen:
            seen.add(p)
            uniq.append((p, d, k))
    return uniq


def mounted_images(cfg):
    """Mount points of disk images the person has mounted (not the system's own)."""
    if getattr(cfg, "volume_roots", None) is not None:
        return list(cfg.volume_roots)
    if cfg.sysroot != "/":
        return []
    rc, out, _ = cfg.run(["/usr/bin/hdiutil", "info", "-plist"], timeout=20)
    if rc != 0 or not out:
        return []
    try:
        doc = plistlib.loads(out.encode("utf-8"))
    except Exception:
        return []
    pts = []
    for img in doc.get("images") or []:
        ip = str(img.get("image-path") or "")
        if ip.startswith(("/System/", "/Library/Developer/", "/private/var/db/", "/Library/Apple/")):
            continue
        for ent in img.get("system-entities") or []:
            mp = ent.get("mount-point")
            if isinstance(mp, str) and mp.startswith("/Volumes/"):
                pts.append(mp)
    return pts[:8]


def walk(root, depth):
    """Yields (path, lstat, is_bundle). Never follows a link, never enters a bundle or a skipped folder."""
    count = 0
    stack = [(root, 0)]
    while stack:
        d, lvl = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for e in it:
                count += 1
                if count > MAX_ENTRIES:
                    return
                name = e.name
                if name in (".DS_Store", ".localized", "Icon\r"):
                    continue
                try:
                    if e.is_symlink():
                        continue
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode):
                    ext = os.path.splitext(name)[1]
                    kind = BUNDLE_EXT.get(ext) or BUNDLE_EXT.get(ext.lower())
                    if kind == "skip" or name in SKIP_DIRS:
                        continue
                    if kind:
                        yield e.path, st, True
                    elif lvl + 1 < depth:
                        stack.append((e.path, lvl + 1))
                elif stat.S_ISREG(st.st_mode):
                    yield e.path, st, False


def signature_of(path, st, is_bundle, exe=None):
    """What must stay the same for a file or bundle to count as unchanged."""
    sig = [st.st_size if not is_bundle else 0, st.st_mtime_ns, st.st_ino]
    if is_bundle:
        for rel in ("Contents", "Contents/Info.plist", "Contents/MacOS", "Contents/_CodeSignature/CodeResources"):
            s = U.lstat(os.path.join(path, rel))
            sig += [s.st_size, s.st_mtime_ns] if s else [0, 0]
        if exe:
            s = U.lstat(exe)
            sig += [s.st_size, s.st_mtime_ns] if s else [0, 0]
    return sig


# ---------------------------------------------------------------- where a file came from

def origin(cfg, path):
    """({flags, agent, approved} | None | "unknown", [scheme://host])."""
    rc, out, _ = cfg.run(["/usr/bin/xattr", "-p", "com.apple.quarantine", path], timeout=8)
    q = None
    if rc in (124, 127):
        q = "unknown"
    elif rc == 0 and out.strip():
        parts = out.strip().split(";")
        try:
            flags = int(parts[0], 16)
        except ValueError:
            flags = 0
        q = {"flags": parts[0][:8], "agent": U.clean(parts[2], 60) if len(parts) > 2 and parts[2] else None,
             "approved": bool(flags & 0x40)}
    hosts = []
    rc, out, _ = cfg.run(["/usr/bin/mdls", "-raw", "-name", "kMDItemWhereFroms", path], timeout=8)
    if rc == 0 and out:
        for m in re.finditer(r"\"((?:https?|ftp)://[^\"\s]*)\"", out):
            h = U.url_host(m.group(1))
            if h and h not in hosts:
                hosts.append(h)
    return q, hosts[:4]


def origin_evidence(q, hosts):
    ev = []
    if isinstance(q, dict):
        ev.append(("quarantine mark", "present, set by %s%s" % (q.get("agent") or "an app", "; already opened and approved once" if q.get("approved") else ""),
                   "xattr com.apple.quarantine"))
    elif q == "unknown":
        ev.append(("quarantine mark", "could not be read", "xattr"))
    else:
        ev.append(("quarantine mark", "none", "xattr com.apple.quarantine"))
    if hosts:
        ev.append(("downloaded from", ", ".join(hosts), "mdls kMDItemWhereFroms (host only)"))
    return ev


# ---------------------------------------------------------------- analysis

class Draft:
    def __init__(self, path, kind, where):
        self.path, self.kind, self.where = path, kind, where
        self.name = os.path.basename(path.rstrip("/"))
        self.reasons, self.evidence = [], []
        self.sha256 = None
        self.team = None
        self.exe = None
        self.vouched = False
        self.unchecked = []

    def add(self, code, text, severity, pct, measured=False):
        self.reasons.append(U.Reason(code, text, severity, pct, measured))


def name_reasons(d):
    if DOUBLE_EXT.search(d.name) or SPACED_EXT.search(d.name) or "‮" in d.name:
        d.add("double-extension", "Its name is made to look like a document, but it is a program: the real ending is “%s”." % os.path.splitext(d.name)[1],
              "high", 85)


def internet_text(q, hosts):
    if hosts:
        return "it was downloaded from %s" % hosts[0].split("://", 1)[-1]
    if isinstance(q, dict):
        return "it was downloaded (by %s)" % (q.get("agent") or "an app")
    return None


def unsigned_reasons(d, cs, q, hosts, thing):
    """An unsigned or ad-hoc signed program: how bad depends on where it came from and where it sits."""
    state = "is not signed at all" if not cs.get("signed") else "is only ad-hoc signed, which names no developer"
    came = internet_text(q, hosts)
    if came:
        d.add("unsigned-internet", "This %s %s, and %s. Nobody vouches for what it does, and Apple has not checked it for malware." % (thing, state, came),
              "high", 70 if isinstance(q, dict) and not q.get("approved") else 60)
        if hosts and q is None:
            d.add("quarantine-stripped", "It came from the internet but no longer carries the quarantine mark macOS puts on downloads: "
                  "someone or something removed it, so macOS will not check it when it opens.", "high", 55)
    elif d.where == "apps":
        d.add("unsigned", "This %s %s. That is normal for something built on this Mac and unusual for anything else." % (thing, state), "low", 35)
    else:
        d.add("unsigned", "This %s %s and nothing records where it came from." % (thing, state), "medium", 45)


def analyze_app(ctx, d, prev):
    cfg = ctx.cfg
    info, exe = U.app_executable(d.path)
    d.exe = exe
    name_reasons(d)
    cs = ctx.sigs.info(d.path)
    q, hosts = origin(cfg, d.path)
    d.evidence.append(("signature", U.signer_text(cs), "codesign -dv"))
    d.team = cs.get("teamId")
    if cs.get("teamId"):
        d.evidence.append(("team id", cs["teamId"], "codesign -dv"))
    d.evidence += origin_evidence(q, hosts)
    exe_ok = False
    if exe:
        real = os.path.realpath(exe)
        exe_ok = U.within(real, os.path.realpath(d.path))
        if not exe_ok:
            tcs = ctx.sigs.info(real) if os.path.isfile(real) else {"signed": None}
            if tcs.get("signed") and not tcs.get("adhoc") and ctx.sigs.verify(real, timeout=60)[0] is True:
                # A launcher: the bundle only points at a program that is itself properly signed.
                d.evidence.append(("starts", "%s, signed by %s" % (cfg.show(real), U.signer_text(tcs)), "link in Contents/MacOS"))
                d.launcher = True
            else:
                d.add("exe-outside", "The program this app starts is a link that points outside the app, to something that is not properly signed.", "high", 70)
    script_exe = False
    if exe and exe_ok:
        head = U.read_head(os.path.realpath(exe), 4096)
        script_exe = U.is_script(head)
    if cs.get("signed") is None:
        d.unchecked.append("signature of %s: %s" % (d.name, cs.get("error") or "codesign could not read it"))
    elif (not cs["signed"] or cs.get("adhoc")) and info and not internet_text(q, hosts) and re.match(
            r"^com\.(google\.Chrome|brave\.Browser|microsoft\.edgemac|thebrowser\.Browser)\.app\.", str(info.get("CFBundleIdentifier") or "")):
        d.vouched = True        # a web-app shortcut a browser made on this Mac: ad-hoc signed by design
    elif not cs["signed"] or cs.get("adhoc"):
        unsigned_reasons(d, cs, q, hosts, "app")
    else:
        valid, vtext = ctx.sigs.verify(d.path)
        d.evidence.append(("seal", vtext if valid is not None else "not verified: " + (vtext or "timed out"), "codesign --verify --deep --strict"))
        if valid is None:
            d.unchecked.append("seal of %s: %s" % (d.name, vtext or "timed out"))
        if valid == "resources":
            valid = True
        if getattr(d, "launcher", False):
            d.vouched = True
        elif valid is False:
            d.add("tampered", "It carries a signature (%s), but the files no longer match it: the app was changed after it was signed." % U.signer_text(cs),
                  "high", 80)
        elif cs.get("apple") and valid:
            d.vouched = True
        else:
            a = ctx.sigs.assess(d.path, "execute")
            d.evidence.append(("Gatekeeper", ("accepted" if a["accepted"] else "rejected" if a["accepted"] is False else "no verdict") +
                               (": " + a["source"] if a.get("source") else "") + ((" (%s)" % a["text"]) if a.get("text") else ""),
                               "spctl --assess --type execute"))
            if a["accepted"] is None:
                d.unchecked.append("Gatekeeper verdict for %s: %s" % (d.name, a.get("text") or "spctl gave none"))
            elif a["accepted"]:
                d.vouched = valid is True
            elif a.get("revoked"):
                d.add("revoked", "Apple revoked the certificate this app is signed with. That is what Apple does when a developer is caught shipping malware.",
                      "critical", 90)
            elif (a.get("source") or "").startswith("Unnotarized") or cs.get("developerId"):
                came = internet_text(q, hosts)
                if came and d.where != "apps":
                    d.add("unnotarized", "It is signed by %s but Apple has not notarized (malware-checked) it, and %s. Gatekeeper refuses it." % (
                        U.signer_text(cs), came), "medium", 50)
                elif d.where != "apps":
                    d.add("unnotarized", "It is signed by %s but Apple has not notarized (malware-checked) it." % U.signer_text(cs), "low", 45)
            else:
                d.add("gatekeeper-rejects", "Gatekeeper refuses it%s." % ((": " + a["text"]) if a.get("text") else ""),
                      "medium" if internet_text(q, hosts) else "low", 50)
    if script_exe and not d.vouched:
        d.add("script-executable", "What looks like an app is a shell script wearing an app's icon and name: opening it runs the script. "
              "Password stealers are shipped this way because a script needs no developer signature.", "high", 65)
        text = U.read_text(os.path.realpath(exe)) if exe_ok else None
        d.reasons += H.script_reasons(text, "script inside the app")
    if prev and prev.get("team") and d.team and prev["team"] != d.team:
        d.add("signer-changed", "This app used to be signed by team %s and is now signed by team %s." % (prev["team"], d.team), "high", 60)
    if info:
        ident = info.get("CFBundleIdentifier")
        if isinstance(ident, str):
            d.evidence.append(("bundle id", ident, "Info.plist"))


def analyze_macho(ctx, d):
    cs = ctx.sigs.info(d.path)
    q, hosts = origin(ctx.cfg, d.path)
    d.evidence.append(("signature", U.signer_text(cs), "codesign -dv"))
    d.evidence += origin_evidence(q, hosts)
    d.team = cs.get("teamId")
    name_reasons(d)
    if cs.get("signed") is None:
        d.unchecked.append("signature of %s: %s" % (d.name, cs.get("error") or "codesign could not read it"))
    elif not cs["signed"] or cs.get("adhoc"):
        unsigned_reasons(d, cs, q, hosts, "program")
    else:
        valid, vtext = ctx.sigs.verify(d.path, timeout=60)
        if valid is False:
            d.add("tampered", "It carries a signature (%s), but the file no longer matches it." % U.signer_text(cs), "high", 80)
        elif valid:
            d.vouched = True


def analyze_script(ctx, d, st, text=None):
    q, hosts = origin(ctx.cfg, d.path)
    name_reasons(d)
    if st.st_size <= U.CONTENT_MAX:
        text = text if text is not None else U.read_text(d.path)
        found = H.script_reasons(text, "script")
        d.reasons += found
    else:
        found = []
        d.unchecked.append("content of %s: larger than 50 MB, not read" % d.name)
    ext = os.path.splitext(d.name)[1].lower()
    if (found or ext in (".command", ".tool")) and (isinstance(q, dict) or hosts):
        d.evidence += origin_evidence(q, hosts)
    if not found and ext in (".command", ".tool") and internet_text(q, hosts):
        d.add("runs-on-open", "A double-click runs this script in Terminal, and %s." % internet_text(q, hosts), "low", 50)


def analyze_pkg(ctx, d):
    cfg = ctx.cfg
    q, hosts = origin(cfg, d.path)
    name_reasons(d)
    rc, out, err = cfg.run(["/usr/sbin/pkgutil", "--check-signature", d.path], timeout=60)
    text = (out or "") + (err or "")
    status = re.search(r"Status:\s*(.+)", text)
    d.evidence.append(("package signature", U.clean(status.group(1), 120) if status else "no answer", "pkgutil --check-signature"))
    d.evidence += origin_evidence(q, hosts)
    if rc in (124, 127) or not status:
        d.unchecked.append("signature of %s: pkgutil gave no answer" % d.name)
        return
    s = status.group(1).lower()
    notarized = "trusted by the apple notary service" in text.lower()
    if "no signature" in s:
        came = internet_text(q, hosts)
        d.add("unsigned-pkg", "This installer is not signed%s. An installer runs its scripts as administrator, so an unsigned one can do anything to this Mac." % (
            (", and " + came) if came else ""), "high" if came else "medium", 65 if came else 45)
    elif "revoked" in s:
        d.add("revoked", "The certificate this installer is signed with has been revoked.", "critical", 90)
    elif "expired" in s or "untrusted" in s or "invalid" in s:
        d.add("gatekeeper-rejects", "The installer's signature is not valid: %s." % U.clean(status.group(1), 100), "medium", 55)
    elif "apple software" in s or notarized:
        d.vouched = True
    elif internet_text(q, hosts):
        d.add("unnotarized", "The installer is signed but Apple has not notarized (malware-checked) it.", "low", 45)


def analyze_profile(ctx, d):
    raw = U.read_head(d.path, 512 * 1024) or b""
    types = []
    m = re.search(rb"<\?xml.*?</plist>", raw, re.S)
    try:
        doc = plistlib.loads(m.group(0) if m else raw)
    except Exception:
        doc = None
    if isinstance(doc, dict):
        for p in doc.get("PayloadContent") or []:
            if isinstance(p, dict) and isinstance(p.get("PayloadType"), str):
                types.append(p["PayloadType"])
    risky = sorted({PROFILE_RISK[t] for t in types if t in PROFILE_RISK})
    d.add("profile", "A configuration profile changes how the whole Mac works once installed%s. Install one only when you know exactly who made it and why." % (
        (": this one " + "; ".join(risky)) if risky else " (it can add root certificates, proxies, VPNs and remote management)"), "high", 90 if risky else 75)
    if types:
        d.evidence.append(("payload types", ", ".join(sorted(set(types))[:12]), "the profile's PayloadType names (values not read)"))
    q, hosts = origin(ctx.cfg, d.path)
    d.evidence += origin_evidence(q, hosts)


def analyze_terminal(ctx, d):
    doc = U.load_plist(d.path)
    cmd = doc.get("CommandString") if isinstance(doc, dict) else None
    q, hosts = origin(ctx.cfg, d.path)
    if isinstance(cmd, str) and cmd.strip():
        d.evidence.append(("runs", U.redact(cmd, 200), "CommandString"))
        found = H.script_reasons(cmd, "command it runs")
        d.reasons += found
        if not found and internet_text(q, hosts):
            d.add("runs-on-open", "Opening this Terminal settings file runs a command, and %s." % internet_text(q, hosts), "medium", 55)
    d.evidence += origin_evidence(q, hosts)


def analyze_archive(ctx, d, st):
    if st.st_size > 2 * 1024 * 1024 * 1024:
        return
    try:
        with zipfile.ZipFile(d.path) as z:
            names = [n for n in z.namelist()[:5000]]
    except Exception:
        return
    bad = [n for n in names if DOUBLE_EXT.search(n.rstrip("/")) or "‮" in n]
    if bad:
        d.add("archive-disguise", "Inside this archive is a program named to look like a document (%d such name%s)." % (len(bad), "" if len(bad) == 1 else "s"),
              "medium", 60)
        d.evidence.append(("disguised name", U.clean(os.path.basename(bad[0].rstrip("/")), 120), "zip file list"))
        q, hosts = origin(ctx.cfg, d.path)
        d.evidence += origin_evidence(q, hosts)


def analyze_other_runnable(ctx, d, what):
    """A jar, a workflow, a compiled script, a browser extension archive: it runs code when opened."""
    q, hosts = origin(ctx.cfg, d.path)
    name_reasons(d)
    came = internet_text(q, hosts)
    if came:
        d.add("runs-on-open", "This %s runs code when it is opened or installed, and %s. Nothing vouches for it." % (what, came), "medium", 45)
        d.evidence += origin_evidence(q, hosts)


def volume_reasons(ctx, root, drafts):
    """A mounted disk image whose contents tell the person to get around Gatekeeper."""
    words = False
    try:
        names = os.listdir(root)
    except OSError:
        return
    look = list(names)
    for sub in (".background", ".bg"):
        try:
            look += os.listdir(os.path.join(root, sub))
        except OSError:
            pass
    for n in look:
        if BYPASS_WORDS.search(n.replace("_", " ")):
            words = True
    for n in names:
        if n.lower().endswith((".txt", ".rtf", ".md", ".html")):
            p = os.path.join(root, n)
            s = U.lstat(p)
            if s and stat.S_ISREG(s.st_mode) and s.st_size <= 64 * 1024:
                t = U.read_text(p, 64 * 1024)
                if t and BYPASS_WORDS.search(t):
                    words = True
    if not words:
        return
    for d in drafts:
        if not d.vouched and d.kind in ("app", "macho", "script", "pkg"):
            d.add("bypass-instructions", "The disk image it sits on tells you to right-click and choose Open, or to open it anyway. "
                  "That instruction exists to get an unsigned program past macOS's warning; genuine software does not need it.", "high", 75)


def classify(path, st, is_bundle):
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1]
    if is_bundle:
        return BUNDLE_EXT.get(ext) or BUNDLE_EXT.get(ext.lower()) or "bundle", None
    kind = FILE_EXT.get(ext.lower())
    head = None
    if kind in (None, "other") or kind == "script":
        head = U.read_head(path, 4096)
        if head is None:
            return "unreadable", None
        if U.is_macho(head):
            kind = "macho"
        elif kind is None and U.is_script(head):
            kind = "script"
    return kind or "other", head


def build(ctx, d, baseline):
    """Turn a draft with reasons into a finding (or None)."""
    if not d.reasons:
        return None
    cfg = ctx.cfg
    sev, _, _ = U.judge(d.reasons)
    lead = sorted(d.reasons, key=lambda r: (U.SEV_RANK[r.severity], r.measured, r.pct), reverse=True)[0]
    place = {"downloads": "in %s" % cfg.show(os.path.dirname(d.path)), "apps": "in Applications",
             "volume": "on a mounted disk image"}.get(d.where, "")
    title = "%s: %s" % (TITLES.get(lead.code, "Suspicious file"), d.name)
    detail = "%s %s. %s" % ({"app": "An app", "macho": "A program", "script": "A script", "pkg": "An installer package", "profile": "A configuration profile",
                             "terminal": "A Terminal settings file", "archive": "An archive", "dmg": "A disk image"}.get(d.kind, "A file"),
                            place, lead.text)
    malware = any(r.code in ("malware", "yara", "test-file") for r in d.reasons)
    if malware:
        fix = "Do not open it. Quarantine it here, then delete it from the quarantine folder yourself once you are sure. If you already opened it, change the passwords you used on this Mac."
    elif lead.code == "profile":
        fix = "Do not install it unless you know who made it and why. If you do not need it, move it to the Trash."
    elif sev in ("high", "critical"):
        fix = "Do not open it unless you are sure where it came from. Quarantine it here if you are not; if it is yours, mark it trusted."
    else:
        fix = "If you know it and want to keep it, mark it trusted. Otherwise move it to the Trash."
    if d.sha256:
        d.evidence.insert(0, ("sha256", d.sha256, "computed"))
    return U.make_finding(
        d.path, "malware" if malware else "download", title, detail,
        {"type": "app" if d.kind == "app" else "file", "name": d.name, "path": d.path, "sha256": d.sha256},
        d.reasons, evidence=d.evidence, fix={"text": fix}, fp=U.digest(d.path, d.sha256 or "", *[r.code for r in d.reasons]),
        baseline=baseline, quarantinable=True)


def analyze(ctx, path, st, is_bundle, where, prev):
    kind, head = classify(path, st, is_bundle)
    d = Draft(path, kind, where)
    if kind == "unreadable":
        d.unchecked.append("%s: the file could not be read" % d.name)
    if kind in ("other", "unreadable", "skip", "shortcut", "dmg"):
        if kind == "other" and st.st_size <= 1024 and head is not None and head.lstrip()[:len(EICAR)] == EICAR:
            d.add("test-file", "This is the EICAR antivirus test file: a harmless text every antivirus is built to flag. "
                  "It proves the scanner sees new files; it is not malware.", "critical", 100, measured=True)
            d.evidence.append(("known file", "EICAR standard antivirus test file", "built-in signature"))
            d.sha256 = U.sha256_file(path)
        if kind == "dmg":
            name_reasons(d)
        return d
    if kind == "app":
        analyze_app(ctx, d, prev)
    elif kind == "macho":
        analyze_macho(ctx, d)
    elif kind == "script":
        analyze_script(ctx, d, st, head.decode("utf-8", "replace") if head is not None and st.st_size <= len(head) else None)
    elif kind == "pkg":
        analyze_pkg(ctx, d)
    elif kind == "profile":
        analyze_profile(ctx, d)
    elif kind == "terminal":
        analyze_terminal(ctx, d)
    elif kind == "archive":
        analyze_archive(ctx, d, st)
    elif kind in ("jar", "workflow", "applescript", "extension"):
        analyze_other_runnable(ctx, d, {"jar": "Java archive", "workflow": "Automator workflow", "applescript": "compiled script",
                                        "extension": "browser extension package"}[kind])
    else:
        name_reasons(d)
    if not is_bundle and (d.reasons or kind in ("macho", "pkg", "script", "profile", "terminal", "jar", "applescript", "extension")):
        d.sha256 = U.sha256_file(path)
    return d


def scan(ctx):
    res = U.Result()
    cfg, b = ctx.cfg, ctx.baseline
    index = ctx.cache.get("items") or {}
    new_index = {}
    engines = ctx.engines
    clam_on = bool((engines.get("clamav") or {}).get("installed"))
    yara_on = bool((engines.get("yara") or {}).get("installed") and (engines.get("yara") or {}).get("rules"))
    clam_stamp = (engines.get("clamav") or {}).get("signaturesAt") if clam_on else None
    # With newer signatures, files that passed before are looked at again (not the apps Gatekeeper vouches for).
    rescan_all = bool(clam_on and clam_stamp and ctx.cache.get("clamStamp") not in (None, clam_stamp)
                      and time.time() - (ctx.cache.get("clamFullAt") or 0) > 7 * 86400)
    deadline = time.time() + BUDGET_SEC
    todo, drafts_by_root, unchecked = [], {}, []
    live = []
    for root, depth, where in roots(ctx):
        if not os.path.isdir(root):
            continue
        first = b.begin("root:" + ("volume" if where == "volume" else root))
        for path, st, is_bundle in walk(root, depth):
            res.items += 1
            prev = index.get(path)
            sig = signature_of(path, st, is_bundle, (prev or {}).get("exe"))
            live.append(path)
            if prev and prev.get("sig") == sig and not (prev.get("recheckAt") and time.time() > prev["recheckAt"]):
                new_index[path] = prev
                unchecked += prev.get("unchecked") or []
                if prev.get("finding"):
                    res.add(dict(prev["finding"]))
                if rescan_all and where != "apps" and not is_bundle and st.st_size <= E.CLAM_MAX_FILE:
                    todo.append((path, st, is_bundle, where, root, first, prev, True))
                continue
            todo.append((path, st, is_bundle, where, root, first, prev, False))
    res.seen.update(live)
    scan_paths, analysed = [], []
    total = len([t for t in todo if not t[7]])
    done = 0
    for path, st, is_bundle, where, root, first, prev, only_clam in todo:
        if only_clam:
            scan_paths.append(path)
            continue
        if time.time() > deadline:
            res.partial = True
            res.keep.append(path)
            continue
        done += 1
        ctx.progress("checking %d of %d: %s" % (done, total, U.clean(os.path.basename(path), 60)))
        d = analyze(ctx, path, st, is_bundle, where, prev)
        d.first = first
        analysed.append((d, st, is_bundle, root))
        drafts_by_root.setdefault((root, where), []).append(d)
        unchecked += d.unchecked
        if clam_on and d.kind not in ("unreadable", "skip") and not d.vouched and (is_bundle or st.st_size <= E.CLAM_MAX_FILE):
            scan_paths.append(path)
    for (root, where), drafts in drafts_by_root.items():
        if where == "volume":
            volume_reasons(ctx, root, drafts)
    by_path = {d.path: d for d, _, _, _ in analysed}
    clam_error = None
    if clam_on and scan_paths:
        ctx.progress("ClamAV is reading %d file%s" % (len(scan_paths), "" if len(scan_paths) == 1 else "s"), force=True)
        hits, clam_error = E.clam_scan(cfg, engines, scan_paths)
        for hit_path, signame in hits.items():
            owner = hit_path if hit_path in by_path or hit_path in new_index else next(
                (p for p in scan_paths if hit_path.startswith(p.rstrip("/") + "/")), None)
            if owner is None:
                continue
            d = by_path.get(owner)
            if d is None:       # a file that passed before and is named by newer signatures
                st = U.lstat(owner)
                if st is None:
                    continue
                d = Draft(owner, (new_index.get(owner) or {}).get("kind") or "other", "downloads")
                d.first, d.sha256 = False, U.sha256_file(owner)
                by_path[owner] = d
                analysed.append((d, st, False, None))
            d.add("malware", "ClamAV, an antivirus engine, names this file as %s." % signame, "critical", 100, measured=True)
            d.evidence.append(("ClamAV", signame + ((" (inside " + cfg.show(hit_path) + ")") if hit_path != owner else ""), "clamscan"))
            if d.sha256 is None and not os.path.isdir(owner):
                d.sha256 = U.sha256_file(owner)
        if clam_error:
            unchecked.append("ClamAV: %s" % clam_error)
        elif rescan_all:
            ctx.cache["clamFullAt"] = time.time()
    if yara_on:
        targets = [d.path for d, _, ib, _ in analysed if not ib and not d.vouched and d.kind != "unreadable"]
        yhits, yerr = E.yara_scan(cfg, engines, targets[:200])
        for p, rules in yhits.items():
            d = by_path[p]
            d.add("yara", "A YARA malware rule matches this file: %s." % ", ".join(sorted(set(rules))[:5]), "high", 100, measured=True)
            d.evidence.append(("YARA", ", ".join(sorted(set(rules))[:5]), "yara"))
            if d.sha256 is None:
                d.sha256 = U.sha256_file(p)
        if yerr and not yhits:
            unchecked.append("YARA: %s" % yerr)
    for d, st, is_bundle, root in analysed:
        f = build(ctx, d, getattr(d, "first", False))
        exe = d.exe
        entry = {"sig": signature_of(d.path, st, is_bundle, exe), "kind": d.kind, "finding": f}
        if exe:
            entry["exe"] = exe
        if d.team:
            entry["team"] = d.team
        if d.sha256:
            entry["sha256"] = d.sha256
        if not (clam_error and not d.vouched):
            entry["clam"] = clam_stamp
        if d.unchecked:
            # Something about it could not be checked: it stays listed as not checked, and is tried again in six hours.
            entry["unchecked"] = d.unchecked[:4]
            entry["recheckAt"] = time.time() + 6 * 3600
        new_index[d.path] = entry
        res.findings = [x for x in res.findings if x["key"] != d.path]
        if f:
            res.add(f)
    ctx.cache["items"] = new_index
    ctx.cache["clamStamp"] = clam_stamp if clam_on else ctx.cache.get("clamStamp")
    if clam_on and "clamFullAt" not in ctx.cache:
        ctx.cache["clamFullAt"] = time.time()
    if not clam_on:
        res.unchecked("known malware (antivirus signatures)", "ClamAV is not installed, so no file was compared with known malware. "
                      "Only signatures, Gatekeeper and the heuristics were used. Install it with: brew install clamav && freshclam")
    elif (engines.get("clamav") or {}).get("stale"):
        res.unchecked("recent malware (antivirus signatures)", "ClamAV's signatures are older than a week (%s). Run: freshclam" % (clam_stamp or "")[:10])
    if not yara_on:
        res.unchecked("YARA rules", "YARA is not installed or has no rule files (data/yara/*.yar), so no rule was applied.")
    res.unchecked("inside disk images and archives", "A .dmg is only looked into once you mount it, and a .zip is only listed, never unpacked"
                  + (" (ClamAV does read inside them)." if clam_on else "."))
    unchecked = list(collections.OrderedDict.fromkeys(unchecked))
    for u in unchecked[:12]:
        res.unchecked(u.split(":", 1)[0], u.split(":", 1)[1].strip() if ":" in u else "could not be checked")
    if res.partial:
        res.unchecked("some new files", "the run stopped after %d minutes; the rest are checked on the next run" % (BUDGET_SEC // 60))
    res.detail = "%d files and apps watched, %d checked this run%s" % (res.items, done, ", ClamAV read %d" % len(scan_paths) if clam_on and scan_paths else "")
    return res
