"""What every scanner shares: the config (injectable roots), a subprocess runner that never uses a
shell, redaction, hashing that never follows a link, code-signature reading and the finding builder.

Rules kept here so no scanner can forget them:
- a path found on disk is data: it is only ever one argv item, never part of a shell string;
- nothing is executed or imported from a scanned location;
- a command line shown to the person goes through redact() first.
"""
import hashlib
import os
import plistlib
import re
import socket
import stat
import subprocess
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
import collectors as C  # noqa: E402

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
HASH_MAX = 1024 * 1024 * 1024       # no sha256 above 1 GB: recorded as not hashed
CONTENT_MAX = 50 * 1024 * 1024      # no content heuristics above 50 MB
TEXT_READ = 1024 * 1024             # a script is read up to 1 MB
PLIST_MAX = 2 * 1024 * 1024


def run(argv, timeout=10, env=None, nice=False, input=None):
    """(returncode, stdout, stderr). Never raises, never uses a shell. `nice` lowers the priority of heavy tools."""
    argv = [str(a) for a in argv]
    if nice:
        argv = ["/usr/bin/nice", "-n", "15"] + argv
    e = None
    if env:
        e = dict(os.environ)
        e.update(env)
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL if input is None else None, input=input,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=e)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except Exception as ex:  # missing binary, permission
        return 127, "", "%s: %s" % (type(ex).__name__, ex)


class Config:
    """Where Sentinel looks. Tests pass a temp `home`, a temp `sysroot` and a fake `run`.

    HM_SENTINEL_HOME points the home-relative scanners at another directory (then system paths resolve
    under HM_SENTINEL_SYSROOT, by default a directory that does not exist, so the real machine is not read).
    HM_SENTINEL_ROOTS adds folders (os.pathsep-separated) to what `downloads` watches."""

    def __init__(self, home=None, sysroot=None, run=None, repo=None, notify=None, extra_roots=None, monitor=None,
                 tcp_open=None, lan_ip=None, volume_roots=None):
        env_home = os.environ.get("HM_SENTINEL_HOME")
        self.isolated = bool(home or env_home)
        self.home = os.path.realpath(home or env_home or os.path.expanduser("~"))
        self.sysroot = sysroot or os.environ.get("HM_SENTINEL_SYSROOT") or (
            os.path.join(self.home, ".sentinel-sysroot") if self.isolated else "/")
        self._run = run or globals()["run"]
        self.repo = os.path.realpath(repo or ROOT)
        if notify is None:
            notify = not self.isolated and os.environ.get("HM_SENTINEL_NOTIFY") != "0"
        self.notify = notify
        if extra_roots is None:
            extra_roots = [p for p in (os.environ.get("HM_SENTINEL_ROOTS") or "").split(os.pathsep) if p]
        self.extra_roots = [os.path.realpath(p) for p in extra_roots]
        self.monitor = monitor
        self.volume_roots = volume_roots      # None: ask hdiutil which disk images are mounted
        self.uid = os.getuid()
        # Probes of this Mac's own ports. Pointed at another home, nothing is probed unless a test passes fakes.
        self.tcp_open = tcp_open or ((lambda ip, port, timeout=0.6: False) if self.isolated else globals()["tcp_open"])
        self.lan_ip = lan_ip or ((lambda: None) if self.isolated else globals()["lan_ip"])

    def run(self, argv, timeout=10, **kw):
        return self._run(argv, timeout=timeout, **kw)

    def h(self, *parts):
        return os.path.join(self.home, *parts)

    def s(self, path):
        """A system path, under the sysroot."""
        if self.sysroot == "/":
            return path
        return os.path.join(self.sysroot, path.lstrip("/"))

    def show(self, path):
        """A path for people: the home folder shown as ~."""
        if not path:
            return path
        if path == self.home or path.startswith(self.home + os.sep):
            return "~" + path[len(self.home):]
        if self.sysroot != "/" and path.startswith(self.sysroot + os.sep):
            return path[len(self.sysroot):]
        return path


# ---------------------------------------------------------------- text safety

_SECRET_WORD = r"(?:pass(?:word|wd)?|secret|token|api[-_]?key|apikey|access[-_]?key|private[-_]?key|auth|credential|bearer|session|cookie|signature|sig|jwt|key)"
_REDACTIONS = [
    # KEY=value and --key value / --key=value, where the name smells like a secret
    (re.compile(r"(?i)\b([A-Za-z0-9_.-]*%s[A-Za-z0-9_.-]*)(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s&\"']+)" % _SECRET_WORD), r"\1\2[redacted]"),
    (re.compile(r"(?i)(--?[A-Za-z0-9-]*%s[A-Za-z0-9-]*)(\s+)(\"[^\"]*\"|'[^']*'|[^\s-][^\s]*)" % _SECRET_WORD), r"\1\2[redacted]"),
    (re.compile(r"(?i)\b(authorization\s*:\s*)(basic|bearer)?\s*[^\s\"']+"), r"\1[redacted]"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [redacted]"),
    (re.compile(r"(://)[^/\s:@]+:[^/\s@]+@"), r"\1[redacted]@"),           # user:password@host
    (re.compile(r"(\?)[^\s\"']+"), r"\1[redacted]"),                        # a URL's query string
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?"), "[redacted]"),   # JWT
    (re.compile(r"\b(?:sk|pk|rk|ghp|gho|ghs|ghu|github_pat|xox[abprs]|AKIA|ASIA|AIza|glpat|npm)[-_][A-Za-z0-9_-]{12,}|\bAKIA[A-Z0-9]{12,}"), "[redacted]"),
    # a long run of letters and digits that is not a path component or a file name
    (re.compile(r"(?<![A-Za-z0-9/+_.-])(?=[A-Za-z0-9+_-]*[0-9])(?=[A-Za-z0-9+_-]*[A-Za-z])[A-Za-z0-9+_-]{32,}={0,2}(?![A-Za-z0-9/+_.-])"), "[redacted]"),
]
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]")


def clean(text, n=300):
    """One line of display text: control and direction-override characters out, capped."""
    if text is None:
        return None
    t = _CTRL.sub(" ", str(text)).replace("\n", " ").strip()
    return t if len(t) <= n else t[:n - 1] + "…"


def redact(text, n=300):
    """A command line or setting value that is safe to show: anything that looks like a secret is replaced."""
    if text is None:
        return None
    t = str(text)
    for rx, rep in _REDACTIONS:
        t = rx.sub(rep, t)
    return clean(t, n)


def url_host(url):
    """scheme://host of a URL: the path and the query can carry signed tokens, so they are never shown."""
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://(?:[^/@\s]*@)?(\[[0-9a-fA-F:]+\]|[^/:?#\s]+)(?::(\d+))?", url or "")
    if not m:
        return None
    return "%s://%s%s" % (m.group(1).lower(), m.group(2).lower(), (":" + m.group(3)) if m.group(3) else "")


def digest(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(("" if p is None else str(p)).encode("utf-8", "surrogatepass"))
        h.update(b"\x00")
    return h.hexdigest()


# ---------------------------------------------------------------- files

def lstat(path):
    try:
        return os.lstat(path)
    except OSError:
        return None


def mode_text(st):
    return "%04o" % stat.S_IMODE(st.st_mode)


def within(path, root):
    """True when `path` is `root` or inside it. Both should already be real paths."""
    root = root.rstrip(os.sep) or os.sep
    return path == root or path.startswith(root + os.sep if root != os.sep else os.sep)


def open_nofollow(path):
    """A read-only file object, refusing a symbolic link in the last component and anything that is not a regular file."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        return os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise


def read_head(path, n=4096):
    try:
        with open_nofollow(path) as f:
            return f.read(n)
    except OSError:
        return None


def sha256_file(path, limit=HASH_MAX):
    """Hex digest, or None when the file is a link, unreadable or larger than `limit`."""
    try:
        with open_nofollow(path) as f:
            if os.fstat(f.fileno()).st_size > limit:
                return None
            h = hashlib.sha256()
            while True:
                b = f.read(1024 * 1024)
                if not b:
                    break
                h.update(b)
            return h.hexdigest()
    except OSError:
        return None


def read_text(path, limit=TEXT_READ):
    b = read_head(path, limit)
    return None if b is None else b.decode("utf-8", "replace")


def load_plist(path, limit=PLIST_MAX):
    """A parsed property list (XML or binary), or None. Never raises."""
    try:
        with open_nofollow(path) as f:
            if os.fstat(f.fileno()).st_size > limit:
                return None
            return plistlib.loads(f.read())
    except Exception:
        return None


MACHO_MAGIC = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")


def is_macho(head):
    if not head or len(head) < 8:
        return False
    if head[:4] in MACHO_MAGIC:
        return True
    # A fat binary shares its magic with Java class files: a fat header counts a handful of architectures.
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        return int.from_bytes(head[4:8], "big") < 20
    return False


def is_script(head):
    return bool(head) and head[:2] == b"#!"


def app_executable(app):
    """(Info.plist dict or None, path of the main executable or None) of an app bundle."""
    info = load_plist(os.path.join(app, "Contents", "Info.plist"), 1024 * 1024)
    exe = None
    if isinstance(info, dict):
        name = info.get("CFBundleExecutable")
        if isinstance(name, str) and name and "/" not in name and name not in (".", ".."):
            exe = os.path.join(app, "Contents", "MacOS", name)
    else:
        info = None
    if exe is None:
        guess = os.path.join(app, "Contents", "MacOS", os.path.splitext(os.path.basename(app.rstrip("/")))[0])
        if os.path.lexists(guess):
            exe = guess
    return info, exe


# ---------------------------------------------------------------- network facts about this Mac

def lan_ip():
    """This Mac's primary address (no packet is sent), or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        ip = s.getsockname()[0]
        return None if ip.startswith("127.") or ip == "0.0.0.0" else ip
    except OSError:
        return None
    finally:
        s.close()


def tcp_open(ip, port, timeout=0.6):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def is_loopback(addr):
    a = (addr or "").strip("[]")
    return a.startswith("127.") or a in ("::1", "localhost")


# ---------------------------------------------------------------- code signatures

class Signatures:
    """Reads code signatures, caching by (path, mtime, size). `codesign` and `spctl` only read."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.cache = {}

    def _key(self, path):
        st = lstat(path)
        return None if st is None else (path, st.st_mtime_ns, st.st_size)

    def info(self, path):
        """{signed, adhoc, teamId, authority: [..], identifier, apple, appStore, developerId, error}.
        `signed` is None when codesign could not be run (never assume unsigned)."""
        key = self._key(path)
        if key is None:
            return {"signed": None, "error": "cannot read the file"}
        with self.lock:
            if key in self.cache:
                return self.cache[key]
        rc, _, err = self.cfg.run(["/usr/bin/codesign", "-dv", "--verbose=2", path], timeout=30)
        res = parse_codesign(rc, err)
        with self.lock:
            if len(self.cache) > 4000:
                self.cache.clear()
            self.cache[key] = res
        return res

    def verify(self, path, timeout=180):
        """(True | False | "resources" | None, text): does the seal still match what is on disk.

        None: could not be checked. "resources": the code is intact but files that are not programs were added
        inside the bundle after signing (caches an app writes into itself), which is not tampering."""
        rc, out, err = self.cfg.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=4", path], timeout=timeout, nice=True)
        err = (err or "") + "\n" + (out or "")       # the "file added:" lines arrive on stdout, the verdict on stderr
        if rc == 0:
            return True, "valid on disk"
        if rc in (124, 127):
            return None, clean(err, 160)
        if "detritus not allowed" in err:
            # --strict objects to Finder attributes on the bundle; that says nothing about the code. Ask again without it.
            rc, out, err = self.cfg.run(["/usr/bin/codesign", "--verify", "--deep", "--verbose=4", path], timeout=timeout, nice=True)
            err = (err or "") + "\n" + (out or "")
            if rc == 0:
                return True, "valid on disk (Finder attributes on the bundle ignored)"
            if rc in (124, 127):
                return None, clean(err, 160)
        verdict = [l for l in err.splitlines() if l.strip() and not l.startswith(("--", "file "))]
        first = clean((verdict or [""])[0].replace(path, "").strip(": "), 200) or "the signature does not verify"
        changed = re.findall(r"^file (added|modified|missing): (.+)$", err, re.M)
        hard = re.search(r"code or signature have been modified|invalid signature|invalid Info\.plist|not signed at all|code has no resources", err)
        if changed and not hard:
            programs = 0
            root = os.path.realpath(path)
            for kind, p in changed:
                st = lstat(p)
                if kind == "missing" or st is None:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    programs += 0 if within(os.path.realpath(p), root) else 1
                elif stat.S_ISDIR(st.st_mode):
                    # A nested bundle that was added: fine when it carries a valid signature of its own from the same signer.
                    mine, theirs = self.info(path), self.info(p)
                    same = theirs.get("signed") and not theirs.get("adhoc") and (
                        (mine.get("apple") and theirs.get("apple")) or (mine.get("teamId") and mine.get("teamId") == theirs.get("teamId")))
                    r2 = self.cfg.run(["/usr/bin/codesign", "--verify", p], timeout=60)[0] if same else 1
                    programs += 0 if r2 == 0 else 1
                elif kind == "modified" or is_macho(read_head(p, 8)) or is_script(read_head(p, 2)):
                    head = read_head(p, 8)
                    programs += 1 if (is_macho(head) or is_script(head)) else 0
            if not programs:
                return "resources", "%d file%s added or changed inside the bundle since it was signed, none of them a program" % (
                    len(changed), "" if len(changed) == 1 else "s")
            return False, "%s (%d program file%s added or changed)" % (first, programs, "" if programs == 1 else "s")
        return False, first

    def assess(self, path, kind="execute", timeout=120):
        """Gatekeeper's verdict: {accepted: True|False|None, source, origin, text}."""
        argv = ["/usr/sbin/spctl", "--assess", "--type", kind, "-vv", path]
        if kind == "open":
            argv = ["/usr/sbin/spctl", "--assess", "--type", "open", "--context", "context:primary-signature", "-vv", path]
        rc, out, err = self.cfg.run(argv, timeout=timeout, nice=True)
        return parse_spctl(rc, out + err)


def parse_codesign(rc, text):
    text = text or ""
    if rc in (124, 127):
        return {"signed": None, "error": clean(text, 160) or "codesign could not be run"}
    if "not signed at all" in text:
        return {"signed": False, "adhoc": False, "teamId": None, "authority": [], "identifier": None,
                "apple": False, "appStore": False, "developerId": False, "error": None}
    if rc != 0:
        return {"signed": None, "error": clean(text, 160) or "codesign failed"}
    auth = re.findall(r"^Authority=(.+)$", text, re.M)
    team = re.search(r"^TeamIdentifier=(.+)$", text, re.M)
    team = team.group(1).strip() if team else None
    if team in ("not set", ""):
        team = None
    ident = re.search(r"^Identifier=(.+)$", text, re.M)
    adhoc = bool(re.search(r"^Signature=adhoc", text, re.M)) or "(adhoc" in text or ",adhoc" in text
    first = auth[0] if auth else ""
    apple = first in ("Software Signing", "macOS Software Signing") or first.startswith("Apple iPhone OS Application Signing")
    store = first.startswith("Apple Mac OS Application Signing") or first.startswith("TestFlight Beta Distribution")
    return {"signed": True, "adhoc": adhoc and not auth, "teamId": team, "authority": auth[:3],
            "identifier": ident.group(1).strip() if ident else None, "apple": apple, "appStore": store,
            "developerId": first.startswith("Developer ID Application"), "error": None}


def parse_spctl(rc, text):
    text = text or ""
    if rc in (124, 127):
        return {"accepted": None, "source": None, "origin": None, "text": clean(text, 160) or "spctl could not be run"}
    src = re.search(r"^source=(.+)$", text, re.M)
    org = re.search(r"^origin=(.+)$", text, re.M)
    accepted = None
    if re.search(r": accepted\s*$", text, re.M):
        accepted = True
    elif re.search(r": rejected", text) or rc == 3:
        accepted = False
    reason = re.search(r": rejected(?: \((.+)\))?", text)
    return {"accepted": accepted, "source": src.group(1).strip() if src else None,
            "origin": org.group(1).strip() if org else None,
            "text": clean(reason.group(1), 160) if reason and reason.group(1) else None,
            "revoked": "CSSMERR_TP_CERT_REVOKED" in text or "revoked" in text.lower()}


def signer_text(cs):
    if cs.get("signed") is None:
        return "could not be checked (%s)" % (cs.get("error") or "unknown reason")
    if not cs["signed"]:
        return "not signed"
    if cs.get("adhoc"):
        return "ad-hoc signed (no developer identity)"
    who = (cs.get("authority") or ["unknown authority"])[0]
    return who


# ---------------------------------------------------------------- findings

class Reason:
    __slots__ = ("code", "text", "severity", "pct", "measured")

    def __init__(self, code, text, severity, pct, measured=False):
        self.code, self.text, self.severity, self.pct, self.measured = code, text, severity, int(pct), measured


def confidence_label(pct, measured=False):
    if measured:
        return "confirmed"
    return "high" if pct >= 75 else "medium" if pct >= 45 else "low"


def judge(reasons):
    """(severity, confidence, confidencePct) from the reasons.

    Severity is the worst reason's. Confidence is that reason's own, nudged up by other reasons that
    point the same way. `confirmed` only when the reason that sets the severity was measured directly
    or named by a signature engine: a heuristic never reaches it."""
    top = max(SEV_RANK[r.severity] for r in reasons)
    lead = sorted((r for r in reasons if SEV_RANK[r.severity] == top), key=lambda r: (r.measured, r.pct), reverse=True)[0]
    if lead.measured:
        return lead.severity, "confirmed", 100
    extra = sum(1 for r in reasons if r is not lead and not r.measured and SEV_RANK[r.severity] >= SEV_RANK["medium"])
    pct = min(95, lead.pct + 5 * extra)
    return lead.severity, confidence_label(pct), pct


def make_finding(key, category, title, detail, subject, reasons, evidence=None, fix=None, fp=None, baseline=False,
                 quarantinable=False):
    """A finding as a scanner hands it to the store. `key` is the stable subject key within the scanner;
    `fp` is what must stay the same for a `trusted` state to hold."""
    severity, confidence, pct = judge(reasons)
    ev = []
    for e in evidence or []:
        if e and e[1] is not None and e[1] != "":
            ev.append({"label": clean(e[0], 60), "value": clean(e[1], 400), "source": clean(e[2] if len(e) > 2 else "", 80)})
    subject = {k: v for k, v in (subject or {}).items() if v is not None}
    if "name" in subject:
        subject["name"] = clean(subject["name"], 160)
    f = fix or {}
    return {"key": key, "category": category, "title": clean(title, 160), "detail": clean(detail, 900),
            "severity": severity, "confidence": confidence, "confidencePct": pct, "subject": subject,
            "evidence": ev[:24], "reasons": [{"code": r.code, "text": clean(r.text, 400)} for r in reasons],
            "fix": {"text": clean(f.get("text"), 600) or "", "command": f.get("command") or None, "needsSudo": bool(f.get("needsSudo"))},
            "fp": fp if fp is not None else digest(key, severity, *[r.code for r in reasons]),
            "baseline": bool(baseline), "quarantinable": bool(quarantinable)}


class Result:
    """What one scanner run produced."""

    def __init__(self):
        self.findings = []
        self.seen = set()          # keys of items that exist (a trusted finding stays while its item is here)
        self.keep = []             # key prefixes that were not evaluated this run: their findings are left alone
        self.not_checked = []      # [{check, why}]: reported as not checked, never as passed
        self.items = 0
        self.detail = None
        self.partial = False

    def add(self, finding):
        if finding:
            self.findings.append(finding)
            self.seen.add(finding["key"])

    def unchecked(self, check, why, keep=None):
        self.not_checked.append({"check": clean(check, 120), "why": clean(why, 240)})
        if keep:
            self.keep.append(keep)
