"""What does the scanning: ClamAV, YARA, XProtect, Gatekeeper. Shown as-is so nobody assumes an engine
that is not there. Running one never changes anything: they read files and print names."""
import datetime
import os
import re

from . import util as U

CLAM_DIRS = ("/opt/homebrew/bin", "/usr/local/bin")
CLAM_DB_DIRS = ("/opt/homebrew/var/lib/clamav", "/usr/local/var/lib/clamav", "/var/lib/clamav")
CLAM_SOCKETS = ("/opt/homebrew/var/run/clamav/clamd.sock", "/tmp/clamd.sock", "/usr/local/var/run/clamav/clamd.sock")
XPROTECT = ("/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
            "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist")
CLAM_STALE_DAYS = 7
# Before the first scan has looked: nothing is known, and nothing is claimed.
UNKNOWN = {"clamav": {"installed": None, "version": None, "signaturesAt": None}, "yara": {"installed": None, "rules": 0},
           "xprotect": {"version": None, "updatedAt": None}, "gatekeeper": {"enabled": None}}
CLAM_MAX_FILE = 200 * 1024 * 1024


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


def _find(cfg, names):
    for d in CLAM_DIRS:
        for n in names:
            p = cfg.s(os.path.join(d, n))
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
    return None


def yara_rule_files(cfg):
    out = []
    for d in (os.path.join(cfg.repo, "data", "yara"), cfg.h(".config", "home-observability-hub", "yara")):
        try:
            for n in sorted(os.listdir(d)):
                if n.endswith((".yar", ".yara")) and os.path.isfile(os.path.join(d, n)):
                    out.append(os.path.join(d, n))
        except OSError:
            pass
    return out[:50]


def detect(cfg):
    """The `engines` object of the contract, plus what the scanners need to call them."""
    clam = {"installed": False, "version": None, "signaturesAt": None, "daemon": False, "stale": None}
    scan_bin = _find(cfg, ("clamscan",))
    d_bin = _find(cfg, ("clamdscan",))
    if scan_bin or d_bin:
        db_at = None
        for d in CLAM_DB_DIRS:
            try:
                for n in os.listdir(cfg.s(d)):
                    if n.endswith((".cvd", ".cld")):
                        db_at = max(db_at or 0, os.stat(os.path.join(cfg.s(d), n)).st_mtime)
            except OSError:
                pass
        rc, out, _ = cfg.run([scan_bin or d_bin, "--version"], timeout=15)
        m = re.match(r"ClamAV\s+([0-9.]+)", out or "")
        clam.update(installed=db_at is not None, version=m.group(1) if m else None,
                    signaturesAt=_iso(db_at) if db_at else None,
                    stale=bool(db_at and (datetime.datetime.now().timestamp() - db_at) > CLAM_STALE_DAYS * 86400),
                    daemon=bool(d_bin and any(os.path.exists(cfg.s(s)) for s in CLAM_SOCKETS)))
        if db_at is None:
            clam["note"] = "ClamAV is installed but has no signature database yet (run freshclam)."
    yara_bin = _find(cfg, ("yara", "yara-x", "yr"))
    rules = yara_rule_files(cfg)
    xp = {"version": None, "updatedAt": None}
    for p in XPROTECT:
        info = U.load_plist(cfg.s(p))
        if isinstance(info, dict):
            st = U.lstat(cfg.s(p))
            xp = {"version": str(info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or "") or None,
                  "updatedAt": _iso(st.st_mtime) if st else None}
            break
    rc, out, err = cfg.run(["/usr/sbin/spctl", "--status"], timeout=10)
    gk = None if rc in (124, 127) else ("assessments enabled" in (out + err))
    return {"clamav": clam, "yara": {"installed": bool(yara_bin), "rules": len(rules)},
            "xprotect": xp, "gatekeeper": {"enabled": gk},
            "_bins": {"clamscan": scan_bin, "clamdscan": d_bin if clam.get("daemon") else None, "yara": yara_bin,
                      "yaraRules": rules}}


def public(engines):
    return {k: v for k, v in (engines or {}).items() if not k.startswith("_")}


def clam_scan(cfg, engines, paths, timeout=1800):
    """{path: signature name} for the infected ones, plus an error text or None.
    ClamAV reads the files; nothing is moved or removed (no --remove, no --move)."""
    bins = (engines or {}).get("_bins") or {}
    exe = bins.get("clamdscan") or bins.get("clamscan")
    if not exe or not (engines.get("clamav") or {}).get("installed"):
        return {}, "ClamAV is not installed"
    hits, error = {}, None
    daemon = exe == bins.get("clamdscan")
    for i in range(0, len(paths), 400):
        chunk = [p for p in paths[i:i + 400] if p.startswith("/")]
        if not chunk:
            continue
        if daemon:
            argv = [exe, "--fdpass", "--no-summary", "--infected", "--stdout"] + chunk
        else:
            argv = [exe, "--no-summary", "--infected", "--stdout", "-r", "--max-filesize=200M", "--max-scansize=400M",
                    "--follow-dir-symlinks=0", "--follow-file-symlinks=0"] + chunk
        rc, out, err = cfg.run(argv, timeout=timeout, nice=True)
        for line in (out or "").splitlines():
            m = re.match(r"^(/.*): (.+) FOUND\s*$", line)
            if m:
                hits[m.group(1)] = U.clean(m.group(2), 120)
        if rc not in (0, 1):
            error = U.clean((err or out or "clamscan failed").strip().splitlines()[-1] if (err or out) else "clamscan failed", 200)
            if daemon:      # the daemon is not answering: fall back to the standalone scanner once
                bins["clamdscan"] = None
                more, error = clam_scan(cfg, engines, paths[i:], timeout)
                hits.update(more)
                break
    return hits, error


def yara_scan(cfg, engines, paths, timeout=120):
    bins = (engines or {}).get("_bins") or {}
    exe, rules = bins.get("yara"), bins.get("yaraRules") or []
    if not exe or not rules:
        return {}, "YARA is not installed or has no rules"
    hits, error = {}, None
    for p in paths:
        for rf in rules:
            rc, out, err = cfg.run([exe, "-w", "-N", rf, p], timeout=timeout, nice=True)
            if rc != 0:
                error = U.clean(err, 160) or "yara failed"
                continue
            names = [l.split(" ", 1)[0] for l in (out or "").splitlines() if l.strip()]
            if names:
                hits.setdefault(p, []).extend(U.clean(n, 80) for n in names)
    return hits, error
