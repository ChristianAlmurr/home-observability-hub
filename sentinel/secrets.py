"""secrets: who can read the household's key and token files, and whether git tracks them.

This scanner never opens one of these files. It reads the mode, the owner and the size with lstat,
and asks git whether a file is tracked or ignored. A finding carries a path and a mode, nothing else.
"""
import os
import shlex
import stat

from . import util as U
import site_config as SITE

# Always checked; data/site.json secretDirs adds more (stores()).
STORES = (".ssh", ".aws", ".config/gh", ".gnupg", ".kube", ".docker", ".config/gcloud", ".config/home-observability-hub")
# The ones that should never be open to other accounts even when no single file in them looks like a secret.
PRIVATE = (".ssh", ".aws", ".gnupg", ".config/home-observability-hub")
FILES = (".netrc", ".npmrc", ".pypirc", ".claude.json", ".git-credentials")


def site_rels():
    """data/site.json secretDirs as paths relative to the home folder ("~/.vault" -> ".vault"). Absolute paths under
    the real home folder are made relative too; anything else is skipped (Sentinel only looks inside the home folder)."""
    home = os.path.expanduser("~")
    out = []
    for raw in SITE.secret_dirs_raw():
        if raw.startswith("~/"):
            rel = raw[2:]
        elif raw.startswith(home + "/"):
            rel = raw[len(home) + 1:]
        else:
            continue
        rel = os.path.normpath(rel)
        if rel and not rel.startswith("..") and rel != "." and rel not in out:
            out.append(rel)
    return out


def stores():
    """(folders, single files) to check, relative to the home folder."""
    folders, files = list(STORES), list(FILES)
    for rel in site_rels():
        if rel in folders or rel in files or rel.startswith("Library"):
            continue
        folders.append(rel)
    return folders, files
KEY_NAMES = ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")
KEY_EXT = (".pem", ".p8", ".p12", ".pfx", ".key", ".keystore", ".jks")
ENV_OK = (".example", ".sample", ".template", ".defaults", ".dist", ".tmpl")
SKIP = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".next", "DerivedData", "Pods", ".cache", "vendor", "target"}
GIT = ["/usr/bin/git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]


def is_secret_name(name):
    low = name.lower()
    if low.endswith(".pub"):
        return False
    return (low in KEY_NAMES or low.endswith(KEY_EXT) or low.startswith(".env") or low.endswith(".env") or "token" in low or "secret" in low
            or "credential" in low or low in ("hosts.yml", "config.json", "accounts.json", "auth.json") or low.endswith("_ed25519") or low.endswith("_rsa"))


def reachable_by_others(cfg, path):
    """True when every folder from the home folder down to `path` lets other accounts pass through."""
    home = cfg.home
    p = os.path.dirname(path)
    while True:
        st = U.lstat(p)
        if st is None or not (stat.S_IMODE(st.st_mode) & 0o011):
            return False
        if p == home or len(p) <= len(home):
            return True
        p = os.path.dirname(p)


def scan_store(ctx, res, rel):
    cfg = ctx.cfg
    root = cfg.h(rel)
    st = U.lstat(root)
    if st is None or stat.S_ISLNK(st.st_mode):
        return
    key = "store:" + root
    res.seen.add(key)
    loose, foreign, count = [], [], 0
    open_dir = bool(stat.S_IMODE(st.st_mode) & 0o077) and reachable_by_others(cfg, root)
    stack = [(root, 0)]
    while stack and count < 3000:
        d, lvl = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            res.unchecked("inside %s" % cfg.show(d), "the folder cannot be listed", keep=key)
            continue
        with it:
            for e in it:
                count += 1
                try:
                    s = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(s.st_mode):
                    if lvl < 3 and e.name not in SKIP:
                        stack.append((e.path, lvl + 1))
                    continue
                if not stat.S_ISREG(s.st_mode):
                    continue
                mode = stat.S_IMODE(s.st_mode)
                if s.st_uid != cfg.uid:
                    foreign.append((e.path, s))
                if mode & 0o044 and is_secret_name(e.name) and reachable_by_others(cfg, e.path):
                    loose.append((e.path, s))
    res.items += count
    reasons = []
    if loose:
        reasons.append(U.Reason("readable-by-others", "%d secret file%s in %s can be read by other accounts on this Mac, because the file and every folder above it let them in." % (
            len(loose), "" if len(loose) == 1 else "s", cfg.show(root)), "medium", 100, measured=True))
    elif open_dir and (rel in PRIVATE or rel in site_rels()):
        reasons.append(U.Reason("store-open", "The folder %s can be entered or listed by other accounts on this Mac (mode %s). Its files are protected only by their own modes." % (
            cfg.show(root), U.mode_text(st)), "low", 100, measured=True))
    if foreign:
        reasons.append(U.Reason("foreign-owner", "%d file%s in %s belong%s to another account, which can therefore change them." % (
            len(foreign), "" if len(foreign) == 1 else "s", cfg.show(root), "s" if len(foreign) == 1 else ""), "medium", 100, measured=True))
    if not reasons:
        return
    ev = [("folder", "%s, mode %s" % (cfg.show(root), U.mode_text(st)), "stat")]
    ev += [("readable by others", "%s, mode %s" % (cfg.show(p), U.mode_text(s)), "stat (contents not read)") for p, s in loose[:12]]
    ev += [("other owner", "%s, uid %d" % (cfg.show(p), s.st_uid), "stat") for p, s in foreign[:6]]
    res.add(U.make_finding(key, "secrets", "Secrets in %s are readable by other accounts" % cfg.show(root) if loose else
                           "%s is not private" % cfg.show(root), reasons[0].text,
                           {"type": "file", "name": rel, "path": root}, reasons, evidence=ev,
                           fix={"text": "Make the folder and everything in it readable by you alone.",
                                "command": "chmod -R go-rwx %s" % shlex.quote(root), "needsSudo": False},
                           fp=U.digest(U.mode_text(st), *sorted("%s:%s" % (p, U.mode_text(s)) for p, s in loose + foreign)),
                           baseline=ctx.baseline.first("stores")))


def scan_single(ctx, res, rel):
    cfg = ctx.cfg
    p = cfg.h(rel)
    st = U.lstat(p)
    if st is None or not stat.S_ISREG(st.st_mode):
        return
    res.items += 1
    key = "file:" + p
    res.seen.add(key)
    if stat.S_IMODE(st.st_mode) & 0o044 and reachable_by_others(cfg, p):
        res.add(U.make_finding(key, "secrets", "%s is readable by other accounts" % cfg.show(p),
                               "%s usually holds logins or tokens, and other accounts on this Mac can read it (mode %s)." % (cfg.show(p), U.mode_text(st)),
                               {"type": "file", "name": rel, "path": p},
                               [U.Reason("readable-by-others", "Mode %s lets other accounts read it." % U.mode_text(st), "medium", 100, measured=True)],
                               evidence=[("file", "%s, mode %s, %d bytes" % (cfg.show(p), U.mode_text(st), st.st_size), "stat (contents not read)")],
                               fix={"text": "Make it readable by you alone.", "command": "chmod 600 %s" % shlex.quote(p), "needsSudo": False},
                               fp=U.mode_text(st), baseline=ctx.baseline.first("stores")))


def env_files(cfg, limit=400):
    out, count = [], 0
    stack = [(cfg.h("projects"), 0)]
    while stack and count < 60000:
        d, lvl = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for e in it:
                count += 1
                try:
                    if e.is_symlink():
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if lvl < 4 and e.name not in SKIP and not (e.name.startswith(".") and e.name not in (".config",)):
                            stack.append((e.path, lvl + 1))
                    elif (e.name.startswith(".env") or e.name.endswith(".env")) and e.name != ".envrc":
                        if not e.name.lower().endswith(ENV_OK) and e.stat(follow_symlinks=False).st_size > 0 and len(out) < limit:
                            out.append(e.path)
                except OSError:
                    continue
    return sorted(out)


def git_state(cfg, path, cache):
    """(repo root or None, tracked, ignored, has remote). None values mean git could not say."""
    d, name = os.path.dirname(path), os.path.basename(path)
    if d not in cache:
        rc, out, _ = cfg.run(GIT + ["-C", d, "rev-parse", "--show-toplevel"], timeout=10)
        top = out.strip() if rc == 0 and out.strip() else None
        remote = None
        if top:
            if top not in cache:
                rc2, out2, _ = cfg.run(GIT + ["-C", top, "remote"], timeout=10)
                cache[top] = bool(out2.strip()) if rc2 == 0 else None
            remote = cache[top]
        cache[d] = (top, remote, rc in (124, 127))
    top, remote, failed = cache[d]
    if failed:
        return None, None, None, None
    if not top:
        return None, False, False, False
    rc, _, _ = cfg.run(GIT + ["-C", d, "ls-files", "--error-unmatch", "--", name], timeout=10)
    tracked = rc == 0 if rc not in (124, 127) else None
    rc, _, _ = cfg.run(GIT + ["-C", d, "check-ignore", "-q", "--", name], timeout=10)
    ignored = rc == 0 if rc in (0, 1) else None
    return top, tracked, ignored, remote


def scan_env(ctx, res):
    cfg = ctx.cfg
    cache = {}
    first = ctx.baseline.first("env")
    ctx.baseline.begin("env")
    failed = 0
    for p in env_files(cfg):
        st = U.lstat(p)
        if st is None:
            continue
        res.items += 1
        key = "env:" + p
        res.seen.add(key)
        top, tracked, ignored, remote = git_state(cfg, p, cache)
        if tracked is None and top is None and ignored is None:
            failed += 1
            res.keep.append(key)
            continue
        reasons = []
        where = cfg.show(p)
        if tracked:
            reasons.append(U.Reason("env-tracked", "%s is tracked by git%s. Its contents are in the repository's history and go wherever the repository goes." % (
                where, ", and the repository has a remote" if remote else ""),
                # .env and .env.local are where the real keys go; .env.production and the like often hold public settings only
                "high" if remote and os.path.basename(p) in (".env", ".env.local") else "medium", 100, measured=True))
        elif top and ignored is False and remote:
            reasons.append(U.Reason("env-not-ignored", "%s is not in .gitignore and the repository has a remote: one “git add .” puts it in a commit and the next push sends it out." % where,
                                    "medium", 100, measured=True))
        if stat.S_IMODE(st.st_mode) & 0o044 and reachable_by_others(cfg, p):
            reasons.append(U.Reason("readable-by-others", "Other accounts on this Mac can read it (mode %s)." % U.mode_text(st), "medium", 100, measured=True))
        if not reasons:
            continue
        name = os.path.basename(p)
        if tracked:
            fix = {"text": "Stop tracking it and ignore it. The values already committed stay in the history, so change those secrets as well.",
                   "command": "git -C %s rm --cached -- %s && echo %s >> %s" % (shlex.quote(os.path.dirname(p)), shlex.quote(name), shlex.quote(name),
                                                                            shlex.quote(os.path.join(os.path.dirname(p), ".gitignore")))}
        elif reasons[0].code == "env-not-ignored":
            fix = {"text": "Add it to .gitignore.", "command": "echo %s >> %s" % (shlex.quote(name), shlex.quote(os.path.join(os.path.dirname(p), ".gitignore")))}
        else:
            fix = {"text": "Make it readable by you alone.", "command": "chmod 600 %s" % shlex.quote(p)}
        res.add(U.make_finding(key, "secrets", "%s: %s" % ("Secrets file is in git" if tracked else "Secrets file could be committed" if reasons[0].code == "env-not-ignored"
                                                          else "Secrets file readable by others", where), reasons[0].text,
                               {"type": "file", "name": name, "path": p}, reasons,
                               evidence=[("file", "%s, mode %s, %d bytes" % (where, U.mode_text(st), st.st_size), "stat (contents not read)"),
                                         ("repository", cfg.show(top) if top else "none", "git rev-parse"),
                                         ("tracked by git", "yes" if tracked else "no", "git ls-files"), ("ignored", "yes" if ignored else "no", "git check-ignore"),
                                         ("has a remote", "yes" if remote else "no", "git remote")],
                               fix=fix, fp=U.digest(tracked, ignored, remote, U.mode_text(st)), baseline=first))
    if failed:
        res.unchecked("%d .env file%s" % (failed, "" if failed == 1 else "s"), "git gave no answer, so whether they are tracked is not known")


def scan(ctx):
    res = U.Result()
    ctx.baseline.begin("stores")
    folders, files = stores()
    for rel in folders:
        if U.lstat(ctx.cfg.h(rel)) is not None and stat.S_ISREG(U.lstat(ctx.cfg.h(rel)).st_mode):
            files.append(rel)           # a secretDirs entry that is a file (~/.netrc style)
            continue
        try:
            scan_store(ctx, res, rel)
        except Exception as e:
            res.unchecked(rel, "the check failed (%s)" % type(e).__name__, keep="store:" + ctx.cfg.h(rel))
    for rel in files:
        scan_single(ctx, res, rel)
    try:
        scan_env(ctx, res)
    except Exception as e:
        res.unchecked(".env files", "the check failed (%s)" % type(e).__name__, keep="env:")
    res.unchecked("keychains and what the secret files contain", "by design: Sentinel reads modes and owners, never a secret")
    res.detail = "%d files looked at (mode and owner only)" % res.items
    return res
