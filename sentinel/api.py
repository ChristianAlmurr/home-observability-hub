"""The /api/threats routes and what the person can do to a finding.

These are the person's own clicks: each is written to audit.jsonl with actor `person`. The only thing
here that touches anything outside Sentinel's own state files is quarantine/restore: a move of one
file (or one app bundle), with the refusals below enforced in code whatever the UI sends.
"""
import errno
import os
import re
import stat

from . import engines as E
from . import util as U
from .util import C

ID_RE = re.compile(r"^f-[0-9a-f]{12}$")
ACTIONS = ("acknowledge", "trust", "quarantine", "restore", "reopen", "rescan")
NEED_CONFIRM = ("trust", "quarantine", "restore")
STATES = ("open", "acknowledged", "trusted", "quarantined", "resolved", "all")


class ActionError(Exception):
    def __init__(self, status, text):
        Exception.__init__(self, text)
        self.status, self.text = status, text


# ---------------------------------------------------------------- quarantine

def quarantine_refusal(engine, path):
    """Plain words when this path may not be quarantined, else None. Checked again at the moment of the move."""
    cfg, store = engine.cfg, engine.store
    if not isinstance(path, str) or not os.path.isabs(path) or "\x00" in path:
        return "This finding has no file path to move."
    st = U.lstat(path)
    if st is None:
        return "The file is no longer there."
    if stat.S_ISLNK(st.st_mode):
        return "This is a link, not the file itself. Sentinel does not move links."
    real = os.path.realpath(path)
    home, apps = cfg.home, os.path.realpath(cfg.s("/Applications"))
    if not (U.within(real, home) or U.within(real, apps)) or real in (home, apps):
        return "Sentinel only quarantines files in your home folder and in Applications."
    protected = [(cfg.repo, "the hub's own folder"), (os.path.realpath(store.dir), "Sentinel's own state"),
                 (os.path.realpath(C.state_dir()), "the hub's own state"),
                 (cfg.h(".ssh"), "~/.ssh"), (cfg.h("Library"), "~/Library"),
                 (cfg.h(".claude"), "~/.claude"), (cfg.h(".config"), "~/.config")]
    # Every secret folder data/site.json lists (secretDirs), under this scan's home folder.
    from . import secrets as SEC
    protected += [(cfg.h(rel), "~/" + rel) for rel in SEC.site_rels()]
    for root, label in protected:
        if U.within(real, os.path.realpath(root)):
            return "It is inside %s, which Sentinel never moves anything out of." % label
    if os.path.dirname(real) == home and os.path.basename(real) in ("Downloads", "Desktop", "Documents", "Applications", "projects",
                                                                     "Pictures", "Movies", "Music", "Public"):
        return "That is one of your main folders, not a single file."
    if stat.S_ISDIR(st.st_mode):
        if not real.endswith(".app") or not os.path.isdir(os.path.join(real, "Contents")):
            return "It is a folder that is not an app. Sentinel moves single files and app bundles only."
    elif not stat.S_ISREG(st.st_mode):
        return "It is not a regular file."
    return None


def do_quarantine(engine, rec):
    subject = rec.get("subject") or {}
    path = subject.get("path")
    if not rec.get("quarantinable") or subject.get("type") not in ("file", "app") or not path:
        raise ActionError(409, "This finding is not about a file, so there is nothing to quarantine.")
    if rec.get("state") not in ("open", "acknowledged"):
        raise ActionError(409, "A finding that is %s cannot be quarantined." % rec.get("state"))
    why = quarantine_refusal(engine, path)
    if why:
        raise ActionError(403, why)
    st = os.lstat(path)
    if stat.S_ISREG(st.st_mode) and subject.get("sha256"):
        if U.sha256_file(path) != subject["sha256"]:
            raise ActionError(409, "The file changed since it was scanned. Scan again first.")
    store = engine.store
    store.ensure()
    dest_dir = os.path.join(store.quarantine_dir, rec["id"])
    dest = os.path.join(dest_dir, os.path.basename(path.rstrip("/")))
    if os.path.lexists(dest_dir):
        raise ActionError(409, "There is already something in quarantine for this finding. Restore it first.")
    os.makedirs(dest_dir, mode=0o700)
    try:
        os.rename(path, dest)
    except OSError as e:
        os.rmdir(dest_dir)
        if e.errno == errno.EXDEV:
            raise ActionError(409, "The file is on another disk. Sentinel only moves a file; it will not copy and delete it.")
        raise ActionError(409, "The file could not be moved (%s)." % (e.strerror or "error"))
    mode = stat.S_IMODE(st.st_mode)
    try:
        os.chmod(dest, 0)
    except OSError:
        pass
    q = {"originalPath": path, "storedPath": dest, "originalMode": mode, "at": C.now_iso()}

    def change(r):
        r["state"] = "quarantined"
        r["quarantine"] = q
        r["fresh"] = False
        # subject.path stays the original path; where the file is now goes in the evidence.
        r["evidence"] = [e for e in r.get("evidence") or [] if e.get("label") != "quarantined at"] + [
            {"label": "quarantined at", "value": dest, "source": "Sentinel quarantine (mode 000)"}]
        engine.store._note(r, "person", "quarantined: moved out of %s" % engine.cfg.show(os.path.dirname(path)))
    out = store.update(rec["id"], change)
    return out, {"moved": True, "from": path, "undo": "Use Restore on this finding to put it back where it was."}


def do_restore(engine, rec):
    q = rec.get("quarantine") or {}
    if rec.get("state") != "quarantined" or not q.get("storedPath"):
        raise ActionError(409, "This finding has nothing in quarantine.")
    stored, orig = q["storedPath"], q["originalPath"]
    qdir = os.path.realpath(engine.store.quarantine_dir)
    if not U.within(os.path.realpath(os.path.dirname(stored)), qdir) or U.lstat(stored) is None:
        raise ActionError(409, "The quarantined file is no longer where Sentinel put it.")
    if os.path.lexists(orig):
        raise ActionError(409, "Something else is now at the original place. Move it away first; nothing is overwritten.")
    if not os.path.isdir(os.path.dirname(orig)):
        raise ActionError(409, "The folder it came from no longer exists.")
    try:
        os.chmod(stored, q.get("originalMode") or 0o600)
        os.rename(stored, orig)
    except OSError as e:
        try:
            os.chmod(stored, 0)
        except OSError:
            pass
        raise ActionError(409, "The file could not be moved back (%s)." % (e.strerror or "error"))
    try:
        os.rmdir(os.path.dirname(stored))
    except OSError:
        pass

    def change(r):
        r["state"] = "open"
        r["raisedAt"] = C.now_iso()
        r.pop("quarantine", None)
        r["evidence"] = [e for e in r.get("evidence") or [] if e.get("label") != "quarantined at"]
        engine.store._note(r, "person", "restored to where it was: open again")
    out = engine.store.update(rec["id"], change)
    return out, {"restored": True, "to": orig}


# ---------------------------------------------------------------- actions

def actions_for(engine, rec):
    """What is possible for this finding now, in the contract's order."""
    st = rec.get("state")
    if st == "resolved":
        return []
    if st == "quarantined":
        return ["restore"]
    out = []
    if st == "open":
        out += ["acknowledge", "trust"]
    elif st == "acknowledged":
        out += ["trust"]
    if st in ("open", "acknowledged") and rec.get("quarantinable") and \
            quarantine_refusal(engine, (rec.get("subject") or {}).get("path")) is None:
        out.append("quarantine")
    if st in ("acknowledged", "trusted"):
        out.append("reopen")
    out.append("rescan")
    return out


def confirm_for(engine, rec, actions):
    """What each confirmable action will do, in the shape device actions use: {action: {title, effect, undo}}."""
    name = U.clean((rec.get("subject") or {}).get("name") or rec.get("title"), 80)
    path = engine.cfg.show((rec.get("subject") or {}).get("path") or "")
    out = {}
    if "trust" in actions:
        out["trust"] = {"title": "Trust %s" % name,
                        "effect": "Marks this as expected and adds it to the baseline. It is not raised again unless it changes; if it changes, it comes back as open.",
                        "undo": "Use Reopen on this finding: it leaves the baseline and is open again."}
    if "quarantine" in actions:
        out["quarantine"] = {"title": "Quarantine %s" % name,
                             "effect": "Moves %s into Home Observability Hub's quarantine folder and removes every permission from it, so it cannot be opened. Nothing is deleted." % (path or "the file"),
                             "undo": "Use Restore on this finding: the file goes back to where it was, with its old permissions."}
    if "restore" in actions:
        q = rec.get("quarantine") or {}
        out["restore"] = {"title": "Restore %s" % name,
                          "effect": "Moves the file back to %s with its old permissions. It can be opened again, and the finding is open again." % (
                              engine.cfg.show(q.get("originalPath") or "") or "where it was"),
                          "undo": "Quarantine it again."}
    return out


def public(engine, rec):
    out = engine.store.public(rec, lambda r: actions_for(engine, r))
    out["confirm"] = confirm_for(engine, rec, out["actions"])
    return out


def perform(engine, fid, body, audit=None):
    """POST /api/threats/<id>/action → {ok, finding, result}. Raises ActionError(status, plain words)."""
    audit = audit or (lambda **k: None)
    action = body.get("action")
    if action not in ACTIONS:
        raise ActionError(400, "action must be one of: %s" % ", ".join(ACTIONS))
    if not ID_RE.match(fid or ""):
        raise ActionError(404, "no such finding")
    rec = engine.store.get(fid)
    if rec is None:
        raise ActionError(404, "no such finding")
    if action in NEED_CONFIRM and body.get("confirm") is not True:
        raise ActionError(400, "This needs confirm: true. Show the person what will happen first.")
    cmd = "%s %s" % (action, fid)
    title = U.clean(rec.get("title"), 200)
    store = engine.store
    try:
        if action == "quarantine":
            rec, result = do_quarantine(engine, rec)
        elif action == "restore":
            rec, result = do_restore(engine, rec)
        elif action not in actions_for(engine, rec):
            raise ActionError(409, "A finding that is %s cannot be %s." % (rec["state"], {
                "acknowledge": "acknowledged", "trust": "trusted", "reopen": "reopened", "rescan": "scanned again"}[action]))
        elif action == "acknowledge":
            def change(r):
                r.update(state="acknowledged", fresh=False, ackSeverity=r["severity"])
                store._note(r, "person", "acknowledged")
            rec, result = store.update(fid, change), {}
        elif action == "trust":
            def change(r):
                r.update(state="trusted", fresh=False, trustedFp=r.get("fp"))
                store._note(r, "person", "trusted: added to the baseline until it changes")
            rec = store.update(fid, change)
            store.baseline_set(rec["scanner"], rec["key"], rec.get("fp"), "person")
            result = {"baseline": True}
        elif action == "reopen":
            was = rec["state"]

            def change(r):
                r.update(state="open", raisedAt=C.now_iso())
                r.pop("trustedFp", None)
                store._note(r, "person", "reopened")
            rec = store.update(fid, change)
            if was == "trusted":
                store.baseline_drop(rec["scanner"], rec["key"])
            result = {}
        else:   # rescan
            result = {"started": engine.trigger([rec["scanner"]])}
    except ActionError as e:
        audit(actor="person", type="threat-action", command=cmd, decision="refused" if e.status == 403 else "confirmed",
              exitCode=1, summary=("%s: %s" % (title, e.text))[:300])
        raise
    audit(actor="person", type="threat-action", command=cmd, decision="confirmed", exitCode=0, summary=title)
    return {"ok": True, "finding": public(engine, rec), "result": result}


# ---------------------------------------------------------------- reads

def threats_doc(engine, state=None, severity=None, scanner=None):
    """GET /api/threats."""
    if state and state not in STATES:
        raise ActionError(400, "state must be one of: %s" % ", ".join(STATES))
    if severity and severity not in U.SEVERITIES:
        raise ActionError(400, "severity must be one of: %s" % ", ".join(reversed(U.SEVERITIES)))
    if scanner and scanner not in engine.names():
        raise ActionError(400, "scanner must be one of: %s" % ", ".join(engine.names()))
    store = engine.store
    return {"ts": C.now_iso(), "enabled": engine.enabled, "summary": store.summary(engine.last_scan()),
            "findings": [public(engine, r) for r in store.listing(state, severity, scanner)],
            "scanners": engine.scanners_doc(),
            # Read from the file the scanners keep: nothing is probed on the request path.
            "engines": store.status().get("engines") or E.UNKNOWN}


def finding_doc(engine, fid):
    """GET /api/threats/<id>: the finding plus its history."""
    if not ID_RE.match(fid or ""):
        return None
    rec = engine.store.get(fid)
    if rec is None:
        return None
    out = public(engine, rec)
    out["history"] = list(reversed(rec.get("history") or []))
    return out


def start_scan(engine, body):
    """POST /api/threats/scan."""
    name = body.get("scanner")
    if name is not None and name not in engine.names():
        raise ActionError(400, "scanner must be one of: %s" % ", ".join(engine.names()))
    return {"ok": True, "started": engine.trigger([name] if name else None)}


def live_summary(engine):
    """What /api/live's summary gains."""
    s = engine.store.summary()
    return {"open": s["open"], "critical": s["bySeverity"]["critical"], "high": s["bySeverity"]["high"], "level": s["level"]}
