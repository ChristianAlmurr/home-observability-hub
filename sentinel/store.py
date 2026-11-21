"""Findings, the baseline and the scanner status, as files under data/state/sentinel/.

The files are the truth: every change is read-modify-write under a file lock, so the server, a
`python3 -m sentinel scan` in a terminal and the request handlers can all work on them.
"""
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
import threading
import time

from . import util as U
from .util import C

NEW_WINDOW = 24 * 3600          # a finding counts as new for a day (the same window version 2 uses for devices)
RESOLVED_KEEP = 200
HISTORY_KEEP = 60
STATES = ("open", "acknowledged", "trusted", "quarantined", "resolved")
PUBLIC = ("id", "scanner", "category", "title", "detail", "severity", "confidence", "confidencePct", "subject",
          "evidence", "reasons", "fix", "state", "isNew", "firstSeen", "lastSeen", "resolvedAt", "actions")


def finding_id(scanner, key):
    return "f-" + hashlib.sha256(("%s\x00%s" % (scanner, key)).encode("utf-8", "surrogatepass")).hexdigest()[:12]


def _ts(iso):
    try:
        return datetime.datetime.fromisoformat(iso).timestamp()
    except Exception:
        return 0.0


class Baseline:
    """One scanner's view of the baseline during a run. Nothing is written until the run ends well.

    Items are recorded per group (for example `launchd-user`): the first time a group is read,
    everything in it is the baseline; after that, a key that is missing is `new` and one whose
    fingerprint differs is `changed`."""

    def __init__(self, scanner, data):
        data = data or {}
        self.scanner = scanner
        self.items = dict(data.get("items") or {})
        self.groups = dict(data.get("groups") or {})
        self.added, self.accepted, self.begun = {}, {}, set()

    def begin(self, group):
        """Call before reading a group. True on that group's first (baseline) run."""
        self.begun.add(group)
        return group not in self.groups

    def first(self, group):
        return group not in self.groups

    def status(self, key, fp, group):
        """`known`, `new` or `changed`. On a group's first run the item is recorded and is `known`."""
        self.begun.add(group)
        if group not in self.groups:
            self.added[key] = fp
            return "known"
        cur = self.accepted.get(key, (self.items.get(key) or {}).get("fp"))
        if cur is None and key not in self.items and key not in self.accepted:
            return "new"
        return "known" if cur == fp else "changed"

    def get(self, key):
        if key in self.accepted:
            return self.accepted[key]
        if key in self.added:
            return self.added[key]
        e = self.items.get(key)
        return e.get("fp") if e else None

    def accept(self, key, fp):
        """Take a change into the baseline without a finding (a change that came through git, say)."""
        self.accepted[key] = fp


class Store:
    def __init__(self, state_dir=None):
        self._dir = state_dir
        self.tlock = threading.RLock()
        self._cache = {}

    # -- paths
    @property
    def dir(self):
        return self._dir or os.path.join(C.state_dir(), "sentinel")

    def path(self, name):
        return os.path.join(self.dir, name)

    @property
    def quarantine_dir(self):
        return self.path("quarantine")

    def ensure(self):
        os.makedirs(self.dir, exist_ok=True)
        q = self.quarantine_dir
        if not os.path.isdir(q):
            os.makedirs(q, exist_ok=True)
        try:
            os.chmod(q, 0o700)
        except OSError:
            pass

    @contextlib.contextmanager
    def locked(self):
        self.ensure()
        with self.tlock:
            fd = os.open(self.path(".lock"), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def _read(self, name, default):
        p = self.path(name)
        try:
            st = os.stat(p)
        except OSError:
            return default
        sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        with self.tlock:
            c = self._cache.get(name)
            if c and c[0] == sig:
                return json.loads(c[1])
        try:
            with open(p) as f:
                raw = f.read()
            doc = json.loads(raw)
        except (OSError, ValueError):
            return default
        with self.tlock:
            self._cache[name] = (sig, raw)
        return doc

    def _write(self, name, doc):
        C.write_json_atomic(self.path(name), doc)
        with self.tlock:
            self._cache.pop(name, None)

    # -- per-scanner working cache (the downloads index, for example)
    def load_cache(self, scanner):
        d = self._read("cache-%s.json" % scanner, {})
        return d if isinstance(d, dict) else {}

    def save_cache(self, scanner, doc):
        self.ensure()
        self._write("cache-%s.json" % scanner, doc)

    # -- baseline
    def baseline(self, scanner):
        doc = self._read("baseline.json", {})
        return Baseline(scanner, (doc.get("scanners") or {}).get(scanner))

    def commit_baseline(self, b):
        """Write what a successful run recorded. An entry a person trusted meanwhile is not overwritten by `added`."""
        if not (b.added or b.accepted or any(g not in b.groups for g in b.begun)):
            return
        now = C.now_iso()
        with self.locked():
            doc = self._read("baseline.json", {})
            s = doc.setdefault("scanners", {}).setdefault(b.scanner, {})
            items, groups = s.setdefault("items", {}), s.setdefault("groups", {})
            for k, fp in b.added.items():
                if k not in items:
                    items[k] = {"fp": fp, "by": "baseline", "ts": now}
            for k, fp in b.accepted.items():
                items[k] = {"fp": fp, "by": "scanner", "ts": now}
            for g in b.begun:
                groups.setdefault(g, now)
            doc["version"] = 1
            self._write("baseline.json", doc)

    def baseline_set(self, scanner, key, fp, by):
        with self.locked():
            doc = self._read("baseline.json", {})
            s = doc.setdefault("scanners", {}).setdefault(scanner, {})
            s.setdefault("items", {})[key] = {"fp": fp, "by": by, "ts": C.now_iso()}
            s.setdefault("groups", {})
            doc["version"] = 1
            self._write("baseline.json", doc)

    def baseline_drop(self, scanner, key):
        with self.locked():
            doc = self._read("baseline.json", {})
            items = ((doc.get("scanners") or {}).get(scanner) or {}).get("items") or {}
            e = items.get(key)
            if e and e.get("by") == "person":
                del items[key]
                self._write("baseline.json", doc)

    # -- findings
    def _findings(self):
        d = self._read("findings.json", {})
        f = d.get("findings") if isinstance(d, dict) else None
        return f if isinstance(f, dict) else {}

    def _save_findings(self, findings):
        resolved = sorted((r for r in findings.values() if r["state"] == "resolved"),
                          key=lambda r: r.get("resolvedAt") or "", reverse=True)
        for r in resolved[RESOLVED_KEEP:]:
            findings.pop(r["id"], None)
        self._write("findings.json", {"version": 1, "ts": C.now_iso(), "findings": findings})

    @staticmethod
    def _note(rec, actor, change, ts=None):
        h = rec.setdefault("history", [])
        h.append({"ts": ts or C.now_iso(), "actor": actor, "change": change})
        del h[:-HISTORY_KEEP]

    def apply(self, scanner, result, now=None):
        """Merge one successful scanner run. Returns {"new": [...], "resolved": [...]} (stored records).

        `new` lists findings that were raised or raised again by this run, outside a baseline run."""
        now = now or C.now_iso()
        changes = {"new": [], "resolved": []}
        with self.locked():
            findings = self._findings()
            emitted = set()
            for f in result.findings:
                fid = finding_id(scanner, f["key"])
                rec = findings.get(fid)
                if rec is not None and rec["state"] == "quarantined":
                    # Something sits at the path of a quarantined file again: that is a finding of its own.
                    fid = finding_id(scanner, f["key"] + "\x00again")
                    rec = findings.get(fid)
                emitted.add(fid)
                raised = False
                if rec is None:
                    rec = {"id": fid, "scanner": scanner, "key": f["key"], "state": "open", "firstSeen": now,
                           "raisedAt": now, "resolvedAt": None, "fresh": not f.get("baseline"), "history": []}
                    self._note(rec, "sentinel", "found" + (" on the baseline run" if f.get("baseline") else ""), now)
                    findings[fid] = rec
                    raised = not f.get("baseline")
                elif rec["state"] == "resolved":
                    rec.update(state="open", raisedAt=now, resolvedAt=None, fresh=True)
                    self._note(rec, "sentinel", "seen again", now)
                    raised = True
                elif rec["state"] == "trusted" and f["fp"] != rec.get("trustedFp"):
                    rec.update(state="open", raisedAt=now, fresh=True)
                    rec.pop("trustedFp", None)
                    self._note(rec, "sentinel", "changed since it was trusted: open again", now)
                    raised = True
                elif rec["state"] == "acknowledged" and U.SEV_RANK[f["severity"]] > U.SEV_RANK.get(rec.get("ackSeverity") or rec["severity"], 0):
                    rec.update(state="open", raisedAt=now, fresh=True)
                    self._note(rec, "sentinel", "became %s since it was acknowledged: open again" % f["severity"], now)
                    raised = True
                for k in ("category", "title", "detail", "severity", "confidence", "confidencePct", "subject", "evidence",
                          "reasons", "fix", "fp", "quarantinable"):
                    rec[k] = f[k]
                rec["lastSeen"] = now
                if raised:
                    changes["new"].append(rec)
            for rec in findings.values():
                if rec["scanner"] != scanner or rec["id"] in emitted or rec["state"] in ("resolved", "quarantined"):
                    continue
                if any(rec["key"].startswith(p) for p in result.keep):
                    continue
                if rec["state"] == "trusted" and rec["key"] in result.seen:
                    continue
                was = rec["state"]
                rec.update(state="resolved", resolvedAt=now, fresh=False)
                self._note(rec, "sentinel", "no longer found: resolved", now)
                if was in ("open", "acknowledged"):
                    changes["resolved"].append(rec)
            self._save_findings(findings)
        return changes

    def get(self, fid):
        return self._findings().get(fid)

    def update(self, fid, fn):
        """Change one record under the lock. `fn(rec)` mutates it; returns the record or None."""
        with self.locked():
            findings = self._findings()
            rec = findings.get(fid)
            if rec is None:
                return None
            fn(rec)
            self._save_findings(findings)
            return rec

    # -- what the API serves
    @staticmethod
    def is_new(rec, now=None):
        return bool(rec.get("state") == "open" and rec.get("fresh") and (now or time.time()) - _ts(rec.get("raisedAt")) < NEW_WINDOW)

    def public(self, rec, actions_fn=None, now=None):
        out = {k: rec.get(k) for k in PUBLIC}
        out["isNew"] = self.is_new(rec, now)
        out["actions"] = actions_fn(rec) if actions_fn else []
        if rec.get("quarantine"):
            out["quarantine"] = {k: rec["quarantine"].get(k) for k in ("originalPath", "at")}
        return out

    def listing(self, state=None, severity=None, scanner=None):
        """Stored records, worst first: severity, then confidence, then newest. Without `state`, everything not resolved."""
        recs = list(self._findings().values())
        if state == "all":
            pass
        elif state:
            recs = [r for r in recs if r["state"] == state]
        else:
            recs = [r for r in recs if r["state"] != "resolved"]
        if severity:
            recs = [r for r in recs if r["severity"] == severity]
        if scanner:
            recs = [r for r in recs if r["scanner"] == scanner]
        recs.sort(key=lambda r: r.get("raisedAt") or r.get("firstSeen") or "", reverse=True)
        recs.sort(key=lambda r: (U.SEV_RANK.get(r["severity"], 0), r.get("confidencePct") or 0), reverse=True)
        return recs

    def summary(self, last_scan=None):
        now = time.time()
        by = {s: 0 for s in reversed(U.SEVERITIES)}
        n_open = n_new = n_ack = 0
        level = "secure"
        for r in self._findings().values():
            if r["state"] == "acknowledged":
                n_ack += 1
            if r["state"] != "open":
                continue
            n_open += 1
            by[r["severity"]] = by.get(r["severity"], 0) + 1
            if self.is_new(r, now):
                n_new += 1
            if r["severity"] == "critical" and r["confidence"] in ("confirmed", "high"):
                level = "compromised"
        worst = next((s for s in reversed(U.SEVERITIES) if by.get(s)), "none")
        if level != "compromised":
            level = "at-risk" if by["critical"] or by["high"] else "watch" if by["medium"] else "secure"
        return {"open": n_open, "new": n_new, "acknowledged": n_ack, "bySeverity": by, "worst": worst, "level": level,
                "lastScan": last_scan}

    def open_counts(self):
        out = {}
        for r in self._findings().values():
            if r["state"] == "open":
                out[r["scanner"]] = out.get(r["scanner"], 0) + 1
        return out

    # -- scanner status and engines
    def status(self):
        d = self._read("scanners.json", {})
        return d if isinstance(d, dict) else {}

    def set_status(self, name, **fields):
        with self.locked():
            d = self.status()
            s = d.setdefault("scanners", {}).setdefault(name, {})
            s.update(fields)
            self._write("scanners.json", d)
            return s

    def set_meta(self, **fields):
        with self.locked():
            d = self.status()
            d.update(fields)
            self._write("scanners.json", d)
