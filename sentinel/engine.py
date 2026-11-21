"""The Sentinel scheduler: one daemon thread that hands due scanners to a small worker pool.

Started by server.py next to the collectors. `HM_SENTINEL=0` switches it off. A scanner that fails
is marked `ok: false` with its error and its earlier findings are left exactly as they were.
"""
import collections
import concurrent.futures
import importlib
import os
import threading
import time

from . import engines as E
from . import util as U
from .store import Store
from .util import C

# name -> (module, label, description, every seconds)
SCANNERS = collections.OrderedDict([
    ("posture", ("posture", "Mac settings", "Firewall, disk encryption, updates, remote access, sharing and accounts on this Mac.", 600)),
    ("downloads", ("downloads", "Downloads and apps", "New files and apps: signature, Gatekeeper, antivirus and what they do.", 60)),
    ("persistence", ("persistence", "Startup items", "Launch items, cron, shell startup files, sudo rules, SSH keys and profiles.", 300)),
    ("plugins", ("plugins", "Plugins", "Claude Code hooks and MCP servers, browser and editor extensions, installed packages.", 600)),
    ("processes", ("processes", "Open ports", "Programs listening beyond this Mac or running from temporary folders.", 120)),
    ("secrets", ("secrets", "Secret files", "Who can read key and token files, and whether git tracks them. Never their contents.", 1800)),
    ("network", ("network", "Network", "Router settings and changes to them, new devices and devices with risky ports.", 300)),
    ("integrity", ("integrity", "Home Observability Hub", "Home Observability Hub's own code, its launchd job and the Claude Code hooks.", 600)),
])
NOTIFY_PER_HOUR = 4
EVENT_FROM = U.SEV_RANK["medium"]
NOTIFY_FROM = U.SEV_RANK["high"]


class Context:
    """What a scanner gets: the config, its baseline, a working cache that persists, and the engines."""

    def __init__(self, engine, name):
        self.engine, self.name = engine, name
        self.cfg, self.store = engine.cfg, engine.store
        self.baseline = engine.store.baseline(name)
        self.cache = engine.store.load_cache(name)
        self.sigs = engine.sigs
        self.monitor = engine.cfg.monitor
        self._last_progress = 0.0

    @property
    def engines(self):
        return self.engine.engines()

    def progress(self, text, force=False):
        """Shown in scanners.<name>.progress while a long run is going. Throttled."""
        now = time.time()
        if force or now - self._last_progress >= 2.0:
            self._last_progress = now
            try:
                self.store.set_status(self.name, progress=U.clean(text, 160))
            except OSError:
                pass


class Engine:
    def __init__(self, cfg=None, store=None, scanners=None, enabled=None, workers=2):
        self.cfg = cfg or U.Config()
        self.store = store or Store()
        self.sigs = U.Signatures(self.cfg)
        self.enabled = (os.environ.get("HM_SENTINEL") != "0") if enabled is None else enabled
        self.scanners = scanners          # name -> callable(ctx) -> Result; None: the real modules
        self.workers = workers
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.thread = None
        self.pool = None
        self.lock = threading.Lock()
        self.running = set()
        self.next_due = {}
        self.notified = collections.deque(maxlen=NOTIFY_PER_HOUR)
        self._engines = (0.0, None)

    # -- what there is
    def names(self):
        return list(self.scanners) if self.scanners is not None else list(SCANNERS)

    def _fn(self, name):
        if self.scanners is not None:
            return self.scanners[name]
        return importlib.import_module("sentinel." + SCANNERS[name][0]).scan

    def meta(self, name):
        m = SCANNERS.get(name)
        return {"label": m[1], "description": m[2], "intervalSec": m[3]} if m else {"label": name, "description": "", "intervalSec": 600}

    def engines(self, fresh=False):
        with self.lock:
            t, e = self._engines
        if e is None or fresh or time.time() - t > 600:
            e = E.detect(self.cfg)
            with self.lock:
                self._engines = (time.time(), e)
            try:
                self.store.set_meta(engines=E.public(e))
            except OSError:
                pass
        return e

    # -- scheduling
    def start(self):
        if not self.enabled or self.thread:
            return False
        try:
            self._clear_running()
        except OSError:
            pass
        self.thread = threading.Thread(target=self._loop, name="sentinel", daemon=True)
        self.thread.start()
        return True

    def _clear_running(self):
        """A server that was stopped mid-scan leaves `running: true` in the file: nothing is running at start."""
        st = (self.store.status().get("scanners") or {})
        for name, s in st.items():
            if s.get("running"):
                self.store.set_status(name, running=False, progress=None)

    def _pool(self):
        with self.lock:
            if self.pool is None:
                self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="sentinel-scan")
            return self.pool

    def _loop(self):
        # Let the server and the collectors settle first, then start the cheap scanners before the heavy one.
        self.stop.wait(8)
        order = [n for n in self.names() if n != "downloads"] + [n for n in self.names() if n == "downloads"]
        while not self.stop.is_set():
            now = time.time()
            for name in order:
                if now >= self.next_due.get(name, 0):
                    self.submit(name)
            self.wake.wait(5)
            self.wake.clear()

    def submit(self, name):
        """Queue one scanner unless it is already queued or running. True when queued."""
        with self.lock:
            if name in self.running:
                return False
            self.running.add(name)
            self.next_due[name] = time.time() + self.meta(name)["intervalSec"]
        try:
            self.store.set_status(name, running=True, queuedAt=C.now_iso())
        except OSError:
            pass
        self._pool().submit(self._run_guarded, name)
        return True

    def trigger(self, names=None):
        """POST /api/threats/scan: run these now, in the background. Returns the names that were started."""
        return [n for n in (names or self.names()) if n in self.names() and self.submit(n)]

    def _run_guarded(self, name):
        try:
            self._run(name)
        finally:
            with self.lock:
                self.running.discard(name)

    def run_scanner(self, name):
        """Run one scanner now, in this thread (the terminal command and the tests). Returns its status."""
        with self.lock:
            if name in self.running:
                return None
            self.running.add(name)
        try:
            return self._run(name)
        finally:
            with self.lock:
                self.running.discard(name)

    def _run(self, name):
        t0 = time.time()
        status = {"running": False, "progress": None, "lastRun": None, "durationMs": None, "ok": False, "error": None}
        changes = {"new": [], "resolved": []}
        try:
            self.store.set_status(name, running=True, startedAt=C.now_iso())
            ctx = Context(self, name)
            result = self._fn(name)(ctx)
            changes = self.store.apply(name, result)
            self.store.commit_baseline(ctx.baseline)
            if ctx.cache:
                self.store.save_cache(name, ctx.cache)
            status.update(ok=True, itemsScanned=result.items, notChecked=result.not_checked, detail=result.detail,
                          partial=bool(result.partial))
        except Exception as e:      # the scanner failed: say so, and leave its findings as they were
            status.update(ok=False, error=U.clean("%s: %s" % (type(e).__name__, e), 300))
        status.update(lastRun=C.now_iso(), durationMs=int((time.time() - t0) * 1000))
        try:
            self.store.set_status(name, **status)
        except OSError:
            pass
        try:
            self._announce(changes)
        except Exception:
            pass
        return status

    # -- events and notifications
    def _announce(self, changes):
        events = os.path.join(C.state_dir(), "events.jsonl")
        for rec in changes["new"]:
            if U.SEV_RANK[rec["severity"]] < EVENT_FROM:
                continue
            C.append_jsonl(events, {
                "ts": C.now_iso(), "kind": "security", "device": (rec.get("subject") or {}).get("deviceId"), "link": None,
                "from": None, "to": rec["severity"], "code": "threat", "findingId": rec["id"], "severity": rec["severity"],
                "text": "Sentinel: %s (%s, confidence %s)." % (rec["title"], rec["severity"], rec["confidence"])})
            if U.SEV_RANK[rec["severity"]] >= NOTIFY_FROM:
                self._notify(rec)
        for rec in changes["resolved"]:
            if U.SEV_RANK[rec["severity"]] < EVENT_FROM:
                continue
            C.append_jsonl(events, {
                "ts": C.now_iso(), "kind": "security", "device": (rec.get("subject") or {}).get("deviceId"), "link": None,
                "from": rec["severity"], "to": "resolved", "code": "threat-resolved", "findingId": rec["id"],
                "severity": rec["severity"], "text": "Sentinel: no longer found: %s." % rec["title"]})

    def _notify(self, rec):
        """One macOS notification per finding, a few per hour at most. Title and severity only, never a path."""
        if not self.cfg.notify or rec.get("notifiedAt"):
            return False
        now = time.time()
        with self.lock:
            recent = [t for t in self.notified if now - t < 3600]
            if len(recent) >= NOTIFY_PER_HOUR:
                return False
            self.notified.append(now)
        self.store.update(rec["id"], lambda r: r.update(notifiedAt=C.now_iso()))
        # The texts travel as arguments to a fixed script: nothing from a finding is ever AppleScript source.
        script = ["-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run"]
        self.cfg.run(["/usr/bin/osascript"] + script + ["Home Observability Hub: %s threat" % rec["severity"], U.clean(rec["title"], 120)], timeout=10)
        return True

    # -- what the API serves
    def scanners_doc(self):
        st = self.store.status().get("scanners") or {}
        counts = self.store.open_counts()
        with self.lock:
            running = set(self.running)
        out = collections.OrderedDict()
        for name in self.names():
            s = st.get(name) or {}
            d = self.meta(name)
            d.update({"lastRun": s.get("lastRun"), "durationMs": s.get("durationMs"), "ok": s.get("ok"), "error": s.get("error"),
                      "itemsScanned": s.get("itemsScanned"), "open": counts.get(name, 0),
                      "running": name in running or bool(s.get("running")),
                      "progress": s.get("progress"), "notChecked": s.get("notChecked") or [], "detail": s.get("detail")})
            out[name] = d
        return out

    def last_scan(self):
        runs = [s.get("lastRun") for s in (self.store.status().get("scanners") or {}).values() if s.get("lastRun")]
        return max(runs) if runs else None
