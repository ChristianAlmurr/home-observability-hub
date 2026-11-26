#!/usr/bin/env python3
"""Home Observability Hub server. Python 3 standard library only (3.9+).

    python3 server.py            # 127.0.0.1:8799, or HM_PORT

Serves ui/ and the /api/* routes in docs/CONTRACT.md. Collectors run in a
background thread and write data/state/live.json; request handlers only read
files. Never binds anything but 127.0.0.1.
"""
import json
import mimetypes
import os
import re
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import collectors as C  # noqa: E402
import agent_runner as A  # noqa: E402
import identify as I  # noqa: E402
import router as R  # noqa: E402
import actions as X  # noqa: E402
import reporters as RP  # noqa: E402
import sentinel as S  # noqa: E402
import sentinel.api as SA  # noqa: E402
import site_config as SITE  # noqa: E402

VERSION = "0.2.0"
HOST = "127.0.0.1"
MAX_BODY = 64 * 1024
UI_DIR = os.path.join(ROOT, "ui")
PLACEHOLDER = b"<!doctype html><meta charset=utf-8><title>Home Observability Hub</title><p>Home Observability Hub is running. The interface is not built yet.</p>\n"
CTYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
          ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".json": "application/json; charset=utf-8",
          ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".ico": "image/x-icon",
          ".woff2": "font/woff2", ".woff": "font/woff", ".ttf": "font/ttf", ".otf": "font/otf", ".txt": "text/plain; charset=utf-8",
          ".md": "text/markdown; charset=utf-8", ".map": "application/json"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def knowledge_dir():
    return A.knowledge_dir()


# ================================================================ settings

# routerWrites: until the person switches it on, block and unblock only rehearse (they return the commands, send nothing).
DEFAULT_SETTINGS = {"agentMode": "advise", "scanning": True, "scanIntervalSec": 30, "agentModel": "claude-opus-5-5",
                    "routerWrites": False}


class Settings:
    def __init__(self):
        self.lock = threading.Lock()

    @property
    def path(self):
        return os.path.join(C.state_dir(), "settings.json")

    def get(self):
        with self.lock:
            s = dict(DEFAULT_SETTINGS)
            try:
                with open(self.path) as f:
                    d = json.load(f)
                if isinstance(d, dict):
                    s.update({k: v for k, v in d.items() if k in DEFAULT_SETTINGS})
            except (OSError, ValueError):
                pass
            return s

    def update(self, body):
        if not isinstance(body, dict):
            raise ValueError("body must be an object")
        extra = [k for k in body if k not in DEFAULT_SETTINGS]
        if extra:
            raise ValueError("unknown settings: %s" % ", ".join(extra))
        s = self.get()
        if "agentMode" in body:
            if body["agentMode"] not in ("advise", "approve", "paused"):
                raise ValueError("agentMode must be advise, approve or paused")
            s["agentMode"] = body["agentMode"]
        if "scanning" in body:
            if not isinstance(body["scanning"], bool):
                raise ValueError("scanning must be true or false")
            s["scanning"] = body["scanning"]
        if "routerWrites" in body:
            if not isinstance(body["routerWrites"], bool):
                raise ValueError("routerWrites must be true or false")
            s["routerWrites"] = body["routerWrites"]
        if "scanIntervalSec" in body:
            v = body["scanIntervalSec"]
            if isinstance(v, bool) or not isinstance(v, int) or not 10 <= v <= 3600:
                raise ValueError("scanIntervalSec must be a whole number from 10 to 3600")
            s["scanIntervalSec"] = v
        if "agentModel" in body:
            v = body["agentModel"]
            if not isinstance(v, str) or not re.match(r"^[A-Za-z0-9][A-Za-z0-9.\-_\[\]]{1,63}$", v):
                raise ValueError("agentModel is not a valid model name")
            s["agentModel"] = v
        with self.lock:
            C.write_json_atomic(self.path, s)
        return s


SETTINGS = Settings()


# ================================================================ audit / files

def audit(actor, type, runId=None, actionId=None, command=None, decision=None, exitCode=None, summary=None):
    row = {"ts": C.now_iso(), "actor": actor, "type": type, "runId": runId, "actionId": actionId,
           "command": command, "decision": decision, "exitCode": exitCode, "summary": summary}
    try:
        C.append_jsonl(os.path.join(C.state_dir(), "audit.jsonl"), row)
    except OSError:
        pass


def read_jsonl_tail(path, limit, pred=None):
    """Newest first, at most `limit` rows."""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 4 * 1024 * 1024))
            data = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    out = []
    for line in reversed(data.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if pred is None or pred(row):
            out.append(row)
            if len(out) >= limit:
                break
    return out


def read_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def knowledge_for(did):
    kd = knowledge_dir()
    specs = read_json(os.path.join(kd, did + ".specs.json"))
    guide = None
    try:
        with open(os.path.join(kd, did + ".md")) as f:
            guide = f.read()
    except OSError:
        pass
    return specs, guide


def live_doc():
    d = read_json(os.path.join(C.state_dir(), "live.json"))
    if not isinstance(d, dict):
        d = {"ts": None, "devices": {}, "links": {}, "strangers": [], "summary": {"online": 0, "offline": 0, "unknown": 0}}
    if SENTINEL is not None and isinstance(d.get("summary"), dict):
        # Read from Sentinel's store as live is served, so it changes the moment a finding does.
        try:
            d["summary"]["threats"] = SA.live_summary(SENTINEL)
        except Exception:
            pass
    return d


# ================================================================ the house: site, layout, setup

def site_doc():
    """GET /api/site: site_config.public() plus the problems found reading data/site.json."""
    _, problems = SITE.load()
    return dict(SITE.public(), problems=problems)


def layout_doc():
    """GET /api/layout: data/layout.json (or HM_LAYOUT) as written, plus `problems`. {} plus problems when missing or broken."""
    layout, problems = SITE.load_layout()
    return dict(layout, problems=problems)


def knowledge_files():
    try:
        return len([n for n in os.listdir(knowledge_dir())
                    if (n.endswith(".md") or n.endswith(".specs.json")) and n.lower() != "readme.md"])
    except OSError:
        return 0


def setup_doc():
    """GET /api/setup: how far onboarding has come. Reads files only; never probes the network or the router."""
    site, _ = SITE.load()
    inv = C.load_inventory()
    rtype = SITE.router_type()
    snap = read_json(os.path.join(C.state_dir(), "router.json"), {}) or {}
    reachable = None
    if rtype == "asuswrt" and (snap.get("ts") or snap.get("lastRun")):
        reachable = bool(snap.get("ok"))
    layout, lprobs = SITE.load_layout()
    return {"siteConfigured": bool(site.get("configured")),
            "inventoryDevices": len(inv.get("devices") or []),
            "layoutPresent": os.path.isfile(SITE.layout_path()) and not lprobs,
            "knowledgeFiles": knowledge_files(),
            "routerType": rtype,
            "routerReachable": reachable,
            "haConfigured": bool(SITE.ha_url()) and SITE.ha_token() is not None,
            "claudeCli": (SITE._tilde(SITE.claude_cli()) if SITE.claude_cli() else None)}


def action_context():
    return X.Context(MONITOR, runs=RUNS, audit=audit, settings=SETTINGS.get)


def router_doc():
    """GET /api/router: what the collectors last read, with each client tied to its device. No secrets."""
    snap = read_json(os.path.join(C.state_dir(), "router.json"), {}) or {}
    status = MONITOR.router.status() if MONITOR else {"configured": False, "ok": False, "error": None, "lastRun": None, "transport": None}
    by_mac = {}
    for did, a in (I.load_picture().get("addresses") or {}).items():
        for m in a.get("macs") or []:
            by_mac.setdefault(m, did)
    clients = [dict(c, deviceId=by_mac.get(c["mac"])) for c in snap.get("clients") or []]
    nodes = [dict(n, deviceId=by_mac.get(n["mac"])) for n in snap.get("nodes") or []]
    return {"configured": status["configured"], "ok": bool(snap.get("ok")) and status["configured"],
            "error": status.get("error") or snap.get("error"), "lastRun": snap.get("ts") or status.get("lastRun"),
            "transport": status.get("transport"), "stale": bool(snap.get("stale")),
            "model": snap.get("model"), "firmware": snap.get("firmware"), "clients": clients, "nodes": nodes,
            "ssids": snap.get("ssids") or {}, "posture": snap.get("posture") or {},
            "blockList": [dict(b, deviceId=by_mac.get(b["mac"]) or I.host_id(b.get("ip") if b.get("online") else None, b["mac"]))
                          for b in snap.get("blockList") or []],
            "sshKey": R.ssh_available(), "webLogin": R.keychain_account() is not None,
            "type": SITE.router_type(), "enabled": R.enabled(),
            # False: block and unblock only rehearse. It takes router.writes in data/site.json and routerWrites in settings.
            "siteWrites": SITE.router_writes(),
            "routerWrites": SETTINGS.get().get("routerWrites") is True and SITE.router_writes() and os.environ.get("HM_ROUTER_DRY_RUN") != "1"}


def router_login(body):
    """Test the login against the router, then store it in the Keychain. The password is never logged or returned."""
    if not R.enabled():
        return {"ok": False, "error": "Router reading is not set up: set router.type to asuswrt in data/site.json first."}
    user, pw = body.get("username"), body.get("password")
    if not isinstance(user, str) or not isinstance(pw, str) or not user.strip() or not pw:
        return {"ok": False, "error": "Give the router's username and password."}
    try:
        info = MONITOR.router.test_login(user.strip(), pw)
        R.keychain_set(user.strip(), pw)
    except R.RouterError as e:
        audit("person", "router-login", decision="failed", exitCode=1, summary=str(e)[:200])
        return {"ok": False, "error": str(e)}
    finally:
        del pw
    audit("person", "router-login", decision="stored", exitCode=0, summary="router login for %s tested and stored in the Keychain" % user.strip()[:40])
    MONITOR.router.last_poll = 0.0
    MONITOR.wake.set()
    return dict({"ok": True}, **info)


# ================================================================ HTTP

MONITOR = None
SENTINEL = None
RUNS = None
PORT = None


class Handler(BaseHTTPRequestHandler):
    server_version = "HomeObservabilityHub/" + VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if os.environ.get("HM_QUIET"):
            return
        sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), fmt % args))

    # -- helpers
    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _err(self, code, text):
        self._send(code, {"error": text})

    def _allowed_hosts(self):
        port = self.server.server_address[1]
        hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}
        # Extra names this server may be reached by, for example the tailnet name that
        # `tailscale serve` forwards from. Off unless HM_ALLOWED_HOSTS names them.
        hosts.update(h.strip() for h in (os.environ.get("HM_ALLOWED_HOSTS") or "").split(",") if h.strip())
        try:
            hosts.update(h.strip() for h in (SITE.get().get("server") or {}).get("allowedHosts") or [] if isinstance(h, str) and h.strip())
        except Exception:
            pass
        return hosts

    def _host_ok(self):
        return (self.headers.get("Host") or "") in self._allowed_hosts()

    def _post_ok(self):
        if self.headers.get("X-House-Monitor") != "1":
            return False
        if not self._host_ok():
            return False
        origin = self.headers.get("Origin")
        if origin is not None:
            u = urllib.parse.urlsplit(origin)
            if u.scheme not in ("http", "https") or u.netloc not in self._allowed_hosts():
                return False
        return True

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0:
            raise ValueError("bad Content-Length")
        if n > MAX_BODY:
            raise OverflowError()
        raw = self.rfile.read(n) if n else b""
        if not raw.strip():
            return {}
        return json.loads(raw.decode("utf-8"))

    def _limit(self, q, default, cap):
        try:
            return max(1, min(cap, int((q.get("limit") or [default])[0])))
        except ValueError:
            return default

    # -- verbs
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        path, q = u.path, urllib.parse.parse_qs(u.query)
        if path.startswith("/api/"):
            if not self._host_ok():
                return self._err(403, "wrong Host")
            try:
                return self.api_get(path, q)
            except BrokenPipeError:
                return
            except Exception as e:
                return self._err(500, "%s: %s" % (type(e).__name__, e))
        return self.static(path)

    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        if not u.path.startswith("/api/"):
            return self._err(404, "not found")
        if not self._post_ok():
            return self._err(403, "POST needs the X-House-Monitor: 1 header and this server's own Origin/Host")
        try:
            body = self._body()
        except OverflowError:
            return self._err(413, "body larger than 64 KB")
        except ValueError:
            return self._err(400, "body is not JSON")
        if not isinstance(body, dict):
            return self._err(400, "body must be a JSON object")
        try:
            return self.api_post(u.path, body)
        except A.AgentError as e:
            return self._err(e.status, e.text)
        except Exception as e:
            return self._err(500, "%s: %s" % (type(e).__name__, e))

    def do_PUT(self):
        self._err(405, "method not allowed")

    do_DELETE = do_PATCH = do_PUT

    # -- API
    def api_get(self, path, q):
        if path == "/api/health":
            h = dict(MONITOR.health) if MONITOR else {}
            return self._send(200, {"ok": all(v.get("ok") for v in h.values()) if h else False,
                                    "version": VERSION, "collectors": h})
        if path == "/api/inventory":
            inv = I.served_inventory()
            for d in inv.get("devices") or []:
                specs, guide = knowledge_for(d["id"])
                d["knowledge"] = specs
                d["hasGuide"] = guide is not None
            return self._send(200, inv)
        m = re.match(r"^/api/device/([^/]+)/actions$", path)
        if m:
            did = urllib.parse.unquote(m.group(1))
            ctx = action_context()
            dev, inv = ctx.device(did) if ID_RE.match(did) else (None, None)
            if dev is None:
                return self._err(404, "no such device")
            return self._send(200, X.describe(ctx, dev, inv))
        if path == "/api/router":
            return self._send(200, router_doc())
        if path == "/api/site":
            return self._send(200, site_doc())
        if path == "/api/layout":
            return self._send(200, layout_doc())
        if path == "/api/setup":
            return self._send(200, setup_doc())
        m = re.match(r"^/api/device/([^/]+)$", path)
        if m:
            did = urllib.parse.unquote(m.group(1))
            if not ID_RE.match(did):
                return self._err(404, "no such device")
            inv = I.served_inventory()
            dev = next((d for d in inv.get("devices") or [] if d["id"] == did), None)
            if dev is None:
                return self._err(404, "no such device")
            live = live_doc()
            specs, guide = knowledge_for(did)
            links = []
            for l in inv.get("links") or []:
                if did in (C.parse_end(l.get("from"))[0], C.parse_end(l.get("to"))[0]):
                    links.append(dict(l, live=(live.get("links") or {}).get(l["id"])))
            lids = {l["id"] for l in links}
            events = read_jsonl_tail(os.path.join(C.state_dir(), "events.jsonl"), 50,
                                     lambda r: r.get("device") == did or r.get("link") in lids)
            return self._send(200, {"device": dev, "knowledge": {"specs": specs, "guideMarkdown": guide},
                                    "live": (live.get("devices") or {}).get(did), "links": links, "events": events})
        if path == "/api/threats":
            try:
                return self._send(200, SA.threats_doc(SENTINEL, *[(q.get(k) or [None])[0] or None for k in ("state", "severity", "scanner")]))
            except SA.ActionError as e:
                return self._err(e.status, e.text)
        m = re.match(r"^/api/threats/([^/]+)$", path)
        if m:
            doc = SA.finding_doc(SENTINEL, m.group(1))
            if doc is None:
                return self._err(404, "no such finding")
            return self._send(200, doc)
        if path == "/api/live":
            return self._send(200, live_doc())
        if path == "/api/events":
            return self._send(200, read_jsonl_tail(os.path.join(C.state_dir(), "events.jsonl"), self._limit(q, 100, 1000)))
        if path == "/api/audit":
            return self._send(200, read_jsonl_tail(os.path.join(C.state_dir(), "audit.jsonl"), self._limit(q, 100, 1000)))
        if path == "/api/settings":
            return self._send(200, SETTINGS.get())
        if path == "/api/reporters":
            return self._send(200, RP.listing(C.load_inventory()))
        if path == "/api/agent/runs":
            return self._send(200, RUNS.list(self._limit(q, 20, 200)))
        m = re.match(r"^/api/agent/run/([^/]+)(/stream)?$", path)
        if m:
            rec = RUNS.get(m.group(1))
            if rec is None:
                return self._err(404, "no such run")
            if m.group(2):
                return self.stream(rec)
            return self._send(200, rec)
        return self._err(404, "not found")

    def api_post(self, path, body):
        if path == "/api/reporters":
            did = str(body.get("device") or "")
            if body.get("remove"):
                had = RP.remove(did)
                audit("person", "reporter", summary="stopped taking socket reports from %s" % did)
                return self._send(200, {"removed": had})
            try:
                out = RP.add(did, C.load_inventory())
            except ValueError as e:
                return self._err(400, str(e))
            audit("person", "reporter", summary="%s may now report its own sockets" % did)
            return self._send(200, out)
        if path == "/api/settings":
            try:
                s = SETTINGS.update(body)
            except ValueError as e:
                return self._err(400, str(e))
            audit("person", "settings", summary=json.dumps(body)[:300])
            if MONITOR:
                MONITOR.wake.set()
            return self._send(200, s)
        m = re.match(r"^/api/device/([^/]+)/action$", path)
        if m:
            did = urllib.parse.unquote(m.group(1))
            if not ID_RE.match(did):
                return self._err(404, "no such device")
            try:
                return self._send(200, X.perform(action_context(), did, body))
            except X.ActionError as e:
                return self._err(e.status, e.text)
        if path == "/api/threats/scan":
            try:
                if not SENTINEL.enabled:
                    return self._err(409, "Sentinel is switched off on this server (HM_SENTINEL=0).")
                return self._send(200, SA.start_scan(SENTINEL, body))
            except SA.ActionError as e:
                return self._err(e.status, e.text)
        if path == "/api/threats/bulk":
            try:
                return self._send(200, SA.perform_bulk(SENTINEL, body, audit))
            except SA.ActionError as e:
                return self._err(e.status, e.text)
        m = re.match(r"^/api/threats/([^/]+)/action$", path)
        if m:
            try:
                return self._send(200, SA.perform(SENTINEL, m.group(1), body, audit))
            except SA.ActionError as e:
                return self._err(e.status, e.text)
        if path == "/api/router/login":
            return self._send(200, router_login(body))
        if path == "/api/router/logout":
            gone = R.keychain_delete()
            audit("person", "router-logout", summary="router login removed from the Keychain" if gone else "no router login was stored")
            if MONITOR:
                MONITOR.router.last_poll = 0.0
                MONITOR.wake.set()
            return self._send(200, {"ok": True, "removed": gone})
        if path == "/api/agent/ask":
            run_id, thread_id = RUNS.ask(body.get("message"), body.get("deviceIds") or [], body.get("threadId"))
            return self._send(200, {"runId": run_id, "threadId": thread_id})
        m = re.match(r"^/api/agent/run/([^/]+)/cancel$", path)
        if m:
            stopped = RUNS.cancel(m.group(1))
            return self._send(200, {"ok": True, "stopped": stopped})
        m = re.match(r"^/api/agent/action/([^/]+)/decide$", path)
        if m:
            r = RUNS.decide(m.group(1), body.get("decision"))
            return self._send(200, r)
        return self._err(404, "not found")

    def stream(self, rec):
        """Server-sent events. Replays from the start, or from Last-Event-ID."""
        try:
            after = int(self.headers.get("Last-Event-ID") or 0)
        except ValueError:
            after = 0
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        deadline = time.time() + 1800
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            while time.time() < deadline:
                evs, open_ = RUNS.wait_events(rec["runId"], after, timeout=15)
                for e in evs:
                    data = json.dumps(e["data"], ensure_ascii=False)
                    self.wfile.write(("id: %d\nevent: %s\ndata: %s\n\n" % (e["seq"], e["type"], data)).encode("utf-8"))
                    after = e["seq"]
                if not evs:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
                if not open_ and not evs:
                    break
                if not open_:
                    # Drain anything that arrived with the last batch, then stop.
                    more, _ = RUNS.wait_events(rec["runId"], after, timeout=0)
                    if not more:
                        break
        except (BrokenPipeError, ConnectionResetError):
            pass

    # -- static
    def static(self, path):
        path = urllib.parse.unquote(path)
        if "\x00" in path or ".." in path.split("/") or "\\" in path:
            return self._err(404, "not found")
        if not os.path.exists(os.path.join(UI_DIR, "index.html")):
            if path in ("/", "/index.html") or not os.path.splitext(path)[1]:
                return self._send(200, PLACEHOLDER, "text/html; charset=utf-8")
            return self._err(404, "not found")
        rel = path.lstrip("/") or "index.html"
        full = os.path.realpath(os.path.join(UI_DIR, rel))
        ui = os.path.realpath(UI_DIR)
        if not (full == ui or full.startswith(ui + os.sep)):
            return self._err(404, "not found")
        if os.path.isdir(full):
            full = os.path.join(full, "index.html")
        if not os.path.isfile(full):
            if os.path.splitext(rel)[1]:
                return self._err(404, "not found")
            full = os.path.join(ui, "index.html")      # client-side route
        ext = os.path.splitext(full)[1].lower()
        ctype = CTYPES.get(ext) or mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as f:
            data = f.read()
        return self._send(200, data, ctype)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(port, start_collectors=True):
    global MONITOR, RUNS, PORT, SENTINEL
    os.makedirs(os.path.join(C.state_dir(), "runs"), exist_ok=True)
    RUNS = A.Runs(SETTINGS.get, inventory_fn=I.served_inventory, audit_fn=audit)
    n = RUNS.recover()
    if n:
        sys.stderr.write("marked %d run(s) left running as interrupted\n" % n)
    srv = Server((HOST, port), Handler)      # bind first: a taken port fails before anything runs
    PORT = srv.server_address[1]
    MONITOR = C.Monitor(settings_fn=SETTINGS.get)
    MONITOR.specs_fn = lambda did: knowledge_for(did)[0]
    SENTINEL = S.Engine(cfg=S.Config(monitor=MONITOR))
    if start_collectors:
        MONITOR.start()
        err = RP.start(MONITOR)
        if err:
            sys.stderr.write("socket reports: %s\n" % err)
        SENTINEL.start()        # no-op when HM_SENTINEL=0
    return srv


def main():
    try:
        site_port = int((SITE.get().get("server") or {}).get("port") or 8799)
    except (TypeError, ValueError):
        site_port = 8799
    port = int(os.environ.get("HM_PORT") or site_port)
    srv = make_server(port, start_collectors=os.environ.get("HM_NO_COLLECTORS") != "1")
    sys.stderr.write("Home Observability Hub on http://%s:%d\n" % (HOST, srv.server_address[1]))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
