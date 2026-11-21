"""Other computers reporting their own sockets.

The computer the hub runs on can read its own sockets. A cable plugged into another computer is only visible to that computer,
so it runs portscan.py and sends the reading here. This module keeps who may report (one token per computer,
in data/state/reporters.json, never served back) and runs the small listener they send to.

The main server stays on 127.0.0.1. This listener is the only thing on the LAN: it starts only once a computer
has been added, answers two paths (GET /portscan.py, POST /report), needs the computer's token for a report,
and what comes in is cut down to the expected shape before anything reads it.
"""
import hmac
import json
import os
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import collectors as C
import site_config as SITE

ROOT = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("HM_REPORT_PORT") or 8798)
MAX_BODY = 256 * 1024
LOCK = threading.Lock()
_srv = None
_monitor = None


def path():
    return os.path.join(C.state_dir(), "reporters.json")


def _load():
    try:
        with open(path()) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(d):
    C.write_json_atomic(path(), d)
    try:
        os.chmod(path(), 0o600)
    except OSError:
        pass


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((C.router_ip(), 9))      # no packet is sent: this only asks which address would be used
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def url():
    ip = lan_ip()
    return "http://%s:%d" % (ip, PORT) if ip else None


def command(token, loop=True):
    base = url() or "http://<this Mac's address>:%d" % PORT
    return ("curl -s %s/portscan.py -o ~/portscan.py && python3 ~/portscan.py --post %s/report --token %s%s"
            % (base, base, token, " --loop 20" if loop else ""))


def listing(inv):
    """Who reports, without the tokens."""
    import wiring
    hosts = (wiring.load_state(C.state_dir()).get("hosts") or {})
    names = {d["id"]: d.get("name", d["id"]) for d in inv.get("devices") or []}
    reg = _load()
    out = []
    for did, r in sorted(reg.items()):
        h = hosts.get(did) or {}
        out.append({"device": did, "name": names.get(did, did), "added": r.get("added"),
                    "lastReport": h.get("ts") if h.get("source") == "report" else None,
                    "ageSec": int(time.time() - h["epoch"]) if h.get("source") == "report" and h.get("epoch") else None,
                    "computer": h.get("computer") if h.get("source") == "report" else None})
    host = SITE.host_device(inv)
    hands = set(SITE.hands_off_ids())
    # "work": a hands-off computer (data/site.json); the UI says so before offering the command to run on it.
    can = [{"device": d["id"], "name": d.get("name", d["id"]), "work": d["id"] in hands}
           for d in inv.get("devices") or []
           if d.get("kind") == "computer" and d["id"] != host and d["id"] not in reg and not d.get("dynamic")]
    return {"reporters": out, "candidates": can, "listening": _srv is not None, "url": url()}


def add(device_id, inv):
    if not any(d["id"] == device_id and d.get("kind") == "computer" for d in inv.get("devices") or []) or device_id == SITE.host_device(inv):
        raise ValueError("not a computer in the inventory that can report")
    token = secrets.token_urlsafe(24)
    with LOCK:
        reg = _load()
        reg[device_id] = {"token": token, "added": C.now_iso()}
        _save(reg)
    ensure_listener()
    return {"device": device_id, "command": command(token), "once": command(token, loop=False)}


def remove(device_id):
    import wiring
    with LOCK:
        reg = _load()
        had = reg.pop(device_id, None) is not None
        _save(reg)
    if had:
        with wiring.LOCK:
            st = wiring.load_state(C.state_dir())
            if (st.get("hosts") or {}).pop(device_id, None) is not None:
                wiring.save_state(C.state_dir(), st)
        if _monitor:
            _monitor.wake.set()
    return had


def who(token):
    if not token:
        return None
    for did, r in _load().items():
        if hmac.compare_digest(str(r.get("token") or ""), token):
            return did
    return None


def clean(v, depth=0):
    """Cut an incoming reading down: bounded depth, list length and string length, plain JSON types only."""
    if depth > 5:
        return None
    if isinstance(v, dict):
        return {str(k)[:40]: clean(x, depth + 1) for k, x in list(v.items())[:40]}
    if isinstance(v, list):
        return [clean(x, depth + 1) for x in v[:96]]
    if isinstance(v, str):
        return "".join(ch for ch in v[:120] if ch.isprintable())
    if isinstance(v, (bool, int, float)) or v is None:
        return v
    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "HomeObservabilityHubReport"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/portscan.py":
            with open(os.path.join(ROOT, "portscan.py"), "rb") as f:
                return self._send(200, f.read(), "text/x-python")
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/report":
            return self._send(404, {"error": "not found"})
        did = who(self.headers.get("X-Report-Token"))
        if did is None:
            return self._send(403, {"error": "unknown token"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n <= 0 or n > MAX_BODY:
            return self._send(413, {"error": "body missing or larger than 256 KB"})
        try:
            obs = json.loads(self.rfile.read(n).decode("utf-8", "replace"))
        except ValueError:
            return self._send(400, {"error": "body is not JSON"})
        if not isinstance(obs, dict):
            return self._send(400, {"error": "body must be an object"})
        try:
            _monitor.report(did, clean(obs))
        except Exception as e:
            return self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})
        self._send(200, {"ok": True, "device": did})


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def ensure_listener():
    """Start the LAN listener if a computer has been added and it is not running. Returns an error text or None."""
    global _srv
    with LOCK:
        if _srv is not None or _monitor is None or not _load():
            return None
        ip = lan_ip()
        if not ip:
            return "this Mac has no address on the home network"
        try:
            _srv = _Server((ip, PORT), Handler)
        except OSError as e:
            return "could not listen on %s:%d: %s" % (ip, PORT, e)
        threading.Thread(target=_srv.serve_forever, name="reports", daemon=True).start()
        return None


def start(monitor):
    global _monitor
    _monitor = monitor
    if os.environ.get("HM_REPORTS", "1") == "1":
        return ensure_listener()
    return None
