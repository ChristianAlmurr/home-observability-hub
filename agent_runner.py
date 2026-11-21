"""Home Observability Hub fix agent: runs Claude Code headless, translates its stream
into the contract's SSE events, keeps run records, guards and runs actions.

Standard library only, Python 3.9+.
"""
import datetime
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
import uuid

import collectors as C
import site_config as SITE

ROOT = C.ROOT
RUN_TIMEOUT = 600          # a run is stopped after 10 minutes
ACTION_TIMEOUT = 120
MAX_RUNNING = 2
PROBE_RULE = "Bash(python3 bin/probe.py *)"
AGENT_TOOLS = ["Read", "Glob", "Grep", "WebSearch", "WebFetch", "Bash"]
DENIED_TOOLS = ["Edit", "Write", "NotebookEdit", "Agent", "Task"]
PHASE_TEXT = {
    "identify": "Working out which devices this is about",
    "read-docs": "Reading the device guides",
    "inspect": "Checking the live system",
    "research": "Looking things up on the web",
    "answer": "Writing the answer",
}
BLOCK_TYPES = ("text", "steps", "checks", "facts", "compare", "warning")
OUR_LAUNCHD_PREFIX = "com.home-observability-hub"


def now_iso():
    return C.now_iso()


def knowledge_dir():
    return os.environ.get("HM_KNOWLEDGE") or os.environ.get("HM_KNOWLEDGE_DIR") or os.path.join(ROOT, "knowledge")


def claude_bin():
    """HM_CLAUDE_BIN, then `claude` on PATH, then ~/.local/bin, /opt/homebrew/bin, /usr/local/bin. None when not installed."""
    return SITE.claude_cli()


# ================================================================ action guard

def sudo_text():
    return "needs root: %s types this in a terminal" % SITE.owner_or("the person")


_REFUSALS = [
    (r"\bsudo\b|\bdoas\b|(^|[;&|]\s*)su\b|with administrator privileges", None, True),
    (r"\.ssh\b", "touches ~/.ssh", False),
    (r"\.env\b|HASS_TOKEN|\btoken\b", "touches secrets", False),
    (r"\bsecurity\s", "keychain access (security)", False),
    (r"\bdiskutil\b|(^|[\s;&|(])dd\s|\bmkfs|\bnewfs|\bfdisk\b|\bgpt\s|\basr\s", "disk tools are never run from here", False),
    (r"\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|ksh|fish|python3?|perl|ruby|node|osascript)\b",
     "pipes a download into an interpreter", False),
    (r"\|\s*(sh|bash|zsh|dash|ksh|fish)\b", "pipes into a shell", False),
    (r"[$<]\(\s*(curl|wget|fetch)\b", "runs a download", False),
    (r"\beval\b|\bsource\s|(^|[;&|]\s*)\.\s+\S", "eval/source is not allowed", False),
    (r"\.claude\b|CLAUDE\.md", "writes near Claude configuration", False),
    (r"\bssh\b|\bscp\b|\bsftp\b", "remote shells are not run from here", False),
    (r"\.\./", "relative parent paths are not allowed", False),
    (r"(^|[\s'\"=:(])(\./)?(bin|agent)(/|\b)", "touches the monitor's own code", False),
    (r"\b(server|collectors|agent_runner)\.py\b", "touches the monitor's own code", False),
    (r"\bcrontab\b|\bchsh\b|\bdscl\b|\bpasswd\b|\bcsrutil\b|\bnvram\b|\bfdesetup\b|\bspctl\b|\bkextload\b|\bshutdown\b|\breboot\b|\bhalt\b",
     "system administration commands are not run from here", False),
]


def guard_command(command, target, state_dir=None):
    """Hard refusals in code, whatever the model said. Returns
    {"ok": bool, "reason": str|None, "needsSudo": bool}."""
    state_dir = os.path.realpath(state_dir or C.state_dir())
    if not isinstance(command, str) or not command.strip():
        return {"ok": False, "reason": "empty command", "needsSudo": False}
    if len(command) > 2000:
        return {"ok": False, "reason": "command too long", "needsSudo": False}
    if re.search(r"[\x00-\x08\x0b-\x1f\x7f]", command):
        return {"ok": False, "reason": "control characters in the command", "needsSudo": False}
    h = SITE.hands_off_match(target=target)
    if h:
        return {"ok": False, "reason": "%s is hands-off (%s): steps by hand only" % (target, h["why"]), "needsSudo": False}
    for rx, why, sudo in _REFUSALS:
        if re.search(rx, command, re.I if not sudo else 0):
            return {"ok": False, "reason": why or sudo_text(), "needsSudo": sudo}
    for rx, why in site_refusals():
        if re.search(rx, command, re.I):
            return {"ok": False, "reason": why, "needsSudo": False}
    # Deleting: only inside data/state.
    if re.search(r"(^|[\s;&|(])(rm|rmdir|unlink|shred|srm|trash)\b|-delete\b|\bfind\b.*-exec\s+rm", command):
        try:
            toks = shlex.split(command)
        except ValueError:
            return {"ok": False, "reason": "cannot parse a delete command", "needsSudo": False}
        if any(t in ("-delete",) for t in toks) or re.search(r"\bfind\b.*-exec", command):
            return {"ok": False, "reason": "find -delete/-exec is not allowed", "needsSudo": False}
        i = 0
        seen_rm = False
        while i < len(toks):
            if toks[i] in ("rm", "rmdir", "unlink", "shred", "srm", "trash") or toks[i].endswith("/rm"):
                seen_rm = True
                j = i + 1
                while j < len(toks) and toks[j] not in (";", "&&", "||", "|"):
                    a = toks[j]
                    if not a.startswith("-"):
                        if re.search(r"[*?$`~{}\[\]]", a):
                            return {"ok": False, "reason": "deletes with wildcards or variables are not allowed", "needsSudo": False}
                        p = os.path.realpath(os.path.join(state_dir, a))
                        if not (p == state_dir or p.startswith(state_dir + os.sep)) or p == state_dir:
                            return {"ok": False, "reason": "deleting outside data/state", "needsSudo": False}
                    j += 1
                i = j
            else:
                i += 1
        if not seen_rm:
            return {"ok": False, "reason": "unrecognised delete command", "needsSudo": False}
    # launchctl: only our own jobs may be stopped.
    m = re.search(r"\blaunchctl\s+(unload|bootout|remove|disable|kill|stop)\b(.*)", command)
    if m and OUR_LAUNCHD_PREFIX not in m.group(2):
        return {"ok": False, "reason": "launchctl may only stop Home Observability Hub's own jobs", "needsSudo": False}
    # Writes into the project outside data/state.
    for pm in re.finditer(re.escape(ROOT) + r"(/[^\s'\"]*)?", command):
        rest = pm.group(1) or ""
        if not rest.startswith("/data/state"):
            return {"ok": False, "reason": "touches the monitor's own files", "needsSudo": False}
    # The folder's name anywhere (a copy, a relative path), but not our own launchd labels (com.home-observability-hub.*).
    # Matched as a whole path component, so a short folder name ("hub", "c") never refuses "github" or "echo".
    if re.search(r"(?:^|[\s'\"=:/])" + re.escape(os.path.basename(ROOT)) + r"(?=$|[\s'\"/])(?!/data/state)", command):
        return {"ok": False, "reason": "touches the monitor's own files", "needsSudo": False}
    return {"ok": True, "reason": None, "needsSudo": False}


_END = r"(?![A-Za-z0-9_.-])"


def site_refusals():
    """[(regex, reason)] from data/site.json: the secret folders, and every hands-off device by id, address and name."""
    out = []
    for raw in SITE.secret_dirs_raw():
        rel = raw[2:] if raw.startswith("~/") else raw
        pats = [re.escape(os.path.expanduser(raw)) + _END]
        if raw.startswith("~/"):
            pats.append(r"~/" + re.escape(rel) + _END)
            pats.append(r"\$HOME/" + re.escape(rel) + _END)
            if rel.startswith("."):
                pats.append(r"(^|[\s'\"=:/])" + re.escape(rel) + _END)
        out.append(("|".join(pats), "touches %s" % raw))
    try:
        inv = C.load_inventory()
    except Exception:
        inv = {}
    ids, ips, names = SITE.hands_off_all(inv)
    toks = [re.escape(i) + _END for i in sorted(ids)] + [re.escape(i) + r"(?![0-9])" for i in sorted(ips)] + \
        [re.escape(n) + r"(?![A-Za-z0-9_-])" for n in sorted(names) if len(n) >= 4]
    if toks:
        out.append((r"(?<![A-Za-z0-9_.-])(" + "|".join(toks) + ")", "targets a hands-off device"))
    return out


# ================================================================ answer parsing

def extract_json(text):
    """The outermost JSON object in the model's final text, or None.
    Handles code fences and prose around the object."""
    if not isinstance(text, str):
        return None
    t = text.strip()
    cands = [t]
    for m in re.finditer(r"```(?:json|JSON)?\s*\n?(.*?)```", t, re.S):
        cands.insert(0, m.group(1).strip())
    for c in cands:
        try:
            v = json.loads(c)
            if isinstance(v, dict):
                return v
        except ValueError:
            pass
    dec = json.JSONDecoder()
    best, best_len = None, -1
    starts = [i for i, ch in enumerate(t) if ch == "{"][:200]
    for i in starts:
        try:
            v, end = dec.raw_decode(t, i)
        except ValueError:
            continue
        if isinstance(v, dict) and end - i > best_len:
            best, best_len = v, end - i
    return best


def fallback_answer(raw, subjects):
    return {"title": "Answer", "verdict": "", "confidence": "low", "subjects": list(subjects or []),
            "blocks": [{"type": "text", "markdown": raw or "(no answer)"}], "actions": [], "sources": [],
            "unknowns": ["The agent's reply was not in the expected format, so it is shown as plain text."],
            "parsed": False}


def _s(v, n=4000):
    return v[:n] if isinstance(v, str) else ("" if v is None else str(v)[:n])


def normalize_answer(doc, inventory, run_id, requested=None, state_dir=None):
    """Validate ids against the inventory, give actions global ids and run the
    guard. Unknown ids go to `unknowns`; nothing is trusted as-is."""
    dev_ids = {d["id"] for d in inventory.get("devices") or []}
    link_ids = {l["id"] for l in inventory.get("links") or []}
    unknowns = [_s(u, 600) for u in (doc.get("unknowns") or []) if isinstance(u, (str, int, float))]
    bad = []

    def dev(x):
        if isinstance(x, str) and x in dev_ids:
            return x
        if x not in (None, ""):
            bad.append(str(x)[:80])
        return None

    out = {"title": _s(doc.get("title"), 200) or "Answer", "verdict": _s(doc.get("verdict"), 2000),
           "confidence": doc.get("confidence") if doc.get("confidence") in ("high", "medium", "low") else "low"}
    out["subjects"] = [x for x in (dev(s) for s in (doc.get("subjects") or [])) if x]
    if not out["subjects"] and requested:
        out["subjects"] = [d for d in requested if d in dev_ids]
    p = doc.get("path")
    if isinstance(p, dict):
        links = [l for l in p.get("links") or [] if isinstance(l, str)]
        for l in links + [l for l in p.get("suspect") or [] if isinstance(l, str)]:
            if l not in link_ids:
                bad.append(l[:80])
        out["path"] = {"links": [l for l in links if l in link_ids],
                       "suspect": [l for l in p.get("suspect") or [] if isinstance(l, str) and l in link_ids],
                       "note": _s(p.get("note"), 600)}
    blocks = []
    for b in doc.get("blocks") or []:
        if not isinstance(b, dict) or b.get("type") not in BLOCK_TYPES:
            continue
        b = dict(b)
        if isinstance(b.get("items"), list):
            items = []
            for it in b["items"]:
                if isinstance(it, dict):
                    it = dict(it)
                    if "device" in it and dev(it.get("device")) is None:
                        it.pop("device", None)
                    items.append(it)
                elif isinstance(it, str):
                    items.append({"text": it} if b["type"] == "steps" else {"label": it, "value": ""})
            b["items"] = items
        if b["type"] == "warning" and b.get("level") not in ("info", "caution", "danger"):
            b["level"] = "info"
        blocks.append(b)
    out["blocks"] = blocks
    actions = []
    for i, a in enumerate(doc.get("actions") or []):
        if not isinstance(a, dict):
            continue
        local = re.sub(r"[^A-Za-z0-9]", "", str(a.get("id") or "")) or "a%d" % (i + 1)
        target = a.get("target")
        if target not in dev_ids:
            unknowns.append("A proposed action (%s) named a target that is not in the inventory (%s), so it was dropped."
                            % (_s(a.get("label"), 80), _s(target, 60)))
            continue
        act = {"id": "%s-%s" % (run_id, local[:12]), "label": _s(a.get("label"), 200), "why": _s(a.get("why"), 1000),
               "command": a.get("command") if isinstance(a.get("command"), str) else "",
               "target": target, "risk": a.get("risk") if a.get("risk") in ("read", "change", "destructive") else "change",
               "reversible": bool(a.get("reversible")), "undo": _s(a.get("undo"), 2000) or None,
               "needsSudo": bool(a.get("needsSudo"))}
        g = guard_command(act["command"], target, state_dir=state_dir)
        if act["needsSudo"] or g["needsSudo"]:
            act["needsSudo"] = True
            act["state"] = "copy-only"
            act["refusal"] = g["reason"] or sudo_text()
        elif not g["ok"]:
            act["state"] = "refused"
            act["refusal"] = g["reason"]
        else:
            act["state"] = "proposed"
            act["refusal"] = None
        if [x for x in actions if x["id"] == act["id"]]:
            act["id"] += "-%d" % i
        actions.append(act)
    out["actions"] = actions
    srcs = []
    for s in doc.get("sources") or []:
        if isinstance(s, dict):
            s = {"title": _s(s.get("title"), 300), "url": _s(s.get("url"), 1000), "device": dev(s.get("device"))}
            srcs.append({k: v for k, v in s.items() if v})
        elif isinstance(s, str):
            srcs.append({"title": s[:300], "url": s[:1000] if s.startswith("http") else ""})
    out["sources"] = srcs
    for b in sorted(set(bad)):
        unknowns.append("The agent referred to “%s”, which is not an id in the inventory." % b)
    out["unknowns"] = unknowns
    out["parsed"] = True
    return out


# ================================================================ stream translation

def _possessive(name):
    return name + ("'" if name.endswith("s") else "'s")


class Translator:
    """Claude stream-json lines -> contract events [(type, data)]."""

    def __init__(self, inventory):
        self.devs = {d["id"]: d for d in inventory.get("devices") or []}
        self.ip_names = {}
        for d in inventory.get("devices") or []:
            for n in d.get("net") or []:
                if n.get("ip"):
                    self.ip_names[n["ip"]] = d.get("name")
        self.phase = None
        self.session_id = None
        self.last_text = ""
        self.result_text = None
        self.result_error = None
        self.tools = {}           # tool_use_id -> name
        self.tool_log = []        # (tool, text) for the audit

    def _name(self, did):
        """'the UGREEN KVM', 'HomeNAS', "Kim's iPhone": plain words for a device id."""
        d = self.devs.get(did)
        if not d:
            return did
        nm = d.get("name") or did
        if d.get("kind") == "nas" or re.search(r"[’']s\b", nm) or nm.lower().startswith("the "):
            return nm
        return "the " + nm

    def _host(self, h):
        for did, d in self.devs.items():
            if any(n.get("ip") == h for n in d.get("net") or []):
                return self._name(did)
        return h

    def describe(self, tool, inp):
        """(phase, plain-words text, detail)"""
        inp = inp if isinstance(inp, dict) else {}
        if tool == "Read":
            path = str(inp.get("file_path") or "")
            rel = os.path.relpath(path, ROOT) if path.startswith("/") else path
            m = re.match(r"^knowledge/([a-z0-9-]+)\.(md|specs\.json)$", rel)
            if m:
                did = m.group(1)
                return "read-docs", "Reading %s %s" % (_possessive(self._name(did)), "guide" if m.group(2) == "md" else "specs"), rel
            if rel == "data/inventory.json":
                return "identify", "Reading the inventory", rel
            if rel.startswith("data/state/live"):
                return "inspect", "Reading the live status", rel
            if rel.startswith("docs/"):
                return "read-docs", "Reading %s" % rel, rel
            return None, "Reading %s" % rel, rel
        if tool in ("Glob", "Grep"):
            pat = str(inp.get("pattern") or "")
            where = str(inp.get("path") or "")
            ph = "read-docs" if "knowledge" in where or "knowledge" in pat else None
            return ph, ("Searching the knowledge files for “%s”" % pat if ph else "Searching the project for “%s”" % pat), where or None
        if tool == "WebSearch":
            return "research", "Searching the web: %s" % _s(inp.get("query"), 160), None
        if tool == "WebFetch":
            url = str(inp.get("url") or "")
            m = re.match(r"https?://([^/]+)", url)
            return "research", "Reading %s" % (m.group(1) if m else url[:80]), url[:300]
        if tool == "Bash":
            cmd = str(inp.get("command") or "")
            try:
                argv = shlex.split(cmd)
            except ValueError:
                argv = cmd.split()
            if argv[:2] == ["python3", "bin/probe.py"]:
                return "inspect", self.probe_text(argv[2:]), cmd
            return None, "Tried to run a command that is not allowed", cmd[:300]
        if tool == "ToolSearch":
            return None, "Loading a tool", None
        return None, "Using %s" % tool, None

    def probe_text(self, args):
        sub = args[0] if args else ""
        a = args[1:]
        h = self._host(a[0]) if a else ""
        if sub == "--list":
            return "Listing the probes"
        if sub == "live":
            return "Reading the live status of every device"
        if sub == "device":
            return "Checking %s live status" % _possessive(self._name(a[0] if a else "?"))
        if sub == "ping":
            return "Pinging %s" % h
        if sub == "tcp":
            return "Testing port %s on %s" % (a[1] if len(a) > 1 else "?", h)
        if sub == "dns":
            return "Looking up %s in DNS" % h
        if sub == "rdns":
            return "Asking the router what %s is called" % h
        if sub == "route":
            return "Checking which way this Mac reaches %s" % h
        if sub == "interfaces":
            return "Listing the network interfaces"
        if sub == "interface":
            return "Checking the link speed on %s" % (a[0] if a else "?")
        if sub == "service-order":
            return "Checking the network service order"
        if sub == "wifi":
            return "Checking Wi-Fi"
        if sub == "usb":
            return "Listing USB devices"
        if sub == "displays":
            return "Checking the display mode"
        if sub == "thunderbolt":
            return "Checking the Thunderbolt ports"
        if sub == "mdns":
            return "Looking for %s on the network (Bonjour)" % (a[0] if a else "services")
        if sub == "cast":
            return "Asking %s for its details" % h
        if sub == "http-head":
            return "Checking %s" % (a[0] if a else "a web address")
        if sub == "ha-state":
            return "Asking Home Assistant about %s" % (a[0] if a else "?")
        if sub == "ha-states":
            return "Listing Home Assistant %s" % (("%s entities" % a[0]) if a else "entities")
        if sub == "sweep":
            return "Sweeping the network for devices that answer"
        if sub == "nas":
            return "Checking whether the NAS answers"
        if sub == "bluetooth":
            return "Listing this Mac's Bluetooth devices"
        if sub == "ssdp":
            return "Asking devices to announce themselves (UPnP)"
        if sub == "ports":
            return "Checking which common ports are open on %s" % h
        if sub == "identity":
            return "Reading the evidence about %s" % self._name(a[0] if a else "?")
        return "Running the probe: %s" % " ".join(args)[:80]

    def feed(self, j):
        out = []
        t = j.get("type")
        if t == "system" and j.get("subtype") == "init":
            self.session_id = j.get("session_id") or self.session_id
        elif t == "assistant":
            for b in ((j.get("message") or {}).get("content") or []):
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "tool_use":
                    name = b.get("name") or "?"
                    self.tools[b.get("id")] = name
                    ph, text, detail = self.describe(name, b.get("input"))
                    if ph and ph != self.phase:
                        self.phase = ph
                        out.append(("phase", {"phase": ph, "text": PHASE_TEXT[ph]}))
                    act = {"tool": name, "text": text}
                    if detail:
                        act["detail"] = detail
                    out.append(("activity", act))
                    self.tool_log.append((name, text, detail))
                elif b.get("type") == "text" and b.get("text"):
                    self.last_text = b["text"]
        elif t == "user":
            for b in ((j.get("message") or {}).get("content") or []):
                if isinstance(b, dict) and b.get("type") == "tool_result" and b.get("is_error"):
                    name = self.tools.get(b.get("tool_use_id"), "tool")
                    c = b.get("content")
                    if isinstance(c, list):
                        c = " ".join(x.get("text", "") for x in c if isinstance(x, dict))
                    out.append(("activity", {"tool": name, "text": "That was refused or failed",
                                             "detail": _s(c, 300)}))
        elif t == "result":
            self.session_id = j.get("session_id") or self.session_id
            if isinstance(j.get("result"), str) and j["result"].strip():
                self.result_text = j["result"]
            if j.get("is_error") or (j.get("subtype") and j.get("subtype") != "success"):
                errs = j.get("errors") or []
                self.result_error = _s("; ".join(str(e) for e in errs) or j.get("result") or j.get("subtype"), 400)
        return out

    def final_text(self):
        return self.result_text if self.result_text else self.last_text


# ================================================================ prompt

def inventory_summary(inv):
    lines = ["Devices (id | name | kind | model | zone | verified | probe | addresses):"]
    for d in inv.get("devices") or []:
        addrs = ", ".join(filter(None, ["%s%s" % (n.get("ip") or n.get("name") or "", (" on " + n["if"]) if n.get("if") else "")
                                        for n in d.get("net") or []]))
        lines.append("- %s | %s | %s | %s | %s | %s | %s | %s" % (
            d["id"], d.get("name"), d.get("kind"), d.get("model"), d.get("zone"), d.get("verified"),
            (d.get("probe") or {}).get("type"), addrs or "-"))
        for c in d.get("constraints") or []:
            lines.append("    constraint: %s" % c)
    lines.append("")
    lines.append("Links (id | from -> to | cable | speed | verified):")
    for l in inv.get("links") or []:
        lines.append("- %s | %s -> %s | %s | %s | %s" % (l["id"], l.get("from"), l.get("to"), l.get("cable"),
                                                       l.get("speed") or "-", l.get("verified")))
    return "\n".join(lines)


ANSWER_SCHEMA = {
    "title": "Short title", "verdict": "The answer in one or two sentences.", "confidence": "high|medium|low",
    "subjects": ["device-id"],
    "path": {"links": ["link-id"], "suspect": ["link-id"], "note": "why this hop"},
    "blocks": [
        {"type": "text", "markdown": "..."},
        {"type": "steps", "title": "Do this", "items": [{"text": "...", "device": "device-id", "detail": "...", "expect": "what you should see"}]},
        {"type": "checks", "title": "What I checked", "items": [{"label": "...", "value": "...", "ok": True, "source": "python3 bin/probe.py ..."}]},
        {"type": "facts", "title": "From the manual", "items": [{"label": "...", "value": "...", "device": "device-id", "source": "url or knowledge file"}]},
        {"type": "compare", "title": "Options", "columns": ["A", "B"], "rows": [{"label": "...", "values": ["...", "..."]}], "recommended": 0},
        {"type": "warning", "level": "info|caution|danger", "text": "..."},
    ],
    "actions": [{"id": "a1", "label": "...", "why": "...", "command": "exact shell command", "target": "device-id",
                 "risk": "read|change|destructive", "reversible": True, "undo": "exact undo command", "needsSudo": False}],
    "sources": [{"title": "...", "url": "...", "device": "device-id"}],
    "unknowns": ["What could not be established, and what would settle it."],
}


def probe_list():
    rc, out, err = C.run([sys.executable, os.path.join(ROOT, "bin", "probe.py"), "--list"], timeout=10)
    return out.strip() if rc == 0 else "python3 bin/probe.py --list"


def prompt_values(inv):
    """What agent/prompt.md is filled in with: everything that makes it this house, from data/site.json."""
    devs = {d["id"]: d for d in inv.get("devices") or []}
    name = SITE.owner_or("")
    host = SITE.host_device(inv)
    hname = (devs.get(host) or {}).get("name") if host else None
    ho = SITE.hands_off()
    if ho:
        hands = "never propose a command for these and never port-scan them; anything about them is a step the person does by hand, written as a `steps` block: " + \
            "; ".join("`%s` (%s)" % (h["id"], h["why"]) for h in ho) + "."
    else:
        hands = "none are listed in data/site.json."
    return {
        "{{OWNER}}": name or "the person",
        "{{WHO}}": ("%s, who lives here." % name) if name else "The person who lives here.",
        "{{HOME_NAME}}": SITE.home_name() if SITE.home_name() != "Home" else "this home",
        "{{HOST_LINE}}": ("%s (inventory id `%s`)" % (hname or host, host)) if host else "this computer",
        "{{HOST_SHORT}}": ("%s (`%s`)" % (hname or host, host)) if host else "this computer (the one the hub runs on)",
        "{{HANDS_OFF}}": hands,
        "{{SECRET_DIRS}}": ", ".join("`%s`" % p for p in SITE.secret_dirs_raw()),
    }


def build_prompt(inv):
    with open(os.path.join(ROOT, "agent", "prompt.md")) as f:
        tpl = f.read()
    for k, v in prompt_values(inv).items():
        tpl = tpl.replace(k, v)
    return (tpl.replace("{{TODAY}}", datetime.date.today().isoformat())
            .replace("{{PROBE_LIST}}", probe_list())
            .replace("{{INVENTORY_SUMMARY}}", inventory_summary(inv))
            .replace("{{ANSWER_SCHEMA}}", json.dumps(ANSWER_SCHEMA, indent=1)))


def build_message(message, device_ids, inv):
    devs = {d["id"]: d for d in inv.get("devices") or []}
    kd = knowledge_dir()
    lines = ["Request from %s: %s" % (SITE.owner_or("the person"), message.strip()), ""]
    if device_ids:
        lines.append("Devices selected in the app: " + ", ".join("%s (%s)" % (d, devs[d]["name"]) for d in device_ids if d in devs))
        have, missing = [], []
        for d in device_ids:
            for suf in (".md", ".specs.json"):
                (have if os.path.exists(os.path.join(kd, d + suf)) else missing).append("knowledge/%s%s" % (d, suf))
        if have:
            lines.append("Knowledge files present: " + ", ".join(have))
        if missing:
            lines.append("Knowledge files missing: " + ", ".join(missing))
    else:
        lines.append("No devices were selected in the app: work out from the request which ones are meant.")
    lines.append("")
    lines.append("Follow your method (identify, read-docs, inspect, research, answer) and finish with the answer document as one JSON object.")
    return "\n".join(lines)


def claude_argv(model, prompt, resume=None):
    """The exact command line. See the module notes in README-less form:
    - --tools limits the built-in tools that exist at all;
    - --allowedTools pre-approves them, Bash only for probe.py;
    - --permission-mode dontAsk + --permission-prompts none: anything else is denied, never asked;
    - --restricted: user/project settings are ignored and file tools are confined to the repo;
    - the PreToolUse hook (bin/agent_gate.py) denies every Bash command that is not exactly probe.py,
      because Claude Code otherwise auto-approves read-only commands such as ls or cat;
    - --strict-mcp-config with an empty config: no MCP servers, no connectors."""
    cli = claude_bin()
    if not cli:
        raise RuntimeError("the Claude Code CLI is not installed (looked for `claude` on PATH, in ~/.local/bin, "
                           "/opt/homebrew/bin and /usr/local/bin; HM_CLAUDE_BIN names another place)")
    gate = "%s %s" % (shlex.quote(sys.executable if os.path.exists(sys.executable) else "/usr/bin/python3"),
                      shlex.quote(os.path.join(ROOT, "bin", "agent_gate.py")))
    settings = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": gate, "timeout": 10}]}]}}
    argv = [cli, "-p",
            "--model", model,
            "--output-format", "stream-json", "--verbose",
            "--append-system-prompt", prompt,
            "--tools", ",".join(AGENT_TOOLS),
            "--allowedTools", "Read", "Glob", "Grep", "WebSearch", "WebFetch", PROBE_RULE,
            "--disallowedTools", *DENIED_TOOLS,
            "--permission-mode", "dontAsk",
            "--permission-prompts", "none",
            "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
            "--restricted",
            "--settings", json.dumps(settings),
            "--no-chrome",
            "--disable-slash-commands"]
    if resume:
        argv += ["--resume", resume]
    return argv


def child_env():
    """Only what the CLI needs to run and find its login. Nothing from an outer
    Claude Code session (CLAUDE*, ANTHROPIC*) and none of the server's own env."""
    env = {k: os.environ[k] for k in ("PATH", "HOME", "USER", "LANG", "TERM") if os.environ.get(k)}
    env.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    cli = claude_bin()
    if cli and os.path.dirname(cli) not in env["PATH"].split(":"):
        env["PATH"] = os.path.dirname(cli) + ":" + env["PATH"]
    env.setdefault("LANG", "en_US.UTF-8")
    # So probe.py and the gate read the same house as this server.
    for k in ("HM_STATE_DIR", "HM_SITE", "HM_INVENTORY", "HM_LAYOUT", "HM_KNOWLEDGE", "HM_KNOWLEDGE_DIR", "HOH_CONFIG_DIR"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


def action_env():
    env = {k: os.environ[k] for k in ("PATH", "HOME", "USER", "LANG", "TERM") if os.environ.get(k)}
    env.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    return env


def kill_group(proc, grace=3):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except (OSError, ProcessLookupError):
            return
        try:
            proc.wait(timeout=grace)
            return
        except Exception:
            continue


# ================================================================ runs

class AgentError(Exception):
    def __init__(self, status, text):
        Exception.__init__(self, text)
        self.status = status
        self.text = text


class Runs:
    def __init__(self, settings_fn, inventory_fn=None, audit_fn=None):
        self.settings_fn = settings_fn
        self.inventory_fn = inventory_fn or C.load_inventory
        self.audit_fn = audit_fn or (lambda **kw: None)
        self.lock = threading.RLock()
        self.cond = threading.Condition(self.lock)
        self.runs = {}            # active and recently touched records
        self.procs = {}
        self.cancels = {}
        self.action_procs = {}

    # -- storage
    @property
    def dir(self):
        return os.path.join(C.state_dir(), "runs")

    def _path(self, run_id):
        return os.path.join(self.dir, run_id + ".json")

    def _save(self, rec):
        C.write_json_atomic(self._path(rec["runId"]), rec)

    def get(self, run_id):
        if not re.match(r"^r[0-9a-f]{12}$", run_id or ""):
            return None
        with self.lock:
            if run_id in self.runs:
                return self.runs[run_id]
            try:
                with open(self._path(run_id)) as f:
                    rec = json.load(f)
            except (OSError, ValueError):
                return None
            self.runs[run_id] = rec
            return rec

    def list(self, limit=20):
        recs = []
        try:
            names = [n for n in os.listdir(self.dir) if n.endswith(".json")]
        except OSError:
            names = []
        for n in names:
            r = self.get(n[:-5])
            if r:
                recs.append(r)
        recs.sort(key=lambda r: r.get("startedAt") or "", reverse=True)
        out = []
        for r in recs[:limit]:
            s = {k: r.get(k) for k in ("runId", "threadId", "question", "deviceIds", "status", "startedAt", "endedAt", "model", "error")}
            s["title"] = (r.get("answer") or {}).get("title")
            s["verdict"] = (r.get("answer") or {}).get("verdict")
            out.append(s)
        return out

    def recover(self):
        """At start: runs left running belong to a server that died. Mark them
        interrupted, and stop their claude process if it is still alive."""
        try:
            names = [n for n in os.listdir(self.dir) if n.endswith(".json")]
        except OSError:
            return 0
        n_marked = 0
        for n in names:
            try:
                with open(os.path.join(self.dir, n)) as f:
                    rec = json.load(f)
            except (OSError, ValueError):
                continue
            changed = False
            if rec.get("status") in ("running", "queued"):
                pid = rec.get("pid")
                if pid:
                    rc, out, _ = C.run(["/bin/ps", "-o", "command=", "-p", str(pid)], timeout=5)
                    if rc == 0 and "claude" in out and "bin/probe.py" in out:
                        try:
                            os.killpg(int(pid), signal.SIGTERM)
                        except OSError:
                            pass
                rec["status"] = "interrupted"
                rec["endedAt"] = rec.get("endedAt") or now_iso()
                rec["error"] = "The server stopped while this run was going."
                changed = True
            for a in (rec.get("actions") or {}).values():
                if a.get("state") in ("approved", "running"):
                    a["state"] = "interrupted"
                    changed = True
            if changed:
                n_marked += 1
                C.write_json_atomic(os.path.join(self.dir, n), rec)
        return n_marked

    # -- events
    def _emit(self, rec, typ, data, save=True):
        with self.cond:
            ev = {"seq": len(rec["events"]) + 1, "type": typ, "data": data, "ts": now_iso()}
            rec["events"].append(ev)
            if save:
                self._save(rec)
            self.cond.notify_all()
        return ev

    def wait_events(self, run_id, after, timeout=15.0):
        """(new events after seq `after`, open) where open says whether more can come."""
        deadline = time.time() + timeout
        with self.cond:
            while True:
                rec = self.get(run_id)
                if rec is None:
                    return [], False
                evs = [e for e in rec["events"] if e["seq"] > after]
                open_ = self.stream_open(rec)
                if evs or not open_:
                    return evs, open_
                left = deadline - time.time()
                if left <= 0:
                    return [], True
                self.cond.wait(left)

    def stream_open(self, rec):
        if rec.get("status") in ("queued", "running"):
            return True
        acts = (rec.get("actions") or {}).values()
        if any(a.get("state") in ("approved", "running") for a in acts):
            return True
        try:
            mode = self.settings_fn().get("agentMode")
        except Exception:
            mode = None
        return mode == "approve" and any(a.get("state") == "proposed" for a in acts)

    # -- ask
    def ask(self, message, device_ids, thread_id=None):
        settings = self.settings_fn()
        if settings.get("agentMode") == "paused":
            raise AgentError(409, "The agent is paused. Switch it to advise or approve in settings to ask.")
        if not isinstance(message, str) or not message.strip():
            raise AgentError(400, "message is required")
        if len(message) > 8000:
            raise AgentError(400, "message is too long (8000 characters at most)")
        if not isinstance(device_ids, list) or not all(isinstance(d, str) for d in device_ids):
            raise AgentError(400, "deviceIds must be a list of ids")
        inv = self.inventory_fn()
        known = {d["id"] for d in inv.get("devices") or []}
        unknown = [d for d in device_ids if d not in known]
        if unknown:
            raise AgentError(400, "unknown device ids: %s" % ", ".join(unknown[:10]))
        resume = None
        with self.lock:
            if thread_id is not None:
                if not isinstance(thread_id, str) or not re.match(r"^t[0-9a-f]{12}$", thread_id):
                    raise AgentError(400, "bad threadId")
                prior = [r for r in self._thread_runs(thread_id)]
                if not prior:
                    raise AgentError(404, "unknown thread")
                if any(r.get("status") in ("queued", "running") for r in prior):
                    raise AgentError(409, "This thread already has a run going. Wait for it or cancel it.")
                with_session = [r for r in prior if r.get("sessionId")]
                if not with_session:
                    raise AgentError(409, "The earlier run in this thread never started a session, so it cannot be continued. Ask a new question.")
                resume = with_session[-1]["sessionId"]
            running = [r for r in self.runs.values() if r.get("status") in ("queued", "running")]
            if len(running) >= MAX_RUNNING:
                raise AgentError(429, "Two questions are already being worked on. Try again when one finishes.")
            run_id = "r" + uuid.uuid4().hex[:12]
            thread_id = thread_id or ("t" + uuid.uuid4().hex[:12])
            model = settings.get("agentModel") or "claude-opus-5-5"
            rec = {"runId": run_id, "threadId": thread_id, "question": message, "deviceIds": device_ids,
                   "status": "running", "startedAt": now_iso(), "endedAt": None, "model": model,
                   "resumedFrom": resume, "sessionId": None, "pid": None, "events": [], "answer": None,
                   "actions": {}, "error": None, "agentMode": settings.get("agentMode")}
            self.runs[run_id] = rec
            self._save(rec)
        self.audit_fn(actor="person", type="ask", runId=run_id, summary=message[:500])
        t = threading.Thread(target=self._run, args=(rec, inv, model, resume), name="agent-" + run_id, daemon=True)
        t.start()
        return run_id, thread_id

    def _thread_runs(self, thread_id):
        out = []
        try:
            names = [n for n in os.listdir(self.dir) if n.endswith(".json")]
        except OSError:
            names = []
        for n in names:
            r = self.get(n[:-5])
            if r and r.get("threadId") == thread_id:
                out.append(r)
        out.sort(key=lambda r: r.get("startedAt") or "")
        return out

    def _run(self, rec, inv, model, resume):
        run_id = rec["runId"]
        tr = Translator(inv)
        cancel = threading.Event()
        self.cancels[run_id] = cancel
        self._emit(rec, "phase", {"phase": "identify", "text": PHASE_TEXT["identify"]})
        tr.phase = "identify"
        status, err = "done", None
        stderr_buf = []
        try:
            prompt = build_prompt(inv)
            msg = build_message(rec["question"], rec["deviceIds"], inv)
            argv = claude_argv(model, prompt, resume)
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, cwd=ROOT, env=child_env(), start_new_session=True, bufsize=1)
        except Exception as e:
            self._finish(rec, "error", "Could not start Claude: %s" % e, None)
            return
        with self.lock:
            self.procs[run_id] = proc
            rec["pid"] = proc.pid
            self._save(rec)

        def feed():
            try:
                proc.stdin.write(msg)
                proc.stdin.close()
            except Exception:
                pass
        threading.Thread(target=feed, daemon=True).start()
        threading.Thread(target=lambda: stderr_buf.append(proc.stderr.read() or ""), daemon=True).start()
        timed_out = threading.Event()

        def on_timeout():
            timed_out.set()
            kill_group(proc, grace=2)
        killer = threading.Timer(float(os.environ.get("HM_RUN_TIMEOUT") or RUN_TIMEOUT), on_timeout)
        killer.daemon = True
        killer.start()

        def watch():
            while proc.poll() is None:
                if cancel.wait(0.5):
                    kill_group(proc, grace=1)
                    return
        threading.Thread(target=watch, daemon=True).start()
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    j = json.loads(line)
                except ValueError:
                    continue
                for typ, data in tr.feed(j):
                    self._emit(rec, typ, data)
                    if typ == "activity":
                        self.audit_fn(actor="agent", type="tool", runId=run_id,
                                      command=data.get("detail") if data.get("tool") == "Bash" else None,
                                      summary="%s: %s" % (data.get("tool"), data.get("text")))
                if tr.session_id and not rec.get("sessionId"):
                    with self.lock:
                        rec["sessionId"] = tr.session_id
                        self._save(rec)
        except Exception as e:
            err = "Reading the agent's output failed: %s" % e
        finally:
            killer.cancel()
            try:
                proc.wait(timeout=10)
            except Exception:
                kill_group(proc, grace=1)
            with self.lock:
                self.procs.pop(run_id, None)
            for s_ in (proc.stdout, proc.stderr):
                try:
                    s_.close()
                except Exception:
                    pass
        rec["sessionId"] = tr.session_id or rec.get("sessionId")
        if cancel.is_set():
            self._finish(rec, "cancelled", "Cancelled.", None)
            return
        if timed_out.is_set():
            self._finish(rec, "timeout", "The run took longer than 10 minutes and was stopped.", tr)
            return
        text = tr.final_text()
        if not text:
            raw = ("".join(stderr_buf) or "").strip()
            self._finish(rec, "error", err or tr.result_error or ("No answer came back. %s" % raw[-300:]).strip(), None)
            return
        if tr.result_error and not text:
            status, err = "error", tr.result_error
        self._finish(rec, status, err, tr, text)

    def _finish(self, rec, status, err, tr, text=None):
        run_id = rec["runId"]
        if text is None and tr is not None:
            text = tr.final_text()
        if text:
            if tr is not None and tr.phase != "answer":
                self._emit(rec, "phase", {"phase": "answer", "text": PHASE_TEXT["answer"]}, save=False)
            doc = extract_json(text)
            inv = self.inventory_fn()
            if doc is None:
                ans = fallback_answer(text, rec.get("deviceIds"))
            else:
                ans = normalize_answer(doc, inv, run_id, rec.get("deviceIds"))
            with self.lock:
                rec["answer"] = ans
                rec["actions"] = {a["id"]: dict(a, decidedAt=None, exitCode=None) for a in ans.get("actions") or []}
            self._emit(rec, "answer", ans, save=False)
            for a in ans.get("actions") or []:
                self.audit_fn(actor="agent", type="proposal", runId=run_id, actionId=a["id"], command=a["command"],
                              decision=a["state"] if a["state"] != "proposed" else None,
                              summary="%s%s" % (a["label"], (" (refused: %s)" % a["refusal"]) if a.get("refusal") else ""))
        if err:
            self._emit(rec, "error", {"text": err}, save=False)
        with self.lock:
            rec["status"] = status
            rec["error"] = err
            rec["endedAt"] = now_iso()
        self._emit(rec, "done", {"ok": status == "done"})
        self.audit_fn(actor="agent", type="run-end", runId=run_id, summary="%s%s" % (status, (": " + err) if err else ""))
        self.cancels.pop(run_id, None)

    def cancel(self, run_id):
        rec = self.get(run_id)
        if rec is None:
            raise AgentError(404, "no such run")
        ev = self.cancels.get(run_id)
        stopped = False
        if ev is not None and rec.get("status") == "running":
            ev.set()
            stopped = True
        for aid, p in list(self.action_procs.items()):
            if aid.startswith(run_id + "-"):
                kill_group(p, grace=1)
                stopped = True
        self.audit_fn(actor="person", type="cancel", runId=run_id, summary="cancel requested" + ("" if stopped else " (nothing running)"))
        return stopped

    # -- actions
    def find_action(self, action_id):
        m = re.match(r"^(r[0-9a-f]{12})-[A-Za-z0-9-]{1,20}$", action_id or "")
        if not m:
            return None, None
        rec = self.get(m.group(1))
        if not rec:
            return None, None
        return rec, (rec.get("actions") or {}).get(action_id)

    def decide(self, action_id, decision):
        if decision not in ("approve", "reject"):
            raise AgentError(400, "decision must be approve or reject")
        rec, act = self.find_action(action_id)
        if act is None:
            raise AgentError(404, "no such action")
        with self.lock:
            if act.get("state") != "proposed":
                raise AgentError(409, "This action was already decided (%s)." % act.get("state"))
            if decision == "reject":
                act["state"] = "rejected"
                act["decidedAt"] = now_iso()
                self._save(rec)
                self.audit_fn(actor="person", type="decision", runId=rec["runId"], actionId=action_id,
                              command=act["command"], decision="reject", summary=act.get("label"))
                return {"ok": True, "state": "rejected"}
            mode = self.settings_fn().get("agentMode")
            if mode != "approve":
                raise AgentError(409, "Actions can only run in approve mode (now: %s)." % mode)
            g = guard_command(act["command"], act.get("target"))
            if not g["ok"]:
                act["state"] = "copy-only" if g["needsSudo"] else "refused"
                act["refusal"] = g["reason"]
                act["needsSudo"] = act.get("needsSudo") or g["needsSudo"]
                act["decidedAt"] = now_iso()
                self._save(rec)
                self.audit_fn(actor="guard", type="refused", runId=rec["runId"], actionId=action_id,
                              command=act["command"], decision="refused", summary=g["reason"])
                raise AgentError(403, "Refused: %s" % g["reason"])
            act["state"] = "running"
            act["decidedAt"] = now_iso()
            self._save(rec)
        self.audit_fn(actor="person", type="decision", runId=rec["runId"], actionId=action_id,
                      command=act["command"], decision="approve", summary=act.get("label"))
        threading.Thread(target=self._run_action, args=(rec, act), daemon=True).start()
        return {"ok": True, "state": "running"}

    def _run_action(self, rec, act):
        aid = act["id"]
        sd = C.state_dir()
        os.makedirs(sd, exist_ok=True)
        try:
            # -f: no startup files, so exactly the shown string runs.
            proc = subprocess.Popen(["/bin/zsh", "-f", "-c", act["command"]], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=sd,
                                    env=action_env(), start_new_session=True)
        except Exception as e:
            self._emit(rec, "action-output", {"actionId": aid, "stream": "stderr", "text": "could not start: %s" % e})
            self._action_done(rec, act, 127)
            return
        self.action_procs[aid] = proc
        timer = threading.Timer(ACTION_TIMEOUT, lambda: kill_group(proc, grace=2))
        timer.daemon = True
        timer.start()

        def pump(stream, name):
            for line in stream:
                self._emit(rec, "action-output", {"actionId": aid, "stream": name, "text": line.rstrip("\n")[:4000]}, save=False)
        ts = [threading.Thread(target=pump, args=(proc.stdout, "stdout"), daemon=True),
              threading.Thread(target=pump, args=(proc.stderr, "stderr"), daemon=True)]
        for t in ts:
            t.start()
        rc = proc.wait()
        for t in ts:
            t.join(5)
        timer.cancel()
        for s_ in (proc.stdout, proc.stderr):
            try:
                s_.close()
            except Exception:
                pass
        self.action_procs.pop(aid, None)
        self._action_done(rec, act, rc)

    def _action_done(self, rec, act, rc):
        with self.lock:
            act["exitCode"] = rc
            act["state"] = "done" if rc == 0 else "failed"
        self._emit(rec, "action-result", {"actionId": act["id"], "exitCode": rc, "ok": rc == 0})
        self.audit_fn(actor="system", type="action-result", runId=rec["runId"], actionId=act["id"],
                      command=act["command"], exitCode=rc, summary="exit %s" % rc)
