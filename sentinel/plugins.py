"""plugins: code that other programs load for you. Claude Code hooks, MCP servers, plugins and skills;
browser, editor and Stream Deck extensions; Homebrew, npm and pip packages.

Environment variables and headers are reported by name only, URLs without their query, and command
lines redacted. On the first run what exists is the baseline and is judged on its merits; afterwards
anything new or changed is a finding until trusted.
"""
import json
import os
import re
import shlex

from . import heur as H
from . import util as U
from .persistence import emit

BROWSERS = (("Chrome", "Library/Application Support/Google/Chrome"), ("Arc", "Library/Application Support/Arc/User Data"),
            ("Brave", "Library/Application Support/BraveSoftware/Brave-Browser"), ("Edge", "Library/Application Support/Microsoft Edge"),
            ("Dia", "Library/Application Support/Dia/User Data"), ("Chromium", "Library/Application Support/Chromium"))
BROAD_HOSTS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*", "file:///*")
POWERFUL = ("cookies", "webRequest", "webRequestBlocking", "nativeMessaging", "debugger", "proxy", "declarativeNetRequestWithHostAccess",
            "history", "clipboardRead", "management", "privacy", "desktopCapture", "tabCapture")
VERY_POWERFUL = ("debugger", "proxy", "nativeMessaging")
RUNNERS = {"npx", "bunx", "uvx", "pnpx", "pipx"}
BROAD_ALLOW = re.compile(r"^(?:\*|Bash|Bash\(\*\)|Bash\(\*:\*\)|Bash\((?:sudo|rm|curl|wget|sh|bash|zsh|osascript|python3?|node)(?::\*|\s\*)?\))$")
JSON_MAX = 8 * 1024 * 1024


def load_json(path, limit=JSON_MAX):
    try:
        with U.open_nofollow(path) as f:
            if os.fstat(f.fileno()).st_size > limit:
                return None
            return json.loads(f.read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None


def project_dirs(cfg, limit=200):
    """Folders that may hold project-level Claude Code settings: ~/projects/* and one level below."""
    out = []
    base = cfg.h("projects")
    try:
        with os.scandir(base) as it:
            for e in it:
                if e.is_dir(follow_symlinks=False) and not e.name.startswith(".") and e.name != "node_modules":
                    out.append(e.path)
    except OSError:
        pass
    return sorted(out)[:limit]


# ---------------------------------------------------------------- Claude Code

def scan_claude_hooks(ctx, res):
    cfg = ctx.cfg
    ctx.baseline.begin("claude-hooks")
    files = [cfg.h(".claude", "settings.json"), cfg.h(".claude", "settings.local.json")]
    for d in project_dirs(cfg):
        files += [os.path.join(d, ".claude", "settings.json"), os.path.join(d, ".claude", "settings.local.json")]
    for path in files:
        if U.lstat(path) is None:
            continue
        doc = load_json(path)
        if not isinstance(doc, dict):
            res.unchecked("Claude Code settings %s" % cfg.show(path), "could not be read as JSON", keep="claude-hook:" + path + ":")
            continue
        hooks = doc.get("hooks")
        for event, groups in (hooks.items() if isinstance(hooks, dict) else []):
            for g in groups if isinstance(groups, list) else []:
                if not isinstance(g, dict):
                    continue
                for h in g.get("hooks") if isinstance(g.get("hooks"), list) else []:
                    if not isinstance(h, dict):
                        continue
                    cmd = h.get("command") if isinstance(h.get("command"), str) else (h.get("url") if isinstance(h.get("url"), str) else json.dumps(h, sort_keys=True))
                    hook_reasons(ctx, res, path, str(event), g.get("matcher"), cmd)
        perms = doc.get("permissions") if isinstance(doc.get("permissions"), dict) else {}
        allow = [a for a in perms.get("allow") or [] if isinstance(a, str)]
        broad = [a for a in allow if BROAD_ALLOW.match(a.strip())]
        mode = perms.get("defaultMode")
        reasons = []
        if mode == "bypassPermissions":
            reasons.append(U.Reason("bypass-permissions", "Claude Code is set to skip every permission prompt here (defaultMode: bypassPermissions): "
                                    "whatever a prompt or a web page talks it into, it runs.", "high", 100, measured=True))
        if broad:
            reasons.append(U.Reason("broad-allow", "Claude Code may run these without asking: %s. A rule this wide lets a poisoned page or file run commands unseen." % (
                ", ".join(U.clean(a, 40) for a in broad[:6])), "medium", 100, measured=True))
        key = "claude-permissions:" + path
        res.seen.add(key)
        if reasons:
            res.items += 1
            res.add(U.make_finding(key, "plugin", "Claude Code runs commands without asking (%s)" % cfg.show(path), reasons[0].text,
                                   {"type": "setting", "name": "Claude Code permissions", "path": path}, reasons,
                                   evidence=[("file", cfg.show(path), "settings"), ("defaultMode", mode, "permissions"),
                                             ("allow rules", "%d, of which %d very broad" % (len(allow), len(broad)), "permissions.allow")],
                                   fix={"text": "Open the file and narrow or remove the broad rules; keep prompts on for shell commands."},
                                   fp=U.digest(mode, *sorted(broad)), baseline=ctx.baseline.first("claude-hooks")))


def hook_reasons(ctx, res, path, event, matcher, cmd):
    cfg = ctx.cfg
    key = "claude-hook:%s:%s:%s" % (path, event, U.digest(matcher, cmd)[:12])
    reasons = H.script_reasons(cmd, "hook command")
    script = None
    try:
        for part in shlex.split(cmd):
            p = os.path.expanduser(part.replace("$CLAUDE_PROJECT_DIR", os.path.dirname(os.path.dirname(path))).replace("${CLAUDE_PROJECT_DIR}", os.path.dirname(os.path.dirname(path))))
            if p.startswith("/") and os.path.isfile(p) and not U.within(os.path.realpath(p), "/usr") and not U.within(os.path.realpath(p), "/bin"):
                script = p
                break
    except ValueError:
        pass
    text = cmd
    script_hash = None
    if script:
        st = U.lstat(script)
        if st and st.st_size <= U.TEXT_READ:
            body = U.read_text(os.path.realpath(script))
            script_hash = U.digest(body)
            text = cmd + "\n" + (body or "")
            reasons += [r for r in H.script_reasons(body, "hook script") if r.code not in {x.code for x in reasons}]
    if H.reaches_network(text) and not any(r.code in ("pipe-to-shell", "reverse-shell") for r in reasons):
        reasons.append(U.Reason("hook-network", "This hook reaches the network. A hook runs on every matching tool call with your account's rights and "
                                "sees what Claude Code is doing, so a hook that talks to another machine can send that out.", "medium", 50))
    fp = U.digest(cmd, script_hash)
    scope = "every Claude Code session" if U.within(path, cfg.h(".claude")) else "the project %s" % os.path.basename(os.path.dirname(os.path.dirname(path)))
    status = ctx.baseline.status(key, fp, "claude-hooks")
    emit(ctx, res, key, fp, "claude-hooks", reasons,
         "A Claude Code hook was added for %s (%s). A hook is a command that runs by itself, with your rights, each time the event fires." % (scope, U.clean(event, 30)),
         "This Claude Code hook, or the script it runs, changed.", sev_new="high", sev_changed="high", category="plugin",
         title="%s Claude Code hook (%s) in %s" % ("New" if status == "new" else "Changed" if status == "changed" else "Risky", U.clean(event, 30), cfg.show(path)),
         subject={"type": "setting", "name": "Claude Code hook: %s" % U.clean(event, 30), "path": path},
         evidence=[("file", cfg.show(path), "settings"), ("event", event, "hooks"), ("matcher", U.clean(matcher, 80) if isinstance(matcher, str) else None, "hooks"),
                   ("runs", U.redact(cmd, 240), "hooks"), ("script", cfg.show(script) if script else None, "resolved from the command")],
         fix={"text": "Open the settings file and read the hook. Remove it if you did not add it; if it is yours, mark it trusted."})


def mcp_sources(cfg):
    """[(label, {name: server})] from every place Claude Code, Claude Desktop and Cursor keep MCP servers."""
    out = []
    doc = load_json(cfg.h(".claude.json"))
    if isinstance(doc, dict):
        if isinstance(doc.get("mcpServers"), dict):
            out.append(("~/.claude.json", doc["mcpServers"]))
        for proj, v in (doc.get("projects") or {}).items() if isinstance(doc.get("projects"), dict) else []:
            if isinstance(v, dict) and isinstance(v.get("mcpServers"), dict) and v["mcpServers"]:
                out.append(("~/.claude.json, project %s" % cfg.show(str(proj)), v["mcpServers"]))
    elif U.lstat(cfg.h(".claude.json")) is not None:
        out.append(("~/.claude.json", None))
    files = [cfg.h(".claude", "settings.json"), cfg.h("Library", "Application Support", "Claude", "claude_desktop_config.json"),
             cfg.h(".cursor", "mcp.json"), cfg.h(".mcp.json")]
    files += [os.path.join(d, ".mcp.json") for d in project_dirs(cfg)] + [os.path.join(d, ".cursor", "mcp.json") for d in project_dirs(cfg)]
    for p in files:
        if U.lstat(p) is None:
            continue
        d = load_json(p)
        if isinstance(d, dict) and isinstance(d.get("mcpServers"), dict):
            if d["mcpServers"]:
                out.append((cfg.show(p), d["mcpServers"]))
        elif not isinstance(d, dict):
            out.append((cfg.show(p), None))
    return out


def scan_mcp(ctx, res):
    cfg = ctx.cfg
    ctx.baseline.begin("mcp")
    for label, servers in mcp_sources(cfg):
        if servers is None:
            res.unchecked("MCP servers in %s" % label, "the file could not be read as JSON", keep="mcp:%s:" % label)
            continue
        for name, s in servers.items():
            if not isinstance(s, dict):
                continue
            key = "mcp:%s:%s" % (label, name)
            cmd = s.get("command") if isinstance(s.get("command"), str) else None
            args = [a for a in s.get("args") or [] if isinstance(a, str)] if isinstance(s.get("args"), list) else []
            url = s.get("url") if isinstance(s.get("url"), str) else None
            env = sorted(str(k) for k in s.get("env")) if isinstance(s.get("env"), dict) else []
            headers = sorted(str(k) for k in s.get("headers")) if isinstance(s.get("headers"), dict) else []
            host = U.url_host(url) if url else None
            fp = U.digest(cmd, json.dumps(args), host, (url or "").split("?")[0], ",".join(env), ",".join(headers))
            reasons = []
            if cmd:
                reasons += H.script_reasons(" ".join([cmd] + args), "server command")
                base = os.path.basename(cmd)
                if base in RUNNERS:
                    pkg = next((a for a in args if not a.startswith("-")), None)
                    if pkg and not re.search(r".@\d", pkg) and not pkg.startswith((".", "/", "~")):
                        reasons.append(U.Reason("unpinned-package", "It is started with “%s %s”: whatever version of that package is newest is downloaded and run each time, "
                                                "with your rights. If the package or its name is ever taken over, the new code runs here unseen." % (base, U.clean(pkg, 60)),
                                                "medium", 80))
            if url:
                if url.lower().startswith("http://") and not U.is_loopback(host.split("://")[1].split(":")[0] if host else ""):
                    reasons.append(U.Reason("plain-http", "It is reached over plain http: what Claude sends it, and the tool instructions it sends back, can be read and changed on the way.",
                                            "high", 80))
                elif host and re.match(r"^https?://(\d{1,3}\.){3}\d{1,3}", host) and not U.is_loopback(host.split("://")[1].split(":")[0]):
                    reasons.append(U.Reason("ip-host", "It is reached at a bare address instead of a name, which no certificate ties to anyone.", "medium", 50))
            status = ctx.baseline.status(key, fp, "mcp")
            what = ("the command %s" % U.redact(" ".join([os.path.basename(cmd)] + args[:3]), 80)) if cmd else ("the remote server %s" % (host or "?"))
            emit(ctx, res, key, fp, "mcp", reasons,
                 "A new MCP server was added to Claude Code: %s. An MCP server gives Claude tools and instructions, and Claude acts on what it returns." % what,
                 "This MCP server's command, address or settings changed.", category="plugin",
                 title="%s MCP server: %s" % ("New" if status == "new" else "Changed" if status == "changed" else "Risky", U.clean(name, 60)),
                 subject={"type": "package", "name": "MCP server %s" % U.clean(name, 60)},
                 evidence=[("configured in", label, "MCP settings"), ("command", U.redact(" ".join(shlex.quote(a) for a in [cmd] + args), 240) if cmd else None, "mcpServers"),
                           ("address", ((host or "") + re.sub(r"^[a-z]+://[^/]*", "", (url or "").split("?")[0].split("#")[0])[:80]) if url else None, "mcpServers (query not shown)"),
                           ("environment", ", ".join(env[:20]) if env else None, "variable names only"),
                           ("headers", ", ".join(headers[:20]) if headers else None, "header names only")],
                 fix={"text": "If you added it, mark it trusted (pin a version if it is started with npx). If not, remove it with: claude mcp remove <name>."})


def scan_claude_plugins(ctx, res):
    cfg = ctx.cfg
    ctx.baseline.begin("claude-plugins")
    p = cfg.h(".claude", "plugins", "installed_plugins.json")
    if U.lstat(p) is not None:
        doc = load_json(p)
        if not isinstance(doc, dict):
            res.unchecked("Claude Code plugins", "installed_plugins.json could not be read", keep="claude-plugin:")
        else:
            markets = load_json(cfg.h(".claude", "plugins", "known_marketplaces.json")) or {}
            for name, installs in (doc.get("plugins") or {}).items() if isinstance(doc.get("plugins"), dict) else []:
                inst = installs[0] if isinstance(installs, list) and installs and isinstance(installs[0], dict) else {}
                market = name.split("@", 1)[1] if "@" in name else ""
                src = ((markets.get(market) or {}).get("source") or {}) if isinstance(markets, dict) else {}
                repo = src.get("repo") or src.get("url") or src.get("path")
                emit(ctx, res, "claude-plugin:" + name, "installed", "claude-plugins", [],
                     "A Claude Code plugin was installed: %s. A plugin can add hooks, commands, agents and MCP servers that run with your rights." % U.clean(name, 80),
                     "", category="plugin", title="New Claude Code plugin: %s" % U.clean(name, 80),
                     subject={"type": "package", "name": name, "path": inst.get("installPath") if isinstance(inst.get("installPath"), str) else None},
                     evidence=[("marketplace", U.clean(str(repo), 120) if repo else market, "known_marketplaces.json"),
                               ("version", U.clean(str(inst.get("version")), 40), "installed_plugins.json")],
                     fix={"text": "If you installed it, mark it trusted. If not: /plugin in Claude Code, then uninstall it."})
    # Skills, agents and commands: instructions and scripts Claude follows.
    ctx.baseline.begin("claude-skills")
    for sub, noun in (("skills", "skill"), ("agents", "agent"), ("commands", "command")):
        base = cfg.h(".claude", sub)
        try:
            names = sorted(n for n in os.listdir(base) if not n.startswith("."))
        except OSError:
            continue
        for n in names[:500]:
            path = os.path.join(base, n)
            fp, scripts = tree_fingerprint(path)
            status = ctx.baseline.status("claude-%s:%s" % (noun, n), fp, "claude-skills")
            emit(ctx, res, "claude-%s:%s" % (noun, n), fp, "claude-skills", [],
                 "A Claude Code %s was added: %s. Claude follows what it says%s." % (noun, U.clean(n, 60), " and it brings scripts" if scripts else ""),
                 "The Claude Code %s %s changed. Claude follows what it says, so a changed %s is changed instructions." % (noun, U.clean(n, 60), noun),
                 sev_new="low", sev_changed="info", category="plugin",
                 title="%s Claude Code %s: %s" % ("New" if status == "new" else "Changed", noun, U.clean(n, 60)),
                 subject={"type": "package", "name": n, "path": path},
                 evidence=[("folder", cfg.show(path), "~/.claude"), ("scripts inside", "yes" if scripts else "no", "file names")],
                 fix={"text": "If you or your own agents wrote it, mark it trusted. Otherwise read it before the next session uses it."})
    ctx.baseline.begin("claude-instructions")
    p = cfg.h(".claude", "CLAUDE.md")
    text = U.read_text(p, 512 * 1024) if U.lstat(p) is not None else None
    if text is not None:
        emit(ctx, res, "claude-instructions", U.digest(text), "claude-instructions", [], "",
             "Your global Claude Code instructions (~/.claude/CLAUDE.md) changed. Every session on this Mac reads them first.",
             sev_changed="low", category="plugin", title="Global Claude Code instructions changed",
             subject={"type": "file", "name": "CLAUDE.md", "path": p}, evidence=[("file", cfg.show(p), "hash of the text")],
             fix={"text": "Read the file. If the change is yours, mark it trusted."})


def tree_fingerprint(path, max_files=300):
    """(fingerprint, has scripts) of a file or a small folder: names, sizes and content hashes, links not followed."""
    st = U.lstat(path)
    if st is None:
        return "gone", False
    if not os.path.isdir(path) or os.path.islink(path):
        return U.digest(os.readlink(path) if os.path.islink(path) else U.sha256_file(path, 4 * 1024 * 1024)), False
    parts, scripts, n = [], False, 0
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d not in ("node_modules", ".git", "__pycache__"))
        for f in sorted(files):
            n += 1
            if n > max_files:
                break
            full = os.path.join(root, f)
            s = U.lstat(full)
            if s is None:
                continue
            if f.endswith((".py", ".sh", ".js", ".ts", ".rb", ".command")):
                scripts = True
            parts.append("%s:%d:%s" % (os.path.relpath(full, path), s.st_size, U.sha256_file(full, 2 * 1024 * 1024) or s.st_mtime_ns))
    return U.digest(*parts), scripts


# ---------------------------------------------------------------- browsers and editors

def _msg(ext_dir, manifest, value):
    """Resolve __MSG_name__ through _locales."""
    m = re.match(r"^__MSG_(.+)__$", value or "")
    if not m:
        return value
    for loc in (manifest.get("default_locale"), "en", "en_US", "en_GB"):
        if not isinstance(loc, str) or "/" in loc or ".." in loc:
            continue
        d = load_json(os.path.join(ext_dir, "_locales", loc, "messages.json"), 2 * 1024 * 1024)
        if isinstance(d, dict):
            for k, v in d.items():
                if k.lower() == m.group(1).lower() and isinstance(v, dict) and isinstance(v.get("message"), str):
                    return v["message"]
    return value


def scan_browsers(ctx, res):
    cfg = ctx.cfg
    ctx.baseline.begin("browser-extensions")
    for browser, rel in BROWSERS:
        base = cfg.h(rel)
        if U.lstat(base) is None:
            continue
        try:
            profiles = [n for n in os.listdir(base) if n == "Default" or n.startswith("Profile ") or n == "Guest Profile"]
        except OSError as e:
            res.unchecked("%s extensions" % browser, "macOS does not let Home Observability Hub read %s's folder (%s). Give /usr/bin/python3 Full Disk Access to include them."
                          % (browser, e.strerror or "permission denied"), keep="ext:%s:" % browser)
            continue
        for prof in sorted(profiles):
            ext_root = os.path.join(base, prof, "Extensions")
            try:
                ids = sorted(os.listdir(ext_root))
            except OSError:
                continue
            for eid in ids:
                if not re.match(r"^[a-p]{32}$", eid):
                    continue
                try:
                    versions = sorted(os.listdir(os.path.join(ext_root, eid)))
                except OSError:
                    continue
                if not versions:
                    continue
                ext_dir = os.path.join(ext_root, eid, versions[-1])
                man = load_json(os.path.join(ext_dir, "manifest.json"), 2 * 1024 * 1024)
                if not isinstance(man, dict):
                    continue
                browser_extension(ctx, res, browser, prof, eid, ext_dir, man)
    # Firefox keeps a list with permissions per profile.
    fbase = cfg.h("Library", "Application Support", "Firefox", "Profiles")
    try:
        fprofiles = sorted(os.listdir(fbase))
    except OSError:
        fprofiles = []
    for prof in fprofiles:
        doc = load_json(os.path.join(fbase, prof, "extensions.json"))
        for a in (doc.get("addons") or []) if isinstance(doc, dict) else []:
            if not isinstance(a, dict) or a.get("type") != "extension" or a.get("location") in ("app-builtin", "app-system-defaults"):
                continue
            perms = a.get("userPermissions") if isinstance(a.get("userPermissions"), dict) else {}
            man = {"name": (a.get("defaultLocale") or {}).get("name") if isinstance(a.get("defaultLocale"), dict) else a.get("id"),
                   "version": a.get("version"), "permissions": perms.get("permissions") or [], "host_permissions": perms.get("origins") or [],
                   "update_url": "store" if a.get("signedState") in (1, 2, 3) else None}
            browser_extension(ctx, res, "Firefox", prof, str(a.get("id")), a.get("path") if isinstance(a.get("path"), str) else None, man)
    # Safari: names and ids only.
    rc, out, _ = cfg.run(["/usr/bin/pluginkit", "-mAvvv", "-p", "com.apple.Safari.web-extension"], timeout=20)
    if rc != 0:
        res.unchecked("Safari extensions", "pluginkit gave no answer", keep="ext:Safari:")
    else:
        for m in re.finditer(r"^\s*[+!-]?\s*(\S+)\((\S*)\)\s*$", out or "", re.M):
            bid = m.group(1)
            emit(ctx, res, "ext:Safari:" + bid, "installed", "browser-extensions", [],
                 "A Safari extension was added: %s." % U.clean(bid, 80), "", category="plugin",
                 title="New Safari extension: %s" % U.clean(bid, 80), subject={"type": "extension", "name": bid},
                 evidence=[("bundle id", bid, "pluginkit"), ("version", m.group(2), "pluginkit")],
                 fix={"text": "Safari > Settings > Extensions: switch it off or uninstall it if you do not know it."})
        res.unchecked("what Safari extensions may read", "Safari does not publish an extension's site permissions outside Safari; only their presence is watched")


def browser_extension(ctx, res, browser, profile, eid, ext_dir, man):
    cfg = ctx.cfg
    name = man.get("name") if isinstance(man.get("name"), str) else eid
    if ext_dir:
        name = _msg(ext_dir, man, name)
    perms = [p for p in (man.get("permissions") or []) + (man.get("optional_permissions") or []) if isinstance(p, str)]
    hosts = [p for p in (man.get("host_permissions") or []) + (man.get("optional_host_permissions") or []) if isinstance(p, str)]
    hosts += [p for p in perms if "://" in p or p == "<all_urls>"]
    for cs in man.get("content_scripts") or []:
        if isinstance(cs, dict):
            hosts += [m for m in cs.get("matches") or [] if isinstance(m, str)]
    broad = sorted({h for h in hosts if h in BROAD_HOSTS or re.match(r"^\*://\*\.?/?\*?$", h)})
    strong = sorted({p for p in perms if p in POWERFUL})
    sideloaded = not man.get("update_url") and not man.get("key")
    key = "ext:%s:%s:%s" % (browser, profile, eid)
    reasons = []
    if broad and any(p in VERY_POWERFUL for p in strong):
        reasons.append(U.Reason("extension-full-control", "It may read and change every site you open and also has %s: enough to watch or reroute all browsing, logins included." % (
            ", ".join(p for p in strong if p in VERY_POWERFUL)), "medium" if sideloaded else "low", 100, measured=True))
    elif broad and strong:
        reasons.append(U.Reason("extension-broad", "It may read and change every site you open, with %s. That is what a password manager or ad blocker needs, "
                                "and also all a spying extension needs." % ", ".join(strong[:5]), "low", 100, measured=True))
    if sideloaded:
        reasons.append(U.Reason("extension-sideloaded", "It did not come from the browser's store (it has no update address): nobody reviewed it and it never updates.",
                                "high" if broad else "medium", 60))
    fp = U.digest(sideloaded, ",".join(broad), ",".join(strong))
    status = ctx.baseline.status(key, fp, "browser-extensions")
    emit(ctx, res, key, fp, "browser-extensions", reasons,
         "A browser extension was added to %s: %s." % (browser, U.clean(name, 60)),
         "The extension %s in %s now asks for different permissions." % (U.clean(name, 60), browser), category="plugin",
         title="%s %s extension: %s" % ("New" if status == "new" else "Changed" if status == "changed" else
                                        "Sideloaded" if sideloaded else "Powerful", browser, U.clean(name, 60)),
         subject={"type": "extension", "name": name, "path": ext_dir},
         evidence=[("id", eid, "extension folder"), ("version", U.clean(str(man.get("version")), 40), "manifest.json"), ("profile", profile, browser),
                   ("site access", ", ".join(broad) if broad else "%d site pattern(s), none of them every site" % len(set(hosts)), "manifest.json"),
                   ("permissions", ", ".join(sorted(set(perms))[:20]) or "none", "manifest.json"),
                   ("from the store", "no" if sideloaded else "yes", "manifest.json update_url")],
         fix={"text": "%s > Extensions: remove it if you do not use it or do not know it. If you rely on it, mark it trusted." % browser})


def scan_editors(ctx, res):
    cfg = ctx.cfg
    for label, rel in (("VS Code", ".vscode/extensions"), ("Cursor", ".cursor/extensions")):
        base = cfg.h(rel)
        group = "editor:" + label
        try:
            names = sorted(n for n in os.listdir(base) if not n.startswith(".") and os.path.isdir(os.path.join(base, n)))
        except OSError:
            continue
        ctx.baseline.begin(group)
        seen = {}
        for n in names:
            pkg = load_json(os.path.join(base, n, "package.json"), 2 * 1024 * 1024) or {}
            ident = "%s.%s" % (pkg.get("publisher"), pkg.get("name")) if pkg.get("publisher") and pkg.get("name") else re.sub(r"-\d[\w.]*(-[\w-]+)?$", "", n)
            seen[str(ident)] = n
        aggregate(ctx, res, group, "editor-ext:%s" % label, seen, "%s extension" % label,
                  "An editor extension runs with your rights whenever the editor is open.",
                  "%s > Extensions: uninstall the ones you do not know." % label)
    base = cfg.h("Library", "Application Support", "com.elgato.StreamDeck", "Plugins")
    try:
        names = sorted(n for n in os.listdir(base) if n.endswith(".sdPlugin"))
    except OSError:
        names = None
    if names is not None:
        ctx.baseline.begin("streamdeck")
        aggregate(ctx, res, "streamdeck", "streamdeck", {n[:-9]: n for n in names}, "Stream Deck plugin",
                  "A Stream Deck plugin is a program that runs while Stream Deck is open.", "Stream Deck > Preferences > Plugins: remove the ones you do not know.")


def aggregate(ctx, res, group, key, items, noun, why, fix, sev="low", extra_reasons=None):
    """One finding for everything new in a list (packages, extensions) instead of one per item."""
    b = ctx.baseline
    first = b.first(group)
    new = []
    for name in sorted(items):
        res.items += 1
        res.seen.add("%s:%s" % (key, name))
        if b.status("%s:%s" % (key, name), "installed", group) == "new":
            new.append(name)
    res.seen.add(key + ":new")
    if new and b.get(key + ":new") == U.digest(*sorted(new)):
        # The person trusted exactly this list: the items join the baseline and the list starts empty again.
        for name in new:
            b.accept("%s:%s" % (key, name), "installed")
        new = []
    reasons = list(extra_reasons or [])
    if new:
        reasons.insert(0, U.Reason("new", "%d new %s%s since the baseline: %s. %s" % (
            len(new), noun, "" if len(new) == 1 else "s", ", ".join(U.clean(n, 50) for n in new[:12]) + (" and more" if len(new) > 12 else ""), why),
            sev, 100, measured=True))
    if reasons:
        res.add(U.make_finding(key + ":new", "plugin", "%d new %s%s" % (len(new), noun, "" if len(new) == 1 else "s") if new else "%s needs a look" % noun.capitalize(),
                               reasons[0].text, {"type": "package", "name": "%ss" % noun}, reasons,
                               evidence=[(noun, U.clean(n, 100), "installed since the baseline") for n in new[:20]],
                               fix={"text": fix + " If they are all yours, mark this trusted."},
                               fp=U.digest(*sorted(new)), baseline=first))
    return new


# ---------------------------------------------------------------- packages

def scan_packages(ctx, res):
    cfg = ctx.cfg
    brew = cfg.s("/opt/homebrew")
    if not os.path.isdir(os.path.join(brew, "Cellar")):
        brew = cfg.s("/usr/local")
    if os.path.isdir(os.path.join(brew, "Cellar")):
        ctx.baseline.begin("brew")
        items, third = {}, []
        for sub in ("Cellar", "Caskroom"):
            try:
                for n in os.listdir(os.path.join(brew, sub)):
                    if not n.startswith("."):
                        items[n] = sub
            except OSError:
                pass
        taps = []
        try:
            for user in os.listdir(os.path.join(brew, "Library", "Taps")):
                for repo in os.listdir(os.path.join(brew, "Library", "Taps", user)):
                    if user != "homebrew":
                        taps.append("%s/%s" % (user, repo.replace("homebrew-", "")))
        except OSError:
            pass
        new = aggregate(ctx, res, "brew", "brew", items, "Homebrew package", "Each was downloaded and installed with your rights.",
                        "Check each with: brew info <name>. Remove with: brew uninstall <name>.", sev="info")
        for n in new:
            if items[n] != "Cellar":
                continue
            try:
                vers = sorted(os.listdir(os.path.join(brew, "Cellar", n)))
            except OSError:
                continue
            rec = load_json(os.path.join(brew, "Cellar", n, vers[-1], "INSTALL_RECEIPT.json"), 1024 * 1024) if vers else None
            tap = ((rec or {}).get("source") or {}).get("tap") if isinstance(rec, dict) else None
            if isinstance(tap, str) and tap and not tap.startswith("homebrew/"):
                third.append((n, tap))
        for n, tap in third:
            key = "brew-third:" + n
            res.add(U.make_finding(key, "plugin", "New Homebrew package from a third-party tap: %s" % U.clean(n, 60),
                                   "It was installed from the tap %s, not from Homebrew's own reviewed collection. A tap is a repository anyone can publish; its formula can run any command while installing." % U.clean(tap, 60),
                                   {"type": "package", "name": n},
                                   [U.Reason("third-party-tap", "It comes from the third-party tap %s." % U.clean(tap, 60), "low", 100, measured=True)],
                                   evidence=[("tap", tap, "INSTALL_RECEIPT.json")], fix={"text": "If you installed it on purpose, mark it trusted.", "command": "brew info %s" % shlex.quote(n)},
                                   fp=tap))
        ctx.baseline.begin("brew-taps")
        aggregate(ctx, res, "brew-taps", "brew-tap", {t: t for t in taps}, "Homebrew tap",
                  "A tap is a third-party repository of install recipes; each recipe can run any command.", "Remove with: brew untap <name>.")
    # global npm packages
    for nm in (os.path.join(brew, "lib", "node_modules"), cfg.h(".npm-global", "lib", "node_modules")):
        try:
            names = [n for n in os.listdir(nm) if not n.startswith(".")]
        except OSError:
            continue
        ctx.baseline.begin("npm")
        pkgs = {}
        for n in names:
            if n.startswith("@"):
                try:
                    for sub in os.listdir(os.path.join(nm, n)):
                        pkgs["%s/%s" % (n, sub)] = os.path.join(nm, n, sub)
                except OSError:
                    pass
            else:
                pkgs[n] = os.path.join(nm, n)
        new = aggregate(ctx, res, "npm", "npm", pkgs, "global npm package", "A global npm package puts commands on your PATH.",
                        "Remove with: npm uninstall -g <name>.", sev="info")
        for n in new:
            pkg = load_json(os.path.join(pkgs[n], "package.json"), 2 * 1024 * 1024) or {}
            scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
            hooks = [k for k in ("preinstall", "install", "postinstall") if scripts.get(k)]
            if hooks:
                res.add(U.make_finding("npm-script:" + n, "plugin", "New global npm package ran an install script: %s" % U.clean(n, 60),
                                       "It declares %s. An install script is a command the package ran on this Mac, with your rights, the moment it was installed." % ", ".join(hooks),
                                       {"type": "package", "name": n, "path": pkgs[n]},
                                       [U.Reason("install-script", "It has an install script (%s)." % ", ".join(hooks), "low", 100, measured=True)],
                                       evidence=[("script", "%s: %s" % (h, U.redact(str(scripts.get(h)), 160)), "package.json") for h in hooks],
                                       fix={"text": "Read the script in its package.json. If it is a tool you chose, mark it trusted."}, fp=U.digest(*hooks)))
    # pip: distributions in the user and Homebrew site-packages
    import glob
    dists = {}
    pats = [cfg.h("Library", "Python", "*", "lib", "python", "site-packages"), os.path.join(brew, "lib", "python3*", "site-packages")]
    for pat in pats:
        for sp in glob.glob(pat):
            try:
                for n in os.listdir(sp):
                    if n.endswith(".dist-info"):
                        dists[re.sub(r"-[^-]+\.dist-info$", "", n).lower()] = sp
            except OSError:
                pass
    if dists:
        ctx.baseline.begin("pip")
        aggregate(ctx, res, "pip", "pip", dists, "Python package", "A Python package is code your scripts import and run.",
                  "Remove with: pip3 uninstall <name>.", sev="info")


PARTS = (("Claude Code hooks and permissions", scan_claude_hooks, ("claude-hook:", "claude-permissions:")), ("MCP servers", scan_mcp, ("mcp:",)),
         ("Claude Code plugins and skills", scan_claude_plugins, ("claude-",)), ("browser extensions", scan_browsers, ("ext:",)),
         ("editor and Stream Deck extensions", scan_editors, ("editor-ext:", "streamdeck")),
         ("Homebrew, npm and pip packages", scan_packages, ("brew", "npm", "pip")))


def scan(ctx):
    res = U.Result()
    for name, fn, prefixes in PARTS:
        try:
            fn(ctx, res)
        except Exception as e:
            for p in prefixes:
                res.unchecked(name, "the check failed (%s)" % type(e).__name__, keep=p)
    res.detail = "%d plugins, extensions, servers and packages" % res.items
    return res
