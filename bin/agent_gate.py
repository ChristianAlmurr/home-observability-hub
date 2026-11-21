#!/usr/bin/env python3
"""PreToolUse hook for the fix agent: Bash may run exactly one program,
`python3 bin/probe.py <subcommand> [args]`, with plain arguments.

Claude Code auto-approves commands it considers read-only (ls, cat, echo, ...)
even in dontAsk mode, so a `Bash(python3 bin/probe.py *)` allow rule alone
does not make probe.py the only program. This hook closes that gap: it denies
every other Bash command before it runs. Every other tool passes through to the
normal permission rules.

Exit 0 with a JSON decision on stdout. Any error denies.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# One token: plain characters, or a single-quoted string without quotes inside.
TOKEN = r"(?:[A-Za-z0-9._:/@%=,+-]+|'[^'\n\\]*')"
ALLOWED = re.compile(r"^python3 bin/probe\.py(?: " + TOKEN + r"){0,4}$")


READ_ONLY_TOOLS = ("Read", "Glob", "Grep", "WebSearch", "WebFetch", "ToolSearch")
# Always secret, whatever data/site.json says: dotenv files, keychains and the usual key folders.
FIXED_SECRET = r"\.env\b|Keychains|\.ssh\b|\.gnupg\b|\.aws\b|\.netrc\b"
END = r"(?![A-Za-z0-9_.-])"


def secret_path_re():
    """The fixed patterns plus every folder in secretDirs (site_config.secret_dirs_raw: the fixed list and
    data/site.json's). "~/.vault" matches ~/.vault and the expanded path, and, since it is a dot folder,
    .vault as a path part anywhere. A broken site file still leaves the fixed patterns."""
    parts = [FIXED_SECRET]
    try:
        import site_config
        home = os.path.expanduser("~")
        for raw in site_config.secret_dirs_raw():
            if raw.startswith("~/"):
                rel = raw[2:]
                parts.append(r"(~|%s)/%s%s" % (re.escape(home), re.escape(rel), END))
                if rel.startswith("."):
                    parts.append(r"(^|/)%s%s" % (re.escape(rel), END))
            elif raw.startswith("/"):
                parts.append(re.escape(raw) + END)
    except Exception:
        pass
    return re.compile("|".join(parts), re.I)


def decide(tool, tool_input):
    """(allowed, reason). Pure apart from reading data/site.json, so the tests can call it."""
    if tool in READ_ONLY_TOOLS:
        ti = tool_input or {}
        secret = secret_path_re()
        for k in ("file_path", "path", "pattern"):
            v = ti.get(k)
            if isinstance(v, str) and secret.search(v):
                return False, "That path holds secrets and is never read."
        return True, ""
    if tool != "Bash":
        return False, "Only Read, Glob, Grep, WebSearch, WebFetch and the probe are available."
    cmd = (tool_input or {}).get("command")
    if not isinstance(cmd, str):
        return False, "No command."
    cmd = cmd.strip()
    if len(cmd) > 400:
        return False, "Command too long."
    if ALLOWED.match(cmd):
        return True, ""
    return False, ("Only `python3 bin/probe.py <subcommand> [args]` may run, one command at a time, "
                   "with plain arguments (no pipes, redirections, substitutions or other programs). "
                   "Run `python3 bin/probe.py --list` for the subcommands.")


def main():
    try:
        ev = json.load(sys.stdin)
        ok, reason = decide(ev.get("tool_name"), ev.get("tool_input"))
    except Exception as e:  # anything unexpected denies
        ok, reason = False, "gate error: %s" % e
    if ok:
        return 0
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
