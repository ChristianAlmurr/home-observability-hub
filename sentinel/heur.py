"""Content heuristics shared by the scanners: what a script or a command line does that malware does.

Each returns Reason objects whose text never quotes the content, only what kind of thing was seen
and on which line, so a secret inside a script cannot leak through a finding. None of these is ever
`confirmed`: they are patterns, and the percentages say how often such a pattern is a real problem.
"""
import re

from .util import Reason

_SH = r"(?:/bin/|/usr/bin/)?(?:ba|z|k|da)?sh\b"
_FETCH = r"\b(?:curl|wget)\b"
PIPE_SHELL = re.compile(
    _FETCH + r"[^\n|;&]*\|\s*(?:sudo\s+)?(?:env\s+)?" + _SH +
    r"|\b(?:ba|z|k|da)?sh\s+(?:-c\s+)?[\"']?\$\(\s*" + _FETCH +
    r"|\b(?:ba|z)sh\s+<\(\s*" + _FETCH +
    r"|\beval\s+[\"']?\$\(\s*" + _FETCH +
    r"|" + _FETCH + r"[^\n|;&]*\|\s*(?:sudo\s+)?(?:python3?|perl|ruby|osascript|node)\b")
B64_EXEC = re.compile(
    r"base64\s+(?:-d|-D|--decode)\b[^\n|;]*\|\s*(?:sudo\s+)?" + _SH +
    r"|eval\s+[\"']?\$\([^)\n]*base64\s+(?:-d|-D|--decode)"
    r"|exec\s*\(\s*(?:base64\.b64decode|__import__\(\s*['\"]base64|zlib\.decompress\(\s*base64)"
    r"|echo\s+[\"']?[A-Za-z0-9+/=]{60,}[\"']?\s*\|\s*base64\s+(?:-d|-D|--decode)"
    r"|osascript\s+-e\s+[\"']?\$\([^)\n]*base64\s+(?:-d|-D|--decode)")
HIDDEN_ANSWER = re.compile(r"hidden\s+answer", re.I)
PASSWORD_WORD = re.compile(r"pass\s?word|passwort|wachtwoord|contrase|mot de passe|system preferences|system settings|administrator", re.I)
AUTH_CHECK = re.compile(r"\bdscl\s+\S+\s+-authonly\b")
STRIP_QUARANTINE = re.compile(r"\bxattr\s+(?:-\w+\s+)*-(?:r?d|dr)\s+(?:-\w+\s+)*com\.apple\.quarantine|\bxattr\s+-c?r?c\b")
DISABLE_PROTECTION = re.compile(r"\bspctl\s+--(?:master|global)-disable|\bcsrutil\s+disable|\btccutil\s+reset\s+All")
CREDENTIALS = re.compile(
    r"\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)\b|Login\s?Data|Cookies\.binarycookies"
    r"|/Library/Keychains/|logins\.json|key4\.db|/\.ssh/id_|wallet\.dat|Exodus|/Library/Application Support/Google/Chrome/[^\n]*Cookies")
EXFIL = re.compile(_FETCH + r"[^\n]*(?:\s-F\s|\s--form\s|\s--data-binary\s|\s-T\s|\s--upload-file\s|\s-d\s+@)|\bnc\s+[^\n]*<")
REVERSE_SHELL = re.compile(r"/dev/tcp/\d|/dev/udp/\d|\bnc(?:at)?\s+[^\n]*\s-e\s|\bsocat\s+[^\n]*exec:|bash\s+-i\s+>&")
FETCH_RUN_TMP = re.compile(_FETCH + r"[^\n]*(?:\s-o\s*|\s-O\s*|\s--output\s+)[\"']?(?:/tmp/|/private/tmp/|/var/tmp/|\$TMPDIR|\$\{TMPDIR)[^\n]*(?:\n[^\n]*){0,3}?chmod\s+(?:\+x|[0-7]*7[0-7]*)")
INSTALL_LAUNCH = re.compile(r"Library/Launch(?:Agents|Daemons)/[^\n]*\.plist|\blaunchctl\s+(?:load|bootstrap)\b")
NETWORK = re.compile(_FETCH + r"|\b(?:nc|ncat|ssh|scp|sftp|rsync|telnet|ftp)\s+\S|https?://(?!127\.0\.0\.1|localhost|\[::1\])|\burllib|\brequests\.(?:get|post)|\bfetch\s*\(|/dev/tcp/")


def _line(text, pos):
    return text.count("\n", 0, pos) + 1


STRICT = ("pipe-to-shell", "base64-exec", "reverse-shell", "credential-check", "disables-protection")


def script_reasons(text, what="script", strict=False):
    """Reasons from the text of a script or a command. `what` names the thing in the reason text.
    `strict` keeps only the patterns that have no everyday use (for files people write themselves, like .zshrc)."""
    out = _script_reasons(text, what)
    return [r for r in out if r.code in STRICT] if strict else out


def _script_reasons(text, what):
    if not text:
        return []
    out = []

    def add(code, rx, sev, pct, words):
        m = rx.search(text)
        if m:
            out.append(Reason(code, "%s (line %d of the %s)." % (words, _line(text, m.start()), what), sev, pct))
        return m
    add("pipe-to-shell", PIPE_SHELL, "high", 65,
        "It fetches something from the network and runs it straight away, without saving it for anyone to look at")
    add("base64-exec", B64_EXEC, "high", 70, "It decodes hidden (base64) text and runs the result")
    add("reverse-shell", REVERSE_SHELL, "high", 80, "It opens a shell to another machine over the network")
    m = HIDDEN_ANSWER.search(text)
    if m and PASSWORD_WORD.search(text[max(0, m.start() - 500):m.end() + 500]):
        out.append(Reason("password-prompt", "It shows its own password dialog with a hidden field, the way password-stealing malware does "
                          "(line %d of the %s)." % (_line(text, m.start()), what), "high", 70))
    add("credential-check", AUTH_CHECK, "high", 75, "It checks a typed password against the system, which is how a stolen password is verified")
    cred = add("credential-files", CREDENTIALS, "high", 50, "It reads where passwords, browser cookies, keys or wallets are stored")
    if cred and EXFIL.search(text):
        out.append(Reason("exfiltration", "It also uploads files to another machine.", "high", 75))
    add("strips-quarantine", STRIP_QUARANTINE, "medium", 55, "It removes the quarantine mark that makes macOS check a download before it opens")
    add("disables-protection", DISABLE_PROTECTION, "high", 70, "It switches a macOS protection off")
    add("fetch-run-temp", FETCH_RUN_TMP, "high", 60, "It downloads a file into a temporary folder and makes it runnable")
    if out:
        add("installs-launch-item", INSTALL_LAUNCH, "medium", 50, "It also sets something up to start by itself")
    return out


def reaches_network(text):
    return bool(text and NETWORK.search(text))
