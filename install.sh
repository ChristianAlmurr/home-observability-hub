#!/bin/sh
# Home Observability Hub installer. POSIX sh, safe to run again.
#
#   From a clone:   sh install.sh [--no-test] [--global]
#   From the web:   curl -fsSL https://raw.githubusercontent.com/ChristianAlmurr/home-observability-hub/main/install.sh | sh
#                   curl -fsSL https://raw.githubusercontent.com/ChristianAlmurr/home-observability-hub/main/install.sh | sh -s -- --dir ~/somewhere
#
# It checks the Mac, Python and Claude Code, creates the config folder (mode 700) and data/state,
# and runs the test suite once as a self-check. It does NOT scan the network and does NOT install
# the background service: both happen inside /setup, after you have said yes.
#
#   --dir DIR    where the hub lives (default: the clone this script is in, else ~/home-observability-hub)
#   --no-test    skip the self-check
#   --global     also link the hub's skills into ~/.claude/skills (default: project-only)
#   --repo URL   clone from this URL (default $HOH_REPO_URL)
set -u

REPO_URL="${HOH_REPO_URL:-https://github.com/ChristianAlmurr/home-observability-hub.git}"
DIR=""
RUN_TESTS=1
GLOBAL=0

say()  { printf '%s\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
warn() { printf '  warn  %s\n' "$*"; }
die()  { printf '  FAIL  %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) [ $# -ge 2 ] || die "--dir needs a folder"; DIR="$2"; shift 2 ;;
    --dir=*) DIR="${1#--dir=}"; shift ;;
    --no-test) RUN_TESTS=0; shift ;;
    --global) GLOBAL=1; shift ;;
    --repo) [ $# -ge 2 ] || die "--repo needs a URL"; REPO_URL="$2"; shift 2 ;;
    -h|--help) sed -n '2,19p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

say "Home Observability Hub: install"

# ---- the Mac
[ "$(uname -s)" = "Darwin" ] || die "This is $(uname -s). The hub runs on macOS."
ok "macOS $(sw_vers -productVersion 2>/dev/null || echo '?')"

# ---- Python (the Command Line Tools provide /usr/bin/python3 and git; calling the shim without them pops a dialog)
PY=""
if xcode-select -p >/dev/null 2>&1 && [ -x /usr/bin/python3 ]; then
  PY=/usr/bin/python3
elif command -v python3 >/dev/null 2>&1 && [ "$(command -v python3)" != "/usr/bin/python3" ]; then
  PY="$(command -v python3)"
fi
[ -n "$PY" ] || die "Python 3 is missing. Run: xcode-select --install   (installs Apple's Command Line Tools), then run this again."
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null \
  || die "$PY is older than Python 3.9. Run: xcode-select --install, then run this again."
ok "Python $("$PY" -c 'import platform; print(platform.python_version())') ($PY)"

# ---- where the hub lives
here=""
case "$0" in
  */install.sh|install.sh) here="$(cd "$(dirname "$0")" 2>/dev/null && pwd)" ;;
esac
is_hub() { [ -f "$1/server.py" ] && [ -f "$1/discover.py" ] && [ -f "$1/bin/hoh" ]; }

if [ -n "$DIR" ]; then
  case "$DIR" in "~"/*) DIR="$HOME/${DIR#"~/"}" ;; esac
  mkdir -p "$DIR" 2>/dev/null || die "cannot create $DIR"
  DIR="$(cd "$DIR" && pwd)"
elif [ -n "$here" ] && is_hub "$here"; then
  DIR="$here"
else
  DIR="$HOME/home-observability-hub"
fi

if is_hub "$DIR"; then
  ok "hub at $DIR"
else
  command -v git >/dev/null 2>&1 || die "git is missing. Run: xcode-select --install, then run this again."
  if [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; then
    die "$DIR exists and is not the hub. Choose another folder with --dir."
  fi
  say "  ...   cloning $REPO_URL into $DIR"
  git clone --depth 1 "$REPO_URL" "$DIR" || die "git clone failed"
  is_hub "$DIR" || die "the clone at $DIR does not look like the hub"
  ok "cloned into $DIR"
fi

# ---- Claude Code
CLAUDE=""
for c in "$(command -v claude 2>/dev/null)" "$HOME/.local/bin/claude" /opt/homebrew/bin/claude /usr/local/bin/claude; do
  if [ -n "$c" ] && [ -x "$c" ]; then CLAUDE="$c"; break; fi
done
if [ -n "$CLAUDE" ]; then
  ok "Claude Code at $CLAUDE"
else
  warn "Claude Code is not installed. Install it with:"
  say  "          curl -fsSL https://claude.ai/install.sh | bash"
  say  "        then open a new Terminal window. (Continuing without it.)"
fi

# ---- folders
CONF="${HOH_CONFIG_DIR:-$HOME/.config/home-observability-hub}"
mkdir -p "$CONF" && chmod 700 "$CONF" || die "cannot create $CONF"
ok "config folder $CONF (mode 700: router key and tokens live here, never in the repo)"
mkdir -p "$DIR/data/state" "$DIR/knowledge" || die "cannot create $DIR/data/state"
chmod +x "$DIR/bin/hoh" "$DIR/discover.py" "$DIR/bin/run.sh" "$DIR/bin/inventory_check.py" 2>/dev/null
[ -f "$DIR/bin/layout_check.py" ] && chmod +x "$DIR/bin/layout_check.py"
ok "data/state ready"

# ---- skills everywhere (optional)
if [ "$GLOBAL" = 1 ]; then
  mkdir -p "$HOME/.claude/skills"
  record="$CONF/global-skills.txt"
  for s in "$DIR"/.claude/skills/*/; do
    [ -d "$s" ] || continue
    name="$(basename "$s")"
    dest="$HOME/.claude/skills/$name"
    if [ -L "$dest" ] || [ -e "$dest" ]; then
      if [ "$(readlink "$dest" 2>/dev/null)" = "${s%/}" ]; then ok "skill $name already linked"; else warn "skip $name: $dest exists"; fi
      continue
    fi
    ln -s "${s%/}" "$dest" && printf '%s\n' "$dest" >> "$record" && ok "linked skill $name"
  done
fi

# ---- self-check
if [ "$RUN_TESTS" = 1 ]; then
  log="$DIR/data/state/install-selftest.log"
  say "  ...   self-check (the test suite, offline, under a minute)"
  if (cd "$DIR" && HM_SENTINEL_NOTIFY=0 "$PY" -m unittest discover -s tests -q) >"$log" 2>&1; then
    ok "self-check passed"
  else
    warn "self-check failed; details in $log. The hub may still work: tell Claude in /setup."
  fi
fi

say ""
say "Installed. Nothing has been scanned and no service is running yet."
say "Next:"
say "    cd \"$DIR\" && claude"
say "then type  /setup"
exit 0
