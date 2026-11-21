#!/bin/sh
# Home Observability Hub: update the code, check it, restart the service if it is installed.
#
#   sh update.sh
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR" || exit 1
PY=/usr/bin/python3
[ -x "$PY" ] || PY="$(command -v python3)"
LABEL="${HOH_LABEL:-com.home-observability-hub.server}"
AGENTS="${HOH_LAUNCH_AGENTS:-$HOME/Library/LaunchAgents}"

git pull --ff-only || { printf 'git pull --ff-only failed: local changes or a diverged branch. Nothing was changed.\n' >&2; exit 1; }
chmod +x bin/hoh discover.py bin/inventory_check.py 2>/dev/null
"$PY" bin/hoh check || printf 'The inventory or layout has problems (above). Ask Claude: /doctor\n'
if [ -f "$AGENTS/$LABEL.plist" ]; then
  # Re-render the plist (the template may have changed), which also restarts the service.
  "$PY" bin/hoh service install
fi
"$PY" bin/hoh doctor
