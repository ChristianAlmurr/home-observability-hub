#!/bin/sh
# Home Observability Hub: remove the background service, and (after asking) its data.
#
#   sh uninstall.sh          asks before deleting data/ and the config folder
#   sh uninstall.sh --yes    deletes them without asking
#
# The code folder itself is left in place: delete it yourself when you are done.
# HOH_LABEL and HOH_LAUNCH_AGENTS are honoured, as in bin/hoh.
set -u
YES=0
for a in "$@"; do
  case "$a" in
    --yes|-y) YES=1 ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'unknown option: %s\n' "$a" >&2; exit 2 ;;
  esac
done

DIR="$(cd "$(dirname "$0")" && pwd)"
LABEL="${HOH_LABEL:-com.home-observability-hub.server}"
AGENTS="${HOH_LAUNCH_AGENTS:-$HOME/Library/LaunchAgents}"
PLIST="$AGENTS/$LABEL.plist"
CONF="${HOH_CONFIG_DIR:-$HOME/.config/home-observability-hub}"

ask() {
  [ "$YES" = 1 ] && return 0
  [ -r /dev/tty ] || { printf '%s [skipped: no terminal; use --yes]\n' "$1"; return 1; }
  printf '%s [y/N] ' "$1"
  read -r ans </dev/tty || return 1
  case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# The service: only our own label, never anything else.
if launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null && printf 'stopped %s\n' "$LABEL"
fi
if [ -f "$PLIST" ]; then rm -f "$PLIST" && printf 'removed %s\n' "$PLIST"; fi

# Global skill links that install.sh --global made (only links that point into this folder).
REC="$CONF/global-skills.txt"
if [ -f "$REC" ]; then
  while IFS= read -r link; do
    [ -n "$link" ] || continue
    if [ -L "$link" ]; then
      case "$(readlink "$link")" in "$DIR"/*) rm -f "$link" && printf 'removed skill link %s\n' "$link" ;; esac
    fi
  done < "$REC"
  rm -f "$REC"
fi

if [ -d "$DIR/data" ] && ask "Delete this house's data ($DIR/data: inventory, layout, site, history)?"; then
  rm -rf "$DIR/data/state" "$DIR/data/site.json" "$DIR/data/inventory.json" "$DIR/data/layout.json"
  find "$DIR/knowledge" -type f ! -name README.md -exec rm -f {} + 2>/dev/null
  printf 'deleted data/ and knowledge/ files\n'
fi
if [ -d "$CONF" ] && ask "Delete $CONF (router SSH key, Home Assistant token)?"; then
  rm -rf "$CONF" && printf 'deleted %s\n' "$CONF"
  printf 'If you added the router key, also remove it from the router: Administration > System > Authorized Keys.\n'
fi
printf 'Done. The code is still in %s.\n' "$DIR"
