#!/bin/sh
# Start Home Observability Hub in the foreground on 127.0.0.1 (port from HM_PORT, default 8799).
cd "$(dirname "$0")/.." || exit 1
PY=python3
[ -x /opt/homebrew/bin/python3 ] && PY=/opt/homebrew/bin/python3
exec "$PY" server.py "$@"
