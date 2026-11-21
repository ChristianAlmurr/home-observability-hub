---
description: Check that the hub, this Mac, the network access and the data files are healthy, and fix what can be fixed
---

Run `python3 bin/hoh doctor` and go through every line that is not OK:

- Fix it yourself when the fix is one of the hub's own commands (`python3 bin/hoh service install`,
  `python3 bin/hoh restart`, `python3 bin/inventory_check.py` and editing the error it names).
- Network FAIL with a default route: macOS Local Network permission. Explain: System Settings >
  Privacy & Security > Local Network, switch on the app running Claude Code, quit and reopen it, then
  `claude --continue`. If this shell is sandboxed, the same symptom appears: retry outside the sandbox.
- Service FAIL: `python3 bin/hoh logs`, read the error, fix, `python3 bin/hoh restart`.
- Port taken: choose a free port in 8800-8899, set `server.port` in `data/site.json`, reinstall the service.
- Router or Home Assistant FAIL: follow the `router-access` skill, or have the owner make a new token and
  run `python3 bin/hoh ha set-token` in their own Terminal window.

Never read `~/.config/home-observability-hub/` or `~/.ssh`. Never stop or restart any launchd job other
than the hub's own (`python3 bin/hoh …` only touches its own label). End with doctor run again and a
one-line verdict.
