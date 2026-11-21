# Home Observability Hub

A local map of one home's network and desk wiring: every device, how it connects, whether it is up,
and a fix agent that can only propose changes. It runs on a Mac in the home, on 127.0.0.1 only.

**New here? Type `/setup`.** It checks this Mac, scans the network (read-only, after you agree),
asks you about what it cannot tell, writes your house's files and starts the hub. It picks up where it
left off if interrupted. Later: `/rescan`, `/wiring`, `/identify`, `/add-device`, `/doctor`.

## One house's files

The code is the same for every home. Your home is (see `docs/SITE.md`):

- `data/site.json`: network, router, the computer the hub runs on, protected and hands-off devices, owner
- `data/inventory.json`: devices, ports, cables, rooms, zones, open questions (`docs/CONTRACT.md`)
- `data/layout.json`: optional pins for the two maps
- `knowledge/<id>.md`, `knowledge/<id>.specs.json`: per-device documentation digests
- `~/.config/home-observability-hub/`: router SSH key, Home Assistant token (mode 700)

`data/state/` is runtime output (discovery.json, live.json, logs, onboarding.json).

## Rules

- **Never invent hardware.** A vendor or model is written only when a probe shows it (SSDP description,
  mDNS TXT model, Cast API, system_profiler, the router) or the owner says it. A MAC prefix, hostname or
  open port is a lead, never an identity. What nobody can settle goes in `openQuestions`.
- **Evidence levels** on every device, net entry and link: `live` (probed), `reported` (the owner said
  so), `plan` (drawn, not confirmed). Never upgrade without a probe.
- **Hands-off devices** (`site.json` `handsOff`: a work laptop, a housemate's computer) are look-only: no
  port checks, no research, no proposed commands.
- **Secrets**: never read `~/.config/home-observability-hub/`, `~/.ssh`, `~/.aws`, the Keychain or any
  token file; never ask for or store a router password. Tokens go in through `python3 bin/hoh ha set-token`.
- **The fix agent is read-only** (`agent/prompt.md`, `bin/probe.py`, `bin/agent_gate.py`): changes are
  proposals a person approves one by one. Do not widen its tools.
- **Discovery is read-only**: `discover.py` pings, queries mDNS/SSDP, connects to a few ports and reads
  landing pages. Never log into devices or routers.
- `data/` and `knowledge/` are never committed (`.gitignore`).
- Validate after every inventory edit: `python3 bin/inventory_check.py` (and `python3 bin/layout_check.py`).
- Only ever stop or restart the hub's own launchd job (`python3 bin/hoh …`), never `pkill` by pattern.

## Commands

```bash
python3 bin/hoh doctor                 # health, with a fix per problem
python3 bin/hoh scan [--diff] [--json] # discovery → data/state/discovery.json
python3 bin/hoh check                  # inventory + layout validation
python3 bin/hoh service install        # launchd job com.home-observability-hub.server (HOH_LABEL overrides)
python3 bin/hoh start|stop|restart|status|logs|open
python3 portscan.py                    # what is plugged into this Mac
python3 site_config.py                 # the resolved site settings
bin/run.sh                             # the server in the foreground
```

## Tests

Standard library only; must pass on `/usr/bin/python3` (3.9) and a newer `python3`:

```bash
/usr/bin/python3 -m unittest discover -s tests
python3 -m unittest discover -s tests
```

Tests never touch the network, launchd, the Keychain or the real `data/`.

## Layout of the code

`server.py` (HTTP + API), `collectors.py` (probes, writes live.json), `identify.py` (evidence → identity),
`router.py` (AsusWRT, read-only), `wiring.py` + `portscan.py` (live cables), `sentinel/` (threat
scanner), `agent_runner.py` (the fix agent), `discover.py` (onboarding discovery), `bin/` (CLI and
checks), `ui/` (static, no build), `.claude/` (the onboarding commands, skills and agents),
`docs/` (CONTRACT, SITE, SETUP, DESIGN).
