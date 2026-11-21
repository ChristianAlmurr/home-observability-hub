# Installing and setting up

## What you need

- A Mac that stays in the home and on its network (a Mac mini is ideal), macOS 12 or newer.
- Python 3.9 or newer. Apple's Command Line Tools provide it: `xcode-select --install`.
- Claude Code, logged in: `curl -fsSL https://claude.ai/install.sh | bash`, then `claude` once to log in.

## Install

```bash
git clone <repository url> ~/home-observability-hub
cd ~/home-observability-hub
sh install.sh
```

or in one line: `curl -fsSL https://raw.githubusercontent.com/ChristianAlmurr/home-observability-hub/main/install.sh | sh` (clones into `~/home-observability-hub`;
`sh -s -- --dir <folder>` to choose another).

`install.sh` checks macOS, Python and Claude Code, creates `~/.config/home-observability-hub` (mode 700)
and `data/state`, and runs the tests once (`--no-test` skips them). It does **not** scan your network or
start anything. `--global` also links the hub's skills into `~/.claude/skills`. Running it again is safe.

## Set up

```bash
cd ~/home-observability-hub
claude
```

then type `/setup`. Claude explains what will happen and asks before it scans. On the first scan macOS
may ask whether Terminal (or the app you run Claude Code in) may "find devices on local networks":
click **Allow**. If you clicked Don't Allow: System Settings > Privacy & Security > Local Network, switch
it on, quit and reopen the app, and run `claude --continue`.

The setup takes about 20 minutes and can be interrupted: `/setup` again continues where it stopped.

What it asks you: your first name and a name for the home, the rooms, what the devices it could not
identify are and where they are, which devices are not yours to manage, your router, Home Assistant,
and (optionally) your cables. What it reads: what devices on your network say about themselves
(addresses, names, advertised services, landing pages), and what is plugged into this Mac. Nothing is
logged into and nothing is changed. Nothing leaves the Mac except what Claude Code sends to Claude
during the conversation.

## Router access (optional)

AsusWRT and ZenWiFi routers can be read over SSH with a key: `python3 bin/hoh router setup-key` makes one
and prints the steps (Administration > System: Enable SSH LAN only, Allow Password Login No, paste the
key). Other routers: the hub finds devices without them. Details: `.claude/skills/router-access/SKILL.md`.

## Day to day

| | |
|---|---|
| open the hub | `python3 bin/hoh open` (http://127.0.0.1:8799) |
| something changed on the network | `/rescan` in Claude Code |
| cables moved | `/wiring` |
| unknown devices | `/identify` |
| something is wrong | `/doctor`, or `python3 bin/hoh doctor` |
| stop / start | `python3 bin/hoh stop`, `python3 bin/hoh start` |
| update | `sh update.sh` |
| remove | `sh uninstall.sh` (asks before deleting your data) |

## The service

`python3 bin/hoh service install` renders `deploy/launchd.plist.template` into
`~/Library/LaunchAgents/com.home-observability-hub.server.plist` (this folder's path, `/usr/bin/python3`,
logs in `data/state/server.log` and `server.err`) and starts it. `HOH_LABEL` changes the label (tests use
it); any `HM_*` variable set when you run `service install` is written into the job's environment
(`HM_PORT`, `HM_STATE_DIR`, `HM_ALLOWED_HOSTS`, …). The port comes from `HM_PORT`, else `server.port` in
`data/site.json`, else 8799.
