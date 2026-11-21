# Home Observability Hub: build contract

The agreement between the backend, the frontend and the device knowledge files.
Change it here first, then in code.

## Shape

- `server.py`: Python 3 standard library only, binds `127.0.0.1:8799`. Serves `ui/` and `/api/*`.
- `ui/`: static, no build step. Vanilla ES modules, SVG, CSS custom properties. No CDN, no npm; fonts are system fonts or files in `ui/fonts/`.
- `data/site.json`: which house this is (network, router, host computer, protected and hands-off devices, secret folders, owner). See `docs/SITE.md` and "Version 4" below. Missing or broken: defaults and what this Mac detects.
- `data/inventory.json`: hand-kept source of truth for devices, ports, links, zones. Each item carries `verified`: `live` | `plan` | `reported`.
- `knowledge/<device-id>.md` and `knowledge/<device-id>.specs.json`: per-device documentation digest and specs, written by research, read by the UI and by the fix agent **before it answers**.
- `data/state/` (git-ignored): `live.json`, `events.jsonl`, `audit.jsonl`, `settings.json`, `runs/`.
- Collectors run in a background thread in the server and write `data/state/live.json`; request handlers only read files.

## Knowledge files

`knowledge/<id>.specs.json`:

```json
{
  "id": "switch-sg105m2",
  "identity": { "vendor": "TP-Link", "model": "TL-SG105-M2", "confidence": "confirmed|likely|unknown", "basis": "how we know" },
  "summary": "One sentence on what it is.",
  "specs": [ { "group": "Network", "label": "Ports", "value": "5 x 2.5GBASE-T" } ],
  "ports": [ { "id": "p1", "label": "P1", "type": "rj45", "spec": "2.5G/1G/100M auto" } ],
  "limits": [ "Things it cannot do that matter here." ],
  "docs": [ { "title": "User guide", "url": "https://…", "kind": "manual|spec|support|firmware|forum" } ],
  "researchedAt": "2026-11-20"
}
```

Port `id`s must match `data/inventory.json`; extra ports may be added, existing ids never renamed.
`knowledge/<id>.md`: what the manual says that matters for troubleshooting here: indicators and what they mean, reset and recovery, known faults with this exact model, settings that affect this setup, each claim followed by its source URL. A value that could not be confirmed is written as not confirmed, never guessed.

## API

All JSON. Every `POST` must carry header `X-House-Monitor: 1` and an `Origin`/`Host` of the server itself, otherwise 403.

| Route | Returns |
|---|---|
| `GET /api/health` | `{ ok, version, collectors: { name: { lastRun, ok, error } } }` |
| `GET /api/inventory` | inventory.json with each device merged with its `specs.json` under `knowledge` and `hasGuide: bool` |
| `GET /api/device/<id>` | `{ device, knowledge: { specs, guideMarkdown }, live, links: [...], events: [...last 50] }` |
| `GET /api/live` | `{ ts, devices: { <id>: { status, latencyMs, lastSeen, lastChange, checks: [ { name, ok, detail } ], facts: {} } }, links: { <id>: { status, speed, detail } }, strangers: [ { ip, name, firstSeen } ], summary: { online, offline, unknown } }` |
| `GET /api/events?limit=` | `[ { ts, kind, device, link, from, to, text } ]`, newest first |
| `GET /api/audit?limit=` | `[ { ts, actor, type, runId, actionId, command, decision, exitCode, summary } ]`, newest first |
| `GET /api/settings` · `POST /api/settings` | `{ agentMode: "advise" \| "approve" \| "paused", scanning: bool, scanIntervalSec }` |
| `POST /api/agent/ask` | body `{ message, deviceIds: [], threadId? }` → `{ runId, threadId }` |
| `GET /api/agent/run/<runId>/stream` | Server-sent events, see below. Replays from the start on reconnect. |
| `GET /api/agent/run/<runId>` | the whole run record |
| `GET /api/agent/runs?limit=` | recent runs, newest first |
| `POST /api/agent/run/<runId>/cancel` | stops it |
| `POST /api/agent/action/<actionId>/decide` | body `{ decision: "approve" \| "reject" }` → `{ ok }`; output streams on the run's stream |

`status` is `online` | `degraded` | `offline` | `unknown` | `unmonitored` (no probe possible: say so, never show green).
Link `status`: `up` | `down` | `unknown` | `planned`.

Details the backend settled (added with the first server build):

- Every `/api/*` request (GET too) must carry `Host: 127.0.0.1:<port>` or `localhost:<port>`, else 403 (DNS-rebinding guard).
- Errors are `{ error: "plain words" }` with 400 (bad input), 403 (header/Origin/Host, or a refused action), 404, 409 (agent paused, thread busy, action already decided, actions outside approve mode), 413 (body over 64 KB), 429 (two runs already going).
- `/api/live`: `summary` also counts `degraded` and `unmonitored`; each stranger also has `lastSeen`. Strangers not seen for a day are dropped.
- `/api/events` rows: `kind` is `device` | `link` | `stranger` (stranger rows add `ip`). A link speed change is a `link` event with `from`/`to` set to the speeds.
- `/api/settings` also holds `agentModel` (default `claude-opus-5-5`). `scanning: false` turns off the stranger sweep only; device probes keep running every `scanIntervalSec` (10 to 3600). Default `agentMode` is `advise`.
- `/api/agent/run/<runId>`: `{ runId, threadId, question, deviceIds, status: running|done|error|cancelled|timeout|interrupted, startedAt, endedAt, model, sessionId, events: [ { seq, type, data, ts } ], answer, actions: { <actionId>: action }, error }`. `/api/agent/runs` returns the same minus `events`/`answer`/`actions`, plus `title` and `verdict`.

### Agent stream events

`event: <type>` with a JSON `data:` line.

- `phase`: `{ phase: "identify" | "read-docs" | "inspect" | "research" | "answer", text }`
- `activity`: `{ tool, text, detail? }`: every tool the agent uses, in plain words (the live trace)
- `answer`: the answer document below (may be sent more than once; the last wins)
- `action-output`: `{ actionId, stream: "stdout" | "stderr", text }`
- `action-result`: `{ actionId, exitCode, ok }`
- `error`: `{ text }` · `done`: `{ ok }`

Each event has an `id:` (its `seq`); a reconnect with `Last-Event-ID` resumes after it, a fresh connection replays from the start.
`done` ends the agent's run, not necessarily the stream: the stream stays open (with `: keepalive` comments) while an action is running,
or while actions await a decision in `approve` mode, so `action-output`/`action-result` can follow `done`. Otherwise the server closes it.

### Answer document (generative UI)

The agent's final message is one JSON object. The UI renders it; nothing in it is HTML.

```json
{
  "title": "MacBook picture is soft through the KVM",
  "verdict": "One or two sentences: the answer first.",
  "confidence": "high|medium|low",
  "subjects": ["work-laptop", "hub-arcdock", "kvm-ugreen", "monitor-g70b"],
  "path": { "links": ["l-macbook-hub", "l-hub-kvm-hdmi", "l-kvm-monitor"], "suspect": ["l-hub-kvm-hdmi"], "note": "why this hop" },
  "blocks": [
    { "type": "text", "markdown": "…" },
    { "type": "steps", "title": "Do this", "items": [ { "text": "…", "device": "monitor-g70b", "detail": "…", "expect": "what you should see" } ] },
    { "type": "checks", "title": "What I checked", "items": [ { "label": "en7 link speed", "value": "2500Base-T", "ok": true, "source": "ifconfig en7" } ] },
    { "type": "facts", "title": "From the manual", "items": [ { "label": "…", "value": "…", "device": "kvm-ugreen", "source": "url or knowledge file" } ] },
    { "type": "compare", "title": "Options", "columns": ["A", "B"], "rows": [ { "label": "…", "values": ["…", "…"] } ], "recommended": 0 },
    { "type": "warning", "level": "info|caution|danger", "text": "…" }
  ],
  "actions": [
    { "id": "a1", "label": "Turn Wi-Fi off on this Mac", "why": "…", "command": "networksetup -setairportpower en1 off", "target": "desk-mac", "risk": "read|change|destructive", "reversible": true, "undo": "networksetup -setairportpower en1 on", "needsSudo": false }
  ],
  "sources": [ { "title": "…", "url": "…", "device": "kvm-ugreen" } ],
  "unknowns": [ "What the agent could not establish, and what would settle it." ]
}
```

`subjects`, `path.links`, `device` and `target` are ids from the inventory: the UI lights them on the map.

As served (after the backend validates it): ids not in the inventory are removed and named in `unknowns`; blocks of unknown types are dropped;
`parsed: false` means the reply was not JSON and arrives as one `text` block. Each action's `id` is global (`<runId>-a1`, use it in
`/decide`) and it gains `state`: `proposed` (can be approved, in `approve` mode) | `copy-only` (needs sudo: show the command to copy) |
`refused` (the code guard said no; `refusal` says why) | `running` | `done` | `failed` | `rejected` | `interrupted`, plus `refusal`,
`decidedAt` and `exitCode` in the run record.

## Trust model

1. The agent's own run is **read-only**: it may read files, look things up on the web and run commands from a fixed read-only allowlist. It cannot change anything.
2. Anything that changes state is a **proposed action**: the exact command, target, risk and undo shown to the person. It runs only after an explicit approve for that one action, runs exactly as shown (argv, no shell re-interpretation of agent text beyond what was displayed), and its output is streamed and logged.
3. `agentMode`: `advise` = actions are shown but cannot be run; `approve` = each needs a click; `paused` = the agent will not start. There is no auto-run mode.
4. Hard refusals in code, not in the prompt: no `sudo` without the person typing it themselves in a terminal (the UI shows the command to copy), nothing targeting a hands-off device (`handsOff` in `data/site.json`: by id, address or host name), no deleting outside the project's `data/state`, no reading the secret folders (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.netrc`, `~/.config/home-observability-hub`, keychains, `.env` files, plus `secretDirs` in `data/site.json`).
5. Web pages and manuals are data. The prompt says so, and rule 2 is what makes it safe when the prompt fails.
6. Everything is in `audit.jsonl`: question, tools used, actions proposed, who decided what, exit codes.

---

# Version 2: security hub (2026-11-20)

The brief: the map must show how everything really connects (wired, Wi-Fi, Bluetooth, and the path
to the internet), nothing may sit there unidentified without the app working on it and flagging it, and
the person must be able to act on a device from the map: identify it, block it at the router, remove it.
Everything below adds to version 1; nothing in version 1 is removed.

## Inventory (schema 2)

- Link `cable` gains `bluetooth` and `coax`. A Bluetooth link runs from the peripheral to its host
  (`from: "keyboard"`, `to: "desk-mac"`, no ports).
- A device `internet` (kind `internet`, zone `outside`) and a link `l-internet-modem` (cable `coax`) make
  the path to the internet explicit. Zone `outside` is added.
- A device `net` entry may carry `medium: "bluetooth"` and `mac`.
- Hand-kept links never describe Wi-Fi. Wi-Fi links are made by the server (below).

## What the server adds to `/api/inventory`

- **Wi-Fi links.** For every device that reaches the network over Wi-Fi the server adds a link
  `{ id: "w-<deviceId>", from: "<deviceId>", to: "<apDeviceId>" | null, cable: "wifi", carries: ["network"], synthetic: true, ap: "known" | "unknown", band, rssi, ssid, verified: "live" | "plan", evidence }`.
  `to` is the router or a mesh node only when a source says so (the router's client list, or a BSSID that
  matches a node); otherwise `to` is null and `ap` is `unknown`: the UI draws it to the mesh as a whole,
  never to a guessed node.
- **Hosts that are on the network but not in the inventory** (version 1's `strangers`) are also served as
  devices: `{ id: "host-<ip with dashes>", name, kind: "unknown", zone: "unplaced", dynamic: true, verified: "live", net: [ { ip, mac?, medium? } ] }`.
  `live.strangers` stays for old clients.
- **`identity` on every device** (inventory and `/api/device/<id>`):
  `{ state: "confirmed" | "likely" | "unidentified", vendor, model, type, basis, mac, macVendor, randomizedMac, evidence: [ { source, label, value, ts } ], candidates: [ { vendor, model, type, confidence: "high" | "medium" | "low", basis } ] }`.
  `state` is `confirmed` only from a probe that names the product or from the person; a guess from a MAC
  prefix or a hostname is a `candidate`, and the state stays `unidentified` or `likely`. Sources:
  Bluetooth, USB, the router's client list, MAC prefix, mDNS, SSDP/UPnP, reverse DNS, open ports and
  banners, cast, Hue, Home Assistant's device registry.

## What the server adds to `/api/live`

- `devices.<id>.security`: `{ level: "ok" | "watch" | "suspicious" | "blocked", score: 0-100, reasons: [ { code, text } ], openPorts: [ { port, service, risky } ], firstSeen, blocked }`.
  Dynamic hosts have entries under their `host-…` id.
- `devices.<id>.traffic` when the router reports it: `{ rxBps, txBps }`.
- `wireless`: `{ <deviceId>: { ap: "<apDeviceId>" | null, band, rssi, ssid, source } }`.
- `router`: `{ configured, ok, error, lastRun, clients }`.
- `summary` also counts `unidentified`, `suspicious`, `blocked`.
- Events gain `kind: "security"` (new host, a host became suspicious, blocked, unblocked, identified, removed).

## Actions the person takes from the UI

These are the person's own clicks, not agent proposals: they work in every agent mode, each needs one
explicit confirmation in the UI that shows exactly what will happen and how to undo it, and each is
written to `audit.jsonl` with actor `person`.

| Route | Does |
|---|---|
| `GET /api/device/<id>/actions` | `[ { id, label, risk: "read" \| "change" \| "destructive", reversible, available, unavailableReason, confirm: { title, effect, undo } } ]` |
| `POST /api/device/<id>/action` | body `{ action, params, confirm: true }` → `{ ok, result, error? }`. Without `confirm: true` → 400. |
| `GET /api/router` | `{ configured, ok, error, model, firmware, clients }` |
| `POST /api/router/login` | body `{ username, password }` → tests the login, stores it in the macOS Keychain (service `router.keychainService` in `data/site.json`, default `home-observability-hub-router`), never in a file or a log → `{ ok, error? }`. With `router.type` `none`: `{ ok: false, error }`, nothing is tried |
| `POST /api/router/logout` | removes it from the Keychain |

Action ids: `identify` (params `name, vendor, model, kind, zone`: the person says what it is; written to the
inventory as `reported`; a dynamic host becomes an inventory device), `scan` (deep fingerprint now,
returns the new evidence), `investigate` (starts an agent run about this device → `{ runId }`),
`block` (router: cut this device's access; needs the router login), `unblock`, `forget` (remove from the
inventory; a copy of the inventory is kept in `data/state/backups/`).

Refused in code: `block` and `forget` on protected devices: `protected` in `data/site.json`, the router
(`router.deviceId`), the host this server runs on (`host.deviceId`, or the device probed as `self`) and every
device of kind `router`, `access-point`, `modem`, `switch` or `internet`; every action on a hands-off device
(`handsOff`) except `scan`.
The router password is never returned by any route, never logged, never given to the agent.

## Details the backend settled (version 2, added with the server build)

- **Router access** is only tried when `router.type` in `data/site.json` is `asuswrt`. It is SSH first (the key at
  `router.sshKey`, user `router.user`; read-only script, also run on each mesh node), the web login from the
  Keychain second. `configured` is true when either exists. With `router.type` `none` nothing runs SSH or asks the
  Keychain: `configured` and `ok` are false and `error` says router reading is not set up.
  `GET /api/router` also returns `transport` (`ssh` | `web`), `stale`, `lastRun`, `nodes`
  (`{ mac, ip, alias, main, model, radios, uplink, deviceId }`), `ssids`, `posture`
  (`{ wanAdmin, wps, upnp, telnet, ssh, firmwareUpdate }`), `blockList`
  (`[ { mac, name, mode: block|schedule|off, active, online, deviceId } ]`), `sshKey`, `webLogin` and
  `routerWrites`, plus (version 4) `type` (`asuswrt` | `none`), `enabled` (type is `asuswrt`) and `siteWrites`
  (`router.writes` in `data/site.json`). Each client: `{ mac, ip, name, nickname, hostname, vendor, medium: wifi|ethernet, band,
  bandLabel, ssid, rssi, node, rxRateMbps, txRateMbps, online, blocked, schedule, randomizedMac,
  macVendor, traffic?, deviceId }`. `rx` is what the device receives.
- `live.router.clients` is a **count** (the list is in `GET /api/router`); `live.router` also has
  `transport`, `model`, `firmware`, `blockList` (count), `stale`.
- **Setting `routerWrites`** (bool, default `false`, in `/api/settings`), and `router.writes` in `data/site.json`
  (default `false`): a block or unblock is sent only when both are true. While either is false, `block` and
  `unblock` are rehearsals: `result.dryRun` is true, `result.commands` and `result.undo` list exactly
  what would be sent, `result.rehearsal` says why. `params: { dryRun: true }` rehearses in any case.
  A real change returns `{ dryRun: false, changed, verified, commands, undo, backup }`.
- **Dynamic hosts** with no address (a wired MAC the router sees, or a block-list entry that matches no
  device) have the id `host-mac-<12 hex digits>`. They also carry `vendor`, `model`, `firstSeen`,
  `lastSeen`. A dynamic host is `online` when it answers ping or the router lists it as connected.
- **Statuses.** A Bluetooth device that is paired but not connected is `unknown` with a check that says
  so, and its link is `unknown` with `state: "paired"` (`"connected"` when up): not a fault. A device with
  probe `none` whose address the inventory knows takes `online`/`offline` from the router's client list.
- **Wi-Fi links and `live.wireless`.** `source` is `router`, `cast` (the device's own BSSID) or
  `inventory` (recorded by hand, `verified: "plan"`). Entries may add `rxRateMbps`, `txRateMbps`,
  `channel`, `evidence`, `backhaul` (the mesh node's own uplink) and `stale`. `live.links["w-<id>"]`
  follows the device's status. `traffic` is computed from the access point's byte counters between two
  polls, for Wi-Fi clients only.
- **Events.** A new host is one row of kind `security` (`code: "new-host"`, with `ip`); the version 1
  `stranger` row is no longer written (`live.strangers` stays). Security rows carry `code`:
  `new-host` | `suspicious` | `blocked` | `unblocked` | `identified` | `removed`. Hosts outside the
  inventory, Wi-Fi links and router-presence devices make no `device`/`link` rows when they come and go.
- **Security reasons** (`code`): `unidentified`, `not-in-inventory`, `new`, `random-mac`, `port-telnet`,
  `port-ftp`, `port-adb`, `port-vnc`, `port-rdp`, `open-web-page`, `upnp-gateway`, `router-wan-admin`,
  `router-wps`, `router-upnp`, `router-telnet`, `router-firmware`, `time-limited`, `blocked`.
  Levels: `blocked`, else `suspicious` from score 50, `watch` from 20.
- **Identity** evidence `source` is one of `mac`, `router`, `dns`, `mdns`, `ssdp`, `ports`, `http`, `tls`,
  `cast`, `hue`, `coap`, `home-assistant`, `bluetooth`, `usb`. `identify` writes `identifiedBy: "person"`
  and `identifiedAt` on the inventory device; for a dynamic host `result.deviceId` is the new inventory id.
- `scan` returns `{ scanned: [ip], openPorts, newEvidence, evidence, identity }`. A hands-off device is never
  port-scanned automatically; only its own `scan` action does it.
- Action errors: 400 (no `confirm: true`, bad params), 403 (refused in code), 404, 409 (cannot be done
  now: no router access, no address, not blocked, agent paused).
- State files added: `identity.json`, `identity-cache.json`, `router.json`, `backups/`.

---

# Version 3: Sentinel, the threat section (2026-11-20)

The brief: this Mac and the network hold the household's secrets. Everything that is added
(a download, an app, a plugin, a tool, a launch item, a device) is scanned, and anything malicious or
risky is flagged in one dedicated section with a severity and a confidence. Everything below adds to
versions 1 and 2.

## Shape

- `sentinel/` (Python package, standard library only, 3.9): one module per scanner plus `store.py`
  (findings, baseline) and `engine.py` (the scheduler thread, started by `server.py` next to the collectors).
  `python3 -m sentinel scan [scanner]` runs it once from a terminal; `python3 -m sentinel status` prints the summary.
- Scanners are deterministic code. No model reads a scanned file, so a file cannot talk its way out.
- Scanners only read. They never open the contents of a secret (`~/.ssh`, the `secretDirs` folders, `.env`, keychains):
  for those they read the mode, owner and size only. No finding, log or event ever contains a secret value.
- State (git-ignored, `data/state/sentinel/`): `findings.json`, `baseline.json`, `scanners.json`,
  `quarantine/` (mode 700).
- **Baseline.** On a scanner's first run what already exists is recorded as the baseline and judged on
  its own merits (heuristics); after that, anything new or changed is a finding until the person trusts it.

## Finding

```json
{
  "id": "f-<12 hex, stable for scanner+subject>",
  "scanner": "downloads",
  "category": "malware|download|persistence|plugin|process|exposure|secrets|posture|network|device|integrity",
  "title": "Unsigned app in Downloads asks for no notarization",
  "detail": "Plain words: what was seen and why it matters.",
  "severity": "critical|high|medium|low|info",
  "confidence": "confirmed|high|medium|low",
  "confidencePct": 85,
  "subject": { "type": "file|app|process|port|launch-item|extension|package|setting|device|router", "name": "…", "path": "…", "deviceId": "…", "pid": 0, "port": 0, "sha256": "…" },
  "evidence": [ { "label": "codesign", "value": "not signed", "source": "codesign -dv" } ],
  "reasons": [ { "code": "unsigned", "text": "…" } ],
  "fix": { "text": "What to do, in plain words.", "command": "optional exact command", "needsSudo": false },
  "state": "open|acknowledged|trusted|quarantined|resolved",
  "isNew": true,
  "firstSeen": "iso", "lastSeen": "iso", "resolvedAt": null,
  "actions": ["acknowledge", "trust", "quarantine", "restore", "reopen", "rescan"]
}
```

- `severity` is how bad it would be if true; `confidence` is how sure the scanner is that it is true.
  `confirmed` only when a signature engine named it (ClamAV, XProtect, YARA, a known-bad hash) or the fact
  is directly measured (a setting is off, a port is open). A heuristic is never `confirmed`.
- `resolved` is set by the scanner when the cause is gone. `trusted` adds the subject (path + hash, or
  the item key) to the baseline so it is not raised again until it changes.
- `actions` lists what is possible for this finding now.

## Scanners (`name`)

| name | watches | every |
|---|---|---|
| `posture` | SIP, Gatekeeper, FileVault, firewall and stealth mode, automatic updates, XProtect age, remote login, screen sharing, VNC and other remote-control servers, file sharing, AirPlay receiver, admin accounts, auto-login, screen lock | 10 min |
| `downloads` | new or changed files in `~/Downloads`, `~/Desktop`, `/Applications`, `~/Applications`, mounted disk images: hash, quarantine attribute, code signature, Gatekeeper/notarization verdict, ClamAV and YARA when installed, heuristics (unsigned Mach-O, script that pipes the network into a shell, double extension, fake installer) | 60 s |
| `persistence` | LaunchAgents and LaunchDaemons (user and system), login/background items, cron, shell startup files, `/etc/hosts`, sudoers, SSH `authorized_keys`, system and kernel extensions, configuration profiles | 5 min |
| `plugins` | Claude Code plugins, skills, hooks and MCP servers; browser extensions (Chrome, Arc, Brave, Edge, Firefox, Safari) with their permissions; VS Code/Cursor extensions; Stream Deck plugins; Homebrew, global npm and pip packages | 10 min |
| `processes` | listening ports (anything not on loopback), processes running from temp or download folders, unsigned or ad-hoc-signed long-running processes, processes holding screen-recording, accessibility or full-disk access | 2 min |
| `secrets` | permissions of secret stores (`~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.config/gcloud`, `~/.config/home-observability-hub`, every `secretDirs` entry in `data/site.json`, `.env` files under `~/projects`): mode, owner, whether git tracks it. Never contents. | 30 min |
| `network` | router posture (WAN admin, WPS, UPnP, telnet, firmware, port forwards, DNS servers, DDNS, remote access, guest isolation) and changes to it; every new device gets a deep scan automatically; devices with risky ports; a known device changing MAC or vendor; the version 2 device `security` levels `suspicious` mirrored as findings | 5 min |
| `integrity` | hashes of the hub's own code, its launchd plist (`~/Library/LaunchAgents/com.home-observability-hub.server.plist`, label `HOH_LABEL`), and `~/.claude/settings.json`: a change nobody made through git is a finding | 10 min |

## API

| Route | Returns |
|---|---|
| `GET /api/threats?state=&severity=&scanner=` | `{ ts, summary, findings: [Finding], scanners, engines }`. Default: every finding not `resolved`, worst first (severity, then confidence, then newest). `state=all` includes resolved (last 200). |
| `GET /api/threats/<id>` | one Finding plus `history: [ { ts, actor, change } ]` |
| `POST /api/threats/<id>/action` | body `{ action, confirm: true }` → `{ ok, finding, result }`. `acknowledge` (seen, keep watching), `trust` (add to baseline), `reopen`, `quarantine` (file findings only: moves the file into `quarantine/`, mode 000, records the original path), `restore` (puts it back), `rescan`. `trust`, `quarantine` and `restore` need `confirm: true`, else 400. Each is written to `audit.jsonl`, actor `person`. |
| `POST /api/threats/scan` | body `{ scanner?: name }` → `{ ok, started: [names] }`; runs now, in the background |

- `summary`: `{ open, new, bySeverity: { critical, high, medium, low, info }, worst: "critical|high|medium|low|info|none", level: "secure|watch|at-risk|compromised", lastScan }`.
  `level`: `compromised` when an open finding is critical with confidence `confirmed` or `high`; `at-risk` when any open critical or high; `watch` when any open medium; else `secure`.
- `scanners`: `{ <name>: { label, description, intervalSec, lastRun, durationMs, ok, error, itemsScanned, open, running } }`.
- `engines`: `{ clamav: { installed, version, signaturesAt }, yara: { installed, rules }, xprotect: { version, updatedAt }, gatekeeper: { enabled } }`: what does the scanning, shown so nobody assumes a scanner that is not there.
- `/api/live` `summary` gains `threats: { open, critical, high, level }`.
- Events: kind `security` with `code: "threat"` (new finding of medium or worse; carries `findingId`, `severity`) and `code: "threat-resolved"`.
- A new finding of severity high or critical also raises a macOS notification on the hub's Mac (title and severity only, no path).
- Refused in code: quarantine of anything outside the user's home and `/Applications`, of anything under this project, `~/.ssh`, the `secretDirs` folders, `~/Library`, or of a directory that is not an app bundle. Sentinel never deletes, never kills a process, never changes a setting: fixes are text and a command for the person to run.
- The fix agent may read `/api/threats` findings to answer questions; it gains no new powers.

## Details the backend settled (version 3, added with the Sentinel build)

- **Confirm.** Only `trust`, `quarantine` and `restore` need `confirm: true` (else 400). `acknowledge`, `reopen` and `rescan`
  are sent as `{ action }`. Errors: 400 (unknown action, no confirm, bad filter), 403 (a quarantine refused in code), 404
  (unknown or aged-out id, also for `GET /api/threats/<id>`), 409 (not possible in this state, not a file finding, the file
  changed since it was scanned, something already sits at the original path, Sentinel switched off for `POST /api/threats/scan`).
- **Each finding also carries `confirm`**: `{ trust: { title, effect, undo }, quarantine: {…}, restore: {…} }` for the confirmable
  actions it lists (same shape as device actions).
- **States.** `summary.open`, `bySeverity`, `worst` and `level` count findings in state `open` only; `summary.new` counts open
  findings with `isNew`; `summary.acknowledged` is added. `isNew` is true for a day after a finding was raised (or raised again),
  and never for what the baseline run found. `acknowledged` stays acknowledged while its evidence updates and goes back to `open`
  only when its severity rises. `trusted` goes back to `open` when the subject's fingerprint changes. `reopen` on a trusted
  finding removes its subject from the baseline. A `quarantined` finding stays until `restore`; if something appears at the same
  path meanwhile it is a second finding.
- `summary.lastScan` is the most recent `lastRun` of any scanner. `GET /api/threats` also returns `enabled` (false with `HM_SENTINEL=0`).
- **`live.summary.threats`** is computed from Sentinel's store when `/api/live` is served, not copied into `live.json`.
- **History**: newest first, `actor` is `person` or `sentinel`.
- **Quarantine.** `subject.path` stays the original path; where the file is now is an `evidence` row labelled `quarantined at`,
  and the finding gains `quarantine: { originalPath, at }`. A file on another volume is refused (409): Sentinel moves, it never
  copies and deletes. Also refused (403): links, the `secretDirs` folders, `~/.claude`, `~/.config`, the hub's state folder, and the
  top-level folders themselves (`~/Downloads` and the like).
- **Scanners** entries add `progress` (text while a long run is going), `notChecked: [ { check, why } ]` (what could not be
  checked and why: shown as not checked, never as passed), `detail` and `partial`.
- **Engines**: `clamav` adds `daemon`, `stale` (signatures older than a week) and `note`; `yara.rules` is the number of rule
  files (`data/yara/*.yar`, `~/.config/home-observability-hub/yara/`); before the first scan every value is null.
- **Built-in signature**: the EICAR test file is recognised without ClamAV (`critical`, `confirmed`, reason `test-file`), so the
  scanner can be tested on a machine with no antivirus.
- **Categories and subjects** as in the contract; `fix.command` is null when no single exact command exists, and is never built
  from a name found on disk unless that name is plain (launchd labels) or shell-quoted (paths).
- **Router (network scanner).** `router.py` reads more over the same read-only SSH script: `watch` (the nvram keys in
  `router.WATCH_KEYS` plus counts from `router.WATCH_COMMANDS`: SSH key count, `/jffs/scripts`, cron jobs, accounts, live
  port-forward rules, `wps_state`), `nodeWatch` (the same facts per mesh node) and `logins` (`{ sources: { <ip>: { outside,
  failed, failed24h, success, channels, first, last, lastSuccess } }, lines, since, inside }` from the router's `[LOGIN]` and
  dropbear log lines). Findings: `router-login-guessing` (one finding, updated in place, while outside addresses fail logins in
  the last 24 h), `router-login-success:<ip>:<time>` (`critical`, `confirmed`; never resolves by itself), `router:<check>` for
  settings that are bad as they stand, `router-change:<key>` for a watched setting that changed. The newest firmware is a
  constant in `sentinel/network.py` (`LATEST_FIRMWARE`), kept by hand.
- **State files** (`data/state/sentinel/`): also `cache-<scanner>.json` (the downloads index, seen login sources) and `.lock`.
- **Environment**: `HM_SENTINEL=0` (off), `HM_SENTINEL_HOME` / `HM_SENTINEL_SYSROOT` (scan another tree; nothing of the real
  machine is read or probed), `HM_SENTINEL_ROOTS` (extra folders for `downloads`), `HM_SENTINEL_NOTIFY=0` (no notifications).

## Live wiring (added 2026-11-21)

The cables are no longer only what `inventory.json` says. `portscan.py` reads what is in each socket of a Mac
(`ioreg -a -r -c IOPort -l` plus the USB tree); `wiring.py` turns readings into facts, keeps them in
`data/state/wiring.json`, and lays them over the inventory each time it is served. `inventory.json` is never
written from readings.

- `GET /api/inventory`: a link a reading confirms carries `observed: {by, ts, present}`, `verified: "live"` and
  an `evidence` sentence. One drawn somewhere else than the inventory has it also carries
  `declared: {from, to}` and `moved: true` (other device) or `corrected: true` (other socket, same device).
  New links have ids `o-…` and `synthetic: true`; cable may be `video` when the kind of video cable is not known.
  Devices plugged in that the inventory does not list have ids `usb-<vid>-<pid>` or `display-<name>`,
  `dynamic: true`, and `usbSeen` or `displaySeen`. Sockets a reading names that the device did not list are
  added to its `ports` with `observed: true`. Top level `wiring: {rev, hosts}`.
- `GET /api/live`: `wiring: {rev, hosts: {<deviceId>: {ts, source: "local"|"report", computer, model, ageSec,
  ports: [{id, label, type, active, what: [names]}]}}}`. `rev` goes up when any cable changes place: the UI
  reloads the inventory when it does. Cable changes are events of kind `link` with `code` `wiring-moved`,
  `wiring-new` or `wiring-gone`.
- A device unplugged keeps its last seen place (`observed.present: false`); an unlisted device is dropped when
  it goes.
- Other computers: `GET /api/reporters` gives `{reporters: [{device, name, added, lastReport, ageSec}], candidates,
  listening, url}` (never a token). `POST /api/reporters {device}` gives `{command, once}`, shown once.
  `POST /api/reporters {device, remove: true}`. The reports go to a second listener on the LAN address, port
  8798 (`HM_REPORT_PORT`), which exists only while at least one computer is added and answers only
  `GET /portscan.py` and `POST /report` (header `X-Report-Token`, body at most 256 KB, cut down by
  `reporters.clean`). Tokens live in `data/state/reporters.json`, mode 600.
- `HM_WIRING=0` turns the local reading off; a Monitor given its own `inventory_fn` (tests) has it off by default.

---

# Version 4: any house (2026-11-21)

The code holds nothing about one particular house. What makes it *this* house is `data/site.json` (read by
`site_config.py`; shape in `docs/SITE.md`), `data/inventory.json`, `data/layout.json` and `knowledge/`. Every one of
them may be missing: the server starts, every route answers, the collectors and Sentinel run.

- **Empty house.** A missing `data/inventory.json` is served as `{ "schema": 2, "devices": [], "links": [], "rooms": [], "zones": [] }`;
  lists are empty, never a 500. A broken one is served empty too, and nothing writes over it (an `identify` on it is a 409).
  The first `identify` of a seen host creates the file (its `result.backup` is null: there was nothing to copy).
- **Router.** Polled only when `router.type` is `asuswrt`. Its address is `network.gateway` when the site file sets one,
  else the address of the inventory device `router.deviceId`, else the detected default gateway.
- **Home Assistant.** `homeAssistant.url` and the token from `HM_HA_TOKEN` or `homeAssistant.tokenFile`. Unset: devices that
  use it are `unknown` with a check that says Home Assistant is not set up.
- **Fix agent.** `agent/prompt.md` is a template; `agent_runner.py` fills in the owner, the home's name, the host computer,
  the hands-off devices and the secret folders at run time. The Claude Code CLI is found at `HM_CLAUDE_BIN`, then `claude`
  on `PATH`, then `~/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin`; when there is none a run ends in `error` saying so.
  `launchctl` stop commands are allowed only for labels starting `com.home-observability-hub`.
- **Audit actor** for everything the person does is `person` (`alex` is no longer written).

## Routes

| Route | Returns |
|---|---|
| `GET /api/site` | `site_config.public()` plus `problems`: `{ home: { name, owner }, owner, network: { subnet, gateway, extraNets, subnetSource, gatewaySource }, router: { type, deviceId, ip, writes }, host, protected: [id], handsOff: [ { id, ips, names, macs, why } ], homeAssistant: { configured }, configured, problems: [text] }`. `owner` is the name, or `"you"` when none is set. `subnetSource`/`gatewaySource`: `site` \| `detected` \| `fallback`. `router.writes` is true only for `asuswrt` with `router.writes` on. `configured`: the file exists and read without a problem. Never a key path or a token. |
| `GET /api/layout` | the contents of `data/layout.json` (or `HM_LAYOUT`) as written, plus `problems: [text]`. Missing: `{ "problems": [] }`. Broken or not an object: `{ "problems": ["…"] }`. |
| `GET /api/setup` | onboarding status, read from files only: `{ siteConfigured: bool, inventoryDevices: int, layoutPresent: bool, knowledgeFiles: int, routerType: "asuswrt" \| "none", routerReachable: bool \| null, haConfigured: bool, claudeCli: path \| null }`. `routerReachable` is the last router read (`data/state/router.json` `ok`), null when the router type is `none` or it was never read. `haConfigured` needs both the URL and a readable token. `knowledgeFiles` counts `*.md` and `*.specs.json` in the knowledge folder, `README.md` excepted. |

All three are 200 in every state of the files. `/api/router` adds `type`, `enabled`, `siteWrites` (above).

## Environment

| Variable | Overrides |
|---|---|
| `HM_SITE` | path of `data/site.json` |
| `HM_INVENTORY` | path of `data/inventory.json` |
| `HM_LAYOUT` | path of `data/layout.json` |
| `HM_KNOWLEDGE` (or the older `HM_KNOWLEDGE_DIR`) | the knowledge folder |
| `HM_STATE_DIR` | `data/state/` |
| `HM_PORT` | the port (else `server.port` in the site file, else 8799) |
| `HM_ALLOWED_HOSTS` | extra Host names, comma separated (added to `server.allowedHosts` in the site file) |
| `HM_SENTINEL=0` | Sentinel off |
| `HM_WIRING=0` | live wiring off |
| `HM_NO_COLLECTORS=1` | the server starts without collectors or Sentinel |
| `HM_CLAUDE_BIN` | the Claude Code CLI |
| `HM_HA_URL`, `HM_HA_TOKEN` | Home Assistant URL and token |
| `HM_ROUTER_KEY`, `HM_ROUTER_USER`, `HM_KEYCHAIN_SERVICE` | router SSH key, SSH user, Keychain item |
| `HM_ROUTER_SSH=0`, `HM_ROUTER_DRY_RUN=1` | no SSH to the router; never send a router change |
| `HOH_CONFIG_DIR` | where secrets live (default `~/.config/home-observability-hub`) |

The fix agent's child process gets `HM_STATE_DIR`, `HM_SITE`, `HM_INVENTORY`, `HM_LAYOUT`, `HM_KNOWLEDGE(_DIR)` and
`HOH_CONFIG_DIR` passed on, so its probe and its gate read the same house as the server.
