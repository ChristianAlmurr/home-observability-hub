---
name: home-onboarding
description: The complete first-run procedure for Home Observability Hub - from a fresh clone to a live map of the home network and desk wiring. Use for /setup, or when someone says "set this up", "onboard my house", "start over", "continue the setup", "map my home network", or opens the project with no data/site.json or data/inventory.json.
---

# Home onboarding

You take someone from nothing to a working hub: their devices found and named, their cables mapped,
the service running, both maps checked by eye. They may not be technical. Be brief, plain and
concrete; one thing at a time; never paste raw JSON at them.

Skills you will use: `device-identification`, `inventory-authoring`, `router-access`, `wiring-mapping`.
Agents: `network-scout`, `device-researcher`, `layout-designer`.

## Ground rules (they hold through every step)

- **Never invent hardware.** A model goes in only when a probe shows it or the person says it. What
  nobody can settle goes into `openQuestions`.
- **Evidence levels**: `live` (seen by a probe now), `reported` (the person said so), `plan` (assumed).
- **Read-only toward the network.** Discovery only looks. Never log into anything, never try passwords,
  never port-scan hands-off devices.
- **Secrets**: never read `~/.config/home-observability-hub/`, `~/.ssh`, the Keychain, or any token file.
  Never ask for a router password. Tokens go in through `python3 bin/hoh ha set-token`, which the person runs
  in a separate Terminal window (it asks with a hidden prompt), never through this chat.
- **Consent first**: nothing is scanned and no service is installed before the person agrees (step 1),
  and the background service only with a second yes (step 10).
- `data/`, `knowledge/` and the config folder are never committed.
- Validate after every write: `python3 bin/inventory_check.py` (and `python3 bin/layout_check.py` when
  present). Never leave the inventory failing.

## Progress file and resuming

Keep `data/state/onboarding.json` up to date after each step:

```json
{ "version": 1, "startedAt": "…", "updatedAt": "…", "step": "interview",
  "done": ["consent", "doctor", "scan"],
  "answers": { "owner": "Sam", "home": "The Flat", "rooms": ["living", "study"], "routerAccess": "later",
               "homeAssistant": false, "handsOff": ["work-laptop"] },
  "skipped": { "wiring": "Sam will do it at the weekend" } }
```

Steps, in order: `consent`, `doctor`, `scan`, `interview`, `router`, `write`, `reconcile`, `wiring`,
`knowledge`, `service`, `summary`.

**On start, work out where things stand before saying anything else:**

1. Read `data/state/onboarding.json` if it exists.
2. Otherwise infer: `data/site.json` exists → consent, doctor and interview happened; `data/inventory.json`
   exists and passes inventory_check → `write` is done; `python3 bin/hoh status` answering → `service` done;
   `knowledge/*.specs.json` present → `knowledge` started.
3. If something is already done, say so in one line ("You set up The Flat on 21 November: 23 devices, the
   service is running. I'll continue with the wiring.") and continue from the first step not done. Offer
   "start over" only if they ask; starting over never deletes their inventory without an explicit yes
   (back it up to `data/state/backups/inventory-<date>.json` first).

## Step 1: welcome and consent

Say, in about five lines:

> I'll map your home network and, if you like, the cables at your desk and TV.
> 1. I check this Mac is ready. 2. I scan your home network once: which devices answer, what they say
> about themselves (names, services), and what is plugged into this Mac. Read-only; nothing is changed
> or logged into. 3. I ask you about what I can't tell, a few questions at a time. 4. I write it all into
> files in this folder and start the hub as a small background service you open in the browser.
> Nothing leaves this Mac except what Claude Code itself sends to Claude while we talk. About 20 minutes.

Ask (AskUserQuestion): "Shall I start?" with options "Yes, go ahead", "Explain more first", "Not now".
Record consent with a timestamp in onboarding.json.

## Step 2: doctor

`python3 bin/hoh doctor`. For each WARN/FAIL, fix what you can (run the fix command it prints, when it
is one of the hub's own commands) and explain the rest in one line. Before the first scan, warn:

> macOS may now ask: "Allow <Terminal> to find devices on local networks?" Please click **Allow**.

If the network check FAILs (gateway silent although there is a route), it is almost always Local
Network permission: System Settings > Privacy & Security > Local Network, turn it on for the app they
run Claude Code in (Terminal, iTerm, Warp, VS Code, Cursor …), then quit and reopen that app and run
`claude` again (`claude --continue` resumes this conversation). A sandboxed Bash tool has the same effect: if the
scan finds nothing, re-run it outside the sandbox before concluding anything.
Missing Claude login, old Python and so on: doctor names the fix.

## Step 3: first scan

Run the `network-scout` agent, or directly `python3 bin/hoh scan --json` (about 10 to 60 s). If
`localNetwork.ok` is false or the sweep found nothing: stop and fix permissions (step 2). Read
`data/state/discovery.json` for details; never re-run the scan just to look again.

Tell the person what was found in three lines: how many devices, what kinds (from leads and claims),
what router, whether Home Assistant answers, how many need their help. No addresses unless they ask.

## Step 4: interview (small batches)

Use AskUserQuestion, at most 4 questions per call, options from the scan wherever possible. Order:

1. **About them**: first name (for the app's copy; "skip" allowed), a name for the home ("The Flat").
2. **Rooms**: offer common rooms as multi-select (Living room, Kitchen, Bedroom, Study/Office) plus
   Other; then ask once for any more. These become `rooms` and one zone each.
3. **This Mac**: confirm where it sits (room, and desk or not).
4. **Router**: "Your router looks like <brand from scan> (<basis in plain words>). Right?" options:
   that brand, another (Other), don't know. Ask the model only if the scan did not show it, and suggest
   the label on the bottom.
5. **Unknown devices**, grouped by what the leads say (phones, speakers and TVs, computers, small
   gadgets, no clue), one question per host or per obvious group, options from the leads (see
   `device-identification`), always with "Not mine / don't know". Ask the room in the same question when
   natural ("Kitchen speaker or living room?"). Devices with a claim (the device named its model) need only
   a confirmation of the room and whose it is, in a batch.
6. **Hands-off**: "Is any of these not yours to look after (a work laptop, a housemate's computer)?"
   multi-select of computers and phones found. These go to `site.json` `handsOff` with `why`.
7. **Home Assistant**: if found on 127.0.0.1:8123 or they mention it: "Use Home Assistant for phone
   presence and device names?" If yes, they open a second Terminal window and run
   `cd <this folder> && python3 bin/hoh ha set-token` themselves (hidden prompt; give them the exact line) after making a long-lived token (Home Assistant, their profile, Security, Long-lived access
   tokens). Set `homeAssistant.url`.
8. **Router access**: "Let the hub read your router's list of connected devices?" options: Yes, Later,
   No. (Only AsusWRT/ZenWiFi is supported; for others say plainly what that means, see `router-access`.)

Save answers to onboarding.json after each batch so an interruption loses nothing.

## Step 5: router access (optional)

If they said yes and the family is asuswrt: follow the `router-access` skill exactly. Otherwise
`router.type: "none"`. Never ask for the router password.

## Step 6: write the files

Following `inventory-authoring`:

1. `data/site.json`: home, owner, network (`"auto"` unless detection is wrong), router, host, handsOff,
   homeAssistant, server port (8799 unless doctor said it is taken: then pick a free one in 8800-8899).
   Check with `python3 site_config.py`.
2. `data/inventory.json`: rooms, zones, `internet` + modem/router path, this Mac (`self` probe, its
   interfaces, its USB devices, displays and Bluetooth peripherals that matter: ask "keyboard, mouse,
   headphones: which of these do you want on the map?" rather than listing every paired gadget), every
   host found with the right probe, `verified` and identity fields, and `openQuestions` for every host
   nobody could name.
3. `python3 bin/inventory_check.py` until OK.

## Step 7: reconcile

`python3 bin/hoh scan --diff --json` (or the `network-scout` agent with diff). Work through:

- `unexplained`: hosts not in the inventory. Ask about them (step 4 style) or add them as
  `unknown-…` with an open question.
- `notSeen`: inventory devices with an address that did not answer. Asleep or away is normal for phones
  and laptops; for fixed things, ask ("Is the printer switched off?"). Do not delete.
- `changed`: a device moved address. Update the net entry and probe.

Repeat until nothing is unexplained; whatever is left is in `openQuestions`. At most three rounds:
say what is still open and move on.

## Step 8: wiring and layout

Ask whether they want the cables mapped now (desk, TV corner, network cabinet), later, or not at all.
If now: the `wiring-mapping` skill. Mention they can drop photos into the chat.

## Step 9: knowledge digests

Pick the devices that matter for troubleshooting: router and mesh nodes, modem, switches, docks and
KVMs, NAS, printer, the main screens, TVs and speakers. Never hands-off devices; never unidentified ones
(no model means nothing to research). Launch `device-researcher` agents **in parallel, at most 8**, one
device each, giving each: the device id, vendor and model as written, its ports from the inventory, and
how it is used here. Each writes `knowledge/<id>.md` and `knowledge/<id>.specs.json`. Check each
result is valid JSON with matching port ids. Tell the person this step uses web searches.

## Step 10: start the hub

Ask: "Start the hub now? It runs in the background at login, only on this Mac
(http://127.0.0.1:<port>), and you can stop it any time with `python3 bin/hoh stop`." If yes:

1. `python3 bin/hoh service install` (waits until `/api/setup` answers).
2. `python3 bin/hoh doctor`: everything OK or explained.
3. Headless screenshots of both maps (commands in `wiring-mapping`): `#/map` and `#/map?layer=wiring`,
   into `data/state/shot-net.png` and `data/state/shot-wiring.png`. Read both images and look: are all
   devices there, nothing overlapping, no error banner, no "unplaced" pile that should be placed? Fix
   (inventory or layout, or the `layout-designer` agent), then shoot again.
4. `python3 bin/hoh open` to open it in their browser.

If something fails: `python3 bin/hoh logs`, fix, `python3 bin/hoh restart`.

## Step 11: summary

Short and concrete:

- what is on the map now (counts by kind, rooms), what is `live` vs `reported`;
- what is still open (`openQuestions`, in plain words, with how they can settle each);
- how to keep it current: `/rescan` (new or gone devices), `/wiring` (cables moved), `/identify`
  (work through unknowns), `/add-device`, `/doctor`; the app's own Ask tab for troubleshooting.

Mark `summary` done in onboarding.json.
