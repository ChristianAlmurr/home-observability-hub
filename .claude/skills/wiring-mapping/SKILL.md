---
name: wiring-mapping
description: Map the physical cables of a home (desk, TV corner, network cabinet) into data/inventory.json links and data/layout.json for Home Observability Hub's wiring map. Use during /setup's wiring step, for /wiring, or when someone says "map my cables", "what is plugged into what", "I moved a cable", "the wiring map is wrong", "here is a photo of my desk".
---

# Mapping the wiring

Goal: every cable the person cares about is a link with honest `verified`, every wired device has its
ports, and the wiring map shows it without overlaps. Ask little, confirm a lot from what this Mac reads.

## 1. Read what this Mac sees first

`python3 portscan.py` prints this Mac's own sockets: each port (`type`, `n`, `active`), what is behind
it over USB and Thunderbolt, and displays. Also `data/state/discovery.json` → `host.usb`, `host.displays`,
`host.bluetooth`, `host.interfaces` (an Ethernet interface with a speed is a cable you can confirm).
Everything plugged into **this** Mac can be written `verified: "live"` with that evidence. Cables
between two other things cannot be read by anything: they are `reported` (the person says so) or `plan`.

## 2. Ask per surface, not per cable

Go surface by surface: the desk, the TV corner, the network cabinet or shelf, anything else the
person names. For each, one short batch (AskUserQuestion):

- What is on this surface? (offer the devices from the inventory in that room as options)
- For the network gear: "Which device does the internet come in to (modem, fibre box, router)?",
  "Is there a switch? How many ports, roughly, and what is plugged into it?"
- For the desk: "Is there a dock, hub or KVM between the computer and the screen?", "Which screen
  inputs are in use?"
- For the TV corner: "Is the TV wired (Ethernet) or on Wi-Fi? Anything plugged into the TV (console,
  soundbar, streaming stick)?"

**Offer photos**: "If it is easier, drag a photo of the back of the switch / the desk cables into this
chat." Read labels, port numbers and cable colours from it, say what you read, and ask only about what
the photo does not show. A photo is `reported` evidence ("from Sam's photo"), not `live`.

Do not ask for port numbers on things that do not matter (which LAN port of a switch is rarely
useful); write the port as unknown in `label` ("which port is not confirmed") and move on.

## 3. Write it

Per the `inventory-authoring` skill: add `ports` to each wired device, then links
`{id, from: "dev:port", to: "dev:port", cable, carries, label, verified, evidence}`. `carries` tells the
map what flows: a USB-C cable to a dock that carries video and USB is `["video", "usb"]`; Thunderbolt to
a dock with Ethernet `["video", "usb", "network"]`; power-only cables only if the person wants them.
Unmanaged switches get probe `inferred` from their links. Then `python3 bin/inventory_check.py`.

## 4. The map layout

Both maps place everything automatically (`docs/SITE.md`, `data/layout.json`): write layout only to
fix what the automatic placement gets wrong. For more than small touches, hand it to the
`layout-designer` agent with what to fix. Yourself:

1. `python3 bin/layout_check.py` (exists in this version? if not, skip): reports unknown ids, overlaps,
   boxes outside the world.
2. Headless screenshot of the wiring map, then look at it with the Read tool:
   ```
   "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu \
     --hide-scrollbars --window-size=1600,1000 --virtual-time-budget=8000 \
     --screenshot=data/state/shot-wiring.png "http://127.0.0.1:<port>/?v=1#/map?layer=wiring"
   ```
   The network map is `#/map`. Query parameters must go after the `#` (the app reads the hash).
   No Chrome? Try `/Applications/Chromium.app/...` or Microsoft Edge the same way; else ask the person
   to open the page and describe or screenshot it.
3. Fix overlapping boxes, crossing cables and labels that collide by pinning positions in
   `data/layout.json` (10 px grid), re-check, re-shoot. Stop when it reads cleanly; do not chase pixels.

## 5. Tell the person

Summarise per surface: what is confirmed by this Mac (live), what they told you (reported), and what
stays open. Cables that move are found again by `/rescan` only when they touch this Mac; other moves
need `/wiring` again.
