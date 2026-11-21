# One house's files

The code is the same in every home. What makes it *your* home is four things under `data/` and one
folder of secrets outside the repo. All of them are git-ignored: nothing about a house is ever committed.

| File | Written by | What it holds |
|---|---|---|
| `data/site.json` | onboarding (`/setup`), or by hand | the network, the router, the hub's own computer, protected and hands-off devices, the owner's name |
| `data/inventory.json` | onboarding, then the person and the agent | every device, port, cable and room, each with how we know it (`docs/CONTRACT.md`) |
| `data/layout.json` | onboarding (optional) | where things sit on the two maps; anything missing is placed automatically |
| `knowledge/<id>.md`, `.specs.json` | onboarding and the agent | each device's documentation digest |
| `~/.config/home-observability-hub/` | onboarding | router SSH key, Home Assistant token. Mode 700. Never read by the agent |

`data/state/` is runtime output (live.json, events, audit log, Sentinel findings) and is rebuilt.

## `data/site.json`

Every key is optional. A missing file or `"auto"` falls back to what this Mac detects
(`python3 site_config.py` prints the resolved result).

```json
{
  "schema": 1,
  "home": { "name": "The Flat", "owner": "Alex" },
  "network": { "subnet": "auto", "gateway": "auto", "extraNets": ["192.168.100.1/32"] },
  "router": { "type": "asuswrt", "deviceId": "router", "user": "admin",
              "sshKey": "~/.config/home-observability-hub/router_ed25519", "writes": false },
  "host": { "deviceId": "mac-mini" },
  "protected": ["switch-office"],
  "handsOff": [ { "id": "work-laptop", "ips": ["192.168.1.40"], "names": ["CORP-1234"], "why": "managed by an employer" } ],
  "secretDirs": ["~/.ssh", "~/.aws"],
  "homeAssistant": { "url": "http://127.0.0.1:8123", "tokenFile": "~/.config/home-observability-hub/ha-token" },
  "server": { "port": 8799, "allowedHosts": [] }
}
```

- `router.type`: `asuswrt` (any AsusWRT or ZenWiFi router: read over SSH with a key, or the web login kept in the
  Keychain) or `none`. With `none` the hub still finds every device by ping sweep, mDNS, SSDP and the ARP table;
  it cannot say which mesh unit a Wi-Fi device uses or block one at the router.
- `protected`: never offered for blocking or removal. The router, network gear (`kind` router, access-point, modem,
  switch, internet) and the host computer are always protected; list anything else here.
- `handsOff`: the agent never proposes a command for these and probes refuse them. Use it for a work laptop or a
  housemate's computer. Optional `macs` lists hardware addresses it may show up with (a laptop's built-in address
  behind its private Wi-Fi ones): a host with one of them, or announcing one of its `names`, is never port-scanned
  on the hub's own initiative, even before it is matched to the device.

## `data/layout.json`

Both maps place everything automatically. Use this file only to pin what the automatic layout gets wrong:
an authored entry wins over the automatic one for the same id, and everything it leaves out is still placed.
Every key is optional; an id that is not in the inventory is ignored. `python3 bin/layout_check.py` reports those
ids, overlapping boxes, port stubs for ports a device does not list, routes for links that do not exist, and the
cabled devices left to automatic placement (`--json` for a machine-readable result; exit 1 on an error).
`examples/example-house/layout.json` is a complete one.

```json
{
  "schema": 1,
  "network": {
    "spineY": 440,
    "pos": { "internet": [60, 440], "modem": [175, 440], "router": [330, 440] },
    "hull": { "x": 256, "y": 376, "w": 618, "h": 128 },
    "remote": [[60, 300], [175, 300]],
    "auto": [[1085, 690], [1200, 690]],
    "shelf": { "x": [1085, 1200, 1315, 1425], "y": 830, "dy": 96 }
  },
  "wiring": {
    "world": { "w": 1420, "h": 1040 },
    "home":  { "x": 0, "y": 0, "w": 1420, "h": 760 },
    "zones": [ { "id": "office", "x": 20, "y": 4, "w": 1380, "h": 736, "title": "Home Office", "note": "…", "tip": "…", "level": 0, "zones": ["office"] } ],
    "nodes": { "mac-mini": { "x": 80, "y": 80, "w": 200, "rows": 2, "ports": { "tb-1": { "side": "r", "row": 0 }, "usb": { "side": "t", "x": 160 } }, "free": { "side": "l", "row": 1 } } },
    "plan":  { "x": 20, "y": 780, "w": 680, "h": 420, "ox": 40, "oy": 816, "rowH": 22, "headH": 28,
               "rooms": { "living": { "x": 0, "y": 0, "w": 380, "h": 150, "note": "…" } },
               "cards": { "spares": { "x": 1120, "y": 548, "w": 240 } },
               "extra": { "x": 740, "y": 1140, "w": 310 },
               "trunk": { "fromX": 920, "y": 765, "toX": 360 } },
    "looseEnds": { "l-router-hue": { "a": { "side": "b", "x": 1205, "unknown": true } } },
    "routes": { "l-mini-switch": [[300, 180], [300, 220]] },
    "labelAt": { "l-hub-switch": { "x": 540, "y": 510 } }
  }
}
```

The units are SVG pixels on a 10 px grid.

**`network`** (the network map)

| Key | What it pins |
|---|---|
| `pos` | `{ id: [x, y] }`: a device's centre. Pin the spine (internet, modem, router, access points) and the devices around it; anything not pinned is placed automatically, clear of what is. |
| `spineY` | The y of the spine, the line from the internet to the access points (default 440). |
| `hull` | `{x, y, w, h}`: the zone drawn around the access points ("the mesh" with more than one, else the router's Wi-Fi). With it set, the Wi-Fi rows are the first build's: five across, alternating above and below. Without it the hull is fitted around the access points. |
| `remote` | `[[x, y], …]`: places for devices seen only over Tailscale. Default: a column left of the internet. |
| `auto` | `[[x, y], …]`: places for cabled devices that could not be put beside what they hang off. Default: a row under everything. |
| `shelf` | `{ x: [columns], y, dy }`: the shelf of devices with no connection to draw. Default: under everything. |

**`wiring`** (the wiring map)

| Key | What it pins |
|---|---|
| `nodes` | `{ id: { x, y, w, rows, ports, free } }`: a device drawn as a box. Height is 48 with no port rows, else `54 + 20 * rows`. A port on the left or right is `{ side: "l" \| "r", row }` (centre y = `y + 60 + 20 * row`); on the top or bottom `{ side: "t" \| "b", x }` at an absolute x, `end: true` puts its label on the left of the stub. `free` is where the "+3 free" chip goes. A cable whose end has no stub on a pinned box gets one on the side that faces its other end, on the first free row. |
| `zones` | Frames: `{ id, x, y, w, h, title?, note?, tip?, level: 0 \| 1, zones: [inventory zone ids] }`. `title` defaults to the inventory zone's name; `zones` is what the lists use to centre a frame. |
| `looseEnds` | `{ linkId: { a?: spec, b?: spec } }`: where a cable lands when the inventory names no port for that end. A spec is a port spec plus `unknown: true` (drawn as "port ?") or `bare: true` (no stub). |
| `routes` | `{ linkId: [[x, y], …] }`: waypoints between the two stubs. Without one, a cable between pinned boxes runs straight or with one bend; one that touches an automatic box is routed around every box. |
| `labelAt` | `{ linkId: { x, y } }`: where a cable's label sits when the middle of its longest run lands on a frame line. |
| `plan` | The room plan. `x, y, w, h` is its frame; each room in `rooms` is a card at `(ox + x, oy + y)`; `cards` places the cards that are not rooms (`spares`, `unplaced`, `remote`, other zones); `extra` is where any other card goes, two to a row; `trunk` draws one mesh line from the backhaul down to the plan (drawn only with more than one access point). Rows that do not fit a card's height run on in a second column. Without `plan`, the rooms are a grid of cards under the boxes. |
| `world`, `home` | The bounds Fit shows, and the bounds the map opens on. Default: everything, and the boxes. |

**What the automatic layout does**, so you know what is worth pinning:

- *Network map.* The spine follows the cables that carry the network from the internet to the main router (the one
  `router.deviceId` names, else the router nearest the internet), then every access point in use, with a switch only
  where it leads to one. Every device a cable reaches from there hangs below what it is plugged into, as a tree;
  more than six leaves become a small grid fed by a bus. A cabled group that reaches no spine device (a desk behind
  a Wi-Fi laptop) stands to the right, rooted at the device that brings it onto the network. Wi-Fi devices and hosts
  on the LAN by an unknown medium take places in rows above the hull, each as near its access point as possible;
  the place is remembered in the browser, so a device joining does not move the others. Bluetooth things sit beside
  their host; Tailscale-only ones left of the internet; things with no connection on a shelf.
- *Wiring map.* Every device with a cable (not Wi-Fi, not Bluetooth) is a box. Boxes are grouped in one frame per
  zone, titled "Room › Zone", the frames ordered from the internet inwards and wrapped into rows; inside a frame the
  boxes stand in columns by signal flow (towards the internet is upstream for network cables, a computer is upstream
  of what it drives). Each cable end gets a stub on the side facing its other end, ordered so cables cross as little
  as they can; cables are routed orthogonally through the channels between columns and never through a box.
