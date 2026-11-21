# Home Observability Hub: design spec

Status: describes what is built. First written 2026-11-20 against schema 1; sections 1 to 4, 5.1, 7 and
parts of 8, 9, 11 and 12 were rewritten the same day for version 2 (the security hub) after Alex rejected
the first map as "extremely basic": still, flat, Wi-Fi devices as rows in room boxes, nothing to act on.
Values marked **(ours)** are decisions made here. Anything marked **(unverified)** could not be confirmed.

---

## 1. Design position

Home Observability Hub is the security console for one home network. The first screen is the network itself, alive:
every device is a node, every node has a visible path to the internet, and what moves on screen is
something the data says. The person looks at it to answer three questions in this order: is anything on my
network that should not be, what is it and how do we know, and what can I do about it right now.

The direction is a night instrument: a blue-black field, with colour spent in two places only: on what a
connection is made of (cable, Wi-Fi, Bluetooth) and on what needs attention (not identified, suspicious,
blocked). It shares Midnight ink with Agent Hub, Stash and Atnas (section 7): Schibsted Grotesk for text,
JetBrains Mono for figures, square corners, hairlines instead of shadows. Floating controls sit on the panel
colour over the map; panels are flat.

It keeps the first build's discipline about truth. The house is a set of objects (devices, links) with
properties, every property says where it came from, and nothing is drawn as more certain than the data. The
agent still only proposes. What is new is that the person can act directly on a device, after one
confirmation that states the effect and the undo.

### Rules that follow

1. **Provenance is never optional.** Every value carries its trust: `live` (with age), `plan`, `reported`.
   On cables: solid = live, dashed = plan, dotted = reported. Identity has its own three words:
   `confirmed`, `likely`, `not identified`, and a device that is not `confirmed` is marked wherever it
   appears (map, lists, table, inspector).
2. **Never show green you did not measure.** `unmonitored` and `unknown` are grey dashed rings. A device the
   server has no security findings for says "not assessed", not "no findings".
3. **Never draw a line to a guess.** A Wi-Fi device goes to the access point the data names. When none is
   named it goes to the mesh as a whole, a visible object with its own outline, and the caption on the mesh
   counts how many devices are in that state.
4. **Motion carries information or it is not there.** See 4.6. All of it stops when the tab is hidden and
   under `prefers-reduced-motion`, and every moving cue has a still one (colour, dash, badge, word).
5. **Selection is global.** One selection, shared by the map, both drawings of it, the lists, the table, the
   inspector, the agent's answers and the URL (`?sel=`).
6. **Every action asks once and says what it does.** Unavailable actions stay visible with their reason.
   Destructive ones are red, and Cancel has the focus.
7. **The agent only proposes.** Unchanged: see section 6.
8. **Calm by default.** One sweep per scan, slow rings on the access points, small dots on the links. The
   only thing that insists is a suspicious device.

---

## 2. Information architecture

Seven views, reached from the left rail (desktop) or the bottom bar (phone). The inspector is a panel that
opens on any view when something is selected.

| View | Route | What it is for |
|---|---|---|
| **Map** (default) | `#/map` | The network, alive: who is on it, how each device reaches the internet, what needs attention. `?layer=wiring` is the desk schematic. |
| **Security** | `#/security` | The counts, then every device that needs a decision, worst first, with its actions. The router's own findings. |
| **Devices** | `#/devices` | The inventory as a table: identity, security, connection, access point, trust. The accessible equivalent of the map. |
| **Agent** | `#/agent` | Ask the fix agent; read past runs; approve or reject proposed actions. |
| **Activity** | `#/activity` | *Events* (security, status, link) and *Audit* (what the agent did, what the person did). |
| **Questions** | `#/questions` | The inventory's open questions. |
| **Settings** | `#/settings` | Agent mode, the router (how the app reaches it, whether it may change it, the web login), scanning, collectors, theme. |

Sample data: `?demo=1` (no router login) and `?demo=2` (router login stored) lay sample hosts, findings and
router state over the real inventory so every state can be seen; a "Sample data" chip shows in the top bar
and actions change that copy only. `#/agent?fixture=1` is the agent's sample run.

### Landing: the first 5 seconds

- **Top bar**: one verdict pill (the worst true thing: "1 suspicious device", "9 not identified",
  "No findings", or "Security not assessed" when the server sends no findings), then counts: devices, not
  identified, suspicious, blocked, new today, offline (only when not zero), then the age of the last scan.
  A count is a button: it dims everything else on the map and filters the lists. The verdict opens Security.
- **The map**, fitted to everything, already moving.
- **Watch list**, at the top of the device list (`[`): the five worst, each with its first reason.

---

## 3. Layout frame

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ Top bar 48: beacon + wordmark · view · verdict · counts · scan age · ⌘K · agent mode · theme │
├────┬─────────────────────────────────────────────────────────────┬─────────────────────┤
│Rail│ Canvas: the map is full width                               │ Right panel 400     │
│ 52 │  ┌ toolbar (glass, top-left) ┐                               │ (Inspector | Agent) │
│    │                                                             │                     │
│    │  ┌ selection bar (glass, bottom centre) ┐        ┌ zoom ┐    │                     │
│    ├─────────────────────────────────────────────────────────────┤                     │
│    │ Activity drawer: 30px ticker, 240px open                                          │
└────┴───────────────────────────────────────────────────────────────────────────────────┘
```

On **Map** and **Security** the device list is an overlay opened with `[` or the rail's list button, at
every width: the map gets the room. On the other views it docks at 300px from 1440px up, as before.

| Width | Behaviour |
|---|---|
| **≥ 1440** | Rail + canvas + right panel 400. List docks except on Map and Security. |
| **1024–1439** | List is an overlay everywhere. Right panel 360. Count labels in the top bar drop to figures. |
| **768–1023** | Right panel becomes a sheet over the canvas; the map keeps the selection clear of it. |
| **< 768** (phone) | Top bar 44: view, verdict pill, mode pill. Bottom tabs: Map, Security, Devices, Agent, More (Activity, Questions, Settings). The map is the same living map, opened on the mesh and its clients at a readable size, with pan and pinch; Fit shows everything. Tapping a node opens the selection bar (name, path, actions) and "Details" opens the inspector full screen. Touch targets 44. |

---

## 4. The map

Two drawings of the same house share one selection and one toolbar switch (`1` / `2`):

- **Network** (`ui/js/netmap.js`, `netlayout.js`): the default. Everything, and how it reaches the internet.
- **Wiring** (`ui/js/map.js`, `layout.js`): the schematic of every cable, with ports, KVM inputs and cable types,
  then the rooms with what has no cable. A Bluetooth peripheral that is a box there carries a flag naming its host,
  never a line across the desk.

Both read their places from `data/layout.json` (served by `/api/layout`, schema in `docs/SITE.md`) and place
everything it does not pin automatically. No house is written into the code: the same rules draw a studio with one
router and a house with three mesh nodes and 150 devices, and the same inventory always gives the same picture.

### 4.1 Where things sit (network)

The path to the internet is one horizontal line, read left to right:
internet → (outside | at home) → modem → router ══ access points (and a switch only where it leads to one).
The line between outside and home falls half way from the internet to the next thing on the spine.

- **The spine** follows the cables that carry the network: from the internet to the main router (the one the site
  names, else the router nearest the internet), then every access point in use. Cabled children follow their parent
  straight away; a mesh hop that has to reach past something on the spine is drawn as a bridge just above the hull,
  which reads as radio. A pinned `network.pos` wins for any device.
- **The hull** is a quiet square zone around the access points: "The mesh: Wi-Fi for the whole home" when there is
  more than one, "Wi-Fi: <router>" when there is one, "The home network: no router recorded" when the inventory has
  none (it is still where Wi-Fi and LAN links land). A 4% violet wash and a dashed violet hairline, no glow; its title
  inside the top edge, the count of Wi-Fi devices just under the bottom edge on a plate above the lines. Its edges are
  where "access point not known" links land, each straight onto the edge at its own small square dock. At least
  320 wide so its title reads.
- **Below the spine, the cables.** Every device a cable reaches hangs under what it is plugged into, as a tree:
  branches side by side, then the leaves in one row, or in a grid of up to six across fed by a bus on its left when
  there are more. Links in a tree are drawn orthogonally from the parent down to a bus and across, so no line runs
  through a device; neighbouring families put their bus 10px apart so two never read as one line. A computer claims
  what hangs off it before a dock does (the KVM sits under the desk's computer). A name sits on a plate the colour
  of the canvas, so a line passing under it never runs through its letters.
- **Islands.** A cabled group that reaches no spine device (a desk behind a Wi-Fi laptop) stands to the right of
  the trees, rooted at the device that brings it onto the network; its Wi-Fi or LAN link goes up to the hull.
- **The air.** Things that come and go (Wi-Fi clients, hosts the scan finds, hosts on the LAN by an unknown medium)
  take places in rows above the hull, 120 apart across and 116 up, each row staggered, at least five to a row and
  more as the crowd grows (about the square root of its size). Rows also go below the hull when no cables hang
  there. A device takes the free place nearest its access point (or the middle of the hull, when the access point is
  not known). The place is remembered in this browser (`hm.slots`), so a refresh, a new host or another device
  leaving does not move the rest. A device moves only when its own access point changes, and that move is
  animated: roaming is information. Places of things not seen for a week are released.
- **Bluetooth peripherals** sit beside their host; when the host is in a crowd of Wi-Fi devices, at the nearest free
  place in that crowd.
- **Seen only over Tailscale**: left of the internet, outside, with a faint dotted line to it.
- **Not on the network** (spares, a router on a shelf, things with no recorded connection): a shelf under
  everything in its own dashed neutral zone, dimmed, with no lines. The fit keeps 60px clear at the bottom so the
  zoom control never sits on it.
- **A pinned layout** (`network.hull` set) keeps the first build's rows: five across, alternating above and below
  the hull. `examples/example-house/layout.json` is that house, pinned.

### 4.2 Node anatomy

The map speaks the family's language: square tiles in the panel step, one hairline edge, and colour only
where a person is needed. Every node carries **one liveness cue** (how solid the tile is) and **at most one
attention flag**. Healthy is quiet ink.

| Part | Spec |
|---|---|
| Tile | A square, no radius. Infrastructure (internet, modem, router, mesh node, switch): 48px on the raised step with an `--edge` hairline. Everything else: 36px on `--bg-node`. Peripherals and shelf items: 28px. Every edge is an `--edge` hairline (3.4:1 on the ground in dark, 3.3:1 in light) drawn 1px on screen at any zoom. Kind icon inside at 24 / 20 / 16px, its stroke 1.5px on screen at any zoom. |
| Liveness | Answering: ink icon, solid tile. Not probed or no answer (unknown, unmonitored, inferred, plan): the icon in `--text-muted`. Degraded: amber edge. Offline or asleep: hollow tile (canvas colour), dashed edge, faint icon, muted name. No green anywhere on the map: "online" is the quiet default, so nothing is green without a probe. |
| Flag | Top-right corner, a 14px square, one at a time, worst first: suspicious (rose fill, `!`), blocked (rose outline, a slash), not identified (amber wash and outline, `?`), worth a look (amber outline, a small square). The edge takes the flag's colour (suspicious also gets a rose wash and a rose name; blocked goes hollow with a muted name). "Likely" carries no flag: it is said in the label on hover, the tooltip and the inspector. |
| New | Top-left corner: a 6px cobalt square when first seen in the last 24 hours. Still. |
| Name | 12px/600, centred under the tile, in balanced lines: one when it fits, else two, and a third only so the name is not cut. Breaks fall after a space, a hyphen or an underscore; an ellipsis only when one word is wider than the label. Label widths: 110 (infrastructure), 112 (devices), 104 (peripherals); peripherals' names are 12px too. Infrastructure uses the short name ("XT8 router"). |
| Make and model | 11px, `--text-subtle`, one line, shown on hover, on selection and at 130% zoom and above; "likely …" when likely, amber "maybe …" or "not identified" when not identified. |

Labels keep a readable size when the map is small: they scale up as the zoom drops (to 1.375×, so a name is 11px or more
on screen down to 66%), and below 34%
only infrastructure, the selection and suspicious devices keep a name. Text is re-fitted on zoom steps, not on
every frame.

### 4.3 Link encoding (network)

What a connection is made of is the colour; how sure we are is the dash; how alive it is, the opacity. Lines
are thin (1.5px, Wi-Fi dots 2px) so devices, not wiring, carry the picture, but they read at fit zoom: below 100%
widths, the mesh caption, the outside/in the flat labels and speed tags keep their screen size (`--lk`, up to
2×). A healthy link is at 85% (Wi-Fi dots 75%), which keeps it at 3:1 or more against the ground in both
themes; the less sure forms (no known access point, paired only, medium not known) drop to 40 to 50%. A link
comes to full strength (2.25px, opacity 1) when it is on the lit path, hovered or selected.

| Link | Drawn as | Token |
|---|---|---|
| Cable carrying the network | aqua line; a square speed tag at its middle on hover, on the lit path or at 130% zoom | `--m-wired` |
| Coax (the line in) | thick sand line | `--m-coax` |
| Wi-Fi to a named access point | violet round dots, slightly curved | `--m-wifi` |
| Wi-Fi, access point not known | wider-spaced fainter violet dots to a dock on the mesh edge | `--m-wifi` |
| Mesh backhaul | heavy violet dots when it is radio; a double line when it is cabled | `--m-wifi` |
| Bluetooth | fine blue dashes to the host; fainter and wider when only paired | `--m-bt` |
| Desk cable (video, USB) | thin slate line, no motion | `--m-desk` |
| On the LAN, medium not known | grey dashes to the mesh edge | `--m-none` |
| Tailscale | faint dotted line to the internet | `--m-desk` |
| Blocked | the link goes grey and is cut: a gap with two red bars | `--sec-blocked` |
| Offline end | the link keeps its colour at 18% opacity, nothing moves on it | its own |

A device that is both cabled and on Wi-Fi (the Mac mini) shows the cable as its path and the Wi-Fi as a
faint second arc that stays quiet until the device is selected.

### 4.4 Selection, hover and the path to the internet

- **Hover**: the node, its links and neighbours stay; the rest dims to 50%. Tooltip after 400ms: name, make
  and identity word, status, connection (with band and signal), address, traffic, first finding.
- **Select**: the device's whole path to the internet lights (hop by hop through the access point, the
  backhaul, the router and the modem), the rest dims, and the **selection bar** rises at the bottom: name,
  identity and security chips, the path as a strip in the link colours, and the action buttons. A Wi-Fi hop
  with no known access point reads "the mesh · access point not known" and continues from the main router.
- **Right-click a node**: the same actions as a menu, plus Ask the agent, Show on the desk wiring, Copy IP.
- **A count in the top bar**: dims everything that does not match.
- **An answer's path** (pinned from the agent): its links and devices light, suspect hops get a red halo.
- Trace (`T`) is the desk wiring's tool for following a cable through the KVM and the dock.

### 4.5 Status, identity and security at rest

Everything below is visible with motion off.

| State | Still cue |
|---|---|
| not identified | amber edge, amber `?` flag |
| likely | nothing on the tile; "likely …" in the label on hover and in the tooltip |
| worth a look | amber-tinted edge, amber flag with a small square |
| suspicious | rose edge and wash, rose `!` flag, rose name |
| blocked | hollow tile, dashed edge, rose slash flag, muted name, cut link |
| new | cobalt corner square |
| offline, paired and asleep | hollow tile, dashed edge, faint icon, muted name, faint link |

### 4.6 Motion

| What moves | What it says | How |
|---|---|---|
| Small squares along a link (no glow) | The link is up and which way the internet is. With router traffic: dots run both ways and their number and speed follow the measured rate (log scale, 160 b/s to 16 Mb/s); an idle device has none. Without it: one calm dot per ~190px, towards the internet. The router counts Wi-Fi clients only, so cabled links show the calm form. | canvas layer over the SVG, positions computed from the clock (stateless, so a re-render does not jump) |
| Wavefronts on Wi-Fi | The same, on radio: short arcs across the direction of travel instead of dots | canvas |
| A square ripple from each access point | Where the radio is | one SVG square per access point, 6s, scale and opacity, peak 30% |
| The sweep | A new reading arrived: one faint ring runs out from the router and each tile's edge brightens as it passes | once per scan, 1.7s |
| An edge pulse on one node | Its status changed | once, 0.8s |
| Rose edge breathing out | Suspicious | 2.4s, the only insistent motion |
| A node gliding | It moved to another access point | CSS transform, 620ms |
| A node growing in / fading out | It joined or left | 420ms in, 240ms out |
| White dashes on the lit path | The selected device's way out | `stroke-dashoffset` on the lit links only |
| The view easing | Fit, show selection | 420ms, interruptible by any pan or zoom |

Rules: only transform, opacity and `stroke-dashoffset` are animated in the SVG; the canvas draws about 100
dots. Nothing runs while the tab is hidden, the Map is not showing, or `prefers-reduced-motion` is set:
the class `animating` on the SVG is the single switch, the canvas is cleared, and node moves are instant.
Measured: about 4 ms of main-thread work per frame with 55 nodes (headless Chrome, 2026-11-20).

### 4.7 The wiring map

The first build's schematic, kept and made general: signal left to right, orthogonal cables, colour = cable type
(`--cable-*`), line style = trust, ports as stubs with labels, free ports as "+3 free", the KVM's inside drawn for
the input in view, the KVM view toggle (it shows, it does not switch; it appears only when a KVM has input cables,
and each input is named after the computer behind it).

- **Boxes.** Every device with a cable that is not Wi-Fi or Bluetooth. One frame per zone, titled "Room › Zone",
  frames ordered from the internet inwards and wrapped into rows so the drawing keeps roughly a screen's shape.
  Inside a frame, columns by signal flow: towards the internet is upstream for network cables, a computer is
  upstream of what it drives, then a dock, a KVM, a screen. Each column is ordered by where its cables go.
- **Ports.** One stub per cable end on the side that faces the other end, ordered by the other end's height so
  cables cross as little as they can. An end with no port named is "port ?", or no stub at all for a device with
  no ports (the internet) or a radio backhaul.
- **Cables** run through the channels between columns and frames, in lanes 10px apart, never through a box, never
  along a frame's edge or through its title. A cable that would lie on another costs more than a detour.
- **Rooms.** Under the boxes, a grid of cards: each room of `inventory.rooms` with the devices that are not boxes
  as rows (status, name, the address's last part), then "Room not known", Remote, Spares. A card with more than 14
  rows spans two columns. A pinned `wiring.plan` draws the floor plan instead.

Selecting something that has no cable offers "Show on the network map".

### 4.8 Toolbar, filters, pan and zoom

Toolbar (glass, top-left): Network | Wiring · (wiring only: KVM input, Trace) · Filter (how sure we
are; only what needs attention; wiring: carries) · Legend · filter tags · a caution note when no router
access exists. Zoom control bottom right (`-` `+` `F`). Wheel pans, pinch or ⌘-wheel zooms, drag pans.
The view refits on resize only while the person has not moved it; with a selection it only keeps the
selection in view.


### 4.9 First run

When the inventory has no devices the Map shows a welcome panel instead of an empty canvas, and the map's tools
step aside. A 560px panel on the canvas, a 2px cobalt top edge: the product name in mono, "Nothing on the map yet",
one paragraph on what the hub is (it reads and reports; it changes nothing unless you approve that one change),
then three numbered steps (open Terminal in the hub's folder, run `claude` with a copy button, type `/setup`) and
the checklist from `/api/setup`: site, devices, device guides, map layout, router, Home Assistant, Claude CLI, each
with a status shape (jade done, amber not yet, grey dotted optional) and one line of plain words. It is read again
every 10 seconds while the home is empty, so it follows `/setup`; the map appears by itself when the first devices
are in. An older server without `/api/setup` gets the steps and a line saying the checklist is not reported.

---

## 5. The inspector

Right panel, 400px, scrolls as one column. Device and link inspectors share the structure.

### 5.1 Device inspector, in order

1. **Header** (sticky, 72px): status glyph + name (16px/600), kind and model (12px muted), trust tag.
   Buttons: Ask agent about this (primary, small), Trace path, overflow (copy id, copy IP, open admin
   URL if `facts.admin`). Close ✕.
   On the Network map "Trace path" is "Trace cables" and opens the desk wiring.
2. **Status strip**: status word with age ("Offline · last seen 3 days ago"), latency, last change.
   For unmonitored: "Not monitored: no probe is possible for this device (USB keyboard, no
   address)." Never blank.
3. **Actions**: every action the server lists for the device, as rows: icon, label, what kind of change it
   is (reads only / changes something / destructive), and, when it cannot be used, the reason in place
   ("Needs the router login. Add it in Settings"). See section 8, Device actions.
4. **Identity**: the state chip and what it rests on; MAC address and its maker (or that it is randomized
   and says nothing); candidates, each with a three-step confidence meter and its basis; the evidence rows
   (source, label, value, age); then Identify, Deep scan, Investigate.
5. **Security**: level chip and score bar, the reasons as sentences, open ports (risky ones outlined red),
   first seen, traffic now. "Not assessed" when the server sends nothing.
6. **Path to the internet**: the hops as a vertical strip in the link colours; for Wi-Fi the access point
   (or "not known"), band, signal and network name, each with its trust, and the evidence sentence.
7. **Role**: `role` text in body size, one paragraph.
4. **Live checks**: rows from `live.checks`: ✓ / ✕ glyph, name, detail mono. Collector time in the
   section header ("checked 40 s ago").
9. **Cables**: one row per cable (see 5.3).
6. **Ports**: every port, connected or free (see 5.3).
7. **Network**: one row per `net` entry: interface, IP (mono), medium, link speed, trust.
8. **Facts** and **Constraints**: property list. Constraints (e.g. "Managed device: the fix agent must
   never run commands on it") render as a caution callout, above facts.
9. **Specs** from `knowledge.specs`, grouped by `group`, plus **Limits** as a plain list.
10. **Documentation**: the `docs` list with kind tag (manual, spec, support, firmware, forum) and
    host name; then the rendered guide (`guideMarkdown`) collapsed to its first 3 headings with
    "Show full guide". Identity confidence shown as "Identity: likely · basis: EDID product code".
11. **History**: last 50 events, newest first, 28px rows: time (relative, absolute on hover), text.
12. **Raw**: collapsed, the device JSON in mono, for when the person wants the source.

Sections are collapsible (Blueprint `Section` style: 40px header, 14px/600 title, chevron right).
Collapse state persists per section name, not per device.

### 5.2 Property rows and provenance

```
 Link speed          2500Base-T full duplex            ━ live · 40 s
 Ethernet port       P2                                ┄ plan
 Power               100 W PD in, ~85 W to laptop      ⋯ reported · order email
 Exact model         not confirmed                     ⋯ reported
```

- Grid: label column 136px `--text-muted` 12px; value column flex `--text` 13px (mono for IPs,
  interfaces, ids, commands, speeds); trust column 96px right-aligned 11px.
- Row height 28px min, wraps. Divider 1px `--border-subtle` between rows.
- **Trust glyph**: a 14px line segment drawn in the trust's line style (solid / dashed / dotted) in
  `--text-muted`, then the word, then the age for `live` or the basis for `reported` when known. The
  same glyph is used in the legend, so the person learns it once.
- **"Not confirmed"**: any value, or the substring "not confirmed" inside a value, renders the phrase
  in `--text-muted` italic with a dotted underline; hover explains what would settle it if the data
  says (from `openQuestions` or the link `evidence`).
- Values inherit trust from their item unless they carry their own (`net[].verified`). Where the inventory
  `_evidence` says "Never upgrade plan/reported to live without a probe", the UI follows it literally:
  it never displays plan values with live styling even if the device is live.

### 5.3 Connections and ports

**Connections** list, one row per link (48px, two lines):

```
 [▬] Thunderbolt 2  ━━ USB-C · 5 Gb/s USB ━━▸  UGREEN 2.5G adapter · USB-C       ━ live
     carries: network                                  evidence ▾
```

- Left swatch: 4 × 24px bar in the cable colour with trust line style.
- Local port → cable type and speed → **peer device · peer port** (peer is a link: click selects the
  peer and keeps the inspector history so Back returns).
- `evidence` and `risk` expand inline.

**Ports** grid: one row per port, 28px: port label (mono), type tag, connected peer or "free", link
status glyph. Free ports in `--text-muted`. Sorted by the device's own port order.

### 5.4 Link inspector

Header: "USB-C · Mac mini → UGREEN KVM". Then: both ends (device + port, each clickable), type,
carries, speed, label, KVM input, trust + evidence, risk, live link status, and the trace from this
link. Same property-row styling.

---

## 6. The agent surface

### 6.1 Where it lives

- **Right panel, Agent tab** on every view: ask about what you're looking at without leaving the map.
  The answer drives the map in the canvas beside it.
- **Agent view** (`#/agent`): run history (left, 280px list: title, verdict first line, time, status),
  thread (centre), and the right panel showing a **mini-map** (the full map scaled to fit 400px wide,
  path highlighted, click to jump to Map with the path kept).
- On phone, Agent is a full-screen tab; the answer's path appears as a vertical path strip.

### 6.2 Ask box and scoping

- Multiline textarea, 3 lines min, grows to 10; 14px. Placeholder: "Describe the problem, for example:
  the MacBook picture is soft through the KVM." Send `⌘↵`; plain `↵` is a newline.
- **Scope chips** above the box: the devices the agent will work on. Pre-filled from the current
  selection (shift-click several on the map), from "Ask agent about this" in the inspector, or from a
  Question. Chip: status glyph + name + ✕, 24px tall. "+ Add device" opens a device picker. Empty
  scope is allowed: the chip row says "Agent will identify the devices".
- Suggested prompts (only when the thread is empty): the open questions, as 1-line buttons.
- If `agentMode` is `paused`, the box is disabled with "The agent is paused. Change mode to ask."

### 6.3 Live activity trace

While a run streams, the thread shows a **trace** above the answer area:

- **Phase rail**: five steps in a row: Identify · Read docs · Inspect · Research · Answer. Done =
  `--text` with ✓, current = blue with a 2px progress underline (indeterminate), pending = muted.
- **Activity rows** (from `activity` events), one per tool use, 24px, mono 12px: icon per tool
  (file, web, terminal, device), plain-words text ("Read the UGREEN KVM guide", "Ran ifconfig en8"),
  elapsed time right. `detail` expands inline (mono, max 12 lines, then scroll). Web reads show the
  host name, so the person sees what outside material is being read.
- Live: newest row appears at the bottom with a 100ms fade; the list auto-follows unless the person
  scrolled up ("Jump to latest" pill).
- After the answer arrives, the trace collapses to one line: "Worked for 48 s · 11 steps · read 3
  manuals · ran 4 read-only commands ▸" and expands on click.
- `error` events render as a danger callout in place; `done` with `ok: false` keeps the trace open.
- **Cancel** (secondary button, right of the phase rail) calls `/cancel`.

### 6.4 Answer document

Rendered from the JSON, never as HTML. Width: the panel or thread column, max 720px for reading.

| Part | Treatment |
|---|---|
| `title` | 16px/600. |
| `verdict` | 16px/400 `--text`, directly under the title, before anything else. The answer first. |
| `confidence` | Next to the title: a 3-segment meter (12×4px segments, filled = `--text`, empty = `--border`) and the word: "High confidence" / "Medium confidence" / "Low confidence". Low also tints the meter orange. No percentages. |
| `subjects` | Chip row (status glyph + name). Hover highlights the node on the map; click selects. |
| `path` | **Path strip**: the hops as a horizontal chain of device names joined by cable-coloured connectors in trust style. Suspect hops: connector in `--danger` with a 2px red outline pill and a ⚠ above. `note` below in muted text: "Why this hop: …". On render, the map highlights the path (others to 15%), suspect cables pulse once and keep a red 6px halo at 35%. "Show on map" button pins it; Esc unpins. |
| `text` | Markdown subset: paragraphs, bold, italic, inline code, lists, links. No images, no raw HTML, no headings above h4. |
| `steps` | Numbered list, number in a 20px circle. Each item: `text` (14px), device chip if `device`, `detail` muted, then **"You should see:"** + `expect` in a 2px left-ruled block. Each step has a checkbox the person can tick (local only, not sent to the agent). |
| `checks` | Table, 28px rows: result glyph (✓ green / ✕ red / – grey when `ok` absent), label, value (mono), source (mono muted, e.g. `ifconfig en8`). Header "What I checked" + count of passed/failed. |
| `facts` | Property rows (§5.2 layout): label, value, device chip, source as a numbered citation `[2]` that links to `sources`. Header "From the manual". |
| `compare` | Table, columns as given. `recommended` column: 2px blue top border on its header, "Recommended" tag, cells in `--text` while others in `--text-muted`. Row labels left, 12px muted. Horizontal scroll on narrow widths, first column sticky. |
| `warning` | Callout: `info` blue, `caution` orange, `danger` red. 3px left border in intent colour, 8% tint background, icon, text. |
| `actions` | Action cards (6.5), after all blocks, under the header "Proposed actions". |
| `sources` | Numbered list: title (link, opens in new tab), host name mono muted, device chip. Header "Sources". |
| `unknowns` | Header "Not established". `?` glyph per item, muted text. Always shown when present, never collapsed. |

The answer can be re-sent (last wins): re-render in place without scroll jumps; if the path changes,
the map transitions in 200ms.

### 6.5 Action card

```
┌ Turn Wi-Fi off on the Mac mini ───────────────────────── CHANGE · reversible ┐
│ Why: Ethernet already carries everything; Wi-Fi is a second route.          │
│ Target   ● Mac mini                                                          │
│ Command  ┌──────────────────────────────────────────────────────────┐ Copy  │
│          │ networksetup -setairportpower en1 off                     │      │
│          └──────────────────────────────────────────────────────────┘      │
│ Undo     networksetup -setairportpower en1 on                                │
│                                                       [Reject] [Approve and run] │
└──────────────────────────────────────────────────────────────────────────────┘
```

- **Risk tag** top-right: `READ` grey, `CHANGE` orange, `DESTRUCTIVE` red (tag text is uppercase
  only inside this tag, as a code-like label; everything else is sentence case). Then "reversible" or
  "not reversible" (the latter in red).
- **Command**: mono 13px, `--bg-code` block, wraps (never truncated, never horizontally hidden); the
  exact argv the server will run. Copy button.
- **Target**: device chip; hovering highlights it on the map.
- **Undo**: the undo command in mono, or "No undo. This cannot be reversed." in red.
- **Buttons**: Reject (default button) and Approve and run (intent primary; intent danger + label
  "Approve and run, not reversible" when destructive). Approve requires a click or Enter on the focused
  button. **No keyboard shortcut approves.** Destructive actions additionally require typing the
  target's name in an inline field before the button enables.
- **States**:

| State | Shows |
|---|---|
| Proposed (approve mode) | Buttons enabled. |
| Advise mode | Buttons replaced by "Advise only: copy the command to run it yourself" + Copy. |
| Paused | "The agent is paused." Buttons disabled. |
| Refused | `needsSudo`, a target listed under `handsOff` in `data/site.json`, or another hard refusal: "This runs only if you type it yourself in Terminal." + Copy. Grey left border. No Approve button exists. |
| Running | Spinner in the header, Approve/Reject replaced by "Running…" and a Stop link; **output** panel opens below: mono 12px, stdout `--text`, stderr `--status-degraded`-text colour, max 240px then scroll, auto-follow. |
| Succeeded | ✓ "Ran at 14:02 · exit 0" in green; output stays, collapsed to last 6 lines. If reversible: "Undo" button, which **proposes** the undo as a new action card (it still needs its own approval). |
| Failed | ✕ "Failed · exit 1" in red; output expanded. |
| Rejected | Card collapses to one line: "Rejected by you at 14:01". Expand to see the command. |
| Superseded | When a re-sent answer drops the action: one muted line "No longer proposed". |

- One action runs at a time; other cards' Approve buttons disable with "Another action is running".
- Every state change writes an audit row; the card links to it ("See in audit").

### 6.6 Mode switch and stop

- Top bar segmented control, always visible: **Advise · Approve · Paused**. Advise is grey, Approve
  blue, Paused orange with a pause glyph. Changing mode is immediate and toasts the change. On phone
  it is a pill in the top bar that opens a sheet with the three options and one sentence each:
  - Advise: "The agent can look and suggest. Nothing runs."
  - Approve: "Each proposed action runs only when you approve it."
  - Paused: "The agent will not start."
- There is no auto-run option, and the UI never implies one.
- **Stop** (danger, minimal style until active): appears in the top bar whenever a run streams or an
  action is running. One click cancels the run, stops a running action if the server supports it, and
  sets mode to Paused. Shortcut `⌘.`. Toast: "Stopped. The agent is paused."
- Settings shows the **hard refusals** as a read-only list with the sentence "These are enforced in
  code. They cannot be changed here."

---

## 7. Design tokens

The tokens are in `ui/css/tokens.css`; that file is the source and this section says what they are for.
All colour, size and motion in the CSS goes through them.

Home Observability Hub uses **Midnight ink**, the system Agent Hub, Stash and Atnas share, so the four tools read as
siblings: every surface is a step of one hue, nothing is rounded, cobalt acts and selects, jade is good, rose
needs a person, amber is worth a look. The sibling names (`--ground`, `--ink`, `--accent`, `--go`...) are the
primitives; the Home Observability Hub role names (`--bg-*`, `--text-*`, `--status-*`, `--m-*`) point at them, so the
rest of the CSS did not have to change.

| Group | Dark (default) | Light | Used for |
|---|---|---|---|
| Surfaces | ground `#0b1020` (canvas, app, rail), panel `#11182b`, field `#18213a` (raised, hover), raise `#212c4a` (active, selected), press `#2e3b5e`, term `#0a0f1e` (code) | ground `#f4f6fb`, panel `#FFFFFF`, field `#eef1f8`, raise `#e3e8f3`, press `#d3dbec` | Steps of one hue. Depth is a step or a hairline, never a drop shadow. |
| Lines | line `rgba(200,214,255,.12)` separators, line2 `.32`, edge `.44` control boundaries (`--border`) | line `rgba(11,16,32,.1)`, edge `.48` | Drawn as inset 1px box-shadows. |
| Text | ink `#eef2ff`, soft `#b4beda` (muted), faint `#8a97ba` (subtle) | `#0b1020`, `#3b4565`, `#55617f` | faint is the lowest step that still reads on raise. |
| Accent | cobalt `#2f62f5` fills primary buttons; accent-ink `#8fb0ff` is focus, selection, links, the current view; wash `#16245a` behind a selection | `#2f62f5`, `#2550d0`, `#e2e9ff` | Acting and selecting only. Not a map link colour. |
| States | jade `#2dd4a0` online / good, amber `#f5b84a` degraded / watch, rose `#ff5c8a` offline, suspicious, blocked, danger; unknown is faint. Washes are the hue at 14% | graphics `#0f8f68` / `#a86b00` / `#d0305f`, text `#08694d` / `#8a5a00` / `#b8245a`, washes at 12% | Rings, glyphs, the verdict, callouts. Rose means a person should look. |
| Medium | wired `#4cc3e6` cyan, Wi-Fi `#a98af0` violet, Bluetooth `#a6c45a` olive, coax `#a7a08a` stone, desk cable `#7d8bae` neutral | `#0a7fa3`, `#7a4fd6`, `#5f7d12`, `#77705a`, `#66739a` | `--m-*`: network map links, path strips, the Connection column. Each sits 30 degrees or more of OKLCH hue from cobalt, jade, amber and rose, so a link never reads as a state. |
| Cable type | USB-C `#e38bd9` orchid, HDMI `#f39a6b` coral, USB `#cdb08f` tan; Ethernet = wired, mesh = Wi-Fi, Bluetooth, coax | `#b0409f`, `#c2531f`, `#8f6a3e` | `--cable-*`: desk wiring only. HDMI moved off amber so it no longer reads as "watch". |

Type: Schibsted Grotesk (`--sans`, `--font-sans`) for words; JetBrains Mono (`--mono`, `--font-mono`,
and `--font-display`, which now points at it) for counts, zoom, speed tags, badges, addresses, times and
commands. Both are self-hosted in `ui/fonts/` and preloaded. Sizes 11 / 12 / 13 / 14 / 16 / 18 in rem, with
30px display figures on the Security view. Tabular figures on mono, counts and numeric columns only: in
Schibsted Grotesk `tnum` also widens the full stop, so prose stays proportional.

Shape: radius 0 everywhere (the `--radius*` names stay, all 0). Panels and rows take an inset 1px `--line`;
floating things (popovers, dialogs, the device list over the map) an inset 1px `--line2`; state is a 2px
inset edge on the left, as Agent Hub marks an alert. `--shadow-1` to `-4` are those hairlines. Map chrome is
`--glass`, the panel at 94%.

Controls (Agent Hub's): a button is a hairline and a word, and hovering fills it from the left with ink. The
primary button is cobalt, the danger button rose with ground-coloured text. A segmented control's chosen
option is the accent wash with an accent-ink line.

Shell: a 40px top bar on the panel: the name and the view ("Home Observability Hub / Map"), the verdict as one line in
its state's colour, then only the counts that are not zero (a mono figure and a word), the scan age, search,
the agent mode and the theme. Under 1600px search keeps only its icon and shortcut; under 1440px the scan age
keeps only its square. The rail is the ground with marks only; the current view is the raise step with a 2px
accent-ink edge.

Motion: `--ease` `cubic-bezier(.23, 1, .32, 1)`; 120ms for state changes, 200ms for panels, dialogs and the
button sweep, 620ms for a node moving. Buttons, action chips and nodes scale to 0.96 while pressed. All
durations are 0 under `prefers-reduced-motion`.

### Contrast (WCAG 2.x, computed 2026-11-21)

| Text, dark | ground `#0b1020` | panel `#11182b` | field `#18213a` | raise `#212c4a` |
|---|---|---|---|---|
| ink `#eef2ff` | 16.9 | 15.8 | 14.3 | 12.3 |
| soft `#b4beda` | 10.2 | 9.5 | 8.6 | 7.4 |
| faint `#8a97ba` | 6.5 | 6.1 | 5.5 | 4.7 |
| accent-ink `#8fb0ff` | 8.9 | 8.3 | 7.5 | 6.4 |
| jade / amber / rose | 10.0 / 10.7 / 6.4 | 9.3 / 10.0 / 6.0 | 8.4 / 9.0 / 5.4 | 7.2 / 7.8 / 4.7 |

| Text, light | ground `#f4f6fb` | panel `#FFFFFF` | field `#eef1f8` | raise `#e3e8f3` |
|---|---|---|---|---|
| ink `#0b1020` | 17.5 | 18.9 | 16.7 | 15.4 |
| soft `#3b4565` | 8.7 | 9.4 | 8.3 | 7.7 |
| faint `#55617f` | 5.7 | 6.2 | 5.5 | 5.0 |
| accent-ink `#2550d0` | 6.2 | 6.7 | 5.9 | 5.5 |
| success / caution / danger text | 6.2 / 5.5 / 5.6 | 6.7 / 5.9 / 6.1 | 5.9 / 5.2 / 5.4 | 5.5 / 4.8 / 5.0 |

| Graphics (need 3:1) | Dark, on ground / raise | Light, on panel / raise |
|---|---|---|
| wired / Wi-Fi / Bluetooth / coax / desk | 9.2 / 6.8 / 9.6 / 7.2 / 5.6 — 6.7 / 5.0 / 7.0 / 5.3 / 4.1 | 4.6 / 5.4 / 4.7 / 4.9 / 4.7 — 3.7 / 4.4 / 3.9 / 4.0 / 3.8 |
| USB-C / HDMI / USB | 8.1 / 8.7 / 9.2 — 5.9 / 6.3 / 6.7 | 5.1 / 4.6 / 4.9 — 4.2 / 3.8 / 4.0 |
| status jade / amber / rose | 10.0 / 10.7 / 6.4 — 7.2 / 7.8 / 4.7 | 4.1 / 4.4 / 4.9 — 3.3 / 3.6 / 4.0 |
| control boundary `--border` (edge) | 3.4 on panel, 3.1 on raise | 3.35 on panel |

| Fill pairs | Ratio |
|---|---|
| white on cobalt `#2f62f5` (both themes) / on hover `#2550d0` | 5.0 / 6.7 |
| ground `#0b1020` on rose `#ff5c8a` (danger button, suspicious, dark) | 6.4 (white would be 3.2, so it is not used) |
| white on rose `#d0305f` (light) | 4.9 |
| accent-ink on the accent wash (a chosen option): dark / light | 6.8 / 5.5 |
| state text on its own wash over the panel: rose / amber / jade, dark | 5.0 / 7.6 / 7.1 |
| state text on its own wash, light: danger / caution / success | 5.1 / 5.1 / 5.8 |
| tooltip: ink on press (dark) / light ink on ground-ink (light) | 9.9 / 16.9 |

---

## 8. Components

Sizes are the first build's (control heights 24 / 30 / 40, rows 28) with the radii, shadows and type of section 7. States listed for each; every
interactive component also has a visible focus ring: 2px `--selection` outline, 2px offset (ours;
Blueprint uses a similar blue focus outline).

| Component | Spec | States |
|---|---|---|
| **Button** | Heights 24/30/40. Padding 0 12px (md). 14px text, 600 for primary. Radius 4. Variants: default (`--bg-raised` + 1px `--border`), primary (blue fill), danger (red fill), minimal (no fill, hover fill). Icon 16px, 8px gap. | default, hover (`--bg-hover`), active (`--bg-active`), focus, disabled (`--text-disabled`, no hover), loading (spinner replaces icon, label stays, width fixed). |
| **Segmented control** | Mode switch, KVM toggle, layer switch. 30px, 1px border, selected segment `--bg-active` + `--text`, others `--text-muted`. | hover, focus, selected, disabled. |
| **Tag** | 20px tall, 0 6px, radius 2, 12px. Neutral = `--bg-hover`. Intent tags use 15% tint background and -5 (dark) / -2 (light) text. Removable tags have an ✕ 12px. | default, hover (removable only), focus. |
| **Status glyph** | 10px, square-cornered like the map's tiles, one outline per state so it survives greyscale: filled square (online), triangle (degraded), diamond (offline), half-filled square (asleep), dashed square (unmonitored), square with a centre (inferred), square with `?` (unknown), two dashes (plan). 8px in dense rows. Always paired with a text label somewhere on the same surface or in its tooltip/aria-label. | static; one-off pulse on change. |
| **Trust glyph** | 14 × 2px line in trust style + word. | static. |
| **Property row** | §5.2. | default, hover (row `--bg-hover`, copy button appears at right), focus. |
| **Table** (Devices view) | Header 30px, `--bg-raised`, 12px/600 muted, sticky. Rows 28px (22px "compact" toggle), 1px row dividers, no zebra. Columns: Status, Name, Kind, Make and model, Identity (chip), Security (chip), Room, Address (mono), Connection (medium swatch and where it goes), Access point, Trust, Last seen, Latency. Columns drop from the right as the width falls; identity and security stay to the phone. Sort by clicking header (arrow). Group by zone toggle. Row click selects + opens inspector; row stays highlighted `--bg-active` with 2px blue left bar. | hover, selected, focus (row outline), loading (skeleton rows), empty, error. |
| **Tabs** | 36px, text 14px, selected = `--text` + 2px blue underline, others muted. | hover, focus, selected, disabled. |
| **Section** (collapsible) | 40px header, 14px/600, chevron; body padding 12px 16px. | open, closed, focus. |
| **Callout** | 3px left border intent colour, 8% tint, 16px icon, 12px padding. | info, caution, danger, success. |
| **Drawer / sheet** | Activity drawer and overlay panels; slides 200ms `--ease`; resizable edge 4px hit area with 1px visible line that turns blue on hover. | closed, open, resizing. |
| **Toast** | Bottom-right 16px from edges (phone: above tab bar, full width minus 16px). Max 3 stacked. 360px wide, elevation 3, intent left border. Auto-dismiss 5s unless it carries an action or is danger. | info, success, caution, danger; hover pauses timer. |
| **Command palette** | `⌘K`. 640px wide, top 20% of viewport, elevation 3, input 40px. Results grouped: Devices, Links, Views, Commands (e.g. "Set agent mode to paused", "Trace path from Mac mini", "Show KVM input PC2"), Recent runs. Rows 32px: icon, name, right-aligned meta (IP, kind) and shortcut. Fuzzy match on name, id, IP, model. | empty query (recent + views), results, no results ("No device or command matches 'x'"), loading. |
| **Tooltip** | 12px, `--bg-active` (dark) / dark-gray1 with white text (light), radius 2, 6px 8px padding, 400ms delay, 0 on subsequent hovers within 300ms. Never holds the only copy of essential info on touch devices. | — |
| **Device chip** | 24px, status glyph + name, radius 2, `--bg-hover`. Hover highlights on map. | default, hover, selected, removable. |
| **Path strip** (desk wiring, answers) | §4.7 / §6.4. Horizontal scroll if long; on phone vertical. | normal, suspect hop, hovered hop (highlights cable). |
| **Action card** | §6.5. | listed there. |
| **Identity chip** | 20px pill. confirmed: outline, green check. likely: outline, italic, `~`. not identified: caution tint, `?`. Tooltip says what it rests on. | static |
| **Security chip** | 20px pill. no findings: grey, green check (only where asked for). worth a look: caution tint, eye. suspicious: red fill. blocked: red outline, ⊘. Tooltip lists the reasons. | static |
| **Internet path** | Device pills joined by connectors in the medium colour and style; "the mesh · access point not known" where the access point is not named. Horizontal in the selection bar, vertical in the inspector. | hover lights the hop on the map; click selects |
| **Device actions** | From `GET /api/device/<id>/actions`, in the order identify, scan, investigate, block or unblock, remove. Three forms: a bar of buttons (selection bar, Security rows as icons), rows (inspector), a menu (right-click). An unavailable action is shown dimmed with a lock; hover, focus or click gives its reason, and a reason that names the router login links to Settings. | available, unavailable, loading |
| **Confirmation** | Dialog: the device (icon, name, make, address, status), the kind of change, "What happens" and "Undo" in the server's words, then Cancel (focused) and the action's own verb. Destructive: red title, red ring, red button, "This cannot be undone from the app". Identify adds the form (name, maker, model, kind, room) with one-click fills from the candidates. While running the button says what is happening. Then the same dialog shows the result: done and what changed, the new evidence of a scan, a link to the agent run, or the error with Try again. A block or unblock while router changes are off is labelled "rehearsal only" before, and after shows "Rehearsal: nothing was changed" with the exact commands that would be sent and the ones that would undo them. | confirm, working, done, rehearsal, failed |

**Empty, loading, error** (every data region):

- Loading: skeletons matching the final layout (row bars, node outlines on the map in `--border-subtle`),
  no spinners for under 300ms; after 300ms skeleton; after 10s add "Still loading from the server…".
- Empty: one sentence saying why and one action. Devices filter empty: "No devices match these
  filters." + Clear filters. Agent history empty: "No runs yet. Ask about a problem to start." Audit
  empty: "Nothing has been logged yet."
- Error: callout in place, the server's message in mono, a Retry button. If `/api/health` shows a
  collector failing, the top bar summary shows "Scan failing: arp (2 min)" in caution colour, and
  live values age visibly ("live · 6 min", turning caution after 3 × scan interval).
- Offline from the server (Tailscale drop on phone): a 28px caution bar under the top bar "Can't reach
  the Mac mini. Showing what was last loaded at 14:02." Everything stays readable; actions disable.

### Keyboard map

| Keys | Action |
|---|---|
| `⌘K` / `Ctrl K` | Command palette |
| `/` | Focus the object list filter (or the table search on Devices) |
| `Esc` | Close the topmost layer: palette → popover → unpin path → clear selection → close right panel |
| `G` then `M` / `T` / `X` / `D` / `A` / `Y` / `Q` / `S` | Go to Map / Threats / Security / Devices / Agent / activitY / Questions / Settings |
| `Arrow keys` (map) | Move selection to the nearest node in that direction (centre-to-centre, within a 90° cone); with nothing in that cone, the next or previous node in reading order, so every node is reachable |
| `Home` / `End` (map) | First / last node in reading order |
| `Tab` (map) | Leaves the map: the map is one Tab stop, so 57 devices never trap the keyboard |
| `Enter` (map) | Open inspector for the selection |
| `[` / `]` | Toggle object list / right panel |
| `` ` `` | Toggle activity drawer |
| `1` `2` | Map: the network / the desk wiring |
| Right-click a node | Its actions as a menu |
| `T` | Trace cables from the selection (desk wiring) |
| `K` | Cycle KVM input view (desk wiring) |
| `F` / `0` / `+` / `-` | Fit / 100% / zoom in / zoom out |
| `A` | Ask the agent about the selection (opens Agent tab with scope chips filled) |
| `⌘↵` | Send in the ask box |
| `⌘.` | Stop: cancel run and pause agent |
| `?` | Keyboard shortcuts sheet |

Single-letter shortcuts are inactive while focus is in a text field. No shortcut approves an action.
The map is a `role="application"` region with an `aria-label` and a live region that announces the
selected node ("Mac mini, online, Ethernet 2.5G → 2.5G switch, 5 hops to the internet"). The Devices table is the accessible equivalent of
the map and must stay complete.

---

## 9. Activity, Questions and Settings views

**Activity · Events**: table rows 28px: time, kind tag (security, status, link, new host), device chip, text
("HomeNAS went offline", "New host 10.20.0.77 on the network"). Filters: kind, device, time range
(1h, 24h, 7d). Strangers (`/api/live.strangers`) appear as "New on the network" events plus a
persistent block at the top of the Devices view, with "Not in the inventory. Add it to
`data/inventory.json` to track it." (The app reads files; it does not edit the inventory.)

**Activity · Audit**: rows grouped by `runId`: question as the group header, then each entry: time,
actor (`agent` / `you`), type (question, tool, proposed, approved, rejected, ran, refused), command in
mono, exit code, summary. Decisions by the person are bold. "Open run" re-opens the full answer.
Export as JSONL (download of what the server returned).

**Questions**: one card per `openQuestions` item, device chips, "Ask the agent" (pre-fills scope and
text), "Show on map".

**Security**: a header with the verdict, six count tiles (devices, not identified, suspicious, blocked, new
today, offline; a tile filters the list and the map) and, when they apply, a line that the server sends no
findings or that there is no router access. Then groups, worst first: Needs a decision (suspicious, then
not identified), Blocked at the router, Worth a look, The router itself (remote admin from the internet,
WPS, UPnP, Telnet, SSH, firmware: each as a finding or a tick), Likely not confirmed, and a collapsed
"Identified, no findings". A row: kind icon, status, name, "new", make · address · connection, chips, the
first reason and when it was first seen, and the actions as icon buttons. Block-list entries that match no
device are served as devices by the server and appear in the Blocked group with Unblock; if a server ever
lists one without a device, it gets its own row.

**Settings**: Agent mode; **Router**: how the app reaches it (SSH key or web login), model, firmware,
clients, age of the reading; a switch "Allow the app to change the router", off by default, that asks
before turning on and says in place what Block does in each position; the web login form (user name and
a password field that is emptied before the request is answered, never kept in state, storage or the
address, and cannot be shown again) with "Remove the login", whose confirmation says the Keychain item
is shared with other tools on the Mac; then what the agent can and cannot do, Scanning, Collectors, Theme,
About.

---

## 10. Copy rules

- Sentence case everywhere: buttons, headers, tabs, menu items ("Approve and run", not "Approve And
  Run"). The only uppercase is the risk tag on action cards.
- Name things as the house does: device `name` from the inventory, ports by their `label`
  ("Thunderbolt 5 (rear 2)"), never ids, unless in the Raw section or a command.
- Status words: Online, Degraded, Offline, Unknown, Not monitored, Inferred from links.
- Trust words: **live** ("measured 40 s ago"), **plan** ("drawn, not confirmed"), **reported** ("Alex
  said so, or an order email").
- Uncertainty, in order of preference: say what is known, then what isn't, then what would settle it.
  "Which rear port is used is not confirmed. Checking the cable at the back would settle it." Never
  "probably", "should be fine", "seems". The agent's confidence is a word: high, medium, low.
- Errors say what happened and what to do: "Couldn't reach the router at 10.20.0.1. Check that it
  is powered on, then retry." Not "Error 500".
- Buttons are verbs with their object: "Ask agent about this", "Trace path", "Copy command",
  "Approve and run". Destructive buttons say the consequence.
- Numbers: units always ("2.5G", "5 Gb/s", "48 ms"), tabular figures, relative times under 24h
  ("3 min ago"), absolute after ("18 Nov, 14:02"), absolute on hover always. 24-hour clock.
- No exclamation marks, no emoji, no "Oops", no anthropomorphic filler from the agent ("I'd be happy
  to"). The agent writes in first person only in "What I checked".

---

## 11. What we deliberately do not do

- No force-directed graph. Wired positions are authored; what comes and goes takes a remembered place.
- No Wi-Fi line to a guessed access point: the mesh as a whole is the target when the data names none.
- No motion that says nothing, and none that cannot be turned off by the system setting.
- No green for anything not probed; no "all good" banner computed from unknowns.
- No percent confidence, no "AI" sparkle iconography, no chat bubbles: answers are documents.
- No auto-run mode, no "approve all", no keyboard shortcut that approves, no approving while the
  command is hidden or truncated.
- No silent edits: the only changes the UI makes are the listed device actions and the router settings,
  each after its own confirmation, each in the audit log.
- No 3D, no isometric illustration, no device photos, no glow for its own sake. Icons are line icons.
- No web fonts, no CDN, no build step (per the contract).
- No dashboard of charts. The map is the dashboard; the Security view is a list of decisions.
- No hiding panes behind hamburger menus on phone: bottom tabs only.

---

## 12. Decisions I was unsure about

1. **Destructive actions on phone.** The spec allows them with a typed confirmation. The alternative
   is "Open on a desktop to approve" for `destructive` below 768px. I lean to allowing it, because it
   is his house and his phone over Tailscale, but this is his call.
2. **Agent placement.** Right-panel tab (beside the inspector) plus a full Agent view. A bottom drawer
   was the other candidate; rejected because answers are long and tall.
3. **Cable colours.** No industry standard exists (AV sources disagree), so the palette is ours, drawn
   from Blueprint's extended colours and checked for contrast. USB-C (indigo) and USB (sand) are
   deliberately far apart even though both carry USB, because the cable type is what he plugs in.
4. **Phone map.** The phone gets the same horizontal map, opened on the mesh, rather than a portrait
   layout of its own. A portrait layout would use the screen better; it was not built.
6. **"New today"** means first seen in the last 24 hours, from `security.firstSeen`. A fresh server state
   makes everything it discovers itself new for a day.
7. **Slots are per browser.** The phone and the desktop each remember their own places for Wi-Fi devices,
   so the same device can sit in a different place on each.
5. **KVM default input** depends on the server exposing which input is live; if `/api/live` does not
   expose it, the UI should infer PC1 from the KVM's hub being enumerated on the Mac mini, and say so.

---

## 13. Sources

Read for this spec (2026-11-20):

- Blueprint colour palette, source: https://raw.githubusercontent.com/palantir/blueprint/develop/packages/colors/src/_colors.scss
- Blueprint variables (spacing 4px, grid 10px, font sizes, line height, radius 4px, control heights, elevation shadows, transition 100ms and easing, font stack): https://raw.githubusercontent.com/palantir/blueprint/develop/packages/core/src/common/_variables.scss and https://github.com/palantir/blueprint/blob/develop/packages/core/src/common/_variables.scss
- Blueprint colour aliases (dark app background, text, muted, dividers, intents): https://raw.githubusercontent.com/palantir/blueprint/develop/packages/core/src/common/_color-aliases.scss
- Palantir AIP Logic staged writes: https://palantir.com/docs/foundry/logic/staged-writes/
- Palantir AIP Logic in Automate (proposals tab, reason, preview, agent decision log, accept → applied): https://palantir.com/docs/foundry/logic/aip-logic-integration-automate/
- Palantir AIP Agent Studio tools (action tool "can be configured to run automatically or to run after confirmation from the user"): https://www.palantir.com/docs/foundry/agent-studio/tools/
- Palantir AIP Chatbot Studio overview: https://www.palantir.com/docs/foundry/agent-studio/overview/
- Palantir Vertex overview: https://www.palantir.com/docs/foundry/vertex/overview/
- Palantir Object Explorer overview: https://www.palantir.com/docs/foundry/object-explorer/overview/
- Palantir Gotham product description (graph + map + timeline/histogram helper apps), seen via search summary only: https://s3.documentcloud.org/documents/810526/1035-palantir-product-description-gotham.pdf
- NetBox cable model (status Active / Planned / Decommissioning; trace follows pass-through ports to the far end): https://netboxlabs.com/docs/netbox/models/dcim/cable/
- Cisco Meraki switch port view (port colour legend, per-port detail): https://documentation.meraki.com/MS/Monitoring_and_Reporting/Switch_Port_View
- Grafana node graph (node anatomy, edge thickness/colour/dash, layouts, 200-node limit): https://grafana.com/docs/grafana/latest/panels-visualizations/visualizations/node-graph/
- Vercel AI SDK generative UI (tool parts mapped to components, invocation states): https://ai-sdk.dev/docs/ai-sdk-ui/generative-user-interfaces
- Vercel AI SDK tool calling (tool approval requests and responses, denied output): https://ai-sdk.dev/docs/ai-sdk-core/tools-and-tool-calling
- Claude Code permissions (tiered approval, read-only tools without prompts): https://code.claude.com/docs/en/permissions
- GitHub Copilot coding agent session logs (reasoning, tools, stop session): https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/track-copilot-sessions
- Android window size classes (compact <600, medium 600–839, expanded 840–1199, large 1200–1599): https://developer.android.com/develop/ui/compose/layouts/adaptive/use-window-size-classes
- Mobbin, incident.io alert routing (active path in colour, other routes grey): https://mobbin.com/screens/8caac5d7-b89d-4093-8e36-a54de851e947
- Mobbin, Quo call flow (canvas + right inspector): https://mobbin.com/screens/da1c81a1-d69f-4ac0-abca-6e0cb8bcd15f
- AV signal-flow practice (legend, consistent colour/line meaning, label origin/destination/signal type; Biamp orthogonal lines), from search summaries only, no primary standard found: https://support.biamp.com/Tesira/Programming/Signal_lines , https://xchange.avixa.org/posts/the-importance-of-clean-cable-management-and-how-to-actually-achieve-it

Could not fetch: UniFi help centre (403), Material 3 layout page (404), Palantir Vertex display-options
and Object View properties pages (404). UniFi and Apple Home patterns are therefore not cited here.

---

## 14. Threats (version 3, Sentinel)

Added 2026-11-20 for `docs/CONTRACT.md` "Version 3". An eighth view, `#/threats` (`G` then `T`), second in
the rail. On a phone the tabs are Map, Threats, Security, Agent, More; Devices moved into More. Security
stays the page about devices on the network; Threats is what the scanners found on this Mac and the network.

- **Unchecked is never shown as safe.** The level is `summary.level` only when the scans behind it are
  working. No `/api/threats` (404): "Not scanning", and the page says nothing has been checked. No scanner
  run for 20 minutes, or every scanner failing or overdue: "Not current". Some scanners with `ok: false`,
  never run, or overdue (three intervals): "Partly checked". Only then is `secure` shown, as "No open
  findings" (or "Low findings only"), in green. The other levels read "Worth a look", "At risk" (tinted
  red), "Compromised" (solid red, the only use of it on this page besides the Critical chip).
- **The top bar's verdict is the worse of two**: the device verdict and the threat level. Compromised
  outranks everything; at risk ties with a suspicious device and wins the tie; an unchecked threat scan
  outranks "No findings" so the pill is never green while it is unchecked. The pill opens the view it
  speaks for. A red dot sits on the Threats button while the level is at risk or compromised.
- **Severity and confidence are two different kinds of mark.** Severity is a coloured chip with its word
  (Critical solid red, High tinted red, Medium amber, Low neutral, Info outlined; the two worst carry a
  warning mark) and a 3px bar on the row. Confidence is never coloured: four bars and the words
  "confirmed", "high confidence", "medium confidence", "low confidence", so "High" alone always means
  severity. The percent is shown only in the detail, next to the word. The detail says once what each means.
- **The list** is as served, worst first: open findings by default, with one line under it linking to
  acknowledged, trusted, quarantined and resolved. The five severity counts are the severity filter. A
  state select and a kind select appear only when there is more than one thing to filter. Under 760px of
  list width a row stacks: chip and date, title, subject, confidence.
- **The detail** uses the inspector panel (a full sheet on a phone); a finding is a selection like any
  other (`?sel=f-…`). Order: title and subject, severity and confidence, what was seen, what to do (text,
  then the command in a block with Copy; "needs sudo" is marked and the app never runs it), the actions
  from `finding.actions`, why it was raised, evidence (label, value, source; values wrap and each can be
  copied), details, history. Trust, Quarantine and Restore open the confirmation of section 8 with what
  happens and how to undo it, Cancel focused; Acknowledge, Reopen and Scan again are one click.
- **Text from a finding is not trusted.** It is rendered as text nodes through `ui/js/safe.js`, never as
  HTML, a link or a style. Bidirectional overrides, zero-width and control characters are shown as their
  code (`U+202E`) in an amber tag, and the detail says so when a name contains one. A long path gives way
  in the middle so the file name and its ending stay visible. Copy copies the text as displayed.
- **Coverage** sits under the list: the eight scanners (what each watches, last run, items, the error in
  the server's words, "Scan now") and the engines. A missing engine or a failing scanner is also one line
  in the header.
- **Nothing open** is one heading and one sentence: how many scanners looked at how many items, and when.
- **A new critical or high finding** while the app is open: one toast with Open, and the row tints for
  under two seconds. Nothing pulses.
- A device finding links to its device; the device inspector lists that device's open findings, and its
  Security row carries a count.
- Sample data: `#/threats?demo=1&threats=0|1|3|40|missing|failing|stale|arrive`.
