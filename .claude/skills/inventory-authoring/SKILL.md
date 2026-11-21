---
name: inventory-authoring
description: How to write and edit data/inventory.json and data/site.json for Home Observability Hub - device ids, kinds, ports, net entries, links with carries, probe types per device class, rooms and zones, openQuestions - and validate them. Use whenever adding, changing or removing a device, cable, room or zone, when /setup or /rescan writes the inventory, or when someone says "add this device", "move it to the kitchen", "it is plugged into the switch".
---

# Writing the inventory

`data/inventory.json` is the hand-kept truth the hub draws and probes. `docs/CONTRACT.md` is the full
contract; `tests/fixtures/inventory.json` is a complete example house (52 devices). This skill is the
short version. **After every write, run `python3 bin/inventory_check.py` and fix every ERROR before
moving on.** It also checks the ids `data/site.json` refers to.

Edit with small, targeted edits (Edit tool) once the file exists; never regenerate a whole inventory
the person has already corrected. Keep the file pretty-printed with 1 or 2 space indent.

## Top level

```
{ "schema": 2,
  "site": { "name", "subnet", "gateway", "surveyedAt", "ssid" },     informational
  "_evidence": "one sentence: what live / reported / plan mean in this house and when it was surveyed",
  "rooms": [ {id, name} ],  "zones": [ {id, name, room, note} ],
  "devices": [ … ],  "links": [ … ],  "openQuestions": [ {id, text, devices: [ids]} ] }
```

## Ids

Lower-case letters, digits and dashes, start with a letter or digit, at most 64 characters, unique.
Name by what it is plus where or whose: `mac-mini`, `router`, `node-office`, `switch-desk`,
`tv-living`, `speaker-kitchen`, `phone-sam`, `printer`. Unidentified things: `unknown-<hint>` such as
`unknown-mxchip-53`. Links: `l-<from>-<to>` (`l-router-switch`), Bluetooth `l-bt-<device>`.
**Never rename an id that exists**: knowledge files, layout and history refer to it.

## Rooms and zones

Rooms are the floor plan. Zones are where a device sits; every zone belongs to a room. Make one zone
per room with the room's id (the room in general), plus one per wired surface the person mentions:
`desk`, `network-cabinet` (or `rack`), `tv-corner`. Always add `unplaced` (things not yet placed) and
`outside` (the internet); these two have no `room`. A device's `zone` must exist.

## Devices

```
{ "id", "name", "kind", "vendor"?, "model"?, "zone", "role"?, "verified",
  "ports"?: [ {id, label, type} ], "net"?: [ … ], "probe": { type, … }, "facts"?: {},
  "identifiedBy"?: "person", "identifiedAt"?: "2026-11-21" }
```

`kind`: computer, laptop, phone, tablet, display, tv, speaker, headphones, peripheral, adapter, hub, dock,
kvm, switch, router, access-point, modem, internet, nas, bridge, camera, doorbell, vacuum, appliance,
console, wearable, printer, light, plug, sensor, thermostat, media-player, iot, unknown.
`vendor`/`model` follow the `device-identification` skill: a model only when a probe or the person
confirms it.

Ports (only for things with cables you draw): `id` lower-case (`lan1`, `wan`, `p1`, `tb-1`, `usb-c-1`,
`hdmi-1`, `coax`), `type` one of rj45, usb-a, usb-c, thunderbolt, usb-b, hdmi, dp, coax, fiber, power,
audio.

Net entries (one per address the device has):
`{ "if"?, "ip"?, "mac"?, "medium": "ethernet"|"wifi"|"bluetooth", "name"?, "ssid"?, "ap"?, "band"?,
"linkSpeed"?, "via"?, "randomizedMac"?, "macVendor"?, "verified", "note"? }`. Every `ip` must sit in the
home subnet or `site.json` `network.extraNets` (a cable modem's 192.168.100.1 needs `"extraNets":
["192.168.100.1/32"]`). `ap` and `via` are device ids. MACs are written `AA:BB:CC:DD:EE:FF`.

## Probes: which one per device

| device | probe | fields |
|---|---|---|
| the Mac the hub runs on (exactly one) | `self` | its `net` entries carry `if` (en0, en1, …), `ip`, `medium`, `linkSpeed` |
| router, mesh node, switch with an address, NAS, printer, camera, IoT with a fixed address | `ping` | `ip`, optional `tcp` port that must also answer |
| something that ignores ping but has a port (NAS, file server) | `tcp` | `host` (name) and/or `fallbackIps`, `tcp` |
| Google Cast speaker, display, TV, Chromecast | `cast` | `ip` |
| Hue bridge or anything with a JSON status page | `http` | `url` (`http://<ip>/api/0/config` for Hue) |
| a laptop or computer that sleeps and moves | `mdns` | `name` (its mDNS name prefix), optional `serviceTypes` |
| USB device on this Mac (KVM hub, Stream Deck, dock with a USB id) | `usb` | `vendorId`, `productId` as `0x05e3` (from discovery `host.usb`) |
| display on this Mac | `display` | `match`: a part of the display name from discovery `host.displays` |
| USB Ethernet adapter on this Mac | `interface` | `if` (en8) |
| Bluetooth keyboard, mouse, headphones paired with this Mac | `bluetooth` | `mac`, `name` (from discovery `host.bluetooth`) |
| something Home Assistant tracks (a phone's presence, a vacuum) | `ha` | `entity` (`device_tracker.sam_phone`) |
| an unmanaged switch with no address | `inferred` | `from`: ids of the links into it |
| a cable-only thing, passive hub, power strip, anything with nothing to ask | `none` | |

Phones and watches: use `ha` when Home Assistant tracks them, else `none` with their `net` entry (they
sleep and change address; with router access the router's list gives presence). Addresses that change
break `ping`/`cast` probes: suggest a DHCP reservation in the router for fixed devices, and `/rescan`
finds the moves.

## Links

```
{ "id": "l-router-switch", "from": "router:lan1", "to": "switch-desk:p1", "cable": "ethernet",
  "carries": ["network"], "label": "Cat6", "speed": "1G", "verified": "reported",
  "evidence": "Sam: the blue cable from the router goes to the desk switch, port 1" }
```

`from`/`to` are `device` or `device:port` (the port must be in that device's `ports`). `cable`: ethernet,
usb, usb-c, thunderbolt, hdmi, dp, bluetooth, coax, fiber, dsl, mesh (wireless backhaul between mesh
units), power, audio. `carries`: network, video, usb, audio, power, input, data. **Never write Wi-Fi
links**: the server draws them from each device's Wi-Fi net entry. Bluetooth links run from the peripheral
to its computer, no ports. The path to the internet is explicit: a device `internet` (kind internet, zone
outside) and a link `l-internet-modem` (or `l-internet-router` when there is no separate modem).

## Worked example (a small flat; passes inventory_check with subnet 192.168.1.0/24)

```json
{
 "schema": 2,
 "site": {"name": "The Flat", "subnet": "192.168.1.0/24", "gateway": "192.168.1.1", "surveyedAt": "2026-11-21"},
 "_evidence": "live = seen by discover.py from the iMac on 2026-11-21; reported = Sam said so; plan = drawn, not confirmed.",
 "rooms": [{"id": "living", "name": "Living Room"}, {"id": "study", "name": "Study"}],
 "zones": [
  {"id": "living", "name": "Living room", "room": "living"},
  {"id": "tv-corner", "name": "TV corner", "room": "living", "note": "router and TV"},
  {"id": "study", "name": "Study", "room": "study"},
  {"id": "desk", "name": "Desk", "room": "study"},
  {"id": "unplaced", "name": "Not placed yet"},
  {"id": "outside", "name": "Outside"}
 ],
 "devices": [
  {"id": "internet", "name": "Internet", "kind": "internet", "zone": "outside", "verified": "live",
   "probe": {"type": "none"}},
  {"id": "router", "name": "Router", "kind": "router", "vendor": "ASUS", "model": "RT-AX58U", "zone": "tv-corner",
   "verified": "live", "facts": {"identifiedFrom": "SSDP device description modelName RT-AX58U"},
   "ports": [{"id": "wan", "label": "WAN", "type": "rj45"}, {"id": "lan1", "label": "LAN 1", "type": "rj45"}],
   "net": [{"ip": "192.168.1.1", "medium": "ethernet", "verified": "live"}],
   "probe": {"type": "ping", "ip": "192.168.1.1", "tcp": 80}},
  {"id": "imac", "name": "iMac", "kind": "computer", "vendor": "Apple", "model": "iMac (iMac21,1)", "zone": "desk",
   "verified": "live", "ports": [{"id": "eth", "label": "Ethernet", "type": "rj45"}, {"id": "usb-c-1", "label": "USB-C 1", "type": "usb-c"}],
   "net": [{"if": "en0", "ip": "192.168.1.20", "medium": "ethernet", "linkSpeed": "1G", "verified": "live"}],
   "probe": {"type": "self"}},
  {"id": "switch-desk", "name": "Desk switch", "kind": "switch", "vendor": "TP-Link", "model": "5-port switch (model not confirmed)",
   "zone": "desk", "verified": "reported",
   "ports": [{"id": "p1", "label": "1", "type": "rj45"}, {"id": "p2", "label": "2", "type": "rj45"}],
   "probe": {"type": "inferred", "from": ["l-router-switch", "l-switch-imac"]}},
  {"id": "speaker-kitchen", "name": "Kitchen speaker", "kind": "speaker", "vendor": "Google", "model": "Google Nest Mini",
   "zone": "living", "verified": "live", "facts": {"identifiedFrom": "mDNS _googlecast md=Google Nest Mini"},
   "net": [{"ip": "192.168.1.31", "medium": "wifi", "verified": "live"}], "probe": {"type": "cast", "ip": "192.168.1.31"}},
  {"id": "keyboard", "name": "Magic Keyboard", "kind": "peripheral", "vendor": "Apple", "model": "Magic Keyboard",
   "zone": "desk", "verified": "live", "net": [{"medium": "bluetooth", "mac": "AA:BB:CC:00:11:22", "verified": "live"}],
   "probe": {"type": "bluetooth", "mac": "AA:BB:CC:00:11:22", "name": "Magic Keyboard"}},
  {"id": "phone-sam", "name": "Sam's iPhone", "kind": "phone", "vendor": "Apple", "model": "iPhone", "zone": "unplaced",
   "verified": "reported", "identifiedBy": "person", "identifiedAt": "2026-11-21",
   "net": [{"ip": "192.168.1.44", "medium": "wifi", "randomizedMac": true, "verified": "live"}], "probe": {"type": "none"}},
  {"id": "unknown-mxchip-53", "name": "Unknown gadget (mxchip)", "kind": "unknown", "model": "not identified",
   "zone": "unplaced", "verified": "live", "facts": {"candidates": "MXCHIP Wi-Fi module: an appliance or gadget built on it"},
   "net": [{"ip": "192.168.1.53", "name": "mxchip", "medium": "wifi", "verified": "live"}],
   "probe": {"type": "ping", "ip": "192.168.1.53"}}
 ],
 "links": [
  {"id": "l-internet-router", "from": "internet", "to": "router:wan", "cable": "fiber", "carries": ["network"],
   "verified": "reported", "evidence": "Sam: fibre box on the wall, into the router's WAN port"},
  {"id": "l-router-switch", "from": "router:lan1", "to": "switch-desk:p1", "cable": "ethernet", "carries": ["network"],
   "verified": "reported", "evidence": "Sam traced the cable"},
  {"id": "l-switch-imac", "from": "switch-desk:p2", "to": "imac:eth", "cable": "ethernet", "carries": ["network"],
   "speed": "1G", "verified": "live", "evidence": "en0 is active at 1000baseT on the iMac"},
  {"id": "l-bt-keyboard", "from": "keyboard", "to": "imac", "cable": "bluetooth", "carries": ["input"],
   "verified": "live", "evidence": "system_profiler lists Magic Keyboard as connected"}
 ],
 "openQuestions": [
  {"id": "q-mxchip-53", "text": "What is the Wi-Fi gadget named mxchip at 192.168.1.53? Unplug suspects one at a time and run /rescan.",
   "devices": ["unknown-mxchip-53"]}
 ]
}
```

## data/site.json

Written once by `/setup`, then rarely. Shape in `docs/SITE.md`. Minimum:

```json
{ "schema": 1, "home": {"name": "The Flat", "owner": "Sam"},
  "network": {"subnet": "auto", "gateway": "auto", "extraNets": []},
  "router": {"type": "none", "deviceId": "router"},
  "host": {"deviceId": "imac"}, "protected": [], "handsOff": [],
  "homeAssistant": {"url": ""}, "server": {"port": 8799} }
```

`router.deviceId`, `host.deviceId`, `protected` and `handsOff[].id` must be inventory ids (inventory_check
says so when they are not). `handsOff` entries: `{"id", "ips": [], "names": [], "why"}`. Check the resolved
result with `python3 site_config.py`.

## After writing

1. `python3 bin/inventory_check.py` until it says OK (warnings are worth a look, not a stop).
2. `python3 bin/layout_check.py` if `data/layout.json` exists (ids that left the inventory).
3. If the service runs, the hub picks the change up on its next cycle (about 30 s); no restart needed.
