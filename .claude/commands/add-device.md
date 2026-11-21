---
description: Add one device to the inventory (something new, or something discovery cannot see)
argument-hint: "[what it is, e.g. 'the new printer in the study']"
---

Add a device the owner describes: $ARGUMENTS

1. Ask what you still need, in one AskUserQuestion batch: what it is (vendor and model if they know;
   a photo of the label is welcome), which room and surface, how it connects (Wi-Fi, cable to what, USB
   or Bluetooth to this Mac, nothing).
2. Look for it: `python3 bin/hoh scan --diff --json` (or the `network-scout` agent) for a new host;
   `python3 portscan.py` and `data/state/discovery.json` → `host.usb`, `host.displays`, `host.bluetooth`
   for things on this Mac. Match by name, vendor lead or timing ("it appeared since the last scan").
3. Write it with the `inventory-authoring` skill: id, kind, zone, the right probe, net entry, ports and
   links if cabled. `verified` is `live` only if a probe saw it now; the model only if a probe claims it
   or the owner said it (`identifiedBy: "person"`).
4. `python3 bin/inventory_check.py` until OK.
5. If it is worth it (network gear, dock, screen, printer, NAS), offer a `device-researcher` agent for its
   knowledge digest.
