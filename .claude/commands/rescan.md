---
description: Scan the network again, show what changed, and update the inventory with the owner
---

1. Run the `network-scout` agent with a diff (`python3 bin/hoh scan --diff --json`), or run that
   command yourself and read `data/state/discovery.json` → `diff`.
2. If local network access is blocked (`localNetwork.ok` false), say how to fix it (see `/doctor`) and stop.
3. Tell the owner in plain words: new devices, devices gone, devices that changed address, inventory
   devices that did not answer (asleep or away is normal for phones and laptops).
4. Ask about each new or unexplained host in small AskUserQuestion batches, with the scan's leads as
   options (`device-identification` skill). Ask whether gone devices were removed for good or are just off.
5. Update `data/inventory.json` (`inventory-authoring` skill): add what was named (verified `reported`
   with `identifiedBy: "person"`, or `live` when a probe claim names it), fix moved addresses in net
   entries and probes, record anything nobody can name in `openQuestions`. Remove a device only when the
   owner says it is gone for good; back up the file to `data/state/backups/` first.
6. `python3 bin/inventory_check.py` until OK. The running hub picks the change up within a minute.
