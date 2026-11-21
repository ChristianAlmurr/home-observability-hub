---
description: Work through the devices that are still unidentified, one small batch at a time
---

1. Read `data/inventory.json` (devices with `kind: "unknown"`, hedged models, and `openQuestions`) and
   `data/state/discovery.json` (hosts with no `inventoryId`). If the discovery is older than a day, refresh it
   with `python3 bin/hoh scan --diff --json` first.
2. For each, gather what evidence already says (leads with their sources; claims first). Follow the
   `device-identification` skill: claims may name a model, candidates never do.
3. Ask the owner in batches of up to 4 (AskUserQuestion), options built from the leads, always with
   "Not mine / don't know". Suggest a quick way to settle each one they do not know (unplug and rescan,
   the device's app shows its IP or MAC, the label underneath).
4. Write each answer (`inventory-authoring` skill): `identifiedBy: "person"`, `identifiedAt`,
   `verified: "reported"`, a real `id` instead of `unknown-…` only for new entries (never rename an
   existing id; change `name`, `kind`, `vendor`, `model` instead). Close the open question, or update its
   text with what was learned.
5. Hosts that turn out to be someone else's managed device: add to `site.json` `handsOff`.
6. `python3 bin/inventory_check.py` until OK. Report what is now identified and what stays open.
