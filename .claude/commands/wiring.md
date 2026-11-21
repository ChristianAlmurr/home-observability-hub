---
description: Walk through the cables (desk, TV corner, network cabinet) and update links and the wiring map
argument-hint: "[surface, e.g. desk]"
---

Follow the `wiring-mapping` skill for: $ARGUMENTS (all surfaces when empty).

Start from what this Mac reads itself (`python3 portscan.py`, discovery's `host` block): those cables
are `live`. Ask about the rest surface by surface in small AskUserQuestion batches, and invite photos of
the back of the switch, dock or desk. Write ports and links with honest `verified` and `evidence`
(`inventory-authoring` skill), run `python3 bin/inventory_check.py`, then check the wiring map: run
`python3 bin/layout_check.py` if it exists, take the headless screenshot, look at it, and fix the layout
(or hand it to the `layout-designer` agent). Finish with a per-surface summary of live, reported and open.
