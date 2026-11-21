---
description: Set up Home Observability Hub for this home, from nothing to a live map (resumable)
argument-hint: "[start over]"
---

Set up the Home Observability Hub for this person's home. Follow the `home-onboarding` skill
exactly (load it now with the Skill tool if it is not already loaded): welcome and consent, doctor,
first scan, interview in small AskUserQuestion batches, optional router access, write and validate
`data/site.json` and `data/inventory.json`, reconcile with `--diff` until nothing is unexplained,
wiring and layout, knowledge digests (parallel `device-researcher` agents, at most 8), install the
service after a second yes, screenshot and check both maps, then the summary.

Before anything else, detect where setup stands (`data/state/onboarding.json`, `data/site.json`,
`data/inventory.json`, `python3 bin/hoh status`) and continue from the first unfinished step instead of
starting over. If the person passed "start over" ($ARGUMENTS), confirm it with them first and back up
the existing inventory to `data/state/backups/` before replacing anything.

Rules that never bend: never invent hardware or a model; evidence levels live/reported/plan;
read-only toward the network; never read `~/.config/home-observability-hub/`, `~/.ssh` or the
Keychain; never ask for a router password; `python3 bin/inventory_check.py` after every write.
