#!/usr/bin/env python3
"""Check data/layout.json against data/inventory.json.

    python3 bin/layout_check.py [--layout PATH] [--inventory PATH] [--json]

Errors (exit 1): an id in the layout that the inventory does not have, two wiring boxes that overlap, a port stub
for a port the device does not list, a route, loose end or label spot for a link the inventory does not have, a file
that is not valid JSON. Warnings: network places so close that two devices would sit on each other, frames that
name zones the inventory does not have. Notes: devices with a cable that the layout leaves to automatic placement.

Defaults: data/layout.json and data/inventory.json, or HM_LAYOUT / HM_INVENTORY. Reads files only. Python 3.9,
standard library only.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def node_height(n):
    rows = n.get("rows") or 0
    return 54 + 20 * rows if rows else 48


def end_of(value):
    dev, _, port = str(value or "").partition(":")
    return dev, (port or None)


def load(path, what, problems):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        problems.append(("error", "bad-json", what, "%s could not be read as JSON: %s" % (path, e)))
        return None


def check(layout, inv):
    """Returns a list of (level, code, where, message)."""
    out = []
    add = lambda level, code, where, msg: out.append((level, code, where, msg))
    devices = {d.get("id"): d for d in inv.get("devices") or [] if isinstance(d, dict) and d.get("id")}
    links = {l.get("id"): l for l in inv.get("links") or [] if isinstance(l, dict) and l.get("id")}
    zones = {z.get("id") for z in inv.get("zones") or [] if isinstance(z, dict)}
    ports = {i: {p.get("id") for p in d.get("ports") or [] if isinstance(p, dict)} for i, d in devices.items()}

    net = layout.get("network") if isinstance(layout.get("network"), dict) else {}
    wiring = layout.get("wiring") if isinstance(layout.get("wiring"), dict) else {}

    # ---------------------------------------------------------------- network map
    pos = net.get("pos") if isinstance(net.get("pos"), dict) else {}
    placed = []
    for i, p in sorted(pos.items()):
        if i not in devices:
            add("error", "unknown-id", "network.pos." + i, "%s is not in the inventory; its place is ignored" % i)
            continue
        if not (isinstance(p, list) and len(p) >= 2 and all(isinstance(v, (int, float)) for v in p[:2])):
            add("error", "bad-value", "network.pos." + i, "a place is [x, y] in SVG pixels")
            continue
        placed.append((i, p[0], p[1]))
    for a in range(len(placed)):
        for b in range(a + 1, len(placed)):
            (ia, xa, ya), (ib, xb, yb) = placed[a], placed[b]
            if abs(xa - xb) < 100 and abs(ya - yb) < 84:
                add("warning", "too-close", "network.pos." + ia, "%s and %s are less than 100 x 84 apart: their tiles and labels overlap" % (ia, ib))
    hull = net.get("hull")
    if hull is not None and not (isinstance(hull, dict) and all(isinstance(hull.get(k), (int, float)) for k in ("x", "y", "w", "h"))):
        add("error", "bad-value", "network.hull", "the hull is {x, y, w, h}")

    # ---------------------------------------------------------------- wiring map
    nodes = wiring.get("nodes") if isinstance(wiring.get("nodes"), dict) else {}
    boxes = []
    for i, n in sorted(nodes.items()):
        where = "wiring.nodes." + i
        if i not in devices:
            add("error", "unknown-id", where, "%s is not in the inventory; its box is ignored" % i)
            continue
        if not isinstance(n, dict) or not all(isinstance(n.get(k), (int, float)) for k in ("x", "y")):
            add("error", "bad-value", where, "a box needs x and y")
            continue
        for pid, spec in sorted((n.get("ports") or {}).items()):
            if pid not in ports[i]:
                add("error", "unknown-port", where + ".ports." + pid, "%s lists no port %s (it has: %s)" % (i, pid, ", ".join(sorted(p for p in ports[i] if p)) or "none"))
            if not isinstance(spec, dict) or spec.get("side") not in ("l", "r", "t", "b"):
                add("error", "bad-value", where + ".ports." + pid, "a stub is {side: l|r, row} or {side: t|b, x}")
        boxes.append((i, n["x"], n["y"], n.get("w") or 200, node_height(n)))
    for a in range(len(boxes)):
        for b in range(a + 1, len(boxes)):
            ia, xa, ya, wa, ha = boxes[a]
            ib, xb, yb, wb, hb = boxes[b]
            if xa < xb + wb and xb < xa + wa and ya < yb + hb and yb < ya + ha:
                add("error", "overlap", "wiring.nodes." + ia, "the boxes of %s and %s overlap" % (ia, ib))
    for key in ("routes", "looseEnds", "labelAt"):
        block = wiring.get(key) if isinstance(wiring.get(key), dict) else {}
        for lid in sorted(block):
            if lid not in links:
                add("error", "unknown-link", "wiring.%s.%s" % (key, lid), "the inventory has no link %s" % lid)
    for z in wiring.get("zones") or []:
        if not isinstance(z, dict):
            continue
        for zid in z.get("zones") or []:
            if zid not in zones:
                add("warning", "unknown-zone", "wiring.zones." + str(z.get("id")), "frame %s names zone %s, which the inventory does not have" % (z.get("id"), zid))
    plan = wiring.get("plan") if isinstance(wiring.get("plan"), dict) else {}
    rooms = {r.get("id") for r in inv.get("rooms") or [] if isinstance(r, dict)}
    for rid in sorted((plan.get("rooms") or {})):
        if rid not in rooms:
            add("warning", "unknown-room", "wiring.plan.rooms." + rid, "the inventory has no room %s" % rid)

    # cable ends on an authored box with no stub: the UI adds one, facing the other end
    loose = wiring.get("looseEnds") if isinstance(wiring.get("looseEnds"), dict) else {}
    for lid, l in sorted(links.items()):
        if l.get("cable") in ("wifi", "bluetooth"):
            continue
        for key, raw in (("a", l.get("from")), ("b", l.get("to"))):
            dev, port = end_of(raw)
            n = nodes.get(dev)
            if not isinstance(n, dict) or dev not in devices:
                continue
            has = (port and port in (n.get("ports") or {})) or (isinstance(loose.get(lid), dict) and key in loose[lid])
            if not has:
                add("info", "auto-stub", "wiring.nodes." + dev, "cable %s has no stub on %s (%s); one is added on the side facing the other end" % (lid, dev, port or "port not named"))

    # ---------------------------------------------------------------- what is left to automatic placement
    cabled = set()
    for l in links.values():
        if l.get("cable") in ("wifi", "bluetooth"):
            continue
        a, b = end_of(l.get("from"))[0], end_of(l.get("to"))[0]
        if a in devices and b in devices and a != b:
            cabled.update((a, b))
    auto_boxes = sorted(cabled - set(nodes))
    if nodes and auto_boxes:
        add("info", "auto-box", "wiring.nodes", "%d cabled device(s) placed automatically on the wiring map: %s" % (len(auto_boxes), ", ".join(auto_boxes)))
    elif not nodes and cabled:
        add("info", "auto-box", "wiring.nodes", "no boxes are pinned: all %d cabled devices are placed automatically" % len(cabled))
    auto_net = sorted(i for i in cabled if i not in pos)
    if pos and auto_net:
        add("info", "auto-place", "network.pos", "%d cabled device(s) placed automatically on the network map: %s" % (len(auto_net), ", ".join(auto_net)))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check data/layout.json against data/inventory.json.")
    ap.add_argument("--layout", default=os.environ.get("HM_LAYOUT") or os.path.join(ROOT, "data", "layout.json"))
    ap.add_argument("--inventory", default=os.environ.get("HM_INVENTORY") or os.path.join(ROOT, "data", "inventory.json"))
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    args = ap.parse_args(argv)

    problems = []
    inv = load(args.inventory, "inventory", problems)
    layout = load(args.layout, "layout", problems)
    if inv is None and not problems:
        problems.append(("error", "missing", "inventory", "%s does not exist" % args.inventory))
    if layout is None and not any(p[2] == "layout" for p in problems):
        problems.append(("info", "missing", "layout", "%s does not exist: both maps place everything automatically" % args.layout))
    if isinstance(inv, dict) and isinstance(layout, dict):
        problems += check(layout, inv)
    elif layout is not None and not isinstance(layout, dict):
        problems.append(("error", "bad-value", "layout", "layout.json must be a JSON object"))

    errors = [p for p in problems if p[0] == "error"]
    if args.json:
        pack = lambda lvl: [{"code": c, "where": w, "message": m} for (l, c, w, m) in problems if l == lvl]
        print(json.dumps({"ok": not errors, "layout": args.layout, "inventory": args.inventory,
                          "errors": pack("error"), "warnings": pack("warning"), "info": pack("info")}, indent=2))
    else:
        print("layout:    " + args.layout)
        if isinstance(inv, dict):
            print("inventory: %s (%d devices, %d links)" % (args.inventory, len(inv.get("devices") or []), len(inv.get("links") or [])))
        else:
            print("inventory: " + args.inventory)
        if problems:
            print()
        word = {"error": "ERROR  ", "warning": "WARNING", "info": "note   "}
        for level in ("error", "warning", "info"):
            for (l, c, w, m) in problems:
                if l == level:
                    print("%s %s: %s" % (word[l], w, m))
        n = lambda lvl: sum(1 for p in problems if p[0] == lvl)
        print()
        print("%d error%s, %d warning%s, %d note%s" % (n("error"), "" if n("error") == 1 else "s", n("warning"), "" if n("warning") == 1 else "s", n("info"), "" if n("info") == 1 else "s"))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
