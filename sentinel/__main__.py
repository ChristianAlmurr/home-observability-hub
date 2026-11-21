"""python3 -m sentinel scan [scanner] | status [--json]

Runs against the same state files as the server (data/state/sentinel/, or HM_STATE_DIR). Nothing here
needs the server to be running; with the server running, both write under the same file lock.
"""
import json
import sys
import time

from . import api, engines
from .engine import Engine, SCANNERS


def print_status(eng, as_json=False):
    doc = api.threats_doc(eng)
    if as_json:
        print(json.dumps(doc, indent=1, ensure_ascii=False))
        return
    s = doc["summary"]
    print("Sentinel: %s. %d open (%d new, %d acknowledged). Worst: %s. Last scan: %s" % (
        s["level"], s["open"], s["new"], s["acknowledged"], s["worst"], s["lastScan"] or "never"))
    e = doc["engines"]
    print("Engines: ClamAV %s, YARA %s (%s rule files), XProtect %s, Gatekeeper %s" % (
        ("%s, signatures %s" % (e["clamav"].get("version"), (e["clamav"].get("signaturesAt") or "?")[:10])) if e["clamav"].get("installed") else "not installed",
        "installed" if e["yara"].get("installed") else "not installed", e["yara"].get("rules"),
        e["xprotect"].get("version") or "unknown", {True: "on", False: "OFF", None: "unknown"}[e["gatekeeper"].get("enabled")]))
    for f in doc["findings"]:
        print("  [%-8s %-9s %3d%%] %-12s %-11s %s  (%s)" % (f["severity"], f["confidence"], f["confidencePct"], f["state"], f["scanner"], f["title"], f["id"]))
    for name, sc in doc["scanners"].items():
        print("  %-11s %s  %6s ms  %s items, %d open%s" % (
            name, "ok " if sc["ok"] else "never run" if sc["ok"] is None else "FAILED: %s" % sc["error"], sc["durationMs"], sc["itemsScanned"], sc["open"],
            "".join("\n      not checked: %s: %s" % (n["check"], n["why"]) for n in sc["notChecked"])))


def main(argv):
    if not argv or argv[0] not in ("scan", "status"):
        print(__doc__.strip())
        print("scanners: " + ", ".join(SCANNERS))
        return 2
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    eng = Engine(enabled=True)
    if argv[0] == "scan":
        names = argv[1:] or list(SCANNERS)
        bad = [n for n in names if n not in SCANNERS]
        if bad:
            print("no such scanner: %s (there are: %s)" % (", ".join(bad), ", ".join(SCANNERS)))
            return 2
        eng.engines(fresh=True)
        for n in names:
            t0 = time.time()
            st = eng.run_scanner(n)
            if not as_json:
                print("%-11s %s in %.1f s" % (n, "ok" if st and st["ok"] else "FAILED: %s" % (st or {}).get("error", "already running"), time.time() - t0), file=sys.stderr)
    print_status(eng, as_json)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
