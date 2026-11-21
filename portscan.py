#!/usr/bin/env python3
"""What is plugged into each socket of this Mac, read from macOS itself.

Self-contained on purpose (standard library only, Python 3.9): the Home Observability Hub server imports it for the
Mac it runs on, and any other Mac can run this one file to report its own sockets:

    python3 portscan.py                       print what this Mac sees
    python3 portscan.py --post URL --token T  send it to Home Observability Hub once
    python3 portscan.py --post URL --token T --loop 20     keep sending, every 20 s and at once when a cable moves

It only reads (ioreg, system_profiler, scutil). It changes nothing on the Mac it runs on.
"""
import json
import plistlib
import subprocess
import sys
import time

V = 1


def _run(argv, timeout=30):
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 1, b""


def _hex4(n):
    try:
        if isinstance(n, str):
            n = int(n.split()[0], 16) if n.lower().startswith("0x") else int(n.split()[0])
        return "%04x" % (int(n) & 0xFFFF)
    except (ValueError, TypeError, IndexError):
        return ""


def _s(v, n=80):
    return str(v).strip()[:n] if v not in (None, "") else None


def read_ports():
    """[{type, n, active, usb: [...], display: {...}|None, thunderbolt: bool}] from the IO registry.
    Empty on a Mac whose registry has no IOPort records (Intel)."""
    rc, out = _run(["/usr/sbin/ioreg", "-a", "-r", "-c", "IOPort", "-l"])
    if rc != 0 or not out.strip():
        return []
    try:
        roots = plistlib.loads(out)
    except Exception:
        return []
    ports = []
    for node in roots if isinstance(roots, list) else []:
        typ = _s(node.get("PortTypeDescription"), 20)
        num = node.get("PortNumber")
        if not typ or not isinstance(num, int):
            continue
        port = {"type": typ.lower(), "n": num, "active": bool(node.get("ConnectionActive")),
                "usb": [], "display": None, "thunderbolt": False}
        for t in node.get("IORegistryEntryChildren") or []:
            if not t.get("Active"):
                continue
            kind = t.get("TransportTypeDescription") or ""
            if kind in ("USB2", "USB3"):
                vid, pid = _hex4(t.get("Vendor ID")), _hex4(t.get("Product ID"))
                if vid or pid:
                    port["usb"].append({"vendorId": vid, "productId": pid, "name": _s(t.get("Product")),
                                        "vendor": _s(t.get("Manufacturer")), "serial": _s(t.get("Serial Number"), 40),
                                        "speed": _s(t.get("DataRateDescription"), 40),
                                        "hub": t.get("Device Class") == 9})
            elif kind in ("DisplayPort", "HDMI"):
                if t.get("SinkCount", 1) or t.get("ProductName"):
                    port["display"] = {"name": _s(t.get("ProductName")), "vendor": _s(t.get("ManufacturerName"), 12),
                                       "productId": _hex4(t.get("ProductID")),
                                       "rate": _s(t.get("LinkRateDescription"), 40), "lanes": t.get("LaneCount")}
            elif kind == "CIO":
                port["thunderbolt"] = True
        port["active"] = port["active"] or bool(port["usb"] or port["display"])
        ports.append(port)
    return sorted(ports, key=lambda p: (p["type"], p["n"]))


def read_usb_tree():
    """Flat USB list, each with the index of its parent in the list (None at the top) and builtIn."""
    rc, out = _run(["/usr/sbin/system_profiler", "SPUSBHostDataType", "-json"], timeout=40)
    try:
        doc = json.loads(out.decode("utf-8", "replace") or "{}") if rc == 0 else {}
    except ValueError:
        doc = {}
    flat = []

    def walk(items, parent):
        for it in items or []:
            vid, pid = _hex4(it.get("USBDeviceKeyVendorID") or ""), _hex4(it.get("USBDeviceKeyProductID") or "")
            me = parent
            if vid or pid:
                flat.append({"vendorId": vid, "productId": pid, "name": _s(it.get("_name")),
                             "vendor": _s(it.get("USBDeviceKeyVendorName")),
                             "serial": None if (it.get("USBDeviceKeySerialNumber") or "").lower().startswith("not ") else _s(it.get("USBDeviceKeySerialNumber"), 40),
                             "speed": _s(it.get("USBDeviceKeyLinkSpeed"), 40), "power": _s(it.get("USBDeviceKeyPowerAllocation"), 40),
                             "builtIn": it.get("USBKeyHardwareType") == "Built-in", "parent": parent})
                me = len(flat) - 1
            walk(it.get("_items"), me)
    walk(doc.get("SPUSBHostDataType"), None)
    return flat


def read_displays():
    """External and built-in displays by name: the fallback where the registry has no port records."""
    rc, out = _run(["/usr/sbin/system_profiler", "SPDisplaysDataType", "-json"], timeout=40)
    try:
        doc = json.loads(out.decode("utf-8", "replace") or "{}") if rc == 0 else {}
    except ValueError:
        doc = {}
    res = []
    for gpu in doc.get("SPDisplaysDataType") or []:
        for d in gpu.get("spdisplays_ndrvs") or []:
            res.append({"name": _s(d.get("_name")),
                        "builtIn": d.get("spdisplays_connection_type") == "spdisplays_internal" or "spdisplays_display_type" in d and "built" in str(d.get("spdisplays_display_type")).lower(),
                        "connection": _s(d.get("spdisplays_connection_type"), 40)})
    return res


def observe():
    rc, name = _run(["/usr/sbin/scutil", "--get", "ComputerName"], timeout=5)
    rc2, model = _run(["/usr/sbin/sysctl", "-n", "hw.model"], timeout=5)
    return {"v": V, "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "computer": _s(name.decode("utf-8", "replace"), 80),
            "model": _s(model.decode("utf-8", "replace"), 40),
            "ports": read_ports(), "usb": read_usb_tree(), "displays": read_displays()}


def fingerprint(obs):
    return json.dumps({k: obs.get(k) for k in ("ports", "usb", "displays")}, sort_keys=True)


def _post(url, token, obs):
    import urllib.request
    req = urllib.request.Request(url, data=json.dumps(obs).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-Report-Token": token})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status


def main(argv):
    def opt(name, default=None):
        return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else default
    url, token, loop = opt("--post"), opt("--token"), opt("--loop")
    if not url:
        json.dump(observe(), sys.stdout, indent=1)
        print()
        return 0
    if not token:
        print("--post needs --token", file=sys.stderr)
        return 2
    if not loop:
        print("sent, HTTP %s" % _post(url, token, observe()))
        return 0
    every = max(5, int(loop))
    last, last_sent = None, 0
    while True:
        try:
            # The registry read is cheap: look every 5 s, send when something moved or the interval is up.
            ports = read_ports()
            quick = json.dumps(ports, sort_keys=True)
            if quick != last or time.time() - last_sent >= every * 6:
                obs = observe()
                _post(url, token, obs)
                last, last_sent = quick, time.time()
        except Exception as e:      # the server being away must not stop the loop
            print("report failed: %s" % e, file=sys.stderr)
        time.sleep(5)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
