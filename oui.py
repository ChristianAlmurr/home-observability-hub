"""MAC address helpers: who made the network chip, and is the address a private one.

`oui_table.json` is a filtered copy of the IEEE registry (24-bit prefixes of
vendors found in homes), so a miss means "not in the table", never "unknown
maker". A vendor from a MAC prefix names the maker of the radio, which is often
a module maker (Espressif, MXCHIP, Murata) and not the brand on the box: it is
a lead, never an identity.
"""
import json
import os
import re
import threading

ROOT = os.path.dirname(os.path.abspath(__file__))
_lock = threading.Lock()
_table = None       # {"AABBCC": vendor}
_modules = set()

MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?)[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}$")

# Bluetooth SIG company ids and USB-IF vendor ids that system_profiler prints for peripherals.
PERIPHERAL_VENDORS = {
    0x046D: "Logitech", 0x004C: "Apple", 0x05AC: "Apple", 0x009E: "Bose", 0x045E: "Microsoft", 0x0006: "Microsoft",
    0x054C: "Sony", 0x012D: "Sony", 0x0075: "Samsung", 0x04E8: "Samsung", 0x00E0: "Google", 0x18D1: "Google",
    0x0057: "Harman", 0x0087: "Garmin", 0x1532: "Razer", 0x3434: "Keychron", 0x0A5C: "Broadcom", 0x000F: "Broadcom",
    0x000A: "Qualcomm (CSR)", 0x001D: "Qualcomm", 0x0002: "Intel", 0x02E5: "Espressif", 0x0171: "Amazon",
    0x0103: "Bang & Olufsen", 0x0067: "Jabra (GN)",
}


def normalize(mac):
    """'aa-bb-cc-61-02-91' or 'aabbccddeeff' -> 'AA:BB:CC:61:02:91'; None when it is not a MAC."""
    if not isinstance(mac, str) or not MAC_RE.match(mac.strip()):
        return None
    h = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def _load():
    global _table, _modules
    with _lock:
        if _table is not None:
            return
        t = {}
        try:
            with open(os.path.join(ROOT, "oui_table.json")) as f:
                doc = json.load(f)
            for vendor, blob in (doc.get("vendors") or {}).items():
                for i in range(0, len(blob) - 5, 6):
                    t[blob[i:i + 6]] = vendor
            _modules = set(doc.get("modules") or [])
        except (OSError, ValueError):
            pass
        _table = t


def is_randomized(mac):
    """True for a locally administered address: phones and laptops use these as
    private Wi-Fi addresses, and no maker can be read from them."""
    m = normalize(mac)
    if not m:
        return False
    return bool(int(m[:2], 16) & 0x02)


def vendor(mac):
    """Maker of the network chip, or None (randomised address, or not in the table)."""
    m = normalize(mac)
    if not m or is_randomized(m):
        return None
    _load()
    return _table.get(m.replace(":", "")[:6])


def is_module_maker(vendor_name):
    """True when the vendor makes radios that go inside other brands' products."""
    _load()
    return vendor_name in _modules


def peripheral_vendor(vendor_id):
    """'0x046D' or '0x004C (Apple)' -> 'Logitech'. None when not in the small table."""
    m = re.match(r"\s*(0x[0-9A-Fa-f]{1,4})", str(vendor_id or ""))
    if not m:
        return None
    return PERIPHERAL_VENDORS.get(int(m.group(1), 16))
