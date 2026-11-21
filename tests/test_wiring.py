"""Live wiring: readings from computers laid over the inventory (wiring.py). No server, no real sockets."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ["HM_SITE"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "site.json")   # never the real house
import wiring  # noqa: E402

INV = {"devices": [
    {"id": "mac-mini", "name": "Mac mini", "kind": "computer", "zone": "desk", "probe": {"type": "self"},
     "portMap": {"usb-c-1": "tb-1", "usb-c-2": "tb-2"}, "ports": [{"id": "tb-1", "label": "Rear 1"}, {"id": "tb-2", "label": "Rear 2"}]},
    {"id": "laptop", "name": "Laptop", "kind": "computer", "zone": "desk", "probe": {"type": "ping"}, "ports": []},
    {"id": "kvm", "name": "KVM", "kind": "kvm", "probe": {"type": "usb", "vendorId": "0x05e3", "productId": "0x0610"}},
    {"id": "dock", "name": "Dock", "kind": "hub", "probe": {"type": "none"}},
    {"id": "screen", "name": "Screen", "kind": "display", "probe": {"type": "display", "match": "Odyssey"}},
    {"id": "deck", "name": "Deck", "kind": "peripheral", "probe": {"type": "usb", "vendorId": "0x0fd9", "productId": "0x009a"}},
], "links": [
    {"id": "l-mini-kvm", "from": "mac-mini:tb-1", "to": "kvm:pc1", "cable": "usb-c", "carries": ["video", "usb"]},
    {"id": "l-kvm-screen", "from": "kvm:out", "to": "screen:in", "cable": "hdmi", "carries": ["video"]},
    {"id": "l-kvm-deck", "from": "kvm:usb-1", "to": "deck:usb", "cable": "usb"},
    {"id": "l-laptop-dock", "from": "laptop:usbc-1", "to": "dock:host", "cable": "usb-c", "verified": "plan"},
    {"id": "l-dock-kvm", "from": "dock:hdmi", "to": "kvm:pc2-hdmi", "cable": "hdmi", "carries": ["video"], "verified": "plan"},
]}
HUB = [{"vendorId": "05e3", "productId": "0626", "name": "USB3.1 Hub", "hub": True}, {"vendorId": "05e3", "productId": "0610", "name": "USB2.1 Hub", "hub": True}]
MINI = {"ports": [{"type": "usb-c", "n": 2, "active": True, "usb": HUB, "display": {"name": "Odyssey G70B"}}],
        "usb": [{"vendorId": "05ac", "productId": "800b", "name": "USB2 Hub", "builtIn": True, "parent": None},
                {"vendorId": "05e3", "productId": "0610", "name": "USB2.1 Hub", "parent": None},
                {"vendorId": "0fd9", "productId": "009a", "name": "Deck", "parent": 1},
                {"vendorId": "05e3", "productId": "0626", "name": "USB3.1 Hub", "parent": None}]}


def fresh():
    return {"rev": 0, "hosts": {}, "learned": {}, "applied": {}}


def link(inv, lid):
    return next(l for l in inv["links"] if l["id"] == lid)


class Wiring(unittest.TestCase):
    def test_own_sockets_correct_the_port_and_invent_nothing(self):
        st = fresh()
        wiring.update_host(st, INV, "mac-mini", MINI, "local")
        out = wiring.apply(INV, st)
        self.assertEqual(link(out, "l-mini-kvm")["from"], "mac-mini:tb-2")
        self.assertTrue(link(out, "l-mini-kvm").get("corrected"))
        self.assertFalse(link(out, "l-mini-kvm").get("moved"))
        self.assertEqual(link(out, "l-kvm-deck")["from"], "kvm:usb-1")
        self.assertTrue(link(out, "l-kvm-screen")["observed"]["present"])
        self.assertEqual([d["id"] for d in out["devices"] if d.get("dynamic")], [])     # the hub's other half is the KVM
        self.assertEqual(INV["links"][0]["from"], "mac-mini:tb-1")                       # the inventory itself is untouched

    def test_peripheral_moved_to_the_computer(self):
        st = fresh()
        obs = {"ports": [{"type": "usb-c", "n": 1, "active": True, "usb": [{"vendorId": "0fd9", "productId": "009a", "name": "Deck"}]}],
               "usb": [{"vendorId": "0fd9", "productId": "009a", "name": "Deck", "parent": None}]}
        wiring.update_host(st, INV, "mac-mini", obs, "local")
        out = wiring.apply(INV, st)
        l = link(out, "l-kvm-deck")
        self.assertEqual(l["from"], "mac-mini:tb-1")
        self.assertTrue(l["moved"])
        self.assertEqual(l["declared"]["from"], "kvm:usb-1")
        ev = wiring.diff_events(INV, out, st)
        self.assertTrue(any(e[0] == "l-kvm-deck" and e[2] == "wiring-moved" for e in ev))
        self.assertEqual(wiring.diff_events(INV, wiring.apply(INV, st), st), [])         # said once

    def test_hdmi_straight_into_the_laptop_and_back(self):
        st = fresh()
        wiring.update_host(st, INV, "mac-mini", MINI, "local")
        direct = {"ports": [{"type": "hdmi", "n": 1, "active": True, "usb": [], "display": {"name": "Odyssey G70B"}}], "usb": []}
        wiring.update_host(st, INV, "laptop", direct, "report")
        out = wiring.apply(INV, st)
        l = link(out, "l-dock-kvm")
        self.assertEqual((l["from"], l["to"]), ("laptop:hdmi-1", "kvm:pc2-hdmi"))
        self.assertTrue(l["moved"])
        self.assertIn("hdmi-1", [p["id"] for p in next(d for d in out["devices"] if d["id"] == "laptop")["ports"]])
        self.assertEqual(link(out, "l-mini-kvm")["from"], "mac-mini:tb-2")               # the other computer's cable stays put
        via_dock = {"ports": [{"type": "usb-c", "n": 2, "active": True, "usb": [{"vendorId": "2109", "productId": "0817", "name": "USB3.0 Hub", "hub": True}],
                               "display": {"name": "Odyssey G70B"}}],
                    "usb": [{"vendorId": "2109", "productId": "0817", "name": "USB3.0 Hub", "parent": None}]}
        wiring.update_host(st, INV, "laptop", via_dock, "report")
        out = wiring.apply(INV, st)
        l = link(out, "l-dock-kvm")
        self.assertEqual(l["from"], "dock:hdmi")
        self.assertFalse(l.get("moved"))
        self.assertEqual(st["learned"]["dock"], [["2109", "0817"]])                      # the dock's USB id is remembered

    def test_unknown_usb_device_appears_and_goes(self):
        st = fresh()
        obs = {"ports": [{"type": "usb-c", "n": 1, "active": True, "usb": [{"vendorId": "1234", "productId": "abcd", "name": "Stick"}]}],
               "usb": [{"vendorId": "1234", "productId": "abcd", "name": "Stick", "vendor": "Acme", "parent": None}]}
        wiring.update_host(st, INV, "mac-mini", obs, "local")
        out = wiring.apply(INV, st)
        self.assertIn("usb-1234-abcd", [d["id"] for d in out["devices"]])
        self.assertEqual(link(out, "o-usb-1234-abcd")["from"], "mac-mini:tb-1")
        wiring.diff_events(INV, out, st)
        wiring.update_host(st, INV, "mac-mini", {"ports": [], "usb": []}, "local")
        out = wiring.apply(INV, st)
        self.assertNotIn("usb-1234-abcd", [d["id"] for d in out["devices"]])
        self.assertTrue(any(e[2] == "wiring-gone" for e in wiring.diff_events(INV, out, st)))

    def test_unplugged_inventory_device_keeps_its_last_place(self):
        st = fresh()
        wiring.update_host(st, INV, "mac-mini", MINI, "local")
        wiring.update_host(st, INV, "mac-mini", {"ports": [], "usb": []}, "local")
        out = wiring.apply(INV, st)
        self.assertEqual(link(out, "l-mini-kvm")["from"], "mac-mini:tb-2")
        self.assertFalse(link(out, "l-mini-kvm")["observed"]["present"])

    def test_report_is_cut_down(self):
        import reporters
        c = reporters.clean({"a" * 100: "x" * 500, "l": list(range(500)), "deep": {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}, "o": object()})
        self.assertTrue(all(len(k) <= 40 for k in c))
        self.assertEqual(len(c["l"]), 96)
        self.assertIsNone(c["o"])


if __name__ == "__main__":
    unittest.main()
