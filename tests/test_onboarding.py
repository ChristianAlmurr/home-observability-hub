"""Onboarding tests: discover.py's parsers and diff, bin/inventory_check.py, bin/hoh's plist, install.sh.

Offline: nothing here sends a packet, touches launchd or reads the real home folder. install.sh runs
in a throwaway HOME against a copy of the repository.
"""
import copy
import importlib.machinery
import importlib.util
import json
import os
import plistlib
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "bin"))

import discover as D  # noqa: E402
import inventory_check as IC  # noqa: E402
import ipaddress  # noqa: E402

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "inventory.json")


def load_hoh():
    loader = importlib.machinery.SourceFileLoader("hoh_cli", os.path.join(ROOT, "bin", "hoh"))
    spec = importlib.util.spec_from_loader("hoh_cli", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def fixture():
    with open(FIXTURE) as f:
        return json.load(f)


FIXTURE_NETS = [ipaddress.ip_network(n) for n in ("10.20.0.0/24", "127.0.0.1/32", "100.64.0.0/10", "192.168.100.1/32")]


# ================================================================ discover: parsers

class ArpTest(unittest.TestCase):
    def test_normal(self):
        text = ("? (192.168.1.1) at a4:2b:b0:a:b:c on en0 ifscope [ethernet]\n"
                "? (192.168.1.20) at (incomplete) on en0 ifscope [ethernet]\n"
                "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
                "? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n"
                "? (192.168.1.33) at 76:e2:36:69:4a:d3 on en0 ifscope [ethernet]\n")
        r = D.parse_arp(text)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["entries"]["192.168.1.1"]["mac"], "A4:2B:B0:0A:0B:0C")
        self.assertNotIn("192.168.1.20", r["entries"])
        self.assertNotIn("192.168.1.255", r["entries"])
        self.assertNotIn("224.0.0.251", r["entries"])
        self.assertEqual(r["incomplete"], 1)
        self.assertEqual(r["withMac"], 2)

    def test_empty(self):
        for text in ("", "\n", "arp: no entries\n"):
            r = D.parse_arp(text)
            self.assertEqual(r["status"], "empty")
            self.assertEqual(r["entries"], {})
        self.assertIn("printed nothing", D.ARP_NOTES["empty"])

    def test_redacted(self):
        text = ("? (192.168.1.1) at <redacted> on en0 ifscope [ethernet]\n"
                "? (192.168.1.7) at (redacted) on en0 ifscope [ethernet]\n")
        r = D.parse_arp(text)
        self.assertEqual(r["status"], "redacted")
        self.assertEqual(r["redacted"], 2)
        self.assertIsNone(r["entries"]["192.168.1.1"]["mac"])

    def test_partial(self):
        r = D.parse_arp("? (10.0.0.1) at 0:11:22:33:44:55 on en0 [ethernet]\n? (10.0.0.2) at hidden on en0 [ethernet]\n")
        self.assertEqual(r["status"], "partial")

    def test_norm_mac(self):
        self.assertEqual(D.norm_mac("0:1:2:a:bb:c"), "00:01:02:0A:BB:0C")
        self.assertEqual(D.norm_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")
        self.assertIsNone(D.norm_mac("(incomplete)"))
        self.assertIsNone(D.norm_mac(None))


class SsdpTest(unittest.TestCase):
    RESP = (b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.4:80/description.xml\r\n"
            b"SERVER: Linux/3.14.0 UPnP/1.0 IpBridge/1.65.0\r\nST: upnp:rootdevice\r\n"
            b"USN: uuid:2f402f80-da50-11e1-9b23-001788000000::upnp:rootdevice\r\n\r\n")
    DESC = ("<?xml version=\"1.0\"?><root><device><deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>"
            "<friendlyName>Hue Bridge (192.168.1.4)</friendlyName><manufacturer>Signify</manufacturer>"
            "<modelName>Philips hue bridge 2015</modelName><modelNumber>BSB002</modelNumber></device></root>")

    def test_response(self):
        r = D.parse_ssdp_response(self.RESP)
        self.assertEqual(r["location"], "http://192.168.1.4:80/description.xml")
        self.assertEqual(r["st"], "upnp:rootdevice")
        self.assertIn("IpBridge", r["server"])

    def test_not_ssdp(self):
        self.assertIsNone(D.parse_ssdp_response(b"garbage"))
        self.assertIsNone(D.parse_ssdp_response(b"HTTP/1.1 404 Not Found\r\n\r\n"))

    def test_location_only_same_host(self):
        self.assertTrue(D.location_ok("http://192.168.1.4:80/description.xml", "192.168.1.4"))
        self.assertFalse(D.location_ok("http://192.168.1.5/description.xml", "192.168.1.4"))
        self.assertFalse(D.location_ok("https://192.168.1.4/x", "192.168.1.4"))
        self.assertFalse(D.location_ok("http://evil.example/x", "192.168.1.4"))

    def test_description(self):
        d = D.parse_device_description(self.DESC)
        self.assertEqual(d["manufacturer"], "Signify")
        self.assertEqual(d["modelNumber"], "BSB002")
        self.assertNotIn("igd", d)
        self.assertTrue(D.parse_device_description("<deviceType>urn:InternetGatewayDevice:1</deviceType>")["igd"])


def _name(n):
    out = b""
    for lab in n.split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"


def _rr(name, typ, rdata):
    return _name(name) + struct.pack("!HHIH", typ, 1, 120, len(rdata)) + rdata


class MdnsTest(unittest.TestCase):
    def test_dnssd_lines(self):
        text = ("Browsing for _googlecast._tcp.local.\nDATE: ---Sat 21 Nov 2026---\n"
                "18:54:07.123  ...STARTING...\n"
                "Timestamp     A/R    Flags  if Domain               Service Type         Instance Name\n"
                "18:54:07.456  Add        3  14 local.               _googlecast._tcp.    Living Room speaker\n"
                "18:54:07.456  Add        2  14 local.               _googlecast._tcp.    Kitchen display-abc123\n"
                "18:54:07.500  Rmv        0  14 local.               _googlecast._tcp.    Gone one\n"
                "18:54:07.600  Add        2  14 local.               _googlecast._tcp.    Living Room speaker\n")
        rows = D.parse_dnssd_browse(text)
        self.assertEqual(rows, [{"type": "_googlecast._tcp", "instance": "Living Room speaker"},
                                {"type": "_googlecast._tcp", "instance": "Kitchen display-abc123"}])

    def test_packet_and_assemble(self):
        inst = "Kitchen._googlecast._tcp.local"
        srv = struct.pack("!HHH", 0, 0, 8009) + _name("kitchen-1.local")
        txt = bytes([len(b"md=Google Nest Mini")]) + b"md=Google Nest Mini"
        body = (_rr("_googlecast._tcp.local", 12, _name(inst)) + _rr(inst, 33, srv) + _rr(inst, 16, txt)
                + _rr("kitchen-1.local", 1, socket.inet_aton("192.168.1.30"))
                + _rr("stranger.local", 1, socket.inet_aton("10.9.9.9")))
        pkt = struct.pack("!6H", 0, 0x8400, 0, 5, 0, 0) + body
        recs = D.parse_dns(pkt)
        types = [t for _, t, _ in recs]
        self.assertEqual(types, ["PTR", "SRV", "TXT", "A", "A"])
        out = D.assemble_mdns([("192.168.1.30",) + r for r in recs], ipaddress.ip_network("192.168.1.0/24"))
        self.assertEqual(list(out), ["192.168.1.30"])          # 10.9.9.9 is outside the net
        e = out["192.168.1.30"]
        self.assertEqual(e["hostnames"], ["kitchen-1"])
        self.assertEqual(e["services"][0]["instance"], "Kitchen")
        self.assertEqual(e["services"][0]["port"], 8009)
        self.assertEqual(e["services"][0]["txt"]["md"], "Google Nest Mini")

    def test_parse_dns_never_raises(self):
        for junk in (b"", b"\x00" * 5, b"\xff" * 40, os.urandom(64)):
            self.assertIsInstance(D.parse_dns(junk), list)

    def test_query(self):
        q = D.dns_query([("_hap._tcp.local", 12)], unicast=True)
        self.assertEqual(struct.unpack("!6H", q[:12])[2], 1)
        self.assertTrue(q.endswith(struct.pack("!2H", 12, 0x8001)))


# ================================================================ discover: router fingerprint, leads

def page(port=80, status=200, title=None, server=None, location=None, realm=None, body="", path="/"):
    h = {}
    if server:
        h["server"] = server
    if location:
        h["location"] = location
    if realm:
        h["www-authenticate"] = 'Basic realm="%s"' % realm
    b = body or ("<html><head><title>%s</title></head></html>" % title if title else "")
    return {"port": port, "status": status, "headers": h, "body": b, "path": path}


class RouterTest(unittest.TestCase):
    def test_asus_login_page(self):
        fp = D.router_fingerprint([page(status=302, server="httpd/3.0", location="/Main_Login.asp"),
                                   page(title="ASUS Login", server="httpd/3.0", path="/Main_Login.asp")])
        self.assertEqual(fp["family"], "asuswrt")
        self.assertEqual(fp["routerType"], "asuswrt")
        self.assertEqual(fp["confidence"], "high")
        self.assertIsNone(fp["model"])                  # a title is not a model claim
        self.assertTrue(all(b["source"] for b in fp["basis"]))

    def test_asus_by_name_and_ssdp_model(self):
        fp = D.router_fingerprint([page(server="httpd/3.0", body="<script>location='/Main_Login.asp'</script>")],
                                  ssdp={"description": {"manufacturer": "ASUSTeK Computer Inc.", "modelName": "ZenWiFi XT8"}},
                                  names=[{"value": "ZenWiFi_XT8-7E50", "source": "mDNS A record"}])
        self.assertEqual(fp["family"], "asuswrt")
        self.assertEqual(fp["model"]["value"], "ZenWiFi XT8")
        self.assertEqual(fp["model"]["source"], "SSDP device description")

    def test_others(self):
        cases = [([page(title="FRITZ!Box")], "fritzbox"),
                 ([page(status=302, location="/manage"), page(title="UniFi OS", path="/manage")], "unifi"),
                 ([page(status=401, realm="NETGEAR R7000")], "netgear"),
                 ([page(title="Orbi")], "orbi"),
                 ([page(title="Opening...", server="TP-LINK HTTPD/1.0")], "tplink"),
                 ([page(title="Linksys Smart Wi-Fi")], "linksys"),
                 ([page(title="RouterOS router configuration page")], "mikrotik"),
                 ([page(title="OpenWrt - LuCI")], "openwrt"),
                 ([page(title="CableCo Connect Box")], "isp")]
        for pages, fam in cases:
            fp = D.router_fingerprint(pages)
            self.assertEqual(fp["family"], fam, pages)
            self.assertEqual(fp["routerType"], "none", fam)
        self.assertEqual(D.router_fingerprint([], mac_vendor="eero inc.")["family"], "eero")
        self.assertEqual(D.router_fingerprint([], mac_vendor="eero inc.")["confidence"], "low")

    def test_unknown(self):
        fp = D.router_fingerprint([page(title="Login", server="lighttpd")])
        self.assertEqual(fp["family"], "unknown")
        self.assertEqual(fp["confidence"], "none")
        self.assertEqual(D.router_fingerprint([{"port": 80, "status": None, "headers": {}, "body": ""}])["http"], [])


class LeadsTest(unittest.TestCase):
    def test_claims_and_candidates(self):
        h = {"ip": "192.168.1.30", "names": [{"value": "Google-Home-Mini", "source": "rdns"}], "ports": [8009],
             "mdns": {"services": [{"type": "_googlecast._tcp", "instance": "Kitchen", "txt": {"md": "Google Nest Mini"}},
                                   {"type": "_googlecast._tcp", "instance": "Group", "txt": {"md": "Google Cast Group"}}]},
             "ssdp": {"description": {"manufacturer": "Google Inc.", "modelName": "Eureka Dongle"}},
             "mac": "D8:EB:46:00:00:01", "macVendor": "Google, Inc.", "randomizedMac": False}
        hh = [(r"^google-home", "Google", "speaker", "a Google Home or Nest device")]
        ph = {8009: ("Google", None, "it answers on the Google Cast port")}
        leads = D.leads_for(h, hh, ph)
        claims = [l for l in leads if l["kind"] == "claim"]
        self.assertEqual({l["source"] for l in claims}, {"SSDP device description", "mDNS TXT md="})
        self.assertFalse(any("Cast Group" in l["text"] for l in leads))
        cands = {l["source"] for l in leads if l["kind"] == "candidate"}
        self.assertTrue({"hostname", "TCP connect", "MAC prefix (IEEE table)", "mDNS _googlecast._tcp"} <= cands)

    def test_randomized(self):
        leads = D.leads_for({"ip": "x", "names": [], "randomizedMac": True}, [], {})
        self.assertEqual(leads[0]["source"], "MAC address bit")
        self.assertEqual(leads[0]["kind"], "candidate")


# ================================================================ discover: diff

def H(ip, mac=None, names=(), ports=(), rnd=False, **kw):
    h = {"ip": ip, "mac": mac, "randomizedMac": rnd, "names": [{"value": n, "source": "mDNS"} for n in names],
         "ports": list(ports), "sources": ["ping"]}
    h.update(kw)
    return h


class DiffTest(unittest.TestCase):
    def doc(self, hosts, ts="t", ports_ok=True):
        return {"ts": ts, "hosts": hosts, "probes": {"ports": {"ok": ports_ok}}}

    def test_new_gone_changed(self):
        prev = self.doc([H("192.168.1.2", "00:11:22:33:44:55", ["nas"], [445]), H("192.168.1.3", None, ["printer"]),
                         H("192.168.1.9", None, ["old"])], ts="before")
        cur = self.doc([H("192.168.1.12", "00:11:22:33:44:55", ["nas"], [445, 80]), H("192.168.1.3", None, ["printer-2"]),
                        H("192.168.1.50", None, ["newcomer"])])
        d = D.diff(prev, cur)
        self.assertEqual(d["previousTs"], "before")
        self.assertEqual([h["ip"] for h in d["new"]], ["192.168.1.50"])
        self.assertEqual([h["ip"] for h in d["gone"]], ["192.168.1.9"])
        ch = {c["ip"]: {x["field"] for x in c["changes"]} for c in d["changed"]}
        self.assertEqual(ch["192.168.1.12"], {"ip", "ports"})     # same MAC, moved address
        self.assertEqual(ch["192.168.1.3"], {"names"})
        self.assertEqual(d["notSeen"], [])

    def test_first_scan_has_no_new(self):
        d = D.diff(None, self.doc([H("192.168.1.2")]))
        self.assertEqual(d["new"], [])
        self.assertIsNone(d["previousTs"])

    def test_ports_ignored_when_a_scan_skipped_them(self):
        prev = self.doc([H("192.168.1.2", ports=[80])])
        cur = self.doc([H("192.168.1.2", ports=[])], ports_ok=False)
        self.assertEqual(D.diff(prev, cur)["changed"], [])

    def test_inventory(self):
        inv = {"devices": [
            {"id": "nas", "net": [{"ip": "192.168.1.2", "mac": "00:11:22:33:44:55"}]},
            {"id": "tv", "probe": {"type": "cast", "ip": "192.168.1.7"}},
            {"id": "laptop", "probe": {"type": "mdns", "name": "Alexs-MacBook"}, "net": [{"ip": "192.168.1.40"}]},
            {"id": "keyboard", "net": [{"medium": "bluetooth", "mac": "AA:AA:AA:AA:AA:AA"}]},
            {"id": "mini", "probe": {"type": "self"}, "net": [{"ip": "192.168.1.5"}]},
        ]}
        site = {"handsOff": [{"id": "work", "ips": ["192.168.1.77"]}]}
        cur = self.doc([H("192.168.1.22", "00:11:22:33:44:55"), H("192.168.1.41", None, ["alexs-macbook.local"]),
                        H("192.168.1.77"), H("192.168.1.99"), H("192.168.1.5", self=True)])
        d = D.diff(None, cur, inv, site)
        self.assertEqual([h["ip"] for h in d["unexplained"]], ["192.168.1.99"])
        self.assertEqual([x["id"] for x in d["notSeen"]], ["tv"])      # keyboard is Bluetooth, mini is this Mac
        idx = D.inventory_index(inv, site)
        self.assertEqual(D.match_host(H("192.168.1.22", "00:11:22:33:44:55"), idx), ("nas", "mac"))
        self.assertEqual(D.match_host(H("192.168.1.41", None, ["Alexs-MacBook"]), idx), ("laptop", "name"))
        self.assertEqual(D.match_host(H("192.168.1.77"), idx), ("work", "ip"))

    def test_fixture_matches_itself(self):
        inv = fixture()
        hosts = []
        for d in inv["devices"]:
            for n in d.get("net") or []:
                if n.get("ip") and n.get("medium") != "bluetooth":
                    hosts.append(H(n["ip"], n.get("mac"), rnd=bool(n.get("randomizedMac"))))
        d = D.diff(None, self.doc(hosts), inv, {})
        self.assertEqual(d["unexplained"], [])


class DiscoverSafetyTest(unittest.TestCase):
    def test_refuses_big_subnet(self):
        with self.assertRaises(SystemExit) as cm:
            D.discover(subnet="10.0.0.0/16", ports=False, quick=True)
        self.assertIn("--force", str(cm.exception))

    def test_ifconfig_and_ports(self):
        t = ("en8: flags=8863<UP> mtu 1500\n\tether ec:1a:c3:f:1e:fd\n\tinet 192.168.1.140 netmask 0xffffff00 broadcast "
             "192.168.1.255\n\tmedia: autoselect (2500Base-T <full-duplex>)\n\tstatus: active\n")
        i = D.parse_ifconfig(t)
        self.assertEqual((i["ipv4"], i["prefix"], i["mac"], i["status"]), ("192.168.1.140", 24, "EC:1A:C3:0F:1E:FD", "active"))
        self.assertEqual(D.speed_label(i["speedRaw"]), "2.5G")
        hp = D.parse_hardware_ports("Hardware Port: Wi-Fi\nDevice: en1\nEthernet Address: 3c:a6:f6:00:00:01\n\n"
                                    "Hardware Port: USB 10/100/1000 LAN\nDevice: en8\nEthernet Address: ec:1a:c3:0f:1e:fd\n")
        self.assertEqual([(h["device"], D.medium_of(h["port"])) for h in hp], [("en1", "wifi"), ("en8", "ethernet")])
        self.assertEqual(D.parse_ssid("Current Wi-Fi Network: HomeNet\n", ""), ("HomeNet", "networksetup -getairportnetwork"))
        self.assertEqual(D.parse_ssid("You are not associated with an AirPort network.\n", "  SSID : <redacted>\n"), (None, None))
        self.assertEqual(D.parse_ssid("", "  SSID : Flat 2\n"), ("Flat 2", "ipconfig getsummary"))


# ================================================================ inventory_check

class InventoryCheckTest(unittest.TestCase):
    def errors(self, inv, nets=FIXTURE_NETS, site=None):
        return [e["text"] for e in IC.check(inv, nets, site).errors]

    def test_fixture_is_clean(self):
        r = IC.check(fixture(), FIXTURE_NETS, {})
        self.assertEqual(r.errors, [])

    def test_broken(self):
        base = fixture()

        def broken(fn):
            inv = copy.deepcopy(base)
            fn(inv)
            return " | ".join(self.errors(inv))
        self.assertIn("used twice", broken(lambda i: i["devices"].append(dict(i["devices"][0]))))
        self.assertIn("not slug-like", broken(lambda i: i["devices"][0].update(id="Mac Mini")))
        self.assertIn("`verified` must be", broken(lambda i: i["devices"][1].update(verified="maybe")))
        self.assertIn("not in `zones`", broken(lambda i: i["devices"][1].update(zone="attic")))
        self.assertIn("not in `rooms`", broken(lambda i: i["zones"][0].update(room="cellar")))
        self.assertIn("probe type 'teleport'", broken(lambda i: i["devices"][1].update(probe={"type": "teleport"})))
        self.assertIn("needs `ip`", broken(lambda i: i["devices"][1].update(probe={"type": "ping"})))
        self.assertIn("outside the allowed nets", broken(lambda i: i["devices"][1]["net"][0].update(ip="8.8.8.8")))
        self.assertIn("outside the allowed nets", broken(lambda i: i["devices"][1].update(probe={"type": "ping", "ip": "10.1.1.1"})))
        self.assertIn("not an IP address", broken(lambda i: i["devices"][1]["net"][0].update(ip="300.1.1.1")))
        self.assertIn("does not exist", broken(lambda i: i["links"][0].update(to="ghost:p1")))
        self.assertIn("not in that device's `ports`", broken(lambda i: i["links"][0].update(to="monitor-g70b:nope")))
        self.assertIn("never describe Wi-Fi", broken(lambda i: i["links"][0].update(cable="wifi")))
        self.assertIn("link id", broken(lambda i: i["links"].append(dict(i["links"][0]))))
        self.assertIn("refers to device", broken(lambda i: i["openQuestions"][0].update(devices=["ghost"])))
        self.assertIn("no `basis`", broken(lambda i: i["devices"][1].update(identity={"state": "confirmed", "model": "X"})))
        self.assertIn("lower-case hex", broken(lambda i: i["devices"][3].update(probe={"type": "usb", "vendorId": "05E3",
                                                                                   "productId": "0x0610"})))

    def test_site_refs(self):
        errs = self.errors(fixture(), site={"router": {"deviceId": "no-such-router"}})
        self.assertTrue(any("router.deviceId" in e or "no-such-router" in e for e in errs))

    def test_cli(self):
        d = tempfile.mkdtemp()
        try:
            site = os.path.join(d, "site.json")
            with open(site, "w") as f:
                json.dump({"network": {"subnet": "10.20.0.0/24", "gateway": "10.20.0.1",
                                       "extraNets": ["192.168.100.1/32"]}}, f)
            env = dict(os.environ, HM_SITE=site)
            cmd = [sys.executable, os.path.join(ROOT, "bin", "inventory_check.py")]
            p = subprocess.run(cmd + [FIXTURE, "--json"], env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertTrue(json.loads(p.stdout)["ok"])
            bad = os.path.join(d, "bad.json")
            inv = fixture()
            inv["links"][0]["to"] = "ghost"
            with open(bad, "w") as f:
                json.dump(inv, f)
            p = subprocess.run(cmd + [bad], env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 1)
            self.assertIn("ghost", p.stdout)
            with open(bad, "w") as f:
                f.write("{not json")
            p = subprocess.run(cmd + [bad], env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 1)
            p = subprocess.run(cmd + [os.path.join(d, "missing.json")], env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 2)
        finally:
            shutil.rmtree(d)


# ================================================================ bin/hoh

class HohTest(unittest.TestCase):
    def test_render_plist(self):
        hoh = load_hoh()
        with open(os.path.join(ROOT, "deploy", "launchd.plist.template")) as f:
            tpl = f.read()
        text = hoh.render_plist(tpl, "com.home-observability-hub.test", "/Users/x/My Hub & Co", "/usr/bin/python3",
                                "/Users/x/My Hub & Co/data/state", "/Users/x", 8851,
                                env={"HM_STATE_DIR": "/tmp/s<1>", "HM_SENTINEL": "0"})
        d = plistlib.loads(text.encode())
        self.assertEqual(d["Label"], "com.home-observability-hub.test")
        self.assertEqual(d["ProgramArguments"], ["/usr/bin/python3", "/Users/x/My Hub & Co/server.py"])
        self.assertEqual(d["WorkingDirectory"], "/Users/x/My Hub & Co")
        self.assertEqual(d["StandardErrorPath"], "/Users/x/My Hub & Co/data/state/server.err")
        env = d["EnvironmentVariables"]
        self.assertEqual(env["HM_PORT"], "8851")
        self.assertEqual(env["HM_STATE_DIR"], "/tmp/s<1>")
        self.assertEqual(env["HM_SENTINEL"], "0")
        for p in ("/opt/homebrew/bin", "/Users/x/.local/bin", "/usr/bin"):
            self.assertIn(p, env["PATH"].split(":"))
        self.assertTrue(d["KeepAlive"] and d["RunAtLoad"])
        with self.assertRaises(ValueError):
            hoh.render_plist(tpl + "{{NOPE}}", "l", "/r", "/p", "/s", "/h", 1)

    def test_label_and_env(self):
        hoh = load_hoh()
        old = dict(os.environ)
        try:
            os.environ["HOH_LABEL"] = "com.home-observability-hub.test"
            os.environ["HOH_LAUNCH_AGENTS"] = "/tmp/la"
            os.environ["HM_FOO"] = "1"
            os.environ["HM_PORT"] = "8852"
            self.assertEqual(hoh.plist_path(), "/tmp/la/com.home-observability-hub.test.plist")
            self.assertEqual(hoh.port(), 8852)
            env = hoh.service_env()
            self.assertEqual(env.get("HM_FOO"), "1")
            self.assertNotIn("HM_PORT", env)
            self.assertNotIn("HOH_LABEL", env)
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_cli_help_and_version(self):
        p = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "hoh"), "version"], capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0)
        self.assertIn("home-observability-hub", p.stdout)
        p = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "hoh"), "nonsense"], capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 2)

    def test_ha_set_token_from_stdin(self):
        d = tempfile.mkdtemp()
        try:
            conf = os.path.join(d, "conf")
            site = os.path.join(d, "site.json")
            with open(site, "w") as f:
                json.dump({"homeAssistant": {"url": "http://127.0.0.1:9", "tokenFile": os.path.join(conf, "ha-token")}}, f)
            env = dict(os.environ, HOH_CONFIG_DIR=conf, HM_SITE=site)
            tok = "abc.DEF-123_" * 4
            p = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "hoh"), "ha", "set-token"], input=tok + "\n",
                               env=env, capture_output=True, text=True, timeout=30)
            self.assertNotIn(tok, p.stdout + p.stderr)          # never echoed
            tf = os.path.join(conf, "ha-token")
            self.assertEqual(stat.S_IMODE(os.stat(tf).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(conf).st_mode), 0o700)
            with open(tf) as f:
                self.assertEqual(f.read().strip(), tok)
            p = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "hoh"), "ha", "set-token"], input="short\n",
                               env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 1)
        finally:
            shutil.rmtree(d)


# ================================================================ install.sh / uninstall.sh

@unittest.skipUnless(sys.platform == "darwin", "install.sh is for macOS")
class InstallTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.copy = os.path.join(self.tmp, "hub")
        shutil.copytree(ROOT, self.copy, ignore=shutil.ignore_patterns(".git", "data", "__pycache__", "node_modules", "*.pyc"))
        self.env = {"HOME": self.home, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOH_LABEL": "com.home-observability-hub.test-none",
                    "HOH_LAUNCH_AGENTS": os.path.join(self.tmp, "LaunchAgents")}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sh(self, *args, stdin=""):
        return subprocess.run(["/bin/sh"] + list(args), env=self.env, capture_output=True, text=True, timeout=120,
                              input=stdin, cwd=self.tmp)

    def test_install_twice_then_uninstall(self):
        for _ in range(2):          # idempotent
            p = self.sh(os.path.join(self.copy, "install.sh"), "--dir", self.copy, "--no-test", "--global")
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        out = p.stdout
        self.assertIn("/setup", out)
        self.assertIn('cd "%s" && claude' % self.copy, out)
        conf = os.path.join(self.home, ".config", "home-observability-hub")
        self.assertEqual(stat.S_IMODE(os.stat(conf).st_mode), 0o700)
        self.assertTrue(os.path.isdir(os.path.join(self.copy, "data", "state")))
        self.assertTrue(os.access(os.path.join(self.copy, "bin", "hoh"), os.X_OK))
        self.assertFalse(os.path.exists(self.env["HOH_LAUNCH_AGENTS"]))      # no service installed
        self.assertFalse(os.path.exists(os.path.join(self.copy, "data", "state", "discovery.json")))  # no scan
        skills = os.path.join(self.home, ".claude", "skills")
        linked = sorted(os.listdir(skills))
        self.assertIn("home-onboarding", linked)
        self.assertEqual(os.readlink(os.path.join(skills, "home-onboarding")),
                         os.path.join(self.copy, ".claude", "skills", "home-onboarding"))
        with open(os.path.join(conf, "global-skills.txt")) as f:
            self.assertEqual(len(f.read().split()), len(linked))      # the second run added no duplicates

        with open(os.path.join(self.copy, "data", "site.json"), "w") as f:
            f.write("{}")
        p = self.sh(os.path.join(self.copy, "uninstall.sh"), "--yes")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(os.listdir(skills), [])
        self.assertFalse(os.path.exists(conf))
        self.assertFalse(os.path.exists(os.path.join(self.copy, "data", "site.json")))
        self.assertTrue(os.path.exists(os.path.join(self.copy, "server.py")))        # code stays

    def test_default_dir_is_the_clone(self):
        p = self.sh(os.path.join(self.copy, "install.sh"), "--no-test")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("hub at %s" % self.copy, p.stdout)

    def test_refuses_foreign_dir(self):
        other = os.path.join(self.tmp, "other")
        os.makedirs(other)
        with open(os.path.join(other, "x"), "w") as f:
            f.write("x")
        p = self.sh(os.path.join(self.copy, "install.sh"), "--dir", other, "--no-test")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("not the hub", p.stdout + p.stderr)

    def test_bad_option(self):
        p = self.sh(os.path.join(self.copy, "install.sh"), "--bogus")
        self.assertNotEqual(p.returncode, 0)


# ================================================================ .claude assets

def frontmatter(path):
    with open(path) as f:
        text = f.read()
    if not text.startswith("---\n"):
        return None, text
    head, _, body = text[4:].partition("\n---\n")
    meta = {}
    for line in head.splitlines():
        k, _, v = line.partition(":")
        if k.strip() and v.strip():
            meta[k.strip()] = v.strip()
    return meta, body


class ClaudeAssetsTest(unittest.TestCase):
    C = os.path.join(ROOT, ".claude")

    def test_settings(self):
        with open(os.path.join(self.C, "settings.json")) as f:
            s = json.load(f)
        allow, deny = s["permissions"]["allow"], s["permissions"]["deny"]
        self.assertIn("Bash(python3 bin/hoh *)", allow)
        self.assertIn("Read(~/.config/home-observability-hub/**)", deny)
        self.assertIn("Read(~/.ssh/**)", deny)
        self.assertNotIn("hooks", s)

    def test_skills(self):
        want = {"home-onboarding", "device-identification", "inventory-authoring", "wiring-mapping", "router-access"}
        have = set(os.listdir(os.path.join(self.C, "skills")))
        self.assertTrue(want <= have, want - have)
        for name in have:
            meta, body = frontmatter(os.path.join(self.C, "skills", name, "SKILL.md"))
            self.assertEqual(meta.get("name"), name)
            self.assertGreater(len(meta.get("description", "")), 60, name)
            self.assertGreater(len(body), 500, name)

    def test_agents_and_commands(self):
        for name in ("network-scout", "device-researcher", "layout-designer"):
            meta, _ = frontmatter(os.path.join(self.C, "agents", name + ".md"))
            self.assertEqual(meta.get("name"), name)
            self.assertTrue(meta.get("description") and meta.get("tools"), name)
        self.assertNotIn("Write", frontmatter(os.path.join(self.C, "agents", "network-scout.md"))[0]["tools"])
        for name in ("setup", "rescan", "doctor", "add-device", "wiring", "identify"):
            meta, body = frontmatter(os.path.join(self.C, "commands", name + ".md"))
            self.assertTrue(meta.get("description"), name)

    def test_commands_in_docs_exist(self):
        """Every `python3 bin/hoh <sub>` the assets mention is a real subcommand."""
        hoh = load_hoh()
        import re
        for dirpath, _, files in os.walk(self.C):
            for fn in files:
                if fn.endswith(".md"):
                    with open(os.path.join(dirpath, fn)) as f:
                        for sub in re.findall(r"python3 bin/hoh ([a-z-]+)", f.read()):
                            self.assertIn(sub, hoh.COMMANDS, "%s mentions hoh %s" % (fn, sub))

    def test_worked_example_passes_the_check(self):
        import re
        with open(os.path.join(self.C, "skills", "inventory-authoring", "SKILL.md")) as f:
            text = f.read()
        blocks = [json.loads(b) for b in re.findall(r"```json\n(.*?)\n```", text, re.S)]
        inv = [b for b in blocks if "devices" in b][0]
        nets = [ipaddress.ip_network(n) for n in ("192.168.1.0/24", "127.0.0.1/32")]
        r = IC.check(inv, nets, {"router": {"deviceId": "router"}, "host": {"deviceId": "imac"}})
        self.assertEqual(r.errors, [])
        self.assertEqual(r.warnings, [])


if __name__ == "__main__":
    unittest.main()
