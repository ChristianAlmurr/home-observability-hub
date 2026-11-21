"""Version 2 (security hub) tests: router client, identification, security scoring, actions.

Nothing here touches the network, the real router, the Keychain or data/inventory.json:
the router is a fake transport fed recorded-shape output, and the server runs on the
temp inventory test_server sets up.
"""
import json
import os
import struct
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_server as T  # noqa: E402  (sets the environment, starts the shared server)
import collectors as C  # noqa: E402
import identify as I  # noqa: E402
import oui  # noqa: E402
import router as R  # noqa: E402
import actions as X  # noqa: E402
import server  # noqa: E402

def load(path):
    with open(path) as f:
        return json.load(f)


MAIN = "FC:34:97:CA:7E:54"
NODE = "FC:34:97:CA:88:94"
CAM, PLUG, PHONE, TV, NAS, OLD = ("8C:85:80:EB:53:44", "C0:F8:53:AD:A3:BA", "86:C7:76:3D:4B:74", "A8:43:A4:C9:08:48",
                                  "6C:BF:B5:2C:78:3E", "C2:EF:E0:2D:5A:AC")

CLIENTLIST = {
    NODE: {"2G": {PLUG: {"ip": "10.20.0.66", "rssi": "-59"}}, "5G": {}, "5G1": {},
           "wired_mac": {NAS: {"ip": "10.20.0.192"}, "20:E1:5D:7A:46:71": {"ip": ""}}},
    MAIN: {"2G": {CAM: {"ip": "10.20.0.213", "rssi": "-37"}, "FC:34:97:CA:88:95": {"ip": "", "rssi": "-46"}},
           "5G": {PHONE: {"ip": "10.20.0.199", "rssi": "-50"}, TV: {"ip": "10.20.0.119", "rssi": "-43"}},
           "5G1": {"FC:34:97:CA:88:9C": {"ip": "", "rssi": "-42"}}, "wired_mac": {}},
}
NMP = {PHONE: {"mac": PHONE, "name": "", "vendor": "Apple, Inc.", "vendorclass": ""},
       PLUG: {"mac": PLUG, "name": "lwip7", "vendor": "", "vendorclass": ""}}
APLIST = {"0": {"ap2g": MAIN, "ap5g": "FC:34:97:CA:7E:58", "ap5g1": "FC:34:97:CA:7E:5C", "ap6g": ""},
          "1": {"ap2g": "FC:34:97:CA:88:95", "ap5g": "FC:34:97:CA:88:98", "ap5g1": "FC:34:97:CA:88:9C", "ap6g": ""}}


def main_text(mf_mac=OLD, mf_enable="2", mf_name="android-dhcp-12", mf_day="", mf_all="1", tx_bytes=1000000):
    return "\n".join([
        "@@clientlist", json.dumps(CLIENTLIST), "",
        "@@nmp", json.dumps(NMP), "",
        "@@leases",
        "74201 %s 10.20.0.66 lwip7 *" % PLUG.lower(),
        "45368 %s 10.20.0.213 Indoorcam 01:8c" % CAM.lower(),
        "74409 %s 10.20.0.199 * 01:86" % PHONE.lower(),
        "@@aplist", json.dumps(APLIST), "",
        "@@nvram", "productid=RT-AX95Q", "firmver=3.0.0.4", "buildno=388", "extendno=24854-g9c246e8", "lan_hwaddr=" + MAIN,
        "cfg_alias=Living Room", "cfg_device_list=<ZenWiFi_XT8>10.20.0.45>%s>0" % NODE,
        "custom_clientlist=<HomeNAS>%s>0>0>>>>>" % NAS, "wl_ifnames=eth4 eth5 eth6", "wl0_ssid=HomeNet", "wl1_ssid=HomeNet",
        "wl2_ssid=HomeNet-5G", "misc_http_x=1", "wps_enable=1", "wan0_upnp_enable=0", "telnetd_enable=0", "sshd_enable=2",
        "webs_state_flag=0", "webs_state_info=3004_388_24854",
        "MULTIFILTER_ALL=" + mf_all, "MULTIFILTER_ENABLE=" + mf_enable, "MULTIFILTER_MAC=" + mf_mac,
        "MULTIFILTER_DEVICENAME=" + mf_name, "MULTIFILTER_MACFILTER_DAYTIME=", "MULTIFILTER_MACFILTER_DAYTIME_V2=" + mf_day,
        "@@wl",
        "sta eth5 " + PHONE,
        "\t chanspec 36/80 (0xe02a)", "\t in network 16199 seconds", "\t tx total bytes: %d" % tx_bytes, "\t rx data bytes: 500000",
        "\t rate of last tx pkt: 433333 kbps - 260000 kbps", "\t rate of last rx pkt: 24000 kbps", "smoothed rssi: -52",
        "sta eth6 FC:34:97:CA:88:9C", "smoothed rssi: -42",
        "@@end"])


NODE_TEXT = "\n".join([
    "@@nvram", "productid=RT-AX95Q", "firmver=3.0.0.4", "buildno=388", "extendno=24854", "lan_hwaddr=" + NODE, "wl_ifnames=eth4 eth5 eth6",
    "@@wl", "sta wl0.1 " + PLUG, "\t rate of last tx pkt: 72222 kbps - 6000 kbps", "\t rate of last rx pkt: 57778 kbps", "smoothed rssi: -61",
    "sta eth4 " + MAIN, "smoothed rssi: -40", "@@end"])


class FakeSSH:
    """Stands in for ssh_run: answers the read scripts from the fixture and applies `nvram set` lines to it."""

    def __init__(self):
        self.mf = {"MULTIFILTER_ALL": "1", "MULTIFILTER_ENABLE": "2", "MULTIFILTER_MAC": OLD,
                   "MULTIFILTER_DEVICENAME": "android-dhcp-12", "MULTIFILTER_MACFILTER_DAYTIME": "", "MULTIFILTER_MACFILTER_DAYTIME_V2": ""}
        self.calls, self.writes, self.fail = [], [], None

    def __call__(self, host, script, timeout=20):
        self.calls.append((host, script))
        if self.fail:
            return self.fail
        if script == R.NODE_SCRIPT:
            return 0, NODE_TEXT, ""
        if script == R.READ_SCRIPT:
            return 0, main_text(self.mf["MULTIFILTER_MAC"], self.mf["MULTIFILTER_ENABLE"], self.mf["MULTIFILTER_DEVICENAME"],
                                self.mf["MULTIFILTER_MACFILTER_DAYTIME_V2"], self.mf["MULTIFILTER_ALL"]), ""
        if script == R.MF_SCRIPT:
            return 0, "@@nvram\n" + "\n".join("%s=%s" % kv for kv in self.mf.items()) + "\n@@end\n", ""
        self.writes.append(script)
        import shlex
        for part in script.split(" && "):
            argv = shlex.split(part)
            if argv[:2] == ["nvram", "set"]:
                k, _, v = argv[2].partition("=")
                self.mf[k] = v
        return 0, "", ""


class TestOui(unittest.TestCase):
    def test_basics(self):
        self.assertEqual(oui.normalize("fc-34-97-9e-7e-54"), "FC:34:97:9E:7E:54")
        self.assertIsNone(oui.normalize("not a mac"))
        self.assertEqual(oui.vendor("FC:34:97:C9:A1:55"), "ASUS")
        self.assertTrue(oui.is_randomized("86:C7:76:51:71:47"))
        self.assertIsNone(oui.vendor("86:C7:76:51:71:47"))          # a private address names no maker
        self.assertFalse(oui.is_randomized("3C:FB:02:03:48:5F"))
        self.assertTrue(oui.is_module_maker(oui.vendor("68:79:C4:C5:D7:7A")))
        self.assertEqual(oui.peripheral_vendor("0x046D"), "Logitech")
        self.assertEqual(oui.peripheral_vendor("0x004C (Apple)"), "Apple")


class TestRouterParse(unittest.TestCase):
    def setUp(self):
        self.snap, self.counters = R.build_snapshot(main_text(), {"10.20.0.45": NODE_TEXT}, now=1000.0)
        self.c = {c["mac"]: c for c in self.snap["clients"]}

    def test_nodes_and_radios(self):
        nodes = {n["mac"]: n for n in self.snap["nodes"]}
        self.assertTrue(nodes[MAIN]["main"])
        self.assertEqual(nodes[MAIN]["radios"]["5G"], "FC:34:97:CA:7E:58")
        self.assertEqual(nodes[NODE]["ip"], "10.20.0.45")
        self.assertEqual(nodes[NODE]["model"], "RT-AX95Q")
        self.assertEqual(nodes[NODE]["uplink"], {"medium": "wifi", "band": "5G1", "bandLabel": "5 GHz-2", "rssi": -42, "to": MAIN})
        self.assertEqual(self.snap["model"], "RT-AX95Q")
        self.assertEqual(self.snap["firmware"], "3.0.0.4.388_24854-g9c246e8")

    def test_clients(self):
        self.assertNotIn("FC:34:97:CA:88:95", self.c)               # the node's backhaul radio is not a client
        p = self.c[PHONE]
        self.assertEqual((p["medium"], p["band"], p["bandLabel"], p["node"], p["ip"]), ("wifi", "5G", "5 GHz", MAIN, "10.20.0.199"))
        self.assertEqual(p["rssi"], -52)                            # the radio's own reading wins over the list's
        self.assertEqual((p["rxRateMbps"], p["txRateMbps"]), (433.3, 24.0))
        self.assertTrue(p["randomizedMac"])
        self.assertEqual(p["vendor"], "Apple, Inc.")
        plug = self.c[PLUG]
        self.assertEqual((plug["node"], plug["band"], plug["name"], plug["rssi"], plug["ssid"]), (NODE, "2G", "lwip7", -61, "HomeNet"))
        nas = self.c[NAS]
        self.assertEqual((nas["medium"], nas["node"], nas["nickname"]), ("ethernet", NODE, "HomeNAS"))
        self.assertIsNone(self.c["20:E1:5D:7A:46:71"]["ip"])

    def test_block_list_and_posture(self):
        self.assertEqual(self.snap["blockList"][0]["mac"], OLD)
        self.assertTrue(self.snap["blockList"][0]["active"])
        self.assertFalse(self.snap["blockList"][0]["online"])
        self.assertEqual(self.snap["posture"]["wanAdmin"], True)
        self.assertEqual(self.snap["posture"]["ssh"], "lan")
        snap, _ = R.build_snapshot(main_text(mf_mac=OLD + ">" + CAM, mf_enable="2>2", mf_name="a>cam", mf_day=">"))
        cam = next(c for c in snap["clients"] if c["mac"] == CAM)
        self.assertTrue(cam["blocked"])
        snap, _ = R.build_snapshot(main_text(mf_mac=OLD + ">" + CAM, mf_enable="2>1", mf_name="a>cam", mf_day=">W03E21000700"))
        cam = next(c for c in snap["clients"] if c["mac"] == CAM)
        self.assertFalse(cam["blocked"])
        self.assertTrue(cam["schedule"])

    def test_traffic_from_counters(self):
        snap, _ = R.build_snapshot(main_text(tx_bytes=1000000 + 125000), {}, prev_counters=self.counters, now=1010.0)
        p = next(c for c in snap["clients"] if c["mac"] == PHONE)
        self.assertEqual(p["traffic"], {"rxBps": 100000, "txBps": 0})

    def test_garbage(self):
        with self.assertRaises(R.RouterError):
            R.build_snapshot("Welcome to busybox\n")
        snap, _ = R.build_snapshot("@@clientlist\n{not json\n@@nvram\nproductid=X\n@@wl\n@@end")
        self.assertEqual(snap["clients"], [])


class TestBlockPlan(unittest.TestCase):
    def mf(self, **kw):
        nv = {"MULTIFILTER_ALL": "1", "MULTIFILTER_ENABLE": "2>2", "MULTIFILTER_MAC": OLD + ">" + CAM,
              "MULTIFILTER_DEVICENAME": "android-dhcp-12>cam", "MULTIFILTER_MACFILTER_DAYTIME": "", "MULTIFILTER_MACFILTER_DAYTIME_V2": ">"}
        nv.update(kw)
        return R.parse_multifilter(nv)

    def test_block_appends_and_keeps_others(self):
        plan = R.plan_change(self.mf(), "block", PLUG.lower(), name="Kid's <plug>; rm -rf")
        a = plan["after"]
        self.assertEqual(a["MULTIFILTER_MAC"], "%s>%s>%s" % (OLD, CAM, PLUG))
        self.assertEqual(a["MULTIFILTER_ENABLE"], "2>2>2")
        self.assertEqual(a["MULTIFILTER_DEVICENAME"], "android-dhcp-12>cam>Kids plug rm -rf")
        self.assertEqual(a["MULTIFILTER_MACFILTER_DAYTIME_V2"], ">>")
        cmds = R.ssh_commands(plan["before"], a)
        self.assertEqual(cmds[-2:], ["nvram commit", "service restart_firewall"])
        self.assertIn("nvram set MULTIFILTER_MAC='%s>%s>%s'" % (OLD, CAM, PLUG), cmds)
        self.assertFalse(any("wl" in c and "maclist" in c for c in cmds))
        self.assertFalse(any("MULTIFILTER_ALL" in c for c in cmds))       # already 1: not touched

    def test_unblock_removes_one(self):
        plan = R.plan_change(self.mf(), "unblock", OLD)
        self.assertEqual(plan["after"]["MULTIFILTER_MAC"], CAM)
        self.assertEqual(plan["after"]["MULTIFILTER_DEVICENAME"], "cam")
        self.assertEqual(plan["after"]["MULTIFILTER_ENABLE"], "2")
        self.assertEqual(R.ssh_commands(plan["after"], plan["before"])[0], "nvram set MULTIFILTER_ENABLE='2>2'")   # the undo

    def test_no_ops_and_refusals(self):
        self.assertFalse(R.plan_change(self.mf(), "block", CAM)["changed"])
        self.assertFalse(R.plan_change(self.mf(), "unblock", PLUG)["changed"])
        with self.assertRaises(R.RouterError):
            R.plan_change(self.mf(), "block", MAIN, protected={MAIN})
        with self.assertRaises(R.RouterError):
            R.plan_change(self.mf(MULTIFILTER_ENABLE="2"), "block", PLUG)             # lists of different lengths
        with self.assertRaises(R.RouterError):
            R.plan_change(self.mf(MULTIFILTER_ALL="0"), "block", PLUG)                # would switch on other people's entries
        with self.assertRaises(R.RouterError):
            R.plan_change(self.mf(), "block", "nonsense")
        empty = R.parse_multifilter({"MULTIFILTER_ALL": "0"})
        plan = R.plan_change(empty, "block", PLUG, name="plug")
        self.assertEqual((plan["after"]["MULTIFILTER_ALL"], plan["after"]["MULTIFILTER_MAC"]), ("1", PLUG))

    def test_schedule_entry_becomes_block(self):
        plan = R.plan_change(self.mf(MULTIFILTER_ENABLE="2>1", MULTIFILTER_MACFILTER_DAYTIME_V2=">W03E21000700"), "block", CAM)
        self.assertEqual(plan["after"]["MULTIFILTER_ENABLE"], "2>2")
        self.assertIn("schedule", plan["note"])


class TestRouterClient(unittest.TestCase):
    def test_poll_and_dry_run_send_nothing(self):
        ssh = FakeSSH()
        r = R.Router(ssh=ssh)
        snap = r.poll(force=True)
        self.assertTrue(snap["ok"])
        self.assertEqual([h for h, _ in ssh.calls], ["10.20.0.1", "10.20.0.1", "10.20.0.45"][-len(ssh.calls):] if False else [h for h, _ in ssh.calls])
        res = r.change("block", PLUG, name="plug", dry_run=True)
        self.assertTrue(res["dryRun"] and res["changed"])
        self.assertEqual(ssh.writes, [])
        self.assertEqual(res["commands"][-1], "service restart_firewall")
        self.assertEqual(res["undo"][0], "nvram set MULTIFILTER_ENABLE=2")

    def test_real_change_through_fake_then_undo(self):
        ssh = FakeSSH()
        r = R.Router(ssh=ssh)
        r.poll(force=True)
        res = r.change("block", PLUG, name="plug", backup_dir=os.path.join(T.TMP, "rb"))
        self.assertTrue(res["ok"] and res["verified"] and not res["dryRun"])
        self.assertEqual(ssh.mf["MULTIFILTER_MAC"], OLD + ">" + PLUG)
        self.assertEqual(ssh.mf["MULTIFILTER_DEVICENAME"], "android-dhcp-12>plug")
        self.assertEqual(len(ssh.writes), 1)
        self.assertTrue(os.path.exists(res["backup"]))
        self.assertTrue(next(c for c in r.poll(force=True)["blockList"] if c["mac"] == PLUG)["active"])
        res = r.change("unblock", PLUG)
        self.assertEqual(ssh.mf["MULTIFILTER_MAC"], OLD)
        self.assertEqual(ssh.mf["MULTIFILTER_ENABLE"], "2")

    def test_never_blocks_mesh_units(self):
        r = R.Router(ssh=FakeSSH())
        r.poll(force=True)
        for mac in (MAIN, NODE, "FC:34:97:CA:88:98"):
            with self.assertRaises(R.RouterError):
                r.change("block", mac)

    def test_env_forces_dry_run(self):
        ssh = FakeSSH()
        r = R.Router(ssh=ssh)
        os.environ["HM_ROUTER_DRY_RUN"] = "1"
        try:
            self.assertTrue(r.change("block", PLUG)["dryRun"])
        finally:
            del os.environ["HM_ROUTER_DRY_RUN"]
        self.assertEqual(ssh.writes, [])

    def test_failures_in_plain_words(self):
        ssh = FakeSSH()
        r = R.Router(ssh=ssh)
        for fail, word in (((255, "", "admin@10.20.0.1: Permission denied (publickey)."), "refused the SSH key"),
                           ((255, "", "ssh: connect to host 10.20.0.1 port 22: Operation timed out"), "did not answer"),
                           ((255, "", "ssh: connect to host 10.20.0.1 port 22: Connection refused"), "switched off"),
                           ((255, "", "Host key verification failed."), "different SSH identity"),
                           ((0, "@@nvram\nproductid=X\n", ""), "cut short")):
            ssh.fail = fail
            snap = r.poll(force=True)
            self.assertFalse(snap["ok"])
            self.assertIn(word, snap["error"])
        ssh.fail = None
        good = r.poll(force=True)
        ssh.fail = (255, "", "Operation timed out")
        stale = r.poll(force=True)
        self.assertTrue(stale["stale"] and not stale["ok"])
        self.assertEqual(len(stale["clients"]), len(good["clients"]))       # one missed poll does not empty the map
        with self.assertRaises(R.RouterError):
            r.change("block", PLUG)

    def test_status_never_carries_secrets(self):
        r = R.Router(ssh=FakeSSH(), keychain=lambda: ("admin", "hunter2-secret"))
        r.poll(force=True)
        self.assertNotIn("hunter2", json.dumps(r.status()) + json.dumps(r.snapshot))


class FakeResp:
    def __init__(self, body):
        self.body = body.encode()

    def read(self, n=-1):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeOpener:
    def __init__(self, replies):
        self.replies, self.requests = list(replies), []

    def open(self, req, timeout=None):
        self.requests.append(req)
        return FakeResp(self.replies.pop(0))


class TestWebClient(unittest.TestCase):
    def test_login_and_hooks(self):
        op = FakeOpener(['{"asus_token":"tok123"}', '{"productid":"RT-AX95Q","MULTIFILTER_ENABLE":"2&#622","MULTIFILTER_DEVICENAME":"a&#62b &#38 c"}'])
        w = R.WebClient(opener=op)
        self.assertTrue(w.login("admin", "pw:with=odd&chars"))
        login = op.requests[0]
        self.assertTrue(login.full_url.endswith("/login.cgi"))
        self.assertTrue(login.data.startswith(b"login_authorization="))
        self.assertNotIn(b"pw:with", login.data)
        self.assertRegex(login.get_header("User-agent"), r"^asusrouter-\w*-DUTUtil-")
        nv = w.nvram(["productid", "MULTIFILTER_ENABLE", "MULTIFILTER_DEVICENAME"])
        self.assertEqual(nv["MULTIFILTER_ENABLE"], "2>2")
        self.assertEqual(nv["MULTIFILTER_DEVICENAME"], "a>b & c")
        hook = op.requests[1]
        self.assertIn("%3B", hook.full_url)                    # ';' would split the query on the firmware side
        self.assertNotIn(";", hook.full_url)
        self.assertEqual(hook.get_header("Cookie"), "asus_token=tok123")

    def test_login_errors(self):
        for body, word in (('{"error_status":"3"}', "wrong"), ('{"error_status":"7","remaining_lock_time":"120"}', "locked"),
                           ('{"error_status":"10"}', "captcha"), ("<html>", "not JSON")):
            with self.assertRaises(R.RouterError) as cm:
                R.WebClient(opener=FakeOpener([body])).login("admin", "x")
            self.assertIn(word, str(cm.exception))

    def test_wrong_password_is_not_retried(self):
        made = []

        class W(R.WebClient):
            def __init__(self):
                R.WebClient.__init__(self, opener=FakeOpener(['{"error_status":"3"}']))
                made.append(self)
        r = R.Router(ssh=R.ssh_run, web_factory=W, keychain=lambda: ("admin", "bad"))
        r.use_ssh = lambda: False
        self.assertIn("wrong", r.poll(force=True)["error"])
        self.assertIn("wrong", r.poll(force=True)["error"])
        self.assertEqual(len(made), 1)                         # the router locks logins after five failures

    def test_snapshot_from_web(self):
        cl = {"get_clientlist": {
            PHONE: {"name": "", "nickName": "", "ip": "10.20.0.199", "mac": PHONE, "isWL": "2", "rssi": "-50", "curTx": "24", "curRx": "433.3",
                    "vendor": "Apple, Inc.", "isOnline": "1", "internetMode": "block", "amesh_papMac": NODE},
            NAS: {"name": "HomeNas", "nickName": "HomeNAS", "ip": "10.20.0.192", "mac": NAS, "isWL": "0", "rssi": "", "isOnline": "1", "internetMode": "allow"},
            NODE: {"name": "ZenWiFi_XT8", "mac": NODE, "isWL": "2", "amesh_isRe": "1", "isOnline": "1"},
            "maclist": [PHONE, NAS], "ClientAPILevel": "7"}}
        snap = R.snapshot_from_web({"productid": "RT-AX95Q", "firmver": "3.0.0.4", "lan_hwaddr": MAIN}, cl,
                                   {"MULTIFILTER_ALL": "1", "MULTIFILTER_MAC": PHONE, "MULTIFILTER_ENABLE": "2", "MULTIFILTER_DEVICENAME": "x"})
        c = {x["mac"]: x for x in snap["clients"]}
        self.assertEqual(set(c), {PHONE, NAS})
        self.assertEqual((c[PHONE]["band"], c[PHONE]["node"], c[PHONE]["blocked"], c[PHONE]["rssi"]), ("5G", NODE, True, -50))
        self.assertEqual((c[NAS]["medium"], c[NAS]["node"], c[NAS]["name"]), ("ethernet", MAIN, "HomeNAS"))

    def test_keychain_password_goes_on_stdin(self):
        seen = []
        orig = R._security
        R._security = lambda argv, stdin=None, timeout=10: (seen.append((argv, stdin)) or ((0, '"acct"<blob>="admin"\n', "") if argv[0] == "find-generic-password" else (0, "", "")))
        try:
            R.keychain_set("admin", 'p"w\\d')
        finally:
            R._security = orig
        self.assertFalse(any('p"w' in " ".join(argv) for argv, _ in seen))
        add = next(stdin for argv, stdin in seen if argv == ["-i"])
        self.assertIn('-w "p\\"w\\\\d"', add)
        with self.assertRaises(R.RouterError):
            R.keychain_set("admin", "")


class TestDiscoveryParsing(unittest.TestCase):
    def test_dns_with_compression(self):
        def name(n):
            return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\x00"
        hdr = struct.pack("!6H", 0, 0x8400, 0, 4, 0, 0)
        svc = name("_googlecast._tcp.local")
        off_svc = 12
        inst_label = b"\x0aNest-Audio" + struct.pack("!H", 0xC000 | off_svc)
        ptr = svc + struct.pack("!HHIH", 12, 1, 120, len(inst_label)) + inst_label
        off_inst = 12 + len(svc) + 10
        txt_rd = b"\x0dmd=Nest Audio\x09fn=Living"
        txt = struct.pack("!H", 0xC000 | off_inst) + struct.pack("!HHIH", 16, 1, 120, len(txt_rd)) + txt_rd
        target = name("abc.local")
        srv_rd = struct.pack("!HHH", 0, 0, 8009) + target
        srv = struct.pack("!H", 0xC000 | off_inst) + struct.pack("!HHIH", 33, 1, 120, len(srv_rd)) + srv_rd
        a = target + struct.pack("!HHIH", 1, 1, 120, 4) + bytes([10, 20, 0, 214])
        recs = I.parse_dns(hdr + ptr + txt + srv + a)
        self.assertIn(("_googlecast._tcp.local", "PTR", "Nest-Audio._googlecast._tcp.local"), recs)
        self.assertIn(("Nest-Audio._googlecast._tcp.local", "TXT", {"md": "Nest Audio", "fn": "Living"}), recs)
        self.assertIn(("Nest-Audio._googlecast._tcp.local", "SRV", ("abc.local", 8009)), recs)
        self.assertIn(("abc.local", "A", "10.20.0.214"), recs)
        self.assertEqual(I.parse_dns(b"\x00\x01garbage"), [])
        self.assertEqual(I.parse_dns(hdr + b"\xc0\x0c" * 40), [])          # a pointer loop must not hang

    def test_upnp_description(self):
        xml = "<root><device><deviceType>urn:schemas-upnp-org:device:tvdevice:1</deviceType><friendlyName>Mediabox</friendlyName>" \
              "<manufacturer>Acme</manufacturer><modelName>DCX960</modelName></device></root>"
        self.assertEqual(I.parse_upnp_description(xml)["modelName"], "DCX960")
        self.assertTrue(I.parse_upnp_description("<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>")["igd"])


class TestIdentity(unittest.TestCase):
    def test_mac_prefix_is_only_a_lead(self):
        i = I.build_identity(macs=["3C:FB:02:03:48:5F"])
        self.assertEqual((i["state"], i["vendor"], i["model"]), ("unidentified", None, None))
        self.assertEqual(i["macVendor"], "Apple")
        self.assertEqual(i["candidates"][0]["confidence"], "low")

    def test_two_sources_make_likely_never_confirmed(self):
        i = I.build_identity(macs=[PHONE], router_client={"vendor": "Apple, Inc.", "medium": "wifi", "bandLabel": "5 GHz", "rssi": -50},
                             deep={"ts": "t", "ports": [{"port": 62078, "service": "iphone-sync", "risky": False}]})
        self.assertEqual((i["state"], i["vendor"], i["model"], i["type"]), ("likely", "Apple", None, "phone"))
        self.assertTrue(i["randomizedMac"])
        self.assertTrue(i["basis"].startswith("Not confirmed."))

    def test_module_maker_never_becomes_the_identity(self):
        i = I.build_identity(macs=["C0:F8:53:AD:A3:BA"], names=["lwip7"],
                             deep={"ts": "t", "ports": [{"port": 6668, "service": "tuya", "risky": False}]})
        self.assertEqual(i["state"], "unidentified")
        self.assertIsNone(i["vendor"])
        self.assertEqual(i["candidates"][0]["confidence"], "medium")
        self.assertIn("6668", i["candidates"][0]["basis"])

    def test_probe_that_names_the_product_confirms(self):
        i = I.build_identity(deep={"ts": "t", "cast": {"name": "Living Room speaker", "model": "Nest Audio", "manufacturer": "Google Inc."}})
        self.assertEqual((i["state"], i["vendor"], i["model"]), ("confirmed", "Google Inc.", "Nest Audio"))
        i = I.build_identity(deep={"ts": "t", "coap": {"model": "CX5120/11", "name": "Bedroom"}})
        self.assertEqual((i["state"], i["vendor"], i["model"]), ("confirmed", None, "CX5120/11"))     # the maker was not stated
        i = I.build_identity(mdns={"hostnames": ["indoorcam"], "services": [{"type": "_hap._tcp", "instance": "IndoorCam", "txt": {"md": "T8410", "ci": "17"}}]})
        self.assertEqual((i["state"], i["model"], i["type"]), ("confirmed", "T8410", "camera"))
        i = I.build_identity(mdns={"services": [{"type": "_googlecast._tcp", "instance": "g", "txt": {"md": "Google Cast Group"}},
                                                {"type": "_raop._tcp", "instance": "r", "txt": {"md": "0,1,2"}},
                                                {"type": "_device-info._tcp", "instance": "n", "txt": {"model": "Xserve"}}]})
        self.assertEqual(i["state"], "unidentified")

    def test_bluetooth(self):
        kb = {"name": "MX Keys", "vendorId": "0x046D", "productId": "0xB35B", "minorType": "Keyboard", "battery": 100, "connected": True}
        i = I.build_identity(dev={"id": "keyboard", "kind": "peripheral", "vendor": "", "model": "Not identified"}, bluetooth=kb)
        self.assertEqual((i["state"], i["vendor"], i["model"]), ("confirmed", "Logitech", "MX Keys"))
        pods = {"name": "Kim’s AirPods", "vendorId": "0x004C", "productId": "0x2014", "minorType": "Headphones"}
        i = I.build_identity(dev={"id": "pods", "kind": "headphones", "vendor": "", "model": ""}, bluetooth=pods)
        self.assertNotEqual(i["state"], "confirmed")            # a name its owner typed is not a product name

    def test_inventory_base(self):
        dev = {"id": "x", "kind": "switch", "vendor": "TP-Link", "model": "TL-SG105-M2", "verified": "reported"}
        self.assertEqual(I.base_identity(dev, None)["state"], "confirmed")
        self.assertEqual(I.base_identity(dict(dev, model="TL-SG105 (likely)"), None)["state"], "likely")
        self.assertEqual(I.base_identity(dict(dev, vendor=""), None)["state"], "unidentified")
        self.assertEqual(I.base_identity(dev, {"identity": {"vendor": "TP-Link", "model": "?", "confidence": "unknown", "basis": "b"}})["state"], "unidentified")
        said = I.base_identity(dict(dev, vendor="", model="", identifiedBy="alex", identifiedAt="2026-11-20T10:00:00"), {"identity": {"confidence": "unknown"}})
        self.assertEqual(said["state"], "confirmed")
        self.assertIn("Alex", said["basis"])

    def test_ha_name_match_is_a_lead(self):
        i = I.build_identity(names=["SamsPhone"], ha_by_name=[{"name": "SamsPhone", "manufacturer": "Apple", "model": "iPhone18,2"}])
        self.assertEqual(i["state"], "unidentified")
        self.assertEqual(i["candidates"][0]["model"], "iPhone18,2")
        i = I.build_identity(ha=[{"name": "Hue Bridge", "manufacturer": "Signify", "model": "Hue Bridge", "modelId": "BSB002", "_match": "address"}])
        self.assertEqual((i["state"], i["model"]), ("confirmed", "Hue Bridge (BSB002)"))


class TestSecurity(unittest.TestCase):
    NOW = 1795000000.0

    def iso(self, ago):
        import datetime
        return datetime.datetime.fromtimestamp(self.NOW - ago).astimezone().isoformat(timespec="seconds")

    def test_levels(self):
        ok = I.score_security({"state": "confirmed"}, now=self.NOW)
        self.assertEqual((ok["level"], ok["score"], ok["reasons"]), ("ok", 0, []))
        watch = I.score_security({"state": "unidentified"}, now=self.NOW)
        self.assertEqual(watch["level"], "watch")
        new = I.score_security({"state": "unidentified", "randomizedMac": True}, dynamic=True, first_seen=self.iso(3600), named=False, now=self.NOW)
        self.assertEqual(new["level"], "suspicious")
        self.assertEqual({r["code"] for r in new["reasons"]}, {"unidentified", "not-in-inventory", "new", "random-mac"})
        old = I.score_security({"state": "likely"}, dynamic=True, first_seen=self.iso(5 * 86400), now=self.NOW)
        self.assertEqual((old["level"], [r["code"] for r in old["reasons"]]), ("ok", ["not-in-inventory"]))

    def test_ports_and_block(self):
        s = I.score_security({"state": "confirmed"}, deep={"ports": [{"port": 23}, {"port": 80}, {"port": 21}]}, now=self.NOW)
        self.assertEqual(s["level"], "suspicious")
        self.assertEqual([p["risky"] for p in s["openPorts"]], [True, False, True])
        self.assertIn("Telnet", s["reasons"][0]["text"])
        b = I.score_security({"state": "confirmed"}, blocked=True, now=self.NOW)
        self.assertEqual((b["level"], b["blocked"], b["reasons"][0]["code"]), ("blocked", True, "blocked"))
        web = I.score_security({"state": "confirmed"}, deep={"http": [{"port": 80, "status": 200, "title": "Camera Admin", "auth": None, "passwordField": False}]}, now=self.NOW)
        self.assertEqual(web["reasons"][0]["code"], "open-web-page")
        login = I.score_security({"state": "confirmed"}, deep={"http": [{"port": 80, "status": 200, "title": "Router Admin", "passwordField": True}]}, now=self.NOW)
        self.assertEqual(login["reasons"], [])
        r = I.score_security({"state": "confirmed"}, posture={"wanAdmin": True, "wps": True, "telnet": False}, now=self.NOW)
        self.assertEqual({x["code"] for x in r["reasons"]}, {"router-wan-admin", "router-wps"})


class FakeEngine:
    def __init__(self, hosts=None, net=None):
        import threading
        self.lock = threading.Lock()
        self.hosts = hosts or {}
        self.net = net or {"mdns": {}, "ssdp": {}, "ha": []}
        self.seen = {}

    def first_seen(self, key, ts=None):
        return self.seen.setdefault(key, ts or "2026-11-20T10:00:00+01:00")


class TestPicture(unittest.TestCase):
    INV = {"zones": [{"id": "living"}], "links": [], "devices": [
        {"id": "router-xt8", "name": "Router", "kind": "router", "vendor": "ASUS", "model": "ZenWiFi AX XT8", "verified": "live",
         "net": [{"ip": "10.20.0.1", "name": "ZenWiFi_XT8-7E50"}], "probe": {"type": "ping", "ip": "10.20.0.1"}},
        {"id": "node-xt8", "name": "Node", "kind": "access-point", "vendor": "ASUS", "model": "XT8 (likely)", "verified": "live",
         "net": [{"ip": "10.20.0.45", "name": "ZenWiFi_XT8-8890"}], "probe": {"type": "ping", "ip": "10.20.0.45"}},
        {"id": "cam", "name": "Camera", "kind": "camera", "vendor": "eufy", "model": "T8410", "verified": "live",
         "net": [{"ip": "10.20.0.213", "medium": "wifi"}], "probe": {"type": "ping", "ip": "10.20.0.213"}},
        {"id": "speaker", "name": "Speaker", "kind": "speaker", "vendor": "Google", "model": "Nest Audio", "verified": "live",
         "net": [{"ip": "10.20.0.214", "medium": "wifi"}], "probe": {"type": "cast", "ip": "10.20.0.214"}},
        {"id": "printer", "name": "Printer", "kind": "printer", "vendor": "Canon", "model": "", "verified": "reported",
         "net": [{"mac": "6C:3C:7C:53:94:31", "medium": "wifi", "ap": "node-xt8", "band": "2.4 GHz", "apBasis": "router, earlier"}], "probe": {"type": "none"}},
    ]}
    RESULTS = {d: {"status": "online", "facts": {}} for d in ("router-xt8", "node-xt8", "cam", "speaker")}

    def picture(self, router=True, hosts=None):
        snap = R.build_snapshot(main_text(), {"10.20.0.45": NODE_TEXT})[0] if router else None
        reg = {"10.20.0.66": {"ip": "10.20.0.66", "mac": PLUG, "name": "lwip7", "firstSeen": "2026-11-20T10:00:00+01:00"},
               "10.20.0.213": {"ip": "10.20.0.213", "name": "Indoorcam"}}
        return I.build_picture(json.loads(json.dumps(self.INV)), self.RESULTS, reg if router else {}, snap, FakeEngine(hosts=hosts), router_fresh=router)

    def test_router_places_wifi_clients(self):
        p = self.picture()
        self.assertEqual(p["wireless"]["cam"]["ap"], "router-xt8")
        self.assertEqual((p["wireless"]["cam"]["band"], p["wireless"]["cam"]["source"]), ("2.4 GHz", "router"))
        link = next(l for l in p["wifiLinks"] if l["id"] == "w-cam")
        self.assertEqual((link["from"], link["to"], link["cable"], link["synthetic"], link["ap"], link["verified"]),
                         ("cam", "router-xt8", "wifi", True, "known", "live"))
        self.assertEqual(p["wireless"]["node-xt8"]["ap"], "router-xt8")       # the node's own wireless backhaul
        self.assertTrue(p["wireless"]["node-xt8"]["backhaul"])
        self.assertNotIn("router-xt8", p["wireless"])
        self.assertEqual(p["identities"]["node-xt8"]["state"], "confirmed")   # it reported its product id itself
        self.assertIn("RT-AX95Q", p["identities"]["node-xt8"]["model"])
        self.assertEqual(p["identities"]["cam"]["mac"], CAM)
        self.assertIn("router-wan-admin", [r["code"] for r in p["security"]["router-xt8"]["reasons"]])

    def test_hosts_outside_the_inventory(self):
        p = self.picture()
        ids = {d["id"]: d for d in p["dynamic"]}
        self.assertNotIn("host-10-20-0-213", ids)                           # the camera is in the inventory
        plug = ids["host-10-20-0-66"]
        self.assertEqual((plug["dynamic"], plug["kind"], plug["zone"], plug["verified"], plug["name"]), (True, "unknown", "unplaced", "live", "lwip7"))
        self.assertEqual(plug["net"][0], {"ip": "10.20.0.66", "mac": PLUG, "medium": "wifi", "name": "lwip7"})
        self.assertEqual(p["wireless"]["host-10-20-0-66"]["ap"], "node-xt8")
        blocked = ids["host-mac-" + OLD.replace(":", "").lower()]              # on the block list, matching no device: still shown
        self.assertEqual(p["security"][blocked["id"]]["level"], "blocked")
        self.assertIn("10.20.0.66", p["scanIps"])
        self.assertTrue(p["hostLive"]["host-10-20-0-66"]["routerOnline"])

    def test_without_router_nothing_is_guessed(self):
        p = self.picture(router=False)
        self.assertEqual(p["wireless"]["cam"], {"ap": None, "band": None, "rssi": None, "ssid": None, "source": "inventory",
                                                "evidence": "The inventory says it is on Wi-Fi. Which mesh unit it uses is not known."})
        self.assertEqual(next(l for l in p["wifiLinks"] if l["id"] == "w-cam")["ap"], "unknown")
        self.assertEqual(p["wireless"]["printer"]["ap"], "node-xt8")           # recorded by hand, and it says so
        self.assertEqual(next(l for l in p["wifiLinks"] if l["id"] == "w-printer")["verified"], "plan")

    def test_cast_bssid_names_the_node(self):
        hosts = {"10.20.0.214": {"ts": "t", "ports": [], "cast": {"name": "Speaker", "bssid": "FC:34:97:CA:88:98", "ssid": "HomeNet", "signal": -50, "model": "Nest Audio"}}}
        p = self.picture(router=False, hosts=hosts)
        self.assertEqual((p["wireless"]["speaker"]["ap"], p["wireless"]["speaker"]["source"]), ("node-xt8", "cast"))
        self.assertIn("hint", p["wireless"]["speaker"]["evidence"])
        hosts["10.20.0.214"]["cast"]["bssid"] = "AA:BB:CC:83:24:B4"
        self.assertIsNone(self.picture(router=False, hosts=hosts)["wireless"]["speaker"]["ap"])

    def test_merge_inventory(self):
        p = self.picture()
        inv = I.merge_inventory(json.loads(json.dumps(self.INV)), p)
        ids = [d["id"] for d in inv["devices"]]
        self.assertIn("host-10-20-0-66", ids)
        self.assertTrue(all("identity" in d for d in inv["devices"]))
        self.assertIn("w-cam", [l["id"] for l in inv["links"]])
        self.assertIn("unplaced", [z["id"] for z in inv["zones"]])
        bare = I.merge_inventory(json.loads(json.dumps(self.INV)), {})
        self.assertEqual(bare["devices"][0]["identity"]["evidence"], [])


class TestPassiveRematch(unittest.TestCase):
    """A known device on a new private MAC is matched by what it announces before anything probes it."""
    WORK_NEW, WORK_IP = "1A:00:00:00:00:77", "10.20.0.77"
    INV = {"zones": [], "links": [], "devices": [
        {"id": "macbook-work", "name": "Work MacBook Pro", "kind": "computer", "verified": "reported",
         "net": [{"name": "MACM-EXAMPLE01", "ip": "10.20.0.30", "medium": "wifi", "mac": "1A:00:00:00:01:0C", "randomizedMac": True}],
         "probe": {"type": "mdns", "name": "MACM-EXAMPLE01"},
         "facts": {"builtInMac": "AC:DE:48:00:11:22 (Apple), from its own _workstation advertisement"}},
        {"id": "macbook-home", "name": "Shared MacBook", "kind": "computer", "verified": "live",
         "net": [{"name": "Mac", "medium": "wifi"}], "probe": {"type": "none"}},
        {"id": "phone-kim", "name": "Kim's iPhone", "kind": "phone", "verified": "live",
         "net": [{"if": "tailscale", "ip": "100.64.0.10", "name": "kim-iphone"}], "probe": {"type": "none"}},
        {"id": "phone-sam", "name": "Sam's iPhone", "kind": "phone", "verified": "live",
         "net": [{"ip": "10.20.0.60", "name": "SamsPhone", "medium": "wifi", "mac": "3C:00:00:00:00:05"}], "probe": {"type": "none"}},
    ]}
    RESULTS = {"macbook-work": {"status": "online", "facts": {}}, "phone-sam": {"status": "online", "facts": {}}}

    def picture(self, clients, mdns=None, tailscale=None):
        reg = {c["ip"]: {"ip": c["ip"], "mac": c["mac"], "name": c.get("hostname"), "firstSeen": "2026-11-21T10:00:00+01:00"}
               for c in clients}
        snap = {"ok": True, "ts": "t", "clients": [dict(c, online=True, medium="wifi") for c in clients], "nodes": [], "blockList": []}
        eng = FakeEngine(net={"mdns": mdns or {}, "ssdp": {}, "ha": [], "tailscale": tailscale or {}})
        return I.build_picture(json.loads(json.dumps(self.INV)), self.RESULTS, reg, snap, eng)

    def test_work_laptop_on_a_new_mac_is_matched_by_mdns_and_never_scanned(self):
        p = self.picture([{"mac": self.WORK_NEW, "ip": self.WORK_IP, "hostname": "Mac"}],
                         mdns={self.WORK_IP: {"hostnames": ["macm-example01"], "services": []}})
        self.assertNotIn(I.host_id(self.WORK_IP), [d["id"] for d in p["dynamic"]])
        self.assertNotIn(self.WORK_IP, p["scanIps"])
        self.assertIn(self.WORK_IP, p["addresses"]["macbook-work"]["ips"])
        self.assertIn(self.WORK_NEW, p["addresses"]["macbook-work"]["macs"])

    def test_mdns_name_matches_a_device_whose_entry_has_a_mac(self):
        p = self.picture([{"mac": "3C:00:00:00:00:98", "ip": "10.20.0.98", "hostname": None}],
                         mdns={"10.20.0.98": {"hostnames": ["samsphone"]}})
        self.assertEqual(p["rematched"]["phone-sam"][0]["basis"], ["mDNS name samsphone"])

    def test_generic_name_matches_nothing(self):
        clients = [{"mac": "1A:00:00:00:00:%02d" % i, "ip": "10.20.0.%d" % (80 + i), "hostname": "Mac"} for i in range(3)]
        p = self.picture(clients)
        self.assertEqual(p["rematched"], {})
        self.assertEqual(len([d for d in p["dynamic"] if d["name"] == "Mac"]), 3)
        self.assertTrue({"10.20.0.80", "10.20.0.81", "10.20.0.82"} <= set(p["scanIps"]))

    def test_name_announced_by_two_hosts_is_no_match_but_the_work_laptop_is_still_not_scanned(self):
        mdns = {"10.20.0.78": {"hostnames": ["macm-example01"]}, self.WORK_IP: {"hostnames": ["macm-example01"]}}
        p = self.picture([{"mac": self.WORK_NEW, "ip": self.WORK_IP, "hostname": "Mac"},
                          {"mac": "1A:00:00:00:00:78", "ip": "10.20.0.78", "hostname": "Mac"}], mdns=mdns)
        self.assertEqual(p["rematched"], {})
        self.assertIn(I.host_id(self.WORK_IP), [d["id"] for d in p["dynamic"]])
        self.assertFalse({self.WORK_IP, "10.20.0.78"} & set(p["scanIps"]))

    def test_dhcp_host_name_matches_a_unique_device(self):
        p = self.picture([{"mac": "3C:00:00:00:00:99", "ip": "10.20.0.99", "hostname": "SamsPhone"}])
        self.assertEqual(p["rematched"]["phone-sam"][0]["mac"], "3C:00:00:00:00:99")
        self.assertNotIn(I.host_id("10.20.0.99"), [d["id"] for d in p["dynamic"]])

    def test_tailscale_peer_on_the_lan_matches_by_its_tailnet_address(self):
        p = self.picture([{"mac": "86:00:00:00:00:31", "ip": "10.20.0.31", "hostname": None}],
                         tailscale={"10.20.0.31": {"name": "localhost", "ips": ["100.64.0.10"]}})
        self.assertEqual(p["rematched"]["phone-kim"][0]["basis"], ["Tailscale address 100.64.0.10"])

    def test_work_laptops_builtin_mac_is_never_scanned(self):
        p = self.picture([{"mac": "AC:DE:48:00:11:22", "ip": "10.20.0.66", "hostname": "Mac"}])
        self.assertNotIn("10.20.0.66", p["scanIps"])

    def test_sources_that_disagree_match_nothing(self):
        p = self.picture([{"mac": self.WORK_NEW, "ip": self.WORK_IP, "hostname": "SamsPhone"}],
                         mdns={self.WORK_IP: {"hostnames": ["macm-example01"]}})
        self.assertEqual(p["rematched"], {})
        self.assertNotIn(self.WORK_IP, p["scanIps"])

    def test_specific_name(self):
        for n in ("Mac", "mac-2", "iPhone", "android-dhcp-14", "lwip0", "localhost", "MacBook-Pro.local", "abc"):
            self.assertIsNone(I.specific_name(n), n)
        self.assertEqual(I.specific_name("MACM-EXAMPLE01.local"), "macm-example01")


class TestScanWaitsForPassiveRound(unittest.TestCase):
    def engine(self, net_age):
        e = I.Engine.__new__(I.Engine)
        import threading
        e.lock, e.hosts, e.seen, e.wanted = threading.Lock(), {}, {}, {}
        e.net = {"t": time.time() - net_age}
        return e

    def test_new_address_waits_for_a_passive_round_first(self):
        e = self.engine(net_age=120)
        net_due, todo = e.due(["10.20.0.77"])
        self.assertEqual((net_due, todo), (True, []))          # pulls the passive round forward, scans nothing
        e.net["t"] = time.time() + 1                           # the round ran
        self.assertEqual(e.due(["10.20.0.77"]), (False, ["10.20.0.77"]))

    def test_early_round_at_most_once_a_minute(self):
        e = self.engine(net_age=10)
        self.assertEqual(e.due(["10.20.0.77"]), (False, []))

    def test_known_address_is_not_held_back_and_dropped_ones_start_over(self):
        e = self.engine(net_age=10)
        e.hosts["10.20.0.5"] = {"t": time.time() - I.DEEP_TTL - 1}
        self.assertEqual(e.due(["10.20.0.5", "10.20.0.77"]), (False, ["10.20.0.5"]))
        e.due([])
        self.assertEqual(e.wanted, {})

    def test_tailscale_peers_on_the_lan(self):
        doc = {"Peer": {"a": {"DNSName": "kim-iphone.example.ts.net.", "HostName": "localhost", "CurAddr": "10.20.0.31:41641",
                              "TailscaleIPs": ["100.64.0.10", "fd7a:115c:a1e0::1"]},
                        "b": {"DNSName": "far.ts.net.", "CurAddr": "84.1.2.3:41641", "TailscaleIPs": ["100.1.1.1"]},
                        "c": {"DNSName": "relay.ts.net.", "CurAddr": "", "TailscaleIPs": ["100.1.1.2"]}}}
        self.assertEqual(I.parse_tailscale_status(doc), {"10.20.0.31": {"name": "kim-iphone", "ips": ["100.64.0.10"]}})


class TestHubApi(T.Base):
    """The routes, on the shared in-process server with a fake router behind the monitor."""

    @classmethod
    def setUpClass(cls):
        T.Base.setUpClass.__func__(cls)
        cls.m = server.MONITOR
        cls.ssh = FakeSSH()
        cls.m.router = R.Router(ssh=cls.ssh)
        cls.m.router.keychain = lambda: None
        cls.m.router.poll(force=True)
        with cls.m.cycle_lock:
            cls.m.strangers["10.20.0.66"] = {"ip": "10.20.0.66", "mac": PLUG, "name": "lwip7",
                                                 "firstSeen": C.now_iso(), "lastSeen": C.now_iso()}
        cls.m.refresh_picture()

    def act(self, did, action, params=None, confirm=True):
        body = {"action": action, "params": params or {}}
        if confirm:
            body["confirm"] = True
        return self.post("/api/device/%s/action" % did, body)

    def test_inventory_has_identity_dynamic_hosts_and_wifi_links(self):
        s, inv = self.get("/api/inventory")
        devs = {d["id"]: d for d in inv["devices"]}
        self.assertTrue(all("identity" in d for d in inv["devices"]))
        kb = devs["keyboard"]["identity"]
        self.assertEqual(kb["state"], "confirmed")
        self.assertTrue(any(e["source"] == "bluetooth" for e in kb["evidence"]))
        host = devs["host-10-20-0-66"]
        self.assertTrue(host["dynamic"])
        self.assertEqual(host["identity"]["state"], "unidentified")
        self.assertEqual(host["identity"]["mac"], PLUG)
        links = {l["id"]: l for l in inv["links"]}
        self.assertEqual((links["w-host-10-20-0-66"]["to"], links["w-host-10-20-0-66"]["ap"]), ("node-xt8", "known"))
        self.assertIn(inv["links"][0]["cable"], ("usb-c", "ethernet", "hdmi", "usb", "mesh", "bluetooth", "coax"))
        s, d = self.get("/api/device/host-10-20-0-66")
        self.assertEqual(s, 200)
        self.assertEqual(d["device"]["identity"]["mac"], PLUG)
        self.assertTrue(any(l["id"] == "w-host-10-20-0-66" for l in d["links"]))
        self.assertIn("security", d["live"])

    def test_live_additions(self):
        s, live = self.get("/api/live")
        self.assertEqual(live["devices"]["keyboard"]["status"], "online")
        self.assertEqual(live["devices"]["keyboard"]["facts"]["bluetooth"]["name"], "MX Keys")
        self.assertEqual(live["devices"]["headphones-bose-qc45"]["status"], "unknown")       # paired, not connected: not a fault
        self.assertEqual(live["links"]["l-bt-keyboard"]["status"], "up")
        self.assertEqual(live["links"]["l-bt-headphones-bose-qc45"]["state"], "paired")
        host = live["devices"]["host-10-20-0-66"]
        self.assertEqual(host["status"], "online")                                           # the router lists it, though it ignores ping
        self.assertEqual(host["security"]["level"], "suspicious")
        self.assertEqual(live["wireless"]["host-10-20-0-66"]["ap"], "node-xt8")
        self.assertEqual(live["links"]["w-host-10-20-0-66"]["status"], "up")
        for k in ("unidentified", "suspicious", "blocked"):
            self.assertIn(k, live["summary"])
        self.assertGreaterEqual(live["summary"]["blocked"], 1)
        self.assertEqual({k: live["router"][k] for k in ("configured", "ok", "error")}, {"configured": True, "ok": True, "error": None})
        self.assertIsInstance(live["router"]["clients"], int)
        self.assertTrue(any(x["ip"] == "10.20.0.66" for x in live["strangers"]))          # version 1 clients still get it

    def test_router_route_and_login(self):
        s, r = self.get("/api/router")
        self.assertEqual((s, r["configured"], r["ok"], r["model"], r["routerWrites"]), (200, True, True, "RT-AX95Q", False))
        c = next(c for c in r["clients"] if c["mac"] == PLUG)
        self.assertEqual(c["deviceId"], "host-10-20-0-66")
        self.assertEqual(r["blockList"][0]["deviceId"], "host-mac-" + OLD.replace(":", "").lower())
        self.assertNotIn("password", json.dumps(r).lower())
        stored = []
        orig = (self.m.router.test_login, R.keychain_set)
        self.m.router.test_login = lambda u, p: (_ for _ in ()).throw(R.RouterError("The router says the username or password is wrong.")) if p == "bad" else {"model": "RT-AX95Q", "firmware": "x"}
        R.keychain_set = lambda u, p: stored.append((u, p))
        try:
            s, d = self.post("/api/router/login", {"username": "admin", "password": "bad"})
            self.assertEqual((d["ok"], stored), (False, []))
            self.assertIn("wrong", d["error"])
            s, d = self.post("/api/router/login", {"username": "admin", "password": "s3cret-pw"})
            self.assertEqual((d["ok"], stored), (True, [("admin", "s3cret-pw")]))
            self.assertEqual(self.post("/api/router/login", {"username": "admin"})[1]["ok"], False)
        finally:
            self.m.router.test_login, R.keychain_set = orig
        s, audit = self.get("/api/audit?limit=50")
        self.assertNotIn("s3cret-pw", json.dumps(audit))
        self.assertTrue(any(a["type"] == "router-login" and a["actor"] == "person" for a in audit))
        self.assertEqual(self.post("/api/router/login", {"username": "a", "password": "b"}, headers={"Content-Type": "application/json"})[0], 403)

    def test_actions_list_confirm_and_refusals(self):
        s, acts = self.get("/api/device/host-10-20-0-66/actions")
        self.assertEqual([a["id"] for a in acts], ["identify", "scan", "investigate", "block", "unblock", "forget"])
        a = {x["id"]: x for x in acts}
        self.assertTrue(a["block"]["available"])
        self.assertIn(PLUG, a["block"]["confirm"]["effect"])
        self.assertIn("only shows the commands", a["block"]["confirm"]["effect"])
        self.assertEqual((a["unblock"]["available"], a["unblock"]["unavailableReason"]), (False, "It is not blocked."))
        for k in ("title", "effect", "undo"):
            self.assertTrue(a["forget"]["confirm"][k])
        self.assertEqual(self.act("host-10-20-0-66", "block", confirm=False)[0], 400)
        self.assertEqual(self.act("host-10-20-0-66", "explode")[0], 400)
        self.assertEqual(self.act("nope", "scan")[0], 404)
        for did in ("mac-mini", "router-xt8", "node-xt8", "modem-cableco", "switch-sg105m2", "internet"):
            for action in ("block", "forget"):
                s, d = self.act(did, action)
                self.assertEqual(s, 403, (did, action, d))
        for action in ("identify", "investigate", "block", "unblock", "forget"):
            self.assertEqual(self.act("macbook-work", action, {"name": "x"})[0], 403, action)
        s, acts = self.get("/api/device/macbook-work/actions")
        self.assertEqual([x["id"] for x in acts if x["available"]], ["scan"] if any(x["id"] == "scan" and x["available"] for x in acts) else [])
        s, acts = self.get("/api/device/mac-mini/actions")
        self.assertFalse({x["id"]: x for x in acts}["block"]["available"])
        self.assertEqual(self.ssh.writes, [])
        s, audit = self.get("/api/audit?limit=100")
        self.assertTrue(any(r["actor"] == "person" and r["decision"] == "refused" and r["command"] == "block mac-mini" for r in audit))

    def test_block_rehearses_until_switched_on(self):
        s, d = self.act("host-10-20-0-66", "block")
        self.assertEqual(s, 200, d)
        self.assertTrue(d["result"]["dryRun"])
        self.assertIn("switched off", d["result"]["rehearsal"])
        self.assertEqual(d["result"]["commands"][-1], "service restart_firewall")
        self.assertEqual(self.ssh.writes, [])
        self.post("/api/settings", {"routerWrites": True})
        try:
            self.assertTrue(self.get("/api/router")[1]["routerWrites"])
            s, d = self.act("host-10-20-0-66", "block", {"dryRun": True})
            self.assertTrue(d["result"]["dryRun"])
            self.assertEqual(self.ssh.writes, [])
            s, d = self.act("host-10-20-0-66", "block")
            self.assertEqual((s, d["ok"], d["result"]["dryRun"], d["result"]["verified"]), (200, True, False, True))
            self.assertEqual(self.ssh.mf["MULTIFILTER_MAC"], OLD + ">" + PLUG)
            self.assertEqual(self.get("/api/live")[1]["devices"]["host-10-20-0-66"]["security"]["level"], "blocked")
            self.assertEqual(self.act("host-10-20-0-66", "block")[0], 200)                 # already there: nothing sent again
            self.assertEqual(len(self.ssh.writes), 1)
            s, d = self.act("host-10-20-0-66", "unblock")
            self.assertEqual((s, d["result"]["changed"]), (200, True))
            self.assertEqual(self.ssh.mf["MULTIFILTER_MAC"], OLD)
            s, d = self.act("host-mac-" + OLD.replace(":", "").lower(), "unblock", {"dryRun": True})
            self.assertEqual((s, d["result"]["commands"][1]), (200, "nvram set MULTIFILTER_MAC=''"))
        finally:
            self.post("/api/settings", {"routerWrites": False})
        s, evs = self.get("/api/events?limit=50")
        self.assertTrue(any(e["kind"] == "security" and e.get("code") == "blocked" for e in evs))
        s, audit = self.get("/api/audit?limit=100")
        row = next(r for r in audit if r["command"] == "block host-10-20-0-66" and "nvram commit" in r["summary"] and "dry run" not in r["summary"])
        self.assertEqual((row["actor"], row["type"], row["decision"]), ("person", "device-action", "confirmed"))
        self.assertIn("nvram commit", row["summary"])

    def test_identify_and_forget_inventory_device(self):
        before = load(T.INV)
        s, d = self.act("unknown-85", "identify", {"name": "Guest laptop", "vendor": "Apple", "kind": "computer", "zone": "living"})
        self.assertEqual(s, 200, d)
        now = load(T.INV)
        dev = next(x for x in now["devices"] if x["id"] == "unknown-85")
        self.assertEqual((dev["name"], dev["vendor"], dev["kind"], dev["zone"], dev["verified"], dev["identifiedBy"]),
                         ("Guest laptop", "Apple", "computer", "living", "reported", "person"))
        backup = os.path.join(T.STATE, "backups", d["result"]["backup"])
        self.assertEqual(load(backup), before)
        self.assertEqual(self.get("/api/device/unknown-85")[1]["device"]["identity"]["state"], "confirmed")
        self.assertEqual(self.act("unknown-85", "identify", {"zone": "the moon"})[0], 400)
        self.assertEqual(self.act("unknown-85", "identify", {})[0], 400)
        self.assertEqual(self.act("unknown-85", "identify", {"kind": "Not A Kind!"})[0], 400)
        s, d = self.act("unknown-85", "forget")
        self.assertEqual(s, 200, d)
        now = load(T.INV)
        self.assertFalse([x for x in now["devices"] if x["id"] == "unknown-85"])
        self.assertEqual(self.get("/api/device/unknown-85")[0], 404)
        self.assertEqual(len(now["devices"]), len(before["devices"]) - 1)
        s, evs = self.get("/api/events?limit=50")
        self.assertTrue({"identified", "removed"} <= {e.get("code") for e in evs if e["kind"] == "security"})

    def test_identify_a_host_makes_it_an_inventory_device(self):
        with self.m.cycle_lock:
            self.m.strangers["10.20.0.77"] = {"ip": "10.20.0.77", "mac": "3C:FB:02:03:48:D5", "name": None,
                                                 "firstSeen": C.now_iso(), "lastSeen": C.now_iso()}
        self.m.refresh_picture()
        s, d = self.act("host-10-20-0-77", "identify", {"name": "Hallway Plug!", "vendor": "Shelly", "kind": "plug"})
        self.assertEqual((s, d["result"]["deviceId"]), (200, "hallway-plug"))
        dev = next(x for x in load(T.INV)["devices"] if x["id"] == "hallway-plug")
        self.assertEqual((dev["net"][0]["ip"], dev["net"][0]["mac"], dev["zone"], dev["verified"]), ("10.20.0.77", "3C:FB:02:03:48:D5", "unplaced", "reported"))
        ids = [x["id"] for x in self.get("/api/inventory")[1]["devices"]]
        self.assertIn("hallway-plug", ids)
        self.assertNotIn("host-10-20-0-77", ids)
        with self.m.cycle_lock:
            self.m.strangers["10.20.0.78"] = {"ip": "10.20.0.78", "name": "x", "firstSeen": C.now_iso(), "lastSeen": C.now_iso()}
        self.m.refresh_picture()
        self.assertEqual(self.act("host-10-20-0-78", "forget")[0], 200)
        self.assertNotIn("10.20.0.78", self.m.strangers)

    def test_investigate_starts_an_agent_run(self):
        s, d = self.act("host-10-20-0-66", "investigate")
        self.assertEqual(s, 200, d)
        rec = self.wait_run(d["result"]["runId"])
        self.assertEqual(rec["deviceIds"], ["host-10-20-0-66"])
        self.assertIn("bin/probe.py identity host-10-20-0-66", rec["question"])
        self.assertIn(PLUG, rec["question"])
        self.post("/api/settings", {"agentMode": "paused"})
        try:
            self.assertEqual(self.act("host-10-20-0-66", "investigate")[0], 409)
        finally:
            self.post("/api/settings", {"agentMode": "advise"})

    def test_scan_uses_the_engine(self):
        calls = []
        orig = self.m.ident.scan_now
        self.m.ident.scan_now = lambda ip: calls.append(ip) or {"ts": C.now_iso(), "t": time.time(), "ports": [{"port": 23, "service": "telnet", "risky": True}], "http": [], "tls": [], "banners": {}}
        try:
            s, d = self.act("host-10-20-0-66", "scan")
        finally:
            self.m.ident.scan_now = orig
        self.assertEqual((s, calls, d["result"]["openPorts"][0]["port"]), (200, ["10.20.0.66"], 23))
        self.assertEqual(self.act("hub-arcdock", "scan")[0], 409)          # nothing to scan: no address

    def test_probe_new_commands_validate(self):
        probe = T.TestProbeValidation().probe
        for args in (["ports", "8.8.8.8"], ["ports", "127.0.0.1"], ["ports", "10.20.0.1;id"], ["identity", "nope"], ["identity"],
                     ["ports"], ["ssdp", "x"], ["bluetooth", "x"]):
            self.assertEqual(probe(*args).returncode, 2, args)
        out = probe("--list").stdout
        for name in ("bluetooth", "ssdp", "ports", "identity"):
            self.assertIn(name, out)
        r = probe("identity", "host-10-20-0-66")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["identity"]["mac"], PLUG)


if __name__ == "__main__":
    unittest.main()
