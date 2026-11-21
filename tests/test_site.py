"""One house's files: data/site.json (site_config.py), an empty house, router type none, hands-off and
protected devices driven by the site file, and the /api/site, /api/layout, /api/setup routes.

Every site file here is a temp file named through HM_SITE: the developer's own data/site.json is never read.
"""
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_server as T  # noqa: E402  (sets the environment, HM_SITE included, and starts the shared server)
import site_config as SITE  # noqa: E402
import collectors as C  # noqa: E402
import router as R  # noqa: E402
import actions as X  # noqa: E402
import agent_runner as A  # noqa: E402
import server  # noqa: E402
import sentinel as S  # noqa: E402
import agent_gate  # noqa: E402  (test_server put bin/ on the path)

FIXTURE = json.load(open(T.SITE_FIXTURE))
TMP = tempfile.mkdtemp(prefix="hoh-site-test-")


def site_file(doc, name=None):
    p = os.path.join(TMP, name or "site-%d.json" % (abs(hash(json.dumps(doc, sort_keys=True))) % 10 ** 8))
    with open(p, "w") as f:
        f.write(doc if isinstance(doc, str) else json.dumps(doc))
    return p


@contextlib.contextmanager
def env(**kw):
    """Set (or with None, remove) environment variables for one block, and start site_config from scratch."""
    old = {k: os.environ.get(k) for k in kw}
    for k, v in kw.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    SITE.reset_cache()
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        SITE.reset_cache()


def with_site(**changes):
    """The example house's site.json with some top-level keys replaced."""
    doc = json.loads(json.dumps(FIXTURE))
    doc.update(changes)
    return site_file(doc)


class TestSiteConfig(unittest.TestCase):
    def tearDown(self):
        SITE.reset_cache()

    def test_defaults_without_a_file(self):
        with env(HM_SITE=os.path.join(TMP, "missing.json")):
            s, probs = SITE.load()
            self.assertEqual(probs, [])
            self.assertFalse(s["configured"])
            self.assertEqual(SITE.router_type(), "none")
            self.assertEqual(SITE.owner(), "you")
            self.assertEqual(SITE.home_name(), "Home")
            self.assertEqual(SITE.hands_off(), [])
            self.assertFalse(SITE.router_writes())
            self.assertIn("~/.ssh", SITE.secret_dirs_raw())
            self.assertIsNone(SITE.host_device({"devices": []}))

    def test_merge_keeps_defaults_for_missing_keys(self):
        p = site_file({"home": {"owner": "Robin"}, "router": {"type": "asuswrt"}, "network": {"subnet": "10.0.7.0/24", "gateway": "10.0.7.254"}})
        with env(HM_SITE=p):
            s, probs = SITE.load()
            self.assertEqual(probs, [])
            self.assertTrue(s["configured"])
            self.assertEqual(s["home"]["name"], "Home")               # default kept beside the given owner
            self.assertEqual(s["router"]["user"], "admin")
            self.assertFalse(s["router"]["writes"])
            self.assertEqual(SITE.owner(), "Robin")
            self.assertEqual(SITE.router_type(), "asuswrt")
            self.assertEqual(SITE.router_ip(), "10.0.7.254")
            self.assertEqual(s["network"]["subnetSource"], "site")
            self.assertTrue(SITE.ip_allowed("10.0.7.20"))
            self.assertFalse(SITE.ip_allowed("10.20.0.20"))

    def test_broken_json_and_wrong_types(self):
        for text in ('{"home": ', "[1, 2]", '{"router": "asus", "handsOff": "x"}', '{"network": {"subnet": "not-a-cidr", "gateway": "10.1.1.1"}}'):
            with env(HM_SITE=site_file(text)):
                s, probs = SITE.load()
                self.assertTrue(probs, text)
                self.assertFalse(s["configured"], text)
                self.assertIn(SITE.router_type(), ("none", "asuswrt"))
                SITE.subnet()                                           # always a usable network
                SITE.public()

    def test_auto_detection_and_its_fallback(self):
        orig = SITE.detect
        try:
            with env(HM_SITE=os.path.join(TMP, "missing.json")):
                SITE.detect = lambda: {"gateway": None, "interface": None, "address": None, "subnet": None}
                s = SITE.load(fresh=True)[0]
                self.assertEqual((s["network"]["subnet"], s["network"]["subnetSource"]), ("192.168.1.0/24", "fallback"))
                self.assertEqual((s["network"]["gateway"], s["network"]["gatewaySource"]), ("192.168.1.1", "fallback"))
                SITE.detect = lambda: {"gateway": "172.20.0.1", "interface": "en0", "address": "172.20.3.9", "subnet": "172.20.0.0/22"}
                s = SITE.load(fresh=True)[0]
                self.assertEqual((s["network"]["subnet"], s["network"]["subnetSource"]), ("172.20.0.0/22", "detected"))
                self.assertEqual((s["network"]["gateway"], s["network"]["gatewaySource"]), ("172.20.0.1", "detected"))
        finally:
            SITE.detect = orig

    def test_router_ip_from_the_inventory_when_the_gateway_is_auto(self):
        p = site_file({"network": {"subnet": "10.20.0.0/24"}, "router": {"type": "asuswrt", "deviceId": "router-xt8"}})
        with env(HM_SITE=p):
            self.assertEqual(SITE.router_ip(C.load_inventory()), "10.20.0.1")

    def test_layout_file(self):
        good = os.path.join(TMP, "layout-good.json")
        with open(good, "w") as f:
            json.dump({"schema": 1, "network": {"pos": {"router-xt8": [1, 2]}}}, f)
        with env(HM_LAYOUT=good):
            self.assertEqual(SITE.load_layout(), ({"schema": 1, "network": {"pos": {"router-xt8": [1, 2]}}}, []))
        with env(HM_LAYOUT=site_file("{broken", "layout-bad.json")):
            d, probs = SITE.load_layout()
            self.assertEqual(d, {})
            self.assertTrue(probs)
        with env(HM_LAYOUT=os.path.join(TMP, "no-layout.json")):
            self.assertEqual(SITE.load_layout(), ({}, []))

    def test_claude_cli(self):
        with env(HM_CLAUDE_BIN="/opt/x/claude"):
            self.assertEqual(SITE.claude_cli(), "/opt/x/claude")


class TestProtectedAndHandsOff(unittest.TestCase):
    def test_protected_ids_from_site_and_kinds(self):
        inv = C.load_inventory()
        with env(HM_SITE=with_site(protected=["hue-bridge"])):
            p = set(SITE.protected_ids(inv))
            self.assertTrue({"hue-bridge", "router-xt8", "mac-mini", "node-xt8", "modem-cableco", "switch-sg105m2", "internet"} <= p, p)
            self.assertNotIn("tv-philips", p)
            devs = {d["id"]: d for d in inv["devices"]}
            self.assertTrue(X.is_protected(devs["hue-bridge"], inv))
            self.assertIn("cannot be blocked", X.refusal(devs["hue-bridge"], "block", inv))
            self.assertIsNone(X.refusal(devs["tv-philips"], "block", inv))
        self.assertFalse(X.is_protected({"id": "hue-bridge", "kind": "bridge"}, inv))     # the example house does not protect it

    def test_hands_off_macs_are_never_scanned(self):
        import identify as I
        site = with_site(handsOff=[{"id": "work-laptop", "names": ["CORP-L0042"], "macs": ["AC:DE:48:00:99:01"]}])
        snap = {"ok": True, "clients": [{"mac": "AC:DE:48:00:99:01", "ip": "10.20.0.71", "hostname": "Mac", "online": True},
                                        {"mac": "1A:00:00:00:99:02", "ip": "10.20.0.72", "hostname": "corp-l0042", "online": True},
                                        {"mac": "1A:00:00:00:99:03", "ip": "10.20.0.73", "hostname": "Mac", "online": True}],
                "nodes": [], "blockList": []}
        reg = {c["ip"]: {"ip": c["ip"], "mac": c["mac"], "name": c["hostname"]} for c in snap["clients"]}

        class Eng:
            import threading
            lock, hosts, net = threading.Lock(), {}, {"mdns": {}, "ssdp": {}, "ha": []}

            def first_seen(self, key, ts=None):
                return "2026-01-01T00:00:00+00:00"
        with env(HM_SITE=site):
            self.assertEqual(SITE.hands_off_macs(), ["AC:DE:48:00:99:01"])
            p = I.build_picture({"devices": []}, {}, reg, snap, Eng())
        self.assertEqual(p["scanIps"], ["10.20.0.73"])

    def test_hands_off_comes_from_the_site_file(self):
        inv = C.load_inventory()
        devs = {d["id"]: d for d in inv["devices"]}
        tv = {"id": "tv-philips", "ips": ["10.20.0.119"], "names": ["Living Room TV"], "why": "the landlord's"}
        with env(HM_SITE=with_site(handsOff=[tv])):
            self.assertFalse(A.guard_command("echo hi", "tv-philips")["ok"])
            self.assertIn("hands-off", A.guard_command("echo hi", "tv-philips")["reason"])
            self.assertFalse(A.guard_command("ping -c 1 10.20.0.119", "mac-mini")["ok"])
            self.assertTrue(A.guard_command("ping -c 1 10.20.0.11", "mac-mini")["ok"])      # a neighbouring address is fine
            self.assertTrue(A.guard_command("echo hi", "macbook-work")["ok"])                 # no longer hands-off in this house
            self.assertIn("hands-off", X.refusal(devs["tv-philips"], "block", inv))
            self.assertIsNone(X.refusal(devs["tv-philips"], "scan", inv))
            self.assertIsNone(X.refusal(devs["macbook-work"], "identify", inv))
            p = A.build_prompt(inv)
            self.assertIn("`tv-philips` (the landlord's)", p)
            self.assertNotIn("macbook-work` (", p)
            r = subprocess.run([sys.executable, os.path.join(ROOT, "bin", "probe.py"), "ping", "10.20.0.119"],
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertIn("hands-off", r.stderr)
        self.assertFalse(A.guard_command("echo hi", "macbook-work")["ok"])
        self.assertFalse(A.guard_command("ssh MACM-EXAMPLE01.local", "mac-mini")["ok"])

    def test_secret_dirs_from_the_site_file(self):
        with env(HM_SITE=with_site(secretDirs=["~/.vault-of-keys"])):
            self.assertFalse(A.guard_command("cat ~/.vault-of-keys/a", "mac-mini")["ok"])
            self.assertFalse(agent_gate.decide("Read", {"file_path": os.path.expanduser("~/.vault-of-keys/a")})[0])
            self.assertFalse(agent_gate.decide("Read", {"file_path": os.path.expanduser("~/.ssh/id_ed25519")})[0])    # fixed ones stay
            self.assertTrue(agent_gate.decide("Read", {"file_path": ROOT + "/knowledge/x.md"})[0])
            self.assertIn("`~/.vault-of-keys`", A.build_prompt({"devices": []}))

    def test_prompt_is_filled_in(self):
        p = A.build_prompt(C.load_inventory())
        self.assertNotIn("{{", p)
        self.assertIn("Alex, who lives here.", p)
        self.assertIn("Example House", p)
        self.assertIn("`mac-mini`", p)
        self.assertIn("`macbook-work` (managed by an employer)", p)
        with env(HM_SITE=os.path.join(TMP, "missing.json")):
            p = A.build_prompt({"devices": []})
            self.assertNotIn("{{", p)
            self.assertIn("The person who lives here.", p)
            self.assertIn("none are listed", p)
            self.assertNotRegex(p, r"Alex|Example House")


class FakeSSH:
    def __init__(self):
        self.calls = []

    def __call__(self, host, script, timeout=20):
        self.calls.append(host)
        return 255, "", "should never run"


class TestRouterNone(unittest.TestCase):
    def test_none_never_reaches_ssh_or_the_keychain(self):
        sec_calls = []
        orig = R._security
        R._security = lambda argv, stdin=None, timeout=10: (sec_calls.append(argv), (1, "", ""))[1]
        try:
            with env(HM_SITE=with_site(router={"type": "none"})):
                ssh = FakeSSH()
                r = R.Router(ssh=ssh)
                self.assertFalse(r.configured())
                snap = r.poll(force=True)
                self.assertFalse(snap["ok"])
                st = r.status()
                self.assertEqual((st["configured"], st["type"], st["enabled"]), (False, "none", False))
                self.assertIn("not set up", st["error"])
                with self.assertRaises(R.RouterError):
                    r.change("block", "C0:F8:53:AD:A3:BA")
                with self.assertRaises(R.RouterError):
                    R.keychain_set("admin", "pw")
                self.assertIsNone(R.keychain_account())
                self.assertFalse(R.keychain_delete())
                self.assertFalse(R.ssh_available())
                m = C.Monitor(settings_fn=lambda: {"scanning": False}, inventory_fn=lambda: {"devices": []})
                m.router = r
                self.assertIsNone(m.poll_router())
                self.assertEqual(ssh.calls, [])
        finally:
            R._security = orig
        self.assertEqual(sec_calls, [])

    def test_writes_need_the_site_switch(self):
        class SSH(FakeSSH):
            def __call__(self, host, script, timeout=20):
                self.calls.append(host)
                if "nvram set" in script:
                    raise AssertionError("a write was sent")
                return 0, "@@nvram\nMULTIFILTER_ALL=1\nMULTIFILTER_ENABLE=2\nMULTIFILTER_MAC=AA:BB:CC:00:00:01\n" \
                          "MULTIFILTER_DEVICENAME=x\nMULTIFILTER_MACFILTER_DAYTIME=\nMULTIFILTER_MACFILTER_DAYTIME_V2=\n@@end\n", ""
        with env(HM_SITE=with_site(router=dict(FIXTURE["router"], writes=False))):
            res = R.Router(ssh=SSH()).change("block", "C0:F8:53:AD:A3:BA", name="plug")
            self.assertTrue(res["dryRun"])
            self.assertFalse(SITE.public()["router"]["writes"])


class TestSiteRoutes(T.Base):
    def test_site_layout_setup(self):
        s, d = self.get("/api/site")
        self.assertEqual(s, 200)
        self.assertEqual((d["owner"], d["router"]["type"], d["router"]["deviceId"], d["host"], d["problems"]), ("Alex", "asuswrt", "router-xt8", "mac-mini", []))
        self.assertEqual(d["network"]["subnet"], "10.20.0.0/24")
        self.assertEqual([h["id"] for h in d["handsOff"]], ["macbook-work"])
        self.assertIn("router-xt8", d["protected"])
        self.assertNotIn("sshKey", json.dumps(d))
        self.assertNotIn("tokenFile", json.dumps(d))
        s, d = self.get("/api/layout")
        self.assertEqual((s, d), (200, {"problems": []}))
        with open(os.environ["HM_LAYOUT"], "w") as f:
            f.write("{nope")
        try:
            s, d = self.get("/api/layout")
            self.assertEqual(s, 200)
            self.assertEqual(list(d), ["problems"])
            self.assertTrue(d["problems"])
            with open(os.environ["HM_LAYOUT"], "w") as f:
                json.dump({"schema": 1, "wiring": {"world": {"w": 10, "h": 10}}}, f)
            self.assertEqual(self.get("/api/layout")[1], {"schema": 1, "wiring": {"world": {"w": 10, "h": 10}}, "problems": []})
        finally:
            os.remove(os.environ["HM_LAYOUT"])
        s, d = self.get("/api/setup")
        self.assertEqual(s, 200)
        self.assertEqual(set(d), {"siteConfigured", "inventoryDevices", "layoutPresent", "knowledgeFiles", "routerType",
                                  "routerReachable", "haConfigured", "claudeCli"})
        self.assertTrue(d["siteConfigured"])
        self.assertGreater(d["inventoryDevices"], 10)
        self.assertEqual((d["layoutPresent"], d["routerType"], d["haConfigured"]), (False, "asuswrt", False))
        self.assertEqual(d["knowledgeFiles"], 2)
        self.assertEqual(d["claudeCli"], os.environ["HM_CLAUDE_BIN"])

    def test_router_route_says_when_reading_is_off(self):
        with env(HM_SITE=with_site(router={"type": "none"})):
            orig = server.MONITOR.router
            server.MONITOR.router = R.Router(ssh=FakeSSH())
            try:
                s, d = self.get("/api/router")
                self.assertEqual((s, d["configured"], d["ok"], d["type"], d["enabled"], d["routerWrites"]), (200, False, False, "none", False, False))
                self.assertIn("not set up", d["error"])
                s, d = self.post("/api/router/login", {"username": "admin", "password": "x"})
                self.assertEqual((s, d["ok"]), (200, False))
                s, acts = self.get("/api/device/tv-philips/actions")
                self.assertEqual({a["id"]: a["unavailableReason"] for a in acts}["block"], "Router reading is not set up.")
            finally:
                server.MONITOR.router = orig


class TestEmptyHouse(unittest.TestCase):
    """No data/inventory.json, no data/site.json, no data/layout.json and an empty knowledge folder."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="hoh-empty-")
        os.makedirs(os.path.join(cls.dir, "knowledge"))
        cls.env = {"HM_STATE_DIR": os.path.join(cls.dir, "state"), "HM_INVENTORY": os.path.join(cls.dir, "inventory.json"),
                   "HM_SITE": os.path.join(cls.dir, "site.json"), "HM_LAYOUT": os.path.join(cls.dir, "layout.json"),
                   "HM_KNOWLEDGE": os.path.join(cls.dir, "knowledge"), "HM_KNOWLEDGE_DIR": os.path.join(cls.dir, "knowledge")}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_server_boots_and_every_get_answers(self):
        e = {k: v for k, v in os.environ.items() if not k.startswith(("HM_", "HOH_"))}
        e.update(self.env, HM_PORT="0", HM_NO_COLLECTORS="1", HM_SENTINEL="0", HM_QUIET="1", HM_NO_IDENTIFY="1",
                 HM_ROUTER_SSH="0", HM_CLAUDE_BIN=os.path.join(self.dir, "no-claude"))
        proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py")], env=e, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            line = proc.stderr.readline()
            m = re.search(r"http://127\.0\.0\.1:(\d+)", line)
            self.assertTrue(m, line + (proc.stderr.read() if proc.poll() is not None else ""))
            port = int(m.group(1))
            for path in ("/api/health", "/api/inventory", "/api/live", "/api/router", "/api/events", "/api/audit", "/api/settings",
                         "/api/reporters", "/api/agent/runs", "/api/threats", "/api/site", "/api/layout", "/api/setup"):
                with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=10) as r:
                    self.assertEqual(r.status, 200, path)
                    doc = json.loads(r.read().decode())
                if path == "/api/inventory":
                    self.assertEqual(doc["devices"], [])
                    self.assertEqual(doc["links"], [])
                if path == "/api/setup":
                    self.assertEqual(doc, {"siteConfigured": False, "inventoryDevices": 0, "layoutPresent": False, "knowledgeFiles": 0,
                                           "routerType": "none", "routerReachable": None, "haConfigured": False,
                                           "claudeCli": os.path.join(self.dir, "no-claude")})
                if path == "/api/site":
                    self.assertEqual((doc["owner"], doc["router"]["type"], doc["configured"], doc["problems"]), ("you", "none", False, []))
                if path == "/api/layout":
                    self.assertEqual(doc, {"problems": []})
                if path == "/api/router":
                    self.assertIn("not set up", doc["error"])
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen("http://127.0.0.1:%d/api/device/nope" % port, timeout=10)
            self.assertEqual(cm.exception.code, 404)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
            proc.stdout.close()
            proc.stderr.close()
        self.assertFalse(os.path.exists(self.env["HM_INVENTORY"]))          # reading never writes one

    def test_collectors_and_sentinel_run(self):
        with env(**self.env):
            m = C.Monitor(settings_fn=lambda: {"scanning": True, "scanIntervalSec": 30})     # the real inventory loader
            m.wiring_on = False             # this Mac's own sockets: nothing to lay them over in an empty house
            orig = C.sweep
            C.sweep = lambda network=None, workers=64: {}
            try:
                results, links = m.cycle(sweep_now=True)
            finally:
                C.sweep = orig
            self.assertEqual((results, links), ({}, {}))
            with open(os.path.join(self.env["HM_STATE_DIR"], "live.json")) as f:
                live = json.load(f)
            self.assertEqual(live["devices"], {})
            self.assertFalse(live["router"]["configured"])
            self.assertFalse([k for k, v in m.health.items() if not v.get("ok")], m.health)
            home = os.path.join(self.dir, "home")
            os.makedirs(home, exist_ok=True)
            eng = S.Engine(cfg=S.Config(home=home, sysroot=os.path.join(self.dir, "sys"), run=lambda argv, timeout=10, **kw: (127, "", "")),
                           store=S.Store(os.path.join(self.dir, "sentinel")), enabled=True)
            for name in ("network", "secrets"):
                st = eng.run_scanner(name)
                self.assertTrue(st["ok"], st)
            self.assertEqual([f for f in eng.store.listing() if f["scanner"] == "network"], [])

    def test_identify_creates_the_first_inventory(self):
        with env(**self.env):
            res, backup = X._write_inventory(lambda inv: inv["devices"].append({"id": "lamp", "name": "Lamp"}) or "lamp")
            self.assertEqual((res, backup), ("lamp", None))
            self.assertEqual([d["id"] for d in C.load_inventory()["devices"]], ["lamp"])
            os.remove(self.env["HM_INVENTORY"])


import atexit  # noqa: E402
atexit.register(shutil.rmtree, TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()


class TestShortFolderName(unittest.TestCase):
    """The guard matches the repo folder only as a path component: a clone in ~/hub must not refuse `github`."""

    def test_short_names_do_not_refuse_ordinary_commands(self):
        import agent_runner as A
        old = A.ROOT
        try:
            for root in ("/Users/x/c", "/Users/x/hub"):
                A.ROOT = root
                name = os.path.basename(root)
                self.assertTrue(A.guard_command("echo hello", None)["ok"])
                self.assertTrue(A.guard_command("git ls-remote https://github.com/a/b", None)["ok"])
                self.assertFalse(A.guard_command("rm ~/%s/server.py" % name, None)["ok"])
                self.assertFalse(A.guard_command("cat ../%s/agent_runner.py" % name, None)["ok"])
        finally:
            A.ROOT = old
