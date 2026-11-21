---
name: router-access
description: Set up (or decide against) read access to the home router for Home Observability Hub. Use when the person wants the hub to read the router's client list, when discovery names the router family, when router.type in data/site.json is being set, or when someone says "connect the router", "router access", "SSH key for the router", "can it see my mesh", "my router is a Fritz!Box / UniFi / Eero".
---

# Router access

With router access the hub knows every client the router knows (also the quiet ones that ignore ping),
which mesh unit each Wi-Fi device uses, its signal, and the router's own security settings. Without it
the hub still finds devices by ping sweep, mDNS and SSDP: router access is an improvement, not a
requirement. Ask before setting anything up, and say what it gives.

**Never ask for, type, store or echo the router's password.** Not in a file, not in a command, not in
this chat. The hub reads the router with an SSH key (AsusWRT) or, if the person chooses it later in the
web app, a login they type into the hub's own form, which stores it in the macOS Keychain. You never
see it. Never read `~/.config/home-observability-hub/` (the private key lives there), `~/.ssh` or the
Keychain.

## What the scan found

`python3 bin/hoh scan --json` → `router`: `family`, `brand`, `confidence`, `basis` (each with its source),
and `model` only when the router named itself over SSDP. Confirm brand and model with the person
before writing them into the inventory.

## AsusWRT and ZenWiFi (family `asuswrt`)

Supported: RT-AX/AC/BE, GT-, TUF-, ZenWiFi (XT8, XT9, ET8, BQ16 …), ROG Rapture, and Asuswrt-Merlin.

1. Explain: "I can create a key on this Mac that lets the hub read the router's client list over SSH.
   It reads only; it never changes a router setting. You paste the public half into the router's page."
2. Run `python3 bin/hoh router setup-key` (add `--user <name>` if their router login is not `admin`:
   the SSH user is the router's admin login name). It creates
   `~/.config/home-observability-hub/router_ed25519` (mode 600, folder 700), prints the **public** key and
   these steps, then tests:
   - open `http://<gateway>` and log in as usual;
   - **Administration > System**;
   - **Enable SSH: LAN only** (never "LAN & WAN"), port 22;
   - **Allow Password Login: No**;
   - **Authorized Keys**: paste the public key line;
   - **Apply**, wait about 30 seconds.
3. When they say done: `python3 bin/hoh router setup-key --test`. It runs one read-only command
   (`nvram get productid`) and prints the model the router reports: that is a `live` claim for the
   router's `model`.
4. Write in `data/site.json`: `"router": {"type": "asuswrt", "deviceId": "<router id>", "user": "<name>",
   "sshKey": "~/.config/home-observability-hub/router_ed25519", "writes": false}`. `writes` stays false
   (the hub can then only rehearse blocking a device). Turning it on is the person's own decision in the
   web app's settings, never part of setup.
5. Mesh nodes: the router lists them; add each as a device (`kind: "access-point"`, probe `ping`) and a
   link `cable: "mesh"` (wireless backhaul) or `ethernet` (wired backhaul, if the person says so).

If the test fails: "refused the key" (not pasted, or pasted with a line break, or the user name is
different), "SSH is switched off" (step 3 not applied), "no answer" (Local Network permission, see
`/doctor`). `python3 bin/hoh doctor` repeats the check.

## Other routers

Set `"router": {"type": "none", "deviceId": "<router id>"}`. Tell the person plainly what that means:

| family | what is possible |
|---|---|
| Fritz!Box | No client-list reading in this version. TR-064 exists but needs the router password; not used. |
| UniFi | No reading in this version (the controller API needs a login). The UniFi app shows clients. |
| TP-Link, Deco, NETGEAR, Orbi, Linksys | No local read access without the admin password; not used. |
| Eero, Google/Nest Wifi | Cloud-only management; nothing local to read. |
| MikroTik, OpenWrt | SSH exists, but this version only speaks AsusWRT. |
| an internet provider's box | Usually locked; nothing to read. |

In every case the hub still finds devices by sweep, mDNS and SSDP, and the person can look at their
router's own app for the client list and tell you names (record those as `reported`).
Never try a router's default password, never post a login form, never "just check" an admin page past
its landing page.
