---
name: device-identification
description: Evidence rules for saying what a device on the home network is. Use when naming an unknown host, deciding whether a model is confirmed, writing vendor/model/verified/identifiedBy in data/inventory.json, reading a MAC prefix or a randomized MAC, or when someone asks "what is this device", "what is 192.168.x.y", "identify the unknown devices", "is this my printer".
---

# Device identification

The rule that everything else follows: **never state a product that the evidence does not show.**
A wrong model on the map is worse than "not identified": people trust the map, and the fix agent
reads it before it answers.

## Claims and leads

`python3 bin/hoh scan --json` (discover.py) gives every host a `leads` list. Each lead has a `kind`:

| kind | what it is | may set `model`? |
|---|---|---|
| `claim` | the device names its own product: SSDP device description (`manufacturer`, `modelName`), an mDNS TXT model field (`md=` on `_googlecast`, `model=` on `_airplay`, `ty=` on `_ipp`), the Cast API's device description | yes, with `verified: "live"` |
| `candidate` | a lead: MAC prefix, hostname, open port, advertised service type, private MAC | **no** |

The person saying what it is also settles it (`identifiedBy: "person"`, `verified: "reported"`), and so
does an order confirmation or invoice they show you, or the label on the device they read out or photograph.

What each candidate source really tells you:

- **MAC prefix (OUI vendor)** names the maker of the *network chip*, not the product. Espressif, MXCHIP,
  Tuya, Murata, AzureWave, Realtek, USI, Hon Hai/Foxconn, Liteon, Universal Global Scientific are module
  makers: the brand on the box is almost always someone else (`oui.is_module_maker`). Even "Apple" or
  "Samsung" only says who made the radio.
- **Private (randomized) MAC**: the locally administered bit is set (second hex digit 2, 6, A or E).
  Phones, tablets, watches and laptops use one per Wi-Fi network. No maker can be read from it, and it
  can change when the device forgets the network. Never key an identity on it alone.
- **Hostname** (reverse DNS at the router, mDNS): set by the device or its owner. `iPhone`, `Galaxy-S23`,
  `HP1A2B3C` are good leads; `espressif`, `lwip0`, `mxchip` only say "small embedded device".
- **Open ports**: 8008/8009 Cast, 1400 Sonos, 631/9100 printer, 554 camera, 62078 iPhone/iPad sync,
  8123 Home Assistant, 445 file sharing. A port is a lead about the *type*, never the model.
- **Service types** (mDNS): `_hap` HomeKit accessory, `_matter` Matter, `_companion-link` Apple device,
  `_raop`/`_airplay` AirPlay receiver.
- **Cast name / SSDP friendlyName** is a name the owner gave it ("Living Room speaker"): useful to ask
  about, not a model.

## Asking the person

Group unknown hosts so each question is quick, and offer the leads as answer options
(AskUserQuestion, at most 4 options; "Other" is always there):

> 192.168.1.53: a small Wi-Fi gadget (name "mxchip", chip by MXCHIP), on since the last scan. What is it?
> options: "A smart plug or switch", "A kitchen or laundry appliance", "Not mine / I don't know", (Other)

Tell them how to find out when they do not know: unplug the suspect and rescan; read the device's app
(most apps show the device's IP or MAC under device info); look at the router's client list.
Something nobody can name goes in `openQuestions`, never guessed into the inventory.

## Writing it into data/inventory.json

The hub derives each device's identity state from these fields (identify.py `base_identity`):

| what you know | write | resulting state |
|---|---|---|
| a probe claim names vendor and model | `vendor`, `model`, `verified: "live"`, the claim in `facts.identifiedFrom` | confirmed |
| the person says what it is | `vendor`, `model` as they said, `verified: "reported"`, `identifiedBy: "person"`, `identifiedAt: "<ISO date>"` | confirmed |
| the maker is clear, the model is not | `vendor`, and `model` written with a hedge: `"Smart plug (model not confirmed)"` | likely |
| only leads | `vendor` omitted or the module maker named as such in `facts`, `kind: "unknown"` or the type the person agreed to, `model` like `"not identified"`, candidates in `facts.candidates` | unidentified |

Words in `model` that keep it from being read as confirmed: "not confirmed", "not identified",
"unidentified", "likely", "probably", "unknown", "candidate". Use them honestly; do not use them to
hedge something a probe confirmed.

`verified` on a device, net entry or link:

- `live`: a probe on this Mac saw it in this session (ping, mDNS, SSDP, Cast, system_profiler, ioreg, the
  router's client list). Say which in `evidence` or the net entry's `note`.
- `reported`: the person said so, or an order email / label they showed.
- `plan`: drawn but not confirmed by anyone (a cable you inferred, a room you assumed).

Never upgrade `plan` or `reported` to `live` without a probe. Never write a model from memory of what
"usually" sits at an address.

Hands-off devices (a work laptop, a housemate's computer): record what is visible (name, address,
`verified: "live"`), put them in `data/site.json` `handsOff` with `why`, and never port-scan, research or
propose anything for them.
