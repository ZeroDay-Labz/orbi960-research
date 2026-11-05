# orbi-owner-agent — network / VLAN capability matrix

Produced for Phase 2 of directive 705a.
Evidence date: 2026-11-04 (initial pass) and 2026-11-05 (revision after
directive 705a corrections: full 0–127 swconfig slot enumeration + full
HYD UCI/generated-conf dump).
Scope: RBRE960 live-verified; RBSE960 inferred from rootfs (no live sat access).

All platform conclusions below are grounded in live `swconfig`/`brctl`/`ip`/
`/proc/net/vlan/config`/`lsmod`/`ubus`/`uci show` output in
`_evidence/live_master_recon.txt` and `_evidence/live_master_recon_20261105.txt`,
cross-checked against the extracted rootfs.

**Evidence scope note (per 2026-11-05 corrections):**

- "swconfig view" throughout this document means the visible state via the
  legacy `swconfig dev switch0 ...` surface. QCA HPPE is managed in
  practice by the Qualcomm SSDK/NSS stack; HW state programmed through
  `ssdk_sh` or NSS-internal APIs may not surface through swconfig. We did
  not run `ssdk_sh`-based queries this turn.
- The `vlan_create` method shipped in the agent creates only the Linux
  802.1Q sub-interface layer. It does NOT by itself establish physical
  switch VLAN membership, wireless SSID assignment, routing, firewall
  isolation, DHCP service, or NSS flow-cache compatibility. Each of
  those layers is a separate dependency, documented per-row below and
  summarized in `known-limitations.md`.

---

## 1. Switch architecture

| field | value | evidence |
|---|---|---|
| Switch IC | QCA HPPE (Hardware Packet Processing Engine), 128 VLAN slots exposed | live `swconfig list` → `Found: switch0 - QCA HPPE` |
| Driver stack | QCA SSDK + HPPE kernel stack (vendor); legacy swconfig is one front, `ssdk_sh` is the vendor-native front, NSS stack is the in-kernel data path | `/usr/sbin/ssdk_sh` (697 KB) present on both RBRE and RBSE rootfs; `qca_nss_drv` loaded (1.65 MB) |
| DSA support | absent (kernel 4.4 pre-DSA-mainline; no `drivers/net/dsa/*` artefacts) | no DSA interfaces in `ip link`; no `br-*` with `vlan_filtering` in `ip -d link show br-lan` (bridge VLAN filtering is the DSA/switchdev replacement for swconfig; neither surface is in use here) |
| Primary API in stock firmware | undetermined — vendor scripts call BOTH `swconfig` and `ssdk_sh`; actual steering path not confirmed | we inspected the swconfig view only; `ssdk_sh` queries were NOT run this turn |
| 2026-11-05 swconfig-view enumeration | all 128 VLAN slots (0–127) returned `vid=0 ports=[]` | `_evidence/live_master_recon_20261105.txt` — 128/128 slots inspected |

**Implication (revised 2026-11-05):**

- The **swconfig view** of hardware VLAN state is uniformly empty across
  all 128 HPPE slots on the live master.
- This proves only that stock firmware does not program VLANs through
  the legacy swconfig surface; it does NOT prove the HPPE holds no
  VLAN state, because the SSDK/NSS path can program VLAN state the
  legacy swconfig front does not expose.
- For the owner-agent's initial Phase-A scope, `vlan_create` writes at
  the Linux 802.1Q layer only, using the same pattern the stock
  firmware demonstrably uses for VLAN 4093/4094 (software VLAN sub-
  interface + bridge membership). We deliberately do NOT program
  HPPE-level VLAN state via `swconfig vlan N set` or `ssdk_sh`, and we
  flag this as a known limitation: switch-ingress untagged traffic
  will not be VLAN-tagged by the hardware for owner-created VLANs
  until a Phase-B investigation has reverse-engineered the vendor's
  SSDK/NSS programming path.

---

## 2. Bridge VLAN filtering

Not in use on this firmware. Both bridges (`br-lan`, `br-guest`) are plain
Linux bridges (not VLAN-aware). VLAN separation is achieved by **binding
pre-tagged (`eth2.4093`-style) and untagged interfaces to different bridges**,
not by setting `bridge vlan` filters on a single aware bridge. Evidence:

```
br-guest  …  interfaces = ath01, ath11.4093, ath12, ath2.4093,
                           eth0.4093, eth1.4093, eth2.4093, eth3.4093
br-lan    …  interfaces = ath0, ath02, ath1, ath11.4094, ath13,
                           ath2.4094, ath3, ath31, eth0, eth1, eth2, eth3
```

This is the **classic OpenWrt "per-VLAN interface in its own bridge" pattern**,
not the modern `bridge vlan_filtering 1` pattern. Our owner-agent targets this
model (simpler, well-supported on kernel 4.4).

---

## 3. 802.1Q VLAN sub-interface creation (kernel layer only)

**Kernel layer confirmed functional.** The 8021q kernel module is
**built into the kernel** (not shipped as a `.ko`), evidenced by:

- No `8021q.ko` under `lib/modules/4.4.60/` in either RBRE or RBSE rootfs.
- `lsmod` grep for `^8021q ` returns nothing → not loaded as a module.
- `cat /proc/net/vlan/config` (2026-11-05 live) shows exactly 8 VLAN
  sub-interfaces present: `eth0.4093`, `eth1.4093`, `eth2.4093`,
  `eth3.4093`, `ath11.4093`, `ath11.4094`, `ath2.4093`, `ath2.4094`.
  Only VIDs 4093 and 4094 are in use.
- `ip -d link show ath11.4094` reports
  `vlan protocol 802.1Q id 4094 <REORDER_HDR>` and `master br-lan` —
  the stock vendor pattern is Linux-8021q sub-interface + plain bridge
  membership.

In the owner-agent's `vlan_create` method, `ip link add link <phys>
name <phys>.<vid> type vlan id <vid>` is expected to work without any
module-load step.

### Important scope limitation (per 2026-11-05 corrections)

Creating a Linux 802.1Q sub-interface is **only one layer** of a
complete VLAN deployment. The agent's `vlan_create` performs that one
layer and nothing more. End-to-end VLAN operation requires, each
separately:

| layer | required for | handled by `vlan_create`? | status |
|---|---|---|---|
| Kernel 802.1Q sub-interface | sub-interface to exist, carry tagged traffic to/from the CPU | **yes** | functional — same pattern as stock |
| UCI `config interface '<name>'` + `ifname` wiring | netifd to keep the sub-interface up and in a bridge across reboots | **yes** (`owner_v<id>` + `owner_<name>`) | functional at the UCI level; not runtime-tested |
| Switch-level VLAN port membership (HPPE VLAN programming) | untagged ingress traffic on physical switch ports to be tagged correctly before reaching the CPU | **no** | NOT programmed — see §1 and the NSS/SSDK caveat |
| Wireless SSID-to-VLAN binding (hostapd + MAP) | a wireless SSID's traffic to be placed on a specific VLAN | **no** | deferred — see §6, §7 and `known-limitations.md` |
| Routing (netifd/network kernel FIB) | the VLAN subnet to be reachable from other subnets through the master | **no** | owner must configure separately through UCI, or via a later agent method |
| Firewall isolation (`arno-iptables-firewall` on master; fw3 on sat) | the VLAN to be security-isolated from others | **no** | deferred — see §9 and `known-limitations.md` |
| DHCP service (dnsmasq config) | hosts on the VLAN to obtain IP addresses | **no** | out of Phase-A scope |
| NSS flow-cache compatibility | accelerated flows to respect the new VLAN topology and any firewall rules on it | **no** | unverified — stock precedent for VLAN 4093 on br-guest suggests it works, but we have not stress-tested owner VLANs |

**Therefore:** `vlan_create` is a **VLAN sub-interface creator**, not a
complete VLAN deployer. The agent documentation (`architecture.md` and
`known-limitations.md`) must describe it this way; the capability
matrix below does too.

---

## 4. netifd and VLAN configuration surface

`/lib/netifd/proto/` on-device: `464xlat.sh 6rd.sh dhcp.sh dslite.sh l2tp.sh
map.sh ppp.sh tayga.sh`. Standard OpenWrt set minus `pppoa` and `pptp`, plus
`6rd`. **No `vlan.sh`** — matches OpenWrt convention (VLAN is a netifd
built-in handled via `ifname=eth0.100` or UCI `config interface` with
`ifname eth0.100`).

`/etc/config/network` on live uses the stock-style syntax:

```
network.loopback=interface
network.globals=globals
network.@switch[0]=switch
network.lan=interface
network.wan=interface
network.wan6=interface
network.guest=interface
network.eth0..eth4=interface   (device-named interfaces for per-port roles)
```

This confirms the owner-agent can define a new `config interface 'owner_mgmt'`
section with `option ifname 'br-lan.NNN'` or similar and `/etc/init.d/network
reload` will apply it (standard OpenWrt UCI flow).

---

## 5. Hardware acceleration (NSS / ECM) and its effect on steering

The master's `lsmod` shows a rich QCA-NSS stack:

```
acos_nat             1478656    (vendor NAT in kernel, 1.4 MB)
qca_nss_cfi_cryptoapi  … (NSS crypto)
ecm                  (Enhanced Connection Manager, QCA NSS shortcut layer)
bonding              131072     (loaded by ecm)
asf                  16384      (QCA packet-processing)
br_hijack            122880     (vendor bridge hijack — steers packets to NSS)
br_packet_filter     16384      (vendor netfilter-bridge hook)
```

**What this means:** NSS/ECM attempts to shortcut flows around the Linux
netfilter path for performance. Historically on NSS platforms, this can cause
iptables rules and policy routing to be **bypassed** once a flow is accelerated.
UCI firewall changes still take effect on the slow path (new flows, control
traffic) but established accelerated flows may ignore rule changes until
`echo flush > /proc/sys/net/sf_ipv4_flow_track` or equivalent clears the cache.

**Owner-agent implication:** any firewall / segmentation action MUST pair the
rule change with an NSS flow-cache flush helper, or document that the change
takes effect "for new connections only." This is documented in
`docs/known-limitations.md` (Phase 4 deliverable).

The exact flush-knob path is **not confirmed live** (requires further recon
without running `echo > ...`, which would be a write and is forbidden). Phase 4
will ship a helper script that detects the knob at install time from well-known
NSS paths (`/sys/kernel/debug/ecm/*/stop`, `/proc/net/nss/*`) and uses whatever
is present.

---

## 6. Wireless VLAN — hostapd capabilities and HYD UCI schema

### 6.1 hostapd compile-time capability (binary evidence)

`strings` on `/usr/sbin/hostapd` (rbre_7288 rootfs) yields the symbol/config
tokens:

```
vlan_bridge
dynamic_vlan
vlan_file
vlan_naming
```

All four are **compile-time options** of upstream hostapd:
- `dynamic_vlan` — per-station VLAN assignment from RADIUS or `vlan_file`.
- `vlan_file` — static station-MAC → VLAN mapping file.
- `vlan_bridge` — the bridge each VLAN station interface joins.
- `vlan_naming` — controls per-VLAN interface naming scheme.

This proves the binary supports those features; it does NOT prove any
specific SSID is configured to use them.

### 6.2 HYD UCI schema (live config evidence, 2026-11-05)

Live `uci show hyd` (filtered to VLAN-related keys) returns:

```
hyd.config.SwitchInterface='auto'
hyd.config.SwitchLanVid='1'
hyd.@Vlanid[0].ifname='eth1'   hyd.@Vlanid[0].vid='4094'
hyd.@Vlanid[1].ifname='eth0'   hyd.@Vlanid[1].vid='4093'
hyd.MultiAP.NumberOfVLANSupported='0'
hyd.MultiAP.Map2TrafficSepEnabled='0'
hyd.MultiAP.Map8021QPCP='0'
hyd.MultiAP.VlanIDNwPrimary='0'
hyd.MultiAP.VlanIDNwOne='0'
hyd.MultiAP.VlanIDNwTwo='0'
hyd.MultiAP.VlanIDNwThree='0'
```

**Interpretation (CONFIRMED configuration-schema evidence, not
capability-proof):**

- Two schema surfaces coexist in `/etc/config/hyd`:
  1. **`@Vlanid[*]`** sections — `(ifname, vid)` pairs that become the
     `VlanIds=` list in the generated `/tmp/hyd-*.conf` files. This is
     the surface the stock mesh uses for VLAN 4093/4094.
  2. **`MultiAP.*`** keys — WiFi-Alliance Multi-AP SSID-to-VLAN
     separation (`NumberOfVLANSupported`, `Map2TrafficSepEnabled`,
     `Map8021QPCP`, `VlanIDNwPrimary/One/Two/Three`). These are all 0
     on the live master. **The Multi-AP SSID-to-VLAN separation
     feature is schema-defined but currently inactive.**
- Both surfaces appear in the generated conf files (`/tmp/hyd-lan.conf`,
  `/tmp/hyd-guest.conf`) at known line ranges; see
  `_evidence/live_master_recon_20261105.txt` for the verbatim grep.

### 6.3 UCI → HYD translator (reverse-engineered 2026-11-05)

The code paths that turn UCI config into HYD config are:

- `/lib/functions/hyfi-iface.sh::hyfi_get_iface_vlanids()` iterates all
  `@Vlanid[*]` sections and builds the comma-separated list
  `ifname1.vid1,ifname2.vid2,...`.
- `/lib/functions/hyfi-iface.sh::__hyfi_get_switch_lan_vid()` reads
  `hyd.config.SwitchLanVid`.
- `/lib/functions/hyfi-iface.sh::__hyfi_get_switch_cpu_port()` walks
  `/etc/config/network`'s `switch_vlan` sections, finds the one matching
  `lan_vid`, and extracts the CPU port.
- `/etc/init.d/hyd` (around line 318–332) calls those helpers and
  appends `SwitchLanVid=`, `SwitchCpuPort=`, `SwitchDeviceId=`, and
  `VlanIds=` to the per-bridge HYD conf file.

This matches the live example precisely:

```
hyd.@Vlanid[0] = eth1:4094
hyd.@Vlanid[1] = eth0:4093
hyd.config.SwitchLanVid = 1
  →  /tmp/hyd-lan.conf   : VlanIds=eth1.4094,eth0.4093 ; SwitchLanVid=1
  →  /tmp/hyd-guest.conf : VlanIds=eth1.4094,eth0.4093 ; SwitchLanVid=1
```

**What the translator covers:** adding an `@Vlanid[*]` section with an
`(ifname, vid)` pair causes hyd to carry that VLAN tag on that interface
(wired or wireless sub-interface). This is a known-capability path.

**What the translator does NOT cover:** the `MultiAP.*` SSID-to-VLAN
separation keys. That is a separate subsystem (Multi-AP spec; routes
through `/etc/config/MAP`, hostapd and `repacd`), and is currently
disabled. **Reverse-engineering the MAP SSID-to-VLAN wiring path is
Phase-B work** — not done this turn; the owner-agent's Phase-A scope
does NOT expose an SSID-to-VLAN method until that path is studied.

### 6.4 Live confirmation of the stock wireless VLAN pattern

`ath11.4093` → bridged to `br-guest`, state UP, forwarding (2026-11-05).
`ath11.4094` → bridged to `br-lan`, state UP, forwarding.
`ath2.4093` → bridged to `br-guest`, state UP, forwarding.
`ath2.4094` → bridged to `br-lan`, state UP, forwarding.

Each reports `vlan protocol 802.1Q id <vid> <REORDER_HDR>` — exactly
the Linux-8021q sub-interface + bridge pattern described in §3. The
stock VLAN deployment is **not** through hostapd `dynamic_vlan`
(which would have per-station vifs). It is through a fixed VLAN
sub-interface on the AP `ath*` phy, driven by the HYD `@Vlanid[*]`
mechanism. Owner-added VLANs would use the same mechanism.

**Therefore, for the master:**

- Adding a VLAN tag to an existing interface via HYD (`@Vlanid`) is a
  known-capability path — but it still requires `hyd` + `wsplcd`
  restart to take effect, and we have not validated this live for an
  owner-added entry. Phase-B work.
- Adding a **new SSID** that is mapped to a **specific VLAN** via the
  Multi-AP schema is NOT a known-capability path on this firmware
  until the MAP + hostapd + repacd code paths are studied. The
  schema exists; the implementation path is uninvestigated.

---

## 7. Multiple SSIDs / radios → VLANs (qualified)

`/etc/config/wireless` live output (top-level section headers only, no secrets):

```
config wifi-device 'wifi0'   # 2.4 GHz radio
config wifi-device 'wifi1'   # 5 GHz low
config wifi-device 'wifi2'   # 5 GHz high / backhaul
config wifi-device 'wifi3'   # 6 GHz

config wifi-iface 'FhAp2'    # fronthaul 2.4 GHz
config wifi-iface 'FhAp5'    # fronthaul 5 GHz
config wifi-iface 'FhAp6'    # fronthaul 6 GHz
config wifi-iface 'BhAp2'    # backhaul 2.4 GHz (AP side on master)
config wifi-iface 'BhAp5'    # backhaul 5 GHz
config wifi-iface 'Guest2'   # guest SSID 2.4 GHz
…
```

`/usr/sbin/iw dev` reports **17 interfaces** across the 4 radios. The bridge
listing shows these are already apportioned: `ath0`/`ath1`/`ath2`/`ath3` =
fronthaul APs per radio; `ath0?` = guest APs; `ath1?.4094` = backhaul AP VLANs.

**Qualification (per 2026-11-05 corrections):** the fact that multiple
SSIDs exist and are bridged, and that hostapd contains the
`dynamic_vlan`/`vlan_bridge`/`vlan_file`/`vlan_naming` compile-time
options, does not by itself prove that arbitrary **new** SSID-to-VLAN
mappings can be driven from UCI through to running hostapd state
without:

1. Reverse-engineering the UCI→MultiAP SSID-to-VLAN translator path
   (`hyd.MultiAP.*` schema + whichever `/lib/functions/*.sh` helpers
   project it into generated hostapd/hyd config). The `@Vlanid[*]` →
   `VlanIds=` path IS reverse-engineered (§6.3); the MAP SSID-to-VLAN
   path is NOT.
2. Validating `hyd` + `wsplcd` restart behavior for the owner-added
   SSID entry without disrupting the live mesh. The master runs two
   HYD instances (`-P 7777` for br-lan, `-P 8888` for br-guest); a
   wrong restart sequence could drop the live sat backhaul.
3. Propagating the SSID change to the satellites via the vendor's
   repacd/Multi-AP onboarding channel, which we have not investigated.

**Status of the "SSID-to-VLAN" method in the owner-agent:** deferred
to Phase B. The capability matrix row for "Wireless SSID → VLAN" is
downgraded from ✓ to ◇ accordingly (see §11).

---

## 8. Backhaul coexistence

Mesh backhaul uses **VLAN 4093 (guest-tagged) and VLAN 4094** on the shared
`ath11` wireless phy *and* on wired `eth0-3` ports, per the `brctl show`
output in section 2 above. Explicitly: adding a new client-facing SSID or a
new VLAN on the wired switch does NOT interfere with 4093/4094 traffic
because they are handled on distinct tagged subinterfaces, each in its own
bridge.

**Constraint:** VLAN IDs **4093 and 4094 are reserved** by the stock mesh. Any
owner-controlled VLAN must use a different VID. Owner-agent validates this
at configuration time (`vid < 4093 && vid > 0 && vid != 1`).

**Known-limit:** we cannot change the mesh backhaul VLAN IDs without
reprogramming NETGEAR's hyd/wsplcd/repacd stack, which is out of scope and
would break mesh pairing. The owner-agent's VLAN features sit **alongside**
the backhaul, not in place of it.

---

## 9. Wired + wireless VLANs in the same routing / firewall policy

Live `/etc/config` on master includes `network` but **no stock `firewall`
file** (master uses `arno-iptables-firewall` instead of fw3; see fingerprint
§4). This is a complication:

- A UCI `zone` on master is **not** the enforcement point; `arno-iptables-firewall`
  reads its own config at `/etc/arno-iptables-firewall/firewall.conf`.
- MEMORY.md notes: "firewall NOT uci-covered" — matches.

**Owner-agent policy:** on the **master**, firewall integration must either
(a) write `arno-iptables-firewall`-format rules into a dedicated
`/etc/arno-iptables-firewall/plugins/orbi-owner-*.conf`, or (b) emit raw
`iptables` rules via a procd-managed script that re-applies on every boot
(and on any flush event). Option (a) is cleaner and uses the vendor plugin
architecture.

On the **satellite** (per rootfs: fw3 present), standard UCI zone/forwarding
rules apply; owner-agent writes to `/etc/config/firewall` via `uci set` and
`fw3 reload`.

Inter-VLAN routing on the **master** is normal Linux-routing; adding a new
`config interface '<name>'` with `option proto 'static'` and `option ipaddr`/
`option netmask` gives the master an IP in that subnet, and routing works via
the kernel FIB. NSS acceleration (§5) applies to the forwarding path; flush
needed after rule changes.

---

## 10. Monitoring surface (telemetry inputs for the external controller)

On the master, ubus exposes (live):

```
log            — syslog read via ubus
network.*      — netifd state (device, interface, interface.<name>)
network.wireless — wifi status
orbi_wlparam   — NETGEAR WL params (RSSI, channel, …)
orbistats      — NETGEAR aggregate stats
satellite      — mesh satellite status
securebootstatus — secure-boot report
service        — procd service table
session        — rpcd session mgmt
system         — uptime/load/memory
uci            — config read via ubus
```

This is a **rich read-only surface** the owner-agent can expose over its own
authenticated channel to the Proxmox controller with no extra daemons needed.

On the satellite, the ubus registry is smaller (no live verification; from
rootfs plugin inventory the sat has `ntgr_stats.so` and `ntgr_wlparam.so`
rpcd plugins, same shape as master, plus the standard OpenWrt objects).

---

## 11. Capability matrix

Legend:
- ✓ = supported AND runtime-verified for the stock use-case
- ◇ = supported per code/config but not runtime-verified for owner-added use
- ◇-defer = capability exists at some layer but a specific layer blocks it from being driven by the owner-agent in Phase A; see Limitations column
- ✗ = not supported
- *o-o* = offline-only (rootfs evidence only, not live-verified)

| Feature | RBRE960 | RBSE960 | Evidence | Limitations |
|---|---|---|---|---|
| **802.1Q kernel VLAN sub-interface** | ✓ | ◇ *o-o* | live `/proc/net/vlan/config` (2026-11-05) shows 8 VLAN sub-ifaces with 4093/4094 on eth[0-3], ath11, ath2; 8021q kernel-builtin | VIDs 4093/4094 reserved for mesh/guest; owner VIDs must avoid them. **This is only one layer of a VLAN deployment** — see §3 end-to-end table |
| **VLAN-aware bridge (kernel)** | ✗ | ✗ | both bridges are plain (non-filtering) Linux bridges; no `vlan_filtering 1` observed | Agent uses "one tagged subinterface per VLAN per bridge" pattern (same as stock) |
| **swconfig-visible HPPE VLAN programming** | ◇-defer | ◇-defer *o-o* | 2026-11-05 live enumeration: all 128 swconfig slots return `vid=0 ports=[]`; stock firmware does NOT program VLANs through swconfig | HPPE may hold VLAN state through SSDK/NSS that swconfig does not expose. `vlan_create` deliberately does NOT program HPPE VLANs; untagged ingress traffic on physical switch ports is NOT auto-tagged by hardware for owner VLANs |
| **Wireless SSID → VLAN (owner-added)** | ◇-defer | ◇-defer *o-o* | hostapd binary supports `dynamic_vlan`/`vlan_bridge`/`vlan_file`/`vlan_naming`; HYD `@Vlanid[*]`→`VlanIds=` translator CONFIRMED (§6.3); Multi-AP SSID-to-VLAN schema present but values all 0 (§6.2) | Translator for `@Vlanid[*]` is understood; MAP SSID-to-VLAN translator path is NOT. hyd+wsplcd restart risk + sat propagation risk. Deferred to Phase B |
| **Inter-VLAN routing (kernel FIB)** | ◇-defer | *N/A* (sat does not route) | standard Linux FIB on master; interface-IP + zone-forwarding mechanism | `vlan_create` does NOT configure an IP on the new interface; owner must add `option ipaddr`/`option netmask` to the UCI `config interface` section, or wait for a Phase-B routing method. NSS/ECM shortcut may cache stale flows |
| **Firewall segmentation** | ◇-defer (arno) | ◇-defer (fw3) *o-o* | master = `/etc/arno-iptables-firewall/` script-driven (NOT uci-covered); sat = `/sbin/fw3` + `/etc/config/firewall` | Agent does NOT expose a firewall method in Phase A. Two different backends would be needed. |
| **DHCP service on owner VLAN** | ◇-defer | ✗ (sat does not serve DHCP) | dnsmasq present on master; can be driven via `/etc/config/dhcp` | Agent does NOT configure DHCP in Phase A |
| **NSS flow-cache compatibility for owner VLAN** | ◇-defer | ◇-defer | stock VLAN 4093 on br-guest works through NSS (precedent) | Not stress-tested for an owner-added VLAN. Rule changes may not propagate to accelerated flows without a cache flush; flush path is not confirmed |
| **Monitoring / telemetry (read-only)** | ✓ | ◇ *o-o* | rich ubus registry (network.*, satellite, orbistats, orbi_wlparam, system, service); `/sbin/logd` streamable | Read-only surface — safe to expose via owner-agent to external Proxmox controller |
| **Mesh backhaul compatibility** | ✓ | ◇ *o-o* | existing VLAN 4093/4094 trunks continue to function on all four ports + ath11/ath2; new kernel-layer VLAN sub-interfaces are additive at that layer | Do NOT change VIDs 4093/4094 or touch the QCA hyd/wsplcd/repacd stack |

---

## 12. Summary — acceptance questions 6–8 (revised 2026-11-05)

| Q | Answer |
|---|---|
| **Does the firmware support the required VLAN features?** | **Partially, with layer-by-layer qualifications.** The kernel 802.1Q sub-interface layer is active (stock VLAN 4093/4094). VLAN-aware bridges are NOT used (`CONFIG_BRIDGE_VLAN_FILTERING` absent); the stock per-VLAN-subinterface pattern is. Switch-level VLAN programming through `swconfig` is NOT in stock use (all 128 slots `vid=0 ports=[]`); HPPE state may still be managed through SSDK/NSS, which was not inspected this turn. Wireless SSID-to-VLAN at the HYD `@Vlanid[*]` layer has a known-and-verified translator path; at the Multi-AP SSID-mapping layer the schema exists but is inactive and its translator is not reverse-engineered. Firewall segmentation requires model-specific backends (arno on master, fw3 on sat), neither of which Phase-A integrates with. |
| **Which VLAN features are available only on the master?** | Inter-VLAN routing (sat is a pure AP/bridge). The HYD `@Vlanid[*]`→`VlanIds=` translator (exists on sat too but isn't owner-callable there). The user-facing Seal REST surface (CVE-2026-0415 territory; 7.2.8.5+ hardens it). The `arno-iptables-firewall` plugin surface for firewall policy. |
| **Which features are available on the satellites?** | Not covered by Phase A — no sat agent ships. Rootfs evidence: VLAN tagging kernel capability matches the master; hostapd has the same VLAN compile-time options; fw3 is present. The sat can transport and bridge-filter VLAN traffic; it does not route; sat-side agent deployment is blocked by CONFIRMED-ABSENT sat SSH (see `root-access-dependency.md` and reports 31/35/36/38). |

### Phase A scope (preserved per 2026-11-05 corrections)

The orbi-owner-agent Phase-A package:

- Is **source-complete** (25 files, offline tests pass).
- Has **NOT** been built into a signed or unsigned `.ipk` against the matching SDK.
- Has **NOT** been installed on any device (ROE forbids device-changing operations).
- Has **NOT** been exercised through rpcd on a live device (no live `ubus call orbi.owner.agent info` has been run against an installed instance).
- Has **NOT** had its `vlan_create`/`vlan_delete` methods validated against live traffic (no owner VLAN has been created on the live router in this investigation).

**Deferred to Phase B** (explicit list):

- Binary `.ipk` build against a matching OpenWrt Chaos Calmer 15.05.1 SDK.
- Target install + first-boot bootstrap verification.
- Live `ubus call` integration test (list, info, status, network, vlan_list, backup, audit_tail).
- Owner-added VLAN end-to-end validation: kernel sub-interface → bridge → switch port → routing → firewall → DHCP → NSS flow-cache.
- Wireless SSID-to-VLAN method, pending reverse-engineering of the UCI→Multi-AP translator and a safe hyd/wsplcd restart sequence.
- Satellite deployment, pending resolution of sat-side configuration propagation and sat SSH (currently CONFIRMED-ABSENT).

See `architecture.md` and `security-model.md` for how the owner-agent intends to exploit the capabilities above while respecting the stock mesh and NSS constraints, and `known-limitations.md` for the full list of deferred items.
