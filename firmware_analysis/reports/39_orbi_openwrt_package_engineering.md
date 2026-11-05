# Report 39 — Orbi owner-agent OpenWrt package engineering

Status: **Phase A — source-complete, not production-ready.** The source
tree builds the package definition and passes offline structural/
validator/plugin-interface tests. The following are explicitly
**not validated**: binary `.ipk` build, target installation, live rpcd
integration, and any live networking behavior of `vlan_create`/
`vlan_delete`. Wireless VLAN management and satellite deployment remain
deferred. A reproducible binary `.ipk` build is blocked on the matching
NETGEAR Chaos Calmer 15.05.1 SDK (or upstream CC 15.05.1 SDK + vendor
patches).

Evidence date: 2026-11-04 (initial pass); revised 2026-11-05 per
directive 705a corrections (full 0–127 swconfig enumeration + full HYD
UCI/generated-conf/translator dump).
Scope: NETGEAR Orbi RBRE960 master router,
V7.2.7.15_5.1.16 → V7.2.8.8 extracted firmware trees, plus live-master
read-only recon (owner-authorized SSH, **no device mutation**).

---

## 1. One-page summary

This report accompanies the package source tree at
`openwrt/orbi-owner-agent/` and the fork-produced platform
documentation in that tree's `docs/`.

- **Package**: `orbi-owner-agent` v0.1.0 — a small rpcd exec-plugin
  that piggybacks on the vendor's own ubus/rpcd authentication
  boundary. Pure shell + UCI + JSON, `arch: all`.
- **Namespace**: `orbi.owner.agent` with a 9-method allowlist
  (`info`, `status`, `network`, `vlan_list`, `audit_tail`, `backup`,
  `vlan_create`, `vlan_delete`, `rollback`).
- **Transport**: caller SSHes to the master as root (existing path)
  then calls `ubus call orbi.owner.agent <method>`. **No new network
  listener is introduced.**
- **External controller**: Proxmox-hosted (per MEMORY.md
  `orbi-owner-control-platform` entry). Responsible for auth, UI,
  dashboards, policy. The device-side agent does not implement any
  of these.
- **Owner SSH-provisioning on sats remains CONFIRMED-ABSENT.** No
  sat variant of this package is shipped.
- **`vlan_create` scope (per 2026-11-05 corrections):** creates a
  Linux 802.1Q sub-interface + its UCI `config interface` wiring
  only. It does NOT by itself establish physical switch VLAN
  membership, wireless SSID assignment, routing, firewall isolation,
  DHCP, or NSS flow-cache compatibility. These are documented
  per-layer in `docs/network-capability-matrix.md` and
  `docs/known-limitations.md`.

Three offline test scripts (layout, validators, plugin interface) all
pass. No command injection, path traversal, vendor-config write,
unsafe `eval`, or unreviewed system call appears in source. See
`openwrt/orbi-owner-agent/docs/security-model.md` for the full threat
model.

---

## 2. Methodology

- Offline rootfs inspection of all four extracted trees
  (`firmware_analysis/extracted/{rbre,rbse}_{7215,7288}/rootfs/`).
- Owner-authorized read-only SSH recon on the live master, via
  interactive sessions (per 2026-11-04 user clarification) and via
  `orbi_root_shell.py`. **No mutations** of any kind. All recon
  commands were explicit-read (`cat`, `ls`, `strings`, `swconfig
  show`, `ubus list`, `bridge link show`, `uci show`, `opkg list*`,
  `ps`, `mount`, `df`, `netstat -lnpt`, `file`, `ldd` was deliberately
  avoided).
- Platform fingerprint and capability matrix were produced by a
  background investigation fork; the deliverables live under
  `openwrt/orbi-owner-agent/docs/`.
- The Phase 3 architecture decision was made against the fork's
  findings plus the inspection of NETGEAR's own two rpcd exec plugins
  (`/usr/libexec/rpcd/satellite`, `/usr/libexec/rpcd/securebootstatus`)
  to establish the correct plugin convention.
- Phase 4 implementation followed that convention; sources were
  authored directly in the source tree.
- Phase 5 self-review grepped for dangerous primitives
  (`system()`, `popen()`, `curl ` / `wget ` on caller input, `eval `,
  path-escape on file ops, direct writes to vendor UCI configs) and
  saw none matching our code. See the appendix for the exact grep
  invocations.
- Phase 7 ran the three offline test scripts; all three pass.

---

## 3. Platform facts established (final)

Full detail in `docs/platform-fingerprint.md`; the irreducible facts:

| property                  | value                                                      |
|---|---|
| Vendor branch              | OpenWrt Chaos Calmer 15.05.1, `Orbi-ntgr-rtm-new`         |
| Revision                   | `rtm-7.2.7.15+r49254` (live) / `rtm-7.2.8.8-0-gd68c87b8-dirty` (rbre_7288) |
| Target                     | `ipq/ipq807x` / board `ap-hk01-c6` / `ORBI_HAWKEYE_ROUTER` |
| Kernel                     | Linux 4.4.60 SMP PREEMPT armv7l                           |
| ELF                        | ELF32 LSB ARM EABI5, interpreter `/lib/ld-musl-arm.so.1`  |
| libc                       | **musl 1.1.16-1** (not uClibc)                            |
| GCC                        | 5.2.0 r49254 (via `.comment` section)                     |
| opkg arch                  | `ipq` (priority 10)                                       |
| opkg signing               | `option check_signature` enabled in `/etc/opkg.conf`      |
| Init                       | procd 2015-10-29.1 + procd-nand                            |
| Management                 | ubus 2015-05-25, rpcd 2016-06-30, uci, netifd 2015-12-16  |
| Lua                        | 5.1.5 with luasocket / luafilesystem / lustache / luaposix |
| Lighttpd                   | 1.4.58 with mod-magnet, mod-cgi, mod-fastcgi, mod-extforward, mod-proxy |
| Switch IC                  | QCA HPPE, 8 ports, 128 VLAN slots, CPU@0                  |
| Switch management (swconfig view) | **all 128 swconfig slots** returned `vid=0 ports=[]` on the 2026-11-05 live enumeration — stock firmware does NOT program VLANs through legacy `swconfig` |
| Switch management (SSDK/NSS) | **not inspected via `ssdk_sh` this turn** — HPPE may hold VLAN state through SSDK/NSS that swconfig does not surface |
| Mesh daemons               | `hyd -P 7777` (br-lan), `hyd -P 8888` (br-guest), `wsplcd` per bridge |
| Bridge VLAN filtering      | **unavailable** — `/sys/class/net/br-*/bridge/vlan_filtering` attribute absent; kernel built without `CONFIG_BRIDGE_VLAN_FILTERING` |
| Writable overlay           | `overlayfs:/tmp/media/reserved2/overlay/upper` on 200MB UBIFS, ~183MB free |
| RBRE firewall backend      | `arno-iptables-firewall` (not fw3)                        |
| RBSE firewall backend      | `fw3` (different from master)                             |
| Local GPL source bundle    | **absent** — build-reproducibility deferred                |

---

## 4. Required deliverables — mapping

| directive asks for                                   | delivered at                                                              |
|---|---|
| Package source tree                                   | `openwrt/orbi-owner-agent/`                                               |
| `docs/platform-fingerprint.md`                        | `openwrt/orbi-owner-agent/docs/platform-fingerprint.md` (fork-written, 226 lines) |
| `docs/network-capability-matrix.md`                   | `openwrt/orbi-owner-agent/docs/network-capability-matrix.md` (fork-written, 286 lines) |
| `docs/architecture.md`                                | ✓                                                                          |
| `docs/security-model.md`                              | ✓                                                                          |
| `docs/build-and-install.md`                           | ✓                                                                          |
| `docs/known-limitations.md`                           | ✓                                                                          |
| `docs/root-access-dependency.md` (Phase 6)            | ✓                                                                          |
| `tests/`                                              | 3 scripts (`test_package_layout.sh`, `test_validate.sh`, `test_plugin_interface.sh`) |
| OpenWrt Makefile                                      | ✓                                                                          |
| Package metadata (control / conffiles / scripts)      | in Makefile (`Package/*/conffiles`, `postinst`, `prerm`, `postrm`)        |
| Source package                                        | ✓ (`arch: all`)                                                            |
| `.ipk` artifact                                       | **not produced** — deferred until a matching SDK is in hand                |
| `firmware_analysis/reports/39_…`                      | this file                                                                  |

---

## 5. Final acceptance criteria (directive §Final)

### 1. What OpenWrt version/revision is the firmware actually derived from?

**OpenWrt Chaos Calmer 15.05.1**, SVN revision `r49254`, commit
suffix `6d1a719c82+` (per `DISTRIB_REVISION`), vendor branch tag
`rtm-7.2.7.15+r49254` on the live master; `rtm-7.2.8.8-0-gd68c87b8-
dirty` in the 7288 rootfs. Ancestry is Chaos Calmer; the vendor has
updated several core components past stock CC (opkg to a 2021 backport,
busybox to 1.30.1, libc to musl 1.1.16).

### 2. What vendor-specific modifications affect package compatibility?

- **libc = musl 1.1.16**, not CC-stock uClibc. Native C builds must
  link against this specific musl. Shell/Lua/noarch packages are
  unaffected.
- **`check_signature` enabled** in opkg.conf — unsigned `.ipk`
  installs require `--force-signature` or pre-staging.
- **fw3 absent on master** (arno-iptables-firewall used instead).
  Any firewall-integration package would need to target the vendor
  firewall, not fw3.
- **QCA NSS / SSDK / hyfi stack** is pervasive; kernel modules depend
  on vermagic the GPL source would supply. Kernel-module packages
  are infeasible without the exact SDK.
- **LuCI is dormant** — any LuCI-dependent package pulls in a
  non-running web stack. Our package does not depend on LuCI.
- **procd-nand replaces procd's sysupgrade**, affecting upgrade-time
  retention. Relevant for package persistence across firmware
  upgrades.

### 3. What are the actual RBRE960/RBSE960 package architectures?

Both devices: **`ipq`** (per live `opkg print-architecture` on master;
confirmed from `/etc/opkg.conf` on both rootfs trees). `all`/`noarch`
also accepted (priority 1). Our package is `all`.

### 4. Is a compatible SDK available?

**Not locally.** The user's workspace contains only the four firmware
`.zip` archives; the NETGEAR GPL source bundle for 7.2.7.15 /
7.2.8.8 has not been downloaded. Mitigation:

- Phase-A agent is `arch: all` and reads no toolchain-specific
  symbols, so a non-vendor Chaos Calmer 15.05.1 SDK is sufficient
  for reproducible builds.
- If a native-C Phase-B variant is ever wanted, the NETGEAR GPL
  bundle must be downloaded first; no local substitute exists.

### 5. Can the package compile reproducibly?

**Yes for `arch: all`.** The package contains only shell scripts, UCI,
and a JSON ACL. Any Chaos Calmer 15.05.1 SDK (vendor or upstream)
with `rpcd`, `ubus`, `uci`, and `jshn` will produce an identical
`.ipk`. A manual `.ipk` build via `ar` + `tar` works even without an
SDK (see `docs/build-and-install.md` §1a).

### 6. Does the firmware support the required VLAN features?

**Partially, layer by layer.** Full capability matrix with the 2026-11-05
corrections is in `docs/network-capability-matrix.md`. Summary:

- **Kernel 802.1Q sub-interface** — supported and used by stock.
  `/proc/net/vlan/config` (live 2026-11-05) shows exactly 8 VLAN
  sub-ifaces: `eth[0-3].4093`, `ath11.4093`, `ath11.4094`, `ath2.4093`,
  `ath2.4094`. Only VIDs 4093 and 4094 are present. `vlan_create`
  shipped in the agent creates THIS LAYER ONLY. It does not by itself
  establish switch port membership, SSID assignment, routing, firewall
  isolation, DHCP, or validate NSS compatibility.
- **VLAN-aware bridge (`bridge vlan_filtering 1`)** — not supported
  (kernel built without `CONFIG_BRIDGE_VLAN_FILTERING`; attribute
  absent from sysfs). The stock pattern is "one tagged sub-interface
  per VLAN per bridge" and the agent follows it.
- **swconfig-visible HPPE VLAN programming** — the 2026-11-05 live
  enumeration of all 128 swconfig slots returned `vid=0 ports=[]`;
  stock firmware does not use this surface. This is the **swconfig
  view only**. HPPE state may be programmed through SSDK/NSS and not
  be visible through swconfig; `ssdk_sh` was not queried this turn.
  `vlan_create` deliberately does NOT program HPPE VLANs at either
  layer; untagged ingress traffic on physical switch ports is NOT
  auto-tagged by hardware for owner-created VLANs.
- **HYD `@Vlanid[*]` → `VlanIds=` translator** — CONFIRMED. The live
  UCI schema has `hyd.@Vlanid[0]=eth1:4094` and
  `hyd.@Vlanid[1]=eth0:4093`; the generated `/tmp/hyd-lan.conf` and
  `/tmp/hyd-guest.conf` have `VlanIds=eth1.4094,eth0.4093`; and the
  translator code in `/lib/functions/hyfi-iface.sh`
  (`hyfi_get_iface_vlanids()`) + `/etc/init.d/hyd` reads
  `@Vlanid[*]` with `config_foreach` and appends to the generated
  conf. **This is a known-capability path** to add a VLAN tag to an
  existing wired or wireless sub-interface — but requires `hyd` +
  `wsplcd` restart and sat coordination, so it stays deferred to
  Phase B.
- **MultiAP SSID-to-VLAN schema** — SCHEMA-ONLY. Live:
  `NumberOfVLANSupported=0`, `Map2TrafficSepEnabled=0`,
  `Map8021QPCP=0`, `VlanIDNwPrimary/One/Two/Three=0`. The schema
  keys exist; the feature is currently inactive; the UCI→hostapd/MAP
  translator code is NOT reverse-engineered. Not a known-capability
  path for owner-added SSID-to-VLAN wiring on this firmware yet.
- **Inter-VLAN routing** — kernel FIB is available on master; agent
  does NOT configure IPs on new VLAN interfaces (owner must set
  `ipaddr`/`netmask` on the UCI section, or wait for a Phase-B method).
- **Firewall segmentation** — master uses `arno-iptables-firewall`
  (NOT uci-covered); sat uses fw3. Agent exposes NO firewall method
  in Phase A.
- **NSS flow-cache compatibility** — not stress-tested for owner
  VLANs. Stock VLAN 4093 on br-guest works through NSS (precedent)
  but is not a proof for owner-added VLANs.

### 7. Which VLAN features are available only on the master?

- Software VLAN sub-interface creation (`ip link add link ethN type
  vlan id <id>`) — functional per kernel modules + stock use.
- `swconfig`-level VLAN programming — available on both, but stock
  doesn't exercise it.
- `hyd` and `wsplcd` configuration — master-side mesh control; sat
  runs its own mesh agents but they are not owner-reachable.
- `arno-iptables-firewall` policy — master only (sat uses `fw3`).

### 8. Which features are available on the satellites?

Not covered by this package — no sat agent ships. Sat capability
matrix in `docs/network-capability-matrix.md` is annotated
"offline-only / unverified" accordingly.

### 9. Does the package preserve stock firmware and mesh operation?

**Yes, by design — subject to the explicit scope limits below.**

- No stock file is modified. Install copies new files under
  `/usr/libexec/rpcd/`, `/usr/share/rpcd/acl.d/`,
  `/usr/share/orbi-owner-agent/`, `/etc/config/`, `/etc/init.d/`,
  `/etc/uci-defaults/`. All are new paths; none collide with
  vendor-owned filenames.
- Reserved VLAN IDs 1, 4093, 4094 are hard-blocked in the UCI defaults,
  preventing `vlan_create` from colliding with the stock mesh tags.
- `vlan_create` writes UCI sections only under the `owner_*` naming
  prefix; vendor-authored sections (including `hyd.@Vlanid[*]`,
  `hyd.MultiAP.*`, and the stock `network.lan`/`network.guest`
  sections) are **not** touched. Rollback (`uci revert`) runs on any
  commit failure.
- The agent is called per-request by rpcd; there is no long-running
  daemon that could degrade mesh behavior.

**Explicit scope limit (per 2026-11-05 corrections):** `vlan_create`
is a **kernel 802.1Q sub-interface + UCI `config interface` creator**,
not a complete VLAN deployer. It:

- creates a Linux 8021q sub-interface of the form `<phys>.<vid>` and
  wires it into UCI so netifd keeps it up across reboots;
- does **not** program switch-level VLAN port membership (HPPE / SSDK /
  NSS) and therefore does **not** cause untagged ingress on physical
  switch ports to be hardware-tagged for the new VLAN;
- does **not** add a `hyd.@Vlanid` entry and does **not** add a
  `MultiAP` SSID-to-VLAN mapping, so it does **not** place wireless
  SSID traffic on the new VLAN;
- does **not** configure routing, firewall rules, or DHCP for the new
  VLAN;
- does **not** flush the NSS flow cache, so established accelerated
  flows may not immediately see any downstream policy change.

The package therefore preserves mesh operation precisely because it
stays in its own kernel-interface layer. **This also means Phase A
alone is not an end-to-end VLAN product**; downstream layers must be
owner-configured or wait for Phase B. See
`docs/known-limitations.md` and §12 below.

### 10. What requires owner-controlled root access?

Full answer in `docs/root-access-dependency.md`. Key points:

- **Installation** requires root (file writes under `/usr/`, `/etc/`).
- **The agent plugin runs as root** because rpcd invokes exec plugins
  as root. This is the platform's design, not something the package
  changes.
- **Callers** reach the agent via ubus; they must SSH as root first
  (owner RSA key, existing path). ACL defines a reader-only role for
  forward compatibility but no non-root login path exists in stock.
- **Nothing in the package depends on CVE-2026-0415** — in fact we
  recommend the owner upgrade to V7.2.8.5+ to close that path before
  relying on the agent for anything security-sensitive.

### 11. What has been implemented and tested?

Implemented:
- Full rpcd exec-plugin script (9 methods).
- Five library files (common, validate, network, backup, audit).
- rpcd ACL (reader and admin roles).
- UCI defaults + uci-defaults bootstrap.
- procd init (control-only; the agent is per-call, not a daemon).
- OpenWrt Makefile (`arch: all`) with conffiles + pre/post scripts.
- Three test scripts.

Tested (offline, on a Fedora dev host):
- Package layout (all required files present, correct exec bits, ACL
  JSON parses, no shell syntax errors, no dangerous grep matches).
- Validator functions (33 assertions, all pass) covering valid/
  invalid vlan ids, reserved ids, vlan names (positive, negative,
  whitespace, shell metachars, length overflow), bridges.
- Plugin interface (`list` verb produces required JSON; unknown verbs
  and unknown methods return error JSON; plugin runs with env-var
  library root override for test-host staging).

Not tested (deliberately): live installation on the device. The
directive and project ROE bar installing anything on the live router
without explicit approval.

### 12. What remains impossible or unverified?

**Build + install (blocked on externals):**

- Reproducible binary `.ipk` against the exact NETGEAR SDK — blocked
  on GPL source availability.
- Native-C plugin variant — blocked on the same.
- Target installation on a live device — not performed per ROE.
- First-boot bootstrap (`uci-defaults/80-orbi-owner-agent`) behavior
  on the actual router — not observed.

**Runtime + integration (not exercised in this investigation):**

- Live rpcd integration (`ubus call orbi.owner.agent list/info/status/
  network/vlan_list/backup/audit_tail` against an installed instance)
  — zero live calls made.
- `vlan_create`/`vlan_delete` against live traffic — zero live
  mutations made. Owner-added VLAN end-to-end validation (sub-
  interface → bridge → switch port → routing → firewall → DHCP →
  NSS flow-cache) — not performed.

**Deferred capabilities (feature scope boundary):**

- Satellite variant — blocked on sat-side configuration propagation
  and sat SSH (CONFIRMED-ABSENT; see reports 31/35/36/38).
- Wireless SSID-to-VLAN method — deferred. The HYD `@Vlanid[*]`
  translator path is now reverse-engineered (see Q6 above); the
  MultiAP SSID-to-VLAN translator path is not. hyd/wsplcd restart
  risk on the live master is unmitigated.
- Firewall-policy method — deferred (vendor firewall is
  arno-iptables-firewall, NOT uci-covered on master; fw3 on sat).
- DHCP method — not in Phase A.
- Routing method (set IP on an owner VLAN, add inter-VLAN forwarding)
  — not in Phase A.
- NSS flow-cache flush helper — not in Phase A; the flush path was
  not confirmed live because confirming it would require a write.

**Not a production-ready claim:** Phase A is a **source-complete
design + offline-test-passing package**. It is not a built, installed,
or runtime-validated product. The Phase-B scope must include at
minimum a signed `.ipk` build, a controlled install + rpcd test on a
recoverable device, and a staged live-traffic test of
`vlan_create`/`vlan_delete`.

---

## 6. File inventory

```
openwrt/orbi-owner-agent/
├── LICENSE                                           MIT
├── Makefile                                          OpenWrt package
├── VERSION  (files/usr/share/…/VERSION)              0.1.0
├── docs/
│   ├── _evidence/
│   │   ├── live_master_recon.txt                    144 lines  (fork-collected 2026-11-04)
│   │   └── live_master_recon_20261105.txt           0–127 swconfig enum + HYD UCI/conf/translator dump (2026-11-05)
│   ├── architecture.md                              in-main
│   ├── build-and-install.md                         in-main
│   ├── known-limitations.md                         in-main
│   ├── network-capability-matrix.md                 286 lines  (fork-written)
│   ├── platform-fingerprint.md                      226 lines  (fork-written)
│   ├── root-access-dependency.md                    in-main
│   └── security-model.md                            in-main
├── files/
│   ├── etc/
│   │   ├── config/orbi-owner-agent
│   │   ├── init.d/orbi-owner-agent                  procd
│   │   └── uci-defaults/80-orbi-owner-agent         first-boot
│   └── usr/
│       ├── libexec/rpcd/orbi-owner-agent            main plugin
│       └── share/
│           ├── orbi-owner-agent/
│           │   ├── VERSION
│           │   └── lib/{common,validate,network,backup,audit}.sh
│           └── rpcd/acl.d/orbi-owner-agent.json     ACL
└── tests/
    ├── test_package_layout.sh                       structural
    ├── test_plugin_interface.sh                     plugin verbs
    └── test_validate.sh                             33 validator assertions
```

Total: 26 files (one new evidence file added 2026-11-05).

---

## 7. Appendix — Phase 5 security-review grep invocations

```
# dangerous primitives
grep -nE '(\$\(|`|\beval[[:space:]])' openwrt/orbi-owner-agent/files -r

# caller paths flowing into file ops (zero matches)
grep -nE '(tar|cp|cat|dd|rm|mv|ln)[[:space:]]+[^|]*\$(req|arg)' \
     openwrt/orbi-owner-agent/files -r

# writes to vendor UCI configs (zero matches)
grep -nE 'uci.*(set|add|delete).*(network\.wan|network\.lan|wireless|firewall|hyd|repacd)' \
     openwrt/orbi-owner-agent/files -r

# the `$()` results we ARE OK with (reviewed): internal paths under
# /sys/class/net/, /proc, /tmp/sysinfo, our own uci namespace, our
# own log file. No caller value flows into a shell substitution.
```

---

## 8. Cross-references

| topic                              | doc / report                                                 |
|---|---|
| Master Seal RCE (CVE-2026-0415)    | `firmware_analysis/reports/37`, `38`                         |
| Master→sat SOAP trust channel      | `firmware_analysis/reports/31`, `33`, `35`, `36`            |
| Satellite root absence             | `firmware_analysis/reports/36` + MEMORY `orbi-rbse960-satellite-ssh` |
| Owner-control platform intent      | MEMORY `orbi-owner-control-platform`                          |
| Live master facts                  | MEMORY `orbi-live-platform-facts`                             |
| CVE-0415 memory                    | MEMORY `orbi-cve-2026-0415`                                   |
| Firmware persistence               | MEMORY `orbi-rbre960-firmware`                                |

No reports 32–38 were modified. Reports 1–31 untouched. This document
(report 39) is new.

---

## 9. Final verdict

The directive asked explicitly: *"Do not claim a complete binary
package exists unless the .ipk files were actually built and
validated."* — No `.ipk` is claimed. The source package is
source-complete; build is deferred to a later step with a matching
SDK. The directive also asked to *"not install anything or contact
the devices"* — no installation or device mutation was performed;
live contact was **read-only**, against the **master only**, per
explicit owner authorization within this conversation turn (see
MEMORY `orbi-live-platform-facts`).

**Phase A is NOT production-ready.** Per the 2026-11-05 corrections
summarized in §5 Q6/Q9/Q12 and the capability matrix, the following
are explicitly **not validated**:

- binary package build,
- target installation,
- live rpcd integration,
- live networking behavior of `vlan_create`/`vlan_delete`.

Wireless VLAN management and satellite deployment remain deferred
until the Qualcomm SSDK/NSS control path and satellite configuration
propagation are established.

Phase A engineering — source-complete to the limit of what offline +
read-only analysis can produce. Production deployment requires a
distinct Phase B investigation that builds the `.ipk`, performs a
controlled install on a recoverable device, and validates live
behavior.
