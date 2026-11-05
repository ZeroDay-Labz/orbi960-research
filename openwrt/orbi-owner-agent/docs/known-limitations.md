# orbi-owner-agent — Known limitations

Short, honest list of what this Phase-A package deliberately does not do
and what it cannot do on this platform.

## Satellites (RBSE960)

- **No sat variant is shipped.**
  Reports 31, 35, 36, and 38 establish that there is no in-boundary
  satellite root and no sat `ubus` reachable to an external owner.
  Installing this package on a sat would require solving sat SSH first,
  which prior research has not achieved without firmware modification
  (RULED OUT for this project).

## Firewall segmentation

- RBRE uses `arno-iptables-firewall`, not OpenWrt's `fw3`. MEMORY.md
  also records "firewall NOT uci-covered". Therefore the agent does
  **not** expose a `firewall_zone_add` method. Whichever firewall rules
  the owner authors must be applied via vendor-native mechanisms, not
  `/etc/config/firewall`.
- Qualcomm NSS shortcuts (kmod `qca_nss_drv` 1.65 MB + bridge-mgr +
  VLAN-mgr) can bypass Linux netfilter for cached flows. A policy
  change may not take effect on existing flows until the NSS cache is
  flushed. This behavior is out of our package's scope.

## Wireless SSID-to-VLAN

- Platform runs vendor-patched hostapd (`vlan_bridge`, `dynamic_vlan`,
  `vlan_file`, `vlan_naming` strings present in the binary) and two
  `hyd` instances (per-bridge, listening on 127.0.0.1:7777 and
  127.0.0.1:8888).
- Two schema surfaces for VLAN config live in `/etc/config/hyd`:
  - **`@Vlanid[*]`** `(ifname, vid)` pairs — the stock mesh uses two
    entries: `eth1:4094` and `eth0:4093`. The UCI→HYD translator at
    `/lib/functions/hyfi-iface.sh::hyfi_get_iface_vlanids()` (called
    by `/etc/init.d/hyd`) projects these to `VlanIds=` in the
    generated `/tmp/hyd-*.conf`. This path IS reverse-engineered —
    adding an owner `@Vlanid` entry would add the VLAN tag to the
    named interface; but requires `hyd` + `wsplcd` restart, which
    risks mesh disruption on the live master.
  - **`MultiAP.*`** — `NumberOfVLANSupported`, `Map2TrafficSepEnabled`,
    `Map8021QPCP`, `VlanIDNwPrimary/One/Two/Three`. All zero on the
    live master; the Multi-AP SSID-to-VLAN separation feature is
    schema-defined but inactive. The UCI-to-generated-conf translator
    for this surface is NOT reverse-engineered.
- The agent therefore defers all wireless SSID-to-VLAN wiring to
  Phase B.

## Switch-level VLAN rules

- The 2026-11-05 live enumeration of **all 128 swconfig VLAN slots**
  (0–127) on QCA HPPE returned `vid=0 ports=[]` for every slot. The
  stock firmware does **not** program VLANs through the legacy
  swconfig surface.
- This is the **swconfig view only.** The HPPE is managed in practice
  by the Qualcomm SSDK/NSS stack (`ssdk_sh`, `qca_nss_drv`,
  `qca_ssdk`, `qca_nss_vlan`), which can program VLAN state that
  swconfig does not expose. `ssdk_sh`-based queries were NOT run
  this turn; the full hardware VLAN-programming state is therefore
  partially unknown.
- Stock topology creates VLAN sub-interfaces entirely in software
  (`eth0.4093`, `ath11.4094`, etc.) and relies on `ebt_vlan` + Linux
  8021q. There are exactly 8 such sub-interfaces live (see
  `_evidence/live_master_recon_20261105.txt`).
- `vlan_create` follows the same software-sub-interface pattern.
  HW-level VLAN tagging via `swconfig vlan N set ports`, `ssdk_sh`,
  or NSS APIs is **deliberately not performed**. Owner-created VLANs
  ride alongside stock VLANs in software without touching hardware
  switch configuration.
- Consequence: untagged ingress traffic on a physical wired port will
  NOT be hardware-tagged to the owner VLAN. The owner-agent's
  `vlan_create` is useful for owner-tagged traffic (VLAN-aware
  clients, mesh satellites configured with matching VLANs), not for
  untagged client VLAN segregation.

## opkg signing

- `/etc/opkg.conf` has `option check_signature`. The source-tree
  `.ipk` we produce is unsigned. Install options:
  1. **Pre-stage to `/ipk/`** (as NETGEAR does with
     `qca-hyd-init.ipk` and `qca-hyd-son.ipk`), then
     `opkg install --force-signature /ipk/orbi-owner-agent_*.ipk`.
  2. Add an owner signing key to `/etc/opkg/keys/` and sign the `.ipk`
     with `usign` or `opkg-make-index`. Documented in
     `build-and-install.md`.

## Build reproducibility

- **No NETGEAR GPL source bundle for 7.2.7.15 / 7.2.8.8 is present
  in this workspace.** Reproducing an identical build requires:
  - OpenWrt Chaos Calmer 15.05.1 SDK tagged at or near r49254.
  - NETGEAR vendor patches for ipq807x / Hawkeye target.
  - A toolchain matching GCC 5.2.0 on the device's `.comment` string.
- The current package is **arch=all** (shell + config only), so it
  will install correctly even against an SDK that does not exactly
  match the vendor patch set. The Makefile declares that explicitly.

## Agent trust model

- The agent assumes the root caller is the owner. The firmware is
  single-user (root), so this is the practical truth. A privilege-
  gap between "someone with ubus access" and "root" cannot be
  enforced from inside the agent alone.
- A root attacker with on-device access can replace
  `/usr/libexec/rpcd/orbi-owner-agent`. This is true of every OpenWrt
  package; our mitigation is to keep the plugin small and source-
  readable so tampering is visible.

## CVE-2026-0415

- The live master (as of 2026-11-04) is on V7.2.7.15 — vulnerable
  version per reports 37/38. The Seal `install` endpoint can rewrite
  files reachable through a `..` path traversal, which includes our
  plugin's install path. **Upgrade to V7.2.8.5+ before relying on
  this agent for anything security-sensitive**, or sanitize the
  CVE-0415 exposure by an alternative means (owner can patch
  `seal-services.lua` manually by hand-installing the 7288 version).
- The agent's audit log would record any method call it saw. It
  cannot record a `seal-services.lua`-driven file write that
  bypasses the agent entirely.

## Reboot persistence of writable overlay

- All agent files install under `/` which is `overlayfs:/tmp/media/
  reserved2/overlay/upper`. They survive reboot by living in the
  writable overlay.
- Firmware upgrades (the vendor's own upgrade flow) can erase or
  reinitialize the overlay depending on the upgrade script path.
  Report 25B and the MEMORY entry "Orbi RBRE960 firmware" discuss
  this. After a firmware upgrade, the agent may need reinstallation.

## Not a monitoring platform

- `status`, `network`, `vlan_list`, `audit_tail` return *point-in-time*
  data. There is no time-series, no alerting, no trending. Those
  functions belong on the external Proxmox controller, which should
  poll the agent periodically.

## Not an authentication gateway

- The agent never evaluates passwords, tokens, or certificates. All
  authentication happens at the SSH layer before the caller's shell
  reaches `ubus`. If SSH key auth is compromised, the agent has no
  defense.
