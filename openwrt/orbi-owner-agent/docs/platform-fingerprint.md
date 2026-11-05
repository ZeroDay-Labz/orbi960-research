# orbi-owner-agent — platform fingerprint

Produced for Phase 1 of directive 705a.
Evidence date: 2026-11-04.
All evidence is either offline (extracted rootfs) or live read-only recon of the
master at 10.0.0.1 (transcript: `_evidence/live_master_recon.txt`).

> **Firmware version footnote.** The *extracted rootfs* under
> `firmware_analysis/extracted/` carries both V7.2.7.15 and V7.2.8.8 trees. The
> **live master runs V7.2.7.15** (DISTRIB_REVISION `rtm-7.2.7.15+r49254`,
> /etc/version `7.2.7.15`, base-files `157.2-rtm-7.2.7.15+r49254`,
> `/www-seal/rest/rest.lua` size 7670 B → sha256
> `59e48af4076e4122217ad8cfdb5a1fd1ccec34aafb1aaf951073443d17b8259b` ≡
> rbre_7215/rootfs). This is the **unpatched CVE-2026-0415 version** per
> report 38; the live master's Seal REST handler is vulnerable at the time of
> this fingerprint. The owner-agent package is designed against the 7215
> runtime but must build cleanly against both.

---

## 1. Operating system

| field | value | evidence |
|---|---|---|
| Linux kernel | **4.4.60** SMP PREEMPT | live `uname -a` (Linux RBRE960 4.4.60 #3 SMP PREEMPT Thu Nov 14 21:04:07 UTC 2024 armv7l); offline `lib/modules/4.4.60/` present in both RBRE and RBSE 7215/7288 rootfs |
| Distribution | OpenWrt **Chaos Calmer 15.05.1** | live `cat /etc/openwrt_release` |
| OpenWrt revision | `r49254` (+patch `6d1a719c82` on 7288, `rtm-7.2.7.15+r49254` on live 7215) | `DISTRIB_REVISION` in `/etc/openwrt_release` |
| Vendor branch | `Orbi-ntgr-rtm-new`, tag `rtm-7.2.8.8-0-gd68c87b8-dirty` (rootfs) / `rtm-7.2.7.15` (live) | `/etc/git_version` |
| ODM version | 5.1.24 | `/etc/odm_version` |
| Hardware model | `Qualcomm Technologies, Inc. IPQ807x/AP-HK01-C6` | `/tmp/sysinfo/model` |
| Board name | `ap-hk01-c6` | `/tmp/sysinfo/board_name` |
| Module name | `ORBI_HAWKEYE_ROUTER` | `/module_name` |
| Architecture | **armv7l** (ARMv7-A, 32-bit) | `uname -m`; `file bin/busybox` → `ELF 32-bit LSB shared object, ARM, EABI5` |
| Endianness | little-endian | `file` output; `ELF32-LE` |
| ELF class | **ELF32** shared-object style (PIE) | every sampled binary is `shared object` (position-independent), not `executable` |
| Target / subtarget | `ipq/ipq807x` | `DISTRIB_TARGET` in openwrt_release |
| Taints | `no-all busybox override` | `DISTRIB_TAINTS`; indicates a non-stock OpenWrt build with vendor BusyBox override |

---

## 2. Libc, dynamic linker, toolchain

| field | value | evidence |
|---|---|---|
| libc implementation | **musl 1.1.16** | `strings lib/libc.so` → `musl libc (arm)` + version string `1.1.16`; live `opkg list-installed` → `libc 1.1.16-1`; same on both RBRE and RBSE |
| Dynamic linker | **/lib/ld-musl-arm.so.1** | every sampled ELF carries this interpreter; `ld-musl-arm.so.1` is a symlink to `libc.so` |
| Compiler | **GCC 5.2.0 (OpenWrt GCC 5.2.0 bda89f4+r49254)** | `readelf -p .comment firmware_analysis/extracted/rbre_7288/rootfs/usr/sbin/httpd` → `GCC: (OpenWrt GCC 5.2.0 bda89f4+r49254) 5.2.0` |
| C++ runtime | uClibc++ 0.2.4 (`libuClibc++-0.2.4.so`) | `/usr/lib/libuClibc++-0.2.4.so` present on RBRE 7288 rootfs |
| Binutils | r49254-era (bundled with GCC 5.2.0 in CC toolchain) | inferred from toolchain build id; not independently stamped in ELF |

**Platform-defining fact:** this image uses **musl** rather than the uClibc that
stock OpenWrt Chaos Calmer 15.05.1 shipped. That means a package built against a
generic Chaos Calmer SDK will link to the wrong libc and will not run.
The toolchain must be reproduced as **musl 1.1.16 + GCC 5.2.0 r49254**.

---

## 3. Kernel configuration and modules

| field | value | evidence |
|---|---|---|
| Module count on disk | RBRE 7288 = **367** `.ko`, RBSE 7288 = **350** `.ko` | `find lib/modules/4.4.60 -name '*.ko' \| wc -l` |
| 8021q (VLAN) | **built into kernel** (not shipped as a .ko) | `find lib/modules/... -name '*8021q*'` → empty; **but** `/proc/net/vlan/config` live shows active VLANs 4093/4094 → kernel supports 8021q intrinsically |
| Bridge | built-in (no `bridge.ko` in modules dir) | `brctl show` works live; no `bridge.ko` filesystem entry |
| NSS acceleration | present (`qca-nss-*`, `acos_nat`, `ecm`) | live `lsmod` shows `acos_nat` (1.4MB!), `qca_nss_cfi_cryptoapi`, `ecm` (ECM = Enhanced Connection Manager, QCA-NSS) |
| Vendor hooks | `br_hijack`, `br_packet_filter`, `br_dhcp_filter`, `AttDevKerm`, `bootconfig`, `nvram_kernel_module`, `fxcn_kernel_module`, `oops_writer`, `opendns.ko` | `lib/modules/4.4.60/acos/` directory |
| Kernel config availability | **not present** on-disk | no `/proc/config.gz` referenced; no `config.gz` or kconfig under rootfs; a build would need the vendor kernel source (absent, see §7) |
| Kernel module ABI vermagic | not easily extractable from the stripped .ko’s we inspected | `strings` on sample .ko did not yield a vermagic line; vendor strips modinfo. Package must therefore **avoid kernel-module content** unless we obtain the kernel source and build against the exact `.config`. |

---

## 4. OpenWrt component presence and functionality

Each row = present-and-functional (✓) / present-but-vendor-modified (M) /
replaced-by-vendor (V) / absent (✗). "RBRE" column = live-verified where
possible; "RBSE" column = offline rootfs only (no live sat access).

| component | RBRE | RBSE | path | notes |
|---|---|---|---|---|
| **opkg** | ✓ | ✓ | `/bin/opkg` | Version `2021-01-31-c5dccea9-1` (**modern backport**, not CC-era); `check_signature` enabled; package arch = `ipq`; 3 arches (all, noarch, ipq) with priorities 1/1/10. |
| **UCI** | ✓ | ✓ | `/sbin/uci` | 30+ configs under `/etc/config/` (live): network, wireless, firewall, dhcp, dropbear, hyd, lbd, etc. |
| **ubus** | ✓ | ✓ | `/bin/ubus`, `/sbin/ubusd` | CC-era (2015-05-25); `ubus list` registers standard OpenWrt objects (log, network, session, system, uci, service) plus NETGEAR objects (orbi_wlparam, orbistats, satellite, securebootstatus). |
| **rpcd** | ✓ | ✓ | `/usr/sbin/rpcd`, `/usr/share/rpcd/acl.d/`, `/usr/lib/rpcd/` | Version `2016-06-30`; ACL dir present; vendor plugins `ntgr_stats.so`, `ntgr_wlparam.so`; `unauthenticated.json` ACL exposes only `session.{access,login}`. |
| **netifd** | ✓ | ✓ | `/sbin/netifd` | Version `2015-12-16`; proto scripts `6rd/464xlat/dhcp/dslite/l2tp/map/ppp/tayga` under `/lib/netifd/proto/`. No VLAN proto script (VLAN is built-in). |
| **procd** | ✓ | ✓ | `/sbin/procd`, `/sbin/init` (procd-init) | Version `2015-10-29`; init.d scripts use procd (`USE_PROCD=1`) format. `procd-nand` also installed for UBI/NAND integration. |
| **logd / ubox** | ✓ | ✓ | `/sbin/logd` | Standard OpenWrt syslog via ubus. |
| **LuCI** | ✗ (dormant) | ✗ (dormant) | `/usr/lib/lua/luci/` present | MEMORY.md confirms: no `.lua` route in stock lighttpd; `lighttpd2` never auto-starts; only `luci/version.lua` differs 7215↔7288. Effectively absent at runtime. |
| **bridge-utils (brctl)** | ✓ | ✓ | `/usr/sbin/brctl` | Live `brctl show` lists `br-lan`, `br-guest`. |
| **swconfig** | ✓ | n/a | `/sbin/swconfig` | Live `swconfig list` → `switch0 - QCA HPPE`. Satellite does not route; switch role differs. |
| **DSA** | ✗ | ✗ | — | Kernel 4.4 pre-DSA-mainline; SoC uses QCA SSDK + HPPE (vendor driver), not DSA. |
| **hostapd** | V (vendor-patched) | V | `/usr/sbin/hostapd` | Strings confirm **VLAN capabilities compiled in**: `vlan_bridge`, `dynamic_vlan`, `vlan_file`, `vlan_naming`. Likely vendor-patched for QCA Hy-Fi/repacd mesh; runs under `qca-hostapd` init. |
| **wpad** | ✗ | ✗ | — | Not present as a separate binary; hostapd is the only wpa_s-family binary shipped. |
| **fw3** | ✗ | ✓ (sbin/fw3) | — on RBRE | RBRE uses `arno-iptables-firewall` (script-driven, under `/etc/arno-iptables-firewall/`) instead of fw3. RBSE has standard fw3. **Firewall architecture diverges between master and satellite.** |
| **iptables** | ✓ | ✓ | `/usr/sbin/iptables` | Classic netfilter stack. MEMORY.md flag: firewall is **not** fully UCI-managed on master (arno-based); any UCI-driven firewall edits via `/etc/config/firewall` apply only through fw3 workflows that don't exist on master. |
| **nftables** | ✗ | ✗ | — | Not shipped; kernel 4.4 era + iptables-only build. |

---

## 5. Package infrastructure

| field | value | evidence |
|---|---|---|
| opkg version | `2021-01-31-c5dccea9-1` | live `opkg list-installed` (modern backport of opkg into a CC image) |
| Supported package arch | **`ipq`** (plus `all`, `noarch`) | live `opkg print-architecture`: `arch all 1 / arch noarch 1 / arch ipq 10` |
| Package metadata layout | standard opkg | `/usr/lib/opkg/status` (installed db) + `/usr/lib/opkg/info/<pkg>.{control,list,conffiles,postinst,prerm}` |
| Package signing | **check_signature on** | `/etc/opkg.conf`: `option check_signature`; `/etc/opkg/keys/` holds trusted usign keys. A package not signed by a trusted key will be refused by `opkg install`. |
| Feed configuration | vendor-controlled | `/etc/opkg/customfeeds.conf` is the stock placeholder; the vendor adds feeds via `customfeeds_rsu.sh` and `customfeeds_gen2.sh`. No public feed URLs. |
| Pre-staged IPKs on-device | 2 | `/ipk/qca-hyd-init.ipk` (38.4 KB, Nov 14 2024), `/ipk/qca-hyd-son.ipk` (210.3 KB) — vendor uses opkg to late-install packages at runtime. |
| Writable install target | `/tmp/media/reserved2` overlayfs upper; 183 MB free | `mount`, `df -h` live |

**Implication:** we can produce standard opkg IPKs with `arch: ipq`, and `opkg install`
will accept them *if* they are signed by a key already in `/etc/opkg/keys/`.
Since we cannot sign with the vendor's private key, two realistic paths exist:

1. **Install unsigned:** `opkg install --nocheck-signature /tmp/orbi-owner-agent_*.ipk`
   (explicit flag, owner-approved, single-shot).
2. **Install via `tar -x` + manual `/usr/lib/opkg/status` append**: effectively the
   same contents, bypasses opkg; more fragile.

The package's `files/usr/share/orbi-owner-agent/README-install.md` (produced in
Phase 4) documents both options. The package **does not** attempt to insert its
own usign key into `/etc/opkg/keys/` (that would alter the vendor trust root).

---

## 6. Vendor-specific daemons and control plane

Living alongside the standard OpenWrt stack in `/usr/sbin/`:

| binary | role (per prior reports and inventory labels) |
|---|---|
| `soapc` | Master-side SOAP client (speaks to each satellite). Lazy-spawned; not resident. **Report 33 deep-RE'd.** |
| `soap_agent` | SOAP CGI (authenticated management surface). Reports 31, 36. |
| `configd` | Configuration DAL daemon; gates SOAP state changes. Report 36. |
| `httpd` | Primary management webserver. Report 37. |
| `heartbeat` | Mesh heartbeat. |
| `wandetect` | WAN connectivity detection. |
| `scheact` | Scheduled actions. |
| `check_fw` | Firmware upgrade helper. |
| `launchService` | Service launcher (works with Seal `service_action_handler`). |
| `ssdk_sh` | QCA SSDK shell — switch management CLI. |
| `ipcCmd`, `ipcTask` | QCA/NETGEAR IPC primitives. |
| `telnetenabled` | Telnet enable probe (legacy). |
| Seal Lua stack | `/usr/share/lua/seal-{config,development,environ,io,log,monit,platform,services,...}.lua`, `/www-seal/rest/rest.lua`, `/www-seal/seal/index.lua`. **CVE-2026-0415 lives here (reports 37/38).** Seal runs under a secondary lighttpd on `127.0.0.1:16667` as **uid 0** (report 38). |

`/etc/init.d/` contents include both OpenWrt standards (`network`, `firewall`
via `arno-iptables-firewall`, `cron`, `log`, `lighttpd`) and NETGEAR services
(`hyd`, `hyfi-bridging`, `qca-acfg`, `qca-hostapd`, `repacd`, `wsplcd`,
`lbd`, `ssid-steering`, `init_configd`, `init_model_id`, `init_sshenable`,
`init_standalone_router`, `fcpuethctrl`, `ntgrdone`, `monit`, `openvpn`,
`openvswitch`, `pot_init`, `powerctl`, `breakpad`, `ftm`, `cnss_diag`,
`diag_socket_app`, `ndppd`, `mount_pot_partition`, `inetd`, `macsec`,
`miniupnpd`, `igmpproxy`, `aqr_init`, `led`).

---

## 7. NETGEAR GPL source availability

Searched `~`, `~/Downloads`, `~/PycharmProjects/orbi_test`, and the extracted
firmware trees for any NETGEAR GPL source bundle (`RBRE960*gpl*`,
`RBSE960*gpl*`, `*gpl_source*`, `ipq807x*sdk*`, `orbi*gpl*`, loose `.tar.*`/`.zip`
archives). **Nothing found.**

The only archives on the workstation are the firmware .zip images themselves
(V7.2.7.15 and V7.2.8.8 for both models), which contain binary rootfs + kernel,
not source.

**Implication for Phase 4:** we cannot produce a reproducible toolchain-verified
build without either (a) downloading the vendor GPL tarball from the NETGEAR
GPL index (user-initiated), or (b) building against a reconstructed toolchain
(musl 1.1.16 + gcc 5.2.0 + the matching CC 15.05.1 r49254 SDK). Phase 7
documents this explicitly and ships source + a build-requirements note rather
than a pre-built .ipk.

---

## 8. RBRE / RBSE differences that matter for packaging

| facet | RBRE960 | RBSE960 | consequence for package |
|---|---|---|---|
| libc | musl 1.1.16 | musl 1.1.16 | shared binary-compatible libc; one build of a no-kmod C package *might* run on both, but not before per-model dependency check |
| Package arch | `ipq` | `ipq` (expected, not live-confirmed) | same ARCH line in IPK metadata |
| Kernel | 4.4.60 | 4.4.60 | same ABI |
| Modules on disk | 367 | 350 | diff ~17 modules; master-only ones are mostly WAN/routing (`icm`, etc.). Packaging implication: a kmod-dependent feature must check per model. |
| Firewall | arno-iptables-firewall (script) | fw3 (OpenWrt) | configuration surfaces diverge; owner-agent's firewall integration must have **two implementations** or restrict to master-only until a fw3 wrapper is added |
| Routing | br-lan + br-guest + eth0 WAN | br-lan AP only | VLAN + inter-VLAN routing features only make sense on master |
| Seal REST | present (`/www-seal/`, `www-seal/rest/rest.lua`) | **absent** (report 38) | master is the integration target for CVE-0415-aware features; satellite needs a separate control plane |
| rpcd ACL | present + vendor extras | present + vendor extras | owner-agent ACL rules apply to both |
| Seal Lua stack | present | absent | owner-agent must not depend on Seal Lua modules |
| ubus registry | 20+ vendor-adjacent objects (`orbi_wlparam`, `orbistats`, `satellite`, …) | smaller | master has richer mesh-status surface for telemetry |

**Build policy:** produce two IPK artifacts — `orbi-owner-agent` (master) and
`orbi-owner-agent-satellite` (sat). Common code lives in a shared tree; per-model
`files/` and `postinst` select between arno vs fw3 integration and enable/disable
master-only features. Both use the same `ipq` arch and same musl runtime.

---

## 9. Live master firmware state — operational note

The master's running firmware is **V7.2.7.15**, which is **unpatched for
CVE-2026-0415** (report 38's RBRE-side CONFIRMED finding). Implication for
owner-agent deployment:

- The package itself must not depend on the Seal REST handler being hardened —
  our package's own control plane is independent of Seal.
- Owner may want to upgrade to V7.2.8.8 for the CVE-0415 fix before deploying
  the owner-agent in production. Upgrade behavior (overlay preservation,
  authorized_keys survival) was analyzed in prior firmware research and lives
  in `MEMORY.md` → `orbi-rbre960-firmware`.
- If the owner stays on 7.2.7.15, the external Proxmox controller SHOULD NOT
  rely on Seal REST for any management call — direct SSH + ubus/uci on the
  owner-agent's own channel is safer until the upgrade lands.

---

## 10. Summary table (answers to Phase 1 acceptance questions 1–4)

| Q | Answer |
|---|---|
| OpenWrt revision | Chaos Calmer 15.05.1, r49254, vendor branch `Orbi-ntgr-rtm-new` tag `rtm-7.2.7.15+r49254` (live) / `rtm-7.2.8.8-0-gd68c87b8-dirty` (newer offline tree) |
| Vendor modifications affecting compat | musl 1.1.16 instead of uClibc; vendor BusyBox override; vendor firewall = `arno-iptables-firewall` on master (fw3 on sat); vendor-patched hostapd for QCA Hy-Fi mesh; QCA SSDK/HPPE switch stack (no DSA); ~20 NETGEAR-specific daemons (`soapc`, `configd`, `heartbeat`, `wandetect`, `ssdk_sh`, `ipcCmd`, `ipcTask`, `hyd`, `repacd`, `wsplcd`, `lbd`); modern opkg (2021-01-31) backported into a CC base; Seal Lua REST on master only (uid 0, port 16667) |
| Package arches | **`ipq`** (plus `all`, `noarch`) — same for RBRE and RBSE |
| Compatible SDK availability | **NONE on local system.** NETGEAR GPL archive would be needed; alternatively reconstruct toolchain = musl 1.1.16 + GCC 5.2.0 r49254 + CC 15.05.1 SDK. Documented in `build-and-install.md`. |

See `network-capability-matrix.md` for the Phase 2 feature inventory.
