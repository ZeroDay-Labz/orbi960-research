# Orbi RBRE960 / RBSE960 - Consolidated Research Dossier

Date: 2026-11-02 - Owner-authorized security research on personally owned hardware.
This document indexes and summarizes everything completed so far. Detailed evidence
lives in the per-topic reports cited below; this is the map + the current state.
Evidence labels: VERIFIED / STRONGLY INDICATED / HYPOTHESIS / UNKNOWN / RULED OUT.

Sanitization: device identifiers (MACs, serial) are redacted here and across the repo;
real values live only in the git-ignored `orbi_local_config.json`. See `SANITIZATION.md`.

---

## 0. Scope & devices

| Role | Model | Firmware (running) | Mgmt IP | Root SSH |
|---|---|---|---|---|
| Master router | RBRE960 | V7.2.7.15_5.1.16 | <router-ip> | **VERIFIED (uid 0)** via stock Seal `enable_ssh` |
| Satellite 1 | RBSE960 | V7.2.7.15 | discovered (was <satellite-1-ip>) | **not reachable in-boundary** |
| Satellite 2 | RBSE960 | V7.2.7.15 | discovered (was <satellite-2-ip>) | **not reachable in-boundary** |

Firmware images held locally and analyzed: RBRE960 7.2.7.15 & 7.2.8.8; RBSE960 7.2.7.15 & 7.2.8.8.
Latest available update line: **7.2.8.8** (both models).

---

## 1. Master (RBRE960) root access - DONE & VERIFIED

**Mechanism (stock, owner-authenticated - not an exploit):** `POST /api/v1/enable_ssh`
(Seal REST, lighttpd proxies `^/api/` -> localhost:16667). JSON `{username,password,pubkey}`;
`verify_admin` (admin user + SHA-256(password) vs digest) + a <=5-attempt counter (resets on
reboot). On success it writes the caller's **public** key to `/etc/dropbear/authorized_keys`
and starts `dropbear -s -g -p 22 -K 300 -T 3 -R` (key-only root).

**Connect:** `ssh -i ~/.ssh/orbi_rbre960_rsa root@<router-ip>` with old-algo flags
(`HostKeyAlgorithms=+ssh-rsa`, `PubkeyAcceptedAlgorithms=+ssh-rsa`) -> `uid=0(root)`.
Helpers: `seal_dropbear_enable.py` (enable), `orbi_root_shell.py` (connect/verify).
Notes: Dropbear does **not** auto-start (dangling boot wiring) and regenerates its host key
on each start, so re-run the enable after a reboot and re-accept the host key.

Detail: `RBRE960_ROOT_ACCESS_RESEARCH.md`, `RBRE960_ROOT_ACCESS_WRITEUP.md`.

---

## 2. Firmware acquisition, verification & extraction - DONE

- 4 `.chk` images located, hashed (SHA-256), model/version confirmed from embedded
  `metadata.txt` + CHK `board_id` (not filename). Board gate: RBRE=`U12H451T00_NETGEAR`,
  RBSE=`U12H452T00_NETGEAR` -> **not cross-flashable**. (VERIFIED)
- Container chain: `CHK (0x2a23245e, 58-B header, board_id) -> U-Boot FIT (d00dfeed) -> UBI ->
  volumes {kernel (FIT), ubi_rootfs (squashfs xz), rootfs_data (overlay, ships empty)}`.
- SoC **Qualcomm IPQ807x**; OS = NETGEAR fork of OpenWrt Chaos Calmer, kernel 4.4.60, armv7l,
  musl, procd. All four rootfs extracted to `firmware_analysis/extracted/{rbre,rbse}_{7215,7288}/rootfs`.

Detail + hashes: `firmware_analysis/reports/00_discovery_and_verification.md`.

---

## 3. RBRE960 7.2.7.15 -> 7.2.8.8 diff & SSH persistence - DONE

- `enable_ssh` handler (`seal-development.lua`) **byte-identical** across versions; dropbear
  binary identical -> **the master's root method survives the upgrade** (re-run the POST). (VERIFIED)
- `rest.lua` dispatcher hardened in 7.2.8.8 (drops spoofable X-Forwarded-For/localhost trust ->
  internal-only header; adds route allowlist + path-traversal check). Does **not** change the
  credentialed `enable_ssh` contract. (VERIFIED strings; STRONGLY INDICATED for route equivalence)
- Overlay/key persistence across a firmware upgrade is **path-dependent** (sysupgrade keep-list
  would preserve `/etc/dropbear/`; raw `flash.scr`/NMRP wipes it; A/B slot gets a fresh empty
  overlay). The GUI-upgrade path is the open UNKNOWN (httpd is proprietary).

Detail: `firmware_analysis/reports/10_comparison_ssh_persistence.md`.

---

## 4. RBSE960 satellite administration - DONE (the core of this phase)

**The satellites are built to be managed *through* the router, with no owner SSH-enable path.**

- **No Seal / `enable_ssh` on the satellite** - no `www-seal/`, no handler, no `/api` proxy.
  Runtime-proven: `POST /api/v1/enable_ssh` -> **HTTP 404** on both satellites. (VERIFIED)
- The satellite *does* ship an intended, admin-password-authenticated remote-shell facility -
  but it is a **vendor remote-support** design, not owner-usable:
  `remoteshellenable` (magic packet `AMBIT_TELNET_ENABLE`, admin-password-derived) -> starts
  **OpenSSH sshd**, which is **pubkey-only against a NETGEAR key** (`/etc/ssh/id_rsa.pub`,
  `root@<vendor-build-host>`, private half held by NETGEAR, on neither device) + `ForceCommand`
  that re-checks the admin password. So the admin password brackets a key layer you don't hold. (VERIFIED)
- **Dropbear** present and its `/etc/init.d/dropbear` is a real init with `S19dropbear`
  (auto-starts if enabled) - but `/etc/config/dropbear` ships `enable='0'` and there is **no
  remote way to flip it**. Runtime: TCP 22 and 23 **closed** on both. (VERIFIED)
- **Telnet** (`login.sh`, admin-password -> root) present but **dormant** - nothing creates
  `/tmp/telnet_enabled`. (STRONGLY INDICATED). *Completeness note (VERIFIED):* a real
  `set_telnet_enable`/`get_telnet_status` **is** compiled into `usr/lib/libuiapi.so` (it touches
  `/tmp/telnet_enabled` and runs `/etc/init.d/telnet`), but it is **orphaned** - no shipped daemon
  or rpcd plugin imports that symbol, and the only object that registers `netgear.log`
  (`debuglog.so`) has no telnet method. So the capability exists as dead code + a dead GUI button;
  it is not remotely invokable. This explains why the ACL entry and GUI control exist.
- **ubus/rpcd** is LAN-reachable (`/ubus` proxied; HTTP 200) and admin-authenticated, but its
  ACL grants `uci` **read-only** and no write/shell method; the ACL's `telnet_enable` is **not
  implemented** in the shipped `debuglog.so`. (VERIFIED)
- **soap_agent** (master<->satellite channel) = firmware-update + diagnostics RPC (MD5 session),
  no enable-ssh / no generic write-exec. (VERIFIED)
- The satellite **SSH/telnet/ubus** components are **byte-identical between 7.2.7.15 and 7.2.8.8**
  (`dropbear` init+config, `netgear.json` ACL, `debuglog.so`, `libuiapi.so`, `init.d/telnet` all
  SAME). **`soap_agent` *differs*** between the two versions (it carries the firmware-update logic);
  the earlier blanket "all components byte-identical" was imprecise. (VERIFIED)

Detail: reports `20_rbse960_admin_diagnostics.md`, `21_rbse960_ssh_enablement_path.md`,
`22_rbse960_owner_ssh_implementation_plan.md`.

---

## 5. Firmware signing / custom-image feasibility - DONE (analysis only)

- **The kernel/rootfs firmware image is NOT cryptographically signed.** Gates are checksum +
  identity only: `upgrade_check` (CHK header + `board_id` + size), FIT **crc32** (0 signature
  nodes, both versions), `flash.scr` (no verify), soap/sysupgrade (MD5 integrity). No
  image-verification public key in the rootfs. Vendor's own FIT is unsigned => U-Boot doesn't
  require signed FITs. (STRONGLY INDICATED; components VERIFIED)
- The "signing" that exists is **Qualcomm secure boot over the bootloader** (SBL/QSEE/U-Boot;
  partitions present, fuse state UNKNOWN) - it does not gate the kernel/rootfs.
- => A minimally-modified RBSE960 image (enable dropbear + owner key, repack with correct
  CRC32/CHK/board_id) would be **accepted without circumventing a signature** = custom-rootfs
  route is feasible *in principle*. Preserve untouched: SBL1/MIBIB/QSEE*/DEVCFG*/APDP*/RPM*/
  CDT*/APPSBL*/**ART** (radio cal)/board_data/nvram. Safety net: A/B slots + NMRP + stock `.chk`.

Detail: `firmware_analysis/reports/23_rbse960_firmware_signing_feasibility.md`.

---

## 6. Tooling built

| File | Purpose |
|---|---|
| `seal_dropbear_enable.py` + test | Master: stock `enable_ssh` client (root via owner key). |
| `orbi_root_shell.py` | Master: connect / verify uid 0 / interactive shell. |
| `orbi_telnet_enable.py` | Legacy telnet-enable (old 128-B protocol; superseded on 7.2.7.15). |
| `orbi_satellite_ssh.py` + test | Satellites: discover / status / plan / enable / verify / rollback. Read-only by default; `enable` refuses unless an authorized first-shell exists (no exploit). 25 mocked tests. |
| `orbi_local_config.json` | **Git-ignored** real device identifiers (MACs/IPs/keys). |

Detail: `README_orbi_satellite_ssh.md`.

---

## 7. Current state & the open decision

- Master: owner root, repeatable. Satellites: **no in-boundary route to a shell** exists; the
  tool correctly refuses to invent one.
- To get satellite root you must pick (owner decision; nothing will be done without approval):
  - **A. Vendor key on the master** - **RULED OUT (VERIFIED 2026-11-02, live master root shell).**
    Read-only recon of the running master found the fleet **public** key (`root@<vendor-build-host>`) but
    **no SSH private key anywhere** on the device (only Bitdefender/Circle TLS `.pem` certs), and
    **no on-device private key derives the fleet pubkey**. So the master cannot drive the
    satellite's vendor `remoteshellenable`->`sshd` path. Observed master<->satellite plane: `hyd` +
    `wsplcd` (mesh/SON) and a SOAP client (`soapc`, `/tmp/soapc_log`) = firmware-update +
    diagnostics only - no shell/key channel.
  - **B. Modified firmware** via the vendor update channel - feasible (no signature to defeat),
    but requires flashing (brick risk; needs NMRP recovery + A/B validation first). **Deferred by
    owner; not started.**
  - **C. UART** - standard for owned hardware, lowest brick risk - **excluded by project rules.**
  - **D. Exploitation / command injection** - **prohibited** and will not be done.

---

## 8. Report index

| # | File | Topic |
|---|---|---|
| 00 | `00_discovery_and_verification.md` | Firmware acquisition, hashes, extraction |
| 10 | `10_comparison_ssh_persistence.md` | RBRE 7215<->7288 diff, SSH upgrade persistence |
| 20 | `20_rbse960_admin_diagnostics.md` | Satellite admin/shell mechanisms |
| 21 | `21_rbse960_ssh_enablement_path.md` | Runtime recon, soap_agent RE, reversible runbook |
| 22 | `22_rbse960_owner_ssh_implementation_plan.md` | ubus/rpcd investigation, tool design, blocker |
| 23 | `23_rbse960_firmware_signing_feasibility.md` | Signing analysis, custom-image feasibility |
| 24 | `24_rbre_to_rbse_management_plane_map.md` | Master-to-satellite management-plane map |
| 25 | `25_remoteshellenable_analysis.md` | remoteshellenable / init_sshenable analysis |
| 26 | `26_owner_control_capability_assessment.md` | Owner-control platform: VLANs, rollback, capability classes |
| 30 | `30_consolidated_research_dossier.md` | (this document) |
| - | `RBRE960_ROOT_ACCESS_RESEARCH.md` / `_WRITEUP.md` | Master root access (primary docs) |
| - | `REPRODUCE.md` | Repeatable path to recreate this state |
| - | `SANITIZATION.md` | What is redacted + pre-share checklist |

---

## 9. Standing safety posture (unchanged)

Static/read-only analysis preferred. No factory reset, no UART, no bootloader/flash changes,
no firmware flashing this phase, no custom firmware build yet. No password guessing, auth
bypass, command injection, or exploitation of management services. No device-changing command
without explicit owner approval, with effect + rollback stated first. Credentials/keys kept out
of source, logs, and reports.
