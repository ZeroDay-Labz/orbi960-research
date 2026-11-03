# RBRE960/RBSE960 7.2.7.15 -> 7.2.8.8 - Comparison, SSH & Persistence

Date: 2026-11-02 - Offline, read-only static analysis
Covers deliverables #1 (RBRE old/new), #3 (RBRE vs RBSE), #4 (SSH/persistence), #5 (upgrade/recovery).
Evidence labels: VERIFIED / STRONGLY INDICATED / HYPOTHESIS / UNKNOWN / RULED OUT.

Extraction provenance (all from local `.chk`, verified by embedded `metadata.txt`):
`CHK(0x2a23245e)+58B -> FIT(d00dfeed) -> UBI -> unsquashfs(ubi_rootfs, squashfs4.0/xz)`.
Images: `firmware_analysis/extracted/{rbre_7215,rbre_7288,rbse_7215,rbse_7288}/rootfs`.

---

## A. Platform (VERIFIED)

- SoC **Qualcomm IPQ807x**; firmware = QSDK/OpenWrt-derived (rootfs node `openwrt-ipq-ipq807x-ubi-root.img`).
- `flash.scr` gates: `soc_hw_version in {200d0100,200d0101,200d0102,200d0200}`, `machid in {8010000,801000d,8010500}`.
- NAND: page 2048, erase 128 KiB. UBI volumes: `kernel`, `ubi_rootfs` (squashfs), `rootfs_data` (overlay, **ships empty, 0 blocks in all 4 images**).
- Board gate (CHK `board_id`): RBRE=`U12H451T00_NETGEAR`, RBSE=`U12H452T00_NETGEAR` -> **not cross-flashable**.

## B. SSH enablement across the upgrade (objective 2) - the key result

| Component | 7.2.7.15 | 7.2.8.8 | Verdict |
|---|---|---|---|
| `enable_ssh` handler `usr/share/lua/seal-development.lua` | sha `566a85a6...` | sha `566a85a6...` | **byte-identical - handler UNCHANGED** (VERIFIED) |
| Seal REST dispatcher `www-seal/rest/rest.lua` | 7670 B | 8291 B | **changed - security hardening** (VERIFIED) |
| Dropbear `/usr/sbin/dropbear` | 2019.78-2 | 2019.78-2 | same version/binary (VERIFIED) |
| `dropbearkey`, `dbclient`, `/etc/config/dropbear`, host key | present | present | present (VERIFIED) |
| Boot autostart (`rc.d/S19dropbear -> init.d/dropbear`) | symlink present, **target absent** | same | **dangling in both - no boot autostart** (VERIFIED) |
| `authorized_keys` in stock squashfs | absent | absent | created at runtime into overlay (VERIFIED) |

**Handler contract (re-read from the identical bytecode, confirms prior research):**
POST `/api/v1/enable_ssh` (JSON `{username,password,pubkey}`) -> `verify_admin` via
`seal plat get_admin_username` / `get_admin_password_digest`; rate limit `/tmp/enable-ssh-attempt-counter`
(<=5, resets on reboot); on success writes pubkey to `/etc/dropbear/authorized_keys`, `rm`s the RSA host
key, launches `/usr/sbin/dropbear -P /var/run/dropbear.pid -s -g -p 22 -K 300 -T 3 -R`
(`-s` no-password, `-g` no-root-password-login, `-R` regen host key). -> key-only root on :22.

**rest.lua dispatcher change (string-constant diff):**
- Added: route-name allowlist `^[A-Za-z0-9_-]+$`, `%.%.` path-traversal check, `HTTP_X_SEAL_INTERNAL`
  internal-request header, `Bad Request` / `Invalid request` rejections, `ProxyInternal`.
- Removed: `HTTP_X_FORWARDED_FOR`, `HTTP_X_HOST`, `HostAddr`, `ServerAddr`, `localhost`, `localhost`.
- Interpretation (STRONGLY INDICATED): replaces spoofable X-Forwarded-For/localhost trust with an
  internal-only header + stricter input validation. A generic dispatcher hardening (consistent with the
  release notes' "security fixes"); it does **not** alter the credentialed `enable_ssh` contract.
- NOTE: full bytecode decompile of rest.lua is pending (vendor Lua uses number-const tag 9 / 4-byte
  lua_Number; needs unluac or the patched parser). Until then, "route unchanged for the credentialed
  path" is STRONGLY INDICATED, not VERIFIED.

**Bottom line (objective 2):** The owner-authenticated enable_ssh mechanism **remains fully available on
7.2.8.8** - identical handler, same dropbear. After an upgrade you re-run the same POST (orbi_root_shell.py)
to reinstall your key and start dropbear. STRONGLY INDICATED (pending the rest.lua decompile + a live test).

## C. Overlay / key persistence across an upgrade - PATH-DEPENDENT (correction)

There are two upgrade paths with opposite effects; the stock image shipping `rootfs_data` empty means the
new rootfs boots with an empty overlay unless something restores files.

1. **OpenWrt `sysupgrade`** (`/sbin/sysupgrade`, `/lib/upgrade/{common,nand,platform}.sh`):
   `lib/upgrade/keep.d/base-files:3` lists **`/etc/dropbear/`** -> sysupgrade backs it up and restores it,
   so **authorized_keys + host key would be PRESERVED**. [keep-list content VERIFIED]
2. **`flash.scr`** (U-Boot / NMRP recovery, raw `nand erase 0x11c00000 0x06d00000` + `nand write`): fully
   destructive -> overlay wiped. [VERIFIED]
3. **A/B dual-rootfs** (`platform.sh`: `/proc/boot_info/*/upgradepartition`, `primaryboot`, `rootfs`/`rootfs_1`):
   the running-system update flashes the **inactive** slot via `mtd write` and flips the active slot. The new
   slot has its own fresh (empty) `rootfs_data`. [STRONGLY INDICATED]

**UNKNOWN:** whether the NETGEAR **GUI** firmware-update actually invokes `sysupgrade`'s keep-list
save/restore across the A/B switch (httpd is a proprietary binary - not resolvable from scripts). This is
the single open question that decides whether your SSH key survives a normal GUI upgrade.
-> Resolve by: (a) Ghidra on `/usr/sbin/httpd` + `acos_service` to see the upgrade invocation, or
   (b) a controlled upgrade test on the live router (approval-gated; root access makes it observable/recoverable).

Reboot (no upgrade): overlay persists -> key survives, but dropbear still won't auto-start (dangling symlink).

## D. RBRE vs RBSE (deliverable #3) - major divergence (VERIFIED)

- **RBSE satellite firmware has NO Seal REST interface and NO enable_ssh at all**: no `www-seal/`, no
  `enable_ssh` string anywhere (text or binary), no `seal*.lua`/`rest.lua`. Only `/etc/seal_version` +
  `flash_eraseall` remain. `product_id = RBS`.
- RBSE **does** ship the dropbear binary, but there is **no owner-authenticated web mechanism to install a
  key and start it** - so the router's method does not transfer to the satellites as-is. (Root on satellites
  needs a different approach - open item.)
- Different NAND maps: rootfs UBI at RBRE `0x11c00000` (~109 MiB region) vs RBSE `0x03e80000` (~66 MiB).
- Different image scope: RBRE MODEL_ID `RBR960 RBRE960`; RBSE MODEL_ID `RBS960 RBSE960 RBSE950` (one
  satellite image covers 3 models). File counts: RBRE ~5295, RBSE ~4110.

## E. RBRE 7.2.7.15 -> 7.2.8.8 whole-image delta (deliverable #1)

- 9 files added, 10 removed, **1085 changed** of ~5295 (lists in `firmware_analysis` scratch manifests).
- Added: `etc/ntgr/rsu/applications/rae.json`, `etc/xagent/*/*.staging2.env` (telemetry/agent), `usr/bin/{general_info.sh,move_ssvc_syslog.sh,redirect_syslogs.sh}`.
- Removed: `etc/init.d/create_cronjob.init`, `etc/rc.d/S99create_cronjob.init`, `etc/RASwitch.sh`,
  `usr/bin/{seal_randcron,seal_randinit,trigger_event,d2_countryname.sh}`, `www/genie_bpa{,2}.htm`.
- **None of the added/removed files touch dropbear / enable_ssh / sshd.** The SSH surface change is confined
  to the rest.lua dispatcher hardening (section B).

## F. RBSE 7.2.7.15 -> 7.2.8.8 (deliverable #2, partial)

- Same container/UBI structure; same NAND map both versions. `seal-development.lua`/`rest.lua` absent in both
  (nothing to diff there). Full component diff still to run (binary/library deltas).

## G. Device-specific data to preserve (deliverable #10, preliminary)

- `flash.scr` erase ranges target **only** the rootfs UBI region, not lower/other NAND offsets -> ART/radio
  calibration, bootloader, and factory ID partitions are NOT in the firmware image and are left intact by an
  official upgrade. STRONGLY INDICATED; to be VERIFIED against the DTB `partitions` node (kernel-volume DTBs
  located at offsets 0x3ea63c+; `dtc` now available to decode them).

## Open items / next steps
1. Decompile both `rest.lua` (unluac or patched Lua-5.1/tag-9 parser) to VERIFY the enable_ssh route/auth is byte-for-byte equivalent.
2. Ghidra on `/usr/sbin/httpd` (+ `acos_service`) to determine the GUI upgrade path (sysupgrade vs raw) - resolves section C UNKNOWN.
3. Decode kernel-volume DTB `partitions` node -> authoritative NAND partition map (calibration/recovery).
4. Full RBSE 7.2.7.15<->7.2.8.8 binary diff (deliverable #2).
5. Custom-firmware feasibility (#6/#7): fetch NETGEAR GPL 7.2.8.8 source; assess OpenWrt ipq807x board support for RBRE960/RBSE960.
