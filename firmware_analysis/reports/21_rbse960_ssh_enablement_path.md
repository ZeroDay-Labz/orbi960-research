# RBSE960 - SSH Enablement Path: Runtime Recon, soap_agent RE, and Reversible Runbook

Date: 2026-11-02 - Companion to `20_rbse960_admin_diagnostics.md`
Covers: (a) authorized read-only runtime recon of the live satellites, (b) offline RE of
the satellite `soap_agent` (the master<->satellite management channel), (c) a reversible
end-state runbook for owner-controlled dropbear SSH - **pending** a bootstrap channel.
Evidence labels: VERIFIED / STRONGLY INDICATED / HYPOTHESIS / UNKNOWN / RULED OUT.

---

## 1. Runtime recon of the live satellites (read-only, user-authorized) - VERIFIED

Both satellites on the LAN, probed from the workstation (no changes made):

| | <satellite-1-ip> | <satellite-2-ip> |
|---|---|---|
| MAC (ARP) | `<SAT1_MAC>` | `<SAT2_MAC>` (NETGEAR OUI, redacted; real values in git-ignored `orbi_local_config.json`) |
| `currentsetting.htm` | Model=**RBSE960**, Firmware=**V7.2.7.15**, RegionTag=RBSE960_NA, Region=US | identical |
| SOAP | SOAPVersion 3.63, SOAP_HTTPs_Port 443 | identical |
| TCP 22 (ssh) | **closed** | **closed** |
| TCP 23 (telnet) | **closed** | **closed** |
| TCP 53 / 80 / 443 | open / open / open | open / open / open |

**Conclusions (VERIFIED):**
- Both devices independently confirmed as RBSE960 running **7.2.7.15** - exactly the image
  analysed statically (resolves the prior "inferred from filename/ARP" caveat).
- **Dropbear and telnet are confirmed OFF right now** (22 and 23 closed) - matches the
  static finding that nothing auto-starts them on the satellite.
- The only admin-reachable surfaces are **80/443 (lighttpd + SOAP)** and 53 (dnsmasq).
  So any remote management of a satellite goes through the SOAP agent on 443.

## 2. Master <-> satellite channel = `soap_agent` (offline RE) - what it is, and what it is NOT

Binary: `usr/sbin/cgi-bin/soap_agent` (served as `www/soap/server_sa`),
SHA-256 `a3ee8ac93b41ac52de17e53051b9569f3b063deca0cd585de6337cb1dcf12502`,
ELF ARM musl, 408 procedures, decompiled with Ghidra.

**What it IS (VERIFIED from symbols/strings):** an ONC-RPC + SOAP agent (rpcgen `*_1`
version-1 stubs, XDR serializers) that the **master (CAP) uses to manage the satellite
(RE)**. Its intended action surface:
- Firmware lifecycle: `UpdateNewFirmware2`, `CheckAndDownloadNewFirmwareByFolder`,
  `xdr_UpdateFirmware2ResponseCode`, `FirmwareCheckStatus` (`DOWNLOADED`/`DOWNLOADING`/
  `FAILED_TO_GETINFO_OR_DOWNLOAD`), writes `/tmp/firmware_log.txt`, `/tmp/fileinfo1.txt`.
- Device/diagnostics: `board_data -r %s` (product/board info), throughput test
  (`tput_mid`/`tput_avg`/`TestDuration` -> `tput_measure`), `SystemWps`, DeviceConfig
  service (`urn:NETGEAR-ROUTER:service:DeviceConfig:1`), `PasswordHash`.
- Session auth: `authenticate_satellite_1()`, `/tmp/sessionId.txt`,
  `/tmp/authResponse.xml`, MD5-based (`Invalid Authentication username`,
  `MD5SUM calculation failed`, `Authentication failed`) - i.e. the master authenticates
  with the **admin credential** and gets a session.
- Spawns helpers via `popen`/`posix_spawn` with **fixed internal command strings**
  (`board_data -r ...`, `/etc/init.d/init_configd`, `tput_measure`) - not a generic
  command interface.

**What it is NOT (VERIFIED / STRONGLY INDICATED):**
- **No SSH/dropbear/telnet-enable action.** No `enable_ssh`, `dropbear`, `authorized_keys`,
  `remoteshell`, or `/tmp/telnet_enabled` anywhere in the binary. (Consistent with the
  satellite deliberately shipping without the router's Seal `enable_ssh`.) VERIFIED.
- **No general "write arbitrary file" or "run arbitrary command" action** in the intended
  surface. The `popen` command templates observed are fixed, not request-shaped. STRONGLY
  INDICATED (the observable action set is firmware/diagnostics only).

-> **The vendor master->satellite channel cannot, by its intended design, enable dropbear or
install an owner key.** (STRONGLY INDICATED - it exposes firmware-update + diagnostics, not
shell/key provisioning.)

## 3. The fleet SSH key, re-confirmed - RULED OUT for the owner

- Master and satellite ship the **identical** `/etc/ssh/id_rsa.pub`
  (`<vendor-fleet-key-fingerprint>`, `root@<vendor-build-host>`).
- **No matching private key exists on the master or the satellite** (searched both trees).
  **Runtime-confirmed on the live master 2026-11-02** (root shell, read-only): no SSH private key
  present anywhere on the device (only Bitdefender/Circle TLS `.pem` certs), and no on-device
  private key derives the fleet pubkey. (VERIFIED)
- -> The satellite's vendor OpenSSH path (magic packet -> sshd) cannot be completed by the
  owner, and the master cannot use it to reach satellites either. RULED OUT as an
  owner channel. (VERIFIED)

## 4. The core tension (must be decided before any action)

The objective - **owner-controlled SSH on each satellite** - is achievable *as an end state*
(§5). But **every** way to perform the *first* change on a satellite crosses one of the
constraints set for this project:

| Candidate bootstrap | Status | Conflicts with |
|---|---|---|
| Router Seal `enable_ssh` relayed to satellite | **RULED OUT** | n/a - doesn't exist on RBSE |
| Vendor OpenSSH (magic packet + key) | **RULED OUT** | needs NETGEAR private key (not held) |
| `soap_agent` **intended** actions | **RULED OUT** | no enable-ssh / no write-exec by design |
| `soap_agent` **command injection** on a firmware/diag param | HYPOTHESIS (unverified; not attempted) | project rule: *no command injection / no exploitation of satellite management services* |
| Push a **modified satellite firmware** via `UpdateNewFirmware2` | HYPOTHESIS (heavy) | project rule: *do not modify satellite firmware*; also board-gate/signature + brick risk |
| UART / serial console | out of scope | project rule: *no hardware/UART* |

So within the boundaries as written, **there is no clean path to enable a satellite's
dropbear.** NETGEAR built the RBSE deliberately without an owner SSH-enable mechanism; the
router's Seal method has no satellite analogue. (STRONGLY INDICATED - exhaustive over the
reachable surfaces and the extractable code.)

This is a genuine decision point for the device owner (see §6). No device-changing step
is taken without explicit, specific authorization and a stated rollback.

## 5. End-state runbook (owner-controlled dropbear) - REVERSIBLE, pending a §4 bootstrap

*This is the target once a write/exec channel on a satellite exists. It assumes you have
accepted a §4 route. It changes only the overlay; it does not touch mesh, Wi-Fi, radio
calibration, the bootloader, or any flash partition. Fully reversible.*

Why this is clean on the satellite (VERIFIED from §20 report): the satellite's
`/etc/init.d/dropbear` is a real, working OpenWrt init and `S19dropbear` is present, so it
auto-starts at boot from `/etc/config/dropbear` - no dangling-symlink problem like the
router had.

**Enable (run on the satellite, as root, via the chosen bootstrap):**
```sh
# 1. install YOUR public key (owner key; never a private key on the device)
mkdir -p /etc/dropbear
cat >> /etc/dropbear/authorized_keys <<'EOF'
<your-ssh-rsa-public-key-here>
EOF
chmod 0600 /etc/dropbear/authorized_keys

# 2. turn on key-only dropbear in UCI (persists in the overlay; auto-starts via S19)
uci set dropbear.@dropbear[0].enable='1'
uci set dropbear.@dropbear[0].PasswordAuth='off'      # key-only; empty root pw stays unusable
uci set dropbear.@dropbear[0].RootPasswordAuth='off'
uci commit dropbear

# 3. start it now without reboot
/etc/init.d/dropbear enable
/etc/init.d/dropbear start
```
Then from the workstation: `ssh -i ~/.ssh/orbi_rbre960_rsa root@<satellite-1-ip>` (and `...@<satellite-2-ip>`).
Dropbear on the satellite is 2019.78-x; the same old-algorithm client flags used for the
router may be needed. The key lives in the writable overlay -> **survives reboot**.

**Rollback (full):**
```sh
/etc/init.d/dropbear stop
/etc/init.d/dropbear disable
uci set dropbear.@dropbear[0].enable='0'; uci commit dropbear
rm -f /etc/dropbear/authorized_keys
```
After rollback, port 22 is closed again and the overlay is back to stock. A firmware
upgrade that rewrites the rootfs would also clear it (per report `10`).

**Safety notes:** touches only `/etc/config/dropbear` + `/etc/dropbear/authorized_keys` in
the overlay; `repacd`/`wsplcd`/`hyd`/`lbd` mesh and all Wi-Fi/routing are untouched; no
flash partition, bootloader, or calibration data is written. Do **one** satellite first,
verify, then the second.

## 6. Recommendation & open decision

- **Recon + static analysis are complete** for the satellite question. The honest result:
  the satellites have **no vendor-intended, owner-usable SSH-enable mechanism**, and the
  clean remote channels are all ruled out (§4).
- **Lowest-risk, in-boundary outcome:** leave the satellites without SSH (the mesh and
  router-root management are unaffected), and manage them through the router as NETGEAR
  intends.
- **If satellite root is worth relaxing a boundary**, the two real options are
  (a) the **modified-firmware route** via the vendor `UpdateNewFirmware2` channel - this is
  the Phase-Three custom-firmware project for the RBSE, and must not proceed until image
  signing/validation and a **recovery path** are established (brick risk), or (b) a
  **controlled command-injection** against `soap_agent`'s authenticated firmware/diagnostic
  parameters - faster, but it is exploitation of a management service and would require
  explicit, written re-authorization because it steps over the "no command injection /
  no exploitation" project rule.

**Open decision:** accept no-SSH on satellites, or authorize investigation of
one specific boundary-relaxed route (and which). No device-changing step runs before
that.

---

*No credentials, password hashes, or private keys are reproduced here. `id_rsa.pub`
fingerprint is public key material. Runtime recon was read-only; no satellite was modified.*
