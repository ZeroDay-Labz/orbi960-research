# RBSE960 Owner-SSH Provisioning - Implementation Plan & Bootstrap Investigation

Date: 2026-11-02 - Companion to reports `20` and `21`
Deliverable for the `orbi_satellite_ssh.py` utility.
Evidence labels: VERIFIED / STRONGLY INDICATED / HYPOTHESIS / UNKNOWN / RULED OUT.
Distinguishes **offline analysis**, **live read-only tests**, and **config changes**.

---

## 0. Bottom line

- The read-only half of the objective is fully met: a utility that **discovers**
  the two RBSE960 satellites, confirms identity/firmware, and reports SSH/dropbear
  status, using only legitimate read-only interfaces. (Built, tested.)
- The write half has a **verified blocker**: the RBSE960 firmware exposes **no
  supported remote configuration operation** that can enable dropbear, install an
  `authorized_keys`, or open a root shell. This was checked at the *implementation*
  level, not just from ACL/config text.
- Per the project rule ("if no supported route exists, report the blocker; do not
  silently substitute an exploit"), `enable --apply` is implemented to **apply the
  verified, reversible change the moment an authorized first-shell transport
  exists, and otherwise refuse** with the documented blocker.

## 1. Management interfaces discovered on the satellite (LAN-reachable)

Live read-only probe (2026-11-02, both satellites, no changes): open TCP =
**53, 80, 443**; **22 and 23 CLOSED**. `http://<ip>/currentsetting.htm` ->
Model=RBSE960, Firmware=V7.2.7.15. (VERIFIED)

| Interface | Transport | Auth | Can it enable dropbear / write files / shell? |
|---|---|---|---|
| `currentsetting.htm` | http :80 | none | No (read-only identity) |
| SOAP `soap_agent` (`/soap/server_sa`, `soapapi.cgi`) | http/https :80/:443 | admin MD5 session (`authenticate_satellite_1`) | **No** - firmware update + diagnostics only (report 21 §2) |
| **ubus JSON-RPC** (`/ubus` -> lighttpd proxy -> `localhost:8000`) | http/https :80/:443 | ubus session (`session login`) | **No** - see §2 |
| `webui-io` upload/download | via SOAP/ubus | admin | No (firmware staging, validated) |
| Wi-Fi mesh (`repacd`/`wsplcd`/`hyd`/`lbd`) | backhaul | internal | No (Wi-Fi config sync; out of scope to touch) |
| Vendor OpenSSH (magic packet -> sshd) | UDP + :22 | admin packet **+ NETGEAR private key** | RULED OUT for owner (key not held; report 20 §3) |

## 2. ubus / rpcd investigation (the most promising lead) - VERIFIED

- lighttpd `conf.d/30-proxy.conf` proxies `/ubus` -> `localhost:8000`, so the ubus
  RPC endpoint **is reachable from the LAN on 80/443** (live: `POST /ubus` -> HTTP
  200 on both satellites). (VERIFIED)
- rpcd ACL `usr/share/rpcd/acl.d/netgear.json` - an authenticated session's rights:
  - **read:** `uci ["*"]`, `system info`, `session`, `netgear.get`
    (pot_details, satellite_status, connected_device, get_language),
    `netgear.log` statuses, `netgear.upgrade` status, `webui-io download`.
  - **write:** `netgear.log` {ntgrlog_start/stop, log_boot_enable/disable,
    **telnet_enable/telnet_disable**, packet_capture_start/stop},
    `netgear.upgrade upgrade_start`, `netgear.set set_language`, `webui-io upload`.
- **Critical correction (VERIFIED):** the `telnet_enable`/`telnet_disable` methods
  named in the ACL are **NOT implemented** by the shipped plugin. `netgear.log` is
  provided by `usr/lib/rpcd/debuglog.so`, whose registered methods are only
  `ntgrlog_*`, `log_boot_*`, `packet_capture_*` (string `telnet` does not occur in
  the binary; the master `rbre_7215` does not even ship `debuglog.so`). The ACL is a
  shared NETGEAR superset; the method is absent on these devices. So the
  "authenticated telnet-enable over ubus" path **does not exist** here.
  - *Completeness note (VERIFIED):* a real `set_telnet_enable`/`get_telnet_status` **is**
    compiled into `usr/lib/libuiapi.so` (touches `/tmp/telnet_enabled`, runs `/etc/init.d/telnet`),
    but it is **orphaned** - no shipped binary imports that symbol (it occurs only inside
    `libuiapi.so`; the four rpcd plugins link the lib but call other functions), and no ubus object
    registers a telnet method reaching it. Byte-identical in 7.2.7.15 and 7.2.8.8. So the helper is
    dead code behind a dead GUI button; it is not remotely invokable. This is *why* the ACL entry
    and GUI control exist, and it does not open a path.
- **Net result:** via ubus the owner can legitimately **read** all uci config
  (good for status) but has **no write method** that enables dropbear, writes a
  key, or runs a shell; `uci` is **read-only** in the ACL. (VERIFIED)

Evidence: `firmware_analysis/extracted/rbse_7215/rootfs/etc/lighttpd/conf.d/30-proxy.conf`,
`usr/share/rpcd/acl.d/netgear.json`, `usr/lib/rpcd/debuglog.so`
(sha256 `1115fa0379...`, Ghidra).

## 3. The blocker, stated precisely (VERIFIED)

> There is no shipped, authenticated, remote configuration operation on the
> RBSE960 (7.2.7.15 or 7.2.8.8) that can set `dropbear.enable`, write
> `/etc/dropbear/authorized_keys`, or otherwise yield a root shell - and the
> satellite ships with TCP 22/23 closed. The router's Seal `enable_ssh` has no
> satellite analogue; the vendor OpenSSH path needs a NETGEAR-held key; the ubus
> surface is uci-read-only.

Reaching a satellite root shell therefore requires a route that crosses a project
boundary (all currently prohibited for this phase):
- command injection / exploitation of `soap_agent` or a `popen`-based ubus method;
- a **modified firmware** pushed via the vendor `UpdateNewFirmware2` upgrade channel
  (firmware flashing; signature/board gate; brick risk);
- the NETGEAR private key (not held);
- UART/serial (hardware; excluded).

This matches the §4C expectation. The utility does not cross any of these; it
reports the blocker and stops.

## 4. The change set (verified, minimal, reversible) - applied only via an authorized transport

Once a root shell exists on a satellite (by a means you authorize), the exact
owner-SSH change is (VERIFIED safe against the satellite init/config semantics in
report 20):

1. `cp -a /etc/config/dropbear /etc/config/dropbear.orbitool.bak` (backup)
2. `mkdir -p /etc/dropbear && chmod 0700 /etc/dropbear`
3. install owner **public** key idempotently into `/etc/dropbear/authorized_keys`
   (`grep -qF ... || echo ... >>`), `chmod 0600`
4. `uci set dropbear.@dropbear[0].enable='1'`, `PasswordAuth='off'`,
   `RootPasswordAuth='off'`, `uci commit dropbear`
5. `/etc/init.d/dropbear enable; /etc/init.d/dropbear restart`

**Why this is clean on the satellite (VERIFIED, report 20):** `/etc/init.d/dropbear`
is a real OpenWrt init and `S19dropbear` is present, so step 4 makes dropbear
**auto-start on every boot**; the key lives in the writable overlay so it **survives
reboot**. Dropbear is 2019.78 (old algorithms -> the same client flags as the router).

**Scope guarantees (VERIFIED by `test_no_mesh_or_flash_commands`):** touches only
`/etc/config/dropbear` and `/etc/dropbear/authorized_keys`; no `hyd/wsplcd/repacd/lbd`,
no Wi-Fi/radio/backhaul, no `mtd/nand/flash_erase/sysupgrade`, no firewall flush.

**Firewall:** inspected read-only first; the satellite's LAN input zone normally
already accepts LAN traffic. A LAN-only input rule for :22 is added **only if** :22
is not already reachable; SSH is never exposed on WAN.

**Rollback:** `/etc/init.d/dropbear stop; disable`; restore the uci backup (or
`enable='0'`); remove **only** the owner key this tool installed (matched by its
`orbi-rbre960-root` comment - never a blanket wipe of `authorized_keys`).

## 5. The utility - `orbi_satellite_ssh.py`

Stdlib-only, Python 3.11+. State in `~/.orbi_satellite_ssh/` (backups, audit logs,
tool-managed `known_hosts`, TLS cert pins).

| Mode | R/W | What it does |
|---|---|---|
| `discover` | read | master-SSH neighbour/lease tables -> match known MACs -> confirm via `currentsetting.htm`; prints inventory. |
| `status [--admin]` | read | ports 22/23, firmware/identity, and (with `--admin`) dropbear uci via an authenticated ubus session. |
| `plan` | read | prints the exact change set + the bootstrap blocker. |
| `enable --satellite N [--apply]` | write* | identity check -> backup -> resolve transport -> confirm -> apply -> verify. *Refuses with the blocker if no authorized transport (:22/:23) is open. One satellite at a time, explicit `yes`. |
| `verify --satellite N` | read | TCP 22, `ssh root@... id` (UID 0), mesh-daemon liveness. |
| `rollback --satellite N` | write | reverts this tool's changes over SSH; removes only the tool's key. |

Security properties (enforced/[tested]): single deliberate auth, never a guessing
loop; `getpass` for passwords, never on argv; private-key material refused as input
and redacted from logs; TLS cert **pinning** (not blanket `verify=off`); SSH host-key
pinning via a tool-managed `known_hosts` (`accept-new`); explicit timeouts; never
reports success unless SSH + UID 0 are independently verified.

Transport design: `enable`/`rollback` act over an **authorized** transport only -
`SSHTransport` when :22 is already up (re-runs, key rotation, rollback). A telnet
transport is deliberately *not* implemented unless telnet was opened by an
authorized means (`resolve_transport` raises `BootstrapUnavailable` and explains).

## 6. Compatibility across firmware versions

All satellite SSH/admin/ubus/rpcd components are **byte-identical between 7.2.7.15 and
7.2.8.8** (report 20 §7; `netgear.json`/`debuglog.so`/`dropbear` init all SAME). The
change set and the blocker apply equally to both. (VERIFIED)

## 7. Known limitations / open items

- `enable --apply` cannot self-bootstrap a fresh satellite (no supported route) -
  **by design and by evidence**, not a bug. (VERIFIED blocker.)
- `netgear.get`/`system info` field availability at runtime is UNKNOWN beyond what the
  ACL lists; `status --admin` degrades gracefully if a read is unavailable.
- Whether a controlled upgrade via `UpdateNewFirmware2` could carry a minimally
  modified, board-valid image is UNKNOWN and out of scope this phase (needs the image
  signing/validation + recovery analysis first; brick risk).

## 8. Decision required to achieve satellite root (unchanged from report 21)

Either (A) accept satellites remain non-SSH (fully in-boundary; mesh + router-root
management intact), or (B) authorize one specific boundary-relaxed bootstrap - the
modified-firmware upgrade route (preferred over injection; still needs recovery
analysis first). No device-changing step runs without explicit owner approval.

---

*No credentials, hashes, or private keys are reproduced here. Runtime probes were
read-only; no satellite was modified.*
