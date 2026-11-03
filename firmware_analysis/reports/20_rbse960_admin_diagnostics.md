# RBSE960 Satellite - Administration & Diagnostic Mechanism Report

Date: 2026-11-02 - Offline, read-only static analysis - Owner-authorized (own hardware)
Scope: RBSE960 satellite firmware **7.2.7.15** and **7.2.8.8** root filesystems, already
extracted under `firmware_analysis/extracted/{rbse_7215,rbse_7288}/rootfs`.
No device was touched; no firmware or config was modified.

Evidence labels: VERIFIED / STRONGLY INDICATED / HYPOTHESIS / UNKNOWN / RULED OUT.
Provenance of every citation below: `CHK -> FIT -> UBI -> unsquashfs(ubi_rootfs)` chain
documented in report `00_discovery_and_verification.md`.

---

## 0. Executive summary

**The RBSE960 satellite does contain an intended, owner-authenticated remote-shell
facility - but it is a different mechanism from the router's Seal `enable_ssh`, and as
shipped it is gated by a NETGEAR-held SSH private key, which makes it a vendor/support
channel rather than an owner self-service one.** (VERIFIED for the mechanism; STRONGLY
INDICATED for the "not owner-completable with stock firmware alone" conclusion.)

The satellite's shell chain is:

```
LAN (br-lan) comes up
   └─ hotplug 95-ssh -> init.d/init_sshenable -> /usr/sbin/remoteshellenable  (daemon)
          └─ waits for NETGEAR "AMBIT_TELNET_ENABLE" magic packet
                 authenticated with the ADMIN WEB PASSWORD hash + LAN MAC
          └─ on valid packet: runs ssh_update_ntgr.sh, then `/etc/init.d/sshd start`
                 └─ OpenSSH sshd :22, PasswordAuth=no, pubkey only against
                    /etc/ssh/id_rsa.pub  (NETGEAR key; private half NOT in firmware)
                       └─ ForceCommand /bin/ssh_login_ntgr.sh
                              └─ prompts admin user/password, re-checks against
                                 the admin web password hash -> root ash shell (uid 0)
```

So there are **three** stacked gates - two of which (the magic packet and the
ForceCommand) are keyed to the owner's admin GUI password, and one of which (the SSH
pubkey) is keyed to a key the owner does not possess from the firmware.

**Every component of this chain is byte-for-byte identical between 7.2.7.15 and 7.2.8.8.**
(VERIFIED - see §7.)

The router's `enable_ssh`/dropbear method does **not** exist on the satellite and does
**not** transfer to it. (VERIFIED - confirms prior report `10`.)

---

## 1. What the satellite firmware does NOT have (RULED OUT)

- **No Seal REST interface, no `/api/v1/enable_ssh` handler.** No `www-seal/`, no
  `seal-development.lua`, no `rest.lua`, no `enable_ssh` string anywhere. The only Seal
  remnants are `etc/seal_version` and `usr/sbin/flash_eraseall`. (VERIFIED)
- Therefore the router's dropbear-key-install mechanism (`orbi_root_shell.py` /
  `seal_dropbear_enable.py`) has **no endpoint to talk to** on a satellite. (VERIFIED)
- `product_id = RBS`; role marker `/tmp/ntgr_satellite` created when
  `board_data -r board_model_id` begins with `RBS`
  (`etc/init.d/init_configd:58-66`). (VERIFIED)

---

## 2. The real satellite mechanism: `remoteshellenable` (VERIFIED)

Package `remoteshellenable` v1 (`usr/lib/opkg/info/remoteshellenable.control`,
`Description: unlocking the utelnetd`). Files it installs
(`usr/lib/opkg/info/remoteshellenable.list`):

```
/etc/init.d/init_sshenable
/usr/sbin/ssh_update_ntgr.sh
/etc/hotplug.d/iface/95-ssh
/usr/sbin/remoteshellenable
```

Binary: `usr/sbin/remoteshellenable` - ELF 32-bit ARM musl, stripped, deps
`libc libssp libjson-c`. SHA-256 prefix `1d4ac86700e4a6b8...` (identical both versions).

**Behaviour reconstructed from its string table** (binary is stripped, so control flow
is STRONGLY INDICATED, not fully VERIFIED):

- Reads the LAN bridge MAC: strings `lan_bridge`, `lan_iface`, `br-lan`,
  `Can't get the MAC address of %s.`
- Reads the admin password hash from `/tmp/httpwd` (written by `ssh_update_ntgr.sh`).
- Opens a datagram socket (`socket`, `bind`, `recvfrom`, `sendto`, `select`) and waits
  for a packet matching `AMBIT_TELNET_ENABLE+%s`, where `%s` is derived from the MAC +
  admin credential (classic NETGEAR *telnetenable* magic-packet protocol; the hex table
  `0123456789ABCDEF` and `memcmp` are consistent with the known MD5/hex token scheme).
- On a valid packet it runs `/usr/sbin/ssh_update_ntgr.sh`, prints
  `The ssh server is enabled now!!!`, and `execve`s `/etc/init.d/sshd` `start`.
  (`The sshenable is running ...`, `/etc/init.d/sshd`, `start`, `execve`, `vfork`.)

**Listening port:** not recoverable from the stripped binary. By direct lineage from
NETGEAR's `telnetenable`/`AMBIT_TELNET_ENABLE` protocol the listener is **UDP/23**.
-> STRONGLY INDICATED (UDP 23); exact port is UNKNOWN until a runtime check.

**Authentication of the magic packet = the admin web password.** `ssh_update_ntgr.sh`
(`usr/sbin/ssh_update_ntgr.sh`) populates `/tmp/httpwd`:

```sh
if [ -f /tmp/ntgr_satellite ]; then
        nvram get http.passwordHash > /tmp/httpwd      # satellite path
else
        echo `fnvram get http_passwd_digest` | awk '{print toupper($0)}' > /tmp/httpwd
fi
```

-> On a satellite the token is checked against `nvram http.passwordHash`, i.e. the
device's **admin GUI password**. (VERIFIED from script; packet-to-hash binding STRONGLY
INDICATED from the binary.)

**Start trigger (how the daemon actually runs - it is NOT an rc.d boot service):**
there is **no `S*init_sshenable` symlink** in `etc/rc.d/`. Instead it is launched by a
hotplug rule when the LAN bridge comes up:

`etc/hotplug.d/iface/95-ssh`:
```sh
if [ "$DEVICE" = "br-lan" ]; then
    /etc/init.d/init_sshenable stop
    /etc/init.d/init_sshenable start
fi
```
`etc/init.d/init_sshenable` kills/removes any legacy `telnetenabled` and execs
`/usr/sbin/remoteshellenable`. -> So `remoteshellenable` **is running on a live
satellite** (br-lan is always up), listening for the magic packet. (STRONGLY INDICATED -
depends on the proprietary hotplug/netifd actually firing `iface` events for br-lan,
which is standard OpenWrt behaviour.)

---

## 3. The SSH layer it starts: OpenSSH, pubkey-only, admin-password ForceCommand

`/etc/init.d/sshd` + `/etc/ssh/sshd_config` (both identical across versions). Key config
lines (`etc/ssh/sshd_config`):

```
Port 22
PermitRootLogin yes
PasswordAuthentication no          # <- no password login over SSH
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile /etc/ssh/id_rsa.pub   # single fixed file, not per-user ~/.ssh
UsePAM no
ForceCommand /bin/ssh_login_ntgr.sh      # runs regardless of requested command
```

`etc/init.d/sshd` binds `sshd` to the **LAN IP of br-lan only** (`ListenAddress $lan_ip`),
regenerates an RSA host key if missing, and copies `sshd_config` fresh from `/rom` each
start (`cp -rf /rom/etc/ssh/sshd_config /etc/ssh/`) - so the ForceCommand/pubkey policy
cannot be weakened by a persisted edit; it is restored from the read-only image on every
start. (VERIFIED)

### 3.1 The pubkey gate - the decisive limitation (VERIFIED fact, STRONGLY INDICATED implication)

`AuthorizedKeysFile` is the single fixed path `/etc/ssh/id_rsa.pub`, which **is shipped in
the squashfs**:

- `etc/ssh/id_rsa.pub` - 2048-bit RSA public key, comment `root@<vendor-build-host>`,
  fingerprint `<vendor-fleet-key-fingerprint>`.
- **No matching private key exists anywhere in either firmware image** (searched
  `id_rsa*`, `*authorized_keys*` across all rootfs trees - only the `.pub` is present).

Because SSH password auth is disabled and the only accepted key is this NETGEAR key:

- To complete the SSH transport you must hold the **private half of
  `root@<vendor-build-host>`**, which NETGEAR retains and the owner does not get from the
  firmware. -> The `remoteshellenable -> sshd` path as shipped is a **NETGEAR
  support/engineering channel**, not an owner self-service one. (STRONGLY INDICATED)
- The owner's admin password alone (which satisfies the magic packet *and* the
  ForceCommand) is **not sufficient** to get through the SSH key layer. (VERIFIED from the
  config + absence of the private key.)

### 3.2 The ForceCommand gate - genuinely owner-authenticated, yields uid 0

`/bin/ssh_login_ntgr.sh` runs after a successful SSH login, ignoring the requested
command:

```sh
if [ -f /tmp/ntgr_satellite ]; then
    username=`cat /etc/config/rpcd | grep username | awk '{print $3}' | tr -d \'`  # = admin
    password_hash=`nvram get http.passwordHash`
else
    username=`fnvram get http_username`; password_hash=`fnvram get http_passwd_digest` ...
fi
read  -rp  'Enter the Username: ' answer1
read -srp 'Enter the Password: ' answer2
hash_ans2=`echo -n $answer2 | openssl dgst -sha256 | ... toupper`
if [ "X$answer1" = "X$username" ] && [ "X$password_hash" = "X$hash_ans2" ]; then
        exec ${SSH_ORIGINAL_COMMAND-$SHELL -l}     # <- root shell, or arbitrary cmd as root
else echo "Login Incorrect !!!"; fi
```

- Username source on satellite = `etc/config/rpcd` -> `admin`
  (`option username 'admin'`, `option password '$p$admin'` = "use system admin password").
- Password check = SHA-256(entered) vs `nvram http.passwordHash` (admin GUI password).
- On success it `exec`s `$SHELL -l` (root's shell is `/bin/ash`, `etc/passwd:
  root:x:0:0:...:/bin/ash`) -> **uid 0 root shell**; or, if the client supplied one,
  `$SSH_ORIGINAL_COMMAND` runs as root. (VERIFIED from scripts.)

---

## 4. The dormant telnet path (STRONGLY INDICATED: not reachable from stock scripts)

`etc/init.d/telnet` (`START=50`, `S50telnet` symlink present) starts `telnetd -l
/bin/login.sh` **only if** `[ -e "/tmp/telnet_enabled" ]` *and* no SSH pubkey / no root
password is configured. `/bin/login.sh` authenticates against `nvram http.passwordHash`
(admin password -> root ash, "Use 'passwd' to set your login password").

**But nothing in any of the four firmware images ever creates `/tmp/telnet_enabled`** -
the only reference is the consumer `etc/init.d/telnet` itself (grepped across all rootfs).
-> On a stock satellite the telnet admin shell is **present but never triggered** by any
filesystem script. A proprietary binary (httpd/configd GUI "debug" toggle) could create
the marker at runtime, but no such trigger is evidenced in the extractable scripts.
-> Telnet owner-shell: STRONGLY INDICATED dormant; a GUI-driven enable path is HYPOTHESIS
(needs httpd/configd binary analysis or a runtime check to confirm or rule out).

---

## 5. Dropbear on the satellite - present but unused (VERIFIED)

- `/usr/sbin/dropbear` ships, and `etc/init.d/dropbear` here is a **full, working**
  OpenWrt init (unlike the router, whose `init.d/dropbear` target was absent/dangling),
  and `S19dropbear` is present.
- **However `etc/config/dropbear` ships `option enable '0'`**, and `start_service`
  returns early when `enable=0`. No `authorized_keys` ships (only a 0-byte
  `etc/dropbear/dropbear_rsa_host_key`), and there is **no web/API mechanism on the
  satellite to flip `enable` or install a key** (no Seal).
- -> Dropbear is effectively dead weight on the satellite; the live SSH daemon is OpenSSH
  via `remoteshellenable`, not dropbear. (VERIFIED)

---

## 6. Master <-> satellite communication (objective 6) - not a shell channel

The router->satellite control plane is **Wi-Fi mesh / Multi-AP auto-configuration**, not a
remote-shell channel:

- `repacd` (Qualcomm Repeater/AP auto-config daemon): `etc/config/repacd` ->
  `DeviceType 'RE'`, `Role 'NonCAP'` (the router is the CAP/controller). Plus `wsplcd`,
  `hyd` (Hy-Fi), `lbd` (load-balancing/band-steering), `mcsd` - the SON/Multi-AP stack.
  These synchronise SSIDs/keys/steering over the backhaul; they do **not** expose a root
  shell. (VERIFIED components; "config push only, no shell" STRONGLY INDICATED.)
- `uhttpd` on the satellite listens on **localhost:8000 only** (`etc/config/uhttpd`
  `list listen_http localhost:8000`) -> local ubus/RPC, not a LAN admin surface.
- `lighttpd` runs with `lighttpd_satellite.conf` on **:80 and :443** - the satellite's
  minimal local/registration web UI. `etc/config/rpcd` exposes ubus login `admin` with
  the system admin password. Whether this surface offers any shell/diagnostic RPC is
  UNKNOWN from scripts alone (would need the httpd/rpcd binary + ubus ACL analysis).
- Practical consequence: the realistic owner route to a satellite shell leans on the
  **existing verified RBRE root** plus the mesh relationship (the router can reach each
  satellite over the backhaul LAN), rather than on any satellite-side self-service API.
  (HYPOTHESIS for a concrete working route - not attempted; device-changing, out of scope
  for this offline phase.)

---

## 7. 7.2.7.15 vs 7.2.8.8 (objective 8) - NO CHANGE (VERIFIED)

Every satellite administration/diagnostic component is **byte-identical** across the two
firmware versions (SHA-256, first 16 hex shown; full hashes in analysis logs):

| File | 7.2.7.15 | 7.2.8.8 | Verdict |
|---|---|---|---|
| `usr/sbin/remoteshellenable` | `1d4ac86700e4a6b8` | `1d4ac86700e4a6b8` | SAME |
| `bin/login.sh` | `d08cabd2671a814b` | `d08cabd2671a814b` | SAME |
| `bin/ssh_login_ntgr.sh` | `e5dc13a0587880d2` | `e5dc13a0587880d2` | SAME |
| `usr/sbin/ssh_update_ntgr.sh` | `57c247b050327488` | `57c247b050327488` | SAME |
| `etc/init.d/init_sshenable` | `63453b7a36a69b55` | `63453b7a36a69b55` | SAME |
| `etc/init.d/sshd` | `ed4523f6d22571d6` | `ed4523f6d22571d6` | SAME |
| `etc/init.d/telnet` | `3409e5ca7c39603d` | `3409e5ca7c39603d` | SAME |
| `etc/init.d/dropbear` | `2afaf188d1db9906` | `2afaf188d1db9906` | SAME |
| `etc/ssh/sshd_config` | `b6eddd9c23c04716` | `b6eddd9c23c04716` | SAME |
| `etc/ssh/id_rsa.pub` | `de78c3a2c43ea31d` | `de78c3a2c43ea31d` | SAME |
| `etc/config/dropbear` | `0a90b388ee4dd733` | `0a90b388ee4dd733` | SAME |
| `etc/config/rpcd` | `a29762fa70bfe129` | `a29762fa70bfe129` | SAME |
| `etc/hotplug.d/iface/95-ssh` | `2a7e2636d2d40447` | `2a7e2636d2d40447` | SAME |

-> The satellite admin mechanism is **compatible with and unchanged between both
versions**; a method that works on one works on the other. (VERIFIED) The 7.2.8.8
security fixes noted in the release notes do not touch this satellite surface (they land
elsewhere; the router-side `rest.lua` dispatcher hardening from report `10` has no
satellite equivalent because the satellite has no Seal).

---

## 8. Findings by classification

**VERIFIED**
1. Satellite has no Seal/`enable_ssh`; router method does not apply. (§1)
2. Intended satellite shell facility = `remoteshellenable` magic-packet daemon -> OpenSSH
   `sshd`, with the admin web password gating both the magic packet (`ssh_update_ntgr.sh`
   -> `/tmp/httpwd` = `nvram http.passwordHash`) and the `ForceCommand ssh_login_ntgr.sh`.
   (§2, §3)
3. `sshd` is pubkey-only (`PasswordAuthentication no`), accepting only
   `/etc/ssh/id_rsa.pub` (`root@<vendor-build-host>`), whose private key is **absent** from both
   images. (§3.1)
4. ForceCommand yields a genuine uid-0 root ash shell (or arbitrary root command via
   `SSH_ORIGINAL_COMMAND`) on correct admin credentials. (§3.2)
5. Dropbear ships but `enable=0` with no key and no enable API -> unused on satellite. (§5)
6. All admin/diagnostic components byte-identical 7.2.7.15 <-> 7.2.8.8. (§7)
7. `/tmp/ntgr_satellite` is the runtime RBS role marker (`init_configd`). (§1)

**STRONGLY INDICATED**
8. `remoteshellenable` implements the NETGEAR `AMBIT_TELNET_ENABLE` magic-packet scheme
   (MAC+admin-credential token), listening UDP/23, and starts `sshd` on a valid packet.
   (stripped binary - string/lineage evidence) (§2)
9. As shipped, the SSH path is a **NETGEAR support/engineering channel**, not an
   owner-completable one, because the owner lacks the `id_rsa.pub` private key. (§3.1)
10. Master->satellite link is mesh/Multi-AP config sync (`repacd`/`wsplcd`/`hyd`/`lbd`),
    not a shell channel; `uhttpd` is localhost-only. (§6)
11. The telnet admin shell (`login.sh`, admin-password-gated) is present but dormant -
    nothing in the filesystem sets `/tmp/telnet_enabled`. (§4)

**HYPOTHESIS**
12. A proprietary GUI/configd "debug" toggle could create `/tmp/telnet_enabled` (->
    admin-password telnet root) or otherwise enable a shell. Needs httpd/configd/rpcd
    binary analysis or a runtime check. (§4, §6)
13. A realistic owner route to satellite root likely goes **via the existing RBRE root +
    the backhaul**, or by provisioning the owner's own key into `/etc/ssh/id_rsa.pub` -
    both are device-changing and out of scope for this offline phase. (§6)

**UNKNOWN**
14. Exact `remoteshellenable` listen port/packet format (stripped binary). (§2)
15. Whether the satellite's lighttpd/rpcd surface exposes any diagnostic RPC. (§6)

**RULED OUT**
16. Router Seal `enable_ssh`/dropbear-key-install working against a satellite. (§1, §5)
17. SSH password or empty-password login to the satellite (`PasswordAuthentication no`,
    `PermitEmptyPasswords no`, `UsePAM no`). (§3)

---

## 9. Is there a legitimate owner-authenticated mechanism? - direct answer

**Yes, by design, but not fully owner-usable with stock firmware alone.** The satellite
ships a deliberate, admin-password-authenticated remote-shell facility
(`remoteshellenable` -> OpenSSH -> `ssh_login_ntgr.sh`). Two of its three gates are keyed to
the owner's admin GUI password. The third gate - SSH public-key auth against a
NETGEAR-held key - is the blocker: it makes the stock mechanism effectively a
**vendor-assisted** channel (owner opens it with their password; NETGEAR connects with
their private key; the ForceCommand re-verifies the owner's password).

**Prerequisites to actually obtain an owner root shell on a satellite** (each is
device-changing and therefore outside this offline phase - listed for planning, not
action):
- Admin GUI password (owner has it) - satisfies the magic packet and the ForceCommand.
- The private key for `/etc/ssh/id_rsa.pub` **or** the ability to replace that file with
  the owner's own public key (requires pre-existing root on the satellite -> chicken/egg),
  **or** enabling the dormant telnet path (requires creating `/tmp/telnet_enabled`).
- Compatible with **both** 7.2.7.15 and 7.2.8.8 identically.

**Recommended next steps (all read-only or approval-gated):**
1. Confirm the live satellites' firmware version and whether `remoteshellenable` is
   actually listening (read-only runtime check; it is observation, not a change).
2. Decide whether the goal justifies a device-changing route (provision the owner key via the
   existing RBRE root/backhaul, or a GUI debug path). Any such route is documented with its
   exact effect and rollback **before** anything is executed, per the project safety rules.
3. Optional deeper static work to close UNKNOWNs: disassemble `remoteshellenable` (confirm
   port + token algorithm) and the satellite `httpd`/`rpcd`/`configd` (confirm whether any
   GUI toggle enables telnet or a diagnostic RPC).

---

*No credentials, password hashes, or private keys are reproduced in this report. The
`id_rsa.pub` fingerprint shown is public key material. No device or archive was modified.*
