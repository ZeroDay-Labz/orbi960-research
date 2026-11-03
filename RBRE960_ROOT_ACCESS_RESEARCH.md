# RBRE960 Root Access Research

**Target:** Netgear Orbi RBRE960 (owner-operated)
**Running firmware:** `V7.2.7.15_5.1.16`
**Router IP:** `<router-ip>`  -  **LAN MAC:** `<MASTER_LAN_MAC>` (redacted)
**Goal:** persistent, owner-authenticated root shell, ideally `ssh root@<router-ip>`
**Host:** Fedora Linux  -  **Scope:** personally owned hardware/firmware, isolated LAN
**Document status:** consolidation of prior RE work, re-verified against the extracted `7.2.7.15` rootfs. Last updated 2026-11-02.

> **Hard rules honored in this document:** no UART, no factory reset, no case opening, prefer reversible changes, investigate stock firmware before replacement, **no router modification or firmware flashing performed as part of this research.** Everything below is static analysis of local files plus clearly-labeled runtime tests you can choose to run later.

---

## Evidence confidence legend

| Tag | Meaning |
|---|---|
| **VERIFIED** | Directly established from firmware source, decompiled binary behavior, or config on disk. |
| **STRONGLY INDICATED** | Multiple consistent pieces of evidence; one link not yet runtime-proven. |
| **HYPOTHESIS** | Plausible, needs runtime or additional artifact to confirm. |
| **RULED OUT** | Investigated and not viable under the stated constraints. |

Distinctions kept strictly: *daemon exists != daemon running*; *service starts != authentication succeeds*; *crypto self-test passes != router accepts the packet*; *SSH server reachable != interactive root shell*; *filesystem writable != survives reboot/upgrade*.

---

## 1. Executive Summary

The device ships **four** candidate shell-enable mechanisms. They are **not** equivalent, and most are not usable by the owner as shipped:

1. **Seal REST `/enable_ssh` endpoint (Dropbear installer) - RECOMMENDED.** An authenticated LAN admin can POST their own SSH public key to a REST endpoint; the device installs it into `/etc/dropbear/authorized_keys` and launches **Dropbear** (key-only, root permitted) on TCP 22. This is an intentional Netgear owner/support feature, requires only credentials the owner already has, needs **no** factory-reset / blank state, is reversible, and yields a true UID 0 shell. **(VERIFIED by decompiling `seal-development.lua` + `rest.lua`.)** The only unproven link is the exact external URL / whether lighttpd fronts it without an extra session - a 1-command runtime probe settles it.

2. **`remoteshellenable` UDP magic packet -> OpenSSH `sshd`.** This is the live daemon on 7.2.7.15 (not `telnetenabled`). A correctly-crafted 248-byte Blowfish packet keyed on the admin-password digest makes the device start **OpenSSH**. **But OpenSSH is locked**: `PasswordAuthentication no`, and `AuthorizedKeysFile` is a **Netgear-held** key you do not possess, behind a `ForceCommand`. So starting `sshd` does **not** grant the owner a shell. This path is for Netgear, not you. **This is also exactly why the earlier `orbi_telnet_enable.py` attempt failed** (details in §5).

3. **BusyBox telnet.** Gated on `/tmp/telnet_enabled`, which on 7.2.7.15 **nothing creates** (the daemon that used to create it, `telnetenabled`, is deleted at boot - see §5). RULED OUT for initial access without an existing shell.

4. **Firmware modification / custom image.** The CHK container uses a *recomputable* checksum, not a signature. Whether U-Boot enforces FIT signature verification (secure boot) is **unproven** from the shipped artifacts. Feasible-in-principle but high brick risk; a last resort.

**Bottom line:** pursue avenue #1 (Seal `/enable_ssh` -> Dropbear). It is the shortest, safest, reversible, owner-authenticated route to `ssh root@<router-ip>`. Avenues #2-#4 are documented for completeness and because #2 explains the prior failure.

---

## 2. Hardware and Firmware Identification

| Property | Value | Source |
|---|---|---|
| Device | Netgear Orbi RBRE960 | - |
| Firmware (running) | `7.2.7.15` | `etc/version` = `7.2.7.15` (VERIFIED) |
| SoC | Qualcomm IPQ807x, ARM 32-bit | devicetree / binaries (VERIFIED) |
| libc | musl (`/lib/ld-musl-arm.so.1`) | ELF interpreter of every binary (VERIFIED) |
| Base OS | Netgear fork of OpenWrt Chaos Calmer 15.05.1, kernel 4.4.60, procd init | rootfs layout, `/etc/rc.common` (VERIFIED) |
| Board ID (CHK) | `U12H451T00_NETGEAR` | CHK header (VERIFIED) |
| Per-build key | 32-hex in `/.sec_key` | file present (VERIFIED) |

**Firmware images analyzed**: `RBRE960-V6.3.7.5`, `RBRE960-V7.2.7.15` (**running**), `RBRE960-V7.2.8.5`, `RBRE960-V7.2.8.8`. Each was extracted locally into its own working directory (for example `rbre_7215/rootfs` for the running image).

> Paths in this document use `$R` = the extracted running (7.2.7.15) root filesystem.
> Re-extract from the corresponding `.chk` with the chain in section 19 if the working copy is gone.

---

## 3. Existing Reverse-Engineering Findings (carried forward and re-verified)

From earlier analysis, **re-confirmed against the 7.2.7.15 rootfs**:

- **Packaging chain (VERIFIED):** Netgear CHK (`*#$^`, 58-byte header, board `U12H451T00_NETGEAR`) -> U-Boot FIT (`d00dfeed`; `metadata.txt`, `flash.scr`, `openwrt-ipq-ipq807x-ubi-root.img`) -> UBI (`UBI#`) -> volumes: kernel (FIT w/ kernel+DTBs), `ubi_rootfs` (SquashFS4/xz), `rootfs_data` (writable overlay). `flash.scr` writes UBI to NAND `0x11c00000`.
- **Web stack (VERIFIED):** lighttpd front end (443/80) -> proxies `^/api/` to the **Seal** REST backend on `localhost:16667`; the legacy SOAP/HTML admin server is `/usr/sbin/httpd`. Seal document root `/www-seal`.
- **Credentials model (VERIFIED):** `/etc/shadow` effectively empty; passwords live in NVRAM at runtime. `root` is `uid 0`, shell `/bin/ash`. Admin auth everywhere compares `sha256(entered_password)` against NVRAM `http_passwd_digest`.
- **`7.2.8.5 -> 7.2.8.8` security diff (from prior work):** `extforward.forwarder` tightened `"all"=>"trust"` => `"localhost"=>"trust"`; `rest.lua` dropped trust of client `HTTP_X_HOST`/`HTTP_X_FORWARDED_FOR` and added `HTTP_X_SEAL_INTERNAL` + `service_name` validation; TLS hardening. `httpd`/`telnetenabled` byte-identical across those two = recompiles, not where the fix is.
- **Earlier approach:** a re-implementation of the legacy **`telnetenabled`** magic-packet protocol (128-byte layout) was attempted against this firmware. See §5 for why it does not match the running daemon. That operational packet tooling is intentionally not part of this publication (see `SECURITY.md`).

**Established in this analysis:**
- The live enabler on 7.2.7.15 is **`remoteshellenable`**, not `telnetenabled` (decompiled - §5).
- `seal-development.lua` **is present** in 7.2.7.15 (earlier thought absent) and contains a working, admin-authenticated **`enable_ssh`** handler wired to a REST route (decompiled - §9). This resolves the open discrepancy from the task.

---

## 4. Firmware Architecture and Boot Process

```
CHK (*#$^, 58B hdr, board U12H451T00_NETGEAR, recomputable checksum)
 └─ U-Boot FIT (d00dfeed): metadata.txt + flash.scr + ubi-root.img, hash@1/hash@2 nodes
     └─ UBI (UBI#): [kernel FIT] [ubi_rootfs squashfs-xz = /] [rootfs_data = overlay]
         └─ OpenWrt/procd boot
             ├─ squashfs mounted read-only at /rom
             ├─ rootfs_data as overlayfs upper -> writable / (persists across reboot)
             ├─ procd runs /etc/rc.d/S*  (lighttpd S50, dropbear S19* see note)
             └─ hotplug: br-lan ifup -> /etc/hotplug.d/iface/95-ssh -> init_sshenable
```

- **Overlay (STRONGLY INDICATED):** `/rom`, `/overlay`, `/data` present; standard OpenWrt overlayfs. Writes to `/etc` land in `rootfs_data` and **survive reboot**; a **factory reset** wipes `rootfs_data`; a **firmware upgrade** reformats it *except* paths kept by `/lib/upgrade/keep.d` + `sysupgrade.conf` (which include `/etc/dropbear/` and `/etc/config/` - VERIFIED, relevant to persistence in §11).
- **`95-ssh` hotplug (VERIFIED):** on `br-lan` up, runs `/etc/init.d/init_sshenable stop; start`.
- **`init_sshenable` (VERIFIED, `$R/etc/init.d/init_sshenable`):**
  ```sh
  start() {
      pid_telnet=`pidof telnetenabled`
      kill -9 pid_telnet
      rm -rf usr/sbin/telnetenabled      # removes the OLD telnet-enable daemon
      /usr/sbin/remoteshellenable         # starts the CURRENT daemon
  }
  ```
  **Consequence:** on every LAN bring-up the legacy `telnetenabled` is killed/removed and **`remoteshellenable`** is launched. This single fact reorders the whole investigation.

---

## 5. Remote Shell Enable Mechanisms

### 5.1 `remoteshellenable` - the live daemon (VERIFIED by decompilation)

Binary: `$R/usr/sbin/remoteshellenable` (ARM, musl, stripped, sha256 `1d4ac867...e8de`). Decompiled with Ghidra. Key functions: `main @0x10bec`, packet builder `FUN_00012484 @0x12484`.

**`main` behavior (VERIFIED):**
- `socket(AF_INET, SOCK_DGRAM)` -> `bind` to **UDP port `0x17` = 23** on `br-lan` (`SIOCGIFADDR`), `SO_BROADCAST` set, `daemon(1,1)`, prints `"The sshenable is running ..."`.
- Loop: `recvfrom` up to 512 bytes. On any datagram:
  1. runs `/usr/sbin/ssh_update_ntgr.sh` (regenerates `/tmp/httpwd` every packet),
  2. `len = FUN_00012484(expected)` - builds the **expected** packet locally,
  3. if `recv_len == len` **and** `memcmp(received, expected, len) == 0`:
     - prints `"The ssh server is enabled now!!!"`,
     - runs `/etc/init.d/sshd start` (once; guarded),
     - replies `"ACK"` (3 bytes, `0x4b4341`).

**Validation = exact byte equality** of the received datagram against a locally-built blob. No tolerance.

**`FUN_00012484` - expected-packet construction (VERIFIED):**
- reads the admin password digest from **`/tmp/httpwd`** (written by `ssh_update_ntgr.sh`, see below),
- `SIOCGIFHWADDR` on `br-lan` -> MAC as **12 uppercase hex chars**,
- builds a **248-byte (`0xf8`) plaintext** struct:
  | offset | field | content |
  |---|---|---|
  | `0x00..0x10` | MD5 | `MD5(plaintext[0x10 .. 0x10+0x70])` (over the next 112 bytes) |
  | `0x10..0x20` | MAC | 12 uppercase hex chars, NUL-padded (16-byte field) |
  | `0x20..`    | user | `"admin"` (literal, from `local_204`), NUL-padded |
  | `.....0xf8`   | pw   | admin password **digest** (contents of `/tmp/httpwd`), 0x87-byte field |
- key string = `snprintf("AMBIT_TELNET_ENABLE+%s", <contents of /tmp/httpwd>)`,
- Blowfish key schedule `FUN_000111d4(key)`; Blowfish-encrypt 248 bytes `FUN_0001239c` -> expected blob,
- `/bin/rm /tmp/httpwd`.

**`ssh_update_ntgr.sh` (VERIFIED, `$R/usr/sbin/ssh_update_ntgr.sh`):**
```sh
if [ -f /tmp/ntgr_satellite ]; then nvram get http.passwordHash > /tmp/httpwd
else echo `fnvram get http_passwd_digest` | awk '{print toupper($0)}' > /tmp/httpwd ; fi
```
So the password material is **`UPPER(sha256_hex(admin_password))`**.

**Net:** a valid packet = `Blowfish_ECB( 248-byte plaintext, key = "AMBIT_TELNET_ENABLE+" + UPPER(sha256_hex(pw)) )`, where the password *field inside the plaintext* is also `UPPER(sha256_hex(pw))` (the digest, **not** the plaintext password). Blowfish uses the standard algorithm with little-endian word packing and a cyclically-repeated arbitrary-length key (same engine already captured in `orbi_telnet_enable.py`).

**Why this does NOT give the owner a shell (VERIFIED, critical):** on success it only runs `/etc/init.d/sshd start`, i.e. **OpenSSH**, which is locked (see §6). You can make `sshd` start, you cannot authenticate to it. **Root potential for the owner: none, by itself.**

### 5.2 Why the earlier `orbi_telnet_enable.py` attempt failed (VERIFIED)

`orbi_telnet_enable.py` is a faithful implementation of **`telnetenabled`** (its own docstring says so), whose protocol is:
- plaintext **128 bytes**, password field = **plaintext password**, key digest **lowercase**, and on success it launches **`utelnetd`/`login_telnet2`**.

The running daemon is **`remoteshellenable`**, which expects:
- plaintext **248 bytes**, password field = **UPPERCASE sha256 digest**, key digest **UPPERCASE**, and on success launches **`sshd`**.

`main` checks `recv_len == expected_len` *first*; `128 != 248` => rejected before any crypto comparison. Even if lengths matched, the uppercase-vs-lowercase digest and plaintext-vs-digest password field differ. So the packet was silently dropped - **no ACK, no service**. The tool targeted a daemon that `init_sshenable` deletes at boot.

**Reusing the tool:** the Blowfish engine and packet scaffolding in `orbi_telnet_enable.py` are correct and reusable; to target `remoteshellenable` you would change: packet length -> 248, password field -> `UPPER(sha256_hex(pw))`, key suffix -> `UPPER(sha256_hex(pw))`, username field -> `admin`. **But do not bother** unless you specifically need `sshd` started - it will not let you in (§6). The owner path is §9, not this.

### 5.3 `init_sshenable` / `95-ssh` - see §4. (VERIFIED.)

---

## 6. OpenSSH Analysis

Files: `$R/usr/sbin/sshd` (dropbear-sized? no - real OpenSSH), `$R/etc/ssh/sshd_config`, `$R/bin/ssh_login_ntgr.sh`, `$R/etc/ssh/id_rsa.pub`, `$R/etc/init.d/sshd`.

**`sshd_config` (VERIFIED - the lockdown):**
```
Port 22
PermitRootLogin yes
PubkeyAuthentication yes
AuthorizedKeysFile  /etc/ssh/id_rsa.pub        # single, fixed, Netgear-provisioned
PasswordAuthentication no                      # <-- passwords disabled
PermitEmptyPasswords no
UsePAM no
ForceCommand /bin/ssh_login_ntgr.sh            # every session is wrapped
ListenAddress  <LAN ip>                        # added at start from br-lan
```
- **`AuthorizedKeysFile = /etc/ssh/id_rsa.pub`** and that file contains a **Netgear** key: `ssh-rsa AAAA...EbTkfJXDZ root@<vendor-build-host>` (VERIFIED). The matching **private key is held by Netgear**, not on the device.
- With `PasswordAuthentication no`, SSH **transport auth requires that private key**. The owner cannot pass this stage.
- Even past transport auth, `ForceCommand /bin/ssh_login_ntgr.sh` runs; it prompts for username+password, compares `UPPER(sha256(pw))` to `UPPER(fnvram http_passwd_digest)`, and on match `exec ${SSH_ORIGINAL_COMMAND-$SHELL -l}` (= root `/bin/ash`, or an arbitrary command if `ssh root@ip '<cmd>'`). (VERIFIED.)

**`sshd` init (VERIFIED, `$R/etc/init.d/sshd`):** generates `ssh_host_rsa_key` if missing, copies `sshd_config` from `/rom`, binds to the `br-lan` IP, runs `sshd -D`. **Not symlinked into `/etc/rc.d`** -> not started at boot; it is started only by `remoteshellenable` on a valid magic packet (§5.1).

**Conclusion (OpenSSH): RULED OUT as an owner entry path, as shipped.** The owner would need to place their own public key into `/etc/ssh/id_rsa.pub` (or flip `PasswordAuthentication on`) *first*, which itself requires existing write access - a chicken-and-egg. The legitimate owner option is to reconfigure OpenSSH **after** getting a root shell by another route (§11), not to use it for the first foothold.

---

## 7. Dropbear Analysis

Files: `$R/usr/sbin/dropbear` (present, ELF ARM), `$R/etc/config/dropbear`, `$R/etc/rc.d/{S19,K50}dropbear`. **`/etc/init.d/dropbear` is ABSENT** (VERIFIED).

- **`/etc/config/dropbear` (VERIFIED):** `PasswordAuth 'on'`, `RootPasswordAuth 'on'`, `Port '22'`.
- **Boot wiring is broken (VERIFIED):** `/etc/rc.d/S19dropbear` and `K50dropbear` exist but point at the **missing** `/etc/init.d/dropbear`, so procd cannot start Dropbear at boot. Password auth is also moot because no root password is set in `/etc/shadow`.
- **Dropbear is therefore not running normally** - it is started **on demand** only by the Seal `enable_ssh` handler (§9), which invokes the binary directly with explicit flags (bypassing the missing init script). (VERIFIED.)
- **Authorized-keys location (VERIFIED):** this build's Dropbear reads **`/etc/dropbear/authorized_keys`** for root - confirmed independently by `/etc/init.d/telnet`'s `has_ssh_pubkey()` which greps `^ssh-` in exactly that file. `/etc/dropbear/` is also in the upgrade keep-list (§11).

**Conclusion (Dropbear): the most practical owner route, but only via the `enable_ssh` installer in §9 - not via the (broken) init path.**

---

## 8. Telnet and Failsafe Analysis

Files: `$R/usr/sbin/utelnetd`, `$R/usr/sbin/telnetenabled` (present on disk, **deleted at boot** by `init_sshenable`), `$R/etc/init.d/telnet`, `$R/bin/login.sh`, `$R/bin/login_telnet2`.

- **`/etc/init.d/telnet` (VERIFIED):** starts `telnetd -F -l /bin/login.sh` **only if** `[ -e /tmp/telnet_enabled ]` **and** neither dropbear nor sshd is enabled and there's no ssh pubkey/root password.
- **Who creates `/tmp/telnet_enabled`?** A full-rootfs search finds **no creator** on 7.2.7.15 (only `init.d/telnet` *reads* it). The historical creator was `telnetenabled`, which `init_sshenable` kills and removes. (VERIFIED.)
- **`login.sh` / `login_telnet2` (VERIFIED):** both check `fnvram get disable_telnet_login`; if `1`, they `exec /bin/ash --login` with **no password**. Otherwise they prompt and verify admin creds (`sha256(pw)` vs `http_passwd_digest`) then `exec /bin/ash --login` (= root). `disable_telnet_login` is not set to `1` anywhere in the static config (STRONGLY INDICATED; runtime NVRAM value unknown).

**Conclusion (Telnet): RULED OUT for initial access** - the gating file is never created on 7.2.7.15 and `telnetd` is never launched without it. The password-less `disable_telnet_login=1` branch is unreachable without first reaching `telnetd`.

---

## 9. Web API and Administrative Interfaces - the owner path

### 9.1 Seal REST backend and exposure (VERIFIED)

- lighttpd (`$R/etc/lighttpd_conf.ltp`) terminates TLS on 443 and, for `$HTTP["url"] =~ "(^/api/)"`, **proxies to `localhost:16667`** - the Seal REST app (`server.port = 16667`, docroot `/www-seal`). (VERIFIED.)
- `extforward.forwarder = ("all" => "trust")` on 7.2.7.15 - lighttpd trusts `X-Forwarded-For`/`X-Real-IP`/`Forwarded` from **any** source (the header-trust weakness, §13). (VERIFIED.)

### 9.2 `rest.lua` routing (VERIFIED by decompilation)

`$R/www-seal/rest/rest.lua` (Lua 5.1 bytecode; this build tags number constants as type `9` and uses a 4-byte `lua_Number` - noted so the disassembly reproduces). The router (`third_party/router`) registers service routes under base `/api/v1` **and** registers a standalone route:

```
routes['GET']['/enable_ssh']  = <handler>
routes['POST']['/enable_ssh'] = <handler>
```

The request object is populated from CGI env: `REQUEST_METHOD`, `REQUEST_URI`, `HTTP_CONTENT` (body), `HTTP_X_HOST`->`HostAddr`, `HTTP_X_FORWARDED_FOR`->`HttpXForwardedFor`, `QUERY_STRING`. The `/enable_ssh` handler itself does **not** consult `HostAddr`/`HttpXForwardedFor` - it authenticates purely on the submitted admin credentials. (VERIFIED.)

**`/enable_ssh` handler (VERIFIED, decompiled `rest.lua` proto):**
```
username = req.username or ''
password = req.password or ''
pubkey   = req.pubkey   or ''
if enable_ssh(username, password, pubkey) then  respond(200, "OK")
else                                            respond(418, "I'm a teapot")  end
```
(Response codes decoded from the float-encoded integer constants: `200` and `418`.)

### 9.3 `seal-development.lua :: enable_ssh` (VERIFIED by decompilation)

`$R/usr/share/lua/seal-development.lua`, module `_version 0.1.0`, loaded via `require` from `rest.lua`. Reconstructed logic:

```
function enable_ssh(username, password, pubkey)
    if pubkey is empty then pubkey = '-'
    if attempt_counter() >= 5 then return false          -- rate limit, counter in /tmp
    if not verify_admin(username, password) then
        increment_attempt_counter(); return false
    end
    cmds = {
      "/bin/sed -i 's#/bin/ash#/bin/sh#' /etc/shells",
      "/bin/echo '" .. pubkey .. "' > /etc/dropbear/authorized_keys",
      "/bin/rm -f /etc/dropbear/dropbear_rsa_host_key",
      "/usr/sbin/dropbear -P /var/run/dropbear.pid -s -g -p 22 -K 300 -T 3 -R || true",
    }
    runner = is_orbi() and os.execute or print      -- on a real Orbi it RUNS; on a dev host it only prints
    for _,c in pairs(cmds) do if runner(c) ~= 0 then print("Error on command: "..c) end end
    return true
end

function verify_admin(user, pass)   -- VERIFIED
    return user == run_shell("seal plat get_admin_username")
       and run_shell("seal plat get_admin_password_digest")
           == run_shell("echo -n "..pass.." | sha256sum | cut -d ' ' -f0")
end
```

**Decisive facts (VERIFIED):**
- **No blank/factory-state requirement.** `is_in_blank_state` exists in the module but `enable_ssh` **does not call it**. The only gates are the **<=5-attempt counter** and **`verify_admin`**. => works on a normally-configured device.
- **Caller supplies the public key.** `pubkey` comes straight from the request and is written verbatim to `/etc/dropbear/authorized_keys`. => you install *your own* key.
- **On a real Orbi it actually executes** (the `"On target, this would execute:"` print is the *dev-host* dry-run branch, selected by `is_orbi()==false`).
- Dropbear flags `-s -g` = key-only (password + root-password logins disabled); root login via the installed key; `-R` self-generates host keys.
- `verify_admin` *is* the authentication, so the endpoint is **self-authenticating** on the password parameter; no separate web session is required by the handler. Whether lighttpd fronts `/api/...` without its own auth is the one runtime unknown (§16).

**Conclusion (Web API): VERIFIED owner-authenticated route to a true root (UID 0) shell via Dropbear.** This resolves the earlier `seal-development.lua` / `enable_ssh` discrepancy: the file **is** in 7.2.7.15 and the handler is real and wired.

### 9.4 Legacy SOAP server / `debug.htm`
`/usr/sbin/httpd` serves the classic admin UI and SOAP (`fw_serv.cgi`, firmware handlers, etc.). Prior work found the `debug.htm` telnet toggle disabled ("MR2.0 enforce disabled telnet"). No separate SSH-enable handler was found in `httpd` strings. Not pursued further; the Seal path supersedes it. (STRONGLY INDICATED.)

---

## 10. NVRAM and Runtime Configuration

Tools present (VERIFIED): `$R/usr/sbin/fnvram`, `$R/usr/sbin/nvram`, `$R/usr/bin/seal` (`seal plat get_admin_username|get_admin_password_digest`).

| Setting | Role | Status |
|---|---|---|
| `http_username` | admin login name used by every auth path | VERIFIED (referenced by `login.sh`, `ssh_login_ntgr.sh`, `verify_admin`) |
| `http_passwd_digest` | `sha256_hex(admin_password)` (lowercase in NVRAM) | VERIFIED |
| `http.passwordHash` | satellite-mode variant (if `/tmp/ntgr_satellite`) | VERIFIED |
| `disable_telnet_login` | `=1` => password-less telnet login shell | VERIFIED (consumed); runtime value unknown (needs runtime test) |
| `lan_hwaddr` / `br-lan` MAC | fed into `remoteshellenable` packet | VERIFIED |

No NVRAM variable by itself starts SSH/Dropbear; the Seal handler is the control point. Runtime values require a shell or the web UI to read - do not infer them.

---

## 11. Filesystem and Persistence

- **Layout (VERIFIED/STRONGLY INDICATED):** `/` = SquashFS (read-only, `/rom`) + `rootfs_data` overlay (`/overlay`, `/data`). `/etc` is writable via the overlay.
- **Persistence tiers for the §9 result:**
  1. **SSH service restart:** Dropbear started by `enable_ssh` keeps running until killed/rebooted. (STRONGLY INDICATED.)
  2. **Reboot:** `/etc/dropbear/authorized_keys` **persists** (overlay). **But Dropbear itself does not auto-start** (broken init, §7) and the `/tmp` attempt-counter resets. => after reboot you must re-invoke `enable_ssh` (or add a boot hook). For hands-off persistence you would add a start command to an overlay boot hook (e.g. `/etc/rc.local`, currently a no-op) - a deliberate, reversible owner change made *after* first access. (STRONGLY INDICATED.)
  3. **Firmware upgrade:** `sysupgrade.conf` keeps `/etc/dropbear/` and `/etc/config/` (VERIFIED), so the key file survives an upgrade, but again the auto-start hook must live in a kept path. A **factory reset wipes everything** (overlay reformatted).
- **Gotcha (STRONGLY INDICATED):** `enable_ssh` rewrites `/etc/shells` `ash`->`sh`. If Dropbear enforces `/etc/shells` against root's passwd shell (`/bin/ash`), that entry is now absent. Key-only logins (`-s`) typically skip the password/shell checks, but confirm at runtime; if login is refused, restore `/etc/shells` to list `/bin/ash`.

---

## 12. Firmware Modification and Custom Firmware

- **CHK container (VERIFIED):** `*#$^`, 58-byte header, board `U12H451T00_NETGEAR`, body is the FIT. The integrity field is a **recomputable checksum** (`image.chksum=%X` in `httpd`; "Invalid Firmware!" on mismatch) + board-ID string match - **not** a cryptographic signature at the CHK layer. Trivially recomputable.
- **FIT (STRONGLY INDICATED):** carries `hash@1`/`hash@2` nodes and `configurations`. Whether U-Boot **enforces FIT signature verification** (QCA secure boot, `qca,secure`/`qcom,secure` present in DT) depends on blown SoC fuses - **not determinable from the shipped image**. (HYPOTHESIS: if secure boot is enforced, a modified rootfs will fail to boot.)
- **Feasibility:** *If* signatures are not enforced, a minimally-modified image (e.g. add your pubkey to `/etc/ssh/id_rsa.pub`, or flip `PasswordAuthentication on`, or add a boot hook that starts Dropbear) could be repacked (SquashFS -> UBI -> FIT -> CHK, fix checksums) and offered to the stock updater. Complexity **High**, brick risk **High**.
- **Recovery:** RBRE960 TFTP recovery (`nmrpflash`) is the fallback if a bad image is flashed - but this is exactly the kind of risk the constraints ask to avoid. **Last resort only. Nothing flashed here.**

---

## 13. Security Vulnerability Findings

Separated from the normal owner-access paths. A weakness is **not** automatically a root path.

**Confirmed weaknesses (from the 7.2.8.5->7.2.8.8 diff + this analysis):**
| # | Component | Ver | Root cause | Impact | Local-access relevance | Fixed in 7.2.8.8? |
|---|---|---|---|---|---|---|
| V1 | lighttpd `extforward.forwarder = "all"=>"trust"` (`lighttpd_conf.ltp`) | 7.2.7.15 / 8.5 | Trusts `X-Forwarded-For` from anyone | Client can spoof apparent source IP to the Seal backend | Could bypass any IP/origin ACL on Seal endpoints | **Yes** -> `"localhost"=>"trust"` |
| V2 | `rest.lua` trusts client `HTTP_X_HOST`/`HTTP_X_FORWARDED_FOR` | 7.2.7.15 / 8.5 | Client-controlled headers used for origin decisions | Spoofable "internal request" context | Potentially reach origin-gated handlers | **Yes** -> internal-only `HTTP_X_SEAL_INTERNAL` + `service_name` validation |
| V3 | REST `service_name` path handling on `/service_uppers/` | 7.2.7.15 / 8.5 | Missing `^[A-Za-z0-9_-]+$` / `..` checks | Path traversal | File read/write scope | **Yes** (regex + `%.%.` check added) |

**Design observations (not "bugs", but security-relevant):**
- `/enable_ssh` is **self-authenticating on a password parameter over the LAN API** and has only a 5-try counter that **resets on reboot**. For the owner this is the intended feature; as a posture note it means admin-password strength is the only barrier to enabling root SSH from the LAN.
- OpenSSH ships a **vendor public key** in `/etc/ssh/id_rsa.pub` with `PermitRootLogin yes` - a vendor-retained access capability (not owner-usable, see §6).

**Suspected / needs more work (HYPOTHESIS):** whether V1/V2 let an *unauthenticated* or *off-LAN* actor reach `/enable_ssh` - not required for the owner and not validated here.

---

## 14. Root Access Avenue Comparison Matrix

Ranked most->least practical for the owner.

| Rank | Approach | Required access | Auth | Root (UID 0)? | Persistence | Difficulty | Risk | Reversible | Evidence | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | **Seal `/enable_ssh` -> Dropbear** (§9) | LAN + admin web creds | admin user+pass (in-handler `verify_admin`) | **Yes** (key->root) | reboot: re-run or add hook; key file survives reboot/upgrade | **Low-Med** | **Low** (reversible, no flash) | Yes (kill dropbear, rm authorized_keys) | `seal-development.lua`, `rest.lua` decompiled | **VERIFIED mechanism**; external URL = STRONGLY INDICATED |
| 2 | Post-access OpenSSH reconfig (§6/§11) | existing root shell | n/a | Yes | persists (overlay) | Low | Low | Yes | `sshd_config`, overlay | VERIFIED (requires #1 first) |
| 3 | `remoteshellenable` packet -> OpenSSH (§5) | LAN + admin creds | admin pw digest | **No** for owner (key-locked sshd) | n/a | Med | Low | Yes | binary decompiled | VERIFIED it does **not** grant owner shell |
| 4 | Telnet (§8) | - | - | (would be yes) | - | - | - | - | `init.d/telnet` | **RULED OUT** (no `/tmp/telnet_enabled` creator) |
| 5 | Dropbear via init (§7) | - | - | - | - | - | - | - | missing `init.d/dropbear` | **RULED OUT** (broken init) |
| 6 | Modified firmware (§12) | build host + flash | recompute CHK checksum | Yes | survives upgrade (it *is* the image) | **High** | **High** (brick) | hard (TFTP recovery) | CHK/FIT analysis | HYPOTHESIS (secure-boot unknown) |

---

## 15. Recommended Investigation Order

1. **Confirm the `/enable_ssh` endpoint is reachable and self-authenticating** (read-only probe, §16.1). One request settles the only open question.
2. **Exercise the owner path** with your own key (§16.2) -> `ssh root@<router-ip>`.
3. **Once in:** decide on persistence - either accept "re-run after reboot", or add a reversible boot hook / reconfigure OpenSSH to accept your key (§16.3).
4. Only if #1 is unexpectedly blocked: revisit header-trust weakness V1/V2 to understand *why*, or reconsider `remoteshellenable`->OpenSSH **combined with** writing your key (needs a shell first - circular), i.e. fall through to firmware mod (§12) as a true last resort.

---

## 16. Step-by-Step Research Roadmap

> Read-only investigations are separated from device-changing actions. The device-changing step (16.2) uses the **intended Netgear feature** with **your own** credentials and key and is fully reversible. Nothing here flashes firmware.

### 16.1 Read-only feasibility probe (no device change)
- **Verify locally** (already done, re-runnable) the handler logic:
  ```bash
  python3 -I luadis.py "$R/usr/share/lua/seal-development.lua" | less   # see §19
  ```
- **Probe the endpoint shape** with *deliberately wrong* credentials so nothing is enabled - you are only checking routing/response:
  ```bash
  # Expect HTTP 418 "I'm a teapot" (bad creds) if routed & self-authenticating; 404 => wrong URL.
  curl -k -i "https://<router-ip>/api/v1/enable_ssh?username=x&password=x&pubkey=x"
  curl -k -i "https://<router-ip>/api/enable_ssh?username=x&password=x&pubkey=x"   # fallback path
  ```
  - **Expected:** `418`/`I'm a teapot` on a bad-cred hit at the correct URL; `200`/`OK` only on correct creds. `404` means try the other path spelling.
  - **What could go wrong:** lighttpd may require the request on 443 (HTTP is 308-redirected to HTTPS); a front-door session/XSRF token may be required; the 5-try counter increments on each *valid-URL wrong-cred* hit (resets on reboot) - keep probes few.
  - **Prerequisite:** on the LAN; TLS cert is self-signed (`-k`).

### 16.2 Enable the owner path (device change - reversible)
- **Generate a dedicated keypair** on the workstation, then submit the **public** key with the real admin username/password to the verified endpoint. Success = `200 OK`, after which:
  ```bash
  ssh -i ~/.ssh/orbi_key root@<router-ip>      # key-only Dropbear on :22 -> /bin/ash (root)
  ```
- **Expected outcome:** interactive UID 0 shell (`id` -> `uid=0`). 
- **What could go wrong / checks:** if login is refused, verify `/etc/shells` lists the root shell (§11 gotcha) and that `/etc/dropbear/authorized_keys` holds exactly your key.
- **Reverse it:**
  ```sh
  kill "$(cat /var/run/dropbear.pid)" 2>/dev/null; pkill dropbear
  rm -f /etc/dropbear/authorized_keys
  # (optional) restore /etc/shells to contain /bin/ash
  ```
  A reboot also stops Dropbear (it does not auto-start).

### 16.3 Persistence options (device change - reversible, choose after 16.2)
- **Minimal/none:** re-run 16.2 after each reboot (nothing left running).
- **Boot hook:** append the `dropbear ... ` start line to `/etc/rc.local` (overlay, survives reboot; kept across upgrade only if in `sysupgrade.conf`). Remove the line to revert.
- **OpenSSH instead:** with a root shell, add your public key to `/etc/ssh/id_rsa.pub` (and/or set `PasswordAuthentication yes`); note `ForceCommand ssh_login_ntgr.sh` still prompts for admin creds unless removed. All overlay edits, reversible.
- **Do not** rely on any of these surviving a **factory reset**.

---

## 17. Risks and Recovery Procedures

| Action | Risk | Mitigation / Recovery |
|---|---|---|
| Endpoint probe (16.1) | increments 5-try counter; TLS/session surprises | keep probes few; counter resets on reboot |
| Enable Dropbear (16.2) | opens :22 with your key on the LAN | isolated LAN; remove key + kill dropbear to revert |
| Boot hook (16.3) | mis-edit of `/etc/rc.local` | it is a no-op by default; keep a copy; remove the added line |
| `/etc/shells` rewrite (by handler) | possible shell-not-listed login refusal | restore `/bin/ash` entry |
| Firmware mod (§12) | **brick**, secure-boot rejection | **avoid**; if ever attempted, have `nmrpflash` + stock CHK ready for TFTP recovery |

No action in the recommended path (16.1-16.3) touches NAND, the bootloader, or firmware images. All are LAN-side configuration using owner credentials.

---

## 18. Outstanding Questions

1. **Exact external URL of `/enable_ssh`** (`/api/v1/enable_ssh` vs `/api/enable_ssh`) and whether lighttpd requires an authenticated web session or XSRF token in front of it. -> 16.1 settles it. (Current best guess: `/api/v1/enable_ssh`, STRONGLY INDICATED.)
2. **Runtime value of `disable_telnet_login`** and whether any process ever creates `/tmp/telnet_enabled` at runtime (static analysis says no). 
3. **Does Dropbear here honor `/etc/shells`** for key-only root login (the `ash`->`sh` rewrite gotcha)?
4. **Is FIT signature verification enforced** by the bootloader (secure-boot fuses)? Determines §12 feasibility; not answerable from the image alone.
5. **Blowfish helper constants in `remoteshellenable`** were treated as the standard algorithm (consistent with the already-verified `telnetenabled` engine); a byte-level confirmation of `FUN_000111d4`/`FUN_0001239c` would upgrade §5.1 crypto details from STRONGLY INDICATED to fully VERIFIED. (Not needed for the recommended path.)

---

## 19. Appendix: Commands, File Paths, Binary Functions, References

### 19.1 Re-extract the running firmware (if the working copy is gone)
```bash
# extraction chain, driven from the model-specific .chk you downloaded:
bash extract_chk.sh RBRE960-V7.2.7.15.chk <outdir>
# chain: CHK -> FIT (dumpimage/binwalk) -> UBI (ubireader) -> squashfs (7z/unsquashfs)
```

### 19.2 Lua 5.1 bytecode disassembler
`luadis.py`
- Handles this build's quirks: **4-byte `lua_Number`**, **number constants tagged type `9`**, stripped debug.
- Usage: `python3 -I luadis.py <compiled.lua>`  (also works on `rest.lua`, `seal-io.lua`, etc.)

### 19.3 Key file paths (in `$R` = extracted 7.2.7.15 rootfs)
| Path | Role |
|---|---|
| `usr/sbin/remoteshellenable` | live UDP:23 magic-packet daemon -> starts OpenSSH (§5) |
| `usr/sbin/telnetenabled` | legacy daemon, **deleted at boot** by init_sshenable |
| `usr/sbin/ssh_update_ntgr.sh` | writes `/tmp/httpwd` = `UPPER(sha256 digest)` |
| `etc/init.d/init_sshenable`, `etc/hotplug.d/iface/95-ssh` | boot wiring (§4) |
| `etc/ssh/sshd_config`, `etc/ssh/id_rsa.pub`, `bin/ssh_login_ntgr.sh` | OpenSSH lockdown (§6) |
| `usr/sbin/dropbear`, `etc/config/dropbear` | Dropbear (started only by enable_ssh) |
| `etc/init.d/telnet`, `bin/login.sh`, `bin/login_telnet2` | telnet gating (§8) |
| `usr/share/lua/seal-development.lua` | **`enable_ssh` handler (owner path, §9)** |
| `www-seal/rest/rest.lua` | REST router, `/enable_ssh` route (§9) |
| `etc/lighttpd_conf.ltp` | TLS + `^/api/`->16667 proxy + extforward trust (§9/§13) |
| `usr/sbin/fnvram`, `usr/sbin/nvram`, `usr/bin/seal` | config/credential access (§10) |
| `/lib/upgrade/keep.d`, `sysupgrade.conf` | upgrade keep-list incl. `/etc/dropbear/` (§11) |

### 19.4 Binary functions of record (`remoteshellenable`, sha256 `1d4ac867...e8de`)
| Addr | Role |
|---|---|
| `0x10bec` `main` | UDP:23 bind, recv, `memcmp(recv, expected)`, `/etc/init.d/sshd start`, reply `"ACK"` |
| `0x12484` | builds 248-byte expected plaintext (MD5 hdr / MAC / "admin" / pw-digest), Blowfish key `AMBIT_TELNET_ENABLE+<digest>`, encrypt |
| `0x111d4` / `0x1239c` | Blowfish key schedule / encrypt (standard algorithm, LE word packing) |
| `0x11fe0` | read `/tmp/httpwd` |
| `0x120a8` | spawn helper (`ssh_update_ntgr.sh`, `/etc/init.d/sshd`, `/bin/rm`) |

### 19.5 Decompiled Lua of record
- `enable_ssh`, `verify_admin`, `is_in_blank_state`, attempt-counter helpers - `seal-development.lua` (§9.3).
- `/enable_ssh` handler + router + header handling - `rest.lua` (§9.2); response codes `200`/`418`.

### 19.6 External references
- NVRAM/firmware behavior and recovery: Netgear RBRE960 release notes (`~/Downloads/RBRE960-V7.2.7.15/...Release_Notes.html`); `nmrpflash` for TFTP recovery (only if §12 is ever attempted).

---

*End of document. No router modification or firmware flashing was performed in producing this research; §16.2-16.3 are proposed, reversible, owner-authenticated actions for you to run at your discretion.*