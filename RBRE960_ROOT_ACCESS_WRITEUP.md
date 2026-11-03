# Owner-Authorized Root Access on the NETGEAR Orbi RBRE960

**A reproducible, administrator-authenticated method using stock firmware**

| | |
|---|---|
| **Device** | NETGEAR Orbi RBRE960 (Wi-Fi 6E router) |
| **Firmware** | V7.2.7.15_5.1.16 |
| **Platform** | ARMv7l, Linux 4.4.60, OpenWrt "Chaos Calmer" base, BusyBox v1.30.1 |
| **Result** | Verified interactive root shell (`uid=0(root)`) over SSH |
| **Date** | 2026-11-02 |
| **Authorization** | Device owner, isolated LAN, owner-authorized security research |
| **Status** | Reproducible; non-persistent (reverts on reboot) |

> **Scope & ethics.** This documents administration of hardware the author owns,
> on an isolated LAN, using the firmware's *own* administrator-authenticated
> mechanism. It does **not** bypass authentication, brute-force credentials,
> exploit the command-injection weakness, modify firmware, or establish hidden
> persistence. The command-injection sink described in §9 was observed by static
> analysis and deliberately **not** exercised.

---

## 1. Abstract

The RBRE960 stock firmware exposes an administrator-authenticated REST endpoint,
`POST /api/v1/enable_ssh`, that installs a caller-supplied SSH public key into
`/etc/dropbear/authorized_keys` and starts the Dropbear SSH daemon on TCP 22 with
key-only root login. Supplying the device owner's own credentials and an **RSA**
public key yields a verified `uid=0` root shell. No exploit is required - the
method uses an intended (if undocumented) administrative capability of the stock
image. Access is **not** persistent across reboot by default, which this document
treats as the desirable low-footprint state.

---

## 2. Evidence classification

Findings are labelled per the project convention:

- **VERIFIED** - established by firmware/binary analysis or direct runtime evidence.
- **STRONGLY INDICATED** - multiple corroborating signals, not fully confirmed.
- **HYPOTHESIS** - plausible, needs more work.
- **RULED OUT** - investigated and found not viable here.

---

## 3. Target environment

| Item | Value |
|---|---|
| Router LAN IP | `<router-ip>` (`br-lan`) |
| Router LAN MAC | `<MASTER_LAN_MAC>` (redacted) |
| WAN interface | `eth4` (public IP via DHCP) |
| Guest bridge | `br-guest` `<guest-bridge-subnet>` |
| Admin web/SOAP | `lighttpd` on 443/80; Seal REST + SOAP (SOAP_HTTPs_Port 443) |
| TLS certificate | self-signed leaf, `CN=routerlogin.net`, RSA-1024, `CA:FALSE` |
| Workstation | Fedora Linux (OpenSSH + Python 3), on the same LAN over Wi-Fi 6E |

---

## 4. The mechanism (VERIFIED by firmware static analysis)

The Seal REST handler was recovered from the firmware's Lua implementation
(`www-seal/rest/rest.lua`, `seal-development.lua`).

**Request contract**

```
POST https://<router-ip>/api/v1/enable_ssh
Content-Type: application/json

{ "username": "<admin user>", "password": "<admin password>", "pubkey": "<ssh public key>" }
```

- Route is **POST-only** (no GET route). Body **must** be JSON; query-string
  parameters are ignored by the handler.
- The handler self-authenticates via `verify_admin()`. No separate web session or
  CSRF token is required in the handler path.
- On success it writes the public key to `/etc/dropbear/authorized_keys` and
  starts Dropbear.

**Response contract**

| HTTP | Meaning |
|---|---|
| `200 OK` | `verify_admin()` passed and the handler ran. **Does not** prove Dropbear started, the key installed, or TCP 22 is open - verify separately. |
| `418 I'm a teapot` | handler returned false: **wrong credentials OR rate-limited** (ambiguous by design) |
| `400 Bad Request` | body was not valid JSON (rejected before authentication) |
| `500 Server Error` | handler raised on the device |

**Rate limiter (VERIFIED).** A counter in `/tmp/enable-ssh-attempt-counter`
increments only on a *failed* `verify_admin()`. At `>= 5` the endpoint refuses
*before* checking credentials. It is never reset on success and never time-decays;
it lives on tmpfs, so only a reboot (or deleting the file) clears it.
**Consequence:** at most 5 wrong-password attempts before lockout-until-reboot -
do not guess.

---

## 5. Prerequisites

1. LAN access to the router (same subnet; here Wi-Fi).
2. Python 3 with `requests` (the client in `seal_dropbear_enable.py`).
3. The device **administrator credentials** (entered interactively; never stored).
4. An **RSA** SSH key pair - see §8 for why ed25519 does not work:
   ```bash
   ssh-keygen -t rsa -b 2048 -f ~/.ssh/orbi_rbre960_rsa -C "orbi-rbre960-root"
   ```
5. The router's TLS certificate SHA-256 fingerprint for pinning (see §7).

---

## 6. Reproduction - step by step

### 6.1 Establish connectivity (and the anti-scan gotcha)

**STRONGLY INDICATED:** the router runs NETGEAR Armor (BitDefender) and will
**temporarily RST management connections from a LAN source that behaves like a
scanner** (rapid repeated connects, directory brute-forcing). Symptom: ports
80/443 return "connection refused" (fast TCP RST from the router MAC) while ARP,
NAT, and internet forwarding keep working, and other clients (e.g. a phone) are
unaffected. It **self-clears within minutes** once probing stops.

Diagnosis without over-probing:
```bash
ip neigh show <router-ip>            # L2 reachable?
ip route get <router-ip>            # correct interface/route?
curl -sS -k -m6 https://<router-ip>/currentsetting.htm   # management plane alive? (model/firmware)
```
If refused: **stop all probing and wait** - do not scan, do not loop `nc`. Do not
reboot; this is not a crashed service (see §10).

### 6.2 TLS trust (without weakening the host)

The device cert is RSA-1024, which Fedora's system crypto policy (OpenSSL
SECLEVEL=2) rejects as "EE certificate key too weak" - a *key-strength* rejection,
not a trust failure. The client solves this per-connection (SECLEVEL=1 on one
socket only) and anchors trust by **pinning the certificate's SHA-256 fingerprint**
(`--pin-sha256`). Capture the fingerprint read-only:
```bash
echo | openssl s_client -connect <router-ip>:443 2>/dev/null \
  | openssl x509 -fingerprint -sha256 -noout
```

### 6.3 Counter-safe reachability probe (no credentials)

Confirms the endpoint and validates the pin **without** touching the attempt
counter (it POSTs invalid JSON, rejected at the JSON layer before `verify_admin`):
```bash
python3 seal_dropbear_enable.py --probe --pin-sha256 <fingerprint-hex>
# expected: Outcome: probe_reachable (HTTP 400)  -> malformed-JSON message
```

### 6.4 Enable SSH (owner-authenticated, device-changing)

```bash
python3 seal_dropbear_enable.py --enable --pin-sha256 <fingerprint-hex>
# prompts: type ENABLE  ->  admin username  ->  admin password (hidden)
# expected: HTTP 200 OK
```
The client validates the password for shell-safety **before** opening a socket
(see §9) and never logs it.

### 6.5 Connect and verify root

Dropbear here is an **old build**: it presents only an `ssh-rsa` host key and
regenerates it on (re)start, and it does not accept ed25519 *user* keys. Modern
OpenSSH therefore needs explicit legacy-algorithm opt-ins, and the regenerated
host key must be re-learned:
```bash
ssh-keygen -R <router-ip>                                  # clear the regenerated host key
ssh -i ~/.ssh/orbi_rbre960_rsa \
    -o HostKeyAlgorithms=+ssh-rsa \
    -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    root@<router-ip> id
# success condition:  uid=0(root) gid=0(root)
```
Persist the options in `~/.ssh/config`:
```
Host orbi <router-ip>
    HostName <router-ip>
    User root
    IdentityFile ~/.ssh/orbi_rbre960_rsa
    IdentitiesOnly yes
    HostKeyAlgorithms +ssh-rsa
    PubkeyAcceptedAlgorithms +ssh-rsa
```

### 6.6 One-command wrapper

`orbi_root_shell.py` orchestrates the whole flow (ensure RSA key -> counter-safe
probe -> `ENABLE` + credentials -> clear stale host key -> wait for TCP 22 -> verify
`uid=0` -> interactive shell). `--connect-only` skips the enable when SSH is already
up; `-c "<cmd>"` runs one command. It imports `seal_dropbear_enable.py` rather than
re-implementing the request logic.

---

## 7. Common failure modes and fixes (all VERIFIED during testing)

| Symptom | Cause | Fix |
|---|---|---|
| `Connection refused` / TCP RST on 80/443, ARP+internet fine | Armor transient anti-scan block | Stop probing, wait minutes. Not a crash; do not reboot. |
| `--probe` transport error with plain verify | RSA-1024 cert vs Fedora SECLEVEL | Use `--pin-sha256` (or `--insecure-probe` for the probe only) |
| Tool refuses the password | Password contains shell metacharacters (e.g. `$`) | The firmware hashes it via an unquoted shell; such a password cannot authenticate here. Set a metacharacter-free admin password. |
| `HTTP 418` | wrong credentials **or** 5-attempt lockout | Use correct creds; if locked, only a reboot clears the counter |
| `no matching host key type ... Their offer: ssh-rsa` | old Dropbear host key type | add `-o HostKeyAlgorithms=+ssh-rsa` |
| `Permission denied (publickey)` with an ed25519 key | Dropbear build lacks ed25519 user-key support | use an **RSA** key and re-run `--enable` with it |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | Dropbear regenerated its host key on restart | `ssh-keygen -R <router-ip>` |

---

## 8. Post-access device characterization (read-only, VERIFIED)

- **OS/userland:** Linux 4.4.60 ARMv7l, OpenWrt base, BusyBox 1.30.1 ash.
- **Dropbear invocation:** `dropbear -P /var/run/dropbear.pid -s -g -p 22 -K 300 -T 3 -R`
  (`-s` no password auth, `-g` no root-password login, `-R` generate host keys on
  demand -> the source of host-key churn). Launched directly by the enable handler,
  **not** from `/etc/config/dropbear` (which is inert, see §10).
- **Security/telemetry stack running as root:** NETGEAR Armor / BitDefender
  (`boxbdnc`, `bdbrokerd`, `bdcloudd`, `bddevicediscovery`, an `armor-bd` LXC),
  Circle parental controls (`spc-circle` LXC), Fing (`fing_dil`), and the Netgear
  cloud agent `xagent` with an AWS link (`aws_json`, `aws_heartbeat`).
- **Mesh/backhaul:** `hyd` (7777 LAN / 8888 guest, loopback-only), `wsplcd`, and
  `acfg_tool -t <internal-backhaul-ip>` (an internal backhaul-management address).
- **Separate SSH-enable lineage (not this method):** `/etc/init.d/init_sshenable`
  -> `/usr/sbin/remoteshellenable` -> `/usr/sbin/ssh_update_ntgr.sh` drives an
  **OpenSSH** (`/usr/sbin/sshd`) debug path, distinct from the Seal->Dropbear path.
  `ssh_update_ntgr.sh` branches on `/tmp/ntgr_satellite` - a lead for satellites (§12).

---

## 9. The `verify_admin()` command-injection weakness (VERIFIED, NOT exercised)

`verify_admin()` computes the password digest with, in effect:
```
run_shell("echo -n " .. password .. " | sha256sum | ...")   -- password UNQUOTED
```
The password is interpolated unquoted into `/bin/sh -c`. Two consequences:

1. **Benign but blocking:** a legitimate password containing shell metacharacters
   (space, `$`, `` ` ``, `;`, `|`, `&`, quotes, globs, ...) is mangled by the shell,
   so it hashes the wrong string and **cannot authenticate at this endpoint** -
   even though it works on the normal login page. Workaround used here: set a
   metacharacter-free admin password.
2. **Security sink:** a crafted metacharacter payload would be command injection.
   This is the same *class* of issue public researchers have repeatedly reported in
   Orbi (see §13). **This research did not construct or send any such payload.** The
   client enforces this by rejecting metacharacter passwords *before* any socket is
   opened, and by validating the public key cannot break the device-side
   `authorized_keys` write.

---

## 10. Persistence analysis (VERIFIED: NOT reboot-persistent)

- Root filesystem `/` is an **overlayfs** whose upper layer is on **UBI flash**
  (`ubi2:Reserved` -> `/tmp/media/reserved2/overlay/upper`). So files written under
  `/etc` **do persist** - the installed `authorized_keys` and the regenerated
  `dropbear_rsa_host_key` are both confirmed present in the flash-backed overlay.
- **But Dropbear does not start at boot.** `/etc/init.d/dropbear` **does not exist**
  (removed by NETGEAR); the `/etc/rc.d/S19dropbear` and `K50dropbear` symlinks are
  therefore **dangling** and start nothing. `/etc/config/dropbear` exists but is
  inert without the init script (and its `PasswordAuth on` contradicts the live
  `-s -g` flags, confirming the handler launches Dropbear directly).
- Corroboration: the router had **13 days uptime with TCP 22 closed** until the
  enable ran.

**Conclusion:** after a reboot, Dropbear is not running; the key remains on flash,
so re-running the method re-enables access in one step. Access is effectively
**on-demand** - the smaller security footprint, and recommended to keep.

---

## 11. Exposure assessment (VERIFIED)

- Dropbear binds `0.0.0.0:22` and `:::22` (wildcard), **but the firewall makes it
  LAN-only.** `INPUT` policy is `DROP`; `INT_INPUT_CHAIN` ends in `ACCEPT all` for
  `br-lan` (how LAN SSH works), while `REMOTE_MGMT_WAN_CHAIN` explicitly drops
  WAN-facing 80/53/5000 and there is **no accept for WAN->22**, so it falls through
  to the default `DROP`. IPv6 `INPUT` has the same shape. **Not internet-reachable.**
- Confirm after any change:
  ```bash
  iptables -L INPUT -nv --line-numbers
  iptables -L REMOTE_MGMT_WAN_CHAIN -nv
  ```

---

## 12. The RBSE960 satellites

**VERIFIED:** two satellites on the LAN - `<satellite-1-ip>` and `<satellite-2-ip>`, both
`Model=RBSE960`, firmware `V7.2.7.15`, `lighttpd` on 443.
Each satellite presents its own self-signed TLS certificate; the per-device SHA-256 pins are recorded locally and kept out of this publication.

**RULED OUT (as-is):** the Seal method does not transfer - a counter-safe probe to
`/api/v1/enable_ssh` returns **HTTP 404** on both (the router returns 400), i.e. the
Seal REST app is **not mounted** on satellites (likely gated off in satellite/AP
mode).

**HYPOTHESIS (future work):** the `remoteshellenable` / `ssh_update_ntgr.sh`
OpenSSH debug lineage appears present on the satellite side (the script branches on
`/tmp/ntgr_satellite`), and the router manages the satellites over the
`<internal-backhaul-subnet>` backhaul via `hyd`/`wsplcd`/`acfg_tool`. Root on a satellite most
plausibly comes from (a) static analysis of the **RBSE960 firmware image**, or
(b) a read-only pivot from the already-rooted router over the backhaul.

---

## 13. Related prior work (external; verify against vendor advisories)

Rooting Orbi is established ground, though a published write-up of *this* specific
authenticated Seal endpoint on the RBRE960 was not found:

- **Cisco Talos (2022)** documented a hidden telnet/remote-shell feature on the Orbi
  router (CVE-2022-38452) and a ubus-backend command execution on the Orbi satellite
  (CVE-2022-36429), on the earlier RBR750/RBS750 family. These are the direct
  ancestors of the `remoteshellenable`/`telnetenabled` and satellite-ubus machinery
  seen here.
- NETGEAR's **`telnetenable` magic-packet** lineage is long-standing and public.
- For the 960 series specifically, public vulnerability databases list
  **CVE-2026-3088** (out-of-bounds write) as affecting RBRE960/RBSE960 firmware
  **before V7.2.7.15** (i.e. fixed at or before the running image). A separate
  authentication-bypass entry (CVE-2026-0405) is described against Orbi devices
  generally but without a confirmed RBRE960/RBSE960 fixed-version mapping, and a
  stack-overflow entry (CVE-2026-0413) is listed against other Orbi router models,
  not the 960 series. The local `7.2.8.5 -> 7.2.8.8` dispatcher hardening is
  consistent with a generic "security fixes" note but is not tied to a specific CVE
  here. See `REFERENCES.md`; confirm all mappings against NETGEAR's official
  advisory tables.

---

## 14. Rollback and safety

- **Reboot** reverts everything (Dropbear stops; tmpfs counter clears; key remains
  on flash but unused until re-enabled).
- **Manual teardown** from the root shell: stop Dropbear and remove the key:
  ```sh
  kill "$(cat /var/run/dropbear.pid)" 2>/dev/null
  rm -f /etc/dropbear/authorized_keys
  ```
- Out of scope / not performed: factory reset, firmware/bootloader modification,
  UART, disabling Armor/DoS protection, WAN exposure, hidden persistence.

---

## 15. Tooling in this project

| File | Role |
|---|---|
| `seal_dropbear_enable.py` | Verified Seal client: request contract, SECLEVEL-1 TLS pinning, password shell-safety validation, counter-safe `--probe`, response classification. Covered by `test_seal_dropbear_enable.py`. |
| `test_seal_dropbear_enable.py` | Unit tests (mocked HTTP + local-cert TLS handshake); no router contact, no credentials. |
| `orbi_root_shell.py` | One-command orchestration wrapper around the above (probe -> enable -> connect -> verify `uid=0` -> shell). |

---

## 16. Open questions / future work

1. RBSE960 satellite root (firmware analysis vs backhaul pivot) - §12.
2. Exact persistence flag, if any, that `remoteshellenable` sets for the OpenSSH path.
3. Behavioural characterization of the Armor anti-scan trigger/threshold (read-only).
4. Owner-side telemetry audit: what Armor, Fing, and `xagent`/AWS actually transmit.

---

## 17. Appendix - minimal command reference

```bash
# one-time
ssh-keygen -t rsa -b 2048 -f ~/.ssh/orbi_rbre960_rsa -C "orbi-rbre960-root"
echo | openssl s_client -connect <router-ip>:443 2>/dev/null | openssl x509 -fingerprint -sha256 -noout

# probe (safe) then enable (authenticated)
python3 seal_dropbear_enable.py --probe  --pin-sha256 <fp>
python3 seal_dropbear_enable.py --enable --pin-sha256 <fp>     # ENABLE, user, password

# connect
ssh-keygen -R <router-ip>
ssh -i ~/.ssh/orbi_rbre960_rsa -o HostKeyAlgorithms=+ssh-rsa \
    -o PubkeyAcceptedAlgorithms=+ssh-rsa root@<router-ip> id      # -> uid=0(root)

# or, all of the above in one step
python3 orbi_root_shell.py
```

*End of document.*
