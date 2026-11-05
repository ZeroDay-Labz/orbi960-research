# orbi-owner-agent — Architecture

**Status:** draft design, aligned with the actual firmware platform established by Phase 1 (`platform-fingerprint.md`) and Phase 2 (`network-capability-matrix.md`).

**Target:** NETGEAR Orbi RBRE960 master router running vendor-modified OpenWrt
Chaos Calmer 15.05.1 (`rtm-7.2.7.15+r49254`) on Qualcomm IPQ807x /
`ap-hk01-c6`, kernel 4.4.60, libc musl 1.1.16-1, opkg arch `ipq`.

## 1. Goals and non-goals

### Goals
- Small, auditable device-side management agent.
- Uses only the platform components NETGEAR already runs (`rpcd`, `ubus`,
  `uci`, `procd`, `jshn`), so no new network listener is introduced.
- Explicit method allowlist: every callable operation is named, documented,
  and validated.
- External Proxmox controller does authentication, authorization, UI,
  dashboards, multi-device coordination, history and backup retention.
- Clean uninstall; stock firmware untouched.

### Non-goals (explicit)
- **No** general-purpose `exec`, `shell`, `write-file`, or
  `install-arbitrary-ipk` endpoint.
- **No** replacement of the stock firmware.
- **No** modification of the bootloader, QSEE, DEVCFG, APPSBL,
  ART / wifi calibration data, or any MTD partition outside the writable
  overlay.
- **No** setuid helper, no bind-shell, no backdoor, no hard-coded
  credentials.
- **No** separate network listener. The agent is **not** reachable from the
  WAN or LAN directly; callers reach it only via `rpcd`/`ubus`, which is
  itself reachable only to UNIX-socket clients on the device — meaning
  remote callers must SSH in first.

## 2. Platform-fit decision — why rpcd exec-plugin

The on-device inventory establishes:

- `rpcd 2016-06-30-23417e94…` installed and running.
- `/usr/libexec/rpcd/*` is the vendor's own exec-plugin directory
  (observed scripts: `satellite`, `securebootstatus`).
- `/usr/lib/rpcd/*.so` holds compiled plugins (`ntgr_stats.so`,
  `ntgr_wlparam.so`).
- ACLs under `/usr/share/rpcd/acl.d/*.json` gate who can call what.

The vendor's `satellite` plugin establishes the pattern we follow:

```sh
#!/bin/sh
case "$1" in
    list) echo '{"method1": {}, "method2": {}}' ;;
    call)
        case "$2" in
            method1)
                . /usr/share/libubox/jshn.sh
                # read request from stdin, validate, act, echo JSON
                ;;
        esac ;;
esac
```

Because this is a **pure shell** plugin:
- No compilation; the package architecture is `all`, which sidesteps the
  musl/ipq toolchain requirement for a C build.
- `jshn` (`/usr/bin/jshn`) and `jsonfilter` (`/usr/bin/jsonfilter`) are
  already installed — JSON parse/produce needs no new dependency.
- Install-size is a few kilobytes.
- Stop/restart is not a concern — rpcd invokes the plugin per-call; there
  is no persistent daemon state to corrupt.

A C `/usr/lib/rpcd/orbi-owner-agent.so` plugin would let us drop the
per-call `exec(sh)` overhead, but introduces a toolchain dependency on
the exact NETGEAR SDK that we cannot fully reproduce without their GPL
source bundle and matching proprietary pieces (see Phase 1). We ship the
shell plugin first; a C plugin is a Phase-B option.

## 3. On-device footprint

```
/usr/libexec/rpcd/orbi-owner-agent              rpcd exec plugin, ~5 KB
/usr/share/rpcd/acl.d/orbi-owner-agent.json     ACL
/usr/share/orbi-owner-agent/lib/common.sh       shared helpers
/usr/share/orbi-owner-agent/lib/validate.sh     whitelist validators
/usr/share/orbi-owner-agent/lib/network.sh      network-read helpers
/usr/share/orbi-owner-agent/lib/backup.sh       backup helpers
/usr/share/orbi-owner-agent/lib/audit.sh        audit logger
/etc/config/orbi-owner-agent                    UCI policy
/etc/init.d/orbi-owner-agent                    procd init (control-only, not a daemon)
/etc/uci-defaults/80-orbi-owner-agent           first-boot bootstrap
```

**Not installed:**
- No binaries outside `/usr/libexec/rpcd/`.
- No kernel modules.
- No setuid files.
- No writes into `/rom`, `/etc/config/network`, `/etc/config/wireless`,
  `/etc/config/firewall`, or any other vendor UCI config unless the owner
  explicitly invokes a method whose purpose is to write them.

## 4. ubus namespace and method surface

Namespace: `orbi.owner.agent`

The method surface is ALLOWLIST-only and is intended to grow slowly. Phase 1
methods:

| method       | class     | side effect | notes |
|---|---|---|---|
| `info`       | read      | none        | agent version, package build hash |
| `status`     | read      | none        | model, firmware version, uptime, mesh fronthaul/backhaul radio status |
| `network`    | read      | none        | `ip -details link show` + `/proc/net/vlan/config` + current bridge VLAN membership — JSON-structured |
| `vlan_list`  | read      | none        | current 802.1Q interface list (names, ids, parent) |
| `audit_tail` | read      | none        | last N audit-log lines (bounded by `max_tail_lines` UCI) |
| `backup`     | read      | none        | tarball of `/etc/config/orbi-owner-agent`, `/etc/config/network`, and declared-persistent files only; streamed base64 in JSON |
| `vlan_create`| write     | adds UCI `interface` + `device` section for an 802.1Q sub-interface **under the orbi-owner namespace**; commits network | strict validation: id 2-4094, name `^owner_[a-z0-9]{1,8}$`, parent must be an allowed bridge |
| `vlan_delete`| write     | removes the matching owner-namespaced 802.1Q | identifier must match `^owner_[a-z0-9]{1,8}$` |
| `rollback`   | write     | `uci revert` on any uncommitted changes under `network` **made in this ubus call-chain** | never touches vendor commits |

Phase 2 (deferred, blocked on capability matrix): `firewall_zone_add`,
`wireless_guest_vlan_bind`.

**What is NOT exposed:**
- `exec`, `system`, `shell`, `run`, `command`.
- `install`, `remove`, `upgrade`, `opkg`.
- `write_file`, `read_file`, `path_get`.
- Any method that takes a path parameter from the caller.
- Any method that takes a shell template with substitution.

## 5. Caller authentication

External Proxmox controller → SSH to `root@10.0.0.1` with the owner's
RSA key → `ubus call orbi.owner.agent <method> '<json>'` **as root**.

Rationale:
- The owner's existing authenticated-SSH path (`orbi_root_shell.py` plus
  Dropbear-RSA key) is already VERIFIED and does not require a new
  transport.
- Adding a new HTTP listener would create new attack surface and risk
  colliding with the existing lighttpd/Seal stack. Phase-A deliberately
  avoids it.
- The rpcd ACL below is defense-in-depth: even if some future code path
  grants a non-root session a ubus handle, it cannot reach these
  methods.

## 6. rpcd ACL

```json
{
  "orbi-owner-agent-reader": {
    "description": "Read-only owner-agent telemetry",
    "read": {
      "ubus": {
        "orbi.owner.agent": [
          "info", "status", "network", "vlan_list",
          "audit_tail", "backup"
        ]
      }
    }
  },
  "orbi-owner-agent-admin": {
    "description": "Owner-agent VLAN management",
    "read":  { "ubus": { "orbi.owner.agent": ["info", "status", "network", "vlan_list", "audit_tail", "backup"] } },
    "write": { "ubus": { "orbi.owner.agent": ["vlan_create", "vlan_delete", "rollback"] } }
  }
}
```

The ACL names two roles. We do not create a new rpcd `login` for them —
root callers skip ACL evaluation per rpcd's design. The roles exist so
that a future non-root caller (e.g., a dedicated owner-agent UNIX user)
can be granted *only* read access, or read+vlan, without `root`
privileges. This is forward compatibility, not a current requirement.

## 7. Input validation

Every method validates every argument. Validation lives in
`/usr/share/orbi-owner-agent/lib/validate.sh` as named functions:

| validator         | pattern                       | length cap |
|---|---|---|
| `valid_vlan_id`   | `^[1-9][0-9]{0,3}$`, 2-4094   | ≤4 chars |
| `valid_vlan_name` | `^owner_[a-z0-9]{1,8}$`       | ≤14 chars |
| `valid_bridge`    | strict allowlist from UCI     | ≤16 chars |
| `valid_int`       | `^[0-9]{1,6}$`                | ≤6 chars |
| `valid_bool`      | `^(0|1|true|false)$`          | ≤5 chars |

**Never:**
- Build a shell command by string concatenation on untrusted input.
- Pass caller-supplied paths to `tar`, `cp`, `cat`, `dd`, `rm`.
- Pass caller-supplied values to `eval`.
- Log credentials or secrets, even redacted.

Writes to UCI go through the `uci` CLI with discrete argv (not shell
interpolation) and are **committed in an atomic block** — all changes in
one method call are either all applied or all reverted.

## 8. UCI policy — `/etc/config/orbi-owner-agent`

```
config agent 'main'
    option enabled '1'
    option max_tail_lines '500'
    option audit_log '/tmp/orbi-owner-agent.log'
    option audit_max_bytes '262144'
    list allowed_bridge 'br-lan'

config policy 'vlan'
    option enabled '1'
    option min_id '2'
    option max_id '4094'
    list reserved_id '1'
    list reserved_id '4093'    # vendor backhaul tag per MEMORY entry
    list reserved_id '4094'    # vendor backhaul tag per MEMORY entry
```

The reserved list hard-blocks any owner-created VLAN from colliding with
the vendor mesh-backhaul tags that are already in use (per
MEMORY.md "Orbi owner-control platform" entry: backhaul already
802.1Q-trunks 4093/4094).

## 9. Audit log

- Path: `/tmp/orbi-owner-agent.log` (tmpfs, per UCI default).
- Rotation: once file exceeds `audit_max_bytes` (default 256 KB), truncate.
  Rotation is in the agent itself; no cron/logrotate dependency.
- Format (one line per call, no newlines inside fields):
  `<timestamp_utc> method=<name> caller_uid=<N> args=<json> result=<ok|err:<code>> dur_ms=<N>`
- `args` is the **validated, canonicalized** form, not the raw input.
- Secrets never appear in the log (none of our methods take a secret).

## 10. procd integration

The agent is NOT a long-running daemon. The procd script is control-only:

- `start`: validates installation, writes default UCI if absent, touches
  the audit log path — exits.
- `stop`: no-op (nothing to stop).
- `reload`: re-reads UCI (relevant to the plugin's next invocation — the
  plugin reads UCI on each call).
- `enabled`: honors `/etc/config/orbi-owner-agent.main.enabled`.

The plugin itself is invoked by rpcd per ubus call. No systemd, no cron.

## 11. Uninstall behavior

`postrm` removes:
- `/usr/libexec/rpcd/orbi-owner-agent`
- `/usr/share/rpcd/acl.d/orbi-owner-agent.json`
- `/usr/share/orbi-owner-agent/`
- `/etc/init.d/orbi-owner-agent` (after `enabled` → disable)
- `/etc/uci-defaults/80-orbi-owner-agent`
- `/etc/config/orbi-owner-agent` (**only** if user agreed via opkg flag;
  stock package retention behavior is to keep UCI config)

What persists by design:
- Audit log file at `/tmp/…` — tmpfs; gone on reboot anyway.
- Any UCI `network` sections the owner CREATED via the agent remain,
  because they represent network state the owner authored, not package
  files. A separate `vlan_delete` call should be used to remove them
  first.

## 12. Failure / recovery

| failure mode                             | behavior |
|---|---|
| Agent script missing or corrupt           | rpcd returns `UBUS_STATUS_METHOD_NOT_FOUND`; no state changed. |
| Invalid argument                          | Validator returns error JSON; no state changed. |
| `uci set` succeeds but `uci commit` fails | Agent calls `uci revert network`; returns error with code. |
| `/etc/config/orbi-owner-agent` missing    | Agent reconstructs defaults from code; logs reconstruction. |
| Audit log path unwritable                 | Call still proceeds; audit logging degrades silently to console (procd-captured). |
| rpcd restart mid-call                     | Plugin is per-call; no cross-call state. Next call runs fresh. |
| Mesh disruption attempted via reserved VLAN | Validator blocks at `vlan_create` time with `ERR_RESERVED_VLAN`. |

## 13. What this architecture does NOT solve

- **Satellite management:** The sat has no reachable root shell
  (CONFIRMED-ABSENT across reports 31, 36). This package runs only on
  the master. Management of sat state remains indirect via master→sat
  admin channels documented in reports 33/35/36.
- **Firewall policy:** Vendor firewall is not uci-covered (per MEMORY
  entry). `firewall_zone_add` is deferred until Phase 2 establishes
  whether the vendor firewall even reads `/etc/config/firewall`.
- **Wireless VLAN tagging:** Deferred until the capability matrix
  confirms hostapd/wpad support.
- **Package signing:** `option check_signature` is set in
  `/etc/opkg.conf`. Our source-tree `.ipk` will be unsigned. Installing
  requires either `opkg --force-signature install`, pre-staging to
  `/ipk/` and installing from there, or adding the owner's signing key
  to `/etc/opkg/keys/`. Addressed in `build-and-install.md`.

## 14. Cross-reference

| topic                | report / doc |
|---|---|
| Live master recon    | `docs/_evidence/live_master_recon.txt` (fork-collected) |
| Platform fingerprint | `docs/platform-fingerprint.md` (fork-written) |
| Network capability   | `docs/network-capability-matrix.md` (fork-written) |
| Security model       | `docs/security-model.md` |
| Build & install      | `docs/build-and-install.md` |
| Known limits         | `docs/known-limitations.md` |
| CVE-2026-0415        | `firmware_analysis/reports/37`, `38` |
| Master→sat channel   | `firmware_analysis/reports/31, 33, 35, 36` |
| Owner-control intent | `MEMORY.md` → `orbi-owner-control-platform` |
