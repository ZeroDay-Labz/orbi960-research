# orbi-owner-agent — Root-access dependency (Phase 6)

Important: this package does not grant root access. It uses pre-existing
owner-authorized root.

## Root required for: package install & agent runtime

- **Installation** writes files under `/usr/libexec/rpcd/`,
  `/usr/share/rpcd/acl.d/`, `/usr/share/orbi-owner-agent/`,
  `/etc/config/`, `/etc/init.d/`, `/etc/uci-defaults/`. These paths
  are writable only by root.
- **rpcd invokes `/usr/libexec/rpcd/<plugin>` as root.** This is a
  property of the stock firmware; our package does not change it.
- **The agent calls `uci commit` and manipulates `/etc/config/network`
  sections** it authors. Writing the overlay requires root.

## Root NOT required, by design, for: callers of the agent

- The agent's methods are reachable via `ubus` on the local UNIX
  socket. rpcd evaluates the ACL for every call. A hypothetical
  non-root ubus caller holding only the `orbi-owner-agent-reader`
  role could call `info`, `status`, `network`, `vlan_list`,
  `audit_tail`, `backup` without root.
- This firmware does not currently offer a non-root ubus login path,
  so the reader-only role is forward compatibility rather than a
  present-day capability.

## Blocked by current project constraints

- **No sat-side agent.** Reports 31, 35, 36, 38 establish that no
  in-boundary sat root exists. Installing the agent on a sat is
  blocked until sat SSH is solved; current research has RULED OUT
  all tested paths within the project's no-flash constraint.
- **No firewall policy.** The vendor firewall is not uci-covered
  (MEMORY.md) and uses `arno-iptables-firewall` rather than fw3.
  A firewall-policy method would need a vendor-native integration
  path that we have not built or verified.
- **No wireless-SSID VLAN binding.** hyd + hostapd configuration
  needs to be edited in `/etc/config/hyd` with awareness of the 200+
  interacting mesh options, and hyd + wsplcd restarted. The risk of
  disrupting mesh connectivity is too high to attempt in Phase A.

## What owner root enables but we deliberately do not expose

Each of these is doable by root at a shell, but the agent does NOT
provide a ubus endpoint for it:

- `exec` / `system` / arbitrary command run
- Arbitrary file read or write
- Arbitrary `opkg install` / `opkg remove` (would collide with the
  very CVE-2026-0415 surface we are trying to avoid being a party to)
- `reboot`, `shutdown`, factory reset
- Firmware upgrade
- NVRAM write
- Any method that takes a caller-supplied path, template, or
  shell-fragment parameter

Any future expansion of the method surface requires updating
`architecture.md`, adding ACL entries, and writing a security-review
pass in `security-model.md`.

## Rollback story if the owner wants out

1. `ubus call orbi.owner.agent vlan_delete` for each owner VLAN.
2. `opkg remove orbi-owner-agent` (or the manual uninstall from
   `build-and-install.md` §4).
3. Reboot optional — the agent writes only to the overlay; stock
   firmware files are untouched. A firmware upgrade or factory reset
   would also clear any residual agent state.

## Relationship to the project's broader root-access research

- RBRE master root is **VERIFIED** (reports: the initial Seal
  enable_ssh path still works on 7.2.7.15).
- RBSE sat root is **CONFIRMED-ABSENT** in-boundary.
- CVE-2026-0415 is **CONFIRMED** on master as a different
  authenticated-admin → RCE path (reports 37/38). Owner should NOT
  rely on CVE-0415 to deliver this package; use the authorized SSH
  path.
