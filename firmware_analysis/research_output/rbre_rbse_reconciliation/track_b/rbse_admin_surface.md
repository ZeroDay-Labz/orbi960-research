# RBSE 7288 admin-surface inventory (Track B evidence)

## Top-level admin surface

| path | contents / role |
|---|---|
| `www/` | `assets/`, `cgi-bin/`, `luci-static/`, `soap/`, `index.htm` — LuCI-style web root |
| `www/cgi-bin/` | Empty in listing (no LuCI dispatcher binary, uses `/usr/sbin/cgi-bin/soap_agent`) |
| `usr/sbin/cgi-bin/` | `soap_agent` — the only CGI binary (already ruled out as CVE-0415 location in reports 32–36 for the auth-refactor delta) |
| `etc/lighttpd/` | Sat lighttpd config tree |
| `usr/lib/lua/` | 120 LuCI Lua files (all unchanged between 7215 and 7288 except `luci/version.lua`) |
| `usr/share/rpcd/acl.d/` | `netgear.json`, `unauthenticated.json` — only 2 ACL files |
| `usr/lib/rpcd/` | `debuglog.so`, `setrequest.so`, `uirequest.so`, `upgrade.so` — 4 rpcd plugins |

**Absent on RBSE** (present on RBRE):
- `/www-seal/` (Seal REST web root)
- `/www-seal/rest/rest.lua` (CVE-fix location #2)
- `/usr/share/lua/seal-services.lua` (CVE-fix location #1)
- Any `/api/v1/install`, `/api/v1/uninstall`, `/api/v1/services/*` route
- Any `/etc/lighttpd_root_conf.ltp` (the root-privileged internal lighttpd variant)

## rpcd ACL — admin-writable surface

From `rbse_7288/rootfs/usr/share/rpcd/acl.d/netgear.json`:

**Write (admin-mutating) operations exposed:**
- `webui-io.upload`
- `netgear.log.{ntgrlog_start, ntgrlog_stop, log_boot_enable, log_boot_disable, telnet_enable, telnet_disable, packet_capture_start, packet_capture_stop}`
- `netgear.upgrade.upgrade_start`
- `netgear.set.set_language`

**Read operations exposed:**
- `webui-io.download`
- `netgear.log.{ntgrlog_status, log_boot_status, telnet_status, packet_capture_status, firmware_version, hop_count, cpu_load}`
- `netgear.upgrade.{upgrade_status, upgrade_version}`
- `netgear.get.{pot_details, satellite_status, connected_device, get_language}`
- `system.info`, `session.{access, destroy, get}`, `uci.*`

## Byte-identical check: critical rpcd plugins across 7215 and 7288

`usr/lib/rpcd/upgrade.so` — sha256 `412cbd77587bd443a638b9d5a4d7461b9abc90d6d87beec70daf43845211803b`
in both `rbse_7215` and `rbse_7288`. The firmware-upgrade RPC path did not
change between the two sat firmware versions.

## Fingerprint scan for Seal-service sinks

Command (over all of `usr/sbin/`, `usr/bin/`, `usr/libexec/`, `usr/lib/rpcd/`,
`www/cgi-bin/` in `rbse_7288/rootfs/`):

```
strings <file> | grep -E "(opkg (install|remove|status)|ssvc status|/usr/bin/nsh.sh argument|service_action_handler|service_uppers)"
```

**Zero hits across the entire admin-surface binary set.**

## Conclusion (summarized)

RBSE 7288 contains **no equivalent code path** to the master's Seal-service
lifecycle handlers (install / uninstall / state / webapp / token /
validateToken / service_action_handler). The sat exposes a narrow rpcd ACL
whose write operations are `webui-io.upload`, logging toggles, firmware
upgrade start, and language setting — none of which concatenates admin-controlled
service names into shell commands.
