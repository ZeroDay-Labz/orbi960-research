# RBRE960 -> RBSE960 Management-Plane Map

**Scope:** Does the RBRE960 master have a *supported, authenticated* mechanism to
provision configuration or services (specifically SSH / Dropbear / authorized_keys)
on its RBSE960 satellites?

**Method:** Static analysis of extracted firmware (`rbre_7215`, `rbse_7215`,
`rbse_7288` rootfs) + read-only runtime inspection of the live master (ubus, netstat,
process list, init layout). No configuration changes, no flashing, no exploitation.

**Date:** 2026-11-02. **Evidence labels:** VERIFIED / STRONGLY INDICATED / HYPOTHESIS / UNKNOWN / RULED OUT.

---

## 1. Management-interface map

| Component | Role | Comms mechanism | Auth / Authz | Operations exposed | Affects satellite? | Evidence | Confidence |
|---|---|---|---|---|---|---|---|
| **soap_agent** (satellite) `/usr/sbin/cgi-bin/soap_agent` | SOAP **server** on the satellite; the master's management endpoint into each RE | HTTP(S) CGI under lighttpd (satellite :80/:443) | `Authenticate` / admin **password hash** (`PasswordHash`, `authenticate_satellite_1()`, `ParseAuthenticate`); hash kept in sync via `UpdateAdminPasswordHashed` | Fixed typed set (50 methods): Wi-Fi/backhaul/SSID/WMM/ACL/block-device, device naming, NTP/timezone, `GetInfo`/satellite-info/throughput, `Reboot`, `ResetToFactoryDefault`, `FactoryAndReboot`, `UpdateNewFirmware2` / `CheckAndDownloadNewFirmwareByFolder` | **Yes** - this *is* the on-satellite management surface | `strings soap_agent` method/Response tokens; auth strings | VERIFIED |
| **soapc** (master) `/usr/sbin/soapc` | SOAP **client**; master-side driver that calls satellite `soap_agent` and NETGEAR cloud | HTTP(S) SOAP, URN `urn:NETGEAR-ROUTER:service:{DeviceConfig,DeviceInfo,WLANConfiguration,...}:1` | Uses admin credential/hash prepared by `ssh_update_ntgr.sh` -> `/tmp/httpwd` | Calls the same typed methods (firmware check/download, GetCurrentSatellites*, ConfigurationStarted/Finished, AttachDevice, etc.) | Yes (as caller) | `strings soapc` M1: action templates | VERIFIED |
| **repacd** (both) QCA SON/Multi-AP coordinator | CAP (master) -> RE (satellite) **Wi-Fi/mesh config sync** | Qualcomm Multi-AP (1905.1/CFG) over backhaul | Backhaul association (WPA) | SSID/key/backhaul/VLAN/steering/roaming **parameters only** | Yes (Wi-Fi params) | `/etc/config/repacd` (MAPConfig); `strings repacd` -> **no** ssh/scp/tftp/uci/authorized_keys/`/etc/` file-push refs | VERIFIED |
| **wsplcd** (both) `/usr/sbin/wsplcd` | Wi-Fi SON / backhaul credential push (Qualcomm whole-home) | Proprietary over backhaul | Backhaul assoc | Backhaul/credential sync for mesh formation | Yes (Wi-Fi only) | process list (`-c /tmp/wsplcd-lan.conf`); `/etc/config/wsplcd` | STRONGLY INDICATED |
| **hyd** (both) `/usr/sbin/hyd` | Hybrid/Hy-Fi data-path (backhaul bridging) | localhost ctrl :7777/:8888 | n/a (local) | Data-path/bridging; **no config-provisioning RPC to RE** | Data plane only | netstat (localhost only); role is forwarding | STRONGLY INDICATED |
| **ubus `satellite`** (master) | Topology read | ubus (local) | local root | `list_satellites` **only** | Read-only | `ubus -v list` | VERIFIED |
| **ubus `uci` / `service`** (master) | Config/service mgmt | ubus (local) | session login | Full on the **master**; **not** proxied to satellites | Master only | `ubus -v list` | VERIFIED |
| **d2d** (satellite) `/usr/bin/d2d` | Cloud device-to-device / genie-remote agent | HTTPS to `*.netgear.com`, `*.ngxcld.com` | cloud tokens | Cloud claim/registration/presence | No LAN admin path | `strings d2d` (cloud URLs, `genie_soap_port`) | VERIFIED |
| **init_sshenable / telnet / sshd** (both) | Legacy NETGEAR debug remote-shell | init.d scripts, nvram-flag gated | nvram/debug flag | Enables telnet/remote shell **if a flag is set** | On-device only; **not reachable from the SOAP API** | `/etc/init.d/init_sshenable`, `S50telnet`; prior note: ubus `telnet_enable` unimplemented, `set_telnet_enable` orphaned | STRONGLY INDICATED |

---

## 2. Satellite SOAP method surface (complete)

`soap_agent` Response tokens (identical set in 7.2.7.15 and 7.2.8.8, **50 methods, zero delta**):

- **Auth/password:** Authenticate, UpdateAdminPassword, UpdateAdminPasswordHashed
- **Query:** GetInfo, GetAttachDevice, GetCurrentSatellitesInfo, GetCurrentSatellitesWIFIinfo, GetConfigurationTimestamp, GetSupportFeatureListXML, Get6GWirelessMode, TputMeasureStart/Stop/GetResult
- **Wi-Fi / mesh / device:** Set5G/6G/WLAN SSID-key-enable-WMM-broadcast-preamble, Set{Backhaul,5GBackhaul}Passphrase, SetAdvancedWirelessSettings, SetAllGuestAccessEnabled, SetBlockDeviceByMAC/Enable/StateByDefault, DeleteBlockDeviceAll, SetDaisyChainEnable, SetRoamingAggressive, SetDeviceInfoByMAC, SetNetgearDeviceName/SetOrbiDevName, SetNTP, SetTimeZone(ByIndex), SetEnable, ApplySettings, ConfigurationStarted/Finished, SetConfigurationTimestamp
- **Lifecycle:** Reboot, ResetToFactoryDefault, FactoryAndReboot, UpdateNewFirmware2, CheckAndDownloadNewFirmwareByFolder

**Absent (verified negative):** any `ssh`, `dropbear`, `telnet`, `authorized_keys`, `pubkey`, `RunCmd`/`command`/`exec`/`shell`/`script`, arbitrary **file-write**, or **uci-write** method. The only `popen` in the binary is an internal "restart configd on hang" path, not an exposed operation. `dbg_*` strings are internal logging.

---

## 3. Why SSH can't be turned on through a supported path

1. **No operation exists.** The authenticated SOAP plane is a closed, typed API for Wi-Fi/mesh/device settings + reboot/factory-reset + firmware update. None of its 50 methods touches SSH, the Dropbear service, a key file, a service enable, a file write, or command execution. (VERIFIED)
2. **Dropbear is present but config-disabled on the satellite.** `/etc/config/dropbear` -> `option enable '0'` (with `RootPasswordAuth 'on'`, `Port 22`). The `S19dropbear` init runs at boot but the instance stays down, and no SOAP/ubus-proxied operation can flip `enable` to `1`. (VERIFIED)
3. **The sync daemons move Wi-Fi state, not files.** `repacd`/`wsplcd` push SSID/keys/backhaul/VLAN parameters over the Multi-AP/SON protocol; `strings repacd` shows no `scp`/`tftp`/`/etc/`/`authorized_keys`/`uci` file-transfer primitive. `hyd` is data-path only. (VERIFIED / STRONGLY INDICATED)
4. **No new door in 7.2.8.8.** The SOAP surface delta is empty, so upgrading changes nothing here. (VERIFIED)
5. **Legacy `init_sshenable`/telnet exist on the satellite but are not reachable from the management plane** - gated by an nvram/debug flag with no SOAP method and (per prior runtime work) an unimplemented ubus `telnet_enable`. Reaching it is not a *documented* owner path. (STRONGLY INDICATED)

---

## 4. Conclusion - most promising documented mechanism

**None exists.** There is no supported, authenticated RBRE960->RBSE960 operation that
installs an SSH key, enables Dropbear, manages a service, writes a file, or runs a
command on the satellite. The vendor channel (SOAP `soap_agent`, authenticated by the
admin password hash) is deliberately scoped to Wi-Fi/mesh/device configuration,
reboot/factory-reset, and firmware update, and that scope is unchanged in 7.2.8.8.

The **only** supported operations that could place owner-controlled code on a satellite
are the firmware-flash methods (`UpdateNewFirmware2` / `CheckAndDownloadNewFirmwareByFolder`)
- i.e. installing a modified image. The kernel/rootfs image is NOT cryptographically
signed; its gates are the CHK board-ID match and recomputable checksums/hashes, not a
vendor signature (see `23_rbse960_firmware_signing_feasibility.md`). The real blockers are
therefore the unresolved boot-enforcement question (Qualcomm secure boot, fuse state
UNKNOWN) and the brick risk of flashing; this route is explicitly out of scope for this
phase (no flashing). `ResetToFactoryDefault`/`FactoryAndReboot` are destructive and useless
for the goal.

**Implication for the larger project:** owner root SSH on the satellite is not reachable
through any supported remote administrative path. It reduces to the custom/modified-firmware
question (Approach A/C), which is itself gated by image signing - not to a management-plane
operation. This is a firm "establish that none exists" result, not an incomplete one.

---

## 5. Suggested read-only confirmations (live master, non-changing)

- `uci show dropbear` **on a satellite** once reachable (confirm `enable 0` at runtime).
- Confirm satellite SOAP listener: from master, `curl -sk https://<satellite-1-ip>/... ` GET of a
  benign method (e.g. `GetInfo`) to verify the agent is live and auth-gated (read-only).
- `strings /usr/sbin/cgi-bin/soap_agent` on the *live* satellite vs. the extracted image
  (verify the running build matches `rbse_7215`).
