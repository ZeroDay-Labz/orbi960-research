# Report 31 — Master↔Satellite SOAP Trust Channel: Complete Map

Date: 2026-11-04
Scope: static analysis of the `soap_agent` CGI on RBSE960 satellite, its `configd` back-end,
       the lighttpd routing in front of it, and the master-side SOAP binaries.
Binaries examined (sha256):
- `rbse_7215/.../usr/sbin/cgi-bin/soap_agent` — `a3ee8ac93b41ac52de17e53051b9569f3b063deca0cd585de6337cb1dcf12502`
- `rbse_7288/.../usr/sbin/cgi-bin/soap_agent` — `19feab2445e047084aefac0ac80910fd5732d21c9f2d2538b4b612e5eb85d2ad`
- `rbre_7215/.../usr/sbin/soapc` — `531b932b0488a4d60d38cd575d0d1b44f7f4285f40eafe5593a3c8d975f74a7b`
- `rbre_7288/.../usr/sbin/soapc` — `6c4e4004fcfb21bd73a5a4c0382d54a70b83c28f1c20fd2cefa5fa848ee26b2d`
- `rbse_7215/.../usr/sbin/configd` — strings-analyzed (binary-level examined)

All findings are **VERIFIED** (strings/lighttpd config) except where flagged.

## 1. HTTP transport

**VERIFIED.** On the satellite, the SOAP endpoint is mounted via lighttpd:

```
# etc/lighttpd/conf.d/30-rewrite.conf
"^.*/soap/server_sa([^?]*)$" => "/soapapi.cgi?$1",

# etc/lighttpd/conf.d/30-cgi.conf
cgi.assign = ( "soapapi.cgi" => "/usr/sbin/cgi-bin/soap_agent", ... )
```

`soapapi.cgi` is a single-line comment file (`//skip 404 not found, for soap request`) —
a stub whose existence forces lighttpd to route via its CGI assignment. All requests to
`https://<sat_ip>/soap/server_sa` execute `/usr/sbin/cgi-bin/soap_agent`.

**No `auth.require` / HTTP-basic / cookie guard** is applied to the `/soap/` prefix in
lighttpd — authentication is entirely enforced inside `soap_agent` via the SOAP
envelope's own session-ID mechanism.

## 2. Complete method inventory (47 M1 methods on sat)

### Pre-auth reachable (1)
- `M1:Authenticate` — the only method that dispatches without a valid session.

### Read-only (post-auth) (8)
- `GetInfo`, `GetAttachDevice`, `GetSupportFeatureListXML`,
- `GetConfigurationTimestamp`, `GetCurrentSatellitesInfo`, `GetCurrentSatellitesWIFIinfo`,
- `Get6GWirelessMode`, `TputMeasureGetResult`.

### State-changing (post-auth) (38)
Session bracket: `ConfigurationStarted`, `ConfigurationFinished`, `SetConfigurationTimestamp`.
Password: `UpdateAdminPassword`, `UpdateAdminPasswordHashed`.
Reboot/reset: `Reboot`, `ResetToFactoryDefault`.
Firmware: `CheckAndDownloadNewFirmwareByFolder`, `UpdateNewFirmware2`.
Wireless: `SetSSIDBroadcast`, `Set5GSSIDBroadcast`, `SetEnable`, `Set5GEnable`,
`SetWLANNoSecurity`, `SetWLANWPAPSKByPassphrase`, `Set6GWLANWPAPSKByPassphrase`,
`Set5GWMMEnable`, `SetWMMEnable`, `SetAdvancedWirelessSettings`,
`SetAllGuestAccessEnabled`, `SetBackhaulPassphrase`, `Set5GBackhaulPassphrase`,
`SetDaisyChainEnable`, `SetRoamingAggressive`, `Set6GSepFronthaulEnable`,
`Set5G2FronhaulEnable`.
Block/allow: `SetBlockDeviceEnable`, `SetBlockDeviceStateByDefault`,
`SetBlockDeviceByMAC`, `DeleteBlockDeviceAll`, `SetDeviceInfoByMAC`.
Identity/time: `SetNetgearDeviceName`, `SetOrbiDevName`, `SetTimeZone`,
`SetTimeZoneByIndex`, `SetNTP`.
Diagnostic: `TputMeasureStart`, `TputMeasureStop`.

## 3. Authentication mechanism (sat)

**VERIFIED.** The HTTP layer is unguarded. `soap_agent` parses the SOAP envelope,
pulls `NewUsername`/`NewPassword` (M1:Authenticate) or `SessionID` (all others), and
**forwards the auth decision to `configd` via Sun RPC on the local Unix socket
`/tmp/ntgr_orbi_rpc`**:

- `soap_agent` is the Sun RPC *client*: calls `authenticate_satellite_1()` (strings:
  `authenticate_satellite_1() call failed`).
- `configd` is the Sun RPC *server*: exports `authenticate_satellite_1_svc`,
  `update_admin_password_1_svc`.
- XDR structs: `xdr_auth_info`, `xdr_admin_password`, `xdr_FactoryAndReboot`,
  `xdr_AttachDevice`, `xdr_UpdateFirmware2ResponseCode`, etc.

`configd` reads the expected credential from two NVRAM/DAL keys: `http.password`
(plaintext) and `http.passwordHash` (PBKDF2_HMAC_SHA1 / SHA256 — both primitives
are linked into `configd`).

### Default-admin-password derivation — **PSIRT-worthy finding**
Both `configd` and `soap_agent` embed the format string:

```
NETGEAR_Orbi_%02X_%02X_%02X_%02X_%02X_%02X_password
```

A factory-fresh or mid-pairing satellite whose NVRAM `http.password`/`http.passwordHash`
has not been synced from the master accepts this MAC-derived default. For an attacker
on-LAN, the sat's LAN MAC is discoverable via ARP, so the default admin credential is
fully predictable from publicly observable data. **CONFIDENCE: STRONGLY INDICATED
(static)** — needs a runtime check against an actual un-paired sat to confirm it is
the pre-pairing fallback and not dead code.

The master does **not** contain this template. The sat generates its own default;
during SON pairing the master overwrites it with the master's own admin-password hash
(delivered via the mesh plane, not through `soap_agent` — the master is not an
observed caller of `M1:UpdateAdminPasswordHashed`).

### Session model

On successful `M1:Authenticate`, `soap_agent`:
1. writes the session token to `/tmp/sessionId.txt` (single-file → **exactly one
   active session globally**),
2. writes the response envelope to `/tmp/authResponse.xml` (same file every time),
3. returns the sessionId in the response body (`m:AuthenticateResponse`).

Subsequent calls include the sessionId in the envelope. If missing/invalid, 7288
returns the string literal `"Session I'd is invalid so returning the Authentication
response"` (7215 silently returns a generic "Authentication failed" without this
diagnostic).

## 4. authResponse.xml structure

Written to `/tmp/authResponse.xml` as plain SOAP response. Contents are SOAP-ENV
Body with `m:AuthenticateResponse` and a sessionId string. Not keyed/signed — the
session token is a plain string that `soap_agent` later string-compares against
`/tmp/sessionId.txt` on inbound requests. No per-call challenge, no HMAC.

## 5. Master-side caller

`soapc` on the master is primarily the master's **own** SOAP *server* (its templated
strings `<%Authenticate();%>`, `<%getURN();%>` serve its own web UI). It contains
the method templates `<M1:Authenticate xmlns:M1="...service:ParentalControl:1">`,
`<M1:GetCurrentSatellitesInfo xmlns:M1="...service:DeviceInfo:1">` etc., but those
are for CLIENTS authenticating TO the master, not for the master calling sats.

Who actually calls satellite `M1:*` methods from the master? Not fully isolated in
this pass. `heartbeat` references `/tmp/soap/soapc_running` (a presence file) but
does not itself originate `M1:Authenticate` traffic. The mesh/SON binaries
(`hyd`, `wsplcd`) sync admin password out-of-band. **HYPOTHESIS:** master
originates SOAP to sat via a shell/Lua script (likely in `/usr/sbin/*.sh` or
`/usr/lib/lua/`) using curl against `https://<sat_ip>/soap/server_sa`. Needs
targeted follow-up to isolate.

## 6. Code-execution / shell-primitive surface

**None found at static-review depth.**

- Every state-changing method writes through `configd`'s DAL (Data Abstraction Layer)
  tables: `FactoryAndReboot`, `FW_UPDATE_DAL_TABLE`, `WLS_CONFIG_DAL_TABLE`,
  `adv_wls_dal_param`, `backhaul_passphrase_dal_param`, `guest_access_dal_param`,
  `netgear_device_name_dal_param`, `ntp_info_dal_param`, `ntp_timezone_dal_param`,
  `wlan_no_security_dal_param`. These are schema-validated writes, not file writes or
  shell invocations.
- `soap_agent` contains exactly one `popen` call site (not yet decompiled);
  surrounding strings point to firmware-upload file management (unlink of
  `/tmp/fileinfo1.txt`, `/tmp/firmware_log.txt`). **Not** reachable with
  master-controlled argv at static-review depth.
- `M1:TputMeasure{Start,Stop,GetResult}` flow through DAL tables; the actual
  measurement runs in the mesh plane (hyd), not via master-controlled argv.
- `M1:SetTimeZone[ByIndex]` writes `ntp_timezone_dal_param`; configd regenerates
  `/etc/TZ` from a validated enum.
- `M1:UpdateNewFirmware2` is the only method writing executable content to flash —
  this is **the firmware-flash boundary the project ROE forbids**.

## 7. 7215 vs 7288 diff

Binary differs in 61,145 bytes (address shifts + new code). String-level diff shows
exactly three new strings in 7288:

1. `RBS750` — new model identifier (RBS750 satellite family support).
2. `RBS750QV` — new model identifier variant.
3. `Session I'd is invalid so returning the Authentication response` — new debug/error
   log string on invalid-session path.

**No new methods, no methods removed, no auth-logic change.** The SOAP attack surface
is identical between the two firmware versions for RBRE960/RBSE960 pairings.

## 8. Owner-angle summary

- Owner knows the master's admin password; after SON pairing the sat's admin password
  equals the master's → owner can authenticate to `https://<sat_ip>/soap/server_sa`
  using known credentials via `M1:Authenticate`.
- Factory-fresh or un-paired sat may accept `NETGEAR_Orbi_<MAC>_password`
  (PSIRT-worthy pre-pairing default credential, if confirmed at runtime).
- Authenticated sessions can read all `Get*` methods and write wireless / block-list /
  NTP / device-name settings — all low-risk, all reversible, all ROE-compatible.
- **No SOAP method exposes a shell / file-write / exec primitive to the authenticated
  master**. The firmware-upload method (`UpdateNewFirmware2`) is the only one with
  flash-write capability and is ROE-forbidden.

**Bottom line:** the master→satellite SOAP channel is a disciplined management API. It
is not a pathway to a satellite shell. The one PSIRT-worthy finding is the MAC-derived
default admin password pattern — document it, confirm at runtime against an un-paired
sat only with explicit owner approval, then include in the disclosure draft.

## 9. Follow-up items for later passes

- Decompile the single `popen` site in `soap_agent` (filename-handling or
  `cp`/`mv` during firmware upload?) — confirm argv is not master-controlled.
- Isolate the master binary/script that originates `M1:*` requests to a sat
  (likely hyd/wsplcd/sh). Confirm whether the sat admin password is sent plaintext
  across the backhaul.
- Runtime: against an un-paired factory-reset sat (OWNER APPROVAL REQUIRED and the
  project ROE explicitly says "do not factory reset"), confirm
  `NETGEAR_Orbi_<MAC>_password` is the accepted default.
