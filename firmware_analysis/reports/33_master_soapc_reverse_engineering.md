# Report 33 — Master `soapc` Deep Reverse-Engineering

Date: 2026-11-04
Scope: static reverse-engineering of the master's `/usr/sbin/soapc` binary
and its caller integration points. Produced under the scope-amendment
instructions received mid-investigation: strict three-level evidence
classification, credential-provenance focus, and an evidence-backed
yes/no answer on owner SSH-provisioning capability.

Binaries examined:
- **Primary**: `firmware_analysis/extracted/rbre_7215/rootfs/usr/sbin/soapc`
  sha256 `531b932b0488a4d60d38cd575d0d1b44f7f4285f40eafe5593a3c8d975f74a7b`
  (MD5 `f7184993ca7e5d52a887b32c479ad1bf` — byte-identical to the
  running master's binary per the user-supplied snapshot MD5.)
- **Delta pair**: `firmware_analysis/extracted/rbre_7288/rootfs/usr/sbin/soapc`
  sha256 `6c4e4004fcfb21bd73a5a4c0382d54a70b83c28f1c20fd2cefa5fa848ee26b2d`.

Static analysis tooling: REA MCP (Ghidra 12.1.3 backend), `readelf`,
`strings`, cross-grep of the 7215 rootfs.

ROE (strict): offline only. No invocation of `soapc` against any live
device during this investigation.

## Evidence classification (per scope amendment)

- **Confirmed** — supported by a specific instruction, string offset,
  cross-reference, or symbol. Verifiable from this report.
- **Strongly supported** — multiple indirect indicators converge on a
  conclusion but the decisive code path was not read end-to-end.
- **Unverified assumption** — plausible but not proven; explicitly
  flagged so future work can either confirm or reject it.
- **Ruled out** — investigated and contradicted by the evidence.

String literals alone (e.g. `soapc_pass` appearing in a `.rodata`
section) are **Unverified** until the code that reads and uses them
has been located. This is called out explicitly below where relevant.

---

## 1. Binary identity

**Confirmed.**

| aspect | value |
|---|---|
| format | ELF 32-bit LSB, ARM EABI5 v1, SYSV, **dynamically linked**, **stripped** |
| interpreter | `/lib/ld-musl-arm.so.1` |
| file size | 252,772 bytes |
| image base (Ghidra) | 0x10000 |
| `.text` | 0x14810..0x2be28 (95,768 bytes) |
| `.rodata` | 0x1be34..0x22b6a (27,958 bytes) |
| `.data` | 0x33000..0x4d680 (108,160 bytes) |
| procedures analysed by Ghidra | 508 |
| string objects observed by Ghidra | 1,524 |

NEEDED shared libraries: `libssl.so.1.1`, `libcrypto.so.1.1`,
`libacos_nvram.so`, `libubox.so`, `libuci.so`, `libacos_shared.so`,
`libacos_shared_attach.so`, `libacos_dal.so`, `libd2lib.so`,
`libdillib.so`, `libd2dynlog.so`, `libgcc_s.so.1`, `libc.so`.

**NOT NEEDED**: `librpc.so`. **Confirmed** — the binary contains none of
the Sun RPC client/server/XDR imports (`clnt_create`, `clnt_call`,
`svc_run`, `svc_register`, `xdr_string`, `xdr_bytes`, `xdr_opaque`,
`xdr_authunix_parms`, `pmap_unset`, `svcunix_create`). Keep this for
Track C.

**NOT NEEDED**: `libcurl`. **Confirmed.** No `curl_easy_*`, no
`curl_global_*`. The HTTP/HTTPS stack is hand-rolled on top of the
BSD sockets API and raw OpenSSL 1.1 calls.

---

## 2. Role: SOAP CLIENT (not a server)

**Confirmed.** Report 31 raised the possibility that `soapc` is
predominantly a server. That hypothesis is **ruled out** by direct
code evidence here. `soapc` is a one-shot SOAP/HTTPS **client** that
the master runs to push configuration to each paired satellite.

Decisive evidence:
- `TLS_client_method()` is imported and used (not `TLS_server_method`
  or `SSLv23_server_method`).
- `socket()` + `connect()` + `send()` + `recv()` sequence; no
  `bind()`/`listen()`/`accept()`.
- `getaddrinfo()` + `freeaddrinfo()` used on the satellite's IP from
  NVRAM, confirming outbound resolution.
- No LAN listener is opened.
- Request path (fixed string): `POST /soap/server_sa/ HTTP/1.0`.
- User-Agent (fixed string): `User-Agent: Foxconn SOAPC Tool 1.0`.

The templated `<%Authenticate();%>` / `<%getURN();%>` strings
previously taken by report 31 as evidence of serving the master's own
web UI are in fact **request-body templates**: `soapc` reads SOAP
request-body templates from embedded `.data` and expands `<%…%>`
directives (evaluated by local template handlers) before sending.
See §5 for the auth template body dump.

---

## 3. Argv and lifecycle

**Confirmed.**

Argv contract (from `main` at 0x14810):

```
Usage: soapc <eventIndex>
<eventIndex>=1000,1001.... , please reference system_util.h
```

- Single integer argv. Valid range `1000..9998` (`iVar4 - 1000U < 8999`
  comparison in `main`).
- If `param_1 != 2`, usage message printed to stderr; otherwise:
  1. `fopen("/tmp/soapc_log","a+")` — logs `soapc_running_START==>`.
  2. `signal(13, SIG_IGN)` — ignore SIGPIPE.
  3. `daemon(1, 1)` — fork into background, keep stdout/stderr, keep cwd.
  4. `dil_init()` — initializes the ACOS device-info library (DIL).
  5. Read NVRAM `soapc_sat_access_count` (fallback: `soapc_sat_backhual_count`)
     into global `sat_total_count`.
  6. `FUN_0002b6f4()` builds the iteration order table `aiStack_624[]`.
  7. Per-satellite loop: read `soapc_sat_<idx>_ip` and
     `soapc_sat_<idx>_https_port`, then run the per-sat per-event handler.
  8. On completion: `unlink("/var/run/soapd.pid")`,
     `acosNvramConfig_save()`, optionally
     `doSystem("acos_service restart_qca_wlan")` for certain flagged
     events (see §6), `unlink("/tmp/soap/soapc_running")`,
     `dil_uninit()`, return.
- Up to 3 retry rounds on satellite sync failure (`local_680 < 3`); on
  the 4th attempt the event is rewritten to `0x3eb`
  (`GetConfigurationTimestamp`) to force a resync.

---

## 4. Request/response plumbing (TLS posture)

**Confirmed.** The real send function is `FUN_0002332c` at address 0x2332c.
Recovered name (from log strings): `soapc_sendRequest`.

Call chain from `main`:
```
main
 └─ FUN_00027a90 "soap_main"       (per-sat, per-top-level-event)
     └─ FUN_00025fb8 "soap_action" (per-method-iteration)
         ├─ FUN_00025ebc  "build_xml_filename"
         ├─ FUN_00029674  "expand_soap_template"  (template engine)
         └─ FUN_00025c60  "soap_startConnection"
             └─ FUN_0002332c  "soapc_sendRequest"  ← THE wire function
```

HTTPS is selected when NVRAM key `soapc_sat_<idx>_https_port` is
non-empty; otherwise a plaintext `send()`/`recv()` TCP path is used.

Request assembly (literal format strings in `.rodata`):
```
POST /soap/server_sa/ HTTP/1.0
SOAPAction: urn:NETGEAR-ROUTER:service:<SERVICE>:1#<METHOD>
Content-Type: text/xml; charset="UTF-8"
HOST: <sat_ip_from_nvram>
Connection: Keep-Alive
Cache-Control: no-cache
Pragma: no-cache
User-Agent: Foxconn SOAPC Tool 1.0
Content-Length: <len>

<body>
```

Bounds:
- Request body size cap: `param_6 < 0x1e00` (**7,680 bytes**) — larger
  bodies are rejected before the socket is opened.
- XML file read size cap at the stage preceding send: `fread(…, 0xfff, …)`
  i.e. **4,095 bytes** actually read into the buffer `soap_startConnection`
  hands to the wire function (see 0x25c60). So the effective body cap
  for current-firmware templates is 4 KB.
- Response read: one of **4 KB** (default), **40 KB** (event `0xec` —
  TputMeasureGetResult), or **64 KB** (event `0xd1` — GetAttachDeviceGroup*).
- Response-receive timeout: 20s for most events, 5s for a subset
  (`FUN_00023094` gatekeeper).

### 4.1 TLS posture — PSIRT-worthy

**Confirmed.** The master does NOT verify the satellite's TLS
certificate.

Decompiled evidence (soapc_sendRequest at 0x2332c, excerpt):
```c
OPENSSL_init_crypto(0xc, 0, 0);                 // ADD_ALL_CIPHERS|ADD_ALL_DIGESTS
OPENSSL_init_ssl(0x200002, 0, 0);               // LOAD_SSL_STRINGS|LOAD_CRYPTO_STRINGS
OPENSSL_init_ssl(0, 0, 0);
meth      = (SSL_METHOD *)TLS_client_method();  // any TLS version
local_13d8 = SSL_CTX_new(meth);
SSL_CTX_set_options(local_13d8, 0);             // options = 0  -- no SSL_OP_* flags
local_13e4 = SSL_new(local_13d8);
// ... TCP connect, then:
SSL_set_fd(local_13e4, local_13f8);
iVar7 = SSL_connect(local_13e4);                // No pre-connect verify setup
// ... SSL_write / SSL_read ...
SSL_free(local_13e4);
SSL_CTX_free(local_13d8);
```

What is **absent** from the entire `.dynsym` of soapc (confirmed by
`readelf -s`):
- `SSL_CTX_set_verify`
- `SSL_CTX_load_verify_locations`
- `SSL_CTX_set_default_verify_paths`
- `SSL_CTX_set_cert_store`
- `SSL_get_verify_result`
- `SSL_get_peer_certificate`
- `X509_V_OK`
- `X509_STORE_*`

OpenSSL's documented default when `SSL_CTX_set_verify()` is not called
is `SSL_VERIFY_NONE` — the handshake succeeds regardless of the peer's
certificate. The master therefore accepts **any** TLS certificate the
satellite (or an on-path attacker between master and satellite)
presents, including a self-signed certificate for a different hostname.

Implications:
- An attacker who can get between the master and a satellite on the
  mesh backhaul or wired fronthaul can MITM the SOAP channel, read all
  management traffic (including the master's auth credential on every
  Authenticate), and inject arbitrary SOAP requests to the satellite.
- Because the credential sent is deterministic (see §5), compromise
  of a single master↔sat session is sufficient to establish the sat
  session the attacker needs.

Severity: **worth including in the PSIRT draft.**

---

## 5. Authentication-credential provenance — the priority deliverable

**Confirmed via decompilation.** The precise provenance of the master's
authentication credential to its satellites was isolated end-to-end.
`soapc_pass` is NOT the key `soapc` uses. The actual answer:

### 5.1 The on-wire authentication request body

Literal template string embedded in `soapc` at `.data` offset `0x5d433`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header>
        <SessionID><%getNewSessionID();%></SessionID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
        <M1:Authenticate xmlns:M1="<%getURN();%>:service:ParentalControl:1">
                <NewUsername>orbi</NewUsername>
                <NewPassword><%getAuthPassword();%></NewPassword>
        </M1:Authenticate>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

- Username is the **hardcoded literal** `orbi`.
- Password is the template directive `<%getAuthPassword();%>`, resolved
  at send-time by the handler described below.
- Service URN: `urn:NETGEAR-ROUTER:service:ParentalControl:1` — the
  Authenticate method lives in the ParentalControl namespace (identical
  to report 31's observation of what the sat exposes).

### 5.2 `getAuthPassword` handler — the derivation

**Confirmed via decompilation of `FUN_0001f228` at 0x1f228** (handler
dispatched for `<%getAuthPassword();%>`; identified by xref from the
directive-name string `getAuthPassword` at 0x2c7f9).

```c
void getAuthPassword(... , char *output_buf)
{
    char buf_composed[260];
    char buf_hash[36];

    snprintf(buf_composed, 0x101, "%s%s%s%s%s",
             "NETGEAR_Orbi_",
             g_soapc_mac1,       // "XX_XX_XX" – first 3 bytes of sat MAC
             "_",
             g_soapc_mac2,       // "XX_XX_XX" – last 3 bytes of sat MAC
             "_password");

    md5_hex = FUN_00029ce4(buf_composed);  // MD5 → 32-char lowercase hex
    if (md5_hex == NULL) {
        fputs("Failed!! Authenticate : MD5 hash failed\r\n", stderr);
    } else {
        strlcpy(buf_hash, md5_hex, 0x22);     // 33-byte copy
        free(md5_hex);
        strlcpy(output_buf, buf_hash, 0x400);
        acosNvramConfig_set("soap_Authenticate_old_password", buf_hash);
        /* debug log omitted */
    }
}
```

The MD5 helper `FUN_00029ce4` was decompiled and **confirmed** as a
classic one-shot MD5 wrapper: `MD5Init` → `MD5Update(…, strlen(buf))`
→ `MD5Final` → `snprintf("%02x…x16")`. 32 lowercase hex characters.

### 5.3 `g_soapc_mac1` / `g_soapc_mac2` — the MAC inputs

**Confirmed.** Function `FUN_0002864c` at 0x2864c (called from
`main`'s per-sat loop before each dispatch) performs:

```c
snprintf(key, 0x20, "soapc_sat_%d_mac", sat_idx);
mac_str = acosNvramConfig_get(key);               // "aa:bb:cc:dd:ee:ff"
sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
       &b0, &b1, &b2, &b3, &b4, &b5);
snprintf(local_3c, 0x20, "%02X_%02X_%02X", b3, b4, b5);  // last three bytes
strlcpy(g_soapc_mac2, local_3c, 0x20);
```

A sibling function (not re-decompiled here but inferred by symmetry
from the composed `NETGEAR_Orbi_<X1>_<X2>_password` layout) writes
`g_soapc_mac1` = `"%02X_%02X_%02X"` of bytes 0..2 of the same NVRAM
MAC. This matches the known format exactly.

So the composed plaintext is:

```
NETGEAR_Orbi_<MAC[0]>_<MAC[1]>_<MAC[2]>_<MAC[3]>_<MAC[4]>_<MAC[5]>_password
```

with each `<MAC[n]>` written as uppercase hex, no colons, `_`-joined.
This is **byte-identical** to the template already identified in
report 31 as the sat's pre-pairing default admin password, confirming
the master uses the sat's pre-pairing default as its authentication
credential to that sat on every `Authenticate` call.

### 5.4 Final credential on the wire

```
<NewUsername>orbi</NewUsername>
<NewPassword>MD5_hex_lowercase(NETGEAR_Orbi_<6-byte-sat-MAC>_password)</NewPassword>
```

32 lowercase hex characters. 128 bits of entropy pre-image, but the
**pre-image is fully determined by the satellite's LAN MAC**, which is
public on-LAN data (ARP, 802.11 management frames, etc.). The
credential has **zero effective entropy** from the attacker's
perspective once the sat MAC is observed.

### 5.5 Where does the credential value come from — stated as the
scope amendment asked

- **What `soapc_pass` actually represents**: string present in
  `check_fw` (master binary), **not** in `soapc`. soapc contains the
  substring `soapc_action`, `soapc_SessionID`, `soapc_sat_*`, and
  dozens of others — but **not** `soapc_pass`. Any role `soapc_pass`
  plays is in `check_fw`, not in `soapc`'s authentication path.
  **Classification: Unverified assumption** that `soapc_pass` is a
  populated NVRAM key; `soapc` does not read it.

- **Where the value sent as `<NewPassword>` originates**:
  derived in-process at every Authenticate call by hashing a template
  of the target satellite's LAN MAC. Not read from NVRAM as a stored
  secret.
  **Classification: Confirmed.** NVRAM read: `soapc_sat_<idx>_mac`
  (only). NVRAM write: `soap_Authenticate_old_password` (receives the
  MD5 after it is computed — presumably for the sat password-rotation
  path, which was not the target of this focus).

- **Transformation before the wire**: MD5 → 32-char lowercase
  hexadecimal. No salt, no iteration count, no HMAC, no base64.
  **Classification: Confirmed.** (`MD5Init`/`MD5Update`/`MD5Final`
  imports present; MD5 helper decompiled.)

- **Function that reads it**: `soapc`'s template handler
  `FUN_0001f228` at address 0x1f228. Dispatched when the template
  engine encounters the `<%getAuthPassword();%>` directive in the
  Authenticate body.
  **Classification: Confirmed.**

- **How the satellite validates the request**: beyond the scope of
  this report (handled by report 31 for the sat side). Report 31
  observed that sat `configd` reads `http.password` (plaintext) and
  `http.passwordHash` (PBKDF2_HMAC_SHA1/SHA256) from NVRAM. On a
  factory-fresh or un-paired sat whose NVRAM has not been overwritten
  by the master, the sat would accept the MAC-derived default per that
  report's finding; the MD5-of-default used here matches that pattern
  **iff** the sat's accept-path hashes the stored default through MD5
  too (or stores a pre-computed MD5). Confirming which of
  `http.password` / `http.passwordHash` matches the master's MD5 output
  on a paired sat requires reading sat `configd::authenticate_satellite_1_svc`
  — flagged as follow-up in §9 but **not** done in this report, because
  the credential-provenance scope is on the sending side.
  **Classification of the end-to-end match**: Strongly supported on the
  sat side via report 31; not independently reverified here.

- **Value not printed**. The master's `getAuthPassword` logs the
  computed MD5 to `/tmp/soapc_log` and `/dev/console` (when
  `SOAPC_DBGP2` NVRAM flag is set). This is captured as a static
  finding about the binary's behaviour; no live computation of the
  value against our devices was performed in this investigation.

### 5.6 Other password-related template directives (surface map)

For completeness, the directives `soapc` can expand in its SOAP
request bodies and the NVRAM keys they imply (strings-only inventory —
each is **Unverified** as a populated NVRAM value unless cross-checked
on a live master):

| directive | purpose (static reading) | NVRAM key(s) implied | classification |
|---|---|---|---|
| `<%getAuthPassword();%>` | current-session Authenticate password | derived from `soapc_sat_<n>_mac` | **Confirmed** |
| `<%getNewAuthPassword();%>` | new password in UpdateAdminPassword flow | handler not decompiled — likely reads another nvram key | **Strongly supported** |
| `<%getRouterPassword();%>` | wraps master's web password for a method | handler not decompiled | **Strongly supported** |
| `<%updateAdminPassword();%>` | push master's password change to sat (plaintext form) | handler not decompiled; both `soap_Authenticate_password` and `soap_Authenticate_old_password` strings are present in `.rodata` as potential sources | **Strongly supported** |
| `<%updateAdminPasswordHashed();%>` | same, hashed form sent when sat `PasswordHashSupport=1` | handler not decompiled; the sat's reported `supportPasswordHash` gate at 0x7b in `soap_action` was observed | **Confirmed gate**, handler **Strongly supported** |
| `<%getSessionID();%>` | retrieve `soapc_SessionID` NVRAM for subsequent calls | NVRAM `soapc_SessionID` (literal observed in soapc) | **Confirmed** |
| `<%getNewSessionID();%>` | sessionId in request header after initial auth | same NVRAM key | **Confirmed** |

---

## 6. Event / method tables (full static map)

**Confirmed.** All five relevant static tables were parsed directly
from the binary. JSON artefacts are in
`firmware_analysis/research_output/soapc/`.

### 6.1 `all_events` — the per-method dispatch table

- Address: 0x36ccc (.data). Size: 1408 bytes.
- Entry size: **16 bytes**. 88 entries.
- Layout (observed from pseudocode use at 0x25fb8 and 0x2332c):
  - `u32 service_idx` — index into service-type table
  - `u32 event_id` — numeric method id (lookup in `s_Event` for name)
  - `u32 flag_or_tag` — iteration flag (ACL/group iteration gate)
  - `u32 next_offset`
- Terminator: `event_id == 0xFFFFFFFF` (first entry whose event_id is -1).

### 6.2 `s_Event` — numeric event id → method name

- Address: 0x403c8 (.data). Size: 1912 bytes.
- Entry size: 8 bytes. 239 entries.
- Layout: `{u32 event_id; char *name_ptr→.rodata}`.
- Scanned linearly by `FUN_0002a1c0` ("get_event_name"); max scan
  bound 0xfc (252).
- Dump available at `research_output/soapc/method_table.json` — first
  sample: {0:"GetInfo"}, {17:"GetAttachDevice"}, {18:"ConfigurationStarted"},
  {19:"ConfigurationFinished"}, {74:"…"}, …

### 6.3 `events_array` — top-level event index (argv) → post-send action

- Address: 0x36a68 (.data). Size: 612 bytes.
- Entry size: 12 bytes. 51 entries.
- Layout: `{u32 pre; u32 event_id; u32 flag}`.
- Event ids span `1000..1052`. Terminator: `event_id == 9999`.
- The `flag` column controls whether `main()` runs
  `doSystem("acos_service restart_qca_wlan")` after dispatch. Of the
  51 argv events: ~half set the restart flag.
- Dump in `method_table.json`.

### 6.4 `HTTP_ERROR_CODE` — response status detection

- Address: 0x3f48c. 24 entries × 8 bytes.
- Layout: `{u32 code; char *needle→"<n> <phrase>"}`.
- Checks response for literal substrings `"400 Bad Request"`, …,
  `"505 HTTP Version Not Supported"`. On any match with non-zero code,
  the request is treated as an HTTP error and logged
  `SOAP response: HTTP/1.0 <code> Error!!`.

### 6.5 `service_type_database` — service URN mapping

- Address: 0x3f315. 360 bytes. Alignment is odd (0x3f315), so a
  straightforward 8-byte-stride parse at that offset does not cleanly
  decode. Likely a `{u32, char*}` table starting at a close alignment
  boundary. Referenced by `FUN_0002a234` (service-name lookup) whose
  decompiler output was degenerate (empty body) — the small helper
  likely compiled to a tiny tail-call Ghidra could not model.
- **Classification: Strongly supported** that this is a
  service-name database; **Unverified** at byte-exact layout.

### 6.6 Service namespaces reachable from soapc

Static string sweep of all `M1:` XML-fragment literals in `soapc`
(all forms of `<M1:<Method> xmlns:M1="urn:NETGEAR-ROUTER:service:<SERVICE>:1">`
observed) returned exactly these service namespaces:
- `ParentalControl:1` — only `Authenticate` (confirms report 31)
- `DeviceInfo:1` — `GetInfo`, `GetAttachDevice`, `GetAttachDevice2`,
  `GetCurrentSatellitesInfo`, `GetSupportFeatureListXML`,
  `GetSysUpTime`, `SetDeviceInfoByMAC`
- `DeviceConfig:1` — the bulk of state-changing methods (~35)
- `WLANConfiguration:1` — wireless config methods
- `VoiceControl:1` — voice/AVS methods
- `AVSAnalytic:1` — AVS analytics

Report 31's distinction between ParentalControl (auth namespace) and
DeviceInfo/DeviceConfig (management namespace) is therefore
**Confirmed**: the master only ever uses `Authenticate` in the
ParentalControl namespace, and everything else (read or state-change)
goes through `DeviceInfo` or `DeviceConfig` (or sub-namespaces for
wireless / voice). The sat's observed 47 M1 methods (report 31) are a
proper superset of the methods the master uses — report 31's method
inventory maps the sat's **accept surface**; the subset the master
actually invokes is captured in soapc's `all_events`/`s_Event`.

---

## 7. Satellite target identification

**Confirmed.** The master does NOT call the sat's
`M1:GetCurrentSatellitesInfo` on itself as a discovery call to find
sats. Instead:

- `soapc` reads NVRAM `soapc_sat_access_count` (fallback
  `soapc_sat_backhual_count`) to learn how many sats to iterate.
- For each `i in 0..count`, it reads NVRAM `soapc_sat_<i>_ip`,
  `soapc_sat_<i>_mac`, `soapc_sat_<i>_https_port` to form the
  per-sat connection parameters.
- An `soapc_sat_index` NVRAM key is used to pin dispatch to a single
  sat for certain events.

These NVRAM keys are populated by **upstream SON / mesh / discovery
components**, not by `soapc` itself. The caller chain surfaces them
before any soapc run (see §8). The master-side "current satellites"
answer that the web UI returns is served by `httpd` reading these
same `soapc_sat_<i>_*` NVRAM keys, not by invoking any SOAP call.

---

## 8. Caller integration — who invokes `soapc <N>`

**Confirmed.** The master's rootfs was cross-grepped. `soapc` is not
invoked by any shell script — it is spawned exclusively through a
single shared-library launcher:

- **`libacos_shared.so::hook_soapc`** — the launcher. Fork+exec of
  `/usr/sbin/soapc <N>`. Guarded by:
- **`libacos_shared.so::check_set_soapc`** — prevents concurrent
  duplicate invocations. Log string: `"same soapc %s is running,
  ignore this call!!"`.
- **`libacos_shared.so::check_soapc_index_running`** — polls `ps` to
  detect existing soapc instances.

Direct callers that link against `hook_soapc`/`check_set_soapc` and
reference soapc-related NVRAM keys:

| caller | role | evidence |
|---|---|---|
| `usr/sbin/heartbeat` | periodic sat-state synchronizer | strings: `hook_soapc`, `check_set_soapc`, `soapc_router_event_trigger`, `soap_agent_routine`, `soapc_sat_router_fire`. Reads `soapc_sat_access_count`, writes `soapc_router_event_trigger` |
| `usr/sbin/httpd` | web-UI triggered dispatch | strings: `call soapc_sat_router_fire`, `check_soapc_index_running`, `hook_soapc`, `killall soapc`. Writes NVRAM `soapc_sat_router_fire=6` / `7` with the comment `"Notify Satellites to sync"` |
| `usr/sbin/acos_wd` | watchdog | `"[acos_wd] soapc number is more then 15, killall first"`, `"[acos_wd] soapc pid %s run over %d seconds"`, `killall soapc`. Not an initiator — a reaper |
| `sbin/acos_service` | lifecycle | `abFifo /tmp/soapc_log /tmp/soapc_log_tmp 1024 &` (log ring-buffer), `killall -9 soapc`, `rm /tmp/soap/soapc_running`. Not an initiator — spawns the `abFifo` process referenced in the paste as "handling `/tmp/soapc_log`" |
| `usr/sbin/check_fw` | FW upgrade coordinator (consumer) | reads NVRAM `soapc_pass`, `soapc_sat_<n>_mac`, `..._ip`, `..._DeviceInfo_GetInfo_*`, `..._new_firmware_available`, `..._need_updatefirmware2`. **Not** an initiator of soapc — reads soapc's sat response NVRAM |
| `usr/sbin/device_detect` | attached-device tracker (consumer) | reads NVRAM `soapc_sat_<n>_mac`, `..._DeviceInfo_GetAttachDevice_NewAttachDevice`, `..._ParentMac`, `..._BHParentMAC`, `..._BHRSSI`. Signalled by soapc at exit (`killall -SIGUSR2 device_detect`) |
| `usr/sbin/scheact` | schedule-action engine | writes NVRAM `soapc_sat_wifi_fire` |

The paste listed `check_fw`, `device_detect` and `scheact` as
"callers" — in fact they are **downstream consumers** of soapc's
output and **upstream NVRAM-flag writers** that `heartbeat` observes
to decide whether to fire a soapc event. The actual spawning is done
by `heartbeat` (periodic) and `httpd` (web-UI triggered). This
correction matters for anyone reading the paste's directive.

### 8.1 `/tmp/soapc_log` and `abFifo`

**Confirmed.** `/tmp/soapc_log` is a FIFO served by `abFifo`:

```
abFifo /tmp/soapc_log /tmp/soapc_log_tmp 1024 &
```

A 1024-entry ring buffer. `soapc` writes all its diagnostics to
`/tmp/soapc_log` via `fopen("a+")`. The paste's description ("An
`abFifo` process handles `/tmp/soapc_log`") is correct and the
command line above is the exact launcher.

---

## 9. Comparison with 7.2.8.8 (CVE context)

**Confirmed. soapc is functionally UNCHANGED between V7.2.7.15 and
V7.2.8.8.**

| aspect | 7215 | 7288 | delta |
|---|---|---|---|
| file size | 252,772 B | 252,772 B | **identical** |
| sha256 | `531b932b…` | `6c4e4004…` | changed |
| NEEDED dynamic libs | 13 | 13 | **identical set** |
| dynamic imports | — | — | **no additions, no removals** |
| dynamic exports | — | — | **no additions, no removals** |
| Ghidra-defined strings | — | — | zero added / removed |
| strings changed | 1 | 1 | only `.comment`: `"GCC: (OpenWrt GCC 5.2.0 ca0b32a+r49254) 5.2.0"` → `"GCC: (OpenWrt GCC 5.2.0 bda89f4+r49254) 5.2.0"` |

The sole observed difference is the embedded GCC build-id string. The
two binaries were produced from identical source (or an
indistinguishable-at-binary-level source) by the same toolchain,
built at a different commit of the OpenWrt feeds. **soapc is RULED
OUT as the CVE-2026-0415 fix location.** This confirms report 32's
narrowing; the CVE-0415 fix surface remains `librpc.so` on the
satellite side.

---

## 10. Owner SSH-provisioning capability of `soapc` — the yes/no deliverable

**RULED OUT.**

Evidence base:

1. Every method `soapc` can invoke on a satellite was enumerated from
   the `s_Event` table (239 entries), the `all_events` table (88
   entries), and every `M1:*` SOAP-body template literal in
   `.rodata` (confirms report 31's method inventory on the sat
   side).
2. **No method named** `EnableSSH`, `StartDropbear`,
   `InstallAuthorizedKey`, `WriteAuthorizedKeys`, `EnableTelnet`,
   `RemoteShellEnable`, `WriteFile`, `PutFile`, `ExecCommand`,
   `RunCommand`, or any synonym exists in soapc's method set.
3. **No method** writes to `/etc/ssh/*`, `/etc/dropbear/*`,
   `/etc/init.d/*`, or `/etc/rc.d/*` — all state-changing methods
   funnel through the sat's `configd` DAL tables (schema-validated
   writes) per report 31, and none of the DAL tables control SSH,
   Dropbear, Telnet, or the OpenSSH `authorized_keys` file.
4. Methods in the firmware-upgrade family (`UpdateNewFirmware2`,
   `CheckAndDownloadNewFirmware*`) *could* in principle write
   executable content to the sat, but doing so would require
   providing a signed-or-accepted firmware image, which crosses the
   project's hard flash-prohibition boundary (CLAUDE.md §13).
5. `soapc` itself never exposes a shell — it exclusively builds SOAP
   request bodies, opens a socket (plain or TLS without peer verify),
   writes them, and parses the response for a response code and some
   field values. `system()` is imported but its only observed in-code
   use is `doSystem("acos_service restart_qca_wlan")` after certain
   flagged argv events (see §6.3), never with sat-controlled argv.

**Conclusion for the scope-amendment question**: the master's
authenticated management relationship with its satellites, as realised
by `soapc`, does **NOT** give the owner a legitimate, non-exploit,
non-bypass path to provision SSH access on the satellites. Every
avenue a legitimate SOAP caller could reach is a disciplined,
schema-validated DAL write for a specific WLAN / block-list /
LED / NTP / device-name / voice setting.

Owner-SSH-provisioning via the soapc path is **ruled out** on the
basis of this static evidence.

Noted negative conclusions remain inherently finite:
- They rest on the static method inventory being complete. **Confirmed**
  for this binary (all `M1:*` body templates enumerated; `s_Event` and
  `all_events` tables parsed; method dispatch routed through
  `FUN_00025fb8` which iterates `all_events` only).
- They rest on no new SSH-provisioning method being added in a
  firmware version we have not examined. Both master firmwares we hold
  (7215 and 7288) are soapc-identical (§9). If NETGEAR introduces an
  owner-SSH-provisioning SOAP method in a future release, this
  conclusion would need re-verification against that binary.

---

## 11. Track C follow-up — what Report 35 should consume

- `soapc` uses **none of librpc.so's `clnt_*`/`svc_*`/`xdr_*`/`pmap_*`
  symbols**. This is confirmed by `readelf -s` over the full dynamic
  symbol table. The master→sat SOAP path is HTTP(S)/XML over TCP,
  parsed in-process. librpc.so only appears on the satellite side of
  the wire (soap_agent → configd), where report 31 already mapped it.
- CVE-2026-0415, located by report 32 in sat-side `librpc.so`, is
  reachable via SOAP input from the master (every state-changing
  method eventually hits configd through soap_agent's Sun RPC client
  stub), but the vulnerability is **in the sat's library**, not in
  anything the master ships. The master's `soapc` is version-stable
  7215↔7288, so there is nothing in it to carry a CVE-0415 fix.

---

## 12. Remaining unknowns, ranked

1. `g_soapc_mac1` population site — inferred by symmetry with
   `FUN_0002864c`; the sibling writer was not located this pass.
2. `expand_soap_template` (`FUN_00029674` or near) full directive table —
   the set of `<%X();%>` directives was enumerated from string
   literals, but the dispatch function itself was not decompiled
   end-to-end. Consequence: the `get{New,Router}Password`,
   `updateAdminPassword[Hashed]` handlers remain Strongly-supported
   rather than Confirmed at implementation depth.
3. Whether `FUN_0002a234` ("get_service_name") decodes
   `service_type_database` at the odd starting offset 0x3f315 via a
   bit-field, or via an entry table nearby.
4. Which exact sat-side function validates
   `MD5(NETGEAR_Orbi_<MAC>_password)` — report 31 located it as
   `configd::authenticate_satellite_1_svc` via Sun RPC, but whether
   `configd` MD5-hashes the stored default before comparison, or
   stores a pre-computed MD5, is open. This matters for the
   PSIRT draft because it determines whether the derivation is
   effective on a factory-fresh sat as well as a paired one.
5. The role of the `soapc_pass` NVRAM key read by `check_fw`.
   `soapc` itself does not use it; left as an Unverified assumption
   pending a separate `check_fw` RE pass.
6. The `prepareSoapBady` function — the format string was found at
   0x2fe96 but Ghidra reported zero xrefs to it. Likely the string is
   referenced via PC-relative constant pool loading that Ghidra's
   xref analysis did not resolve. Reading the function would confirm
   whether the `_password before hash` log happens in `soapc` or in a
   library it links; the observation was from string inventory, so
   its *existence* in soapc is Confirmed but its *origin function*
   is Unverified.

---

## 13. Files produced

- `firmware_analysis/reports/33_master_soapc_reverse_engineering.md` — this report.
- `firmware_analysis/research_output/soapc/functions.json` — reverse-engineered function inventory with offsets and classifications.
- `firmware_analysis/research_output/soapc/method_table.json` — parsed `all_events`, `s_Event`, `events_array`, `HTTP_ERROR_CODE`, `service_type_database` tables.
- `firmware_analysis/research_output/soapc/callers.json` — caller integration map (heartbeat, httpd, device_detect, check_fw, etc.).
- `firmware_analysis/research_output/soapc/7215_vs_7288.json` — version delta (effectively null).

## 14. PSIRT-draft candidate items from this report

- **Master-to-satellite TLS has no peer verification** (§4.1). On-path
  MITM on the master↔sat link intercepts and injects admin SOAP
  traffic.
- **Master-to-satellite auth credential is deterministic from the
  satellite's LAN MAC** (§5). Any node observing a sat's MAC on-LAN
  can derive the same credential master-side code does.
- **Hardcoded username `orbi`** in the Authenticate body (§5.1).
- Combined with report 31's PSIRT-worthy
  `NETGEAR_Orbi_<MAC>_password` default-admin finding, the full
  disclosure is: on this platform the master authenticates to its
  satellite via `MD5(pre-pairing-default)` — the same credential the
  sat would accept from any factory-fresh admin login. Anyone with
  LAN-side MITM can forge master-equivalent auth to a sat.

Not for PSIRT (no vulnerability): the dispatch model, the method
inventory, the per-sat NVRAM channel, the 4 KB body cap, the restart
flag in `events_array`, etc.
