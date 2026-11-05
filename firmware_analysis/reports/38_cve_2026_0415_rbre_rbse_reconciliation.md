# Report 38 — CVE-2026-0415 RBRE / RBSE evidence reconciliation

Status (per-product, per directive 705a):

| product | classification | note |
|---|---|---|
| RBRE960 (master) | **CONFIRMED** (sharpened) | Validator and sink-prologues confirmed opcode-level; report 37's finding verified and corrected in two minor particulars. |
| RBSE960 (satellite) | **RULED OUT** as the CVE-fix location | No equivalent code path; no 7215→7288 Lua code change; only `luci/version.lua` touched (version string). |

Evidence date: 2026-11-04
Scope: Master and satellite firmware V7.2.7.15_5.1.16 → V7.2.8.8 offline diff.

---

## 1. Methodology

- All firmware SHAs verified at the path in prior reports.
- Lua bytecode parsed opcode-level with a purpose-built Lua 5.1 parser
  (`research_output/rbre_rbse_reconciliation/track_a/lua51_parse.py`), which
  also handles the vendor extension `LUA_TINT_VENDOR = 9` (4-byte integer
  constants) observed in these firmware images — standard off-the-shelf
  decompilers do not handle this extension.
- Each candidate function dumped as a per-proto instruction stream plus
  constant table; dumps saved under
  `research_output/rbre_rbse_reconciliation/track_a/*.listing.txt`.
- Trust-boundary inspection via plain-text diff of `lighttpd_conf.ltp` and
  `lighttpd_root_conf.ltp`.
- RBSE sat surface: comparative Lua enumeration (120 common files, one change),
  rpcd ACL dump, fingerprint-grep of all admin binaries.
- Offline only. No device contact, no PoC, no firmware modification.

---

## 2. SHA256 anchors (all independently verified)

| artifact | version | sha256 |
|---|---|---|
| `rbre_7215/rootfs/usr/share/lua/seal-services.lua` | V7.2.7.15 vuln | `3e24b97b41a4db23f6d76d22611c1a932cf5421d529af127c92c0b4f6a8682eb` |
| `rbre_7288/rootfs/usr/share/lua/seal-services.lua` | V7.2.8.8 fixed | `27063966010939a1c6eac05b175fc3b3e26345f1221a66060df2290ad0d62da0` |
| `rbre_7215/rootfs/www-seal/rest/rest.lua` | V7.2.7.15 vuln | `59e48af4076e4122217ad8cfdb5a1fd1ccec34aafb1aaf951073443d17b8259b` |
| `rbre_7288/rootfs/www-seal/rest/rest.lua` | V7.2.8.8 fixed | `45e8cd5c2fd192ea26024cd6fa16f37b56bb225321fc23b5770933db4d165c1b` |
| `rbre_7215/rootfs/etc/lighttpd_conf.ltp` | V7.2.7.15 vuln | `cf7420a94dc21bd7c1e4162ef734e3e31fbc4505aa78f56d36418e20ce899399` |
| `rbre_7288/rootfs/etc/lighttpd_conf.ltp` | V7.2.8.8 fixed | `d740454ea8583f3e780cf416a6675af0b9b3e5bf9411b2e3ba2b017f8c80cf1f` |
| `rbre_7215/rootfs/etc/lighttpd_root_conf.ltp` | both | `1f4324d6eefc38c97161c6799e9f9b9f1d9fb148b4999a19ac4aaf78dc9aad45` (byte-identical across versions) |
| `rbse_7215/rootfs/usr/lib/lua/luci/version.lua` | V7.2.7.15 | `9ab35d786acf…` (sole-change) |
| `rbse_7288/rootfs/usr/lib/lua/luci/version.lua` | V7.2.8.8 | `3e1370f16b04…` |
| `rbse_*/rootfs/usr/lib/rpcd/upgrade.so` | both | `412cbd77587bd443a638b9d5a4d7461b9abc90d6d87beec70daf43845211803b` (byte-identical across RBSE versions) |

All eight RBRE SHAs match report 37's citations exactly.

---

## 3. Track A — 8-point independent verification of report 37

### 3.1 Vulnerable V7.2.7.15 `service_action_handler`: **CONFIRMED**

- File: `rbre_7215/rootfs/usr/share/lua/seal-services.lua`.
- In the shipped bytecode, `service_action_handler` is proto[16] of the
  top-level module. Registered at main-function instruction `[66] SETTABLE
  A=0 B=K20="service_action_handler" C=R15` (main-fn `SETTABLE` with the
  string constant `K20=service_action_handler` as key).
- Signature: `nparams=2 nups=1 ncode=27`. The two parameters are the
  service name and the action; the upvalue is the action-map
  `{enabled="ACTIVATE", disabled="DEACTIVATE"}`.
- Final sink inside the function body (vulnerable path):

  ```
  [10] GETGLOBAL  R2 = _G.io
  [11] GETTABLE   R2 = R2["popen"]
  [12] LOADK      R3 = "/usr/bin/nsh.sh argument 0 "
  [13] GETUPVAL   R4 = actionMap    (upvalue[0])
  [14] GETTABLE   R4 = actionMap[action]
  [15] CONCAT     R3 = R3 .. R4     (command string is built — service_name
                                     is in R0, concatenation is actually
                                     R3 .. R0 .. R4 via adjacent registers)
  [16] CALL       io.popen(…)
  ```

- Raw admin input `service_name` reaches the `io.popen` sink via Lua string
  concatenation with no prior validation. Companion sinks in the same file
  share this pattern (see §3.3).

### 3.2 Fixed V7.2.8.8 implementation: **CONFIRMED** (with corrections)

- File: `rbre_7288/rootfs/usr/share/lua/seal-services.lua`.
- `service_action_handler` is proto[17] in the fixed version (index shifted
  by one because a new validator proto was inserted at index 0).
- Signature grew: `nparams=2 nups=2 ncode=33`. The added upvalue is a
  reference to the module-local validator function (see below).
- Fixed proto[17] now starts with:

  ```
  [0] GETUPVAL   R2 = upvalue[0]  ; validator
  [1] MOVE       R3 = R0          ; service_name
  [2] CALL       R2 = validator(service_name)
  [3] TEST       R2 (truth test)
  [4] JMP        +1
  [5] RETURN     A=0 B=1          ; silent early return
  [6]…          original body
  ```

- Two corrections to report 37's wording:

  **Correction A — distribution.** Report 37 describes "a guard clause
  inserted at the top of `service_action_handler`". The actual fix is
  **broader**: the same 5-instruction validator-upvalue prologue is also
  inserted at the top of each of the five sink protos
  (see §3.3). The guard is applied at five functions, not one.

  **Correction B — failure mode.** Report 37 refers to the fail path as
  returning `invalid_request_reply()` / `"Invalid request"`. The
  **actual** opcode stream performs a **silent early return** (`RETURN A=0
  B=1`) in `service_action_handler`, and `LOADBOOL R=0; RETURN` (returning
  `false`) in the `is_installed` sink. No error reply is sent to the
  client at this layer. The string `"Invalid request"` originates one
  layer out, in `rest.lua`'s dispatcher (see §3.4).

### 3.3 All five command-construction call sites: **CONFIRMED** (unified table)

| # | behaviour | 7215 proto / sink | 7288 proto / ncode | guard-prologue in 7288 |
|---|---|---|---|---|
| 1 | `io.popen("opkg install " .. service_name)` | proto[14] / `ncode=13 nups=0` | proto[15] / `ncode=19 nups=1` | validator-upvalue call, silent return on fail |
| 2 | `io.popen("opkg remove " .. service_name)` | proto[15] / `ncode=13 nups=0` | proto[16] / `ncode=19 nups=1` | same shape |
| 3 | `io.popen("opkg status seal-service-" .. service_name .. " | grep '^Status: ' | awk '{printf \"%s\", $4}'")` | proto[4] / `ncode=18 nups=0` | proto[5] / `ncode=25 nups=1` | validator-upvalue, returns `false` on fail |
| 4 | `os.execute("ssvc status " .. normalised_name .. " >/dev/null 2>&1")` | proto[5] / `ncode=24 nups=0` | proto[6] / `ncode=31 nups=1` | validator-upvalue, silent on fail |
| 5 | `io.popen("/usr/bin/nsh.sh argument 0 " .. service_name)` (`service_action_handler`) | proto[16] / `ncode=27 nups=1` | proto[17] / `ncode=33 nups=2` | validator-upvalue, silent on fail |

Each 7288 sink gains the five-instruction validator prologue
(`GETUPVAL / MOVE / CALL / TEST / JMP` → `RETURN`); the remainder of the
body is byte-identical modulo the new upvalue slot. Byte-level difference
per sink ranges from +5 to +7 instructions, matching the +4-7 bytecode
size deltas observed in the compiled file.

### 3.4 Six (actually **seven**) REST dispatch validation sites: **CONFIRMED with correction**

Report 37 said "six REST dispatch validation sites". The actual count in
`rbre_7288/rootfs/www-seal/rest/rest.lua` is **seven** handler protos that
exhibit the paired `service_name` + `Invalid request` constants, each
preceded by a validator call. The seven handlers are protos
[3], [6], [7], [8], [9], [12], [13] (zero-indexed; proto[0] is the new
validator itself, as in `seal-services.lua`).

URL routes defined at the main-function level (constant strings in the
main proto, unchanged between 7215 and 7288):

| route | reached via |
|---|---|
| `GET /api/v1/services` | list endpoint |
| `POST /api/v1/install/:service_name` | install sink (§3.3 #1) |
| `POST /api/v1/uninstall/:service_name` | uninstall sink (§3.3 #2) |
| `GET /api/v1/services/:service_name` | service-detail |
| `GET /api/v1/services/:service_name/state` | state query; invokes `service_action_handler` (§3.3 #5) |
| `POST /api/v1/services/:service_name/state` | activate/deactivate; invokes `service_action_handler` |
| `GET /api/v1/services/:service_name/webapp` | webapp assets |
| `GET /api/v1/services/:service_name/webapp/:webapp_version` | webapp assets by version |
| `GET/POST /api/v1/services/:service_name/validateToken` | token validation |
| `GET /api/v1/services/:service_name/token` | token issuance |

Each of the seven 7288 rest-handler protos (the service-name-parameterised
ones) carries the validator call before dispatch. `"Invalid request"` is
the client-visible error reply at this layer (plus a companion
`"Bad Request"` constant newly present in 7288 for the HTTP status line).

The validator in `rest.lua` is **opcode-for-opcode identical** to the
validator in `seal-services.lua` (33 instructions, 8 constants, identical
match pattern / length cap / find pattern). The project gets layered
defence — validation at both the REST dispatch layer and at the sink
layer.

Additionally, the validator semantics are **stronger than report 37
described**:

```
function is_valid_service_name(x)
    if type(x) ~= "string"       then return false end
    if x == ""                   then return false end
    if #x > 32                   then return false end    -- missing from report 37
    if not x:match("^[A-Za-z0-9_-]+$") then return false end
    if x:find("%.%.")            then return false end
    return true
end
```

The 32-character length cap and the empty-string reject were not surfaced
in report 37.

### 3.5 URL decoding / normalisation order: **CONFIRMED safe**

Request path:

```
client (plaintext or TLS over :80/:443)
  → external lighttpd (port 80/443, user process after lighttpd_conf.ltp applies)
      ─ %XX URL-decoding happens here, during request parsing
      ─ "." and ".." segment canonicalisation happens here, before url.rewrite
      ─ $HTTP["url"] =~ "(^/api/)" matched against the canonicalised path
  → proxy forwards to 127.0.0.1:16667 (no second decode of path segments)
  → internal lighttpd (port 16667, running as root per lighttpd_root_conf.ltp)
      ─ $HTTP["url"] =~ "(^/api/)" { url.rewrite = ( "" => "/rest/rest.lua" ) }
      ─ cgi.assign += ( ".lua" => "/usr/bin/lua" )
  → CGI handoff: /usr/bin/lua runs rest.lua with env vars (REQUEST_URI,
    QUERY_STRING, HTTP_X_SEAL_INTERNAL, etc.)
  → rest.lua extracts path segments via Lua pattern-match from REQUEST_URI
  → validator applies to the EXTRACTED service_name segment
```

Key implications:

- The validator sees a **fully-decoded** `service_name`. A client-side
  `%2e%2e` in the URL path becomes literal `..` at the Lua layer; the
  `x:find("%.%.")` branch catches it.
- Double-encoding (`%252e%252e`) collapses to `%2e%2e` at the Lua layer,
  which does not contain literal `..` — but the whitelist regex
  `^[A-Za-z0-9_-]+$` still rejects it on the grounds that `%` is not in
  the allow-set. The whitelist is the primary defence; the `%.%.` check
  is defence-in-depth.
- Lighttpd canonicalises `..` path segments at the URL level (default
  mod_dirlisting / url behaviour), so a URL like
  `/api/v1/services/../../foo/token` is collapsed to `/foo/token` and
  misses the `^/api/` match — the request does not even reach rest.lua.

### 3.6 Internal lighttpd authentication boundary: **CONFIRMED — reworked, not merely renamed**

Delta in `etc/lighttpd_conf.ltp` (external, user-port lighttpd):

```diff
 extforward.headers = ("Forwarded", "X-Forwarded-For", "X-Real-IP")
-extforward.forwarder = ("all" => "trust")
+extforward.forwarder = ("127.0.0.1" => "trust")
…
 else $HTTP["url"] =~ "(^/api/)" {
     proxy.server = ( "" => ( "" => ( "host" => "127.0.0.1", "port" => 16667 ) ) )
+    setenv.add-request-header += ( "X-Seal-Internal" => "1" )
 }
```

7215's rest.lua trust check (opcodes [124]–[227] of the main proto):

```
HostAddr = os.getenv("HTTP_X_HOST")
HttpXForwardedFor = os.getenv("HTTP_X_FORWARDED_FOR")
…
if HostAddr == "127.0.0.1" or HostAddr == "localhost" or ServerAddr == "127.0.0.1" then
    -- treated as "internal/trusted" request
```

Since 7215 lighttpd trusts `X-Forwarded-For` from **all** sources, and the
Lua also honours the client-settable `X-Host` header, a remote attacker on
the LAN could forge both headers and make the Lua trust-flag evaluate
true. This is a real vulnerability vector, separate from the primary
CVE-0415 service-name sink but exploited by the same attacker class.

7288's rest.lua trust check (opcodes [130]–[225] of the main proto):

```
ProxyInternal = os.getenv("HTTP_X_SEAL_INTERNAL") or ""
…
if ProxyInternal == "1" then
    -- treated as "internal" request
```

The header is set by the external lighttpd via
`setenv.add-request-header += ("X-Seal-Internal" => "1")` after the
`/api/` proxy block. This is a stronger pattern:

- The external lighttpd runs after client parsing; its `setenv.add-request-header`
  adds the marker on the server side. A client-supplied
  `X-Seal-Internal: 1` header arriving from outside would, per lighttpd
  mod_setenv semantics for `+=`, result in a duplicate header forwarded
  alongside the proxy-injected one; the CGI layer merges duplicates into
  a comma-separated value, which the Lua's strict `== "1"` equality test
  would reject.
- Note: I did not test lighttpd runtime merge semantics on live hardware
  — this is a static-analysis reading of `mod_setenv`'s documented
  behaviour. A live PoC is out of scope per directive.

Regardless of the trust-boundary subtlety, the internal boundary is **not
the primary CVE-0415 fix**; that is the service-name whitelist.
`X-Seal-Internal` is adjacent hardening of the debug-endpoint gate and
the forwarded-for trust model.

### 3.7 Process UID and privilege: **CONFIRMED uid 0**

`etc/lighttpd_root_conf.ltp` (byte-identical in 7215 and 7288 — sha256
`1f4324d6…`) opens with:

```
# Lighttpd configuration, built using a Lua template
# vi:syntax=conf

####################################################
# Run new instance of lighttpd with root privilege #
####################################################
server.port                    = 16667
server.bind                    = "127.0.0.1"
…
cgi.assign                    += ( ".lua" => "/usr/bin/lua" )

$HTTP["url"] =~ "(^/api/)" {
    url.rewrite = ( "" => "/rest/rest.lua" )
}
```

There is **no** `server.username`, `server.groupname`, `server.set-uid`,
or `server.set-gid` directive in this configuration. The file does not
drop privileges. The internal lighttpd inherits the privilege of whatever
init / monit / rc script starts it; in OpenWrt-derived Orbi firmware this
is launched as root. All CGI processes forked for `/api/*.lua` inherit
that uid 0.

### 3.8 Overlayfs upper-layer reach from `..` traversal: **CONFIRMED**

Grounds:

- `etc/netgear.conf` in `rbre_7288` sets
  `service_uppers = /tmp/media/reserved2/service_uppers` (host origin of
  service "uppers").
- CLAUDE.md (project-level) establishes that
  `/tmp/media/reserved2/overlay/upper/` is the writable upper layer of
  the rootfs overlayfs mount (the Dropbear `authorized_keys` file is in
  this tree in confirmed runtime observation).
- `/var` and `/tmp` are commonly linked under OpenWrt on these devices;
  `/var/media/reserved2` maps to the same UBIFS mount as
  `/tmp/media/reserved2`.
- `configService` (`usr/bin/configService` in `rbre_7288`) constructs the
  per-service upper directory at
  `${service_uppers}/${name}/upper` and bind-mounts it as the upper of a
  per-service overlayfs.
- A path `${service_uppers}/<service_name>/upper/<token>` with
  `<service_name> = "..%2f..%2f..%2foverlay%2fupper%2fetc%2fdropbear"`
  (decoded: `../../../overlay/upper/etc/dropbear`) would, if not blocked
  by the validator, resolve to the rootfs overlay upper layer. The fixed
  whitelist rejects all such inputs at the Lua layer, so the attack
  surface is now closed. But in the vulnerable 7215 version, the
  traversal reach would have landed in the writable overlayfs upper of
  the rootfs — a persistent-modification primitive.

---

## 4. Track B — RBSE960 advisory reconciliation

### 4.1 Six-question outcome

| # | question | answer | basis |
|---|---|---|---|
| 1 | Is the vulnerability genuinely absent from RBSE960? | **Yes.** | No `seal-services.lua`, no `rest.lua`, no `/api/v1/*` surface; no code path concatenating admin input into `popen`/`os.execute`. Validator fingerprint `^[A-Za-z0-9_-]+$` not present on either sat version (fix string ≠ vuln string — absent on both). |
| 2 | Does RBSE960 have a different implementation of the vulnerable functionality? | **No.** | Sat admin interface is SOAP / LuCI / rpcd; none exposes "install arbitrary opkg package by name" or equivalent remote service-management. |
| 3 | Is there another satellite-side handler with equivalent unsafe input handling? | **None identified by this investigation.** | Fingerprint scan over `usr/sbin/`, `usr/bin/`, `usr/libexec/`, `usr/lib/rpcd/`, `www/cgi-bin/` in `rbse_7288` returns zero hits for `opkg install`, `opkg remove`, `opkg status`, `ssvc status`, `/usr/bin/nsh.sh argument`, `service_action_handler`, `service_uppers`. |
| 4 | Does the satellite use a different management path that could explain the advisory listing? | **Yes — sat is managed from the master.** | The master's Seal REST handler (the vulnerable code) is the sole authenticated-admin management surface for the Orbi kit's higher-level operations. The sat is driven by the master over the backhaul (SOAP `authenticate_satellite_1_svc` and its companion RPCs). Compromising the master on CVE-0415 provides master root, which in turn exercises the master→sat channel; the sat itself has no equivalent surface to patch. |
| 5 | Is the advisory's RBSE960 entry supported by the extracted firmware evidence? | **Indirectly, yes.** | NETGEAR's advisory treats the RBK/RBRE/RBSE Orbi kit as a product-family unit. V7.2.8.5 was published for both models; the RBSE firmware shipped the version bump to maintain kit-level cohesion, but the sat image contains no code-level CVE-0415 fix because the sat has no vulnerable code. This is a common vendor advisory pattern (kit-level rollup) and the firmware evidence is consistent with it. |
| 6 | Can we identify a distinct satellite-side fix between V7.2.7.15 and V7.2.8.8? | **No.** | Of 120 common .lua files, one changed (`luci/version.lua`, -16 bytes, version string only). `upgrade.so` is byte-identical. The only non-trivial native-code sat deltas are in `soap_agent` (auth refactor, already ruled out), `configd` (ruled out), `libcrypto.so.1.1` (timestamp only, ruled out in report 36), and kernel crypto modules. None are CVE-0415 fixes. |

### 4.2 Hypothesis selected

From the directive's four hypotheses, the evidence supports **hypothesis
(a) + (d) combined**: the sat has no equivalent code path at all
(no vulnerable implementation and no fix to apply), and the advisory's
RBSE960 entry is **product-family grouping**. The kit's shipped firmware
bump to V7.2.8.5 covers both models, but the actual fix is master-only.

Note: this is distinct from "the advisory is wrong". The advisory is
accurate at the kit level — an Orbi kit owner running V7.2.7.15 on their
RBRE is vulnerable, and the advisory tells them to update, which
distributes new firmware to both master and satellites in the kit.

---

## 5. Track C — Separated security impact / scope verdicts

**RBRE960 master vulnerability: CONFIRMED.** Admin-authenticated attacker
reaches `popen` and `os.execute` with raw input via five sinks reachable
through at least ten URL routes under `/api/v1/*`. The fix is present in
the two Lua files identified above.

**RBSE960 satellite vulnerability: NOT PRESENT.** The sat has no
equivalent code path, no equivalent URL route, no equivalent admin
interface, and no code-level change between 7215 and 7288 that could
implement the same fix.

**Root privilege of the vulnerable handler: CONFIRMED uid 0.** The
master's Lua handler runs under the internal root-privileged lighttpd
(port 16667). No privilege demotion in that config.

**Ability to modify software: CONFIRMED.** Two independent primitives on
7215 master:
(a) direct invocation of `opkg install <attacker-name>` /
`opkg remove <attacker-name>` with no name validation — either corrupts
the package database or installs a locally-staged `.ipk` named after a
real package;
(b) path traversal from `service_uppers/<service_name>/upper/<token>`
reaches the writable overlayfs upper layer of the rootfs; files written
via the token-persistence code path can therefore land in
`/overlay/upper/etc/…` and persist across reboot.

**Ability to execute operating-system commands: CONFIRMED arbitrary
shell.** The five sinks all build command strings by raw string
concatenation and pass them to `io.popen` (shell-interpreted) or
`os.execute` (also shell-interpreted). Attacker-controlled
`service_name` can embed shell metacharacters (` `, `;`, `|`, `` ` ``,
`$()`, `&`, etc.) which are evaluated by the shell under the uid-0
lighttpd child process. Chaining with the non-vulnerable sink is not
needed — a single admin-authenticated call on the vulnerable
`/api/v1/install/<service_name>` provides immediate uid-0 RCE.

**Ability to obtain a shell on a satellite: NOT DEMONSTRATED.** Prior
reports (24, 25, 25B, 31, 36, 37) established that owner SSH-provisioning
on the satellites remains **CONFIRMED-ABSENT** across 65 reachable auth
operations, four independent defence layers, and the full master→sat
admin channel. CVE-2026-0415 does not change that classification. A
successful exploit of CVE-0415 on an unpatched master yields master root
(which was already obtainable via the owner-authorised
`seal_dropbear_enable.py` path); the sat side gains no new authenticated
primitive from the master-root compromise beyond the already-documented
master→sat SOAP / backhaul admin channel. That channel does **not**
provide satellite root shell — see reports 31, 36 for the full argument.

---

## 6. Advisory-to-firmware reconciliation (one paragraph)

NETGEAR's June 2026 advisory lists RBRE960 and RBSE960 as affected by
CVE-2026-0415 and names V7.2.8.5 as the fix version for both. The
master-side fix is CONFIRMED in `seal-services.lua` and `rest.lua` (see
§3). The satellite-side firmware shipped the matching version bump
(V7.2.7.15 → V7.2.8.8 in our local images, spanning the advisory's
V7.2.8.5 fix point), but contains **no code-level implementation of the
CVE-0415 fix** because the satellite does not contain the vulnerable
code path to begin with. The advisory's listing of RBSE960 is therefore
accurate at the Orbi-kit product level (the kit-owner needs to update
both master and satellites to stay on a supported firmware pair) but the
code-level fix is master-only. This is a routine vendor-advisory
convention and is not evidence of a hidden sat-side vulnerability.

---

## 7. Deltas vs. report 37 (preservation + corrections)

Report 37 is preserved unchanged on disk. The following corrections
apply going forward:

| § | report 37 statement | corrected statement |
|---|---|---|
| guard location | "guard clause at the top of `service_action_handler`" | Guard is replicated at the top of **each of the five sink protos** (install, uninstall, opkg_status, ssvc_status, service_action_handler), plus a copy in `rest.lua` as proto[0]. |
| guard failure | "returns `invalid_request_reply()` / `Invalid request`" | At the Lua-module layer, failure is a **silent early return** (`RETURN`) or `return false`. The `"Invalid request"` reply is emitted only at the REST-dispatch layer in `rest.lua`. |
| validator strength | `type / string / match / ^[A-Za-z0-9_-]+$ / find / %.%.` | Same regex + a 32-character length cap + an explicit empty-string reject. Validator is 33 opcodes, not 6 constants with a 3-step match. |
| rest.lua dispatch sites | "six REST dispatch validation sites" | **Seven** service-name-parameterised handler protos carry the validator in `rest.lua` 7288. |
| trust-boundary framing | "narrowing from `HTTP_X_FORWARDED_FOR` / `HTTP_X_HOST` to `HTTP_X_SEAL_INTERNAL`" | Correct in direction; add that the 7288 external lighttpd also narrows `extforward.forwarder` from `"all" => "trust"` to `"127.0.0.1" => "trust"`, and that the new `X-Seal-Internal` header is set via `setenv.add-request-header +=` after the `/api/` proxy block. |

None of the corrections change the final per-product classification.

---

## 8. Missing evidence and limits

1. **`setenv.add-request-header` merge semantics** — the exact behaviour
   of lighttpd 1.4 when a client already sets `X-Seal-Internal` was not
   verified on hardware. Static analysis (documentation + the Lua strict
   equality check) suggests the fix is sound; live verification would
   require sending a request from a client with a forged header, which
   is outside the offline scope.
2. **Live validator reachability** — the Lua opcode flow proves the
   validator is *linked* to each sink; I did not run the validator on a
   live request to measure its actual rejection behaviour. The static
   evidence is sufficient for the CONFIRMED classification but a
   dynamic test is the next possible step.
3. **Advisory-text access** — I could not fetch the NETGEAR advisory
   HTML offline; the advisory text used here is the one-line summary
   established in report 32 and reused in report 37. If the full
   advisory lists additional affected models or clarifies the kit vs
   per-device distinction, that nuance is out of this report.
4. **Non-Lua admin surface on the sat** — I fingerprint-scanned the
   obvious admin binaries but did not do a full pseudocode diff of every
   changed sat binary in the 44-candidate shortlist for CVE-0415-shape
   patches. Prior reports (32-36) and the libacos_shared audit covered
   the native-binary candidates. If a yet-unaudited sat binary carries
   the fix, this report would miss it — but the Track B evidence
   (no validator fingerprint, no popen/service-mgmt strings, no
   seal-services equivalent) makes that unlikely.
5. **Historical attribution** — I cannot verify from offline evidence
   when the vulnerable code was introduced or who authored the fix; the
   git revision strings in `luci/version.lua` give only a general
   release date.

---

## 9. Reproduction (offline)

From repo root:

```
# Verify SHAs
sha256sum firmware_analysis/extracted/rbre_7{215,288}/rootfs/usr/share/lua/seal-services.lua \
          firmware_analysis/extracted/rbre_7{215,288}/rootfs/www-seal/rest/rest.lua \
          firmware_analysis/extracted/rbre_7{215,288}/rootfs/etc/lighttpd_conf.ltp

# Parse Lua bytecode
python3 firmware_analysis/research_output/rbre_rbse_reconciliation/track_a/lua51_parse.py \
    firmware_analysis/extracted/rbre_7288/rootfs/usr/share/lua/seal-services.lua \
    /tmp/seal_services_7288

# Validator-fingerprint scan (expect: only 7288 master hits)
for k in rbre_7215 rbre_7288 rbse_7215 rbse_7288; do
    echo "=== $k ==="
    grep -rlaF '^[A-Za-z0-9_-]+$' firmware_analysis/extracted/$k/rootfs/ 2>/dev/null
done
```

All supporting artefacts:

- `firmware_analysis/research_output/rbre_rbse_reconciliation/track_a/lua51_parse.py`
- `.../track_a/seal_services_{7215,7288}.{json,listing.txt}`
- `.../track_a/rest_{7215,7288}.{json,listing.txt}`
- `.../track_a/seal_services.strings.diff`
- `.../track_a/validator_fingerprint_scan.md`
- `.../track_b/rbse_lua_delta.md`
- `.../track_b/rbse_admin_surface.md`
- `.../01_rbse_delta_shortlist.json`

Prior reports retained unchanged: 32, 33, 34, 35, 36, 37.
