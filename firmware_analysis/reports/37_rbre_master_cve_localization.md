# Report 37 — CVE-2026-0415 localised in the RBRE master Seal REST handler

Status: **CONFIRMED**
Evidence date: 2026-11-04
Scope: Master (RBRE960) firmware delta V7.2.7.15_5.1.16 → V7.2.8.8

---

## Advisory under investigation

NETGEAR advisory (June 2026):
<https://kb.netgear.com/000070811/June-2026-NETGEAR-Security-Advisory>

- CVE: **CVE-2026-0415**
- Advisory one-liner: *"insufficient input validation allowing authenticated
  local-network administrators to make unauthorized modifications to router
  software and functionality"*.
- Affected models (listed): RBRE960, RBSE960, plus other Orbi products.
- Fix landed in 7.2.8.5; both local 7288 images are 7.2.8.8.

Prior project localisations that had been ruled out: `librpc.so`, master
`soapc`, master `configd`, satellite `soap_agent`, satellite `configd`,
`libcrypto.so.1.1`, master `libacos_shared.so` (all in reports 32–36 and
`libacos_shared_cve_audit.md`). This report inverts the overall CVE-0415
status back from `Unverified` to **CONFIRMED** on new binary evidence.

---

## Classification

**CONFIRMED — the CVE-2026-0415 fix is implemented in the master Seal
REST handler** (two Lua bytecode files) with a companion hardening in
`etc/lighttpd_conf.ltp`.

The vulnerable primitive is **admin-controlled `service_name` reaching five
distinct `popen`/`os.execute` call sites by raw Lua string concatenation
inside `service_action_handler`**, which runs under uid 0 in the
root-privileged lighttpd instance bound to `127.0.0.1:16667`. The 7288 fix
inserts a `^[A-Za-z0-9_-]+$` identifier whitelist plus a `%.%.`
path-traversal rejection at both the REST dispatcher and at the service
handler itself.

---

## Fix sites (primary evidence)

### 1. `usr/share/lua/seal-services.lua` — `service_action_handler`

| version | sha256 | size |
|---|---|---|
| V7.2.7.15 | `3e24b97b41a4db23f6d76d22611c1a932cf5421d529af127c92c0b4f6a8682eb` | pre-fix |
| V7.2.8.8  | `27063966010939a1c6eac05b175fc3b3e26345f1221a66060df2290ad0d62da0` | post-fix |

Lua 5.1 bytecode. Loaded by `rest.lua` via `require("seal-services")`.

**Diff (constant table, in bytecode order)** — the 7288 version inserts six
new constants between the declaration of `service_action_handler` and its
first legitimate instruction (`ipairs` over the service catalog):

```
type
string
match
^[A-Za-z0-9_-]+$
find
%.%.
```

This is the fingerprint of a guard clause at the top of the function body
(reconstructed form; exact tokens recovered from the bytecode constant table):

```lua
function service_action_handler(service_name, action, payload)
    if type(service_name) ~= "string"
       or not string.match(service_name, "^[A-Za-z0-9_-]+$")
       or string.find(service_name, "%.%.") then
        return invalid_request_reply()    -- "Invalid request"
    end
    -- unchanged original body follows (ipairs over catalog, etc.)
end
```

**Downstream shell concatenation sites that `service_name` reaches** (all
present in both versions, preserved verbatim in 7288 but now unreachable
with hostile input):

| string position in 7288 | shell string | Lua primitive |
|---|---|---|
| line 51–52 of `seal-services.7288.strings.txt` | `opkg status seal-service-{service_name} \| grep '^Status: ' \| awk '{printf "%s", $4}'` | `popen` |
| line 60–61 | `ssvc status {service_name} >/dev/null 2>&1` | `os.execute` |
| line 117 | `opkg install {service_name}` | `popen` |
| line 121 | `opkg remove {service_name}` | `popen` |
| line 128 | `/usr/bin/nsh.sh argument 0 {service_name}` | `popen` |

Each is `shell_primitive(hard_prefix .. service_name [.. hard_suffix])` Lua
concatenation — no quoting, no escaping, no argv-array form.

Artifacts: `firmware_analysis/research_output/rbre_cve_0415/seal_services_lua/`
contains byte-identical copies of both versions, the in-order string listings
(`seal-services.{7215,7288}.strings.txt`), the unified diff of those listings
(`seal-services.strings.diff`), and `notes.md`.

### 2. `www-seal/rest/rest.lua` — the REST dispatcher

| version | sha256 |
|---|---|
| V7.2.7.15 | `59e48af4076e4122217ad8cfdb5a1fd1ccec34aafb1aaf951073443d17b8259b` |
| V7.2.8.8  | `45e8cd5c2fd192ea26024cd6fa16f37b56bb225321fc23b5770933db4d165c1b` |

**Routes dispatched** (byte-identical list in both versions, taken from
the constant table of the main chunk):

```
GET  /api/v1/services
GET  /api/v1/services/:service_name
GET  /api/v1/services/:service_name/token
POST /api/v1/install/:service_name
POST /api/v1/uninstall/:service_name
POST /api/v1/services/:service_name/state
POST /api/v1/services/:service_name/webapp/:webapp_version
GET  /api/v1/services/:service_name/webapp
POST /api/v1/services/:service_name/validateToken
POST /api/v1/enable_ssh
```

The `:service_name` path component is extracted by `third_party/router` and
handed to the handler unmodified.

**Diff (constant table)**:

| removed in 7288 | added in 7288 |
|---|---|
| `HostAddr` | `ProxyInternal` |
| `HTTP_X_HOST` | `HTTP_X_SEAL_INTERNAL` |
| `HttpXForwardedFor` | `^[A-Za-z0-9_-]+$` |
| `HTTP_X_FORWARDED_FOR` | `%.%.` |
| `ServerAddr` | `find` |
| `127.0.0.1`, `localhost` | `Invalid request`, `Bad Request` |
| `Server Error` | `type`, `string`, `match` |

The guard-clause constants (`type`, `string`, `match`, `^[A-Za-z0-9_-]+$`,
`find`, `%.%.`) + `Invalid request` string pair appear **six separate times**
in the 7288 constant stream (positions 79, 90, 107, 114, 120, 145, 160 in
`rest.7288.strings.txt`). Each marks one dispatch site where the handler
now rejects a non-whitelisted `service_name` before calling into
`service_action_handler`, `file_exists`, `is_directory`,
`read_all_from_file`, or `write_to_file` on a path of the form
`/var/media/reserved2/service_uppers/{service_name}/upper/...`.

The companion header change (`HTTP_X_FORWARDED_FOR` / `HTTP_X_HOST` /
`HostAddr` / `127.0.0.1` / `localhost` family removed, `HTTP_X_SEAL_INTERNAL`
added) replaces a client-settable trust source with a server-side origin
mark set by lighttpd (see §3). This closes a *secondary* path: without the
guard, an unauthenticated attacker able to spoof `X-Forwarded-For: 127.0.0.1`
could reach the `/debugEnable` branch that previously conditioned on that
header.

Artifacts: `firmware_analysis/research_output/rbre_cve_0415/rest_lua/` —
copies of both versions, in-order string listings, strings diff, `notes.md`.

### 3. `etc/lighttpd_conf.ltp` — companion proxy hardening

| version | sha256 |
|---|---|
| V7.2.7.15 | `cf7420a94dc21bd7c1e4162ef734e3e31fbc4505aa78f56d36418e20ce899399` |
| V7.2.8.8  | `d740454ea8583f3e780cf416a6675af0b9b3e5bf9411b2e3ba2b017f8c80cf1f` |

Two changes (plus unrelated TLS cipher-suite hardening):

1. `extforward.forwarder = ("all" => "trust")` → `("127.0.0.1" => "trust")`.
   The pre-fix line told lighttpd to trust the `X-Forwarded-For` header from
   any source; the post-fix line restricts trust to lighttpd's own loopback.
2. New `setenv.add-request-header += ("X-Seal-Internal" => "1")` on the
   `/api/` → `127.0.0.1:16667` proxy block. The Seal REST backend keys its
   "is this an internal origin?" decision on this header in 7288 instead of
   on `HTTP_X_FORWARDED_FOR` / `HTTP_X_HOST`.

Unified diff saved at
`firmware_analysis/research_output/rbre_cve_0415/scripts/lighttpd_conf.ltp.diff`.

### 4. Root-privileged backend lighttpd — unchanged

`etc/lighttpd_root_conf.ltp` has sha256 `1f4324d6eefc38c97161c6799e9f9b9f1d9fb148b4999a19ac4aaf78dc9aad45`
in **both** 7215 and 7288. Its header reads:

```
####################################################
# Run new instance of lighttpd with root privilege #
####################################################
server.port                    = 16667
server.bind                    = "127.0.0.1"
...
$HTTP["url"] =~ "(^/api/)" {
    url.rewrite = ( "" => "/rest/rest.lua" )
}
cgi.assign                    += ( ".lua" => "/usr/bin/lua" )
```

This is the process that spawns `/usr/bin/lua rest.lua`. It runs with uid 0.

---

## Methodology

1. **Phase 1 — Full master delta**. Used the existing toolkit output
   `firmware_analysis/research_output/compare/rbre_7215__vs__rbre_7288/changes.json`
   (1104 changed files). Filtered to directive-priority paths
   (`usr/{sbin,bin,lib,libexec}/`, `www/`, `lib/`, `etc/init.d/`,
   `etc/rc.d/`, `etc/startup.d.in/`, `etc/lighttpd*`, `etc/httpd*`,
   `etc/config/`), excluded `lib/modules/`, `opt/services/`,
   `usr/lib/python`/`lua`/`opkg`/`ipsec`, and the seven previously
   ruled-out candidates. Result: **193 candidates** (112 ELF, 81 script /
   text). Artifact: `01_inventory_shortlist.{json,md}`.

2. **Phase 2 — Tier 4 (scripts / configs) first** because they are cheap.
   `diff -u` on `lighttpd_conf.ltp`, `lighty.yaml`, `feature_switch.sh`,
   `seallog_save.sh`, `create_self_signed_certificate.sh`, `WLG_adv_qca.htm`.
   Surfaced the lighttpd trust-model change and pointed to the Seal REST
   backend as the next target.

3. **Phase 2 — Tier 1 ELFs via REA and dynsym-diff**:
   - `usr/sbin/httpd` (+4040): new libcurl imports (`curl_global_init`,
     `curl_easy_setopt`, …) for `netgear.api.oemdns.com` hostname-check;
     orthogonal TLS hygiene change.
   - `usr/sbin/check_fw` (+16), `heartbeat` (+80), `scheact` (+60),
     `wandetect` (+108), `rc`, `telnetenabled`, and 73 other binaries:
     the only dynsym change is **`_eval` → `_eval_daemon`**.
   - Decompiled `libacos_shared.so` 7215 (via REA/Ghidra 12.1.3): the
     `_eval` symbol is a **thunk** that tail-calls `_eval_daemon`. The
     migration is thunk inlining across 79 binaries, not a semantic
     change. Separately confirms the prior
     `libacos_shared_cve_audit.md` conclusion that `_eval_daemon`'s
     +68-byte delta is a `<` input-redirect feature addition, not a fix.

4. **Phase 2 — Lua byte-code diffs**. `diff -rq` across `www-seal/`,
   `usr/share/lua/`, `usr/lib/lua/` surfaced three changed Lua files:
   `rest.lua`, `seal-services.lua`, `seal-monit-templates.lua`. The last
   one is a one-line `monit` template change
   (`if status = 2 then stop` added) and unrelated.

5. **Phase 3 — Constant-table reconstruction**. Because the Lua bytecode
   is Lua 5.1 with a non-standard `integral` flag that our local parser
   could not advance past, we fell back to in-order `strings` listings
   (`strings | nl`). Lua 5.1 `luac` emits string constants in the order the
   compiler encounters them within each function body, in function
   definition order. The in-order diff of `strings` is therefore a
   reliable projection of **which constants a specific function gained or
   lost**, even without full decompilation. Applied to `seal-services.lua`
   and `rest.lua`, this surfaces the six-constant guard clause at the
   exact lexical position where the handler body begins — the only place
   those strings could land, given their adjacency to `service_action_handler`
   and the preserved subsequent constants.

6. **Phase 4 — RBSE correlation**. `find firmware_analysis/extracted/rbse_7215
   firmware_analysis/extracted/rbse_7288 -name "{rest,seal-services}.lua"`
   returns zero files. `grep -rl "service_action_handler"` across both sat
   rootfs also returns zero hits. Satellite firmware has no `www-seal/`
   directory, no `/api/v1/*` endpoint, no Seal REST backend. Only
   `etc/seal_version` placeholder is present on the sat.

All work was offline and read-only.

---

## Directive answers

### 1. Where is the CVE-2026-0415 fix?

**Two Lua bytecode files on the RBRE master**, with a companion lighttpd
proxy config change:

1. `www-seal/rest/rest.lua` — the REST dispatcher reached at
   `POST /api/v1/*`. Fix is a six-constant guard applied at **six** call
   sites touching `service_name`, plus removal of client-settable header
   trust (`HTTP_X_FORWARDED_FOR`, `HTTP_X_HOST`, `HostAddr`, `ServerAddr`)
   in favour of `HTTP_X_SEAL_INTERNAL`.
2. `usr/share/lua/seal-services.lua` — the in-process module whose
   `service_action_handler(service_name, …)` builds and runs shell command
   strings. Fix is the same six-constant guard inserted as a top-of-function
   precondition, defence-in-depth behind the dispatcher guard.
3. `etc/lighttpd_conf.ltp` — narrows `extforward.forwarder` from
   `"all"` to `"127.0.0.1"` and stamps `X-Seal-Internal: 1` on the
   proxy-to-root-lighttpd path.

### 2. What exact behavior changed?

Pre-fix 7215: `service_name` (admin-controlled path component of
`/api/v1/*`) was substituted into five shell command strings without
any validation, quoting, or escaping. Specifically:

| sink | pre-fix command string |
|---|---|
| `popen(…)` | `opkg install ` .. `service_name` |
| `popen(…)` | `opkg remove ` .. `service_name` |
| `popen(…)` | `opkg status seal-service-` .. `service_name` .. ` \| grep ...` |
| `os.execute(…)` | `ssvc status ` .. `service_name` .. ` >/dev/null 2>&1` |
| `popen(…)` | `/usr/bin/nsh.sh argument 0 ` .. `service_name` |

Post-fix 7288: the handler now rejects `service_name` with `"Invalid
request"` unless it is a Lua `string` matching `^[A-Za-z0-9_-]+$` and not
containing `..`. The rejection happens both at the REST dispatcher (per
route) and at the top of `service_action_handler` (defence in depth).
The shell concatenation sinks are preserved unchanged; they are now
unreachable with hostile input.

Trust-source change: pre-fix 7215 used client-settable HTTP headers
(`X-Forwarded-For`, `X-Host`, derived `HostAddr`/`ServerAddr`) to decide
whether a request was "internal". Post-fix 7288 uses
`HTTP_X_SEAL_INTERNAL`, written by the user-facing lighttpd on the
proxy hop and therefore not propagated from the client.

### 3. Which administrator-facing interface reaches the affected functionality?

The admin-authenticated REST endpoints on the RBRE master:

- `POST /api/v1/install/<service_name>`
- `POST /api/v1/uninstall/<service_name>`
- `POST /api/v1/services/<service_name>/state`
- `POST /api/v1/services/<service_name>/webapp/<webapp_version>`
- `GET  /api/v1/services/<service_name>/webapp`
- `POST /api/v1/services/<service_name>/validateToken`
- `GET  /api/v1/services/<service_name>/token`

All of these are served by the same `rest.lua` dispatcher that terminates
at `service_action_handler` or at the `/var/media/reserved2/service_uppers/{service_name}/upper/…`
filesystem operations. Reached over HTTP(S) via the user-facing lighttpd
(ports 80/443, `http:www-data`) which proxies `/api/` to the
root-privileged backend on `127.0.0.1:16667`.

The advisory specifies **authenticated admin**; handler-level admin
verification (not the lighttpd config itself) enforces this. Our
`POST /api/v1/enable_ssh` endpoint on the same dispatcher is known from
earlier project work to require admin credentials; by construction the
sibling `/api/v1/services/*` handlers are reached by the same
authenticated pipeline.

### 4. Does the affected code execute with root privileges?

**Yes, uid 0.** The Lua interpreter is spawned by
`etc/lighttpd_root_conf.ltp`, which is byte-identical in 7215 and 7288
(sha256 `1f4324d6…`) and whose own header reads *"Run new instance of
lighttpd with root privilege"*. Confirmed cross-references:
`etc/startup.d.in/lighty_root.yaml` is the yaml descriptor that launches
this second lighttpd; `etc/netgear.conf` sets
`lighttpd_server_dir=/www-seal`; the CGI binding is
`cgi.assign += (".lua" => "/usr/bin/lua")`; and the
`/api/` rewrite rule rewrites to `/rest/rest.lua`. `opkg install`,
`opkg remove`, and `ssvc status` all require root to do their jobs
on this platform, which is consistent with the uid 0 context.

### 5. Does the vulnerability provide unauthorized configuration changes, arbitrary command execution, or both?

**Both**, but command execution is the primary impact.

- **Arbitrary command execution as root**: a `service_name` value of
  (illustratively, not a working PoC)
  `foo;{WHATEVER}`
  turns `popen("opkg install " .. service_name)` into
  `popen("opkg install foo;{WHATEVER}")`. The command runs in the handler's
  uid-0 shell. Five independent injection points
  (`opkg install`, `opkg remove`, `opkg status`, `ssvc status`,
  `/usr/bin/nsh.sh argument 0`) share this shape.
- **Unauthorized file modification**: `service_name` with `..` reaches
  path operations rooted at `/var/media/reserved2/service_uppers/`. A
  traversal escapes that root and reaches `/var/media/reserved2/`, the
  UBIFS partition that backs the overlayfs upper layer; a successful
  write to `/var/media/reserved2/overlay/upper/…` persists across
  reboots. This is the advisory wording's *"unauthorized modifications
  to router software and functionality"*.

### 6. Is equivalent vulnerable functionality present in RBSE960?

**No — the vulnerable surface is master-only.** Direct evidence:

- `find rbse_{7215,7288}/rootfs -name "rest.lua"` returns zero files.
- `find rbse_{7215,7288}/rootfs -name "seal-services.lua"` returns zero
  files.
- `grep -rl "service_action_handler"` across both sat rootfs returns
  zero hits.
- Sat has no `www-seal/` directory and no `/api/v1/*` lighttpd route.
- Only `etc/seal_version` placeholder is present on the sat.

The advisory nevertheless lists the RBSE960. Two possibilities, both
consistent with the binary evidence:

(a) The advisory lists the Orbi system (RBK960 kit) by model group: when
    the master is vulnerable, the whole kit is named.
(b) A separate sat-side CVE-0415 issue exists elsewhere and is not in
    this master-side Lua fix. We have no binary evidence for (b); every
    sat-side candidate the project has investigated to date
    (`soap_agent`, `configd`, `libcrypto.so.1.1`) was ruled out in
    reports 32–36. If a separate sat fix exists, it is still to be
    located.

### 7. Does this provide any demonstrated route to satellite root access?

**Not directly, but transitively if the master is unpatched.**

- Directly: the sat has no counterpart to this REST endpoint, so the
  CVE-0415 vector cannot be aimed at the sat's own management plane.
- Transitively: an authenticated admin exploiting this on an unpatched
  7.2.7.15 master gains uid 0 on the master. From master root, the
  previously-documented master→sat administrative channels
  (soap_agent proxy, remoteshellenable, mesh authentication templates,
  firmware upgrade pipeline) are available as a next step. That next
  step is covered in reports 30, 31, 33, 35, 36 and is not expanded
  here.

On a patched 7.2.8.8 master, this specific route is closed by the
whitelist. Owner SSH provisioning on the satellite remains
**CONFIRMED-ABSENT** per `root_access_assessment.md`.

---

## Per-candidate shortlist verdicts

| Candidate | Delta | Verdict |
|---|---|---|
| `www-seal/rest/rest.lua` | bytecode, +strings | **CONFIRMED — primary fix site** |
| `usr/share/lua/seal-services.lua` | bytecode, +strings | **CONFIRMED — co-site inside the shell-concat function** |
| `etc/lighttpd_conf.ltp` | +~1 KiB | **CONFIRMED (companion) — trust-model hardening** |
| `usr/sbin/httpd` | +4040 | RULED OUT as CVE-0415 — libcurl adoption for cloud hostname check; orthogonal TLS hygiene |
| `usr/sbin/check_fw` | +16 | RULED OUT — identical symbol table; only `_eval` → `_eval_daemon` thunk inlining |
| `usr/sbin/heartbeat`, `scheact`, `wandetect`, `launchService`, `ddnsd`, `wdhcp6c`, `telnetenabled`, `rc`, `mdns`, `zip*` | small ±0..±400 | RULED OUT — all accounted for by the `_eval` → `_eval_daemon` thunk inlining migration (79 binaries total; symbol tables otherwise identical) |
| `usr/bin/dalh`, `d2d`, `fing_dil`, `upagent`, `libdillib.so`, `libfwcheck.so` | +4096..-8300 | RULED OUT — DIL/DAL/fing feature churn + libcurl adoption; no new admin-facing input-validation guards; preserved for completeness but not CVE-0415 |
| `etc/startup.d.in/lighty.yaml` | +530 | RULED OUT as CVE-0415 — regenerates 1024→2048-bit cert; TLS hygiene |
| `usr/bin/create_self_signed_certificate.sh` | -2 | RULED OUT — RSA 1024→2048, cert days 36500→3650; TLS hygiene |
| `usr/bin/seallog_save.sh` | +120 | RULED OUT — `rm` → `printf "" >` for dal_ash truncation; log hygiene |
| `usr/bin/feature_switch.sh` | +1314 | RULED OUT — new `show` action; `gamebooster`/`rsu_updates` catalog entries; feature extension |
| `www/WLG_adv_qca.htm` | +76 | RULED OUT — string-table id shifts + RBR860-hide conditional; webui cosmetic |
| `etc/lighttpd_conf.ltp` cipher suites | — | tagged companion only; TLS hygiene, not CVE-0415 |
| `usr/sbin/soapc`, `configd`, `soap_agent`, `librpc.so`, `libcrypto.so.1.1`, `libacos_shared.so` | — | already ruled out in reports 32–36 and `libacos_shared_cve_audit.md`; no new evidence contradicts |

---

## Missing evidence / limits

- **No full Lua 5.1 decompile** was produced. The constant-table and
  in-order `strings` projection is a reliable lower bound on which
  constants were added where; it is not a token-level AST. A full
  decompile (via `luadec`, `unluac`, or Ghidra's Lua-5.1 bytecode loader)
  would resolve the exact Lua expression tree. The fix pattern is
  unambiguous from the constant-table evidence, so this gap does not
  change the classification.
- **No PoC was built**, per directive. Command-injection and
  path-traversal payloads are described structurally but never
  constructed.
- **Admin-authentication model not re-derived here**. The project
  accepted the advisory's "authenticated admin" framing. Whether the
  Seal REST dispatcher enforces session/cookie auth before reaching
  `service_action_handler` is covered by prior reports; it is not
  re-examined in this report.
- **Why the advisory lists RBSE960 is not fully answered**. Three
  possibilities remain: (a) product-family grouping, (b) a separate
  sat-side CVE-0415 fix not yet located, (c) the sat is listed because
  the kit's trust boundary crosses from master to sat. Binary evidence
  only supports (a) and (c). A fresh sat-side Priority-2/3 survey
  would be needed to definitively rule out (b).
- **Transitive master→sat impact not quantified** in this report. See
  reports 30, 31, 33, 35, 36 for the already-documented master→sat
  administrative channels.

---

## Supporting artifacts

All under `firmware_analysis/research_output/rbre_cve_0415/`:

```
01_inventory_shortlist.json          193-candidate shortlist (JSON)
01_inventory_shortlist.md            same in human-readable form
rest_lua/
    rest.7215.luac                   byte-identical copy, sha256 59e48af4…
    rest.7288.luac                   byte-identical copy, sha256 45e8cd5c…
    rest.{7215,7288}.strings.txt     in-order constant projections
    rest.strings.diff                unified strings-diff (fix fingerprint)
    notes.md                         route list, fix diff, trust model
seal_services_lua/
    seal-services.{7215,7288}.luac   byte-identical copies
    seal-services.{7215,7288}.strings.txt
    seal-services.strings.diff
    notes.md                         function-level fix detail + sink list
seal/                                legacy diff stubs (binary diffs, len=1)
scripts/
    lighttpd_conf.ltp.diff           companion trust-model diff
    lighty.yaml.diff                 TLS cert regen hygiene
    feature_switch.sh.diff           feature extension
    seallog_save.sh.diff             log hygiene
    create_self_signed_certificate.sh.diff
    WLG_adv_qca.htm.diff             webui cosmetic
    lua51_dump.py                    partial Lua 5.1 bytecode parser
sha256.txt                           hashes of the four Lua copies
```

Rootfs paths cited in this report:

- `firmware_analysis/extracted/rbre_7215/rootfs/usr/share/lua/seal-services.lua`
- `firmware_analysis/extracted/rbre_7288/rootfs/usr/share/lua/seal-services.lua`
- `firmware_analysis/extracted/rbre_7215/rootfs/www-seal/rest/rest.lua`
- `firmware_analysis/extracted/rbre_7288/rootfs/www-seal/rest/rest.lua`
- `firmware_analysis/extracted/rbre_7215/rootfs/etc/lighttpd_conf.ltp`
- `firmware_analysis/extracted/rbre_7288/rootfs/etc/lighttpd_conf.ltp`
- `firmware_analysis/extracted/rbre_7215/rootfs/etc/lighttpd_root_conf.ltp` (unchanged)
- `firmware_analysis/extracted/rbre_7288/rootfs/etc/lighttpd_root_conf.ltp` (unchanged)

All other reports (1–36) are preserved unchanged.
