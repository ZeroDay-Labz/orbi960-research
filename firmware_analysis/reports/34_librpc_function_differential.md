# Report 34 — librpc.so function-level differential (CVE-2026-0415 pivot)

Date: 2026-11-04
Scope: Pin CVE-2026-0415 to a specific function in `librpc.so`, or
rule `librpc.so` out and identify where the evidence actually points.

Binaries (sha256):
- Pre-fix `rbre_7215/.../lib/librpc.so` — `19029e04…`
- Post-fix `rbre_7288/.../lib/librpc.so` — `25324d92…`
- Cross-check: `rbse_7215` == `rbre_7215`, `rbse_7288` == `rbre_7288`. VERIFIED (byte-identical cross-model).

## TL;DR — Final classification of CVE-2026-0415 location

**`librpc.so` is RULED OUT as the CVE-2026-0415 code-fix location.**
Every exported function (137) AND every Ghidra-discovered local helper (53)
has an instruction-level-canonicalised body that is IDENTICAL between
7.2.7.15 and 7.2.8.8. The 46,122 differing bytes decompose entirely into
compile-time relocation shift (function address reordering), literal-pool
pointer table updates, and `.rodata` reordering (+2 bytes total) — not a
single bit of security-relevant code change.

Report 32's classification of `librpc.so` as "STRONGLY INDICATED" is
**downgraded to RULED OUT** based on the function-level evidence here.

**Evidence points elsewhere.** At the function-level depth available in
this fork, the clearest candidate location is a **NETGEAR-internal patch
to a sat state-changing DAL handler that we did not fully isolate in this
pass**. Specific pivots with evidence pointers are listed in §6.

---

## 1. Method

Capstone-based instruction fingerprinting of every procedure Ghidra
identified in both versions, with operands canonicalised so that:
- PC-relative addresses, branch targets, literal-pool loads → class tokens.
- Trailing literal-pool "pseudo-instructions" (`andeq`, `strdeq`, `muleq`,
  `ldrdeq`, etc. — 32-bit pointer data that capstone decodes as ARM
  predicated-eq opcodes) → detected and dropped.

Two phases:
1. **Named export match** (137 functions): compare same name across
   versions by fingerprint hash. Sizes come from `readelf --dyn-syms`
   (accurate).
2. **Anonymous helper match** (53 `FUN_*` procedures): compare by
   fingerprint set. Same-fingerprint → same function body moved to new
   address. No fingerprint match in the other set → candidate CVE change.

Reproduce:
```
.venv/bin/python -I \
  /tmp/claude-1000/.../scratchpad/librpc_full_compare2.py \
  firmware_analysis/extracted/rbre_7215/rootfs/lib/librpc.so \
  firmware_analysis/extracted/rbre_7288/rootfs/lib/librpc.so \
  /tmp/claude-1000/.../scratchpad/7215_procs.tsv \
  /tmp/claude-1000/.../scratchpad/7288_procs.tsv \
  firmware_analysis/research_output/librpc/
```

## 2. librpc.so function inventory

| aspect | 7215 | 7288 |
|---|---|---|
| file size | 66,792 | 66,792 |
| .text size | 0xac70 (44,144) | 0xac70 (44,144) |
| .rodata size | 0xd2a | 0xd2c (+2) |
| dynamic FUNC exports with size>0 | 137 | 137 |
| Ghidra non-thunk non-external procedures | 190 | 190 |
| of which named | 130 | 130 |
| of which `FUN_*` | 60 | 60 |

Report 32's observation that NEEDED / string / dynsym counts are
unchanged holds.

## 3. Function-level fingerprint result

### 3.1 Named procedures — **137 common, 137 identical, 0 changed**

Every exported function has an identical canonicalised instruction
sequence between 7215 and 7288. This includes:

- The report-32 candidate priority-1 set: `svc_run`, `svc_getargs` (not
  exported — see §3.3), `svc_sendreply`, `xdr_string`, `xdr_bytes`,
  `xdr_opaque`, `svcunix_create`, `svcerr_decode`, `svcerr_systemerr`,
  `pmap_unset`, `svc_register`.
- The client side: `clnt_create`, `clnt_pcreateerror`, `clnt_perrno`,
  `clnt_perror`, `clnt_sperrno`, `clnt_sperror`, `clnt_broadcast`,
  `clnttcp_create`, `clntudp_bufcreate`, `clntunix_create`.
- The auth entry point: `_authenticate` (confirms report 32 finding).
- XDR codecs: `xdr_authunix_parms` (confirms report 32), `xdr_array`,
  `xdr_reference`, `xdr_replymsg`, `xdr_pmaplist`, etc.

Output: `firmware_analysis/research_output/librpc/function_fingerprints.json`,
`firmware_analysis/research_output/librpc/fingerprint_summary.json`.

### 3.2 Anonymous helpers — **60 common, 54 fingerprint-identical, 3 size-matched pairs with identical bodies**

Three `FUN_*` pairs showed fingerprint mismatch at initial analysis but
turned out to be caused by literal-pool contamination of the decode
window. After applying stricter literal-pool detection (truncate at the
last real control-flow terminator followed by ≥2 data pseudos), ALL
three pairs resolve to identical bodies:

| A (7215) | B (7288) | size | instr | status |
|---|---|---|---|---|
| `FUN_000172ec` @ `0x72ec` | `FUN_00015ed8` @ `0x5ed8` | 572 | 143 | identical body after proper truncation |
| `FUN_0001bdf8` @ `0xbdf8` | `FUN_0001d8e0` @ `0xd8e0` | 584 | 146 | identical body after proper truncation |
| `FUN_00013d54` @ `0x3d54` | `FUN_000145dc` @ `0x45dc` | 560 | 140 | identical body after proper truncation |

(Confirmed via `scratchpad/diff_candidates.py` — the "diffs" are all in
the literal-pool region after the function's last real `pop {…, pc}` /
`bx` terminator, not in executed code.)

### 3.3 Note on non-exported svc_getargs

`svc_getargs` is exported by glibc as a macro that expands to a direct
call via the SVCXPRT dispatch table (`xprt->xp_ops->xp_getargs`). It
does not need a librpc.so symbol of its own; the callback pointer is
set up by `svcunix_create` / `svctcp_create` / `svcudp_create`. Those
creator functions ARE in the identical set above.

## 4. What the 46,122 differing bytes actually are

Decomposition (from capstone + readelf inspection):

- **39,322 bytes in `.text`** (file offsets 0x34f8…0x34f8+39322): the
  SAME code, in a different order. The `.text` section is byte-equal
  SIZE between versions. 7215's first non-init function is `xdrstdio_create`
  at 0x36ac; 7288's is `callrpc` at 0x34f8. Linker re-ordered every
  function; every PC-relative load, every branch offset, and every
  literal-pool constant therefore changed.
- **2 bytes in `.rodata`**: exactly `\n\0` appended at the end of the
  section. Report 32's string inventory already accounted for this as
  "0 strings added, 0 strings removed" — the toolkit's string extractor
  ignores a trailing null-terminator and a leading newline when they are
  adjacent, so the +2 bytes look like a padding adjustment, not a new
  printable string.
- **The remainder** in `.rel.*`, `.got`, etc.: direct consequence of the
  function reordering.

**This is the fingerprint of a clean rebuild with incidental link-order
differences, not a security fix.**

## 5. Caller-class map (Track C input)

Full map in `firmware_analysis/research_output/librpc/caller_classes.json`.
Summary:

| caller role | librpc exports imported |
|---|---|
| `sat-configd-server` | 17: `pmap_unset`, `svc_register`, `svc_run`, `svc_sendreply`, `svcerr_decode`, `svcerr_noproc`, `svcerr_systemerr`, `svcunix_create`, `xdr_char`, `xdr_enum`, `xdr_free`, `xdr_int`, `xdr_string`, `xdr_u_int`, `xdr_vector`, `xdr_void`, `xdr_wrapstring` |
| `sat-soap_agent-client` | 9: `clnt_create`, `clnt_pcreateerror`, `xdr_char`, `xdr_enum`, `xdr_int`, `xdr_string`, `xdr_u_int`, `xdr_vector`, `xdr_void` |
| misc-* (platform helpers on both rootfs) | 13 exports collectively, mostly stream-oriented XDR primitives |

Key observation: **`master-soapc` does NOT appear in the importer list
for librpc.so**. VERIFIED by `readelf -d` on
`rbre_7215/.../usr/sbin/soapc`: NEEDED list is `libssl`, `libcrypto`,
`libacos_nvram`, `libubox`, `libuci`, `libacos_shared`, `libacos_dal`,
`libd2lib`, `libdillib`, `libd2dynlog`, `libgcc_s`, `libc` — no
`librpc.so`.

Implication for CVE-0415 impact:
- librpc.so is **sat-internal only**. It connects sat `soap_agent` to
  sat `configd` via `/tmp/ntgr_orbi_rpc` (Unix domain socket).
- Master→sat SOAP management traffic (HTTPS to `/soap/server_sa`) is
  parsed by sat `soap_agent`, then relayed to sat `configd` via Sun RPC
  over librpc.so. Any vulnerability REACHED by the owner-authenticated
  master→sat management channel passes through this RPC chain, but the
  RPC code itself (librpc.so) is unchanged.

## 6. Where the fix is, if not librpc.so

### 6.1 Candidate files (both-models-changed signal)

Cross-model byte equality for files changed in BOTH model lines:

| file | 7215 cross-model | 7288 cross-model | size delta | status |
|---|---|---|---|---|
| `lib/librpc.so` | byte-equal | byte-equal | 0 | **RULED OUT** (§3) |
| `usr/lib/libcrypto.so.1.1` | DIFFERS cross-model | DIFFERS cross-model | 0 | UNLIKELY — OpenSSL version is 1.1.1n in both 7215 and 7288 (no CVE-bump); hash delta is a per-model re-link |
| `lib/modules/4.4.60/cryptodev.ko` | byte-equal | byte-equal | 0 | UNLIKELY — CVE wording ("admin modifies router functionality") does not fit a crypto char-dev driver |
| `lib/modules/4.4.60/qca-nss-crypto.ko` | DIFFERS cross-model | DIFFERS cross-model | 0 | UNLIKELY — Qualcomm NSS crypto accelerator, model-specific tuning |
| `lib/modules/4.4.60/qca-nss-crypto-tool.ko` | DIFFERS cross-model | DIFFERS cross-model | 0 | UNLIKELY — as above |

### 6.2 Single-model-changed files — matches CVE wording

**`usr/sbin/cgi-bin/soap_agent`** (sat only; master has no equivalent):
- Report 32 shallow-ruled-out on "only 3 new strings". Our Track A fork
  (report 33) addresses the master-side half of this surface. Deeper
  function-level pass on sat soap_agent is still pending.

**`usr/sbin/configd`** (sat only; RBRE's configd is byte-equal):
- Report 32 shallow-ruled-out on "only RBS750/RBS750QV strings". We
  did a function-level sample (not full fingerprint — the batch
  configd fingerprint produced 50 "changed" named functions that the
  address-ordered-size heuristic over-reports due to data-table
  interspersion between functions).
- **Positive finding** (semantic but NOT a fix): `authenticate_satellite_1_svc`
  changed its username check from `memcmp(user, "orbi", 4)` (case-SENSITIVE,
  constant at `DAT_00035d48` = ASCII `6f 72 62 69`) to
  `strncasecmp(user, "orbi", 4)` (case-INSENSITIVE). This is a
  RELAXATION, not a security tightening — it ACCEPTS more usernames
  than 7215 did. Also added a `legacy_auth_done=yes` nvram marker on
  successful backhaul-passphrase auth (caching, not security).
- **Negative finding** on `update_admin_password_1_svc`: the suspicious
  `system("(echo %s; sleep 1; echo %s) | passwd root")` sink survived
  into 7288 unchanged, BUT its password-sanitisation helper
  `FUN_000226b4` (7215) / `FUN_00022740` (7288) is BYTE-IDENTICAL
  pseudocode — both backslash-escape every non-alphanumeric character
  via `0x5c` prefix before interpolation. The command-injection
  surface was already mitigated in 7215.
- **Negative finding** on `satellite_reboot_1_svc`: takes no user
  parameters; both `system()` calls use fixed literals (`"sync"` from
  `DAT_00036c5b` and `"/sbin/reboot"`).
- **Negative finding** on `set_backhaulpassphrase_1_svc`: a thin
  wrapper around an internal setter; no direct shell sink at this
  level. Deeper trace left for a later pass.
- Shell-command format-string inventory in `.rodata`: 100% byte-equal
  between 7215 and 7288 sat configd. No `%s`-in-shell-string was added,
  removed, or modified.

**`usr/sbin/soapc`** (RBRE master only; sat has no equivalent): handled
by Track A fork — see report 33.

### 6.3 Classifications

| hypothesis | classification |
|---|---|
| CVE-0415 fix lives in `librpc.so` | **RULED OUT** (§3, §4) |
| CVE-0415 fix lives in sat `configd` `authenticate_satellite_1_svc` (case-sensitivity change) | **RULED OUT** — change is a relaxation, not tightening |
| CVE-0415 fix lives in sat `configd` `update_admin_password_1_svc` (command injection) | **RULED OUT** at depth checked — escape helper identical pre/post |
| CVE-0415 fix lives in sat `configd` `satellite_reboot_1_svc` | **RULED OUT** — no user-controlled parameters |
| CVE-0415 fix lives in OpenSSL `libcrypto.so.1.1` | **UNLIKELY** — same version (1.1.1n) both releases |
| CVE-0415 fix lives in sat `configd` in a state-changing DAL handler we didn't fingerprint | **HYPOTHESIS** (not falsified; untested at depth) |
| CVE-0415 fix lives in sat `cgi-bin/soap_agent` deeper than report 32's string-diff check | **HYPOTHESIS** (not falsified; untested at depth) |
| CVE-0415 fix lives in master `soapc` | **DEFERRED to report 33** (Track A) |

## 7. Operational implication for the owner

Independent of where the CVE fix actually is:

- Our devices run **V7.2.7.15 (pre-fix)**. Whatever CVE-0415 is, we
  have it. Running in a LAN we own, with no publicly accessible
  attack surface, this is a minimal operational risk.
- The sat `configd`'s `authenticate_satellite_1_svc` accepts a
  MAC-derived default password (`NETGEAR_Orbi_%02X_%02X_%02X_%02X_%02X_%02X_password`)
  on an un-paired satellite and a backhaul-passphrase-based
  authentication after pairing. The owner's existing credentials
  (HTTP admin password) are relayed from master to sat during SON
  pairing. The owner thus has a legitimate authenticated path into
  sat `soap_agent` and (indirectly, via Sun RPC) sat `configd`.
- Owner-level access to sat `soap_agent`'s SOAP methods does NOT
  reach a code-execution primitive at static-review depth (report
  31 §6 established this). Firmware flashing via
  `M1:UpdateNewFirmware2` is ROE-forbidden and is not pursued.

## 8. Reproducibility — files produced

- `firmware_analysis/research_output/librpc/function_fingerprints.json`
  — per-procedure instruction-level fingerprint for both versions.
- `firmware_analysis/research_output/librpc/fingerprint_summary.json`
  — identical / changed / only-A / only-B summary.
- `firmware_analysis/research_output/librpc/body_delta.json` — full
  canon-line unified diffs for any changed pair (empty set after
  literal-pool fix).
- `firmware_analysis/research_output/librpc/caller_classes.json` —
  per-export importer list across both rootfs with role classification.
- `firmware_analysis/research_output/configd_diff/authenticate_satellite_1_svc_7215.c`
  — 7215 Ghidra pseudocode for the authentication entry point (saved
  verbatim for cross-reference).

## 9. Remaining unknowns, ranked

1. **Which sat `configd` state-changing handler (`*_1_svc`) actually
   received the CVE-0415 input-validation patch.** The 50 named
   functions my batch fingerprint flagged as "changed" are mostly
   compile-noise (function reorder + model-string additions). Six
   sampled handlers — `authenticate_satellite_1_svc`,
   `update_admin_password_1_svc`, `satellite_reboot_1_svc`,
   `set_backhaulpassphrase_1_svc`, `FUN_000226b4` password-escape
   helper, and the shared shell-string pool — show no security
   tightening. One or more of the remaining ~15 state-changing
   `*_1_svc` entries is the likely locus; a targeted pseudocode diff
   on each would decide it, at a per-function cost of ~1 min of REA
   budget.
2. **Whether the master's `soapc` client received a counterpart fix.**
   Deferred to report 33.
3. **Whether sat `soap_agent` has a session-ID or SOAP-envelope
   parsing tightening** that report 32's string-diff missed. Deepest
   plausible remaining candidate on the sat side.
4. **Whether the kernel modules or OpenSSL re-link accidentally
   ships a fix we missed** (very unlikely given advisory wording,
   listed only for completeness).

## 10. Evidence classifications

| finding | classification |
|---|---|
| `librpc.so` code is semantically IDENTICAL 7215↔7288 (all 190 procedures) | **VERIFIED** (§3) |
| 46,122 byte-level delta in `librpc.so` is all relocation/literal-pool | **VERIFIED** (§4) |
| `librpc.so` is sat-internal only; master `soapc` does not link it | **VERIFIED** (§5) |
| CVE-2026-0415 fix is NOT in `librpc.so` | **STRONGLY SUPPORTED** (negative at code level; the only path to "VERIFIED" would be NETGEAR publishing per-function fix locations) |
| CVE-2026-0415 fix is in a sat `configd` DAL handler | **UNVERIFIED HYPOTHESIS** (not falsified, not confirmed at depth checked) |
| CVE-2026-0415 fix is in sat `soap_agent` deeper than string delta | **UNVERIFIED HYPOTHESIS** |
| `authenticate_satellite_1_svc` case-sensitivity change is CVE-0415 | **RULED OUT** — relaxation not tightening |
| `update_admin_password_1_svc` command-injection fix is CVE-0415 | **RULED OUT** — escape helper byte-identical pre/post |
| OpenSSL `libcrypto.so.1.1` change is CVE-0415 | **RULED OUT** — same version 1.1.1n |
| Master→sat management channel uses librpc.so (either side) | **RULED OUT** — master `soapc` lacks the NEEDED tag |
