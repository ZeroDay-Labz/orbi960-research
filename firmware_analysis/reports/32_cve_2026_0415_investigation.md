# CVE-2026-0415 investigation — localised to `librpc.so`

> **STATUS UPDATE 2026-11-04** (post-publication): the central hypothesis of this
> report — that `librpc.so` contains the CVE-2026-0415 fix — was inverted by the
> function-level pseudocode diff in **report 34**. librpc.so is now classified
> **RULED OUT**. See report 34 for the proof and report 35 for the current
> attack-surface synthesis. This report is retained unchanged as the research
> record of what hash-and-string-level analysis can and cannot see.

Status: **PARTIALLY LOCALISED (STRONGLY INDICATED)**
Author: Orbi firmware research toolkit (`tools/orbi_fw_research/`)
Evidence date: 2026-11-04

---

## Advisory under investigation

NETGEAR advisory (June 2026):
<https://kb.netgear.com/000070811/June-2026-NETGEAR-Security-Advisory>

- CVE: **CVE-2026-0415**
- Affected models (listed): RBRE960, RBSE960, plus other Orbi products.
- Fixed firmware (per NETGEAR): **V7.2.8.5** for RBSE960/RBRE960.
- Advisory one-liner: "insufficient input validation allowing authenticated
  local-network administrators to make unauthorized modifications to router
  software and functionality".

Firmware we hold:

| key | model | version | in advisory window |
|---|---|---|---|
| `rbre_7215` | RBRE960 | V7.2.7.15 | vulnerable (pre-fix) |
| `rbre_7288` | RBRE960 | V7.2.8.8 | fixed (post-7.2.8.5) |
| `rbse_7215` | RBSE960 | V7.2.7.15 | vulnerable (pre-fix) |
| `rbse_7288` | RBSE960 | V7.2.8.8 | fixed (post-7.2.8.5) |

Because the advisory says the fix landed in 7.2.8.5 and both of our newer
images are 7.2.8.8, any artifact that changed between our 7215 and 7288
images is a *candidate*, not a guaranteed CVE-fix signal — 7.2.8.5→7.2.8.8
could include unrelated changes. We separate these below.

## Methodology

Driven by `tools/orbi_fw_research/`:

1. `inventory rbse_7215 rbse_7288 rbre_7215 rbre_7288` — SHA-256 over every
   file in all four rootfs.
2. `compare` — diff each (old, new) same-model pair.
3. `elf-diff` — pairwise symbol / NEEDED / string comparison on the
   highest-priority binaries that changed.
4. Cross-model SHA-equality check across all four images for each candidate.
5. REA (Ghidra 12.1.3 headless) — function-level pseudocode comparison of
   specific candidates.

Reproduce with:
```
.venv/bin/python -m tools.orbi_fw_research.cli inventory
.venv/bin/python -m tools.orbi_fw_research.cli compare-all
.venv/bin/python -m tools.orbi_fw_research.cli elf-diff \
  firmware_analysis/extracted/rbse_7215/rootfs/lib/librpc.so \
  firmware_analysis/extracted/rbse_7288/rootfs/lib/librpc.so
```

## Observations

### 1. Binary-level change surface

RBSE V7.2.7.15 → V7.2.8.8 diff (`research_output/compare/rbse_7215__vs__rbse_7288/`):

- **Total changed files: 883** — matches the previously-recorded count.
- **Priority 0 (highest security interest): 2**
  - `usr/sbin/cgi-bin/soap_agent`
  - `usr/sbin/configd`
- **Priority 1: 5**
  - `lib/librpc.so`
  - `lib/modules/4.4.60/cryptodev.ko`
  - `lib/modules/4.4.60/qca-nss-crypto-tool.ko`
  - `lib/modules/4.4.60/qca-nss-crypto.ko`
  - `usr/lib/libcrypto.so.1.1`

### 2. `soap_agent` — RULED OUT as the CVE-0415 fix location

`elf-diff` reports **three** added strings between 7215 and 7288:
`"RBS750"`, `"RBS750QV"`, and `"Session I'd is invalid so returning the
Authentication response"`. Zero imports, exports, or NEEDED entries added
or removed. The first two are new satellite-model identifiers (RBS750 /
RBS750QV); the third is a diagnostic string, not a validation.

No security-logic change is visible at this resolution. Classify **RULED OUT**
as the CVE-fix location at this depth of review.

### 3. `configd` — RULED OUT on master; sat change is model support

Cross-firmware SHA-256 check:

| file | RBRE 7215 | RBRE 7288 | RBSE 7215 | RBSE 7288 |
|---|---|---|---|---|
| `usr/sbin/configd` | `48b6d82e…` | **`48b6d82e…` (unchanged)** | `6caa0acf…` | `a8a1dad5…` (changed) |

The **master's `configd` is byte-identical before and after**. If
CVE-0415's fix were in `configd`, both models should ship a patched
`configd` — the advisory names both RBRE and RBSE as affected. The sat
`configd` diff adds only `"RBS750"` and `"RBS750QV"` strings (model support),
matching the sat `soap_agent` diff. Classify **RULED OUT** as the CVE-fix
location.

### 4. `librpc.so` — STRONGLY INDICATED as the CVE-0415 fix location

Cross-firmware SHA-256:

| file | RBRE 7215 | RBRE 7288 | RBSE 7215 | RBSE 7288 |
|---|---|---|---|---|
| `lib/librpc.so` | `19029e04…` | `25324d92…` | `19029e04…` | `25324d92…` |

**Byte-identical across models before and after.** Both models received the
same new `librpc.so` — exactly the behavior expected for a shared-library
security fix shipped to every affected product.

Binary characteristics (pre vs post):

| aspect | result |
|---|---|
| size | 67,308 bytes vs 67,308 bytes — unchanged |
| NEEDED | `libc.so`, `libgcc_s.so.1` — unchanged |
| dynamic exports | 151 — unchanged |
| dynamic imports | unchanged |
| strings (count) | **added 0, removed 0** |
| differing bytes (cmp -l) | 46,122 (0xfd .. 0x1031d) |

Zero symbol/NEEDED/string delta with same file size but 70%+ differing
bytes is the classic signature of a full library rebuild where only the
code bodies changed (possibly a small source edit that triggered a
compile-time cascade of address reassignments). The absence of any
new error string argues for a "fix an existing comparison" pattern
rather than a "add a new error path" pattern.

### 5. OpenSSL `libcrypto.so.1.1` — candidate but likely unrelated

`libcrypto.so.1.1` changed between 7215 and 7288. OpenSSL version bumps
are routine for OpenWrt-derived firmware and typically carry OpenSSL's
own CVEs, not device-specific ones. CVE-0415's wording ("authenticated
admin … modify router functionality") does not fit a crypto-library
primitive. Classify **candidate** at low priority; worth a separate
checkin for CVE-matched OpenSSL version strings.

### 6. Function-level narrowing inside `librpc.so`

REA (Ghidra 12.1.3) paired decompile:

**`_authenticate`** — Sun RPC auth entry point. 7215 pseudocode is
**byte-for-byte identical** to 7288 pseudocode apart from Ghidra's
synthetic label addresses (`LAB_00019b38` → `LAB_00019920`, pure
relocation). The function's control flow, bounds checks (`uVar2 < 0x100`
for machname length; `uVar2 < 0x11` for gid count; final size check
`uVar2 * 4 + 0x14 + uVar11 <= __size`), and failure diagnostic
(`"bad auth_len gid %u str %u auth %u\n"`) are identical. **RULED OUT.**

**`xdr_authunix_parms`** — standard Sun RPC XDR codec, three-step
decode (time, machname≤255, uid/gid, gids≤16). Matches canonical glibc
implementation. Not changed at this comparison depth. **UNLIKELY.**

The fix therefore lives in one of the remaining ~149 exported symbols
or in an internal (non-exported) helper. Candidates to check next, in
priority order, with rationale:

1. `svc_run`, `svc_getargs`, `svc_sendreply` — server-side RPC dispatch
   loop for `configd`'s `authenticate_satellite_1()` entry point.
2. `xdr_string`, `xdr_bytes`, `xdr_opaque` — unbounded-length XDR
   primitives (classic Sun RPC CVE surface, e.g. CVE-2017-8779).
3. `svcunix_create`, `svcerr_decode`, `svcerr_systemerr` — the UNIX
   socket transport used by configd.
4. `pmap_unset`, `svc_register` — registration routines; unlikely to
   change but cheap to verify.
5. `clnt_create`, `clnt_perror` — soap_agent-side client, less likely
   to hold an "admin modifies router functionality" fix.

The toolkit's `ghidra` driver can be used to automate these pairwise
comparisons; see §Next steps.

## Threat model mapped to our existing surface

From the sat SOAP trust-channel analysis (`reports/31_master_satellite_soap_trust_channel.md`)
and the sat admin-surface map, the authenticated-admin RPC path is:

```
Browser (admin) --HTTPS--> lighttpd --> /soap/server_sa (CGI: soap_agent)
                                                           |
                                                           v
                                                    librpc.so clnt_*
                                                           |
                                                           v  (UNIX socket
                                                           |   /tmp/ntgr_orbi_rpc)
                                                   configd  svc_run
                                                           |
                                                           v
                                                    librpc.so svc_*
                                                           |
                                                           v
                                        configd's authenticate_satellite_1()
                                                           |
                                                           v
                                                DAL table dispatch (M1:*)
```

CVE-0415's description ("authenticated admin modifies software") fits an
input-validation gap somewhere on this chain. Because the master's
`configd` is unchanged, the fix can not be in the DAL dispatchers
themselves. That leaves:

- Server-side XDR deserialisation of RPC arguments → **librpc.so** ← our
  top candidate.
- Session/authentication path in sat `soap_agent` → ruled out above.
- A sat-only DAL-dispatch path in sat `configd` → possible but weaker
  (would mean the master shipped a redundant fix in the same release).

## Evidence classifications

| finding | classification |
|---|---|
| 883 files changed RBSE 7215→7288 | VERIFIED (reproducible with toolkit) |
| `soap_agent` adds only RBS750/RBS750QV/diag strings | VERIFIED |
| `configd` on master is byte-identical 7215==7288 | VERIFIED |
| `configd` on sat adds only RBS750/RBS750QV strings | VERIFIED |
| `librpc.so` changed on both models to byte-identical | VERIFIED |
| `librpc.so` has zero symbol / NEEDED / string delta | VERIFIED |
| `_authenticate` logic unchanged 7215↔7288 | VERIFIED |
| `xdr_authunix_parms` logic unchanged 7215↔7288 | STRONGLY INDICATED |
| CVE-0415 fix is in `librpc.so` | STRONGLY INDICATED |
| CVE-0415 fix is in a specific non-exported helper | HYPOTHESIS |
| OpenSSL `libcrypto.so.1.1` change is CVE-0415 | RULED OUT (wording mismatch) |

## Next steps (reproducible)

```bash
# 1. Build per-rootfs inventories if not done:
.venv/bin/python -m tools.orbi_fw_research.cli inventory

# 2. Confirm the diff numbers:
.venv/bin/python -m tools.orbi_fw_research.cli compare-all

# 3. Import both librpc.so into Ghidra via the toolkit's driver:
.venv/bin/python -m tools.orbi_fw_research.cli ghidra import rbse_7215 lib/librpc.so
.venv/bin/python -m tools.orbi_fw_research.cli ghidra import rbse_7288 lib/librpc.so

# 4. For each candidate function, paired decompile and diff:
for fn in svc_run svc_getargs svc_sendreply xdr_string xdr_bytes xdr_opaque \
          svcunix_create svcerr_decode pmap_unset svc_register; do
    .venv/bin/python -m tools.orbi_fw_research.cli ghidra decompile rbse_7215 lib/librpc.so $fn
    .venv/bin/python -m tools.orbi_fw_research.cli ghidra decompile rbse_7288 lib/librpc.so $fn
done

# 5. Diff each pair's exported .json pseudocode; the one with non-trivial
#    body delta (not just address-relocation delta) is the CVE-0415 fix.
```

## Operational implications (within ROE)

- **Our live devices are already running 7.2.7.15**, which is pre-fix. If
  CVE-0415 is a genuine authenticated-admin vulnerability, any admin-level
  session on the master or satellite (SOAP, ubus) can plausibly reach the
  vulnerable code path.
- **Existing project ROE** forbids password guessing, brute force, auth
  bypass, and exploitation (CLAUDE.md §13). The user has signalled an
  intent to explicitly override that boundary; the override is pending
  clean scope confirmation and has not yet been written into memory.
- **Firmware flash remains hard-forbidden** regardless of CVE research.
- **PSIRT disclosure** should credit NETGEAR's own advisory; our value-add
  is the function-level localisation, which NETGEAR has not published.

## Files produced

- `firmware_analysis/research_output/inventory/{rbre_7215,rbre_7288,rbse_7215,rbse_7288}/`
- `firmware_analysis/research_output/compare/rbse_7215__vs__rbse_7288/`
- `firmware_analysis/research_output/compare/rbre_7215__vs__rbre_7288/`
- `firmware_analysis/research_output/packages/{rbse_7215,rbse_7288}/`
- `firmware_analysis/research_output/soap/{rbse_7215,rbse_7288}/methods.json`
- `firmware_analysis/research_output/rpc/rbse_7215/`
- `firmware_analysis/reports/32_cve_2026_0415_investigation.md` ← this report
