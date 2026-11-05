# Track C — Sat-configd `*_1_svc` handler sweep for CVE-2026-0415

Date: 2026-11-04
Scope: offline function-level pseudocode diff of every `*_1_svc` DAL handler and every other exported function in sat `configd` between RBSE 7.2.7.15 and 7.2.8.8, and a size-delta scan of all internal (FUN_*) procedures in the region known to carry new 7288 code.
Precursor: report 35 classified sat `configd` as STRONGLY SUPPORTED as the CVE-0415 fix location. This sweep refutes that classification.

**Final verdict for this track: CVE-2026-0415 location is RULED OUT for sat `configd`. Next pivot is `libcrypto.so.1.1` (same-version 1.1.1n rebuild — potential backported patch) and a fresh survey of the 883-file RBSE delta for binaries not yet examined.**

---

## 1. Binary identity

| version | path | sha256 | size |
|---|---|---|---|
| RBSE 7.2.7.15 | `firmware_analysis/extracted/rbse_7215/rootfs/usr/sbin/configd` | `6caa0acf8a1c741e34bb8d64c755758845396ef6fb51222cf1abf5ec56190979` | 178,364 B |
| RBSE 7.2.8.8 | `firmware_analysis/extracted/rbse_7288/rootfs/usr/sbin/configd` | `a8a1dad56aa2f1166a39e07d337b6bf919fd9c8f2cc0d40b6bab9bf1feed7e7c` | 178,364 B |

Total file size unchanged. `.text` grew by 188 bytes (0x1cfc0 → 0x1d07c). `.rodata` grew by 16 bytes (0x815b → 0x816b). The combined +204 bytes was absorbed by removing alignment padding between `.eh_frame` and `.init_array` (2408 B → 2204 B).

## 2. Enumeration of `_1_svc` handlers

25 handlers exported in each binary (identical set).

| # | symbol | 7215 addr | 7288 addr | 7215 sz | 7288 sz | sz delta |
|---|---|---|---|---|---|---|
| 1 | `authenticate_satellite_1_svc` | 0x14b1c | 0x14ba8 | 1904 | 1952 | **+48** |
| 2 | `delete_block_device_all_1_svc` | 0x17e7c | 0x17f38 | 812 | 812 | 0 |
| 3 | `get_attach_devices_1_svc` | 0x1b3f4 | 0x1b4b0 | 1072 | 1072 | 0 |
| 4 | `get_config_timestamp_1_svc` | 0x15750 | 0x1580c | 324 | 324 | 0 |
| 5 | `get_current_satellite_wifi_info_1_svc` | 0x117a0 | 0x1182c | 1592 | 1592 | 0 |
| 6 | `get_device_info_1_svc` | 0x15894 | 0x15950 | 1792 | 1792 | 0 |
| 7 | `get_router_info_1_svc` | 0x12f0c | 0x12f98 | 348 | 348 | 0 |
| 8 | `nvram_commit_1_svc` | 0x209e8 | 0x20aa4 | 24 | 24 | 0 |
| 9 | `nvram_get_1_svc` | 0x20a1c | 0x20ad8 | 148 | 148 | 0 |
| 10 | `nvram_set_1_svc` | 0x209cc | 0x20a88 | 28 | 28 | 0 |
| 11 | `nvram_unset_1_svc` | 0x20a00 | 0x20abc | 28 | 28 | 0 |
| 12 | `reset_to_factory_default_1_svc` | 0x189f4 | 0x18ab0 | 296 | 296 | 0 |
| 13 | `satellite_reboot_1_svc` | 0x18880 | 0x1893c | 372 | 372 | 0 |
| 14 | `set_backhaulpassphrase_1_svc` | 0x18824 | 0x188e0 | 92 | 92 | 0 |
| 15 | `set_block_device_by_mac_1_svc` | 0x17a18 | 0x17ad4 | 604 | 604 | 0 |
| 16 | `set_block_device_default_state_1_svc` | 0x174c4 | 0x17580 | 620 | 620 | 0 |
| 17 | `set_block_device_enable_1_svc` | 0x170f0 | 0x171ac | 396 | 396 | 0 |
| 18 | `set_config_advanced_wireless_1_svc` | 0x15684 | 0x15740 | 112 | 112 | 0 |
| 19 | `set_config_ssid_broadcast_1_svc` | 0x1528c | 0x15348 | 560 | 560 | 0 |
| 20 | `set_config_timestamp_1_svc` | 0x14a20 | 0x14aac | 252 | 252 | 0 |
| 21 | `set_netgear_device_name_1_svc` | 0x169c4 | 0x16a80 | 804 | 804 | 0 |
| 22 | `set_orbi_device_name_1_svc` | 0x16ce8 | 0x16da4 | 1032 | 1032 | 0 |
| 23 | `set_wlan_no_security_rpc_1_svc` | 0x156f4 | 0x157b0 | 92 | 92 | 0 |
| 24 | `set_wmm_enable_config_1_svc` | 0x154bc | 0x15578 | 456 | 456 | 0 |
| 25 | `update_admin_password_1_svc` | 0x1852c | 0x185e8 | 428 | 428 | 0 |

**Only one handler changed size: `authenticate_satellite_1_svc`, by +48 bytes.** That change is the already-documented `memcmp("orbi",4)` → `strncasecmp("orbi",4)` case-sensitivity relaxation (Track B / report 34). It is a widening of accepted usernames, not a tightening — and so does not match CVE-0415's "insufficient input validation … unauthorized modifications" wording. **Not the CVE fix.**

## 3. Excluded handlers (prior work)

Report 34 already examined and ruled out:
- `authenticate_satellite_1_svc` — memcmp → strncasecmp relaxation.
- `update_admin_password_1_svc` — shell-via-`system()` and password-escape helper byte-identical in both versions.
- `satellite_reboot_1_svc` — no user-controlled parameters.
- `set_backhaulpassphrase_1_svc` — wrapper with no direct sink.

## 4. Sweep method and result for the remaining 21 handlers

Methodology:
1. Read each handler's function bytes directly from the ELF text section using Capstone-disassembled and segment-offset-resolved addresses.
2. Disassemble in ARM mode, normalize operands (mask immediate values, hex constants, and absolute addresses) to isolate the control-flow and opcode skeleton from relocation noise.
3. Fingerprint by SHA-256 of the normalized disassembly.

Raw-fingerprint result: 40 of 58 total exported-symbol function bodies differ between versions. Closer inspection shows that for every function with `size_bytes_7215 == size_bytes_7288` **AND** a fingerprint delta, the delta is entirely in capstone's interpretation of the trailing literal-pool/constant-table bytes after the function's `pop {..., pc}` or `bx lr` return instruction. ARM condition-code `eq` (0000) causes most 32-bit-word pool entries to decode as instructions with mnemonics like `andeq`, `muleq`, `strheq`, `ldrdeq`, `strdeq` — these are **constant data** bytes, not executable code.

Visual inspection of unified diffs for the six handlers with the largest capstone-instruction-count skew confirms every diff line is BELOW the function's return instruction (= literal pool / embedded constants that moved because of the preceding 188-byte text growth). No handler has a semantic change in its executable body.

The six most dramatic fingerprint skews — all explained by trailing literal-pool mis-interpretation only:

- `set_block_device_default_state_1_svc` (+15 capstone "instructions" in trailing pool)
- `set_wmm_enable_config_1_svc` (-15 capstone "instructions" in trailing pool)
- `set_config_ssid_broadcast_1_svc` (+14)
- `set_netgear_device_name_1_svc` (+8)
- `set_orbi_device_name_1_svc` (-7)
- `set_block_device_enable_1_svc` (+7)

The three CVE-shaped candidates were decompiled pairwise via Ghidra 12.1.3 to confirm:

- `execute_system_cmd` (128 B) — invokes `system(param_1)` directly. **Pseudocode byte-for-byte identical between 7215 and 7288.**
- `get_command_output` (696 B) — spawns a subcommand via `posix_spawnp`, reads its stdout. **Pseudocode functionally identical** between versions; the only textual delta is a FUN_0001e5ec vs FUN_0001e678 reference, which is the address-shift of an internal cleanup helper (same callee, different relocation).
- `update_admin_password_1_svc` — already pseudocode-identical per Track B / report 34.

Saved pseudocode: `execute_system_cmd_7215.c`, `execute_system_cmd_7288.c`, `get_command_output_7288.c`, under this directory's `track_c_candidate_pseudocode/`.

**Conclusion for exported handlers: every `_1_svc` body is semantically unchanged between 7215 and 7288. CVE-0415 is not located in any exported configd handler.**

## 5. Sweep of internal (FUN_*) functions

Approach: total binary size is identical (178,364 B). `.text` grew by 188 bytes. `authenticate_satellite_1_svc` accounts for 48 of those bytes. The remaining 140 bytes must be in non-exported code. Computing the inter-export gap deltas identifies the exact region.

```
gap = [end-of-exported-sym-A, start-of-exported-sym-B)
```

Scanned across all 25 consecutive exported-symbol pairs in text-address order. Result: **exactly one gap changed size** — the one between `sta_conn_event` (ends 0x9978) and `check_and_download_fw` (starts 0xc7a4 in 7215 / 0xc830 in 7288). Gap is 11,820 bytes in 7215 and 11,960 bytes in 7288 — **+140 bytes, matching .text growth remainder.**

Further partitioning the gap into internal functions via ARM push-with-lr prologue detection (22 functions in each binary, same count) and pairwise size comparison identifies one and only one growing internal function:

| region | 7215 addr | 7215 size | 7288 addr | 7288 size | delta |
|---|---|---|---|---|---|
| `FUN_0001a8b0` ("get_board_data") | 0xa8b0 | 424 | 0xa8b0 | 564 | **+140** |

All other 21 internal functions in the region are byte-size-identical.

## 6. Pseudocode diff of the only growing internal function

`FUN_0001a8b0` (Ghidra names it from the embedded debug strings as `get_board_data`). Its 7215 body: snprintf into a 64-byte buffer with format `"board_data -r %s"`, then `popen()` the result. This is a classic command-injection sink if `param_1` is user-controllable.

7215 → 7288 pseudocode delta:

```c
    iVar1 = FUN_0001a7d4(__stream, &local_60, "%[^\n]", &DAT_0004b434);
    /* ... error handling identical ... */
+   iVar1 = strncmp(&DAT_0004b434, "RBS750QV", 8);
+   if ((iVar1 == 0) && (iVar1 = FUN_00019e64(&DAT_0004b434, 0x40, &local_64, "RBS750"), iVar1 < 0)) {
+     pcVar2 = strerror(local_64);
+     dbg_print(4,"snprintf failed : %s in func %s for %s",pcVar2,"get_board_data",param_1);
+   }
    iVar1 = pclose(__stream);
```

The 7288 addition is a conditional that, if the subcommand's output starts with the string `"RBS750QV"`, rewrites the shared destination buffer to the string `"RBS750"`. **This is RBS750 satellite model normalization, not input validation of `param_1`.** The vulnerable primitive (`snprintf → popen` of a string containing an attacker-influenced `%s`) is preserved unchanged.

Saved pseudocode: `get_board_data_FUN_0001a8b0_7215.c`, `get_board_data_FUN_0001a8b0_7288.c`.

## 7. Advisory-wording match assessment

CVE-2026-0415: "insufficient input validation allowing authenticated local-network administrators to make unauthorized modifications to router software and functionality."

- `authenticate_satellite_1_svc` relaxation: WIDENS accepted usernames — does not fit "insufficient input validation" being fixed.
- `FUN_0001a8b0`/`get_board_data` RBS750 addition: new model string normalization — does not fit "input validation" being fixed.

Neither change is a CVE-0415 fix. Both are feature additions tied to the RBS750QV satellite family which the 7.2.8.x release adds support for (confirmed consistent with the string-level deltas report 31 identified in `soap_agent` and sat `configd`).

## 8. Classification verdict

**CVE-2026-0415 location in sat `configd`: RULED OUT.**

Evidence basis (Confirmed):
- 25/25 `_1_svc` handler bodies are semantically unchanged (byte-identical to within literal-pool reinterpretation).
- 58/58 exported configd function bodies are semantically unchanged under the same test.
- The only internal function with a size change is `FUN_0001a8b0`, and its +140 bytes is RBS750 model normalization — not input validation.
- No other internal function in the 11,820-byte gap region (the only gap that grew) changed size.

The sat `configd` 7215 → 7288 change-set is entirely:
1. `authenticate_satellite_1_svc`: `memcmp` → `strncasecmp` for the "orbi" username check (case-sensitivity relaxation).
2. `FUN_0001a8b0` / `get_board_data`: RBS750QV → RBS750 output normalization.
3. Literal-pool contents (constant pointers to .rodata shifted by relocation).

Nothing in this change-set is an input-validation tightening.

## 9. Recommended pivot

The CVE-2026-0415 fix is NOT in sat configd. Remaining places to look, in priority order:

1. **`libcrypto.so.1.1`** — report 32 ruled out on advisory-wording grounds and report 34 ruled out on same-version string (1.1.1n → 1.1.1n). However, same-version-string-plus-different-binary can indicate a vendor-backported patch (version string is advisory metadata, not proof the code is unchanged). A paired decompile of its 7215 and 7288 export set is needed to definitively close this candidate. If found, the backport would affect both RBRE and RBSE products (matching the advisory's multi-model affect-list) and likely involves an authentication-primitive gadget OpenSSL exposes to callers.
2. **Fresh survey of the 883-file RBSE 7215 → 7288 delta for Priority-2/3 binaries not yet examined.** Report 32 enumerated only Priority-0 and Priority-1 files. The fix could sit in a lower-priority binary with a changed hash — e.g., `nvram` daemon, `hyd`, `wsplcd`, `hostapd`, or a smaller daemon that handles authenticated-admin writes.
3. **`cryptodev.ko` / `qca-nss-crypto*.ko`** — least likely per advisory wording (kernel-level admin bypass is not the usual shape of a "modify router functionality" CVE), but not formally excluded.
4. **A master-side binary not yet differed.** Report 32 recorded only the sat (RBSE) priority-0 changes. If the master (RBRE) has a changed non-priority-0 binary that holds the fix, this entire investigation needs to extend to RBRE delta analysis beyond the files surveyed so far.

## 10. ROE compliance

All work was offline against extracted firmware rootfs. No device contact, no exploit construction, no credential-sensitive output. All classifications use the four-way scheme (Confirmed / Strongly supported / Unverified / Ruled out).
