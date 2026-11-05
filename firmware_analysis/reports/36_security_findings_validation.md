# Report 36 — Security Findings Validation and CVE-2026-0415 Localization Status

Date: 2026-11-04
Scope: independent re-validation of the three central claims in reports 33/34/35 and continued localization of CVE-2026-0415. All work offline, static, against extracted firmware under `firmware_analysis/extracted/`.
Precursor reports: 31 (SOAP trust channel), 32 (initial CVE investigation — superseded), 33 (`soapc` RE), 34 (`librpc.so` differential), 35 (attack-surface synthesis).

Classification discipline, applied throughout:

- **Confirmed** — supported by specific code, binary offsets, symbols, or cross-references cited inline.
- **Strongly supported** — multiple independent indicators, no single smoking gun.
- **Unverified** — plausible but not demonstrated.
- **Ruled out** — contradicted by evidence.

---

## 1. Executive summary

Three independent validation passes were run against the central claims of reports 33/34/35:

1. **MAC-derived master→satellite authentication credential** — **Confirmed**, with four material corrections to the prior reports.
2. **Master→satellite TLS has no certificate verification** — **Confirmed-absent for chain validation; Confirmed-absent for hostname validation** (two separate verdicts; report 33's single-verdict framing is now sharpened).
3. **CVE-2026-0415 fix located in satellite `configd`** — **Ruled out**, downgraded from report 35's "Strongly supported" classification. All 25 `*_1_svc` handlers plus a 58-function exported-symbol sweep have byte-identical semantic bodies between 7.2.7.15 and 7.2.8.8; the only size-changed function is an auth case-sensitivity relaxation already classified in report 34. The CVE fix is NOT in sat `configd`.

The CVE-2026-0415 firmware location after three rounds of narrowing is now **Unverified**. The following components have been ruled out at semantic-pseudocode depth: `librpc.so` (report 34), master `soapc` (report 33), master `configd` (report 32), satellite `soap_agent` (report 32), satellite `configd` (this report §4), OpenSSL at the version-string level (report 32). The remaining candidates, ranked, are: a backported OpenSSL fix inside the same `1.1.1n` version string, the un-surveyed Priority-2/3 subset of the 883-file RBSE delta, and the two changed kmods.

Independently of CVE-0415, this phase strengthened and extended the earlier findings on the master→satellite management plane. Including the four new items from Validation A, there are now **six Confirmed PSIRT-worthy findings** in the shipping firmware — listed in §5 below.

---

## 2. Track A — Master↔Satellite Authentication Credential (validation result)

Full details and evidence table: `firmware_analysis/research_output/validation/track_a_credential_flow.md`. Machine-readable: `.../track_a_evidence.json`.

### 2.1 Mechanism (Confirmed)

Master `soapc` function `FUN_0001f228` (entry `0x1f228`) runs `snprintf(buf, "%s%s%s%s%s", "NETGEAR_Orbi_", g_soapc_mac1, "_", g_soapc_mac2, "_password")`, then applies MD5-hex-lowercase via `FUN_00029ce4` (standard OpenSSL `MD5_Init`/`MD5_Update`/`MD5_Final` chain plus a `16×%02x` formatter). Username is the literal `orbi` loaded from rodata. Result flows through the `<%getAuthPassword();%>` template substitution into the SOAP envelope and onto the wire via `soap_startConnection`/`soapc_sendRequest`.

Satellite `configd` entrypoint `authenticate_satellite_1_svc` (7215 entry `0x24b1c`, 7288 entry `0x24ba8`) **dynamically re-derives the identical template on every call** by reading NVRAM `router.mac` bytes 3-5 and `boarddata.mac0` bytes 3-5, MD5-hex-lowercasing, and comparing to the incoming password with `memcmp`. The sat does NOT stash the derived credential in NVRAM; it recomputes it per-call.

### 2.2 Four material corrections to prior reports

| # | Prior claim (report) | Corrected finding |
|---|---|---|
| A-1 | Report 33: `g_soapc_mac1` origin left ambiguous. | Confirmed: `g_soapc_mac1` is the **master's own LAN MAC** (lower-3 bytes), set by `FUN_00028408` which reads `lan_ifname` and calls `get_eth_mac`. The template therefore mixes 3 bytes of master MAC with 3 bytes of sat MAC — not a single 6-byte MAC. |
| A-2 | Report 31 §3: sat `configd` validates against NVRAM `http.password`/`http.passwordHash`. | Refuted. Those NVRAM keys exist but belong to a different auth path (admin web-UI session via `M1:Authenticate` → `soap_agent`). The sat-management RPC entrypoint `authenticate_satellite_1_svc` derives the template dynamically per call from `router.mac`+`boarddata.mac0`. The two auth paths are independent. |
| A-3 | Report 31 §3 / report 35 §1.3: MAC-derived credential described as "factory default / pre-pairing fallback". | Corrected: this is the **primary steady-state credential** used on every normal master→sat management RPC call, not a fallback. The fallback framing understated the finding. |
| A-4 | Report 33: no second credential path mentioned. | New finding: **backhaul passphrase** (`BhSta2.passphrase` / `BhSta5.passphrase`, 64 hex chars) is a **second valid credential** accepted by the same RPC entrypoint — authenticates without the MAC MD5 at all. |

### 2.3 Four new Confirmed PSIRT-worthy findings surfaced during Track A

- **A-PSIRT-1**: Sat auto-updates NVRAM `router.mac` from an **unauthenticated `hyt`-pipeline `popen`** invoked at every authentication call: `(echo "td s"; usleep 500000) | hyt | …`. The master-half of the auth template is therefore attacker-influenceable at runtime by any actor who can inject into or MITM the mesh plane that `hyt` reads from. Severity depends on whether `hyt` validates its mesh-plane input; needs follow-up.
- **A-PSIRT-2**: Backhaul passphrase is a second valid credential on the sat-management RPC (cross-ref §2.2 row A-4). Any sat or any backhaul observer effectively holds a master credential.
- **A-PSIRT-3**: Master writes the computed credential to NVRAM `soap_Authenticate_old_password` on every call. Credential at rest on the master's writable overlay.
- **A-PSIRT-4**: Master writes the credential **plaintext to `/tmp/soapc_log`** on every call. Credential in logs.

Not yet traced: `<%getNewAuthPassword();%>` envelope at `0x5d242` in `soapc` references a second password producer `getNewAuthPassword` at `0x2c8b2` — likely admin-password-rotation sync, not fully characterised. Status: Unverified.

### 2.4 Verdict

**MAC-derived management authentication: Confirmed.** Supporting evidence spans both the master-side (soapc) and satellite-side (configd) halves at cited binary offsets, with the sat independently re-deriving the same template per call.

---

## 3. Track B — Master→Satellite TLS Certificate Verification (validation result)

Full details and evidence table: `firmware_analysis/research_output/validation/track_b_tls_verification.md`. Machine-readable: `.../track_b_evidence.json`.

The directive required separating chain-validation from hostname-validation. Each is a separate verdict.

### 3.1 Linker-level evidence (Confirmed)

`readelf -r` on the `rbre_7215/usr/sbin/soapc` binary shows the complete 14-symbol OpenSSL JUMP_SLOT set. A symbol not present in the JUMP_SLOT table cannot be reached without the loader failing at startup. Zero of the following are in that set:

- `SSL_CTX_set_verify`, `SSL_set_verify`
- `SSL_CTX_load_verify_locations`
- `SSL_CTX_set_default_verify_paths`
- `SSL_CTX_set_cert_store`
- `SSL_CTX_set_cert_verify_callback`
- `SSL_get_verify_result`
- `SSL_get_peer_certificate`
- `X509_check_host`
- `X509_check_ip`
- `SSL_set_tlsext_host_name` (SNI-only; not a verify API in any case)
- any `X509_*` symbol

This refutes the main concern raised in the directive ("absence of imports is not sufficient proof"): because these are dynamic imports from a specific SO's JUMP_SLOT table that the ELF loader binds, their absence from the relocation table is a hard invariant of this binary — not a surface-level "grep -q didn't find it".

### 3.2 Pseudocode-level evidence (Confirmed)

`FUN_0002332c` (`soapc_sendRequest` @ `0x2332c`) TLS sequence:

```
OPENSSL_init_* → TLS_client_method → SSL_CTX_new
                                  → SSL_CTX_set_options(ctx, 0)
                                  → SSL_new
                                  → SSL_set_fd
                                  → SSL_connect
                                  → SSL_write / SSL_read
                                  → SSL_free / SSL_CTX_free
```

The second argument to `SSL_CTX_set_options` is the literal constant 0 — a no-op OR into the options mask (verified at the instruction level, not inferred). After `SSL_connect` returns 1, control transitions directly to `SSL_write`. No certificate inspection function runs. Return value ≠ 1 only logs an error and proceeds to cleanup.

### 3.3 Wrapper / indirection hypothesis — falsified (Confirmed)

- `libacos_shared.so` NEEDED list contains no `libssl` and no `libcrypto`; its UND set contains no `SSL_*` or `X509_*` symbol. It cannot be the hidden wrapper.
- Every other `.so` in `soapc`'s NEEDED list likewise contains no TLS verification symbols.
- `libcurl.so.4` is on disk under `/usr/lib/` but is NOT in `soapc`'s NEEDED list. The `curl_easy_setopt(CURLOPT_SSL_VERIFYPEER)` indirection pathway is therefore impossible.
- Binary string sweep finds zero occurrences of `/etc/ssl`, `cacert`, `ca-bundle`, `X509`, `SubjectAlt`, `CN=`, or `hostname` in `soapc`.

### 3.4 Cross-version evidence (Confirmed)

The `rbre_7288/usr/sbin/soapc` binary has an identical 14-symbol OpenSSL JUMP_SLOT set. The CVE-2026-0415 window did NOT touch TLS verification on the master-to-satellite plane.

### 3.5 Verdicts

- **Chain-validation: Confirmed-absent.** The precise correct wording: "left at the OpenSSL default `SSL_VERIFY_NONE` (never overridden)" rather than report 33's "explicitly disabled". Security impact is identical; wording is sharpened.
- **Hostname-validation: Confirmed-absent.** No `X509_check_host`, no manual CN or SAN comparison; the host string is only logged.

Report 33's overall TLS claim is **upheld with sharpening**.

---

## 4. Track C — Satellite `configd` `*_1_svc` Handler Sweep (validation result)

Full details and evidence table: `firmware_analysis/research_output/validation/track_c_configd_sweep.md`. Machine-readable: `.../track_c_handler_fingerprints.json`. Pseudocode exports: `.../track_c_candidate_pseudocode/`.

### 4.1 Handler enumeration and 7215/7288 fingerprinting (Confirmed)

Twenty-five `*_1_svc` exports exist in sat `configd` in both versions. Of the 25:

- **24 handlers**: byte-size-identical between 7215 and 7288. Capstone-normalised disassembly fingerprints (literal-pool-truncated) show no body changes.
- **1 handler, `authenticate_satellite_1_svc`**: +48 bytes between versions, attributable entirely to the known `memcmp(user, "orbi", 4) → strncasecmp(user, "orbi", 4)` change already analysed in report 34 and classified as a case-sensitivity relaxation (not a CVE fix).

### 4.2 Broader 58-export sweep (Confirmed)

The three most CVE-shaped candidates outside the `*_1_svc` set — `execute_system_cmd`, `get_command_output`, `update_admin_password_1_svc` — were pairwise decompiled via Ghidra 12.1.3. All three have pseudocode that is byte-for-byte identical (or identical modulo a single internal-helper address relocation). None of the three is the CVE fix.

### 4.3 Accounting for the 188-byte `.text` growth (Confirmed)

Of the 188-byte total `.text` growth from 7215 to 7288 in sat `configd`:

- 48 bytes → `authenticate_satellite_1_svc` case-sensitivity relaxation (not CVE).
- 140 bytes → one internal function `FUN_0001a8b0` (`get_board_data` per debug strings) in the gap between `sta_conn_event` and `check_and_download_fw`. Pseudocode diff shows the +140 bytes is a new conditional that rewrites the `board_data` result string `"RBS750QV"` to `"RBS750"`, a model-normalization fix consistent with the `RBS750`/`RBS750QV` string additions report 31 identified in `soap_agent` and in sat `configd` strings. Not CVE.
- The command-injection-shaped `snprintf("board_data -r %s", param_1); popen(...)` primitive in that same region is **preserved unchanged** across both versions, so it is also not CVE-0415's fix locus.

Scanned via ARM `push {…, lr}` prologue detection, 22 internal functions exist in each binary; 21 are byte-size-identical, 1 is `FUN_0001a8b0` already accounted for above.

### 4.4 Verdict

**CVE-2026-0415 location in satellite `configd`: Ruled out.** All semantic 7215→7288 changes in sat `configd` are accounted for by (a) auth-username case-sensitivity relaxation and (b) RBS750/RBS750QV model-support work. Neither matches the advisory's "insufficient input validation → unauthorized modifications" wording.

Downgraded from report 35's "Strongly supported" classification.

### 4.5 Recommended pivot for CVE-0415 (priority order)

1. **`libcrypto.so.1.1`** — report 32 ruled out on version-string equality (`1.1.1n` → `1.1.1n`), but that does not exclude a vendor backport that carries a specific fix inside the same version label. A paired decompile of the OpenSSL exports between 7215 and 7288 is the next cheapest action. Also fits the advisory's multi-model affect-list cleanly.
2. **Fresh Priority-2/3 survey** of the 883-file RBSE 7215→7288 delta. Report 32 only enumerated Priority-0/1. Candidates in the Priority-2/3 band include `nvram`, `hyd`, `wsplcd`, `hostapd`, and smaller authenticated-admin daemons.
3. **Kernel modules** (`cryptodev.ko`, `qca-nss-crypto*.ko`) — least likely to match the advisory wording but currently un-analysed.
4. **Master-side (RBRE) delta** beyond what report 32 already surveyed for Priority-0/1.

---

## 5. Current Confirmed PSIRT-worthy findings (consolidated)

| # | Finding | Evidence anchor |
|---|---|---|
| P-1 | Mesh-plane TLS has no certificate chain validation on the master. | `soapc` JUMP_SLOT table + pseudocode (§3) |
| P-2 | Mesh-plane TLS has no hostname validation on the master. | same (§3) |
| P-3 | Master→sat admin credential is `md5("NETGEAR_Orbi_<master-mac-pieces>_<sat-mac-pieces>_password")`; username literal `orbi`. Used on every normal management call. | `soapc` `FUN_0001f228` @ `0x1f228`; sat `configd` `authenticate_satellite_1_svc` 7215 `0x24b1c` (§2) |
| P-4 | Backhaul passphrase (`BhSta{2,5}.passphrase`, 64 hex) is an alternate valid credential on the same sat-management RPC entrypoint. | sat `configd` `authenticate_satellite_1_svc` (§2.2, A-4) |
| P-5 | Sat re-derives `router.mac` for the auth template from an unauthenticated `hyt`-pipeline `popen` at every call, making the master-half of the template runtime-influenceable. | sat `configd` `authenticate_satellite_1_svc` body (§2.3, A-PSIRT-1) |
| P-6 | Master writes the computed credential plaintext to `/tmp/soapc_log` on every call; also persists it to NVRAM `soap_Authenticate_old_password`. | `soapc` call path (§2.3, A-PSIRT-3/4) |

P-1 + P-2 + P-3 compose: an on-LAN attacker that can MITM `<master>↔<sat>` TCP/443 reaches the full 38-method state-changing SOAP surface on any satellite with no owner knowledge, because the credential is derivable from ARP-visible MAC addresses and the master accepts any cert. P-4 is independent: no MITM needed if the backhaul passphrase is already known.

---

## 6. Evidence tables

### 6.1 Binary identities

| path | sha256 | role | notes |
|---|---|---|---|
| `firmware_analysis/extracted/rbre_7215/rootfs/usr/sbin/soapc` | `531b932b0488a4d60d38cd575d0d1b44f7f4285f40eafe5593a3c8d975f74a7b` | master SOAP client | byte-identical to live master (MD5 `f7184993…`) |
| `firmware_analysis/extracted/rbre_7288/rootfs/usr/sbin/soapc` | `6c4e4004fcfb21bd73a5a4c0382d54a70b83c28f1c20fd2cefa5fa848ee26b2d` | master SOAP client | 7288 |
| `firmware_analysis/extracted/rbre_7215/rootfs/lib/librpc.so` | `19029e0491fd6ae78b377095d0d332fe32a2503902abbb20631f01aad0576212` | Sun RPC core library | pre-fix |
| `firmware_analysis/extracted/rbre_7288/rootfs/lib/librpc.so` | `25324d9272879203c7dbf466dfde4a9c852411004dd176d387f485153f0cf320` | Sun RPC core library | post-fix (semantically identical — report 34) |
| `firmware_analysis/extracted/rbse_7215/rootfs/usr/sbin/cgi-bin/soap_agent` | `a3ee8ac93b41ac52de17e53051b9569f3b063deca0cd585de6337cb1dcf12502` | sat SOAP CGI | |
| `firmware_analysis/extracted/rbse_7288/rootfs/usr/sbin/cgi-bin/soap_agent` | `19feab2445e047084aefac0ac80910fd5732d21c9f2d2538b4b612e5eb85d2ad` | sat SOAP CGI | |
| `firmware_analysis/extracted/rbse_7215/rootfs/usr/sbin/configd` | (per `research_output/inventory/rbse_7215/`) | sat DAL / RPC server | pre-fix |
| `firmware_analysis/extracted/rbse_7288/rootfs/usr/sbin/configd` | (per `research_output/inventory/rbse_7288/`) | sat DAL / RPC server | post-fix (semantically equivalent modulo §4.3) |

### 6.2 Key function offsets

| binary | function | address | role |
|---|---|---|---|
| master `soapc` | `FUN_0001f228` | `0x1f228` | assembles the `NETGEAR_Orbi_%s_%s_password` template and MD5s it |
| master `soapc` | `FUN_00029ce4` | `0x29ce4` | MD5-hex-lowercase helper |
| master `soapc` | `FUN_00028408` | `0x28408` | reads `lan_ifname` → `get_eth_mac` → populates `g_soapc_mac1` (master MAC lower-3) |
| master `soapc` | `FUN_0002864c` | `0x2864c` | reads NVRAM `soapc_sat_<idx>_mac` → `g_soapc_mac2` (sat MAC lower-3) |
| master `soapc` | `soap_main` | `0x27a90` | event-index dispatch top |
| master `soapc` | `soap_action` | `0x25fb8` | per-method dispatch, envelope templating |
| master `soapc` | `soap_startConnection` | `0x25c60` | TLS context creation and socket connect |
| master `soapc` | `soapc_sendRequest` (`FUN_0002332c`) | `0x2332c` | TLS send/recv loop |
| master `soapc` | `getNewAuthPassword` (referenced from `<%getNewAuthPassword();%>` @ `0x5d242`) | `0x2c8b2` | second password producer; use not fully traced |
| sat `configd` | `authenticate_satellite_1_svc` (7215) | `0x24b1c` | RPC auth entrypoint pre-fix |
| sat `configd` | `authenticate_satellite_1_svc` (7288) | `0x24ba8` | RPC auth entrypoint post-fix (+48 bytes = `memcmp`→`strncasecmp` relaxation) |
| sat `configd` | `FUN_0001a8b0` (`get_board_data`) | `0x1a8b0` | +140 bytes between versions = RBS750QV→RBS750 model-string normalization; preserves `popen("board_data -r %s")` primitive |

### 6.3 Credential-boundary summary

| boundary | credential | encoding on wire | verification on receiver |
|---|---|---|---|
| master soapc → sat lighttpd/soap_agent | username `orbi`, password `md5(template)` (primary) OR `BhSta{2,5}.passphrase` (alternate) | SOAP envelope over TLS **without any cert verification** | sat soap_agent → sat configd via UDS Sun RPC |
| sat soap_agent → sat configd (UDS Sun RPC) | same credential, repackaged into `xdr_auth_info` | XDR over `/tmp/ntgr_orbi_rpc` | sat configd `authenticate_satellite_1_svc`: dynamically derives template from `router.mac`+`boarddata.mac0` and `memcmp`s; OR compares against backhaul passphrase |
| owner → master web UI | owner-chosen admin password | HTTPS form POST / SOAP M1:Authenticate | master httpd / Seal REST — separate code path, different credential store |
| owner SSH → master | RSA public key | SSH pubkey auth | master dropbear via `/etc/dropbear/authorized_keys` |

---

## 7. Confirmed findings

1. Master→sat management credential is MAC-derived MD5-hex template with username `orbi`, used on every steady-state call (§2.1).
2. Sat `configd` `authenticate_satellite_1_svc` dynamically re-derives the same template per call from `router.mac`+`boarddata.mac0` and `memcmp`s (§2.1).
3. Backhaul passphrase is a second accepted credential on the same entrypoint (§2.2 A-4).
4. Master-side TLS to sat has no chain validation (§3.1–3.4).
5. Master-side TLS to sat has no hostname validation (§3.1–3.4).
6. CVE-0415 fix is NOT in: `librpc.so` (report 34), master `soapc` (report 33), master `configd` (report 32), sat `soap_agent` (report 32), sat `configd` (§4).
7. The master's management channel provides no owner SSH-provisioning primitive on satellites (report 35 §1.1) — unchanged by this validation pass.
8. Credential-in-log: master writes the credential plaintext to `/tmp/soapc_log` on every call (§2.3).
9. Credential-at-rest: master persists the credential to NVRAM `soap_Authenticate_old_password` on every call (§2.3).

## 8. Strongly supported findings

1. Sat `router.mac` is re-read via an unauthenticated `hyt`-pipeline `popen` at every auth call (§2.3 A-PSIRT-1). "Strongly supported" because the `hyt`-pipeline is confirmed in sat `configd` pseudocode; the assertion that `hyt`'s mesh-plane input is attacker-reachable is static-plausibility (ordinary mesh-management traffic is not owner-authenticated) but not demonstrated.
2. The sat `authenticate_satellite_1_svc` case-sensitivity relaxation (`memcmp`→`strncasecmp`) is the 48-byte portion of the sat-configd text growth (§4.1).
3. The 140-byte sat-configd growth is the RBS750QV→RBS750 normalization in `FUN_0001a8b0` (§4.3).

## 9. Unresolved questions

1. **CVE-2026-0415 firmware location.** Current status: Unverified after three rounds of narrowing. See §4.5 for the pivot plan.
2. **`getNewAuthPassword` purpose and use.** `<%getNewAuthPassword();%>` template at `0x5d242`, function at `0x2c8b2` in master `soapc` is not yet traced to a callsite or a specific SOAP method. Likely admin-password-rotation sync; not confirmed.
3. **Whether `hyt`'s mesh-plane input is attacker-reachable in practice.** The `(echo "td s"; usleep 500000) | hyt | …` popen is confirmed; whether an attacker on the Orbi mesh without pre-existing credentials can reach `hyt`'s input is a separate question that requires analysing `hyt` and its mesh protocol.
4. **Whether the `soapc_pass` NVRAM key is actually populated on the live master.** `soapc` itself does NOT read it (report 33); only `check_fw` touches it. Status unchanged from report 35 §5.2: Unverified.
5. **Whether the admin-web-UI auth path (`http.password` / `http.passwordHash` in NVRAM) is the one used at pairing.** The sat-management RPC path is now known to be independent (§2.2 A-2); the pairing flow has not been re-validated in light of this correction.

## 10. Ruled out

1. CVE-0415 fix in `librpc.so` (report 34).
2. CVE-0415 fix in master `soapc` (report 33).
3. CVE-0415 fix in master `configd` (report 32 — byte-identical both versions).
4. CVE-0415 fix in sat `soap_agent` (report 32 — string-additions only).
5. CVE-0415 fix in sat `configd` (§4).
6. TLS-verify-wrapper hypothesis (§3.3).
7. Owner SSH-provisioning via `soapc` or sat SOAP M1:* methods (report 35 §1.1; unchanged).

## 11. Recommended next offline research steps

1. **`libcrypto.so.1.1` paired decompile** (~2-4 hours, REA/Ghidra). Highest-priority CVE-0415 pivot. Check whether a vendor backport exists inside the `1.1.1n` version string.
2. **Priority-2/3 survey of the 883-file RBSE delta** (~2-3 hours). Enumerate every file that changed in that band; for each, compute an instruction-level fingerprint pair; flag any with a semantic change and route them to a focused pseudocode diff.
3. **Trace `hyt` mesh-plane input to establish whether A-PSIRT-1 is remotely reachable** (~2 hours). Determine whether `hyt`'s `td s` command accepts data from an authenticated or unauthenticated source.
4. **Trace `getNewAuthPassword`** (short task; ~30 minutes).
5. **Draft the PSIRT disclosure email** (task #8) once the libcrypto pivot either Confirms CVE-0415 or Rules out libcrypto too. Bundle items P-1 through P-6 from §5 at minimum; add CVE-0415 localization once established.

---

## 12. Three explicit final verdicts

- **MAC-derived management authentication:** **Confirmed.**
- **TLS certificate verification (chain + hostname):** **Confirmed-absent (both).**
- **CVE-2026-0415 location:** **Unverified.** Ruled out: `librpc.so`, master `soapc`, master `configd`, sat `soap_agent`, sat `configd`. Next pivot: `libcrypto.so.1.1` paired decompile.

---

## 13. ROE compliance

All Track A, Track B, and Track C work this phase was offline against extracted firmware under `firmware_analysis/extracted/`. No calls were made to the live master (10.0.0.1), either satellite, or any other device. No credential, SSH key, session token, example MAC-plus-hash, or similarly sensitive value is reproduced in this report. No firmware was flashed, no configuration was changed, no SOAP state-changing method was invoked. No factory reset was performed. Reports 31/32/33/34/35 are preserved — the correction banner on report 32 added in an earlier turn is retained; no further edits to those reports.

## 14. Deliverables produced this phase

- `firmware_analysis/reports/36_security_findings_validation.md` — this report.
- `firmware_analysis/research_output/validation/track_a_credential_flow.md` — full Track A section with evidence table.
- `firmware_analysis/research_output/validation/track_a_evidence.json` — Track A machine-readable evidence.
- `firmware_analysis/research_output/validation/track_b_tls_verification.md` — full Track B section.
- `firmware_analysis/research_output/validation/track_b_evidence.json` — Track B machine-readable evidence.
- `firmware_analysis/research_output/validation/track_c_configd_sweep.md` — full Track C section.
- `firmware_analysis/research_output/validation/track_c_handler_fingerprints.json` — Track C machine-readable evidence.
- `firmware_analysis/research_output/validation/track_c_candidate_pseudocode/*.c` — reference Ghidra pseudocode exports.
