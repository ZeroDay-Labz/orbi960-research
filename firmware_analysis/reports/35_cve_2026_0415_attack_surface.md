# Report 35 — CVE-2026-0415 Attack-Surface Map and Owner SSH-Provisioning Verdict

Date: 2026-11-04
Scope: synthesis of Track A (master `soapc` RE), Track B (`librpc.so` function-level diff), and Track C (master↔sat management-plane correlation).
Precursor reports: 31 (SOAP trust channel), 32 (CVE-0415 investigation — see §Correction below), 33 (`soapc` RE), 34 (`librpc.so` differential).

This report reserves **Confirmed** for findings supported by specific code, offsets, symbols, or cross-references. **Strongly supported** means multiple independent indicators without a smoking gun. **Unverified assumption** is explicitly called out. **Ruled out** means contradicted by evidence.

---

## 1. Headline verdicts

### 1.1 Owner SSH-provisioning via the master's management relationship with its satellites — **RULED OUT**

The master's authenticated management relationship with its satellites does not provide a legitimate, owner-controlled path to provision SSH access on the satellites.

Evidence basis (Confirmed):

- The master's management-plane client is `/usr/sbin/soapc`. It is a *client* only (Track A overturned report 31's server-side hypothesis). It supports exactly one dispatch form: `soapc <eventIndex>` spawned by `libacos_shared.so::hook_soapc` out of `heartbeat` and `httpd`.
- `soapc` contains no primitive capable of writing to `/etc/ssh/*`, `/etc/dropbear/*`, `/etc/init.d/*`, `authorized_keys`, Dropbear/OpenSSH host-key files, or any similar SSH-adjacent target.
- `soapc` contains no `system`/`popen`/`exec*` callsite driving a shell. Request payload construction is fully template-based (string substitution into bodies ≤4 KB) and the request transport is a direct TLS socket (no shell exec).
- The reachable sat-side SOAP method set (47 M1 methods, report 31 §2) contains no SSH-provisioning method. The eight read-only methods cannot change state. The 38 state-changing methods write exclusively through `configd`'s DAL (Data Abstraction Layer) tables — schema-validated typed-column writes, not filesystem writes.
- The only sat-side method capable of landing executable content on flash is `UpdateNewFirmware2`, which the project ROE forbids.

The only remaining theoretical ownership path to sat SSH is the owner-authorized firmware-mod route, which the project ROE and CLAUDE.md §13 explicitly prohibit at this phase.

### 1.2 CVE-2026-0415 fix location — **librpc.so RULED OUT; sat `configd` DAL dispatcher STRONGLY SUPPORTED**

Report 32 classified `librpc.so` as *STRONGLY INDICATED* based on hash-change + byte-cascade signature. Track B inverted this verdict at the function-pseudocode level. Every one of librpc.so's 190 procedures (137 named + 53 anonymous) has a byte-identical instruction stream between 7215 and 7288 after literal-pool truncation. The 46,122-byte raw delta is 100% attributable to function reordering, literal-pool pointer shifts, and two bytes of `.rodata` padding. No new validation, no new bounds check, no new error path.

The CVE-0415 fix is therefore not in librpc.so. The remaining evidence vector, by elimination and by the advisory's "authenticated local-network admin makes unauthorized modifications" wording, is a sat-side `configd` DAL handler (`*_1_svc`) that was not caught by the prior string-level diff because it got a logic change rather than a message-string change.

### 1.3 Two newly-documented PSIRT-worthy findings (both Confirmed via static analysis)

Beyond CVE-0415 itself, Track A surfaced two independent security issues in the shipping master↔sat management plane:

- **Mesh-plane TLS has no certificate verification.** `soapc` calls `TLS_client_method` + `SSL_CTX_set_options(ctx, 0)` + `SSL_connect` and imports none of `SSL_CTX_set_verify`, `SSL_CTX_load_verify_locations`, `SSL_CTX_set_default_verify_paths`, `SSL_get_peer_certificate`. Any on-LAN attacker that can redirect `<master>↔<sat>` traffic (ARP spoof, DHCP-driven DNS poisoning, or a malicious device on the backhaul VLAN) can MITM the entire sat-management channel.

- **Master↔sat admin credential is a MAC-derived predictable string.** Confirmed via `getAuthPassword()` → `FUN_0001f228` in `soapc`: the password sent on every management call equals `md5_hex_lowercase("NETGEAR_Orbi_" + <sat-mac-piece-1> + "_" + <sat-mac-piece-2> + "_password")`, with username `orbi` hardcoded. The sat's MAC is discoverable via ARP for any on-LAN attacker. This is the same template report 31 flagged at the sat side (as a factory-default fallback), now confirmed as the actual on-the-wire credential for every master→sat call in normal steady-state operation. The sat's `configd` validates it via `authenticate_satellite_1_svc` against `http.password` / `http.passwordHash` in NVRAM. Values are not reproduced in this report.

Combined, these two findings compound: TLS-verify-none plus a MAC-derivable credential lets an on-LAN attacker reach the full 38-method state-changing SOAP surface on any satellite without owner knowledge or interaction.

---

## 2. Master-to-satellite management sequence (Confirmed)

Pipeline per Track A findings, with offsets from the 7215 `soapc` (which is byte-identical to the live master):

```
                           MASTER                                          SATELLITE
                           ──────                                          ─────────

 heartbeat / httpd / scheact / acos_wd
                 │
                 │ (shared-lib call)
                 ▼
 libacos_shared.so :: hook_soapc()
                 │
                 │ fork + exec: /usr/sbin/soapc <eventIndex>
                 ▼
 soapc main()  @ 0x27a90
                 │
                 ▼                                         ┌──────────────────────────────┐
 soap_main()   @ 0x27a90                                   │                              │
                 │                                         │                              │
                 │ reads NVRAM: soapc_sat_<idx>_ip,        │                              │
                 │              soapc_sat_<idx>_mac,       │                              │
                 │              soapc_sat_<idx>_https_port │                              │
                 ▼                                         │                              │
 soap_action() @ 0x25fb8                                   │                              │
                 │                                         │                              │
                 │ template-expand SOAP envelope:          │                              │
                 │   <%getAuthPassword();%>                │                              │
                 │     → FUN_0001f228:                     │                              │
                 │       md5(fmt(NETGEAR_Orbi_%02X_%02X_   │                              │
                 │             password, mac1, mac2))      │                              │
                 │   username := literal "orbi"            │                              │
                 ▼                                         │                              │
 soap_startConnection() @ 0x25c60                          │                              │
                 │                                         │                              │
                 │ TLS_client_method                       │                              │
                 │ SSL_CTX_set_options(ctx, 0)             │                              │
                 │ (no SSL_CTX_set_verify, no root CA)     │                              │
                 ▼                                         │                              │
            TCP connect ─────────────────────────────────▶ │  lighttpd :443               │
                                                          │        │                     │
                 ┌────────────────────────────────────────┤        │                     │
                 │                                        │        ▼                     │
                 │                                        │  rewrite  /soap/server_sa    │
                 │                                        │        ▼                     │
                 │                                        │  cgi.assign → soap_agent     │
                 │                                        │        │                     │
                 │                                        │        ▼                     │
                 │                                        │  soap_agent parses envelope  │
                 │                                        │        │                     │
                 │                                        │        │ Sun RPC via UDS     │
                 │                                        │        │ /tmp/ntgr_orbi_rpc  │
                 │                                        │        ▼                     │
                 │                                        │  configd                     │
                 │                                        │  authenticate_satellite_1_svc│
                 │                                        │        │                     │
                 │                                        │        │ compare user/pass   │
                 │                                        │        │ with NVRAM          │
                 │                                        │        │ http.password /     │
                 │                                        │        │ http.passwordHash   │
                 │                                        │        ▼                     │
                 │                                        │  On success: DAL dispatch   │
                 │                                        │  (M1:* → schema-validated   │
                 │                                        │  write to <object>_dal_param│
                 │                                        │  table)                      │
                 │                                        │        │                     │
                 │ ◀──────────────────────────────────────┤        │                     │
                 │  authResponse.xml / M1:*Response       │                              │
                 ▼                                         └──────────────────────────────┘
 soapc_sendRequest() @ 0x2332c
 soapc writes result into FIFO /tmp/soapc_log
 (consumed by abFifo)
 exits
```

Nothing in this chain reads or calls `librpc.so` on the master side (Confirmed via `readelf -d /usr/sbin/soapc` in Track A). librpc.so is exclusively a sat-side library.

### 2.1 Which credentials cross which boundary (Confirmed)

| boundary | credential | encoding on wire | checked by |
|---|---|---|---|
| master soapc → sat lighttpd | username=`orbi`, password=md5-of-MAC-template | SOAP envelope over TLS (unverified) | sat soap_agent → sat configd via UDS Sun RPC |
| sat soap_agent → sat configd | the same credential, repackaged into `xdr_auth_info` | XDR over Unix domain socket | sat configd `authenticate_satellite_1_svc` compares against NVRAM `http.password` / `http.passwordHash` |
| owner → master web UI | admin password (owner-chosen) | HTTPS form POST / SOAP | master httpd / Seal REST |
| owner SSH → master | RSA public key | SSH pubkey auth | master dropbear via `/etc/dropbear/authorized_keys` |

Note that the owner's admin credential (used at the master web UI) is **not** the credential the master sends to its satellites. The master uses the MAC-derived string instead. This means an attacker who recovers the sat's MAC-derived credential does not learn the owner's real admin password — but it also means that rotating the owner admin password does not change the master↔sat credential.

---

## 3. CVE-2026-0415 attack-surface status

### 3.1 Elimination table

| component | changed 7215→7288? | semantic change? | classification |
|---|---|---|---|
| master `soapc` | `.comment` only | none | **RULED OUT** (Track A) |
| master `configd` | no (byte-identical) | n/a | **RULED OUT** (report 32) |
| sat `soap_agent` | yes | 3 string additions, no logic | **RULED OUT** (report 32) |
| `librpc.so` (both models) | yes | none at pseudocode level | **RULED OUT** (Track B) |
| `libcrypto.so.1.1` | yes | OpenSSL 1.1.1n → 1.1.1n (patch rebuild?) | **RULED OUT** (Track B — same version) |
| sat `configd` | yes (different sha256) | partially unexamined | **STRONGLY SUPPORTED as location** |
| `cryptodev.ko`, `qca-nss-crypto*.ko` | yes | not analysed | **Unverified** (unlikely per advisory wording) |

### 3.2 What is known about the sat-configd residual candidate

Track B partially examined sat `configd` and found:

- `authenticate_satellite_1_svc`: real semantic change — `memcmp(user, "orbi", 4)` → `strncasecmp(user, "orbi", 4)`. This is a case-sensitivity *relaxation*, not a tightening. Not CVE-0415 but worth noting (it means `Orbi`, `ORBI`, `oRbI` all now authenticate equivalently; marginal attack-surface widening, not a vulnerability by itself).
- `update_admin_password_1_svc`: shell invocation via `system("(echo %s; sleep 1; echo %s) | passwd root")` preserved in both versions; the escape helper (`FUN_000226b4` / `FUN_00022740`) backslash-escapes all non-alphanumerics identically in both. **Not the CVE fix**, but the surrounding construction is a worrying design pattern worth documenting in the PSIRT draft.
- `satellite_reboot_1_svc`: no user-controlled parameters. Not the CVE.
- `set_backhaulpassphrase_1_svc`: wrapper, no direct sink. Not the CVE.

Approximately 15 unchecked `*_1_svc` handlers remain. The CVE-0415 fix is most likely in one of these — a targeted pseudocode diff on each would decide it (~1 min per function in REA/Ghidra 12.1.3).

### 3.3 Status of the CVE-0415 fix location

**Strongly supported:** the fix is in sat `configd`, in a `*_1_svc` DAL handler not yet pseudocode-compared.

**Unverified assumption:** that the vulnerable handler is reachable from the owner-authenticated master→sat path (vs. the owner-authenticated sat-admin-web-UI path, which is a different reachable graph). Tightening this classification requires picking the candidate handler and tracing its caller back to one of the 38 state-changing M1 methods.

**Ruled out:** librpc.so, soapc, soap_agent, master configd, libcrypto.

---

## 4. Correction to report 32

Report 32 classified `librpc.so` as *STRONGLY INDICATED* as the CVE-0415 fix location. Report 34 inverted that verdict at the function-pseudocode level. The classification is now **RULED OUT**. Report 32 is preserved as-is for the research-record trail (what a hash-and-string-level comparison can and cannot see); readers of report 32 should read report 34 for the follow-up and this report for the current picture.

The investigative lesson: byte-level cascade across a shared library is a *necessary* but not a *sufficient* condition for a semantic security fix. A clean compile-cascade with a fresh build-id can produce 70% differing bytes with zero semantic change. The function-level pseudocode comparison must be the arbiter, not the hash.

---

## 5. Remaining technical unknowns (ranked)

1. **Which sat `configd` `*_1_svc` handler contains the CVE-2026-0415 fix.** Estimated ~15 unchecked handlers; each is a ~1-minute REA pseudocode diff. This is the single most actionable follow-up. Doing it cleanly answers CVE-0415 location at **Confirmed**.

2. **Whether the `soapc_pass` NVRAM key is actually populated on the live master.** Track A confirmed `soapc` itself does NOT read it (only `check_fw` touches it). So the string's presence in the binary is not evidence of a working alternate credential path. Status: **Unverified assumption** that the NVRAM key is non-empty on the live master. A read-only check against the master's NVRAM via Seal would resolve this; it was previously queued as task #18 but has not been performed and requires per-step owner approval under CLAUDE.md §§6–7.

3. **Whether the MAC-derived master→sat credential and TLS-verify-none findings are already known to NETGEAR.** These are independently PSIRT-worthy findings from this phase. PSIRT disclosure is queued as task #8 and should bundle these two with any CVE-0415 location result once confirmed.

4. **Whether `remoteshellenable` (UDP/23 magic-knock, already decoded in report 25B) can be issued by the master to one of its own satellites as part of pairing.** If yes, it would give the owner a legitimate mechanism to enable the sat-side OpenSSH that the fleet key gates. Prior passes concluded the magic packet is accepted by every unit and starts OpenSSH keyed to the fleet-authorized-keys file. The owner's key is NOT in that file; there is no public code path to write an owner key into it. Status unchanged: **Ruled out** as an owner-ownership path without fleet-key possession.

5. **Whether sat-pairing software (`hyd`, `wsplcd`) exercises any `librpc.so` path that would be relevant to CVE-0415.** Track B's caller-class map attributes 17 librpc exports to sat-configd-server and 9 to sat-soap_agent-client. The mesh-plane binaries (`hyd`, `wsplcd`) are not currently mapped to librpc symbols. If either does call librpc, it opens an additional attack surface not yet characterised. **Unverified.**

6. **Behavioural proof of the two PSIRT findings in §1.3.** Static analysis is complete and confirms the primitives exist. A live proof-of-concept (own on-LAN probe showing the MAC-derived credential accepted by the sat, or a captured TLS handshake showing the master skipping verification) would upgrade the classifications from Confirmed-static to Confirmed-dynamic. These require owner approval per CLAUDE.md §13, and the first one in particular would count as a credential test that CLAUDE.md §13 explicitly covers.

---

## 6. ROE compliance statement

All work in Tracks A, B, and C was performed offline against extracted firmware rootfs under `firmware_analysis/extracted/`. No calls were made to the live master (10.0.0.1), either satellite (10.0.0.3 / 10.0.0.4), or any other device. No credential, SSH key, session token, or similarly sensitive value is reproduced in this report or in reports 33 / 34. No firmware was flashed, no configuration was changed, no SOAP state-changing method was invoked. No factory reset was performed. The current master running state is unchanged from the start of this phase.

---

## 7. Deliverables produced this phase

- `firmware_analysis/reports/33_master_soapc_reverse_engineering.md` — Track A deep RE of `soapc`.
- `firmware_analysis/reports/34_librpc_function_differential.md` — Track B function-level librpc.so diff and refutation of report 32's hypothesis.
- `firmware_analysis/reports/35_cve_2026_0415_attack_surface.md` — this report.
- `firmware_analysis/research_output/soapc/{functions,method_table,callers,7215_vs_7288}.json` — Track A machine-readable artefacts.
- `firmware_analysis/research_output/librpc/{function_fingerprints,fingerprint_summary,body_delta,caller_classes}.json` — Track B machine-readable artefacts.
- `firmware_analysis/research_output/configd_diff/authenticate_satellite_1_svc_7215.c` — reference Ghidra pseudocode saved during Track B.

---

## 8. Recommended next actions, in priority order

1. Finish the sat-configd `*_1_svc` sweep to pinpoint CVE-0415 at Confirmed classification.
2. Draft the PSIRT disclosure email (currently task #8). Bundle three items:
   - CVE-0415 location (once Confirmed).
   - Mesh-plane TLS-verify-none.
   - MAC-derived master→sat credential template (also reachable as sat-pre-pairing default per report 31).
3. Document the owner SSH-provisioning RULED-OUT verdict in the top-level findings summary (task #7).
4. Leave the live-master NVRAM check for `soapc_pass` for a separate explicit request from the owner — it is not blocking any of the above.
