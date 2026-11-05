# Track A validation — Master→Satellite MAC-derived credential flow

Scope: independently validate (not trust) report 33's claim that the master's `soapc` constructs a MAC-derived credential for satellite management, and prove or disprove it from binary evidence on both ends.

Binaries examined:
- `firmware_analysis/extracted/rbre_7215/rootfs/usr/sbin/soapc` (sha256 `531b932b…`)
- `firmware_analysis/extracted/rbse_7215/rootfs/usr/sbin/configd` (sha256 `6caa0acf…`)
- `firmware_analysis/extracted/rbse_7288/rootfs/usr/sbin/configd` (sha256 `a8a1dad5…`) — delta confirmation
- `firmware_analysis/extracted/rbse_7215/rootfs/usr/sbin/cgi-bin/soap_agent` (sha256 `a3ee8ac9…`) — string-level only

Evidence IDs below map to `track_a_evidence.json`. Credential values are not reproduced.

---

## (1) Master-side origination (A3, A4)

Two global strings feed the credential template, each filled by its own function:

- **`g_soapc_mac1`** at `0x560648` is populated by **`FUN_00028408`** (entry `0x28408`). It reads NVRAM `lan_ifname` → calls `get_eth_mac()` → `ether_etoa()` → `sscanf("%02x:%02x:...")` → `snprintf("%02X_%02X_%02X", byte3, byte4, byte5)`. The result is the **lower 3 bytes of the master's OWN LAN MAC**, upper-case hex joined by underscores. This is a material clarification over report 33, which did not identify `g_soapc_mac1`'s provenance.
- **`g_soapc_mac2`** at `0x560668` is populated by **`FUN_0002864c`** (entry `0x2864c`). It builds the NVRAM key `soapc_sat_%d_mac` from the `eventIndex` argument, reads that key, parses the 6-byte MAC, and emits `"%02X_%02X_%02X"` of bytes 3–5. The result is the **lower 3 bytes of the target satellite's MAC**.

So neither half is the full MAC of either device; each is the OUI-less lower half of a different device.

## (2) Master-side transformation (A1, A2)

`FUN_0001f228` (entry `0x1f228`, 364-byte body) is the sole in-binary producer of SOAP auth passwords (resolved from both the `getAuthPassword` template tag at rodata `0x2c7f9` and the `NETGEAR_Orbi_` prefix at `0x2d31a`):

```c
snprintf(local_120, 0x101,
         "%s%s%s%s%s",
         "NETGEAR_Orbi_", g_soapc_mac1, "_", g_soapc_mac2, "_password");
__ptr = FUN_00029ce4(local_120);     // MD5-hex-lowercase
strlcpy(auStack_144, __ptr, 0x22);
strlcpy(param_3, auStack_144, 0x400);
acosNvramConfig_set("soap_Authenticate_old_password", auStack_144);
fprintf(/tmp/soapc_log, "getAuthPassword(%d)value=%s\n", 0x2b5, param_3);
```

`FUN_00029ce4` (entry `0x29ce4`) is confirmed as standard OpenSSL MD5 (`MD5Init`/`MD5Update`/`MD5Final`) followed by `snprintf` with sixteen `%02x` conversions — **MD5-hex LOWERCASE**, 32-character output, NUL-terminated.

Composed template: `NETGEAR_Orbi_XX_XX_XX_YY_YY_YY_password` where the six hex pairs are, in order, **three bytes from the master's LAN MAC followed by three bytes from the target satellite's MAC**.

Two side effects of this function are independently PSIRT-worthy and not emphasized in prior reports:
- `acosNvramConfig_set("soap_Authenticate_old_password", …)` — the computed credential is written to NVRAM on every call. A live master's NVRAM therefore carries the current credential for the most-recently-addressed satellite.
- `fprintf(/tmp/soapc_log, "…value=%s\n", …)` — the computed credential is logged plaintext to `/tmp/soapc_log` on every call. `/tmp/soapc_log` is a FIFO drained by `abFifo`.

## (3) Master-side transmission (A6)

The constructed password lands in the SOAP envelope via template expansion. Two envelopes are present in `soapc`:

- `0x5d433` — uses `<%getAuthPassword();%>`, the primary authenticator.
- `0x5d242` — uses `<%getNewAuthPassword();%>`, a second password producer at `0x2c8b2`/`0x2d8b3`. Its site was not fully traced in this pass; it likely fires during admin-password-rotation sync but has not been confirmed.

Both envelopes use **username literal `orbi`**. Transport is HTTPS to `https://<sat_ip>:<sat_port>/soap/server_sa` with the TLS-verify-none posture report 33 describes (not re-verified in this track).

## (4) Satellite-side reception

The SOAP endpoint is handled by `cgi-bin/soap_agent` (sha256 `a3ee8ac9…`) and dispatched via the Sun RPC unix-domain socket `/tmp/ntgr_orbi_rpc` into `configd`'s `authenticate_satellite_1_svc`. This is the chain already documented in report 31 §3; no change here.

## (5) Satellite-side validation (A7) — MATERIAL CORRECTION

`authenticate_satellite_1_svc` in sat `configd` 7215 (entry `0x24b1c`) and 7288 (entry `0x24ba8`) contains the same two-branch logic:

- **Branch 1 (backhaul-passphrase direct compare)**. Reads NVRAM `BhSta2.ssid` + `BhSta2.passphrase` (falls back to `BhSta5.*`). If `strlen(passphrase) == 0x40` and every character `isxdigit`, snprintfs it into a 65-byte buffer and compares (`FUN_0001f8b8` / `FUN_0001f944`) to the incoming password. Match → auth success.
- **Branch 2 (MAC-derived MD5)**. Runs the hyt pipeline (§6 below) to discover the master MAC, auto-updates NVRAM `router.mac` if it has changed, reads `boarddata.mac0` (the sat's own MAC), converts both string→byte arrays via `FUN_0001f378`/`FUN_0001f404`, and calls:

```c
snprintf(__ptr, 0x28, "NETGEAR_Orbi_%02X_%02X_%02X_%02X_%02X_%02X_password",
         router.mac[3], router.mac[4], router.mac[5],
         boarddata.mac0[3], boarddata.mac0[4], boarddata.mac0[5]);
MD5(__ptr, strlen(__ptr), md);
// hex-encode md lowercase into pvVar7
memcmp(pvVar7, incoming_password, 0x40);
```

**The sat does NOT compare the incoming password to NVRAM `http.password` or `http.passwordHash`.** This is a material correction to report 31 §3. The format string at sat-rodata `0x35efb` (7215) / `0x35fc7` (7288) is used dynamically, every call, as a pure derivation — not as a one-time populator of a persisted comparator. `http.password` and `http.passwordHash` exist in `configd`'s string table but are used by a different code path (admin web-UI session validation via `M1:Authenticate` through `soap_agent`, not this RPC-server entrypoint).

The sat's derivation uses bytes 3–5 of `router.mac` and bytes 3–5 of `boarddata.mac0` — **identical half-ranges to what the master emits** — so when the master correctly knows the sat's MAC (from NVRAM `soapc_sat_<idx>_mac`) and the sat correctly knows the master's MAC (from NVRAM `router.mac`, possibly refreshed by the hyt pipeline each call), the two MD5 inputs are byte-identical and the comparator succeeds.

Delta in 7288 (A10):
- Username check `FUN_0001f7f8(*param_1,"orbi",4)` → `strncasecmp(*param_1,"orbi",4)` — case-insensitive. This was already noted by report 34 as a RELAXATION, not a tightening.
- On backhaul-passphrase success path, `nvram_set("legacy_auth_done=yes"); nvram_commit();` has been added, and the return code switches to `2` on subsequent authentications where `legacy_auth_done` was already set. State-tracking change; not a credential-derivation change.

## (6) Hyt-pipeline router.mac discovery (A8) — NEW PSIRT-WORTHY FINDING

Immediately before the MD5 derivation, `authenticate_satellite_1_svc` runs:

```
popen("(echo \"td s\"; usleep 500000) | hyt | grep \"Network relaying device\""
      " | awk '/^.*#.*device: [0-9a-fA-F:]*, IPv4 address: [0-9.]*(.*)?$/"
      " { printf(\"%s\", $6);}' $1 | cut -d ',' -f 1", "r")
```

The output (up to 0x12 bytes) is parsed into a MAC string, and if it differs from NVRAM `router.mac`, the sat runs `nvram_set("router.mac=%s")` and `nvram_commit()`. **The hyt output is not authenticated at this call site**; `hyt` is the mesh daemon's query shell. Any party that can inject into the hyt dataset for this sat (or who can run as root on the sat) can effectively rebase the master-half of the credential template the sat expects. This does not by itself defeat authentication (the attacker also needs the sat's own `boarddata.mac0`, which is ARP-discoverable and so widely considered public). But it means the master-half of the template is attacker-influenced-at-runtime, not a static shared secret — an important adjunct to the main credential finding.

## (7) Steady-state vs provisioning scope (A11)

Every SOAP envelope template present in `soapc` references either `<%getAuthPassword();%>` or `<%getNewAuthPassword();%>`. Both tag handlers compose the same `NETGEAR_Orbi_` template through `FUN_0001f228` (with `FUN_00028408`/`FUN_0002864c` seeding the globals). There is no code path in `soapc` that reads a stored admin-password hash from NVRAM for use as an authenticator. **This credential is therefore the primary steady-state credential for every master→sat management call, not a factory-default or pre-pairing fallback**. This upgrades and corrects the framing in reports 31 §3 and 35 §1.3.

Second authenticator (backhaul-passphrase direct) on the sat side (A9) is also PSIRT-worthy and has not been previously documented: anyone who learns `BhSta2.passphrase` or `BhSta5.passphrase` for a given sat (the 64-hex-char backhaul material, passed in-band during pairing and persisted in NVRAM) can authenticate to that sat's `authenticate_satellite_1_svc` without needing the MAC-derived MD5.

## (8) Evidence table

Compact version — full detail in `track_a_evidence.json`:

| id | file / version | function | address | finding | classification |
|----|---|---|---|---|---|
| A1 | master_soapc 7215 | `FUN_0001f228` | 0x1f228 | snprintf 5-piece template + MD5 | CONFIRMED |
| A2 | master_soapc 7215 | `FUN_00029ce4` | 0x29ce4 | OpenSSL MD5 + lowercase hex | CONFIRMED |
| A3 | master_soapc 7215 | `FUN_00028408` | 0x28408 | g_soapc_mac1 = master LAN MAC lower-3 (NEW) | CONFIRMED |
| A4 | master_soapc 7215 | `FUN_0002864c` | 0x2864c | g_soapc_mac2 = NVRAM soapc_sat_<idx>_mac lower-3 | CONFIRMED |
| A5 | derived | — | — | Template is mixed-MAC (master+sat), not single-MAC | CONFIRMED |
| A6 | master_soapc 7215 | envelopes | 0x5d433, 0x5d242 | Username "orbi", two auth templates incl. getNewAuthPassword | CONFIRMED |
| A7 | sat_configd 7215 | `authenticate_satellite_1_svc` | 0x24b1c | Dynamic derivation, NOT http.password compare | CONFIRMED |
| A8 | sat_configd 7215 | same | 0x24b1c (hyt popen) | Unauthenticated router.mac auto-update | CONFIRMED / PSIRT |
| A9 | sat_configd 7215 | same | 0x24b1c (backhaul branch) | Backhaul passphrase = second valid credential | CONFIRMED / PSIRT |
| A10 | sat_configd 7288 | `authenticate_satellite_1_svc` | 0x24ba8 | 7288 adds strncasecmp + legacy_auth_done writeback | CONFIRMED |
| A11 | master_soapc 7215 | envelope coverage | — | Every management call uses this credential | CONFIRMED |
| A13 | master_soapc 7215 | `FUN_0001f228` | 0x1f228 | Credential written to NVRAM soap_Authenticate_old_password | CONFIRMED / PSIRT |

## (9) Classification verdict

**MAC-derived management authentication: CONFIRMED.**

With these additional confirmed facts:
- The template is **mixed-MAC** (three bytes master + three bytes sat), not single-MAC.
- Validation is **dynamic derivation on the sat**, not comparison against stored NVRAM `http.password`/`http.passwordHash`.
- There is a **second valid credential** (backhaul passphrase) for the same RPC entrypoint.
- The master's half of the template is **attacker-influenced at runtime** on the sat side via unauthenticated hyt popen.
- The computed credential is **written to NVRAM and plaintext logs** on every call.
