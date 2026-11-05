# Track B — Master→Satellite TLS certificate verification: validation of report 33's claim

Target: `firmware_analysis/extracted/rbre_7215/rootfs/usr/sbin/soapc`
sha256: `531b932b0488a4d60d38cd575d0d1b44f7f4285f40eafe5593a3c8d975f74a7b`
Byte-identical to the live master's running `/usr/sbin/soapc`.
Cross-version check against `firmware_analysis/extracted/rbre_7288/rootfs/usr/sbin/soapc` (sha256 `6c4e4004…`).

The directive required inspecting actual call sites and control flow rather than relying on the absence of imports alone. This section records what was found at the code level, in the order the directive lays out.

## 1. TLS context creation

Call chain inside `soapc_sendRequest` @ `0x2332c`, from Ghidra pseudocode of `FUN_0002332c`:

```
OPENSSL_init_crypto(0xc, 0, 0)
OPENSSL_init_ssl(0x200002, 0, 0)
OPENSSL_init_ssl(0, 0, 0)
meth = TLS_client_method()
ctx  = SSL_CTX_new(meth)
```

`SSL_CTX_new` with `TLS_client_method()` returns an SSL_CTX initialised with OpenSSL 1.1.1's documented default verify mode `SSL_VERIFY_NONE`. This is the baseline on which everything that follows runs.

PLT relocation evidence (from `readelf -r soapc`): `SSL_CTX_new@OPENSSL_1_1_0` has R_ARM_JUMP_SLOT 0x00032ee4, `TLS_client_method@OPENSSL_1_1_0` has R_ARM_JUMP_SLOT 0x00032d4c — both are real, resolved imports.

## 2. Trust-store / CA configuration

**None observed.**

Full PLT relocation list of `soapc` (readelf -r) contains ZERO occurrences of:

- `SSL_CTX_load_verify_locations`
- `SSL_CTX_set_default_verify_paths`
- `SSL_CTX_set_cert_store`
- `X509_STORE_load_locations`
- `SSL_CTX_use_certificate_chain_file`
- `SSL_CTX_use_certificate_file`

No wrapper exists either: `libacos_shared.so` has zero `NEEDED libssl.so.1.1 / libcrypto.so.1.1` entries and zero `SSL_*` / `TLS_*` / `X509_*` UND imports. The same is true for every other `.so` listed in `soapc`'s NEEDED list (`libacos_nvram.so`, `libacos_shared_attach.so`, `libacos_dal.so`, `libd2lib.so`, `libdillib.so`, `libd2dynlog.so`, `libubox.so`, `libuci.so`). None of them import a TLS verification API, and `libcurl.so.4` is not in soapc's NEEDED list at all.

String-level scan: `strings soapc | grep -iE 'X509|/etc/ssl|/etc/certs|cacert|ca-bundle|ca\.pem|certs\.pem'` returns zero hits.

Classification: **no CA bundle, no CA directory, no trust store is configured by any code path soapc executes.**

## 3. Verification-mode programming

`soapc` calls `SSL_CTX_set_options(ctx, 0)` once (at pseudocode line 185 of `FUN_0002332c`). The second argument is the literal constant 0.

In OpenSSL 1.1.1, `SSL_CTX_set_options` performs `ctx->options |= op`. Passing `op = 0` ORs nothing into the mask. The call has no security effect and, critically, does NOT set any verify mode. (Verify mode is set via `SSL_CTX_set_verify`, which is a separate API and is not imported.)

PLT relocation evidence: `SSL_CTX_set_options@OPENSSL_1_1_0` is present (R_ARM_JUMP_SLOT 0x00032e30). `SSL_CTX_set_verify` and `SSL_set_verify` are NOT present. This is linker metadata, not symbol-listing inference — a function not in the JUMP_SLOT table cannot be called at run time without soapc crashing.

Classification: **verify mode is the OpenSSL default `SSL_VERIFY_NONE`.**

## 4. Callback registration

**None.** Neither `SSL_CTX_set_cert_verify_callback`, nor the callback-argument form of `SSL_CTX_set_verify`, nor `X509_STORE_CTX_set_verify_cb` is in the PLT relocation table. No function pointer is passed into an SSL_CTX in the pseudocode.

## 5. SSL_connect downstream handling

Pseudocode of the post-handshake branch (from `FUN_0002332c`, around pseudocode line 199):

```
SSL_set_fd(ssl, fd);
iVar7 = SSL_connect(ssl);
if (iVar7 == 1) {
    // success: log "Successfully enabled SSL/TLS session to: %s"
} else {
    // failure: log "Error: Could not build a SSL session to: %s"
}
// control falls through to the SSL_write / SSL_read loop
```

Between `SSL_connect` and the data-plane I/O there is no call to:

- `SSL_get_verify_result`
- `SSL_get_peer_certificate` (or `SSL_get1_peer_certificate`)
- `SSL_get_peer_cert_chain`
- any `X509_*`

The "success" branch simply logs and proceeds. The "failure" branch also logs and proceeds into the same I/O loop (SSL_write will subsequently fail if the handshake failed, so no plaintext leaks — but no cert inspection is performed in either branch).

Classification: **the handshake outcome is treated as binary success/failure with no secondary certificate inspection.**

## 6. Hostname validation (distinct from chain validation)

**None.** Neither `X509_check_host`, `X509_check_ip`, `X509_check_email`, `SSL_set_tlsext_host_name`, nor `SSL_CTX_set_tlsext_servername_callback` is imported.

Manual hostname check: the host string `param_2` (the satellite's address from NVRAM key `soapc_sat_<idx>_ip`) is used only in `fprintf` log statements. It is not passed to any certificate-text extraction or string comparison.

String scan: `strings soapc | grep -iE 'hostname|SubjectAlt|check.?host|CN='` returns zero hits.

Classification: **hostname verification is not performed, even by hand.**

## 7. Error paths on verify failure

Moot: because verify mode is `SSL_VERIFY_NONE`, the handshake does not treat an invalid cert chain as a reason to fail. `SSL_connect` returns 1 for any syntactically valid server cert the satellite presents.

If `SSL_connect` returns ≤0 for OTHER reasons (e.g. socket error, protocol mismatch), the code logs and continues into the I/O loop; subsequent `SSL_write` returns error and the request is abandoned. The user-visible effect is a logged failure, not a silent accept — but this is unrelated to certificate verification.

## 8. Wrapper / dynamically-linked indirection

Hypothesis from the directive: a wrapper in `libacos_shared.so` or similar could register verification on behalf of soapc, defeating the pure-imports check.

Falsified:

- `libacos_shared.so` NEEDED list does not include `libssl.so.1.1` or `libcrypto.so.1.1`.
- `libacos_shared.so` has zero UND imports of any `SSL_*`, `TLS_*`, `X509_*`, `OPENSSL_*`, `curl_easy_*` symbol.
- Same result for `libacos_shared_attach.so`, `libacos_shared_vn.so`, `libacos_nvram.so`, `libacos_dal.so`, `libd2lib.so`, `libdillib.so`, `libd2dynlog.so`, `libubox.so`, `libuci.so`.
- `libcurl.so.4` is present on-device but is NOT in `soapc`'s NEEDED list.

The only OpenSSL API `soapc` calls is the 14-symbol set enumerated in §9. There is no hidden wrapper path.

## 9. Full OpenSSL API surface used by soapc (linker-authoritative)

From `readelf -r firmware_analysis/extracted/rbre_7215/rootfs/usr/sbin/soapc`:

| GOT addr | Symbol |
|---|---|
| 0x00032d28 | `PKCS5_PBKDF2_HMAC@OPENSSL_1_1_0` |
| 0x00032d4c | `TLS_client_method@OPENSSL_1_1_0` |
| 0x00032d54 | `SSL_CTX_free@OPENSSL_1_1_0` |
| 0x00032d9c | `SSL_write@OPENSSL_1_1_0` |
| 0x00032dc4 | `SSL_set_fd@OPENSSL_1_1_0` |
| 0x00032de4 | `SSL_new@OPENSSL_1_1_0` |
| 0x00032df4 | `SSL_read@OPENSSL_1_1_0` |
| 0x00032e30 | `SSL_CTX_set_options@OPENSSL_1_1_0` |
| 0x00032e40 | `SSL_connect@OPENSSL_1_1_0` |
| 0x00032e4c | `EVP_sha1@OPENSSL_1_1_0` |
| 0x00032e64 | `SSL_free@OPENSSL_1_1_0` |
| 0x00032e9c | `OPENSSL_init_ssl@OPENSSL_1_1_0` |
| 0x00032ee4 | `SSL_CTX_new@OPENSSL_1_1_0` |
| 0x00032efc | `OPENSSL_init_crypto@OPENSSL_1_1_0` |

14 entries. Dynamic linking is total — anything soapc calls into libssl/libcrypto must appear in this table or the ELF loader would fail to resolve it at startup. No verification API is in this table.

Cross-check against V7.2.8.8 `soapc` (`6c4e4004…`): same 14 symbols, no changes. The 7.2.8.x "fix" window did NOT touch TLS verification.

## 10. Chain-validation verdict

**CONFIRMED-ABSENT.** The master's `soapc` performs no certificate-chain verification. The `SSL_CTX_new()` default `SSL_VERIFY_NONE` is never overridden. No trust store is configured. No verify callback is registered. SSL_connect's outcome is not post-inspected via `SSL_get_verify_result` or `SSL_get_peer_certificate`.

## 11. Hostname-validation verdict

**CONFIRMED-ABSENT.** Neither OpenSSL hostname-checking APIs (`X509_check_host`, `X509_check_ip`) nor a manual CN/SAN comparison path exists. The target hostname string is used only for logging. SNI is not set.

## 12. Classification per directive's four-option taxonomy

(1) explicitly disabled — NO.
**(2) left disabled by default — YES.** No `SSL_CTX_set_verify` call is made; OpenSSL 1.1.1 defaults to `SSL_VERIFY_NONE`.
(3) implemented through another API or wrapper — NO.
(4) indeterminate — NO.

## 13. Status of report 33's claim

**Upheld, with one nuance.** Report 33 said "effectively SSL_VERIFY_NONE". The code-level evidence confirms this and sharpens the precise formulation:

- Report 33's inference from the import-set is correct AND is now backed by linker-level JUMP_SLOT evidence that no other verification API is reachable at run time.
- The precise mechanism is "default, never set" rather than "explicitly disabled" — the security impact is identical, but the latter wording is the technically correct one.
- The 7215↔7288 OpenSSL import set is unchanged, so CVE-2026-0415 does not patch this.
