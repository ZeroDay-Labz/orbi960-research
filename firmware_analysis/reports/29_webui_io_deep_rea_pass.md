# RBSE960 `webui-io` Multicall CGI — Deep REA Pass

**Status:** VERIFIED — static-only; the prior "session-authenticated, mkstemp destination, no obvious vuln" verdict holds after an interactive REA review.

**Target:**
- Path: `firmware_analysis/extracted/rbse_7215/rootfs/usr/libexec/webui-io`
- SHA-256: `2bcd973382330f5be81a4fb1544ea7aaff9c83d455b08d036b98da736af4d35c`
- Byte-identical between RBSE 7.2.7.15 and 7.2.8.8 (confirmed with `sha256sum` on both extracted copies).
- Format: ARM EABI5 ELF32 DYN, musl-linked, stripped.

**Method:** Ghidra 12.1.3 via REA MCP (`open_binary`, `list_procedures`, `procedure_pseudo_code`, `read_function_instructions`, `search_strings`, `xrefs`). Cross-validated with raw `xxd` and `readelf` because the headless Ghidra session was shared with sibling forks and recycled mid-pass; findings below only cite evidence I observed in-session.

---

## 1. ACL — `/usr/share/rpcd/acl.d/netgear.json` + `unauthenticated.json`

Only the `netgear` role grants `webui-io`:

```
netgear.read:  webui-io = ["download"]
netgear.write: webui-io = ["upload"]
```

`unauthenticated.json` grants only `ubus.session.[access, login]`. **There is no unauthenticated path into webui-io at the rpcd layer.** Any `ubus call session access` with `scope="webui-io"` requires a valid `ubus_rpc_session` that has been logged in through the `netgear` ACL.

---

## 2. argv[0] dispatch — only two commands, no hidden third

`main` at 0x10eb4 does exactly:

```c
if (strstr(argv[0], "netgear-upload")) { ... upload branch ... }
else if (strstr(argv[0], "netgear-download")) { ... download branch ... }
else return -1;
```

String search returned exactly three `netgear-*` literals:

```
0x12734  /tmp/netgear-upload.XXXXXX
0x128e9  netgear-upload
0x128f8  netgear-download
```

No further argv[0] substring is matched. If a symlink contains both tokens, `netgear-upload` wins (ordered `strstr`). **No hidden multicall.**

---

## 3. Upload branch (`/soap/netgear-upload`)

Flow (main 0x116c0 → 0x11894, callback at ~0x118c8 — Ghidra missed detecting the latter as a function but its xrefs and byte sequence make its role clear):

1. `get_available_mem()` → compare against `get_threshold_value()`; if too low → "Not enough memory. Please reboot and try again."
2. `CONTENT_TYPE` must start with `multipart/form-data;` (strncmp 0x14 bytes). Then it scans for `=` (the `boundary=` separator), copies `"--" + boundary` into a malloced string.
3. Initialises the libubox multipart parser via `FUN_00012050(boundary, &PTR_LAB_00023004)` — the function table at 0x23004 (xrefed only at 0x117d4) is the parser's callback vector (the strings `parts` and `part_size` leak through `.dynstr`-adjacent rodata, confirming libubox-style parser).
4. Reads stdin in 4096-byte chunks (`read(0, buf, 0x1000)`), feeds to `FUN_000120c8` (parser step). Any leftover stdin after parser ends is drained.
5. **Within the parser callback (uncompiled, 0x118c8 onwards):**
   - When headers for a part end: calls `FUN_00011c44` with state=1 → session auth (`FUN_00011b10("upload","write")`). On fail: emits `Upload permission denied` and sets state to 0 (short-circuits all remaining parsing).
   - Then checks the part's `name` form attribute: missing → `File data without name`. Present but wrong → silently ignore (only `filedata` is accepted — string literal at offset 10529).
   - Only for `name="filedata"` does it `mkstemp("/tmp/netgear-upload.XXXXXX")` — this is the single xref at 0x118f4 to the mkstemp template — storing the resulting path into global `DAT_0002305c` (a strdup of mkstemp's local buffer). **The Content-Disposition `filename="..."` is not used. The destination path is strictly server-chosen by mkstemp.**
   - When the part body ends: calls `FUN_00011c44` with state=4 → `FUN_00011410` performs the final write.
6. `FUN_00011410` opens `DAT_0002305c` with `O_WRONLY|O_CREAT|O_TRUNC`, mode 0600 (`DAT_00023064 = 0x180`), copies the temp body (fd `DAT_0002306c`) 4096 bytes at a time, then `chmod(path, 0600)`.
7. Response via `FUN_00011238`: on success, `fork()` + `execl("/bin/busybox", "/bin/busybox", "md5sum", DAT_0002305c, 0)`. **The md5sum argv is strictly the mkstemp-generated path; no attacker influence.**

### Bugs observed (not exploitable)

- `FUN_00011238` has `printf("\t\"size\": %u,\n\t\"checksum\": \"%s\"\n", sStack_80.st_blksize)` — **missing second format argument**. This reads one uninitialised varargs register/stack slot and prints its contents as a C string into the JSON response. Information disclosure of uninitialised stack memory, not RCE. Still worth flagging in the PSIRT writeup.
- `strcpy(malloc(len+3), "--")` then `strcpy(ptr+2, boundary)` — bounds are correct (`malloc(strlen(boundary)+3)` is `-- + boundary + NUL`). Safe.

---

## 4. Download branch (`/soap/netgear-download`)

1. `CONTENT_TYPE` must equal `application/x-www-form-urlencoded` (strncmp 0x21).
2. Read ≤1023 bytes from stdin into a 1024-byte global (`DAT_000230a4`).
3. Parse `key=value&…` pairs looking for `sessionid=<v>` (strcmp on the key).
4. URL-decode the value in-place (pcVar2 ≤ pcVar11, bounded by the NUL the parser placed at `&` or buffer end — no overflow).
5. `FUN_00011b10("download", "info")` — the "info" literal is at 0x12877. Session-authenticated against `webui-io.download.*`.
6. On success: `chdir("/tmp"); open("debuglog.zip")` and stream it to stdout with `fwrite/fflush`. **Fixed path; attacker cannot select a different file.**

Note: The download branch takes `sessionid` from the form body, not from HTTP_COOKIE, but then `FUN_00011b10` still reads HTTP_COOKIE for the actual access check. The `sessionid` form value is used only as a flag (its content doesn't reach the ubus call). That's an oddity but not a vuln — the authoritative session comes from the cookie.

---

## 5. Session check — `FUN_00011b10` (0x11b10)

```c
int FUN_00011b10(scope_object, scope_function) {
    ctx = ubus_connect();
    if (!ctx) return 0;
    if (ubus_lookup_id(ctx, "session", &id) != 0) { ubus_free; return 0; }
    cookie = getenv("HTTP_COOKIE");
    if (cookie && strncmp(cookie, "sid=", 4) == 0) cookie += 4;
    blob_buf_init(&buf, 0);
    blobmsg_add_string(&buf, "ubus_rpc_session", cookie);
    blobmsg_add_string(&buf, "scope",  "webui-io");
    blobmsg_add_string(&buf, "object", scope_object);  // "upload" | "download"
    blobmsg_add_string(&buf, "function", scope_function); // "write" | "info"
    ubus_invoke(ctx, id, "access", buf, callback, &result, 500);
    ubus_free(ctx);
    return result;  // set to 1 by callback FUN_00011124 iff ubus granted
}
```

Edge cases I looked for:

- **Missing/malformed cookie** — `cookie==NULL`: `FUN_00011acc` (wraps `blobmsg_add_field`) is called with a NULL string, which `blobmsg_add_field` handles by adding a zero-length string field. `ubus session access` then rejects with "permission denied" → result stays 0. Not bypassable.
- **Cookie doesn't start with `sid=`** — the full raw cookie value is passed as `ubus_rpc_session`. `ubus session access` only matches on the exact 32-hex session id in its table; garbage values never match. Not bypassable.
- **Multiple cookies** (`foo=bar; sid=<valid>`) — `strncmp(cookie,"sid=",4)==0` fails, so the whole raw string is sent. lighttpd's cookie ordering when it sets `sid=...` as the only cookie prevents this in practice, but any attacker-controlled extra cookie BEFORE `sid=` would break login. Hardening gap in favor of the defender, not an attacker.
- The ACL check uses `scope="webui-io"` and `object=upload`/`download` — both hardcoded, no attacker influence over the ACL namespace.

---

## 6. TOCTOU / double-fetch

The upload state machine runs linearly inside one process:

- **state=1** (headers end): `FUN_00011b10("upload","write")` → on success, mkstemp allocates the destination; `DAT_0002305c` is set and `DAT_0002306c` (source temp fd) is opened.
- **state=4** (part body end): `FUN_00011410` copies the already-buffered body from fd `DAT_0002306c` into the pre-mkstemp'd path at `DAT_0002305c`.

There is **no path change between auth and write** — both reference the same `DAT_0002305c` set at state=1 by mkstemp. Nothing between the two states re-reads environment or form data for the destination.

---

## 7. Final verdict

**Still no shallow vuln.** The upload CGI is correctly session-authenticated via the rpcd `webui-io.upload.write` ACL (admin-only, under the `netgear` role). The destination is strictly `mkstemp`-generated into `/tmp`, and the single `execl` is on that same server-chosen path. The download CGI returns only a fixed `/tmp/debuglog.zip` and is admin-only via `webui-io.download.*`.

One minor, non-exploitable bug worth noting in PSIRT disclosure:

- **FUN_00011238 format-string arg mismatch** (`\"size\": %u, \"checksum\": \"%s\"` with only `st_blksize` passed) leaks ~1 varargs slot of uninitialised stack as the JSON `checksum` value. Information disclosure only — no RCE path, and the content is non-deterministic uninitialised data, not pointers to anything sensitive. Low severity.

**Not worth live probing for shell access.** No path here reaches arbitrary file write, arbitrary exec, or an unauthenticated code path.

---

**Out-of-scope observation (one line):** The `debuglog.zip` download endpoint will cheerfully return whatever `/tmp/debuglog.zip` happens to be — which is populated by the `debuglog.so` rpcd plugin's `log_collect` method. If a sibling admin session dumps diagnostics, that content is available to any session that can hit `/soap/netgear-download`. This is session-authenticated so not a bypass, but it's a lateral/privacy consideration if multiple admins share the box.
