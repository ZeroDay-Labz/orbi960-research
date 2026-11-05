# rest.lua — CVE-2026-0415 secondary fix site (RBRE master)

## Files

| version | path | sha256 |
|---|---|---|
| V7.2.7.15 | `firmware_analysis/extracted/rbre_7215/rootfs/www-seal/rest/rest.lua` | `59e48af4076e4122217ad8cfdb5a1fd1ccec34aafb1aaf951073443d17b8259b` |
| V7.2.8.8  | `firmware_analysis/extracted/rbre_7288/rootfs/www-seal/rest/rest.lua` | `45e8cd5c2fd192ea26024cd6fa16f37b56bb225321fc23b5770933db4d165c1b` |

Lua 5.1 bytecode. Entry point for every `POST /api/v1/*` on the master.

## Routes dispatched (both versions, identical list)

Declared via `router.match(method, path)`:

```
GET  /api/v1/services
GET  /api/v1/services/:service_name
GET  /api/v1/services/:service_name/token
POST /api/v1/services                          (unused param stub)
POST /api/v1/install/:service_name
POST /api/v1/uninstall/:service_name
POST /api/v1/services/:service_name/state
POST /api/v1/services/:service_name/webapp/:webapp_version
GET  /api/v1/services/:service_name/webapp
POST /api/v1/services/:service_name/validateToken
POST /api/v1/enable_ssh
```

`:service_name` is admin-controlled path-component input, lifted straight
from the URL by `third_party/router` into the handler.

## Fix diff (in-order string constants)

Removed in 7288 — the 7215 trust model consulted client-settable headers:

```
HostAddr                 HTTP_X_HOST
HttpXForwardedFor        HTTP_X_FORWARDED_FOR
ServerAddr               127.0.0.1
localhost                Server Error
```

Added in 7288:

```
ProxyInternal            HTTP_X_SEAL_INTERNAL   -- new trust source,
                                                -- set by the user-facing
                                                -- lighttpd on proxied /api/
^[A-Za-z0-9_-]+$         find   %.%.            -- same guard as the one
type  string                                    -- added in seal-services
Invalid request          Bad Request
```

The `service_name` guard + `Invalid request` string pair appears **six times**
in the 7288 constant stream (see `rest.7288.strings.txt` lines 79, 90, 107,
114, 120, 145, 160). Each marks one dispatch site where the handler now
rejects a non-whitelisted `service_name` before calling into
`seal-services.service_action_handler`, `file_exists`, `is_directory`,
`read_all_from_file`, or `write_to_file` on paths constructed as
`/var/media/reserved2/service_uppers/{service_name}/upper/...`.

## Trust-source change (companion lighttpd fix)

`etc/lighttpd_conf.ltp` 7215→7288 diff (unified diff saved at
`../scripts/lighttpd_conf.ltp.diff`):

- `extforward.forwarder = ("all" => "trust")` → `("127.0.0.1" => "trust")`
- new `setenv.add-request-header += ("X-Seal-Internal" => "1")` on the
  `/api/` → `127.0.0.1:16667` proxy block

The pre-fix combination of trust-any `X-Forwarded-For` + REST backend
consulting `HTTP_X_FORWARDED_FOR`/`HTTP_X_HOST` would have allowed an
external authenticated admin to appear "internal" to the handler by setting
the forwarded header themselves. The new `HTTP_X_SEAL_INTERNAL` is written
by lighttpd, not propagated from the client — a server-side origin mark.
