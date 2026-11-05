# seal-services.lua — CVE-2026-0415 fix site (RBRE master)

## Files

| version | path | sha256 |
|---|---|---|
| V7.2.7.15 | `firmware_analysis/extracted/rbre_7215/rootfs/usr/share/lua/seal-services.lua` | `3e24b97b41a4db23f6d76d22611c1a932cf5421d529af127c92c0b4f6a8682eb` |
| V7.2.8.8  | `firmware_analysis/extracted/rbre_7288/rootfs/usr/share/lua/seal-services.lua` | `27063966010939a1c6eac05b175fc3b3e26345f1221a66060df2290ad0d62da0` |

Both are Lua 5.1 bytecode (LuaQ, version 0x51), executed by `/usr/bin/lua` on
the RBRE. Loaded by `rest.lua` via `require("seal-services")`.

## Fix diff (constant-table reconstruction, in bytecode order)

Pre-fix 7215 constant sequence inside `service_action_handler`
(see `seal-services.7215.strings.txt` lines 14..47):

```
details         -- field in webapp-list reply
get_webapp
list
seal_version
install
uninstall
enabled
ACTIVATE
disabled
DEACTIVATE
service_action_handler   -- function declared
ipairs                   -- first instruction uses ipairs over catalog
...
```

Post-fix 7288 constant sequence (see `seal-services.7288.strings.txt` lines 14..31):

```
details
get_webapp
list
seal_version
install
uninstall
enabled
ACTIVATE
disabled
DEACTIVATE
service_action_handler   -- function declared
type                     -- NEW: type(service_name) ~= "string" check
string                   -- NEW
match                    -- NEW: string.match(service_name, "^[A-Za-z0-9_-]+$")
^[A-Za-z0-9_-]+$         -- NEW: strict identifier whitelist
find                     -- NEW: string.find(service_name, "%.%.")
%.%.                     -- NEW: path-traversal defensive check (redundant with whitelist)
ipairs                   -- existing first-statement instruction preserved
```

The six new constants (`type`, `string`, `match`, `^[A-Za-z0-9_-]+$`, `find`,
`%.%.`) appear only inside `service_action_handler` and only in 7288. Their
in-order position between the function declaration and the first legitimate
instruction (`ipairs`) is the signature of a guard clause inserted at the top
of the function body:

```lua
-- reconstructed Lua guard (shape; exact token names recovered from bytecode)
function service_action_handler(service_name, action, payload)
    if type(service_name) ~= "string"
       or not string.match(service_name, "^[A-Za-z0-9_-]+$")
       or string.find(service_name, "%.%.") then
        return invalid_request_reply()    -- "Invalid request" error path
    end
    -- unchanged body follows
end
```

The identifier whitelist rejects every shell metacharacter used in command
injection (`;`, `|`, `&`, `` ` ``, `$`, `(`, `)`, `>`, `<`, SPACE, newline, etc.),
and `%.%.` rejects path-traversal via `..`. Everything downstream of the guard
stays bytewise unchanged in the diff: the handler's dangerous call sites are
preserved, only now unreachable with hostile `service_name`.

## Downstream shell concatenation sites that `service_name` reaches
(all present in BOTH versions, preserved verbatim in 7288 — see string
sequence at `seal-services.7288.strings.txt` lines 51, 60, 117, 121, 128):

| line (7288) | shell string | Lua primitive |
|---|---|---|
| 51-52 | `opkg status seal-service-{service_name} | grep '^Status: ' | awk '{printf "%s", $4}'` | `popen` |
| 60-61 | `ssvc status {service_name} >/dev/null 2>&1` | `os.execute` |
| 117 | `opkg install {service_name}` | `popen` |
| 121 | `opkg remove {service_name}` | `popen` |
| 128 | `/usr/bin/nsh.sh argument 0 {service_name}` | `popen` |

Each of these is `shell_primitive(hard_prefix .. service_name [ .. hard_suffix])`
Lua concatenation — no quoting, no escaping. With pre-fix `service_name`
admin input, each is a command-injection sink.

## Caller

`rest.lua` → `service_action_handler(service_name, action, payload)`.

See `../rest_lua/notes.md` and `../rest_lua/rest.7288.strings.txt` for the
dispatcher routes.

## Privilege

The executing Lua interpreter is spawned by the root-privileged
`lighttpd` instance configured in
`/etc/lighttpd_root_conf.ltp` (sha256 `1f4324d6...`, byte-identical in 7215
and 7288), bound to `127.0.0.1:16667`, which the user-facing lighttpd
proxies all `/api/` requests to. The file's top comment reads
"Run new instance of lighttpd with root privilege".

Consequently `popen`/`os.execute` run with uid 0.
