# remoteshellenable — exhaustive path & exec map

**Binary:** `/usr/sbin/remoteshellenable`
**SHA256:** `1d4ac86700e4a6b8993ed5ed2a576642a08565c294e087f55124c99e7eabe8de`
**Size:** 17436 bytes (.text = 7008 B, .rodata = 4500 B)
**Arch:** ARM:LE:32
**Byte-identical on:** RBRE V7.2.7.15, RBRE V7.2.8.8, RBSE V7.2.7.15, RBSE V7.2.8.8.

## Launch chain (both master & satellite)

```
br-lan ifup hotplug
  → /etc/hotplug.d/iface/95-ssh
     → /etc/init.d/init_sshenable start
         → kill any prior telnetenabled    (+ rm -rf usr/sbin/telnetenabled — note: "usr/..." is relative)
         → exec /usr/sbin/remoteshellenable (no args)
```

The binary takes **no CLI args** (argv is never read — no `getopt`, no `argc` check, no env-var read for runtime toggles) and no stdin; it only listens on a socket.

## Socket surface

- `socket(AF_INET, SOCK_DGRAM, 0)` bound via `SO_BINDTODEVICE` to **br-lan**, `SO_BROADCAST=1`.
- `bind(…, port = htons(0x17) = 23, addr = 0.0.0.0)` → **UDP/23 on the LAN bridge only**.
- `daemon(1,1)` then the sole packet loop: `select → recvfrom(buf=512B) → …`.

## Complete inventory of magic strings / markers (`.rodata` scan)

The ENTIRE rodata user-string set, in address order:

```
lan_bridge              br-lan                lan_iface
0123456789ABCDEF        /tmp/httpwd           admin
AMBIT_TELNET_ENABLE+%s  /bin/rm               /usr/sbin/ssh_update_ntgr.sh
/etc/init.d/sshd        start
The ssh server is enabled now!!!
The sshenable is running ...
Can't open the socket!
Can't get the MAC address of %s.
can not open %s %s
warning: drop some argv!
```

There is **exactly one** magic token in the binary: `AMBIT_TELNET_ENABLE+%s` (the `%s` is substituted with the admin password hash — see below). No `DROPBEAR`, `TELNETD`, `BUSYBOX`, `/bin/sh`, `DEBUG`, `FACTORY`, `UNLOCK`, `BACKDOOR`, or second magic marker exists.

## Complete inventory of exec/system paths

The binary has **ONE** `execve` call site, inside the generic `FUN_000120a8(stdout, stderr, flags, path, argv1, …)` spawn helper (`vfork → execve → wait4`). The whole binary calls that helper from **three fixed sites in `main()` / `FUN_00012484()`**, with these hard-coded program paths:

| # | exec'd program             | argv              | when                                                     | auth gate |
|---|----------------------------|-------------------|----------------------------------------------------------|-----------|
| 1 | `/usr/sbin/ssh_update_ntgr.sh` | (none)        | **every** recvfrom packet, BEFORE auth check             | **none** — runs on any unsolicited UDP packet |
| 2 | `/bin/rm`                  | `/tmp/httpwd`     | after expected-token build (end of `FUN_00012484`)       | n/a (cleanup) |
| 3 | `/etc/init.d/sshd`         | `start`           | only after `memcmp(pkt, expected) == 0`, and only once (`bVar1` latch) | admin-hash + MAC-hex ciphertext match |

No `system()`, no `popen()`, no `/bin/sh`, no `dropbear`, no `telnetd`, no `/etc/init.d/telnet`, no `dropbearkey`, no shell-command formatting. The varargs-truncation message `"warning: drop some argv!"` is an internal safety warning inside `FUN_000120a8` when the varargs list exceeds its 100-slot buffer; it is **not** a CLI-arg handler for `remoteshellenable` itself.

## The crypto path (expected-token build — `FUN_00012484`)

1. Read admin hash from `/tmp/httpwd` into `pwhash[0x87]`.
2. `ioctl(SIOCGIFHWADDR, "br-lan")` → 6-byte MAC, converted to 12 uppercase hex chars (`0123456789ABCDEF` table) in `mac_hex[12]`.
3. Assemble a 112-byte (0x70) Blowfish key block:
   - `mac_hex` (16 bytes, including NUL padding)
   - literal `"admin\0"` (bytes 16..32)
   - `pwhash` (up to 135 bytes, used only up to key-length 112)
4. Blowfish init → key schedule with that 112-byte key (`FUN_00011dd8`, `FUN_00011e18`).
5. Derive 16-byte IV from the keyed context (`FUN_00011ef4`).
6. Plaintext: `snprintf(buf, 0x100, "AMBIT_TELNET_ENABLE+%s", pwhash)`.
7. Pad the plaintext (`FUN_000111d4`).
8. Blowfish-encrypt plaintext with the IV → `expected_ciphertext` (up to 0xf8 = 248 bytes). This is the length returned to `main`.
9. `rm /tmp/httpwd` (hash file is ephemeral per packet).

`main()` then does `memcmp(received_packet, expected_ciphertext, len) == 0` as the ONLY auth check. On success it spawns `/etc/init.d/sshd start` and sends back a 3-byte `"ACK\0"` (literal `0x4b4341` little-endian).

**The same crypto path is used for every packet.** There is no alternate packet-type byte, no magic prefix dispatch, no second cipher mode, no byte-count-based branching. No weaker-authenticated variant.

Master/satellite asymmetry lives OUTSIDE this binary, in `ssh_update_ntgr.sh`, which decides how `/tmp/httpwd` gets populated:

- If `/tmp/ntgr_satellite` exists → `nvram get http.passwordHash > /tmp/httpwd` (satellite).
- else → `` `fnvram get http_passwd_digest | awk toupper` `` > `/tmp/httpwd` (master).

Either way, the binary ends up with the admin-password hash as the shared secret.

## (a) Complete list of exec/system calls + auth condition

- See table above. Three exec sites total, one and only one lands on a service (`sshd`) and it is gated by the Blowfish-knock memcmp.

## (b) Complete list of magic-packet "modes"

- **One mode.** `AMBIT_TELNET_ENABLE+<admin_hash>` encrypted under Blowfish with a key derived from the br-lan MAC + the literal `"admin"` + the admin-hash. 248-byte ciphertext expected. No alternative magic, no bypass marker, no fallback.

## (c) Weaker-authenticated branch?

- **None.** Every path through `main()` that reaches exec-sshd goes through the same memcmp. The one unauthenticated side effect is that *any* UDP/23 packet on br-lan causes `/usr/sbin/ssh_update_ntgr.sh` to run (refreshing `/tmp/httpwd`). That script is itself nvram-read-only and produces an owner-controlled file; it does not grant a shell.

## (d) Verdict

- **No legitimate owner-knockable path in this binary opens telnetd, dropbear, `/bin/sh`, or any non-key-gated shell.** The only effect of a valid knock is `/etc/init.d/sshd start` — which on both RBRE and RBSE loads OpenSSH with the fleet-key-gated `sshd_config` (per [[orbi-rbse960-satellite-ssh]], confirmed byte-identical sshd config path).
- The user's intuition that "telnet should switch on ssh" is partially correct in the historical sense — `AMBIT_TELNET_ENABLE` is the legacy NETGEAR "telnet enable" magic string repurposed here to start sshd instead of telnetd. There is no branch that *actually* starts telnetd. The binary used to (hinted by the `telnetenabled` pidof/kill in `init_sshenable`), but this build drops that path entirely.
- No argv/env/debug/factory handling. No command injection in the exec wrapper (fixed program path, static argv). No path traversal (no attacker-controlled filenames). No shell meta-chars reach a shell (no shell is invoked).

## Follow-on question (outside this fork's scope)

The upstream unlock remains: even with a valid owner knock, the sshd that starts refuses password auth and accepts only the fleet pubkey (whose private key was ruled out at firmware level and on the live master, per prior reports). Any owner-shell path has to come from a different mechanism than this binary. `remoteshellenable` is correctly implemented and offers no additional owner surface.
