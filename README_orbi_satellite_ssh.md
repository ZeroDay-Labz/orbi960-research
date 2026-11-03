# orbi_satellite_ssh.py - Owner-controlled SSH for RBSE960 satellites

A read-only-by-default utility to discover, inspect, and (when an authorized
first-shell exists) provision owner-controlled **dropbear** SSH on two personally
owned NETGEAR Orbi **RBSE960** satellites, without disturbing the Orbi mesh.

Companion to the RBRE960 tooling (`orbi_root_shell.py`, `seal_dropbear_enable.py`).
Full analysis: `firmware_analysis/reports/20`, `21`, `22`.

> **Read this first.** The satellite firmware has **no supported remote
> configuration operation** that can turn on SSH (verified - see report 22 §2-3).
> So `enable --apply` can *apply* the change only when a root shell on the satellite
> already exists by a means you have authorized (i.e. TCP 22 or 23 already open).
> On a stock satellite (22/23 closed) it will **refuse with a clear blocker** rather
> than exploit a service. The read-only modes work fully regardless.

## Requirements

- Fedora Linux, Python 3.11+ (developed on 3.14), standard library only.
- `ssh` client in `PATH`; verified root SSH to the master (`~/.ssh/orbi_rbre960_rsa`).
- Your SSH **public** key (default `~/.ssh/orbi_rbre960_rsa.pub`, or `--pubkey PATH`).

## Quick start

```bash
# 1. find the satellites and see the inventory (read-only)
python3 orbi_satellite_ssh.py discover

# 2. detailed status; add --admin to read dropbear uci via authenticated ubus
python3 orbi_satellite_ssh.py status
python3 orbi_satellite_ssh.py status --admin

# 3. see exactly what 'enable' would change (read-only)
python3 orbi_satellite_ssh.py plan

# 4. provision ONE satellite (requires an authorized first-shell; see blocker note)
python3 orbi_satellite_ssh.py enable --satellite 1 --apply

# 5. independently verify, and roll back if needed
python3 orbi_satellite_ssh.py verify   --satellite 1
python3 orbi_satellite_ssh.py rollback --satellite 1
```

## Modes

| Mode | Changes device? | Summary |
|---|---|---|
| `discover` | no | Master neighbour/DHCP tables -> match known MACs -> confirm model/firmware via `currentsetting.htm`. Prints an inventory table. IPs are discovered, never hardcoded. |
| `status [--admin]` | no | Per-satellite: TCP 22/23, identity/firmware; with `--admin`, reads `dropbear` uci via an authenticated ubus session (prompts for the admin password). |
| `plan` | no | Prints the exact commands `enable` would run and the bootstrap requirement. |
| `enable --satellite N [--apply]` | yes* | Without `--apply`: dry run (= `plan`). With `--apply`: identity check -> backup -> resolve an **authorized** transport -> explicit `yes` confirm -> apply -> verify. One satellite per invocation. *Refuses if no authorized transport (:22/:23) is open. |
| `verify --satellite N` | no | TCP 22 reachable, `ssh root@... id` shows `uid=0`, and mesh daemons (`hyd/wsplcd/repacd/lbd`) still up. |
| `rollback --satellite N` | yes | Over SSH: stop+disable dropbear, restore the uci backup, remove **only** the key this tool installed. |

Global flags: `--pubkey PATH` (owner public key), `--no-log` (disable audit logging).

## What `enable` changes (and does not)

Changes, all in the writable overlay (`firmware_analysis/reports/22` §4):
- `/etc/dropbear/authorized_keys` - appends your **public** key (idempotent).
- `/etc/config/dropbear` - `enable='1'`, `PasswordAuth='off'`, `RootPasswordAuth='off'`.
- `/etc/init.d/dropbear enable + restart` - key-only SSH on LAN :22, auto-starts at boot.

Never touched: `hyd`, `wsplcd`, `repacd`, `lbd`, Wi-Fi/radio/backhaul, NSS/ECM,
calibration/regulatory data, flash partitions, the bootloader, NETGEAR Armor. No
firewall flush; a LAN-only :22 rule is added only if not already allowed; SSH is
never exposed on WAN.

Reboot-persistent (overlay). A firmware upgrade that rewrites the rootfs clears it
(re-run `enable`).

## Security & safety

- Single, deliberate authentication - **no** password guessing or retry loops.
- Passwords read via `getpass`, never passed on the command line; never printed.
- Your **private** key is never requested, transmitted, stored, or placed on a
  device; a private key given as `--pubkey` is rejected. Logs are redacted.
- TLS to the satellite is **cert-pinned** (trust-on-first-use + fail-on-change),
  not blanket-disabled. SSH host keys are pinned in a tool-managed `known_hosts`.
- Explicit timeouts; partial failures are reported; **never** claims success unless
  SSH + UID 0 are independently verified.
- State (backups, audit logs, pins, known_hosts) under `~/.orbi_satellite_ssh/`.

## The bootstrap blocker (why `enable` may refuse)

The RBSE960 has no Seal `enable_ssh`, its ubus ACL grants `uci` **read-only** (and the
ACL's `telnet_enable` method is **not implemented** in the shipped plugin), and the
vendor OpenSSH path needs a NETGEAR-held key. With 22/23 closed there is no authorized
way to make the first change remotely, so `enable --apply` exits with
`BLOCKED: ...` (code 3). Resolving this is a policy decision (accept no-SSH, or authorize
a modified-firmware upgrade route) - see report 22 §8. The tool will not bypass auth,
inject commands, or exploit a management service to get around this.

## Testing

```bash
python3 -m unittest test_orbi_satellite_ssh -v   # 24 mocked tests; no device contact
```

## Exit codes

`0` success - `1` aborted by user - `2` usage/identity error - `3` bootstrap blocked -
`4` partial apply failure - `5` verification failed.
