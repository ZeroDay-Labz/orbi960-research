# orbi-owner-agent — Security model

## Threat model

### Adversaries

1. **Unauthenticated remote attacker on WAN.** Mitigation: the agent has
   no WAN listener. It is callable only via the local `ubus` UNIX socket.
   The firewall (vendor-controlled; see `known-limitations.md`) must not
   be re-opened to allow WAN→rpcd.
2. **Unauthenticated LAN attacker.** Mitigation: `ubus`'s default UNIX
   socket is `0666` on OpenWrt, so any user on the device could connect
   if they obtained one. On this firmware, LAN clients cannot reach the
   `ubus` socket directly — they can only reach services NETGEAR exposes
   (lighttpd 80/443 → SOAP/Seal). We do not add an HTTP route, so LAN
   attackers have no path to the agent.
3. **Authenticated non-owner LAN user.** Not applicable: this firmware
   does not offer an unprivileged user login. Any SSH-authenticated user
   is root by design.
4. **Malicious owner-controller compromise.** Mitigation: the ACL allows
   only an allowlisted method surface. Even if the external Proxmox
   controller is compromised, it cannot call `exec`, `write_file`, or
   `install` — those methods do not exist on the agent.
5. **Local on-device attacker (root).** Out of scope. A root-local
   attacker already has every capability the agent provides.
6. **Supply-chain attacker on the OpenWrt feed.** Mitigation: the owner
   builds the `.ipk` from the source tree in this repository; signed
   release artifacts are optional. `opkg --force-signature` is NOT the
   default install path — see `build-and-install.md`.

### Assets

- Stock Orbi firmware integrity.
- Mesh backhaul operation (VLANs 4093, 4094).
- Owner SSH key authority on the master.
- UCI configuration files.
- CVE-2026-0415-patchable state (owner should upgrade; the agent does
  not depend on an unpatched Seal handler).

### Trust boundaries

```
+----------------------------+       +------------------------------+
| External Proxmox owner VM  |       | NETGEAR Orbi RBRE960 (master)|
| - Web UI                   |  SSH  | - sshd (dropbear, root key)  |
| - Auth (TOTP + password)   |------>| - ubusd (UNIX socket)        |
| - Policy engine            |       |   |                          |
| - Backup store             |       |   +---rpcd                   |
+----------------------------+       |        |                     |
                                     |        +---/usr/libexec/rpcd/|
                                     |              orbi-owner-agent|
                                     |                              |
                                     | Satellites unreachable       |
                                     +------------------------------+
```

- Trust crosses on **SSH authentication** (owner RSA key).
- The agent itself is **not** a trust boundary — it assumes its root
  caller is the owner, which SSH has already enforced.
- The ACL exists for defense in depth: it will refuse the agent's own
  dangerous methods even to a non-root caller that somehow gets a ubus
  handle.

## Attack-class controls

### Command injection

Every system call uses `argv`, never a shell-concatenated template.
Where a shell is used (e.g., `uci commit && echo ok`), no caller input
appears in the shell text. All input is placed in environment variables
after validation; the shell interpolation reads those env vars only
by exact name.

### Path traversal

No method accepts a caller path. `backup` tars a hardcoded allowlist
of files; `audit_tail` reads one hardcoded log path; UCI writes operate
on named sections only.

### UCI injection

UCI arguments are quoted with explicit discrete argv. No `uci set
network.$name.ifname=$val` style shell template is used anywhere.
Instead: `uci -q set "network.$name.ifname=$val"` where `$name` and
`$val` are already validated and the shell is invoked with
`"$@"`-safe argv.

### ubus authorization

The ACL enumerates every method by name. Adding a method requires
updating `orbi-owner-agent.json` — removing one is a one-line change.

### UID / privilege

The plugin runs as **root** because rpcd invokes its exec plugins as
root — this is unavoidable on this platform. We minimize this by:
- Making the plugin *source-readable* and *small* (so it is auditable).
- Not binding any listener.
- Keeping privileged operations to the specific UCI sections we author.

### File permissions

| path                                                     | mode |
|---|---|
| `/usr/libexec/rpcd/orbi-owner-agent`                     | 0755 |
| `/usr/share/rpcd/acl.d/orbi-owner-agent.json`            | 0644 |
| `/usr/share/orbi-owner-agent/lib/*.sh`                   | 0644 |
| `/etc/config/orbi-owner-agent`                           | 0644 |
| `/etc/init.d/orbi-owner-agent`                           | 0755 |
| `/etc/uci-defaults/80-orbi-owner-agent`                  | 0755 |
| `/tmp/orbi-owner-agent.log`                              | 0640 |

No file is setuid. No file is world-writable.

### Credential exposure

- The agent never reads the owner password hash, Dropbear host key,
  SSH authorized_keys, any key material from `/etc/dropbear/`, NVRAM
  secrets, backhaul passphrases, or SOAP admin hashes.
- The `backup` method tarballs ONLY the agent's own UCI file and the
  parts of `/etc/config/network` that the agent authored (sections with
  name prefix `owner_`). Vendor-authored sections are **excluded**.

### Logging

Every call writes one audit line with validated-argument copies.
Logs never contain file contents, NVRAM values, keys, or passwords
because no method surfaces those as arguments.

## Known residual risks

- **Vendor firewall is not uci-covered.** If the owner re-opens
  WAN→rpcd by some vendor mechanism, the agent becomes remote-reachable.
  We cannot prevent this from the agent; `known-limitations.md`
  documents it.
- **CVE-2026-0415 unpatched on vulnerable firmware.** If the owner runs
  V7.2.7.15 and an authenticated admin opens the Seal `install`
  endpoint with a crafted `service_name`, a shell command could
  conceptually replace our plugin binary. Owner should upgrade to
  V7.2.8.5+ (which includes the CVE-0415 fix we located in reports
  37/38) **before** relying on this agent for anything security-sensitive.
- **Package signature.** The stock `opkg` has `check_signature` set.
  The owner's `.ipk` is unsigned by default, so install requires
  either an explicit `--force-signature` or pre-staging to `/ipk/`.
  `build-and-install.md` details both paths.
- **No tamper detection.** If a root-local attacker overwrites
  `/usr/libexec/rpcd/orbi-owner-agent`, the next call runs the
  attacker's code. This is identical to any OpenWrt package's trust
  model — root can always replace a file; the defense is that no
  non-root caller can.
