# remoteshellenable / init_sshenable - Master & Satellite Analysis

**Question:** Is `remoteshellenable` a vendor-intended master->satellite remote-shell
mechanism, and does it give the owner a path to a satellite root shell?

**Method:** Static RE of extracted firmware (all four trees) + correlation with live-master
read-only output. No execution, no packets sent, no config changes.

**Date:** 2026-11-02. Labels: VERIFIED / STRONGLY INDICATED / HYPOTHESIS / UNKNOWN / RULED OUT.

---

## 1. Artifact inventory

| Binary | rbre_7215 | rbre_7288 | rbse_7215 | rbse_7288 | Notes |
|---|---|---|---|---|---|
| `/usr/sbin/remoteshellenable` | [yes] | [yes] | [yes] | [yes] | **Byte-identical in all four** (sha256 `1d4ac867...`, 17436 B). ARM, musl, stripped. |
| `/usr/sbin/telnetenabled` | [yes] | [yes] (differs) | [no] | [no] | Legacy; **master-only**. `init_sshenable` kills/removes it before starting remoteshellenable. |
| `/etc/init.d/init_sshenable` | [yes] | [yes] | [yes] | [yes] | Launcher. **Not** in `rc.d` (no boot symlink). |
| `/etc/hotplug.d/iface/95-ssh` | [yes] | [yes] | [yes] | [yes] | **Identical** master/sat/version. The actual trigger. |
| `/etc/init.d/sshd` + `/usr/sbin/sshd` (OpenSSH) | [yes] | [yes] | [yes] | [yes] | What gets started on success. |

VERIFIED: the mechanism is **present and identical on the satellite**, unchanged 7.2.7.15 -> 7.2.8.8.

## 2. The trigger chain (VERIFIED, static)

```
br-lan ifup/ifupdate
  -> /etc/hotplug.d/iface/95-ssh
      -> /etc/init.d/init_sshenable stop; start
          -> kill telnetenabled; rm telnetenabled
          -> /usr/sbin/remoteshellenable        # daemonizes, UDP listener
              -> (on valid authenticated knock) -> /etc/init.d/sshd start
```

`95-ssh` fires on every `br-lan` ifup, so the launcher runs at runtime (not via rc.d).
STRONGLY INDICATED: `remoteshellenable` is **running on the live satellites** (br-lan comes
up at boot). Not yet runtime-confirmed - see §7. (The master `ps` dump did not disprove it;
its grep filter excluded the process name.)

## 3. What remoteshellenable does (ELF evidence)

- **Imports:** `socket, bind, recvfrom, sendto, setsockopt, htonl, htons, select` (UDP server);
  `ioctl` (reads `br-lan` MAC - string `"Can't get the MAC address of %s."`);
  `daemon` (backgrounds); `vfork/execve/wait4` (runs a child); `memcmp` (auth compare);
  `fopen/fgets` (reads `/tmp/httpwd`); `libjson-c`. (VERIFIED)
- **Strings:** `AMBIT_TELNET_ENABLE+%s`, `br-lan`, `/tmp/httpwd`,
  `/usr/sbin/ssh_update_ntgr.sh`, `/etc/init.d/sshd`, `0123456789ABCDEF` (hex encode),
  `.hash`, `"The sshenable is running ..."`, `"The ssh server is enabled now!!!"`. (VERIFIED)

**Behaviour (STRONGLY INDICATED):** daemonizes; obtains `br-lan` MAC; invokes
`ssh_update_ntgr.sh` to write the **admin password hash** to `/tmp/httpwd`; binds a UDP
socket; waits for a "secret-knock" datagram whose expected value is derived from the
`AMBIT_TELNET_ENABLE` magic + device MAC + admin-password hash (classic NETGEAR
telnet/ssh-enable scheme); on a `memcmp` match it `execve`s `/etc/init.d/sshd` to start
**OpenSSH** (not Dropbear, not telnet).

UNKNOWN (not extracted; would require decompilation): exact UDP port, exact hash algorithm,
exact datagram layout. These do not affect the conclusion in §5.

## 4. ssh_update_ntgr.sh / /tmp/httpwd relationship (VERIFIED)

`ssh_update_ntgr.sh` supplies the **authentication secret** remoteshellenable checks against:

```sh
if [ -f /tmp/ntgr_satellite ]; then nvram get http.passwordHash > /tmp/httpwd      # satellite branch
else echo `fnvram get http_passwd_digest` | awk '{print toupper($0)}' > /tmp/httpwd  # router branch
fi
```

So the knock is gated on the **owner's own admin credential hash** + device MAC. It is an
*authenticated* feature, not an unauthenticated backdoor, and it uses an independent
credential (admin hash), **not** an SSH key.

## 5. The blocker - the sshd it starts is NETGEAR-maintenance-only (VERIFIED)

Satellite `/etc/ssh/sshd_config`:

```
Port 22
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication no        # <- no password login
UsePAM no
AuthorizedKeysFile /etc/ssh/id_rsa.pub
```

- `AuthorizedKeysFile` is the shipped **NETGEAR fleet public key** `/etc/ssh/id_rsa.pub`
  (`ssh-rsa root@<vendor-build-host>`). Root login is accepted **only** for the holder of the
  matching **fleet private key**.
- That private key is **not on the master** (prior exhaustive search found no match - fleet
  key `[[orbi-rbse960-satellite-ssh]]` Option A RULED OUT). It is held by NETGEAR.
- `PasswordAuthentication no` + root shadow field empty => the empty root password is
  **not** remotely usable.
- `/root/.ssh/authorized_keys` does not exist in the image; the only authorized key is the
  fleet pubkey.

**Therefore:** the owner (or a knock issued from the master using the owner's admin hash)
can *start* the satellite's sshd, but **cannot authenticate to it** - only NETGEAR, holding
the fleet private key, can. This is a **vendor maintenance/diagnostic mechanism**, not an
owner-administration path.

## 6. Deliverable answers

1. **What does remoteshellenable do?** An authenticated UDP "secret-knock" daemon that, on a
   packet keyed to the device's br-lan MAC + the admin password hash, starts OpenSSH `sshd`.
   (VERIFIED it targets sshd; STRONGLY INDICATED on the knock composition.)
2. **Does it communicate with satellites?** No. It is a **local listener on each device**.
   There is no master->satellite transport inside it (no satellite-inventory use, no outbound
   to <satellite-1-ip>/.11). A knock could be *sent* to a satellite over the LAN by anything on
   br-lan, but the binary itself is per-device and local. (VERIFIED - no inventory/remote refs.)
3. **What does ssh_update_ntgr.sh supply?** The admin-password-hash auth secret, into
   `/tmp/httpwd`, which remoteshellenable reads to validate the knock. (VERIFIED)
4. **Why does the master have init_sshenable?** It is the launcher invoked by the `95-ssh`
   br-lan hotplug to run remoteshellenable; present on both master and satellite. (VERIFIED)
5. **Master vs satellite difference?** remoteshellenable, init_sshenable, 95-ssh, and sshd
   are identical. Only difference: master also ships legacy `telnetenabled` (satellite does
   not). Functionally equivalent. (VERIFIED)
6. **Does an authenticated vendor satellite remote-shell capability exist?** **Yes - but for
   NETGEAR, not the owner.** The enable step is owner-authenticated (admin hash); the login
   step requires the NETGEAR fleet private key the owner does not possess. (VERIFIED)
7. **Evidence:** §1-§5 - identical binary hashes, the hotplug->launcher->sshd chain, ELF
   imports/strings, and the satellite `sshd_config` + fleet `AuthorizedKeysFile`.
8. **Next safe step:** read-only runtime confirmation (§7).

## 7. Next safe step - read-only runtime checks (from master root shell; non-changing)

- Is the listener actually up on a satellite? `ps w | grep -i remoteshellenable` (note: must
  grep that exact name). From master: `nmap -sU <satellite-1-ip>` is change-nothing but active; a
  purely passive alternative is to read it once a satellite shell exists.
- Is the satellite already serving sshd? From master: `nc -z -w2 <satellite-1-ip> 22` / a TCP connect
  probe (read-only), and compare the satellite's live `sshd_config` to the image.
- Confirm the live satellite `AuthorizedKeysFile` really is the fleet pubkey (matches image).

**Do not** send a crafted enable knock or start any service - enabling a maintenance sshd the
owner cannot log into provides no benefit and changes device state.

## 8. Bottom line

`remoteshellenable` is a real, authenticated, vendor-intended remote-shell **enabler** that
exists on the satellite and is wired to a hotplug trigger. It is **not** an owner path to a
satellite root shell, because the OpenSSH instance it launches authorizes root **only**
against the NETGEAR-held fleet key (`PasswordAuthentication no`). Getting owner SSH on the
satellite still reduces to changing the satellite's authorized key / sshd policy - which
needs an existing shell or a (signature-gated) firmware image, i.e. the custom-firmware
track - not this mechanism. This refines, and does not overturn, report 24's conclusion:
the *enable* path exists; the *login* path is vendor-locked.
