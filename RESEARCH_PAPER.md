# Owner-Authorized Administrative Access and Firmware Architecture of the NETGEAR Orbi RBRE960 / RBSE960 (Qualcomm IPQ807x)

A technical research paper on the stock-firmware administrative surface, the
master-to-satellite management plane, firmware packaging and update behavior, and
the practical limits of owner control on a quad-band Wi-Fi 6E Orbi system, based
on static firmware analysis and read-only observation of owned hardware.

Evidence labels used throughout: **VERIFIED**, **STRONGLY INDICATED**,
**HYPOTHESIS**, **UNKNOWN**, **RULED OUT**.

---

## 1. Abstract

The NETGEAR Orbi RBRE960 router and RBSE960 satellites are an OpenWrt-derived,
Qualcomm IPQ807x quad-band Wi-Fi 6E mesh system. This paper establishes, with
firmware and read-only runtime evidence, four results.

First, root access on the RBRE960 router is reachable through an existing,
administrator-authenticated mechanism in the stock firmware: a Seal REST endpoint
that verifies the admin credential, installs a caller-supplied SSH public key, and
starts the Dropbear SSH daemon with key-only root login. This is an intended
vendor capability, not an exploit or an authentication bypass. A verified
interactive root shell (user id 0) was obtained this way.

Second, that mechanism is unchanged between firmware V7.2.7.15 and V7.2.8.8: the
handler is byte-identical across the two releases, while the surrounding REST
dispatcher was hardened in the newer release in a way that does not alter the
credentialed contract.

Third, the RBSE960 satellites expose no equivalent owner path. They ship no Seal
endpoint, ship Dropbear disabled with no remote way to enable it, expose a
read-only authenticated UCI surface over ubus, and reach a vendor remote-shell
daemon whose OpenSSH instance is locked to a NETGEAR-held key the owner does not
possess. The master-to-satellite management plane is a fixed, typed SOAP interface
plus the Qualcomm Wi-Fi SON daemons, none of which can enable SSH, write an
arbitrary file, or run an arbitrary command.

Fourth, the kernel and root filesystem portion of the firmware image is not
cryptographically signed; its only gates are a recomputable checksum, a board-ID
match, and integrity hashes. Qualcomm secure boot, if the relevant device fuses
are set, covers the bootloader chain only. Whether a modified image would actually
boot is therefore not established from the shipped artifacts alone, and no image
was built or flashed.

## 2. Introduction

Rooting consumer Orbi hardware for owner administration is established ground, but
a documented, administrator-authenticated path on the RBRE960 specifically, and a
careful map of what the RBSE960 does and does not allow, were not readily
available. This research was undertaken by the device owner to obtain and
understand owner-authorized administrative access to a personally owned system, to
determine whether that access survives firmware updates, and to assess what
additional owner control is practical on stock firmware without flashing or
modifying the devices.

The work proceeded in four stages: router root via the stock authenticated
mechanism; a firmware comparison across two releases and across the two models; a
satellite administration study; and a feasibility assessment of an out-of-band
owner-control model that drives the unmodified devices over authenticated SSH and
ubus.

## 3. Research objectives and scope

Objectives:

1. Determine whether a stock, owner-authenticated path to a root shell on the
   RBRE960 exists, and if so characterize it precisely.
2. Determine whether that path survives the upgrade to the latest firmware.
3. Determine whether any equivalent owner path exists on the RBSE960 satellites,
   and map the master-to-satellite management plane.
4. Characterize firmware packaging, the update mechanism, persistence behavior,
   and image-integrity enforcement, without flashing.
5. Assess owner-control capabilities (visibility, VLANs over the mesh backhaul,
   configuration rollback) achievable on stock firmware.

Scope and constraints: owned hardware, isolated LAN, owner credentials and keys
only; static and read-only analysis preferred; no factory reset, no UART, no
bootloader or flash modification, no firmware flashing in this phase; no password
guessing, authentication bypass, command injection, or exploitation of management
services. No device-changing action without a stated effect and rollback.

## 4. Hardware architecture

| Property | Value | Confidence |
|---|---|---|
| Router model | RBRE960 (board id `U12H451T00_NETGEAR`) | VERIFIED |
| Satellite model | RBSE960 (board id `U12H452T00_NETGEAR`; image also covers RBS960/RBSE950) | VERIFIED |
| SoC | Qualcomm IPQ807x | VERIFIED |
| CPU architecture | 32-bit ARM (ARMv7l) | VERIFIED |
| C library | musl (`/lib/ld-musl-arm.so.1`) | VERIFIED |
| Kernel | Linux 4.4.60 | VERIFIED |
| Radios | quad-band (2.4 GHz, 5 GHz fronthaul, 5 GHz backhaul, 6 GHz) | VERIFIED (interfaces observed) |

The router and satellite are distinct hardware image classes with different NAND
layouts and different board-ID gates; their firmware images are not
cross-flashable (VERIFIED). Radio calibration data, factory MAC and serial data,
and the bootloader live in NAND regions that are not part of the kernel/rootfs
firmware image and are not written by an official rootfs update (STRONGLY
INDICATED; the erase ranges in the update script target only the rootfs UBI
region).

## 5. Qualcomm IPQ807x platform

The firmware is a NETGEAR fork of OpenWrt (the "Chaos Calmer" lineage) on the
Qualcomm QSDK, using procd init, UCI configuration, ubus, and rpcd. The
root filesystem node in the image is named for the ipq807x target. The platform
runs the Qualcomm Wi-Fi SON / Multi-AP stack for whole-home mesh:

- `repacd` (repeater/AP auto-configuration coordinator), with the router acting as
  the controller and each satellite as a managed agent;
- `wsplcd` (backhaul credential and SON synchronization);
- `hyd` (hybrid data-path / backhaul bridging);
- `lbd` (load balancing and band steering).

These daemons synchronize SSIDs, keys, backhaul parameters, VLAN tags, steering,
and roaming across the mesh. They move Wi-Fi state, not files, and expose no
remote shell or file-write primitive (VERIFIED components; "config sync only, no
shell" STRONGLY INDICATED from the binaries' string and import tables).

## 6. Firmware architecture

The container chain is:

```
NETGEAR CHK (magic 0x2a23245e, 58-byte header, board_id gate, recomputable checksum)
  -> U-Boot FIT (magic d00dfeed): metadata.txt, flash.scr, UBI root image, hash nodes
       -> UBI volumes:
            kernel       (FIT: kernel + device trees)
            ubi_rootfs   (SquashFS, xz-compressed, read-only, mounted at /rom)
            rootfs_data  (writable overlay; ships empty)
```

At boot, procd mounts the SquashFS read-only at `/rom` and overlays `rootfs_data`
as the writable upper layer, so writes to `/etc` land in the overlay and survive
an ordinary reboot (VERIFIED/STRONGLY INDICATED). The CHK `board_id` and FIT
`metadata.txt` identify the model and version (VERIFIED).

## 7. Firmware extraction methodology (summary)

See `METHODOLOGY.md` for the full procedure. In brief: carve the FIT past the
58-byte CHK header, parse the FIT, extract and enumerate the UBI volumes, and
unpack the SquashFS root filesystem, recording SHA-256 of each component. The
original vendor archives are not redistributed; recorded hashes let an independent
analyst confirm identical input bytes.

## 8. Filesystem analysis

Key observations on the extracted router root filesystem:

- The web stack is `lighttpd` terminating TLS, which proxies requests under the
  API prefix to the Seal REST backend on the loopback interface; the legacy
  SOAP/HTML admin server is a separate proprietary `httpd` (VERIFIED).
- Credentials are not in `/etc/shadow` (effectively empty); the admin password
  lives in NVRAM at runtime, and authentication paths compare a SHA-256 of the
  entered password against the stored digest (VERIFIED).
- SSH-related startup wiring on the router is broken by design: the Dropbear init
  script is absent while its rc symlinks remain dangling, so Dropbear does not
  auto-start at boot (VERIFIED). It is started on demand by the Seal handler.
- The satellite root filesystem has no Seal web application at all (VERIFIED).

## 9. UBUS and UCI architecture

The platform uses ubus (a local message bus) with rpcd exposing objects under
ACLs. On the satellite the ubus endpoint is reachable from the LAN through a
`lighttpd` proxy to a loopback port, and an authenticated admin session can call
it. The shipped rpcd ACL grants that session UCI **read** access and a set of
logging and upgrade methods, but **no** UCI write and no shell or service-enable
method that could turn on Dropbear or install a key (VERIFIED).

The ACL names telnet enable/disable methods, but the shipped plugin that backs
that object does not implement them (the string does not occur in the binary). A
real telnet enable/status helper is compiled into a shared library, but it is
orphaned: no shipped daemon or plugin imports it, and no ubus object registers a
method that reaches it. It is therefore dead code behind a non-functional control,
which explains why the ACL entry exists while the capability is not remotely
invokable (VERIFIED).

## 10. NETGEAR RPC and SOAP management

The satellite runs a SOAP agent (`soap_agent`, an ONC-RPC plus SOAP service) that
is the on-device management endpoint the router drives, and the router runs the
corresponding SOAP client (`soapc`). The agent exposes a fixed, typed set of
methods (on the order of 50) covering authentication and admin-password sync,
Wi-Fi and mesh and device settings, device naming, NTP and timezone, information
and throughput queries, reboot, factory reset, and firmware update/download
(VERIFIED from the method and response token tables; authentication is an
admin-password-hash session).

The agent exposes **no** SSH, Dropbear, telnet-enable, `authorized_keys`, pubkey,
arbitrary-file-write, UCI-write, or arbitrary-command method (VERIFIED negative).
The only process-spawning calls observed use fixed internal command templates
(for example a configd restart), not request-shaped commands (STRONGLY INDICATED).
The method set is identical between V7.2.7.15 and V7.2.8.8; the `soap_agent`
binary itself differs between the two versions because it carries the
firmware-update logic.

## 11. Satellite management architecture

Consequence of sections 9 and 10: the only supported, authenticated operation that
could place owner-controlled code on a satellite is a firmware update through the
vendor update methods, that is, installing a modified image. Every other supported
remote operation is scoped to Wi-Fi/mesh/device configuration, reboot, factory
reset, and firmware update, and that scope is unchanged in the newer firmware. The
mesh/SON daemons synchronize Wi-Fi parameters, not files. There is therefore no
supported management-plane route to a satellite root shell (STRONGLY INDICATED,
exhaustive over the reachable surfaces and the extractable code). This refines
rather than contradicts the vendor remote-shell finding in section 13: the
*enable* path exists on the satellite, but the *login* path is vendor-locked.

## 12. Dropbear and OpenSSH implementation

The platform ships both Dropbear and OpenSSH, used differently on the two models.

On the router:

- Dropbear (version 2019.78) is present. It is launched directly by the Seal
  `enable_ssh` handler with key-only, root-permitted flags; it is not started from
  its init script (which is absent) and not from UCI (VERIFIED).
- It reads the owner's installed key from the Dropbear `authorized_keys` path and
  regenerates its host key on each start (so the client must re-learn the host key
  after every enable or reboot) (VERIFIED).
- OpenSSH is present but, as shipped, is not an owner entry path: its
  configuration disables password authentication, pins `AuthorizedKeysFile` to a
  single fixed file containing a NETGEAR-held public key, and wraps every session
  in a `ForceCommand`. It is started only by the vendor remote-shell daemon on a
  valid authenticated packet (VERIFIED; RULED OUT as an owner first-foothold).

On the satellite:

- Dropbear is present, its init script is a complete working init, and its rc
  symlink is present, so it would auto-start at boot if enabled. But its UCI config
  ships disabled, no `authorized_keys` is shipped, and there is no remote method to
  enable it. TCP 22 and 23 were observed closed on both satellites (VERIFIED).
- OpenSSH on the satellite is the target of the vendor remote-shell daemon and is
  locked the same way as on the router (section 13).

## 13. Remote-shell initialization architecture

Both models ship a vendor remote-shell enabler, `remoteshellenable`, launched by a
LAN-bring-up hotplug rule (not from the rc boot sequence). It is an authenticated
"magic packet" daemon in the long-standing NETGEAR `AMBIT_TELNET_ENABLE` family:
it reads the admin-password hash (written by a helper script) and the LAN bridge
MAC, listens on a datagram socket, and on a packet that matches a locally computed
expected value starts OpenSSH (VERIFIED that it targets OpenSSH; the exact listen
port, packet layout, and hash algorithm are STRONGLY INDICATED from the stripped
binary's strings and imports, not byte-verified, and are not reproduced here).

The decisive limitation: the OpenSSH instance it starts authenticates root only
against a NETGEAR-held public key, with password authentication disabled. No
matching private key exists in either firmware image, and a read-only search of
the running router found no on-device private key deriving that public key. So the
owner (or a packet issued using the owner's admin hash) can start the daemon but
cannot authenticate to it. This is a vendor maintenance and support channel, not
an owner-administration path (VERIFIED for the mechanism; the "vendor only"
conclusion follows from the configuration plus the absence of the private key).

The legacy `telnetenabled` daemon exists on the router only and is removed at LAN
bring-up by the same launcher. A BusyBox telnet path exists but is gated on a
marker file that nothing in any of the four images creates, so it is dormant
(RULED OUT as an initial access path; a proprietary-GUI trigger is HYPOTHESIS).

The operational magic-packet construction tooling and the extracted cipher
constants are deliberately not part of this publication (see `SECURITY.md`); this
section describes the mechanism and its security implication only.

## 14. Authentication and authorization

Across the platform, administrative authentication reduces to the admin web
password: paths compare a SHA-256 digest of the entered password against the
stored digest (lowercase hex in NVRAM on the router; a hashed NVRAM variable in
satellite mode). The router's Seal `enable_ssh` handler self-authenticates on the
submitted admin credential and has a small failed-attempt counter held on tmpfs
that resets on reboot; it requires no separate web session or CSRF token in the
handler path (VERIFIED).

A security-relevant design note, observed by static analysis and not exercised:
the handler computes the password digest by interpolating the password into a
shell command without quoting. A normal password simply hashes; a password
containing shell metacharacters both fails to authenticate and constitutes a
command-injection sink. This is the same class of issue publicly reported in the
Orbi family (see `REFERENCES.md`). No payload is published and none was sent; the
accompanying client refuses passwords containing such characters before opening a
socket.

## 15. Bootloader and partition layout

The Qualcomm boot chain (SBL, QSEE, U-Boot) is present, and the partition table
shows secure-boot-capable regions (QSEE, DEVCFG, APPSBL and their backups) and A/B
duplicates for several partitions. Whether secure boot is actually enforced
depends on fused-in device state (QFPROM), which is not determinable from the
shipped image and was not read; it is UNKNOWN. If enforced, it protects the
bootloader chain, which is not the kernel/rootfs image (section 17).

Radio calibration (ART), factory board data (MACs, serial), and the bootloader
partitions are outside the kernel/rootfs image region that an official update
rewrites (STRONGLY INDICATED from the update script's erase ranges).

## 16. Firmware packaging and update mechanism

An official update rewrites only the rootfs UBI region. Two distinct update paths
exist with opposite persistence effects:

- The OpenWrt `sysupgrade` path keeps the files listed in the upgrade keep-list,
  which includes the Dropbear configuration directory, so an installed
  `authorized_keys` would be preserved across such an upgrade (keep-list content
  VERIFIED).
- The raw U-Boot / recovery path (`flash.scr`: erase then write the rootfs region)
  is fully destructive to the overlay (VERIFIED from the script).

Which path the vendor GUI update actually uses, and whether it invokes the
keep-list save/restore, is implemented in a proprietary binary and is UNKNOWN.
This is the single open question that decides whether an owner's SSH key survives a
normal GUI upgrade. It should not be asserted either way without a controlled test
on recoverable hardware.

## 17. A/B partition architecture and recovery

The partition table and the platform upgrade scripts reference dual rootfs slots
and a boot-selection pointer, consistent with an A/B scheme in which a running
update writes the inactive slot and flips the active pointer, leaving the previous
slot as a fallback (STRONGLY INDICATED, not VERIFIED on these specific models). A
fresh slot gets its own empty overlay.

NETGEAR U-Boot generally supports a TFTP-based firmware recovery mechanism, which
would be the safety net for a bad flash. Whether that recovery behaves as expected
on the RBRE960/RBSE960 specifically was not tested and must not be assumed; it is
STRONGLY INDICATED at the platform-family level and should be confirmed on the
actual hardware before relying on it. No image was flashed, so neither the A/B
switch nor recovery was exercised.

## 18. VLAN and switching capabilities

Runtime observation of the running router shows the mesh backhaul already operates
as an 802.1Q trunk: the firmware tags guest and LAN traffic with distinct VLAN IDs
and carries them across the wireless backhaul and the wired ports today (VERIFIED
from the live interface list). The switch, the kernel bridge, and the access-point
daemon all support additional VLANs, so more segmentation is not blocked by
hardware.

The practical obstacles are (1) the vendor NVRAM and `repacd` configuration layer
that owns virtual-AP and bridge generation, (2) propagating any new VLAN onto the
satellites through a synchronization path built only for vendor-defined networks,
and (3) hardware NAT / NSS offload behavior with custom tags. Deep per-SSID VLAN
segmentation is therefore plausible but high-risk on the Orbi itself; a
VLAN-capable managed switch behind the Orbi is the low-risk alternative when a
clean multi-VLAN design is a hard requirement (STRONGLY INDICATED).

## 19. Wireless and Qualcomm mesh architecture

The system is a controller/agent Multi-AP mesh: the router is the controller and
each satellite a managed agent, synchronized over the Wi-Fi backhaul by the SON
daemons named in section 5. The data path is bridged by `hyd`; control is local to
each device. No part of this plane is a remote-shell or file-provisioning channel
(VERIFIED components; STRONGLY INDICATED for the "no shell/file push" scope).
Satellites are intended to be managed through the router, not administered
directly.

## 20. Security advisories and CVE analysis

The relevant public history is summarized and version-checked in `REFERENCES.md`.
In short:

- The 2022 Cisco Talos Orbi set (CVE-2022-38452 hidden-telnet command execution on
  the RBR750 router; CVE-2022-36429 ubus-backend command execution on the RBS750
  satellite; CVE-2022-37337 access-control command injection) documents the same
  mechanism families this paper maps on the 960 series, on earlier hardware.
- For the 960 series specifically, public vulnerability databases list
  CVE-2026-3088 (out-of-bounds write) as affecting RBRE960 / RBSE960 firmware
  before V7.2.7.15, i.e. fixed at or before the running image. A separate
  authentication-bypass entry (CVE-2026-0405) is described against Orbi devices
  generally but without a confirmed RBRE960 / RBSE960 fixed-version mapping in the
  advisories reviewed, and a stack-overflow entry (CVE-2026-0413) is listed against
  other Orbi router models rather than the 960 series.

The local V7.2.8.5-to-V7.2.8.8 comparison showed Seal REST dispatcher hardening
(section 21) consistent with a generic "security fixes" note, but that observation
does not by itself establish which numbered CVE it addresses. CVE-to-model-and-
version mapping should be taken only from the vendor's advisory tables.

## 21. Firmware version comparison (V7.2.7.15 vs V7.2.8.8)

- The Seal `enable_ssh` handler is **byte-identical** across the two releases, and
  the Dropbear binary is the same version. The owner-authenticated root method
  therefore remains available on the newer firmware; after an upgrade the same
  authenticated request re-installs the key and starts Dropbear (VERIFIED for the
  handler bytes; STRONGLY INDICATED that the end-to-end method is unchanged,
  pending a live test on the newer firmware).
- The Seal REST dispatcher changed: the newer release removes trust of
  client-supplied forwarding and host headers, adds an internal-only request
  header, adds a route-name allowlist, and adds a path-traversal check. This is a
  generic dispatcher hardening and does not alter the credentialed `enable_ssh`
  contract (VERIFIED from the string-constant differences; route equivalence for
  the credentialed path STRONGLY INDICATED).
- On the satellite, the SSH/admin/ubus/rpcd components are byte-identical across
  the two releases; `soap_agent` differs (it carries the firmware-update logic).
- The whole-image file delta on the router is confined away from the SSH surface:
  the added and removed files concern telemetry, agents, and logging utilities, not
  Dropbear, `enable_ssh`, or `sshd`.

## 22. Research findings and evidence

| # | Finding | Confidence |
|---|---|---|
| 1 | RBRE960 root over SSH is reachable through the stock, administrator-authenticated Seal `enable_ssh` endpoint (verify admin credential, install owner public key, start key-only Dropbear). A root shell (uid 0) was obtained. | VERIFIED |
| 2 | The `enable_ssh` handler and request contract are byte-identical between V7.2.7.15 and V7.2.8.8; the surrounding REST dispatcher was hardened without changing the credentialed contract. | VERIFIED (handler bytes); STRONGLY INDICATED (end-to-end on newer firmware) |
| 3 | The RBSE960 satellites expose no owner SSH-enable path: no Seal endpoint, Dropbear shipped disabled with no remote enable, ubus UCI read-only, and the vendor OpenSSH path locked to a NETGEAR-held key. | VERIFIED |
| 4 | The master-to-satellite plane (typed SOAP agent plus Qualcomm SON daemons) exposes no SSH, file-write, or command-execution operation. | VERIFIED (method set); STRONGLY INDICATED (no hidden write/exec) |
| 5 | VLANs already cross the wireless backhaul as an 802.1Q trunk; additional VLANs are not hardware-blocked but are constrained by the vendor configuration layer and satellite propagation. | VERIFIED (runtime trunk); STRONGLY INDICATED (feasibility of more) |
| 6 | Transactional `uci apply/confirm/rollback` is built into rpcd with an in-RAM timer; it does not survive a pre-confirm reboot and does not cover the firewall (which uses an iptables script, not fw3). | STRONGLY INDICATED |
| 7 | The kernel/rootfs image is not cryptographically signed (checksum, board-ID, and integrity hashes only); secure boot, if fused, covers the bootloader only. Whether a modified image boots is not established from the shipped artifacts. | STRONGLY INDICATED (components VERIFIED; boot enforcement UNKNOWN) |
| 8 | An official update rewrites only the rootfs region; persistence across an upgrade is path-dependent and the GUI path is not resolved. | VERIFIED (erase ranges, keep-list); UNKNOWN (GUI path) |

## 23. Owner-control capability assessment (stock firmware)

An out-of-band management model keeps a separate management host out of the
forwarding path while the Orbi remains authoritative for routing, DHCP, DNS, and
mesh; the management host only observes and proposes changes over authenticated
SSH and ubus. The strongest first capability is read-only visibility (topology,
clients, signal, backhaul, traffic counters) collected over SSH, with off-box
configuration backups. Configuration writes should be gated through the native
rollback lifecycle, with the important caveats that the rollback timer is held in
RAM (a pre-confirm reboot keeps a bad change) and that the firewall is not covered
by UCI rollback and needs its own backup and restore. Services absent from the
device (for example WireGuard) belong on the management host, not the router.

## 24. Limitations and unresolved questions

- Whether the bootloader enforces signed images on these specific units (fused
  device state) is UNKNOWN; therefore whether a modified kernel/rootfs would boot
  is not established, and no modified image was built or flashed.
- The exact behavior of the vendor GUI firmware-update path (and thus whether an
  owner key survives a normal GUI upgrade) is UNKNOWN (proprietary binary).
- The A/B update switch and TFTP recovery behavior on these models are STRONGLY
  INDICATED at the platform-family level but were not tested on the hardware.
- The exact listen port, packet layout, and hash algorithm of the vendor
  remote-shell daemon are STRONGLY INDICATED from a stripped binary, not
  byte-verified (and are not reproduced here).
- CVE-to-model-and-version mappings beyond CVE-2026-3088 for the 960 series were
  not fully confirmable from the advisories reviewed.

## 25. Conclusions

On the RBRE960 router, a stock, administrator-authenticated, reversible path to a
verified root shell exists and survives the current firmware upgrade. On the
RBSE960 satellites, the vendor deliberately provides no owner-usable SSH-enable
mechanism: the authenticated remote-shell path is vendor-locked by a key the owner
does not hold, the management plane is a closed typed API, and Dropbear is present
but disabled with no remote enable. Reaching a satellite root shell therefore
reduces to the custom/modified-firmware question, which is itself gated not by a
cryptographic image signature (there is none on the kernel/rootfs) but by an
unresolved boot-enforcement question and by the real brick risk of flashing. The
honest result for the satellites is that, within the stated boundaries, no clean
owner path exists, and the tooling here reports that blocker rather than inventing
one. Considerable owner value is nonetheless available on stock firmware through
read-only visibility and carefully gated, reversible configuration management.

## 26. References and appendices

- References, CVEs (version-checked), and standards: `REFERENCES.md`.
- Methodology, provenance, and reproducibility: `METHODOLOGY.md`.
- Router root-access detail and reproduction: `RBRE960_ROOT_ACCESS_RESEARCH.md`,
  `RBRE960_ROOT_ACCESS_WRITEUP.md`.
- Per-topic reports (discovery and verification; version comparison; satellite
  administration, enablement path, implementation plan; firmware signing
  feasibility; management-plane map; remote-shell analysis; owner-control
  assessment; consolidated dossier): `firmware_analysis/reports/`.
- Tooling: `seal_dropbear_enable.py`, `orbi_root_shell.py`,
  `orbi_satellite_ssh.py`, and their tests; see `README_orbi_satellite_ssh.md`.
- Sanitization policy and placeholder conventions: `SANITIZATION.md`.
