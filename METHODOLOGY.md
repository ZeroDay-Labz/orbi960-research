# Methodology

How the RBRE960 / RBSE960 investigation was performed. The goal is that a reader
with their own hardware and the publicly available firmware images can reproduce
the static findings exactly and the runtime findings on their own device.

Evidence labels used throughout: VERIFIED, STRONGLY INDICATED, HYPOTHESIS,
UNKNOWN, RULED OUT.

## 1. Firmware acquisition and provenance

Four model-specific firmware images were analyzed: RBRE960 V7.2.7.15 (the running
image), RBRE960 V7.2.8.8, RBSE960 V7.2.7.15, and RBSE960 V7.2.8.8. Each was
obtained as a vendor `.chk` image for the matching model.

For each image the following was recorded before any extraction:

- exact file size in bytes;
- SHA-256 of the unmodified archive;
- the container format;
- the embedded model and version, read from the firmware itself rather than from
  the filename.

Model and version were confirmed from the embedded FIT `metadata.txt`
(`VERSION`, `MODEL_ID`) and the CHK `board_id`, so that a mislabeled or renamed
file could not be mistaken for a different image. The original archives were kept
unchanged; all extraction worked on copies.

This repository does not redistribute the images. The recorded SHA-256 values let
anyone who downloads the same vendor images confirm they are analyzing the same
bytes.

## 2. Extraction chain

The container chain is the same for all four images:

```
NETGEAR CHK (magic 0x2a23245e, 58-byte header, board_id gate)
  -> U-Boot FIT (magic d00dfeed): metadata.txt, flash.scr, UBI root image
       -> UBI volumes: kernel (FIT), ubi_rootfs (SquashFS/xz), rootfs_data (overlay)
            -> SquashFS root filesystem
```

Steps:

1. Carve the FIT payload by skipping the 58-byte CHK header.
2. Parse the FIT to extract `metadata.txt`, `flash.scr`, and the UBI root image.
3. Enumerate and extract the UBI volumes.
4. Unpack the SquashFS root filesystem.

Tools: `binwalk`, a FIT/FDT parser (`dtc` / `fdt`), `ubi_reader`
(`ubireader_display_info`, `ubireader_extract_images`), and `unsquashfs`. SHA-256
of each extracted component was recorded so later comparisons reference exact
bytes.

The `rootfs_data` overlay volume ships empty (zero blocks) in all four images; the
writable overlay is created at runtime. This is relevant to persistence analysis:
reboot persistence is not the same as upgrade persistence.

## 3. Filesystem inspection

On the extracted root filesystems the analysis read init scripts
(`/etc/init.d`, `/etc/rc.d`, hotplug rules), service configuration
(`/etc/config/*`, `lighttpd` configuration), the web application tree
(`/www-seal`, `/www`), the SSH configuration (`/etc/ssh`, `/etc/config/dropbear`),
the ubus/rpcd ACLs (`/usr/share/rpcd/acl.d`), and the upgrade keep-lists
(`/lib/upgrade/keep.d`, `sysupgrade.conf`). Cross-file searches confirmed negative
findings (for example, that nothing creates the telnet enable marker, and that no
image contains a private key matching the shipped fleet public key).

## 4. Binary and bytecode analysis

- ELF binaries were examined with `file`, `readelf`, `strings`, and a decompiler
  (Ghidra) for control flow where strings alone were insufficient. Targets
  included `remoteshellenable`, `soap_agent`, `soapc`, `rpcd`, `configd`, the
  Qualcomm SON daemons, and `upgrade_check`.
- SHA-256 of binaries was compared across firmware versions and between the router
  and satellite images to establish which components are byte-identical and which
  changed.
- The Seal REST layer is Lua 5.1 bytecode. This build uses a non-standard numeric
  constant encoding (4-byte `lua_Number`, number constants tagged as type 9), so a
  version-matched disassembler was used to recover the `/enable_ssh` route and the
  `enable_ssh` / `verify_admin` handler logic.

Where a binary is stripped (for example `remoteshellenable`), control flow
reconstructed only from the string table and import list is labeled STRONGLY
INDICATED rather than VERIFIED, and the specific unknowns (exact listen port,
exact packet layout, exact hash algorithm) are stated.

## 5. Firmware comparison

Three comparisons were run:

- RBRE960 V7.2.7.15 versus V7.2.8.8 (whole-image file delta plus targeted
  SSH/auth/startup components);
- RBSE960 V7.2.7.15 versus V7.2.8.8;
- RBRE960 versus RBSE960 within a single release.

Comparison was by SHA-256 per file for identity, plus string-constant and
decompiled-logic comparison for the components that changed (notably the Seal REST
dispatcher). A whole-image byte-identity claim was corrected during the work: the
satellite SSH/admin/ubus components are byte-identical across the two versions,
but `soap_agent` (which carries firmware-update logic) differs, so the blanket
"all components identical" statement was narrowed to the components actually
checked.

## 6. Live-device observation (read-only)

Runtime observation was performed only on the author's own devices, read-only, and
only where it could confirm or refute a static finding. This included:

- unauthenticated identity reads (the `currentsetting.htm` endpoint) to confirm
  model and firmware;
- TCP reachability checks for the SSH and telnet ports;
- authenticated ubus reads (an admin session performing UCI reads only) to confirm
  the satellite configuration and ACL behavior;
- on the already-root router, read-only inspection of mounts, the init/rc layout,
  running processes, listening sockets, the firewall chains, and a search for any
  on-device private key.

No configuration change, service restart, firmware flash, factory reset, or
magic-packet transmission was performed as part of this research. The one
device-changing action in the overall project (using the stock, authenticated
`enable_ssh` endpoint on the router with the owner's own credentials and key) is
the vendor-intended mechanism and is fully reversible; it is documented with its
effect and rollback.

## 7. Reproducibility requirements

To reproduce the static results you need: the matching vendor `.chk` images for
hardware you own, a Linux workstation, and the extraction/analysis tools listed in
`REFERENCES.md`. The runtime results additionally require your own device, your
own administrator credentials, and (for the certificate-pinned client) your own
device's TLS certificate fingerprint. See `REPRODUCE.md` for the concrete steps.

## 8. Confidence and limitations

- Static analysis establishes what code and configuration are present and how they
  are wired. It does not by itself prove runtime behavior; such claims are marked
  and, where possible, confirmed by read-only runtime checks.
- Several questions are not answerable from the shipped artifacts alone and are
  left UNKNOWN: whether the bootloader enforces signed images (depends on
  fused-in device state), the exact behavior of the vendor GUI upgrade path
  (implemented in a proprietary binary), and the precise recovery behavior of
  these specific models. These are not asserted as facts.
- Device identifiers and secrets are excluded from this publication by design, so
  some concrete values that appeared during the original runtime work are shown
  here only as placeholders. This does not change any technical conclusion.
