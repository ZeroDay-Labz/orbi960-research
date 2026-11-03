# RBSE960 Firmware Signing & Custom-Image Feasibility

Date: 2026-11-02 - Offline static analysis of locally held images + read-only master facts.
Answers: "is there firmware key signing?" and "is a modified satellite image feasible
without circumventing a signature?" Companion to reports 20-22.
Evidence labels: VERIFIED / STRONGLY INDICATED / HYPOTHESIS / UNKNOWN / RULED OUT.
No device was modified; nothing was flashed.

---

## 1. Question

To put owner SSH on the satellites via the only remaining in-software route (a
modified rootfs flashed through the vendor update channel), we must know whether the
RBSE960 enforces a **cryptographic signature** on the firmware image. If it does and we
lack NETGEAR's key, the route is closed (and would require signature circumvention,
which is out of scope). If the gates are only checksums + board identity, a modified
image is acceptable without touching any signature.

## 2. Findings - the image is NOT cryptographically signed (STRONGLY INDICATED; components VERIFIED)

| Layer | Mechanism | Signature? | Evidence |
|---|---|---|---|
| NETGEAR CHK container | 58-byte header, board_id, checksum | **No** | `usr/sbin/upgrade_check` strings: only "skip the 58 bytes of chk header", `boarddata.board_id`, "board_id ... not matched", "size matched" - no rsa/sha/signature (VERIFIED) |
| U-Boot FIT (update) | `crc32` hashes on txt/script/firmware nodes | **No** | `dtc -I dtb` of `payload.fit` (both 7.2.7.15 & 7.2.8.8): `algo="crc32"` only; **0** `signature`/`key-name-hint`/`rsa` nodes (VERIFIED) |
| Boot kernel FIT (in UBI `kernel` vol) | hash only | **No** | `dtc` of the kernel volume: no signature/rsa nodes (VERIFIED) |
| `flash.scr` (U-Boot/NMRP apply) | `imxtract` + `nand write`, board gate | **No verify** | `flash.scr` has no sign/verify/rsa/sha step (VERIFIED) |
| GUI/soap apply (`sysupgrade`, `lib/upgrade`, `upgrade.so`, `soap_agent`) | file write + MD5 integrity | **No** | grep: no signature/rsa; `upgrade.so` only writes `/tmp/firmware.bin`; `soap_agent` references MD5 (integrity), not RSA (VERIFIED) |
| Image-verification public key in rootfs | - | **Absent** | `find` for `*.pem/*.pub/*.key` minus TLS/SSH -> none; only `usign` = OpenWrt **package-feed** signing (Ed25519), not image/boot verification (VERIFIED) |
| SoC boot chain (SBL1->QSEE->U-Boot) | Qualcomm secure boot | **Yes, if fused** | `/proc/mtd` shows `QSEE`,`QSEE_1`,`DEVCFG`,`DEVCFG_1`,`APPSBL`,`APPSBL_1` - secure-boot capable. Protects the **bootloader only**; fuse state UNKNOWN (runtime-checkable, read-only) |

**Clincher (STRONGLY INDICATED):** the vendor's own shipping FIT carries **no** signature
nodes, so U-Boot cannot be configured to require signed FITs - it boots unsigned
kernel/rootfs by design. Therefore a modified kernel/rootfs is not signature-gated at boot.

**Conclusion:** the "firmware key signing" that exists is the **Qualcomm secure-boot chain
over the bootloader** (SBL/QSEE/U-Boot). The **kernel+rootfs firmware image is not
cryptographically signed**; its only gates are the CHK board_id/checksum, FIT CRC32, and
an MD5 integrity manifest - all of which are recomputable. A modified RBSE960 image is
therefore **technically acceptable to the device without circumventing any signature.**

## 3. What a modified satellite image would involve (feasibility, NOT a go-ahead)

Minimal change set (add owner key + enable dropbear in the squashfs rootfs), then repack:
`squashfs -> UBI (same layout) -> FIT (fix crc32) -> CHK (fix board_id U12H452..., size, checksum)`.
Push via the vendor update channel (satellite `soap_agent` UpdateNewFirmware2 /
CheckAndDownloadNewFirmwareByFolder, driven from the master).

Must be preserved untouched (device identity / recovery / radio): `SBL1`, `MIBIB`,
`QSEE*`, `DEVCFG*`, `APDP*`, `RPM*`, `CDT*`, `APPSBL*` (U-Boot), **`ART`** (radio
calibration, mtd17), `board_data` (mtd21, factory MACs/serial), `nvram*`. The modified
image writes only the rootfs/kernel UBI region, exactly like a stock update.

## 4. Brick-safety (why this *can* be done recoverably - later, with approval)

- **A/B slots:** `/proc/mtd` shows `rootfs`/`rootfs_1` and `APPSBL`/`APPSBL_1`. A running
  update writes the **inactive** slot and flips the active pointer; a bad image leaves the
  known-good slot to fall back to. (STRONGLY INDICATED)
- **NMRP recovery:** NETGEAR U-Boot supports NMRP (TFTP firmware recovery on boot) - the
  safety net to restore the **original stock `.chk`** (which we have, hashes recorded) if a
  flash goes wrong. (STRONGLY INDICATED; to be confirmed before any flash.)
- Secure boot (if fused) keeps the bootloader/NMRP itself intact and trustworthy, which
  actually *helps* recovery - we never modify that chain.

## 5. Status & recommendation

- **Signing question: answered.** No image signature to circumvent; custom satellite
  rootfs is feasible in principle. (STRONGLY INDICATED)
- **But it still requires flashing**, which the owner has declined for now. So this route
  stays "feasible, not executed." Before it is ever attempted we must: (a) confirm NMRP
  recovery works and stage the stock image, (b) verify the exact A/B update mechanism on
  the satellite, (c) build + validate the modified image offline, (d) test on one
  satellite with the other as a known-good reference.
- **Lower-risk, zero-flash step still open:** Path A - check whether the **master** holds
  the NETGEAR private key for the satellites' vendor OpenSSH (`root@<vendor-build-host>`). If it
  does, satellite SSH needs no firmware work at all. (Read-only; see report 22 / "Test 3".)

## 6. Open items

- Secure-boot **fuse state** (QFPROM) - read-only checkable on the master; affects only the
  bootloader, not this route. UNKNOWN.
- Exact satellite A/B apply + NMRP behaviour - to be VERIFIED before any flash.
- Whether the master-driven `UpdateNewFirmware2` accepts a locally-hosted folder/URL image
  (needed to push our own image) - STRONGLY INDICATED from `soap_agent`
  (`CheckAndDownloadNewFirmwareByFolder`, `FwDownloadUrl`), to be confirmed.

---

*No credentials/keys reproduced. `/proc/mtd` layout is not secret. Nothing was flashed or
modified.*
