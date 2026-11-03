# Firmware Discovery & Artifact Verification (First Task)

Date: 2026-11-02
Workspace: `~/PycharmProjects/orbi_test/firmware_analysis/`
Scope: offline, read-only. No archives modified; no device touched.

---

## 1. Archives found

All four supplied images were located under `~/Downloads/`, each already
unzipped into its own model/version folder alongside its release-notes HTML.

| Role | Path |
|---|---|
| RBRE960 current | `~/Downloads/RBRE960-V7.2.7.15/RBRE960-V7.2.7.15.chk` |
| RBRE960 latest | `~/Downloads/RBRE960-V7.2.8.8/RBRE960-V7.2.8.8_5.1.24.chk` |
| RBSE960 current | `~/Downloads/RBSE960-V7.2.7.15/RBSE960-V7.2.7.15.chk` |
| RBSE960 latest | `~/Downloads/RBSE960-V7.2.8.8/RBSE960-V7.2.8.8.chk` |

No NETGEAR GPL **source** archive is present locally (Approach A will require a download).

## 2. Model + version - VERIFIED from image content (not filename)

Each image carries an embedded FIT `metadata.txt` and a NETGEAR CHK `board_id`.
Version was read from `metadata.txt`, model from both `metadata.txt` and `board_id`.

| File | CHK board_id | FIT metadata VERSION | FIT metadata MODEL_ID |
|---|---|---|---|
| RBRE 7.2.7.15 | `U12H451T00_NETGEAR` | `7.2.7.15` | `RBR960 RBRE960` |
| RBRE 7.2.8.8 | `U12H451T00_NETGEAR` | `7.2.8.8` | `RBR960 RBRE960` |
| RBSE 7.2.7.15 | `U12H452T00_NETGEAR` | `V7.2.7.15` | `RBS960 RBSE960 RBSE950` |
| RBSE 7.2.8.8 | `U12H452T00_NETGEAR` | `V7.2.8.8` | `RBS960 RBSE960 RBSE950` |

- Router board = `U12H451`, satellite board = `U12H452` -> **different hardware image classes; not cross-flashable** (board_id gate).
- The two RBSE `.chk` files share an identical byte size (40,506,274) but have different SHA-256 and different embedded VERSION -> the "latest RBSE" file is genuinely 7.2.8.8, **not** a mislabeled duplicate.

## 3. SHA-256 (original archives, unchanged)

```
c96b1b8978773a6e623268185c916d6655b21dd352b1ab994c8169798ac871bc  RBRE960-V7.2.7.15.chk            (58,069,254 B)
db5b453c2df604a5a33a12b77386611f14fe221c2bd276868f809efda6e939dd  RBRE960-V7.2.8.8_5.1.24.chk     (58,331,394 B)
35acfa4d830c5ba527808045a61193bdf1c2ce707092144e26703b95caf3e7ca  RBSE960-V7.2.7.15.chk           (40,506,274 B)
e17f870bf7321eccd9876916780145c978461d52cf5d2d77705c00252342ddaa  RBSE960-V7.2.8.8.chk            (40,506,274 B)
```

## 4. Structural validity - VERIFIED

Container chain (all four identical in shape):

```
NETGEAR CHK (magic 0x2a23245e, 58-byte header, board_id gate)
  └─ payload @ offset 58 = U-Boot FIT image (magic d00dfeed, version 17)
       ├─ images/txt      -> metadata.txt   (VERSION, MODEL_ID)
       ├─ images/script   -> flash.scr      (U-Boot upgrade script)
       └─ images/ubi-...  -> openwrt-ipq-ipq807x-ubi-root.img  (type=firmware)
            └─ UBI (PEB 128 KiB, min-I/O 2048) volumes:
                 vol0 kernel       (FIT: gzip kernel + DTB)
                 vol1 ubi_rootfs   (squashfs root filesystem)
                 vol2 rootfs_data  (overlay; SHIPPED EMPTY, 0 blocks)
```

- FIT `description` = "Flashing nand 800 20000" (NAND page 0x800=2048, erase 0x20000=128 KiB).
- All headers parse cleanly; CHK magic, FIT magic, and UBI layout all consistent.

## 5. Extraction status

| Layer | Tool | Status |
|---|---|---|
| CHK -> FIT payload | `tail`/python | [yes] carved all 4 |
| FIT -> subimages | custom FDT parser | [yes] metadata.txt, flash.scr, UBI img extracted |
| UBI -> volume list | `ubireader_display_info` | [yes] volumes enumerated (RBRE 7.2.8.8) |
| UBI -> ubi_rootfs blob | `ubireader_extract_images` | [pending] not yet run (ready) |
| squashfs -> files | `unsquashfs` / `sasquatch` | [no] **blocked - tool not installed** |
| DTB -> partition map | `dtc` | [no] **blocked - tool not installed** |

Extracted-component hashes (RBRE 7.2.8.8):
```
28ca1ba83e5688b4a6bf3c5e61fd49e827e631885ab45ad96ce0edad659cdf2a  payload.fit
67ff7533d8af32867711bff6f0238fd6e3b943ef288856ac1e63bc4269ef1ab5  openwrt-ipq-ipq807x-ubi-root.img
```

## 6. Tools present vs missing

Present: `file`, `binwalk`, `strings`, `xxd`, `hexdump`, `7z`, `unzip`, `sha256sum`,
`ubireader_*` (ubi_reader).

Missing (block file-level comparison): `unsquashfs` (squashfs-tools), `sasquatch`,
`dtc`, python `fdt`/`libfdt`, `jefferson`, `unblob`.

## 7. Early high-value findings (beyond the checklist)

- **SoC = Qualcomm IPQ807x** (`openwrt-ipq-ipq807x-ubi-root.img`); firmware is QSDK/OpenWrt-derived.
  `flash.scr` validates `soc_hw_version in {200d0100,200d0101,200d0102,200d0200}` and
  `machid in {8010000,801000d,8010500}`. -> Approach B target is **ipq807x**.
- **Upgrade = destructive rootfs rewrite.** `flash.scr`:
  - RBRE: `nand erase 0x11c00000 0x06d00000` then `nand write ... 0x11c00000` (~109 MiB region).
  - RBSE: `nand erase 0x03e80000 0x04280000` then `nand write ... 0x03e80000` (~66 MiB region).
  Combined with `rootfs_data` shipping at 0 blocks, this **VERIFIES** that a firmware
  upgrade wipes the writable overlay (and therefore `authorized_keys`). Reboot-persistence
  != upgrade-persistence.
- **RBRE vs RBSE flash maps differ substantially** (rootfs UBI at 0x11c00000 vs 0x03e80000) ->
  confirms the two models must be treated as separate artifacts with separate partition layouts.
- The erase ranges target only the rootfs UBI partition, not lower/other NAND offsets ->
  STRONGLY INDICATED that ART/radio-calibration and bootloader are untouched by an official
  upgrade (to be VERIFIED against the DTB partition map once `dtc` is available).

## 8. What is still missing / next prerequisites

1. `squashfs-tools` (+ optionally `sasquatch`) and `dtc` - required to extract the root
   filesystem and device-tree partition map for the Phase Two component comparison.
2. NETGEAR GPL source tarball for 7.2.8.8 (not local) - required for Approach A.
3. Independent confirmation that the two satellites actually run 7.2.7.15 (currently only
   inferred from the download filename + ARP) - a runtime check, deferred, needs approval.
