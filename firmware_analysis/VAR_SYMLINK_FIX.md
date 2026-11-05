# Extracted-rootfs /var symlink replacement

Date: 2026-11-03

## Problem
Each extracted rootfs ships `/var → /tmp` (OpenWrt convention; /var is tmpfs at runtime).
On the host, PyCharm's indexer followed that symlink to the HOST's `/tmp` directory,
which contained a system `grub-btrfs.*` tree with ~976,628 entries, crushing indexing.

## Action taken
Replaced the following symlinks with empty directories:

- rbre_7215/rootfs/var  →  /tmp  (removed, replaced with empty directory)
- rbre_7288/rootfs/var  →  /tmp  (removed, replaced with empty directory)
- rbse_7215/rootfs/var  →  /tmp  (removed, replaced with empty directory)
- rbse_7288/rootfs/var  →  /tmp  (removed, replaced with empty directory)

## Reversal
If needed, restore each with:
```
cd firmware_analysis/extracted/<fw>/rootfs
rmdir var && ln -s /tmp var
```
or re-extract from the original .chk via `scratchpad/extract_chk.sh`.
