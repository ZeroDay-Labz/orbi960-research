# Reproduce

A repeatable path to recreate the static findings and the owner-authorized runtime
results on your own hardware. Owner-authorized, on personally owned devices only.
Nothing here flashes firmware or builds a custom image.

Your device identifiers (router address, satellite MACs, admin credentials, TLS
fingerprint, SSH key) are yours and stay on your machine. Keep them in a local,
version-ignored configuration file (copy `orbi_local_config.example.json` to
`orbi_local_config.json`); it is listed in `.gitignore`.

## 0. Workstation prerequisites

A Linux workstation with:

```bash
# package names vary by distribution
squashfs-tools dtc binwalk openssh-clients curl p7zip jq python3
python3 -m venv .venv && . .venv/bin/activate
pip install ubi_reader fdt requests
```

Optional for binary reverse engineering: Ghidra. Not required to reproduce the
read-only results.

## 1. Local configuration (identifiers kept out of source)

```bash
cp orbi_local_config.example.json orbi_local_config.json
# edit orbi_local_config.json: set the master address, the SSH key path, the owner
# public key path, and the two satellite MACs. This file is git-ignored.
```

## 2. Acquire firmware (do not infer version from filename)

Download the model-specific images you are entitled to (current plus V7.2.8.8) for
the RBRE960 and RBSE960. Record size and SHA-256, then confirm model and version
from the image content, not the filename:

```bash
sha256sum *.chk | tee SHA256SUMS
```

## 3. Extract (CHK to FIT to UBI to rootfs)

```bash
# carve the FIT payload (the CHK header is 58 bytes)
for f in *.chk; do tail -c +59 "$f" > "${f%.chk}.fit"; done
# FIT -> metadata.txt / flash.scr / UBI image (fdt or dumpimage), then:
ubireader_extract_images  <ubi image>        # kernel / ubi_rootfs / rootfs_data
unsquashfs -d <out>/rootfs  <ubi_rootfs squashfs>
# confirm identity from the image, not the filename:
dtc -I dtb -O dts <payload.fit> | grep -E 'VERSION|MODEL_ID|board_id'
```

Keep each extracted tree in its own directory, for example
`rbre_7215/rootfs`, `rbse_7215/rootfs`. The bulk extracted material is large
(on the order of a gigabyte) and is git-ignored; do not commit it.

## 4. Router (RBRE960) root: stock, owner-authenticated

Capture your own device's TLS certificate fingerprint first (see
`RBRE960_ROOT_ACCESS_WRITEUP.md` section 6.2), then:

```bash
# installs YOUR public key via the stock Seal endpoint and starts key-only Dropbear
python3 seal_dropbear_enable.py --enable --pin-sha256 <your-router-cert-sha256>
# enter the admin username and password when prompted (never on the command line)

python3 orbi_root_shell.py --connect-only --pin-sha256 <your-router-cert-sha256>
# verifies uid 0 and opens a shell
```

Re-run the enable after a router reboot (Dropbear does not auto-start and its host
key regenerates).

## 5. Satellites: read-only inventory and status (safe, repeatable)

```bash
python3 orbi_satellite_ssh.py discover          # find satellites, confirm model/firmware
python3 orbi_satellite_ssh.py status --admin    # prompts admin pw; reads dropbear uci via ubus (read-only)
python3 orbi_satellite_ssh.py plan              # exact change set + why enable is blocked
```

## 6. Static analysis that produced the findings (offline, on extracted rootfs)

```bash
R=rbse_7215/rootfs
grep -rl enable_ssh "$R"                               # (empty): no Seal on satellite
cat "$R"/etc/ssh/sshd_config                           # pubkey-only + ForceCommand + fixed AuthorizedKeysFile
cat "$R"/usr/share/rpcd/acl.d/netgear.json             # ubus ACL: uci READ only; no dropbear/write-shell
strings "$R"/usr/sbin/upgrade_check | grep -iE 'board_id|chk|size'   # no rsa/sha: image not signed
dtc -I dtb -O dts rbse_7215/payload.fit | grep -c signature          # 0 signature nodes
```

## 7. Satellite shell: current status

`orbi_satellite_ssh.py enable --satellite N --apply` refuses on a stock satellite
(TCP 22 and 23 closed; no supported remote configuration route). This is expected
and correct. The options to proceed are the owner decision documented in the
consolidated dossier (accept no-SSH, or a modified-firmware route that must not
proceed until recovery and A/B behavior are established; UART and exploitation are
out of scope).

## 8. Run the tests (no device contact)

```bash
python3 -m unittest test_orbi_satellite_ssh
python3 -m unittest test_seal_dropbear_enable
```
