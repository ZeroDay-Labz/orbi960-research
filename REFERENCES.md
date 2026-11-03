# References

Consolidated external references for the RBRE960 / RBSE960 research. Vendor
advisory and CVE entries were checked against public sources; where a model or
fixed-version mapping could not be confirmed from an authoritative advisory, that
is stated explicitly. Always confirm the current affected-version tables on the
vendor's own advisory pages before relying on them, because they are updated over
time.

## 1. Vendor firmware and release information

| Item | Reference |
|---|---|
| NETGEAR RBRE960 / RBSE960 firmware 7.2.8.8 release | NETGEAR KB article `000070913` (https://kb.netgear.com/000070913/) |
| NETGEAR RBRE960 / RBSE960 firmware 7.2.8.5 release | NETGEAR KB article `000070414` (https://kb.netgear.com/000070414/) |
| NETGEAR Orbi 960 series product and support pages | https://www.netgear.com/ (Orbi 960 / RBKE963 series) |
| NETGEAR Security Advisories index | https://kb.netgear.com/000057739/ (NETGEAR Security Advisory landing page) |
| NETGEAR GPL / open-source source code center | https://www.netgear.com/about/opensource/ |

Firmware images are model-specific (the CHK `board_id` gate differs: router
`U12H451T00_NETGEAR`, satellite `U12H452T00_NETGEAR`). Download only the images
for hardware you own. This repository does not redistribute vendor firmware.

## 2. Security advisories and CVEs

### 2.1 Directly relevant to the RBRE960 / RBSE960 (960 series)

| CVE | Class | Public affected-version note | Status for 960 series |
|---|---|---|---|
| CVE-2026-3088 | Out-of-bounds write | Public vulnerability databases list RBRE960 / RBSE960 firmware **before 7.2.7.15** as affected | Fixed at or before 7.2.7.15 for these models (per public DB entries; confirm on the vendor advisory) |
| CVE-2026-0405 | Authentication bypass to the admin web interface (CWE-287) | Described against Orbi devices generally; a fixed version is published for a different model (RBE970) | RBRE960 / RBSE960 fixed-version mapping **UNCONFIRMED** from the advisories reviewed |

### 2.2 Related Orbi-family issues (context, not confirmed for the 960 series)

| CVE | Class | Confirmed affected model(s) | Note |
|---|---|---|---|
| CVE-2026-0413 | Stack-based buffer overflow | RBR750 / RBR840 / RBR850 (fixed 7.2.8.5 per public DBs) | Not listed against RBRE960 / RBSE960 in the sources reviewed |
| CVE-2022-36429 (TALOS-2022-1597) | Command execution in the satellite ubus backend | Orbi Satellite RBS750 4.6.8.5 | Direct ancestor of the RBSE960 `soap_agent` / ubus management surface studied here; NETGEAR PSV-2022-0188 |
| CVE-2022-38452 (TALOS-2022-1595) | Command execution via the hidden telnet service | Orbi Router RBR750 4.6.8.5 | Ancestor of the `telnetenabled` / `remoteshellenable` magic-packet lineage |
| CVE-2022-37337 (TALOS-2022-1596) | Command injection in access-control handling | Orbi (see Talos report for exact model) | Access-control (device-name) command injection class |

Notes on the 2022 Talos set: disclosed to NETGEAR in August 2022, patched by
NETGEAR (for example firmware 4.6.14.3 for the RBR750/RBS750 family), and published
by Cisco Talos on 2023-03-21. These predate the 960 series but document the same
mechanism families (hidden telnet/remote-shell enablement and the satellite ubus
backend) that this research maps on the RBRE960 / RBSE960.

The local V7.2.8.5 to V7.2.8.8 comparison in this research showed Seal REST
dispatcher hardening (removal of client-controlled `X-Forwarded-For` / `X-Host`
trust, an internal-only request header, a route-name allowlist, and a
path-traversal check). This is consistent with a generic "security fixes" note in
the release information and does not, by itself, establish which numbered CVE it
addresses. Treat the CVE-to-version mapping as authoritative only from the
vendor's advisory tables.

### 2.3 Advisory sources used

- Cisco Talos vulnerability reports: https://www.talosintelligence.com/vulnerability_reports/ (TALOS-2022-1595, TALOS-2022-1596, TALOS-2022-1597).
- MITRE CVE: https://www.cve.org/ (per-CVE records).
- NIST National Vulnerability Database: https://nvd.nist.gov/.

## 3. Platform and operating-system documentation

| Topic | Reference |
|---|---|
| OpenWrt (base platform family; "Chaos Calmer" lineage, procd, UCI, ubus, rpcd) | https://openwrt.org/docs/start |
| OpenWrt UCI (Unified Configuration Interface) | https://openwrt.org/docs/guide-user/base-system/uci |
| OpenWrt ubus (micro bus architecture) and rpcd ACLs | https://openwrt.org/docs/techref/ubus |
| OpenWrt sysupgrade and kept-files behavior | https://openwrt.org/docs/guide-user/installation/sysupgrade.cli |
| Dropbear SSH server | https://matt.ucc.asn.au/dropbear/dropbear.html |
| OpenSSH server (`sshd_config`, `ForceCommand`, `AuthorizedKeysFile`) | https://www.openssh.com/manual.html |

## 4. Qualcomm IPQ807x platform

| Topic | Reference |
|---|---|
| Qualcomm IPQ807x / Networking Pro (Wi-Fi 6/6E) platform overview | https://www.qualcomm.com/products/networking (Networking Pro series) |
| Qualcomm QSDK / Wi-Fi SON and Multi-AP (repacd, wsplcd, hyd, lbd) | Qualcomm QSDK documentation (vendor-restricted); public OpenWrt ipq807x target notes at https://openwrt.org/docs/techref/targets/ipq807x |
| U-Boot FIT (Flattened Image Tree) image format | https://docs.u-boot.org/en/latest/usage/fit/index.html |
| UBI / UBIFS (unsorted block images on NAND) | https://www.kernel.org/doc/html/latest/filesystems/ubifs.html and http://www.linux-mtd.infradead.org/doc/ubi.html |
| Wi-Fi Alliance EasyMesh / IEEE 1905.1 (Multi-AP backhaul) | https://www.wi-fi.org/discover-wi-fi/wi-fi-easymesh |

## 5. Tooling referenced in the methodology

| Tool | Reference |
|---|---|
| binwalk (firmware carving) | https://github.com/ReFirmLabs/binwalk |
| ubi_reader (UBI/UBIFS extraction) | https://github.com/jrspruitt/ubi_reader |
| squashfs-tools (`unsquashfs`) | https://github.com/plougher/squashfs-tools |
| Device Tree Compiler (`dtc`) | https://git.kernel.org/pub/scm/utils/dtc/dtc.git |
| Ghidra (binary decompilation) | https://ghidra-sre.org/ |
| OpenSSL (TLS inspection, fingerprinting) | https://www.openssl.org/ |

## 6. Standards used for sanitization

- RFC 5737 (IPv4 address blocks reserved for documentation): any IPv4 literal that
  appears in example configuration or test fixtures in this repository is drawn
  from these documentation ranges and does not correspond to a real network.
- RFC 7042 (documentation MAC address ranges): placeholder MAC values in examples
  and tests use documentation/locally-administered ranges.
