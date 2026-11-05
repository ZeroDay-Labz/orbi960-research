# NETGEAR Orbi RBRE960 / RBSE960: Owner-Authorized Root Access and Firmware Analysis

A documented, evidence-graded security study of the NETGEAR Orbi RBRE960 router
and RBSE960 satellites (quad-band Wi-Fi 6E, Qualcomm IPQ807x). The work covers how
the stock firmware's administrator-authenticated SSH mechanism yields a verified
root shell on the router, a comparison of firmware versions V7.2.7.15 and
V7.2.8.8, a map of the master-to-satellite management plane, firmware packaging
and update behavior, and a feasibility assessment for an owner-control model on
stock firmware.

**Keywords:** NETGEAR Orbi, RBRE960, RBSE960, Qualcomm IPQ807x, OpenWrt, Dropbear,
OpenSSH, Seal REST API, enable_ssh, remoteshellenable, ubus, UCI, SOAP, Wi-Fi 6E
mesh, firmware reverse engineering, router security research, CVE-2026-0415.

## Abstract

Root access on the RBRE960 router is reachable through an existing,
administrator-authenticated mechanism in the stock firmware rather than through
any exploit or authentication bypass: a Seal REST endpoint verifies the admin
credential, installs the owner's SSH public key, and starts Dropbear with key-only
root login. The study establishes, with firmware and read-only runtime evidence,
that this mechanism is unchanged across the two firmware releases examined, that
the RBSE960 satellites expose no equivalent owner path, that the vendor
master-to-satellite plane cannot enable SSH or run commands, and that the
kernel/rootfs image is not cryptographically signed while leaving open whether a
modified image would boot. All claims are graded (VERIFIED, STRONGLY INDICATED,
HYPOTHESIS, UNKNOWN, RULED OUT) and cited to firmware paths, binaries, or runtime
output in the documents below.

## 1. Authorization and scope

This research was performed on hardware owned and administered by the author, on
an isolated LAN, using credentials and keys the author controls. It relies on
existing, administrator-authenticated vendor mechanisms. It is not an
authentication bypass and contains no exploit or command-injection payloads.
Vendor firmware images are not redistributed here. Nothing here should be applied
to devices or networks you are not authorized to test. See `SECURITY.md`.

## 2. Test environment

| Item | Value |
|---|---|
| Router | NETGEAR Orbi RBRE960 (board id `U12H451T00_NETGEAR`) |
| Satellites | 2 x NETGEAR Orbi RBSE960 (board id `U12H452T00_NETGEAR`) |
| SoC and architecture | Qualcomm IPQ807x, ARMv7l, Linux 4.4.60, musl |
| Platform | NETGEAR OpenWrt-derived (Chaos Calmer lineage), Dropbear and OpenSSH |
| Firmware compared | V7.2.7.15 and V7.2.8.8 (RBRE960 and RBSE960) |

## 3. Summary of findings

| # | Finding | Confidence |
|---|---|---|
| 1 | RBRE960 root over SSH is reachable through the stock, administrator-authenticated Seal `enable_ssh` endpoint. A root shell (uid 0) was obtained. | VERIFIED |
| 2 | The `enable_ssh` handler is byte-identical between V7.2.7.15 and V7.2.8.8; the surrounding REST dispatcher was hardened without changing the credentialed contract. | VERIFIED |
| 3 | The RBSE960 satellites expose no owner SSH path: no Seal endpoint, Dropbear shipped disabled with no remote enable, ubus UCI read-only, vendor OpenSSH locked to a NETGEAR-held key. | VERIFIED |
| 4 | The master-to-satellite plane (typed SOAP agent plus Qualcomm SON daemons) exposes no SSH, file-write, or command-execution operation. | VERIFIED / STRONGLY INDICATED |
| 5 | VLANs already cross the wireless backhaul as an 802.1Q trunk; more VLANs are not hardware-blocked but are constrained by the vendor config layer. | VERIFIED (runtime) |
| 6 | `uci apply/confirm/rollback` is built into rpcd with an in-RAM timer; it does not survive a pre-confirm reboot and does not cover the firewall. | STRONGLY INDICATED |
| 7 | The kernel/rootfs image is not cryptographically signed; secure boot, if fused, covers the bootloader only, and whether a modified image boots is not established. | STRONGLY INDICATED (components VERIFIED; boot enforcement UNKNOWN) |
| 8 | CVE-2026-0415 is localized to the master `seal-services.lua` `service_action_handler` (five `popen`/`execute` sinks reachable as uid 0 via an authenticated REST path); fixed in 7.2.8.5+. The RBSE960 satellite has no Seal/Lua equivalent, so the kit-level advisory does not represent a separate sat code path. | VERIFIED (reports 37, 38) |
| 9 | A source-complete OpenWrt `orbi-owner-agent` package (rpcd exec-plugin, 9-method ACL-gated allowlist, `arch: all`) is reproducible against an OpenWrt Chaos Calmer 15.05.1 SDK. `vlan_create` is scoped to the kernel 802.1Q sub-interface layer only; HPPE/SSDK/NSS programming, SSID-to-VLAN wiring, routing, firewall, and DHCP are explicitly deferred to Phase B. The package has not been built into a binary `.ipk` or installed on a device. | VERIFIED source + offline tests; UNVERIFIED runtime |

## 4. Methodology (summary)

Firmware images were verified by content (not filename), extracted through the
CHK to FIT to UBI to SquashFS chain, and compared by SHA-256 per file. Binaries
and Lua bytecode were examined with standard tools and a decompiler. Live
inspection was strictly read-only. No configuration change, service restart, or
firmware flash was performed as part of the analysis. Full detail is in
`METHODOLOGY.md`; reproduction steps are in `REPRODUCE.md`.

## 5. Repository structure

| Path | Contents |
|---|---|
| `RESEARCH_PAPER.md` | The consolidated technical paper (architecture, findings, evidence) |
| `METHODOLOGY.md` | Acquisition, extraction, analysis, and reproducibility |
| `REFERENCES.md` | Vendor docs, version-checked CVEs, platform and tooling references |
| `SECURITY.md` | Research boundaries, responsible disclosure, publication limits |
| `SANITIZATION.md` | What is excluded or placeholdered, and how to keep it that way |
| `REPRODUCE.md` | Step-by-step reproduction on your own hardware |
| `RBRE960_ROOT_ACCESS_RESEARCH.md` | Router root access: mechanism, evidence, roadmap |
| `RBRE960_ROOT_ACCESS_WRITEUP.md` | Narrative write-up of the router root method |
| `README_orbi_satellite_ssh.md` | Guide to the satellite SSH utility |
| `firmware_analysis/reports/` | Per-topic reports: discovery, comparison, satellite analysis, signing, management-plane map, remote-shell analysis, owner-control, consolidated dossier, plus the CVE-2026-0415 localization/reconciliation reports (31–38) and the OpenWrt-package engineering report (39) |
| `firmware_analysis/research_output/` | Supporting firmware-inventory CSV/JSONL, per-binary analyses, Seal-Lua bytecode listings, reconciliation evidence — produced by the toolkit |
| `openwrt/orbi-owner-agent/` | Source-complete OpenWrt rpcd/ubus owner-agent package (shell plugin, ACL, UCI defaults, procd init, offline tests, docs). Phase A — not yet built into a binary `.ipk`; not yet installed on a device; see its `docs/known-limitations.md` |
| `tools/orbi_fw_research/` | Reusable offline firmware toolkit (inventory, package maps, source/sink scans, SOAP/RPC analysis, Ghidra headless driver) |
| `*.py`, `test_*.py` | Approved research tooling and its unit tests |

## 6. Tooling

| File | Purpose |
|---|---|
| `seal_dropbear_enable.py` | Client for the stock `enable_ssh` endpoint (TLS pinning, interactive credentials, response validation, counter-safe probe) |
| `orbi_root_shell.py` | Orchestrates enable plus connect plus verify (uid 0) on the router |
| `orbi_satellite_ssh.py` | Satellite SSH investigation helper (read-only by default; refuses out-of-scope actions) |
| `test_seal_dropbear_enable.py`, `test_orbi_satellite_ssh.py` | Unit tests (mocked; no live device required) |

The tools require your own device, your own administrator credentials, and your
own device's TLS certificate fingerprint; none of these are bundled. Operational
magic-packet (secret-knock) tooling is intentionally excluded (see `SECURITY.md`).

## 7. What is not included

- No vendor firmware images or extracted root filesystems (copyrighted; download
  for hardware you own to reproduce the analysis).
- No device identifiers or secrets: MAC addresses, IP assignments, SSIDs,
  certificate fingerprints, keys, passwords, and hashes are excluded or shown only
  as documentation placeholders. See `SANITIZATION.md`.
- No exploits, command-injection payloads, or magic-packet construction tooling.

## 8. License

Original documentation in this repository is licensed under the Creative Commons
Attribution 4.0 International License (CC BY 4.0); see `LICENSE`. Original source
code (the Python tools and tests) is licensed under the MIT License; see
`LICENSE-CODE`. Vendor names, firmware, and trademarks belong to their respective
owners and are referenced for research and interoperability only; no vendor code
is redistributed here.
