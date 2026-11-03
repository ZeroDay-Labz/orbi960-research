# Security Policy and Responsible-Research Statement

This repository is a defensive security research publication about the NETGEAR
Orbi RBRE960 router and RBSE960 satellites. It documents administrative
mechanisms, firmware architecture, and security-relevant behavior of stock
firmware. It is not an exploit kit.

## 1. Scope and authorization

All runtime observations in this research were performed on hardware owned and
administered by the author, on an isolated LAN, using credentials and keys the
author controls. The methods documented here rely on existing,
administrator-authenticated vendor mechanisms. They are not an authentication
bypass.

Nothing in this repository authorizes you to test, access, or modify any device
or network you do not own or have explicit written permission to assess. Router
and mesh devices carry other people's traffic; treat them accordingly.

## 2. What this publication deliberately does not contain

To keep the work defensively useful without lowering the bar for misuse, the
following were excluded or reduced to a behavioral description:

- No vendor firmware images, extracted root filesystems, or proprietary vendor
  binaries. Download firmware for hardware you own from the vendor if you want to
  reproduce the analysis.
- No private keys, passwords, password hashes, session tokens, authentication
  cookies, or Wi-Fi credentials.
- No device identifiers from the author's own hardware or network (MAC addresses,
  serial numbers, SSIDs/BSSIDs, WAN or LAN addresses, or certificate
  fingerprints). Any address or MAC-shaped value in examples and tests is a
  documentation placeholder (see `SANITIZATION.md`).
- No operational secret-knock / magic-packet construction tooling. The
  `telnetenabled` and `remoteshellenable` magic-packet mechanisms are described
  at the architectural and protocol-family level only; the ready-to-run packet
  builders and the extracted cipher constants are not published.
- No command-injection payloads. A command-injection sink observed by static
  analysis is described as a weakness class, with the affected component and
  defensive implications, but no reusable payload is given, and it was not
  exercised.

The research value (affected components, mechanism, impact, affected firmware
versions, evidence, and remediation direction) is preserved.

## 3. Evidence discipline

Findings are graded (VERIFIED, STRONGLY INDICATED, HYPOTHESIS, UNKNOWN, RULED
OUT). The research distinguishes:

- what is present in extracted firmware versus what was observed on live hardware;
- a service existing versus a service running;
- an endpoint returning a response versus authentication succeeding;
- a filesystem being writable versus a change surviving a reboot or an upgrade.

Hypotheses are not promoted to verified findings to make a conclusion look
stronger. Where device-specific evidence is absent (for example whether the
bootloader enforces signed images, or whether TFTP recovery behaves a particular
way on these exact models), the text says so.

## 4. Reporting a security issue

### 4.1 In the affected product (NETGEAR Orbi)

Vulnerabilities in NETGEAR products should be reported to the vendor through
NETGEAR's Product Security / PSIRT process:

- NETGEAR Security Advisories and reporting: https://kb.netgear.com/000057739/
- NETGEAR responsible-disclosure contact as published on that page.

Give the vendor reasonable time to investigate and remediate before any public
discussion of a previously unreported issue. Cross-check affected models and
fixed firmware versions against the vendor's own advisory tables; see
`REFERENCES.md`.

### 4.2 In this repository (documentation or tooling)

For problems with the research itself (a factual error, a tool defect, a
sanitization concern, or anything in this repository that appears to disclose
more than intended), open an issue or contact the repository maintainer through
the hosting platform. If the concern is itself sensitive, request a private
channel before sharing details.

## 5. Safe-research practices reflected here

- Prefer static and read-only analysis; perform runtime tests only on your own
  isolated hardware.
- Do not factory reset, open the case, use UART, flash firmware, or modify the
  bootloader during analysis unless you have established and tested a recovery
  path first.
- Do not perform password guessing, brute force, authentication bypass, or
  exploitation of management services.
- Keep credentials, hashes, and private keys out of source, logs, and reports.
- State the effect and the rollback for any proposed device-changing action
  before running it.
