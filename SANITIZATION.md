# Sanitization: what is excluded, what is placeholdered, and how to keep it that way

This publication is built so it contains no information that identifies the
author's hardware, network, or workstation, and no secrets. Real device
identifiers and secrets exist only on the owner's own machine and are never part
of this repository.

## 1. Excluded entirely (never published)

- Vendor firmware images, extracted root filesystems, and proprietary vendor
  binaries (copyright and bulk). Download firmware for hardware you own to
  reproduce the analysis.
- Private keys, passwords, password hashes, session tokens, authentication
  cookies, and Wi-Fi credentials.
- The author's raw runtime capture notes (which contained a WAN address and real
  device identifiers) and any local configuration holding real identifiers.
- Operational secret-knock / magic-packet construction tooling and the cipher
  constants extracted from the vendor binary. The mechanism is described in the
  reports at the protocol-family level only; the ready-to-run builders are not
  included (see `SECURITY.md`).
- Project-local notes and editor/IDE metadata.

## 2. Placeholder conventions (no real identifiers)

Where a value is needed for the text or for a tool to function, a non-identifying
placeholder is used instead of any real value:

| Real category | How it appears here |
|---|---|
| Router / satellite LAN addresses | descriptive placeholders such as `<router-ip>`, `<satellite-1-ip>` in prose; the hostname `routerlogin.net` (a vendor default) as a tool default |
| Loopback / internal vendor addresses | written as `localhost`, `<internal-backhaul-ip>`, `<guest-bridge-subnet>` |
| MAC addresses | documentation/locally-administered placeholders (for example `02:00:00:00:00:01`) in examples and tests |
| TLS certificate fingerprint | not bundled; supply your own device's fingerprint at runtime via the tool flag |
| Example/test IPv4 literals | RFC 5737 documentation ranges (for example `198.51.100.0/24`), which route nowhere and identify no network |
| The vendor fleet SSH key | referenced as `<vendor-fleet-key-fingerprint>` / `root@<vendor-build-host>`; the finding (a single fixed NETGEAR-held key whose private half is not in the firmware) is preserved without any value |

No real MAC address, serial number, SSID, BSSID, WAN or LAN address, Wi-Fi
passphrase, administrator password, password hash, certificate fingerprint,
session token, or private key appears in any published file. Firmware version
strings, CVE identifiers, model and board identifiers, Qualcomm/SoC identifiers,
and SHA-256 hashes of publicly downloadable vendor firmware are retained because
they are research content, not personal identifiers, and are identical across all
units.

## 3. Writing conventions

Published text is plain ASCII. There are no em dashes or decorative typographic
glyphs. The documents are a standalone technical publication with no external
authorship, tooling, or chat-session references.

## 4. Pre-publish checks

Run these from the repository root before any push. Each should print a clean
result; investigate anything it surfaces.

```bash
# 1) No real-looking MAC addresses other than the documentation placeholders.
grep -rInE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' . \
  --include='*.py' --include='*.md' --include='*.json' \
  | grep -viE '02:00:00:00:00:0|02:00:00:ab:cd:ef|aa:bb:cc:dd:ee:ff' \
  && echo "REVIEW the lines above" || echo "clean: only placeholder MACs"

# 2) No routable/private IPv4 other than RFC 5737 doc ranges and loopback.
grep -rInE '([0-9]{1,3}\.){3}[0-9]{1,3}' . \
  --include='*.py' --include='*.md' --include='*.json' \
  | grep -viE '198\.51\.100\.|203\.0\.113\.|192\.0\.2\.|127\.0\.0\.1|0\.0\.0\.0|7\.2\.[0-9]|6\.3\.7|5\.1\.[0-9]|4\.4\.60|15\.05|2019\.78' \
  && echo "REVIEW the lines above" || echo "clean: no real IPs"

# 3) No external-authorship, tooling, or chat-session references. Also manually
#    scan for the name of any code-generation or analysis tool you used; it must
#    not appear anywhere in the published tree.
grep -rInEi '\b(co-authored-by|generated with|chat session|prior session)\b' . \
  --include='*.py' --include='*.md' --include='*.json' \
  && echo "REVIEW the lines above" || echo "clean: standalone"

# 4) No em dashes / common decorative unicode.
grep -rInP '[\x{2014}\x{2013}\x{2192}\x{21d2}\x{2022}\x{2705}\x{274c}]' . \
  --include='*.py' --include='*.md' --include='*.json' \
  && echo "REVIEW the lines above" || echo "clean: ASCII punctuation"

# 5) Firmware and local secrets cannot be committed.
git check-ignore -q firmware_analysis/extracted *.chk && echo "ignored OK" || echo "note: nothing to ignore yet"
```

A clean scan is necessary but not sufficient. The README, the research paper, the
reports, and the scripts were also reviewed by hand before publication.
