# Validator fingerprint scan — all four rootfs

Scan for the literal string `^[A-Za-z0-9_-]+$` (the CVE-0415-fix whitelist).

Command (from repo root):

```
grep -rlaF '^[A-Za-z0-9_-]+$' firmware_analysis/extracted/<key>/rootfs/
```

| rootfs | hit count | files |
|---|---|---|
| `rbre_7215/rootfs/` | 0 | — |
| `rbre_7288/rootfs/` | 2 | `usr/share/lua/seal-services.lua`, `www-seal/rest/rest.lua` |
| `rbse_7215/rootfs/` | 0 | — |
| `rbse_7288/rootfs/` | 0 | — |

The fix string is confined to the master (RBRE) fixed-version firmware. Neither
satellite rootfs contains any form of this guard — vulnerable or fixed.
