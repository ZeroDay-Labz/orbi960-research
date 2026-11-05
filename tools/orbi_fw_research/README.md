# orbi_fw_research

Offline firmware research toolkit for the RBRE960 master and RBSE960 satellite.

Scope: **static only**. No module in this package contacts a live device. Live
tests remain in the project's existing scripts (`orbi_root_shell.py`,
`orbi_satellite_ssh.py`, `seal_dropbear_enable.py`) with their own ROE gates.

## Install

No external deps beyond the standard library plus system tools (`file`,
`readelf`, `objdump`, `nm`, `strings`, optionally Ghidra headless).

```
.venv/bin/pip install -e .   # no setup.py yet; run from repo root instead
```

Run as a module:

```
.venv/bin/python -m tools.orbi_fw_research.cli --help
```

## Subcommands

| command | summary |
|---|---|
| `inventory [KEYS...]` | build per-rootfs SHA-256+type inventory (JSONL + CSV) |
| `compare A B` | diff two inventories, ranked by security interest |
| `compare-all` | run every pair in `config.PAIRS` |
| `packages [KEYS...]` | parse opkg metadata, build path->package map |
| `elf PATH` | summarize one ELF (header/sections/imports/exports/needed) |
| `elf-diff A B` | pairwise ELF diff (imports/exports/needed/strings deltas) |
| `sinks FW_KEY [--binary GLOB]` | locate dangerous-sink call sites (hint only) |
| `soap FW_KEY` | extract M1:* method inventory from soap_agent |
| `rpc FW_KEY` | extract rpcd ACL + plugin methods + ACL/implementation mismatches |
| `ghidra check` | probe Ghidra install and report version |
| `ghidra import FW_KEY REL_PATH` | import an ARM ELF into a per-project store |
| `ghidra decompile FW_KEY REL_PATH FN1 FN2 ...` | decompile named functions to JSON |

## Firmware keys

`rbre_7215`, `rbre_7288`, `rbse_7215`, `rbse_7288`. Edit `config.FIRMWARE_KEYS`
to add more.

## Output layout

```
firmware_analysis/
├── research_output/
│   ├── inventory/<KEY>/{inventory.jsonl, inventory.csv, summary.json}
│   ├── compare/<A>__vs__<B>/{changes.json, changes.md}
│   ├── packages/<KEY>/{path_to_pkg.json, pkg_info.json, collisions.json}
│   ├── sinks/<KEY>/hits.json
│   ├── soap/<KEY>/methods.json
│   ├── rpc/<KEY>/{acls.json, plugins.json, plugins_full.json, mismatch.json}
│   └── ghidra/{projects/, scripts/, decompile/<KEY>/<BINARY>.json}
└── reports/   # markdown research reports (hand-written + toolkit-authored)
```

## What's a "hint" vs confirmed

The `sinks` and `soap` subcommands emit heuristic classifications. Confirm with
Ghidra or REA before classing any finding as VERIFIED. The `confidence` field
in every hit record is set to `hint` deliberately — do not promote without a
manual pass.

## ROE

The toolkit never connects to a live device. Permanent restrictions from the
project `CLAUDE.md` apply: no firmware flash, no factory reset, no UART, no
persistent implants, no third-party targets, no WAN testing, no mass scanning,
no password guessing. See the repo-root `CLAUDE.md` for the authoritative list.
