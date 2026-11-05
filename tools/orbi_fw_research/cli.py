"""Command-line entry point: `python -m tools.orbi_fw_research.cli <subcommand>`.

Offline-first: no subcommand contacts a live device.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import config
from .common import get_logger

LOG = get_logger("orbi_fw.cli")


def _cmd_inventory(args: argparse.Namespace) -> int:
    from . import inventory as inv
    keys = list(args.fw_keys) or list(config.FIRMWARE_KEYS)
    for k in keys:
        inv.inventory_for_key(k, hash_files=not args.no_hash,
                              with_file_type=not args.no_file_type)
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    from . import compare
    compare.compare_pair(args.a, args.b)
    return 0


def _cmd_compare_all(args: argparse.Namespace) -> int:
    from . import compare
    for a, b in config.PAIRS:
        try:
            compare.compare_pair(a, b)
        except FileNotFoundError as e:
            LOG.warning("skipping %s/%s: %s", a, b, e)
    return 0


def _cmd_packages(args: argparse.Namespace) -> int:
    from . import package_map
    keys = list(args.fw_keys) or list(config.FIRMWARE_KEYS)
    for k in keys:
        package_map.build_for_key(k)
    return 0


def _cmd_elf(args: argparse.Namespace) -> int:
    from . import elf_analysis
    path = Path(args.path)
    info = elf_analysis.analyze_elf(path)
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


def _cmd_elf_diff(args: argparse.Namespace) -> int:
    from . import elf_analysis
    delta = elf_analysis.diff_elf(Path(args.a), Path(args.b))
    print(json.dumps(delta, indent=2, sort_keys=True))
    return 0


def _cmd_sinks(args: argparse.Namespace) -> int:
    from . import source_sink
    source_sink.scan_for_key(args.fw_key, filter_glob=args.binary)
    return 0


def _cmd_soap(args: argparse.Namespace) -> int:
    from . import soap_analysis
    soap_analysis.build_for_key(args.fw_key)
    return 0


def _cmd_rpc(args: argparse.Namespace) -> int:
    from . import rpc_analysis
    rpc_analysis.build_for_key(args.fw_key)
    return 0


def _cmd_ghidra(args: argparse.Namespace) -> int:
    from . import ghidra
    gh = ghidra.GhidraDriver()
    if args.subaction == "check":
        info = gh.check()
        print(json.dumps(info, indent=2, sort_keys=True))
        return 0 if info["available"] else 2
    if args.subaction == "import":
        gh.import_binary(args.fw_key, args.binary_path, project=args.project)
        return 0
    if args.subaction == "decompile":
        out = gh.decompile(args.fw_key, args.binary_path, args.functions,
                           project=args.project)
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="orbi-fw",
                                description="Orbi firmware research toolkit (offline).")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("inventory", help="build per-rootfs inventory JSONL+CSV")
    s.add_argument("fw_keys", nargs="*",
                   help=f"firmware keys to inventory (default: all). "
                        f"known: {', '.join(config.FIRMWARE_KEYS)}")
    s.add_argument("--no-hash", action="store_true")
    s.add_argument("--no-file-type", action="store_true")
    s.set_defaults(func=_cmd_inventory)

    s = sub.add_parser("compare", help="diff two inventories (a -> b)")
    s.add_argument("a")
    s.add_argument("b")
    s.set_defaults(func=_cmd_compare)

    s = sub.add_parser("compare-all", help="diff every pair in config.PAIRS")
    s.set_defaults(func=_cmd_compare_all)

    s = sub.add_parser("packages", help="build opkg path->package map")
    s.add_argument("fw_keys", nargs="*",
                   help="firmware keys (default: all)")
    s.set_defaults(func=_cmd_packages)

    s = sub.add_parser("elf", help="summarize one ELF")
    s.add_argument("path")
    s.set_defaults(func=_cmd_elf)

    s = sub.add_parser("elf-diff", help="diff two ELFs (symbols/strings/needed)")
    s.add_argument("a")
    s.add_argument("b")
    s.set_defaults(func=_cmd_elf_diff)

    s = sub.add_parser("sinks", help="locate dangerous-sink call sites")
    s.add_argument("fw_key")
    s.add_argument("--binary", default=None, help="restrict to one relative path glob")
    s.set_defaults(func=_cmd_sinks)

    s = sub.add_parser("soap", help="extract SOAP M1 method inventory")
    s.add_argument("fw_key")
    s.set_defaults(func=_cmd_soap)

    s = sub.add_parser("rpc", help="extract rpcd methods + ACL map")
    s.add_argument("fw_key")
    s.set_defaults(func=_cmd_rpc)

    s = sub.add_parser("ghidra", help="Ghidra headless operations")
    gs = s.add_subparsers(dest="subaction", required=True)
    gs.add_parser("check", help="probe Ghidra install").set_defaults(func=_cmd_ghidra)
    gi = gs.add_parser("import", help="import a binary into a Ghidra project")
    gi.add_argument("fw_key")
    gi.add_argument("binary_path", help="rootfs-relative path")
    gi.add_argument("--project", default="orbi_research")
    gi.set_defaults(func=_cmd_ghidra)
    gd = gs.add_parser("decompile",
                       help="decompile named functions from an imported binary")
    gd.add_argument("fw_key")
    gd.add_argument("binary_path")
    gd.add_argument("functions", nargs="+", help="function names to decompile")
    gd.add_argument("--project", default="orbi_research")
    gd.set_defaults(func=_cmd_ghidra)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
