"""ELF analysis: single-binary summary and pairwise diff.

Wraps readelf, nm, and strings. Designed to work on stripped ARM binaries:
exported symbols may be empty; we still get useful imports (dynamic undefined
symbols), NEEDED libraries, section layout, and raw strings.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .common import RunResult, get_logger, have, run

LOG = get_logger("orbi_fw.elf")


def is_elf(path: Path) -> bool:
    """Peek at the first 4 bytes."""
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except (OSError, PermissionError):
        return False


def _readelf(path: Path, flags: str) -> RunResult:
    return run(["readelf", flags, "--wide", str(path)], timeout=30)


_HDR_FIELDS = {
    "Class", "Data", "OS/ABI", "Type", "Machine", "Entry point address",
    "Version", "ABI Version",
}


def elf_header(path: Path) -> dict[str, str]:
    r = _readelf(path, "-h")
    out: dict[str, str] = {}
    for line in r.stdout.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip()
        if k in _HDR_FIELDS:
            out[k] = v.strip()
    return out


def elf_needed(path: Path) -> list[str]:
    r = _readelf(path, "-d")
    needed: list[str] = []
    for line in r.stdout.splitlines():
        m = re.search(r"\(NEEDED\).*\[(.+?)\]", line)
        if m:
            needed.append(m.group(1))
    return sorted(set(needed))


_NM_LINE = re.compile(r"^(?P<addr>[0-9a-fA-F]*)\s+(?P<type>\S)\s+(?P<name>\S.*)$")


def elf_exports(path: Path) -> list[str]:
    """Defined dynamic symbols (--defined-only -D)."""
    if not have("nm"):
        return []
    r = run(["nm", "-D", "--defined-only", "--format=posix", str(path)], timeout=30)
    names: set[str] = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            names.add(parts[0])
    return sorted(names)


def elf_imports(path: Path) -> list[str]:
    """Undefined dynamic symbols - functions this binary calls out to."""
    if not have("nm"):
        return []
    r = run(["nm", "-D", "--undefined-only", "--format=posix", str(path)], timeout=30)
    names: set[str] = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if parts:
            names.add(parts[0])
    return sorted(names)


def elf_sections(path: Path) -> list[dict]:
    r = _readelf(path, "-S")
    out: list[dict] = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        # strip the [N] prefix
        m = re.match(r"\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", line)
        if not m:
            continue
        idx, name, stype, addr, offset, size = m.groups()
        out.append({"idx": int(idx), "name": name, "type": stype,
                    "addr": addr, "offset": offset, "size": size})
    return out


def elf_strings(path: Path, min_len: int = 5) -> list[tuple[int, str]]:
    """Return (file_offset, text) tuples from `strings -a -tx`."""
    r = run(["strings", "-a", "-tx", "-n", str(min_len), str(path)], timeout=60)
    out: list[tuple[int, str]] = []
    for line in r.stdout.splitlines():
        parts = line.lstrip().split(None, 1)
        if len(parts) != 2:
            continue
        try:
            off = int(parts[0], 16)
        except ValueError:
            continue
        out.append((off, parts[1]))
    return out


def analyze_elf(path: Path) -> dict:
    """Return a JSON-friendly summary dict for one ELF."""
    if not path.is_file() or not is_elf(path):
        return {"path": str(path), "elf": False}
    info = {
        "path": str(path),
        "elf": True,
        "header": elf_header(path),
        "needed": elf_needed(path),
        "imports": elf_imports(path),
        "exports": elf_exports(path),
        "sections": elf_sections(path),
    }
    info["imports_count"] = len(info["imports"])
    info["exports_count"] = len(info["exports"])
    info["needed_count"] = len(info["needed"])
    return info


def diff_elf(a: Path, b: Path) -> dict:
    """Pairwise diff of two ELFs: delta in NEEDED, imports, exports, strings."""
    if not (is_elf(a) and is_elf(b)):
        return {"a": str(a), "b": str(b), "error": "one or both are not ELF"}
    a_imp = set(elf_imports(a))
    b_imp = set(elf_imports(b))
    a_exp = set(elf_exports(a))
    b_exp = set(elf_exports(b))
    a_need = set(elf_needed(a))
    b_need = set(elf_needed(b))
    a_str = {s for _, s in elf_strings(a)}
    b_str = {s for _, s in elf_strings(b)}
    return {
        "a": str(a),
        "b": str(b),
        "header_a": elf_header(a),
        "header_b": elf_header(b),
        "needed_added": sorted(b_need - a_need),
        "needed_removed": sorted(a_need - b_need),
        "imports_added": sorted(b_imp - a_imp),
        "imports_removed": sorted(a_imp - b_imp),
        "exports_added": sorted(b_exp - a_exp),
        "exports_removed": sorted(a_exp - b_exp),
        "strings_added": sorted(b_str - a_str)[:200],   # cap for readability
        "strings_removed": sorted(a_str - b_str)[:200],
        "strings_added_count": len(b_str - a_str),
        "strings_removed_count": len(a_str - b_str),
    }
