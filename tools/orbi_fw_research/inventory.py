"""Per-rootfs file inventory.

Walks an extracted rootfs and records for every entry:
    relative path, kind (file/symlink/dir/other), size, mode bits,
    symlink target, SHA-256 (for regular files only), file(1) type string,
    and an ELF architecture string if applicable.

Produces JSONL (one record per line) and a CSV sidecar. Both are deterministic
- entries are sorted by relative path - so output is stable across runs.
"""
from __future__ import annotations

import csv
import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from . import config
from .common import get_logger, run, sha256_file

LOG = get_logger("orbi_fw.inventory")


@dataclass
class Entry:
    path: str                    # posix-style path relative to rootfs
    kind: str                    # file | symlink | dir | fifo | sock | chr | blk | other
    size: int                    # bytes; 0 for non-regular
    mode: str                    # octal like "0755"
    symlink_target: str = ""     # populated for kind=="symlink"
    sha256: str = ""             # populated for kind=="file"
    file_type: str = ""          # populated for kind=="file"; file(1) output
    elf_arch: str = ""           # e.g. "ELF 32-bit LSB shared object, ARM"


def _kind_from_mode(m: int) -> str:
    if stat.S_ISREG(m):
        return "file"
    if stat.S_ISLNK(m):
        return "symlink"
    if stat.S_ISDIR(m):
        return "dir"
    if stat.S_ISFIFO(m):
        return "fifo"
    if stat.S_ISSOCK(m):
        return "sock"
    if stat.S_ISCHR(m):
        return "chr"
    if stat.S_ISBLK(m):
        return "blk"
    return "other"


def walk_rootfs(rootfs: Path) -> Iterator[Path]:
    """Yield every path under rootfs, deterministic by sorted order."""
    if not rootfs.is_dir():
        raise FileNotFoundError(f"rootfs not found: {rootfs}")
    for root, dirs, files in os.walk(rootfs, followlinks=False):
        dirs.sort()
        files.sort()
        for d in dirs:
            yield Path(root) / d
        for f in files:
            yield Path(root) / f


def _file_type(path: Path) -> str:
    """Return file(1) output for a regular file. Empty string on error."""
    r = run(["file", "-b", "--", str(path)], timeout=10)
    return r.stdout.strip() if r.ok else ""


def _elf_arch(file_type_str: str) -> str:
    """Extract an ELF architecture hint from file(1) output, or empty."""
    if file_type_str.startswith("ELF"):
        # Strip after the first ','-delimited pair of fields for compactness.
        parts = file_type_str.split(",")
        return ",".join(p.strip() for p in parts[:3])
    return ""


def inventory_rootfs(rootfs: Path, *, hash_files: bool = True,
                     with_file_type: bool = True) -> list[Entry]:
    """Build a sorted list of Entry records for the rootfs."""
    rootfs = rootfs.resolve()
    entries: list[Entry] = []
    for abs_path in walk_rootfs(rootfs):
        try:
            st = abs_path.lstat()
        except OSError as e:
            LOG.warning("lstat failed for %s: %s", abs_path, e)
            continue
        kind = _kind_from_mode(st.st_mode)
        rel = abs_path.relative_to(rootfs).as_posix()
        e = Entry(
            path=rel, kind=kind, size=int(st.st_size),
            mode=f"{stat.S_IMODE(st.st_mode):04o}",
        )
        if kind == "symlink":
            try:
                e.symlink_target = os.readlink(abs_path)
            except OSError:
                e.symlink_target = ""
        elif kind == "file":
            if hash_files:
                e.sha256 = sha256_file(abs_path)
            if with_file_type:
                e.file_type = _file_type(abs_path)
                e.elf_arch = _elf_arch(e.file_type)
        entries.append(e)
    entries.sort(key=lambda x: x.path)
    return entries


def write_jsonl(entries: Iterable[Entry], out_path: Path) -> int:
    """Write entries as JSONL, one Entry per line. Returns count written."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(asdict(e), separators=(",", ":"), sort_keys=True))
            fh.write("\n")
            n += 1
    return n


def write_csv(entries: Iterable[Entry], out_path: Path) -> int:
    """Write entries as CSV. Returns count written."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows = list(entries)
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=[
            "path", "kind", "size", "mode", "symlink_target",
            "sha256", "file_type", "elf_arch",
        ])
        w.writeheader()
        for e in rows:
            w.writerow(asdict(e))
    return len(rows)


def read_jsonl(path: Path) -> list[Entry]:
    """Load an inventory JSONL back into Entry objects."""
    entries: list[Entry] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            entries.append(Entry(**d))
    return entries


def summarise(entries: list[Entry]) -> dict:
    """Produce a compact summary dict (counts by kind, ELF count, total bytes)."""
    by_kind: dict[str, int] = {}
    elf_count = 0
    total_bytes = 0
    for e in entries:
        by_kind[e.kind] = by_kind.get(e.kind, 0) + 1
        if e.elf_arch:
            elf_count += 1
        if e.kind == "file":
            total_bytes += e.size
    return {
        "entries": len(entries),
        "by_kind": by_kind,
        "elf_files": elf_count,
        "total_bytes": total_bytes,
    }


def inventory_for_key(fw_key: str, *, hash_files: bool = True,
                      with_file_type: bool = True) -> tuple[list[Entry], Path]:
    """Build and save an inventory for a named firmware key. Returns (entries, jsonl_path)."""
    if fw_key not in config.FIRMWARE_KEYS:
        raise KeyError(f"unknown firmware key: {fw_key}")
    key = config.FIRMWARE_KEYS[fw_key]
    entries = inventory_rootfs(
        key.rootfs, hash_files=hash_files, with_file_type=with_file_type,
    )
    out_dir = config.RESEARCH_OUTPUT_DIR / "inventory" / fw_key
    jsonl = out_dir / "inventory.jsonl"
    csv_path = out_dir / "inventory.csv"
    summary = out_dir / "summary.json"
    write_jsonl(entries, jsonl)
    write_csv(entries, csv_path)
    summary.write_text(
        json.dumps(summarise(entries), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    LOG.info("inventory: %s entries=%d -> %s", fw_key, len(entries), jsonl)
    return entries, jsonl
