"""Paired inventory diff with interest-ranked output.

Loads two inventories (built by inventory.py) and classifies each path as:
    added    - present only in B
    removed  - present only in A
    changed  - present in both but different SHA-256 (or different symlink target,
               or different kind)
    renamed  - heuristic: a removed file and an added file share the same
               (sha256, size) and exactly one of each. Currently not emitted
               separately; folded as (added+removed) pair with note.
    same     - identical

The ranked output groups changes by priority bucket (0..99) from
config.INTEREST_PATTERNS. Report formats: JSON (full) and Markdown (top-N).
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from . import config
from .common import get_logger, rank_path
from .inventory import Entry, read_jsonl

LOG = get_logger("orbi_fw.compare")


@dataclass
class Change:
    path: str
    status: str              # added | removed | changed | same
    prio: int
    label: str
    note: str = ""           # e.g. "kind: file->symlink", "size: 1234->5678"
    sha_a: str = ""
    sha_b: str = ""
    size_a: int = 0
    size_b: int = 0
    kind_a: str = ""
    kind_b: str = ""


def diff_inventories(a: list[Entry], b: list[Entry],
                     patterns: Iterable[tuple[int, str, str]] | None = None,
                     ) -> list[Change]:
    patterns = list(patterns) if patterns is not None else config.INTEREST_PATTERNS
    by_a = {e.path: e for e in a}
    by_b = {e.path: e for e in b}
    all_paths = sorted(set(by_a) | set(by_b))
    changes: list[Change] = []
    for p in all_paths:
        ea = by_a.get(p)
        eb = by_b.get(p)
        prio, label = rank_path(p, patterns)
        if ea is None:
            changes.append(Change(p, "added", prio, label,
                                  sha_b=eb.sha256, size_b=eb.size,
                                  kind_b=eb.kind))
            continue
        if eb is None:
            changes.append(Change(p, "removed", prio, label,
                                  sha_a=ea.sha256, size_a=ea.size,
                                  kind_a=ea.kind))
            continue
        # Both present.
        notes = []
        if ea.kind != eb.kind:
            notes.append(f"kind:{ea.kind}->{eb.kind}")
        if ea.kind == "symlink" and ea.symlink_target != eb.symlink_target:
            notes.append(f"symlink:{ea.symlink_target}->{eb.symlink_target}")
        if ea.kind == "file" and eb.kind == "file":
            if ea.sha256 and eb.sha256 and ea.sha256 != eb.sha256:
                notes.append(f"sha:{ea.sha256[:12]}->{eb.sha256[:12]}")
            if ea.size != eb.size:
                notes.append(f"size:{ea.size}->{eb.size}")
        if notes:
            changes.append(Change(
                p, "changed", prio, label, note=" ".join(notes),
                sha_a=ea.sha256, sha_b=eb.sha256,
                size_a=ea.size, size_b=eb.size,
                kind_a=ea.kind, kind_b=eb.kind,
            ))
        # same: not emitted; the Change-list is diff-only by design
    # Deterministic sort: by priority, then status (changed before added/removed), then path
    status_order = {"changed": 0, "added": 1, "removed": 2, "same": 9}
    changes.sort(key=lambda c: (c.prio, status_order.get(c.status, 9), c.path))
    return changes


def summarise(changes: list[Change]) -> dict:
    by_status: dict[str, int] = {}
    by_prio: dict[int, int] = {}
    for c in changes:
        by_status[c.status] = by_status.get(c.status, 0) + 1
        by_prio[c.prio] = by_prio.get(c.prio, 0) + 1
    return {
        "total_changes": len(changes),
        "by_status": by_status,
        "by_priority": {str(k): v for k, v in sorted(by_prio.items())},
    }


def write_json(changes: list[Change], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "summary": summarise(changes),
        "changes": [asdict(c) for c in changes],
    }
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return len(changes)


def write_markdown(changes: list[Change], a_key: str, b_key: str, path: Path,
                   top_n_per_priority: int = 30) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = summarise(changes)
    lines: list[str] = []
    lines.append(f"# Firmware diff: {a_key} -> {b_key}\n")
    lines.append("## Summary\n")
    lines.append(f"- Total changes: **{summary['total_changes']}**")
    lines.append(f"- By status: {summary['by_status']}")
    lines.append(f"- By priority bucket: {summary['by_priority']}\n")
    lines.append("Priority buckets (lower = more security-relevant). "
                 "0=top SOAP/webui/remoteshell; 1=rpcd/http; 2=init/uci; "
                 "3=other binaries; 5=everything else.\n")

    # Group by priority
    by_prio: dict[int, list[Change]] = {}
    for c in changes:
        by_prio.setdefault(c.prio, []).append(c)

    for prio in sorted(by_prio):
        lines.append(f"## Priority {prio}\n")
        bucket = by_prio[prio]
        shown = bucket[:top_n_per_priority]
        hidden = len(bucket) - len(shown)
        lines.append("| Status | Path | Label | Note |")
        lines.append("|---|---|---|---|")
        for c in shown:
            lines.append(f"| {c.status} | `{c.path}` | {c.label} | {c.note or ''} |")
        if hidden > 0:
            lines.append(f"| … | _({hidden} more)_ | | |")
        lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(changes)


def compare_pair(a_key: str, b_key: str) -> tuple[list[Change], Path, Path]:
    """Load inventories for the two keys and write JSON + Markdown reports."""
    inv_dir = config.RESEARCH_OUTPUT_DIR / "inventory"
    a_path = inv_dir / a_key / "inventory.jsonl"
    b_path = inv_dir / b_key / "inventory.jsonl"
    if not a_path.is_file() or not b_path.is_file():
        raise FileNotFoundError(
            f"inventory missing. Run `orbi-fw inventory {a_key}` and "
            f"`orbi-fw inventory {b_key}` first."
        )
    a = read_jsonl(a_path)
    b = read_jsonl(b_path)
    changes = diff_inventories(a, b)
    out_dir = config.RESEARCH_OUTPUT_DIR / "compare" / f"{a_key}__vs__{b_key}"
    json_path = out_dir / "changes.json"
    md_path = out_dir / "changes.md"
    write_json(changes, json_path)
    write_markdown(changes, a_key, b_key, md_path)
    LOG.info("compare %s -> %s: %d changes -> %s", a_key, b_key, len(changes), out_dir)
    return changes, json_path, md_path
