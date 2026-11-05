"""Convenience helpers for writing Markdown research reports.

The toolkit's analysis modules write their own JSON and (for compare) Markdown.
This module adds higher-level synthesis helpers used by cve_report.py and the
future CLI `report` subcommand.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable


def md_table(headers: list[str], rows: Iterable[list[str]]) -> str:
    out: list[str] = []
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    for row in rows:
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(out)


def write_report(path: Path, title: str, sections: list[tuple[str, str]]) -> Path:
    """Write a simple titled report with H2 sections. Returns the path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body: list[str] = []
    body.append(f"# {title}\n")
    for heading, content in sections:
        body.append(f"## {heading}\n")
        body.append(content.rstrip() + "\n")
    path.write_text("\n".join(body) + "\n", encoding="utf-8")
    return path
