#!/usr/bin/env python3
"""Validate direct Rust source paths recorded in source.md indexes."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path


INDEX_ROW = re.compile(r"^\|\s*`([^`]+\.rs)`\s*\|")
IGNORED_DIRECTORIES = {".git", "target", "node_modules", "__pycache__"}


def source_documents(workspace: Path) -> list[Path]:
    return sorted(
        path
        for path in workspace.rglob("source.md")
        if not any(part in IGNORED_DIRECTORIES for part in path.relative_to(workspace).parts)
    )


def indexed_rust_paths(document: Path) -> list[str]:
    return [
        match.group(1)
        for line in document.read_text(encoding="utf-8").splitlines()
        if (match := INDEX_ROW.match(line)) and "/" not in match.group(1)
    ]


def check_document(workspace: Path, document: Path) -> list[str]:
    relative_document = document.relative_to(workspace)
    indexed = indexed_rust_paths(document)
    counts = Counter(indexed)
    direct_sources = sorted(path.name for path in document.parent.glob("*.rs"))
    errors: list[str] = []

    for path in sorted(path for path, count in counts.items() if count > 1):
        errors.append(f"SOURCE_INDEX_DUPLICATE_PATH: {relative_document}: {path}")
    for path in sorted(set(direct_sources) - set(indexed)):
        errors.append(f"SOURCE_INDEX_MISSING_PATH: {relative_document}: {path}")
    for path in sorted(set(indexed) - set(direct_sources)):
        errors.append(f"SOURCE_INDEX_STALE_PATH: {relative_document}: {path}")
    return errors


def check_workspace(workspace: Path) -> list[str]:
    return [
        error
        for document in source_documents(workspace)
        for error in check_document(workspace, document)
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    arguments = parser.parse_args()
    workspace = arguments.workspace.resolve()
    errors = check_workspace(workspace)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"status": "ok", "indexes": len(source_documents(workspace))},
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
