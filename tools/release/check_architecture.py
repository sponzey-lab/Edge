#!/usr/bin/env python3
"""Executable architecture fitness checks for the product dependency boundary."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


INNER_LAYER_FORBIDDEN = {
    "edge-domain": {"mio", "rustls", "rustls-pki-types", "tokio", "instant-acme"},
    "edge-ports": {"mio", "rustls", "rustls-pki-types", "tokio", "instant-acme"},
    "edge-application": {"mio", "rustls", "rustls-pki-types", "tokio", "instant-acme"},
    "edge-core": {"rustls", "rustls-pki-types", "tokio", "instant-acme", "edge-adapters"},
    "edge-admin-api": {
        "mio",
        "rustls",
        "rustls-pki-types",
        "tokio",
        "edge-core",
        "edge-adapters",
    },
}
ENV_READ = re.compile(r"(?:std::)?env::(?:var|vars|var_os|vars_os)\b")
UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")


def dependency_names(manifest: Path) -> set[str]:
    """Read normal and target-specific runtime dependencies without a TOML library."""
    names: set[str] = set()
    in_runtime_dependencies = False
    for raw_line in manifest.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            header = line[1:-1]
            in_runtime_dependencies = header == "dependencies" or header.endswith(".dependencies")
            continue
        if not in_runtime_dependencies or not line or line.startswith("#"):
            continue
        match = re.match(r"([A-Za-z0-9_-]+)\s*=", line)
        if match:
            names.add(match.group(1))
    return names


def product_source_files(workspace: Path) -> list[Path]:
    source_root = workspace / "apps" / "edge-proxy" / "src"
    if not source_root.exists():
        return []
    return sorted(path for path in source_root.rglob("*.rs") if path.name != "bootstrap.rs")


def check_dependencies(workspace: Path, errors: list[str]) -> None:
    for crate_name, forbidden in INNER_LAYER_FORBIDDEN.items():
        manifest = workspace / "crates" / crate_name / "Cargo.toml"
        if not manifest.exists():
            continue
        dependencies = dependency_names(manifest)
        for dependency in sorted(dependencies & forbidden):
            errors.append(
                "ARCHITECTURE_FORBIDDEN_DEPENDENCY: "
                f"{crate_name} must not depend on {dependency} ({manifest.relative_to(workspace)})"
            )


def check_bootstrap_environment(workspace: Path, errors: list[str]) -> None:
    for path in product_source_files(workspace):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if ENV_READ.search(line):
                errors.append(
                    "ARCHITECTURE_ENV_OUTSIDE_BOOTSTRAP: "
                    f"{path.relative_to(workspace)}:{number} reads environment outside bootstrap.rs"
                )


def check_unsafe_invariants(workspace: Path, errors: list[str]) -> None:
    for path in product_source_files(workspace):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if UNSAFE_BLOCK.search(line) and "SAFETY:" not in "\n".join(lines[max(0, index - 3) : index + 1]):
                errors.append(
                    "ARCHITECTURE_UNSAFE_UNDOCUMENTED: "
                    f"{path.relative_to(workspace)}:{index + 1} requires a nearby SAFETY invariant"
                )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    arguments = parser.parse_args()
    workspace = arguments.workspace.resolve()
    errors: list[str] = []
    check_dependencies(workspace, errors)
    check_bootstrap_environment(workspace, errors)
    check_unsafe_invariants(workspace, errors)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 2
    print(json.dumps({"status": "ok", "checks": 3}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
