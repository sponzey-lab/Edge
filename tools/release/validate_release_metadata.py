#!/usr/bin/env python3
"""Fail closed when a release tag disagrees with canonical Rust metadata."""

import argparse
import json
import re
import sys
from pathlib import Path


CANONICAL_REPOSITORY = "https://github.com/sponzey-lab/Sponzey-Edge"
SEMVER_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
PINNED_TOOLCHAIN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class ContractError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def toml_string(path: Path, section: str, key: str) -> str:
    current_section = ""
    section_pattern = re.compile(r"^\[([^]]+)\]\s*$")
    key_pattern = re.compile(rf"^{re.escape(key)}\s*=\s*\"([^\"]+)\"\s*$")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ContractError("RELEASE_METADATA_MISSING", f"cannot read {path}: {error}") from error
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        matched_section = section_pattern.match(line)
        if matched_section:
            current_section = matched_section.group(1)
            continue
        if current_section == section:
            matched_key = key_pattern.match(line)
            if matched_key:
                return matched_key.group(1)
    raise ContractError("RELEASE_METADATA_MISSING", f"missing [{section}] {key} in {path}")


def validate(workspace: Path, tag: str) -> dict[str, str]:
    matched_tag = SEMVER_TAG.fullmatch(tag)
    if matched_tag is None:
        raise ContractError("RELEASE_TAG_INVALID", "tag must be vMAJOR.MINOR.PATCH without a prerelease suffix")

    repository = toml_string(workspace / "Cargo.toml", "workspace.package", "repository")
    if repository != CANONICAL_REPOSITORY:
        raise ContractError("RELEASE_REPOSITORY_INVALID", "workspace repository is not canonical")

    rust_version = toml_string(workspace / "Cargo.toml", "workspace.package", "rust-version")
    toolchain = toml_string(workspace / "rust-toolchain.toml", "toolchain", "channel")
    if PINNED_TOOLCHAIN.fullmatch(toolchain) is None:
        raise ContractError("RELEASE_TOOLCHAIN_UNPINNED", "toolchain channel must be an exact x.y.z release")
    if rust_version != ".".join(toolchain.split(".")[:2]):
        raise ContractError("RELEASE_TOOLCHAIN_MISMATCH", "rust-version must match the pinned toolchain major.minor")

    version = toml_string(workspace / "apps/edge-proxy/Cargo.toml", "package", "version")
    if version != ".".join(matched_tag.groups()):
        raise ContractError("RELEASE_VERSION_MISMATCH", "tag and edge-proxy package version differ")
    return {"repository": repository, "tag": tag, "toolchain": toolchain, "version": version}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    arguments = parser.parse_args()
    try:
        result = validate(arguments.workspace.resolve(), arguments.tag)
    except ContractError as error:
        print(f"{error.code}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
