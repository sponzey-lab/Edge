#!/usr/bin/env python3
"""Validate release artifacts without contacting a registry or reading product data."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


EXPECTED_PLATFORMS = {"linux-amd64", "linux-arm64"}
IMAGE_REPOSITORY = "ghcr.io/sponzey-lab/sponzey-edge"
SEMVER_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ManifestError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def fail(code: str, message: str) -> None:
    raise ManifestError(code, message)


def read_json(path: Path, code: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(code, f"cannot parse {path.name}: {error}")


def safe_name(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or Path(value).name != value:
        fail("RELEASE_MANIFEST_INVALID", f"{field} must be one safe filename")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        fail("RELEASE_ARTIFACT_MISSING", f"cannot read {path.name}: {error}")
    return digest.hexdigest()


def checksum_entries(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        fail("RELEASE_CHECKSUM_MISSING", f"cannot read SHA256SUMS: {error}")
    entries: dict[str, str] = {}
    for line in lines:
        matched = re.fullmatch(r"([0-9a-f]{64})  ([^/\\\s]+)", line)
        if matched is None or matched.group(2) in entries:
            fail("RELEASE_CHECKSUM_INVALID", "SHA256SUMS must contain unique lowercase sha256 filename pairs")
        entries[matched.group(2)] = matched.group(1)
    return entries


def validate_image(value: object, tag: str) -> None:
    if not isinstance(value, str):
        fail("RELEASE_IMAGE_DIGEST_INVALID", "image must be a string")
    expected_prefix = f"{IMAGE_REPOSITORY}:{tag}@sha256:"
    if not value.startswith(expected_prefix) or SHA256.fullmatch(value[len(expected_prefix) :]) is None:
        fail("RELEASE_IMAGE_DIGEST_INVALID", "image must use the canonical repository, tag, and immutable sha256 digest")


def validate(manifest_path: Path, artifacts: Path) -> dict[str, object]:
    manifest = read_json(manifest_path, "RELEASE_MANIFEST_INVALID")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        fail("RELEASE_MANIFEST_INVALID", "manifest schema_version must be 1")
    tag = manifest.get("tag")
    if not isinstance(tag, str) or SEMVER_TAG.fullmatch(tag) is None:
        fail("RELEASE_MANIFEST_INVALID", "manifest tag must be strict SemVer")
    commit = manifest.get("commit")
    if not isinstance(commit, str) or COMMIT.fullmatch(commit) is None:
        fail("RELEASE_MANIFEST_INVALID", "manifest commit must be a lowercase 40-hex identity")
    validate_image(manifest.get("image"), tag)

    artifact_entries = manifest.get("artifacts")
    if not isinstance(artifact_entries, list):
        fail("RELEASE_MANIFEST_INVALID", "artifacts must be a list")
    seen_platforms: set[str] = set()
    expected_files: set[str] = set()
    for item in artifact_entries:
        if not isinstance(item, dict):
            fail("RELEASE_MANIFEST_INVALID", "artifact entry must be an object")
        platform = item.get("platform")
        if not isinstance(platform, str) or platform in seen_platforms:
            fail("RELEASE_PLATFORM_DUPLICATE", "artifact platform must occur exactly once")
        seen_platforms.add(platform)
        archive = safe_name(item.get("archive"), "archive")
        sbom = safe_name(item.get("sbom"), "sbom")
        digest = item.get("sha256")
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            fail("RELEASE_MANIFEST_INVALID", "artifact sha256 must be lowercase hex")
        archive_path = artifacts / archive
        if sha256_file(archive_path) != digest:
            fail("RELEASE_CHECKSUM_MISMATCH", f"manifest checksum differs for {archive}")
        sbom_value = read_json(artifacts / sbom, "RELEASE_SBOM_INVALID")
        if not isinstance(sbom_value, dict) or sbom_value.get("spdxVersion") != "SPDX-2.3":
            fail("RELEASE_SBOM_INVALID", f"{sbom} is not SPDX-2.3 JSON")
        expected_files.update({archive, sbom})
    if seen_platforms != EXPECTED_PLATFORMS:
        fail("RELEASE_PLATFORM_MISSING", "manifest must contain exactly linux-amd64 and linux-arm64")

    checksums = checksum_entries(artifacts / "SHA256SUMS")
    if set(checksums) != expected_files:
        fail("RELEASE_CHECKSUM_INVALID", "SHA256SUMS must cover exactly the manifest artifact and SBOM files")
    for filename, digest in checksums.items():
        if sha256_file(artifacts / filename) != digest:
            fail("RELEASE_CHECKSUM_MISMATCH", f"SHA256SUMS differs for {filename}")
    return {"artifact_count": len(artifact_entries), "schema_version": 1, "tag": tag}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = validate(arguments.manifest.resolve(), arguments.artifacts.resolve())
    except ManifestError as error:
        print(f"{error.code}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
