#!/usr/bin/env python3
"""Assemble a deterministic, locally verifiable Linux release directory."""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path


ARCHIVES = {
    "linux-amd64": "edge-proxy-linux-x86_64.tar.gz",
    "linux-arm64": "edge-proxy-linux-arm64.tar.gz",
}
IMAGE_REPOSITORY = "ghcr.io/sponzey-lab/sponzey-edge"
SEMVER_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AssemblyError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def fail(code: str, message: str) -> None:
    raise AssemblyError(code, message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_bytes(path: Path, value: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())


def require_archive(artifacts: Path, filename: str) -> Path:
    path = artifacts / filename
    if not path.is_file() or path.is_symlink():
        fail("RELEASE_ASSEMBLY_INPUT_INVALID", f"missing regular archive {filename}")
    return path


def validate_inputs(tag: str, commit: str, image: str, created: str) -> None:
    if SEMVER_TAG.fullmatch(tag) is None:
        fail("RELEASE_ASSEMBLY_TAG_INVALID", "tag must be vMAJOR.MINOR.PATCH")
    if COMMIT.fullmatch(commit) is None:
        fail("RELEASE_ASSEMBLY_COMMIT_INVALID", "commit must be lowercase 40-hex")
    image_prefix = f"{IMAGE_REPOSITORY}:{tag}@sha256:"
    if not image.startswith(image_prefix) or SHA256.fullmatch(image[len(image_prefix) :]) is None:
        fail("RELEASE_ASSEMBLY_IMAGE_INVALID", "image must use canonical tag plus immutable sha256 digest")
    try:
        datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise AssemblyError("RELEASE_ASSEMBLY_TIMESTAMP_INVALID", "created must be UTC RFC3339 seconds") from error


def spdx_document(filename: str, digest: str, tag: str, commit: str, platform: str, created: str) -> dict:
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "name": f"sponzey-edge-{tag}-{platform}",
        "documentNamespace": f"https://github.com/sponzey-lab/Sponzey-Edge/releases/{tag}/{commit}/{platform}",
        "creationInfo": {"created": created, "creators": ["Tool: sponzey-edge-release-assembler"]},
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-edge-proxy",
                "name": "edge-proxy",
                "versionInfo": tag[1:],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
            }
        ],
        "files": [
            {
                "SPDXID": "SPDXRef-File-edge-proxy",
                "fileName": filename,
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                "licenseConcluded": "NOASSERTION",
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-Package-edge-proxy",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": "SPDXRef-File-edge-proxy",
            }
        ],
    }


def assemble(artifacts: Path, output: Path, tag: str, commit: str, image: str, created: str) -> dict:
    validate_inputs(tag, commit, image, created)
    if output.exists():
        fail("RELEASE_ASSEMBLY_OUTPUT_EXISTS", "output path already exists")
    parent = output.parent
    if not parent.is_dir() or parent.is_symlink():
        fail("RELEASE_ASSEMBLY_OUTPUT_INVALID", "output parent must be a regular existing directory")
    stage = parent / f".{output.name}.partial"
    if stage.exists():
        fail("RELEASE_ASSEMBLY_OUTPUT_EXISTS", "partial output path already exists")

    sources = {platform: require_archive(artifacts, filename) for platform, filename in ARCHIVES.items()}
    try:
        stage.mkdir()
        manifest_artifacts = []
        checksums = {}
        for platform, source in sources.items():
            archive_name = source.name
            archive_output = stage / archive_name
            shutil.copyfile(source, archive_output)
            archive_digest = sha256_file(archive_output)
            sbom_name = archive_name.removesuffix(".tar.gz") + ".spdx.json"
            sbom_bytes = json.dumps(
                spdx_document(archive_name, archive_digest, tag, commit, platform, created),
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            write_bytes(stage / sbom_name, sbom_bytes)
            manifest_artifacts.append(
                {"archive": archive_name, "platform": platform, "sbom": sbom_name, "sha256": archive_digest}
            )
            checksums[archive_name] = archive_digest
            checksums[sbom_name] = sha256_file(stage / sbom_name)
        manifest = {
            "artifacts": manifest_artifacts,
            "commit": commit,
            "image": image,
            "schema_version": 1,
            "tag": tag,
        }
        write_bytes(
            stage / "release-manifest.json",
            json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        )
        checksum_lines = "".join(f"{checksums[name]}  {name}\n" for name in sorted(checksums))
        write_bytes(stage / "SHA256SUMS", checksum_lines.encode("utf-8"))
        os.replace(stage, output)
    except AssemblyError:
        raise
    except OSError as error:
        fail("RELEASE_ASSEMBLY_IO", str(error))
    return {"artifact_count": len(manifest_artifacts), "schema_version": 1, "tag": tag}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--created", required=True)
    arguments = parser.parse_args()
    try:
        result = assemble(
            arguments.artifacts.resolve(),
            arguments.output.resolve(),
            arguments.tag,
            arguments.commit,
            arguments.image,
            arguments.created,
        )
    except AssemblyError as error:
        print(f"{error.code}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
