import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "tools" / "release" / "validate_release_manifest.py"
IMAGE = "ghcr.io/sponzey-lab/sponzey-edge"


class ReleaseManifestContractTest(unittest.TestCase):
    def make_release(
        self,
        *,
        include_arm64: bool = True,
        image: Optional[str] = None,
        corrupt_checksums: bool = False,
        invalid_sbom: bool = False,
    ) -> tempfile.TemporaryDirectory[str]:
        release = tempfile.TemporaryDirectory()
        root = Path(release.name)
        artifacts = []
        checksums = []
        platforms = ["linux-amd64"] + (["linux-arm64"] if include_arm64 else [])
        for platform in platforms:
            archive = f"edge-proxy-{platform}.tar.gz"
            sbom = f"edge-proxy-{platform}.spdx.json"
            archive_bytes = f"archive:{platform}".encode()
            (root / archive).write_bytes(archive_bytes)
            sbom_body = '{"spdxVersion":"SPDX-2.3"}'
            if invalid_sbom and platform == "linux-amd64":
                sbom_body = '{"spdxVersion":"SPDX-2.2"}'
            (root / sbom).write_text(sbom_body, encoding="utf-8")
            archive_digest = hashlib.sha256(archive_bytes).hexdigest()
            sbom_digest = hashlib.sha256((root / sbom).read_bytes()).hexdigest()
            artifacts.append(
                {
                    "platform": platform,
                    "archive": archive,
                    "sha256": archive_digest,
                    "sbom": sbom,
                }
            )
            checksums.extend([(archive_digest, archive), (sbom_digest, sbom)])
        if corrupt_checksums:
            checksums[0] = ("0" * 64, checksums[0][1])
        (root / "SHA256SUMS").write_text(
            "".join(f"{digest}  {filename}\n" for digest, filename in checksums), encoding="utf-8"
        )
        manifest = {
            "schema_version": 1,
            "tag": "v0.1.0",
            "commit": "a" * 40,
            "image": image or f"{IMAGE}:v0.1.0@sha256:{'b' * 64}",
            "artifacts": artifacts,
        }
        (root / "release-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return release

    def validate(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--manifest",
                str(root / "release-manifest.json"),
                "--artifacts",
                str(root),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_accepts_complete_two_platform_manifest(self) -> None:
        with self.make_release() as directory:
            result = self.validate(Path(directory))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"schema_version":1', result.stdout)

    def test_rejects_missing_linux_arm64_artifact(self) -> None:
        with self.make_release(include_arm64=False) as directory:
            result = self.validate(Path(directory))

        self.assertIn("RELEASE_PLATFORM_MISSING", result.stderr)

    def test_rejects_mutable_only_image_reference(self) -> None:
        with self.make_release(image=f"{IMAGE}:v0.1.0") as directory:
            result = self.validate(Path(directory))

        self.assertIn("RELEASE_IMAGE_DIGEST_INVALID", result.stderr)

    def test_rejects_checksum_mismatch(self) -> None:
        with self.make_release(corrupt_checksums=True) as directory:
            result = self.validate(Path(directory))

        self.assertIn("RELEASE_CHECKSUM_MISMATCH", result.stderr)

    def test_rejects_non_spdx_23_sbom(self) -> None:
        with self.make_release(invalid_sbom=True) as directory:
            result = self.validate(Path(directory))

        self.assertIn("RELEASE_SBOM_INVALID", result.stderr)


if __name__ == "__main__":
    unittest.main()
