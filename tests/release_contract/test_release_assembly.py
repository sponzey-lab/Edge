import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ASSEMBLER = ROOT / "tools" / "release" / "assemble_release_artifacts.py"
MANIFEST_VALIDATOR = ROOT / "tools" / "release" / "validate_release_manifest.py"
IMAGE = f"ghcr.io/sponzey-lab/sponzey-edge:v0.1.0@sha256:{'b' * 64}"


class ReleaseAssemblyContractTest(unittest.TestCase):
    def make_input(self, *, include_arm64: bool = True) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "edge-proxy-linux-x86_64.tar.gz").write_bytes(b"amd64 archive")
        if include_arm64:
            (root / "edge-proxy-linux-arm64.tar.gz").write_bytes(b"arm64 archive")
        return temporary

    def assemble(self, artifacts: Path, output: Path, image: str = IMAGE) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(ASSEMBLER),
                "--artifacts",
                str(artifacts),
                "--output",
                str(output),
                "--tag",
                "v0.1.0",
                "--commit",
                "a" * 40,
                "--image",
                image,
                "--created",
                "2026-08-14T00:00:00Z",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_assembles_verifiable_two_platform_release(self) -> None:
        with self.make_input() as directory:
            root = Path(directory)
            output = root / "output"
            result = self.assemble(root, output)
            validation = subprocess.run(
                [
                    sys.executable,
                    str(MANIFEST_VALIDATOR),
                    "--manifest",
                    str(output / "release-manifest.json"),
                    "--artifacts",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            checksum_exists = (output / "SHA256SUMS").is_file()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(validation.returncode, 0, validation.stderr)
        self.assertTrue(checksum_exists)

    def test_rejects_missing_required_archive(self) -> None:
        with self.make_input(include_arm64=False) as directory:
            root = Path(directory)
            result = self.assemble(root, root / "output")

        self.assertIn("RELEASE_ASSEMBLY_INPUT_INVALID", result.stderr)

    def test_rejects_existing_output(self) -> None:
        with self.make_input() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            result = self.assemble(root, output)

        self.assertIn("RELEASE_ASSEMBLY_OUTPUT_EXISTS", result.stderr)

    def test_rejects_mutable_image(self) -> None:
        with self.make_input() as directory:
            root = Path(directory)
            result = self.assemble(root, root / "output", "ghcr.io/sponzey-lab/sponzey-edge:v0.1.0")

        self.assertIn("RELEASE_ASSEMBLY_IMAGE_INVALID", result.stderr)


if __name__ == "__main__":
    unittest.main()
