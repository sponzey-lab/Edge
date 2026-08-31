import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "tools" / "release" / "validate_release_metadata.py"
CANONICAL_REPOSITORY = "https://github.com/sponzey-lab/Sponzey-Edge"


class ReleaseMetadataContractTest(unittest.TestCase):
    def test_current_compose_documentation_repair_candidate_metadata_is_v007_before_tagging(self) -> None:
        manifest = (ROOT / "apps" / "edge-proxy" / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('version = "0.0.7"', manifest)
        current_state = (ROOT / "docs" / "current-state.md").read_text(encoding="utf-8")
        self.assertIn("v0.0.7 candidate metadata", current_state)
        self.assertIn("no tag or published artifact", current_state)

    def make_workspace(
        self,
        *,
        repository: str = CANONICAL_REPOSITORY,
        version: str = "0.1.0",
        toolchain: str = "1.94.0",
    ) -> tempfile.TemporaryDirectory[str]:
        workspace = tempfile.TemporaryDirectory()
        root = Path(workspace.name)
        (root / "apps" / "edge-proxy").mkdir(parents=True)
        (root / "Cargo.toml").write_text(
            "[workspace.package]\n"
            f'repository = "{repository}"\n'
            'rust-version = "1.94"\n',
            encoding="utf-8",
        )
        (root / "apps" / "edge-proxy" / "Cargo.toml").write_text(
            "[package]\n"
            'name = "edge-proxy"\n'
            f'version = "{version}"\n',
            encoding="utf-8",
        )
        (root / "rust-toolchain.toml").write_text(
            "[toolchain]\n"
            f'channel = "{toolchain}"\n',
            encoding="utf-8",
        )
        return workspace

    def validate(self, workspace: Path, tag: str = "v0.1.0") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), "--workspace", str(workspace), "--tag", tag],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_accepts_canonical_matching_release_metadata(self) -> None:
        with self.make_workspace() as directory:
            result = self.validate(Path(directory))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"tag":"v0.1.0"', result.stdout)

    def test_rejects_placeholder_repository(self) -> None:
        with self.make_workspace(repository="https://example.invalid/sponzey-edge-proxy") as directory:
            result = self.validate(Path(directory))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RELEASE_REPOSITORY_INVALID", result.stderr)

    def test_rejects_malformed_or_mismatched_tag(self) -> None:
        with self.make_workspace() as directory:
            malformed = self.validate(Path(directory), tag="release-0.1.0")
            mismatched = self.validate(Path(directory), tag="v0.1.1")

        self.assertIn("RELEASE_TAG_INVALID", malformed.stderr)
        self.assertIn("RELEASE_VERSION_MISMATCH", mismatched.stderr)

    def test_rejects_moving_toolchain(self) -> None:
        with self.make_workspace(toolchain="stable") as directory:
            result = self.validate(Path(directory))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RELEASE_TOOLCHAIN_UNPINNED", result.stderr)


if __name__ == "__main__":
    unittest.main()
