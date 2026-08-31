import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class BuildWorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github" / "workflows" / "build-binaries.yml").read_text(
            encoding="utf-8"
        )

    def test_uses_pinned_toolchain_and_locked_build(self) -> None:
        self.assertIn("rustup toolchain install 1.94.0 --profile minimal", self.workflow)
        self.assertNotIn("rustup default stable", self.workflow)
        self.assertIn("cargo build --release --locked -p edge-proxy", self.workflow)

    def test_source_quality_job_blocks_build_and_release(self) -> None:
        self.assertIn("quality:\n    name: Source quality", self.workflow)
        for command in (
            "cargo fmt --check",
            "cargo clippy --workspace --all-targets -- -D warnings",
            "cargo test --workspace -- --test-threads=1",
            "cargo run -p edge-core --example http_framing_mutation_fuzz -- 1000",
            "python3 tools/release/check_architecture.py --workspace .",
            "cargo install cargo-audit --version 0.22.2 --locked",
            "cargo audit",
        ):
            self.assertIn(command, self.workflow)
        self.assertIn("  build:\n    needs: quality", self.workflow)
        self.assertIn("    needs: [quality, build]", self.workflow)
        self.assertLess(self.workflow.index("  quality:"), self.workflow.index("  build:"))

    def test_release_docs_describe_the_blocking_quality_gate(self) -> None:
        for relative_path in ("docs/current-state.md", "docs/release-gate.md"):
            contents = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertIn("Source quality", contents, relative_path)
            self.assertIn("cargo audit", contents, relative_path)

    def test_reusable_test_container_uses_the_exact_workspace_toolchain(self) -> None:
        dockerfile = (ROOT / "Dockerfile.test").read_text(encoding="utf-8")
        self.assertIn("FROM rust:1.94.0-bookworm", dockerfile)
        self.assertNotIn("FROM rust:1.94-bookworm", dockerfile)

    def test_validates_release_identity_only_for_semver_tags(self) -> None:
        self.assertIn("Validate release metadata", self.workflow)
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", self.workflow)
        self.assertIn("python3 tools/release/validate_release_metadata.py --workspace . --tag", self.workflow)

    def test_releases_only_supported_linux_assets_and_keeps_pr_read_only(self) -> None:
        self.assertIn("permissions:\n  contents: read", self.workflow)
        self.assertIn("pattern: edge-proxy-linux-*", self.workflow)
        self.assertIn("contents: write", self.workflow)
        self.assertIn("if: startsWith(github.ref, 'refs/tags/v')", self.workflow)

    def test_tag_release_publishes_a_multi_arch_digest_and_assembled_manifest(self) -> None:
        self.assertIn("packages: write", self.workflow)
        self.assertIn("docker/setup-qemu-action@v3", self.workflow)
        self.assertIn("docker/setup-buildx-action@v3", self.workflow)
        self.assertIn("docker/login-action@v3", self.workflow)
        self.assertIn("docker/build-push-action@v6", self.workflow)
        self.assertIn("platforms: linux/amd64,linux/arm64", self.workflow)
        self.assertIn("push: true", self.workflow)
        self.assertIn("steps.image.outputs.digest", self.workflow)
        self.assertIn("tools/release/assemble_release_artifacts.py", self.workflow)
        self.assertIn("tools/release/validate_release_manifest.py", self.workflow)

    def test_tag_release_proves_the_digest_is_pullable_without_registry_credentials(self) -> None:
        self.assertIn("Verify published GHCR image is publicly pullable", self.workflow)
        self.assertIn("docker logout ghcr.io || true", self.workflow)
        self.assertIn(
            "docker pull ghcr.io/sponzey-lab/sponzey-edge:${GITHUB_REF_NAME}@${{ steps.image.outputs.digest }}",
            self.workflow,
        )
        self.assertLess(
            self.workflow.index("Verify published GHCR image is publicly pullable"),
            self.workflow.index("Assemble release assets"),
        )

    def test_linux_archives_include_the_systemd_install_assets(self) -> None:
        self.assertIn("cp packaging/systemd/sponzey-edge.service dist/systemd/", self.workflow)
        self.assertIn("cp packaging/systemd/install.sh packaging/systemd/uninstall.sh packaging/systemd/upgrade-helper dist/systemd/", self.workflow)
        self.assertIn("cp packaging/systemd/preflight.sh dist/systemd/", self.workflow)
        self.assertIn("cp examples/minimal.toml dist/current.toml", self.workflow)

    def test_ci_actions_use_the_node24_action_runtime(self) -> None:
        workflow_paths = (
            ROOT / ".github" / "workflows" / "build-binaries.yml",
            ROOT / ".github" / "workflows" / "performance-smoke.yml",
        )

        for path in workflow_paths:
            with self.subTest(workflow=path.name):
                workflow = path.read_text(encoding="utf-8")
                self.assertNotIn("actions/checkout@v4", workflow)
                self.assertIn("actions/checkout@v5", workflow)

        performance = workflow_paths[1].read_text(encoding="utf-8")
        self.assertNotIn("actions/setup-node@v4", performance)
        self.assertIn("actions/setup-node@v5", performance)


if __name__ == "__main__":
    unittest.main()
