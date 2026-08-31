import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "tools" / "release" / "check_architecture.py"


class ArchitectureFitnessContractTest(unittest.TestCase):
    def run_checker(self, workspace: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(CHECKER), "--workspace", str(workspace)],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_current_workspace_passes_the_executable_fitness_gate(self) -> None:
        result = self.run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"status":"ok"', result.stdout)

    def test_gate_rejects_forbidden_inner_layer_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            crate = root / "crates" / "edge-domain"
            (crate / "src").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["crates/edge-domain"]\n', encoding="utf-8"
            )
            (crate / "Cargo.toml").write_text(
                '[package]\nname = "edge-domain"\nversion = "0.1.0"\n\n[dependencies]\nmio = "1"\n',
                encoding="utf-8",
            )
            (crate / "src" / "lib.rs").write_text("pub struct Route;\n", encoding="utf-8")

            result = self.run_checker(root)

        self.assertEqual(result.returncode, 2)
        self.assertIn("ARCHITECTURE_FORBIDDEN_DEPENDENCY", result.stderr)

    def test_gate_rejects_environment_read_outside_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "apps" / "edge-proxy" / "src"
            source.mkdir(parents=True)
            (source / "main.rs").write_text(
                'fn main() { let _ = std::env::var("SPONZEY_ROUTE_MODE"); }\n',
                encoding="utf-8",
            )

            result = self.run_checker(root)

        self.assertEqual(result.returncode, 2)
        self.assertIn("ARCHITECTURE_ENV_OUTSIDE_BOOTSTRAP", result.stderr)

    def test_gate_rejects_unsafe_without_a_safety_invariant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "apps" / "edge-proxy" / "src"
            source.mkdir(parents=True)
            (source / "main.rs").write_text(
                "fn main() { unsafe { libc::abort(); } }\n", encoding="utf-8"
            )

            result = self.run_checker(root)

        self.assertEqual(result.returncode, 2)
        self.assertIn("ARCHITECTURE_UNSAFE_UNDOCUMENTED", result.stderr)

    def test_build_workflow_runs_the_fitness_gate_before_release_build(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "build-binaries.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("Architecture fitness", workflow)
        self.assertIn("python3 tools/release/check_architecture.py --workspace .", workflow)
        self.assertLess(
            workflow.index("Architecture fitness"), workflow.index("Build release binary")
        )

    def test_operational_docs_name_the_current_fitness_command(self) -> None:
        command = "python3 tools/release/check_architecture.py --workspace ."
        for relative_path in (
            "docs/architecture.md",
            "docs/current-state.md",
            "docs/release-gate.md",
        ):
            contents = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertIn(command, contents, relative_path)
            self.assertNotIn("scripts/check_architecture.sh", contents, relative_path)


if __name__ == "__main__":
    unittest.main()
