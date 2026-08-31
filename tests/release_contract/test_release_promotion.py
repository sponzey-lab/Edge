import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "tools" / "release" / "validate_promotion_evidence.py"
TAG = "v0.1.0"
COMMIT = "a" * 40
IMAGE = f"ghcr.io/sponzey-lab/sponzey-edge:{TAG}@sha256:{'b' * 64}"


class ReleasePromotionContractTest(unittest.TestCase):
    def evidence(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "tag": TAG,
            "commit": COMMIT,
            "image": IMAGE,
            "source_quality": "passed",
            "support_bundle": "passed",
            "manual_or_private_pki_only": True,
            "certificate_automation_deferred": True,
            "matrix": [
                {"deployment": deployment, "platform": platform, "status": "passed"}
                for deployment in ("compose", "systemd")
                for platform in ("linux-amd64", "linux-arm64")
            ],
        }

    def validate(self, evidence: dict[str, object]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "promotion.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            return subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--evidence",
                    str(path),
                    "--tag",
                    TAG,
                    "--commit",
                    COMMIT,
                    "--image",
                    IMAGE,
                ],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_accepts_complete_same_identity_matrix_evidence(self) -> None:
        result = self.validate(self.evidence())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"matrix_cells":4', result.stdout)

    def test_rejects_missing_matrix_cell(self) -> None:
        evidence = self.evidence()
        evidence["matrix"] = evidence["matrix"][:-1]  # type: ignore[index]
        result = self.validate(evidence)
        self.assertIn("PROMOTION_MATRIX_INCOMPLETE", result.stderr)

    def test_rejects_identity_or_certificate_scope_drift(self) -> None:
        evidence = self.evidence()
        evidence["image"] = f"ghcr.io/sponzey-lab/sponzey-edge:{TAG}"
        result = self.validate(evidence)
        self.assertIn("PROMOTION_IDENTITY_MISMATCH", result.stderr)

        evidence = self.evidence()
        evidence["certificate_automation_deferred"] = False
        result = self.validate(evidence)
        self.assertIn("PROMOTION_SCOPE_INVALID", result.stderr)

    def test_workflows_create_only_a_prerelease_until_manual_promotion(self) -> None:
        candidate = (ROOT / ".github/workflows/build-binaries.yml").read_text(encoding="utf-8")
        promotion = (ROOT / ".github/workflows/promote-release.yml").read_text(encoding="utf-8")
        self.assertIn("Create GitHub prerelease candidate", candidate)
        self.assertIn("prerelease: true", candidate)
        self.assertNotIn("Create GitHub Release", candidate)
        self.assertIn("workflow_dispatch", promotion)
        self.assertIn("validate_promotion_evidence.py", promotion)
        self.assertIn("gh release edit", promotion)

    def test_release_docs_describe_tracked_evidence_promotion(self) -> None:
        release_gate = (ROOT / "docs/release-gate.md").read_text(encoding="utf-8")
        template = (ROOT / "docs/release-evidence-template.md").read_text(encoding="utf-8")
        self.assertIn("promote-release.yml", release_gate)
        self.assertIn("promotion.json", template)
        self.assertIn("certificate_automation_deferred", template)


if __name__ == "__main__":
    unittest.main()
