import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ProductScopeDocumentationContractTest(unittest.TestCase):
    def test_operational_docs_defer_external_acme_and_document_support_bundle(self) -> None:
        install = (ROOT / "docs" / "install.md").read_text(encoding="utf-8")
        deployment = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
        current_state = (ROOT / "docs" / "current-state.md").read_text(encoding="utf-8")
        release_gate = (ROOT / "docs" / "release-gate.md").read_text(encoding="utf-8")

        self.assertIn("manual certificates and private PKI only", install)
        self.assertIn("POST /api/v1/support-bundles", deployment)
        self.assertIn("clean-host release evidence", current_state)
        self.assertIn("Manual certificates and private PKI are the only supported certificate paths", release_gate)
        self.assertIn("clean-host", release_gate)

    def test_readmes_describe_the_fixed_secret_free_support_bundle_contract(self) -> None:
        english = (ROOT / "README.md").read_text(encoding="utf-8")
        korean = (ROOT / "README.ko.md").read_text(encoding="utf-8")

        self.assertIn("POST /api/v1/support-bundles", english)
        self.assertIn("secret-free receipt", english)
        self.assertIn("POST /api/v1/support-bundles", korean)
        self.assertIn("private key, secret", korean)

    def test_current_operating_commands_do_not_bootstrap_deferred_acme(self) -> None:
        documents = {
            "README.md": (ROOT / "README.md").read_text(encoding="utf-8"),
            "README.ko.md": (ROOT / "README.ko.md").read_text(encoding="utf-8"),
            "docs/install.md": (ROOT / "docs" / "install.md").read_text(encoding="utf-8"),
            "docs/deployment.md": (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8"),
        }

        for name, document in documents.items():
            with self.subTest(document=name):
                self.assertNotIn("SPONZEY_ACME_CLIENT=", document)

    def test_release_evidence_template_archives_deferred_acme_runbooks(self) -> None:
        template = (ROOT / "docs" / "release-evidence-template.md").read_text(encoding="utf-8")

        self.assertIn("archive-only", template)
        self.assertNotIn("scripts/init_acme_staging", template)
        self.assertNotIn("scripts/check_mvp_release_ready.sh", template)
        self.assertNotIn("scripts/check_acme_staging_evidence.sh", template)

    def test_release_gate_has_no_current_or_archived_acme_runbook_command(self) -> None:
        release_gate = (ROOT / "docs" / "release-gate.md").read_text(encoding="utf-8")

        self.assertNotIn("SPONZEY_ACME_CLIENT=", release_gate)
        self.assertNotIn("scripts/init_acme_staging", release_gate)
        self.assertNotIn("scripts/check_acme_staging", release_gate)
        self.assertNotIn("scripts/check_mvp_release_ready.sh", release_gate)


if __name__ == "__main__":
    unittest.main()
