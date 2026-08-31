import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CURRENT_DOCUMENTS = (
    "README.md",
    "README.ko.md",
    "docs/architecture.md",
    "docs/config-schema.md",
    "docs/admin-api.md",
    "docs/observability.md",
    "docs/install.md",
    "docs/deployment.md",
    "docs/backup-restore.md",
    "docs/troubleshooting.md",
    "docs/testing.md",
    "docs/release-gate.md",
)
MARKDOWN_LINK = re.compile(r"\]\(([^)#]+\.md)(?:#[^)]*)?\)")


class CurrentDocumentationLinkContractTest(unittest.TestCase):
    def test_current_operator_docs_resolve_local_markdown_links(self) -> None:
        for relative_path in CURRENT_DOCUMENTS:
            document = ROOT / relative_path
            contents = document.read_text(encoding="utf-8")
            for target in MARKDOWN_LINK.findall(contents):
                with self.subTest(document=relative_path, target=target):
                    self.assertTrue(
                        (document.parent / target).is_file(),
                        f"missing local document link: {relative_path} -> {target}",
                    )


if __name__ == "__main__":
    unittest.main()
