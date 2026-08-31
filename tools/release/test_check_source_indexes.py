"""Unit tests for the structural Rust source-index validator."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


def load_validator():
    path = Path(__file__).with_name("check_source_indexes.py")
    spec = importlib.util.spec_from_file_location("check_source_indexes", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SourceIndexValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = load_validator()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        self.source_dir = self.workspace / "crate" / "src"
        self.source_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_index(self, rows: list[str]) -> None:
        table = "\n".join(rows)
        (self.source_dir / "source.md").write_text(
            "# Test index\n\n| Path | Responsibility | Boundary |\n| --- | --- | --- |\n"
            f"{table}\n",
            encoding="utf-8",
        )

    def test_accepts_every_direct_rust_source_indexed_once(self) -> None:
        (self.source_dir / "lib.rs").write_text("", encoding="utf-8")
        (self.source_dir / "policy.rs").write_text("", encoding="utf-8")
        self.write_index(
            [
                "| `lib.rs` | Root | None |",
                "| `policy.rs` | Policy | None |",
            ]
        )

        self.assertEqual(self.validator.check_workspace(self.workspace), [])

    def test_reports_missing_stale_and_duplicate_rust_paths(self) -> None:
        (self.source_dir / "lib.rs").write_text("", encoding="utf-8")
        (self.source_dir / "policy.rs").write_text("", encoding="utf-8")
        self.write_index(
            [
                "| `lib.rs` | Root | None |",
                "| `lib.rs` | Duplicate | None |",
                "| `removed.rs` | Stale | None |",
            ]
        )

        self.assertEqual(
            self.validator.check_workspace(self.workspace),
            [
                "SOURCE_INDEX_DUPLICATE_PATH: crate/src/source.md: lib.rs",
                "SOURCE_INDEX_MISSING_PATH: crate/src/source.md: policy.rs",
                "SOURCE_INDEX_STALE_PATH: crate/src/source.md: removed.rs",
            ],
        )


if __name__ == "__main__":
    unittest.main()
