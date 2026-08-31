import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ManualFuzzContractTest(unittest.TestCase):
    def test_manual_http_framing_mutation_runner_is_bounded_and_documented(self) -> None:
        runner = ROOT / "crates" / "edge-core" / "examples" / "http_framing_mutation_fuzz.rs"
        source = runner.read_text(encoding="utf-8")
        testing = (ROOT / "docs" / "testing.md").read_text(encoding="utf-8")

        self.assertIn("const DEFAULT_CASES: u32", source)
        self.assertIn("const MAX_CASES: u32", source)
        self.assertIn("parse_http_request", source)
        self.assertIn("HttpResponseFraming", source)
        self.assertIn("fuzz_connection_state_machine", source)
        self.assertIn("ConnectionEvent", source)
        self.assertIn("case count must be between", source)
        self.assertIn("http_framing_mutation_fuzz", testing)
        self.assertIn("not release evidence", testing)


if __name__ == "__main__":
    unittest.main()
