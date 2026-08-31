import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class DependencyAdvisoryContractTest(unittest.TestCase):
    def test_h2_lockfile_resolution_meets_rustsec_2026_0258_minimum(self) -> None:
        lockfile = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
        match = re.search(
            r'name = "h2"\nversion = "([0-9]+)\.([0-9]+)\.([0-9]+)"', lockfile
        )
        self.assertIsNotNone(match, "Cargo.lock must contain the resolved h2 package")
        assert match is not None
        version = tuple(int(part) for part in match.groups())
        self.assertGreaterEqual(version, (0, 4, 16), "RUSTSEC-2026-0258 requires h2 >= 0.4.16")


if __name__ == "__main__":
    unittest.main()
