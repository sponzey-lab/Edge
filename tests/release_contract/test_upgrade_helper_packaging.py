import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class UpgradeHelperPackagingContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.helper = ROOT / "packaging" / "systemd" / "upgrade-helper"
        cls.install = (ROOT / "packaging" / "systemd" / "install.sh").read_text(encoding="utf-8")
        cls.workflow = (ROOT / ".github" / "workflows" / "build-binaries.yml").read_text(encoding="utf-8")

    def test_helper_is_packaged_and_installed_at_the_runner_allowlist_path(self) -> None:
        self.assertTrue(self.helper.is_file())
        self.assertIn("packaging/systemd/upgrade-helper", self.workflow)
        self.assertIn("/usr/local/libexec/sponzey-edge", self.install)
        self.assertIn("upgrade-helper", self.install)

    def test_helper_has_a_strict_secret_safe_protocol(self) -> None:
        source = self.helper.read_text(encoding="utf-8")
        self.assertIn('case "$command" in', source)
        self.assertIn("backup-create-verify", source)
        self.assertIn('"--passphrase-file"', source)
        self.assertNotIn('"--passphrase"', source)
        self.assertNotIn("eval ", source)
        self.assertIn("backup_id=", source)
        self.assertIn("previous_artifact_digest=", source)
        self.assertIn("STAGED_BINARY=/usr/local/bin/.edge-proxy.staged", source)
        self.assertIn("PREVIOUS_BINARY=/usr/local/bin/.edge-proxy.previous", source)
        self.assertIn('mv "$EDGE_PROXY" "$PREVIOUS_BINARY"', source)
        self.assertIn('mv "$STAGED_BINARY" "$EDGE_PROXY"', source)
        self.assertIn('mv "$PREVIOUS_BINARY" "$EDGE_PROXY"', source)
        self.assertNotIn("stage-artifact is not implemented", source)

    def test_helper_stage_and_switch_require_regular_verified_artifacts(self) -> None:
        source = self.helper.read_text(encoding="utf-8")
        self.assertIn('[ -f "$1" ] && [ ! -L "$1" ]', source)
        self.assertIn('require_regular_file "$STAGED_BINARY"', source)
        self.assertIn('sha256sum "$STAGED_BINARY"', source)
        self.assertIn('"$actual_digest" = "$digest"', source)
        self.assertIn('require_regular_file "$EDGE_PROXY"', source)
        self.assertIn('stage manifest is missing or unsafe', source)

    def test_helper_admits_only_verified_regular_local_artifacts(self) -> None:
        source = self.helper.read_text(encoding="utf-8")
        self.assertIn("admit-artifact)", source)
        self.assertIn('"--input"', source)
        self.assertIn('case "$2" in /*)', source)
        self.assertIn('require_root_owned_file "$2"', source)
        self.assertIn("artifact source must be root-owned", source)
        self.assertIn('sha256sum "$2"', source)
        self.assertIn('"$actual_digest" = "$digest"', source)
        self.assertIn('"$STAGED_BINARY.tmp"', source)
        self.assertIn('mv "$STAGED_BINARY.tmp" "$STAGED_BINARY"', source)
        self.assertIn('staged binary target is unsafe', source)

    def test_root_owned_executable_artifacts_may_be_readable_but_not_writable_by_others(self) -> None:
        source = self.helper.read_text(encoding="utf-8")
        self.assertIn('permission_bits=${mode#?}', source)
        self.assertIn('group_and_other=${permission_bits#?}', source)
        self.assertIn('*[2367]*) fail "artifact source must not be group or world writable"', source)

    def test_helper_is_posix_shell_syntax_valid(self) -> None:
        subprocess.run(["sh", "-n", str(self.helper)], check=True, cwd=ROOT)


if __name__ == "__main__":
    unittest.main()
