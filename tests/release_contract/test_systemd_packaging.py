import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class SystemdPackagingContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.unit = (ROOT / "packaging" / "systemd" / "sponzey-edge.service").read_text(encoding="utf-8")
        cls.install = (ROOT / "packaging" / "systemd" / "install.sh").read_text(encoding="utf-8")
        cls.uninstall = (ROOT / "packaging" / "systemd" / "uninstall.sh").read_text(encoding="utf-8")
        cls.preflight = (ROOT / "packaging" / "systemd" / "preflight.sh").read_text(encoding="utf-8")

    def test_unit_runs_as_dedicated_user_with_hardened_filesystem(self) -> None:
        for required in [
            "User=edge",
            "Group=edge",
            "StateDirectory=sponzey-edge",
            "ProtectSystem=strict",
            "ReadWritePaths=/var/lib/sponzey-edge",
            "NoNewPrivileges=true",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
            "AmbientCapabilities=CAP_NET_BIND_SERVICE",
            "TimeoutStopSec=35s",
            "SPONZEY_ADMIN_BIND=127.0.0.1:9443",
        ]:
            self.assertIn(required, self.unit)
        self.assertNotIn("User=root", self.unit)

    def test_install_and_uninstall_are_explicit_and_non_destructive_to_data(self) -> None:
        self.assertIn('archive_dir=$(dirname -- "$package_dir")', self.install)
        self.assertIn('binary=${1:-"$archive_dir/edge-proxy"}', self.install)
        self.assertIn('config=${2:-"$archive_dir/current.toml"}', self.install)
        self.assertIn("systemctl daemon-reload", self.install)
        self.assertIn("systemctl enable --now sponzey-edge.service", self.install)
        self.assertIn("getent passwd edge", self.install)
        self.assertIn("systemctl disable --now sponzey-edge.service", self.uninstall)
        self.assertNotIn("rm -rf /var/lib/sponzey-edge", self.uninstall)

    def test_preflight_is_read_only_and_rejects_unsupported_hosts(self) -> None:
        self.assertIn("uname -m", self.preflight)
        self.assertIn("x86_64|aarch64", self.preflight)
        self.assertIn("systemctl", self.preflight)
        self.assertIn('ps -p 1 -o comm=', self.preflight)
        self.assertIn("systemd must be PID 1", self.preflight)
        self.assertIn("127.0.0.1:9443", self.preflight)
        self.assertNotIn("systemctl enable", self.preflight)
        self.assertNotIn("install -", self.preflight)


if __name__ == "__main__":
    unittest.main()
