import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ComposePackagingContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.official = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        cls.local = (ROOT / "docker-compose.local.yml").read_text(encoding="utf-8")

    def test_official_compose_requires_a_fixed_runtime_image_reference_and_host_loopback_admin(self) -> None:
        self.assertIn(
            "${SPONZEY_EDGE_IMAGE_REFERENCE:-ghcr.io/sponzey-lab/sponzey-edge:${SPONZEY_EDGE_TAG:?set a SemVer tag}@sha256:${SPONZEY_EDGE_DIGEST:?set the matching immutable image digest}}",
            self.official,
        )
        self.assertIn("network_mode: host", self.official)
        self.assertIn("SPONZEY_ADMIN_BIND: 127.0.0.1:9443", self.official)
        self.assertNotIn("build:", self.official)
        self.assertNotIn("privileged:", self.official)
        self.assertNotIn("docker.sock", self.official)

    def test_official_compose_has_read_only_root_and_readiness_probe(self) -> None:
        self.assertIn("read_only: true", self.official)
        self.assertIn('"edge-proxy", "probe", "ready", "--admin-bind", "127.0.0.1:9443"', self.official)
        self.assertIn("edge-data:/var/lib/sponzey-edge", self.official)
        self.assertNotIn("edge-data:/var/lib/sponzey-edge/data", self.official)

    def test_official_compose_mounts_the_canonical_primary_config_read_only(self) -> None:
        self.assertIn(
            "/etc/sponzey-edge/current.toml:/etc/sponzey-edge/current.toml:ro",
            self.official,
        )

    def test_local_build_is_an_explicit_non_official_override(self) -> None:
        self.assertIn("build:", self.local)
        self.assertIn("profiles: [\"local-build\"]", self.local)
        self.assertNotIn("ghcr.io", self.local)


if __name__ == "__main__":
    unittest.main()
