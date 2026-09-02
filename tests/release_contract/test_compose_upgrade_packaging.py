import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ComposeUpgradePackagingContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = ROOT / "packaging" / "compose"
        cls.helper = cls.directory / "compose-upgrade-helper"
        cls.install = cls.directory / "install.sh"
        cls.prepare = cls.directory / "prepare-upgrade.sh"
        cls.workflow = (ROOT / ".github" / "workflows" / "build-binaries.yml").read_text(
            encoding="utf-8"
        )

    def test_linux_archives_include_fixed_compose_upgrade_assets(self) -> None:
        self.assertTrue(self.helper.is_file())
        self.assertTrue(self.install.is_file())
        self.assertTrue(self.prepare.is_file())
        self.assertTrue(os.access(self.helper, os.X_OK))
        self.assertTrue(os.access(self.install, os.X_OK))
        self.assertTrue(os.access(self.prepare, os.X_OK))
        self.assertIn("packaging/compose/compose-upgrade-helper", self.workflow)
        self.assertIn("packaging/compose/install.sh", self.workflow)
        self.assertIn("packaging/compose/prepare-upgrade.sh", self.workflow)
        self.assertIn("docker-compose.yml dist/compose/docker-compose.yml", self.workflow)

    def test_official_compose_reads_only_the_fixed_runtime_image_manifest(self) -> None:
        helper = self.helper.read_text(encoding="utf-8")
        installer = self.install.read_text(encoding="utf-8")
        self.assertIn("/etc/sponzey-edge/compose/runtime.env", helper)
        self.assertIn('--env-file "$RUNTIME_ENV_FILE"', helper)
        self.assertIn("runtime.env", installer)

    def test_first_install_uses_an_immutable_reference_but_offline_stage_uses_the_admitted_tag(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        helper = self.helper.read_text(encoding="utf-8")
        installer = self.install.read_text(encoding="utf-8")
        self.assertIn(
            "${SPONZEY_EDGE_IMAGE_REFERENCE:-ghcr.io/sponzey-lab/sponzey-edge:${SPONZEY_EDGE_TAG:?set a SemVer tag}@sha256:${SPONZEY_EDGE_DIGEST:?set the matching immutable image digest}}",
            compose,
        )
        self.assertIn('SPONZEY_EDGE_IMAGE_REFERENCE=ghcr.io/sponzey-lab/sponzey-edge:%s@sha256:%s', installer)
        self.assertIn('SPONZEY_EDGE_IMAGE_REFERENCE=ghcr.io/sponzey-lab/sponzey-edge:%s', helper)

    def test_prepared_control_plane_accepts_a_pre_reference_immutable_runtime_manifest(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("SPONZEY_EDGE_IMAGE_REFERENCE:-", compose)
        self.assertIn("SPONZEY_EDGE_TAG:?set a SemVer tag", compose)
        self.assertIn("SPONZEY_EDGE_DIGEST:?set the matching immutable image digest", compose)

    def test_official_compose_documentation_uses_the_fixed_runtime_image_manifest(self) -> None:
        for document in ("README.md", "docs/deployment.md", "docs/install.md"):
            source = (ROOT / document).read_text(encoding="utf-8")
            self.assertIn(
                "--env-file /etc/sponzey-edge/compose/runtime.env",
                source,
                document,
            )

    def test_first_compose_install_preserves_an_existing_canonical_primary_config(self) -> None:
        installer = self.install.read_text(encoding="utf-8")
        self.assertIn("config_target=/etc/sponzey-edge/current.toml", installer)
        self.assertIn('release_root=$(dirname "$package_dir")', installer)
        self.assertIn('[ -e "$config_target" ] || install -o root -g root -m 0644', installer)
        self.assertIn('"$release_root/current.toml" "$config_target"', installer)

    def test_upgrade_override_runs_only_the_backup_operation_as_root_for_owner_only_secret_access(self) -> None:
        upgrade_override = (self.directory / "docker-compose.upgrade.yml").read_text(encoding="utf-8")
        self.assertIn('user: "0:0"', upgrade_override)
        self.assertIn("cap_add:\n      - DAC_OVERRIDE", upgrade_override)
        self.assertIn("      - FOWNER", upgrade_override)
        self.assertIn("/run/secrets/sponzey-edge-upgrade-passphrase", upgrade_override)

    def test_helper_requires_the_fixed_project_and_compose_file_without_docker_socket(self) -> None:
        source = self.helper.read_text(encoding="utf-8")
        self.assertIn("/etc/sponzey-edge/compose", source)
        self.assertIn("/etc/sponzey-edge/compose/docker-compose.yml", source)
        self.assertIn('case "$command" in', source)
        self.assertNotIn("docker.sock", source)
        self.assertNotIn('"--passphrase"', source)
        self.assertNotIn("eval ", source)

    def test_non_receipt_helper_commands_keep_compose_chatter_off_stdout(self) -> None:
        source = self.helper.read_text(encoding="utf-8")
        self.assertIn('run_compose stop --timeout 30 edge >/dev/null', source)
        self.assertIn('run_compose up --no-build --pull never --detach edge >/dev/null', source)
        self.assertIn('edge-proxy probe ready --admin-bind 127.0.0.1:9443 >/dev/null', source)

    def test_shell_assets_are_syntax_valid(self) -> None:
        for path in [self.helper, self.install, self.prepare]:
            subprocess.run(["sh", "-n", str(path)], check=True, cwd=ROOT)

    def test_prepare_upgrade_replaces_only_fixed_control_plane_assets(self) -> None:
        source = self.prepare.read_text(encoding="utf-8")
        self.assertIn("Compose upgrade preparation must run as root", source)
        self.assertIn("/etc/sponzey-edge/compose/docker-compose.yml", source)
        self.assertIn("/etc/sponzey-edge/compose/docker-compose.upgrade.yml", source)
        self.assertIn("/usr/local/libexec/sponzey-edge/compose-upgrade-helper", source)
        self.assertNotIn("runtime.env", source)
        self.assertNotIn("current.toml", source)

    def test_preflight_uses_only_the_fixed_docker_compose_config_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            capture = temporary / "docker-arguments"
            fake_docker = temporary / "docker"
            fake_docker.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CAPTURE\"\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)
            helper = temporary / "compose-upgrade-helper"
            helper.write_text(
                self.helper.read_text(encoding="utf-8").replace(
                    "DOCKER=/usr/bin/docker", f"DOCKER={fake_docker}"
                ).replace("RUNTIME_ENV_FILE=/etc/sponzey-edge/compose/runtime.env", f"RUNTIME_ENV_FILE='{self.helper}'").replace("STAGED_ENV_FILE=/etc/sponzey-edge/compose/runtime.env.stage", f"STAGED_ENV_FILE='{temporary / 'runtime.env.stage'}'"),
                encoding="utf-8",
            )
            helper.chmod(0o755)

            subprocess.run(
                [
                    str(helper),
                    "--project-directory",
                    "/etc/sponzey-edge/compose",
                    "--file",
                    "/etc/sponzey-edge/compose/docker-compose.yml",
                    "preflight",
                    "--version",
                    "v1.2.3",
                    "--image-digest",
                    "sha256:" + "a" * 64,
                ],
                check=True,
                cwd=ROOT,
                env={"CAPTURE": str(capture)},
            )

            self.assertEqual(
                capture.read_text(encoding="utf-8").splitlines(),
                [
                    "compose",
                    "--project-directory",
                    "/etc/sponzey-edge/compose",
                    "--file",
                    "/etc/sponzey-edge/compose/docker-compose.yml",
                    "--env-file",
                    str(self.helper),
                    "config",
                    "--quiet",
                ],
            )
            self.assertEqual(
                (temporary / "runtime.env.stage").read_text(encoding="utf-8"),
                "SPONZEY_EDGE_TAG=v1.2.3\n"
                + "SPONZEY_EDGE_DIGEST=" + "a" * 64 + "\n"
                + "SPONZEY_EDGE_IMAGE_REFERENCE=ghcr.io/sponzey-lab/sponzey-edge:v1.2.3\n",
            )

    def test_preflight_rejects_extra_arguments_before_invoking_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            fake_docker = temporary / "docker"
            fake_docker.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            fake_docker.chmod(0o755)
            helper = temporary / "compose-upgrade-helper"
            helper.write_text(
                self.helper.read_text(encoding="utf-8").replace(
                    "DOCKER=/usr/bin/docker", f"DOCKER={fake_docker}"
                ).replace("RUNTIME_ENV_FILE=/etc/sponzey-edge/compose/runtime.env", f"RUNTIME_ENV_FILE='{self.helper}'"),
                encoding="utf-8",
            )
            helper.chmod(0o755)

            result = subprocess.run(
                [
                    str(helper),
                    "--project-directory",
                    "/etc/sponzey-edge/compose",
                    "--file",
                    "/etc/sponzey-edge/compose/docker-compose.yml",
                    "preflight",
                    "--version",
                    "v1.2.3",
                    "--image-digest",
                    "sha256:" + "a" * 64,
                    "--unexpected",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("invalid preflight arguments", result.stderr)

    def test_lifecycle_uses_fixed_no_pull_stop_start_and_ready_probe_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            capture = temporary / "docker-arguments"
            fake_docker = temporary / "docker"
            fake_docker.write_text(
                "#!/bin/sh\nprintf '%s ' \"$@\" >> \"$CAPTURE\"\nprintf '\\n' >> \"$CAPTURE\"\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)
            helper = temporary / "compose-upgrade-helper"
            helper.write_text(
                self.helper.read_text(encoding="utf-8").replace(
                    "DOCKER=/usr/bin/docker", f"DOCKER={fake_docker}"
                ).replace("RUNTIME_ENV_FILE=/etc/sponzey-edge/compose/runtime.env", f"RUNTIME_ENV_FILE='{self.helper}'"),
                encoding="utf-8",
            )
            helper.chmod(0o755)
            prefix = [
                "--project-directory",
                "/etc/sponzey-edge/compose",
                "--file",
                "/etc/sponzey-edge/compose/docker-compose.yml",
            ]
            environment = {"CAPTURE": str(capture)}

            subprocess.run([str(helper), *prefix, "drain-stop"], check=True, cwd=ROOT, env=environment)
            subprocess.run([str(helper), *prefix, "start-ready"], check=True, cwd=ROOT, env=environment)

            self.assertEqual(
                capture.read_text(encoding="utf-8").splitlines(),
                [
                    f"compose --project-directory /etc/sponzey-edge/compose --file /etc/sponzey-edge/compose/docker-compose.yml --env-file {self.helper} stop --timeout 30 edge ",
                    f"compose --project-directory /etc/sponzey-edge/compose --file /etc/sponzey-edge/compose/docker-compose.yml --env-file {self.helper} up --no-build --pull never --detach edge ",
                    f"compose --project-directory /etc/sponzey-edge/compose --file /etc/sponzey-edge/compose/docker-compose.yml --env-file {self.helper} exec -T edge edge-proxy probe ready --admin-bind 127.0.0.1:9443 ",
                ],
            )

    def test_lifecycle_propagates_docker_failure_without_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            fake_docker = temporary / "docker"
            fake_docker.write_text("#!/bin/sh\nexit 37\n", encoding="utf-8")
            fake_docker.chmod(0o755)
            helper = temporary / "compose-upgrade-helper"
            helper.write_text(
                self.helper.read_text(encoding="utf-8").replace(
                    "DOCKER=/usr/bin/docker", f"DOCKER={fake_docker}"
                ).replace("RUNTIME_ENV_FILE=/etc/sponzey-edge/compose/runtime.env", f"RUNTIME_ENV_FILE='{self.helper}'"),
                encoding="utf-8",
            )
            helper.chmod(0o755)

            result = subprocess.run(
                [
                    str(helper),
                    "--project-directory",
                    "/etc/sponzey-edge/compose",
                    "--file",
                    "/etc/sponzey-edge/compose/docker-compose.yml",
                    "drain-stop",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 37)

    def test_admission_loads_only_a_root_owned_tagged_artifact_and_checks_its_release_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            artifact = temporary / "edge-image.tar"
            artifact.write_bytes(b"test image archive")
            artifact.chmod(0o644)
            digest = "a" * 64
            capture = temporary / "docker-arguments"
            fake_docker = temporary / "docker"
            fake_docker.write_text(
                "#!/bin/sh\nprintf '%s ' \"$@\" >> \"$CAPTURE\"\nprintf '\\n' >> \"$CAPTURE\"\n"
                "if [ \"$1\" = image ] && [ \"$2\" = load ]; then printf '%s\\n' 'loaded image chatter'; fi\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  case \"$4\" in\n"
                "    *version*) printf '%s\\n' v1.2.3 ;;\n"
                "    *revision*) printf '%s\\n' 0123456789abcdef0123456789abcdef01234567 ;;\n"
                "  esac\n"
                "fi\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)
            helper = temporary / "compose-upgrade-helper"
            helper.write_text(
                self.helper.read_text(encoding="utf-8")
                .replace("DOCKER=/usr/bin/docker", f"DOCKER={fake_docker}")
                .replace("ROOT_UID=0", f"ROOT_UID={os.getuid()}"),
                encoding="utf-8",
            )
            helper.chmod(0o755)

            result = subprocess.run(
                [
                    str(helper),
                    "--project-directory",
                    "/etc/sponzey-edge/compose",
                    "--file",
                    "/etc/sponzey-edge/compose/docker-compose.yml",
                    "admit-artifact",
                    "--input",
                    str(artifact),
                    "--version",
                    "v1.2.3",
                    "--image-digest",
                    digest,
                ],
                capture_output=True,
                text=True,
                cwd=ROOT,
                env={"CAPTURE": str(capture)},
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")

            self.assertEqual(
                capture.read_text(encoding="utf-8").splitlines(),
                [
                    f"image load --input {artifact} ",
                    "image inspect --format {{ index .Config.Labels \"org.opencontainers.image.version\" }} ghcr.io/sponzey-lab/sponzey-edge:v1.2.3 ",
                    "image inspect --format {{ index .Config.Labels \"org.opencontainers.image.revision\" }} ghcr.io/sponzey-lab/sponzey-edge:v1.2.3 ",
                ],
            )

    def test_admission_rejects_symlink_before_docker_and_release_label_mismatch_after_load(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            artifact = temporary / "edge-image.tar"
            artifact.write_bytes(b"test image archive")
            artifact.chmod(0o644)
            symlink = temporary / "unsafe-image.tar"
            symlink.symlink_to(artifact)
            digest = "a" * 64
            fake_docker = temporary / "docker"
            fake_docker.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = image ] && [ \"$2\" = load ]; then exit 0; fi\n"
                "printf '%s\\n' 'v9.9.9'\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)
            helper = temporary / "compose-upgrade-helper"
            helper.write_text(
                self.helper.read_text(encoding="utf-8")
                .replace("DOCKER=/usr/bin/docker", f"DOCKER={fake_docker}")
                .replace("ROOT_UID=0", f"ROOT_UID={os.getuid()}"),
                encoding="utf-8",
            )
            helper.chmod(0o755)
            prefix = [
                str(helper),
                "--project-directory",
                "/etc/sponzey-edge/compose",
                "--file",
                "/etc/sponzey-edge/compose/docker-compose.yml",
                "admit-artifact",
                "--input",
            ]

            unsafe = subprocess.run(
                [*prefix, str(symlink), "--version", "v1.2.3", "--image-digest", digest],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(unsafe.returncode, 2)
            self.assertIn("artifact input is missing or unsafe", unsafe.stderr)

            mismatch = subprocess.run(
                [*prefix, str(artifact), "--version", "v1.2.3", "--image-digest", digest],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(mismatch.returncode, 2)
            self.assertIn("loaded artifact version mismatch", mismatch.stderr)

    def test_admission_propagates_docker_load_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            artifact = temporary / "edge-image.tar"
            artifact.write_bytes(b"test image archive")
            artifact.chmod(0o644)
            fake_docker = temporary / "docker"
            fake_docker.write_text("#!/bin/sh\nexit 41\n", encoding="utf-8")
            fake_docker.chmod(0o755)
            helper = temporary / "compose-upgrade-helper"
            helper.write_text(
                self.helper.read_text(encoding="utf-8")
                .replace("DOCKER=/usr/bin/docker", f"DOCKER={fake_docker}")
                .replace("ROOT_UID=0", f"ROOT_UID={os.getuid()}"),
                encoding="utf-8",
            )
            helper.chmod(0o755)

            result = subprocess.run(
                [
                    str(helper),
                    "--project-directory",
                    "/etc/sponzey-edge/compose",
                    "--file",
                    "/etc/sponzey-edge/compose/docker-compose.yml",
                    "admit-artifact",
                    "--input",
                    str(artifact),
                    "--version",
                    "v1.2.3",
                    "--image-digest",
                    "a" * 64,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 41)

    def test_switch_and_rollback_replace_only_fixed_runtime_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            active = temporary / "runtime.env"
            staged = temporary / "runtime.env.stage"
            previous = temporary / "runtime.env.previous"
            active.write_text("SPONZEY_EDGE_TAG=v1.0.0\nSPONZEY_EDGE_DIGEST=" + "a" * 64 + "\nSPONZEY_EDGE_IMAGE_REFERENCE=ghcr.io/sponzey-lab/sponzey-edge:v1.0.0@sha256:" + "a" * 64 + "\n", encoding="utf-8")
            staged.write_text("SPONZEY_EDGE_TAG=v1.1.0\nSPONZEY_EDGE_DIGEST=" + "b" * 64 + "\nSPONZEY_EDGE_IMAGE_REFERENCE=ghcr.io/sponzey-lab/sponzey-edge:v1.1.0\n", encoding="utf-8")
            helper = temporary / "compose-upgrade-helper"
            helper.write_text(
                self.helper.read_text(encoding="utf-8")
                .replace("ROOT_UID=0", f"ROOT_UID={os.getuid()}")
                .replace("RUNTIME_ENV_FILE=/etc/sponzey-edge/compose/runtime.env", f"RUNTIME_ENV_FILE='{active}'")
                .replace("STAGED_ENV_FILE=/etc/sponzey-edge/compose/runtime.env.stage", f"STAGED_ENV_FILE='{staged}'")
                .replace("PREVIOUS_ENV_FILE=/etc/sponzey-edge/compose/runtime.env.previous", f"PREVIOUS_ENV_FILE='{previous}'"),
                encoding="utf-8",
            )
            helper.chmod(0o755)
            prefix = [str(helper), "--project-directory", "/etc/sponzey-edge/compose", "--file", "/etc/sponzey-edge/compose/docker-compose.yml"]

            subprocess.run([*prefix, "switch-staged"], check=True, cwd=ROOT)
            self.assertIn("v1.1.0", active.read_text(encoding="utf-8"))
            self.assertIn("v1.0.0", previous.read_text(encoding="utf-8"))
            subprocess.run([*prefix, "rollback", "--backup-id", "backup", "--previous-artifact-digest", "a" * 64], check=True, cwd=ROOT)
            self.assertIn("v1.0.0", active.read_text(encoding="utf-8"))

    def test_rollback_rejects_a_previous_manifest_with_the_wrong_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            active = temporary / "runtime.env"
            previous = temporary / "runtime.env.previous"
            active.write_text("SPONZEY_EDGE_TAG=v1.1.0\nSPONZEY_EDGE_DIGEST=" + "b" * 64 + "\n", encoding="utf-8")
            previous.write_text("SPONZEY_EDGE_TAG=v1.0.0\nSPONZEY_EDGE_DIGEST=" + "c" * 64 + "\n", encoding="utf-8")
            helper = temporary / "compose-upgrade-helper"
            helper.write_text(
                self.helper.read_text(encoding="utf-8")
                .replace("RUNTIME_ENV_FILE=/etc/sponzey-edge/compose/runtime.env", f"RUNTIME_ENV_FILE='{active}'")
                .replace("PREVIOUS_ENV_FILE=/etc/sponzey-edge/compose/runtime.env.previous", f"PREVIOUS_ENV_FILE='{previous}'"),
                encoding="utf-8",
            )
            helper.chmod(0o755)

            result = subprocess.run(
                [str(helper), "--project-directory", "/etc/sponzey-edge/compose", "--file", "/etc/sponzey-edge/compose/docker-compose.yml", "rollback", "--backup-id", "backup", "--previous-artifact-digest", "a" * 64],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("previous runtime manifest digest mismatch", result.stderr)
            self.assertTrue(previous.exists())
            self.assertIn("v1.1.0", active.read_text(encoding="utf-8"))

    def test_backup_receipt_is_strict_and_excludes_compose_command_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            active = temporary / "runtime.env"
            secret = temporary / "passphrase"
            archive = temporary / "upgrade.sponzey"
            volume_mount = temporary / "compose-edge-data"
            active.write_text("SPONZEY_EDGE_TAG=v1.0.0\nSPONZEY_EDGE_DIGEST=" + "a" * 64 + "\n", encoding="utf-8")
            secret.write_text("not-a-secret-in-test\n", encoding="utf-8")
            fake_docker = temporary / "docker"
            fake_docker.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = volume ] && [ \"$2\" = inspect ]; then printf '%s\\n' \"$VOLUME_MOUNT\"; exit 0; fi\n"
                "printf 'untrusted compose chatter\\n'\n"
                "mkdir -p \"$VOLUME_MOUNT/data/backups\"\nprintf 'fixture archive' > \"$VOLUME_MOUNT/data/backups/upgrade.sponzey\"\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)
            fake_sha256sum = temporary / "sha256sum"
            fake_sha256sum.write_text(
                "#!/bin/sh\nprintf '%s  %s\\n' 'f8b1f712f078009f786ea23ebe0a2b14498c80f454453ed6e8384ad54041acfc' \"$1\"\n",
                encoding="utf-8",
            )
            fake_sha256sum.chmod(0o755)
            helper = temporary / "compose-upgrade-helper"
            helper.write_text(
                self.helper.read_text(encoding="utf-8")
                .replace("DOCKER=/usr/bin/docker", f"DOCKER={fake_docker}")
                .replace("SHA256SUM=/usr/bin/sha256sum", f"SHA256SUM={fake_sha256sum}")
                .replace("ROOT_UID=0", f"ROOT_UID={os.getuid()}")
                .replace("RUNTIME_ENV_FILE=/etc/sponzey-edge/compose/runtime.env", f"RUNTIME_ENV_FILE='{active}'")
                .replace("UPGRADE_PASSPHRASE_FILE=/run/secrets/sponzey-edge-upgrade-passphrase", f"UPGRADE_PASSPHRASE_FILE='{secret}'")
                .replace("BACKUP_ARCHIVE=/var/lib/sponzey-edge/data/backups/upgrade.sponzey", f"BACKUP_ARCHIVE='{archive}'"),
                encoding="utf-8",
            )
            helper.chmod(0o755)

            result = subprocess.run(
                [str(helper), "--project-directory", "/etc/sponzey-edge/compose", "--file", "/etc/sponzey-edge/compose/docker-compose.yml", "backup-create-verify", "--passphrase-file", str(secret)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                env={"VOLUME_MOUNT": str(volume_mount)},
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout.splitlines(),
                [
                    "backup_id=f8b1f712f078009f786ea23ebe0a2b14498c80f454453ed6e8384ad54041acfc",
                    "previous_artifact_digest=sha256:" + "a" * 64,
                ],
            )


if __name__ == "__main__":
    unittest.main()
