use edge_domain::{AppError, ErrorCode, OfflineUpgradeRequest};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupCreateOptions {
    pub data_dir: PathBuf,
    pub output: PathBuf,
    pub passphrase_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupVerifyOptions {
    pub input: PathBuf,
    pub passphrase_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOptions {
    pub input: PathBuf,
    pub target_data_dir: PathBuf,
    pub passphrase_file: PathBuf,
    pub replace: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreRecoverOptions {
    pub target_data_dir: PathBuf,
    pub operation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerifyOptions {
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOptions {
    pub target: ProbeTarget,
    pub admin_bind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeOptions {
    pub data_dir: PathBuf,
    pub deployment: UpgradeDeployment,
    pub request: OfflineUpgradeRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeRecoverOptions {
    pub data_dir: PathBuf,
    pub deployment: UpgradeDeployment,
    pub operation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeDeployment {
    Systemd,
    Compose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeTarget {
    Live,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessMode {
    Serve,
    BackupCreate(BackupCreateOptions),
    BackupVerify(BackupVerifyOptions),
    Restore(RestoreOptions),
    RestoreRecover(RestoreRecoverOptions),
    AuditVerify(AuditVerifyOptions),
    Probe(ProbeOptions),
    Upgrade(UpgradeOptions),
    UpgradeRecover(UpgradeRecoverOptions),
}

pub fn parse_process_mode(args: &[String]) -> Result<ProcessMode, AppError> {
    match args {
        [] => Ok(ProcessMode::Serve),
        [command] if command == "serve" => Ok(ProcessMode::Serve),
        [backup, operation, options @ ..] if backup == "backup" => {
            parse_backup_mode(operation, options)
        }
        [audit, operation, options @ ..] if audit == "audit" && operation == "verify" => {
            let parsed = parse_options(options, &["--data-dir"], &[])?;
            Ok(ProcessMode::AuditVerify(AuditVerifyOptions {
                data_dir: required_path(&parsed.values, "--data-dir")?,
            }))
        }
        [probe, target, options @ ..] if probe == "probe" => parse_probe_mode(target, options),
        [upgrade, recover, options @ ..] if upgrade == "upgrade" && recover == "recover" => {
            parse_upgrade_recover_mode(options)
        }
        [upgrade, options @ ..] if upgrade == "upgrade" => parse_upgrade_mode(options),
        _ => Err(invalid_command()),
    }
}

fn parse_upgrade_recover_mode(tokens: &[String]) -> Result<ProcessMode, AppError> {
    let parsed = parse_options(
        tokens,
        &["--data-dir", "--deployment", "--operation-id"],
        &[],
    )?;
    Ok(ProcessMode::UpgradeRecover(UpgradeRecoverOptions {
        data_dir: required_path(&parsed.values, "--data-dir")?,
        deployment: parse_upgrade_deployment(required_value(&parsed.values, "--deployment")?)?,
        operation_id: required_value(&parsed.values, "--operation-id")?.to_string(),
    }))
}

fn parse_upgrade_mode(tokens: &[String]) -> Result<ProcessMode, AppError> {
    let parsed = parse_options(
        tokens,
        &[
            "--data-dir",
            "--deployment",
            "--version",
            "--image-digest",
            "--artifact-file",
            "--passphrase-file",
        ],
        &[],
    )?;
    Ok(ProcessMode::Upgrade(UpgradeOptions {
        data_dir: required_path(&parsed.values, "--data-dir")?,
        deployment: parse_upgrade_deployment(required_value(&parsed.values, "--deployment")?)?,
        request: OfflineUpgradeRequest {
            target_version: required_value(&parsed.values, "--version")?.to_string(),
            image_digest: required_value(&parsed.values, "--image-digest")?.to_string(),
            artifact_file: required_value(&parsed.values, "--artifact-file")?.to_string(),
            passphrase_file: required_value(&parsed.values, "--passphrase-file")?.to_string(),
        },
    }))
}

fn parse_upgrade_deployment(value: &str) -> Result<UpgradeDeployment, AppError> {
    match value {
        "systemd" => Ok(UpgradeDeployment::Systemd),
        "compose" => Ok(UpgradeDeployment::Compose),
        _ => Err(invalid_command()),
    }
}

fn parse_probe_mode(target: &str, tokens: &[String]) -> Result<ProcessMode, AppError> {
    let target = match target {
        "live" => ProbeTarget::Live,
        "ready" => ProbeTarget::Ready,
        _ => return Err(invalid_command()),
    };
    let parsed = parse_options(tokens, &["--admin-bind"], &[])?;
    Ok(ProcessMode::Probe(ProbeOptions {
        target,
        admin_bind: required_value(&parsed.values, "--admin-bind")?.to_string(),
    }))
}

fn parse_backup_mode(operation: &str, tokens: &[String]) -> Result<ProcessMode, AppError> {
    match operation {
        "create" => {
            let parsed = parse_options(
                tokens,
                &["--data-dir", "--output", "--passphrase-file"],
                &[],
            )?;
            Ok(ProcessMode::BackupCreate(BackupCreateOptions {
                data_dir: required_path(&parsed.values, "--data-dir")?,
                output: required_path(&parsed.values, "--output")?,
                passphrase_file: required_path(&parsed.values, "--passphrase-file")?,
            }))
        }
        "verify" => {
            let parsed = parse_options(tokens, &["--input", "--passphrase-file"], &[])?;
            Ok(ProcessMode::BackupVerify(BackupVerifyOptions {
                input: required_path(&parsed.values, "--input")?,
                passphrase_file: required_path(&parsed.values, "--passphrase-file")?,
            }))
        }
        "restore" => {
            let parsed = parse_options(
                tokens,
                &["--input", "--target-data-dir", "--passphrase-file"],
                &["--replace"],
            )?;
            Ok(ProcessMode::Restore(RestoreOptions {
                input: required_path(&parsed.values, "--input")?,
                target_data_dir: required_path(&parsed.values, "--target-data-dir")?,
                passphrase_file: required_path(&parsed.values, "--passphrase-file")?,
                replace: parsed.flags.contains("--replace"),
            }))
        }
        "restore-recover" => {
            let parsed = parse_options(tokens, &["--target-data-dir", "--operation-id"], &[])?;
            Ok(ProcessMode::RestoreRecover(RestoreRecoverOptions {
                target_data_dir: required_path(&parsed.values, "--target-data-dir")?,
                operation_id: required_value(&parsed.values, "--operation-id")?.to_string(),
            }))
        }
        _ => Err(invalid_command()),
    }
}

struct ParsedOptions {
    values: BTreeMap<String, String>,
    flags: BTreeSet<String>,
}

fn parse_options(
    tokens: &[String],
    value_names: &[&str],
    flag_names: &[&str],
) -> Result<ParsedOptions, AppError> {
    let mut values = BTreeMap::new();
    let mut flags = BTreeSet::new();
    let mut index = 0;
    while index < tokens.len() {
        let name = tokens[index].as_str();
        if flag_names.contains(&name) {
            if !flags.insert(name.to_string()) {
                return Err(invalid_command());
            }
            index += 1;
            continue;
        }
        if !value_names.contains(&name) || index + 1 >= tokens.len() {
            return Err(invalid_command());
        }
        let value = &tokens[index + 1];
        if value.is_empty() || value.starts_with("--") {
            return Err(invalid_command());
        }
        if values.insert(name.to_string(), value.clone()).is_some() {
            return Err(invalid_command());
        }
        index += 2;
    }
    Ok(ParsedOptions { values, flags })
}

fn required_path(values: &BTreeMap<String, String>, name: &str) -> Result<PathBuf, AppError> {
    Ok(PathBuf::from(required_value(values, name)?))
}

fn required_value<'a>(
    values: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, AppError> {
    values
        .get(name)
        .map(String::as_str)
        .ok_or_else(invalid_command)
}

fn invalid_command() -> AppError {
    AppError::new(
        ErrorCode::ProcessCommandInvalid,
        "process command does not match the supported contract",
    )
}

#[cfg(test)]
mod tests {
    use super::{
        parse_process_mode, AuditVerifyOptions, BackupCreateOptions, BackupVerifyOptions,
        ProbeOptions, ProbeTarget, ProcessMode, RestoreOptions, RestoreRecoverOptions,
        UpgradeDeployment, UpgradeOptions, UpgradeRecoverOptions,
    };
    use edge_domain::{ErrorCode, OfflineUpgradeRequest};
    use std::path::PathBuf;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn no_args_and_explicit_serve_select_serve_mode() {
        assert_eq!(parse_process_mode(&[]).unwrap(), ProcessMode::Serve);
        assert_eq!(
            parse_process_mode(&args(&["serve"])).unwrap(),
            ProcessMode::Serve
        );
    }

    #[test]
    fn backup_create_and_restore_options_are_typed() {
        assert_eq!(
            parse_process_mode(&args(&[
                "backup",
                "create",
                "--data-dir",
                "/data",
                "--output",
                "/backup/edge.age",
                "--passphrase-file",
                "/run/secret"
            ]))
            .unwrap(),
            ProcessMode::BackupCreate(BackupCreateOptions {
                data_dir: PathBuf::from("/data"),
                output: PathBuf::from("/backup/edge.age"),
                passphrase_file: PathBuf::from("/run/secret"),
            })
        );
        assert_eq!(
            parse_process_mode(&args(&[
                "backup",
                "restore",
                "--input",
                "/backup/edge.age",
                "--target-data-dir",
                "/restored",
                "--passphrase-file",
                "/run/secret",
                "--replace"
            ]))
            .unwrap(),
            ProcessMode::Restore(RestoreOptions {
                input: PathBuf::from("/backup/edge.age"),
                target_data_dir: PathBuf::from("/restored"),
                passphrase_file: PathBuf::from("/run/secret"),
                replace: true,
            })
        );
    }

    #[test]
    fn unknown_command_and_missing_option_fail_without_serve_fallback() {
        let unknown = parse_process_mode(&args(&["unknown"])).unwrap_err();
        assert_eq!(unknown.code, ErrorCode::ProcessCommandInvalid);

        let incomplete =
            parse_process_mode(&args(&["backup", "create", "--data-dir", "/data"])).unwrap_err();
        assert_eq!(incomplete.code, ErrorCode::ProcessCommandInvalid);
    }

    #[test]
    fn audit_verify_requires_an_explicit_data_directory() {
        assert_eq!(
            parse_process_mode(&args(&["audit", "verify", "--data-dir", "/data"])).unwrap(),
            ProcessMode::AuditVerify(AuditVerifyOptions {
                data_dir: PathBuf::from("/data"),
            })
        );
        assert_eq!(
            parse_process_mode(&args(&["audit", "verify"]))
                .unwrap_err()
                .code,
            ErrorCode::ProcessCommandInvalid
        );
    }

    #[test]
    fn probe_requires_an_explicit_loopback_admin_bind_and_target() {
        assert_eq!(
            parse_process_mode(&args(&["probe", "ready", "--admin-bind", "127.0.0.1:9443"]))
                .unwrap(),
            ProcessMode::Probe(ProbeOptions {
                target: ProbeTarget::Ready,
                admin_bind: "127.0.0.1:9443".to_string(),
            })
        );
        assert_eq!(
            parse_process_mode(&args(&["probe", "ready"]))
                .unwrap_err()
                .code,
            ErrorCode::ProcessCommandInvalid
        );
    }

    #[test]
    fn backup_verify_and_recover_options_are_typed_without_hidden_defaults() {
        assert_eq!(
            parse_process_mode(&args(&[
                "backup",
                "verify",
                "--input",
                "/backup/edge.age",
                "--passphrase-file",
                "/run/secret"
            ]))
            .unwrap(),
            ProcessMode::BackupVerify(BackupVerifyOptions {
                input: PathBuf::from("/backup/edge.age"),
                passphrase_file: PathBuf::from("/run/secret"),
            })
        );
        assert_eq!(
            parse_process_mode(&args(&[
                "backup",
                "restore-recover",
                "--target-data-dir",
                "/restored",
                "--operation-id",
                "restore-001"
            ]))
            .unwrap(),
            ProcessMode::RestoreRecover(RestoreRecoverOptions {
                target_data_dir: PathBuf::from("/restored"),
                operation_id: "restore-001".to_string(),
            })
        );
    }

    #[test]
    fn upgrade_requires_typed_operator_identity_and_secret_file_reference() {
        assert_eq!(
            parse_process_mode(&args(&[
                "upgrade",
                "--data-dir",
                "/var/lib/sponzey-edge/data",
                "--deployment",
                "systemd",
                "--version",
                "v1.2.3",
                "--image-digest",
                &"a".repeat(64),
                "--artifact-file",
                "/root/edge-proxy-1.2.3",
                "--passphrase-file",
                "/run/secrets/upgrade-passphrase"
            ]))
            .unwrap(),
            ProcessMode::Upgrade(UpgradeOptions {
                data_dir: PathBuf::from("/var/lib/sponzey-edge/data"),
                deployment: UpgradeDeployment::Systemd,
                request: OfflineUpgradeRequest {
                    target_version: "v1.2.3".to_string(),
                    image_digest: "a".repeat(64),
                    artifact_file: "/root/edge-proxy-1.2.3".to_string(),
                    passphrase_file: "/run/secrets/upgrade-passphrase".to_string(),
                },
            })
        );
    }

    #[test]
    fn upgrade_accepts_only_explicit_compose_or_systemd_deployments() {
        let mode = parse_process_mode(&args(&[
            "upgrade",
            "--data-dir",
            "/data",
            "--deployment",
            "compose",
            "--version",
            "v1.2.3",
            "--image-digest",
            &"a".repeat(64),
            "--artifact-file",
            "/root/image.tar",
            "--passphrase-file",
            "/run/secrets/upgrade",
        ]))
        .unwrap();
        assert_eq!(
            match mode {
                ProcessMode::Upgrade(value) => value.deployment,
                _ => unreachable!(),
            },
            UpgradeDeployment::Compose
        );
        assert!(parse_process_mode(&args(&["upgrade", "--data-dir", "/data"])).is_err());
    }

    #[test]
    fn upgrade_rejects_partial_duplicate_and_inline_secret_options() {
        for values in [
            vec!["upgrade", "--data-dir", "/data", "--version", "v1.2.3"],
            vec![
                "upgrade",
                "--data-dir",
                "/data",
                "--version",
                "v1.2.3",
                "--version",
                "v1.2.4",
                "--image-digest",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--passphrase-file",
                "/run/secret",
            ],
            vec![
                "upgrade",
                "--data-dir",
                "/data",
                "--version",
                "v1.2.3",
                "--image-digest",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--passphrase",
                "not-allowed",
            ],
        ] {
            assert_eq!(
                parse_process_mode(&args(&values)).unwrap_err().code,
                ErrorCode::ProcessCommandInvalid
            );
        }
    }

    #[test]
    fn upgrade_recover_requires_typed_data_directory_and_operation_id() {
        assert_eq!(
            parse_process_mode(&args(&[
                "upgrade",
                "recover",
                "--data-dir",
                "/var/lib/sponzey-edge/data",
                "--deployment",
                "systemd",
                "--operation-id",
                "upgrade-backup-1",
            ]))
            .unwrap(),
            ProcessMode::UpgradeRecover(UpgradeRecoverOptions {
                data_dir: PathBuf::from("/var/lib/sponzey-edge/data"),
                deployment: UpgradeDeployment::Systemd,
                operation_id: "upgrade-backup-1".to_string(),
            })
        );
        assert_eq!(
            parse_process_mode(&args(&["upgrade", "recover", "--data-dir", "/data"]))
                .unwrap_err()
                .code,
            ErrorCode::ProcessCommandInvalid
        );
    }
}
