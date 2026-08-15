use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use edge_domain::{
    AppError, DataDirectoryLockState, ErrorCode, SupportBundleArchiveReceipt,
    SupportBundleArtifact, SupportBundleOmission, SupportBundleOmissionReason,
};
use edge_ports::{
    DataDirectoryLockGuard, SupportBundleCollector, SupportBundleReport, SupportBundleRequest,
};
use sha2::{Digest, Sha256};

/// Filesystem collector for the fixed, allowlisted support-artifact layout.
/// It does not accept caller-supplied source paths or archive member names.
#[derive(Debug)]
pub struct FileSupportBundleCollector {
    root: PathBuf,
    output: PathBuf,
    offline_lock: Option<Box<dyn DataDirectoryLockGuard>>,
}

impl FileSupportBundleCollector {
    pub fn new_online(root: impl AsRef<Path>, output: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            output: output.as_ref().to_path_buf(),
            offline_lock: None,
        }
    }

    pub fn new_offline(
        root: impl AsRef<Path>,
        output: impl AsRef<Path>,
        lock: Box<dyn DataDirectoryLockGuard>,
    ) -> Result<Self, AppError> {
        if lock.state() != DataDirectoryLockState::HeldExclusive {
            return Err(AppError::new(
                ErrorCode::DataDirectoryLockStateInvalid,
                "offline support bundle requires an exclusive data lock",
            ));
        }
        Ok(Self {
            root: root.as_ref().to_path_buf(),
            output: output.as_ref().to_path_buf(),
            offline_lock: Some(lock),
        })
    }

    fn source_for(artifact: SupportBundleArtifact) -> (&'static str, &'static str) {
        match artifact {
            SupportBundleArtifact::VersionManifest => ("version.manifest", "version.manifest"),
            SupportBundleArtifact::MaskedConfig => ("config/masked.toml", "config/masked.toml"),
            SupportBundleArtifact::BoundedProductLog => ("logs/product.log", "logs/product.log"),
            SupportBundleArtifact::HealthSummary => ("health.json", "health.json"),
            SupportBundleArtifact::ResourceSummary => ("resource.json", "resource.json"),
            SupportBundleArtifact::AuditSummary => ("audit-summary.json", "audit-summary.json"),
        }
    }
}

impl SupportBundleCollector for FileSupportBundleCollector {
    fn collect_support_bundle(
        &mut self,
        request: SupportBundleRequest,
    ) -> Result<SupportBundleReport, AppError> {
        if self
            .offline_lock
            .as_ref()
            .is_some_and(|lock| lock.state() != DataDirectoryLockState::HeldExclusive)
        {
            return Err(AppError::new(
                ErrorCode::DataDirectoryLockStateInvalid,
                "offline support bundle lost its exclusive data lock",
            ));
        }
        let parent = self.output.parent().ok_or_else(|| {
            AppError::new(
                ErrorCode::SupportBundleReportInvalid,
                "support archive has no parent directory",
            )
        })?;
        let parent_metadata = fs::symlink_metadata(parent).map_err(|_| {
            AppError::new(
                ErrorCode::SupportBundleReportInvalid,
                "support archive parent is unavailable",
            )
        })?;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || self.output.symlink_metadata().is_ok()
        {
            return Err(AppError::new(
                ErrorCode::SupportBundleReportInvalid,
                "support archive output is unsafe",
            ));
        }
        let temporary = self.output.with_extension("tmp");
        if temporary.symlink_metadata().is_ok() {
            return Err(AppError::new(
                ErrorCode::SupportBundleReportInvalid,
                "support archive temporary path is unsafe",
            ));
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| {
                AppError::new(
                    ErrorCode::SupportBundleReportInvalid,
                    "support archive cannot be created",
                )
            })?;
        let mut archive = tar::Builder::new(file);
        let mut artifacts = Vec::new();
        let mut omissions = Vec::new();
        let mut total_bytes = 0_u64;
        let mut oldest_log_age_seconds = None;
        for artifact in request.artifacts {
            if artifacts.contains(&artifact) {
                continue;
            }
            let (relative, archive_name) = Self::source_for(artifact);
            let path = self.root.join(relative);
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    metadata
                }
                _ => {
                    omissions.push(SupportBundleOmission {
                        artifact,
                        reason: SupportBundleOmissionReason::NotAvailable,
                    });
                    continue;
                }
            };
            let age = if artifact == SupportBundleArtifact::BoundedProductLog {
                metadata
                    .modified()
                    .ok()
                    .and_then(|time| SystemTime::now().duration_since(time).ok())
                    .map(|duration| duration.as_secs())
            } else {
                None
            };
            if artifacts.len() >= usize::from(request.bounds.max_files)
                || total_bytes.saturating_add(metadata.len()) > request.bounds.max_total_bytes
                || age.is_some_and(|value| value > request.bounds.max_log_age_seconds)
            {
                omissions.push(SupportBundleOmission {
                    artifact,
                    reason: SupportBundleOmissionReason::ExceededCollectionBounds,
                });
                continue;
            }
            let mut input = open_regular_no_follow(&path).map_err(|_| {
                AppError::new(
                    ErrorCode::SupportBundleReportInvalid,
                    "support artifact cannot be opened",
                )
            })?;
            let mut content = Vec::with_capacity(metadata.len() as usize);
            input.read_to_end(&mut content).map_err(|_| {
                AppError::new(
                    ErrorCode::SupportBundleReportInvalid,
                    "support artifact cannot be read",
                )
            })?;
            if contains_sensitive_content(&content) {
                let _ = fs::remove_file(&temporary);
                return Err(AppError::new(
                    ErrorCode::SupportBundleReportInvalid,
                    "support artifact redaction scan failed",
                ));
            }
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            archive
                .append_data(&mut header, archive_name, content.as_slice())
                .map_err(|_| {
                    AppError::new(
                        ErrorCode::SupportBundleReportInvalid,
                        "support archive write failed",
                    )
                })?;
            total_bytes += metadata.len();
            artifacts.push(artifact);
            if let Some(value) = age {
                oldest_log_age_seconds = Some(value);
            }
        }
        let manifest = format!(
            "format=sponzey-support-v1\nartifacts={}\nredaction=passed\n",
            artifacts.len()
        );
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        archive
            .append_data(&mut header, "manifest.txt", manifest.as_bytes())
            .map_err(|_| {
                AppError::new(
                    ErrorCode::SupportBundleReportInvalid,
                    "support manifest write failed",
                )
            })?;
        archive.finish().map_err(|_| {
            AppError::new(
                ErrorCode::SupportBundleReportInvalid,
                "support archive finalization failed",
            )
        })?;
        drop(archive);
        crate::set_private_file_permissions(&temporary).map_err(|_| {
            AppError::new(
                ErrorCode::SupportBundleReportInvalid,
                "support archive permissions failed",
            )
        })?;
        let bytes = fs::read(&temporary).map_err(|_| {
            AppError::new(
                ErrorCode::SupportBundleReportInvalid,
                "support archive cannot be hashed",
            )
        })?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        fs::rename(&temporary, &self.output).map_err(|_| {
            AppError::new(
                ErrorCode::SupportBundleReportInvalid,
                "support archive cannot be published",
            )
        })?;
        Ok(SupportBundleReport {
            archive: SupportBundleArchiveReceipt {
                archive_id: crate::hex_encode_bytes(&digest),
                digest_sha256: digest,
                redaction_applied: true,
            },
            collected_artifacts: artifacts,
            total_bytes,
            oldest_collected_log_age_seconds: oldest_log_age_seconds,
            omissions,
        })
    }
}

fn contains_sensitive_content(bytes: &[u8]) -> bool {
    let content = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    [
        "-----begin private key",
        "authorization:",
        "cookie:",
        "set-cookie:",
        "password=",
        "secret=",
    ]
    .iter()
    .any(|needle| content.contains(needle))
}

#[cfg(unix)]
fn open_regular_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_regular_no_follow(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_domain::SupportBundleBounds;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("edge-support-{label}-{unique}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn request(artifact: SupportBundleArtifact) -> SupportBundleRequest {
        SupportBundleRequest {
            artifacts: vec![artifact],
            bounds: SupportBundleBounds::SAFE_DEFAULT,
        }
    }

    #[derive(Debug)]
    struct Guard(DataDirectoryLockState);

    impl DataDirectoryLockGuard for Guard {
        fn state(&self) -> DataDirectoryLockState {
            self.0
        }
        fn release(&mut self) -> Result<(), AppError> {
            Ok(())
        }
    }

    #[test]
    fn rejects_secret_bearing_fixture_before_archive_publication() {
        let root = root("secret");
        fs::write(root.join("version.manifest"), "-----BEGIN PRIVATE KEY-----").unwrap();
        let output = root.join("bundle.tar");
        let error = FileSupportBundleCollector::new_online(&root, &output)
            .collect_support_bundle(request(SupportBundleArtifact::VersionManifest))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::SupportBundleReportInvalid);
        assert!(!output.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn omits_symlinked_artifact_without_reading_its_target() {
        use std::os::unix::fs::symlink;
        let root = root("symlink");
        let outside = root.join("outside");
        fs::write(&outside, "safe outside content").unwrap();
        symlink(&outside, root.join("version.manifest")).unwrap();
        let output = root.join("bundle.tar");
        let report = FileSupportBundleCollector::new_online(&root, &output)
            .collect_support_bundle(request(SupportBundleArtifact::VersionManifest))
            .unwrap();
        assert!(report.collected_artifacts.is_empty());
        assert_eq!(
            report.omissions[0].reason,
            SupportBundleOmissionReason::NotAvailable
        );
        assert!(output.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn omits_an_artifact_that_exceeds_the_requested_byte_bound() {
        let root = root("bound");
        fs::write(root.join("version.manifest"), "two bytes").unwrap();
        let output = root.join("bundle.tar");
        let report = FileSupportBundleCollector::new_online(&root, &output)
            .collect_support_bundle(SupportBundleRequest {
                artifacts: vec![SupportBundleArtifact::VersionManifest],
                bounds: SupportBundleBounds {
                    max_files: 1,
                    max_total_bytes: 1,
                    max_log_age_seconds: 1,
                },
            })
            .unwrap();
        assert!(report.collected_artifacts.is_empty());
        assert_eq!(
            report.omissions[0].reason,
            SupportBundleOmissionReason::ExceededCollectionBounds
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn offline_collection_requires_an_exclusive_data_lock() {
        let root = root("lock");
        let error = FileSupportBundleCollector::new_offline(
            &root,
            root.join("bundle.tar"),
            Box::new(Guard(DataDirectoryLockState::Released)),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::DataDirectoryLockStateInvalid);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn omits_a_product_log_older_than_the_requested_bound() {
        let root = root("old-log");
        let logs = root.join("logs");
        fs::create_dir(&logs).unwrap();
        let log = logs.join("product.log");
        fs::write(&log, "safe log line").unwrap();
        filetime::set_file_mtime(&log, filetime::FileTime::from_unix_time(1, 0)).unwrap();
        let output = root.join("bundle.tar");
        let report = FileSupportBundleCollector::new_online(&root, &output)
            .collect_support_bundle(SupportBundleRequest {
                artifacts: vec![SupportBundleArtifact::BoundedProductLog],
                bounds: SupportBundleBounds {
                    max_files: 1,
                    max_total_bytes: 1024,
                    max_log_age_seconds: 1,
                },
            })
            .unwrap();
        assert!(report.collected_artifacts.is_empty());
        assert_eq!(
            report.omissions[0].reason,
            SupportBundleOmissionReason::ExceededCollectionBounds
        );
        let _ = fs::remove_dir_all(root);
    }
}
