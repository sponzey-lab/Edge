//! Pure operator-request contract for an offline deployment upgrade.

use crate::{AppError, ErrorCode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineUpgradeRequest {
    pub target_version: String,
    pub image_digest: String,
    /// A root-owned local artifact path reference only; bytes are admitted by an adapter.
    pub artifact_file: String,
    /// A path reference only; the passphrase value is never part of this request.
    pub passphrase_file: String,
}

impl OfflineUpgradeRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        let version = self
            .target_version
            .strip_prefix('v')
            .unwrap_or(&self.target_version);
        if version.split('.').count() != 3
            || version
                .split('.')
                .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(AppError::new(
                ErrorCode::ProcessCommandInvalid,
                "upgrade version must be SemVer",
            ));
        }
        let digest = self
            .image_digest
            .strip_prefix("sha256:")
            .unwrap_or(&self.image_digest);
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AppError::new(
                ErrorCode::BackupDestinationUnsafe,
                "upgrade image digest must be SHA-256",
            ));
        }
        if !self.passphrase_file.starts_with('/') || self.passphrase_file.contains('\0') {
            return Err(AppError::new(
                ErrorCode::BackupSecretInputInvalid,
                "passphrase file must be an absolute path reference",
            ));
        }
        if !self.artifact_file.starts_with('/') || self.artifact_file.contains('\0') {
            return Err(AppError::new(
                ErrorCode::BackupDestinationUnsafe,
                "artifact file must be an absolute path reference",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineUpgradeState {
    Prepared,
    Draining,
    Stopped,
    Switched,
    Ready,
    Committed,
    RollingBack,
    RolledBack,
}

impl OfflineUpgradeState {
    pub fn transition(self, next: Self) -> Result<Self, AppError> {
        let allowed = matches!(
            (self, next),
            (Self::Prepared, Self::Draining)
                | (Self::Draining, Self::Stopped)
                | (Self::Stopped, Self::Switched)
                | (Self::Switched, Self::Ready)
                | (Self::Ready, Self::Committed)
                | (
                    Self::Prepared | Self::Draining | Self::Stopped | Self::Switched | Self::Ready,
                    Self::RollingBack
                )
                | (Self::RollingBack, Self::RolledBack)
        );
        if allowed {
            Ok(next)
        } else {
            Err(AppError::new(
                ErrorCode::BackupStateTransitionInvalid,
                "invalid offline upgrade transition",
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineUpgradeJournal {
    pub operation_id: String,
    pub state: OfflineUpgradeState,
    pub backup_id: String,
    pub previous_artifact_digest: String,
    pub target_artifact_digest: String,
}

impl OfflineUpgradeJournal {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.operation_id.is_empty()
            || self.backup_id.is_empty()
            || !is_sha256_digest(&self.previous_artifact_digest)
            || !is_sha256_digest(&self.target_artifact_digest)
        {
            return Err(AppError::new(
                ErrorCode::BackupManifestInvalid,
                "upgrade journal identity is invalid",
            ));
        }
        Ok(())
    }
}

fn is_sha256_digest(value: &str) -> bool {
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::OfflineUpgradeRequest;

    fn request() -> OfflineUpgradeRequest {
        OfflineUpgradeRequest {
            target_version: "v1.2.3".into(),
            image_digest: format!("sha256:{}", "a".repeat(64)),
            artifact_file: "/root/edge-proxy-1.2.3".into(),
            passphrase_file: "/secure/upgrade.passphrase".into(),
        }
    }

    #[test]
    fn upgrade_request_accepts_identity_without_secret_value() {
        assert!(request().validate().is_ok());
    }

    #[test]
    fn upgrade_request_rejects_unsafe_identity_or_secret_reference() {
        for (version, digest, path, artifact) in [
            ("next", "a", "/secure/p", "/root/artifact"),
            ("v1.2.3", "a", "relative", "/root/artifact"),
            ("v1.2.3", "a", "/secure/p", "relative"),
        ] {
            let mut input = request();
            input.target_version = version.into();
            input.image_digest = digest.into();
            input.passphrase_file = path.into();
            input.artifact_file = artifact.into();
            assert!(input.validate().is_err());
        }
    }

    #[test]
    fn upgrade_state_requires_drain_stop_switch_ready_before_commit() {
        use super::OfflineUpgradeState::*;
        let state = Prepared
            .transition(Draining)
            .unwrap()
            .transition(Stopped)
            .unwrap()
            .transition(Switched)
            .unwrap()
            .transition(Ready)
            .unwrap()
            .transition(Committed)
            .unwrap();
        assert_eq!(state, Committed);
        assert!(Prepared.transition(Committed).is_err());
        assert_eq!(
            Switched
                .transition(RollingBack)
                .unwrap()
                .transition(RolledBack)
                .unwrap(),
            RolledBack
        );
    }

    #[test]
    fn journal_is_secret_free_and_requires_recovery_identities() {
        let journal = super::OfflineUpgradeJournal {
            operation_id: "op-1".into(),
            state: super::OfflineUpgradeState::Switched,
            backup_id: "backup-1".into(),
            previous_artifact_digest: "a".repeat(64),
            target_artifact_digest: "b".repeat(64),
        };
        assert!(journal.validate().is_ok());
        assert!(!format!("{journal:?}").contains("passphrase"));
    }
}
