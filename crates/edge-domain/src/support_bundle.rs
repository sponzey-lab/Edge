#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportBundleArtifact {
    VersionManifest,
    MaskedConfig,
    BoundedProductLog,
    HealthSummary,
    ResourceSummary,
    AuditSummary,
}

/// Secret-free reason why a requested allowlisted artifact was omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportBundleOmissionReason {
    NotAvailable,
    ExceededCollectionBounds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportBundleOmission {
    pub artifact: SupportBundleArtifact,
    pub reason: SupportBundleOmissionReason,
}

/// Secret-free identity of a published support archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundleArchiveReceipt {
    pub archive_id: String,
    pub digest_sha256: [u8; 32],
    pub redaction_applied: bool,
}

impl SupportBundleArchiveReceipt {
    pub fn is_valid(&self) -> bool {
        !self.archive_id.is_empty() && self.redaction_applied
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportBundleBounds {
    pub max_files: u16,
    pub max_total_bytes: u64,
    pub max_log_age_seconds: u64,
}

impl SupportBundleBounds {
    pub const SAFE_DEFAULT: Self = Self {
        max_files: 32,
        max_total_bytes: 16 * 1024 * 1024,
        max_log_age_seconds: 24 * 60 * 60,
    };

    pub fn accepts(self, file_count: usize, total_bytes: u64, log_age_seconds: u64) -> bool {
        file_count <= usize::from(self.max_files)
            && total_bytes <= self.max_total_bytes
            && log_age_seconds <= self.max_log_age_seconds
    }
}

impl SupportBundleArtifact {
    pub fn is_allowed(self) -> bool {
        match self {
            Self::VersionManifest
            | Self::MaskedConfig
            | Self::BoundedProductLog
            | Self::HealthSummary
            | Self::ResourceSummary
            | Self::AuditSummary => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SupportBundleArtifact, SupportBundleOmission, SupportBundleOmissionReason};

    #[test]
    fn allowlist_contains_only_safe_metadata_artifacts() {
        assert!(SupportBundleArtifact::VersionManifest.is_allowed());
        assert!(SupportBundleArtifact::MaskedConfig.is_allowed());
        assert!(SupportBundleArtifact::BoundedProductLog.is_allowed());
        assert!(SupportBundleArtifact::HealthSummary.is_allowed());
        assert!(SupportBundleArtifact::ResourceSummary.is_allowed());
        assert!(SupportBundleArtifact::AuditSummary.is_allowed());
    }

    #[test]
    fn bounds_reject_unbounded_file_count_size_and_log_age() {
        let bounds = super::SupportBundleBounds::SAFE_DEFAULT;
        assert!(bounds.accepts(32, 16 * 1024 * 1024, 24 * 60 * 60));
        assert!(!bounds.accepts(33, 1, 1));
        assert!(!bounds.accepts(1, 16 * 1024 * 1024 + 1, 1));
        assert!(!bounds.accepts(1, 1, 24 * 60 * 60 + 1));
        assert!(!bounds.accepts(usize::from(u16::MAX) + 1, 1, 1));
    }

    #[test]
    fn omission_metadata_cannot_carry_paths_or_secret_values() {
        let omission = SupportBundleOmission {
            artifact: SupportBundleArtifact::BoundedProductLog,
            reason: SupportBundleOmissionReason::ExceededCollectionBounds,
        };

        assert_eq!(omission.artifact, SupportBundleArtifact::BoundedProductLog);
    }

    #[test]
    fn archive_receipt_requires_an_identity_and_redaction_fact() {
        assert!(super::SupportBundleArchiveReceipt {
            archive_id: "archive-1".into(),
            digest_sha256: [1; 32],
            redaction_applied: true,
        }
        .is_valid());
        assert!(!super::SupportBundleArchiveReceipt {
            archive_id: String::new(),
            digest_sha256: [1; 32],
            redaction_applied: true,
        }
        .is_valid());
    }
}
