use edge_domain::{AppError, ErrorCode, SupportBundleBounds};
use edge_ports::{SupportBundleCollector, SupportBundleReport, SupportBundleRequest};

pub struct CollectSupportBundleUseCase<C> {
    collector: C,
}

impl<C> CollectSupportBundleUseCase<C> {
    pub fn new(collector: C) -> Self {
        Self { collector }
    }
}

impl<C: SupportBundleCollector> CollectSupportBundleUseCase<C> {
    pub fn execute(
        &mut self,
        request: SupportBundleRequest,
    ) -> Result<SupportBundleReport, AppError> {
        let report = self.collector.collect_support_bundle(request.clone())?;
        if !report.archive.is_valid() {
            return Err(AppError::new(
                ErrorCode::SupportBundleReportInvalid,
                "support bundle collector returned an invalid archive receipt",
            ));
        }
        if report.collected_artifacts.iter().any(|artifact| {
            !request.artifacts.contains(artifact)
                || report
                    .collected_artifacts
                    .iter()
                    .filter(|candidate| *candidate == artifact)
                    .count()
                    > 1
        }) {
            return Err(AppError::new(
                ErrorCode::SupportBundleReportInvalid,
                "support bundle collector returned an unrequested or duplicate artifact",
            ));
        }
        if report
            .omissions
            .iter()
            .any(|omission| !request.artifacts.contains(&omission.artifact))
        {
            return Err(AppError::new(
                ErrorCode::SupportBundleReportInvalid,
                "support bundle collector omitted an unrequested artifact",
            ));
        }

        let includes_product_log = report
            .collected_artifacts
            .contains(&edge_domain::SupportBundleArtifact::BoundedProductLog);
        let log_age_seconds = match (
            includes_product_log,
            report.oldest_collected_log_age_seconds,
        ) {
            (true, Some(age)) => age,
            (false, None) => 0,
            _ => {
                return Err(AppError::new(
                    ErrorCode::SupportBundleReportInvalid,
                    "support bundle log age metadata does not match collected artifacts",
                ));
            }
        };
        if !request.bounds.accepts(
            report.collected_artifacts.len(),
            report.total_bytes,
            log_age_seconds,
        ) {
            return Err(AppError::new(
                ErrorCode::SupportBundleBoundsExceeded,
                "support bundle collector exceeded requested bounds",
            ));
        }
        Ok(report)
    }
}

pub fn default_support_bundle_bounds() -> SupportBundleBounds {
    SupportBundleBounds::SAFE_DEFAULT
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_domain::SupportBundleArtifact;
    use edge_ports::SupportBundleCollector;

    struct FakeCollector {
        report: SupportBundleReport,
    }

    impl SupportBundleCollector for FakeCollector {
        fn collect_support_bundle(
            &mut self,
            _: SupportBundleRequest,
        ) -> Result<SupportBundleReport, AppError> {
            Ok(self.report.clone())
        }
    }

    #[test]
    fn rejects_a_collector_report_that_exceeds_the_requested_bounds() {
        let mut use_case = CollectSupportBundleUseCase::new(FakeCollector {
            report: SupportBundleReport {
                archive: edge_domain::SupportBundleArchiveReceipt {
                    archive_id: "archive-1".into(),
                    digest_sha256: [0; 32],
                    redaction_applied: true,
                },
                collected_artifacts: vec![SupportBundleArtifact::AuditSummary; 33],
                total_bytes: 1,
                oldest_collected_log_age_seconds: None,
                omissions: vec![],
            },
        });
        assert!(use_case
            .execute(SupportBundleRequest {
                artifacts: vec![SupportBundleArtifact::AuditSummary],
                bounds: SupportBundleBounds::SAFE_DEFAULT,
            })
            .is_err());
    }

    #[test]
    fn rejects_an_artifact_the_caller_did_not_request() {
        let mut use_case = CollectSupportBundleUseCase::new(FakeCollector {
            report: SupportBundleReport {
                archive: edge_domain::SupportBundleArchiveReceipt {
                    archive_id: "archive-1".into(),
                    digest_sha256: [0; 32],
                    redaction_applied: true,
                },
                collected_artifacts: vec![SupportBundleArtifact::MaskedConfig],
                total_bytes: 1,
                oldest_collected_log_age_seconds: None,
                omissions: vec![],
            },
        });

        let error = use_case
            .execute(SupportBundleRequest {
                artifacts: vec![SupportBundleArtifact::HealthSummary],
                bounds: SupportBundleBounds::SAFE_DEFAULT,
            })
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::SupportBundleReportInvalid);
    }

    #[test]
    fn rejects_duplicate_artifacts_and_stale_product_logs() {
        let request = SupportBundleRequest {
            artifacts: vec![SupportBundleArtifact::BoundedProductLog],
            bounds: SupportBundleBounds::SAFE_DEFAULT,
        };
        let mut duplicate = CollectSupportBundleUseCase::new(FakeCollector {
            report: SupportBundleReport {
                archive: edge_domain::SupportBundleArchiveReceipt {
                    archive_id: "archive-1".into(),
                    digest_sha256: [0; 32],
                    redaction_applied: true,
                },
                collected_artifacts: vec![
                    SupportBundleArtifact::BoundedProductLog,
                    SupportBundleArtifact::BoundedProductLog,
                ],
                total_bytes: 1,
                oldest_collected_log_age_seconds: Some(1),
                omissions: vec![],
            },
        });
        assert_eq!(
            duplicate.execute(request.clone()).unwrap_err().code,
            ErrorCode::SupportBundleReportInvalid
        );

        let mut stale_log = CollectSupportBundleUseCase::new(FakeCollector {
            report: SupportBundleReport {
                archive: edge_domain::SupportBundleArchiveReceipt {
                    archive_id: "archive-1".into(),
                    digest_sha256: [0; 32],
                    redaction_applied: true,
                },
                collected_artifacts: vec![SupportBundleArtifact::BoundedProductLog],
                total_bytes: 1,
                oldest_collected_log_age_seconds: Some(24 * 60 * 60 + 1),
                omissions: vec![],
            },
        });
        assert_eq!(
            stale_log.execute(request).unwrap_err().code,
            ErrorCode::SupportBundleBoundsExceeded
        );
    }

    #[test]
    fn rejects_omission_metadata_for_an_unrequested_artifact() {
        let mut use_case = CollectSupportBundleUseCase::new(FakeCollector {
            report: SupportBundleReport {
                archive: edge_domain::SupportBundleArchiveReceipt {
                    archive_id: "archive-1".into(),
                    digest_sha256: [0; 32],
                    redaction_applied: true,
                },
                collected_artifacts: vec![],
                total_bytes: 0,
                oldest_collected_log_age_seconds: None,
                omissions: vec![edge_domain::SupportBundleOmission {
                    artifact: SupportBundleArtifact::MaskedConfig,
                    reason: edge_domain::SupportBundleOmissionReason::NotAvailable,
                }],
            },
        });

        assert_eq!(
            use_case
                .execute(SupportBundleRequest {
                    artifacts: vec![SupportBundleArtifact::HealthSummary],
                    bounds: SupportBundleBounds::SAFE_DEFAULT,
                })
                .unwrap_err()
                .code,
            ErrorCode::SupportBundleReportInvalid
        );
    }
}
