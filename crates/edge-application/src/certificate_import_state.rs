//! Explicit state transitions for manual certificate import and compensation.
use edge_domain::{normalize_host, AppError, CertificateRef, ConfigRevisionId, ErrorCode};
use edge_ports::CertificateMaterial;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualCertificateImportRequest {
    pub certificate_ref: CertificateRef,
    pub domains: Vec<String>,
    pub fullchain_pem: String,
    pub private_key_pem: String,
    pub expected_not_after_epoch_seconds: Option<u64>,
    pub request_id: String,
    pub revision_id: ConfigRevisionId,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualCertificateStatus {
    pub certificate_ref: CertificateRef,
    pub domains: Vec<String>,
    pub source: String,
    pub not_after_epoch_seconds: u64,
    pub private_key_masked: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateImportState {
    Received,
    Validated,
    Stored,
    InstallCommandSent,
    Installed,
    Failed {
        error_code: ErrorCode,
        compensation_failed: bool,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateImportEvent {
    Validated,
    Stored,
    InstallCommandSent,
    Installed,
    Failed {
        error_code: ErrorCode,
        compensation_failed: bool,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateImportMachine {
    state: CertificateImportState,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualCertificateImportOutcome {
    pub status: ManualCertificateStatus,
    pub state: CertificateImportState,
    pub commands_sent: usize,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualCertificateImportFailure {
    pub state: CertificateImportState,
    pub error: AppError,
    pub compensation_error: Option<AppError>,
}
pub(crate) struct NormalizedManualCertificateImport {
    pub certificate_ref: CertificateRef,
    pub domains: Vec<String>,
    pub material: CertificateMaterial,
    pub expected_not_after_epoch_seconds: Option<u64>,
    pub revision_id: ConfigRevisionId,
}
pub(crate) fn normalize_manual_certificate_import_request(
    request: ManualCertificateImportRequest,
) -> Result<NormalizedManualCertificateImport, AppError> {
    let certificate_ref = request.certificate_ref.as_str().trim();
    if certificate_ref.is_empty() {
        return Err(AppError::new(
            ErrorCode::CertificateInvalid,
            "certificate_ref must not be empty",
        ));
    }
    if request.fullchain_pem.trim().is_empty() || request.private_key_pem.trim().is_empty() {
        return Err(AppError::new(
            ErrorCode::CertificateInvalid,
            "certificate and private key PEM must not be empty",
        ));
    }
    let mut domains = BTreeSet::new();
    for domain in request.domains {
        let domain = normalize_host(&domain);
        if domain.is_empty()
            || domain.contains(char::is_whitespace)
            || domain.contains('/')
            || domain.contains('*')
        {
            return Err(AppError::new(
                ErrorCode::CertificateInvalid,
                "certificate domain is invalid or unsupported",
            ));
        }
        domains.insert(domain);
    }
    if domains.is_empty() {
        return Err(AppError::new(
            ErrorCode::CertificateInvalid,
            "at least one certificate domain is required",
        ));
    }
    Ok(NormalizedManualCertificateImport {
        certificate_ref: CertificateRef::new(certificate_ref),
        domains: domains.into_iter().collect(),
        material: CertificateMaterial {
            certificate_pem: request.fullchain_pem,
            private_key_pem: request.private_key_pem,
        },
        expected_not_after_epoch_seconds: request.expected_not_after_epoch_seconds,
        revision_id: request.revision_id,
    })
}
impl Default for CertificateImportMachine {
    fn default() -> Self {
        Self {
            state: CertificateImportState::Received,
        }
    }
}
impl CertificateImportMachine {
    pub fn state(&self) -> &CertificateImportState {
        &self.state
    }
    pub fn transition(&mut self, event: CertificateImportEvent) -> Result<(), AppError> {
        let next = match (&self.state, event) {
            (CertificateImportState::Received, CertificateImportEvent::Validated) => {
                CertificateImportState::Validated
            }
            (CertificateImportState::Validated, CertificateImportEvent::Stored) => {
                CertificateImportState::Stored
            }
            (CertificateImportState::Stored, CertificateImportEvent::InstallCommandSent) => {
                CertificateImportState::InstallCommandSent
            }
            (CertificateImportState::InstallCommandSent, CertificateImportEvent::Installed) => {
                CertificateImportState::Installed
            }
            (
                CertificateImportState::Received
                | CertificateImportState::Validated
                | CertificateImportState::Stored
                | CertificateImportState::InstallCommandSent,
                CertificateImportEvent::Failed {
                    error_code,
                    compensation_failed,
                },
            ) => CertificateImportState::Failed {
                error_code,
                compensation_failed,
            },
            (state, event) => {
                return Err(AppError::new(
                    ErrorCode::InternalBug,
                    format!("invalid certificate import transition: {state:?} + {event:?}"),
                ))
            }
        };
        self.state = next;
        Ok(())
    }
}
