//! Pure certificate status and renewal-decision values.

use edge_domain::{AppError, CertificateRef, ErrorCode};
use edge_ports::StoredCertificate;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateStatus {
    pub certificate_ref: CertificateRef,
    pub domains: Vec<String>,
    pub source: String,
    pub expired: bool,
    pub expiring_soon: bool,
    pub not_after_epoch_seconds: u64,
    pub private_key_masked: &'static str,
}

pub fn certificate_status(
    certificate: &StoredCertificate,
    now_epoch_seconds: u64,
    renewal_window_seconds: u64,
) -> CertificateStatus {
    let seconds_left = certificate
        .not_after_epoch_seconds
        .saturating_sub(now_epoch_seconds);
    CertificateStatus {
        certificate_ref: certificate.certificate_ref.clone(),
        domains: certificate.domains.clone(),
        source: certificate.source.clone(),
        expired: certificate.not_after_epoch_seconds <= now_epoch_seconds,
        expiring_soon: seconds_left <= renewal_window_seconds,
        not_after_epoch_seconds: certificate.not_after_epoch_seconds,
        private_key_masked: certificate.masked_private_key(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalDueReason {
    Expired,
    InsideWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalSkipReason {
    OutsideWindow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateRenewalDecision {
    RenewalDue {
        certificate_ref: CertificateRef,
        domains: Vec<String>,
        reason: RenewalDueReason,
    },
    RenewalSkipped {
        certificate_ref: CertificateRef,
        reason: RenewalSkipReason,
    },
    RenewalFailed {
        certificate_ref: CertificateRef,
        error_code: ErrorCode,
        retryable: bool,
        failed_attempts: u32,
        next_retry_epoch_seconds: Option<u64>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenewalRetryPolicy {
    pub max_attempts: u32,
    pub backoff_seconds: u64,
}

pub fn plan_certificate_renewal(
    certificate: &StoredCertificate,
    now_epoch_seconds: u64,
    renewal_window_seconds: u64,
) -> CertificateRenewalDecision {
    if certificate.not_after_epoch_seconds <= now_epoch_seconds {
        return CertificateRenewalDecision::RenewalDue {
            certificate_ref: certificate.certificate_ref.clone(),
            domains: certificate.domains.clone(),
            reason: RenewalDueReason::Expired,
        };
    }

    let seconds_left = certificate.not_after_epoch_seconds - now_epoch_seconds;
    if seconds_left <= renewal_window_seconds {
        CertificateRenewalDecision::RenewalDue {
            certificate_ref: certificate.certificate_ref.clone(),
            domains: certificate.domains.clone(),
            reason: RenewalDueReason::InsideWindow,
        }
    } else {
        CertificateRenewalDecision::RenewalSkipped {
            certificate_ref: certificate.certificate_ref.clone(),
            reason: RenewalSkipReason::OutsideWindow,
        }
    }
}

pub fn renewal_failure_decision(
    certificate_ref: CertificateRef,
    error: &AppError,
    now_epoch_seconds: u64,
    failed_attempts: u32,
    policy: RenewalRetryPolicy,
) -> CertificateRenewalDecision {
    let fatal_error = matches!(
        error.code,
        ErrorCode::AcmeTermsNotAccepted
            | ErrorCode::ConfigProductionAcmeRequiresOptIn
            | ErrorCode::CertificateNotFound
    );
    let retryable = !fatal_error && failed_attempts < policy.max_attempts;
    let next_retry_epoch_seconds = retryable.then(|| {
        let attempt_multiplier = u64::from(failed_attempts.max(1));
        now_epoch_seconds.saturating_add(policy.backoff_seconds.saturating_mul(attempt_multiplier))
    });

    CertificateRenewalDecision::RenewalFailed {
        certificate_ref,
        error_code: error.code,
        retryable,
        failed_attempts,
        next_retry_epoch_seconds,
    }
}
