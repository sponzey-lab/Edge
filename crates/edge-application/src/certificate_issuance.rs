//! Legacy certificate issuance and Core installation orchestration.
//!
//! This compatibility boundary coordinates already-supplied ACME port calls. It
//! does not schedule, enable, or otherwise expand certificate automation.

use crate::Http01ChallengeRuntime;
use edge_domain::{AppError, CertificateRef, CommandAck, CoreCommand, ErrorCode};
use edge_ports::{
    AcmeClient, AcmeHttp01ChallengeRuntime, AcmeOrderRequest, AcmeOrderResult, AuditEvent,
    AuditSink, CertificateStore, CoreCommandClient, Http01ChallengeProbe, Http01ChallengeStore,
};

pub struct CertificateIssuer<C, S, A> {
    pub acme: C,
    pub store: S,
    pub audit: A,
}

impl<C, S, A> CertificateIssuer<C, S, A>
where
    C: AcmeClient,
    S: CertificateStore,
    A: AuditSink,
{
    pub fn issue(&mut self, request: AcmeOrderRequest) -> Result<AcmeOrderResult, AppError> {
        self.issue_with_target_ref(None, request, "certificate.issue")
    }

    pub fn issue_for_ref(
        &mut self,
        certificate_ref: CertificateRef,
        request: AcmeOrderRequest,
    ) -> Result<AcmeOrderResult, AppError> {
        self.issue_with_target_ref(Some(certificate_ref), request, "certificate.issue")
    }

    pub fn issue_for_ref_with_http01(
        &mut self,
        certificate_ref: CertificateRef,
        request: AcmeOrderRequest,
        challenge_runtime: &mut dyn AcmeHttp01ChallengeRuntime,
    ) -> Result<AcmeOrderResult, AppError> {
        self.issue_with_target_ref_and_http01(
            Some(certificate_ref),
            request,
            challenge_runtime,
            "certificate.issue",
        )
    }

    pub fn renew_for_ref(
        &mut self,
        certificate_ref: CertificateRef,
        request: CertificateRenewRequest,
    ) -> Result<AcmeOrderResult, AppError> {
        let existing = self
            .store
            .load_certificate(&certificate_ref)?
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::CertificateNotFound,
                    format!("certificate not found: {}", certificate_ref.as_str()),
                )
            })?;

        self.issue_with_target_ref(
            Some(certificate_ref),
            AcmeOrderRequest {
                domains: existing.domains,
                account_email: request.account_email,
                production: request.production,
                terms_accepted: request.terms_accepted,
            },
            "certificate.renew",
        )
    }

    fn issue_with_target_ref(
        &mut self,
        certificate_ref: Option<CertificateRef>,
        request: AcmeOrderRequest,
        audit_event: &str,
    ) -> Result<AcmeOrderResult, AppError> {
        if request.production && !request.terms_accepted {
            return Err(AppError::new(
                ErrorCode::AcmeTermsNotAccepted,
                "production ACME requires terms acceptance",
            ));
        }

        let mut result = self.acme.issue_certificate(request)?;
        if let Some(certificate_ref) = certificate_ref {
            result.certificate.certificate_ref = certificate_ref;
        }
        self.store.save_certificate(result.certificate.clone())?;
        self.audit.record(AuditEvent {
            event: audit_event.to_string(),
            revision_id: None,
        })?;
        Ok(result)
    }

    fn issue_with_target_ref_and_http01(
        &mut self,
        certificate_ref: Option<CertificateRef>,
        request: AcmeOrderRequest,
        challenge_runtime: &mut dyn AcmeHttp01ChallengeRuntime,
        audit_event: &str,
    ) -> Result<AcmeOrderResult, AppError> {
        if request.production && !request.terms_accepted {
            return Err(AppError::new(
                ErrorCode::AcmeTermsNotAccepted,
                "production ACME requires terms acceptance",
            ));
        }

        let mut result = self
            .acme
            .issue_certificate_http01(request, challenge_runtime)?;
        if let Some(certificate_ref) = certificate_ref {
            result.certificate.certificate_ref = certificate_ref;
        }
        self.store.save_certificate(result.certificate.clone())?;
        self.audit.record(AuditEvent {
            event: audit_event.to_string(),
            revision_id: None,
        })?;
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRenewRequest {
    pub account_email: String,
    pub production: bool,
    pub terms_accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateIssueOutcome {
    pub certificate_ref: CertificateRef,
    pub domains: Vec<String>,
    pub source: String,
    pub not_after_epoch_seconds: u64,
    pub commands_sent: usize,
}

pub fn issue_certificate_for_ref_and_install<C, S, A, K>(
    issuer: &mut CertificateIssuer<C, S, A>,
    certificate_ref: CertificateRef,
    request: AcmeOrderRequest,
    core: &mut K,
) -> Result<CertificateIssueOutcome, AppError>
where
    C: AcmeClient,
    S: CertificateStore,
    A: AuditSink,
    K: CoreCommandClient + ?Sized,
{
    let result = issuer.issue_for_ref(certificate_ref, request)?;
    install_certificate_result(result, core)
}

pub fn issue_certificate_for_ref_with_http01_and_install<C, S, A, K, T, P>(
    issuer: &mut CertificateIssuer<C, S, A>,
    challenges: &mut T,
    probe: &mut P,
    certificate_ref: CertificateRef,
    request: AcmeOrderRequest,
    core: &mut K,
) -> Result<CertificateIssueOutcome, AppError>
where
    C: AcmeClient,
    S: CertificateStore,
    A: AuditSink,
    K: CoreCommandClient + ?Sized,
    T: Http01ChallengeStore + ?Sized,
    P: Http01ChallengeProbe + ?Sized,
{
    let mut challenge_runtime = Http01ChallengeRuntime::new(challenges, probe);
    let outcome = issuer
        .issue_for_ref_with_http01(certificate_ref, request, &mut challenge_runtime)
        .and_then(|result| install_certificate_result(result, core));
    let cleanup = challenge_runtime.clear_presented_http01();

    match (outcome, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), _) => Err(error),
    }
}

pub fn renew_certificate_for_ref_and_install<C, S, A, K>(
    issuer: &mut CertificateIssuer<C, S, A>,
    certificate_ref: CertificateRef,
    request: CertificateRenewRequest,
    core: &mut K,
) -> Result<CertificateIssueOutcome, AppError>
where
    C: AcmeClient,
    S: CertificateStore,
    A: AuditSink,
    K: CoreCommandClient + ?Sized,
{
    let result = issuer.renew_for_ref(certificate_ref, request)?;
    install_certificate_result(result, core)
}

fn install_certificate_result<K>(
    result: AcmeOrderResult,
    core: &mut K,
) -> Result<CertificateIssueOutcome, AppError>
where
    K: CoreCommandClient + ?Sized,
{
    let certificate = result.certificate;
    match core.send(CoreCommand::InstallCertificate {
        certificate_ref: certificate.certificate_ref.clone(),
    }) {
        CommandAck::Accepted => Ok(CertificateIssueOutcome {
            certificate_ref: certificate.certificate_ref,
            domains: certificate.domains,
            source: certificate.source,
            not_after_epoch_seconds: certificate.not_after_epoch_seconds,
            commands_sent: 1,
        }),
        CommandAck::Rejected(error) => Err(error),
    }
}
