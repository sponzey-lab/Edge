//! Manual certificate import orchestration through typed application ports.

use crate::{
    certificate_import_state::normalize_manual_certificate_import_request, CertificateImportEvent,
    CertificateImportMachine, ManualCertificateImportFailure, ManualCertificateImportOutcome,
    ManualCertificateImportRequest, ManualCertificateStatus,
};
use edge_domain::{normalize_host, AppError, CertificateRef, CommandAck, CoreCommand, ErrorCode};
use edge_ports::{
    AuditEvent, AuditSink, CertificateMaterialValidator, CertificateStore, CoreCommandClient,
    StoredCertificate,
};

/// Validates, persists, audits, and installs manual certificate material.
///
/// On an audit or Core-command failure, it restores the previous stored certificate when
/// possible. The returned failure always retains the primary error and separately reports a
/// compensation failure.
pub fn import_manual_certificate_and_install<V, S, A, K>(
    request: ManualCertificateImportRequest,
    validator: &mut V,
    store: &mut S,
    audit: &mut A,
    core: &mut K,
) -> Result<ManualCertificateImportOutcome, ManualCertificateImportFailure>
where
    V: CertificateMaterialValidator + ?Sized,
    S: CertificateStore + ?Sized,
    A: AuditSink + ?Sized,
    K: CoreCommandClient + ?Sized,
{
    let mut machine = CertificateImportMachine::default();
    let normalized = match normalize_manual_certificate_import_request(request) {
        Ok(normalized) => normalized,
        Err(error) => return Err(import_failure(&mut machine, error, None)),
    };

    let validated = match validator.validate(&normalized.material) {
        Ok(validated) => validated,
        Err(error) => return Err(import_failure(&mut machine, error, None)),
    };
    if validated.not_after_epoch_seconds == 0
        || normalized
            .expected_not_after_epoch_seconds
            .is_some_and(|expected| expected != validated.not_after_epoch_seconds)
    {
        return Err(import_failure(
            &mut machine,
            AppError::new(
                ErrorCode::CertificateInvalid,
                "certificate expiry does not match the validated leaf certificate",
            ),
            None,
        ));
    }
    if let Err(error) = validate_declared_domains_against_certificate_identities(
        &normalized.domains,
        &validated.dns_names,
    ) {
        return Err(import_failure(&mut machine, error, None));
    }
    transition_or_failure(&mut machine, CertificateImportEvent::Validated)?;

    let certificate = StoredCertificate {
        certificate_ref: normalized.certificate_ref.clone(),
        domains: normalized.domains.clone(),
        not_after_epoch_seconds: validated.not_after_epoch_seconds,
        source: "manual".to_string(),
        certificate_pem: normalized.material.certificate_pem,
        private_key_pem: normalized.material.private_key_pem,
    };
    let previous = match store.load_certificate(&certificate.certificate_ref) {
        Ok(previous) => previous,
        Err(error) => return Err(import_failure(&mut machine, error, None)),
    };
    if let Err(error) = store.save_certificate(certificate.clone()) {
        return Err(import_failure(&mut machine, error, None));
    }
    transition_or_failure(&mut machine, CertificateImportEvent::Stored)?;

    if let Err(error) = audit.record(AuditEvent {
        event: "certificate.import".to_string(),
        revision_id: Some(normalized.revision_id),
    }) {
        let compensation_error = restore_certificate(store, previous, &certificate.certificate_ref);
        return Err(import_failure(&mut machine, error, compensation_error));
    }

    transition_or_failure(&mut machine, CertificateImportEvent::InstallCommandSent)?;
    match core.send(CoreCommand::InstallCertificate {
        certificate_ref: certificate.certificate_ref.clone(),
    }) {
        CommandAck::Accepted => {
            transition_or_failure(&mut machine, CertificateImportEvent::Installed)?;
            let private_key_masked = certificate.masked_private_key();
            Ok(ManualCertificateImportOutcome {
                status: ManualCertificateStatus {
                    certificate_ref: certificate.certificate_ref,
                    domains: certificate.domains,
                    source: certificate.source,
                    not_after_epoch_seconds: certificate.not_after_epoch_seconds,
                    private_key_masked,
                },
                state: machine.state().clone(),
                commands_sent: 1,
            })
        }
        CommandAck::Rejected(error) => {
            let compensation_error =
                restore_certificate(store, previous, &certificate.certificate_ref);
            Err(import_failure(&mut machine, error, compensation_error))
        }
    }
}

fn validate_declared_domains_against_certificate_identities(
    declared_domains: &[String],
    certificate_dns_names: &[String],
) -> Result<(), AppError> {
    if certificate_dns_names.is_empty() {
        return Err(certificate_identity_mismatch());
    }
    let identities = certificate_dns_names
        .iter()
        .filter_map(|identity| normalize_certificate_dns_identity(identity))
        .collect::<Vec<_>>();
    if identities.is_empty() {
        return Err(certificate_identity_mismatch());
    }
    for domain in declared_domains {
        if !identities
            .iter()
            .any(|identity| certificate_identity_covers_domain(identity, domain))
        {
            return Err(certificate_identity_mismatch());
        }
    }
    Ok(())
}

fn normalize_certificate_dns_identity(identity: &str) -> Option<String> {
    let normalized = normalize_host(identity);
    if normalized.is_empty()
        || normalized.contains(char::is_whitespace)
        || normalized.contains('/')
        || normalized == "*"
    {
        return None;
    }
    if let Some(suffix) = normalized.strip_prefix("*.") {
        if suffix.is_empty() || suffix.contains('*') {
            return None;
        }
        return Some(format!("*.{suffix}"));
    }
    (!normalized.contains('*')).then_some(normalized)
}

fn certificate_identity_covers_domain(identity: &str, domain: &str) -> bool {
    if let Some(suffix) = identity.strip_prefix("*.") {
        let Some(prefix) = domain.strip_suffix(&format!(".{suffix}")) else {
            return false;
        };
        return !prefix.is_empty() && !prefix.contains('.');
    }
    identity == domain
}

fn certificate_identity_mismatch() -> AppError {
    AppError::new(
        ErrorCode::CertificateInvalid,
        "certificate identity does not cover declared domain",
    )
}

fn restore_certificate<S: CertificateStore + ?Sized>(
    store: &mut S,
    previous: Option<StoredCertificate>,
    certificate_ref: &CertificateRef,
) -> Option<AppError> {
    let result = match previous {
        Some(previous) => store.save_certificate(previous),
        None => store.delete_certificate(certificate_ref),
    };
    result.err()
}

fn transition_or_failure(
    machine: &mut CertificateImportMachine,
    event: CertificateImportEvent,
) -> Result<(), ManualCertificateImportFailure> {
    machine
        .transition(event)
        .map_err(|error| import_failure(machine, error, None))
}

fn import_failure(
    machine: &mut CertificateImportMachine,
    error: AppError,
    compensation_error: Option<AppError>,
) -> ManualCertificateImportFailure {
    let compensation_failed = compensation_error.is_some();
    let _ = machine.transition(CertificateImportEvent::Failed {
        error_code: error.code,
        compensation_failed,
    });
    ManualCertificateImportFailure {
        state: machine.state().clone(),
        error,
        compensation_error,
    }
}
