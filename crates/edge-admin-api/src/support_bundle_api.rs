//! Fixed-allowlist support-bundle API projection and HTTP response adaptation.

use edge_application::{default_support_bundle_bounds, CollectSupportBundleUseCase};
use edge_domain::{AppError, ErrorCode, SupportBundleArtifact};
use edge_ports::{SupportBundleCollector, SupportBundleRequest};

use crate::{
    json_escape, require_csrf, require_session, AdminHttpRequest, AdminHttpResponse, SessionStore,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundleResponse {
    pub archive_id: String,
    pub digest_sha256: String,
    pub collected_artifacts: Vec<String>,
    pub omitted_artifacts: Vec<String>,
    pub total_bytes: u64,
}

/// Creates a bundle with the fixed product allowlist; caller-controlled paths,
/// artifact lists, bounds, service actions, and archive locations are not accepted.
pub fn create_support_bundle<C: SupportBundleCollector>(
    sessions: &SessionStore,
    session_id: Option<&str>,
    csrf_token: Option<&str>,
    collector: C,
) -> Result<SupportBundleResponse, AppError> {
    require_session(sessions, session_id)?;
    let session_id = session_id.expect("session checked above");
    require_csrf(sessions, session_id, csrf_token)?;
    let mut use_case = CollectSupportBundleUseCase::new(collector);
    let report = use_case.execute(SupportBundleRequest {
        artifacts: vec![
            SupportBundleArtifact::VersionManifest,
            SupportBundleArtifact::MaskedConfig,
            SupportBundleArtifact::BoundedProductLog,
            SupportBundleArtifact::HealthSummary,
            SupportBundleArtifact::ResourceSummary,
            SupportBundleArtifact::AuditSummary,
        ],
        bounds: default_support_bundle_bounds(),
    })?;
    Ok(SupportBundleResponse {
        archive_id: report.archive.archive_id,
        digest_sha256: hex_encode(&report.archive.digest_sha256),
        collected_artifacts: report
            .collected_artifacts
            .into_iter()
            .map(support_artifact_name)
            .map(str::to_string)
            .collect(),
        omitted_artifacts: report
            .omissions
            .into_iter()
            .map(|omission| support_artifact_name(omission.artifact).to_string())
            .collect(),
        total_bytes: report.total_bytes,
    })
}

pub fn handle_support_bundle_http<C: SupportBundleCollector>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    collector: C,
) -> AdminHttpResponse {
    match create_support_bundle(
        sessions,
        request.session_id.as_deref(),
        request.csrf_token.as_deref(),
        collector,
    ) {
        Ok(response) => AdminHttpResponse::json(200, support_bundle_response_json(&response)),
        Err(error) => {
            let status = match error.code {
                ErrorCode::AdminAuthRequired => 401,
                ErrorCode::AdminCsrfRequired => 403,
                _ => 422,
            };
            AdminHttpResponse::from_error(status, error, &request.request_id)
        }
    }
}

fn support_bundle_response_json(response: &SupportBundleResponse) -> String {
    let string_array = |values: &[String]| {
        values
            .iter()
            .map(|value| format!("\"{}\"", json_escape(value)))
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "{{\"archive_id\":\"{}\",\"digest_sha256\":\"{}\",\"collected_artifacts\":[{}],\"omitted_artifacts\":[{}],\"total_bytes\":{}}}",
        json_escape(&response.archive_id),
        response.digest_sha256,
        string_array(&response.collected_artifacts),
        string_array(&response.omitted_artifacts),
        response.total_bytes,
    )
}

fn support_artifact_name(artifact: SupportBundleArtifact) -> &'static str {
    match artifact {
        SupportBundleArtifact::VersionManifest => "version_manifest",
        SupportBundleArtifact::MaskedConfig => "masked_config",
        SupportBundleArtifact::BoundedProductLog => "bounded_product_log",
        SupportBundleArtifact::HealthSummary => "health_summary",
        SupportBundleArtifact::ResourceSummary => "resource_summary",
        SupportBundleArtifact::AuditSummary => "audit_summary",
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
