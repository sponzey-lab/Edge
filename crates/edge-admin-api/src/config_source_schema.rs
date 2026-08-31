//! Admin config source parsing and validation schema adaptation.

use edge_application::{parse_mvp_config, ConfigValidator, ValidationReport};
use edge_domain::{ConfigRevisionId, ConfigSnapshot, ValidationError};

pub fn validate_config(snapshot: &ConfigSnapshot) -> ValidationReport {
    ConfigValidator::default().validate_snapshot(snapshot)
}

pub fn validate_config_source(source: &str) -> Vec<ValidationError> {
    match parse_valid_config_source(source, ConfigRevisionId::new("candidate")) {
        Ok(_) => Vec::new(),
        Err(errors) => errors,
    }
}

pub fn parse_valid_config_source(
    source: &str,
    revision_id: ConfigRevisionId,
) -> Result<ConfigSnapshot, Vec<ValidationError>> {
    let parsed = parse_mvp_config(source, revision_id)
        .map_err(|error| vec![ValidationError::new(error.code, error.message)])?;
    let report = validate_config(&parsed.snapshot);
    if report.is_valid() {
        Ok(parsed.snapshot)
    } else {
        Err(report.errors)
    }
}
