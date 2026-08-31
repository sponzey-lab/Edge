//! Stable application-error projection for config validation failures.

use edge_domain::{AppError, ErrorCode, ValidationError};

pub(crate) fn validation_errors_to_app_error(errors: &[ValidationError]) -> AppError {
    let first = errors.first().cloned().unwrap_or_else(|| {
        ValidationError::new(ErrorCode::InternalBug, "unknown validation error")
    });
    AppError::new(first.code, first.message)
}
