//! Retry and passive-health draft normalization for MVP configuration input.

use std::collections::BTreeMap;

use edge_domain::{
    AppError, ErrorCode, PassiveHealthMode, PassiveHealthPolicy, RetryPolicy, Service,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RetryPolicyDraft {
    pub(crate) enabled: Option<bool>,
    pub(crate) max_retries: Option<u8>,
    pub(crate) max_replay_bytes: Option<u64>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct PassiveHealthPolicyDraft {
    pub(crate) enabled: Option<bool>,
    pub(crate) failure_threshold: Option<u8>,
    pub(crate) ejection_ms: Option<u64>,
}

pub(crate) fn normalize_failure_policies(
    services: &mut [Service],
    retries: &BTreeMap<usize, RetryPolicyDraft>,
    passive: &BTreeMap<usize, PassiveHealthPolicyDraft>,
) -> Result<(), AppError> {
    for (&index, draft) in retries {
        let service = services.get_mut(index).ok_or_else(|| {
            AppError::new(
                ErrorCode::InternalBug,
                "retry draft references missing service",
            )
        })?;
        let defaults = RetryPolicy::default();
        service.policy.retry = RetryPolicy::new(
            draft.enabled.unwrap_or(false),
            draft.max_retries.unwrap_or(defaults.max_retries),
            draft.max_replay_bytes.unwrap_or(defaults.max_replay_bytes),
        )
        .map_err(|error| AppError::new(error.code, error.message))?;
    }
    for (&index, draft) in passive {
        let service = services.get_mut(index).ok_or_else(|| {
            AppError::new(
                ErrorCode::InternalBug,
                "passive health draft references missing service",
            )
        })?;
        if draft.enabled.unwrap_or(false) {
            service.policy.passive_health = PassiveHealthMode::Enabled(
                PassiveHealthPolicy::new(
                    draft.failure_threshold.unwrap_or(3),
                    draft.ejection_ms.unwrap_or(30_000),
                )
                .map_err(|error| AppError::new(error.code, error.message))?,
            );
        }
    }
    Ok(())
}
