//! Atomic upstream-request and retry-replay payload charge-pair operations.

use edge_domain::AppError;

use crate::{PayloadBudgetLedger, PayloadClass, ResourceChargeId};

pub(crate) fn reserve(
    upstream_slot: &mut Option<ResourceChargeId>,
    retry_replay_slot: &mut Option<ResourceChargeId>,
    ledger: &mut PayloadBudgetLedger,
    connection_id: usize,
    upstream_bytes: usize,
    retry_replay_bytes: usize,
) -> Result<(), AppError> {
    if upstream_slot.is_some() || retry_replay_slot.is_some() {
        return ledger.fail_accounting("upstream payload charges are already installed");
    }
    let generation = ledger.generation();
    let upstream = ledger.reserve(
        connection_id,
        PayloadClass::UpstreamRequest,
        upstream_bytes,
        generation,
    )?;
    let retry_replay = match ledger.reserve(
        connection_id,
        PayloadClass::RetryReplay,
        retry_replay_bytes,
        generation,
    ) {
        Ok(charge_id) => charge_id,
        Err(error) => {
            ledger.release(upstream, generation)?;
            return Err(error);
        }
    };
    *upstream_slot = Some(upstream);
    *retry_replay_slot = Some(retry_replay);
    Ok(())
}

pub(crate) fn commit(
    upstream_slot: Option<ResourceChargeId>,
    retry_replay_slot: Option<ResourceChargeId>,
    ledger: &mut PayloadBudgetLedger,
    upstream_bytes: usize,
    retry_replay_bytes: usize,
) -> Result<(), AppError> {
    let generation = ledger.generation();
    let Some(upstream) = upstream_slot else {
        return ledger.fail_accounting("upstream charge is not installed");
    };
    let Some(retry_replay) = retry_replay_slot else {
        return ledger.fail_accounting("retry replay charge is not installed");
    };
    ledger.commit(upstream, upstream_bytes, generation)?;
    ledger.commit(retry_replay, retry_replay_bytes, generation)
}

pub(crate) fn release_after_allocation_failure(
    upstream_slot: &mut Option<ResourceChargeId>,
    retry_replay_slot: &mut Option<ResourceChargeId>,
    ledger: &mut PayloadBudgetLedger,
) -> Result<(), AppError> {
    let generation = ledger.generation();
    if let Some(upstream) = *upstream_slot {
        ledger.release_after_allocation_failure(upstream, generation)?;
        *upstream_slot = None;
    }
    if let Some(retry_replay) = *retry_replay_slot {
        ledger.release(retry_replay, generation)?;
        *retry_replay_slot = None;
    }
    Ok(())
}
