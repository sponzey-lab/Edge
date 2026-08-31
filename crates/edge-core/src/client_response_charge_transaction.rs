//! Client-response payload reservation, commit, and rollback transaction helpers.

use edge_domain::AppError;

use crate::payload_budget_ledger::resource_accounting_error;
use crate::{PayloadBudgetLedger, PayloadClass, ResourceChargeId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientResponseChargeChange {
    pub(crate) charge_id: ResourceChargeId,
    pub(crate) previous_bytes: Option<usize>,
    pub(crate) next_bytes: usize,
}

pub(crate) fn resize_in_use(
    slot: &mut Option<ResourceChargeId>,
    ledger: &mut PayloadBudgetLedger,
    next_bytes: usize,
) -> Result<(), AppError> {
    let Some(charge_id) = *slot else {
        return ledger.fail_accounting("client response charge is not installed");
    };
    if next_bytes == 0 {
        ledger.release(charge_id, ledger.generation())?;
        *slot = None;
        Ok(())
    } else {
        ledger.resize(charge_id, next_bytes, ledger.generation())
    }
}

pub(crate) fn prepare(
    slot: &mut Option<ResourceChargeId>,
    ledger: &mut PayloadBudgetLedger,
    connection_id: usize,
    next_bytes: usize,
) -> Result<ClientResponseChargeChange, AppError> {
    let generation = ledger.generation();
    if let Some(charge_id) = *slot {
        let previous_bytes = ledger
            .charge(charge_id)
            .map(|charge| charge.charged_bytes())
            .ok_or_else(|| resource_accounting_error("client response charge disappeared"))?;
        ledger.resize(charge_id, next_bytes, generation)?;
        Ok(ClientResponseChargeChange {
            charge_id,
            previous_bytes: Some(previous_bytes),
            next_bytes,
        })
    } else {
        let charge_id = ledger.reserve(
            connection_id,
            PayloadClass::ClientResponse,
            next_bytes,
            generation,
        )?;
        *slot = Some(charge_id);
        Ok(ClientResponseChargeChange {
            charge_id,
            previous_bytes: None,
            next_bytes,
        })
    }
}

pub(crate) fn commit(
    slot: Option<ResourceChargeId>,
    ledger: &mut PayloadBudgetLedger,
    change: ClientResponseChargeChange,
) -> Result<(), AppError> {
    if slot != Some(change.charge_id) {
        return ledger.fail_accounting("client response change is not current");
    }
    if change.previous_bytes.is_none() {
        ledger.commit(change.charge_id, change.next_bytes, ledger.generation())?;
    }
    Ok(())
}

pub(crate) fn rollback(
    slot: &mut Option<ResourceChargeId>,
    ledger: &mut PayloadBudgetLedger,
    change: ClientResponseChargeChange,
) -> Result<(), AppError> {
    if *slot != Some(change.charge_id) {
        return ledger.fail_accounting("client response rollback is not current");
    }
    let generation = ledger.generation();
    if let Some(previous_bytes) = change.previous_bytes {
        ledger.resize(change.charge_id, previous_bytes, generation)
    } else {
        ledger.release_after_allocation_failure(change.charge_id, generation)?;
        *slot = None;
        Ok(())
    }
}
