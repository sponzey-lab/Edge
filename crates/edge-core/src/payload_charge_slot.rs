//! Generic payload charge-slot lookup, synchronization, and release helpers.

use edge_domain::AppError;

use crate::{PayloadBudgetLedger, PayloadClass, ResourceChargeId};

pub(crate) fn sync(
    slot: &mut Option<ResourceChargeId>,
    payload_class: PayloadClass,
    ledger: &mut PayloadBudgetLedger,
    connection_id: usize,
    next_bytes: usize,
) -> Result<bool, AppError> {
    let current_bytes = bytes(ledger, *slot);
    if current_bytes == next_bytes {
        return Ok(false);
    }
    if next_bytes == 0 {
        release(slot, ledger)?;
        return Ok(true);
    }
    if let Some(charge_id) = *slot {
        ledger.resize(charge_id, next_bytes, ledger.generation())?;
        return Ok(true);
    }
    let generation = ledger.generation();
    let charge_id = ledger.reserve(connection_id, payload_class, next_bytes, generation)?;
    if let Err(error) = ledger.commit(charge_id, next_bytes, generation) {
        let _ = ledger.release(charge_id, generation);
        return Err(error);
    }
    *slot = Some(charge_id);
    Ok(true)
}

pub(crate) fn bytes(ledger: &PayloadBudgetLedger, charge_id: Option<ResourceChargeId>) -> usize {
    charge_id
        .and_then(|charge_id| ledger.charge(charge_id))
        .map(|charge| charge.charged_bytes())
        .unwrap_or(0)
}

pub(crate) fn release(
    slot: &mut Option<ResourceChargeId>,
    ledger: &mut PayloadBudgetLedger,
) -> Result<(), AppError> {
    let Some(charge_id) = *slot else {
        return Ok(());
    };
    ledger.release(charge_id, ledger.generation())?;
    *slot = None;
    Ok(())
}
