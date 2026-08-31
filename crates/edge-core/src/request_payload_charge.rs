//! Request payload charge-slot growth and terminal release helpers.

use edge_domain::AppError;

use crate::{PayloadBudgetLedger, PayloadClass, ResourceChargeId};

pub(crate) fn grow(
    slot: &mut Option<ResourceChargeId>,
    ledger: &mut PayloadBudgetLedger,
    connection_id: usize,
    additional_bytes: usize,
) -> Result<(), AppError> {
    if additional_bytes == 0 {
        return Ok(());
    }
    let generation = ledger.generation();
    if let Some(charge_id) = *slot {
        ledger.grow(charge_id, additional_bytes, generation)
    } else {
        let charge_id = ledger.reserve(
            connection_id,
            PayloadClass::Request,
            additional_bytes,
            generation,
        )?;
        *slot = Some(charge_id);
        Ok(())
    }
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
