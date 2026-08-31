//! TLS pending payload charge-slot synchronization.

use edge_domain::AppError;

use crate::payload_charge_slot;
use crate::{PayloadBudgetLedger, PayloadClass, ResourceChargeId};

pub(crate) fn bytes(ledger: &PayloadBudgetLedger, slot: Option<ResourceChargeId>) -> usize {
    payload_charge_slot::bytes(ledger, slot)
}

pub(crate) fn sync(
    slot: &mut Option<ResourceChargeId>,
    ledger: &mut PayloadBudgetLedger,
    connection_id: usize,
    next_bytes: usize,
) -> Result<bool, AppError> {
    payload_charge_slot::sync(
        slot,
        PayloadClass::TlsPending,
        ledger,
        connection_id,
        next_bytes,
    )
}
