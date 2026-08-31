//! Logical payload accounting with generation checks and fail-closed pressure control.

use std::collections::BTreeMap;

use edge_domain::{AppError, ErrorCode, ResourceChargeState, RuntimeResourcePolicy};

use crate::ResourcePressureState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourceChargeId(u64);

impl ResourceChargeId {
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadClass {
    Request,
    UpstreamRequest,
    RetryReplay,
    ClientResponse,
    WebSocketClientToUpstream,
    WebSocketUpstreamToClient,
    TlsPending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadCharge {
    id: ResourceChargeId,
    connection_id: usize,
    payload_class: PayloadClass,
    charged_bytes: usize,
    generation: u64,
    state: ResourceChargeState,
}

impl PayloadCharge {
    pub fn id(self) -> ResourceChargeId {
        self.id
    }

    pub fn connection_id(self) -> usize {
        self.connection_id
    }

    pub fn payload_class(self) -> PayloadClass {
        self.payload_class
    }

    pub fn charged_bytes(self) -> usize {
        self.charged_bytes
    }

    pub fn generation(self) -> u64 {
        self.generation
    }

    pub fn state(self) -> ResourceChargeState {
        self.state
    }
}

#[derive(Debug)]
pub struct PayloadBudgetLedger {
    limit_bytes: usize,
    used_bytes: usize,
    generation: u64,
    next_charge_id: u64,
    charges: BTreeMap<ResourceChargeId, PayloadCharge>,
    pressure_state: ResourcePressureState,
}

impl PayloadBudgetLedger {
    pub fn new(policy: RuntimeResourcePolicy, generation: u64) -> Self {
        Self {
            limit_bytes: policy.max_inflight_payload_bytes(),
            used_bytes: 0,
            generation,
            next_charge_id: 1,
            charges: BTreeMap::new(),
            pressure_state: ResourcePressureState::Normal,
        }
    }

    pub fn limit_bytes(&self) -> usize {
        self.limit_bytes
    }

    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn live_charge_count(&self) -> usize {
        self.charges.len()
    }

    pub fn pressure_state(&self) -> ResourcePressureState {
        self.pressure_state
    }

    pub fn charge(&self, id: ResourceChargeId) -> Option<&PayloadCharge> {
        self.charges.get(&id)
    }

    pub fn reserve(
        &mut self,
        connection_id: usize,
        payload_class: PayloadClass,
        requested_bytes: usize,
        generation: u64,
    ) -> Result<ResourceChargeId, AppError> {
        if self.pressure_state == ResourcePressureState::FailedClosed {
            return Err(resource_accounting_error(
                "resource admission is failed closed",
            ));
        }
        self.require_generation(generation)?;
        if requested_bytes == 0 {
            return self.fail_accounting("zero-byte resource charge is not allowed");
        }
        let next_used = self
            .used_bytes
            .checked_add(requested_bytes)
            .ok_or_else(resource_capacity_error)?;
        if next_used > self.limit_bytes {
            self.pressure_state = ResourcePressureState::Exhausted;
            return Err(resource_capacity_error());
        }
        let next_charge_id = self.next_charge_id.checked_add(1).ok_or_else(|| {
            self.pressure_state = ResourcePressureState::FailedClosed;
            resource_accounting_error("resource charge identity exhausted")
        })?;
        let id = ResourceChargeId(self.next_charge_id);
        self.next_charge_id = next_charge_id;
        self.used_bytes = next_used;
        self.charges.insert(
            id,
            PayloadCharge {
                id,
                connection_id,
                payload_class,
                charged_bytes: requested_bytes,
                generation,
                state: ResourceChargeState::Granted,
            },
        );
        self.refresh_pressure_after_usage_change();
        Ok(id)
    }

    pub fn commit(
        &mut self,
        id: ResourceChargeId,
        actual_logical_bytes: usize,
        generation: u64,
    ) -> Result<(), AppError> {
        self.require_generation(generation)?;
        let charge = self.live_charge(id, generation)?;
        if charge.state != ResourceChargeState::Granted {
            return self.fail_accounting("only granted charges can be committed");
        }
        self.replace_charge_bytes(id, actual_logical_bytes)?;
        let Some(charge) = self.charges.get_mut(&id) else {
            return self.fail_accounting("committed resource charge disappeared");
        };
        charge.state = ResourceChargeState::InUse;
        Ok(())
    }

    pub fn resize(
        &mut self,
        id: ResourceChargeId,
        next_logical_bytes: usize,
        generation: u64,
    ) -> Result<(), AppError> {
        self.require_generation(generation)?;
        let charge = self.live_charge(id, generation)?;
        if !matches!(
            charge.state,
            ResourceChargeState::Granted
                | ResourceChargeState::InUse
                | ResourceChargeState::Transferred
        ) {
            return self.fail_accounting("charge cannot be resized in its current state");
        }
        self.replace_charge_bytes(id, next_logical_bytes)
    }

    pub fn grow(
        &mut self,
        id: ResourceChargeId,
        additional_bytes: usize,
        generation: u64,
    ) -> Result<(), AppError> {
        self.require_generation(generation)?;
        if additional_bytes == 0 {
            return Ok(());
        }
        let charge = self.live_charge(id, generation)?;
        let Some(next_logical_bytes) = charge.charged_bytes.checked_add(additional_bytes) else {
            self.pressure_state = ResourcePressureState::Exhausted;
            return Err(resource_capacity_error());
        };
        self.resize(id, next_logical_bytes, generation)
    }

    pub fn transfer(
        &mut self,
        id: ResourceChargeId,
        next_connection_id: usize,
        next_payload_class: PayloadClass,
        generation: u64,
    ) -> Result<(), AppError> {
        self.require_generation(generation)?;
        let charge = self.live_charge(id, generation)?;
        if !matches!(
            charge.state,
            ResourceChargeState::Granted
                | ResourceChargeState::InUse
                | ResourceChargeState::Transferred
        ) {
            return self.fail_accounting("charge cannot be transferred in its current state");
        }
        let Some(charge) = self.charges.get_mut(&id) else {
            return self.fail_accounting("transferred resource charge disappeared");
        };
        charge.connection_id = next_connection_id;
        charge.payload_class = next_payload_class;
        charge.state = ResourceChargeState::Transferred;
        Ok(())
    }

    pub fn release(&mut self, id: ResourceChargeId, generation: u64) -> Result<(), AppError> {
        self.require_generation(generation)?;
        self.remove_live_charge(id, generation, ResourceChargeState::Released)?;
        Ok(())
    }

    pub fn release_after_allocation_failure(
        &mut self,
        id: ResourceChargeId,
        generation: u64,
    ) -> Result<(), AppError> {
        self.require_generation(generation)?;
        self.remove_live_charge(id, generation, ResourceChargeState::AllocationFailed)?;
        Ok(())
    }

    fn require_generation(&mut self, generation: u64) -> Result<(), AppError> {
        if generation != self.generation {
            return self.fail_accounting("resource generation is stale");
        }
        Ok(())
    }

    fn live_charge(
        &mut self,
        id: ResourceChargeId,
        generation: u64,
    ) -> Result<PayloadCharge, AppError> {
        let Some(charge) = self.charges.get(&id).copied() else {
            return self.fail_accounting("resource charge is not live");
        };
        if charge.generation != generation || charge.state.is_terminal() {
            return self.fail_accounting("resource charge identity is invalid");
        }
        Ok(charge)
    }

    fn replace_charge_bytes(
        &mut self,
        id: ResourceChargeId,
        next_logical_bytes: usize,
    ) -> Result<(), AppError> {
        if next_logical_bytes == 0 {
            return self.fail_accounting("live resource charge cannot be resized to zero");
        }
        let Some(previous_bytes) = self.charges.get(&id).map(|charge| charge.charged_bytes) else {
            return self.fail_accounting("resized resource charge disappeared");
        };
        let without_previous = self.used_bytes.checked_sub(previous_bytes).ok_or_else(|| {
            self.pressure_state = ResourcePressureState::FailedClosed;
            resource_accounting_error("resource total is below live charge")
        })?;
        let next_used = without_previous
            .checked_add(next_logical_bytes)
            .ok_or_else(resource_capacity_error)?;
        if next_used > self.limit_bytes {
            self.pressure_state = ResourcePressureState::Exhausted;
            return Err(resource_capacity_error());
        }
        self.used_bytes = next_used;
        let Some(charge) = self.charges.get_mut(&id) else {
            return self.fail_accounting("resized resource charge disappeared");
        };
        charge.charged_bytes = next_logical_bytes;
        self.refresh_pressure_after_usage_change();
        Ok(())
    }

    fn remove_live_charge(
        &mut self,
        id: ResourceChargeId,
        generation: u64,
        terminal_state: ResourceChargeState,
    ) -> Result<PayloadCharge, AppError> {
        debug_assert!(terminal_state.is_terminal());
        let charge = self.live_charge(id, generation)?;
        let Some(next_used) = self.used_bytes.checked_sub(charge.charged_bytes) else {
            return self.fail_accounting("resource release exceeds current total");
        };
        let Some(live_charge) = self.charges.get_mut(&id) else {
            return self.fail_accounting("released resource charge disappeared");
        };
        live_charge.state = terminal_state;
        self.charges.remove(&id);
        self.used_bytes = next_used;
        self.refresh_pressure_after_usage_change();
        Ok(charge)
    }

    fn refresh_pressure_after_usage_change(&mut self) {
        if self.pressure_state == ResourcePressureState::FailedClosed {
            return;
        }
        let high_watermark = self.limit_bytes * 80 / 100;
        let low_watermark = self.limit_bytes * 60 / 100;
        self.pressure_state = match self.pressure_state {
            ResourcePressureState::Normal if self.used_bytes < high_watermark => {
                ResourcePressureState::Normal
            }
            ResourcePressureState::Pressured | ResourcePressureState::Exhausted
                if self.used_bytes <= low_watermark =>
            {
                ResourcePressureState::Normal
            }
            ResourcePressureState::Normal
            | ResourcePressureState::Pressured
            | ResourcePressureState::Exhausted => ResourcePressureState::Pressured,
            ResourcePressureState::FailedClosed => ResourcePressureState::FailedClosed,
        };
    }

    pub(crate) fn fail_accounting<T>(&mut self, message: &'static str) -> Result<T, AppError> {
        self.pressure_state = ResourcePressureState::FailedClosed;
        Err(resource_accounting_error(message))
    }
}

fn resource_capacity_error() -> AppError {
    AppError::new(
        ErrorCode::ResourcePayloadCapacityReached,
        "logical payload capacity reached",
    )
}

pub(crate) fn resource_accounting_error(message: &'static str) -> AppError {
    AppError::new(ErrorCode::ResourceAccountingInvariantFailed, message)
}
