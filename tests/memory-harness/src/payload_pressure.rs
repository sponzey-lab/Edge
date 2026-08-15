use std::collections::BTreeMap;

use crate::HarnessError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadPressureState {
    Ready,
    Holding,
    RejectionObserved,
    Recovered,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadPressureResult {
    pub held_connections: usize,
    pub held_payload_bytes: usize,
    pub rejection_metric: u64,
    pub product_events: u64,
    pub recovery_status: u16,
}

pub struct PayloadPressureScenario {
    expected_connections: usize,
    pressure_threshold_bytes: usize,
    state: PayloadPressureState,
    held_payload_bytes: usize,
    rejection_metric: u64,
    product_events: u64,
}

impl PayloadPressureScenario {
    pub fn new(
        expected_connections: usize,
        payload_limit_bytes: usize,
    ) -> Result<Self, HarnessError> {
        if expected_connections == 0 || payload_limit_bytes == 0 {
            return Err(HarnessError::new("payload pressure scenario is invalid"));
        }
        let pressure_threshold_bytes = payload_limit_bytes
            .checked_mul(80)
            .and_then(|value| value.checked_add(99))
            .map(|value| value / 100)
            .ok_or_else(|| HarnessError::new("payload pressure threshold overflow"))?;
        Ok(Self {
            expected_connections,
            pressure_threshold_bytes,
            state: PayloadPressureState::Ready,
            held_payload_bytes: 0,
            rejection_metric: 0,
            product_events: 0,
        })
    }

    pub fn state(&self) -> PayloadPressureState {
        self.state
    }

    pub fn observe_hold(
        &mut self,
        active_connections: usize,
        used_payload_bytes: usize,
        pressure: &str,
    ) -> Result<(), HarnessError> {
        if self.state != PayloadPressureState::Ready
            || active_connections != self.expected_connections
            || used_payload_bytes < self.pressure_threshold_bytes
            || pressure != "pressured"
        {
            return self.fail("payload pressure hold observation is invalid");
        }
        self.held_payload_bytes = used_payload_bytes;
        self.state = PayloadPressureState::Holding;
        Ok(())
    }

    pub fn observe_rejection(
        &mut self,
        preserved_connections: usize,
        metric_value: u64,
        product_events: u64,
        resource_kind: &str,
        reason: &str,
    ) -> Result<(), HarnessError> {
        if self.state != PayloadPressureState::Holding
            || preserved_connections != self.expected_connections
            || metric_value == 0
            || product_events == 0
            || resource_kind != "payload"
            || reason != "payload_pressure"
        {
            return self.fail("payload pressure rejection observation is invalid");
        }
        self.rejection_metric = metric_value;
        self.product_events = product_events;
        self.state = PayloadPressureState::RejectionObserved;
        Ok(())
    }

    pub fn observe_recovery(
        &mut self,
        final_connections: usize,
        final_payload_bytes: usize,
        final_pressure: &str,
        recovery_status: u16,
    ) -> Result<PayloadPressureResult, HarnessError> {
        if self.state != PayloadPressureState::RejectionObserved
            || final_connections != 0
            || final_payload_bytes != 0
            || final_pressure != "normal"
            || recovery_status != 200
        {
            return self.fail("payload pressure recovery observation is invalid");
        }
        self.state = PayloadPressureState::Recovered;
        Ok(PayloadPressureResult {
            held_connections: self.expected_connections,
            held_payload_bytes: self.held_payload_bytes,
            rejection_metric: self.rejection_metric,
            product_events: self.product_events,
            recovery_status,
        })
    }

    fn fail<T>(&mut self, message: &str) -> Result<T, HarnessError> {
        self.state = PayloadPressureState::Failed;
        Err(HarnessError::new(message))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadPressureOptions {
    pub expected_connections: usize,
    pub payload_limit_bytes: usize,
    pub held_connections: usize,
    pub held_payload_bytes: usize,
    pub held_pressure: String,
    pub preserved_connections: usize,
    pub metric_value: u64,
    pub product_events: u64,
    pub resource_kind: String,
    pub reason: String,
    pub final_connections: usize,
    pub final_payload_bytes: usize,
    pub final_pressure: String,
    pub recovery_status: u16,
}

pub fn parse_payload_pressure_options(
    args: &[String],
) -> Result<PayloadPressureOptions, HarnessError> {
    const KEYS: [&str; 14] = [
        "--expected-connections",
        "--payload-limit-bytes",
        "--held-connections",
        "--held-payload-bytes",
        "--held-pressure",
        "--preserved-connections",
        "--metric-value",
        "--product-events",
        "--resource-kind",
        "--reason",
        "--final-connections",
        "--final-payload-bytes",
        "--final-pressure",
        "--recovery-status",
    ];
    if args.len() != KEYS.len() * 2 || !args.len().is_multiple_of(2) {
        return Err(HarnessError::new(
            "payload pressure arguments are incomplete",
        ));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "payload pressure argument is unknown or duplicated",
            ));
        }
    }
    Ok(PayloadPressureOptions {
        expected_connections: positive_usize(&values, "--expected-connections")?,
        payload_limit_bytes: positive_usize(&values, "--payload-limit-bytes")?,
        held_connections: positive_usize(&values, "--held-connections")?,
        held_payload_bytes: positive_usize(&values, "--held-payload-bytes")?,
        held_pressure: required(&values, "--held-pressure")?,
        preserved_connections: positive_usize(&values, "--preserved-connections")?,
        metric_value: positive(&values, "--metric-value")?,
        product_events: positive(&values, "--product-events")?,
        resource_kind: required(&values, "--resource-kind")?,
        reason: required(&values, "--reason")?,
        final_connections: nonnegative_usize(&values, "--final-connections")?,
        final_payload_bytes: nonnegative_usize(&values, "--final-payload-bytes")?,
        final_pressure: required(&values, "--final-pressure")?,
        recovery_status: positive(&values, "--recovery-status")?
            .try_into()
            .map_err(|_| HarnessError::new("payload pressure status exceeds u16"))?,
    })
}

pub fn evaluate_payload_pressure(options: PayloadPressureOptions) -> Result<String, HarnessError> {
    let mut scenario =
        PayloadPressureScenario::new(options.expected_connections, options.payload_limit_bytes)?;
    scenario.observe_hold(
        options.held_connections,
        options.held_payload_bytes,
        &options.held_pressure,
    )?;
    scenario.observe_rejection(
        options.preserved_connections,
        options.metric_value,
        options.product_events,
        &options.resource_kind,
        &options.reason,
    )?;
    let result = scenario.observe_recovery(
        options.final_connections,
        options.final_payload_bytes,
        &options.final_pressure,
        options.recovery_status,
    )?;
    Ok(format!(
        "payload pressure passed held={} payload={} metric={} product_events={} recovery_status={}",
        result.held_connections,
        result.held_payload_bytes,
        result.rejection_metric,
        result.product_events,
        result.recovery_status
    ))
}

fn positive_usize(values: &BTreeMap<String, String>, key: &str) -> Result<usize, HarnessError> {
    positive(values, key)?
        .try_into()
        .map_err(|_| HarnessError::new("payload pressure value exceeds usize"))
}

fn nonnegative_usize(values: &BTreeMap<String, String>, key: &str) -> Result<usize, HarnessError> {
    required(values, key)?
        .parse::<usize>()
        .map_err(|_| HarnessError::new("payload pressure value is invalid"))
}

fn positive(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    let value = required(values, key)?
        .parse::<u64>()
        .map_err(|_| HarnessError::new("payload pressure value is invalid"))?;
    if value == 0 {
        return Err(HarnessError::new("payload pressure value must be positive"));
    }
    Ok(value)
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("payload pressure argument is missing: {key}")))
}
