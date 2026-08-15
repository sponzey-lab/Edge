use std::collections::BTreeMap;

use crate::HarnessError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateHttpsState {
    Ready,
    Loaded,
    NegativesVerified,
    Recovered,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateHttpsResult {
    pub succeeded: usize,
    pub rejected_negatives: usize,
    pub recovery_status: u16,
}

pub struct PrivateHttpsScenario {
    expected: usize,
    expected_negatives: usize,
    state: PrivateHttpsState,
}

impl PrivateHttpsScenario {
    pub fn new(expected: usize, expected_negatives: usize) -> Result<Self, HarnessError> {
        if expected == 0 || expected_negatives == 0 {
            return Err(HarnessError::new("private HTTPS scenario is invalid"));
        }
        Ok(Self {
            expected,
            expected_negatives,
            state: PrivateHttpsState::Ready,
        })
    }

    pub fn state(&self) -> PrivateHttpsState {
        self.state
    }

    pub fn observe_load(&mut self, succeeded: usize, failed: usize) -> Result<(), HarnessError> {
        if self.state != PrivateHttpsState::Ready || succeeded != self.expected || failed != 0 {
            return self.fail("private HTTPS load observation is invalid");
        }
        self.state = PrivateHttpsState::Loaded;
        Ok(())
    }

    pub fn observe_negatives(
        &mut self,
        rejected: usize,
        accepted: usize,
    ) -> Result<(), HarnessError> {
        if self.state != PrivateHttpsState::Loaded
            || rejected != self.expected_negatives
            || accepted != 0
        {
            return self.fail("private HTTPS negative observation is invalid");
        }
        self.state = PrivateHttpsState::NegativesVerified;
        Ok(())
    }

    pub fn observe_recovery(
        &mut self,
        final_connections: usize,
        final_payload: usize,
        final_pressure: &str,
        recovery_status: u16,
    ) -> Result<PrivateHttpsResult, HarnessError> {
        if self.state != PrivateHttpsState::NegativesVerified
            || final_connections != 0
            || final_payload != 0
            || final_pressure != "normal"
            || recovery_status != 200
        {
            return self.fail("private HTTPS recovery observation is invalid");
        }
        self.state = PrivateHttpsState::Recovered;
        Ok(PrivateHttpsResult {
            succeeded: self.expected,
            rejected_negatives: self.expected_negatives,
            recovery_status,
        })
    }

    fn fail<T>(&mut self, message: &str) -> Result<T, HarnessError> {
        self.state = PrivateHttpsState::Failed;
        Err(HarnessError::new(message))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateHttpsOptions {
    pub expected: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub expected_negatives: usize,
    pub rejected_negatives: usize,
    pub accepted_negatives: usize,
    pub final_connections: usize,
    pub final_payload: usize,
    pub final_pressure: String,
    pub recovery_status: u16,
}

pub fn parse_private_https_options(args: &[String]) -> Result<PrivateHttpsOptions, HarnessError> {
    const KEYS: [&str; 10] = [
        "--expected",
        "--succeeded",
        "--failed",
        "--expected-negatives",
        "--rejected-negatives",
        "--accepted-negatives",
        "--final-connections",
        "--final-payload",
        "--final-pressure",
        "--recovery-status",
    ];
    if args.len() != KEYS.len() * 2 || !args.len().is_multiple_of(2) {
        return Err(HarnessError::new("private HTTPS arguments are incomplete"));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "private HTTPS argument is unknown or duplicated",
            ));
        }
    }
    Ok(PrivateHttpsOptions {
        expected: positive_usize(&values, "--expected")?,
        succeeded: nonnegative_usize(&values, "--succeeded")?,
        failed: nonnegative_usize(&values, "--failed")?,
        expected_negatives: positive_usize(&values, "--expected-negatives")?,
        rejected_negatives: nonnegative_usize(&values, "--rejected-negatives")?,
        accepted_negatives: nonnegative_usize(&values, "--accepted-negatives")?,
        final_connections: nonnegative_usize(&values, "--final-connections")?,
        final_payload: nonnegative_usize(&values, "--final-payload")?,
        final_pressure: required(&values, "--final-pressure")?,
        recovery_status: positive(&values, "--recovery-status")?
            .try_into()
            .map_err(|_| HarnessError::new("private HTTPS status exceeds u16"))?,
    })
}

pub fn evaluate_private_https(options: PrivateHttpsOptions) -> Result<String, HarnessError> {
    let mut scenario = PrivateHttpsScenario::new(options.expected, options.expected_negatives)?;
    scenario.observe_load(options.succeeded, options.failed)?;
    scenario.observe_negatives(options.rejected_negatives, options.accepted_negatives)?;
    let result = scenario.observe_recovery(
        options.final_connections,
        options.final_payload,
        &options.final_pressure,
        options.recovery_status,
    )?;
    Ok(format!(
        "private HTTPS passed succeeded={} rejected_negatives={} recovery_status={}",
        result.succeeded, result.rejected_negatives, result.recovery_status
    ))
}

fn positive_usize(values: &BTreeMap<String, String>, key: &str) -> Result<usize, HarnessError> {
    positive(values, key)?
        .try_into()
        .map_err(|_| HarnessError::new("private HTTPS value exceeds usize"))
}

fn nonnegative_usize(values: &BTreeMap<String, String>, key: &str) -> Result<usize, HarnessError> {
    required(values, key)?
        .parse::<usize>()
        .map_err(|_| HarnessError::new("private HTTPS value is invalid"))
}

fn positive(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    let value = required(values, key)?
        .parse::<u64>()
        .map_err(|_| HarnessError::new("private HTTPS value is invalid"))?;
    if value == 0 {
        return Err(HarnessError::new("private HTTPS value must be positive"));
    }
    Ok(value)
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("private HTTPS argument is missing: {key}")))
}
