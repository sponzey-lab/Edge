use std::net::SocketAddr;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::diagnostic_soak::SoakWorkload;
use crate::diagnostic_soak_runner::SoakSchedulePort;
use crate::http_driver::{HttpLoadDriver, HttpLoadSpec, RuntimePressure};
use crate::release_http_scenario::{
    AdminStatusHttpProbe, AttachedProcessObservation, ProcessObservationPort, RuntimeStatusPort,
};
use crate::soak_window::{
    SoakWindowCleanup, SoakWindowLoadPort, SoakWindowLoadResult, SoakWindowProcessPort,
    SoakWindowRuntimePort,
};
use crate::websocket_driver::run_websocket_lifecycles_for_host;
use crate::HarnessError;

pub struct SystemSoakSchedule {
    started_at: Instant,
}

impl SystemSoakSchedule {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }
}

impl Default for SystemSoakSchedule {
    fn default() -> Self {
        Self::new()
    }
}

impl SoakSchedulePort for SystemSoakSchedule {
    fn wait_until_seconds(&mut self, target: u64) -> Result<(), HarnessError> {
        let deadline = self
            .started_at
            .checked_add(Duration::from_secs(target))
            .ok_or_else(|| HarnessError::new("diagnostic soak deadline overflows"))?;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(());
            }
            thread::sleep((deadline - now).min(Duration::from_millis(100)));
        }
    }

    fn elapsed_seconds(&mut self) -> Result<u64, HarnessError> {
        Ok(self.started_at.elapsed().as_secs())
    }
}

pub struct DriverSoakWindowLoad {
    http_address: SocketAddr,
    websocket_address: SocketAddr,
    host: String,
    timeout: Duration,
    max_response_bytes: usize,
    max_websocket_header_bytes: usize,
}

impl DriverSoakWindowLoad {
    pub fn new(
        http_address: SocketAddr,
        websocket_address: SocketAddr,
        host: impl Into<String>,
        timeout: Duration,
        max_response_bytes: usize,
        max_websocket_header_bytes: usize,
    ) -> Result<Self, HarnessError> {
        let host = host.into();
        HttpLoadSpec::new(
            http_address,
            host.clone(),
            1_000,
            timeout,
            max_response_bytes,
        )?;
        if max_websocket_header_bytes == 0 {
            return Err(HarnessError::new("soak WebSocket header bound is invalid"));
        }
        Ok(Self {
            http_address,
            websocket_address,
            host,
            timeout,
            max_response_bytes,
            max_websocket_header_bytes,
        })
    }
}

impl SoakWindowLoadPort for DriverSoakWindowLoad {
    fn run(
        &mut self,
        workload: SoakWorkload,
        expected: u64,
    ) -> Result<SoakWindowLoadResult, HarnessError> {
        match workload {
            SoakWorkload::Baseline if expected == 0 => Ok(SoakWindowLoadResult {
                expected: 0,
                succeeded: 0,
                failed: 0,
            }),
            SoakWorkload::Churn if expected == 1_000 => {
                let spec = HttpLoadSpec::new(
                    self.http_address,
                    self.host.clone(),
                    1_000,
                    self.timeout,
                    self.max_response_bytes,
                )?;
                let mut driver = HttpLoadDriver::new(spec);
                driver.warm()?;
                let counters = driver.load()?;
                driver.cool()?;
                Ok(SoakWindowLoadResult {
                    expected: counters.expected,
                    succeeded: counters.succeeded,
                    failed: counters.failed,
                })
            }
            SoakWorkload::Websocket if expected == 128 => {
                let released = run_websocket_lifecycles_for_host(
                    self.websocket_address,
                    &self.host,
                    128,
                    self.timeout,
                    self.max_websocket_header_bytes,
                )?;
                let succeeded = u64::try_from(released)
                    .map_err(|_| HarnessError::new("soak WebSocket count exceeds u64"))?;
                Ok(SoakWindowLoadResult {
                    expected,
                    succeeded,
                    failed: expected.saturating_sub(succeeded),
                })
            }
            _ => Err(HarnessError::new("soak workload request is invalid")),
        }
    }
}

pub struct AdminSoakWindowRuntime {
    status: AdminStatusHttpProbe,
    expected_revision: String,
    recovery: HttpLoadSpec,
}

impl AdminSoakWindowRuntime {
    pub fn new(
        admin_address: SocketAddr,
        proxy_address: SocketAddr,
        expected_revision: impl Into<String>,
        host: impl Into<String>,
        timeout: Duration,
        max_admin_body_bytes: usize,
        max_response_bytes: usize,
    ) -> Result<Self, HarnessError> {
        let expected_revision = expected_revision.into();
        if expected_revision.is_empty() {
            return Err(HarnessError::new("soak expected revision is invalid"));
        }
        Ok(Self {
            status: AdminStatusHttpProbe::new(admin_address, timeout, max_admin_body_bytes)?,
            expected_revision,
            recovery: HttpLoadSpec::new(proxy_address, host, 1, timeout, max_response_bytes)?,
        })
    }

    fn wait_clean(
        &mut self,
    ) -> Result<crate::http_driver::RuntimeResourceObservation, HarnessError> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(runtime) = self.status.observe(&self.expected_revision) {
                if runtime.active_connections == 0
                    && runtime.used_payload_bytes == 0
                    && runtime.pressure == RuntimePressure::Normal
                {
                    return Ok(runtime);
                }
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::new("soak cleanup deadline exceeded"));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

impl SoakWindowRuntimePort for AdminSoakWindowRuntime {
    fn observe_cleanup(&mut self) -> Result<SoakWindowCleanup, HarnessError> {
        self.wait_clean()?;
        let mut recovery = HttpLoadDriver::new(self.recovery.clone());
        recovery.warm()?;
        let counters = recovery.load()?;
        recovery.cool()?;
        let recovery_status =
            if counters.expected == 1 && counters.succeeded == 1 && counters.failed == 0 {
                200
            } else {
                0
            };
        let runtime = self.wait_clean()?;
        Ok(SoakWindowCleanup {
            active_connections: runtime.active_connections,
            payload_bytes: runtime.used_payload_bytes,
            pressure: match runtime.pressure {
                RuntimePressure::Normal => "normal",
                RuntimePressure::Pressured => "pressured",
                RuntimePressure::Exhausted => "exhausted",
                RuntimePressure::FailedClosed => "failed_closed",
            }
            .to_string(),
            recovery_status,
        })
    }
}

pub struct AttachedSoakWindowProcess {
    inner: AttachedProcessObservation,
}

impl AttachedSoakWindowProcess {
    pub fn attach(pid: u32) -> Result<Self, HarnessError> {
        Ok(Self {
            inner: AttachedProcessObservation::attach(pid)?,
        })
    }

    pub fn start_identity(&self) -> &str {
        self.inner.start_identity()
    }
}

impl SoakWindowProcessPort for AttachedSoakWindowProcess {
    fn is_alive(&mut self) -> Result<bool, HarnessError> {
        self.inner.is_alive()
    }

    fn identity_matches(&mut self) -> Result<bool, HarnessError> {
        self.inner.identity_matches()
    }

    fn sample_rss_bytes(&mut self) -> Result<u64, HarnessError> {
        self.inner.sample_rss_bytes()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn public_driver_contract_fixes_production_window_counts() {
        let mut adapter = DriverSoakWindowLoad::new(
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
            "localhost",
            Duration::from_secs(1),
            65_536,
            4_096,
        )
        .unwrap();
        assert!(adapter.run(SoakWorkload::Churn, 999).is_err());
        assert!(adapter.run(SoakWorkload::Websocket, 127).is_err());
        assert_eq!(
            adapter.run(SoakWorkload::Baseline, 0).unwrap(),
            SoakWindowLoadResult {
                expected: 0,
                succeeded: 0,
                failed: 0,
            }
        );
    }
}
