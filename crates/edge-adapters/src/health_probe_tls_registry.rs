//! Prepared outbound TLS session factories for health probe transport.

use std::collections::BTreeMap;
use std::sync::Arc;

use edge_domain::{AppError, ErrorCode, UpstreamHealthKey};
use edge_ports::{ClientTlsSessionFactory, HealthProbeFailure, TlsSession};

#[derive(Clone, Default)]
pub struct PreparedHealthTlsRegistry {
    factories: BTreeMap<UpstreamHealthKey, Arc<dyn ClientTlsSessionFactory + Send + Sync>>,
}

impl PreparedHealthTlsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert<F>(&mut self, key: UpstreamHealthKey, factory: F) -> Result<(), AppError>
    where
        F: ClientTlsSessionFactory + Send + Sync + 'static,
    {
        if self.factories.contains_key(&key) {
            return Err(AppError::new(
                ErrorCode::UpstreamTlsProfileInvalid,
                "prepared health TLS profile is invalid",
            ));
        }
        self.factories.insert(key, Arc::new(factory));
        Ok(())
    }

    pub fn contains(&self, key: &UpstreamHealthKey) -> bool {
        self.factories.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.factories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }

    pub(crate) fn create_session(
        &self,
        key: &UpstreamHealthKey,
        server_name: &edge_domain::TlsServerName,
    ) -> Result<Box<dyn TlsSession + Send>, HealthProbeFailure> {
        self.factories
            .get(key)
            .ok_or(HealthProbeFailure::TlsProfile)?
            .create_client_session(server_name)
            .map_err(|_| HealthProbeFailure::TlsProfile)
    }
}
