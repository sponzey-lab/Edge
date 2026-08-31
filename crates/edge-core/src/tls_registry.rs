//! Prepared TLS session factories for an immutable runtime generation.
//!
//! The registry owns only factory identity, selection, and snapshot completeness
//! checks. TLS material construction remains an adapter concern, while runtime
//! commands remain in the mio composition module.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use edge_domain::{
    AppError, ConfigSnapshot, ErrorCode, ServiceId, TlsServerName, UpstreamId, UpstreamTlsPolicy,
};
use edge_ports::{ClientTlsSessionFactory, ServerTlsSessionFactory, TlsSession};

#[derive(Clone, Default)]
pub struct PreparedClientTlsRegistry {
    factories: BTreeMap<(ServiceId, UpstreamId), Arc<dyn ClientTlsSessionFactory + Send + Sync>>,
}

impl PreparedClientTlsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert<F>(
        &mut self,
        service_id: ServiceId,
        upstream_id: UpstreamId,
        factory: F,
    ) -> Result<(), AppError>
    where
        F: ClientTlsSessionFactory + Send + Sync + 'static,
    {
        self.insert_shared(service_id, upstream_id, Arc::new(factory))
    }

    pub fn insert_shared(
        &mut self,
        service_id: ServiceId,
        upstream_id: UpstreamId,
        factory: Arc<dyn ClientTlsSessionFactory + Send + Sync>,
    ) -> Result<(), AppError> {
        let key = (service_id, upstream_id);
        if self.factories.contains_key(&key) {
            return Err(upstream_tls_registry_error());
        }
        self.factories.insert(key, factory);
        Ok(())
    }

    pub fn create_session(
        &self,
        service_id: &ServiceId,
        upstream_id: &UpstreamId,
        server_name: &TlsServerName,
    ) -> Result<Box<dyn TlsSession + Send>, AppError> {
        self.factories
            .get(&(service_id.clone(), upstream_id.clone()))
            .ok_or_else(upstream_tls_registry_error)?
            .create_client_session(server_name)
    }

    pub fn contains(&self, service_id: &ServiceId, upstream_id: &UpstreamId) -> bool {
        self.factories
            .contains_key(&(service_id.clone(), upstream_id.clone()))
    }

    pub fn len(&self) -> usize {
        self.factories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }

    pub(crate) fn validate_for_snapshot(&self, snapshot: &ConfigSnapshot) -> Result<(), AppError> {
        let mut expected = 0_usize;
        for service in &snapshot.services {
            for upstream in &service.upstreams {
                if matches!(upstream.tls, UpstreamTlsPolicy::ServerAuthenticated { .. }) {
                    expected = expected.saturating_add(1);
                    if !self.contains(&service.id, &upstream.id) {
                        return Err(upstream_tls_registry_error());
                    }
                }
            }
        }
        if self.len() != expected {
            return Err(upstream_tls_registry_error());
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct PreparedServerTlsRegistry {
    factories: BTreeMap<SocketAddr, Arc<dyn ServerTlsSessionFactory + Send + Sync>>,
}

impl PreparedServerTlsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert<F>(&mut self, bind: SocketAddr, factory: F) -> Result<(), AppError>
    where
        F: ServerTlsSessionFactory + Send + Sync + 'static,
    {
        if self.factories.contains_key(&bind) {
            return Err(runtime_generation_error());
        }
        self.factories.insert(bind, Arc::new(factory));
        Ok(())
    }

    pub(crate) fn factory_for(
        &self,
        bind: &SocketAddr,
    ) -> Option<Arc<dyn ServerTlsSessionFactory + Send + Sync>> {
        self.factories.get(bind).cloned()
    }

    pub fn len(&self) -> usize {
        self.factories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }
}

pub(crate) fn upstream_tls_registry_error() -> AppError {
    AppError::new(
        ErrorCode::UpstreamTlsProfileInvalid,
        "prepared upstream TLS profile is invalid",
    )
}

pub(crate) fn runtime_generation_error() -> AppError {
    AppError::new(
        ErrorCode::RuntimeCommandRejected,
        "prepared TLS runtime generation does not match the active snapshot",
    )
}
