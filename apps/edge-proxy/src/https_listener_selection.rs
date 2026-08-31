//! Bootstrap-only selection of configured manual HTTPS listeners and certificates.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use edge_domain::{CertificateRef, ClientAuthPolicy, ConfigSnapshot, ListenerProtocol};

#[derive(Clone)]
pub(crate) struct StartupHttpsListener {
    pub(crate) bind: SocketAddr,
    pub(crate) client_auth: ClientAuthPolicy,
}

pub(crate) fn https_certificate_refs(snapshot: &ConfigSnapshot) -> Vec<CertificateRef> {
    let mut refs = BTreeSet::new();
    for route in snapshot.routes.iter().filter(|route| route.enabled) {
        if let Some(certificate_ref) = &route.certificate_ref {
            refs.insert(certificate_ref.clone());
        }
    }
    refs.into_iter().collect()
}

pub(crate) fn https_listener_configs(
    snapshot: &ConfigSnapshot,
) -> std::io::Result<Vec<StartupHttpsListener>> {
    let https_listeners: Vec<_> = snapshot
        .listeners
        .iter()
        .filter(|listener| listener.protocol == ListenerProtocol::Https)
        .collect();
    if https_listeners.is_empty() {
        return Ok(Vec::new());
    }

    https_listeners
        .into_iter()
        .map(|listener| {
            let bind = listener.bind.parse::<SocketAddr>().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "HTTPS listener bind is invalid",
                )
            })?;
            Ok(StartupHttpsListener {
                bind,
                client_auth: listener.client_auth.clone(),
            })
        })
        .collect()
}
