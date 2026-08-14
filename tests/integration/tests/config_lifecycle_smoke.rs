use edge_adapters::{MemoryAuditSink, MemoryRevisionRepository};
use edge_application::{ConfigLifecycle, ConfigValidator};
use edge_core::CoreRuntime;
use edge_domain::{
    AdminConfig, AppError, CommandAck, ConfigRevisionId, ConfigSnapshot, CoreCommand, ErrorCode,
    HostMatch, Listener, ListenerId, ListenerProtocol, LogMode, PathMatch, Route, RouteId,
    RouteMatch, RuntimeOptions, Service, ServiceId, Upstream, UpstreamId,
};
use edge_ports::{ConfigRevisionRepository, CoreCommandClient};

struct RuntimeCommandClient {
    runtime: CoreRuntime,
    reject_after: Option<usize>,
    sent: usize,
}

impl RuntimeCommandClient {
    fn accepting() -> Self {
        Self {
            runtime: CoreRuntime::new(8),
            reject_after: None,
            sent: 0,
        }
    }

    fn rejecting_after_first_command_with_runtime(runtime: CoreRuntime) -> Self {
        Self {
            runtime,
            reject_after: Some(1),
            sent: 0,
        }
    }
}

impl CoreCommandClient for RuntimeCommandClient {
    fn send(&mut self, command: CoreCommand) -> CommandAck {
        self.sent += 1;
        if self.reject_after.is_some_and(|count| self.sent >= count) {
            return CommandAck::rejected(AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "runtime rejected command",
            ));
        }
        self.runtime.handle_command(command)
    }
}

fn lifecycle() -> ConfigLifecycle<MemoryRevisionRepository, MemoryAuditSink> {
    ConfigLifecycle {
        revisions: MemoryRevisionRepository::default(),
        audit: MemoryAuditSink::default(),
        validator: ConfigValidator::default(),
    }
}

fn snapshot(revision_id: &str, upstream_url: &str) -> ConfigSnapshot {
    ConfigSnapshot {
        schema_version: 1,
        revision_id: ConfigRevisionId::new(revision_id),
        admin: AdminConfig {
            bind: "127.0.0.1:9443".to_string(),
            auth_required: true,
        },
        listeners: vec![Listener {
            id: ListenerId::new("http"),
            bind: "127.0.0.1:8080".to_string(),
            protocol: ListenerProtocol::Http,
            client_auth: edge_domain::ClientAuthPolicy::Disabled,
        }],
        routes: vec![Route {
            id: RouteId::new("app"),
            route_match: RouteMatch::new(
                vec![HostMatch::exact("app.example.test")],
                vec![PathMatch::prefix("/")],
            ),
            service_id: ServiceId::new("app"),
            priority: 100,
            enabled: true,
            redirect_http_to_https: false,
            certificate_resolver_id: None,
            certificate_ref: None,
        }],
        services: vec![Service {
            policy: edge_domain::ServicePolicy::default(),
            id: ServiceId::new("app"),
            upstreams: vec![Upstream {
                id: UpstreamId::new("app-1"),
                url: upstream_url.to_string(),
                administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                tls: edge_domain::UpstreamTlsPolicy::Disabled,
            }],
        }],
        certificate_resolvers: vec![],
        log_mode: LogMode::Product,
        runtime: RuntimeOptions {
            max_connections: 1024,
            max_inflight_payload_bytes: 128 * 1024 * 1024,
            max_request_header_bytes: 16 * 1024,
            max_request_body_bytes: 1024 * 1024,
            upstream_read_timeout_ms: edge_domain::DEFAULT_UPSTREAM_READ_TIMEOUT_MS,
            metrics: edge_domain::MetricsConfig::default(),
        },
    }
}

#[test]
fn daemon_config_lifecycle_applies_and_rolls_back_through_core_command_boundary() {
    let mut lifecycle = lifecycle();
    let mut core = RuntimeCommandClient::accepting();

    lifecycle
        .apply_with_core(snapshot("rev-1", "http://127.0.0.1:3001"), &mut core)
        .unwrap();
    lifecycle
        .apply_with_core(snapshot("rev-2", "http://127.0.0.1:3002"), &mut core)
        .unwrap();

    assert_eq!(
        lifecycle
            .revisions
            .current()
            .unwrap()
            .unwrap()
            .revision
            .id
            .as_str(),
        "rev-2"
    );
    assert_eq!(
        core.runtime
            .current_snapshot
            .as_ref()
            .unwrap()
            .revision_id
            .as_str(),
        "rev-2"
    );

    lifecycle
        .rollback_with_core(&ConfigRevisionId::new("rev-1"), &mut core)
        .unwrap();

    assert_eq!(
        lifecycle
            .revisions
            .current()
            .unwrap()
            .unwrap()
            .revision
            .id
            .as_str(),
        "rev-1"
    );
    let runtime_snapshot = core.runtime.current_snapshot.as_ref().unwrap();
    assert_eq!(runtime_snapshot.revision_id.as_str(), "rev-1");
    assert_eq!(
        runtime_snapshot.services[0].upstreams[0].url,
        "http://127.0.0.1:3001"
    );
    assert_eq!(
        lifecycle.audit.events().last().unwrap().event,
        "config.rollback"
    );
}

#[test]
fn daemon_config_lifecycle_runtime_rejection_preserves_current_revision() {
    let mut lifecycle = lifecycle();
    let mut core = RuntimeCommandClient::accepting();
    lifecycle
        .apply_with_core(snapshot("rev-1", "http://127.0.0.1:3001"), &mut core)
        .unwrap();

    let mut rejecting =
        RuntimeCommandClient::rejecting_after_first_command_with_runtime(core.runtime);
    let result =
        lifecycle.apply_with_core(snapshot("rev-2", "http://127.0.0.1:3002"), &mut rejecting);

    assert!(result.is_err());
    assert_eq!(
        lifecycle
            .revisions
            .current()
            .unwrap()
            .unwrap()
            .revision
            .id
            .as_str(),
        "rev-1"
    );
    assert_eq!(
        rejecting
            .runtime
            .current_snapshot
            .as_ref()
            .unwrap()
            .revision_id
            .as_str(),
        "rev-1"
    );
    assert_eq!(
        lifecycle.audit.events().last().unwrap().event,
        "config.apply.failure"
    );
}
