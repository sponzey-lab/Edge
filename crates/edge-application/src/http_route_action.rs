//! Pure MVP HTTP route-action selection.

use edge_domain::{ConfigSnapshot, RouteId, ServiceId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpRouteAction {
    Proxy {
        route_id: RouteId,
        service_id: ServiceId,
    },
    Redirect {
        status_code: u16,
        location: String,
    },
    AcmeChallengeBypass {
        token: String,
    },
    NotFound,
}

pub fn select_http_route_action(
    snapshot: &ConfigSnapshot,
    host: &str,
    path: &str,
) -> HttpRouteAction {
    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        return HttpRouteAction::AcmeChallengeBypass {
            token: token.to_string(),
        };
    }

    let Some(route) = snapshot.select_route(host, path) else {
        return HttpRouteAction::NotFound;
    };

    if route.redirect_http_to_https {
        return HttpRouteAction::Redirect {
            status_code: 308,
            location: format!("https://{host}{path}"),
        };
    }

    HttpRouteAction::Proxy {
        route_id: route.id.clone(),
        service_id: route.service_id.clone(),
    }
}
