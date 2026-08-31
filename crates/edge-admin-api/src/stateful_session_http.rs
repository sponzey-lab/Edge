//! Stateful Admin setup, login, and logout HTTP adaptation.

use edge_domain::{AppError, ConfigSnapshot, ErrorCode};
use edge_ports::{SecretRecord, SecretStore};

use crate::{
    error_response, expired_session_cookie_header, handle_http_request, is_mutation_route,
    json_string_field, login_response_json, session_cookie_header, AdminAuthenticator,
    AdminHttpContext, AdminHttpMethod, AdminHttpRequest, AdminHttpResponse, SessionStore,
};

pub struct AdminHttpRuntimeContext<'a> {
    pub snapshot: &'a ConfigSnapshot,
    pub sessions: &'a mut SessionStore,
    pub authenticator: &'a mut Option<AdminAuthenticator>,
    pub secrets: &'a mut dyn SecretStore,
}

pub fn handle_stateful_http_request(
    request: &AdminHttpRequest,
    context: AdminHttpRuntimeContext<'_>,
) -> AdminHttpResponse {
    match (request.method, request.path.as_str()) {
        (AdminHttpMethod::Post, "/api/v1/setup") => {
            handle_setup(request, context.authenticator, context.secrets)
        }
        (AdminHttpMethod::Post, "/api/v1/login") => {
            let Some(authenticator) = context.authenticator.as_mut() else {
                return setup_required_response(&request.request_id);
            };
            handle_login(request, authenticator, context.sessions)
        }
        (AdminHttpMethod::Post, "/api/v1/logout") => {
            if context.authenticator.is_none() {
                return setup_required_response(&request.request_id);
            }
            handle_logout(request, context.sessions)
        }
        _ if context.authenticator.is_none()
            && is_mutation_route(request.method, &request.path) =>
        {
            setup_required_response(&request.request_id)
        }
        _ => handle_http_request(
            request,
            AdminHttpContext {
                snapshot: context.snapshot,
                sessions: context.sessions,
            },
        ),
    }
}

fn handle_setup(
    request: &AdminHttpRequest,
    authenticator: &mut Option<AdminAuthenticator>,
    secrets: &mut dyn SecretStore,
) -> AdminHttpResponse {
    if authenticator.is_some() {
        return setup_already_complete_response(&request.request_id);
    }
    match secrets.load_secret("admin-password-hash") {
        Ok(Some(_)) => return setup_already_complete_response(&request.request_id),
        Ok(None) => {}
        Err(error) => return error_response(500, error, &request.request_id),
    }

    let Some(password_hash) = json_string_field(&request.body, "password_hash") else {
        return error_response(
            400,
            AppError::new(
                ErrorCode::HttpMalformedRequest,
                "setup request requires password_hash",
            ),
            &request.request_id,
        );
    };
    if let Err(error) = secrets.save_secret(SecretRecord {
        name: "admin-password-hash".to_string(),
        value: password_hash.clone(),
    }) {
        return error_response(500, error, &request.request_id);
    }
    *authenticator = Some(AdminAuthenticator::new(password_hash));
    AdminHttpResponse::json(200, "{\"setup_complete\":true}".to_string())
}

fn handle_login(
    request: &AdminHttpRequest,
    authenticator: &mut AdminAuthenticator,
    sessions: &mut SessionStore,
) -> AdminHttpResponse {
    let Some(password_hash) = json_string_field(&request.body, "password_hash") else {
        return error_response(
            400,
            AppError::new(
                ErrorCode::HttpMalformedRequest,
                "login request requires password_hash",
            ),
            &request.request_id,
        );
    };
    match authenticator.login(&password_hash, sessions) {
        Ok(session) => {
            let body = login_response_json(&session);
            AdminHttpResponse::json(200, body)
                .with_header("set-cookie", session_cookie_header(&session.session_id))
        }
        Err(error) => error_response(401, error, &request.request_id),
    }
}

fn handle_logout(request: &AdminHttpRequest, sessions: &mut SessionStore) -> AdminHttpResponse {
    let Some(session_id) = request.session_id.as_deref() else {
        return error_response(
            401,
            AppError::new(ErrorCode::AdminAuthRequired, "admin session is required"),
            &request.request_id,
        );
    };
    if let Err(error) = crate::require_session(sessions, Some(session_id)) {
        return error_response(401, error, &request.request_id);
    }
    if let Err(error) = crate::require_csrf(sessions, session_id, request.csrf_token.as_deref()) {
        return error_response(403, error, &request.request_id);
    }
    sessions.remove(session_id);
    AdminHttpResponse::json(200, "{\"logged_out\":true}".to_string())
        .with_header("set-cookie", expired_session_cookie_header())
}

fn setup_required_response(request_id: &str) -> AdminHttpResponse {
    error_response(
        403,
        AppError::new(
            ErrorCode::AdminSetupRequired,
            "admin setup is required before login",
        ),
        request_id,
    )
}

fn setup_already_complete_response(request_id: &str) -> AdminHttpResponse {
    error_response(
        409,
        AppError::new(
            ErrorCode::AdminSetupAlreadyComplete,
            "admin setup is already complete",
        ),
        request_id,
    )
}
