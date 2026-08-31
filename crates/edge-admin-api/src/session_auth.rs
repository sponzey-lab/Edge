//! In-memory Admin session and CSRF authentication boundary.

use std::collections::BTreeMap;

use edge_domain::{AppError, ErrorCode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub session_id: String,
    pub csrf_token: String,
}

#[derive(Debug, Default, Clone)]
pub struct SessionStore {
    sessions: BTreeMap<String, String>,
}

impl SessionStore {
    pub fn insert(&mut self, session: Session) {
        self.sessions.insert(session.session_id, session.csrf_token);
    }

    pub fn remove(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn verify(&self, session_id: &str) -> bool {
        self.sessions.contains_key(session_id)
    }

    pub fn verify_csrf(&self, session_id: &str, csrf_token: &str) -> bool {
        self.sessions
            .get(session_id)
            .is_some_and(|known| known == csrf_token)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAuthenticator {
    password_hash: String,
    next_session: u64,
    failed_attempts: u32,
    max_failed_attempts: u32,
}

impl AdminAuthenticator {
    pub fn new(password_hash: impl Into<String>) -> Self {
        Self {
            password_hash: password_hash.into(),
            next_session: 1,
            failed_attempts: 0,
            max_failed_attempts: 5,
        }
    }

    /// Accepts only the supplied expected hash and enforces the existing bounded failure count.
    pub fn login(
        &mut self,
        password_hash: &str,
        sessions: &mut SessionStore,
    ) -> Result<Session, AppError> {
        if self.failed_attempts >= self.max_failed_attempts {
            return Err(AppError::new(
                ErrorCode::AdminInvalidCredentials,
                "too many failed attempts",
            ));
        }

        if password_hash != self.password_hash {
            self.failed_attempts += 1;
            return Err(AppError::new(
                ErrorCode::AdminInvalidCredentials,
                "invalid credentials",
            ));
        }

        self.failed_attempts = 0;
        let session = Session {
            session_id: format!("session-{}", self.next_session),
            csrf_token: format!("csrf-{}", self.next_session),
        };
        self.next_session += 1;
        sessions.insert(session.clone());
        Ok(session)
    }
}

pub fn require_session(sessions: &SessionStore, session_id: Option<&str>) -> Result<(), AppError> {
    let Some(session_id) = session_id else {
        return Err(AppError::new(
            ErrorCode::AdminAuthRequired,
            "admin session is required",
        ));
    };

    if sessions.verify(session_id) {
        Ok(())
    } else {
        Err(AppError::new(
            ErrorCode::AdminAuthRequired,
            "admin session is invalid",
        ))
    }
}

pub fn require_csrf(
    sessions: &SessionStore,
    session_id: &str,
    csrf_token: Option<&str>,
) -> Result<(), AppError> {
    let Some(csrf_token) = csrf_token else {
        return Err(AppError::new(
            ErrorCode::AdminCsrfRequired,
            "csrf token is required",
        ));
    };

    if sessions.verify_csrf(session_id, csrf_token) {
        Ok(())
    } else {
        Err(AppError::new(
            ErrorCode::AdminCsrfRequired,
            "csrf token is invalid",
        ))
    }
}
