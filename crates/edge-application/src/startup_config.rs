//! Startup configuration resolution stays at the application boundary.
//!
//! The use case chooses a persisted revision before an optional bootstrap seed
//! and delegates every external operation to typed ports.

use edge_domain::{AppError, ConfigRevisionId, ConfigSnapshot, ErrorCode};
use edge_ports::{BootstrapConfigSeed, ConfigRevisionRepository, StartupConfigPreflight};

use crate::{
    parse_mvp_config, revision_record_for_snapshot, validation_errors_to_app_error, ConfigValidator,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupConfigOrigin {
    RevisionCurrent,
    BootstrapSeedImported,
}

impl StartupConfigOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RevisionCurrent => "revision_current",
            Self::BootstrapSeedImported => "bootstrap_seed_imported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedStartupConfig {
    pub snapshot: ConfigSnapshot,
    pub origin: StartupConfigOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupConfigResolutionState {
    OpeningRepository,
    RepositoryEmpty,
    ReadingSeed,
    ValidatingSeed,
    ImportingSeed,
    ReadingCurrent,
    ValidatingCurrent,
    Resolved,
    Unconfigured,
    Failed { error_code: ErrorCode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupConfigResolutionEvent {
    RepositoryInspected { empty: bool },
    SeedRead,
    SeedAbsent,
    SeedValidated,
    SeedImported,
    CurrentRead,
    CurrentValidated,
    Failed(ErrorCode),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupConfigResolutionMachine {
    state: StartupConfigResolutionState,
}

impl Default for StartupConfigResolutionMachine {
    fn default() -> Self {
        Self {
            state: StartupConfigResolutionState::OpeningRepository,
        }
    }
}

impl StartupConfigResolutionMachine {
    pub fn state(&self) -> &StartupConfigResolutionState {
        &self.state
    }

    pub fn transition(&mut self, event: StartupConfigResolutionEvent) -> Result<(), AppError> {
        use StartupConfigResolutionEvent as Event;
        use StartupConfigResolutionState as State;
        let next = match (&self.state, event) {
            (State::OpeningRepository, Event::RepositoryInspected { empty: true }) => {
                State::RepositoryEmpty
            }
            (State::OpeningRepository, Event::RepositoryInspected { empty: false }) => {
                State::ReadingCurrent
            }
            (State::RepositoryEmpty, Event::SeedRead) => State::ValidatingSeed,
            (State::RepositoryEmpty, Event::SeedAbsent) => State::Unconfigured,
            (State::ValidatingSeed, Event::SeedValidated) => State::ImportingSeed,
            (State::ImportingSeed, Event::SeedImported) => State::Resolved,
            (State::ReadingCurrent, Event::CurrentRead) => State::ValidatingCurrent,
            (State::ValidatingCurrent, Event::CurrentValidated) => State::Resolved,
            (
                State::OpeningRepository
                | State::RepositoryEmpty
                | State::ReadingSeed
                | State::ValidatingSeed
                | State::ImportingSeed
                | State::ReadingCurrent
                | State::ValidatingCurrent,
                Event::Failed(error_code),
            ) => State::Failed { error_code },
            (state, event) => {
                return Err(AppError::new(
                    ErrorCode::InternalBug,
                    format!("invalid startup config transition: {state:?} + {event:?}"),
                ))
            }
        };
        self.state = next;
        Ok(())
    }
}

pub struct ResolveStartupConfigUseCase<'a, R, S, P> {
    revisions: &'a mut R,
    seed: &'a mut S,
    preflight: &'a mut P,
    validator: ConfigValidator,
}

impl<'a, R, S, P> ResolveStartupConfigUseCase<'a, R, S, P>
where
    R: ConfigRevisionRepository,
    S: BootstrapConfigSeed,
    P: StartupConfigPreflight,
{
    pub fn new(revisions: &'a mut R, seed: &'a mut S, preflight: &'a mut P) -> Self {
        Self {
            revisions,
            seed,
            preflight,
            validator: ConfigValidator::default(),
        }
    }

    pub fn execute(&mut self) -> Result<Option<ResolvedStartupConfig>, AppError> {
        let mut machine = StartupConfigResolutionMachine::default();
        let current_revision_id = self.revisions.current_revision_id().map_err(|error| {
            fail_startup_resolution(
                &mut machine,
                ErrorCode::ConfigCurrentRevisionInvalid,
                error.message,
            )
        })?;
        let current = self.revisions.current().map_err(|error| {
            fail_startup_resolution(
                &mut machine,
                ErrorCode::ConfigCurrentRevisionInvalid,
                error.message,
            )
        })?;
        if current_revision_id.is_some() && current.is_none() {
            machine
                .transition(StartupConfigResolutionEvent::RepositoryInspected { empty: false })?;
            return Err(fail_startup_resolution(
                &mut machine,
                ErrorCode::ConfigCurrentRevisionMissing,
                "current revision pointer does not reference a stored revision",
            ));
        }
        if let Some(record) = current {
            machine
                .transition(StartupConfigResolutionEvent::RepositoryInspected { empty: false })?;
            machine.transition(StartupConfigResolutionEvent::CurrentRead)?;
            self.validator
                .validate_snapshot(&record.snapshot)
                .into_result()
                .map_err(|errors| {
                    fail_startup_resolution(
                        &mut machine,
                        ErrorCode::ConfigCurrentRevisionInvalid,
                        validation_errors_to_app_error(&errors).message,
                    )
                })?;
            self.preflight
                .preflight(&record.snapshot)
                .map_err(|error| {
                    fail_startup_resolution(&mut machine, error.code, error.message)
                })?;
            machine.transition(StartupConfigResolutionEvent::CurrentValidated)?;
            return Ok(Some(ResolvedStartupConfig {
                snapshot: record.snapshot,
                origin: StartupConfigOrigin::RevisionCurrent,
            }));
        }
        let history = self.revisions.history()?;
        if !history.is_empty() {
            machine
                .transition(StartupConfigResolutionEvent::RepositoryInspected { empty: false })?;
            return Err(fail_startup_resolution(
                &mut machine,
                ErrorCode::ConfigCurrentRevisionMissing,
                "revision repository is non-empty but current revision is unavailable",
            ));
        }
        machine.transition(StartupConfigResolutionEvent::RepositoryInspected { empty: true })?;
        let Some(seed) = self.seed.read_seed()? else {
            machine.transition(StartupConfigResolutionEvent::SeedAbsent)?;
            return Ok(None);
        };
        machine.transition(StartupConfigResolutionEvent::SeedRead)?;
        let source =
            parse_mvp_config(&seed, ConfigRevisionId::new("bootstrap-seed")).map_err(|error| {
                fail_startup_resolution(
                    &mut machine,
                    ErrorCode::ConfigBootstrapSeedInvalid,
                    error.message,
                )
            })?;
        self.validator
            .validate_source(&source)
            .into_result()
            .map_err(|errors| {
                fail_startup_resolution(
                    &mut machine,
                    ErrorCode::ConfigBootstrapSeedInvalid,
                    validation_errors_to_app_error(&errors).message,
                )
            })?;
        self.preflight
            .preflight(&source.snapshot)
            .map_err(|error| fail_startup_resolution(&mut machine, error.code, error.message))?;
        machine.transition(StartupConfigResolutionEvent::SeedValidated)?;
        let record = revision_record_for_snapshot(source.snapshot.clone(), "bootstrap seed");
        let revision_id = record.revision.id.clone();
        self.revisions.save_revision(record)?;
        self.revisions.set_current(&revision_id)?;
        machine.transition(StartupConfigResolutionEvent::SeedImported)?;
        Ok(Some(ResolvedStartupConfig {
            snapshot: source.snapshot,
            origin: StartupConfigOrigin::BootstrapSeedImported,
        }))
    }
}

fn fail_startup_resolution(
    machine: &mut StartupConfigResolutionMachine,
    code: ErrorCode,
    message: impl Into<String>,
) -> AppError {
    let _ = machine.transition(StartupConfigResolutionEvent::Failed(code));
    AppError::new(code, message)
}
