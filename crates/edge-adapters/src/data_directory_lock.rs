//! Exclusive filesystem ownership adapter for a configured data directory.

use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use edge_domain::{
    AppError, DataDirectoryLockEvent, DataDirectoryLockMachine, DataDirectoryLockState, ErrorCode,
};
use edge_ports::{DataDirectoryLockGuard, DataDirectoryLockManager};
use fs4::{FileExt, TryLockError};

use super::set_private_file_permissions;

#[derive(Debug, Clone)]
pub struct FileDataDirectoryLockManager {
    lock_path: PathBuf,
}

impl FileDataDirectoryLockManager {
    pub fn new(target_data_dir: impl AsRef<Path>) -> Result<Self, AppError> {
        let target = canonical_target_identity(target_data_dir.as_ref())?;
        let parent = target.parent().ok_or_else(data_directory_lock_error)?;
        let basename = target
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .ok_or_else(data_directory_lock_error)?;
        Ok(Self {
            lock_path: parent.join(format!(
                ".sponzey-edge-{}.lock",
                super::hex_encode(basename)
            )),
        })
    }
}

impl DataDirectoryLockManager for FileDataDirectoryLockManager {
    fn try_acquire_exclusive(&self) -> Result<Box<dyn DataDirectoryLockGuard>, AppError> {
        let mut machine = DataDirectoryLockMachine::default();
        machine.transition(DataDirectoryLockEvent::AcquireRequested)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .map_err(|_| data_directory_lock_error())?;
        set_private_file_permissions(&self.lock_path).map_err(|_| data_directory_lock_error())?;
        match FileExt::try_lock(&file) {
            Ok(()) => {
                machine.transition(DataDirectoryLockEvent::AcquireSucceeded)?;
                Ok(Box::new(FileDataDirectoryLockGuard {
                    file: Some(file),
                    machine,
                }))
            }
            Err(TryLockError::WouldBlock) => {
                machine.transition(DataDirectoryLockEvent::AcquireFailed)?;
                Err(AppError::new(
                    ErrorCode::DataDirectoryBusy,
                    "data directory is already exclusively owned",
                ))
            }
            Err(TryLockError::Error(_)) => {
                machine.transition(DataDirectoryLockEvent::AcquireFailed)?;
                Err(data_directory_lock_error())
            }
        }
    }
}

#[derive(Debug)]
struct FileDataDirectoryLockGuard {
    file: Option<File>,
    machine: DataDirectoryLockMachine,
}

impl DataDirectoryLockGuard for FileDataDirectoryLockGuard {
    fn state(&self) -> DataDirectoryLockState {
        self.machine.state()
    }

    fn release(&mut self) -> Result<(), AppError> {
        self.machine
            .transition(DataDirectoryLockEvent::ReleaseRequested)?;
        let file = self.file.as_ref().ok_or_else(data_directory_lock_error)?;
        if FileExt::unlock(file).is_err() {
            self.machine
                .transition(DataDirectoryLockEvent::ReleaseFailed)?;
            return Err(data_directory_lock_error());
        }
        self.file = None;
        self.machine
            .transition(DataDirectoryLockEvent::ReleaseSucceeded)
    }
}

impl Drop for FileDataDirectoryLockGuard {
    fn drop(&mut self) {
        if self.machine.state() == DataDirectoryLockState::HeldExclusive {
            let _ = self.release();
        }
    }
}

fn canonical_target_identity(target: &Path) -> Result<PathBuf, AppError> {
    match fs::canonicalize(target) {
        Ok(path) if path.is_dir() => Ok(path),
        Ok(_) => Err(data_directory_lock_error()),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let parent = target.parent().ok_or_else(data_directory_lock_error)?;
            let basename = target.file_name().ok_or_else(data_directory_lock_error)?;
            Ok(fs::canonicalize(parent)
                .map_err(|_| data_directory_lock_error())?
                .join(basename))
        }
        Err(_) => Err(data_directory_lock_error()),
    }
}

fn data_directory_lock_error() -> AppError {
    AppError::new(
        ErrorCode::DataDirectoryLockFailed,
        "data directory lock operation failed",
    )
}
