//! Owner-only and no-follow trust-bundle file operations.

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;

use edge_domain::AppError;

use crate::{set_private_file_permissions, trust_bundle_limit, trust_bundle_store_error};

pub(crate) fn write_synced_owner_file(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(trust_bundle_store_error)?;
    file.write_all(bytes).map_err(trust_bundle_store_error)?;
    set_private_file_permissions(path).map_err(trust_bundle_store_error)?;
    file.sync_all().map_err(trust_bundle_store_error)
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), AppError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(trust_bundle_store_error)
}

#[cfg(unix)]
pub(crate) fn read_owner_file_nofollow(path: &Path, max_bytes: usize) -> Result<Vec<u8>, AppError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(trust_bundle_store_error)?;
    let metadata = file.metadata().map_err(trust_bundle_store_error)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(trust_bundle_store_error(io::Error::new(
            ErrorKind::PermissionDenied,
            "unsafe trust file",
        )));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(trust_bundle_store_error)?;
    if bytes.len() > max_bytes {
        return Err(trust_bundle_limit());
    }
    Ok(bytes)
}

#[cfg(not(unix))]
pub(crate) fn read_owner_file_nofollow(
    _path: &Path,
    _max_bytes: usize,
) -> Result<Vec<u8>, AppError> {
    Err(trust_bundle_store_error(io::Error::new(
        ErrorKind::Unsupported,
        "secure trust reads are unsupported",
    )))
}
