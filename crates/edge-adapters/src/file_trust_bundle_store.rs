//! File-backed trust-bundle store identity and path mapping.

use std::fs;
use std::io::{self, ErrorKind};
use std::path::PathBuf;

use edge_domain::{AppError, ErrorCode, TrustBundleRef};
use edge_ports::{TrustBundleReader, TrustBundleStore, ValidatedTrustBundle};
use sha2::Digest;

use crate::{
    hex_encode_bytes, parse_trust_metadata, read_owner_file_nofollow, sync_directory,
    trust_bundle_invalid, trust_bundle_store_error, write_synced_owner_file,
};

#[derive(Debug, Clone)]
pub struct FileTrustBundleStore {
    pub(crate) root: PathBuf,
}

impl FileTrustBundleStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub(crate) fn bundle_dir(&self, reference: &TrustBundleRef) -> PathBuf {
        self.root.join(reference.as_str())
    }
}

impl TrustBundleStore for FileTrustBundleStore {
    fn create_trust_bundle(&mut self, bundle: ValidatedTrustBundle) -> Result<(), AppError> {
        #[cfg(not(unix))]
        {
            let _ = bundle;
            return Err(AppError::new(
                ErrorCode::TrustBundleStoreFailed,
                "secure trust bundle publication is unsupported on this platform",
            ));
        }
        #[cfg(unix)]
        {
            let expected_digest: [u8; 32] = sha2::Sha256::digest(bundle.encoded_material()).into();
            if expected_digest != bundle.metadata.content_sha256 {
                return Err(trust_bundle_invalid());
            }
            fs::create_dir_all(&self.root).map_err(trust_bundle_store_error)?;
            let final_dir = self.bundle_dir(&bundle.metadata.trust_bundle_ref);
            if final_dir.symlink_metadata().is_ok() {
                return Err(AppError::new(
                    ErrorCode::TrustBundleAlreadyExists,
                    "trust bundle reference already exists",
                ));
            }
            let temp_dir = self.root.join(format!(
                ".{}.tmp",
                bundle.metadata.trust_bundle_ref.as_str()
            ));
            fs::create_dir(&temp_dir).map_err(trust_bundle_store_error)?;
            let result = (|| {
                let roots = temp_dir.join("roots.pem");
                let metadata = temp_dir.join("metadata.toml");
                write_synced_owner_file(&roots, bundle.encoded_material())?;
                let encoded_metadata = format!(
                    "trust_bundle_ref = \"{}\"\ncertificate_count = {}\nimported_at_epoch_seconds = {}\ncontent_sha256 = \"{}\"\n",
                    bundle.metadata.trust_bundle_ref.as_str(), bundle.metadata.certificate_count,
                    bundle.metadata.imported_at_epoch_seconds, hex_encode_bytes(&bundle.metadata.content_sha256),
                );
                write_synced_owner_file(&metadata, encoded_metadata.as_bytes())?;
                sync_directory(&temp_dir)?;
                fs::rename(&temp_dir, &final_dir).map_err(trust_bundle_store_error)?;
                sync_directory(&self.root)
            })();
            if result.is_err() {
                let _ = fs::remove_dir_all(&temp_dir);
            }
            result
        }
    }

    fn list_trust_bundles(&mut self) -> Result<Vec<edge_ports::TrustBundleMetadata>, AppError> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut entries = fs::read_dir(&self.root)
            .map_err(trust_bundle_store_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(trust_bundle_store_error)?;
        entries.sort_by_key(|entry| entry.file_name());
        let mut items = Vec::new();
        for entry in entries {
            let file_type = entry.file_type().map_err(trust_bundle_store_error)?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(trust_bundle_store_error(io::Error::new(
                    ErrorKind::InvalidData,
                    "unsafe trust store entry",
                )));
            }
            let metadata = read_owner_file_nofollow(&entry.path().join("metadata.toml"), 4096)?;
            items.push(parse_trust_metadata(
                std::str::from_utf8(&metadata).map_err(|_| {
                    trust_bundle_store_error(io::Error::new(
                        ErrorKind::InvalidData,
                        "invalid metadata",
                    ))
                })?,
            )?);
        }
        Ok(items)
    }

    fn delete_trust_bundle(&mut self, reference: &TrustBundleRef) -> Result<(), AppError> {
        let path = self.bundle_dir(reference);
        match path.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                Err(trust_bundle_store_error(io::Error::new(
                    ErrorKind::InvalidData,
                    "unsafe trust store entry",
                )))
            }
            Ok(_) => fs::remove_dir_all(path).map_err(trust_bundle_store_error),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(trust_bundle_store_error(error)),
        }
    }
}

impl TrustBundleReader for FileTrustBundleStore {
    fn load_trust_bundle(
        &mut self,
        reference: &TrustBundleRef,
    ) -> Result<Option<ValidatedTrustBundle>, AppError> {
        let directory = self.bundle_dir(reference);
        match directory.symlink_metadata() {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(trust_bundle_store_error(io::Error::other(
                    "unsafe trust dir",
                )))
            }
            Err(error) => return Err(trust_bundle_store_error(error)),
        }
        let metadata_bytes = read_owner_file_nofollow(&directory.join("metadata.toml"), 4096)?;
        let metadata =
            parse_trust_metadata(std::str::from_utf8(&metadata_bytes).map_err(|_| {
                trust_bundle_store_error(io::Error::new(ErrorKind::InvalidData, "invalid metadata"))
            })?)?;
        if &metadata.trust_bundle_ref != reference {
            return Err(trust_bundle_store_error(io::Error::new(
                ErrorKind::InvalidData,
                "trust ref mismatch",
            )));
        }
        let bytes = read_owner_file_nofollow(&directory.join("roots.pem"), 384 * 1024)?;
        let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
        if digest != metadata.content_sha256 {
            return Err(trust_bundle_store_error(io::Error::new(
                ErrorKind::InvalidData,
                "trust digest mismatch",
            )));
        }
        Ok(Some(ValidatedTrustBundle::new(metadata, bytes)))
    }
}
