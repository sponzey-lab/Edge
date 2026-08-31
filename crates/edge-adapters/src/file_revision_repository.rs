//! File-backed configuration revision and bootstrap-seed port adapters.

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use edge_application::{checksum_snapshot, parse_mvp_config, render_mvp_config_snapshot};
use edge_domain::{AppError, ConfigRevision, ConfigRevisionId, ErrorCode};
use edge_ports::{BootstrapConfigSeed, ConfigRevisionRepository, RevisionRecord};

use crate::{config_store_error, hex_decode, hex_encode};

#[derive(Debug, Clone)]
pub struct FileRevisionRepository {
    root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FileBootstrapConfigSeed {
    path: PathBuf,
}

impl FileBootstrapConfigSeed {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl BootstrapConfigSeed for FileBootstrapConfigSeed {
    fn read_seed(&mut self) -> Result<Option<String>, AppError> {
        match fs::read_to_string(&self.path) {
            Ok(source) => Ok(Some(source)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(config_store_error(error)),
        }
    }
}

impl FileRevisionRepository {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    fn revisions_dir(&self) -> PathBuf {
        self.root.join("revisions")
    }
    fn current_path(&self) -> PathBuf {
        self.root.join("current")
    }
    fn revision_path(&self, revision_id: &ConfigRevisionId) -> PathBuf {
        self.revisions_dir()
            .join(format!("{}.toml", hex_encode(revision_id.as_str())))
    }
    fn ensure_layout(&self) -> Result<(), AppError> {
        fs::create_dir_all(self.revisions_dir()).map_err(config_store_error)
    }
    fn read_record(
        &self,
        revision_id: &ConfigRevisionId,
    ) -> Result<Option<RevisionRecord>, AppError> {
        let path = self.revision_path(revision_id);
        if !path.exists() {
            return Ok(None);
        }
        let source = fs::read_to_string(path).map_err(config_store_error)?;
        let parsed = parse_mvp_config(&source, revision_id.clone())?;
        let snapshot = parsed.snapshot;
        let checksum = checksum_snapshot(&snapshot);
        Ok(Some(RevisionRecord {
            revision: ConfigRevision {
                id: revision_id.clone(),
                schema_version: snapshot.schema_version,
                summary: format!("file revision {}", revision_id),
            },
            snapshot,
            checksum,
        }))
    }
}

impl ConfigRevisionRepository for FileRevisionRepository {
    fn save_revision(&mut self, record: RevisionRecord) -> Result<(), AppError> {
        self.ensure_layout()?;
        let path = self.revision_path(&record.revision.id);
        let temp_path = path.with_extension("toml.tmp");
        fs::write(&temp_path, render_mvp_config_snapshot(&record.snapshot))
            .map_err(config_store_error)?;
        fs::rename(temp_path, path).map_err(config_store_error)
    }
    fn set_current(&mut self, revision_id: &ConfigRevisionId) -> Result<(), AppError> {
        self.ensure_layout()?;
        if self.find_revision(revision_id)?.is_none() {
            return Err(AppError::new(
                ErrorCode::ConfigRevisionNotFound,
                format!("revision not found: {revision_id}"),
            ));
        }
        let path = self.current_path();
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, revision_id.as_str()).map_err(config_store_error)?;
        fs::rename(temp_path, path).map_err(config_store_error)
    }
    fn current_revision_id(&self) -> Result<Option<ConfigRevisionId>, AppError> {
        let path = self.current_path();
        if !path.exists() {
            return Ok(None);
        }
        let revision_id = fs::read_to_string(path).map_err(config_store_error)?;
        Ok(Some(ConfigRevisionId::new(revision_id.trim())))
    }
    fn current(&self) -> Result<Option<RevisionRecord>, AppError> {
        let Some(revision_id) = self.current_revision_id()? else {
            return Ok(None);
        };
        self.find_revision(&revision_id)
    }
    fn find_revision(
        &self,
        revision_id: &ConfigRevisionId,
    ) -> Result<Option<RevisionRecord>, AppError> {
        self.read_record(revision_id)
    }
    fn history(&self) -> Result<Vec<RevisionRecord>, AppError> {
        let dir = self.revisions_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        let mut entries = fs::read_dir(dir)
            .map_err(config_store_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(config_store_error)?;
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            let Some(revision_id) = hex_decode(stem) else {
                continue;
            };
            if let Some(record) = self.find_revision(&ConfigRevisionId::new(revision_id))? {
                records.push(record);
            }
        }
        Ok(records)
    }
}
