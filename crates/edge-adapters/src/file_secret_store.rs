//! File-backed secret-store port adapter.

use std::fs;
use std::path::PathBuf;

use edge_domain::AppError;
use edge_ports::{SecretRecord, SecretStore};

use crate::{config_store_error, hex_encode, write_atomic_private_file};

#[derive(Debug, Clone)]
pub struct FileSecretStore {
    root: PathBuf,
}

impl FileSecretStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn secret_path(&self, name: &str) -> PathBuf {
        self.root.join(format!("{}.secret", secret_file_stem(name)))
    }
}

impl SecretStore for FileSecretStore {
    fn save_secret(&mut self, secret: SecretRecord) -> Result<(), AppError> {
        fs::create_dir_all(&self.root).map_err(config_store_error)?;
        let path = self.secret_path(&secret.name);
        write_atomic_private_file(&path, secret.value.as_bytes(), config_store_error)
    }

    fn load_secret(&self, name: &str) -> Result<Option<SecretRecord>, AppError> {
        let path = self.secret_path(name);
        if !path.exists() {
            return Ok(None);
        }
        let value = fs::read_to_string(path).map_err(config_store_error)?;
        Ok(Some(SecretRecord {
            name: name.to_string(),
            value: value.trim().to_string(),
        }))
    }
}

fn secret_file_stem(name: &str) -> String {
    if !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        name.to_string()
    } else {
        hex_encode(name)
    }
}
