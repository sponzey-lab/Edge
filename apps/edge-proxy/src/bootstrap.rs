use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::Path;

use edge_domain::{BootstrapConfig, LogMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevServeConfig {
    pub listen: SocketAddr,
    pub upstream_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeClientMode {
    Fake,
    LetsEncryptStaging,
}

impl AcmeClientMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fake => "fake",
            Self::LetsEncryptStaging => "letsencrypt-staging",
        }
    }
}

/// Reads environment variables exactly once at the process bootstrap boundary.
pub fn bootstrap_config_from_env() -> BootstrapConfig {
    let data_dir = env::var("SPONZEY_DATA_DIR").unwrap_or_else(|_| ".sponzey".to_string());
    let config_file = env::var("SPONZEY_CONFIG_FILE")
        .unwrap_or_else(|_| format!("{data_dir}/config/current.toml"));
    let admin_bind =
        env::var("SPONZEY_ADMIN_BIND").unwrap_or_else(|_| "127.0.0.1:9443".to_string());
    let log_mode = env::var("SPONZEY_LOG_MODE")
        .ok()
        .and_then(|value| value.parse::<LogMode>().ok())
        .unwrap_or(LogMode::Product);

    BootstrapConfig::new(data_dir, config_file, admin_bind, log_mode)
}

pub fn acme_client_mode_from_env() -> io::Result<AcmeClientMode> {
    acme_client_mode_from_lookup(|name| env::var(name).ok())
}

pub fn acme_client_mode_from_lookup(
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> io::Result<AcmeClientMode> {
    match lookup("SPONZEY_ACME_CLIENT").as_deref() {
        None | Some("") | Some("fake") => Ok(AcmeClientMode::Fake),
        Some("letsencrypt-staging") => Ok(AcmeClientMode::LetsEncryptStaging),
        Some(value) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SPONZEY_ACME_CLIENT must be fake or letsencrypt-staging, got {value}"),
        )),
    }
}

pub fn dev_serve_config_from_env() -> Option<DevServeConfig> {
    dev_serve_config_from_lookup(|name| env::var(name).ok())
}

pub fn dev_serve_config_from_lookup(
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Option<DevServeConfig> {
    let listen = lookup("SPONZEY_DEV_LISTEN")?;
    let upstream_url = lookup("SPONZEY_DEV_UPSTREAM_URL")?;
    let listen = listen.parse::<SocketAddr>().ok()?;
    Some(DevServeConfig {
        listen,
        upstream_url,
    })
}

pub fn ensure_data_layout(data_dir: &str) -> io::Result<()> {
    let root = Path::new(data_dir);
    for relative in [
        "config",
        "config/revisions",
        "certs",
        "secrets",
        "logs",
        "backups",
        "support",
    ] {
        std::fs::create_dir_all(root.join(relative))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_safe_admin_bind() {
        let config = BootstrapConfig::new(
            ".sponzey",
            ".sponzey/config/current.toml",
            "127.0.0.1:9443",
            LogMode::Product,
        );

        assert_eq!(config.admin_bind, "127.0.0.1:9443");
        assert_eq!(config.log_mode, LogMode::Product);
    }

    #[test]
    fn ensures_runtime_data_layout() {
        let root = std::env::temp_dir().join(format!(
            "sponzey-edge-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        ensure_data_layout(root.to_str().unwrap()).unwrap();

        assert!(root.join("config").is_dir());
        assert!(root.join("config/revisions").is_dir());
        assert!(root.join("certs").is_dir());
        assert!(root.join("secrets").is_dir());
        assert!(root.join("logs").is_dir());
        assert!(root.join("backups").is_dir());
        assert!(root.join("support").is_dir());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dev_serve_config_uses_explicit_dev_prefix() {
        let config = dev_serve_config_from_lookup(|name| match name {
            "SPONZEY_DEV_LISTEN" => Some("127.0.0.1:8080".to_string()),
            "SPONZEY_DEV_UPSTREAM_URL" => Some("http://127.0.0.1:3000".to_string()),
            _ => None,
        })
        .expect("dev serve config");

        assert_eq!(config.listen.to_string(), "127.0.0.1:8080");
        assert_eq!(config.upstream_url, "http://127.0.0.1:3000");
    }

    #[test]
    fn dev_serve_config_ignores_legacy_shortcut_names() {
        let config = dev_serve_config_from_lookup(|name| match name {
            "SPONZEY_LISTEN" => Some("127.0.0.1:8080".to_string()),
            "SPONZEY_UPSTREAM_URL" => Some("http://127.0.0.1:3000".to_string()),
            _ => None,
        });

        assert!(config.is_none());
    }

    #[test]
    fn acme_client_mode_defaults_to_fake_for_automatic_smoke() {
        let mode = acme_client_mode_from_lookup(|_| None).unwrap();

        assert_eq!(mode, AcmeClientMode::Fake);
    }

    #[test]
    fn acme_client_mode_accepts_explicit_letsencrypt_staging() {
        let mode = acme_client_mode_from_lookup(|name| match name {
            "SPONZEY_ACME_CLIENT" => Some("letsencrypt-staging".to_string()),
            _ => None,
        })
        .unwrap();

        assert_eq!(mode, AcmeClientMode::LetsEncryptStaging);
    }

    #[test]
    fn acme_client_mode_rejects_unknown_values() {
        let error = acme_client_mode_from_lookup(|name| match name {
            "SPONZEY_ACME_CLIENT" => Some("production".to_string()),
            _ => None,
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
