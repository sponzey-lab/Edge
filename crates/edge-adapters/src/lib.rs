//! External-system adapters.
//!
//! Filesystem, certificate store, metrics, audit, and future ACME/DNS adapters
//! belong here, behind ports.

mod backup;
pub use backup::*;
mod audit_ledger;
pub use audit_ledger::*;
mod data_directory_lock;
pub use data_directory_lock::*;
mod file_secret_store;
pub use file_secret_store::FileSecretStore;
mod file_trust_bundle_store;
pub use file_trust_bundle_store::FileTrustBundleStore;
mod file_revision_repository;
pub use file_revision_repository::{FileBootstrapConfigSeed, FileRevisionRepository};
mod health_probe_tls_registry;
pub use health_probe_tls_registry::*;
mod health_probe_worker_pool;
pub use health_probe_worker_pool::*;
mod health_probe_transport;
pub use health_probe_transport::*;
mod metrics_runtime;
pub use metrics_runtime::*;
mod operational_upgrade;
pub use operational_upgrade::*;
mod support_bundle;
pub use support_bundle::*;
mod structured_log_json;
use structured_log_json::render_log_json_line;
mod trust_bundle_metadata_codec;
use trust_bundle_metadata_codec::{hex_encode_bytes, parse_trust_metadata};
mod trust_bundle_safe_file;
use trust_bundle_safe_file::{read_owner_file_nofollow, sync_directory, write_synced_owner_file};

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(test)]
use std::fs::OpenOptions;
#[cfg(test)]
use std::io::ErrorKind;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
#[cfg(test)]
use std::{net::TcpStream, time::Instant};

#[cfg(test)]
use edge_application::{checksum_snapshot, parse_mvp_config};
use edge_domain::{AppError, CertificateRef, ConfigRevisionId, ErrorCode, TrustBundleRef};
use edge_ports::{
    AcmeClient, AcmeHttp01ChallengeRuntime, AcmeOrderRequest, AcmeOrderResult, AuditEvent,
    AuditSink, CertificateMaterial, CertificateMaterialValidator, CertificateStore,
    ClientTlsSessionFactory, ConfigRevisionRepository, LogSink, MetricEvent, MetricsSink,
    RevisionRecord, ServerTlsSessionFactory, StoredCertificate, StructuredLogEvent,
    TlsPendingBytes, TlsSession, TlsSessionInterest, TlsSessionProgress,
    TrustBundleMaterialValidator, TrustBundleMetadata, ValidatedCertificateMaterial,
    ValidatedTrustBundle,
};
#[cfg(test)]
use edge_ports::{
    BackupArchiveReader, BackupArchiveWriter, BackupArtifactSource, RestoreArchiveExtractor,
    RestorePreflight, RestorePublisher, RestoreReplacePublisher, RestoreTransactionState,
    RestoreTransactionStore,
};
#[cfg(test)]
use edge_ports::{SecretRecord, SecretStore};
use rustls_pki_types::pem::{PemObject, SectionKind};
use sha2::Digest;
use x509_parser::prelude::FromDer;

/// Foundation smoke helper.
pub fn crate_name() -> &'static str {
    "edge-adapters"
}

#[derive(Debug, Clone)]
pub struct LetsEncryptHttp01AcmeClient {
    poll_timeout: Duration,
}

impl Default for LetsEncryptHttp01AcmeClient {
    fn default() -> Self {
        Self {
            poll_timeout: Duration::from_secs(30),
        }
    }
}

impl LetsEncryptHttp01AcmeClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_poll_timeout(mut self, poll_timeout: Duration) -> Self {
        self.poll_timeout = poll_timeout;
        self
    }

    async fn issue_certificate_http01_async(
        &self,
        request: AcmeOrderRequest,
        challenge_runtime: &mut dyn AcmeHttp01ChallengeRuntime,
    ) -> Result<AcmeOrderResult, AppError> {
        if request.production {
            return Err(AppError::new(
                ErrorCode::ConfigProductionAcmeRequiresOptIn,
                "letsencrypt-staging ACME client does not allow production ACME",
            ));
        }
        if !request.terms_accepted {
            return Err(AppError::new(
                ErrorCode::AcmeTermsNotAccepted,
                "Let's Encrypt staging requires terms acceptance",
            ));
        }

        let contact = format!("mailto:{}", request.account_email);
        let contact_refs = [contact.as_str()];
        let directory_url = instant_acme::LetsEncrypt::Staging.url();

        let (account, _credentials) = instant_acme::Account::builder()
            .map_err(acme_client_error)?
            .create(
                &instant_acme::NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: request.terms_accepted,
                    only_return_existing: false,
                },
                directory_url.to_string(),
                None,
            )
            .await
            .map_err(acme_client_error)?;

        let identifiers = request
            .domains
            .iter()
            .cloned()
            .map(instant_acme::Identifier::Dns)
            .collect::<Vec<_>>();
        let mut order = account
            .new_order(&instant_acme::NewOrder::new(identifiers.as_slice()))
            .await
            .map_err(acme_client_error)?;

        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authorization = result.map_err(acme_client_error)?;
            match authorization.status {
                instant_acme::AuthorizationStatus::Pending => {}
                instant_acme::AuthorizationStatus::Valid => continue,
                status => {
                    return Err(acme_client_error(format!(
                        "unexpected authorization status: {status:?}"
                    )))
                }
            }

            let mut challenge = authorization
                .challenge(instant_acme::ChallengeType::Http01)
                .ok_or_else(|| acme_client_error("no HTTP-01 challenge found"))?;
            let token = challenge.token.clone();
            let key_authorization = challenge.key_authorization().as_str().to_string();
            challenge_runtime.present_http01(token.clone(), key_authorization.clone())?;
            challenge_runtime.verify_http01(&token, &key_authorization)?;
            challenge.set_ready().await.map_err(acme_client_error)?;
        }

        let retry_policy = instant_acme::RetryPolicy::default().timeout(self.poll_timeout);
        let status = order
            .poll_ready(&retry_policy)
            .await
            .map_err(acme_client_error)?;
        if status != instant_acme::OrderStatus::Ready {
            return Err(acme_client_error(format!(
                "unexpected ACME order status before finalize: {status:?}"
            )));
        }

        let private_key_pem = order.finalize().await.map_err(acme_client_error)?;
        let certificate_pem = order
            .poll_certificate(&retry_policy)
            .await
            .map_err(acme_client_error)?;
        let not_after_epoch_seconds = certificate_chain_not_after_epoch_seconds(&certificate_pem)?;
        let certificate_ref = CertificateRef::new(format!(
            "letsencrypt-{}",
            request.domains.join("-").replace('.', "-")
        ));

        Ok(AcmeOrderResult {
            certificate: StoredCertificate {
                certificate_ref,
                domains: request.domains,
                not_after_epoch_seconds,
                source: "letsencrypt_staging".to_string(),
                certificate_pem,
                private_key_pem,
            },
        })
    }
}

impl AcmeClient for LetsEncryptHttp01AcmeClient {
    fn issue_certificate(
        &mut self,
        _request: AcmeOrderRequest,
    ) -> Result<AcmeOrderResult, AppError> {
        Err(AppError::new(
            ErrorCode::AcmeChallengeFailed,
            "Let's Encrypt HTTP-01 client requires an explicit challenge runtime",
        ))
    }

    fn issue_certificate_http01(
        &mut self,
        request: AcmeOrderRequest,
        challenge_runtime: &mut dyn AcmeHttp01ChallengeRuntime,
    ) -> Result<AcmeOrderResult, AppError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(acme_client_error)?;
        runtime.block_on(self.issue_certificate_http01_async(request, challenge_runtime))
    }
}

fn acme_client_error(error: impl std::fmt::Display) -> AppError {
    AppError::new(ErrorCode::AcmeChallengeFailed, error.to_string())
}

fn certificate_chain_not_after_epoch_seconds(certificate_pem: &str) -> Result<u64, AppError> {
    let mut certificates =
        rustls_pki_types::CertificateDer::pem_slice_iter(certificate_pem.as_bytes());
    let first_certificate = certificates
        .next()
        .ok_or_else(|| certificate_parse_error("certificate chain is empty"))?
        .map_err(certificate_parse_error)?;
    let (_, certificate) =
        x509_parser::prelude::X509Certificate::from_der(first_certificate.as_ref())
            .map_err(certificate_parse_error)?;
    let timestamp = certificate.validity().not_after.timestamp();
    u64::try_from(timestamp).map_err(certificate_parse_error)
}

fn certificate_chain_leaf_dns_names(certificate_pem: &str) -> Result<Vec<String>, AppError> {
    let mut certificates =
        rustls_pki_types::CertificateDer::pem_slice_iter(certificate_pem.as_bytes());
    let first_certificate = certificates
        .next()
        .ok_or_else(|| certificate_parse_error("certificate chain is empty"))?
        .map_err(certificate_parse_error)?;
    let (_, certificate) =
        x509_parser::prelude::X509Certificate::from_der(first_certificate.as_ref())
            .map_err(certificate_parse_error)?;
    let Some(san) = certificate
        .subject_alternative_name()
        .map_err(certificate_parse_error)?
    else {
        return Ok(Vec::new());
    };
    let mut dns_names = Vec::new();
    for name in &san.value.general_names {
        if let x509_parser::extensions::GeneralName::DNSName(dns_name) = name {
            dns_names.push(dns_name.to_ascii_lowercase());
        }
    }
    Ok(dns_names)
}

fn certificate_parse_error(error: impl std::fmt::Display) -> AppError {
    AppError::new(ErrorCode::CertificateStoreFailed, error.to_string())
}

#[derive(Debug, Default, Clone)]
pub struct MemoryRevisionRepository {
    records: Vec<RevisionRecord>,
    current: Option<ConfigRevisionId>,
}

impl ConfigRevisionRepository for MemoryRevisionRepository {
    fn save_revision(&mut self, record: RevisionRecord) -> Result<(), AppError> {
        self.records.push(record);
        Ok(())
    }

    fn set_current(&mut self, revision_id: &ConfigRevisionId) -> Result<(), AppError> {
        if self
            .records
            .iter()
            .any(|record| &record.revision.id == revision_id)
        {
            self.current = Some(revision_id.clone());
            Ok(())
        } else {
            Err(AppError::new(
                ErrorCode::ConfigSchemaVersionMissing,
                "revision not found",
            ))
        }
    }

    fn current_revision_id(&self) -> Result<Option<ConfigRevisionId>, AppError> {
        Ok(self.current.clone())
    }

    fn current(&self) -> Result<Option<RevisionRecord>, AppError> {
        Ok(self.current.as_ref().and_then(|current| {
            self.records
                .iter()
                .find(|record| &record.revision.id == current)
                .cloned()
        }))
    }

    fn find_revision(
        &self,
        revision_id: &ConfigRevisionId,
    ) -> Result<Option<RevisionRecord>, AppError> {
        Ok(self
            .records
            .iter()
            .find(|record| &record.revision.id == revision_id)
            .cloned())
    }

    fn history(&self) -> Result<Vec<RevisionRecord>, AppError> {
        Ok(self.records.clone())
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryAuditSink {
    events: Vec<AuditEvent>,
}

fn config_store_error(error: std::io::Error) -> AppError {
    AppError::new(ErrorCode::ConfigStoreFailed, error.to_string())
}

fn certificate_store_error(error: std::io::Error) -> AppError {
    AppError::new(ErrorCode::CertificateStoreFailed, error.to_string())
}

fn hex_encode(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hex_decode(value: &str) -> Option<String> {
    if !value.len().is_multiple_of(2) {
        return None;
    }

    let bytes = value
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let text = std::str::from_utf8(chunk).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect::<Option<Vec<_>>>()?;
    String::from_utf8(bytes).ok()
}

impl MemoryAuditSink {
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&mut self, event: AuditEvent) -> Result<(), AppError> {
        self.events.push(event);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct RustlsTrustBundleMaterialValidator;

impl TrustBundleMaterialValidator for RustlsTrustBundleMaterialValidator {
    fn validate_trust_bundle(
        &mut self,
        trust_bundle_ref: &TrustBundleRef,
        encoded_material: &[u8],
        imported_at_epoch_seconds: u64,
    ) -> Result<ValidatedTrustBundle, AppError> {
        if encoded_material.is_empty() {
            return Err(trust_bundle_invalid());
        }
        if encoded_material.len() > 384 * 1024 {
            return Err(trust_bundle_limit());
        }
        let mut certificates = Vec::new();
        let mut unique = BTreeSet::new();
        let mut decoded_bytes = 0_usize;
        for section in <(SectionKind, Vec<u8>) as PemObject>::pem_slice_iter(encoded_material) {
            let (kind, certificate) = section.map_err(|_| trust_bundle_invalid())?;
            if kind != SectionKind::Certificate {
                return Err(trust_bundle_invalid());
            }
            decoded_bytes = decoded_bytes
                .checked_add(certificate.len())
                .ok_or_else(trust_bundle_limit)?;
            if decoded_bytes > 256 * 1024 || certificates.len() >= 32 {
                return Err(trust_bundle_limit());
            }
            if !unique.insert(certificate.clone()) {
                return Err(trust_bundle_invalid());
            }
            let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(&certificate)
                .map_err(|_| trust_bundle_invalid())?;
            let is_ca = parsed
                .basic_constraints()
                .map_err(|_| trust_bundle_invalid())?
                .is_some_and(|constraints| constraints.value.ca);
            if !is_ca {
                return Err(trust_bundle_invalid());
            }
            certificates.push(certificate);
        }
        if certificates.is_empty() {
            return Err(trust_bundle_invalid());
        }
        Ok(ValidatedTrustBundle::new(
            TrustBundleMetadata {
                trust_bundle_ref: trust_bundle_ref.clone(),
                certificate_count: certificates.len() as u8,
                imported_at_epoch_seconds,
                content_sha256: sha2::Sha256::digest(encoded_material).into(),
            },
            encoded_material.to_vec(),
        ))
    }
}

fn trust_bundle_invalid() -> AppError {
    AppError::new(
        ErrorCode::TrustBundleInvalid,
        "trust bundle material is invalid",
    )
}

fn trust_bundle_limit() -> AppError {
    AppError::new(
        ErrorCode::TrustBundleLimitExceeded,
        "trust bundle material limit exceeded",
    )
}

fn trust_bundle_store_error(_error: io::Error) -> AppError {
    AppError::new(
        ErrorCode::TrustBundleStoreFailed,
        "trust bundle store operation failed",
    )
}

#[derive(Debug, Clone)]
pub struct FileCertificateStore {
    root: PathBuf,
}

impl FileCertificateStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn certificate_dir(&self, certificate_ref: &CertificateRef) -> PathBuf {
        self.root
            .join(certificate_ref_dir_name(certificate_ref.as_str()))
    }

    fn read_certificate_from_dir(&self, dir: &Path) -> Result<StoredCertificate, AppError> {
        let metadata = parse_certificate_metadata(
            &fs::read_to_string(dir.join("metadata.toml")).map_err(certificate_store_error)?,
        )?;
        let certificate_pem =
            fs::read_to_string(dir.join("fullchain.pem")).map_err(certificate_store_error)?;
        let private_key_pem =
            fs::read_to_string(dir.join("privkey.pem")).map_err(certificate_store_error)?;

        Ok(StoredCertificate {
            certificate_ref: metadata.certificate_ref,
            domains: metadata.domains,
            not_after_epoch_seconds: metadata.not_after_epoch_seconds,
            source: metadata.source,
            certificate_pem,
            private_key_pem,
        })
    }
}

impl CertificateStore for FileCertificateStore {
    fn save_certificate(&mut self, certificate: StoredCertificate) -> Result<(), AppError> {
        let dir = self.certificate_dir(&certificate.certificate_ref);
        fs::create_dir_all(&dir).map_err(certificate_store_error)?;
        write_atomic_file(
            &dir.join("fullchain.pem"),
            certificate.certificate_pem.as_bytes(),
        )?;
        write_atomic_private_file(
            &dir.join("privkey.pem"),
            certificate.private_key_pem.as_bytes(),
            certificate_store_error,
        )?;
        write_atomic_file(
            &dir.join("metadata.toml"),
            render_certificate_metadata(&certificate).as_bytes(),
        )
    }

    fn load_certificate(
        &self,
        certificate_ref: &CertificateRef,
    ) -> Result<Option<StoredCertificate>, AppError> {
        let dir = self.certificate_dir(certificate_ref);
        if !dir.exists() {
            return Ok(None);
        }

        let certificate = self.read_certificate_from_dir(&dir)?;
        if certificate.certificate_ref != *certificate_ref {
            return Err(AppError::new(
                ErrorCode::CertificateStoreFailed,
                format!(
                    "certificate metadata ref mismatch: requested={}, stored={}",
                    certificate_ref.as_str(),
                    certificate.certificate_ref.as_str()
                ),
            ));
        }
        Ok(Some(certificate))
    }

    fn list_certificates(&self) -> Result<Vec<StoredCertificate>, AppError> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }

        let mut entries = fs::read_dir(&self.root)
            .map_err(certificate_store_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(certificate_store_error)?;
        entries.sort_by_key(|entry| entry.path());

        let mut certificates = Vec::new();
        for entry in entries {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".tmp-"))
            {
                continue;
            }
            if !path.join("metadata.toml").exists() {
                continue;
            }
            certificates.push(self.read_certificate_from_dir(&path)?);
        }
        certificates.sort_by(|left, right| left.certificate_ref.cmp(&right.certificate_ref));
        Ok(certificates)
    }

    fn delete_certificate(&mut self, certificate_ref: &CertificateRef) -> Result<(), AppError> {
        let dir = self.certificate_dir(certificate_ref);
        if !dir.exists() {
            return Ok(());
        }
        fs::remove_dir_all(dir).map_err(certificate_store_error)
    }
}

#[derive(Debug, Clone)]
pub struct LoadedRustlsServerConfig {
    pub certificate_ref: CertificateRef,
    pub domains: Vec<String>,
    pub server_config: Arc<rustls::ServerConfig>,
    certified_key: Arc<rustls::sign::CertifiedKey>,
}

#[derive(Debug, Clone)]
pub struct TlsRuntimeSnapshot {
    configs: BTreeMap<CertificateRef, LoadedRustlsServerConfig>,
    certificate_refs_by_hostname: BTreeMap<String, CertificateRef>,
    default_certificate_ref: CertificateRef,
}

impl TlsRuntimeSnapshot {
    pub fn from_configs(
        configs: Vec<LoadedRustlsServerConfig>,
    ) -> Result<TlsRuntimeSnapshot, AppError> {
        let mut by_ref = BTreeMap::new();
        let mut by_hostname = BTreeMap::new();
        for config in configs {
            let certificate_ref = config.certificate_ref.clone();
            for domain in &config.domains {
                let Some(hostname) = normalize_tls_hostname(domain) else {
                    continue;
                };
                if let Some(existing) =
                    by_hostname.insert(hostname.clone(), certificate_ref.clone())
                {
                    return Err(AppError::new(
                        ErrorCode::CertificateStoreFailed,
                        format!(
                            "duplicate TLS SNI hostname {hostname} for certificate refs {} and {}",
                            existing.as_str(),
                            certificate_ref.as_str()
                        ),
                    ));
                }
            }
            if by_ref.insert(certificate_ref.clone(), config).is_some() {
                return Err(AppError::new(
                    ErrorCode::CertificateStoreFailed,
                    format!(
                        "duplicate loaded TLS certificate config: {}",
                        certificate_ref.as_str()
                    ),
                ));
            }
        }
        let default_certificate_ref = by_ref.keys().next().cloned().ok_or_else(|| {
            AppError::new(
                ErrorCode::CertificateNotFound,
                "TLS runtime snapshot requires at least one certificate config",
            )
        })?;

        Ok(Self {
            configs: by_ref,
            certificate_refs_by_hostname: by_hostname,
            default_certificate_ref,
        })
    }

    pub fn default_config(&self) -> &LoadedRustlsServerConfig {
        self.configs
            .get(&self.default_certificate_ref)
            .expect("TLS runtime snapshot invariant: default config exists")
    }

    pub fn get(&self, certificate_ref: &CertificateRef) -> Option<&LoadedRustlsServerConfig> {
        self.configs.get(certificate_ref)
    }

    pub fn replace_config(&mut self, config: LoadedRustlsServerConfig) -> Result<(), AppError> {
        let certificate_ref = config.certificate_ref.clone();
        let mut next_certificate_refs_by_hostname = self.certificate_refs_by_hostname.clone();
        next_certificate_refs_by_hostname.retain(|_, existing| existing != &certificate_ref);
        for domain in &config.domains {
            if let Some(hostname) = normalize_tls_hostname(domain) {
                if let Some(existing) = next_certificate_refs_by_hostname
                    .insert(hostname.clone(), certificate_ref.clone())
                {
                    return Err(AppError::new(
                        ErrorCode::CertificateStoreFailed,
                        format!(
                            "duplicate TLS SNI hostname {hostname} for certificate refs {} and {}",
                            existing.as_str(),
                            certificate_ref.as_str()
                        ),
                    ));
                }
            }
        }
        self.certificate_refs_by_hostname = next_certificate_refs_by_hostname;
        self.configs.insert(config.certificate_ref.clone(), config);
        Ok(())
    }

    pub fn select_certificate_ref_for_sni(&self, server_name: &str) -> Option<&CertificateRef> {
        let hostname = normalize_tls_hostname(server_name)?;
        self.certificate_refs_by_hostname.get(&hostname)
    }

    pub fn sni_server_config(&self) -> Result<Arc<rustls::ServerConfig>, AppError> {
        let certified_keys_by_hostname = self.certified_keys_by_hostname()?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(tls_loader_error)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SniServerCertResolver {
                certified_keys_by_hostname,
            }));
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(server_config))
    }

    pub fn sni_server_config_with_required_client_auth(
        &self,
        trust_bundle: &ValidatedTrustBundle,
    ) -> Result<Arc<rustls::ServerConfig>, AppError> {
        let mut roots = rustls::RootCertStore::empty();
        let certificates =
            rustls_pki_types::CertificateDer::pem_slice_iter(trust_bundle.encoded_material())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| client_auth_profile_invalid())?;
        if certificates.is_empty() {
            return Err(client_auth_profile_invalid());
        }
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|_| client_auth_profile_invalid())?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|_| client_auth_profile_invalid())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| client_auth_profile_invalid())?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(SniServerCertResolver {
                certified_keys_by_hostname: self.certified_keys_by_hostname()?,
            }));
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(server_config))
    }

    fn certified_keys_by_hostname(
        &self,
    ) -> Result<BTreeMap<String, Arc<rustls::sign::CertifiedKey>>, AppError> {
        let mut certified_keys_by_hostname = BTreeMap::new();
        for (hostname, certificate_ref) in &self.certificate_refs_by_hostname {
            let config = self.configs.get(certificate_ref).ok_or_else(|| {
                AppError::new(
                    ErrorCode::CertificateStoreFailed,
                    format!(
                        "TLS SNI hostname {} references missing certificate {}",
                        hostname,
                        certificate_ref.as_str()
                    ),
                )
            })?;
            certified_keys_by_hostname.insert(hostname.clone(), Arc::clone(&config.certified_key));
        }
        Ok(certified_keys_by_hostname)
    }

    pub fn certificate_refs(&self) -> Vec<CertificateRef> {
        self.configs.keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.configs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }
}

fn client_auth_profile_invalid() -> AppError {
    AppError::new(
        ErrorCode::ConfigClientAuthPolicyInvalid,
        "client authentication trust profile is invalid",
    )
}

#[derive(Debug)]
struct SniServerCertResolver {
    certified_keys_by_hostname: BTreeMap<String, Arc<rustls::sign::CertifiedKey>>,
}

impl rustls::server::ResolvesServerCert for SniServerCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let hostname = normalize_tls_hostname(client_hello.server_name()?)?;
        self.certified_keys_by_hostname.get(&hostname).cloned()
    }
}

fn normalize_tls_hostname(hostname: &str) -> Option<String> {
    let normalized = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

pub fn load_rustls_server_config(
    certificate: &StoredCertificate,
) -> Result<LoadedRustlsServerConfig, AppError> {
    use rustls_pki_types::pem::PemObject;

    let cert_chain =
        rustls_pki_types::CertificateDer::pem_slice_iter(certificate.certificate_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(tls_loader_error)?;
    if cert_chain.is_empty() {
        return Err(AppError::new(
            ErrorCode::CertificateStoreFailed,
            "certificate PEM has no certificate entries",
        ));
    }

    let private_key =
        rustls_pki_types::PrivateKeyDer::from_pem_slice(certificate.private_key_pem.as_bytes())
            .map_err(tls_loader_error)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certified_key = rustls::sign::CertifiedKey::from_der(
        cert_chain.clone(),
        private_key.clone_key(),
        provider.as_ref(),
    )
    .map_err(tls_loader_error)?;
    certified_key.keys_match().map_err(tls_loader_error)?;
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(tls_loader_error)?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(tls_loader_error)?;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(LoadedRustlsServerConfig {
        certificate_ref: certificate.certificate_ref.clone(),
        domains: certificate.domains.clone(),
        server_config: Arc::new(server_config),
        certified_key: Arc::new(certified_key),
    })
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RustlsCertificateMaterialValidator;

impl CertificateMaterialValidator for RustlsCertificateMaterialValidator {
    fn validate(
        &mut self,
        material: &CertificateMaterial,
    ) -> Result<ValidatedCertificateMaterial, AppError> {
        let not_after_epoch_seconds =
            certificate_chain_not_after_epoch_seconds(&material.certificate_pem)
                .map_err(|_| invalid_certificate_material())?;
        let dns_names = certificate_chain_leaf_dns_names(&material.certificate_pem)
            .map_err(|_| invalid_certificate_material())?;
        let certificate = StoredCertificate {
            certificate_ref: CertificateRef::new("manual-import-validation"),
            domains: vec!["manual-import-validation.invalid".to_string()],
            not_after_epoch_seconds,
            source: "manual".to_string(),
            certificate_pem: material.certificate_pem.clone(),
            private_key_pem: material.private_key_pem.clone(),
        };
        load_rustls_server_config(&certificate).map_err(|_| invalid_certificate_material())?;
        Ok(ValidatedCertificateMaterial {
            not_after_epoch_seconds,
            dns_names,
        })
    }
}

fn invalid_certificate_material() -> AppError {
    AppError::new(
        ErrorCode::CertificateInvalid,
        "certificate and private key must be valid and match",
    )
}

#[derive(Debug, Clone)]
pub struct RustlsServerTlsSessionFactory {
    server_config: Arc<rustls::ServerConfig>,
}

impl RustlsServerTlsSessionFactory {
    pub fn new(server_config: Arc<rustls::ServerConfig>) -> Self {
        Self { server_config }
    }
}

impl ServerTlsSessionFactory for RustlsServerTlsSessionFactory {
    fn create_server_session(&self) -> Box<dyn TlsSession + Send> {
        Box::new(RustlsTlsSession::new_server(Arc::clone(
            &self.server_config,
        )))
    }
}

#[derive(Debug, Clone)]
pub struct RustlsClientTlsSessionFactory {
    client_config: Arc<rustls::ClientConfig>,
}

impl RustlsClientTlsSessionFactory {
    pub fn from_trust_bundle(bundle: &ValidatedTrustBundle) -> Result<Self, AppError> {
        Self::from_trust_bundle_with_time_provider(
            bundle,
            Arc::new(rustls::time_provider::DefaultTimeProvider),
        )
    }

    pub fn from_trust_bundle_with_time_provider(
        bundle: &ValidatedTrustBundle,
        time_provider: Arc<dyn rustls::time_provider::TimeProvider>,
    ) -> Result<Self, AppError> {
        let mut roots = rustls::RootCertStore::empty();
        let certificates =
            rustls_pki_types::CertificateDer::pem_slice_iter(bundle.encoded_material())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| upstream_tls_profile_invalid())?;
        if certificates.is_empty() {
            return Err(upstream_tls_profile_invalid());
        }
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|_| upstream_tls_profile_invalid())?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client_config = rustls::ClientConfig::builder_with_details(provider, time_provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| upstream_tls_profile_invalid())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            client_config: Arc::new(client_config),
        })
    }
}

impl ClientTlsSessionFactory for RustlsClientTlsSessionFactory {
    fn create_client_session(
        &self,
        server_name: &edge_domain::TlsServerName,
    ) -> Result<Box<dyn TlsSession + Send>, AppError> {
        let server_name = rustls_pki_types::ServerName::try_from(server_name.as_str().to_string())
            .map_err(|_| upstream_tls_profile_invalid())?;
        Ok(Box::new(RustlsTlsSession::new_client(
            Arc::clone(&self.client_config),
            server_name,
        )?))
    }
}

fn upstream_tls_profile_invalid() -> AppError {
    AppError::new(
        ErrorCode::UpstreamTlsProfileInvalid,
        "upstream TLS profile is invalid",
    )
}

struct RustlsTlsSession {
    connection: rustls::Connection,
    decrypted: Vec<u8>,
    encrypted: Vec<u8>,
    failed: Option<ErrorCode>,
    closing: bool,
    failure_code: ErrorCode,
}

impl RustlsTlsSession {
    fn new_server(server_config: Arc<rustls::ServerConfig>) -> Self {
        let connection = rustls::ServerConnection::new(server_config)
            .expect("validated rustls server config should create server connections");
        Self {
            connection: rustls::Connection::Server(connection),
            decrypted: Vec::new(),
            encrypted: Vec::new(),
            failed: None,
            closing: false,
            failure_code: ErrorCode::TlsHandshakeFailed,
        }
    }

    fn new_client(
        client_config: Arc<rustls::ClientConfig>,
        server_name: rustls_pki_types::ServerName<'static>,
    ) -> Result<Self, AppError> {
        let connection = rustls::ClientConnection::new(client_config, server_name)
            .map_err(|_| upstream_tls_profile_invalid())?;
        let mut session = Self {
            connection: rustls::Connection::Client(connection),
            decrypted: Vec::new(),
            encrypted: Vec::new(),
            failed: None,
            closing: false,
            failure_code: ErrorCode::UpstreamTlsUntrusted,
        };
        session.flush_tls_output()?;
        Ok(session)
    }

    fn mark_failed(&mut self, error: impl ToString) -> AppError {
        self.mark_failed_with(self.failure_code, error)
    }

    fn mark_failed_with(&mut self, code: ErrorCode, error: impl ToString) -> AppError {
        self.failed = Some(code);
        let message = match code {
            ErrorCode::UpstreamTlsIdentityMismatch => {
                "upstream TLS identity verification failed".to_string()
            }
            ErrorCode::UpstreamTlsUntrusted => "upstream TLS peer verification failed".to_string(),
            _ => error.to_string(),
        };
        AppError::new(code, message)
    }

    fn flush_tls_output(&mut self) -> Result<(), AppError> {
        self.connection
            .write_tls(&mut self.encrypted)
            .map(|_| ())
            .map_err(|error| self.mark_failed(error))
    }

    fn collect_plaintext(&mut self) -> Result<(), AppError> {
        let mut buffer = [0_u8; 4096];
        loop {
            match self.connection.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => self.decrypted.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(self.mark_failed(error)),
            }
        }
        Ok(())
    }

    fn drain(buffer: &mut Vec<u8>, max_bytes: usize) -> Vec<u8> {
        let drain = buffer.len().min(max_bytes);
        buffer.drain(..drain).collect()
    }
}

impl TlsSession for RustlsTlsSession {
    fn receive_encrypted(&mut self, bytes: &[u8]) -> Result<usize, AppError> {
        if self.failed.is_some() || self.closing {
            return Ok(0);
        }
        let read = self
            .connection
            .read_tls(&mut std::io::Cursor::new(bytes))
            .map_err(|error| self.mark_failed(error))?;
        if let Err(error) = self.connection.process_new_packets() {
            let code = match &error {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::NotValidForName
                    | rustls::CertificateError::NotValidForNameContext { .. },
                ) => ErrorCode::UpstreamTlsIdentityMismatch,
                _ => self.failure_code,
            };
            return Err(self.mark_failed_with(code, error));
        }
        self.collect_plaintext()?;
        self.flush_tls_output()?;
        Ok(read)
    }

    fn take_decrypted(&mut self, max_bytes: usize) -> Vec<u8> {
        Self::drain(&mut self.decrypted, max_bytes)
    }

    fn receive_plaintext(&mut self, bytes: &[u8]) -> Result<usize, AppError> {
        if self.failed.is_some() || self.closing {
            return Ok(0);
        }
        self.connection
            .writer()
            .write_all(bytes)
            .map_err(|error| self.mark_failed(error))?;
        self.flush_tls_output()?;
        Ok(bytes.len())
    }

    fn take_encrypted(&mut self, max_bytes: usize) -> Vec<u8> {
        Self::drain(&mut self.encrypted, max_bytes)
    }

    fn progress(&self) -> TlsSessionProgress {
        if let Some(code) = self.failed {
            return TlsSessionProgress::Failed { code };
        }
        if self.closing {
            return if self.encrypted.is_empty() {
                TlsSessionProgress::PeerClosed
            } else {
                TlsSessionProgress::Closing
            };
        }
        if self.connection.is_handshaking() {
            TlsSessionProgress::Handshaking
        } else {
            TlsSessionProgress::Established
        }
    }

    fn interest(&self) -> TlsSessionInterest {
        if self.failed.is_some() {
            return TlsSessionInterest::none();
        }
        if self.closing {
            return if self.encrypted.is_empty() {
                TlsSessionInterest::none()
            } else {
                TlsSessionInterest::writable()
            };
        }
        if !self.encrypted.is_empty() || self.connection.wants_write() {
            return TlsSessionInterest::writable();
        }
        if self.connection.wants_read() {
            return TlsSessionInterest::readable();
        }
        TlsSessionInterest::none()
    }

    fn pending_bytes(&self) -> TlsPendingBytes {
        TlsPendingBytes::new(0, self.decrypted.len(), self.encrypted.len())
    }

    fn sni_hostname(&self) -> Option<&str> {
        None
    }

    fn request_close_notify(&mut self) -> Result<(), AppError> {
        self.connection.send_close_notify();
        self.flush_tls_output()?;
        self.closing = true;
        Ok(())
    }
}

fn tls_loader_error(error: impl ToString) -> AppError {
    AppError::new(ErrorCode::CertificateStoreFailed, error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CertificateMetadata {
    certificate_ref: CertificateRef,
    domains: Vec<String>,
    not_after_epoch_seconds: u64,
    source: String,
}

fn write_atomic_file(path: &Path, contents: &[u8]) -> Result<(), AppError> {
    let temp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("tmp")
    ));
    fs::write(&temp_path, contents).map_err(certificate_store_error)?;
    fs::rename(&temp_path, path).map_err(certificate_store_error)
}

fn write_atomic_private_file(
    path: &Path,
    contents: &[u8],
    map_error: fn(io::Error) -> AppError,
) -> Result<(), AppError> {
    let temp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("tmp")
    ));
    fs::write(&temp_path, contents).map_err(map_error)?;
    set_private_file_permissions(&temp_path).map_err(map_error)?;
    fs::rename(&temp_path, path).map_err(map_error)
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn render_certificate_metadata(certificate: &StoredCertificate) -> String {
    format!(
        "certificate_ref = \"{}\"\ndomains = [{}]\nnot_after_epoch_seconds = {}\nsource = \"{}\"\n",
        toml_escape(certificate.certificate_ref.as_str()),
        certificate
            .domains
            .iter()
            .map(|domain| format!("\"{}\"", toml_escape(domain)))
            .collect::<Vec<_>>()
            .join(", "),
        certificate.not_after_epoch_seconds,
        toml_escape(&certificate.source)
    )
}

fn parse_certificate_metadata(source: &str) -> Result<CertificateMetadata, AppError> {
    let mut certificate_ref = None;
    let mut domains = None;
    let mut not_after_epoch_seconds = None;
    let mut cert_source = None;

    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(certificate_metadata_error("metadata line is missing '='"));
        };
        match key.trim() {
            "certificate_ref" => {
                certificate_ref = Some(CertificateRef::new(parse_toml_string(value.trim())?));
            }
            "domains" => {
                domains = Some(parse_toml_string_array(value.trim())?);
            }
            "not_after_epoch_seconds" => {
                not_after_epoch_seconds = Some(value.trim().parse::<u64>().map_err(|_| {
                    certificate_metadata_error("not_after_epoch_seconds must be an integer")
                })?);
            }
            "source" => {
                cert_source = Some(parse_toml_string(value.trim())?);
            }
            _ => {}
        }
    }

    Ok(CertificateMetadata {
        certificate_ref: certificate_ref
            .ok_or_else(|| certificate_metadata_error("certificate_ref is missing"))?,
        domains: domains.ok_or_else(|| certificate_metadata_error("domains is missing"))?,
        not_after_epoch_seconds: not_after_epoch_seconds
            .ok_or_else(|| certificate_metadata_error("not_after_epoch_seconds is missing"))?,
        source: cert_source.ok_or_else(|| certificate_metadata_error("source is missing"))?,
    })
}

fn certificate_metadata_error(message: &str) -> AppError {
    AppError::new(ErrorCode::CertificateStoreFailed, message)
}

fn parse_toml_string(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if !value.starts_with('"') || !value.ends_with('"') || value.len() < 2 {
        return Err(certificate_metadata_error("metadata string is invalid"));
    }
    let inner = &value[1..value.len() - 1];
    let mut parsed = String::new();
    let mut escaped = false;
    for character in inner.chars() {
        if escaped {
            match character {
                '"' => parsed.push('"'),
                '\\' => parsed.push('\\'),
                'n' => parsed.push('\n'),
                'r' => parsed.push('\r'),
                't' => parsed.push('\t'),
                _ => return Err(certificate_metadata_error("metadata escape is invalid")),
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            parsed.push(character);
        }
    }
    if escaped {
        return Err(certificate_metadata_error(
            "metadata string has trailing escape",
        ));
    }
    Ok(parsed)
}

fn parse_toml_string_array(value: &str) -> Result<Vec<String>, AppError> {
    let value = value.trim();
    if !value.starts_with('[') || !value.ends_with(']') {
        return Err(certificate_metadata_error("metadata array is invalid"));
    }
    let inner = value[1..value.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    inner
        .split(',')
        .map(|item| parse_toml_string(item.trim()))
        .collect()
}

fn toml_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            _ => vec![character],
        })
        .collect()
}

pub(crate) fn certificate_ref_dir_name(certificate_ref: &str) -> String {
    if !certificate_ref.is_empty()
        && certificate_ref
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        certificate_ref.to_string()
    } else {
        format!(".ref-{}", hex_encode(certificate_ref))
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryCertificateStore {
    certificates: Vec<StoredCertificate>,
}

impl MemoryCertificateStore {
    pub fn certificates(&self) -> &[StoredCertificate] {
        &self.certificates
    }
}

impl CertificateStore for MemoryCertificateStore {
    fn save_certificate(&mut self, certificate: StoredCertificate) -> Result<(), AppError> {
        self.certificates
            .retain(|item| item.certificate_ref != certificate.certificate_ref);
        self.certificates.push(certificate);
        Ok(())
    }

    fn load_certificate(
        &self,
        certificate_ref: &CertificateRef,
    ) -> Result<Option<StoredCertificate>, AppError> {
        Ok(self
            .certificates
            .iter()
            .find(|certificate| &certificate.certificate_ref == certificate_ref)
            .cloned())
    }

    fn list_certificates(&self) -> Result<Vec<StoredCertificate>, AppError> {
        Ok(self.certificates.clone())
    }

    fn delete_certificate(&mut self, certificate_ref: &CertificateRef) -> Result<(), AppError> {
        self.certificates
            .retain(|certificate| &certificate.certificate_ref != certificate_ref);
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct FakeAcmeClient {
    pub fail_next: bool,
}

impl AcmeClient for FakeAcmeClient {
    fn issue_certificate(
        &mut self,
        request: AcmeOrderRequest,
    ) -> Result<AcmeOrderResult, AppError> {
        if self.fail_next {
            self.fail_next = false;
            return Err(AppError::new(
                ErrorCode::AcmeChallengeFailed,
                "fake ACME challenge failed",
            ));
        }

        Ok(AcmeOrderResult {
            certificate: StoredCertificate {
                certificate_ref: CertificateRef::new(format!(
                    "fake-acme-{}",
                    request.domains.join("-")
                )),
                domains: request.domains,
                not_after_epoch_seconds: 4_102_444_800,
                source: if request.production {
                    "fake-acme-production".to_string()
                } else {
                    "fake-acme-staging".to_string()
                },
                certificate_pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
                    .to_string(),
                private_key_pem: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----"
                    .to_string(),
            },
        })
    }

    fn issue_certificate_http01(
        &mut self,
        request: AcmeOrderRequest,
        challenge_runtime: &mut dyn AcmeHttp01ChallengeRuntime,
    ) -> Result<AcmeOrderResult, AppError> {
        for domain in &request.domains {
            let token = fake_http01_token_for_domain(domain);
            let key_authorization = fake_http01_key_authorization(&token);
            challenge_runtime.present_http01(token.clone(), key_authorization.clone())?;
            challenge_runtime.verify_http01(&token, &key_authorization)?;
        }
        self.issue_certificate(request)
    }
}

fn fake_http01_token_for_domain(domain: &str) -> String {
    let safe_domain = domain.replace('.', "-");
    format!("fake-acme-http01-{safe_domain}")
}

fn fake_http01_key_authorization(token: &str) -> String {
    format!("{token}.fake-acme-account-thumbprint")
}

#[derive(Debug, Default, Clone)]
pub struct MemoryMetricsSink {
    metrics: Vec<MetricEvent>,
}

impl MemoryMetricsSink {
    pub fn metrics(&self) -> &[MetricEvent] {
        &self.metrics
    }
}

impl MetricsSink for MemoryMetricsSink {
    fn record_metric(&mut self, metric: MetricEvent) -> Result<(), AppError> {
        self.metrics.push(metric);
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryLogSink {
    events: Vec<StructuredLogEvent>,
}

impl MemoryLogSink {
    pub fn events(&self) -> &[StructuredLogEvent] {
        &self.events
    }
}

impl LogSink for MemoryLogSink {
    fn record_log(&mut self, event: StructuredLogEvent) -> Result<(), AppError> {
        self.events.push(event);
        Ok(())
    }
}

#[derive(Debug)]
pub struct JsonLineLogSink<W> {
    writer: W,
}

pub type StdoutJsonLogSink = JsonLineLogSink<std::io::Stdout>;
pub type StderrJsonLogSink = JsonLineLogSink<std::io::Stderr>;

pub fn stdout_json_log_sink() -> StdoutJsonLogSink {
    JsonLineLogSink::new(std::io::stdout())
}

pub fn stderr_json_log_sink() -> StderrJsonLogSink {
    JsonLineLogSink::new(std::io::stderr())
}

impl<W> JsonLineLogSink<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W> LogSink for JsonLineLogSink<W>
where
    W: Write,
{
    fn record_log(&mut self, event: StructuredLogEvent) -> Result<(), AppError> {
        let line = render_log_json_line(&event);
        self.writer.write_all(line.as_bytes()).map_err(|error| {
            AppError::new(
                ErrorCode::InternalBug,
                format!("structured log write failed: {error}"),
            )
        })?;
        self.writer.write_all(b"\n").map_err(|error| {
            AppError::new(
                ErrorCode::InternalBug,
                format!("structured log newline write failed: {error}"),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_application::{MetricRegistry, METRIC_MAX_RESPONSE_BYTES};
    use edge_domain::{
        AdminConfig, ConfigRevision, ConfigSnapshot, LogMode, RuntimeOptions, ServiceId,
        UpstreamEndpoint, UpstreamId, UpstreamTlsPolicy,
    };
    use edge_ports::{
        AuditLedgerReader, AuditLedgerVerifier, AuditLedgerWriter, BackupManifestDigester,
        DataDirectoryLockManager, HealthGeneration, HealthProbeFailure, HealthProbeId,
        HealthProbeOutcome, HealthProbeRequest, HealthProbeResult, HealthProbeSubmit,
        HealthProbeTransport, MetricPublishOutcome, MetricPublisher, ScriptedHealthProbeTransport,
        TlsSession, UpstreamHealthKey,
    };
    use sha2::Digest;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::thread::{self, JoinHandle};

    fn snapshot(id: &str) -> ConfigSnapshot {
        ConfigSnapshot {
            schema_version: 1,
            revision_id: ConfigRevisionId::new(id),
            admin: AdminConfig {
                bind: "127.0.0.1:9443".to_string(),
                auth_required: true,
            },
            listeners: vec![],
            routes: vec![],
            services: vec![],
            certificate_resolvers: vec![],
            log_mode: LogMode::Product,
            runtime: RuntimeOptions {
                max_connections: 1024,
                max_inflight_payload_bytes: 128 * 1024 * 1024,
                max_request_header_bytes: 16 * 1024,
                max_request_body_bytes: 1024 * 1024,
                upstream_read_timeout_ms: edge_domain::DEFAULT_UPSTREAM_READ_TIMEOUT_MS,
                metrics: edge_domain::MetricsConfig::default(),
            },
        }
    }

    fn probe_request(address: SocketAddr, path: &str, timeout_ms: u64) -> HealthProbeRequest {
        HealthProbeRequest {
            probe_id: HealthProbeId(1),
            revision_id: ConfigRevisionId::new("rev-probe"),
            generation: HealthGeneration(2),
            key: UpstreamHealthKey {
                service_id: ServiceId::new("app"),
                upstream_id: UpstreamId::new("app-a"),
            },
            endpoint: UpstreamEndpoint::parse(&format!("http://{address}/base")).unwrap(),
            tls: UpstreamTlsPolicy::Disabled,
            path: path.to_string(),
            timeout_ms,
            status_min: 200,
            status_max: 399,
        }
    }

    fn probe_test_guard() -> MutexGuard<'static, ()> {
        static PROBE_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        PROBE_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn spawn_probe_server(
        response: Vec<u8>,
        response_delay: Duration,
    ) -> (SocketAddr, Receiver<Vec<u8>>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let _ = request_tx.send(request);
            thread::sleep(response_delay);
            let _ = stream.write_all(&response);
        });
        ready_rx.recv().unwrap();
        (address, request_rx, handle)
    }

    fn spawn_tls_probe_server(
        server_config: Arc<rustls::ServerConfig>,
    ) -> (SocketAddr, Receiver<Vec<u8>>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let connection = rustls::ServerConnection::new(server_config).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => {
                        request_tx.send(request).unwrap();
                        return;
                    }
                    Ok(read) => read,
                };
                request.extend_from_slice(&buffer[..read]);
            }
            request_tx.send(request).unwrap();
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
        });
        (address, request_rx, handle)
    }

    #[test]
    fn http_health_probe_sends_bounded_get_and_accepts_configured_status() {
        let _guard = probe_test_guard();
        let (address, request_rx, handle) = spawn_probe_server(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec(),
            Duration::ZERO,
        );
        let mut transport = HttpHealthProbeTransport::new();

        let result = transport.probe(probe_request(address, "/health", 5_000));

        assert_eq!(
            result.outcome,
            HealthProbeOutcome::Succeeded { status_code: 204 }
        );
        let request = String::from_utf8(request_rx.recv().unwrap()).unwrap();
        assert!(request.starts_with("GET /base/health HTTP/1.1\r\n"));
        assert!(request.contains(&format!("\r\nHost: {address}\r\n")));
        assert!(request.contains("\r\nConnection: close\r\n"));
        handle.join().unwrap();
    }

    #[test]
    fn phase009_https_health_probe_uses_prepared_root_sni_and_http_host() {
        let _guard = probe_test_guard();
        use edge_ports::{TrustBundleMaterialValidator, UpstreamHealthKey};
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["backend.private.test".to_string()])
            .unwrap()
            .signed_by(&server_key, &root)
            .unwrap();
        let stored = StoredCertificate {
            certificate_ref: CertificateRef::new("health-backend"),
            domains: vec!["backend.private.test".to_string()],
            not_after_epoch_seconds: 4_000_000_000,
            source: "test".to_string(),
            certificate_pem: format!("{}{}", leaf.pem(), root.pem()),
            private_key_pem: server_key.serialize_pem(),
        };
        let server_config = load_rustls_server_config(&stored).unwrap().server_config;
        let (address, backend_request, backend) =
            spawn_tls_probe_server(Arc::clone(&server_config));
        let reference = TrustBundleRef::parse("private-root").unwrap();
        let trust = RustlsTrustBundleMaterialValidator
            .validate_trust_bundle(&reference, root.pem().as_bytes(), 10)
            .unwrap();
        let factory = RustlsClientTlsSessionFactory::from_trust_bundle(&trust).unwrap();
        let key = UpstreamHealthKey {
            service_id: ServiceId::new("app"),
            upstream_id: UpstreamId::new("app-a"),
        };
        let mut registry = PreparedHealthTlsRegistry::new();
        registry.insert(key.clone(), factory.clone()).unwrap();
        let mut request = probe_request(address, "/health", 15_000);
        request.endpoint = UpstreamEndpoint::parse(&format!("https://{address}/base")).unwrap();
        request.tls = edge_domain::UpstreamTlsPolicy::ServerAuthenticated {
            server_name: edge_domain::TlsServerName::parse("backend.private.test").unwrap(),
            http_host: edge_domain::UpstreamHttpHost::parse("health.private.test").unwrap(),
            trust_bundle_ref: reference,
        };
        let mut transport = HttpHealthProbeTransport::with_tls_registry(registry);

        let result = transport.probe(request);

        assert_eq!(
            result.outcome,
            HealthProbeOutcome::Succeeded { status_code: 204 }
        );
        let request = String::from_utf8(backend_request.recv().unwrap()).unwrap();
        backend.join().unwrap();
        assert!(request.starts_with("GET /base/health HTTP/1.1\r\n"));
        assert!(request.contains("\r\nHost: health.private.test\r\n"));

        let (wrong_name_address, wrong_name_request, wrong_name_backend) =
            spawn_tls_probe_server(Arc::clone(&server_config));
        let mut wrong_name_registry = PreparedHealthTlsRegistry::new();
        wrong_name_registry.insert(key.clone(), factory).unwrap();
        let mut wrong_name = probe_request(wrong_name_address, "/health", 15_000);
        wrong_name.endpoint =
            UpstreamEndpoint::parse(&format!("https://{wrong_name_address}/base")).unwrap();
        wrong_name.tls = edge_domain::UpstreamTlsPolicy::ServerAuthenticated {
            server_name: edge_domain::TlsServerName::parse("wrong.private.test").unwrap(),
            http_host: edge_domain::UpstreamHttpHost::parse("health.private.test").unwrap(),
            trust_bundle_ref: TrustBundleRef::parse("private-root").unwrap(),
        };

        let result =
            HttpHealthProbeTransport::with_tls_registry(wrong_name_registry).probe(wrong_name);

        assert_eq!(
            result.outcome,
            HealthProbeOutcome::Failed(HealthProbeFailure::TlsHandshake)
        );
        assert!(wrong_name_request.recv().unwrap().is_empty());
        wrong_name_backend.join().unwrap();

        let mut other_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        other_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let other =
            CertifiedIssuer::self_signed(other_params, KeyPair::generate().unwrap()).unwrap();
        let other_trust = RustlsTrustBundleMaterialValidator
            .validate_trust_bundle(
                &TrustBundleRef::parse("other-root").unwrap(),
                other.pem().as_bytes(),
                10,
            )
            .unwrap();
        let (wrong_root_address, wrong_root_request, wrong_root_backend) =
            spawn_tls_probe_server(server_config);
        let mut wrong_root_registry = PreparedHealthTlsRegistry::new();
        wrong_root_registry
            .insert(
                key,
                RustlsClientTlsSessionFactory::from_trust_bundle(&other_trust).unwrap(),
            )
            .unwrap();
        let mut wrong_root = probe_request(wrong_root_address, "/health", 15_000);
        wrong_root.endpoint =
            UpstreamEndpoint::parse(&format!("https://{wrong_root_address}/base")).unwrap();
        wrong_root.tls = edge_domain::UpstreamTlsPolicy::ServerAuthenticated {
            server_name: edge_domain::TlsServerName::parse("backend.private.test").unwrap(),
            http_host: edge_domain::UpstreamHttpHost::parse("health.private.test").unwrap(),
            trust_bundle_ref: TrustBundleRef::parse("other-root").unwrap(),
        };

        let result =
            HttpHealthProbeTransport::with_tls_registry(wrong_root_registry).probe(wrong_root);

        assert_eq!(
            result.outcome,
            HealthProbeOutcome::Failed(HealthProbeFailure::TlsHandshake)
        );
        assert!(wrong_root_request.recv().unwrap().is_empty());
        wrong_root_backend.join().unwrap();
    }

    #[test]
    fn http_health_probe_classifies_status_mismatch_and_malformed_response() {
        let _guard = probe_test_guard();
        let (mismatch_address, _, mismatch_handle) = spawn_probe_server(
            b"HTTP/1.1 503 Service Unavailable\r\n\r\n".to_vec(),
            Duration::ZERO,
        );
        let mut transport = HttpHealthProbeTransport::new();
        let mismatch = transport.probe(probe_request(mismatch_address, "/health", 5_000));
        assert_eq!(
            mismatch.outcome,
            HealthProbeOutcome::Failed(HealthProbeFailure::StatusMismatch { status_code: 503 })
        );
        mismatch_handle.join().unwrap();

        let (malformed_address, _, malformed_handle) =
            spawn_probe_server(b"NOT HTTP\r\n\r\n".to_vec(), Duration::ZERO);
        let malformed = transport.probe(probe_request(malformed_address, "/health", 5_000));
        assert_eq!(
            malformed.outcome,
            HealthProbeOutcome::Failed(HealthProbeFailure::MalformedResponse)
        );
        malformed_handle.join().unwrap();
    }

    #[test]
    fn http_health_probe_enforces_header_limit() {
        let _guard = probe_test_guard();
        let (oversize_address, _, oversize_handle) =
            spawn_probe_server(vec![b'A'; 8 * 1024 + 1], Duration::ZERO);
        let mut transport = HttpHealthProbeTransport::new();
        let oversize = transport.probe(probe_request(oversize_address, "/health", 5_000));
        assert_eq!(
            oversize.outcome,
            HealthProbeOutcome::Failed(HealthProbeFailure::ResponseTooLarge)
        );
        oversize_handle.join().unwrap();
    }

    #[test]
    fn health_probe_response_reader_classifies_socket_timeout() {
        let _guard = probe_test_guard();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();

        assert_eq!(
            read_health_status(&mut client),
            Err(HealthProbeFailure::ReadTimeout)
        );
    }

    #[test]
    fn health_probe_connect_error_mapping_is_bounded() {
        assert_eq!(
            classify_connect_failure(std::io::Error::new(ErrorKind::TimedOut, "hidden")),
            HealthProbeFailure::ConnectTimeout
        );
        assert_eq!(
            classify_connect_failure(std::io::Error::new(ErrorKind::ConnectionRefused, "hidden")),
            HealthProbeFailure::ConnectError
        );
    }

    #[test]
    fn health_probe_worker_preserves_identity_and_bounds_total_outstanding_work() {
        let first_result = HealthProbeResult::succeeded(204, 7);
        let second_result = HealthProbeResult::failed(HealthProbeFailure::ReadTimeout, 100);
        let transport = ScriptedHealthProbeTransport::new(vec![first_result, second_result]);
        let (mut pool, completions) = HealthProbeWorkerPool::new(vec![transport], 1).unwrap();
        let first = probe_request("127.0.0.1:3001".parse().unwrap(), "/health", 500);
        let second = probe_request("127.0.0.1:3002".parse().unwrap(), "/ready", 500);

        assert_eq!(pool.submit(first.clone()), HealthProbeSubmit::Accepted);
        assert_eq!(pool.submit(second.clone()), HealthProbeSubmit::Full);
        let deadline = Instant::now() + Duration::from_secs(1);
        let completion = loop {
            match completions.try_recv() {
                Ok(completion) => break completion,
                Err(std::sync::mpsc::TryRecvError::Empty) if Instant::now() < deadline => {
                    thread::yield_now();
                }
                Err(error) => panic!("health completion was not available: {error:?}"),
            }
        };
        assert_eq!(completion.request, first);
        assert_eq!(completion.result, first_result);

        assert_eq!(pool.submit(second.clone()), HealthProbeSubmit::Accepted);
        let completion = completions.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(completion.request, second);
        assert_eq!(completion.result, second_result);
        assert_eq!(
            pool.shutdown(),
            HealthProbeShutdownReport {
                cancelled_queued: 0,
                joined_workers: 1,
                already_stopped: false,
            }
        );
        assert_eq!(
            pool.submit(probe_request(
                "127.0.0.1:3003".parse().unwrap(),
                "/health",
                500
            )),
            HealthProbeSubmit::Stopped
        );
        assert_eq!(
            pool.shutdown(),
            HealthProbeShutdownReport {
                cancelled_queued: 0,
                joined_workers: 0,
                already_stopped: true,
            }
        );
    }

    struct DelayedHealthProbeTransport {
        started: mpsc::Sender<()>,
        delay: Duration,
    }

    impl HealthProbeTransport for DelayedHealthProbeTransport {
        fn probe(&mut self, _request: HealthProbeRequest) -> HealthProbeResult {
            self.started.send(()).unwrap();
            thread::sleep(self.delay);
            HealthProbeResult::succeeded(200, self.delay.as_millis() as u64)
        }
    }

    #[test]
    fn health_probe_worker_shutdown_cancels_queued_and_joins_active_work() {
        let (started_tx, started_rx) = mpsc::channel();
        let transport = DelayedHealthProbeTransport {
            started: started_tx,
            delay: Duration::from_millis(100),
        };
        let (mut pool, completions) = HealthProbeWorkerPool::new(vec![transport], 2).unwrap();
        let active = probe_request("127.0.0.1:3001".parse().unwrap(), "/health", 500);
        let queued = probe_request("127.0.0.1:3002".parse().unwrap(), "/health", 500);
        assert_eq!(pool.submit(active.clone()), HealthProbeSubmit::Accepted);
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(pool.submit(queued), HealthProbeSubmit::Accepted);

        assert_eq!(
            pool.shutdown(),
            HealthProbeShutdownReport {
                cancelled_queued: 1,
                joined_workers: 1,
                already_stopped: false,
            }
        );
        let completion = completions.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(completion.request, active);
        assert_eq!(
            completion.result.outcome,
            HealthProbeOutcome::Succeeded { status_code: 200 }
        );
    }

    #[test]
    fn health_probe_worker_rejects_empty_workers_and_zero_capacity() {
        assert_eq!(
            HealthProbeWorkerPool::new(Vec::<ScriptedHealthProbeTransport>::new(), 1).unwrap_err(),
            HealthProbeWorkerBuildError::NoWorkers
        );
        assert_eq!(
            HealthProbeWorkerPool::new(vec![ScriptedHealthProbeTransport::new(vec![])], 0)
                .unwrap_err(),
            HealthProbeWorkerBuildError::ZeroCapacity
        );
    }

    #[derive(Default)]
    struct RecordingHttp01Runtime {
        presented: Vec<(String, String)>,
        verified: Vec<(String, String)>,
    }

    impl AcmeHttp01ChallengeRuntime for RecordingHttp01Runtime {
        fn present_http01(
            &mut self,
            token: String,
            key_authorization: String,
        ) -> Result<(), AppError> {
            self.presented.push((token, key_authorization));
            Ok(())
        }

        fn verify_http01(
            &mut self,
            token: &str,
            expected_key_authorization: &str,
        ) -> Result<(), AppError> {
            self.verified
                .push((token.to_string(), expected_key_authorization.to_string()));
            Ok(())
        }
    }

    fn test_certificate(certificate_ref: &str) -> StoredCertificate {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![format!("{certificate_ref}.example.com")])
                .unwrap();
        StoredCertificate {
            certificate_ref: CertificateRef::new(certificate_ref),
            domains: vec![format!("{certificate_ref}.example.com")],
            not_after_epoch_seconds: 4_000_000_000,
            source: "test".to_string(),
            certificate_pem: cert.pem(),
            private_key_pem: signing_key.serialize_pem(),
        }
    }

    fn rustls_test_client(certificate_pem: &str, host: &str) -> rustls::ClientConnection {
        let certificate =
            rustls_pki_types::CertificateDer::from_pem_slice(certificate_pem.as_bytes()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = rustls_pki_types::ServerName::try_from(host.to_string()).unwrap();
        rustls::ClientConnection::new(Arc::new(client_config), server_name).unwrap()
    }

    fn rustls_test_client_config_with_certificate(
        server_root_pem: &str,
        client_certificate_pem: &str,
        client_private_key_pem: &str,
    ) -> Arc<rustls::ClientConfig> {
        let server_root =
            rustls_pki_types::CertificateDer::from_pem_slice(server_root_pem.as_bytes()).unwrap();
        let client_certificates =
            rustls_pki_types::CertificateDer::pem_slice_iter(client_certificate_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let client_private_key =
            rustls_pki_types::PrivateKeyDer::from_pem_slice(client_private_key_pem.as_bytes())
                .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(server_root).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_client_auth_cert(client_certificates, client_private_key)
                .unwrap(),
        )
    }

    fn rustls_test_client_config_without_certificate(
        server_root_pem: &str,
    ) -> Arc<rustls::ClientConfig> {
        let server_root =
            rustls_pki_types::CertificateDer::from_pem_slice(server_root_pem.as_bytes()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(server_root).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    fn private_client_identity(
        extended_key_usage: rcgen::ExtendedKeyUsagePurpose,
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
        include_intermediate: bool,
    ) -> (String, String, String) {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
        };

        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        root_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        root_params.not_after = rcgen::date_time_ymd(2040, 1, 1);
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();

        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params.extended_key_usages = vec![extended_key_usage];
        client_params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        client_params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let (client, intermediate_pem) = if include_intermediate {
            let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            intermediate_params.key_usages =
                vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            intermediate_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
            intermediate_params.not_after = rcgen::date_time_ymd(2039, 1, 1);
            let intermediate = CertifiedIssuer::signed_by(
                intermediate_params,
                KeyPair::generate().unwrap(),
                &root,
            )
            .unwrap();
            (
                client_params.signed_by(&client_key, &intermediate).unwrap(),
                intermediate.pem(),
            )
        } else {
            (
                client_params.signed_by(&client_key, &root).unwrap(),
                String::new(),
            )
        };
        (
            root.pem(),
            format!("{}{intermediate_pem}", client.pem()),
            client_key.serialize_pem(),
        )
    }

    fn rustls_memory_handshake(
        server_config: Arc<rustls::ServerConfig>,
        client_config: Arc<rustls::ClientConfig>,
        host: &str,
    ) -> Result<(), String> {
        let mut server = rustls::ServerConnection::new(server_config).map_err(|e| e.to_string())?;
        let server_name =
            rustls_pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
        let mut client =
            rustls::ClientConnection::new(client_config, server_name).map_err(|e| e.to_string())?;
        for _ in 0..16 {
            let mut client_bytes = Vec::new();
            client
                .write_tls(&mut client_bytes)
                .map_err(|e| e.to_string())?;
            if !client_bytes.is_empty() {
                server
                    .read_tls(&mut std::io::Cursor::new(client_bytes))
                    .map_err(|e| e.to_string())?;
                server.process_new_packets().map_err(|e| e.to_string())?;
            }
            let mut server_bytes = Vec::new();
            server
                .write_tls(&mut server_bytes)
                .map_err(|e| e.to_string())?;
            if !server_bytes.is_empty() {
                client
                    .read_tls(&mut std::io::Cursor::new(server_bytes))
                    .map_err(|e| e.to_string())?;
                client.process_new_packets().map_err(|e| e.to_string())?;
            }
            if !server.is_handshaking() && !client.is_handshaking() {
                return Ok(());
            }
        }
        Err("TLS handshake did not reach established state".to_string())
    }

    fn drive_tls_handshake(client: &mut rustls::ClientConnection, server: &mut dyn TlsSession) {
        for _ in 0..16 {
            send_client_tls_to_server_fragmented(client, server);
            receive_server_tls_on_client(server, client);
            if !client.is_handshaking()
                && server.progress() == edge_ports::TlsSessionProgress::Established
            {
                return;
            }
        }
        panic!(
            "handshake did not complete: client_handshaking={}, server={:?}",
            client.is_handshaking(),
            server.progress()
        );
    }

    fn send_client_tls_to_server_fragmented(
        client: &mut rustls::ClientConnection,
        server: &mut dyn TlsSession,
    ) {
        let mut encrypted = Vec::new();
        client.write_tls(&mut encrypted).unwrap();
        for chunk in encrypted.chunks(7) {
            server.receive_encrypted(chunk).unwrap();
        }
    }

    fn receive_server_tls_on_client(
        server: &mut dyn TlsSession,
        client: &mut rustls::ClientConnection,
    ) {
        let encrypted = server.take_encrypted(usize::MAX);
        if encrypted.is_empty() {
            return;
        }
        client
            .read_tls(&mut std::io::Cursor::new(encrypted))
            .unwrap();
        client.process_new_packets().unwrap();
    }

    fn drive_tls_session_pair(
        client: &mut dyn TlsSession,
        server: &mut dyn TlsSession,
    ) -> Result<(), AppError> {
        for _ in 0..16 {
            let client_bytes = client.take_encrypted(usize::MAX);
            if !client_bytes.is_empty() {
                server.receive_encrypted(&client_bytes)?;
            }
            let server_bytes = server.take_encrypted(usize::MAX);
            if !server_bytes.is_empty() {
                client.receive_encrypted(&server_bytes)?;
            }
            if client.progress() == TlsSessionProgress::Established
                && server.progress() == TlsSessionProgress::Established
            {
                return Ok(());
            }
        }
        Err(AppError::new(
            ErrorCode::TlsHandshakeTimeout,
            "scripted memory handshake did not complete",
        ))
    }

    fn read_available_client_plaintext(client: &mut rustls::ClientConnection) -> Vec<u8> {
        let mut response = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            match client.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => response.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("client plaintext read failed: {error}"),
            }
        }
        response
    }

    #[test]
    fn exposes_crate_name() {
        assert_eq!(crate_name(), "edge-adapters");
    }

    #[test]
    fn memory_revision_repository_tracks_current() {
        let mut repo = MemoryRevisionRepository::default();
        let revision = ConfigRevision {
            id: ConfigRevisionId::new("rev-1"),
            schema_version: 1,
            summary: "test".to_string(),
        };
        repo.save_revision(RevisionRecord {
            revision,
            snapshot: snapshot("rev-1"),
            checksum: "checksum".to_string(),
        })
        .unwrap();
        repo.set_current(&ConfigRevisionId::new("rev-1")).unwrap();

        assert_eq!(
            repo.current().unwrap().unwrap().revision.id.as_str(),
            "rev-1"
        );
    }

    #[test]
    fn file_revision_repository_tracks_current_and_history() {
        let root = temp_root("file-revisions");
        let mut repo = FileRevisionRepository::new(&root);
        let revision = ConfigRevision {
            id: ConfigRevisionId::new("rev-1"),
            schema_version: 1,
            summary: "test".to_string(),
        };

        repo.save_revision(RevisionRecord {
            revision,
            snapshot: snapshot("rev-1"),
            checksum: "checksum".to_string(),
        })
        .unwrap();
        repo.set_current(&ConfigRevisionId::new("rev-1")).unwrap();

        let current = repo.current().unwrap().unwrap();
        let history = repo.history().unwrap();
        let found = repo
            .find_revision(&ConfigRevisionId::new("rev-1"))
            .unwrap()
            .unwrap();

        assert_eq!(current.revision.id.as_str(), "rev-1");
        assert_eq!(found.snapshot.revision_id.as_str(), "rev-1");
        assert_eq!(history.len(), 1);
        assert!(root.join("current").is_file());
        assert!(root.join("revisions").is_dir());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_revision_repository_rejects_missing_current_revision() {
        let root = temp_root("file-revisions-missing");
        let mut repo = FileRevisionRepository::new(&root);

        let error = repo
            .set_current(&ConfigRevisionId::new("missing"))
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigRevisionNotFound);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn memory_audit_sink_records_events() {
        let mut sink = MemoryAuditSink::default();
        sink.record(AuditEvent {
            event: "config.apply".to_string(),
            revision_id: Some(ConfigRevisionId::new("rev-1")),
        })
        .unwrap();

        assert_eq!(sink.events().len(), 1);
    }

    #[test]
    fn memory_audit_sink_does_not_recover_events_in_a_new_instance() {
        let mut before_restart = MemoryAuditSink::default();
        before_restart
            .record(AuditEvent {
                event: "config.apply".to_string(),
                revision_id: Some(ConfigRevisionId::new("rev-1")),
            })
            .unwrap();

        let after_restart = MemoryAuditSink::default();

        assert_eq!(before_restart.events().len(), 1);
        assert!(after_restart.events().is_empty());
    }

    #[test]
    fn file_secret_store_saves_and_loads_masked_secret() {
        let root = temp_root("file-secrets");
        let mut store = FileSecretStore::new(&root);

        store
            .save_secret(SecretRecord {
                name: "admin-password-hash".to_string(),
                value: "hash".to_string(),
            })
            .unwrap();

        let loaded = store.load_secret("admin-password-hash").unwrap().unwrap();

        assert_eq!(loaded.name, "admin-password-hash");
        assert_eq!(loaded.value, "hash");
        assert_eq!(loaded.masked_value(), "***");
        assert!(root.join("admin-password-hash.secret").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_secret_store_writes_secret_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("file-secret-owner-only");
        let mut store = FileSecretStore::new(&root);

        store
            .save_secret(SecretRecord {
                name: "admin-password-hash".to_string(),
                value: "password-equivalent".to_string(),
            })
            .unwrap();

        let mode = fs::metadata(root.join("admin-password-hash.secret"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o600);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_data_directory_lock_rejects_contention_and_reacquires_after_release() {
        let root = temp_root("data-directory-lock-contention");
        let target = root.join("data");
        fs::create_dir_all(&target).unwrap();
        let manager = FileDataDirectoryLockManager::new(&target).unwrap();

        let mut first = manager.try_acquire_exclusive().unwrap();
        let busy = manager.try_acquire_exclusive().unwrap_err();
        assert_eq!(busy.code, ErrorCode::DataDirectoryBusy);

        first.release().unwrap();
        let duplicate_release = first.release().unwrap_err();
        assert_eq!(
            duplicate_release.code,
            ErrorCode::DataDirectoryLockStateInvalid
        );
        let second = manager.try_acquire_exclusive().unwrap();
        drop(second);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_data_directory_lock_symlink_alias_cannot_bypass_owner() {
        let root = temp_root("data-directory-lock-alias");
        let target = root.join("data");
        let alias = root.join("alias");
        fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(fs::canonicalize(&target).unwrap(), &alias).unwrap();
        let owner = FileDataDirectoryLockManager::new(&target).unwrap();
        let aliased = FileDataDirectoryLockManager::new(&alias).unwrap();

        let held = owner.try_acquire_exclusive().unwrap();
        let busy = aliased.try_acquire_exclusive().unwrap_err();
        assert_eq!(busy.code, ErrorCode::DataDirectoryBusy);

        drop(held);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_backup_source_inventories_only_managed_allowlisted_state() {
        let root = temp_root("backup-source-inventory");
        fs::create_dir_all(root.join("config/revisions")).unwrap();
        fs::create_dir_all(root.join("secrets")).unwrap();
        fs::create_dir_all(root.join("logs")).unwrap();
        fs::create_dir_all(root.join("backups")).unwrap();
        let snapshot = parse_mvp_config(
            include_str!("../../../examples/minimal.toml"),
            ConfigRevisionId::new("rev-1"),
        )
        .unwrap()
        .snapshot;
        let mut revisions = FileRevisionRepository::new(root.join("config"));
        revisions
            .save_revision(RevisionRecord {
                revision: ConfigRevision {
                    id: snapshot.revision_id.clone(),
                    schema_version: 1,
                    summary: "backup fixture".to_string(),
                },
                checksum: checksum_snapshot(&snapshot),
                snapshot,
            })
            .unwrap();
        revisions
            .set_current(&ConfigRevisionId::new("rev-1"))
            .unwrap();
        FileSecretStore::new(root.join("secrets"))
            .save_secret(SecretRecord {
                name: "admin-password-hash".to_string(),
                value: "verifier".to_string(),
            })
            .unwrap();
        fs::write(root.join("config/current.toml"), "bootstrap-only").unwrap();
        fs::write(root.join("logs/access.log"), "excluded").unwrap();
        fs::write(root.join("backups/old.age"), "excluded").unwrap();
        drop(FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap());

        let mut source = FileBackupArtifactSource::new(&root);
        let inventory = source.inventory().unwrap();

        assert!(inventory.admin_initialized);
        assert_eq!(inventory.current_revision_id.as_str(), "rev-1");
        assert_eq!(inventory.artifacts.len(), 4);
        assert_eq!(
            inventory
                .artifacts
                .iter()
                .map(|item| item.relative_logical_path.as_str())
                .collect::<Vec<_>>(),
            vec![
                "audit/segments/0000000000000001",
                "config/current",
                "config/revisions/rev-1",
                "secrets/admin-password-hash"
            ]
        );
        for descriptor in &inventory.artifacts {
            let artifact = source.read_artifact(descriptor).unwrap();
            assert_eq!(artifact.descriptor, *descriptor);
            assert_eq!(artifact.payload.len() as u64, descriptor.length_bytes);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn phase010_backup_v3_restores_audit_history_and_continues_sequence() {
        let workspace = temp_root("backup-v3-audit");
        let source_root = workspace.join("source");
        fs::create_dir_all(source_root.join("config/revisions")).unwrap();
        let snapshot = parse_mvp_config(
            include_str!("../../../examples/minimal.toml"),
            ConfigRevisionId::new("rev-1"),
        )
        .unwrap()
        .snapshot;
        let mut revisions = FileRevisionRepository::new(source_root.join("config"));
        revisions
            .save_revision(RevisionRecord {
                revision: ConfigRevision {
                    id: snapshot.revision_id.clone(),
                    schema_version: 1,
                    summary: "audit backup fixture".to_string(),
                },
                checksum: checksum_snapshot(&snapshot),
                snapshot,
            })
            .unwrap();
        revisions
            .set_current(&ConfigRevisionId::new("rev-1"))
            .unwrap();

        let audit_record =
            |operation: &str, request: &str, timestamp: u64| edge_domain::AuditRecord {
                record_version: 1,
                record_kind: edge_domain::AuditRecordKind::SecurityObservation,
                context: edge_domain::AuditContext {
                    operation_id: edge_domain::AuditOperationId::parse(operation).unwrap(),
                    request_id: edge_domain::AuditRequestId::parse(request).unwrap(),
                    actor_kind: edge_domain::AuditActorKind::BootstrapAdmin,
                    received_at_epoch_seconds: timestamp,
                },
                action: edge_domain::AuditAction::AdminLoginSuccess,
                target_kind: edge_domain::AuditTargetKind::AdminAccount,
                target_id: edge_domain::AuditTargetId::parse("bootstrap-admin").unwrap(),
                before_revision: None,
                after_revision: None,
                outcome: Some(edge_domain::AuditOutcome::Observed),
                error_code: None,
            };
        let mut source_ledger =
            FileAuditLedger::open(&source_root, AuditLedgerOptions::default()).unwrap();
        let source_head = source_ledger
            .append_security_observation(audit_record("operation-1", "request-1", 10))
            .unwrap();
        drop(source_ledger);

        let output = workspace.join("audit-v3.age");
        let source_lock = FileDataDirectoryLockManager::new(&source_root).unwrap();
        let mut source = FileBackupArtifactSource::new(&source_root);
        let mut writer = AgeBackupArchiveWriter::new(&output).unwrap();
        let mut ids = RandomOperationIdGenerator;
        let mut logs = MemoryLogSink::default();
        let receipt = edge_application::CreateBackupUseCase::new(
            &source_lock,
            &mut source,
            &Sha256BackupManifestDigester,
            &mut writer,
            &SystemClock,
            &mut ids,
            &mut logs,
            edge_domain::BackupLimits::schema_v3(),
        )
        .execute(edge_application::CreateBackupInput {
            source_app_version: "test".to_string(),
            destination_identity: "audit-v3.age".to_string(),
            passphrase: edge_domain::SensitiveString::new("test passphrase").unwrap(),
        })
        .unwrap();
        assert_eq!(receipt.schema_version, 3);
        let source_after = FileAuditLedger::open(&source_root, AuditLedgerOptions::default())
            .unwrap()
            .head()
            .unwrap();
        assert_eq!(source_after, source_head);

        let verified = AgeBackupArchiveReader::new(&output)
            .read(
                &edge_domain::SensitiveString::new("test passphrase").unwrap(),
                &edge_domain::BackupLimits::schema_v3(),
            )
            .unwrap();
        assert_eq!(verified.manifest.schema_version, 3);
        assert_eq!(
            verified
                .manifest
                .artifacts
                .iter()
                .filter(|item| item.kind == edge_domain::BackupArtifactKind::AuditLedgerSegment)
                .count(),
            1
        );

        let corrupt_target = workspace.join("corrupt-target");
        let mut corrupt_extractor =
            FileRestoreArchiveExtractor::new(&output, &corrupt_target).unwrap();
        let corrupt_stage = corrupt_extractor
            .extract(
                &edge_domain::SensitiveString::new("test passphrase").unwrap(),
                &edge_domain::BackupLimits::schema_v3(),
            )
            .unwrap();
        OpenOptions::new()
            .append(true)
            .open(
                corrupt_extractor
                    .stage_path()
                    .join("logs/audit/segment-0000000000000001.audit"),
            )
            .unwrap()
            .write_all(b"X")
            .unwrap();
        let mut corrupt_preflight = FileRestorePreflight::new(corrupt_extractor.stage_path());
        assert!(corrupt_preflight.validate_audit(&corrupt_stage).is_err());
        assert!(!corrupt_target.exists());
        corrupt_extractor.cleanup().unwrap();

        let target = workspace.join("restored");
        let target_lock = FileDataDirectoryLockManager::new(&target).unwrap();
        let mut extractor = FileRestoreArchiveExtractor::new(&output, &target).unwrap();
        let stage = extractor.stage_path().to_path_buf();
        let mut preflight = FileRestorePreflight::new(&stage);
        let mut publisher = FileNewTargetRestorePublisher::new(&stage, &target);
        let mut provenance = FileRestoreProvenanceWriter::new(&target);
        let mut restore_ids = RandomOperationIdGenerator;
        let mut restore_logs = MemoryLogSink::default();
        edge_application::RestoreBackupUseCase::new(
            &target_lock,
            &mut extractor,
            &mut preflight,
            &mut publisher,
            &mut provenance,
            &SystemClock,
            &mut restore_ids,
            &mut restore_logs,
            edge_domain::BackupLimits::schema_v3(),
        )
        .execute(edge_application::RestoreBackupInput {
            passphrase: edge_domain::SensitiveString::new("test passphrase").unwrap(),
        })
        .unwrap();

        let mut restored = FileAuditLedger::open(&target, AuditLedgerOptions::default()).unwrap();
        let old = restored.query(&edge_domain::AuditQuery::default()).unwrap();
        assert_eq!(old.head.sequence, source_head.sequence + 1);
        assert_eq!(old.records.len(), 2);
        assert_eq!(
            old.records[0].record.action,
            edge_domain::AuditAction::MaintenanceRestoreImported
        );
        assert_eq!(old.records[0].record.target_id.as_str(), receipt.archive_id);
        let continued = restored
            .append_security_observation(audit_record("operation-2", "request-2", 20))
            .unwrap();
        assert_eq!(continued.sequence, source_head.sequence + 2);
        assert_eq!(restored.verify().unwrap().record_count, 3);
        fs::remove_dir_all(workspace).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn age_backup_writer_publishes_owner_only_authenticated_stream() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("age-backup-writer");
        fs::create_dir_all(&root).unwrap();
        let output = root.join("backup.age");
        let pointer_payload = b"rev-1".to_vec();
        let revision_payload = include_bytes!("../../../examples/minimal.toml").to_vec();
        let pointer = edge_domain::BackupArtifactDescriptor {
            kind: edge_domain::BackupArtifactKind::ConfigRevisionPointer,
            logical_id: "current".to_string(),
            relative_logical_path: "config/current".to_string(),
            length_bytes: pointer_payload.len() as u64,
            sha256: sha2::Sha256::digest(&pointer_payload).into(),
            mode: edge_domain::BackupArtifactMode::Public,
            required_for_restore: true,
        };
        let revision = edge_domain::BackupArtifactDescriptor {
            kind: edge_domain::BackupArtifactKind::ConfigRevision,
            logical_id: "rev-1".to_string(),
            relative_logical_path: "config/revisions/rev-1".to_string(),
            length_bytes: revision_payload.len() as u64,
            sha256: sha2::Sha256::digest(&revision_payload).into(),
            mode: edge_domain::BackupArtifactMode::Public,
            required_for_restore: true,
        };
        let mut manifest = edge_domain::BackupManifest {
            schema_version: 1,
            archive_id: "archive-1".to_string(),
            created_at_epoch_seconds: 1,
            source_app_version: "0.1.0".to_string(),
            source_layout_version: 1,
            current_revision_id: "rev-1".to_string(),
            admin_initialized: false,
            referenced_certificate_refs: vec![],
            referenced_trust_bundle_refs: vec![],
            artifact_count: 2,
            total_plaintext_bytes: (pointer_payload.len() + revision_payload.len()) as u64,
            artifacts: vec![pointer.clone(), revision.clone()],
            manifest_digest: [0; 32],
        };
        manifest
            .validate(&edge_domain::BackupLimits::schema_v1())
            .unwrap();
        manifest.manifest_digest = Sha256BackupManifestDigester.digest(&manifest).unwrap();
        let secret = edge_domain::SensitiveString::new("test passphrase").unwrap();
        let mut writer = AgeBackupArchiveWriter::new(&output).unwrap();
        writer.open(&manifest, &secret).unwrap();
        writer
            .write_record(edge_ports::BackupArtifact {
                descriptor: pointer,
                payload: pointer_payload,
            })
            .unwrap();
        writer
            .write_record(edge_ports::BackupArtifact {
                descriptor: revision,
                payload: revision_payload,
            })
            .unwrap();
        writer.finalize().unwrap();
        writer.sync().unwrap();
        writer.publish().unwrap();

        let encrypted = fs::read(&output).unwrap();
        assert!(encrypted.starts_with(b"age-encryption.org/v1"));
        let decryptor = age::Decryptor::new_buffered(encrypted.as_slice()).unwrap();
        let identity = age::scrypt::Identity::new(age::secrecy::SecretString::from(
            "test passphrase".to_string(),
        ));
        let mut plaintext = Vec::new();
        decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap()
            .read_to_end(&mut plaintext)
            .unwrap();
        assert!(plaintext.starts_with(b"SPONZEY-BACKUP-V1\0"));
        assert!(plaintext
            .windows(b"schema_version = 1".len())
            .any(|window| window == b"schema_version = 1"));
        let verified = AgeBackupArchiveReader::new(&output)
            .read(&secret, &edge_domain::BackupLimits::schema_v1())
            .unwrap();
        assert_eq!(verified.manifest, manifest);
        assert_eq!(verified.records.len(), 2);
        let v1_read_by_v2 = AgeBackupArchiveReader::new(&output)
            .read(&secret, &edge_domain::BackupLimits::schema_v2())
            .unwrap();
        assert_eq!(v1_read_by_v2.manifest, manifest);
        let target = root.join("restored");
        let mut extractor = FileRestoreArchiveExtractor::new(&output, &target).unwrap();
        let stage = extractor
            .extract(&secret, &edge_domain::BackupLimits::schema_v1())
            .unwrap();
        let mut preflight = FileRestorePreflight::new(extractor.stage_path());
        preflight.validate_config(&stage).unwrap();
        preflight.validate_certificates(&stage).unwrap();
        preflight.validate_secrets(&stage).unwrap();
        preflight.preflight_runtime(&stage).unwrap();
        let mut publisher = FileNewTargetRestorePublisher::new(extractor.stage_path(), &target);
        publisher.prepare_new_target(&stage).unwrap();
        publisher.publish_new_target(&stage).unwrap();
        publisher.verify_published_target(&stage).unwrap();
        assert_eq!(
            fs::read_to_string(target.join("config/current")).unwrap(),
            "rev-1"
        );
        assert_eq!(
            fs::metadata(target.join("config/current"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            FileNewTargetRestorePublisher::new(extractor.stage_path(), &target)
                .prepare_new_target(&stage)
                .unwrap_err()
                .code,
            ErrorCode::RestoreTargetNotEmpty
        );
        let mut replace_extractor = FileRestoreArchiveExtractor::new(&output, &target).unwrap();
        let replace_stage = replace_extractor
            .extract(&secret, &edge_domain::BackupLimits::schema_v1())
            .unwrap();
        let mut transaction_store = FileRestoreTransactionStore::new(&target).unwrap();
        let mut replace_publisher =
            FileReplaceRestorePublisher::new(&target, replace_extractor.stage_path()).unwrap();
        let mut transaction = replace_publisher
            .prepare_replace("operation-1", &replace_stage)
            .unwrap();
        transaction_store.persist(&transaction).unwrap();
        replace_publisher
            .move_target_to_rollback(&transaction)
            .unwrap();
        transaction.state = RestoreTransactionState::TargetMoved;
        transaction_store.persist(&transaction).unwrap();
        assert!(!replace_publisher.target_valid(&transaction).unwrap());
        assert!(replace_publisher.rollback_valid(&transaction).unwrap());
        assert_eq!(
            transaction_store.load("wrong-operation").unwrap_err().code,
            ErrorCode::RestoreTransactionUnresolved
        );
        replace_publisher.publish_stage(&transaction).unwrap();
        transaction.state = RestoreTransactionState::StagePublished;
        transaction_store.persist(&transaction).unwrap();
        replace_publisher
            .verify_target(&transaction, &replace_stage)
            .unwrap();
        replace_publisher.cleanup_committed(&transaction).unwrap();
        transaction_store.delete("operation-1").unwrap();
        assert!(replace_publisher.target_valid(&transaction).unwrap());
        assert!(!replace_publisher.rollback_valid(&transaction).unwrap());
        let journal = root.join(".restored.restore-journal");
        let journal_target = root.join("journal-target");
        fs::write(&journal_target, b"not a restore journal").unwrap();
        std::os::unix::fs::symlink(fs::canonicalize(&journal_target).unwrap(), &journal).unwrap();
        assert_eq!(
            transaction_store.load("operation-1").unwrap_err().code,
            ErrorCode::RestoreTransactionUnresolved
        );
        assert_eq!(
            fs::read_to_string(target.join("config/current")).unwrap(),
            "rev-1"
        );
        fs::remove_file(&journal).unwrap();
        let wrong = edge_domain::SensitiveString::new("wrong passphrase").unwrap();
        assert_eq!(
            AgeBackupArchiveReader::new(&output)
                .read(&wrong, &edge_domain::BackupLimits::schema_v1())
                .unwrap_err()
                .code,
            ErrorCode::BackupAuthenticationFailed
        );
        let mut tampered = encrypted.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let tampered_path = root.join("tampered.age");
        fs::write(&tampered_path, tampered).unwrap();
        assert_eq!(
            AgeBackupArchiveReader::new(&tampered_path)
                .read(&secret, &edge_domain::BackupLimits::schema_v1())
                .unwrap_err()
                .code,
            ErrorCode::BackupAuthenticationFailed
        );
        let truncated_path = root.join("truncated.age");
        fs::write(&truncated_path, &encrypted[..encrypted.len() - 8]).unwrap();
        assert_eq!(
            AgeBackupArchiveReader::new(&truncated_path)
                .read(&secret, &edge_domain::BackupLimits::schema_v1())
                .unwrap_err()
                .code,
            ErrorCode::BackupAuthenticationFailed
        );
        let trailing_path = root.join("trailing.age");
        let mut trailing = encrypted.clone();
        trailing.push(0);
        fs::write(&trailing_path, trailing).unwrap();
        assert_eq!(
            AgeBackupArchiveReader::new(&trailing_path)
                .read(&secret, &edge_domain::BackupLimits::schema_v1())
                .unwrap_err()
                .code,
            ErrorCode::BackupAuthenticationFailed
        );
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!output.with_extension("age.tmp").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_backup_source_rejects_unknown_managed_file_and_post_inventory_change() {
        let root = temp_root("backup-source-change");
        fs::create_dir_all(root.join("config/revisions")).unwrap();
        fs::create_dir_all(root.join("secrets")).unwrap();
        let snapshot = parse_mvp_config(
            include_str!("../../../examples/minimal.toml"),
            ConfigRevisionId::new("rev-1"),
        )
        .unwrap()
        .snapshot;
        let mut revisions = FileRevisionRepository::new(root.join("config"));
        revisions
            .save_revision(RevisionRecord {
                revision: ConfigRevision {
                    id: snapshot.revision_id.clone(),
                    schema_version: 1,
                    summary: "backup fixture".to_string(),
                },
                checksum: checksum_snapshot(&snapshot),
                snapshot,
            })
            .unwrap();
        revisions
            .set_current(&ConfigRevisionId::new("rev-1"))
            .unwrap();
        fs::write(root.join("config/unknown.override"), "unsafe").unwrap();
        let error = FileBackupArtifactSource::new(&root)
            .inventory()
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::BackupSourceInvalid);
        fs::remove_file(root.join("config/unknown.override")).unwrap();

        drop(FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap());
        let audit_directory = root.join("logs/audit");
        fs::write(audit_directory.join("unknown.audit"), b"unsafe").unwrap();
        assert_eq!(
            FileBackupArtifactSource::new(&root)
                .inventory()
                .unwrap_err()
                .code,
            ErrorCode::BackupSourceInvalid
        );
        fs::remove_file(audit_directory.join("unknown.audit")).unwrap();
        let first_segment = audit_directory.join("segment-0000000000000001.audit");
        let second_segment = audit_directory.join("segment-0000000000000002.audit");
        fs::hard_link(&first_segment, &second_segment).unwrap();
        assert_eq!(
            FileBackupArtifactSource::new(&root)
                .inventory()
                .unwrap_err()
                .code,
            ErrorCode::BackupSourceInvalid
        );
        fs::remove_file(second_segment).unwrap();

        let mut source = FileBackupArtifactSource::new(&root);
        let inventory = source.inventory().unwrap();
        let revision = inventory
            .artifacts
            .iter()
            .find(|item| item.kind == edge_domain::BackupArtifactKind::ConfigRevision)
            .unwrap();
        let revision_path = root
            .join("config/revisions")
            .join(format!("{}.toml", super::hex_encode("rev-1")));
        fs::write(revision_path, "changed").unwrap();
        assert_eq!(
            source.read_artifact(revision).unwrap_err().code,
            ErrorCode::BackupSourceChanged
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn memory_certificate_store_replaces_by_ref() {
        let mut store = MemoryCertificateStore::default();
        let certificate = StoredCertificate {
            certificate_ref: CertificateRef::new("cert-1"),
            domains: vec!["example.com".to_string()],
            not_after_epoch_seconds: 1_000,
            source: "manual".to_string(),
            certificate_pem: "cert".to_string(),
            private_key_pem: "key".to_string(),
        };

        store.save_certificate(certificate.clone()).unwrap();
        store.save_certificate(certificate).unwrap();

        assert_eq!(store.certificates().len(), 1);
        assert!(store
            .load_certificate(&CertificateRef::new("cert-1"))
            .unwrap()
            .is_some());
    }

    #[test]
    fn file_certificate_store_saves_layout_and_loads_metadata() {
        let root = temp_root("file-certificates");
        let mut store = FileCertificateStore::new(&root);

        store
            .save_certificate(StoredCertificate {
                certificate_ref: CertificateRef::new("cert-app"),
                domains: vec!["app.example.com".to_string(), "www.example.com".to_string()],
                not_after_epoch_seconds: 4_000_000_000,
                source: "manual".to_string(),
                certificate_pem: "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n"
                    .to_string(),
                private_key_pem: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"
                    .to_string(),
            })
            .unwrap();

        let cert_dir = root.join("cert-app");
        let loaded = store
            .load_certificate(&CertificateRef::new("cert-app"))
            .unwrap()
            .unwrap();
        let listed = store.list_certificates().unwrap();

        assert!(cert_dir.join("fullchain.pem").is_file());
        assert!(cert_dir.join("privkey.pem").is_file());
        assert!(cert_dir.join("metadata.toml").is_file());
        assert_eq!(loaded.certificate_ref.as_str(), "cert-app");
        assert_eq!(
            loaded.domains,
            vec!["app.example.com".to_string(), "www.example.com".to_string()]
        );
        assert_eq!(loaded.not_after_epoch_seconds, 4_000_000_000);
        assert_eq!(loaded.source, "manual");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].certificate_ref.as_str(), "cert-app");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn phase009_trust_validator_accepts_ca_and_rejects_leaf_material() {
        use edge_ports::TrustBundleMaterialValidator;
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, CustomExtension, IsCa, KeyPair,
        };

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let leaf = rcgen::generate_simple_self_signed(vec!["leaf.private.test".into()]).unwrap();
        let reference = edge_domain::TrustBundleRef::parse("private-root").unwrap();
        let mut validator = RustlsTrustBundleMaterialValidator;

        let validated = validator
            .validate_trust_bundle(&reference, ca.pem().as_bytes(), 10)
            .unwrap();
        assert_eq!(validated.metadata.certificate_count, 1);
        assert_eq!(validated.metadata.trust_bundle_ref, reference);

        let duplicate = format!("{}{}", ca.pem(), ca.pem());
        assert_eq!(
            validator
                .validate_trust_bundle(&reference, duplicate.as_bytes(), 10)
                .unwrap_err()
                .code,
            ErrorCode::TrustBundleInvalid
        );
        assert_eq!(
            validator
                .validate_trust_bundle(
                    &reference,
                    b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
                    10,
                )
                .unwrap_err()
                .code,
            ErrorCode::TrustBundleInvalid
        );
        let malformed_trailing = format!("{}-----BEGIN CERTIFICATE-----\nnot-base64\n", ca.pem());
        assert_eq!(
            validator
                .validate_trust_bundle(&reference, malformed_trailing.as_bytes(), 10)
                .unwrap_err()
                .code,
            ErrorCode::TrustBundleInvalid
        );

        assert_eq!(
            validator
                .validate_trust_bundle(&reference, leaf.cert.pem().as_bytes(), 10)
                .unwrap_err()
                .code,
            ErrorCode::TrustBundleInvalid
        );

        assert_eq!(
            validator
                .validate_trust_bundle(
                    &reference,
                    b"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n",
                    10,
                )
                .unwrap_err()
                .code,
            ErrorCode::TrustBundleInvalid
        );

        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let ca_bundle = (0_u8..33)
            .map(|value| {
                let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params
                    .custom_extensions
                    .push(CustomExtension::from_oid_content(
                        &[1, 3, 6, 1, 4, 1, 55555, 1],
                        vec![value],
                    ));
                params.self_signed(&key).unwrap().pem()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            validator
                .validate_trust_bundle(&reference, ca_bundle[..32].concat().as_bytes(), 10,)
                .unwrap()
                .metadata
                .certificate_count,
            32
        );
        assert_eq!(
            validator
                .validate_trust_bundle(&reference, ca_bundle.concat().as_bytes(), 10)
                .unwrap_err()
                .code,
            ErrorCode::TrustBundleLimitExceeded
        );

        let mut exact_encoded = ca.pem().into_bytes();
        exact_encoded.resize(384 * 1024, b'\n');
        assert!(validator
            .validate_trust_bundle(&reference, &exact_encoded, 10)
            .is_ok());
        exact_encoded.push(b'\n');
        assert_eq!(
            validator
                .validate_trust_bundle(&reference, &exact_encoded, 10)
                .unwrap_err()
                .code,
            ErrorCode::TrustBundleLimitExceeded
        );

        let certificate_with_payload = |payload_len: usize| {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 55555, 2],
                    vec![0; payload_len],
                ));
            params.self_signed(&key).unwrap()
        };
        let target = 256 * 1024;
        let mut low = 0;
        let mut high = target;
        let mut exact_payload = None;
        while low <= high {
            let candidate = low + (high - low) / 2;
            let length = certificate_with_payload(candidate).der().len();
            match length.cmp(&target) {
                std::cmp::Ordering::Less => low = candidate + 1,
                std::cmp::Ordering::Greater => high = candidate.saturating_sub(1),
                std::cmp::Ordering::Equal => {
                    exact_payload = Some(candidate);
                    break;
                }
            }
        }
        let exact_payload = exact_payload.expect("rcgen DER length should track extension length");
        let exact_decoded = certificate_with_payload(exact_payload).pem();
        assert!(exact_decoded.len() < 384 * 1024);
        let decoded_length =
            rustls_pki_types::CertificateDer::pem_slice_iter(exact_decoded.as_bytes())
                .next()
                .unwrap()
                .unwrap()
                .len();
        assert_eq!(decoded_length, target);
        validator
            .validate_trust_bundle(&reference, exact_decoded.as_bytes(), 10)
            .unwrap();
        let oversized_decoded = certificate_with_payload(exact_payload + 1).pem();
        assert_eq!(
            validator
                .validate_trust_bundle(&reference, oversized_decoded.as_bytes(), 10)
                .unwrap_err()
                .code,
            ErrorCode::TrustBundleLimitExceeded
        );
    }

    #[test]
    fn phase009_file_trust_store_is_create_only_listed_and_deletable() {
        use edge_ports::{TrustBundleMetadata, TrustBundleStore, ValidatedTrustBundle};

        let root = temp_root("phase009-trust-store");
        let reference = edge_domain::TrustBundleRef::parse("private-root").unwrap();
        let bundle = || {
            ValidatedTrustBundle::new(
                TrustBundleMetadata {
                    trust_bundle_ref: reference.clone(),
                    certificate_count: 1,
                    imported_at_epoch_seconds: 10,
                    content_sha256: sha2::Sha256::digest(b"ca-material").into(),
                },
                b"ca-material".to_vec(),
            )
        };
        let mut store = FileTrustBundleStore::new(&root);
        store.create_trust_bundle(bundle()).unwrap();
        assert_eq!(store.list_trust_bundles().unwrap().len(), 1);
        assert!(root.join("private-root/roots.pem").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(root.join("private-root/roots.pem"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert_eq!(
            store.create_trust_bundle(bundle()).unwrap_err().code,
            ErrorCode::TrustBundleAlreadyExists
        );
        store.delete_trust_bundle(&reference).unwrap();
        assert!(store.list_trust_bundles().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn phase009_trust_store_reads_verified_material_and_rejects_tamper() {
        use edge_ports::{TrustBundleReader, TrustBundleStore};
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
        use sha2::Digest;

        let root = temp_root("phase009-trust-read");
        let reference = TrustBundleRef::parse("private-root").unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let bytes = ca.pem().into_bytes();
        let mut validator = RustlsTrustBundleMaterialValidator;
        let validated = validator
            .validate_trust_bundle(&reference, &bytes, 10)
            .unwrap();
        assert_eq!(
            validated.metadata.content_sha256,
            <[u8; 32]>::from(sha2::Sha256::digest(&bytes))
        );

        let mut store = FileTrustBundleStore::new(&root);
        store.create_trust_bundle(validated).unwrap();
        let loaded = store.load_trust_bundle(&reference).unwrap().unwrap();
        assert_eq!(loaded.encoded_material(), bytes);

        fs::write(root.join("private-root/roots.pem"), b"tampered").unwrap();
        assert_eq!(
            store.load_trust_bundle(&reference).unwrap_err().code,
            ErrorCode::TrustBundleStoreFailed
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn phase009_trust_store_rejects_symlinked_material_on_read() {
        use edge_ports::{TrustBundleReader, TrustBundleStore};
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
        use std::os::unix::fs::symlink;

        let root = temp_root("phase009-trust-read-symlink");
        let outside = temp_root("phase009-trust-read-symlink-outside");
        fs::create_dir_all(&outside).unwrap();
        let reference = TrustBundleRef::parse("private-root").unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        let mut validator = RustlsTrustBundleMaterialValidator;
        let validated = validator
            .validate_trust_bundle(&reference, ca.pem().as_bytes(), 10)
            .unwrap();
        let mut store = FileTrustBundleStore::new(&root);
        store.create_trust_bundle(validated).unwrap();
        let roots_path = root.join("private-root/roots.pem");
        fs::remove_file(&roots_path).unwrap();
        let outside_file = outside.join("roots.pem");
        fs::write(&outside_file, ca.pem()).unwrap();
        symlink(&outside_file, &roots_path).unwrap();

        assert_eq!(
            store.load_trust_bundle(&reference).unwrap_err().code,
            ErrorCode::TrustBundleStoreFailed
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn phase009_file_trust_store_rejects_symlink_reference() {
        use edge_ports::{TrustBundleMetadata, TrustBundleStore, ValidatedTrustBundle};
        use std::os::unix::fs::symlink;

        let root = temp_root("phase009-trust-symlink");
        fs::create_dir_all(&root).unwrap();
        let outside = temp_root("phase009-trust-outside");
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("private-root")).unwrap();
        let reference = TrustBundleRef::parse("private-root").unwrap();
        let mut store = FileTrustBundleStore::new(&root);
        let error = store
            .create_trust_bundle(ValidatedTrustBundle::new(
                TrustBundleMetadata {
                    trust_bundle_ref: reference,
                    certificate_count: 1,
                    imported_at_epoch_seconds: 10,
                    content_sha256: sha2::Sha256::digest(b"ca-material").into(),
                },
                b"ca-material".to_vec(),
            ))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::TrustBundleAlreadyExists);
        assert!(outside.read_dir().unwrap().next().is_none());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_certificate_store_writes_private_key_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("file-certificate-permissions");
        let mut store = FileCertificateStore::new(&root);

        store
            .save_certificate(StoredCertificate {
                certificate_ref: CertificateRef::new("cert-app"),
                domains: vec!["app.example.com".to_string()],
                not_after_epoch_seconds: 4_000_000_000,
                source: "manual".to_string(),
                certificate_pem: "cert".to_string(),
                private_key_pem: "key".to_string(),
            })
            .unwrap();

        let mode = fs::metadata(root.join("cert-app/privkey.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o600);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_certificate_store_deletes_certificate_for_import_compensation() {
        let root = temp_root("certificate-delete-compensation");
        let mut store = FileCertificateStore::new(&root);
        let certificate = test_certificate("cert-manual");
        let certificate_ref = certificate.certificate_ref.clone();
        store.save_certificate(certificate).unwrap();

        store.delete_certificate(&certificate_ref).unwrap();

        assert!(store.load_certificate(&certificate_ref).unwrap().is_none());
        store.delete_certificate(&certificate_ref).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_certificate_store_failed_temp_write_keeps_existing_certificate() {
        let root = temp_root("file-certificate-atomic-failure");
        let mut store = FileCertificateStore::new(&root);

        store
            .save_certificate(StoredCertificate {
                certificate_ref: CertificateRef::new("cert-app"),
                domains: vec!["app.example.com".to_string()],
                not_after_epoch_seconds: 1_000,
                source: "manual".to_string(),
                certificate_pem: "old-cert".to_string(),
                private_key_pem: "old-key".to_string(),
            })
            .unwrap();
        fs::create_dir(root.join("cert-app/fullchain.pem.tmp")).unwrap();

        let error = store
            .save_certificate(StoredCertificate {
                certificate_ref: CertificateRef::new("cert-app"),
                domains: vec!["app.example.com".to_string()],
                not_after_epoch_seconds: 2_000,
                source: "manual".to_string(),
                certificate_pem: "new-cert".to_string(),
                private_key_pem: "new-key".to_string(),
            })
            .unwrap_err();
        let loaded = store
            .load_certificate(&CertificateRef::new("cert-app"))
            .unwrap()
            .unwrap();

        assert_eq!(error.code, ErrorCode::CertificateStoreFailed);
        assert_eq!(loaded.not_after_epoch_seconds, 1_000);
        assert_eq!(loaded.certificate_pem, "old-cert");
        assert_eq!(loaded.private_key_pem, "old-key");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rustls_server_config_loader_accepts_valid_pem_certificate() {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["app.example.com".to_string()]).unwrap();
        let loaded = load_rustls_server_config(&StoredCertificate {
            certificate_ref: CertificateRef::new("cert-app"),
            domains: vec!["app.example.com".to_string()],
            not_after_epoch_seconds: 4_000_000_000,
            source: "manual".to_string(),
            certificate_pem: cert.pem(),
            private_key_pem: signing_key.serialize_pem(),
        })
        .unwrap();

        assert_eq!(loaded.certificate_ref.as_str(), "cert-app");
        assert!(!loaded.server_config.alpn_protocols.is_empty());
    }

    #[test]
    fn tls_runtime_snapshot_indexes_loaded_configs_by_certificate_ref() {
        let app = load_rustls_server_config(&test_certificate("cert-app")).unwrap();
        let admin = load_rustls_server_config(&test_certificate("cert-admin")).unwrap();

        let snapshot = TlsRuntimeSnapshot::from_configs(vec![app.clone(), admin.clone()]).unwrap();

        assert_eq!(snapshot.len(), 2);
        assert_eq!(
            snapshot
                .get(&CertificateRef::new("cert-app"))
                .unwrap()
                .certificate_ref
                .as_str(),
            "cert-app"
        );
        assert_eq!(snapshot.certificate_refs().len(), 2);
        assert!(!snapshot.is_empty());
    }

    #[test]
    fn tls_runtime_snapshot_selects_certificate_ref_by_normalized_sni() {
        let app = load_rustls_server_config(&test_certificate("cert-app")).unwrap();
        let admin = load_rustls_server_config(&test_certificate("cert-admin")).unwrap();
        let snapshot = TlsRuntimeSnapshot::from_configs(vec![app, admin]).unwrap();

        let selection = snapshot
            .select_certificate_ref_for_sni("CERT-ADMIN.example.com.")
            .expect("SNI selection");

        assert_eq!(selection.as_str(), "cert-admin");
        assert!(
            snapshot
                .select_certificate_ref_for_sni("missing.example.com")
                .is_none(),
            "unknown SNI must not fall back to an unrelated certificate"
        );
    }

    #[test]
    fn tls_runtime_snapshot_rejects_duplicate_sni_hostname() {
        let mut first = test_certificate("cert-app");
        first.domains = vec!["shared.example.com".to_string()];
        let mut second = test_certificate("cert-admin");
        second.domains = vec!["SHARED.example.com.".to_string()];
        let first = load_rustls_server_config(&first).unwrap();
        let second = load_rustls_server_config(&second).unwrap();

        let error = TlsRuntimeSnapshot::from_configs(vec![first, second]).unwrap_err();

        assert_eq!(error.code, ErrorCode::CertificateStoreFailed);
        assert!(error.message.contains("duplicate TLS SNI hostname"));
    }

    #[test]
    fn tls_runtime_snapshot_builds_sni_server_config() {
        let app = load_rustls_server_config(&test_certificate("cert-app")).unwrap();
        let admin = load_rustls_server_config(&test_certificate("cert-admin")).unwrap();
        let snapshot = TlsRuntimeSnapshot::from_configs(vec![app, admin]).unwrap();

        let server_config = snapshot.sni_server_config().unwrap();

        assert!(!server_config.alpn_protocols.is_empty());
    }

    #[test]
    fn phase009_required_client_auth_accepts_trusted_client_certificate() {
        use edge_ports::TrustBundleMaterialValidator;
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
            KeyPair,
        };

        let server_certificate = test_certificate("cert-app");
        let server = load_rustls_server_config(&server_certificate).unwrap();
        let snapshot = TlsRuntimeSnapshot::from_configs(vec![server]).unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();
        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client = client_params.signed_by(&client_key, &root).unwrap();
        let reference = TrustBundleRef::parse("private-client-root").unwrap();
        let trust = RustlsTrustBundleMaterialValidator
            .validate_trust_bundle(&reference, root.pem().as_bytes(), 10)
            .unwrap();
        let server_config = snapshot
            .sni_server_config_with_required_client_auth(&trust)
            .unwrap();
        let client_config = rustls_test_client_config_with_certificate(
            &server_certificate.certificate_pem,
            &client.pem(),
            &client_key.serialize_pem(),
        );

        rustls_memory_handshake(server_config, client_config, "cert-app.example.com").unwrap();
    }

    #[test]
    fn phase009_required_client_auth_rejects_missing_untrusted_incomplete_and_invalid_clients() {
        use edge_ports::TrustBundleMaterialValidator;
        use rcgen::ExtendedKeyUsagePurpose;

        let server_certificate = test_certificate("cert-app");
        let snapshot =
            TlsRuntimeSnapshot::from_configs(vec![
                load_rustls_server_config(&server_certificate).unwrap()
            ])
            .unwrap();
        let (trusted_root, trusted_chain, trusted_key) = private_client_identity(
            ExtendedKeyUsagePurpose::ClientAuth,
            (2025, 1, 1),
            (2035, 1, 1),
            true,
        );
        let reference = TrustBundleRef::parse("private-client-root").unwrap();
        let trust = RustlsTrustBundleMaterialValidator
            .validate_trust_bundle(&reference, trusted_root.as_bytes(), 10)
            .unwrap();
        let required = || {
            snapshot
                .sni_server_config_with_required_client_auth(&trust)
                .unwrap()
        };
        let no_certificate =
            rustls_test_client_config_without_certificate(&server_certificate.certificate_pem);
        assert!(
            rustls_memory_handshake(required(), no_certificate, "cert-app.example.com").is_err()
        );
        let required_factory = RustlsServerTlsSessionFactory::new(required());
        let mut malformed = required_factory.create_server_session();
        let malformed_error = malformed
            .receive_encrypted(&[0xff, 0x03, 0x03, 0x00, 0x00])
            .unwrap_err();
        assert_eq!(malformed_error.code, ErrorCode::TlsHandshakeFailed);
        assert!(matches!(
            malformed.progress(),
            TlsSessionProgress::Failed {
                code: ErrorCode::TlsHandshakeFailed
            }
        ));

        let (_, wrong_chain, wrong_key) = private_client_identity(
            ExtendedKeyUsagePurpose::ClientAuth,
            (2025, 1, 1),
            (2035, 1, 1),
            true,
        );
        let wrong_root = rustls_test_client_config_with_certificate(
            &server_certificate.certificate_pem,
            &wrong_chain,
            &wrong_key,
        );
        assert!(rustls_memory_handshake(required(), wrong_root, "cert-app.example.com").is_err());

        let leaf_only = trusted_chain
            .split("-----END CERTIFICATE-----")
            .next()
            .map(|pem| format!("{pem}-----END CERTIFICATE-----\n"))
            .unwrap();
        let incomplete = rustls_test_client_config_with_certificate(
            &server_certificate.certificate_pem,
            &leaf_only,
            &trusted_key,
        );
        assert!(rustls_memory_handshake(required(), incomplete, "cert-app.example.com").is_err());

        for (usage, not_before, not_after) in [
            (
                ExtendedKeyUsagePurpose::ServerAuth,
                (2025, 1, 1),
                (2035, 1, 1),
            ),
            (
                ExtendedKeyUsagePurpose::ClientAuth,
                (2020, 1, 1),
                (2021, 1, 1),
            ),
            (
                ExtendedKeyUsagePurpose::ClientAuth,
                (2035, 1, 1),
                (2036, 1, 1),
            ),
        ] {
            let (case_root, chain, key) =
                private_client_identity(usage, not_before, not_after, false);
            let case_trust = RustlsTrustBundleMaterialValidator
                .validate_trust_bundle(&reference, case_root.as_bytes(), 10)
                .unwrap();
            let client = rustls_test_client_config_with_certificate(
                &server_certificate.certificate_pem,
                &chain,
                &key,
            );
            assert!(rustls_memory_handshake(
                snapshot
                    .sni_server_config_with_required_client_auth(&case_trust)
                    .unwrap(),
                client,
                "cert-app.example.com"
            )
            .is_err());
        }
    }

    #[test]
    fn tls_runtime_snapshot_replace_rejects_duplicate_sni_hostname() {
        let app = load_rustls_server_config(&test_certificate("cert-app")).unwrap();
        let admin = load_rustls_server_config(&test_certificate("cert-admin")).unwrap();
        let mut replacement = test_certificate("cert-admin");
        replacement.domains = vec!["cert-app.example.com".to_string()];
        let replacement = load_rustls_server_config(&replacement).unwrap();
        let mut snapshot = TlsRuntimeSnapshot::from_configs(vec![app, admin]).unwrap();

        let error = snapshot.replace_config(replacement).unwrap_err();

        assert_eq!(error.code, ErrorCode::CertificateStoreFailed);
        assert_eq!(
            snapshot
                .select_certificate_ref_for_sni("cert-app.example.com")
                .unwrap()
                .as_str(),
            "cert-app"
        );
    }

    #[test]
    fn tls_runtime_snapshot_rejects_empty_configs() {
        let error = TlsRuntimeSnapshot::from_configs(Vec::new()).unwrap_err();

        assert_eq!(error.code, ErrorCode::CertificateNotFound);
    }

    #[test]
    fn tls_runtime_snapshot_rejects_duplicate_certificate_refs() {
        let first = load_rustls_server_config(&test_certificate("cert-app")).unwrap();
        let second = load_rustls_server_config(&test_certificate("cert-app")).unwrap();

        let error = TlsRuntimeSnapshot::from_configs(vec![first, second]).unwrap_err();

        assert_eq!(error.code, ErrorCode::CertificateStoreFailed);
    }

    #[test]
    fn rustls_server_config_loader_rejects_invalid_private_key_without_panic() {
        let rcgen::CertifiedKey { cert, .. } =
            rcgen::generate_simple_self_signed(vec!["app.example.com".to_string()]).unwrap();
        let error = load_rustls_server_config(&StoredCertificate {
            certificate_ref: CertificateRef::new("cert-app"),
            domains: vec!["app.example.com".to_string()],
            not_after_epoch_seconds: 4_000_000_000,
            source: "manual".to_string(),
            certificate_pem: cert.pem(),
            private_key_pem: "not a private key".to_string(),
        })
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::CertificateStoreFailed);
    }

    #[test]
    fn rustls_certificate_material_validator_returns_leaf_expiry() {
        let certificate = test_certificate("cert-manual");
        let mut validator = RustlsCertificateMaterialValidator;

        let validated = validator
            .validate(&CertificateMaterial {
                certificate_pem: certificate.certificate_pem,
                private_key_pem: certificate.private_key_pem,
            })
            .unwrap();

        assert!(validated.not_after_epoch_seconds > 0);
    }

    #[test]
    fn rustls_certificate_material_validator_returns_leaf_dns_identities() {
        let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec![
            "app.example.com".to_string(),
            "www.example.com".to_string(),
        ])
        .unwrap();
        let mut validator = RustlsCertificateMaterialValidator;

        let validated = validator
            .validate(&CertificateMaterial {
                certificate_pem: cert.pem(),
                private_key_pem: signing_key.serialize_pem(),
            })
            .unwrap();

        assert_eq!(
            validated.dns_names,
            vec!["app.example.com".to_string(), "www.example.com".to_string()]
        );
    }

    #[test]
    fn rustls_tls_session_completes_with_fragmented_client_hello() {
        let certificate = test_certificate("cert-app");
        let config = load_rustls_server_config(&certificate).unwrap();
        let factory = RustlsServerTlsSessionFactory::new(config.server_config);
        let mut server = factory.create_server_session();
        let mut client = rustls_test_client(&certificate.certificate_pem, "cert-app.example.com");

        drive_tls_handshake(&mut client, server.as_mut());

        assert_eq!(
            server.progress(),
            edge_ports::TlsSessionProgress::Established
        );
        assert!(!client.is_handshaking());
    }

    #[test]
    fn phase009_rustls_client_factory_verifies_private_root_and_server_name() {
        use edge_ports::{ClientTlsSessionFactory, TrustBundleMaterialValidator};
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let server = CertificateParams::new(vec!["backend.private.test".to_string()])
            .unwrap()
            .signed_by(&server_key, &ca)
            .unwrap();
        let stored = StoredCertificate {
            certificate_ref: CertificateRef::new("backend"),
            domains: vec!["backend.private.test".to_string()],
            not_after_epoch_seconds: 4_000_000_000,
            source: "test".to_string(),
            certificate_pem: format!("{}{}", server.pem(), ca.pem()),
            private_key_pem: server_key.serialize_pem(),
        };
        let server_factory = RustlsServerTlsSessionFactory::new(
            load_rustls_server_config(&stored).unwrap().server_config,
        );
        let reference = TrustBundleRef::parse("private-root").unwrap();
        let trust = RustlsTrustBundleMaterialValidator
            .validate_trust_bundle(&reference, ca.pem().as_bytes(), 10)
            .unwrap();
        let client_factory = RustlsClientTlsSessionFactory::from_trust_bundle(&trust).unwrap();
        let server_name = edge_domain::TlsServerName::parse("backend.private.test").unwrap();
        let mut client = client_factory.create_client_session(&server_name).unwrap();
        let mut server = server_factory.create_server_session();

        drive_tls_session_pair(&mut *client, &mut *server).unwrap();
        assert_eq!(client.progress(), TlsSessionProgress::Established);
        assert_eq!(server.progress(), TlsSessionProgress::Established);
        client.receive_plaintext(b"ping").unwrap();
        let encrypted = client.take_encrypted(usize::MAX);
        server.receive_encrypted(&encrypted).unwrap();
        assert_eq!(server.take_decrypted(4), b"ping".to_vec());
    }

    #[derive(Debug)]
    struct FixedTlsTime(u64);

    impl rustls::time_provider::TimeProvider for FixedTlsTime {
        fn current_time(&self) -> Option<rustls_pki_types::UnixTime> {
            Some(rustls_pki_types::UnixTime::since_unix_epoch(
                std::time::Duration::from_secs(self.0),
            ))
        }
    }

    #[test]
    fn phase009_certificate_validity_uses_injected_tls_time() {
        use edge_ports::{ClientTlsSessionFactory, TrustBundleMaterialValidator};
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        root_params.not_after = rcgen::date_time_ymd(2040, 1, 1);
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();
        let mut server_params =
            CertificateParams::new(vec!["backend.private.test".to_string()]).unwrap();
        server_params.not_before = rcgen::date_time_ymd(2030, 1, 1);
        server_params.not_after = rcgen::date_time_ymd(2031, 1, 1);
        let server_key = KeyPair::generate().unwrap();
        let server = server_params.signed_by(&server_key, &root).unwrap();
        let stored = StoredCertificate {
            certificate_ref: CertificateRef::new("backend"),
            domains: vec!["backend.private.test".to_string()],
            not_after_epoch_seconds: 1_924_992_000,
            source: "test".to_string(),
            certificate_pem: format!("{}{}", server.pem(), root.pem()),
            private_key_pem: server_key.serialize_pem(),
        };
        let reference = TrustBundleRef::parse("private-root").unwrap();
        let trust = RustlsTrustBundleMaterialValidator
            .validate_trust_bundle(&reference, root.pem().as_bytes(), 10)
            .unwrap();
        let name = edge_domain::TlsServerName::parse("backend.private.test").unwrap();

        for (now, should_succeed) in [(1_800_000_000, false), (1_900_000_000, true)] {
            let client_factory =
                RustlsClientTlsSessionFactory::from_trust_bundle_with_time_provider(
                    &trust,
                    Arc::new(FixedTlsTime(now)),
                )
                .unwrap();
            let server_factory = RustlsServerTlsSessionFactory::new(
                load_rustls_server_config(&stored).unwrap().server_config,
            );
            let mut client = client_factory.create_client_session(&name).unwrap();
            let mut server = server_factory.create_server_session();
            assert_eq!(
                drive_tls_session_pair(&mut *client, &mut *server).is_ok(),
                should_succeed
            );
        }
    }

    #[test]
    fn phase009_rustls_client_factory_rejects_wrong_root_name_chain_and_record() {
        use edge_ports::{ClientTlsSessionFactory, TrustBundleMaterialValidator};
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["backend.private.test".to_string()])
            .unwrap()
            .signed_by(&server_key, &root)
            .unwrap();
        let server_material = |certificate_pem: String| StoredCertificate {
            certificate_ref: CertificateRef::new("backend"),
            domains: vec!["backend.private.test".to_string()],
            not_after_epoch_seconds: 4_000_000_000,
            source: "test".to_string(),
            certificate_pem,
            private_key_pem: server_key.serialize_pem(),
        };
        let server_factory = RustlsServerTlsSessionFactory::new(
            load_rustls_server_config(&server_material(format!("{}{}", leaf.pem(), root.pem())))
                .unwrap()
                .server_config,
        );
        let reference = TrustBundleRef::parse("private-root").unwrap();
        let trust = RustlsTrustBundleMaterialValidator
            .validate_trust_bundle(&reference, root.pem().as_bytes(), 10)
            .unwrap();
        let trusted_factory = RustlsClientTlsSessionFactory::from_trust_bundle(&trust).unwrap();

        let wrong_name = edge_domain::TlsServerName::parse("wrong.private.test").unwrap();
        let mut client = trusted_factory.create_client_session(&wrong_name).unwrap();
        let mut server = server_factory.create_server_session();
        let error = drive_tls_session_pair(&mut *client, &mut *server).unwrap_err();
        assert_eq!(error.code, ErrorCode::UpstreamTlsIdentityMismatch);
        assert_eq!(error.message, "upstream TLS identity verification failed");
        assert!(!error.message.contains("wrong.private.test"));

        let mut other_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        other_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let other =
            CertifiedIssuer::self_signed(other_params, KeyPair::generate().unwrap()).unwrap();
        let other_trust = RustlsTrustBundleMaterialValidator
            .validate_trust_bundle(&reference, other.pem().as_bytes(), 10)
            .unwrap();
        let untrusted_factory =
            RustlsClientTlsSessionFactory::from_trust_bundle(&other_trust).unwrap();
        let correct_name = edge_domain::TlsServerName::parse("backend.private.test").unwrap();
        let mut client = untrusted_factory
            .create_client_session(&correct_name)
            .unwrap();
        let mut server = server_factory.create_server_session();
        let error = drive_tls_session_pair(&mut *client, &mut *server).unwrap_err();
        assert_eq!(error.code, ErrorCode::UpstreamTlsUntrusted);
        assert_eq!(error.message, "upstream TLS peer verification failed");
        assert!(!error.message.contains("backend.private.test"));

        let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let intermediate =
            CertifiedIssuer::signed_by(intermediate_params, KeyPair::generate().unwrap(), &root)
                .unwrap();
        let chained_key = KeyPair::generate().unwrap();
        let chained_leaf = CertificateParams::new(vec!["backend.private.test".to_string()])
            .unwrap()
            .signed_by(&chained_key, &intermediate)
            .unwrap();
        let missing_chain_server = RustlsServerTlsSessionFactory::new(
            load_rustls_server_config(&StoredCertificate {
                certificate_ref: CertificateRef::new("missing-chain"),
                domains: vec!["backend.private.test".to_string()],
                not_after_epoch_seconds: 4_000_000_000,
                source: "test".to_string(),
                certificate_pem: chained_leaf.pem(),
                private_key_pem: chained_key.serialize_pem(),
            })
            .unwrap()
            .server_config,
        );
        let mut client = trusted_factory
            .create_client_session(&correct_name)
            .unwrap();
        let mut server = missing_chain_server.create_server_session();
        assert_eq!(
            drive_tls_session_pair(&mut *client, &mut *server)
                .unwrap_err()
                .code,
            ErrorCode::UpstreamTlsUntrusted
        );

        let mut client = trusted_factory
            .create_client_session(&correct_name)
            .unwrap();
        let malformed = [0xff, 0x03, 0x03, 0x00, 0x00];
        assert_eq!(
            client.receive_encrypted(&malformed).unwrap_err().code,
            ErrorCode::UpstreamTlsUntrusted
        );
        assert!(matches!(
            client.progress(),
            TlsSessionProgress::Failed {
                code: ErrorCode::UpstreamTlsUntrusted
            }
        ));
        assert_eq!(client.interest(), TlsSessionInterest::none());
    }

    #[test]
    fn phase009_rustls_client_factory_rejects_invalid_prevalidated_profile() {
        let malformed = ValidatedTrustBundle::new(
            TrustBundleMetadata {
                trust_bundle_ref: TrustBundleRef::parse("malformed-root").unwrap(),
                certificate_count: 1,
                imported_at_epoch_seconds: 10,
                content_sha256: [0_u8; 32],
            },
            b"not a certificate".to_vec(),
        );

        let error = RustlsClientTlsSessionFactory::from_trust_bundle(&malformed).unwrap_err();

        assert_eq!(error.code, ErrorCode::UpstreamTlsProfileInvalid);
        assert_eq!(error.message, "upstream TLS profile is invalid");
    }

    #[test]
    fn rustls_tls_session_roundtrips_plaintext_after_established() {
        let certificate = test_certificate("cert-app");
        let config = load_rustls_server_config(&certificate).unwrap();
        let factory = RustlsServerTlsSessionFactory::new(config.server_config);
        let mut server = factory.create_server_session();
        let mut client = rustls_test_client(&certificate.certificate_pem, "cert-app.example.com");
        drive_tls_handshake(&mut client, server.as_mut());

        client
            .writer()
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .unwrap();
        send_client_tls_to_server_fragmented(&mut client, server.as_mut());

        assert_eq!(
            server.take_decrypted(64),
            b"GET / HTTP/1.1\r\n\r\n".to_vec()
        );
        assert_eq!(
            server
                .receive_plaintext(b"HTTP/1.1 200 OK\r\n\r\n")
                .unwrap(),
            19
        );
        assert_eq!(
            server.interest(),
            edge_ports::TlsSessionInterest::writable()
        );
        receive_server_tls_on_client(server.as_mut(), &mut client);
        let response = read_available_client_plaintext(&mut client);

        assert_eq!(response, b"HTTP/1.1 200 OK\r\n\r\n");
    }

    #[test]
    fn rustls_tls_session_reports_only_adapter_owned_staging_bytes() {
        let certificate = test_certificate("cert-pending");
        let config = load_rustls_server_config(&certificate).unwrap();
        let factory = RustlsServerTlsSessionFactory::new(config.server_config);
        let mut server = factory.create_server_session();
        let mut client =
            rustls_test_client(&certificate.certificate_pem, "cert-pending.example.com");
        drive_tls_handshake(&mut client, server.as_mut());

        assert_eq!(
            server.pending_bytes(),
            edge_ports::TlsPendingBytes::default()
        );
        server.receive_plaintext(b"response").unwrap();
        let pending = server.pending_bytes();
        assert_eq!(pending.handshake_bytes, 0);
        assert_eq!(pending.decrypted_bytes, 0);
        assert!(pending.encrypted_bytes > 8);
        assert_eq!(pending.total_bytes(), Some(pending.encrypted_bytes));

        let first = server.take_encrypted(5);
        assert_eq!(first.len(), 5);
        assert_eq!(
            server.pending_bytes().encrypted_bytes,
            pending.encrypted_bytes - 5
        );
        server.take_encrypted(usize::MAX);
        assert!(server.pending_bytes().is_zero());
    }

    #[test]
    fn rustls_tls_session_rejects_malformed_record_without_panic() {
        let certificate = test_certificate("cert-app");
        let config = load_rustls_server_config(&certificate).unwrap();
        let factory = RustlsServerTlsSessionFactory::new(config.server_config);
        let mut server = factory.create_server_session();

        let result = server.receive_encrypted(b"not a tls record");

        assert!(result.is_err());
        assert!(matches!(
            server.progress(),
            edge_ports::TlsSessionProgress::Failed {
                code: ErrorCode::TlsHandshakeFailed
            }
        ));
    }

    #[test]
    fn rustls_tls_session_emits_close_notify_without_socket_io() {
        let certificate = test_certificate("cert-app");
        let config = load_rustls_server_config(&certificate).unwrap();
        let factory = RustlsServerTlsSessionFactory::new(config.server_config);
        let mut server = factory.create_server_session();
        let mut client = rustls_test_client(&certificate.certificate_pem, "cert-app.example.com");
        drive_tls_handshake(&mut client, server.as_mut());

        server.request_close_notify().unwrap();

        assert_eq!(server.progress(), edge_ports::TlsSessionProgress::Closing);
        assert_eq!(
            server.interest(),
            edge_ports::TlsSessionInterest::writable()
        );
        assert!(!server.take_encrypted(1).is_empty());
        assert_eq!(server.progress(), edge_ports::TlsSessionProgress::Closing);
        assert!(!server.take_encrypted(usize::MAX).is_empty());
        assert_eq!(
            server.progress(),
            edge_ports::TlsSessionProgress::PeerClosed
        );
        assert_eq!(server.interest(), edge_ports::TlsSessionInterest::none());
    }

    #[test]
    fn rustls_certificate_material_validator_rejects_mismatched_key() {
        let certificate = test_certificate("cert-manual");
        let other = test_certificate("cert-other");
        let mut validator = RustlsCertificateMaterialValidator;

        let error = validator
            .validate(&CertificateMaterial {
                certificate_pem: certificate.certificate_pem,
                private_key_pem: other.private_key_pem,
            })
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::CertificateInvalid);
    }

    #[test]
    fn fake_acme_client_issues_staging_certificate() {
        let mut client = FakeAcmeClient::default();

        let result = client
            .issue_certificate(AcmeOrderRequest {
                domains: vec!["example.com".to_string()],
                account_email: "admin@example.com".to_string(),
                production: false,
                terms_accepted: false,
            })
            .unwrap();

        assert_eq!(result.certificate.source, "fake-acme-staging");
        assert_eq!(result.certificate.masked_private_key(), "***");
    }

    #[test]
    fn fake_acme_client_presents_http01_challenge_before_issuing() {
        let mut client = FakeAcmeClient::default();
        let mut runtime = RecordingHttp01Runtime::default();

        let result = client
            .issue_certificate_http01(
                AcmeOrderRequest {
                    domains: vec!["example.com".to_string()],
                    account_email: "admin@example.com".to_string(),
                    production: false,
                    terms_accepted: false,
                },
                &mut runtime,
            )
            .unwrap();

        assert_eq!(result.certificate.source, "fake-acme-staging");
        assert_eq!(runtime.presented.len(), 1);
        assert_eq!(runtime.presented[0].0, "fake-acme-http01-example-com");
        assert_eq!(runtime.verified, runtime.presented);
    }

    #[test]
    fn letsencrypt_http01_client_rejects_challengeless_issue() {
        let mut client = LetsEncryptHttp01AcmeClient::new();

        let error = client
            .issue_certificate(AcmeOrderRequest {
                domains: vec!["example.com".to_string()],
                account_email: "admin@example.com".to_string(),
                production: false,
                terms_accepted: false,
            })
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::AcmeChallengeFailed);
    }

    #[test]
    fn letsencrypt_staging_client_rejects_production_before_network_io() {
        let mut client = LetsEncryptHttp01AcmeClient::new();
        let mut runtime = RecordingHttp01Runtime::default();

        let error = client
            .issue_certificate_http01(
                AcmeOrderRequest {
                    domains: vec!["example.com".to_string()],
                    account_email: "admin@example.com".to_string(),
                    production: true,
                    terms_accepted: true,
                },
                &mut runtime,
            )
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigProductionAcmeRequiresOptIn);
        assert!(runtime.presented.is_empty());
    }

    #[test]
    fn letsencrypt_staging_client_requires_terms_before_network_io() {
        let mut client = LetsEncryptHttp01AcmeClient::new();
        let mut runtime = RecordingHttp01Runtime::default();

        let error = client
            .issue_certificate_http01(
                AcmeOrderRequest {
                    domains: vec!["example.com".to_string()],
                    account_email: "admin@example.com".to_string(),
                    production: false,
                    terms_accepted: false,
                },
                &mut runtime,
            )
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::AcmeTermsNotAccepted);
        assert!(runtime.presented.is_empty());
    }

    #[test]
    fn certificate_chain_expiry_is_parsed_from_leaf_pem() {
        let rcgen::CertifiedKey { cert, .. } =
            rcgen::generate_simple_self_signed(vec!["app.example.com".to_string()]).unwrap();

        let not_after = certificate_chain_not_after_epoch_seconds(&cert.pem()).unwrap();

        assert!(not_after > 0);
    }

    #[test]
    fn memory_metrics_sink_records_metrics() {
        let mut sink = MemoryMetricsSink::default();

        sink.record_metric(
            MetricEvent::counter_add(
                edge_ports::MetricDescriptor::RequestsTotal,
                1,
                vec![
                    ("route_id".to_string(), "route-a".to_string()),
                    ("status_class".to_string(), "2xx".to_string()),
                ],
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(sink.metrics().len(), 1);
    }

    #[test]
    fn metric_channel_publisher_maps_accepted_full_and_stopped_without_blocking() {
        use edge_ports::{MetricPublishOutcome, MetricPublisher};

        let event = || {
            MetricEvent::gauge_set(edge_ports::MetricDescriptor::MetricsReady, 1, Vec::new())
                .unwrap()
        };
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let publisher = MetricChannelPublisher::new(sender);

        assert_eq!(
            publisher.try_publish(event()),
            MetricPublishOutcome::Accepted
        );
        assert_eq!(publisher.try_publish(event()), MetricPublishOutcome::Full);
        assert_eq!(receiver.try_recv().unwrap(), event());
        drop(receiver);
        assert_eq!(
            publisher.try_publish(event()),
            MetricPublishOutcome::Stopped
        );
    }

    #[test]
    fn metric_registry_collector_publishes_snapshot_and_stops_after_disconnect() {
        use edge_ports::{MetricDescriptor, MetricPublisher};

        let (sender, receiver) = std::sync::mpsc::sync_channel(4);
        let publisher = MetricChannelPublisher::new(sender);
        let (log_sender, log_receiver) = std::sync::mpsc::sync_channel(4);
        let (reader, handle) = spawn_metric_registry_collector(receiver, Some(log_sender));
        assert_eq!(
            publisher.try_publish(
                MetricEvent::gauge_set(MetricDescriptor::ActiveConnections, 3, Vec::new()).unwrap()
            ),
            MetricPublishOutcome::Accepted
        );
        let deadline = Instant::now() + Duration::from_secs(1);
        while reader
            .snapshot()
            .gauge_value(MetricDescriptor::ActiveConnections)
            != Some(3)
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            reader
                .snapshot()
                .gauge_value(MetricDescriptor::ActiveConnections),
            Some(3)
        );
        handle.shutdown();
        assert_eq!(reader.state(), MetricCollectorState::Stopped);
        assert_eq!(
            log_receiver
                .try_iter()
                .map(|event| event.event)
                .collect::<Vec<_>>(),
            vec!["metrics.collector.running", "metrics.collector.stopped"]
        );
    }

    #[test]
    fn prometheus_encoder_is_deterministic_escapes_labels_and_encodes_histogram_seconds() {
        let mut registry = MetricRegistry::default();
        registry
            .observe(
                MetricEvent::histogram_observe(
                    edge_ports::MetricDescriptor::RequestDuration,
                    25,
                    vec![("route_id".into(), "route-\"a\\b\n".into())],
                )
                .unwrap(),
            )
            .unwrap();
        let encoded = encode_prometheus(&registry.snapshot()).unwrap();

        assert!(encoded.contains("# TYPE sponzey_edge_request_duration_seconds histogram\n"));
        assert!(encoded.contains("route_id=\"route-\\\"a\\\\b\\n\""));
        assert!(encoded.contains("le=\"0.025\""));
        assert!(encoded.contains("sponzey_edge_request_duration_seconds_sum{route_id="));
        assert!(encoded.contains("} 0.025\n"));
        assert!(encoded.contains("sponzey_edge_metrics_ready 1\n"));
        assert_eq!(encoded, encode_prometheus(&registry.snapshot()).unwrap());
        assert!(encoded.len() <= METRIC_MAX_RESPONSE_BYTES);
    }

    #[test]
    fn loopback_metrics_listener_serves_only_exact_get_and_stops_cleanly() {
        let _guard = metrics_listener_test_guard();
        let (metric_sender, metric_receiver) = std::sync::mpsc::sync_channel(4);
        let publisher = MetricChannelPublisher::new(metric_sender);
        let (reader, collector) = spawn_metric_registry_collector(metric_receiver, None);
        publisher.try_publish(
            MetricEvent::gauge_set(
                edge_ports::MetricDescriptor::ActiveConnections,
                2,
                Vec::new(),
            )
            .unwrap(),
        );
        let listener = spawn_metrics_listener(
            &edge_domain::MetricsConfig {
                enabled: true,
                bind: "127.0.0.1:0".to_string(),
            },
            reader,
            None,
        )
        .unwrap();
        let address = listener.local_addr().unwrap();
        wait_for_metrics_listener(&listener);

        let response = request_metrics_listener_until_status(
            address,
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "HTTP/1.1 200 OK",
            3,
        );
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response:?}");
        assert!(response.contains("sponzey_edge_active_connections 2\n"));
        assert!(
            request_metrics_listener(address, "GET /metrics?x=1 HTTP/1.1\r\n\r\n")
                .starts_with("HTTP/1.1 400")
        );
        assert!(
            request_metrics_listener(address, "POST /metrics HTTP/1.1\r\n\r\n")
                .starts_with("HTTP/1.1 405")
        );
        listener.shutdown();
        collector.shutdown();
    }

    #[test]
    fn metrics_listener_disabled_opens_no_socket_and_public_bind_is_rejected() {
        let _guard = metrics_listener_test_guard();
        let (_sender, receiver) = std::sync::mpsc::sync_channel(1);
        let (reader, collector) = spawn_metric_registry_collector(receiver, None);
        let disabled =
            spawn_metrics_listener(&edge_domain::MetricsConfig::default(), reader.clone(), None)
                .unwrap();
        assert_eq!(disabled.state(), MetricsListenerState::Disabled);
        assert!(disabled.local_addr().is_none());
        assert!(spawn_metrics_listener(
            &edge_domain::MetricsConfig {
                enabled: true,
                bind: "0.0.0.0:9464".into()
            },
            reader,
            None
        )
        .is_err());
        collector.shutdown();
    }

    #[test]
    fn metrics_listener_bounds_oversized_and_concurrent_scrapes() {
        let _guard = metrics_listener_test_guard();
        let (_sender, receiver) = std::sync::mpsc::sync_channel(1);
        let (reader, collector) = spawn_metric_registry_collector(receiver, None);
        let listener = spawn_metrics_listener(
            &edge_domain::MetricsConfig {
                enabled: true,
                bind: "127.0.0.1:0".into(),
            },
            reader,
            None,
        )
        .unwrap();
        let address = listener.local_addr().unwrap();
        wait_for_metrics_listener(&listener);

        let oversized = format!(
            "GET /metrics HTTP/1.1\r\nX-Fill: {}\r\n\r\n",
            "a".repeat(8 * 1024)
        );
        let oversized_response = request_metrics_listener(address, &oversized);
        assert!(
            oversized_response.starts_with("HTTP/1.1 431"),
            "{oversized_response:?}"
        );

        let scrapes = (0..8)
            .map(|_| {
                std::thread::spawn(move || {
                    request_metrics_listener(address, "GET /metrics HTTP/1.1\r\n\r\n")
                })
            })
            .collect::<Vec<_>>();
        for scrape in scrapes {
            assert!(scrape.join().unwrap().starts_with("HTTP/1.1 200 OK"));
        }

        let started = std::time::Instant::now();
        listener.shutdown();
        assert!(started.elapsed() < Duration::from_secs(3));
        collector.shutdown();
    }

    fn request_metrics_listener(address: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(7)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    fn request_metrics_listener_until_status(
        address: SocketAddr,
        request: &str,
        expected_status: &str,
        attempts: usize,
    ) -> String {
        let mut response = String::new();
        for _ in 0..attempts {
            response = request_metrics_listener(address, request);
            if response.starts_with(expected_status) {
                break;
            }
        }
        response
    }

    fn wait_for_metrics_listener(listener: &MetricsListenerHandle) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while listener.state() == MetricsListenerState::Binding {
            assert!(
                std::time::Instant::now() < deadline,
                "metrics listener did not enter serving state"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(listener.state(), MetricsListenerState::Serving);
    }

    fn metrics_listener_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn memory_log_sink_records_structured_events() {
        let mut sink = MemoryLogSink::default();

        sink.record_log(StructuredLogEvent {
            component: "edge-core".to_string(),
            event: "access".to_string(),
            fields: vec![("request_id".to_string(), "req-1".to_string())],
        })
        .unwrap();

        assert_eq!(sink.events().len(), 1);
    }

    #[test]
    fn json_line_log_sink_writes_structured_event_as_single_json_line() {
        let mut sink = JsonLineLogSink::new(Vec::new());

        sink.record_log(StructuredLogEvent {
            component: "edge-core".to_string(),
            event: "access".to_string(),
            fields: vec![
                ("request_id".to_string(), "req-1".to_string()),
                ("message".to_string(), "quoted \"value\"\nnext".to_string()),
            ],
        })
        .unwrap();

        let output = String::from_utf8(sink.into_inner()).unwrap();

        assert_eq!(
            output,
            "{\"component\":\"edge-core\",\"event\":\"access\",\"fields\":{\"request_id\":\"req-1\",\"message\":\"quoted \\\"value\\\"\\nnext\"}}\n"
        );
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sponzey-edge-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
}
