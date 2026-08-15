use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use rustls_pki_types::pem::PemObject;

use crate::tls_connection_holder::{run_tls_holder_with_config, TlsHolderOptions};
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsHolderOptions {
    pub address: SocketAddr,
    pub connections: usize,
    pub server_name: String,
    pub root_pem: PathBuf,
    pub client_chain_pem: PathBuf,
    pub client_key_pem: PathBuf,
    pub timeout_ms: u64,
    pub hold_timeout_ms: u64,
    pub ready_output: PathBuf,
    pub stop_file: PathBuf,
}

pub fn parse_mtls_holder_options(args: &[String]) -> Result<MtlsHolderOptions, HarnessError> {
    const KEYS: [&str; 10] = [
        "--address",
        "--connections",
        "--server-name",
        "--root-pem",
        "--client-chain-pem",
        "--client-key-pem",
        "--timeout-ms",
        "--hold-timeout-ms",
        "--ready-output",
        "--stop-file",
    ];
    if args.len() != KEYS.len() * 2 || !args.len().is_multiple_of(2) {
        return Err(HarnessError::new("mTLS holder arguments are incomplete"));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "mTLS holder argument is unknown or duplicated",
            ));
        }
    }
    Ok(MtlsHolderOptions {
        address: required(&values, "--address")?
            .parse()
            .map_err(|_| HarnessError::new("mTLS holder address is invalid"))?,
        connections: positive(&values, "--connections")?
            .try_into()
            .map_err(|_| HarnessError::new("mTLS holder count exceeds usize"))?,
        server_name: required(&values, "--server-name")?,
        root_pem: PathBuf::from(required(&values, "--root-pem")?),
        client_chain_pem: PathBuf::from(required(&values, "--client-chain-pem")?),
        client_key_pem: PathBuf::from(required(&values, "--client-key-pem")?),
        timeout_ms: positive(&values, "--timeout-ms")?,
        hold_timeout_ms: positive(&values, "--hold-timeout-ms")?,
        ready_output: PathBuf::from(required(&values, "--ready-output")?),
        stop_file: PathBuf::from(required(&values, "--stop-file")?),
    })
}

pub fn build_mtls_client_config(
    root_pem: &[u8],
    client_chain_pem: &[u8],
    client_key_pem: &[u8],
) -> Result<Arc<rustls::ClientConfig>, HarnessError> {
    let root = rustls_pki_types::CertificateDer::from_pem_slice(root_pem)
        .map_err(|_| HarnessError::new("mTLS holder root parse failed"))?;
    let chain = rustls_pki_types::CertificateDer::pem_slice_iter(client_chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| HarnessError::new("mTLS holder client chain parse failed"))?;
    if chain.is_empty() {
        return Err(HarnessError::new("mTLS holder client chain is empty"));
    }
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(client_key_pem)
        .map_err(|_| HarnessError::new("mTLS holder client key parse failed"))?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(root)
        .map_err(|_| HarnessError::new("mTLS holder root is invalid"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| HarnessError::new("mTLS holder protocol config failed"))?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(|_| HarnessError::new("mTLS holder client identity is invalid"))?;
    Ok(Arc::new(config))
}

pub fn run_mtls_holder(options: MtlsHolderOptions) -> Result<String, HarnessError> {
    let root = fs::read(&options.root_pem)
        .map_err(|_| HarnessError::new("mTLS holder root read failed"))?;
    let chain = fs::read(&options.client_chain_pem)
        .map_err(|_| HarnessError::new("mTLS holder client chain read failed"))?;
    let key = fs::read(&options.client_key_pem)
        .map_err(|_| HarnessError::new("mTLS holder client key read failed"))?;
    let config = build_mtls_client_config(&root, &chain, &key)?;
    let holder = TlsHolderOptions {
        address: options.address,
        connections: options.connections,
        server_name: options.server_name,
        root_pem: options.root_pem,
        timeout_ms: options.timeout_ms,
        hold_timeout_ms: options.hold_timeout_ms,
        ready_output: options.ready_output,
        stop_file: options.stop_file,
    };
    run_tls_holder_with_config(holder, config)
}

fn positive(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    let value = required(values, key)?
        .parse::<u64>()
        .map_err(|_| HarnessError::new("mTLS holder numeric argument is invalid"))?;
    if value == 0 {
        return Err(HarnessError::new("mTLS holder value must be positive"));
    }
    Ok(value)
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("mTLS holder argument is missing: {key}")))
}
