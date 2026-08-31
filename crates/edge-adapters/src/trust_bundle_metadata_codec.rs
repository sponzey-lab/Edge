//! Trust-bundle metadata serialization and parsing contract.

use std::io::{self, ErrorKind};

use edge_domain::{AppError, TrustBundleRef};
use edge_ports::TrustBundleMetadata;

use crate::trust_bundle_store_error;

pub(crate) fn parse_trust_metadata(source: &str) -> Result<TrustBundleMetadata, AppError> {
    let mut reference = None;
    let mut count = None;
    let mut imported_at = None;
    let mut content_sha256 = None;
    for line in source.lines() {
        let Some((key, value)) = line.split_once(" = ") else {
            return Err(invalid_metadata());
        };
        match key {
            "trust_bundle_ref" => {
                reference = Some(
                    TrustBundleRef::parse(value.trim_matches('"'))
                        .map_err(|error| AppError::new(error.code, error.message))?,
                )
            }
            "certificate_count" => count = value.parse::<u8>().ok(),
            "imported_at_epoch_seconds" => imported_at = value.parse::<u64>().ok(),
            "content_sha256" => content_sha256 = parse_sha256(value.trim_matches('"')),
            _ => return Err(invalid_metadata()),
        }
    }
    Ok(TrustBundleMetadata {
        trust_bundle_ref: reference.ok_or_else(invalid_metadata)?,
        certificate_count: count
            .filter(|count| (1..=32).contains(count))
            .ok_or_else(invalid_metadata)?,
        imported_at_epoch_seconds: imported_at.ok_or_else(invalid_metadata)?,
        content_sha256: content_sha256.ok_or_else(invalid_metadata)?,
    })
}

pub(crate) fn hex_encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(digest)
}

fn invalid_metadata() -> AppError {
    trust_bundle_store_error(io::Error::new(ErrorKind::InvalidData, "invalid metadata"))
}
