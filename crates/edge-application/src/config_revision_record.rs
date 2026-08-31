//! Immutable config snapshot projection into revision repository records.

use edge_domain::{ConfigRevision, ConfigSnapshot};
use edge_ports::RevisionRecord;

pub(crate) fn revision_record_for_snapshot(
    snapshot: ConfigSnapshot,
    action: &str,
) -> RevisionRecord {
    let revision = ConfigRevision {
        id: snapshot.revision_id.clone(),
        schema_version: snapshot.schema_version,
        summary: format!("{action} {}", snapshot.revision_id),
    };
    RevisionRecord {
        revision,
        checksum: checksum_snapshot(&snapshot),
        snapshot,
    }
}

/// Produces the stable compatibility checksum stored with a revision record.
///
/// The value is derived only from the supplied immutable snapshot and performs
/// no persistence or validation.
pub fn checksum_snapshot(snapshot: &ConfigSnapshot) -> String {
    format!(
        "schema:{};revision:{};listeners:{};routes:{};services:{}",
        snapshot.schema_version,
        snapshot.revision_id,
        snapshot.listeners.len(),
        snapshot.routes.len(),
        snapshot.services.len()
    )
}
