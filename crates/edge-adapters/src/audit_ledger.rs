#[cfg(test)]
mod tests {
    use super::*;
    use edge_application::{
        admin_setup_audit_operation, certificate_audit_operation, config_audit_operation,
        execute_audited_mutation, proxy_host_audit_operation, trust_audit_operation,
        AuditMutationEffect,
    };
    use edge_domain::{
        AuditAction, AuditActorKind, AuditContext, AuditOperationId, AuditQuery, AuditRecord,
        AuditRecordKind, AuditRequestId, AuditTargetId, AuditTargetKind,
    };
    use edge_ports::{
        AuditAdmissionController, AuditLedgerReader, AuditLedgerVerifier, AuditLedgerWriter,
    };
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::path::PathBuf::from("/tmp").join(format!("sponzey-audit-{name}-{nonce}"))
    }

    fn intent() -> AuditRecord {
        AuditRecord {
            record_version: 1,
            record_kind: AuditRecordKind::Intent,
            context: AuditContext {
                operation_id: AuditOperationId::parse("operation-1").unwrap(),
                request_id: AuditRequestId::parse("request-1").unwrap(),
                actor_kind: AuditActorKind::BootstrapAdmin,
                received_at_epoch_seconds: 10,
            },
            action: AuditAction::ConfigApply,
            target_kind: AuditTargetKind::ConfigRevision,
            target_id: AuditTargetId::parse("revision-2").unwrap(),
            before_revision: Some(AuditTargetId::parse("revision-1").unwrap()),
            after_revision: None,
            outcome: None,
            error_code: None,
        }
    }

    fn small_retention_options() -> AuditLedgerOptions {
        let frame_bytes = encode_frame(1, [0; 32], &encode_record(&intent()).unwrap()).len();
        let checkpoint = retention_record(10, 3).unwrap();
        let checkpoint_bytes = encode_frame(
            1,
            [0; 32],
            &encode_record_with_retention(
                &checkpoint,
                Some(&RetentionMetadata {
                    first_sequence: 1,
                    last_sequence: 2,
                    terminal_hash: [0; 32],
                }),
            )
            .unwrap(),
        )
        .len();
        let segment_bytes = checkpoint_bytes + frame_bytes + 8;
        AuditLedgerOptions::default().with_storage_bounds(segment_bytes, 2, segment_bytes * 2)
    }

    #[test]
    fn acknowledged_intent_survives_reopen_and_verification() {
        let root = root("reopen");
        let mut ledger = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap();
        let acknowledged = ledger.append_intent(intent()).unwrap();
        drop(ledger);

        let mut reopened = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap();
        let report = reopened.verify().unwrap();
        let page = reopened.query(&AuditQuery::default()).unwrap();

        assert_eq!(acknowledged.sequence, 1);
        assert_eq!(report.head, acknowledged);
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].record, intent());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reopen_recovers_only_an_incomplete_trailing_frame() {
        let root = root("trailing");
        let mut ledger = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap();
        let acknowledged = ledger.append_intent(intent()).unwrap();
        drop(ledger);
        let segment = root.join("logs/audit/segment-0000000000000001.audit");
        OpenOptions::new()
            .append(true)
            .open(&segment)
            .unwrap()
            .write_all(b"SPAU")
            .unwrap();

        let recovery_context = AuditContext {
            operation_id: AuditOperationId::parse("recovery-1").unwrap(),
            request_id: AuditRequestId::parse("startup-1").unwrap(),
            actor_kind: AuditActorKind::SystemRecovery,
            received_at_epoch_seconds: 20,
        };
        let mut reopened = FileAuditLedger::open(
            &root,
            AuditLedgerOptions::default().with_recovery_context(recovery_context),
        )
        .unwrap();

        assert_eq!(
            reopened.verify().unwrap().head.sequence,
            acknowledged.sequence + 1
        );
        let records = reopened.query(&AuditQuery::default()).unwrap().records;
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].record.record_kind,
            AuditRecordKind::SystemRecovery
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reopen_rejects_interior_frame_corruption() {
        let root = root("interior");
        let mut ledger = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap();
        ledger.append_intent(intent()).unwrap();
        drop(ledger);
        let segment = root.join("logs/audit/segment-0000000000000001.audit");
        let mut bytes = fs::read(&segment).unwrap();
        bytes[HEADER_LEN] ^= 0x01;
        fs::write(&segment, bytes).unwrap();

        let error = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap_err();

        assert_eq!(error.code, ErrorCode::AuditChainMismatch);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn canonical_payload_is_deterministic_and_payload_bound_is_exact() {
        let payload = encode_record(&intent()).unwrap();
        assert_eq!(payload, encode_record(&intent()).unwrap());
        assert_eq!(
            payload,
            br#"{"record_version":1,"record_kind":"intent","operation_id":"operation-1","request_id":"request-1","actor_kind":"bootstrap_admin","action":"config.apply","target_kind":"config_revision","target_id":"revision-2","before_revision":"revision-1","after_revision":null,"outcome":null,"error_code":null,"timestamp_epoch_seconds":10,"pruned_first_sequence":null,"pruned_last_sequence":null,"pruned_terminal_hash":null}"#
        );

        let exact_root = root("payload-exact");
        let mut exact = FileAuditLedger::open(
            &exact_root,
            AuditLedgerOptions {
                max_payload_bytes: payload.len(),
                ..AuditLedgerOptions::default()
            },
        )
        .unwrap();
        assert!(exact.append_intent(intent()).is_ok());

        let over_root = root("payload-over");
        let mut over = FileAuditLedger::open(
            &over_root,
            AuditLedgerOptions {
                max_payload_bytes: payload.len() - 1,
                ..AuditLedgerOptions::default()
            },
        )
        .unwrap();
        assert_eq!(
            over.append_intent(intent()).unwrap_err().code,
            ErrorCode::AuditRecordTooLarge
        );
        fs::remove_dir_all(exact_root).unwrap();
        fs::remove_dir_all(over_root).unwrap();
    }

    #[test]
    fn append_rejects_record_kind_field_invariant_violation() {
        let root = root("record-invariant");
        let mut ledger = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap();
        let mut invalid = intent();
        invalid.outcome = Some(AuditOutcome::Succeeded);

        assert_eq!(
            ledger.append_intent(invalid).unwrap_err().code,
            ErrorCode::AuditRecordInvalid
        );
        assert_eq!(ledger.head().unwrap().sequence, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_scan_rejects_record_limit_plus_one() {
        let root = root("scan-limit");
        let mut ledger = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap();
        ledger.append_intent(intent()).unwrap();
        let mut second = intent();
        second.context.operation_id = AuditOperationId::parse("operation-2").unwrap();
        ledger.append_intent(second).unwrap();
        drop(ledger);

        let error = FileAuditLedger::open(
            &root,
            AuditLedgerOptions {
                max_scan_records: 1,
                ..AuditLedgerOptions::default()
            },
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::AuditCapacityReached);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codec_and_scanner_reject_unknown_fields_version_and_sequence() {
        let mut payload = encode_record(&intent()).unwrap();
        payload.pop();
        payload.extend_from_slice(b",\"unknown\":true}");
        assert_eq!(
            decode_record(&payload).unwrap_err().code,
            ErrorCode::AuditRecordInvalid
        );

        for (name, offset, bytes, expected) in [
            (
                "version",
                8,
                2_u16.to_be_bytes().to_vec(),
                ErrorCode::AuditUnsupportedVersion,
            ),
            (
                "sequence",
                16,
                2_u64.to_be_bytes().to_vec(),
                ErrorCode::AuditSequenceInvalid,
            ),
        ] {
            let root = root(name);
            let mut ledger = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap();
            ledger.append_intent(intent()).unwrap();
            drop(ledger);
            let segment = root.join("logs/audit/segment-0000000000000001.audit");
            let mut frame = fs::read(&segment).unwrap();
            frame[offset..offset + bytes.len()].copy_from_slice(&bytes);
            fs::write(&segment, frame).unwrap();
            assert_eq!(
                FileAuditLedger::open(&root, AuditLedgerOptions::default())
                    .unwrap_err()
                    .code,
                expected
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn append_and_sync_failures_leave_head_unpublished_and_state_degraded() {
        for failure in [AuditFailurePoint::Append, AuditFailurePoint::Sync] {
            let root = root("failure");
            let mut ledger =
                FileAuditLedger::open(&root, AuditLedgerOptions::default().with_failure(failure))
                    .unwrap();
            let error = ledger.append_intent(intent()).unwrap_err();

            assert!(matches!(
                error.code,
                ErrorCode::AuditAppendFailed | ErrorCode::AuditSyncFailed
            ));
            assert_eq!(ledger.head().unwrap().sequence, 0);
            assert_eq!(ledger.io_state(), AuditLedgerIoState::Degraded);
            assert_eq!(
                ledger.append_intent(intent()).unwrap_err().code,
                ErrorCode::AuditUnavailable
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn ledger_io_state_reducer_enforces_append_order() {
        let state = AuditLedgerIoState::Ready
            .transition(AuditLedgerIoEvent::BeginEncoding)
            .unwrap()
            .transition(AuditLedgerIoEvent::Encoded)
            .unwrap()
            .transition(AuditLedgerIoEvent::Appended)
            .unwrap()
            .transition(AuditLedgerIoEvent::Synced)
            .unwrap();

        assert_eq!(state, AuditLedgerIoState::PublishedHead);
        assert!(AuditLedgerIoState::Ready
            .transition(AuditLedgerIoEvent::Synced)
            .is_err());
        assert!(AuditLedgerIoState::Degraded
            .transition(AuditLedgerIoEvent::BeginEncoding)
            .is_err());
    }

    #[test]
    fn options_cannot_raise_fixed_mvp_bounds_or_spoof_recovery_actor() {
        let oversized = AuditLedgerOptions {
            max_payload_bytes: MAX_PAYLOAD_BYTES + 1,
            ..AuditLedgerOptions::default()
        };
        assert_eq!(
            FileAuditLedger::open(root("oversized-options"), oversized)
                .unwrap_err()
                .code,
            ErrorCode::AuditRecordInvalid
        );

        let spoofed = AuditLedgerOptions::default().with_recovery_context(AuditContext {
            operation_id: AuditOperationId::parse("recovery-1").unwrap(),
            request_id: AuditRequestId::parse("startup-1").unwrap(),
            actor_kind: AuditActorKind::BootstrapAdmin,
            received_at_epoch_seconds: 20,
        });
        assert_eq!(
            FileAuditLedger::open(root("spoofed-recovery"), spoofed)
                .unwrap_err()
                .code,
            ErrorCode::AuditRecordInvalid
        );
    }

    #[test]
    fn rotation_retention_checkpoints_before_whole_segment_deletion() {
        let root = root("retention");
        let options = small_retention_options();
        let mut ledger = FileAuditLedger::open(&root, options.clone()).unwrap();
        for number in 1..=4 {
            let mut record = intent();
            record.context.operation_id =
                AuditOperationId::parse(format!("operation-{number}")).unwrap();
            ledger.append_intent(record).unwrap();
        }
        let stale_cursor = edge_domain::AuditCursor {
            ledger_generation: 0,
            before_sequence: 5,
        };
        let mut fifth = intent();
        fifth.context.operation_id = AuditOperationId::parse("operation-5").unwrap();
        let head = ledger.append_intent(fifth).unwrap();

        let segment_count = fs::read_dir(root.join("logs/audit"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|value| value == "audit")
            })
            .count();
        assert_eq!(segment_count, 2);
        assert_eq!(head.generation, 1);
        let records = ledger.query(&AuditQuery::default()).unwrap().records;
        assert_eq!(
            records[0].record.context.operation_id.as_str(),
            "operation-5"
        );
        assert!(records
            .iter()
            .any(|record| record.record.record_kind == AuditRecordKind::RetentionCheckpoint));
        assert_eq!(
            ledger
                .query(&AuditQuery::default().with_cursor(stale_cursor))
                .unwrap_err()
                .code,
            ErrorCode::AuditCursorInvalid
        );
        drop(ledger);

        let reopened = FileAuditLedger::open(&root, options).unwrap();
        assert_eq!(reopened.head().unwrap(), head);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rotation_obeys_exact_fit_and_fit_plus_one_without_changing_generation() {
        let frame_bytes = encode_frame(1, [0; 32], &encode_record(&intent()).unwrap()).len();
        for (name, segment_bytes, expected_segments) in [
            ("rotation-exact", frame_bytes * 2, 1),
            ("rotation-plus-one", frame_bytes * 2 - 1, 2),
        ] {
            let root = root(name);
            let options = AuditLedgerOptions::default().with_storage_bounds(
                segment_bytes,
                MAX_SEGMENTS,
                segment_bytes * MAX_SEGMENTS,
            );
            let mut ledger = FileAuditLedger::open(&root, options.clone()).unwrap();
            ledger.append_intent(intent()).unwrap();
            let mut second = intent();
            second.context.operation_id = AuditOperationId::parse("operation-2").unwrap();
            let head = ledger.append_intent(second).unwrap();

            assert_eq!(ledger.segments.len(), expected_segments);
            assert_eq!(
                head,
                AuditLedgerHead {
                    generation: 0,
                    sequence: 2
                }
            );
            drop(ledger);
            assert_eq!(
                FileAuditLedger::open(&root, options)
                    .unwrap()
                    .head()
                    .unwrap(),
                head
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn retention_delete_failure_preserves_old_segments_and_degrades_writer() {
        let root = root("retention-delete-failure");
        let options = small_retention_options().with_failure(AuditFailurePoint::RetentionDelete);
        let mut ledger = FileAuditLedger::open(&root, options).unwrap();
        for number in 1..=4 {
            let mut record = intent();
            record.context.operation_id =
                AuditOperationId::parse(format!("operation-{number}")).unwrap();
            ledger.append_intent(record).unwrap();
        }
        let mut fifth = intent();
        fifth.context.operation_id = AuditOperationId::parse("operation-5").unwrap();

        assert_eq!(
            ledger.append_intent(fifth.clone()).unwrap_err().code,
            ErrorCode::AuditUnavailable
        );
        assert_eq!(ledger.io_state(), AuditLedgerIoState::Degraded);
        assert_eq!(ledger.segments.len(), 3);
        assert!(ledger.segments.iter().all(|segment| segment.path.exists()));
        assert!(ledger
            .records
            .iter()
            .any(|record| record.record.record_kind == AuditRecordKind::RetentionCheckpoint));
        assert_eq!(
            ledger.append_intent(fifth).unwrap_err().code,
            ErrorCode::AuditUnavailable
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rotation_publication_failure_preserves_previous_head_and_segment() {
        let root = root("rotation-publication-failure");
        let frame_bytes = encode_frame(1, [0; 32], &encode_record(&intent()).unwrap()).len();
        let options = AuditLedgerOptions::default()
            .with_storage_bounds(frame_bytes, MAX_SEGMENTS, frame_bytes * MAX_SEGMENTS)
            .with_failure(AuditFailurePoint::RotationPublish);
        let mut ledger = FileAuditLedger::open(&root, options).unwrap();
        let head = ledger.append_intent(intent()).unwrap();
        let mut second = intent();
        second.context.operation_id = AuditOperationId::parse("operation-2").unwrap();

        assert_eq!(
            ledger.append_intent(second).unwrap_err().code,
            ErrorCode::AuditUnavailable
        );
        assert_eq!(ledger.head().unwrap(), head);
        assert_eq!(ledger.segments.len(), 1);
        assert!(ledger.segments[0].path.exists());
        assert_eq!(ledger.io_state(), AuditLedgerIoState::Degraded);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reader_accepts_only_current_generation_and_bounded_sequence_range() {
        let root = root("reader-generation");
        let options = small_retention_options();
        let mut ledger = FileAuditLedger::open(&root, options).unwrap();
        for number in 1..=5 {
            let mut record = intent();
            record.context.operation_id =
                AuditOperationId::parse(format!("operation-{number}")).unwrap();
            ledger.append_intent(record).unwrap();
        }
        let head = ledger.head().unwrap();
        let current = edge_domain::AuditCursor {
            ledger_generation: head.generation,
            before_sequence: head.sequence + 1,
        };
        let first = ledger
            .query(&AuditQuery::default().with_cursor(current))
            .unwrap();
        let second = ledger
            .query(&AuditQuery::default().with_cursor(current))
            .unwrap();
        assert_eq!(first, second);

        for before_sequence in [0, head.sequence + 2] {
            let cursor = edge_domain::AuditCursor {
                ledger_generation: head.generation,
                before_sequence,
            };
            assert_eq!(
                ledger
                    .query(&AuditQuery::default().with_cursor(cursor))
                    .unwrap_err()
                    .code,
                ErrorCode::AuditCursorInvalid
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn storage_maintenance_state_rejects_delete_before_checkpoint() {
        use StorageMaintenanceEvent as Event;
        use StorageMaintenanceState as State;
        let state = State::Ready.transition(Event::RequireRotation).unwrap();
        let state = state.transition(Event::PublishSegment).unwrap();
        let state = state.transition(Event::RequireRetention).unwrap();
        assert_eq!(
            state.transition(Event::RemoveSegments).unwrap_err().code,
            ErrorCode::AuditRecordInvalid
        );
        let state = state.transition(Event::SyncCheckpoint).unwrap();
        let state = state.transition(Event::RemoveSegments).unwrap();
        assert_eq!(state.transition(Event::Finish).unwrap(), State::Ready);
    }

    #[test]
    fn config_and_proxy_candidate_recovers_exact_operation_pairs_after_restart() {
        #[derive(Default)]
        struct Admission(AuditAdmissionState);
        impl AuditAdmissionController for Admission {
            fn state(&self) -> AuditAdmissionState {
                self.0
            }
            fn replace_state(&mut self, state: AuditAdmissionState) {
                self.0 = state;
            }
        }

        let root = root("mutation-candidate-restart");
        let options = AuditLedgerOptions::default();
        let mut ledger = FileAuditLedger::open(&root, options.clone()).unwrap();
        let mut admission = Admission(AuditAdmissionState::Healthy);
        let actions = [
            AuditAction::ConfigApply,
            AuditAction::ConfigRollback,
            AuditAction::ProxyHostCreate,
            AuditAction::ProxyHostUpdate,
            AuditAction::ProxyHostDelete,
            AuditAction::CertificateIssue,
            AuditAction::CertificateRenew,
            AuditAction::CertificateImport,
            AuditAction::CertificateInstall,
            AuditAction::TrustBundleImport,
            AuditAction::TrustBundleDelete,
            AuditAction::AdminSetup,
        ];
        for (index, action) in actions.into_iter().enumerate() {
            let number = index + 1;
            let context = AuditContext {
                operation_id: AuditOperationId::parse(format!("candidate-{number}")).unwrap(),
                request_id: AuditRequestId::parse(format!("request-{number}")).unwrap(),
                actor_kind: AuditActorKind::BootstrapAdmin,
                received_at_epoch_seconds: number as u64,
            };
            let operation = match action {
                AuditAction::ConfigApply | AuditAction::ConfigRollback => config_audit_operation(
                    context,
                    action,
                    AuditTargetId::parse(format!("revision-{number}")).unwrap(),
                    None,
                )
                .unwrap(),
                AuditAction::ProxyHostCreate
                | AuditAction::ProxyHostUpdate
                | AuditAction::ProxyHostDelete => proxy_host_audit_operation(
                    context,
                    action,
                    AuditTargetId::parse("proxy-host-1").unwrap(),
                    None,
                )
                .unwrap(),
                AuditAction::CertificateIssue
                | AuditAction::CertificateRenew
                | AuditAction::CertificateImport
                | AuditAction::CertificateInstall => certificate_audit_operation(
                    context,
                    action,
                    AuditTargetId::parse("certificate-1").unwrap(),
                )
                .unwrap(),
                AuditAction::TrustBundleImport | AuditAction::TrustBundleDelete => {
                    trust_audit_operation(
                        context,
                        action,
                        AuditTargetId::parse("private-root-1").unwrap(),
                    )
                    .unwrap()
                }
                AuditAction::AdminSetup => admin_setup_audit_operation(
                    context,
                    AuditTargetId::parse("bootstrap-admin").unwrap(),
                ),
                _ => unreachable!("candidate action list is closed"),
            };
            execute_audited_mutation(&mut ledger, &mut admission, operation, || {
                Ok(AuditMutationEffect {
                    value: number,
                    after_revision: Some(
                        AuditTargetId::parse(format!("revision-{number}")).unwrap(),
                    ),
                })
            })
            .unwrap();
        }
        let head = ledger.head().unwrap();
        assert_eq!(head.sequence, 24);
        drop(ledger);

        let reopened = FileAuditLedger::open(&root, options).unwrap();
        assert_eq!(reopened.head().unwrap(), head);
        let records = reopened.query(&AuditQuery::default()).unwrap().records;
        assert_eq!(records.len(), 24);
        let chronological: Vec<_> = records.into_iter().rev().collect();
        for pair in chronological.chunks_exact(2) {
            assert_eq!(pair[0].record.record_kind, AuditRecordKind::Intent);
            assert_eq!(pair[1].record.record_kind, AuditRecordKind::Terminal);
            assert_eq!(
                pair[0].record.context.operation_id,
                pair[1].record.context.operation_id
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shared_ledger_serializes_writer_clones_and_shares_admission_state() {
        let root = root("shared-ledger");
        let ledger = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap();
        let mut first = SharedFileAuditLedger::new(ledger, AuditAdmissionState::Healthy);
        let mut second = first.clone();
        let mut admission = first.admission();
        first.append_intent(intent()).unwrap();
        let mut other = intent();
        other.context.operation_id = AuditOperationId::parse("operation-2").unwrap();
        second.append_intent(other).unwrap();

        assert_eq!(first.head().unwrap().sequence, 2);
        admission.replace_state(AuditAdmissionState::Degraded);
        assert_eq!(second.admission().state(), AuditAdmissionState::Degraded);
        drop(first);
        drop(second);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unresolved_reconciliation_survives_file_reopen() {
        let root = root("unresolved-reconciliation");
        let options = AuditLedgerOptions::default();
        let mut ledger = FileAuditLedger::open(&root, options.clone()).unwrap();
        let head = ledger.append_intent(intent()).unwrap();
        let mut unresolved = intent();
        unresolved.record_kind = AuditRecordKind::Reconciliation;
        unresolved.outcome = Some(AuditOutcome::ReconciliationUnknown);
        ledger.append_reconciliation(unresolved, head).unwrap();
        assert_eq!(ledger.unresolved_reconciliations().unwrap().len(), 1);
        drop(ledger);

        let reopened = FileAuditLedger::open(&root, options).unwrap();
        assert_eq!(reopened.unresolved_reconciliations().unwrap().len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn reopen_rejects_unsafe_segment_permissions_and_hard_links() {
        use std::os::unix::fs::PermissionsExt;
        let mode_root = root("unsafe-mode");
        drop(FileAuditLedger::open(&mode_root, AuditLedgerOptions::default()).unwrap());
        let segment = mode_root.join("logs/audit/segment-0000000000000001.audit");
        fs::set_permissions(&segment, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            FileAuditLedger::open(&mode_root, AuditLedgerOptions::default())
                .unwrap_err()
                .code,
            ErrorCode::AuditUnavailable
        );

        let link_root = root("hard-link");
        drop(FileAuditLedger::open(&link_root, AuditLedgerOptions::default()).unwrap());
        let segment = link_root.join("logs/audit/segment-0000000000000001.audit");
        fs::hard_link(&segment, link_root.join("linked.audit")).unwrap();
        assert_eq!(
            FileAuditLedger::open(&link_root, AuditLedgerOptions::default())
                .unwrap_err()
                .code,
            ErrorCode::AuditUnavailable
        );
        fs::remove_dir_all(mode_root).unwrap();
        fs::remove_dir_all(link_root).unwrap();

        let directory_root = root("unsafe-directory-mode");
        drop(FileAuditLedger::open(&directory_root, AuditLedgerOptions::default()).unwrap());
        fs::set_permissions(
            directory_root.join("logs/audit"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert_eq!(
            FileAuditLedger::open(&directory_root, AuditLedgerOptions::default())
                .unwrap_err()
                .code,
            ErrorCode::AuditUnavailable
        );
        fs::remove_dir_all(directory_root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn open_rejects_symlink_audit_directory() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let ledger_root = root("symlink");
        let target = root("symlink-target");
        fs::create_dir_all(ledger_root.join("logs")).unwrap();
        fs::create_dir_all(&target).unwrap();
        symlink(&target, ledger_root.join("logs/audit")).unwrap();

        assert_eq!(
            FileAuditLedger::open(&ledger_root, AuditLedgerOptions::default())
                .unwrap_err()
                .code,
            ErrorCode::AuditUnavailable
        );
        fs::remove_dir_all(ledger_root).unwrap();
        fs::remove_dir_all(target).unwrap();

        let segment_root = root("segment-symlink");
        let external = root("segment-target");
        fs::create_dir_all(segment_root.join("logs/audit")).unwrap();
        fs::set_permissions(
            segment_root.join("logs/audit"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(&external, b"").unwrap();
        symlink(
            &external,
            segment_root.join("logs/audit/segment-0000000000000001.audit"),
        )
        .unwrap();
        assert_eq!(
            FileAuditLedger::open(&segment_root, AuditLedgerOptions::default())
                .unwrap_err()
                .code,
            ErrorCode::AuditUnavailable
        );
        fs::remove_dir_all(segment_root).unwrap();
        fs::remove_file(external).unwrap();
    }
}
use edge_domain::{
    AppError, AuditAction, AuditActorKind, AuditAdmissionState, AuditContext, AuditLedgerHead,
    AuditOutcome, AuditPage, AuditQuery, AuditRecord, AuditRecordKind, AuditRecordView,
    AuditRequestId, AuditStableErrorCode, AuditTargetId, AuditTargetKind, ErrorCode,
};
use edge_ports::{
    AuditAdmissionController, AuditLedgerReader, AuditLedgerVerifier, AuditLedgerWriter,
    RestoreProvenanceWriter,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAGIC: &[u8; 8] = b"SPAUDIT\0";
const FRAME_VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 2 + 4 + 8 + 32;
const HASH_LEN: usize = 32;
const MAX_PAYLOAD_BYTES: usize = 8 * 1024;
const MAX_SCAN_RECORDS: usize = 100_000;
const MAX_SEGMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_SEGMENTS: usize = 32;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLedgerOptions {
    pub max_payload_bytes: usize,
    pub max_scan_records: usize,
    pub recovery_context: Option<AuditContext>,
    failure_injection: Option<AuditFailurePoint>,
    max_segment_bytes: usize,
    max_segments: usize,
    max_total_bytes: usize,
}

impl Default for AuditLedgerOptions {
    fn default() -> Self {
        Self {
            max_payload_bytes: MAX_PAYLOAD_BYTES,
            max_scan_records: MAX_SCAN_RECORDS,
            recovery_context: None,
            failure_injection: None,
            max_segment_bytes: MAX_SEGMENT_BYTES,
            max_segments: MAX_SEGMENTS,
            max_total_bytes: MAX_TOTAL_BYTES,
        }
    }
}

impl AuditLedgerOptions {
    pub fn with_recovery_context(mut self, context: AuditContext) -> Self {
        self.recovery_context = Some(context);
        self
    }

    #[cfg(test)]
    fn with_failure(mut self, failure: AuditFailurePoint) -> Self {
        self.failure_injection = Some(failure);
        self
    }

    #[cfg(test)]
    fn with_storage_bounds(
        mut self,
        max_segment_bytes: usize,
        max_segments: usize,
        max_total_bytes: usize,
    ) -> Self {
        self.max_segment_bytes = max_segment_bytes;
        self.max_segments = max_segments;
        self.max_total_bytes = max_total_bytes;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditFailurePoint {
    Append,
    Sync,
    RotationPublish,
    RetentionDelete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLedgerIoState {
    Ready,
    Encoding,
    Appending,
    Syncing,
    PublishedHead,
    Recovering,
    Degraded,
    FailedClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLedgerIoEvent {
    BeginEncoding,
    Encoded,
    Appended,
    Synced,
    Failed,
}

impl AuditLedgerIoState {
    pub fn transition(self, event: AuditLedgerIoEvent) -> Result<Self, AppError> {
        use AuditLedgerIoEvent as Event;
        use AuditLedgerIoState as State;
        match (self, event) {
            (State::Ready | State::PublishedHead | State::Recovering, Event::BeginEncoding) => {
                Ok(State::Encoding)
            }
            (State::Encoding, Event::Encoded) => Ok(State::Appending),
            (State::Appending, Event::Appended) => Ok(State::Syncing),
            (State::Syncing, Event::Synced) => Ok(State::PublishedHead),
            (
                State::Encoding | State::Appending | State::Syncing | State::Recovering,
                Event::Failed,
            ) => Ok(State::Degraded),
            _ => Err(AppError::new(
                ErrorCode::AuditRecordInvalid,
                "audit ledger I/O state transition is invalid",
            )),
        }
    }
}

#[derive(Debug)]
pub struct FileAuditLedger {
    directory_path: PathBuf,
    _directory: File,
    file: File,
    records: Vec<AuditRecordView>,
    record_segments: Vec<u64>,
    segments: Vec<AuditSegment>,
    current_segment: u64,
    current_segment_bytes: usize,
    head: AuditLedgerHead,
    last_hash: [u8; 32],
    options: AuditLedgerOptions,
    state: AuditLedgerIoState,
}

pub struct FileRestoreProvenanceWriter {
    target_root: PathBuf,
}

impl FileRestoreProvenanceWriter {
    pub fn new(target_root: impl AsRef<Path>) -> Self {
        Self {
            target_root: target_root.as_ref().to_path_buf(),
        }
    }
}

impl RestoreProvenanceWriter for FileRestoreProvenanceWriter {
    fn append_restore_provenance(
        &mut self,
        record: AuditRecord,
    ) -> Result<AuditLedgerHead, AppError> {
        let mut ledger = FileAuditLedger::open(&self.target_root, AuditLedgerOptions::default())?;
        let head = ledger.head()?;
        ledger.append_reconciliation(record, head)
    }
}

#[derive(Clone)]
pub struct SharedFileAuditLedger {
    ledger: Arc<Mutex<FileAuditLedger>>,
    admission: SharedAuditAdmission,
}

#[derive(Clone)]
pub struct SharedAuditAdmission {
    state: Arc<Mutex<AuditAdmissionState>>,
}

impl SharedFileAuditLedger {
    pub fn new(ledger: FileAuditLedger, admission_state: AuditAdmissionState) -> Self {
        Self {
            ledger: Arc::new(Mutex::new(ledger)),
            admission: SharedAuditAdmission {
                state: Arc::new(Mutex::new(admission_state)),
            },
        }
    }

    pub fn admission(&self) -> SharedAuditAdmission {
        self.admission.clone()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, FileAuditLedger>, AppError> {
        self.ledger.lock().map_err(|_| {
            AppError::new(
                ErrorCode::AuditUnavailable,
                "shared audit ledger lock is unavailable",
            )
        })
    }
}

impl AuditAdmissionController for SharedAuditAdmission {
    fn state(&self) -> AuditAdmissionState {
        self.state
            .lock()
            .map_or(AuditAdmissionState::FailedClosed, |state| *state)
    }

    fn replace_state(&mut self, state: AuditAdmissionState) {
        if let Ok(mut current) = self.state.lock() {
            *current = state;
        }
    }
}

impl AuditLedgerWriter for SharedFileAuditLedger {
    fn append_intent(&mut self, record: AuditRecord) -> Result<AuditLedgerHead, AppError> {
        self.lock()?.append_intent(record)
    }

    fn append_terminal(
        &mut self,
        record: AuditRecord,
        expected: AuditLedgerHead,
    ) -> Result<AuditLedgerHead, AppError> {
        self.lock()?.append_terminal(record, expected)
    }

    fn append_reconciliation(
        &mut self,
        record: AuditRecord,
        expected: AuditLedgerHead,
    ) -> Result<AuditLedgerHead, AppError> {
        self.lock()?.append_reconciliation(record, expected)
    }

    fn append_security_observation(
        &mut self,
        record: AuditRecord,
    ) -> Result<AuditLedgerHead, AppError> {
        self.lock()?.append_security_observation(record)
    }
}

impl AuditLedgerReader for SharedFileAuditLedger {
    fn query(&self, query: &AuditQuery) -> Result<AuditPage, AppError> {
        let mut page = self.lock()?.query(query)?;
        page.admission_state = self.admission.state();
        Ok(page)
    }

    fn incomplete_operations(&self) -> Result<Vec<AuditRecord>, AppError> {
        self.lock()?.incomplete_operations()
    }

    fn unresolved_reconciliations(&self) -> Result<Vec<AuditRecord>, AppError> {
        self.lock()?.unresolved_reconciliations()
    }

    fn head(&self) -> Result<AuditLedgerHead, AppError> {
        self.lock()?.head()
    }
}

impl AuditLedgerVerifier for SharedFileAuditLedger {
    fn verify(&mut self) -> Result<edge_domain::AuditVerificationReport, AppError> {
        self.lock()?.verify()
    }
}

#[derive(Debug, Clone)]
struct AuditSegment {
    number: u64,
    path: PathBuf,
    first_sequence: u64,
    last_sequence: u64,
    terminal_hash: [u8; 32],
    bytes: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordDto {
    record_version: u16,
    record_kind: String,
    operation_id: String,
    request_id: String,
    actor_kind: String,
    action: String,
    target_kind: String,
    target_id: String,
    before_revision: Option<String>,
    after_revision: Option<String>,
    outcome: Option<String>,
    error_code: Option<String>,
    timestamp_epoch_seconds: u64,
    pruned_first_sequence: Option<u64>,
    pruned_last_sequence: Option<u64>,
    pruned_terminal_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RetentionMetadata {
    first_sequence: u64,
    last_sequence: u64,
    terminal_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageMaintenanceState {
    Ready,
    RotationRequired,
    SegmentPublished,
    RetentionRequired,
    Checkpointed,
    Removed,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageMaintenanceEvent {
    RequireRotation,
    PublishSegment,
    RequireRetention,
    SyncCheckpoint,
    RemoveSegments,
    Finish,
    Fail,
}

impl StorageMaintenanceState {
    fn transition(self, event: StorageMaintenanceEvent) -> Result<Self, AppError> {
        use StorageMaintenanceEvent as Event;
        use StorageMaintenanceState as State;
        match (self, event) {
            (State::Ready, Event::RequireRotation) => Ok(State::RotationRequired),
            (State::RotationRequired, Event::PublishSegment) => Ok(State::SegmentPublished),
            (State::SegmentPublished, Event::RequireRetention) => Ok(State::RetentionRequired),
            (State::RetentionRequired, Event::SyncCheckpoint) => Ok(State::Checkpointed),
            (State::Checkpointed, Event::RemoveSegments) => Ok(State::Removed),
            (State::SegmentPublished | State::Removed, Event::Finish) => Ok(State::Ready),
            (
                State::RotationRequired
                | State::SegmentPublished
                | State::RetentionRequired
                | State::Checkpointed,
                Event::Fail,
            ) => Ok(State::Degraded),
            _ => Err(AppError::new(
                ErrorCode::AuditRecordInvalid,
                "audit storage maintenance transition is invalid",
            )),
        }
    }
}

impl FileAuditLedger {
    pub fn open(root: impl AsRef<Path>, options: AuditLedgerOptions) -> Result<Self, AppError> {
        if options.max_payload_bytes == 0
            || options.max_payload_bytes > MAX_PAYLOAD_BYTES
            || options.max_scan_records == 0
            || options.max_scan_records > MAX_SCAN_RECORDS
            || options.max_segment_bytes < HEADER_LEN + HASH_LEN + 1
            || options.max_segment_bytes > MAX_SEGMENT_BYTES
            || options.max_segments == 0
            || options.max_segments > MAX_SEGMENTS
            || options.max_total_bytes < options.max_segment_bytes
            || options.max_total_bytes > MAX_TOTAL_BYTES
            || options
                .recovery_context
                .as_ref()
                .is_some_and(|context| context.actor_kind != AuditActorKind::SystemRecovery)
        {
            return Err(AppError::new(
                ErrorCode::AuditRecordInvalid,
                "audit ledger bounds must be positive",
            ));
        }
        let directory = root.as_ref().join("logs/audit");
        prepare_private_directory(&directory)?;
        let directory_file = File::open(&directory).map_err(io_error)?;
        let paths = discover_segments(&directory)?;
        let paths = if paths.is_empty() {
            vec![(1, segment_path(&directory, 1))]
        } else {
            paths
        };
        let scan_result = scan_segments(
            &paths,
            &directory_file,
            &options,
            options.recovery_context.is_some(),
        )?;
        let (current_segment, path) = paths.last().cloned().expect("segment list is non-empty");
        let file = open_private_segment(&path)?;
        directory_file.sync_all().map_err(sync_error)?;
        let recovery_context = options.recovery_context.clone();
        let mut ledger = Self {
            directory_path: directory,
            _directory: directory_file,
            file,
            records: scan_result.records,
            record_segments: scan_result.record_segments,
            segments: scan_result.segments,
            current_segment,
            current_segment_bytes: scan_result.current_segment_bytes,
            head: scan_result.head,
            last_hash: scan_result.last_hash,
            options,
            state: if scan_result.recovered {
                AuditLedgerIoState::Recovering
            } else {
                AuditLedgerIoState::Ready
            },
        };
        if scan_result.recovered {
            ledger.append(recovery_record(
                recovery_context.expect("recovery context checked"),
            )?)?;
        }
        Ok(ledger)
    }

    fn append(&mut self, record: AuditRecord) -> Result<AuditLedgerHead, AppError> {
        if self.state == AuditLedgerIoState::Degraded
            || self.state == AuditLedgerIoState::FailedClosed
        {
            return Err(AppError::new(
                ErrorCode::AuditUnavailable,
                "audit ledger is not writable",
            ));
        }
        record.validate().map_err(|_| {
            AppError::new(
                ErrorCode::AuditRecordInvalid,
                "audit record invariant is invalid",
            )
        })?;
        let payload = encode_record(&record)?;
        if payload.len() > self.options.max_payload_bytes {
            return Err(AppError::new(
                ErrorCode::AuditRecordTooLarge,
                "audit payload exceeds limit",
            ));
        }
        let frame_bytes = HEADER_LEN + payload.len() + HASH_LEN;
        if frame_bytes > self.options.max_segment_bytes {
            return Err(AppError::new(
                ErrorCode::AuditRecordTooLarge,
                "audit frame exceeds segment limit",
            ));
        }
        self.prepare_storage(frame_bytes, record.context.received_at_epoch_seconds)?;
        self.append_encoded(record, payload)
    }

    fn append_encoded(
        &mut self,
        record: AuditRecord,
        payload: Vec<u8>,
    ) -> Result<AuditLedgerHead, AppError> {
        let sequence = self.head.sequence.checked_add(1).ok_or_else(|| {
            AppError::new(ErrorCode::AuditSequenceInvalid, "audit sequence overflow")
        })?;
        self.advance(AuditLedgerIoEvent::BeginEncoding)?;
        let frame = encode_frame(sequence, self.last_hash, &payload);
        self.advance(AuditLedgerIoEvent::Encoded)?;
        if self.options.failure_injection == Some(AuditFailurePoint::Append) {
            self.advance(AuditLedgerIoEvent::Failed)?;
            return Err(append_error());
        }
        if self.file.write_all(&frame).is_err() {
            self.advance(AuditLedgerIoEvent::Failed)?;
            return Err(append_error());
        }
        self.advance(AuditLedgerIoEvent::Appended)?;
        if self.options.failure_injection == Some(AuditFailurePoint::Sync)
            || self.file.sync_all().is_err()
        {
            self.advance(AuditLedgerIoEvent::Failed)?;
            return Err(sync_error(std::io::Error::other("audit sync failed")));
        }
        self.last_hash
            .copy_from_slice(&frame[frame.len() - HASH_LEN..]);
        self.current_segment_bytes += frame.len();
        self.head.sequence = sequence;
        self.records.push(AuditRecordView { sequence, record });
        self.record_segments.push(self.current_segment);
        if let Some(segment) = self.segments.last_mut() {
            if segment.first_sequence == 0 {
                segment.first_sequence = sequence;
            }
            segment.last_sequence = sequence;
            segment.terminal_hash = self.last_hash;
            segment.bytes = self.current_segment_bytes;
        }
        self.advance(AuditLedgerIoEvent::Synced)?;
        Ok(self.head)
    }

    fn prepare_storage(&mut self, next_frame_bytes: usize, timestamp: u64) -> Result<(), AppError> {
        if self.current_segment_bytes == 0
            || self.current_segment_bytes + next_frame_bytes <= self.options.max_segment_bytes
        {
            return Ok(());
        }
        let mut maintenance =
            StorageMaintenanceState::Ready.transition(StorageMaintenanceEvent::RequireRotation)?;
        if let Err(error) = self.rotate_segment() {
            let _ = maintenance.transition(StorageMaintenanceEvent::Fail);
            self.state = AuditLedgerIoState::Degraded;
            return Err(error);
        }
        maintenance = maintenance.transition(StorageMaintenanceEvent::PublishSegment)?;

        if self.retention_required(next_frame_bytes) {
            maintenance = maintenance.transition(StorageMaintenanceEvent::RequireRetention)?;
            if let Err(error) = self.retain_for(next_frame_bytes, timestamp) {
                let _ = maintenance.transition(StorageMaintenanceEvent::Fail);
                self.state = AuditLedgerIoState::Degraded;
                return Err(error);
            }
            maintenance = maintenance.transition(StorageMaintenanceEvent::SyncCheckpoint)?;
            maintenance = maintenance.transition(StorageMaintenanceEvent::RemoveSegments)?;
        }
        let _ = maintenance.transition(StorageMaintenanceEvent::Finish)?;
        Ok(())
    }

    fn rotate_segment(&mut self) -> Result<(), AppError> {
        self.file.sync_all().map_err(sync_error)?;
        if self.options.failure_injection == Some(AuditFailurePoint::RotationPublish) {
            return Err(AppError::new(
                ErrorCode::AuditUnavailable,
                "audit segment publication failed",
            ));
        }
        let number = self.current_segment.checked_add(1).ok_or_else(|| {
            AppError::new(ErrorCode::AuditCapacityReached, "audit segment overflow")
        })?;
        let path = segment_path(&self.directory_path, number);
        let file = open_private_segment(&path)?;
        self._directory.sync_all().map_err(sync_error)?;
        self.file = file;
        self.current_segment = number;
        self.current_segment_bytes = 0;
        self.segments.push(AuditSegment {
            number,
            path,
            first_sequence: 0,
            last_sequence: 0,
            terminal_hash: self.last_hash,
            bytes: 0,
        });
        Ok(())
    }

    fn retention_required(&self, next_frame_bytes: usize) -> bool {
        self.segments.len() > self.options.max_segments
            || self.total_bytes().saturating_add(next_frame_bytes) > self.options.max_total_bytes
    }

    fn retain_for(&mut self, next_frame_bytes: usize, timestamp: u64) -> Result<(), AppError> {
        let checkpoint_template = retention_record(timestamp, self.current_segment)?;
        let mut remove_count = 0;
        let mut removed_bytes = 0;
        let metadata = loop {
            if remove_count + 1 >= self.segments.len() {
                return Err(AppError::new(
                    ErrorCode::AuditCapacityReached,
                    "audit retention bounds cannot be satisfied",
                ));
            }
            removed_bytes += self.segments[remove_count].bytes;
            remove_count += 1;
            let first = &self.segments[0];
            let last = &self.segments[remove_count - 1];
            let metadata = RetentionMetadata {
                first_sequence: first.first_sequence,
                last_sequence: last.last_sequence,
                terminal_hash: last.terminal_hash,
            };
            let checkpoint_payload =
                encode_record_with_retention(&checkpoint_template, Some(&metadata))?;
            let checkpoint_bytes = HEADER_LEN + checkpoint_payload.len() + HASH_LEN;
            let segment_count_fits =
                self.segments.len() - remove_count <= self.options.max_segments;
            let total_fits = self
                .total_bytes()
                .saturating_sub(removed_bytes)
                .saturating_add(checkpoint_bytes)
                .saturating_add(next_frame_bytes)
                <= self.options.max_total_bytes;
            if segment_count_fits && total_fits {
                break metadata;
            }
        };
        let payload = encode_record_with_retention(&checkpoint_template, Some(&metadata))?;
        let checkpoint_bytes = HEADER_LEN + payload.len() + HASH_LEN;
        if checkpoint_bytes + next_frame_bytes > self.options.max_total_bytes
            || checkpoint_bytes > self.options.max_segment_bytes
        {
            return Err(AppError::new(
                ErrorCode::AuditCapacityReached,
                "audit retention checkpoint exceeds storage bounds",
            ));
        }
        self.append_encoded(checkpoint_template, payload)?;
        self._directory.sync_all().map_err(sync_error)?;
        if self.options.failure_injection == Some(AuditFailurePoint::RetentionDelete) {
            return Err(AppError::new(
                ErrorCode::AuditUnavailable,
                "audit retention deletion failed",
            ));
        }
        let removed: Vec<_> = self.segments.drain(..remove_count).collect();
        for segment in &removed {
            fs::remove_file(&segment.path).map_err(io_error)?;
        }
        self._directory.sync_all().map_err(sync_error)?;
        let removed_numbers: BTreeSet<_> = removed.iter().map(|segment| segment.number).collect();
        let mut index = 0;
        self.records.retain(|_| {
            let keep = !removed_numbers.contains(&self.record_segments[index]);
            index += 1;
            keep
        });
        self.record_segments
            .retain(|number| !removed_numbers.contains(number));
        self.head.generation = self
            .segments
            .first()
            .map_or(0, |segment| segment.number.saturating_sub(1));
        Ok(())
    }

    fn total_bytes(&self) -> usize {
        self.segments.iter().map(|segment| segment.bytes).sum()
    }

    pub fn io_state(&self) -> AuditLedgerIoState {
        self.state
    }

    fn advance(&mut self, event: AuditLedgerIoEvent) -> Result<(), AppError> {
        self.state = self.state.transition(event)?;
        Ok(())
    }
}

impl AuditLedgerWriter for FileAuditLedger {
    fn append_intent(&mut self, record: AuditRecord) -> Result<AuditLedgerHead, AppError> {
        self.append(record)
    }
    fn append_terminal(
        &mut self,
        record: AuditRecord,
        expected: AuditLedgerHead,
    ) -> Result<AuditLedgerHead, AppError> {
        self.expect_head(expected)?;
        self.append(record)
    }
    fn append_reconciliation(
        &mut self,
        record: AuditRecord,
        expected: AuditLedgerHead,
    ) -> Result<AuditLedgerHead, AppError> {
        self.expect_head(expected)?;
        self.append(record)
    }
    fn append_security_observation(
        &mut self,
        record: AuditRecord,
    ) -> Result<AuditLedgerHead, AppError> {
        self.append(record)
    }
}

impl FileAuditLedger {
    fn expect_head(&self, expected: AuditLedgerHead) -> Result<(), AppError> {
        if expected != self.head {
            return Err(AppError::new(
                ErrorCode::AuditRecordInvalid,
                "audit head mismatch",
            ));
        }
        Ok(())
    }
}

impl AuditLedgerReader for FileAuditLedger {
    fn query(&self, query: &AuditQuery) -> Result<AuditPage, AppError> {
        if query.cursor.is_some_and(|cursor| {
            cursor.ledger_generation != self.head.generation
                || cursor.before_sequence == 0
                || cursor.before_sequence > self.head.sequence.saturating_add(1)
        }) {
            return Err(AppError::new(
                ErrorCode::AuditCursorInvalid,
                "audit cursor is stale or outside the retained range",
            ));
        }
        let before = query
            .cursor
            .map(|cursor| cursor.before_sequence)
            .unwrap_or(u64::MAX);
        let mut records: Vec<_> = self
            .records
            .iter()
            .rev()
            .filter(|view| {
                view.sequence < before
                    && query.action.is_none_or(|value| value == view.record.action)
                    && query
                        .outcome
                        .is_none_or(|value| Some(value) == view.record.outcome)
                    && query
                        .target_kind
                        .is_none_or(|value| value == view.record.target_kind)
                    && query
                        .from_epoch_seconds
                        .is_none_or(|value| view.record.context.received_at_epoch_seconds >= value)
                    && query
                        .to_epoch_seconds
                        .is_none_or(|value| view.record.context.received_at_epoch_seconds <= value)
            })
            .take(query.limit as usize)
            .cloned()
            .collect();
        let next_cursor = records.last().and_then(|last| {
            (self
                .records
                .iter()
                .any(|item| item.sequence < last.sequence))
            .then_some(edge_domain::AuditCursor {
                ledger_generation: self.head.generation,
                before_sequence: last.sequence,
            })
        });
        Ok(AuditPage {
            records: std::mem::take(&mut records),
            next_cursor,
            head: self.head,
            admission_state: AuditAdmissionState::Healthy,
        })
    }
    fn incomplete_operations(&self) -> Result<Vec<AuditRecord>, AppError> {
        let mut open = BTreeSet::new();
        for item in &self.records {
            match item.record.record_kind {
                AuditRecordKind::Intent => {
                    open.insert(item.record.context.operation_id.clone());
                }
                AuditRecordKind::Terminal | AuditRecordKind::Reconciliation => {
                    open.remove(&item.record.context.operation_id);
                }
                _ => {}
            }
        }
        Ok(self
            .records
            .iter()
            .filter(|item| {
                item.record.record_kind == AuditRecordKind::Intent
                    && open.contains(&item.record.context.operation_id)
            })
            .map(|item| item.record.clone())
            .collect())
    }
    fn unresolved_reconciliations(&self) -> Result<Vec<AuditRecord>, AppError> {
        let mut unresolved = std::collections::BTreeMap::new();
        for item in &self.records {
            if item.record.record_kind == AuditRecordKind::Reconciliation {
                match item.record.outcome {
                    Some(AuditOutcome::ReconciliationUnknown) => {
                        unresolved.insert(
                            item.record.context.operation_id.clone(),
                            item.record.clone(),
                        );
                    }
                    Some(
                        AuditOutcome::ReconciledCommitted | AuditOutcome::ReconciledNotCommitted,
                    ) => {
                        unresolved.remove(&item.record.context.operation_id);
                    }
                    _ => {}
                }
            }
        }
        Ok(unresolved.into_values().collect())
    }
    fn head(&self) -> Result<AuditLedgerHead, AppError> {
        Ok(self.head)
    }
}

impl AuditLedgerVerifier for FileAuditLedger {
    fn verify(&mut self) -> Result<edge_domain::AuditVerificationReport, AppError> {
        Ok(edge_domain::AuditVerificationReport {
            head: self.head,
            record_count: self.records.len() as u64,
            segment_count: self.segments.len().try_into().map_err(|_| {
                AppError::new(
                    ErrorCode::AuditCapacityReached,
                    "audit segment count exceeds report bounds",
                )
            })?,
            incomplete_operation_count: self.incomplete_operations()?.len() as u16,
        })
    }
}

fn encode_frame(sequence: u64, previous: [u8; 32], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + HASH_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FRAME_VERSION.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&previous);
    out.extend_from_slice(payload);
    let mut digest = Sha256::new();
    digest.update(FRAME_VERSION.to_be_bytes());
    digest.update(sequence.to_be_bytes());
    digest.update(previous);
    digest.update(payload);
    out.extend_from_slice(&digest.finalize());
    out
}

struct ScanResult {
    records: Vec<AuditRecordView>,
    record_segments: Vec<u64>,
    segments: Vec<AuditSegment>,
    head: AuditLedgerHead,
    last_hash: [u8; 32],
    current_segment_bytes: usize,
    recovered: bool,
}

fn scan_segments(
    paths: &[(u64, PathBuf)],
    directory: &File,
    options: &AuditLedgerOptions,
    allow_recovery: bool,
) -> Result<ScanResult, AppError> {
    let mut previous = [0; 32];
    let mut expected_sequence = 1;
    let mut records = Vec::new();
    let mut record_segments = Vec::new();
    let mut segments = Vec::new();
    let mut recovered = false;
    let first_segment = paths.first().expect("segment list is non-empty").0;
    let mut retained_anchor = None;
    let mut checkpoint_metadata = Vec::new();

    for (path_index, (number, path)) in paths.iter().enumerate() {
        let segment_record_start = records.len();
        let mut file = open_private_segment(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(io_error)?;
        let mut offset = 0;
        let segment_first_sequence = expected_sequence;
        let is_last = path_index + 1 == paths.len();
        while offset < bytes.len() {
            if bytes.len() - offset < HEADER_LEN + HASH_LEN {
                if !allow_recovery || !is_last {
                    return Err(ledger_error(
                        ErrorCode::AuditTrailingFrameIncomplete,
                        "audit trailing frame is incomplete",
                    ));
                }
                truncate_trailing(&mut file, offset)?;
                directory.sync_all().map_err(sync_error)?;
                bytes.truncate(offset);
                recovered = true;
                break;
            }
            if &bytes[offset..offset + 8] != MAGIC {
                return Err(ledger_error(
                    ErrorCode::AuditInteriorCorruption,
                    "audit frame magic is invalid",
                ));
            }
            let version = u16::from_be_bytes(bytes[offset + 8..offset + 10].try_into().unwrap());
            let flags = u16::from_be_bytes(bytes[offset + 10..offset + 12].try_into().unwrap());
            let len =
                u32::from_be_bytes(bytes[offset + 12..offset + 16].try_into().unwrap()) as usize;
            let sequence = u64::from_be_bytes(bytes[offset + 16..offset + 24].try_into().unwrap());
            let frame_previous: [u8; 32] = bytes[offset + 24..offset + 56].try_into().unwrap();
            if version != FRAME_VERSION {
                return Err(ledger_error(
                    ErrorCode::AuditUnsupportedVersion,
                    "audit frame version is unsupported",
                ));
            }
            if flags != 0 {
                return Err(ledger_error(
                    ErrorCode::AuditInteriorCorruption,
                    "audit frame flags are invalid",
                ));
            }
            if records.is_empty() && first_segment > 1 {
                retained_anchor = Some((sequence, frame_previous));
                expected_sequence = sequence;
                previous = frame_previous;
            }
            if frame_previous != previous {
                return Err(ledger_error(
                    ErrorCode::AuditChainMismatch,
                    "audit previous hash does not match",
                ));
            }
            if sequence != expected_sequence {
                return Err(ledger_error(
                    ErrorCode::AuditSequenceInvalid,
                    "audit sequence is invalid",
                ));
            }
            if len > options.max_payload_bytes {
                return Err(ledger_error(
                    ErrorCode::AuditRecordTooLarge,
                    "audit payload exceeds limit",
                ));
            }
            if records.len() >= options.max_scan_records {
                return Err(ledger_error(
                    ErrorCode::AuditCapacityReached,
                    "audit startup record limit exceeded",
                ));
            }
            let end = offset + HEADER_LEN + len + HASH_LEN;
            if end > bytes.len() {
                if !allow_recovery || !is_last {
                    return Err(ledger_error(
                        ErrorCode::AuditTrailingFrameIncomplete,
                        "audit trailing frame is incomplete",
                    ));
                }
                truncate_trailing(&mut file, offset)?;
                directory.sync_all().map_err(sync_error)?;
                bytes.truncate(offset);
                recovered = true;
                break;
            }
            let payload = &bytes[offset + HEADER_LEN..offset + HEADER_LEN + len];
            let expected = encode_frame(sequence, previous, payload);
            if expected[expected.len() - HASH_LEN..] != bytes[end - HASH_LEN..end] {
                return Err(ledger_error(
                    ErrorCode::AuditChainMismatch,
                    "audit frame hash does not match",
                ));
            }
            previous.copy_from_slice(&bytes[end - HASH_LEN..end]);
            let (record, metadata) = decode_record_with_retention(payload)?;
            if let Some(metadata) = metadata {
                checkpoint_metadata.push(metadata);
            }
            records.push(AuditRecordView { sequence, record });
            record_segments.push(*number);
            expected_sequence = sequence.checked_add(1).ok_or_else(|| {
                ledger_error(ErrorCode::AuditSequenceInvalid, "audit sequence overflow")
            })?;
            offset = end;
        }
        segments.push(AuditSegment {
            number: *number,
            path: path.clone(),
            first_sequence: records
                .get(segment_record_start)
                .map(|record| record.sequence)
                .unwrap_or(segment_first_sequence),
            last_sequence: records
                .last()
                .filter(|_| records.len() > segment_record_start)
                .map(|record| record.sequence)
                .unwrap_or(0),
            terminal_hash: previous,
            bytes: bytes.len(),
        });
    }

    if let Some((first_sequence, predecessor_hash)) = retained_anchor {
        let valid_checkpoint = checkpoint_metadata.iter().any(|metadata| {
            metadata.last_sequence.checked_add(1) == Some(first_sequence)
                && metadata.terminal_hash == predecessor_hash
                && metadata.first_sequence <= metadata.last_sequence
        });
        if !valid_checkpoint {
            return Err(ledger_error(
                ErrorCode::AuditChainMismatch,
                "audit retention anchor has no valid checkpoint",
            ));
        }
    }
    let sequence = records.last().map_or(0, |record| record.sequence);
    Ok(ScanResult {
        records,
        record_segments,
        current_segment_bytes: segments.last().map_or(0, |segment| segment.bytes),
        segments,
        head: AuditLedgerHead {
            generation: first_segment.saturating_sub(1),
            sequence,
        },
        last_hash: previous,
        recovered,
    })
}

fn recovery_record(context: AuditContext) -> Result<AuditRecord, AppError> {
    let record = AuditRecord {
        record_version: 1,
        record_kind: AuditRecordKind::SystemRecovery,
        context,
        action: AuditAction::SystemTrailingRecovery,
        target_kind: AuditTargetKind::AuditLedger,
        target_id: AuditTargetId::parse("ledger").map_err(|_| corrupt())?,
        before_revision: None,
        after_revision: None,
        outcome: Some(AuditOutcome::Succeeded),
        error_code: None,
    };
    record.validate().map_err(|_| corrupt())?;
    Ok(record)
}

fn retention_record(timestamp: u64, segment: u64) -> Result<AuditRecord, AppError> {
    let record = AuditRecord {
        record_version: 1,
        record_kind: AuditRecordKind::RetentionCheckpoint,
        context: AuditContext {
            operation_id: edge_domain::AuditOperationId::parse(format!("retention-{segment}"))
                .map_err(|_| corrupt())?,
            request_id: AuditRequestId::parse(format!("internal-{segment}"))
                .map_err(|_| corrupt())?,
            actor_kind: AuditActorKind::SystemRecovery,
            received_at_epoch_seconds: timestamp,
        },
        action: AuditAction::RetentionCheckpoint,
        target_kind: AuditTargetKind::AuditLedger,
        target_id: AuditTargetId::parse("ledger").map_err(|_| corrupt())?,
        before_revision: None,
        after_revision: None,
        outcome: Some(AuditOutcome::Succeeded),
        error_code: None,
    };
    record.validate().map_err(|_| corrupt())?;
    Ok(record)
}

fn encode_record(record: &AuditRecord) -> Result<Vec<u8>, AppError> {
    encode_record_with_retention(record, None)
}

fn encode_record_with_retention(
    record: &AuditRecord,
    metadata: Option<&RetentionMetadata>,
) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(&RecordDto {
        record_version: record.record_version,
        record_kind: record.record_kind.as_str().into(),
        operation_id: record.context.operation_id.as_str().into(),
        request_id: record.context.request_id.as_str().into(),
        actor_kind: record.context.actor_kind.as_str().into(),
        action: record.action.as_str().into(),
        target_kind: record.target_kind.as_str().into(),
        target_id: record.target_id.as_str().into(),
        before_revision: record.before_revision.as_ref().map(|v| v.as_str().into()),
        after_revision: record.after_revision.as_ref().map(|v| v.as_str().into()),
        outcome: record.outcome.map(|v| v.as_str().into()),
        error_code: record.error_code.as_ref().map(|v| v.as_str().into()),
        timestamp_epoch_seconds: record.context.received_at_epoch_seconds,
        pruned_first_sequence: metadata.map(|value| value.first_sequence),
        pruned_last_sequence: metadata.map(|value| value.last_sequence),
        pruned_terminal_hash: metadata.map(|value| encode_hash(value.terminal_hash)),
    })
    .map_err(|_| corrupt())
}
#[cfg(test)]
fn decode_record(bytes: &[u8]) -> Result<AuditRecord, AppError> {
    decode_record_with_retention(bytes).map(|(record, _)| record)
}

fn decode_record_with_retention(
    bytes: &[u8],
) -> Result<(AuditRecord, Option<RetentionMetadata>), AppError> {
    let d: RecordDto = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
    if d.record_version != 1 {
        return Err(ledger_error(
            ErrorCode::AuditUnsupportedVersion,
            "audit record version is unsupported",
        ));
    }
    let record = AuditRecord {
        record_version: d.record_version,
        record_kind: parse_kind(&d.record_kind)?,
        context: AuditContext {
            operation_id: edge_domain::AuditOperationId::parse(d.operation_id)
                .map_err(|_| corrupt())?,
            request_id: AuditRequestId::parse(d.request_id).map_err(|_| corrupt())?,
            actor_kind: parse_actor(&d.actor_kind)?,
            received_at_epoch_seconds: d.timestamp_epoch_seconds,
        },
        action: parse_action(&d.action)?,
        target_kind: parse_target(&d.target_kind)?,
        target_id: AuditTargetId::parse(d.target_id).map_err(|_| corrupt())?,
        before_revision: d
            .before_revision
            .map(AuditTargetId::parse)
            .transpose()
            .map_err(|_| corrupt())?,
        after_revision: d
            .after_revision
            .map(AuditTargetId::parse)
            .transpose()
            .map_err(|_| corrupt())?,
        outcome: d.outcome.as_deref().map(parse_outcome).transpose()?,
        error_code: d
            .error_code
            .map(AuditStableErrorCode::parse)
            .transpose()
            .map_err(|_| corrupt())?,
    };
    record.validate().map_err(|_| corrupt())?;
    let metadata = match (
        d.pruned_first_sequence,
        d.pruned_last_sequence,
        d.pruned_terminal_hash,
    ) {
        (None, None, None) if record.record_kind != AuditRecordKind::RetentionCheckpoint => None,
        (Some(first_sequence), Some(last_sequence), Some(hash))
            if record.record_kind == AuditRecordKind::RetentionCheckpoint
                && first_sequence > 0
                && first_sequence <= last_sequence =>
        {
            Some(RetentionMetadata {
                first_sequence,
                last_sequence,
                terminal_hash: decode_hash(&hash)?,
            })
        }
        _ => return Err(corrupt()),
    };
    Ok((record, metadata))
}

fn encode_hash(hash: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in hash {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hash(value: &str) -> Result<[u8; 32], AppError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(corrupt());
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| corrupt())?;
        output[index] = u8::from_str_radix(text, 16).map_err(|_| corrupt())?;
    }
    Ok(output)
}
fn parse_kind(v: &str) -> Result<AuditRecordKind, AppError> {
    match v {
        "intent" => Ok(AuditRecordKind::Intent),
        "terminal" => Ok(AuditRecordKind::Terminal),
        "reconciliation" => Ok(AuditRecordKind::Reconciliation),
        "security_observation" => Ok(AuditRecordKind::SecurityObservation),
        "retention_checkpoint" => Ok(AuditRecordKind::RetentionCheckpoint),
        "system_recovery" => Ok(AuditRecordKind::SystemRecovery),
        _ => Err(corrupt()),
    }
}
fn parse_actor(v: &str) -> Result<AuditActorKind, AppError> {
    match v {
        "bootstrap_setup" => Ok(AuditActorKind::BootstrapSetup),
        "bootstrap_admin" => Ok(AuditActorKind::BootstrapAdmin),
        "maintenance_cli" => Ok(AuditActorKind::MaintenanceCli),
        "system_recovery" => Ok(AuditActorKind::SystemRecovery),
        _ => Err(corrupt()),
    }
}
fn parse_target(v: &str) -> Result<AuditTargetKind, AppError> {
    match v {
        "config_revision" => Ok(AuditTargetKind::ConfigRevision),
        "proxy_host" => Ok(AuditTargetKind::ProxyHost),
        "certificate" => Ok(AuditTargetKind::Certificate),
        "trust_bundle" => Ok(AuditTargetKind::TrustBundle),
        "admin_account" => Ok(AuditTargetKind::AdminAccount),
        "restore" => Ok(AuditTargetKind::Restore),
        "audit_ledger" => Ok(AuditTargetKind::AuditLedger),
        _ => Err(corrupt()),
    }
}
fn parse_outcome(v: &str) -> Result<AuditOutcome, AppError> {
    match v {
        "succeeded" => Ok(AuditOutcome::Succeeded),
        "failed" => Ok(AuditOutcome::Failed),
        "observed" => Ok(AuditOutcome::Observed),
        "reconciled_committed" => Ok(AuditOutcome::ReconciledCommitted),
        "reconciled_not_committed" => Ok(AuditOutcome::ReconciledNotCommitted),
        "reconciliation_unknown" => Ok(AuditOutcome::ReconciliationUnknown),
        _ => Err(corrupt()),
    }
}
fn parse_action(v: &str) -> Result<AuditAction, AppError> {
    [
        AuditAction::ConfigApply,
        AuditAction::ConfigRollback,
        AuditAction::ProxyHostCreate,
        AuditAction::ProxyHostUpdate,
        AuditAction::ProxyHostDelete,
        AuditAction::CertificateIssue,
        AuditAction::CertificateRenew,
        AuditAction::CertificateImport,
        AuditAction::CertificateInstall,
        AuditAction::TrustBundleImport,
        AuditAction::TrustBundleDelete,
        AuditAction::AdminSetup,
        AuditAction::AdminLoginSuccess,
        AuditAction::AdminLogout,
        AuditAction::AdminLockout,
        AuditAction::AdminAuthFailureSampled,
        AuditAction::MaintenanceRestoreImported,
        AuditAction::SystemTrailingRecovery,
        AuditAction::RetentionCheckpoint,
    ]
    .into_iter()
    .find(|a| a.as_str() == v)
    .ok_or_else(corrupt)
}
fn corrupt() -> AppError {
    AppError::new(
        ErrorCode::AuditRecordInvalid,
        "audit ledger verification failed",
    )
}
fn ledger_error(code: ErrorCode, message: &'static str) -> AppError {
    AppError::new(code, message)
}
fn truncate_trailing(file: &mut File, valid_length: usize) -> Result<(), AppError> {
    file.set_len(valid_length as u64).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}
fn io_error(_: std::io::Error) -> AppError {
    AppError::new(ErrorCode::AuditUnavailable, "audit ledger I/O failed")
}
fn append_error() -> AppError {
    AppError::new(ErrorCode::AuditAppendFailed, "audit ledger append failed")
}
fn sync_error(_: std::io::Error) -> AppError {
    AppError::new(ErrorCode::AuditSyncFailed, "audit ledger sync failed")
}

fn segment_path(directory: &Path, number: u64) -> PathBuf {
    directory.join(format!("segment-{number:016}.audit"))
}

fn discover_segments(directory: &Path) -> Result<Vec<(u64, PathBuf)>, AppError> {
    let mut segments = Vec::new();
    for entry in fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            return Err(corrupt());
        };
        if !file_name.starts_with("segment-") || !file_name.ends_with(".audit") {
            continue;
        }
        let number = file_name
            .strip_prefix("segment-")
            .and_then(|value| value.strip_suffix(".audit"))
            .filter(|value| value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or_else(corrupt)?
            .parse::<u64>()
            .map_err(|_| corrupt())?;
        if number == 0 {
            return Err(corrupt());
        }
        segments.push((number, entry.path()));
    }
    segments.sort_by_key(|(number, _)| *number);
    if segments
        .windows(2)
        .any(|window| window[1].0 != window[0].0 + 1)
    {
        return Err(ledger_error(
            ErrorCode::AuditInteriorCorruption,
            "audit segment sequence is not contiguous",
        ));
    }
    Ok(segments)
}

#[cfg(unix)]
fn prepare_private_directory(path: &Path) -> Result<(), AppError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let existed = fs::symlink_metadata(path).ok();
    if existed
        .as_ref()
        .is_some_and(|metadata| !metadata.file_type().is_dir())
    {
        return Err(AppError::new(
            ErrorCode::AuditUnavailable,
            "audit ledger directory is unsafe",
        ));
    }
    fs::create_dir_all(path).map_err(io_error)?;
    if existed.is_none() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.file_type().is_dir() || metadata.mode() & 0o777 != 0o700 {
        return Err(AppError::new(
            ErrorCode::AuditUnavailable,
            "audit ledger directory is unsafe",
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
fn prepare_private_directory(_: &Path) -> Result<(), AppError> {
    Err(AppError::new(
        ErrorCode::AuditUnavailable,
        "audit ledger platform unsupported",
    ))
}
#[cfg(unix)]
fn open_private_segment(path: &Path) -> Result<File, AppError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.file_type().is_file() || metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1
    {
        return Err(AppError::new(
            ErrorCode::AuditUnavailable,
            "audit ledger segment is unsafe",
        ));
    }
    Ok(file)
}
#[cfg(not(unix))]
fn open_private_segment(_: &Path) -> Result<File, AppError> {
    Err(AppError::new(
        ErrorCode::AuditUnavailable,
        "audit ledger platform unsupported",
    ))
}
