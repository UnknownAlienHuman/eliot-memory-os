//! Durable process-stream staging against the real Windows filesystem and
//! current-user DPAPI adapters. These checks exercise the same Blob owner
//! methods used by Store IPC, including exact retry and restart recovery.

#[cfg(windows)]
mod windows_durable_owner {
    use std::future::Future;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::task::{Context, Poll, Waker};

    use eliot_blob::{
        BlobRootOwner, BlobServicePorts, BlobStoreService, DpapiUserAeadPort, DpapiUserKeyPort,
        BlobPathState, BlobPlatformPort, RleCompressionPort, RootClaimProof,
        UnavailableBlobLiveSetPort, WindowsBlobPlatformPort,
    };
    use eliot_blob_api::{
        BlobCapacityCause, BlobCapacityCleanup, BlobCapacityEffect, BlobCapacityEvidence,
        BlobCapacityFailure, BlobCapacityIdentity, BlobCapacityRecovery, BlobCapacityStage,
        BlobCasCapability, BlobCasProviderResult, BlobCasRequest, BlobError, BlobHash, BlobId,
        BlobPolicyBinding, BlobProcessStreamReadbackRangeRequest,
        BlobProcessStreamReadbackRequest, BlobProcessStreamSourceBinding,
        BLOB_PROCESS_STREAM_STAGE_MAX_CHUNKS, BLOB_PROCESS_STREAM_STAGE_MAX_PREVIEW_BYTES,
        BlobProcessStreamStageAppendRequest, BlobProcessStreamStageFinalizeRequest,
        BlobProcessStreamStageOpenRequest, BlobProcessStreamStageTerminal,
        BlobProcessStreamStageResumeRequest, BlobReceiptContext, BlobStoreClient, ObjectResidencyKey,
        RetentionClass, VersionedContentDigest,
    };
    use eliot_platform::PlatformHandle;
    use eliot_platform_windows::{WindowsBlobStorePlatform, WindowsPlatform};
    use eliot_process::{
        DurableProcessStreamSource, DurableStreamLocatorKind, ProcessExecutionBinding,
        ProcessStreamEvidence, ProcessStreamKind, ProcessStreamPolicyBinding,
        ProcessStreamPrefixPreview, ProcessStreamSinkAbortReason,
        ProcessStreamSinkAbortRequest, ProcessStreamDigestAlgorithm,
        ProcessStreamSinkFinalizeRequest, ProcessStreamSinkLimits,
        ProcessStreamSinkOpenRequest, ProcessStreamSinkSession,
        ProcessStreamSinkSessionId, ProcessStreamSinkSourceId, ProcessStreamSinkState,
        ProcessStreamSinkTerminal, ProcessStreamSinkTerminalId, StreamEvidenceGap,
        StreamPersistenceStatus, StreamTransportStatus,
    };
    use eliot_security_contracts::{EffectCeiling, InstructionTaint, PrivacyClass};
    use sha2::{Digest, Sha256};

    static ROOT_COUNTER: AtomicU64 = AtomicU64::new(1);

    /// Test-only delegated platform wrapper that reports a precise Windows
    /// disk-full result for the next matching durable publication path. It
    /// never fills a volume or changes production fault behavior.
    struct DiskFullAtSelectedPublication {
        inner: WindowsBlobPlatformPort,
        armed: AtomicBool,
        context: BlobReceiptContext,
        path_fragment: &'static str,
    }

    impl BlobPlatformPort for DiskFullAtSelectedPublication {
        fn claim_root(&mut self, lease: &eliot_blob::BlobRootLease) -> Result<RootClaimProof, BlobError> {
            self.inner.claim_root(lease)
        }

        fn inspect_root(&self, lease: &eliot_blob::BlobRootLease) -> Result<RootClaimProof, BlobError> {
            self.inner.inspect_root(lease)
        }

        fn prove_contained(&self, lease: &eliot_blob::BlobRootLease, path: &eliot_platform::WorkScopePath) -> Result<(), BlobError> {
            self.inner.prove_contained(lease, path)
        }

        fn read_bounded(&self, path: &eliot_platform::WorkScopePath, max_bytes: u64) -> Result<Vec<u8>, BlobError> {
            self.inner.read_bounded(path, max_bytes)
        }

        fn write_new_durable(&mut self, path: &eliot_platform::WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
            if path.normalized_identity().contains(self.path_fragment)
                && self.armed.swap(false, Ordering::SeqCst)
            {
                return Err(BlobError::StorageCapacity {
                    failure: Box::new(BlobCapacityFailure {
                        identity: BlobCapacityIdentity::Operation {
                            context: Box::new(self.context.clone()),
                            locator: None,
                        },
                        stage: BlobCapacityStage::PayloadWrite,
                        evidence: BlobCapacityEvidence {
                            cause: BlobCapacityCause::WindowsErrorDiskFull { code: 112 },
                            attempted_bytes: Some(bytes.len() as u64),
                            effect: BlobCapacityEffect::NotAttempted,
                        },
                        cas_request: None,
                        cas_observed: None,
                        cas_backend_generation: None,
                        cas_durability: None,
                        cleanup: BlobCapacityCleanup::NotApplicable,
                        cleanup_stage: None,
                        cleanup_evidence: None,
                        gc_state: None,
                        recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
                    }),
                });
            }
            self.inner.write_new_durable(path, bytes)
        }

        fn replace_durable(&mut self, path: &eliot_platform::WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
            self.inner.replace_durable(path, bytes)
        }

        fn cas_capability(&self) -> BlobCasCapability { self.inner.cas_capability() }

        fn compare_and_replace_durable(&mut self, request: &BlobCasRequest, bytes: &[u8]) -> Result<BlobCasProviderResult, BlobError> {
            self.inner.compare_and_replace_durable(request, bytes)
        }

        fn cas_status(&self, operation_id: &str) -> Result<Option<BlobCasProviderResult>, BlobError> {
            self.inner.cas_status(operation_id)
        }

        fn backend_generation(&self) -> Result<u64, BlobError> { self.inner.backend_generation() }

        fn rename_no_replace_durable(&mut self, source: &eliot_platform::WorkScopePath, destination: &eliot_platform::WorkScopePath) -> Result<(), BlobError> {
            self.inner.rename_no_replace_durable(source, destination)
        }

        fn remove_durable(&mut self, path: &eliot_platform::WorkScopePath) -> Result<(), BlobError> {
            self.inner.remove_durable(path)
        }

        fn stat(&self, path: &eliot_platform::WorkScopePath) -> Result<BlobPathState, BlobError> {
            self.inner.stat(path)
        }

        fn list(&self, prefix: &eliot_platform::WorkScopePath) -> Result<Vec<eliot_platform::WorkScopePath>, BlobError> {
            self.inner.list(prefix)
        }

        fn now_unix_ms(&mut self) -> Result<u64, BlobError> { self.inner.now_unix_ms() }
    }

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Pin::from(Box::new(future));
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn context(effect: &str, operation: &str, generation: u64) -> BlobReceiptContext {
        let epoch = r#"{"lineage_id":"550e8400-e29b-41d4-a716-446655440000","sequence":4}"#;
        let fence = format!(
            "{{\"authority_epoch\":{epoch},\"resource_generation\":{generation},\"task_revision\":null,\"policy_revision\":null,\"integration_revision\":null}}"
        );
        let request = format!("stream-request-{operation}");
        let metadata = format!(
            "{{\"request_id\":\"{request}\",\"session_id\":null,\"task_id\":null,\"product_id\":\"product-stream\",\"source_id\":\"source-stream\",\"state_fence\":{fence},\"clock\":{{\"valid_time_ms\":1,\"known_time_ms\":1,\"transaction_sequence\":null,\"monotonic_ns\":1}}}}"
        );
        let authority_effect = if effect == "READ" {
            "READ"
        } else {
            "REVERSIBLE_MUTATION"
        };
        let json = format!(
            "{{\"work_scope\":{{\"scope_id\":\"scope-stream\",\"product_id\":\"product-stream\",\"resource_generation\":{generation},\"state_fence\":{fence}}},\"task\":null,\"session\":null,\"causal\":{{\"state_fence\":{fence},\"transaction_sequence\":1,\"parent_receipt_id\":null,\"predecessor_receipt_ids\":[]}},\"request\":{{\"metadata\":{metadata},\"state_fence\":{fence}}},\"operation\":{{\"operation_id\":\"stream-op-{operation}\",\"request_id\":\"{request}\",\"idempotency_key\":\"idem-{operation}\",\"operation_kind\":\"blob-process-stream-test\",\"effect\":\"{effect}\",\"state_fence\":{fence}}},\"authority\":{{\"authority_id\":\"authority-stream\",\"authority_owner\":\"test-owner\",\"authority_epoch\":{epoch},\"state_fence\":{fence},\"allowed_effect\":\"{authority_effect}\",\"proof_ceiling\":\"OBSERVED_EXTERNAL_EFFECT\"}}}}"
        );
        serde_json::from_str(&json).expect("valid stream operation context")
    }

    fn open_request(
        owner: &BlobRootOwner,
        session_id: &str,
        source_id: &str,
        stream_kind: &str,
        generation: u64,
        max_bytes: u64,
        max_chunk_bytes: u64,
    ) -> BlobProcessStreamStageOpenRequest {
        let stage_context = context(
            "REVERSIBLE_MUTATION",
            &format!("{session_id}-stage"),
            generation,
        );
        let root_lease = owner
            .lease_for_request(stage_context.request.clone())
            .expect("root lease from authenticated request binding");
        let empty_digest = BlobHash::new(sha256(&[])).expect("digest");
        let policy = BlobPolicyBinding {
            privacy_class: PrivacyClass::Private,
            retention_class: RetentionClass::Task,
            policy_ref: PlatformHandle::new("policy-stream-test").expect("policy ref"),
            instruction_taint: InstructionTaint::DataOnly,
            effect_ceiling: EffectCeiling::CandidateOnly,
        };
        let residency = ObjectResidencyKey {
            scope_domain_id: BlobId::new("scope-stream-test").expect("scope"),
            access_domain_id: BlobId::new("access-stream-test").expect("access"),
            confidentiality_domain_id: BlobId::new("conf-stream-test").expect("confidentiality"),
            encryption_key_domain_id: BlobId::new("process-stream-test-key").expect("key domain"),
            retention_domain_id: BlobId::new("retention-stream-test").expect("retention"),
            erasure_domain_id: BlobId::new("erasure-stream-test").expect("erasure"),
            content_digest: VersionedContentDigest {
                algorithm: BlobId::new("sha256").expect("digest algorithm"),
                version: 1,
                digest: empty_digest,
            },
        };
        BlobProcessStreamStageOpenRequest {
            session_id: session_id.to_owned(),
            source_id: source_id.to_owned(),
            terminal_id: format!("terminal-{session_id}"),
            open_request_sha256: sha256(format!("open-{session_id}").as_bytes()),
            stage_context,
            root_lease,
            policy,
            residency,
            process_source_binding: BlobProcessStreamSourceBinding {
                process_binding_json: "{}".to_owned(),
                process_binding_sha256: sha256(b"{}"),
                stream_kind: stream_kind.to_owned(),
                policy_json: "{}".to_owned(),
                policy_sha256: sha256(b"{}"),
            },
            max_bytes,
            max_chunk_bytes,
            max_chunks: 4,
            max_preview_bytes: 1024,
        }
    }

    fn windows_root_generation(root: &Path) -> u64 {
        WindowsBlobStorePlatform::new(root.to_path_buf())
            .expect("Windows Blob filesystem")
            .root_generation()
            .expect("physical root generation")
    }

    fn service(
        root: &Path,
        owner: &BlobRootOwner,
        request: &BlobProcessStreamStageOpenRequest,
    ) -> BlobStoreService<
        WindowsBlobPlatformPort,
        RleCompressionPort,
        DpapiUserKeyPort,
        DpapiUserAeadPort,
        UnavailableBlobLiveSetPort,
    > {
        let platform = WindowsBlobPlatformPort::new(root.to_path_buf()).expect("Blob platform");
        let anchor = platform.load_or_create_issuer_anchor().expect("pinned issuer anchor");
        let aead_platform = WindowsPlatform::new(root.to_path_buf()).expect("DPAPI platform");
        BlobStoreService::new_with_owner(
            owner,
            request.root_lease.clone(),
            BlobServicePorts {
                platform,
                compression: RleCompressionPort,
                keys: DpapiUserKeyPort::new(
                    BlobId::new("process-stream-test-key").expect("key lineage"),
                    1,
                )
                .expect("DPAPI key lineage"),
                aead: DpapiUserAeadPort::new(aead_platform),
                live_sets: UnavailableBlobLiveSetPort,
                issuer_anchor: anchor,
            },
        )
        .expect("single owner-bound Blob service")
    }

    fn service_with_disk_full_at_chunk_publication(
        root: &Path,
        owner: &BlobRootOwner,
        request: &BlobProcessStreamStageOpenRequest,
    ) -> BlobStoreService<
        DiskFullAtSelectedPublication,
        RleCompressionPort,
        DpapiUserKeyPort,
        DpapiUserAeadPort,
        UnavailableBlobLiveSetPort,
    > {
        let inner = WindowsBlobPlatformPort::new(root.to_path_buf()).expect("Blob platform");
        let anchor = inner.load_or_create_issuer_anchor().expect("pinned issuer anchor");
        let aead_platform = WindowsPlatform::new(root.to_path_buf()).expect("DPAPI platform");
        BlobStoreService::new_with_owner(
            owner,
            request.root_lease.clone(),
            BlobServicePorts {
                platform: DiskFullAtSelectedPublication {
                    inner,
                    armed: AtomicBool::new(true),
                    context: request.stage_context.clone(),
                    path_fragment: ".chunk-",
                },
                compression: RleCompressionPort,
                keys: DpapiUserKeyPort::new(
                    BlobId::new("process-stream-test-key").expect("key lineage"),
                    1,
                )
                .expect("DPAPI key lineage"),
                aead: DpapiUserAeadPort::new(aead_platform),
                live_sets: UnavailableBlobLiveSetPort,
                issuer_anchor: anchor,
            },
        )
        .expect("single owner-bound Blob service with test-only fault adapter")
    }

    fn service_with_disk_full_at_blob_payload_publication(
        root: &Path,
        owner: &BlobRootOwner,
        request: &BlobProcessStreamStageOpenRequest,
    ) -> BlobStoreService<
        DiskFullAtSelectedPublication,
        RleCompressionPort,
        DpapiUserKeyPort,
        DpapiUserAeadPort,
        UnavailableBlobLiveSetPort,
    > {
        let inner = WindowsBlobPlatformPort::new(root.to_path_buf()).expect("Blob platform");
        let anchor = inner.load_or_create_issuer_anchor().expect("pinned issuer anchor");
        let aead_platform = WindowsPlatform::new(root.to_path_buf()).expect("DPAPI platform");
        BlobStoreService::new_with_owner(
            owner,
            request.root_lease.clone(),
            BlobServicePorts {
                platform: DiskFullAtSelectedPublication {
                    inner,
                    armed: AtomicBool::new(true),
                    context: request.stage_context.clone(),
                    path_fragment: ".payload",
                },
                compression: RleCompressionPort,
                keys: DpapiUserKeyPort::new(
                    BlobId::new("process-stream-test-key").expect("key lineage"),
                    1,
                )
                .expect("DPAPI key lineage"),
                aead: DpapiUserAeadPort::new(aead_platform),
                live_sets: UnavailableBlobLiveSetPort,
                issuer_anchor: anchor,
            },
        )
        .expect("single owner-bound Blob service with finalization fault adapter")
    }

    fn append(session: &BlobProcessStreamStageOpenRequest, sequence: u64, offset: u64, bytes: &[u8]) -> BlobProcessStreamStageAppendRequest {
        BlobProcessStreamStageAppendRequest {
            session_id: session.session_id.clone(),
            source_id: session.source_id.clone(),
            terminal_id: session.terminal_id.clone(),
            open_request_sha256: session.open_request_sha256.clone(),
            sequence,
            offset,
            bytes: bytes.to_vec(),
            chunk_sha256: sha256(bytes),
        }
    }

    fn finalize(
        session: &BlobProcessStreamStageOpenRequest,
        final_sequence: u64,
        bytes: &[u8],
    ) -> BlobProcessStreamStageFinalizeRequest {
        BlobProcessStreamStageFinalizeRequest {
            session: BlobProcessStreamStageResumeRequest {
                session_id: session.session_id.clone(),
                source_id: session.source_id.clone(),
                terminal_id: session.terminal_id.clone(),
                open_request_sha256: session.open_request_sha256.clone(),
            },
            terminal_command_sha256: sha256(b"complete-source-finalize"),
            final_sequence,
            final_offset: bytes.len() as u64,
            admitted_sha256: sha256(bytes),
        }
    }

    fn process_open_request(
        session: &BlobProcessStreamStageOpenRequest,
    ) -> ProcessStreamSinkOpenRequest {
        let authority_epoch = serde_json::json!({
            "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
            "sequence": 7
        });
        let binding: ProcessExecutionBinding = serde_json::from_value(serde_json::json!({
            "operation_id": "process-stream-finalize-restart",
            "process_tree_id": "tree-finalize-restart",
            "job_id": "job-finalize-restart",
            "image_id": "image-finalize-restart",
            "session_id": "session-finalize-restart",
            "generation": session.root_lease.root_generation,
            "action_lease_ref": "lease-finalize-restart",
            "authority_id": "authority-finalize-restart",
            "authority_epoch": authority_epoch,
            "state_fence": {
                "authority_epoch": authority_epoch,
                "generation": session.root_lease.root_generation,
                "nonce": "fence-finalize-restart"
            },
            "request_digest": sha256(b"process-stream-finalize-restart-request"),
            "permit_digest": sha256(b"process-stream-finalize-restart-permit"),
            "effect_digest": sha256(b"process-stream-finalize-restart-effect"),
            "validation_revision": 1
        }))
        .expect("typed process execution binding");
        let policy = ProcessStreamPolicyBinding::new(
            session.policy.policy_ref.as_str(),
            "privacy:private",
            "visibility:owner",
            "retention:task",
            "redaction:exact-v1",
        )
        .expect("typed process policy binding");
        let limits = ProcessStreamSinkLimits::new(32, 32, 4, 32, 2, 8, 10, 20, 20)
            .expect("bounded process stream limits");
        ProcessStreamSinkOpenRequest::new(
            ProcessStreamSinkSessionId::new(session.session_id.clone())
                .expect("process sink session id"),
            ProcessStreamSinkSourceId::new(session.source_id.clone())
                .expect("process source id"),
            ProcessStreamSinkTerminalId::new(session.terminal_id.clone())
                .expect("process terminal id"),
            binding,
            ProcessStreamKind::Stdout,
            policy,
            limits,
            ProcessStreamDigestAlgorithm::Sha256,
            ProcessStreamDigestAlgorithm::Sha256,
        )
        .expect("typed process sink open")
    }

    fn bind_process_open(
        session: &mut BlobProcessStreamStageOpenRequest,
        process_open: &ProcessStreamSinkOpenRequest,
    ) {
        session.open_request_sha256 = process_open.open_request_sha256().to_owned();
        session.process_source_binding.process_binding_json =
            serde_json::to_string(process_open.binding()).expect("serialize process binding");
        session.process_source_binding.process_binding_sha256 =
            sha256(session.process_source_binding.process_binding_json.as_bytes());
        session.process_source_binding.policy_json =
            serde_json::to_string(process_open.policy()).expect("serialize process policy");
        session.process_source_binding.policy_sha256 =
            sha256(session.process_source_binding.policy_json.as_bytes());
    }

    fn canonical_json<T: serde::Serialize>(value: &T) -> String {
        let value = serde_json::to_value(value).expect("serialize canonical JSON value");
        serde_json::to_string(&value).expect("encode sorted canonical JSON object")
    }

    fn abort_terminal(
        process_session: ProcessStreamSinkSession,
        bytes: &[u8],
    ) -> ProcessStreamSinkTerminal {
        let digest = sha256(bytes);
        let preview = ProcessStreamPrefixPreview::from_transport_prefix(
            bytes.to_vec(),
            bytes.len() as u64,
        )
        .expect("exact cancellation preview");
        let evidence = ProcessStreamEvidence::new_raw(
            process_session.binding().clone(),
            ProcessStreamKind::Stdout,
            process_session.policy().clone(),
            StreamTransportStatus::CancelledBeforeEof,
            StreamPersistenceStatus::SourceUnavailable,
            digest.clone(),
            bytes.len() as u64,
            preview.clone(),
            None,
            vec![
                StreamEvidenceGap::CancelledBeforeEof,
                StreamEvidenceGap::PersistenceUnavailable,
            ],
        )
        .expect("typed cancellation evidence for the exact staged prefix");
        ProcessStreamSinkTerminal::from_abort(
            process_session.clone(),
            ProcessStreamSinkAbortRequest::new(
                process_session.terminal_id().clone(),
                ProcessStreamSinkAbortReason::Cancellation,
                1,
                bytes.len() as u64,
                1,
                StreamTransportStatus::CancelledBeforeEof,
                digest.clone(),
                bytes.len() as u64,
                preview,
                None,
                evidence.gaps().to_vec(),
            )
            .expect("typed competing Abort command"),
            ProcessStreamSinkState::Cancelled,
            1,
            bytes.len() as u64,
            digest,
            evidence,
        )
        .expect("checked process Abort terminal")
    }

    fn complete_terminal(
        process_session: ProcessStreamSinkSession,
        finalize_request: ProcessStreamSinkFinalizeRequest,
        bytes: &[u8],
        ready: &eliot_blob_api::BlobReadyReceipt,
    ) -> BlobProcessStreamStageTerminal {
        let digest = sha256(bytes);
        let source = DurableProcessStreamSource::exact_transport(
            DurableStreamLocatorKind::Blob,
            format!("blob:{}", ready.locator().hash.as_str()),
            ready.receipt().identity.receipt_id.to_string(),
            ready.plaintext_sha256().to_owned(),
            ready.plaintext_length(),
        )
        .expect("source tied to owner-issued Ready receipt");
        let evidence = ProcessStreamEvidence::new_raw(
            process_session.binding().clone(),
            ProcessStreamKind::Stdout,
            process_session.policy().clone(),
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            digest.clone(),
            bytes.len() as u64,
            ProcessStreamPrefixPreview::from_transport_prefix(bytes.to_vec(), bytes.len() as u64)
                .expect("exact source preview"),
            Some(source),
            Vec::new(),
        )
        .expect("typed complete source evidence from owner readback");
        let terminal = ProcessStreamSinkTerminal::from_finalize(
            process_session,
            finalize_request,
            ProcessStreamSinkState::CompleteSource,
            1,
            bytes.len() as u64,
            digest,
            evidence,
        )
        .expect("checked CompleteSource terminal");
        let terminal_json = canonical_json(&terminal);
        BlobProcessStreamStageTerminal {
            terminal_json_sha256: sha256(terminal_json.as_bytes()),
            terminal_json,
            ready_receipt_sha256: Some(sha256(
                canonical_json(ready).as_bytes(),
            )),
            ready_receipt_json: Some(canonical_json(ready)),
        }
    }

    fn resume_request(session: &BlobProcessStreamStageOpenRequest) -> BlobProcessStreamStageResumeRequest {
        BlobProcessStreamStageResumeRequest {
            session_id: session.session_id.clone(),
            source_id: session.source_id.clone(),
            terminal_id: session.terminal_id.clone(),
            open_request_sha256: session.open_request_sha256.clone(),
        }
    }

    fn isolated_root() -> PathBuf {
        let suffix = ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "eliot-1969-process-stream-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("isolated Blob root");
        path
    }

    fn simulate_pending_append_without_ciphertext(
        root: &Path,
        session: &BlobProcessStreamStageOpenRequest,
        sequence: u64,
    ) {
        // Recreate the durable state at the crash boundary after the pending
        // append record is fsynced but before ciphertext publication. The
        // format/path are intentionally asserted here so recovery tests fail
        // visibly if the owner record contract changes.
        let session_key = session.session_key_sha256().expect("session key");
        let stem = format!(".eliot-process-stream-stage-v1-{session_key}");
        let record_path = root.join("transactions").join(format!(
            "{stem}.append-{sequence:020}"
        ));
        let chunk_path = root
            .join("transactions")
            .join(format!("{stem}.chunk-{sequence:020}"));
        let record = std::fs::read_to_string(&record_path).expect("committed append record");
        let phase = record.replace("\"phase\":\"COMMITTED\"", "\"phase\":\"PENDING\"");
        assert_ne!(phase, record, "append phase is part of the durable contract");
        let digest_start = phase
            .find("\"ciphertext_sha256\":\"")
            .expect("ciphertext digest field")
            + "\"ciphertext_sha256\":\"".len();
        let digest_end = phase[digest_start..]
            .find('"')
            .map(|relative| digest_start + relative)
            .expect("ciphertext digest terminator");
        let pending = format!("{}null{}", &phase[..digest_start - 1], &phase[digest_end + 1..]);
        std::fs::write(&record_path, pending).expect("persist simulated pending append boundary");
        std::fs::remove_file(chunk_path).expect("remove unpublished ciphertext");
    }

    #[test]
    fn durable_stream_chunks_resume_after_service_restart_and_separate_streams() {
        let root = isolated_root();
        let generation = windows_root_generation(&root);
        let root_text = root.to_string_lossy().into_owned();
        let owner = BlobRootOwner::claim(
            root_text,
            "process-stream-owner",
            std::process::id(),
        )
        .expect("exclusive root claim");
        let stdout = open_request(
            &owner,
            "session-stdout",
            "source-stdout",
            "STDOUT",
            generation,
            32,
            8,
        );
        let stderr = open_request(
            &owner,
            "session-stderr",
            "source-stderr",
            "STDERR",
            generation,
            32,
            8,
        );
        let store = service(&root, &owner, &stdout);
        let stdout_open = block_on(store.open_process_stream_stage(stdout.clone()))
            .expect("open stdout");
        let stderr_open = block_on(store.open_process_stream_stage(stderr.clone()))
            .expect("open stderr");
        assert_eq!(stdout_open.preview_bytes, b"");
        assert_eq!(stderr_open.preview_bytes, b"");

        // Cancellation before a future is polled has no owner effect. A
        // skipped sequence is likewise refused without advancing the durable
        // prefix, so a caller cannot silently omit bytes from the stream.
        let cancelled_before_poll = store.append_process_stream_stage(append(&stdout, 0, 0, b"x"));
        drop(cancelled_before_poll);
        assert_eq!(
            block_on(store.resume_process_stream_stage(BlobProcessStreamStageResumeRequest {
                session_id: stdout.session_id.clone(),
                source_id: stdout.source_id.clone(),
                terminal_id: stdout.terminal_id.clone(),
                open_request_sha256: stdout.open_request_sha256.clone(),
            }))
            .expect("prefix after pre-poll cancellation")
            .preview_bytes,
            b""
        );
        assert!(matches!(
            block_on(store.append_process_stream_stage(append(&stdout, 1, 0, b"omitted"))),
            Err(BlobError::InvalidContract(_))
        ));

        // A zero-byte chunk is an actual committed sequence and can be replayed
        // only with the same sequence, offset, and bytes.
        let empty = append(&stdout, 0, 0, b"");
        block_on(store.append_process_stream_stage(empty.clone())).expect("empty append");
        block_on(store.append_process_stream_stage(empty)).expect("exact empty replay");
        let first = append(&stdout, 1, 0, b"out");
        block_on(store.append_process_stream_stage(first.clone())).expect("stdout append");
        let changed = append(&stdout, 1, 0, b"bad");
        assert_eq!(
            block_on(store.append_process_stream_stage(changed)),
            Err(BlobError::IdempotencyConflict)
        );

        let second = append(&stderr, 0, 0, b"err");
        block_on(store.append_process_stream_stage(second.clone())).expect("stderr append");
        simulate_pending_append_without_ciphertext(&root, &stderr, 0);
        let over_limit = append(&stdout, 2, 3, b"123456789");
        assert!(matches!(
            block_on(store.append_process_stream_stage(over_limit)),
            Err(BlobError::InvalidContract(_))
        ));
        drop(store);
        drop(owner);

        // A new process-owned service recovers exact ciphertext and append
        // receipts from the same root; the volatile sink map is not authority.
        let owner = BlobRootOwner::claim(
            root.to_string_lossy().into_owned(),
            "process-stream-owner",
            std::process::id(),
        )
        .expect("reclaim after simulated restart");
        let store = service(&root, &owner, &stderr);
        let recovered_pending = block_on(store.append_process_stream_stage(second))
            .expect("exact retry completes a persisted pending append after restart");
        assert_eq!(recovered_pending.sequence, 0);
        assert_eq!(recovered_pending.next_offset, 3);
        let stdout_reopened = open_request(
            &owner,
            "session-stdout",
            "source-stdout",
            "STDOUT",
            generation,
            32,
            8,
        );
        let reopened = block_on(store.open_process_stream_stage(stdout_reopened))
            .expect("reopen exact stdout identity after restart");
        assert_eq!(reopened.preview_bytes, b"out");
        assert_eq!(reopened.next_sequence, 2);
        let mut changed_operation = open_request(
            &owner,
            "session-stdout",
            "source-stdout",
            "STDOUT",
            generation,
            32,
            8,
        );
        changed_operation.stage_context.operation.idempotency_key =
            "different-current-operation".to_owned();
        assert_eq!(
            block_on(store.open_process_stream_stage(changed_operation)),
            Err(BlobError::IdempotencyConflict)
        );
        let stale_resource_generation = if generation == u64::MAX {
            generation - 1
        } else {
            generation + 1
        };
        let stale_generation = open_request(
            &owner,
            "session-stdout",
            "source-stdout",
            "STDOUT",
            stale_resource_generation,
            32,
            8,
        );
        assert_eq!(
            block_on(store.open_process_stream_stage(stale_generation)),
            Err(BlobError::StaleFence)
        );
        let stdout_readback = block_on(store.resume_process_stream_stage(
            BlobProcessStreamStageResumeRequest {
                session_id: stdout.session_id.clone(),
                source_id: stdout.source_id.clone(),
                terminal_id: stdout.terminal_id.clone(),
                open_request_sha256: stdout.open_request_sha256.clone(),
            },
        ))
        .expect("recover stdout after restart");
        assert_eq!(stdout_readback.preview_bytes, b"out");
        assert_eq!(stdout_readback.next_sequence, 2);
        let stderr_readback = block_on(store.resume_process_stream_stage(
            BlobProcessStreamStageResumeRequest {
                session_id: stderr.session_id.clone(),
                source_id: stderr.source_id.clone(),
                terminal_id: stderr.terminal_id.clone(),
                open_request_sha256: stderr.open_request_sha256.clone(),
            },
        ))
        .expect("recover stderr after restart");
        assert_eq!(stderr_readback.preview_bytes, b"err");
        let after_restart = append(&stdout, 2, 3, b"put");
        // Model a process crash after the durable commit and before the caller
        // observes its acknowledgement: discard the first result, restart the
        // service, then retry the original operation and require the same
        // committed receipt without duplicating bytes.
        let lost_ack_result = block_on(store.append_process_stream_stage(after_restart.clone()))
            .expect("append commits before simulated lost acknowledgement");
        drop(lost_ack_result);
        drop(store);
        drop(owner);
        let owner = BlobRootOwner::claim(
            root.to_string_lossy().into_owned(),
            "process-stream-owner",
            std::process::id(),
        )
        .expect("reclaim after lost append acknowledgement");
        let store = service(&root, &owner, &stdout);
        let replayed_receipt = block_on(store.append_process_stream_stage(after_restart))
            .expect("exact retry resolves the committed append after restart");
        assert_eq!(replayed_receipt.sequence, 2);
        assert_eq!(replayed_receipt.next_offset, 6);
        let after_append = block_on(store.resume_process_stream_stage(
            BlobProcessStreamStageResumeRequest {
                session_id: stdout.session_id.clone(),
                source_id: stdout.source_id.clone(),
                terminal_id: stdout.terminal_id.clone(),
                open_request_sha256: stdout.open_request_sha256.clone(),
            },
        ))
        .expect("read exact append frontier");
        assert_eq!(after_append.preview_bytes, b"output");
        let wrong_session = block_on(store.resume_process_stream_stage(
            BlobProcessStreamStageResumeRequest {
                session_id: stdout.session_id.clone(),
                source_id: stderr.source_id.clone(),
                terminal_id: stdout.terminal_id.clone(),
                open_request_sha256: stdout.open_request_sha256.clone(),
            },
        ));
        assert_eq!(wrong_session, Err(BlobError::NotFound));
        assert_eq!(stdout_readback.terminal, None);
        assert_ne!(stdout_readback.session.root_lease.lease_id, owner.lease_for_request(
            stdout.stage_context.request.clone()
        ).expect("new owner lease").lease_id);
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(root).expect("remove isolated Blob root");
    }

    #[test]
    fn finalization_promotes_bounded_source_larger_than_queue_and_preview_after_restart() {
        let root = isolated_root();
        let generation = windows_root_generation(&root);
        let owner = BlobRootOwner::claim(
            root.to_string_lossy().into_owned(),
            "process-stream-finalize-owner",
            std::process::id(),
        )
        .expect("exclusive root claim");
        let mut session = open_request(
            &owner,
            "session-finalize-bounded",
            "source-finalize-bounded",
            "STDOUT",
            generation,
            128 * 1024,
            8 * 1024,
        );
        session.max_chunks = 64;
        session.max_preview_bytes = 4 * 1024;
        let bytes: Vec<u8> = (0..128 * 1024)
            .map(|index| (index % 251) as u8)
            .collect();
        let store = service(&root, &owner, &session);
        block_on(store.open_process_stream_stage(session.clone())).expect("open durable stage");
        for (sequence, chunk) in bytes.chunks(8 * 1024).enumerate() {
            let offset = u64::try_from(sequence * 8 * 1024).expect("bounded offset");
            block_on(store.append_process_stream_stage(append(
                &session,
                u64::try_from(sequence).expect("bounded sequence"),
                offset,
                chunk,
            )))
            .expect("persist bounded append before acknowledgement");
        }
        let finalize_request = finalize(&session, 16, &bytes);
        let ready = block_on(store.finalize_process_stream_stage(finalize_request.clone()))
            .expect("owner promotes the exact durable source");
        assert_eq!(ready.plaintext_sha256(), sha256(&bytes));
        assert_eq!(ready.plaintext_length(), bytes.len() as u64);
        let read_context = context("READ", "stream-finalize-range-read", generation);
        let read_lease = owner
            .lease_for_request(read_context.request.clone())
            .expect("current source read lease");
        let source = BlobProcessStreamReadbackRequest {
            session_id: session.session_id.clone(),
            terminal_id: session.terminal_id.clone(),
            open_request_sha256: session.open_request_sha256.clone(),
            process_source_binding: session.process_source_binding.clone(),
            expected_content_hash: ready.locator().hash.clone(),
            expected_plaintext_sha256: ready.plaintext_sha256().to_owned(),
            expected_plaintext_length: ready.plaintext_length(),
            ready_receipt_id: ready.receipt().identity.receipt_id.to_string(),
            max_bytes: bytes.len() as u64,
        };
        let range_request = BlobProcessStreamReadbackRangeRequest {
            source: source.clone(),
            offset: 13,
            max_chunk_bytes: 17,
        };
        let range = block_on(store.read_process_stream_source_authorized_range_context(
            range_request,
            read_context.clone(),
            read_lease.clone(),
        ))
        .expect("owner returns only the bounded source range");
        assert_eq!(range.offset(), 13);
        assert_eq!(range.bytes(), &bytes[13..30]);
        range.validate().expect("range retains the full-source read receipt");
        assert_eq!(range.ready_receipt().plaintext_sha256(), sha256(&bytes));
        assert_eq!(range.ready_receipt().plaintext_length(), bytes.len() as u64);
        assert_eq!(
            range
                .ready_receipt()
                .receipt()
                .identity
                .receipt_id
                .as_str(),
            ready.receipt().identity.receipt_id.as_str()
        );
        assert!(range.clone().bounded_range(1, 2).is_err());
        assert!(block_on(store.read_process_stream_source_authorized_range_context(
            BlobProcessStreamReadbackRangeRequest {
                source,
                offset: bytes.len() as u64 + 1,
                max_chunk_bytes: 17,
            },
            read_context,
            read_lease,
        ))
        .is_err());
        let first_receipt_id = ready.receipt().identity.receipt_id.to_string();
        drop(store);
        drop(owner);

        // 128 KiB exceeds the executor's 64 KiB in-flight queue ceiling and
        // the owner's 4 KiB preview. Restart recovery must still promote the
        // exact durable append prefix under the original Stage operation.
        let owner = BlobRootOwner::claim(
            root.to_string_lossy().into_owned(),
            "process-stream-finalize-owner",
            std::process::id(),
        )
        .expect("reclaim after finalized source");
        let mut reopened = open_request(
            &owner,
            "session-finalize-bounded",
            "source-finalize-bounded",
            "STDOUT",
            generation,
            128 * 1024,
            8 * 1024,
        );
        reopened.max_chunks = 64;
        reopened.max_preview_bytes = 4 * 1024;
        let store = service(&root, &owner, &reopened);
        let snapshot = block_on(store.open_process_stream_stage(reopened.clone()))
            .expect("recover the original stage after restart");
        assert_eq!(snapshot.preview_bytes, bytes[..4 * 1024]);
        assert_eq!(snapshot.next_sequence, 16);
        assert_eq!(snapshot.sha256, sha256(&bytes));
        assert_eq!(snapshot.finalize_intent.as_ref(), Some(&finalize_request));
        assert!(matches!(
            block_on(store.append_process_stream_stage(append(
                &reopened,
                16,
                bytes.len() as u64,
                b"late"
            ))),
            Err(BlobError::IdempotencyConflict)
        ));
        let recovered = block_on(store.finalize_process_stream_stage(finalize_request.clone()))
            .expect("same finalization identity resolves after restart");
        assert_eq!(recovered.plaintext_sha256(), sha256(&bytes));
        assert_eq!(recovered.plaintext_length(), bytes.len() as u64);
        assert_eq!(
            recovered.receipt().identity.receipt_id.to_string(),
            first_receipt_id
        );
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(root).expect("remove isolated Blob root");
    }

    #[test]
    fn persisted_finalize_intent_survives_restart_and_refuses_competing_abort() {
        let root = isolated_root();
        let generation = windows_root_generation(&root);
        let owner = BlobRootOwner::claim(
            root.to_string_lossy().into_owned(),
            "process-stream-finalize-restart-owner",
            std::process::id(),
        )
        .expect("exclusive root claim");
        let mut session = open_request(
            &owner,
            "session-finalize-intent-restart",
            "source-finalize-intent-restart",
            "STDOUT",
            generation,
            32,
            32,
        );
        let process_open = process_open_request(&session);
        bind_process_open(&mut session, &process_open);
        let process_session = ProcessStreamSinkSession::from_open_request(process_open)
            .expect("mint the exact process sink session");
        let bytes = b"persisted finalization intent";
        let append_request = append(&session, 0, 0, bytes);
        let process_finalize_request = ProcessStreamSinkFinalizeRequest::new(
            process_session.terminal_id().clone(),
            1,
            bytes.len() as u64,
            1,
            StreamTransportStatus::Complete,
            sha256(bytes),
            bytes.len() as u64,
            ProcessStreamPrefixPreview::from_transport_prefix(
                bytes.to_vec(),
                bytes.len() as u64,
            )
            .expect("exact original Finalize preview"),
            None,
            Vec::new(),
        )
        .expect("typed original Finalize terminal command");
        let finalize_request = BlobProcessStreamStageFinalizeRequest {
            session: resume_request(&session),
            terminal_command_sha256: process_finalize_request
                .command_identity()
                .expect("original Finalize command identity")
                .request_sha256()
                .to_owned(),
            final_sequence: 1,
            final_offset: bytes.len() as u64,
            admitted_sha256: sha256(bytes),
        };

        let store = service_with_disk_full_at_blob_payload_publication(&root, &owner, &session);
        block_on(store.open_process_stream_stage(session.clone())).expect("open durable stage");
        block_on(store.append_process_stream_stage(append_request))
            .expect("persist exact process output");
        match block_on(store.finalize_process_stream_stage(finalize_request.clone()))
            .expect_err("fault occurs after durable Finalize intent")
        {
            BlobError::StorageCapacity { failure } => {
                assert_eq!(failure.stage, BlobCapacityStage::PayloadWrite);
                assert_eq!(
                    failure.evidence.cause,
                    BlobCapacityCause::WindowsErrorDiskFull { code: 112 }
                );
            }
            other => panic!("expected injected payload publication failure, got {other:?}"),
        }
        drop(store);
        drop(owner);

        // A normal owner restart recovers the actual durable StageOpen,
        // committed append prefix, and original Finalize intent.
        let owner = BlobRootOwner::claim(
            root.to_string_lossy().into_owned(),
            "process-stream-finalize-restart-owner",
            std::process::id(),
        )
        .expect("reclaim after simulated restart");
        let store = service(&root, &owner, &session);
        let resumed = block_on(store.resume_process_stream_stage(resume_request(&session)))
            .expect("ordinary resume reads the durable session after restart");
        assert_eq!(resumed.append_receipts.len(), 1);
        assert_eq!(resumed.next_sequence, 1);
        assert_eq!(resumed.next_offset, bytes.len() as u64);
        assert_eq!(resumed.sha256, sha256(bytes));
        assert_eq!(resumed.finalize_intent.as_ref(), Some(&finalize_request));
        assert_eq!(resumed.terminal, None);

        let competing_abort = abort_terminal(process_session.clone(), bytes);
        let competing_abort_json = canonical_json(&competing_abort);
        assert_eq!(
            block_on(store.record_process_stream_stage_terminal(
                resume_request(&session),
                BlobProcessStreamStageTerminal {
                    terminal_json_sha256: sha256(competing_abort_json.as_bytes()),
                    terminal_json: competing_abort_json,
                    ready_receipt_json: None,
                    ready_receipt_sha256: None,
                },
            )),
            Err(BlobError::IdempotencyConflict),
            "Abort cannot replace an exact persisted Finalize intent"
        );
        let after_abort = block_on(store.resume_process_stream_stage(resume_request(&session)))
            .expect("resume remains readable after Abort refusal");
        assert_eq!(after_abort.finalize_intent.as_ref(), Some(&finalize_request));
        assert_eq!(after_abort.terminal, None);

        let ready = block_on(store.finalize_process_stream_stage(finalize_request.clone()))
            .expect("the original same-operation Finalize resolves the Ready object");
        assert_eq!(ready.plaintext_sha256(), sha256(bytes));
        assert_eq!(ready.plaintext_length(), bytes.len() as u64);
        let complete_terminal =
            complete_terminal(process_session, process_finalize_request, bytes, &ready);
        block_on(store.record_process_stream_stage_terminal(
            resume_request(&session),
            complete_terminal,
        ))
        .expect("persist owner-backed CompleteSource terminal and exact Ready receipt");
        drop(store);
        drop(owner);

        // The terminal lookup and Finalize reconciliation are both durable
        // across a second normal service/owner restart.
        let owner = BlobRootOwner::claim(
            root.to_string_lossy().into_owned(),
            "process-stream-finalize-restart-owner",
            std::process::id(),
        )
        .expect("reclaim after persisted CompleteSource terminal");
        let store = service(&root, &owner, &session);
        let terminal_readback =
            block_on(store.resume_process_stream_stage(resume_request(&session)))
                .expect("ordinary resume reads the persisted terminal after restart");
        let persisted_terminal = terminal_readback
            .terminal
            .expect("CompleteSource terminal survived restart");
        persisted_terminal.validate().expect("terminal remains valid");
        assert_eq!(
            terminal_readback.finalize_intent.as_ref(),
            Some(&finalize_request)
        );
        let ready_after_restart =
            block_on(store.finalize_process_stream_stage(finalize_request))
                .expect("exact original Finalize returns the original Ready receipt");
        assert_eq!(ready_after_restart, ready);

        let read_context = context("READ", "finalize-intent-restart-readback", generation);
        let read_lease = owner
            .lease_for_request(read_context.request.clone())
            .expect("current read lease");
        let readback = block_on(store.read_process_stream_source_authorized_range_context(
            BlobProcessStreamReadbackRangeRequest {
                source: BlobProcessStreamReadbackRequest {
                    session_id: session.session_id.clone(),
                    terminal_id: session.terminal_id.clone(),
                    open_request_sha256: session.open_request_sha256.clone(),
                    process_source_binding: session.process_source_binding.clone(),
                    expected_content_hash: ready.locator().hash.clone(),
                    expected_plaintext_sha256: ready.plaintext_sha256().to_owned(),
                    expected_plaintext_length: ready.plaintext_length(),
                    ready_receipt_id: ready.receipt().identity.receipt_id.to_string(),
                    max_bytes: bytes.len() as u64,
                },
                offset: 0,
                max_chunk_bytes: bytes.len() as u64,
            },
            read_context,
            read_lease,
        ))
        .expect("authorized Ready readback from the restarted Blob owner");
        assert_eq!(readback.bytes(), bytes);
        assert_eq!(
            readback.ready_receipt().receipt().identity.receipt_id,
            ready.receipt().identity.receipt_id
        );
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(root).expect("remove isolated Blob root");
    }

    #[test]
    fn process_stream_stage_rejects_unbounded_chunk_and_preview_limits() {
        let root = isolated_root();
        let generation = windows_root_generation(&root);
        let owner = BlobRootOwner::claim(
            root.to_string_lossy().into_owned(),
            "process-stream-bounds-owner",
            std::process::id(),
        )
        .expect("exclusive root claim");
        let mut too_many_chunks = open_request(
            &owner,
            "session-too-many-chunks",
            "source-too-many-chunks",
            "STDOUT",
            generation,
            32 * 1024 * 1024,
            1024,
        );
        too_many_chunks.max_chunks = BLOB_PROCESS_STREAM_STAGE_MAX_CHUNKS + 1;
        assert!(too_many_chunks.validate().is_err());

        let mut oversized_preview = open_request(
            &owner,
            "session-oversized-preview",
            "source-oversized-preview",
            "STDOUT",
            generation,
            32 * 1024 * 1024,
            1024,
        );
        oversized_preview.max_preview_bytes = BLOB_PROCESS_STREAM_STAGE_MAX_PREVIEW_BYTES + 1;
        assert!(oversized_preview.validate().is_err());
        drop(owner);
        std::fs::remove_dir_all(root).expect("remove isolated Blob root");
    }

    #[test]
    fn zero_byte_source_can_be_promoted_under_its_exact_stage_identity() {
        let root = isolated_root();
        let generation = windows_root_generation(&root);
        let owner = BlobRootOwner::claim(
            root.to_string_lossy().into_owned(),
            "process-stream-empty-owner",
            std::process::id(),
        )
        .expect("exclusive root claim");
        let session = open_request(
            &owner,
            "session-empty-source",
            "source-empty-source",
            "STDOUT",
            generation,
            32,
            8,
        );
        let store = service(&root, &owner, &session);
        block_on(store.open_process_stream_stage(session.clone())).expect("open empty stage");
        let ready = block_on(store.finalize_process_stream_stage(finalize(&session, 0, b"")))
            .expect("promote exact zero-byte source");
        assert_eq!(ready.plaintext_sha256(), sha256(b""));
        assert_eq!(ready.plaintext_length(), 0);
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(root).expect("remove isolated Blob root");
    }

    #[test]
    fn omitted_prefix_is_refused_before_it_can_reserve_finalization_identity() {
        let root = isolated_root();
        let generation = windows_root_generation(&root);
        let owner = BlobRootOwner::claim(
            root.to_string_lossy().into_owned(),
            "process-stream-omission-owner",
            std::process::id(),
        )
        .expect("exclusive root claim");
        let session = open_request(
            &owner,
            "session-omission",
            "source-omission",
            "STDOUT",
            generation,
            32,
            8,
        );
        let store = service(&root, &owner, &session);
        block_on(store.open_process_stream_stage(session.clone())).expect("open stage");
        block_on(store.append_process_stream_stage(append(&session, 0, 0, b"prefix")))
            .expect("persist prefix");
        assert!(matches!(
            block_on(store.finalize_process_stream_stage(finalize(
                &session,
                2,
                b"prefix-suffix",
            ))),
            Err(BlobError::MetadataPayloadMismatch)
        ));
        block_on(store.append_process_stream_stage(append(&session, 1, 6, b"-suffix")))
            .expect("append the previously omitted suffix");
        let ready = block_on(store.finalize_process_stream_stage(finalize(
            &session,
            2,
            b"prefix-suffix",
        )))
        .expect("valid complete frontier remains promotable");
        assert_eq!(ready.plaintext_sha256(), sha256(b"prefix-suffix"));
        assert_eq!(ready.plaintext_length(), 13);
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(root).expect("remove isolated Blob root");
    }

    #[test]
    fn typed_disk_full_keeps_pending_append_unknown_until_same_operation_reconciles() {
        let root = isolated_root();
        let generation = windows_root_generation(&root);
        let owner = BlobRootOwner::claim(
            root.to_string_lossy().into_owned(),
            "process-stream-capacity-owner",
            std::process::id(),
        )
        .expect("exclusive root claim");
        let session = open_request(
            &owner,
            "session-disk-full",
            "source-disk-full",
            "STDOUT",
            generation,
            32,
            8,
        );
        let store = service_with_disk_full_at_chunk_publication(&root, &owner, &session);
        block_on(store.open_process_stream_stage(session.clone())).expect("open stream");
        let append_request = append(&session, 0, 0, b"durable-prefix");
        let failure = block_on(store.append_process_stream_stage(append_request.clone()))
            .expect_err("injected ENOSPC at ciphertext publication");
        match failure {
            BlobError::StorageCapacity { failure } => {
                assert_eq!(failure.stage, BlobCapacityStage::PayloadWrite);
                assert_eq!(
                    failure.evidence.cause,
                    BlobCapacityCause::WindowsErrorDiskFull { code: 112 }
                );
                assert_eq!(
                    failure.evidence.effect,
                    BlobCapacityEffect::NotAttempted
                );
                assert!(failure
                    .evidence
                    .attempted_bytes
                    .is_some_and(|attempted| attempted >= b"durable-prefix".len() as u64));
                assert_eq!(
                    failure.recovery,
                    BlobCapacityRecovery::CapacityRevalidationRequired
                );
            }
            other => panic!("expected typed storage-full failure, got {other:?}"),
        }
        assert!(matches!(
            block_on(store.resume_process_stream_stage(BlobProcessStreamStageResumeRequest {
                session_id: session.session_id.clone(),
                source_id: session.source_id.clone(),
                terminal_id: session.terminal_id.clone(),
                open_request_sha256: session.open_request_sha256.clone(),
            })),
            Err(BlobError::UnknownStreamAppendOutcome { sequence: 0, .. })
        ));
        drop(store);
        drop(owner);

        let owner = BlobRootOwner::claim(
            root.to_string_lossy().into_owned(),
            "process-stream-capacity-owner",
            std::process::id(),
        )
        .expect("reclaim after typed storage-full outcome");
        let store = service(&root, &owner, &session);
        let receipt = block_on(store.append_process_stream_stage(append_request))
            .expect("retry exact pending operation after capacity revalidation");
        assert_eq!(receipt.sequence, 0);
        assert_eq!(receipt.next_offset, 14);
        let recovered = block_on(store.resume_process_stream_stage(
            BlobProcessStreamStageResumeRequest {
                session_id: session.session_id.clone(),
                source_id: session.source_id.clone(),
                terminal_id: session.terminal_id.clone(),
                open_request_sha256: session.open_request_sha256.clone(),
            },
        ))
        .expect("readback reconciled append");
        assert_eq!(recovered.preview_bytes, b"durable-prefix");
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(root).expect("remove isolated Blob root");
    }
}
