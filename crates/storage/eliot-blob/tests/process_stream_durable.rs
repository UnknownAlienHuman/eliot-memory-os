//! Durable process-stream staging against the real Windows filesystem and
//! current-user DPAPI adapters. These checks exercise the same Blob owner
//! methods used by Store IPC, including exact retry and restart recovery.

#[cfg(windows)]
mod windows_durable_owner {
    use std::future::Future;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll, Waker};

    use eliot_blob::{
        BlobRootOwner, BlobServicePorts, BlobStoreService, DpapiUserAeadPort, DpapiUserKeyPort,
        RleCompressionPort, UnavailableBlobLiveSetPort, WindowsBlobPlatformPort,
    };
    use eliot_blob_api::{
        BlobError, BlobHash, BlobId, BlobPolicyBinding, BlobProcessStreamSourceBinding,
        BlobProcessStreamStageAppendRequest, BlobProcessStreamStageOpenRequest,
        BlobProcessStreamStageResumeRequest, BlobReceiptContext, BlobStoreClient, ObjectResidencyKey,
        RetentionClass, VersionedContentDigest,
    };
    use eliot_platform::PlatformHandle;
    use eliot_platform_windows::{WindowsBlobStorePlatform, WindowsPlatform};
    use eliot_security_contracts::{EffectCeiling, InstructionTaint, PrivacyClass};
    use sha2::{Digest, Sha256};

    static ROOT_COUNTER: AtomicU64 = AtomicU64::new(1);

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
        let read_context = context("READ", &format!("{session_id}-read"), generation);
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
            read_context,
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

    fn isolated_root() -> PathBuf {
        let suffix = ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "eliot-1969-process-stream-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("isolated Blob root");
        path
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
        assert_eq!(stdout_open.bytes, b"");
        assert_eq!(stderr_open.bytes, b"");

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
        block_on(store.append_process_stream_stage(second)).expect("stderr append");
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
        assert_eq!(reopened.bytes, b"out");
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
        assert_eq!(stdout_readback.bytes, b"out");
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
        assert_eq!(stderr_readback.bytes, b"err");
        let after_restart = append(&stdout, 2, 3, b"put");
        block_on(store.append_process_stream_stage(after_restart)).expect("append after restart");
        let after_append = block_on(store.resume_process_stream_stage(
            BlobProcessStreamStageResumeRequest {
                session_id: stdout.session_id.clone(),
                source_id: stdout.source_id.clone(),
                terminal_id: stdout.terminal_id.clone(),
                open_request_sha256: stdout.open_request_sha256.clone(),
            },
        ))
        .expect("read exact append frontier");
        assert_eq!(after_append.bytes, b"output");
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
}
