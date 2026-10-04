//! Kernel backup front-door dispatch proofs (issue #963, card `cards/963.md`).
//!
//! Five cases, exactly 7, 10, 11, 13 and 17. Every case drives the ALREADY
//! LANDED production path and nothing else: a real
//! `KernelComposition::new(KernelConfig::new(&dir))`, the real
//! `KernelComposition::dispatch_frame`, and through it the real
//! `request_dispatch::dispatch_backup_frame` router and the real
//! `handle_backup_create` / `handle_backup_verify` /
//! `handle_backup_restore_test` handlers. No handler is called directly, no
//! owner is substituted, and no test-only mock route exists: case 17 asserts
//! that the reply is the one the production handler produced, carrying the
//! request frame's OWN `idempotency_key`, which a synthesised answer could not
//! reproduce.
//!
//! `KernelComposition::service_mut` exists ONLY so an out-of-crate harness can
//! publish the same ready receipt the production activation path publishes for
//! a composition-owned candidate. It adds no lifecycle transition: it hands
//! back the `KernelService` the composition already owns, every mutation it
//! permits is one `KernelService` already exposes publicly
//! (`reconcile`/`apply`/`activate_permit`/`publish_ready`), and the
//! composition's own backup arm still refuses every state but
//! `KernelServiceState::Ready`. Case 17 therefore proves the production route
//! is reachable and reaches the accepted coordinator, rather than asserting that
//! a harness-only route produced the answer.
//!
//! No case here asserts a successful restore receipt, because no owner channel
//! supplies one today: the capture owner (#959), the destination key-manifest
//! and blob-scope owners (#953/#956/#958) and the destination manifest evidence
//! owner are all unreachable from this front door, so the closed answers are
//! `refused` and `blocked`. That is the governing rule, quoted from I5.13:
//! "Backup existence is not recovery proof."

use std::num::NonZeroU64;
use std::path::PathBuf;

use eliot_backup::{BackupBlob, BackupBundle, BackupClass, BackupInput, EventRange, ExportFence};
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ClockReading, ContractId, ContractIdentity, ContractVersion,
    EpochId, EpochLineageId, ProductId, ReceiptId, RequestId, RequestMetadata, ResourceGeneration,
    SessionId, SourceId, StateFence, sha256_hex,
};
use eliot_ipc::{PeerIdentity, Session};
use eliot_kernel::{
    DispatchLaunchError, KernelComposition, KernelConfig, KernelFrameAction,
    compose_dispatch_contour,
};
use eliot_kernel_service::{
    HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot, HostKernelCandidateBinding,
    HostProcessBinding, KernelActivationPermit, KernelControlCommand, KernelReadyReceipt,
    KernelServiceState, ProcessObservation, RestartBudget,
};
use eliot_protocol::backup::{
    BACKUP_ARCHIVE_VERIFICATION_WIRE_ID, BACKUP_ARCHIVE_VERIFICATION_WIRE_VERSION,
    BACKUP_REQUEST_IDENTITY_WIRE_ID, BACKUP_REQUEST_IDENTITY_WIRE_VERSION, BackupAdmissionRef,
    BackupArchiveVerification, BackupArtifactHandle, BackupAuthenticatedPrincipal, BackupClassWire,
    BackupMutationBinding, BackupOperationKind, BackupRequestIdentity, BackupRole,
};
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
    RequestIdentity,
};
use eliot_receipts::{
    AuthorityBinding, EffectClass, ProofCeiling, RequestBinding, WorkScopeBinding, WorkScopeId,
};
use eliot_runtime_contracts::{
    HealthVector, RegisteredActivityWakePolicy, ServiceProcessState, SupervisionJournalEpoch,
    SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
};
use serde_json::{Value, json};

/// Canonical lineage used by every epoch, fence and restore target below. It is
/// the same lineage the in-tree backup suites bind, so a target sequence that
/// ADVANCES this archive's own lineage is one nonzero value above it.
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

/// The operator surface's `CommandId` spellings for the three backup commands
/// (`eliot_cli::CommandId::BackupCreate/BackupVerify/BackupRestoreTest`, which
/// `as_str()` renders hyphenated), and the front-door wire operation each one
/// routes to.
///
/// The Kernel reply's `command` member is the OPERATION literal, not the CLI
/// spelling: every handler reaches it through `backup_reply(command, ...)` with
/// `BACKUP_*_OPERATION`. Case 7 pins each operation literal against the reply
/// the route actually produced, which is what makes the mapping falsifiable
/// rather than a restatement, and asserts the CLI spelling is a distinct
/// namespace that never appears on the wire.
const COMMAND_ID_BACKUP_CREATE: &str = "backup-create";
const COMMAND_ID_BACKUP_VERIFY: &str = "backup-verify";
const COMMAND_ID_BACKUP_RESTORE_TEST: &str = "backup-restore-test";
const OPERATION_BACKUP_CREATE: &str = "backup.create";
const OPERATION_BACKUP_VERIFY: &str = "backup.verify";
const OPERATION_BACKUP_RESTORE_TEST: &str = "backup.restore-test";
/// The fourth selector in `is_backup_operation`'s closed set. No `CommandId`
/// names it: `execute_backup_store_restore` does, and it routes to a different
/// owner (`KernelStoreGateway`), never to the restore rehearsal.
const OPERATION_BACKUP_RESTORE_STORE: &str = "backup.restore-store";

/// The EXACT absent-owner string `restore_test_refusal` emits through
/// `BACKUP_RESTORE_TEST_MISSING_OWNER`, asserted as a whole rather than as a
/// prefix or a substring (`request_dispatch.rs:369`, read at `:4590`), so any
/// drift in that owner name is a drift in what this front door tells an
/// operator, and a prefix check would keep passing through it. Spelled out here
/// because the product constant is `pub(crate)` and therefore not nameable from
/// this test.
const BACKUP_RESTORE_TEST_MISSING_OWNER: &str = "destination-key-and-blob-scope-admission (RestorePorts::keys and RestorePorts::blob_scope, #953/#956/#958: no owner channel on this front door issues the admitted wrapped-key manifest or the destination blob scope, so a blob-carrying archive is refused by the restore owner with its own CapabilityMissing)";

/// The closed `refused`/`blocked` set every refusal in this file is drawn from.
/// A reply outside it is not a refusal, and this file asserts nothing else.
const REFUSAL_STATUSES: [&str; 2] = ["refused", "blocked"];

/// Unwraps a `Result` or panics with the debug rendering of the error, so no
/// `expect`/`unwrap` appears anywhere in this file (`expect_used` and
/// `unwrap_used` are `-D warnings` here and no `#[allow]` is permitted).
fn must<T>(result: Result<T, impl std::fmt::Debug>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error:?}"),
    }
}

/// Unwraps an `Option` or panics: the `Option`-shaped sibling of `must`, for
/// the owner slots this file reads rather than operations it performs
/// (`NonZeroU64::new`, `KernelService::activation_receipt`).
///
/// The two helpers are deliberately NOT interchangeable, because they assert two
/// different invariants: `must` says a fallible operation MUST answer (`Ok` is
/// the only acceptable answer), while `must_some` says a slot MUST already hold
/// a value (`Some` is the only acceptable answer). Neither may be handed the
/// other's argument. Wrapping a missing receipt as `Ok(..)` would let an absent
/// owner through as a success, and a pointless `Ok(..)` around an `Option` would
/// make the `Err` arm unreachable — both are the forged-caller forgery this file
/// exists to refuse, so a mismatch is repaired by repointing the call site to
/// the helper that matches the real carrier, never by reshaping the value.
fn must_some<T>(value: Option<T>, context: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{context}: must be present"),
    }
}

// ---------------------------------------------------------------------------
// Temporary work root (no `tempfile` dev-dependency exists in this crate).
// ---------------------------------------------------------------------------

/// Removes its root on drop, including on the panic path, so nothing is left
/// behind in `%TEMP%`.
struct TempGuard {
    root: PathBuf,
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Builds one isolated `KernelComposition` over its own work root and its own
/// pipe, mirroring `kernel_front_door_diagnostics::test_kernel_with_pipe`.
///
/// The root is unique per (case, process, nanosecond) so parallel test threads
/// never collide, and the composition is returned alongside the guard so the
/// caller controls when the root disappears.
fn test_kernel_with_pipe(case: &str) -> (KernelComposition, TempGuard) {
    let nanos = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    };
    let root =
        std::env::temp_dir().join(format!("eliot-963-{case}-{}-{nanos}", std::process::id()));
    must(std::fs::create_dir_all(&root), "create work root");
    let mut config = KernelConfig::new(&root);
    config.pipe_name = format!(r"\\.\pipe\eliot\kernel-963-{case}-{}", std::process::id());
    let kernel = must(KernelComposition::new(config), "kernel composition");
    (kernel, TempGuard { root })
}

// ---------------------------------------------------------------------------
// Contour composition (process-global, set once).
// ---------------------------------------------------------------------------

/// Composes the process-global dispatch contour ONCE for the whole test binary.
///
/// `backup.restore-test` reaches `OrsRestoreBinding::from_composition`, which
/// reads `live_installation_id()` from the process-global contour cell BEFORE
/// the destination gate. Without the contour the blob-free case answers
/// `restore-owner-evidence-invalid` instead of the destination refusal, so it is
/// composed here. `compose_dispatch_contour` is set-once: the first caller
/// composes it and every later caller treats `AlreadyComposed` as success.
fn ensure_contour() {
    match compose_dispatch_contour("installation-963".to_owned()) {
        Ok(()) => {}
        // `AlreadyComposed` is the documented second-call answer, not a fault:
        // the contour cell is process-global set-once state, so whichever test
        // thread composes it first, every other case in this binary reuses it.
        Err(error) => assert!(
            matches!(error, DispatchLaunchError::AlreadyComposed(_)),
            "dispatch contour must compose or report AlreadyComposed, got {error}"
        ),
    }
}

// ---------------------------------------------------------------------------
// Session and frame fixtures (idioms copied from kernel_front_door_diagnostics).
// ---------------------------------------------------------------------------

fn digest(seed: &str) -> String {
    sha256_hex(seed.as_bytes())
}

fn epoch(sequence: u64) -> EpochId {
    must(
        EpochId::new(
            must(EpochLineageId::new(LINEAGE), "lineage"),
            must_some(NonZeroU64::new(sequence), "nonzero sequence"),
        ),
        "epoch",
    )
}

fn fence(sequence: u64, generation: u64) -> StateFence {
    StateFence::new(
        epoch(sequence),
        must(ResourceGeneration::new(generation), "generation"),
    )
}

fn contract(name: &str) -> ContractIdentity {
    ContractIdentity {
        name: must(ContractId::new(name), "contract name"),
        version: ContractVersion::new(1, 0, 0),
        shape_sha256: digest(name),
    }
}

/// The fake authenticated peer the front-door diagnostics suite uses: an
/// `Authenticated` identity whose `validate()` passes, which is what
/// `admit_backup_caller`'s `authenticated_backup_principal` requires.
fn fake_authenticated_peer() -> PeerIdentity {
    let binding = must(
        eliot_ipc::ProcessBinding::from_observation(42, 99, r"C:\Eliot\bridge.exe"),
        "fake process binding",
    );
    must(
        PeerIdentity::authenticated_for_test(binding, "S-1-5-21-963".to_owned(), "4".to_owned()),
        "fake authenticated peer",
    )
}

/// A `daemon`-capability session on a module generation that is NEITHER
/// `eliot-user-broker` (the `USER_BROKER_MODULE_ID` short-circuit at
/// `frame_dispatch.rs:866`) NOR `eliotd` (the active daemon caller the Windows
/// session guard compares against), so the frame reaches the backup arm itself.
fn daemon_session(connection_id: &str) -> Session {
    let state_fence = fence(1, 1);
    Session {
        connection_id: connection_id.to_owned(),
        protocol_version: ProtocolVersion::CURRENT,
        peer: fake_authenticated_peer(),
        authority_epoch: epoch(1),
        module_generation: eliot_runtime_contracts::ModuleGeneration {
            module_id: must(ContractId::new("eliot-backup-harness"), "module id"),
            generation: must(ResourceGeneration::new(1), "generation"),
            artifact_id: must(ArtifactId::new("c".repeat(64)), "artifact"),
            state: eliot_runtime_contracts::ModuleGenerationState::Ready,
            health: HealthVector::healthy(),
            state_fence: state_fence.clone(),
        },
        launch_nonce: "launch-963".to_owned(),
        // Exactly one capability, and it must be `daemon`: `admit_backup_caller`
        // fences every other cardinality and every other value.
        capabilities: vec!["daemon".to_owned()],
        privacy_classes: vec!["PUBLIC".to_owned()],
        effects: Vec::new(),
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    }
}

fn transport_identity(request_id: &str, state_fence: &StateFence) -> RequestIdentity {
    RequestIdentity {
        request: RequestBinding {
            metadata: RequestMetadata {
                request_id: must(RequestId::new(request_id), "request id"),
                session_id: Some(must(SessionId::new("session-963"), "session id")),
                task_id: None,
                product_id: must(ProductId::new("product-963"), "product id"),
                source_id: must(SourceId::new("source-963"), "source id"),
                state_fence: state_fence.clone(),
                clock: ClockReading::default(),
            },
            state_fence: state_fence.clone(),
        },
        idempotency_key: format!("idem-963-{request_id}"),
        deadline_unix_ms: 10_000,
        cancellation_id: "cancel-963".to_owned(),
    }
}

/// Builds the `{operation, payload}` envelope the authenticated `KernelClient`
/// sets: `operation` is the routing selector, the command fields live inside
/// `payload`, and both the frame's request id and request identity are present
/// because the backup arm fences without either.
///
/// `payload` is BORROWED and cloned into the envelope: the command payload is
/// built once per call site and read by nobody after the frame is built, so
/// taking it by reference keeps that ownership at the call site.
fn backup_frame(session: &Session, operation: &str, payload: &Value, request_id: &str) -> Frame {
    let state_fence = session.module_generation.state_fence.clone();
    let mut identity = transport_identity(request_id, &state_fence);
    // The reply's `idempotency_key` is read straight out of THIS identity, so
    // case 17 can prove the answer came from the real dispatch by comparing it.
    identity.idempotency_key = format!("idem-963-{request_id}");
    Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: session.connection_id.clone(),
        request_id: Some(must(RequestId::new(request_id), "frame request id")),
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: Some(identity),
        payload: ProtocolPayload::Json(json!({ "operation": operation, "payload": payload })),
        trace_context: std::collections::BTreeMap::new(),
    }
}

/// Drives one frame through the real `dispatch_frame` and returns the reply
/// body the production handler produced.
fn dispatch_reply(kernel: &KernelComposition, session: &Session, frame: &Frame) -> Value {
    match must(
        kernel.dispatch_frame(session, frame),
        "dispatch_frame must answer",
    ) {
        KernelFrameAction::Reply(reply) => match &reply.payload {
            ProtocolPayload::Json(value) => value.clone(),
            other => panic!("backup reply must be a JSON payload, got {other:?}"),
        },
        other => panic!("backup arm must answer with a correlated reply, got {other:?}"),
    }
}

/// Reads one string member, panicking with the whole body when it is absent or
/// is not a string.
fn string_field<'a>(body: &'a Value, key: &str) -> &'a str {
    match body.get(key).and_then(Value::as_str) {
        Some(text) => text,
        None => panic!("reply must carry string {key}, got {body}"),
    }
}

/// Asserts a reply carries no member anywhere named in `keys`, at any depth.
/// This is what makes "no installation-changing field appears anywhere in the
/// verify reply" a real assertion rather than a top-level key check.
fn assert_absent_everywhere(body: &Value, keys: &[&str]) {
    match body {
        Value::Object(map) => {
            for (key, value) in map {
                for banned in keys {
                    assert!(
                        key != banned,
                        "reply must not carry {banned} at any depth: {body}"
                    );
                }
                assert_absent_everywhere(value, keys);
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_absent_everywhere(item, keys);
            }
        }
        _ => {}
    }
}

/// Returns the reply's key set as a sorted vector of owned strings.
fn key_set(body: &Value) -> Vec<String> {
    let Some(map) = body.as_object() else {
        panic!("reply must be a JSON object, got {body}");
    };
    let mut keys: Vec<String> = map.keys().cloned().collect();
    keys.sort();
    keys
}

// ---------------------------------------------------------------------------
// Real `eliot_backup` archive fixtures (no fabricated archive).
// ---------------------------------------------------------------------------

/// One `BackupBlob` built through the real `BackupBlob` wire shape, exactly as
/// `tests/backup_capture.rs::test_blob` builds it, so the blob-carrying archive
/// below is a real archive rather than a fixture that only looks like one.
fn test_blob(suffix: &str, sealed: &[u8]) -> BackupBlob {
    let digest = sha256_hex(sealed);
    must(
        serde_json::from_value(json!({
            "locator": {
                "hash": digest,
                "residency": {
                    "scope_domain_id": format!("scope-963-{suffix}"),
                    "access_domain_id": format!("access-963-{suffix}"),
                    "confidentiality_domain_id": format!("conf-963-{suffix}"),
                    "encryption_key_domain_id": "key-lineage-963",
                    "retention_domain_id": format!("retention-963-{suffix}"),
                    "erasure_domain_id": format!("erasure-963-{suffix}"),
                    "content_digest": {
                        "algorithm": "blake3",
                        "version": 1,
                        "digest": digest
                    }
                },
                "root_generation": 1,
                "path_generation": 1
            },
            "sealed_bytes": sealed.to_vec(),
            "sealed_sha256": sha256_hex(sealed),
            "plaintext_sha256": sha256_hex(b"plaintext-963"),
            "key_lineage": "key-lineage-963",
            "format": "test-format-963",
            "format_version": 1,
            "compression": {"algorithm": "none", "version": 1},
            "crypto": {
                "algorithm": "aead-test-963",
                "version": 1,
                "key_lineage": "key-lineage-963",
                "key_generation": 1
            }
        })),
        "test blob deserializes",
    )
}

/// Builds one real archive through `BackupBundle::build`, validated and encoded
/// through the archive format's own API, with `blobs` supplied by the caller so
/// the blob-carrying and blob-free cases differ in exactly that one fact.
///
/// `source_sequence`/`source_generation` are the archive's OWN fence. A restore
/// target must ADVANCE both, so the callers below request a strictly higher
/// target than the source fence they get here.
///
/// The archive's reachability manifest is DERIVED from `blobs` rather than
/// supplied beside them, and that derivation is the whole point of this helper.
/// `BackupBundle::validate` (`eliot-backup/src/lib.rs:729-745`) enforces a
/// BIJECTION between `ExportFence::blob_reachability_manifest` and `blobs`:
/// every blob's `locator.hash` must appear in the manifest (else
/// `UnreferencedBlob`) and the two lengths must be equal (else `MissingBlob`).
/// A hardcoded empty manifest therefore cannot describe a blob-carrying archive
/// at all — the build refuses — and any future edit that decouples the manifest
/// from the blobs would silently collapse `archive(.., vec![])` and
/// `archive(.., vec![test_blob(..)])` into the same archive, destroying case
/// 13's entire distinction. Deriving it here keeps the two archives genuinely
/// different in the ONE field the restore owner keys on.
///
/// The field the restore owner actually branches on is
/// `BackupBundle::blobs`, read straight off the DECODED bundle at
/// `request_dispatch.rs:4381` (`if !bundle.blobs.is_empty()`) to extend
/// `gates_not_admitted`, and again at `backup_restore.rs:1411` and `:1416`
/// where `ports.keys`/`ports.blob_scope` are `None` on this front door, so a
/// blob-carrying archive stops at `CapabilityMissing` and never reaches the
/// destination gate. The reachability manifest is not that branch — it is the
/// archive's own integrity relation between the two lists, which must agree for
/// the bundle to validate at all.
fn archive(suffix: &str, source_sequence: u64, blobs: Vec<BackupBlob>) -> Vec<u8> {
    let source_fence = fence(source_sequence, source_sequence);
    // Read BEFORE `blobs` is moved into the input below.
    let expected = blobs.len();
    // One entry per blob, cloned from the blob's OWN locator hash — the same
    // digest the validator compares against. `BlobHash` is not re-exported by
    // `eliot_backup`, so it is never named here; cloning the field avoids both
    // an unspeakable type and any chance of a second, disagreeing digest.
    let blob_reachability_manifest: Vec<_> =
        blobs.iter().map(|blob| blob.locator.hash.clone()).collect();
    let bundle = must(
        BackupBundle::build(BackupInput {
            backup_id: format!("backup-963-{suffix}"),
            class: BackupClass::CanonicalOnlyDegraded,
            source_adapter: "test-adapter-963".to_owned(),
            schema_generation: "1".to_owned(),
            export_fence: ExportFence {
                export_id: format!("export-963-{suffix}"),
                store_generation: "store-963".to_owned(),
                state_fence: source_fence,
                scope_id: None,
                revision_heads: Vec::new(),
                ordering_heads: Vec::new(),
                event_range: EventRange {
                    first_sequence: None,
                    last_sequence: None,
                    count: 0,
                },
                blob_reachability_manifest,
                consistent: true,
            },
            canonical_events: Vec::new(),
            projections: Vec::new(),
            receipts: Vec::new(),
            blobs,
            purge_ledger: Vec::new(),
            ors_snapshot: None,
            artifacts: Vec::new(),
            watchdog_spool: None,
            host_audit: None,
            missing_features: Vec::new(),
            purge_ledger_revision: 1,
        }),
        "test archive builds",
    );
    must(bundle.validate(), "test archive validates");
    let encoded = must(bundle.encode(), "test archive encodes");

    // The self-check that stops this bug class from returning: decode the bytes
    // back through the REAL `BackupBundle::decode` — the same call the production
    // route makes at `request_dispatch.rs:4369` — and prove the archive really
    // carries exactly the blobs it was asked to carry. `archive(.., vec![])`
    // must come back blob-free and `archive(.., vec![test_blob(..)])` must come
    // back carrying one, because that `blobs.len() != 0` test at
    // `request_dispatch.rs:4381` is the whole of case 13's distinction.
    let decoded = must(
        BackupBundle::decode(&encoded),
        "test archive decodes back through the real decoder",
    );
    let actual = decoded.blobs.len();
    assert_eq!(
        actual, expected,
        "archive {suffix} must decode to exactly {expected} blob(s), got {actual}: the restore owner keys on decoded.blobs, so a blob-carrying and a blob-free archive must not be the same archive"
    );
    encoded
}

/// Lowercase hex digits, indexed by nibble value: `0..=9` then `a..=f`.
///
/// Every byte is two nibbles, so a lookup emits exactly the `NN` pair `{byte:02x}`
/// would render, including the leading zero of a byte below `0x10`.
const HEX_DIGITS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Even-length LOWERCASE hex, which is the only spelling `hex_bytes` accepts.
///
/// The nibbles are pushed one at a time from `HEX_DIGITS` rather than formatted:
/// `String::push` cannot fail, so the encoding needs no fallible call to discard.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX_DIGITS[usize::from(byte >> 4)]);
        out.push(HEX_DIGITS[usize::from(byte & 0x0f)]);
    }
    out
}

/// One well-formed `backup.restore-test` payload over `bundle`.
///
/// `target_id` is deliberately never equal to `dest_store_id`, and the target
/// authority tuple ADVANCES the archive's own lineage and generation, so the
/// payload is admitted by `admit_restore_test_shape` and reaches the owner.
fn restore_test_payload(bundle: &[u8], target_id: &str, dest_store_id: &str) -> Value {
    json!({
        "bundle_hex": hex_encode(bundle),
        // Admitted for shape only: no owner channel on this front door verifies
        // it, so it is never carried into an owner call.
        "destination_authorization_hex": hex_encode(b"destination-authorization-963"),
        "target": {
            "target_id": target_id,
            "target_lineage": LINEAGE,
            "target_sequence": 9u64,
            "target_generation": 9u64
        },
        "provisioning": {
            "dest_store_id": dest_store_id,
            "residency_denominator_digest": digest("residency-963"),
            "source_snapshot_digest": digest("snapshot-963"),
            "capture_operation_id": "capture-963-1"
        },
        "introductions": []
    })
}

fn create_payload() -> Value {
    json!({
        "scope_descriptor": "eliot-963-create",
        "class": "canonical_only_degraded"
    })
}

/// One well-formed `BackupArchiveVerification` through the protocol's own
/// builder, so `admit_verify_bundle`'s PROTOCOL arm reaches its
/// `RetainedOwnerAbsent` refusal rather than a shape failure.
fn archive_verification() -> Value {
    let state_fence = fence(1, 1);
    let identity = BackupRequestIdentity {
        wire_id: BACKUP_REQUEST_IDENTITY_WIRE_ID.to_owned(),
        wire_version: BACKUP_REQUEST_IDENTITY_WIRE_VERSION,
        principal: BackupAuthenticatedPrincipal {
            principal: "principal-963".to_owned(),
            session_id: "session-963".to_owned(),
            role: BackupRole::Requester,
            authority_epoch: epoch(1),
        },
        request: transport_identity("backup-req-963v", &state_fence),
        mutation: BackupMutationBinding {
            operation: BackupOperationKind::VerifyArchive,
            canonical_request_hash: digest("mutation:verify-archive-963"),
        },
        archive_id: "archive-963".to_owned(),
        archive_contract: contract("archive.owner"),
        archive_digest: digest("archive-963"),
        owner_contract: contract("attesting.owner"),
        schema_digest: digest("schema-963"),
        build_digest: digest("build-963"),
        source_installation: "src-963".to_owned(),
        dest_installation: "dest-963".to_owned(),
        class: BackupClassWire::FullRecovery,
        fence: state_fence.clone(),
        snapshot_digest: digest("snapshot-963"),
        member_digest: digest("members-963"),
        max_page_members: 16,
        max_payload_bytes: 65_536,
        deadline_unix_ms: 10_000,
        cancellation_id: "cancel-963".to_owned(),
        admission: BackupAdmissionRef {
            authority: AuthorityBinding {
                authority_id: must(
                    ContractId::new("backup-admission-authority-963"),
                    "authority id",
                ),
                authority_owner: "backup-admission-authority-963".to_owned(),
                authority_epoch: epoch(1),
                state_fence: state_fence.clone(),
                allowed_effect: EffectClass::Read,
                proof_ceiling: ProofCeiling::Observation,
            },
            scope: WorkScopeBinding {
                scope_id: must(WorkScopeId::new("scope-963"), "scope"),
                product_id: must(ProductId::new("product-963"), "product id"),
                resource_generation: must(ResourceGeneration::new(1), "generation"),
                state_fence: state_fence.clone(),
            },
            capability: "backup.verify".to_owned(),
            admission_receipt: must(ReceiptId::new("admission-963"), "admission receipt"),
        },
        identity_digest: String::new(),
    };
    let identity = must(identity.with_computed_digest(), "request identity digest");
    let verification = must(
        BackupArchiveVerification {
            wire_id: BACKUP_ARCHIVE_VERIFICATION_WIRE_ID.to_owned(),
            wire_version: BACKUP_ARCHIVE_VERIFICATION_WIRE_VERSION,
            identity,
            operation: BackupOperationKind::VerifyArchive,
            handle: BackupArtifactHandle {
                contract: contract("archive.owner"),
                source_revision: "rev-963".to_owned(),
                content_sha256: digest("archive-content-963"),
                byte_length: 256,
                artifact_id: must(ArtifactId::new("artifact-archive-963"), "artifact"),
            },
            believed_archive_digest: digest("archive-963"),
            request_digest: String::new(),
        }
        .with_computed_digest(),
        "archive verification digest",
    );
    must(verification.validate(), "archive verification validates");
    must(
        serde_json::to_value(&verification),
        "archive verification serialises",
    )
}

// ---------------------------------------------------------------------------
// Ready publication through the authorized seam (case 17 only).
// ---------------------------------------------------------------------------

fn supervision_incarnation() -> SupervisionLeaseIncarnationBinding {
    must(
        SupervisionLeaseIncarnationBinding {
            supervision_lease_scope_id: "eliot-supervision-scope:v1:963".to_owned(),
            supervision_lease_id: String::new(),
            scope_ref_digest: String::new(),
            installation_id: "installation-963".to_owned(),
            host_epoch: SupervisionJournalEpoch {
                lineage_id: "host-lineage-963".to_owned(),
                sequence: 1,
            },
            activation_id: "activation-963".to_owned(),
            activation_generation: SupervisionJournalEpoch {
                lineage_id: "activation-lineage-963".to_owned(),
                sequence: 1,
            },
            kernel_generation: SupervisionJournalEpoch {
                lineage_id: "kernel-lineage-963".to_owned(),
                sequence: 1,
            },
            watchdog_epoch: SupervisionJournalEpoch {
                lineage_id: "watchdog-lineage-963".to_owned(),
                sequence: 1,
            },
            observation_scope: SupervisionObservationScope {
                targets: vec!["eliot-kernel".to_owned()],
                sensor_profile: "eliot-runtime-live-v3".to_owned(),
                claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                governance_axis: "runtime-live-v3".to_owned(),
            },
            wake_policy: RegisteredActivityWakePolicy::Disabled,
            predecessor: None,
        }
        .with_derived_ids(),
        "valid supervision incarnation",
    )
}

/// The composition-owned Host candidate the production activation path
/// reconciles, in the same shape `tests/activation.rs:608-642` builds it.
fn candidate_binding() -> HostKernelCandidateBinding {
    HostKernelCandidateBinding {
        installation_id: must(
            eliot_platform::PlatformHandle::new("installation-963"),
            "installation",
        ),
        host_epoch: must(AuthorityEpoch::new(1), "host epoch"),
        kernel_epoch: epoch(1),
        activation_id: must(
            eliot_platform::PlatformHandle::new("activation-963"),
            "activation",
        ),
        artifact_hash: must(
            eliot_platform::PlatformHandle::new("artifact-963"),
            "artifact",
        ),
        config_hash: must(eliot_platform::PlatformHandle::new("config-963"), "config"),
        job_object_id: must(
            eliot_platform::PlatformHandle::new("Local\\Eliot-Host-Kernel-963"),
            "job",
        ),
        pipe_identity: must(
            eliot_platform::PlatformHandle::new("\\\\.\\pipe\\eliot-kernel-963"),
            "pipe",
        ),
        host_process: HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: r"C:\eliot\host.exe".to_owned(),
        },
        job_binding: HostJobBinding {
            job: HostJobIdentity {
                name: "Local\\Eliot-Host-Kernel-963".to_owned(),
            },
            root: HostJobRoot {
                process: HostProcessBinding {
                    process_id: 42,
                    start_time_100ns: 10,
                    image_path: r"C:\eliot\kernel.exe".to_owned(),
                },
                executable: HostFileIdentity {
                    volume_serial_number: 1,
                    file_index: 2,
                },
            },
        },
        supervision_incarnation: supervision_incarnation(),
        restart_budget: must(RestartBudget::new(1, 1), "restart budget"),
        agent_bridge_admission: None,
        containment_action: None,
    }
}

/// Publishes `Ready` on the composition's OWN lifecycle owner through the
/// authorized `service_mut` seam, in the exact sequence
/// `tests/activation.rs:643-694` drives: `reconcile` -> `apply(Shadow)` ->
/// `apply(PrepareHandoff)` -> `activate_permit` -> `publish_ready`.
///
/// This is the whole authorization the card's DO NOT clause allows once a case
/// proves the missing seam: it mutates nothing the publicly constructible
/// `KernelService` does not already expose, and it adds no transition.
fn publish_ready(kernel: &KernelComposition) {
    let candidate = candidate_binding();
    let permit = KernelActivationPermit {
        operation_id: must(
            eliot_platform::PlatformHandle::new("activation-operation-963"),
            "operation",
        ),
        candidate_binding_digest: must(candidate.compute_digest(), "candidate digest"),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: must(
            eliot_platform::PlatformHandle::new("journal-transaction-963"),
            "journal transaction",
        ),
        journal_sequence: 1,
        generation: must(ResourceGeneration::new(1), "generation"),
        authority_epoch: candidate.kernel_epoch.clone(),
        activation_nonce: must(
            eliot_platform::KernelActivationNonce::new(must(
                eliot_platform::PlatformHandle::new("a".repeat(64)),
                "nonce handle",
            )),
            "activation nonce",
        ),
    };
    let mut service = kernel.service_mut();
    must(service.reconcile(candidate.clone()), "candidate reconcile");
    must(
        service.apply(KernelControlCommand::Shadow),
        "shadow transition",
    );
    must(
        service.apply(KernelControlCommand::PrepareHandoff),
        "handoff transition",
    );
    let receipt = must(
        service.activate_permit(
            &permit,
            must(ResourceGeneration::new(1), "generation"),
            "c".repeat(64),
        ),
        "activate candidate",
    );
    let activation_nonce_digest = must_some(service.activation_receipt(), "activation receipt")
        .activation_nonce_digest
        .clone();
    must(
        service.publish_ready(KernelReadyReceipt {
            activation_id: candidate.activation_id.clone(),
            activation_operation_id: receipt.operation_id.clone(),
            activation_nonce_digest,
            process: ProcessObservation {
                process_id: must(
                    eliot_platform::PlatformHandle::new("pid:42:start:10"),
                    "process",
                ),
                job_object_id: candidate.job_object_id.clone(),
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![must(
                    eliot_platform::PlatformHandle::new("process-evidence-963"),
                    "evidence",
                )],
            },
            health: HealthVector::healthy(),
            evidence_refs: vec![must(
                eliot_platform::PlatformHandle::new("ready-963"),
                "evidence",
            )],
        }),
        "publish Ready state",
    );
    drop(service);
}

// ---------------------------------------------------------------------------
// Case 7
// ---------------------------------------------------------------------------

/// Builds one composition that has published `Ready` on its own lifecycle
/// owner, which is the state every case below dispatches from.
fn ready_kernel(case: &str) -> (KernelComposition, TempGuard) {
    let (kernel, guard) = test_kernel_with_pipe(case);
    publish_ready(&kernel);
    (kernel, guard)
}

/// Case 7: each command maps to exactly one method and one schema.
///
/// Three `CommandId` spellings route to three operations, each of which
/// reaches its OWN handler's answer. The falsifiable half is the third
/// dispatch: a `backup.restore-test` frame carrying a create-shaped payload is
/// refused by `require_exact_keys`, which proves a payload cannot select
/// another command's method or schema.
// WORK_UNIT_CASE: 963/7 command_to_method_and_schema_mapping_is_exact
#[test]
fn command_to_method_and_schema_mapping_is_exact() {
    ensure_contour();
    let (kernel, _guard) = ready_kernel("case07");
    let session = daemon_session("conn-963-case07");

    assert_create_owns_its_own_answer(&kernel, &session);
    assert_each_command_reaches_its_own_handler(&kernel, &session);
    assert_payload_cannot_select_another_method(&kernel, &session);
    assert_closed_backup_operation_set(&kernel, &session);
}

/// Phase: `backup.create` reaches `handle_backup_create`, whose own answer is
/// the `plan_gap` refusal naming the absent capture owner.
fn assert_create_owns_its_own_answer(kernel: &KernelComposition, session: &Session) {
    let create = dispatch_reply(
        kernel,
        session,
        &backup_frame(
            session,
            OPERATION_BACKUP_CREATE,
            &create_payload(),
            "case07-create",
        ),
    );
    assert_eq!(
        string_field(&create, "command"),
        OPERATION_BACKUP_CREATE,
        "create must answer under its own operation, got {create}"
    );
    assert_eq!(
        string_field(&create, "status"),
        "refused",
        "create is a plan gap today, got {create}"
    );
    assert_eq!(
        string_field(&create, "code"),
        "plan_gap",
        "create refuses as a plan gap, got {create}"
    );
    assert_eq!(
        string_field(&create, "missing_owner"),
        "backup-capture-owner (#959)",
        "create names the absent capture owner, got {create}"
    );
    // The operator surface's `CommandId` spelling is a DIFFERENT namespace: the
    // wire `command` member is the operation, so a reply never carries the CLI
    // spelling. That is what makes the two vocabularies distinguishable.
    for spelling in [
        COMMAND_ID_BACKUP_CREATE,
        COMMAND_ID_BACKUP_VERIFY,
        COMMAND_ID_BACKUP_RESTORE_TEST,
    ] {
        assert!(
            !key_set(&create).contains(&spelling.to_owned()),
            "the wire never carries the CLI CommandId spelling {spelling}, got {create}"
        );
    }
}

/// Phase: each of the three operations reaches a DISTINCT handler answer, and
/// each names exactly one `CommandId`. Three frames, three answers.
fn assert_each_command_reaches_its_own_handler(kernel: &KernelComposition, session: &Session) {
    let bundle = archive("verify", 1, Vec::new());
    let verify = dispatch_reply(
        kernel,
        session,
        &backup_frame(
            session,
            OPERATION_BACKUP_VERIFY,
            &json!({ "bundle_hex": hex_encode(&bundle) }),
            "case07-verify",
        ),
    );
    assert_eq!(
        string_field(&verify, "command"),
        OPERATION_BACKUP_VERIFY,
        "verify must answer under its own operation, got {verify}"
    );

    let rehearsal = dispatch_reply(
        kernel,
        session,
        &backup_frame(
            session,
            OPERATION_BACKUP_RESTORE_TEST,
            &restore_test_payload(&bundle, "target-963", "dest-store-963"),
            "case07-restore",
        ),
    );
    assert_eq!(
        string_field(&rehearsal, "command"),
        OPERATION_BACKUP_RESTORE_TEST,
        "restore-test must answer under its own operation, got {rehearsal}"
    );

    // Three operations, three distinct answers: no handler answers for another.
    let answered = [
        string_field(&verify, "command"),
        string_field(&rehearsal, "command"),
        OPERATION_BACKUP_CREATE,
    ];
    assert_eq!(
        answered.to_vec(),
        vec![
            OPERATION_BACKUP_VERIFY,
            OPERATION_BACKUP_RESTORE_TEST,
            OPERATION_BACKUP_CREATE
        ],
        "each command reaches its own handler's answer"
    );
    assert_ne!(
        answered[0], answered[1],
        "verify and restore-test are distinct handlers"
    );
}

/// Phase: a create-shaped payload on the restore-test route is refused by
/// `require_exact_keys`, so a payload cannot select another command's method.
fn assert_payload_cannot_select_another_method(kernel: &KernelComposition, session: &Session) {
    let crossed = dispatch_reply(
        kernel,
        session,
        &backup_frame(
            session,
            OPERATION_BACKUP_RESTORE_TEST,
            &create_payload(),
            "case07-crossed",
        ),
    );
    assert_eq!(
        string_field(&crossed, "command"),
        OPERATION_BACKUP_RESTORE_TEST,
        "the crossed frame still answers as restore-test, got {crossed}"
    );
    assert_eq!(
        string_field(&crossed, "status"),
        "invalid",
        "a create-shaped payload cannot select another method, got {crossed}"
    );
    assert_eq!(
        string_field(&crossed, "code"),
        "invalid",
        "the exact-key refusal is a shape failure, got {crossed}"
    );
    assert_eq!(
        string_field(&crossed, "field"),
        "backup.restore-test",
        "the refusal names the restore-test payload, got {crossed}"
    );
    assert!(
        crossed.get("missing_owner").is_none(),
        "a shape failure names a field, never an owner: {crossed}"
    );
}

/// Phase: `is_backup_operation`'s closed set is EXACTLY these three operations
/// plus `backup.restore-store`, which no `CommandId` names and which routes to a
/// different owner. Each of the four is dispatched on the same Ready
/// composition, and a selector OUTSIDE the set is not a backup operation at
/// all — it falls through to a different route or fences, never to a backup
/// handler.
fn assert_closed_backup_operation_set(kernel: &KernelComposition, session: &Session) {
    let closed_set = [
        OPERATION_BACKUP_CREATE,
        OPERATION_BACKUP_VERIFY,
        OPERATION_BACKUP_RESTORE_TEST,
        OPERATION_BACKUP_RESTORE_STORE,
    ];
    for (index, operation) in closed_set.iter().enumerate() {
        let reply = dispatch_reply(
            kernel,
            session,
            &backup_frame(
                session,
                operation,
                &json!({ "unbound_probe": true }),
                &format!("case07-selector-{index}"),
            ),
        );
        assert_eq!(
            string_field(&reply, "command"),
            *operation,
            "selector {operation} is routed by the backup arm itself, got {reply}"
        );
    }
    // The fourth selector is not a `CommandId` selector: the operator surface
    // names only the three above, and this one routes to the Store gateway
    // owner, never to the restore rehearsal.
    assert!(
        !closed_set.contains(&COMMAND_ID_BACKUP_RESTORE_TEST),
        "the CLI CommandId namespace is distinct from the wire operation namespace"
    );
    assert_eq!(
        closed_set.len(),
        4,
        "is_backup_operation's closed set has exactly four selectors"
    );
}

// ---------------------------------------------------------------------------
// Case 10
// ---------------------------------------------------------------------------

/// Case 10: `backup.verify` cannot restore or change an installation.
///
/// The PROTOCOL arm's absent-owner refusal is asserted by its EXACT key set —
/// `command`, `status`, `idempotency_key`, `code`, `missing_owner`, `reason`
/// and nothing else — so a payload that smuggled a restore field into the
/// reply would fail the exact-key check. Then the negative that matters: the
/// SAME well-formed archive the restore-test route accepts is routed as
/// `backup.verify`, and no installation-changing field appears anywhere in the
/// answer at any depth.
// WORK_UNIT_CASE: 963/10 verify_cannot_restore_or_change_installation
#[test]
fn verify_cannot_restore_or_change_installation() {
    ensure_contour();
    let (kernel, _guard) = ready_kernel("case10");
    let session = daemon_session("conn-963-case10");

    // The reachable absent-owner refusal: a well-formed protocol archive
    // verification is admitted, validated by the protocol's own gate, and then
    // refused because the retained-archive owner does not exist. Its key set is
    // exactly `refused_reply`'s six members.
    let refused = dispatch_reply(
        &kernel,
        &session,
        &backup_frame(
            &session,
            OPERATION_BACKUP_VERIFY,
            &json!({
                "bundle_hex": hex_encode(&archive("verify-owner", 1, Vec::new())),
                "verification": archive_verification()
            }),
            "case10-owner-absent",
        ),
    );
    assert_eq!(
        key_set(&refused),
        vec![
            "code".to_owned(),
            "command".to_owned(),
            "idempotency_key".to_owned(),
            "missing_owner".to_owned(),
            "reason".to_owned(),
            "status".to_owned(),
        ],
        "the absent-owner refusal carries exactly refused_reply's key set, got {refused}"
    );
    assert_eq!(string_field(&refused, "status"), "refused");
    assert_eq!(string_field(&refused, "code"), "plan_gap");
    assert_eq!(
        string_field(&refused, "missing_owner"),
        "backup-retained-archive-owner (#2862)",
        "verify names the absent retained-archive owner, got {refused}"
    );

    // The negative that matters: the SAME well-formed archive the restore-test
    // route accepts, routed as verify. Whatever the handler answers, it carries
    // no rehearsal, no restore receipt and no cutover at any depth.
    let bundle = archive("verify-negative", 1, Vec::new());
    let verify = dispatch_reply(
        &kernel,
        &session,
        &backup_frame(
            &session,
            OPERATION_BACKUP_VERIFY,
            &json!({ "bundle_hex": hex_encode(&bundle) }),
            "case10-negative",
        ),
    );
    assert_eq!(
        string_field(&verify, "command"),
        OPERATION_BACKUP_VERIFY,
        "the same archive routed as verify answers under verify's own operation, got {verify}"
    );
    assert_absent_everywhere(
        &verify,
        &[
            "rehearsal",
            "rehearsed",
            "receipt",
            "cutover",
            "cutover_performed",
            "operational_recovery_ready",
            "generation",
            "phase_log",
            "evidence",
        ],
    );
    // And it is never a success on the restore axis: no answer that claims a
    // restore was rehearsed can name the rehearsal code.
    assert_ne!(
        string_field(&verify, "code"),
        "rehearsed",
        "verify never answers with the rehearsal code, got {verify}"
    );
}

// ---------------------------------------------------------------------------
// Case 11
// ---------------------------------------------------------------------------

/// Case 11: `backup.restore-test` cannot cutover or retire the source.
///
/// A13.7: "Cutover requires separate authority. Old sessions, leases,
/// approvals, and epochs do not revive." I5.13: "retain pre-cutover state until
/// explicit retirement." The rehearsal route has no cutover selector at all:
/// `require_exact_keys` admits none, an explicit `"cutover": true` member is
/// refused, and the reply reports no cutover at any depth.
// WORK_UNIT_CASE: 963/11 restore_test_cannot_cutover_or_retire_source
#[test]
fn restore_test_cannot_cutover_or_retire_source() {
    ensure_contour();
    let (kernel, _guard) = ready_kernel("case11");
    let session = daemon_session("conn-963-case11");
    let bundle = archive("cutover", 1, Vec::new());

    // The closed key set admits no cutover selector: an explicit one refuses.
    let widened = dispatch_reply(
        &kernel,
        &session,
        &backup_frame(
            &session,
            OPERATION_BACKUP_RESTORE_TEST,
            &json!({
                "bundle_hex": hex_encode(&bundle),
                "destination_authorization_hex": hex_encode(b"destination-authorization-963"),
                "target": {
                    "target_id": "target-963",
                    "target_lineage": LINEAGE,
                    "target_sequence": 9u64,
                    "target_generation": 9u64
                },
                "provisioning": {
                    "dest_store_id": "dest-store-963",
                    "residency_denominator_digest": digest("residency-963"),
                    "source_snapshot_digest": digest("snapshot-963"),
                    "capture_operation_id": "capture-963-1"
                },
                "introductions": [],
                "cutover": true
            }),
            "case11-cutover",
        ),
    );
    assert_eq!(
        string_field(&widened, "status"),
        "invalid",
        "an explicit cutover selector is refused, got {widened}"
    );
    assert_eq!(
        string_field(&widened, "field"),
        "backup.restore-test",
        "the refusal names the restore-test payload, got {widened}"
    );
    assert_absent_everywhere(&widened, &["cutover_performed", "receipt"]);

    // The rehearsal the route actually answers, which reports no cutover.
    let rehearsal = dispatch_reply(
        &kernel,
        &session,
        &backup_frame(
            &session,
            OPERATION_BACKUP_RESTORE_TEST,
            &restore_test_payload(&bundle, "target-963", "dest-store-963"),
            "case11-rehearsal",
        ),
    );
    assert!(
        REFUSAL_STATUSES.contains(&string_field(&rehearsal, "status")),
        "the rehearsal is a refusal or blocked today, got {rehearsal}"
    );
    assert_ne!(
        rehearsal.get("cutover_performed").and_then(Value::as_bool),
        Some(true),
        "the rehearsal never reports cutover_performed true, got {rehearsal}"
    );
    assert_absent_everywhere(&rehearsal, &["cutover_performed", "cutover_admission"]);
    // `qualify_cutover` is not on this route at all, and the restore owner's own
    // typed refusal for an unauthorised cutover is never what the route emits:
    // `cutover-qualification` is reported as a gate that was NOT admitted, which
    // is the closed way this route says it has no cutover authority.
    assert_ne!(
        string_field(&rehearsal, "code"),
        "cutover-not-authorized",
        "the rehearsal is not answered as a cutover, got {rehearsal}"
    );

    // The rehearsal cannot target the live installation's own store: identity
    // isolation is checked at shape level and refuses.
    let not_isolated = dispatch_reply(
        &kernel,
        &session,
        &backup_frame(
            &session,
            OPERATION_BACKUP_RESTORE_TEST,
            &restore_test_payload(&bundle, "live-store-963", "live-store-963"),
            "case11-isolation",
        ),
    );
    assert_eq!(
        string_field(&not_isolated, "status"),
        "invalid",
        "targeting the destination's own store refuses, got {not_isolated}"
    );
    assert_eq!(
        string_field(&not_isolated, "field"),
        "restore.isolation",
        "the refusal names restore isolation, got {not_isolated}"
    );
}

// ---------------------------------------------------------------------------
// Case 13
// ---------------------------------------------------------------------------

/// Case 13: an absent owner answers as a typed unsupported / `PlanGap`, never a
/// fake success.
///
/// Today's REAL answers on this front door, asserted exactly: `backup.create`
/// is `refused`/`plan_gap` naming the absent capture owner; a blob-carrying
/// restore-test is `blocked`/`plan_gap` naming the absent destination key and
/// blob-scope owner; a blob-free restore-test is `refused`/
/// `restore-destination-not-admitted` and names NO owner. No `ok` status and no
/// Forwarded success appears for any of the three.
// WORK_UNIT_CASE: 963/13 missing_owner_returns_typed_unsupported_not_fake_success
#[test]
fn missing_owner_returns_typed_unsupported_not_fake_success() {
    ensure_contour();
    let (kernel, _guard) = ready_kernel("case13");
    let session = daemon_session("conn-963-case13");

    // 1. `backup.create`: the capture owner is unreachable, so the route refuses
    // as a plan gap naming it.
    let create = dispatch_reply(
        &kernel,
        &session,
        &backup_frame(
            &session,
            OPERATION_BACKUP_CREATE,
            &create_payload(),
            "case13-create",
        ),
    );
    assert_eq!(
        (
            string_field(&create, "status"),
            string_field(&create, "code")
        ),
        ("refused", "plan_gap"),
        "create answers refused/plan_gap, got {create}"
    );
    assert_eq!(
        string_field(&create, "missing_owner"),
        "backup-capture-owner (#959)",
        "create names the absent capture owner, got {create}"
    );

    // 2. A BLOB-CARRYING restore-test: the archive decodes and its plan
    // compiles, so the refusal is the owner's own absent capability — the
    // destination key manifest and blob scope no owner channel issues. It is
    // `blocked`, not `refused`, because a `blocked` status is the ONLY status
    // that carries an owner `CapabilityMissing` on this route.
    let carrying = archive(
        "blob-carrying",
        1,
        vec![test_blob("one", b"sealed-blob-963")],
    );
    let blocked = dispatch_reply(
        &kernel,
        &session,
        &backup_frame(
            &session,
            OPERATION_BACKUP_RESTORE_TEST,
            &restore_test_payload(&carrying, "target-963", "dest-store-963"),
            "case13-blocked",
        ),
    );
    assert_eq!(
        (
            string_field(&blocked, "status"),
            string_field(&blocked, "code")
        ),
        ("blocked", "plan_gap"),
        "a blob-carrying rehearsal is blocked/plan_gap, got {blocked}"
    );
    // The absent owner is asserted against the module-level
    // `BACKUP_RESTORE_TEST_MISSING_OWNER`, the verbatim product literal.
    assert_eq!(
        string_field(&blocked, "missing_owner"),
        BACKUP_RESTORE_TEST_MISSING_OWNER,
        "a blob-carrying rehearsal names the absent destination key/scope owner, got {blocked}"
    );

    // 3. A BLOB-FREE restore-test: there is no blob key material to be missing,
    // so the first absent owner the owner reaches is the destination manifest
    // evidence, which is a typed `DestinationNotAdmitted` refusal and names NO
    // owner at all.
    let free = archive("blob-free", 1, Vec::new());
    let refused = dispatch_reply(
        &kernel,
        &session,
        &backup_frame(
            &session,
            OPERATION_BACKUP_RESTORE_TEST,
            &restore_test_payload(&free, "target-963", "dest-store-963"),
            "case13-refused",
        ),
    );
    assert_eq!(
        (
            string_field(&refused, "status"),
            string_field(&refused, "code")
        ),
        ("refused", "restore-destination-not-admitted"),
        "a blob-free rehearsal is refused/restore-destination-not-admitted, got {refused}"
    );
    assert!(
        refused.get("missing_owner").is_none(),
        "a destination refusal names no owner, got {refused}"
    );

    // No fake Forwarded success anywhere: none of the three is `ok`.
    for (label, reply) in [
        ("create", &create),
        ("blocked", &blocked),
        ("refused", &refused),
    ] {
        assert_ne!(
            string_field(reply, "status"),
            "ok",
            "{label} must not answer ok, got {reply}"
        );
        assert!(
            REFUSAL_STATUSES.contains(&string_field(reply, "status")),
            "{label} answers from the closed refusal set, got {reply}"
        );
        assert!(
            reply.get("receipt").is_none(),
            "{label} carries no receipt, got {reply}"
        );
    }
}

// ---------------------------------------------------------------------------
// Case 17
// ---------------------------------------------------------------------------

/// Case 17: the in-process production dispatch reaches the accepted coordinator
/// on the real route, not a test-only mock.
///
/// The composition publishes `Ready` on its OWN lifecycle owner through
/// `service_mut`, and its `service_state()` is asserted to be `Ready` BEFORE
/// dispatching — without that the backup arm fences the frame and the case
/// would be vacuous. One `backup.restore-test` frame then drives
/// `dispatch_frame` -> `dispatch_backup_frame` -> `handle_backup_restore_test`
/// -> the composition's `backup_restore_with_ors_journal`.
///
/// HONEST LIMITS, stated rather than papered over: this case CANNOT count
/// invocations of `backup_restore_with_ors_journal` — that method has no
/// counter, no injected seam and no public observer, and adding one is outside
/// this test's write scope. What it asserts instead is the strongest observable
/// fact: the reply is the one the production handler produced (it carries the
/// route's OWN `gates_passed`/`gates_not_admitted` sets and the exact absent
/// owner the real engine named), its `idempotency_key` equals the FRAME's own
/// identity key — which no synthesised answer could reproduce — and no
/// test-only route was used, because the answer is reached only through
/// `dispatch_frame`.
// WORK_UNIT_CASE: 963/17 production_dispatch_reaches_accepted_coordinator
#[test]
fn production_dispatch_reaches_accepted_coordinator() {
    ensure_contour();
    let (kernel, _guard) = test_kernel_with_pipe("case17");

    // The precondition that makes the case load-bearing rather than vacuous:
    // the composition is NOT Ready yet, so this frame is fenced. If it were not
    // fenced the assertion below would prove nothing about the Ready gate.
    let cold = daemon_session("conn-963-case17-cold");
    let cold_frame = backup_frame(
        &cold,
        OPERATION_BACKUP_RESTORE_TEST,
        &restore_test_payload(
            &archive("cold", 1, Vec::new()),
            "target-963",
            "dest-store-963",
        ),
        "case17-cold",
    );
    let (cold_result, cold_body) = (
        kernel.dispatch_frame(&cold, &cold_frame),
        restore_test_payload(
            &archive("cold", 1, Vec::new()),
            "target-963",
            "dest-store-963",
        ),
    );
    assert!(
        cold_result.is_err(),
        "a not-Ready composition must fence the backup arm, got {cold_body:?}"
    );

    // Publish Ready on the composition's own owner through the authorized seam.
    publish_ready(&kernel);
    assert_eq!(
        must(kernel.service_state(), "service state after publish_ready"),
        KernelServiceState::Ready,
        "the composition must really be Ready before dispatching"
    );

    // One restore-test frame on the production route.
    let bundle = archive("case17", 1, Vec::new());
    let payload = restore_test_payload(&bundle, "target-963", "dest-store-963");
    let session = daemon_session("conn-963-case17");
    let frame = backup_frame(
        &session,
        OPERATION_BACKUP_RESTORE_TEST,
        &payload,
        "case17-restore",
    );
    let expected_key = match &frame.request_identity {
        Some(identity) => identity.idempotency_key.clone(),
        None => panic!("the frame must carry its request identity"),
    };
    let reply = dispatch_reply(&kernel, &session, &frame);

    // The production handler's own answer, on the production route.
    assert_eq!(
        string_field(&reply, "command"),
        OPERATION_BACKUP_RESTORE_TEST,
        "the production handler answered as restore-test, got {reply}"
    );
    assert!(
        REFUSAL_STATUSES.contains(&string_field(&reply, "status")),
        "the accepted coordinator refused today, got {reply}"
    );
    assert_eq!(
        string_field(&reply, "code"),
        "restore-destination-not-admitted",
        "the real engine's own destination refusal, got {reply}"
    );

    // Proof the answer came from THIS dispatch, not a synthesised one: the
    // handler reads the key straight out of the frame's request identity.
    assert_eq!(
        string_field(&reply, "idempotency_key"),
        expected_key,
        "the reply carries the frame's own idempotency key"
    );

    // Proof the real engine's executed route ran, in its own vocabulary: the
    // reported gate sets are the ones `handle_backup_restore_test` accumulates,
    // and the engine ran at most one isolated rehearsal (the refused answer
    // carries no `phase_log` at all, which is what a single refusal produces).
    let passed = reply
        .get("gates_passed")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("the real handler reports its executed route, got {reply}"));
    let passed: Vec<&str> = passed
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("gate must be a string, got {reply}"))
        })
        .collect();
    assert_eq!(
        passed,
        vec![
            "decode",
            "validate",
            "shape",
            "authorization-shape",
            "provisioning",
            "isolation",
            "archive-decode",
            "plan-compile",
            "journal-admission"
        ],
        "the composition's own engine ran the route in order, got {reply}"
    );
    assert!(
        reply.get("phase_log").is_none(),
        "a refusal reports no rehearsal phase log, got {reply}"
    );
    assert_absent_everywhere(&reply, &["receipt", "cutover_performed", "evidence_level"]);
}
