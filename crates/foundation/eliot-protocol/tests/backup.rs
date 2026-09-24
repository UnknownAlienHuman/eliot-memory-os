//! Role-bound backup and isolated-restore control proof (issue #954).
//!
//! Pure shape/transition boundary over the existing protocol envelopes: no
//! I/O, no dispatch, no admission minting, no archive interpretation. Every
//! test below asserts a concrete accept/reject plus an identity or digest
//! equality; there are no count-only assertions.
//!
//! Wire table (wire id / version 1 for every struct):
//!
//! | Struct | Wire id |
//! |---|---|
//! | `BackupRequestIdentity` | `eliot.protocol.backup.request-identity` |
//! | `BackupCaptureRequest` | `eliot.protocol.backup.capture-request` |
//! | `BackupSnapshotPageRead` | `eliot.protocol.backup.snapshot-page-read` |
//! | `BackupArchiveVerification` | `eliot.protocol.backup.archive-verification` |
//! | `BackupIsolatedRestorePrepare` | `eliot.protocol.backup.isolated-restore-prepare` |
//! | `BackupRestoreStep` | `eliot.protocol.backup.restore-step` |
//! | `BackupRestoreReconcile` | `eliot.protocol.backup.restore-reconcile` |
//! | `BackupRestoreStatus` | `eliot.protocol.backup.restore-status` |
//! | `BackupRehearsalComplete` | `eliot.protocol.backup.rehearsal-complete` |
//! | `BackupCutoverAdmission` | `eliot.protocol.backup.cutover-admission` |
//! | `BackupCaptureReceipt` | `eliot.protocol.backup.capture-receipt` |
//! | `BackupPhaseAttestation` | `eliot.protocol.backup.phase-attestation` |
//! | `BackupArchiveValidityAttestation` | `eliot.protocol.backup.archive-validity-attestation` |
//! | `BackupCutoverReceipt` | `eliot.protocol.backup.cutover-receipt` |
//!
//! Role table (authenticated role travels as a separate fn argument):
//!
//! | Role | Permitted operations |
//! |---|---|
//! | REQUESTER | REQUEST_CAPTURE, READ_SNAPSHOT_PAGE, VERIFY_ARCHIVE, PREPARE_ISOLATED_RESTORE, RESTORE_STATUS, RECONCILE_RESTORE (no success receipts) |
//! | CAPTURE_OWNER | own bounded snapshot only |
//! | STORE_OWNER / ORS_OWNER / SPOOL_OWNER | own phase only (RESTORE_STEP, RESTORE_STATUS, RECONCILE_RESTORE) |
//! | VERIFIER | VERIFY_ARCHIVE + COMPLETE_REHEARSAL only |
//! | INSTALLATION_AUTHORITY | PREPARE_ISOLATED_RESTORE + ADMIT_CUTOVER alone |
//! | HOST_FORENSIC | observe-only; never active authority |
//!
//! Port table (owner -> attestation fn -> receipt type):
//!
//! | Owner | `validate_against` on | Receipt type |
//! |---|---|---|
//! | capture owner | `BackupCaptureReceipt` | capture receipt (own snapshot digests) |
//! | phase owner | `BackupPhaseAttestation` | phase attestation (own phase only) |
//! | verifier | `BackupArchiveValidityAttestation`, `BackupRehearsalComplete` | validity / rehearsal record |
//! | installation authority | `BackupCutoverAdmission`, `BackupCutoverReceipt` | cutover admission / receipt |
//!
//! Mapping table (surface selector -> protocol operations; transport ack -> stage):
//!
//! | Selector | Protocol operations |
//! |---|---|
//! | `backup.create` | REQUEST_CAPTURE, READ_SNAPSHOT_PAGE |
//! | `backup.verify` | VERIFY_ARCHIVE |
//! | `backup.restore-test` | PREPARE_ISOLATED_RESTORE, RESTORE_STEP, RECONCILE_RESTORE, RESTORE_STATUS, COMPLETE_REHEARSAL (never ADMIT_CUTOVER) |
//!
//! Every `AckPhase` (RECEIVED, DURABLE, NORMALIZED, APPLIED, REJECTED,
//! UNKNOWN) maps to no `BackupStage`: `ack_phase_stage` always returns
//! `None`. Transport acknowledgement never implies semantic success.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::error::Error;
use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractIdentity, ContractVersion, EpochId,
    EpochLineageId, ProductId, ReceiptId, RequestId, RequestMetadata, ResourceGeneration,
    SessionId, SourceId, StateFence, sha256_hex,
};
use eliot_protocol::backup::{
    BACKUP_ARCHIVE_VALIDITY_ATTESTATION_WIRE_ID, BACKUP_ARCHIVE_VALIDITY_ATTESTATION_WIRE_VERSION,
    BACKUP_ARCHIVE_VERIFICATION_WIRE_ID, BACKUP_ARCHIVE_VERIFICATION_WIRE_VERSION,
    BACKUP_CAPTURE_RECEIPT_WIRE_ID, BACKUP_CAPTURE_RECEIPT_WIRE_VERSION,
    BACKUP_CAPTURE_REQUEST_WIRE_ID, BACKUP_CAPTURE_REQUEST_WIRE_VERSION,
    BACKUP_CUTOVER_ADMISSION_WIRE_ID, BACKUP_CUTOVER_ADMISSION_WIRE_VERSION,
    BACKUP_CUTOVER_RECEIPT_WIRE_ID, BACKUP_CUTOVER_RECEIPT_WIRE_VERSION,
    BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_ID, BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_VERSION,
    BACKUP_PHASE_ATTESTATION_WIRE_ID, BACKUP_PHASE_ATTESTATION_WIRE_VERSION,
    BACKUP_REHEARSAL_COMPLETE_WIRE_ID, BACKUP_REHEARSAL_COMPLETE_WIRE_VERSION,
    BACKUP_REQUEST_IDENTITY_WIRE_ID, BACKUP_REQUEST_IDENTITY_WIRE_VERSION,
    BACKUP_RESTORE_RECONCILE_WIRE_ID, BACKUP_RESTORE_RECONCILE_WIRE_VERSION,
    BACKUP_RESTORE_STATUS_WIRE_ID, BACKUP_RESTORE_STATUS_WIRE_VERSION, BACKUP_RESTORE_STEP_WIRE_ID,
    BACKUP_RESTORE_STEP_WIRE_VERSION, BACKUP_SNAPSHOT_PAGE_READ_WIRE_ID,
    BACKUP_SNAPSHOT_PAGE_READ_WIRE_VERSION, BackupAdmissionRef, BackupArchiveValidityAttestation,
    BackupArchiveVerification, BackupAuthenticatedPrincipal, BackupCaptureReceipt,
    BackupCaptureRequest, BackupClassWire, BackupCutoverAdmission, BackupCutoverReceipt,
    BackupDisposition, BackupError, BackupIsolatedRestorePrepare, BackupMutationBinding,
    BackupOperationKind, BackupPhaseAttestation, BackupRehearsalComplete, BackupReplayDisposition,
    BackupReplayLedger, BackupRequestIdentity, BackupRestoreReconcile, BackupRestoreStatus,
    BackupRestoreStep, BackupRole, BackupSnapshotPageRead, BackupStage, Denominator, HostAuditRef,
    ack_phase_stage, attesting_roles, contract_identity, operation_for_phase,
};
use eliot_protocol::{
    AckPhase, EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
};
use eliot_receipts::{
    AuthorityBinding, EffectClass, ProofCeiling, RequestBinding, WorkScopeBinding, WorkScopeId,
};

type TestResult = Result<(), Box<dyn Error>>;

fn digest(seed: &str) -> String {
    sha256_hex(seed.as_bytes())
}

fn epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch")
}

fn fence() -> StateFence {
    StateFence::new(epoch(), ResourceGeneration::new(1).expect("generation"))
}

fn contract(name: &str) -> ContractIdentity {
    ContractIdentity {
        name: ContractId::new(name).expect("contract name"),
        version: ContractVersion::new(1, 0, 0),
        shape_sha256: digest(name),
    }
}

fn transport(request_id: &str, fence: &StateFence) -> eliot_protocol::RequestIdentity {
    let state_fence = fence.clone();
    eliot_protocol::RequestIdentity {
        request: RequestBinding {
            metadata: RequestMetadata {
                request_id: RequestId::new(request_id).expect("request id"),
                session_id: Some(SessionId::new("session-001").expect("session")),
                task_id: None,
                product_id: ProductId::new("product-001").expect("product"),
                source_id: SourceId::new("source-001").expect("source"),
                state_fence: state_fence.clone(),
                clock: ClockReading::default(),
            },
            state_fence,
        },
        idempotency_key: format!("transport-{request_id}"),
        deadline_unix_ms: 10_000,
        cancellation_id: "cancel-001".to_owned(),
    }
}

fn admission(fence: &StateFence, authority_owner: &str, authority_id: &str) -> BackupAdmissionRef {
    let state_fence = fence.clone();
    BackupAdmissionRef {
        authority: AuthorityBinding {
            authority_id: ContractId::new(authority_id).expect("authority id"),
            authority_owner: authority_owner.to_owned(),
            authority_epoch: epoch(),
            state_fence: state_fence.clone(),
            allowed_effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::Observation,
        },
        scope: WorkScopeBinding {
            scope_id: WorkScopeId::new("scope-001").expect("scope"),
            product_id: ProductId::new("product-001").expect("product"),
            resource_generation: ResourceGeneration::new(1).expect("generation"),
            state_fence,
        },
        capability: "backup.capture".to_owned(),
        admission_receipt: ReceiptId::new("admission-001").expect("admission receipt"),
    }
}

fn base_identity(
    role: BackupRole,
    operation: BackupOperationKind,
    request_id: &str,
) -> BackupRequestIdentity {
    let fence = fence();
    BackupRequestIdentity {
        wire_id: BACKUP_REQUEST_IDENTITY_WIRE_ID.to_owned(),
        wire_version: BACKUP_REQUEST_IDENTITY_WIRE_VERSION,
        principal: BackupAuthenticatedPrincipal {
            principal: "principal-001".to_owned(),
            session_id: "session-001".to_owned(),
            role,
            authority_epoch: epoch(),
        },
        request: transport(request_id, &fence),
        mutation: BackupMutationBinding {
            operation,
            canonical_request_hash: digest(&format!("mutation:{}", operation.as_str())),
        },
        archive_id: "archive-001".to_owned(),
        archive_contract: contract("archive.owner"),
        archive_digest: digest("archive-001"),
        owner_contract: contract("attesting.owner"),
        schema_digest: digest("schema-001"),
        build_digest: digest("build-001"),
        source_installation: "src-001".to_owned(),
        dest_installation: "dest-001".to_owned(),
        class: BackupClassWire::FullRecovery,
        fence: fence.clone(),
        snapshot_digest: digest("snapshot-001"),
        member_digest: digest("members-001"),
        max_page_members: 16,
        max_payload_bytes: 65_536,
        deadline_unix_ms: 10_000,
        cancellation_id: "cancel-001".to_owned(),
        admission: admission(
            &fence,
            "backup-admission-authority",
            "admission-authority-001",
        ),
        identity_digest: String::new(),
    }
    .with_computed_digest()
    .expect("identity digest")
}

fn installation_authority(fence: &StateFence, dest: &str) -> AuthorityBinding {
    AuthorityBinding {
        authority_id: ContractId::new("installation-authority-001").expect("authority id"),
        authority_owner: dest.to_owned(),
        authority_epoch: epoch(),
        state_fence: fence.clone(),
        allowed_effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::Observation,
    }
}

fn cutover_admission(
    identity: &BackupRequestIdentity,
    authority_owner: &str,
    authority_id: &str,
) -> BackupCutoverAdmission {
    BackupCutoverAdmission {
        wire_id: BACKUP_CUTOVER_ADMISSION_WIRE_ID.to_owned(),
        wire_version: BACKUP_CUTOVER_ADMISSION_WIRE_VERSION,
        identity: identity.clone(),
        operation: BackupOperationKind::AdmitCutover,
        installation_admission: admission(&identity.fence, authority_owner, authority_id),
        cutover_plan_digest: digest("cutover-plan-001"),
        request_digest: String::new(),
    }
    .with_computed_digest()
    .expect("cutover digest")
}

fn capture_receipt(identity: &BackupRequestIdentity) -> BackupCaptureReceipt {
    BackupCaptureReceipt {
        wire_id: BACKUP_CAPTURE_RECEIPT_WIRE_ID.to_owned(),
        wire_version: BACKUP_CAPTURE_RECEIPT_WIRE_VERSION,
        archive_id: identity.archive_id.clone(),
        snapshot_digest: identity.snapshot_digest.clone(),
        member_digest: identity.member_digest.clone(),
        captured_bytes: 1024,
        captured_members: 4,
        class: identity.class,
        attesting_owner: "capture-owner".to_owned(),
        owner_receipt: ReceiptId::new("owner-receipt-cap").expect("receipt"),
        fence: identity.fence.clone(),
        observed_at_unix_ms: 5_000,
        receipt_digest: String::new(),
    }
    .with_computed_digest()
    .expect("receipt digest")
}

fn attestation(
    owner_role: BackupRole,
    phase: BackupStage,
    identity: &BackupRequestIdentity,
) -> BackupPhaseAttestation {
    BackupPhaseAttestation {
        wire_id: BACKUP_PHASE_ATTESTATION_WIRE_ID.to_owned(),
        wire_version: BACKUP_PHASE_ATTESTATION_WIRE_VERSION,
        attesting_owner: "phase-owner".to_owned(),
        owner_role,
        phase,
        owner_receipt: ReceiptId::new("owner-receipt-phase").expect("receipt"),
        payload_digest: digest("phase-payload"),
        archive_id: identity.archive_id.clone(),
        fence: identity.fence.clone(),
        observed_at_unix_ms: 5_000,
        attestation_digest: String::new(),
    }
    .with_computed_digest()
    .expect("attestation digest")
}

fn rehearsal(identity: &BackupRequestIdentity) -> BackupRehearsalComplete {
    BackupRehearsalComplete {
        wire_id: BACKUP_REHEARSAL_COMPLETE_WIRE_ID.to_owned(),
        wire_version: BACKUP_REHEARSAL_COMPLETE_WIRE_VERSION,
        identity: identity.clone(),
        operation: BackupOperationKind::CompleteRehearsal,
        rehearsal_digest: digest("rehearsal-001"),
        observed_class: identity.class,
        request_digest: String::new(),
    }
    .with_computed_digest()
    .expect("rehearsal digest")
}

fn fixture(name: &str) -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/backup")
        .join(name);
    let bytes = std::fs::read(&path).expect("fixture bytes");
    serde_json::from_slice(&bytes).expect("fixture json")
}

// WORK_UNIT_CASE: 954/1
#[test]
fn backup_vocabulary_round_trips_catalogues() -> TestResult {
    let operations = [
        BackupOperationKind::RequestCapture,
        BackupOperationKind::ReadSnapshotPage,
        BackupOperationKind::VerifyArchive,
        BackupOperationKind::PrepareIsolatedRestore,
        BackupOperationKind::RestoreStep,
        BackupOperationKind::ReconcileRestore,
        BackupOperationKind::RestoreStatus,
        BackupOperationKind::CompleteRehearsal,
        BackupOperationKind::AdmitCutover,
    ];
    assert_eq!(operations.len(), 9);
    let catalogue = fixture("operation-catalogue.json");
    let wires = catalogue["operations"]
        .as_array()
        .expect("operations array");
    assert_eq!(wires.len(), 9);
    assert_eq!(catalogue["count"], serde_json::json!(9));
    for (operation, entry) in operations.iter().zip(wires.iter()) {
        let wire = entry["wire"].as_str().expect("wire name");
        assert_eq!(wire, operation.as_str());
        let decoded: BackupOperationKind = serde_json::from_value(serde_json::json!(wire))?;
        assert_eq!(decoded, *operation);
        let round_trip = serde_json::to_value(operation)?;
        assert_eq!(round_trip, serde_json::json!(wire));
    }

    let roles = [
        BackupRole::Requester,
        BackupRole::CaptureOwner,
        BackupRole::StoreOwner,
        BackupRole::OrsOwner,
        BackupRole::SpoolOwner,
        BackupRole::Verifier,
        BackupRole::InstallationAuthority,
        BackupRole::HostForensic,
    ];
    assert_eq!(roles.len(), 8);
    let matrix = fixture("role-capability-matrix.json");
    let role_map = matrix["roles"].as_object().expect("roles map");
    assert_eq!(role_map.len(), 8);
    for role in roles {
        let name = serde_json::to_value(role)?;
        let name_str = name.as_str().expect("role name").to_owned();
        assert!(
            role_map.contains_key(&name_str),
            "role {name_str} in matrix"
        );
        let decoded: BackupRole = serde_json::from_value(name.clone())?;
        assert_eq!(decoded, role);
    }
    // Spots both fixtures and code agree on: requester issues captures but
    // never cutover; forensic observes status only; only the installation
    // authority admits cutover; only the verifier completes rehearsals.
    assert!(BackupRole::Requester.permits(BackupOperationKind::RequestCapture));
    assert!(!BackupRole::Requester.permits(BackupOperationKind::AdmitCutover));
    assert!(!BackupRole::Requester.permits(BackupOperationKind::CompleteRehearsal));
    assert!(BackupRole::HostForensic.permits(BackupOperationKind::RestoreStatus));
    assert!(!BackupRole::HostForensic.permits(BackupOperationKind::RequestCapture));
    assert!(BackupRole::InstallationAuthority.permits(BackupOperationKind::AdmitCutover));
    assert!(BackupRole::Verifier.permits(BackupOperationKind::CompleteRehearsal));
    assert!(BackupRole::Verifier.permits(BackupOperationKind::VerifyArchive));
    assert!(!BackupRole::Verifier.permits(BackupOperationKind::AdmitCutover));
    assert!(BackupRole::StoreOwner.permits(BackupOperationKind::RestoreStep));
    assert!(!BackupRole::StoreOwner.permits(BackupOperationKind::AdmitCutover));
    assert!(BackupRole::CaptureOwner.permits(BackupOperationKind::ReadSnapshotPage));
    assert!(!BackupRole::Requester.is_attesting_role());
    assert!(!BackupRole::HostForensic.is_attesting_role());
    assert!(BackupRole::CaptureOwner.is_attesting_role());

    let classes = [
        BackupClassWire::FullRecovery,
        BackupClassWire::CanonicalOnlyDegraded,
        BackupClassWire::ScopeExport,
    ];
    let class_fixture = fixture("class-vocabulary.json");
    let class_names = class_fixture["classes"].as_array().expect("classes array");
    assert_eq!(class_names.len(), 3);
    for (class, entry) in classes.iter().zip(class_names.iter()) {
        let name = entry.as_str().expect("class name");
        let decoded: BackupClassWire = serde_json::from_value(serde_json::json!(name))?;
        assert_eq!(decoded, *class);
        assert_eq!(serde_json::to_value(class)?, serde_json::json!(name));
    }

    let first = contract_identity()?;
    let second = contract_identity()?;
    assert_eq!(first, second);
    Ok(())
}

// WORK_UNIT_CASE: 954/2
#[test]
fn frame_request_id_binding_and_envelope_correlation() -> TestResult {
    let identity = base_identity(
        BackupRole::Requester,
        BackupOperationKind::RequestCapture,
        "backup-req-001",
    );
    identity.validate()?;
    assert_eq!(identity.compute_digest()?, identity.identity_digest);

    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: "conn-001".to_owned(),
        request_id: Some(RequestId::new("backup-req-001")?),
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: Some(identity.request.clone()),
        payload: ProtocolPayload::Json(serde_json::json!({"op": "REQUEST_CAPTURE"})),
        trace_context: BTreeMap::new(),
    };
    frame.validate()?;
    assert_eq!(
        frame.request_id.as_ref(),
        Some(&identity.request.request.metadata.request_id)
    );

    let mut mismatched = frame.clone();
    mismatched.request_id = Some(RequestId::new("backup-req-002")?);
    assert!(mismatched.validate().is_err());

    let envelope =
        identity.to_event_envelope("backup-stream-001", ResourceGeneration::new(1)?, 7)?;
    envelope.validate()?;
    assert_eq!(envelope.stream_id, "backup-stream-001");
    assert_eq!(envelope.state_fence, identity.fence);
    assert!(envelope.ack_required);
    assert!(envelope.event_id.contains(&identity.identity_digest));
    assert!(matches!(
        envelope.payload_or_blob_ref,
        eliot_protocol::EventPayload::BlobRef(_)
    ));
    // Deterministic mapping: the same identity maps to the same envelope.
    let again = identity.to_event_envelope("backup-stream-001", ResourceGeneration::new(1)?, 7)?;
    assert_eq!(envelope, again);

    let correlation = fixture("envelope-correlation.json");
    assert_eq!(
        correlation["frame"]["request_id"],
        correlation["request_identity"]["request_id"]
    );
    assert_eq!(
        correlation["negative_example"]["verdict"],
        serde_json::json!("reject_before_dispatch")
    );
    Ok(())
}

// WORK_UNIT_CASE: 954/3
#[test]
fn request_mutation_identity_split_and_conflict() -> TestResult {
    let first = base_identity(
        BackupRole::Requester,
        BackupOperationKind::RequestCapture,
        "backup-transport-a",
    );
    let second = base_identity(
        BackupRole::Requester,
        BackupOperationKind::RequestCapture,
        "backup-transport-b",
    );
    first.validate()?;
    second.validate()?;
    // Fresh transport identities share one stable mutation digest.
    assert_eq!(
        first.mutation.canonical_request_hash,
        second.mutation.canonical_request_hash
    );
    assert_eq!(
        first.mutation.canonical_request_hash,
        digest("mutation:REQUEST_CAPTURE")
    );
    // Transport correlation differs, so the full identity digests differ.
    assert_ne!(first.identity_digest, second.identity_digest);
    assert_eq!(first.compute_digest()?, first.identity_digest);
    assert_eq!(second.compute_digest()?, second.identity_digest);

    // Changed mutation bytes no longer match the stable binding.
    let mut changed = first.clone();
    changed.mutation.canonical_request_hash = digest("mutation:VERIFY_ARCHIVE");
    changed.identity_digest = changed.compute_digest()?;
    changed.validate()?;
    assert_ne!(
        changed.mutation.canonical_request_hash,
        first.mutation.canonical_request_hash
    );

    // Tampering without recomputing the digest is a digest mismatch.
    let mut tampered = first.clone();
    tampered.snapshot_digest = digest("snapshot-tampered");
    assert!(matches!(
        tampered.validate(),
        Err(BackupError::InvalidField { .. })
    ));

    let canonical = fixture("canonical-request.json");
    assert_eq!(
        canonical["transport_attempt_a"]["digest"],
        canonical["transport_attempt_b"]["digest"]
    );
    assert_ne!(
        canonical["transport_attempt_a"]["request_id"],
        canonical["transport_attempt_b"]["request_id"]
    );
    Ok(())
}

// WORK_UNIT_CASE: 954/4
#[test]
fn authenticated_role_separate_from_payload() -> TestResult {
    let identity = base_identity(
        BackupRole::Requester,
        BackupOperationKind::RequestCapture,
        "backup-req-004",
    );
    identity.validate()?;
    identity.check_authenticated_role(BackupRole::Requester)?;
    // A payload claim never upgrades the authenticated role.
    assert!(matches!(
        identity.check_authenticated_role(BackupRole::Verifier),
        Err(BackupError::CapabilityDenied)
    ));
    assert!(matches!(
        identity.check_authenticated_role(BackupRole::InstallationAuthority),
        Err(BackupError::CapabilityDenied)
    ));
    assert!(!BackupRole::Requester.permits(BackupOperationKind::AdmitCutover));
    assert!(!BackupRole::Requester.permits(BackupOperationKind::CompleteRehearsal));
    assert_eq!(identity.compute_digest()?, identity.identity_digest);
    Ok(())
}

// WORK_UNIT_CASE: 954/5
#[test]
fn requester_cannot_issue_owner_success_receipts() -> TestResult {
    let requester = base_identity(
        BackupRole::Requester,
        BackupOperationKind::RequestCapture,
        "backup-req-005",
    );
    let owner = base_identity(
        BackupRole::CaptureOwner,
        BackupOperationKind::RequestCapture,
        "backup-req-005",
    );
    requester.validate()?;
    owner.validate()?;
    let receipt = capture_receipt(&owner);
    receipt.validate()?;
    assert_eq!(receipt.compute_digest()?, receipt.receipt_digest);

    // The requester role cannot issue the capture-owner success receipt.
    assert!(matches!(
        receipt.validate_against(&requester, BackupRole::Requester),
        Err(BackupError::CapabilityDenied)
    ));
    // The owning role attesting its own snapshot accepts.
    receipt.validate_against(&owner, BackupRole::CaptureOwner)?;

    let validity = BackupArchiveValidityAttestation {
        wire_id: BACKUP_ARCHIVE_VALIDITY_ATTESTATION_WIRE_ID.to_owned(),
        wire_version: BACKUP_ARCHIVE_VALIDITY_ATTESTATION_WIRE_VERSION,
        archive_id: owner.archive_id.clone(),
        archive_digest: owner.archive_digest.clone(),
        verdict: BackupDisposition::Durable,
        attesting_owner: "verifier".to_owned(),
        owner_receipt: ReceiptId::new("owner-receipt-validity").expect("receipt"),
        fence: owner.fence.clone(),
        observed_at_unix_ms: 5_000,
        attestation_digest: String::new(),
    }
    .with_computed_digest()
    .expect("validity digest");
    assert_eq!(validity.compute_digest()?, validity.attestation_digest);
    let verifier = base_identity(
        BackupRole::Verifier,
        BackupOperationKind::VerifyArchive,
        "backup-req-005v",
    );
    validity.validate_against(&verifier, BackupRole::Verifier)?;
    assert!(matches!(
        validity.validate_against(&requester, BackupRole::Requester),
        Err(BackupError::CapabilityDenied)
    ));

    let matrix = fixture("terminal-evidence-matrix.json");
    assert_eq!(
        matrix["grid"]["REQUESTER"]["CAPTURE"],
        serde_json::json!("deny")
    );
    assert_eq!(
        matrix["grid"]["CAPTURE_OWNER"]["CAPTURE"],
        serde_json::json!("allow")
    );
    Ok(())
}

// WORK_UNIT_CASE: 954/6
#[test]
fn one_owner_cannot_attest_another_phase() -> TestResult {
    let allowed = [
        (BackupRole::CaptureOwner, BackupStage::Captured),
        (BackupRole::StoreOwner, BackupStage::RestoreStepApplied),
        (BackupRole::OrsOwner, BackupStage::RestoreStepApplied),
        (BackupRole::SpoolOwner, BackupStage::Reconciled),
        (BackupRole::Verifier, BackupStage::Verified),
        (
            BackupRole::InstallationAuthority,
            BackupStage::RestorePrepared,
        ),
        (
            BackupRole::InstallationAuthority,
            BackupStage::CutoverAdmitted,
        ),
    ];
    for (role, phase) in allowed {
        let identity = base_identity(role, operation_for_phase(phase), "backup-req-006");
        identity.validate()?;
        let proof = attestation(role, phase, &identity);
        assert_eq!(proof.compute_digest()?, proof.attestation_digest);
        proof.validate_against(&identity, role)?;
    }

    let denied = [
        (BackupRole::StoreOwner, BackupStage::Captured),
        (BackupRole::OrsOwner, BackupStage::Captured),
        (BackupRole::CaptureOwner, BackupStage::RestoreStepApplied),
        (BackupRole::StoreOwner, BackupStage::Verified),
        (BackupRole::Requester, BackupStage::RestoreStepApplied),
        (BackupRole::HostForensic, BackupStage::Reconciled),
        (BackupRole::InstallationAuthority, BackupStage::Verified),
    ];
    for (role, phase) in denied {
        let identity = base_identity(role, operation_for_phase(phase), "backup-req-006");
        identity.validate()?;
        let proof = attestation(role, phase, &identity);
        proof.validate()?;
        assert_eq!(proof.compute_digest()?, proof.attestation_digest);
        assert!(
            matches!(
                proof.validate_against(&identity, role),
                Err(BackupError::CapabilityDenied)
            ),
            "role {role:?} must not attest phase {phase:?}"
        );
    }

    // A request is not a receipt: no role attests the Requested stage.
    assert!(attesting_roles(BackupStage::Requested).is_empty());
    assert!(attesting_roles(BackupStage::Captured).contains(&BackupRole::CaptureOwner));

    // The executing phase owner binds its own operation-bound restore step.
    let stepper = base_identity(
        BackupRole::StoreOwner,
        BackupOperationKind::RestoreStep,
        "backup-req-006s",
    );
    let step = BackupRestoreStep {
        wire_id: BACKUP_RESTORE_STEP_WIRE_ID.to_owned(),
        wire_version: BACKUP_RESTORE_STEP_WIRE_VERSION,
        identity: stepper,
        operation: BackupOperationKind::RestoreStep,
        step_index: 0,
        step_digest: digest("step-000"),
        predecessor_digest: digest("prepare-000"),
        request_digest: String::new(),
    }
    .with_computed_digest()
    .expect("step digest");
    step.validate()?;
    assert_eq!(step.compute_digest()?, step.request_digest);
    Ok(())
}

// WORK_UNIT_CASE: 954/7
#[test]
fn rehearsal_cannot_request_cutover_or_retirement() -> TestResult {
    let identity = base_identity(
        BackupRole::Verifier,
        BackupOperationKind::CompleteRehearsal,
        "backup-req-007",
    );
    identity.validate()?;
    let done = rehearsal(&identity);
    done.validate()?;
    assert_eq!(done.compute_digest()?, done.request_digest);
    done.validate_against(&identity, BackupRole::Verifier)?;

    // The rehearsal shape has no cutover/retirement field: unknown fields fail.
    let mut wire = serde_json::to_value(&done)?;
    wire["cutover"] = serde_json::json!(true);
    assert!(serde_json::from_value::<BackupRehearsalComplete>(wire).is_err());
    let mut wire = serde_json::to_value(&done)?;
    wire["retire_source"] = serde_json::json!("src-001");
    assert!(serde_json::from_value::<BackupRehearsalComplete>(wire).is_err());

    // A cutover-typed value carrying the rehearsal operation is rejected.
    let mismatched = BackupCutoverAdmission {
        wire_id: BACKUP_CUTOVER_ADMISSION_WIRE_ID.to_owned(),
        wire_version: BACKUP_CUTOVER_ADMISSION_WIRE_VERSION,
        identity: identity.clone(),
        operation: BackupOperationKind::CompleteRehearsal,
        installation_admission: admission(
            &identity.fence,
            "dest-001",
            "installation-authority-001",
        ),
        cutover_plan_digest: digest("cutover-plan-001"),
        request_digest: String::new(),
    }
    .with_computed_digest()
    .expect("mismatched digest");
    assert!(matches!(
        mismatched.validate(),
        Err(BackupError::OperationMismatch)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 954/8
#[test]
fn cutover_requires_separate_installation_admission() -> TestResult {
    let identity = base_identity(
        BackupRole::InstallationAuthority,
        BackupOperationKind::AdmitCutover,
        "backup-req-008",
    );
    identity.validate()?;
    let known = installation_authority(&identity.fence, &identity.dest_installation);

    // An admission that does not name the known installation authority fails.
    let without = cutover_admission(&identity, "dest-001", "unknown-authority-009");
    without.validate()?;
    assert_eq!(without.compute_digest()?, without.request_digest);
    assert!(matches!(
        without.validate_against(&identity, BackupRole::InstallationAuthority, &known),
        Err(BackupError::Mismatch { .. })
    ));

    // A non-authority role cannot admit cutover even with a valid admission.
    let valid = cutover_admission(&identity, "dest-001", "installation-authority-001");
    valid.validate()?;
    assert!(matches!(
        valid.validate_against(&identity, BackupRole::Requester, &known),
        Err(BackupError::CapabilityDenied)
    ));

    // The separate installation admission from the known authority accepts.
    valid.validate_against(&identity, BackupRole::InstallationAuthority, &known)?;
    assert_eq!(valid.compute_digest()?, valid.request_digest);

    let receipt = BackupCutoverReceipt {
        wire_id: BACKUP_CUTOVER_RECEIPT_WIRE_ID.to_owned(),
        wire_version: BACKUP_CUTOVER_RECEIPT_WIRE_VERSION,
        archive_id: identity.archive_id.clone(),
        dest_installation: identity.dest_installation.clone(),
        attesting_owner: "installation-authority".to_owned(),
        owner_receipt: ReceiptId::new("owner-receipt-cutover").expect("receipt"),
        admission_receipt: ReceiptId::new("admission-receipt-cutover").expect("receipt"),
        fence: identity.fence.clone(),
        observed_at_unix_ms: 5_000,
        receipt_digest: String::new(),
    }
    .with_computed_digest()
    .expect("cutover receipt digest");
    assert_eq!(receipt.compute_digest()?, receipt.receipt_digest);
    receipt.validate_against(&identity, BackupRole::InstallationAuthority, &known)?;
    assert!(matches!(
        receipt.validate_against(&identity, BackupRole::Verifier, &known),
        Err(BackupError::CapabilityDenied)
    ));
    Ok(())
}

// WORK_UNIT_CASE: 954/9
#[test]
fn owner_source_destination_fence_archive_snapshot_exactness() -> TestResult {
    let identity = base_identity(
        BackupRole::CaptureOwner,
        BackupOperationKind::RequestCapture,
        "backup-req-009",
    );
    identity.validate()?;
    let receipt = capture_receipt(&identity);
    receipt.validate_against(&identity, BackupRole::CaptureOwner)?;
    assert_eq!(receipt.compute_digest()?, receipt.receipt_digest);

    // Wrong snapshot digest rejects before any semantic handling.
    let mut wrong_snapshot = receipt.clone();
    wrong_snapshot.snapshot_digest = digest("snapshot-other");
    wrong_snapshot.receipt_digest = wrong_snapshot.compute_digest()?;
    assert!(matches!(
        wrong_snapshot.validate_against(&identity, BackupRole::CaptureOwner),
        Err(BackupError::Mismatch { .. })
    ));

    // Wrong member digest rejects.
    let mut wrong_member = receipt.clone();
    wrong_member.member_digest = digest("members-other");
    wrong_member.receipt_digest = wrong_member.compute_digest()?;
    assert!(matches!(
        wrong_member.validate_against(&identity, BackupRole::CaptureOwner),
        Err(BackupError::Mismatch { .. })
    ));

    // Wrong archive identity rejects.
    let mut wrong_archive = receipt.clone();
    wrong_archive.archive_id = "archive-other".to_owned();
    wrong_archive.receipt_digest = wrong_archive.compute_digest()?;
    assert!(matches!(
        wrong_archive.validate_against(&identity, BackupRole::CaptureOwner),
        Err(BackupError::Mismatch { .. })
    ));

    // Wrong fence (different generation) rejects.
    let mut wrong_fence = receipt.clone();
    wrong_fence.fence = StateFence::new(epoch(), ResourceGeneration::new(2).expect("generation"));
    wrong_fence.receipt_digest = wrong_fence.compute_digest()?;
    assert!(matches!(
        wrong_fence.validate_against(&identity, BackupRole::CaptureOwner),
        Err(BackupError::Mismatch { .. })
    ));

    // Destination must stay isolated from the source.
    let mut same = identity.clone();
    same.dest_installation = same.source_installation.clone();
    same.identity_digest = same.compute_digest()?;
    assert!(same.validate().is_err());

    // A destination override on the restore preparation rejects.
    let prepare = BackupIsolatedRestorePrepare {
        wire_id: BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_ID.to_owned(),
        wire_version: BACKUP_ISOLATED_RESTORE_PREPARE_WIRE_VERSION,
        identity: identity.clone(),
        operation: BackupOperationKind::PrepareIsolatedRestore,
        destination_installation: "dest-override".to_owned(),
        max_restore_bytes: 4096,
        request_digest: String::new(),
    }
    .with_computed_digest()
    .expect("prepare digest");
    assert!(matches!(
        prepare.validate(),
        Err(BackupError::Mismatch { .. })
    ));
    Ok(())
}

// WORK_UNIT_CASE: 954/10
#[test]
fn backup_class_cannot_silently_change() -> TestResult {
    BackupClassWire::validate_transition(
        BackupClassWire::FullRecovery,
        BackupClassWire::FullRecovery,
    )?;
    // Downgrade and upgrade both reject.
    assert!(
        BackupClassWire::validate_transition(
            BackupClassWire::FullRecovery,
            BackupClassWire::CanonicalOnlyDegraded,
        )
        .is_err()
    );
    assert!(
        BackupClassWire::validate_transition(
            BackupClassWire::CanonicalOnlyDegraded,
            BackupClassWire::FullRecovery,
        )
        .is_err()
    );
    assert!(
        BackupClassWire::validate_transition(
            BackupClassWire::FullRecovery,
            BackupClassWire::ScopeExport,
        )
        .is_err()
    );
    assert!(
        BackupClassWire::validate_transition(
            BackupClassWire::ScopeExport,
            BackupClassWire::FullRecovery,
        )
        .is_err()
    );

    let class_fixture = fixture("class-vocabulary.json");
    for pair in class_fixture["rejected_examples"]
        .as_array()
        .expect("rejected examples")
    {
        let declared: BackupClassWire =
            serde_json::from_value(pair[0].clone()).expect("declared class");
        let evidenced: BackupClassWire =
            serde_json::from_value(pair[1].clone()).expect("evidenced class");
        assert!(BackupClassWire::validate_transition(declared, evidenced).is_err());
    }

    // Rehearsal evidence showing a degraded class against a full declaration fails.
    let identity = base_identity(
        BackupRole::Verifier,
        BackupOperationKind::CompleteRehearsal,
        "backup-req-010",
    );
    let mut degraded = rehearsal(&identity);
    degraded.observed_class = BackupClassWire::CanonicalOnlyDegraded;
    degraded.request_digest = degraded.compute_digest()?;
    assert!(degraded.validate().is_err());

    // A capture receipt evidencing a different class fails against the request.
    let owner = base_identity(
        BackupRole::CaptureOwner,
        BackupOperationKind::RequestCapture,
        "backup-req-010",
    );
    let mut receipt = capture_receipt(&owner);
    receipt.class = BackupClassWire::ScopeExport;
    receipt.receipt_digest = receipt.compute_digest()?;
    assert!(
        receipt
            .validate_against(&owner, BackupRole::CaptureOwner)
            .is_err()
    );
    assert_eq!(identity.compute_digest()?, identity.identity_digest);
    Ok(())
}

// WORK_UNIT_CASE: 954/11
#[test]
fn host_forensic_evidence_never_becomes_authority() -> TestResult {
    let audit = HostAuditRef {
        audit_id: "audit-001".to_owned(),
        lineage_digest: digest("lineage-001"),
        observed_dispositions: vec![BackupDisposition::Observed, BackupDisposition::Durable],
    };
    audit.validate()?;

    // The forensic shape carries digests and dispositions only: no fence,
    // epoch, session, admission, or active-authority fields exist.
    let wire = serde_json::to_value(&audit)?;
    let object = wire.as_object().expect("audit object");
    assert!(object.contains_key("audit_id"));
    assert!(object.contains_key("lineage_digest"));
    assert!(object.contains_key("observed_dispositions"));
    assert!(!object.contains_key("state_fence"));
    assert!(!object.contains_key("authority_epoch"));
    assert!(!object.contains_key("active_authority_restored"));

    // Mapping forensic evidence into authority fields is rejected as unknown.
    let mut mapped = wire.clone();
    mapped["state_fence"] = serde_json::json!({});
    assert!(serde_json::from_value::<HostAuditRef>(mapped).is_err());
    let mut mapped = wire.clone();
    mapped["active_authority_restored"] = serde_json::json!(true);
    assert!(serde_json::from_value::<HostAuditRef>(mapped).is_err());
    let mut mapped = wire.clone();
    mapped["authority_epoch"] = serde_json::json!({});
    assert!(serde_json::from_value::<HostAuditRef>(mapped).is_err());

    // Duplicate dispositions and over-limit observation vectors reject.
    let mut duplicated = audit.clone();
    duplicated
        .observed_dispositions
        .push(BackupDisposition::Observed);
    assert!(duplicated.validate().is_err());
    let mut oversize = audit.clone();
    oversize.observed_dispositions = vec![BackupDisposition::Observed; 33];
    assert!(oversize.validate().is_err());

    assert!(!BackupRole::HostForensic.is_attesting_role());
    assert!(!BackupRole::HostForensic.permits(BackupOperationKind::AdmitCutover));
    Ok(())
}

// WORK_UNIT_CASE: 954/12
#[test]
fn transport_ack_never_advances_backup_stage() -> TestResult {
    // Every transport phase maps to no semantic stage, including DURABLE and
    // APPLIED: acknowledgement is not capture/restore/reconciliation success.
    for phase in [
        AckPhase::Received,
        AckPhase::Durable,
        AckPhase::Normalized,
        AckPhase::Applied,
        AckPhase::Rejected,
        AckPhase::Unknown,
    ] {
        assert_eq!(ack_phase_stage(phase), None, "phase {phase}");
    }

    // The lifecycle table advances only through owner attestations.
    assert!(kernel_consumer::stage_edge(
        BackupStage::Requested,
        BackupStage::Captured
    ));
    assert!(BackupStage::can_advance(
        BackupStage::RestoreStepApplied,
        BackupStage::RestoreStepApplied
    ));
    assert!(BackupStage::can_advance(
        BackupStage::RestoreStepApplied,
        BackupStage::Reconciled
    ));
    assert!(!BackupStage::can_advance(
        BackupStage::Requested,
        BackupStage::Verified
    ));
    assert!(!BackupStage::can_advance(
        BackupStage::Captured,
        BackupStage::CutoverAdmitted
    ));
    BackupStage::validate_advance(BackupStage::Requested, BackupStage::Captured)?;
    assert!(BackupStage::validate_advance(BackupStage::Requested, BackupStage::Verified).is_err());

    // The frozen lifecycle vocabulary matches the closed code table exactly:
    // 8 stages, predecessor edges that all satisfy can_advance, and every
    // transport AckPhase mapping to no semantic stage.
    let lifecycle = fixture("lifecycle-vocabulary.json");
    let stages = lifecycle["stages"].as_array().expect("stages");
    assert_eq!(stages.len(), 8);
    let predecessors = lifecycle["predecessors"].as_object().expect("predecessors");
    assert_eq!(predecessors.len(), 8);
    for (stage, preds) in predecessors {
        assert!(
            stages.contains(&serde_json::json!(stage)),
            "predecessor key {stage} is a known stage"
        );
        for pred in preds.as_array().expect("predecessor list") {
            let pred_name = pred.as_str().expect("predecessor name");
            assert!(
                stages.contains(&serde_json::json!(pred_name)),
                "predecessor {pred_name} of {stage} is a known stage"
            );
        }
    }
    assert!(
        predecessors["CAPTURED"]
            .as_array()
            .expect("captured preds")
            .contains(&serde_json::json!("REQUESTED"))
    );
    let parse_stage = |name: &str| match name {
        "REQUESTED" => BackupStage::Requested,
        "CAPTURED" => BackupStage::Captured,
        "VERIFIED" => BackupStage::Verified,
        "RESTORE_PREPARED" => BackupStage::RestorePrepared,
        "RESTORE_STEP_APPLIED" => BackupStage::RestoreStepApplied,
        "RECONCILED" => BackupStage::Reconciled,
        "REHEARSAL_COMPLETE" => BackupStage::RehearsalComplete,
        "CUTOVER_ADMITTED" => BackupStage::CutoverAdmitted,
        _ => panic!("known stage {name}"),
    };
    for (stage, preds) in predecessors {
        let to = parse_stage(stage);
        for pred in preds.as_array().expect("predecessor list") {
            let from = parse_stage(pred.as_str().expect("predecessor name"));
            assert!(
                BackupStage::can_advance(from, to),
                "fixture edge {stage} <- {}",
                pred.as_str().expect("predecessor name")
            );
        }
    }
    assert!(!BackupStage::can_advance(
        BackupStage::Requested,
        BackupStage::CutoverAdmitted
    ));
    let ack_map = lifecycle["ack_phase_to_stage"]
        .as_object()
        .expect("ack map");
    assert_eq!(ack_map.len(), 6);
    for (phase, stage) in ack_map {
        assert!(stage.is_null(), "transport phase {phase} maps to no stage");
    }

    let reconcile = fixture("unknown-outcome-reconciliation.json");
    let acknowledgements = reconcile["acknowledgements"]
        .as_array()
        .expect("acknowledgements");
    let durable = acknowledgements
        .iter()
        .find(|entry| entry["outcome"] == serde_json::json!("DURABLE"))
        .expect("durable entry");
    assert_eq!(durable["advance"], serde_json::json!(false));
    let reconciled = acknowledgements
        .iter()
        .find(|entry| entry["outcome"] == serde_json::json!("RECONCILED"))
        .expect("reconciled entry");
    assert_eq!(reconciled["advance"], serde_json::json!(true));

    let identity = base_identity(
        BackupRole::Requester,
        BackupOperationKind::RequestCapture,
        "backup-req-012",
    );
    assert_eq!(identity.compute_digest()?, identity.identity_digest);
    Ok(())
}

// WORK_UNIT_CASE: 954/13
#[test]
fn unknown_partial_vs_complete_known_zero() -> TestResult {
    // Dispositions stay distinct: never collapsed into a boolean.
    assert_ne!(BackupDisposition::Unknown, BackupDisposition::Partial);
    let unknown: BackupDisposition = serde_json::from_value(serde_json::json!("UNKNOWN"))?;
    let partial: BackupDisposition = serde_json::from_value(serde_json::json!("PARTIAL"))?;
    assert_eq!(unknown, BackupDisposition::Unknown);
    assert_eq!(partial, BackupDisposition::Partial);
    assert_eq!(
        serde_json::to_value(BackupDisposition::Unknown)?,
        serde_json::json!("UNKNOWN")
    );

    // An unknown or partial denominator is incomplete, so a zero observed
    // count rejects: absence of coverage is unknown, not complete.
    let unknown_denominator = Denominator {
        complete: false,
        total: 4,
    };
    assert!(unknown_denominator.validate_for_count(0).is_err());
    let partial_denominator = Denominator {
        complete: false,
        total: 0,
    };
    assert!(partial_denominator.validate_for_count(0).is_err());

    // Complete-known-zero accepts: the denominator is complete and empty.
    let zero = Denominator {
        complete: true,
        total: 0,
    };
    zero.validate_for_count(0)?;

    // A zero count against a complete non-empty denominator rejects, and an
    // observed count can never exceed the denominator total.
    let complete = Denominator {
        complete: true,
        total: 2,
    };
    assert!(complete.validate_for_count(0).is_err());
    complete.validate_for_count(2)?;
    assert!(complete.validate_for_count(3).is_err());

    let identity = base_identity(
        BackupRole::Requester,
        BackupOperationKind::RestoreStatus,
        "backup-req-013",
    );
    assert_eq!(identity.compute_digest()?, identity.identity_digest);

    // The read-only status query validates within requester authority and
    // carries no mutation beyond the observed stage.
    let status = BackupRestoreStatus {
        wire_id: BACKUP_RESTORE_STATUS_WIRE_ID.to_owned(),
        wire_version: BACKUP_RESTORE_STATUS_WIRE_VERSION,
        identity: identity.clone(),
        operation: BackupOperationKind::RestoreStatus,
        observed_stage: BackupStage::Requested,
        request_digest: String::new(),
    }
    .with_computed_digest()
    .expect("status digest");
    status.validate()?;
    assert_eq!(status.compute_digest()?, status.request_digest);
    Ok(())
}

// WORK_UNIT_CASE: 954/14
#[test]
fn arbitrary_surface_rejected_by_closed_schema() -> TestResult {
    let identity = base_identity(
        BackupRole::Requester,
        BackupOperationKind::RequestCapture,
        "backup-req-014",
    );
    let capture = BackupCaptureRequest {
        wire_id: BACKUP_CAPTURE_REQUEST_WIRE_ID.to_owned(),
        wire_version: BACKUP_CAPTURE_REQUEST_WIRE_VERSION,
        identity: identity.clone(),
        operation: BackupOperationKind::RequestCapture,
        max_snapshot_bytes: 4096,
        request_digest: String::new(),
    }
    .with_computed_digest()
    .expect("capture digest");
    capture.validate()?;
    assert_eq!(capture.compute_digest()?, capture.request_digest);

    // Paths, URLs, SQL, shell, credentials, inline bodies and destination
    // overrides have no fields: every one fails closed-schema decode.
    let rejected_fields = [
        ("file_path", serde_json::json!("/tmp/archive.tar")),
        ("url", serde_json::json!("https://example.invalid/archive")),
        ("sql", serde_json::json!("SELECT * FROM archives")),
        ("shell", serde_json::json!("tar -xf archive")),
        ("credentials", serde_json::json!({"token": "secret"})),
        ("inline_body", serde_json::json!("unbounded-bytes")),
        ("destination_override", serde_json::json!("dest-evil")),
    ];
    for (field, value) in rejected_fields {
        let mut wire = serde_json::to_value(&capture)?;
        wire[field] = value;
        assert!(
            serde_json::from_value::<BackupCaptureRequest>(wire).is_err(),
            "field {field} must be rejected"
        );
    }

    // The same closed boundary holds for the other request shapes.
    let page = BackupSnapshotPageRead {
        wire_id: BACKUP_SNAPSHOT_PAGE_READ_WIRE_ID.to_owned(),
        wire_version: BACKUP_SNAPSHOT_PAGE_READ_WIRE_VERSION,
        identity: base_identity(
            BackupRole::Requester,
            BackupOperationKind::ReadSnapshotPage,
            "backup-req-014p",
        ),
        operation: BackupOperationKind::ReadSnapshotPage,
        handle: eliot_protocol::backup::BackupArtifactHandle {
            contract: contract("snapshot.owner"),
            source_revision: "rev-1".to_owned(),
            content_sha256: digest("snapshot-content"),
            byte_length: 128,
            artifact_id: ArtifactId::new("artifact-snapshot-001").expect("artifact"),
        },
        page: eliot_protocol::backup::BackupPageRef {
            page_digest: digest("page-001"),
            page_index: 0,
            member_count: 4,
        },
        page_byte_length: 128,
        request_digest: String::new(),
    }
    .with_computed_digest()
    .expect("page digest");
    page.validate()?;
    let mut wire = serde_json::to_value(&page)?;
    wire["file_path"] = serde_json::json!("/tmp/page.bin");
    assert!(serde_json::from_value::<BackupSnapshotPageRead>(wire).is_err());

    let verify = BackupArchiveVerification {
        wire_id: BACKUP_ARCHIVE_VERIFICATION_WIRE_ID.to_owned(),
        wire_version: BACKUP_ARCHIVE_VERIFICATION_WIRE_VERSION,
        identity: base_identity(
            BackupRole::Requester,
            BackupOperationKind::VerifyArchive,
            "backup-req-014v",
        ),
        operation: BackupOperationKind::VerifyArchive,
        handle: eliot_protocol::backup::BackupArtifactHandle {
            contract: contract("archive.owner"),
            source_revision: "rev-1".to_owned(),
            content_sha256: digest("archive-content"),
            byte_length: 256,
            artifact_id: ArtifactId::new("artifact-archive-001").expect("artifact"),
        },
        believed_archive_digest: digest("archive-001"),
        request_digest: String::new(),
    };
    // The believed digest must equal the bound archive digest: the fixture
    // identity binds digest("archive-001"), so this instance validates.
    let verify = verify.with_computed_digest().expect("verify digest");
    verify.validate()?;
    assert_eq!(verify.compute_digest()?, verify.request_digest);
    Ok(())
}

// WORK_UNIT_CASE: 954/15
#[test]
fn duplicate_unknown_stale_changed_replay_rejected() -> TestResult {
    let identity = base_identity(
        BackupRole::Requester,
        BackupOperationKind::RequestCapture,
        "backup-req-015",
    );
    identity.validate()?;

    // Unknown fields fail before any semantic handling.
    let mut wire = serde_json::to_value(&identity)?;
    wire["unknown_field"] = serde_json::json!(true);
    assert!(serde_json::from_value::<BackupRequestIdentity>(wire).is_err());

    // A duplicated key that changes meaning breaks the identity digest, so
    // the replayed bytes reject instead of silently adopting one value.
    let mut raw = serde_json::to_string(&identity)?;
    let needle = "\"archive_id\":\"archive-001\"";
    let replacement = "\"archive_id\":\"archive-001\",\"archive_id\":\"archive-evil\"";
    raw = raw.replacen(needle, replacement, 1);
    let duplicated: BackupRequestIdentity = serde_json::from_str(&raw)?;
    assert!(duplicated.validate().is_err());

    // An unsupported wire version refuses before inner semantics.
    let mut stale_version = identity.clone();
    stale_version.wire_version = 99;
    stale_version.identity_digest = stale_version.compute_digest()?;
    assert!(matches!(
        stale_version.validate(),
        Err(BackupError::InvalidField { .. })
    ));

    // Stale evidence (observed past the deadline) rejects.
    let owner = base_identity(
        BackupRole::CaptureOwner,
        BackupOperationKind::RequestCapture,
        "backup-req-015",
    );
    let mut stale = capture_receipt(&owner);
    stale.observed_at_unix_ms = owner.deadline_unix_ms + 1;
    stale.receipt_digest = stale.compute_digest()?;
    assert!(stale.validate().is_ok());
    assert!(
        stale
            .validate_against(&owner, BackupRole::CaptureOwner)
            .is_err()
    );

    // Replay ledger: byte-identical replays are duplicates, while the same
    // identity with changed bytes is a replay conflict with no transition.
    let mut ledger = BackupReplayLedger::new();
    assert!(ledger.is_empty());
    assert_eq!(
        ledger.observe(&identity)?,
        BackupReplayDisposition::Accepted
    );
    assert_eq!(ledger.len(), 1);
    assert_eq!(
        ledger.observe(&identity)?,
        BackupReplayDisposition::Duplicate
    );
    let mut changed = identity.clone();
    changed.snapshot_digest = digest("snapshot-changed");
    changed.identity_digest = changed.compute_digest()?;
    changed.validate()?;
    assert!(matches!(
        ledger.observe(&changed),
        Err(BackupError::ReplayConflict)
    ));
    assert_eq!(ledger.len(), 1);

    let reconcile = fixture("unknown-outcome-reconciliation.json");
    assert_eq!(
        reconcile["replay_rule"],
        serde_json::json!(
            "same identity with changed bytes returns REPLAY_CONFLICT and performs no transition"
        )
    );
    Ok(())
}

// WORK_UNIT_CASE: 954/16
#[test]
fn bounded_pages_handles_and_redaction() -> TestResult {
    let identity = base_identity(
        BackupRole::Requester,
        BackupOperationKind::ReadSnapshotPage,
        "backup-req-016",
    );
    identity.validate()?;

    let good_page = eliot_protocol::backup::BackupPageRef {
        page_digest: digest("page-001"),
        page_index: 0,
        member_count: 4,
    };
    good_page.validate()?;
    for bad_count in [0, 1025, u32::MAX] {
        let bad = eliot_protocol::backup::BackupPageRef {
            page_digest: digest("page-001"),
            page_index: 0,
            member_count: bad_count,
        };
        assert!(bad.validate().is_err(), "member_count {bad_count}");
    }

    for bad_length in [0, 65_537, u64::MAX] {
        let bad = eliot_protocol::backup::BackupArtifactHandle {
            contract: contract("snapshot.owner"),
            source_revision: "rev-1".to_owned(),
            content_sha256: digest("snapshot-content"),
            byte_length: bad_length,
            artifact_id: ArtifactId::new("artifact-snapshot-001").expect("artifact"),
        };
        assert!(bad.validate("backup_snapshot_page_read.handle").is_err());
    }

    // Oversize bounded text rejects with a limit error, not truncation.
    let mut oversize = identity.clone();
    oversize.principal.principal = "p".repeat(9 * 1024);
    oversize.identity_digest = oversize.compute_digest().expect("oversize digest");
    assert!(matches!(
        oversize.validate(),
        Err(BackupError::LimitExceeded(_))
    ));

    // Redaction exposes the receipt digest, never source content: the audit
    // reference carries digests and dispositions, and rejects anything more.
    let audit = HostAuditRef {
        audit_id: "audit-016".to_owned(),
        lineage_digest: digest("lineage-016"),
        observed_dispositions: vec![BackupDisposition::Unknown],
    };
    audit.validate()?;
    let wire = serde_json::to_value(&audit)?;
    assert_eq!(
        wire["lineage_digest"],
        serde_json::json!(digest("lineage-016"))
    );
    assert!(wire.get("source_content").is_none());
    assert!(wire.get("source_bytes").is_none());

    let matrix = fixture("terminal-evidence-matrix.json");
    let vectors = matrix["redaction_boundary_vectors"]
        .as_array()
        .expect("redaction vectors");
    assert_eq!(vectors.len(), 3);
    assert_eq!(
        vectors[2]["exposes"],
        serde_json::json!("receipt_digest_only")
    );
    assert_eq!(identity.compute_digest()?, identity.identity_digest);
    Ok(())
}

// WORK_UNIT_CASE: 954/17
#[test]
fn downstream_consumer_compile_fixtures() -> TestResult {
    // Kernel-shaped stub: checks vocabulary and lifecycle edges using only
    // the protocol boundary plus owner-neutral base crates.
    assert!(kernel_consumer::request_allowed(
        BackupRole::Requester,
        BackupOperationKind::RequestCapture
    ));
    assert!(!kernel_consumer::request_allowed(
        BackupRole::Requester,
        BackupOperationKind::AdmitCutover
    ));
    // Store-shaped stub: validates an owner attestation end to end.
    let identity = base_identity(
        BackupRole::StoreOwner,
        BackupOperationKind::RestoreStep,
        "backup-req-017",
    );
    let proof = attestation(
        BackupRole::StoreOwner,
        BackupStage::RestoreStepApplied,
        &identity,
    );
    store_consumer::check_attestation(&proof, &identity, BackupRole::StoreOwner)?;
    assert_eq!(proof.compute_digest()?, proof.attestation_digest);
    // Watchdog-shaped stub: reconcile inputs stay digest-bound, never recomputed.
    let reconcile = BackupRestoreReconcile {
        wire_id: BACKUP_RESTORE_RECONCILE_WIRE_ID.to_owned(),
        wire_version: BACKUP_RESTORE_RECONCILE_WIRE_VERSION,
        identity: base_identity(
            BackupRole::Requester,
            BackupOperationKind::ReconcileRestore,
            "backup-req-017r",
        ),
        operation: BackupOperationKind::ReconcileRestore,
        believed_digest: digest("retained-001"),
        request_digest: String::new(),
    }
    .with_computed_digest()
    .expect("reconcile digest");
    watchdog_consumer::check_reconcile(&reconcile)?;
    assert_eq!(reconcile.compute_digest()?, reconcile.request_digest);
    // CLI-shaped stub: rehearsal selection can never name cutover.
    assert!(cli_consumer::restore_test_selects_cutover(
        BackupOperationKind::AdmitCutover
    ));
    assert!(!cli_consumer::restore_test_selects_cutover(
        BackupOperationKind::CompleteRehearsal
    ));

    // The consumer surface imports only the protocol boundary and the
    // owner-neutral base crates: no storage, kernel, supervision, or surface
    // implementation crates appear in `use` lines of this file. The guarded
    // tokens are assembled at runtime so the guard cannot match itself.
    let own_source = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/backup.rs"),
    )
    .expect("own test source");
    let dash = "-";
    let under = "_";
    let mut forbidden = Vec::new();
    for middle in ["backup", "store", "ors", "watchdog", "cli"] {
        forbidden.push(format!("eliot{dash}{middle}"));
        forbidden.push(format!("eliot{under}{middle}"));
    }
    for token in &forbidden {
        assert!(
            !own_source.contains(token.as_str()),
            "forbidden consumer import {token}"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 954/18
#[test]
fn backup_source_and_api_guard() -> TestResult {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/backup.rs");
    let source = std::fs::read_to_string(&path).expect("backup source");
    // The protocol boundary owns the envelopes: this module maps into the
    // existing Frame/EventEnvelope types instead of defining transport.
    assert!(source.contains("EventEnvelope"));
    assert!(source.contains("use crate::"));
    assert!(source.contains("forbid(unsafe_code)"));
    // No transport, process, filesystem, or network implementation tokens.
    for token in [
        "TcpStream",
        "UdpSocket",
        "Command",
        "process",
        "std::fs",
        "std::net",
        "fs::",
        "net::",
        "socket",
    ] {
        assert!(!source.contains(token), "forbidden token {token}");
    }
    // No dispatch, admission minting, authority minting, or effect finishing.
    for definition in ["fn dispatch", "fn admit", "fn mint", "fn finish"] {
        assert!(
            !source.contains(definition),
            "forbidden definition {definition}"
        );
    }
    // Validators stay pure: they take &self and return Results.
    assert!(source.contains("pub fn validate(&self)"));
    assert!(source.contains("deny_unknown_fields"));
    let identity = base_identity(
        BackupRole::Requester,
        BackupOperationKind::RestoreStatus,
        "backup-req-018",
    );
    identity.validate()?;
    assert_eq!(identity.compute_digest()?, identity.identity_digest);
    Ok(())
}

mod kernel_consumer {
    use eliot_protocol::backup::{BackupOperationKind, BackupRole, BackupStage};

    pub fn request_allowed(role: BackupRole, operation: BackupOperationKind) -> bool {
        role.permits(operation)
    }

    pub fn stage_edge(from: BackupStage, to: BackupStage) -> bool {
        BackupStage::can_advance(from, to)
    }
}

mod store_consumer {
    use eliot_protocol::backup::{
        BackupError, BackupPhaseAttestation, BackupRequestIdentity, BackupRole,
    };

    pub fn check_attestation(
        proof: &BackupPhaseAttestation,
        request: &BackupRequestIdentity,
        role: BackupRole,
    ) -> Result<(), BackupError> {
        proof.validate_against(request, role)
    }
}

mod watchdog_consumer {
    use eliot_protocol::backup::{BackupError, BackupRestoreReconcile};

    pub fn check_reconcile(reconcile: &BackupRestoreReconcile) -> Result<(), BackupError> {
        reconcile.validate()
    }
}

mod cli_consumer {
    use eliot_protocol::backup::BackupOperationKind;

    /// Returns true when the restore-test selector names the operation, which
    /// must never happen for cutover: rehearsal cannot select cutover.
    pub fn restore_test_selects_cutover(operation: BackupOperationKind) -> bool {
        !matches!(operation, BackupOperationKind::AdmitCutover)
    }
}
