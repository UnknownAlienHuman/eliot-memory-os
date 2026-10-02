//! The Kernel admission boundary's OWN admission receipt for the retained-archive
//! arm of `backup.verify` (issue #2862, queue item I2).
//!
//! # WHAT THIS FILE IS, AND WHY IT HAD TO BE WRITTEN
//!
//! The previous delivery of #2862 reported I2 as not closable, and named the
//! reason precisely: `BackupAdmissionRef::admission_receipt` is a
//! `eliot_contracts::ReceiptId` (`eliot-protocol/src/backup.rs:690`), that type
//! has no production producer on this tree, and minting one would forge an owner
//! receipt. That measurement was right about the ABSENCE and wrong about the
//! CAUSE, and this file is the correction, at the documented owner rather than
//! beside it:
//!
//! - `BackupAdmissionRef` is documented as "Admission reference supplied by the
//!   owning authority boundary" (`eliot-protocol/src/backup.rs:676`). On this
//!   route the owning authority boundary IS this Kernel front door: it is the
//!   value that admits the caller (`request_dispatch::admit_backup_caller`),
//!   that holds the live `StateFence`, the registered module identity and the
//!   resource generation every admitted operation runs under.
//! - `elipt-receipts` (`eliot_receipts::ReceiptEnvelope::issue`,
//!   `crates/foundation/eliot-receipts/src/lib.rs:1121`) is the repository's
//!   ONE `ReceiptId` issuer, it is already an admitted `bins/eliot-kernel`
//!   dependency (`Cargo.toml`), and it derives the identity from the canonical
//!   bytes of a validated `ReceiptCore` rather than from any text a caller
//!   supplies. So the missing producer is not a new scheme and not a forgery:
//!   it is the receipts owner being asked for the one receipt it already owns.
//!
//! So the producer is here, it is small, and it is the only place in the
//! repository that issues a backup admission receipt.
//!
//! # WHAT THE RECEIPT IS, PRECISELY
//!
//! It records the admission DECISION and nothing else: `kind: Request`, one
//! `Read` effect, `ProofCeiling::Observation`, no verifier, no problem, no
//! coordination. Its core binds
//!
//! - the LIVE `WorkScope` and LIVE `StateFence` this front door admitted the
//!   operation under (module identity, resource generation, Authority Epoch),
//! - the LIVE authenticated principal that admitted caller authorization names,
//! - the caller's own transport `RequestBinding` and `VERIFY_ARCHIVE` operation
//!   identity, read off the admitted protocol request and never re-spelled, and
//! - the archive the request names, as its handle identity, its archive digest
//!   and its owner source revision.
//!
//! Every one of those is a fact this boundary really holds or a value the
//! caller presented that the protocol's own `validate()` already decided. None
//! is invented, and no digest is recomputed as a substitute for validating the
//! recorded value: `check_admission_binding` runs `BackupAdmissionRef::validate`
//! on the ORIGINAL recorded admission reference FIRST, and
//! `ReceiptEnvelope::issue` validates the whole core it is given.
//!
//! # WHAT IT DELIBERATELY DOES NOT CLAIM
//!
//! - It is an ADMISSION receipt, not a capture receipt and not a validity
//!   attestation. It proves that this boundary admitted this request under this
//!   session; it proves nothing about archive bytes, provenance or class.
//! - The transport capability is NOT bound into it. `BackupAdmissionRef`
//!   `.capability` is a protocol backup capability token and the front door's
//!   admitted capability is the transport `daemon` class; `request_dispatch`
//!   already documents that as two different closed vocabularies with no stated
//!   relation, so an equality test would invent a spelling no owner states. The
//!   live principal, scope and fence are bound instead, which are the facts that
//!   decide the admission.
//! - It is issued, not stored. `ReceiptEnvelope::issue` is pure and derives the
//!   identity from the core, so the same admitted request produces the same
//!   receipt on every attempt; it does not persist anything, and this file adds
//!   no table, no second receipt ledger and no second write path (A12.3).
//!
//! # WHAT IS STILL ABSENT AFTER THIS FILE
//!
//! Issuing the admission receipt does NOT make the retained-archive arm of
//! `backup.verify` reachable, and it is stated here rather than left for a
//! reader to assume. The arm still refuses, because the value the receipt
//! admits — the archive handle — still has no admitted owner that resolves it
//! into the bytes it names. Measured on this base: `ArtifactBlobReader`
//! (`crates/instrument/eliot-artifact/src/blob.rs:72`) has zero
//! implementations and `ArtifactOwner::read` is addressed by `BlobLocator`,
//! `expected_metadata_sha256` and `expected_ready_receipt_id`, none of which
//! `BackupArtifactHandle` (`eliot-protocol/src/backup.rs:735`) carries; and
//! `BackupRole::Verifier`, the only role
//! `BackupArchiveValidityAttestation::validate_against` accepts, is bound to no
//! channel. The refusal that answers for it is
//! `request_dispatch::BACKUP_VERIFY_MISSING_OWNER` and it is unchanged.
//!
//! Capability cell: Kernel admission-bound backup verification request identity
//! (one owner-issued admission receipt and its equality check). Forbidden
//! authority: no capture receipt, no validity attestation, no archive retention
//! or publication effect, no proof-ceiling raise, no second receipt scheme.

use eliot_contracts::{ContractId, OperationId, ReceiptId, StateFence, TransactionSequence};
use eliot_protocol::backup::{BackupArchiveVerification, BackupOperationKind};
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, CausalBinding, EffectClass, OperationBinding, ProofCeiling,
    ReceiptCore, ReceiptDisposition, ReceiptEnvelope, ReceiptKind, WorkScopeBinding, WorkScopeId,
};

use super::backup_verify_provenance::BackupProvenanceError;

/// The authority contract identity this front door issues backup admission
/// receipts under.
///
/// It names the ISSUING boundary, not the capability: `BackupRole` is never
/// taken from this string, and the protocol requires the authenticated role to
/// travel as a separate argument that this file does not construct and does not
/// claim.
const BACKUP_VERIFY_ADMISSION_AUTHORITY: &str = "eliot.kernel.backup-verify-admission";

/// Field path the presented admission reference is validated under.
const ADMISSION_FIELD: &str = "backup_verify.admission";
/// Field path the admission receipt is decided under.
const ADMISSION_RECEIPT_FIELD: &str = "backup_verify.admission.admission_receipt";

/// Issues the admission receipt this Kernel front door issues for one admitted
/// `backup.verify` request (issue #2862, item I2).
///
/// `scope_id` and `fence` are the LIVE admitted values — the registered module
/// identity and the session's own `StateFence` — and `principal` is the LIVE
/// authenticated principal the caller authorization admitted. None of the three
/// is read off the payload, and none can be supplied by a frame: this function
/// has no other source for them.
///
/// The request-derived terms (`request`, `operation`, `artifacts`) are read off
/// the ORIGINAL admitted [`BackupArchiveVerification`], so the receipt describes
/// the request that was actually presented rather than a re-spelling of it.
///
/// Fails closed. `ReceiptEnvelope::issue` validates the whole core, and its
/// cross-binding rules mean a request presented under a fence other than the
/// live one — or with a transport `RequestBinding` that does not agree with the
/// identity it sits in — is refused here instead of being admitted under this
/// boundary's name. That refusal is
/// [`BackupProvenanceError::AdmissionNotBound`], which states exactly that and
/// never implies the caller's payload was malformed.
pub(crate) fn issue_admission_receipt(
    verification: &BackupArchiveVerification,
    scope_id: &str,
    principal: &str,
    fence: &StateFence,
) -> Result<ReceiptId, BackupProvenanceError> {
    fn refuse() -> BackupProvenanceError {
        BackupProvenanceError::AdmissionNotBound {
            field: ADMISSION_RECEIPT_FIELD,
        }
    }
    let identity = &verification.identity;
    let core = ReceiptCore {
        contract: eliot_receipts::contract_identity().map_err(|_| refuse())?,
        kind: ReceiptKind::Request,
        // The LIVE admitted scope and fence. `product_id` is the product the
        // caller's own transport metadata names, because the receipts contract
        // requires the work scope and the request to agree on it and this
        // boundary does not own a product identity of its own.
        work_scope: WorkScopeBinding {
            scope_id: WorkScopeId::new(scope_id).map_err(|_| refuse())?,
            product_id: identity.request.request.metadata.product_id.clone(),
            resource_generation: fence.resource_generation,
            state_fence: fence.clone(),
        },
        task: None,
        // The session is already bound by the work scope identity and the fence,
        // and `RequestMetadata.session_id` is optional on this wire, so no
        // separate session binding is asserted from a field that may be absent.
        session: None,
        causal: CausalBinding {
            state_fence: fence.clone(),
            transaction_sequence: TransactionSequence::genesis(),
            parent_receipt_id: None,
            predecessor_receipt_ids: Vec::new(),
        },
        // The caller's own transport request binding, verbatim.
        request: identity.request.request.clone(),
        operation: OperationBinding {
            operation_id: OperationId::new(identity.request.idempotency_key.clone())
                .map_err(|_| refuse())?,
            request_id: identity.request.request.metadata.request_id.clone(),
            idempotency_key: identity.request.idempotency_key.clone(),
            // The protocol's own closed operation NAME, from its total table.
            operation_kind: BackupOperationKind::VerifyArchive.as_str().to_owned(),
            // Verification is read-only on this route (issue #2862 item 11).
            effect: EffectClass::Read,
            state_fence: fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new(BACKUP_VERIFY_ADMISSION_AUTHORITY)
                .map_err(|_| refuse())?,
            // The LIVE authenticated principal, not a payload claim (A12.2).
            authority_owner: principal.to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect: EffectClass::Read,
            // An admission is an observation of one caller's own request. It
            // claims nothing beyond that and can never raise a proof ceiling.
            proof_ceiling: ProofCeiling::Observation,
        },
        artifacts: vec![ArtifactBinding {
            artifact_id: verification.handle.artifact_id.clone(),
            sha256: identity.archive_digest.clone(),
            role: ReceiptKind::Artifact,
            source_revision: Some(verification.handle.source_revision.clone()),
        }],
        verifier: None,
        problem: None,
        coordination: None,
        disposition: ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
    };
    ReceiptEnvelope::issue(core)
        .map(|envelope| envelope.identity.receipt_id)
        .map_err(|_| refuse())
}

/// Requires the admitted protocol request's admission reference to be the one
/// THIS boundary issues for THIS request under THIS admitted session (issue
/// #2862, item I2).
///
/// # WHY THIS EXISTS AT ALL
///
/// `BackupAdmissionRef::validate` deliberately does not decide the receipt: it
/// checks the authority/scope/epoch bindings and the capability's shape, and the
/// receipt travels as an opaque reference. On its own, `admission_receipt` was
/// therefore free text that any caller could satisfy, so a protocol request
/// could name an admission this Kernel never granted. That is exactly the
/// parallel-shape defect item I2 names, one level below the payload: an
/// authority-bearing field with no owner behind it.
///
/// Two independent records meet here, so this is not a self-comparison. The
/// LEFT side is caller-presented text. The RIGHT side is this boundary's own
/// `ReceiptEnvelope::issue` over the live scope, fence and principal. A frame
/// cannot make them agree by choosing its own value: it would have to be
/// admitted under the same module identity, the same Authority Epoch, the same
/// resource generation and the same authenticated principal, all of which this
/// boundary reads from the session it admitted and not from the payload.
///
/// # ORDER, AND WHAT EACH STEP PROVES
///
/// 1. `BackupAdmissionRef::validate` on the ORIGINAL RECORDED value. This is
///    the protocol owner's own decision about the authority/scope/epoch
///    bindings; nothing here re-derives it.
/// 2. The owner's own issue. That is what proves the recorded `admission_receipt`
///    is the identity of a real receipt over a real admitted core.
/// 3. Exact equality between the two.
///
/// A divergence refuses as [`BackupProvenanceError::AdmissionNotBound`], which
/// is NOT the archive-binding refusal `NotBound` names: this one is about the
/// admission, and it is stated as its own variant so the two bounded reasons
/// cannot drift into one sentence that is wrong for one of them.
pub(crate) fn check_admission_binding(
    verification: &BackupArchiveVerification,
    scope_id: &str,
    principal: &str,
    fence: &StateFence,
) -> Result<(), BackupProvenanceError> {
    verification
        .identity
        .admission
        .validate()
        .map_err(|source| BackupProvenanceError::OwnerValueInvalid {
            field: ADMISSION_FIELD,
            source,
        })?;
    let issued = issue_admission_receipt(verification, scope_id, principal, fence)?;
    if verification.identity.admission.admission_receipt != issued {
        return Err(BackupProvenanceError::AdmissionNotBound {
            field: ADMISSION_RECEIPT_FIELD,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::num::NonZeroU64;

    use eliot_contracts::{
        ArtifactId, ClockReading, ContractIdentity, ContractVersion, EpochId, EpochLineageId,
        ProductId, RequestId, RequestMetadata, ResourceGeneration, SessionId, SourceId, sha256_hex,
    };
    use eliot_protocol::RequestIdentity;
    use eliot_protocol::backup::{
        BACKUP_ARCHIVE_VERIFICATION_WIRE_ID, BACKUP_ARCHIVE_VERIFICATION_WIRE_VERSION,
        BACKUP_REQUEST_IDENTITY_WIRE_ID, BACKUP_REQUEST_IDENTITY_WIRE_VERSION, BackupAdmissionRef,
        BackupArtifactHandle, BackupAuthenticatedPrincipal, BackupClassWire, BackupMutationBinding,
        BackupRequestIdentity, BackupRole,
    };
    use eliot_receipts::RequestBinding;

    use super::*;

    const SCOPE: &str = "module-0001";
    const PRINCIPAL: &str = "operator@session-0001";

    fn digest(seed: &str) -> String {
        sha256_hex(seed.as_bytes())
    }

    fn fence_at(sequence: u64) -> StateFence {
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("canonical lineage");
        let epoch = EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero sequence"),
        )
        .expect("valid epoch");
        StateFence::new(
            epoch,
            ResourceGeneration::new(sequence).expect("non-zero generation"),
        )
    }

    fn contract(name: &str) -> ContractIdentity {
        ContractIdentity {
            name: ContractId::new(name).expect("contract name"),
            version: ContractVersion::new(1, 0, 0),
            shape_sha256: digest(name),
        }
    }

    /// One well-formed protocol verification request whose admission reference
    /// carries a PLACEHOLDER receipt, so the positive proof has to install the
    /// boundary's own issued value rather than inherit one.
    fn verification() -> BackupArchiveVerification {
        let state_fence = fence_at(1);
        let request = RequestIdentity {
            request: RequestBinding {
                metadata: RequestMetadata {
                    request_id: RequestId::new("verify-request-0001").expect("request id"),
                    session_id: Some(SessionId::new("session-0001").expect("session")),
                    task_id: None,
                    product_id: ProductId::new("product-0001").expect("product"),
                    source_id: SourceId::new("source-0001").expect("source"),
                    state_fence: state_fence.clone(),
                    clock: ClockReading::default(),
                },
                state_fence: state_fence.clone(),
            },
            idempotency_key: "verify-operation-0001".to_owned(),
            deadline_unix_ms: 10_000,
            cancellation_id: "cancel-0001".to_owned(),
        };
        let identity = BackupRequestIdentity {
            wire_id: BACKUP_REQUEST_IDENTITY_WIRE_ID.to_owned(),
            wire_version: BACKUP_REQUEST_IDENTITY_WIRE_VERSION,
            principal: BackupAuthenticatedPrincipal {
                principal: "operator".to_owned(),
                session_id: "session-0001".to_owned(),
                role: BackupRole::Requester,
                authority_epoch: state_fence.authority_epoch.clone(),
            },
            request,
            mutation: BackupMutationBinding {
                operation: BackupOperationKind::VerifyArchive,
                canonical_request_hash: digest("mutation:VERIFY_ARCHIVE"),
            },
            archive_id: "archive-0001".to_owned(),
            archive_contract: contract("backup.archive.owner"),
            archive_digest: digest("archive-0001"),
            owner_contract: contract("backup.capture.owner"),
            schema_digest: digest("schema-0001"),
            build_digest: digest("build-0001"),
            source_installation: "source-installation-0001".to_owned(),
            dest_installation: "dest-installation-0001".to_owned(),
            class: BackupClassWire::FullRecovery,
            fence: state_fence.clone(),
            snapshot_digest: digest("snapshot-0001"),
            member_digest: digest("member-0001"),
            max_page_members: 16,
            max_payload_bytes: 65_536,
            deadline_unix_ms: 10_000,
            cancellation_id: "cancel-0001".to_owned(),
            admission: BackupAdmissionRef {
                authority: AuthorityBinding {
                    authority_id: ContractId::new(BACKUP_VERIFY_ADMISSION_AUTHORITY)
                        .expect("authority id"),
                    authority_owner: PRINCIPAL.to_owned(),
                    authority_epoch: state_fence.authority_epoch.clone(),
                    state_fence: state_fence.clone(),
                    allowed_effect: EffectClass::Read,
                    proof_ceiling: ProofCeiling::Observation,
                },
                scope: WorkScopeBinding {
                    scope_id: WorkScopeId::new(SCOPE).expect("scope"),
                    product_id: ProductId::new("product-0001").expect("product"),
                    resource_generation: state_fence.resource_generation,
                    state_fence: state_fence.clone(),
                },
                capability: "backup.verify".to_owned(),
                admission_receipt: ReceiptId::new("receipt-not-issued-here")
                    .expect("placeholder receipt id"),
            },
            identity_digest: String::new(),
        }
        .with_computed_digest()
        .expect("identity digest");
        let handle = BackupArtifactHandle {
            contract: contract("backup.archive.retained"),
            source_revision: "revision-0001".to_owned(),
            content_sha256: digest("archive-0001"),
            byte_length: 4_096,
            artifact_id: ArtifactId::new("artifact-0001").expect("artifact id"),
        };
        BackupArchiveVerification {
            wire_id: BACKUP_ARCHIVE_VERIFICATION_WIRE_ID.to_owned(),
            wire_version: BACKUP_ARCHIVE_VERIFICATION_WIRE_VERSION,
            identity,
            operation: BackupOperationKind::VerifyArchive,
            handle,
            believed_archive_digest: digest("archive-0001"),
            request_digest: String::new(),
        }
        .with_computed_digest()
        .expect("request digest")
    }

    /// Installs the boundary's own issued receipt and re-seals both digests, so
    /// the presented value is a receipt this boundary really issued rather than
    /// a placeholder that happens to validate.
    fn sealed_by_this_boundary() -> BackupArchiveVerification {
        let state_fence = fence_at(1);
        let mut presented = verification();
        presented.identity.admission.admission_receipt =
            issue_admission_receipt(&presented, SCOPE, PRINCIPAL, &state_fence)
                .expect("the boundary issues this admission receipt");
        presented.identity = presented
            .identity
            .clone()
            .with_computed_digest()
            .expect("re-sealed identity digest");
        presented
            .with_computed_digest()
            .expect("re-sealed request digest")
    }

    #[test]
    fn admission_receipt_this_boundary_issued_is_admitted() {
        let state_fence = fence_at(1);
        let presented = sealed_by_this_boundary();
        presented
            .validate()
            .expect("the protocol's own validation still decides the request");
        check_admission_binding(&presented, SCOPE, PRINCIPAL, &state_fence)
            .expect("a receipt this boundary issued for this request is admitted");
    }

    #[test]
    fn admission_receipt_this_boundary_did_not_issue_is_refused() {
        let state_fence = fence_at(1);
        let refusal = check_admission_binding(&verification(), SCOPE, PRINCIPAL, &state_fence)
            .expect_err("a caller-chosen receipt is not this boundary's receipt");
        assert!(
            matches!(
                refusal,
                BackupProvenanceError::AdmissionNotBound {
                    field: ADMISSION_RECEIPT_FIELD
                }
            ),
            "the refusal must name the admission receipt, not the archive binding"
        );
    }

    #[test]
    fn admission_under_another_live_fence_is_refused() {
        let refusal =
            check_admission_binding(&sealed_by_this_boundary(), SCOPE, PRINCIPAL, &fence_at(2))
                .expect_err("an admission under another Authority Epoch is not this one");
        assert!(matches!(
            refusal,
            BackupProvenanceError::AdmissionNotBound { .. }
        ));
    }
}
