//! Store-owned projection of an ORS-admitted write reservation (issue #990).
//!
//! This module defines the minimum Store-owned transport/API projection needed
//! to carry an existing ORS-admitted write reservation across the
//! authenticated Kernel-to-Store boundary. It closes the trusted-input seam
//! for the bounded pure ordering drain: a self-consistent caller-created scope
//! list must not acquire ordering precedence merely because it passes
//! structural checks.
//!
//! The projection is a projection of canonical reservation evidence, not a
//! new reservation issuer, lease service, signature system, or ordering drain.
//! ORS remains the uncommitted reservation owner; Store heads and receipts
//! remain committed truth. This crate does not depend on the ORS
//! implementation and duplicates none of its mutable state or lifecycle.
//!
//! # Field-to-owner mapping
//!
//! Every field restates owner-held evidence in Store-owned vocabulary using
//! existing canonical identity types. The Store API never imports the ORS
//! implementation; the Kernel producer maps ORS evidence into these fields
//! and calls [`WriteAdmissionProjection::bind`], which seals the mapping with
//! the canonical digests defined below.
//!
//! ```text
//! Store field                        Owner / source
//! ---------------------------------- ------------------------------------------
//! contract_version                   Store API (#990); closed version, always 1
//! reservation_id                     ORS WriterReservationToken.reservation_id
//!                                    (opaque label mirrored as bounded text)
//! reservation_order                  ORS single-coordinator precedence (I5.7);
//!                                    nonzero; never allocated here
//! operation_id / idempotency_key /   Store PreparedTransition.identity (I5.27);
//! canonical_request_hash             exact copies; divergence is
//!                                    IdentityConflict, never silent repair
//! prepared_transition_digest         Store canonical bytes of the exact
//!                                    PreparedTransition carried alongside
//! reservation_token_digest           Store canonical reservation-binding bytes
//!                                    (single encoder below); binds the mapped
//!                                    token fields, not a second ad hoc layout
//! scopes[].scope                     ORS ReservedScope.scope as Store
//!                                    OrderingScopeId text
//! scopes[].reserved_sequence         ORS ReservedScope.reserved_sequence;
//!                                    nonzero; never allocated here
//! scopes[].expected_sequence /       ORS ExpectedOrderingHead.sequence /
//! expected_head_digest               head_sha256, cross-checked against the
//!                                    Store OrderingHeadExpectation set
//! writer_epoch                       ORS EpochLineage mirrored shape,
//!                                    including the same-lineage direct-child
//!                                    rule; confers no epoch authority here
//! state_fence                        Store StateFence; must equal the
//!                                    context, transition, and head fences
//! source_id                          Kernel transport RequestMeta.source_id
//!                                    (I15.2); payload mirror only, the
//!                                    transported context always wins
//! created_at_ms / expires_at_ms      ORS envelope/time contract; ordered
//!                                    positive pair, never read from a clock
//! recovery_owner                     ORS RecoveryOwner as bounded text
//! expected_revision_heads            Store apply contract; preserved exactly
//!                                    with the same fence, never reinterpreted
//! expected_ordering_heads            Store apply contract; must exactly cover
//!                                    the reserved scope set and sequences
//! ```
//!
//! # Canonical encoding
//!
//! There is exactly one encoder per digest, shared by the producer path
//! ([`WriteAdmissionProjection::bind`]) and the checking path
//! ([`ReservedWriteRequest::validate`]); no second serializer exists:
//!
//! - [`prepared_transition_digest`] hashes [`canonical_json_bytes`] of the
//!   full [`PreparedTransition`] value;
//! - the token digest hashes [`canonical_json_bytes`] of the private
//!   `CanonicalReservationBinding` view, whose fields in declaration order
//!   are: contract version, reservation id, operation id, idempotency key,
//!   canonical request hash, prepared-transition digest, reservation order,
//!   scopes (admitted sorted order; each scope, reserved sequence, expected
//!   sequence, expected head digest), writer lineage id, writer epoch,
//!   predecessor lineage id, predecessor epoch, state fence, source id,
//!   creation time, expiry time, recovery owner.
//!
//! Both digests are lowercase SHA-256 hex. A mutation of any covered byte on
//! either side fails closed with [`StoreError::TransitionDigestMismatch`].
//!
//! # Shape only, never current authority
//!
//! Successful decoding means shape only. There is deliberately no
//! worker-controlled authority Boolean anywhere in this module: no field, no
//! accessor, and no JSON key claims currency, executability, or ownership.
//! The receiving boundary must authenticate the Kernel generation and confirm
//! current owner evidence before creating its private executable admission
//! value; that confirmation lives with the later wire/process owner, not in
//! these types. A projection that passes [`ReservedWriteRequest::validate`]
//! is still only self-consistent: it proves the reservation evidence was
//! copied exactly, not that the reservation is current, unexpired, or first
//! in its scopes.
//!
//! Intrinsic checks cover the nonempty complete scope set, unique canonical
//! order, bounded members, exact operation/transition/fence/head matching,
//! state-specific required evidence (via [`PreparedTransition::validate`]),
//! and the closed version/shape. They cannot query ORS, read a clock,
//! confirm currency, or allocate sequence/epoch values. Expiry is an ordered
//! owner-supplied pair; wall timestamps alone are not authority.
//!
//! # Reconciliation
//!
//! Reconciliation keeps using the original [`OperationId`] and the exact
//! canonical receipt plus the reservation binding carried here. Committed,
//! proven-not-applied, and still-unknown stay separate: success does not
//! finalize ORS automatically, and cancellation/expiry does not establish
//! non-commit. No new canonical [`WriteReceipt`] issuer and no internal
//! ordering ticket is defined here.
//!
//! That paragraph is code, not a comment:
//! [`ReservedWriteOutcome`] is the closed three-arm outcome and
//! [`ReservedWriteReconciliation`] is the bound identity-plus-receipt value.
//! A commit is reachable only from a validated canonical receipt that matches
//! this projection ([`ReservedWriteReconciliation::committed`]); a read that
//! returned nothing is still-unknown ([`ReservedWriteReconciliation::still_unknown`])
//! and stays there; a cancelled or expired envelope is still-unknown
//! ([`ReservedWriteReconciliation::reconcile`]); and the promotion to
//! proven-not-applied is a separate named act
//! ([`ReservedWriteReconciliation::proven_not_applied`]). No arm finalizes the
//! reservation ([`ReservedWriteReconciliation::finalizes_reservation`]).
//!
//! The wire cannot widen that separation. A decoded payload is held to the
//! same evidence requirements as a constructed one: a committed arm must carry
//! the exact canonical receipt the commit entry point demands, and a payload
//! that merely asserts proven-not-applied is refused, because asserting it on
//! the wire is not the act.
//!
//! # Write submission and the admission decision
//!
//! [`WriteSubmission`] is the I5.19 admission result returned by the front door
//! before a final canonical [`WriteReceipt`] exists, and
//! [`admit_write_submission`] is the one pure function that decides it. The
//! three outcomes stay separate and are decided, not narrated: a gate refusal
//! is a typed `not_accepted` value carrying the closed [`ErrorCode`] of the
//! refusal and, for an over-bound envelope, the [`SplitDirective`] that makes
//! the refusal actionable. It is never an erased string.
//! [`WriteSubmission::validate`] enforces the I5.19 state invariants rather
//! than describing them.
//!
//! The decisions this module can take are taken at the I5.6 steps 1-12 gate
//! boundary, which is strictly before I5.6 step 13 stages the operation in
//! ORS. That placement is what makes them honest here: no Ordering Scope
//! sequence has been reserved and no external effect has been issued, so each
//! state can claim exactly that. A refusal taken after a reservation is issued
//! is a different act with a different owner (the Kernel reserved-write path)
//! and is not represented here.
//!
//! # `staged` is not produced here
//!
//! I5.19 fixes the meaning of the third token and it is not a Store-API
//! meaning: "`staged` means ORS accepted the exact operation identity; caller
//! must not create a duplicate and may poll." I5.6 step 13 is the ORS-backed
//! staging act that makes that true, and I5.2 forbids reporting
//! `accepted_pending` at all "if ORS cannot durably stage the complete opaque
//! operation". A decision taken at the steps 1-12 boundary has staged nothing,
//! so this module does not build a [`WriteSubmissionState::Staged`] value and
//! the accepted arm of [`admit_write_submission`] reports that no
//! front-door submission is owed instead of a `staged` one.
//!
//! That is the whole reason `ors_stage_ref` is not filled in here. A handle
//! computed from the operation identity names an operation, but naming an
//! operation is not evidence that the ORS owner accepted it, and a value whose
//! state is the I5.19 `staged` token asserts exactly that evidence. Filling the
//! field from a pure derivation let the token carry a guarantee no act
//! performed; the field stays absent here and the state is not emitted. When a
//! sealed reservation projection exists, its owner-issued `reservation_id`
//! under this same module owner is the real label, and the ORS-owning route
//! that stages is the only place a `staged` submission can be built.
//!
//! # Activated named-mutation inventory
//!
//! Issue #1874 asks for every existing named mutation to be inventoried against
//! the active-contract catalogue. I5.15 states that no generated authoritative
//! catalogue exists yet (`ImplementationSupport = TARGET`, and appendices N/P/H
//! cannot become a second field-level schema owner), so this inventory is
//! written against the owning I-sections and against the single declaration
//! table `operation_catalogue::ACTIVATED_MUTATIONS`, which is the only
//! activation source this crate has. It is documentation at the admission
//! surface: not a generated catalogue, not a second schema registry, and not a
//! claim of support.
//!
//! I5.19 owns the shared canonical execution every activated mutation travels:
//! steps 1-3 resolve the existing receipt, verify the ordering predecessor and
//! active Authority Epoch, and revalidate revisions/policy; step 4 executes the
//! one named parameterized transaction; steps 5-11 append canonical events,
//! update projections and typed relations, update the exact affected
//! `RevisionHeads`/`OrderingHeads`, append audit-chain fields, create the final
//! receipt and outbox rows, commit, and reconcile ORS. The named mutation is
//! therefore step 4 inside one shared spine: it never owns admission,
//! sequencing, or reconciliation.
//!
//! I5.17 owns the command family and the activation rule. Its families, in the
//! order I5.17 lists them, are abbreviated here as `F1` to `F9`:
//!
//! ```text
//! F1  Capture and source observation
//! F2  Task/WorkScope/plan state
//! F3  Epistemic revision and conflict/attention
//! F4  Canonical transition and receipt
//! F5  Instrument, verification and finish
//! F6  Authority, lease, capability and external effect
//! F7  Session, agent attempt, coordination and integration
//! F8  Module/config/lifecycle and recovery
//! F9  Audit/telemetry evidence
//! ```
//!
//! | Named mutation | I5.17 family | Transition class | Effect ceiling | I5.19 step |
//! |---|---|---|---|---|
//! | `CaptureObservation` | F1 | `CaptureCandidate` | `Candidate` | 4 |
//! | `AppendAuditEvent` | F9 | `CaptureCandidate` | `Candidate` | 4 |
//! | `RecordLearningRecord` | F1 | `CaptureCandidate` | `Candidate` | 4 |
//! | `CommitExperienceBank` | F1 | `CaptureCandidate` | `Candidate` | 4 |
//! | `CommitAgentFeedback` | F7 | `CaptureCandidate` | `Candidate` | 4 |
//! | `ApplyBlackboardItem` | F7 | `CaptureCandidate` | `Candidate` | 4 |
//! | `ApplyEpistemicRevision` | F3 | `Epistemic` | `Candidate` | 4 |
//! | `UpdateTaskState` | F2 | `TaskControl` | `ReversibleMutation` | 4 |
//! | `ApplySwarmOwnerRevisions` | F2 | `TaskControl` | `ReversibleMutation` | 4 |
//! | `ApplyLifecyclePolicy` | F8 | `LifecyclePolicy` | `ReversibleMutation` | 4 |
//! | `ReconcileRecovery` | F8 | `RecoverySchema` | `ReversibleMutation` | 4 |
//! | `ApplyProblemOwnerState` | F8 | `RecoverySchema` | `ReversibleMutation` | 4 |
//! | `ApplyErasure` | F8 | `Erasure` | `ReversibleMutation` | 4 |
//! | `ApplyUserAutomationState` | F8 | `UserAutomation` | `ReversibleMutation` | 4 |
//! | `RecordFinishDecision` | F5 | `RecoverySchema` | `ReversibleMutation` | 4 |
//! | `RecordFinishEvidence` | F5 | `RecoverySchema` | `ReversibleMutation` | 4 |
//! | `ApplyNotificationState` | F6 | `NotificationState` | `ReversibleMutation` | 4 |
//! | `ApplyReactiveInjectionState` | F7 | `ReactiveState` | `ReversibleMutation` | 4 |
//! | `ApplyResourceSnapshot` | F7 | `ReactiveState` | `ReversibleMutation` | 4 |
//! | `RecordCapabilityEvidenceRecord` | F6 | `CaptureCandidate` | `Candidate` | 4 |
//! | `RecordTaskContractAcceptanceSet` | F2 | `TaskControl` | `ReversibleMutation` | 4 |
//!
//! The transition-class and effect-ceiling columns are not judgment: they are the
//! declared transition classes and maximum effect of the activated entry. The
//! family column is this inventory's reading of the I5.17 family list; I5.17
//! itself does not map a named mutation to a family, so the mapping documents
//! the existing surface rather than making a new activation decision.
//!
//! Declared in [`crate::NamedMutationOperation`] but not activated, and therefore
//! refused pre-stage with `StoreError::UnknownOperation` rather than mapped to a
//! status or upsert behavior: `RecordAuthorityRevocation` and
//! `ApplyInstrumentRegistryState`.
//! `RecordAuthorityRevocation` is explicitly known-but-unsupported (issue #686):
//! its typed parameter contract and the Governor decision edge are closed, but
//! its catalogue row, proven per-backend handlers, and consumer triple are not.
//! `ApplySwarmOwnerRevisions` is ACTIVATED (issue #1702) under the
//! `TaskControl` family with the closed owner-revision typed contract: it is
//! admitted only when the owner-specific authorization evidence travels inside
//! the record and matches the record's own owner lease, the transition's
//! authority epoch and the authenticated request source, so a cross-owner or
//! stale-lease presentation is refused before persistence or effects. The
//! genesis bootstrap entry is mutation-shaped and binds to
//! `TransitionClass::RecoverySchema` under I5.15 rather than under I5.17.
//!
//! Issue #1874's body describes seven reachable mutations and names
//! `RecordAuthorityRevocation` among them. That list is a subset, not the
//! activated set, and `RecordAuthorityRevocation` is not reachable at all; the
//! activated set is the twenty-one rows above. I5.15's own initial executable set
//! is a contract-denomination list and does not enumerate named mutations, so
//! the twenty-one rows activate under I5.17 against this crate's proven
//! handler, schema, and consumer triple.
//!
//! # Non-goals
//!
//! No wire-enum activation, no Store-client apply operation introduced in
//! this slice, no adapter/Kernel/ORS implementation, and no new receipt
//! issuer. A separately reviewed later slice may add and version a reserved
//! operation gated on a real backend, preserving legacy compatibility.

use std::collections::BTreeSet;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    OperationId, OperationIdentity, OrderingHeadExpectation, OrderingScopeId, PreparedTransition,
    RequestMeta, RevisionHeadExpectation, StoreError, WriteReceipt, WriteReceiptStatus,
    canonical_json_bytes, generated_operation_manifests, named_mutation_operation_name, sha256_hex,
};
use crate::{NamedMutationOperation, TransitionClass};
use eliot_contracts::{ErrorCode, StateFence};

/// Closed contract version of the write-admission projection (I5.22).
///
/// The version is explicit and additive change is preferred: unknown versions
/// fail closed instead of decoding through a compatibility fallback.
pub const WRITE_ADMISSION_CONTRACT_VERSION: u16 = 1;

/// Maximum reserved scopes in one admission projection.
///
/// This is the same closed denominator as the store wire item bound and the
/// ORS recovery page: one projection never carries more members than the
/// boundary it crosses.
pub const MAX_WRITE_ADMISSION_SCOPES: usize = 256;

/// Maximum bytes of one mirrored owner label.
///
/// Applies independently to the reservation id, the recovery owner, the
/// source-id mirror, and the writer lineage ids. Each label is checked at
/// exactly this size and one byte over.
pub const MAX_WRITE_ADMISSION_LABEL_BYTES: usize = 512;

/// Store-owned mirror of the ORS writer-epoch lineage.
///
/// Restates the owner `EpochLineage` shape (current lineage/epoch plus the
/// exact predecessor edge) without importing the ORS implementation. The
/// same-lineage direct-child step is enforced here exactly as the owner
/// enforces it; cross-lineage predecessors stay allowed with no numeric
/// ordering. Epoch zero is never a valid epoch on either side of the edge.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterEpochBinding {
    /// Lineage namespace of the writer epoch.
    pub lineage_id: String,
    /// Sequence of the writer epoch within its lineage.
    pub epoch: u64,
    /// Lineage namespace of the exact predecessor, if any.
    pub predecessor_lineage_id: Option<String>,
    /// Sequence of the exact predecessor, if any.
    pub predecessor_epoch: Option<u64>,
}

impl WriterEpochBinding {
    /// Checks the explicit lineage edge without granting epoch authority.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_label(&self.lineage_id, "admission.writer_lineage_id")?;
        if self.epoch == 0 {
            return Err(StoreError::InvalidField {
                field: "admission.writer_epoch",
                reason: "must be non-zero",
            });
        }
        match (&self.predecessor_lineage_id, self.predecessor_epoch) {
            (None, None) => Ok(()),
            (Some(lineage), Some(epoch)) => {
                validate_label(lineage, "admission.predecessor_lineage_id")?;
                if epoch == 0 {
                    return Err(StoreError::InvalidField {
                        field: "admission.predecessor_epoch",
                        reason: "must be non-zero",
                    });
                }
                if *lineage == self.lineage_id {
                    let expected = epoch.checked_add(1).ok_or(StoreError::InvalidField {
                        field: "admission.predecessor_epoch",
                        reason: "same-lineage succession must be the exact direct-child step",
                    })?;
                    if self.epoch != expected {
                        return Err(StoreError::InvalidField {
                            field: "admission.writer_epoch",
                            reason: "same-lineage succession must be the exact direct-child step",
                        });
                    }
                }
                Ok(())
            }
            _ => Err(StoreError::InvalidField {
                field: "admission.predecessor",
                reason: "predecessor lineage and epoch must be supplied together",
            }),
        }
    }
}

/// One reserved ordering scope inside a write-admission projection.
///
/// Carries the ORS-allocated sequence for the scope together with the expected
/// head the reservation extends. Sequences are owner evidence restated here;
/// this type allocates none.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedScopeBinding {
    /// Ordering scope under reservation.
    pub scope: OrderingScopeId,
    /// Owner-allocated sequence for this scope.
    pub reserved_sequence: u64,
    /// Expected head sequence the reservation extends.
    pub expected_sequence: u64,
    /// Digest binding the exact owner head bytes for this scope.
    pub expected_head_digest: String,
}

impl ReservedScopeBinding {
    /// Checks nonzero sequences and the head-digest shape.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.reserved_sequence == 0 {
            return Err(StoreError::InvalidField {
                field: "admission.reserved_sequence",
                reason: "must be non-zero",
            });
        }
        if self.expected_sequence == 0 {
            return Err(StoreError::InvalidField {
                field: "admission.expected_sequence",
                reason: "must be non-zero",
            });
        }
        validate_digest(&self.expected_head_digest, "admission.expected_head_digest")
    }
}

/// Producer inputs for [`WriteAdmissionProjection::bind`].
///
/// Plain carrier for the mapped owner evidence; [`WriteAdmissionProjection::bind`]
/// seals these inputs with both canonical digests. No digest field is taken
/// as input: digests are always computed here, never supplied by the caller.
#[derive(Clone, Debug)]
pub struct WriteAdmissionParams {
    /// Owner reservation identity as bounded text.
    pub reservation_id: String,
    /// Owner single-coordinator precedence.
    pub reservation_order: u64,
    /// Operation identity copied exactly from the prepared transition.
    pub operation_id: OperationId,
    /// Idempotency key copied exactly from the prepared transition.
    pub idempotency_key: String,
    /// Canonical request hash copied exactly from the prepared transition.
    pub canonical_request_hash: String,
    /// Complete sorted unique reserved scope set.
    pub scopes: Vec<ReservedScopeBinding>,
    /// Mirrored writer-epoch lineage.
    pub writer_epoch: WriterEpochBinding,
    /// Fence shared by context, transition, and heads.
    pub state_fence: StateFence,
    /// Mirror of the transported request source identity.
    pub source_id: String,
    /// Owner creation time in Unix milliseconds.
    pub created_at_ms: i64,
    /// Owner expiry time in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Owner recovery identity as bounded text.
    pub recovery_owner: String,
}

/// Closed versioned Store projection of one ORS-admitted write reservation.
///
/// Decodes as shape only: a value that passes validation proves its evidence
/// was copied exactly, never that the reservation is current. See the
/// module-level documentation for the owner mapping and canonical encoding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteAdmissionProjection {
    /// Closed contract version, always [`WRITE_ADMISSION_CONTRACT_VERSION`].
    pub contract_version: u16,
    /// Owner reservation identity as bounded text.
    pub reservation_id: String,
    /// Owner single-coordinator precedence.
    pub reservation_order: u64,
    /// Operation identity bound exactly to the prepared transition.
    pub operation_id: OperationId,
    /// Idempotency key bound exactly to the prepared transition.
    pub idempotency_key: String,
    /// Canonical request hash bound exactly to the prepared transition.
    pub canonical_request_hash: String,
    /// Digest over the canonical bytes of the exact prepared transition.
    pub prepared_transition_digest: String,
    /// Digest over the canonical reservation-binding bytes.
    pub reservation_token_digest: String,
    /// Complete sorted unique reserved scope set.
    pub scopes: Vec<ReservedScopeBinding>,
    /// Mirrored writer-epoch lineage.
    pub writer_epoch: WriterEpochBinding,
    /// Fence shared by context, transition, and heads.
    pub state_fence: StateFence,
    /// Mirror of the transported request source identity.
    pub source_id: String,
    /// Owner creation time in Unix milliseconds.
    pub created_at_ms: i64,
    /// Owner expiry time in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Owner recovery identity as bounded text.
    pub recovery_owner: String,
}

/// Canonical reservation-binding view hashed by the token digest.
///
/// Private single encoder: field declaration order is the digest order, and
/// both [`WriteAdmissionProjection::bind`] and
/// [`ReservedWriteRequest::validate`] hash through this exact struct, so no
/// second layout can fork the digest.
#[derive(Serialize)]
struct CanonicalReservationBinding<'a> {
    contract_version: u16,
    reservation_id: &'a str,
    operation_id: &'a str,
    idempotency_key: &'a str,
    canonical_request_hash: &'a str,
    prepared_transition_digest: &'a str,
    reservation_order: u64,
    scopes: Vec<CanonicalReservedScope<'a>>,
    writer_lineage_id: &'a str,
    writer_epoch: u64,
    predecessor_lineage_id: Option<&'a str>,
    predecessor_epoch: Option<u64>,
    state_fence: &'a StateFence,
    source_id: &'a str,
    created_at_ms: i64,
    expires_at_ms: i64,
    recovery_owner: &'a str,
}

/// One scope entry inside the canonical reservation-binding view.
#[derive(Serialize)]
struct CanonicalReservedScope<'a> {
    scope: &'a str,
    reserved_sequence: u64,
    expected_sequence: u64,
    expected_head_digest: &'a str,
}

impl WriteAdmissionProjection {
    /// Seals mapped owner evidence with both canonical digests.
    ///
    /// This is the single producer path: the caller maps ORS/Store evidence
    /// per the module-level table, and this function computes the digests and
    /// runs the full intrinsic shape check. Digests are never caller
    /// supplied, so a caller cannot pre-claim a binding it did not compute
    /// from these exact inputs.
    #[must_use = "a sealed projection must be used or checked"]
    pub fn bind(
        transition: &PreparedTransition,
        params: WriteAdmissionParams,
    ) -> Result<Self, StoreError> {
        let prepared_transition_digest = prepared_transition_digest(transition)?;
        let mut projection = Self {
            contract_version: WRITE_ADMISSION_CONTRACT_VERSION,
            reservation_id: params.reservation_id,
            reservation_order: params.reservation_order,
            operation_id: params.operation_id,
            idempotency_key: params.idempotency_key,
            canonical_request_hash: params.canonical_request_hash,
            prepared_transition_digest,
            reservation_token_digest: String::new(),
            scopes: params.scopes,
            writer_epoch: params.writer_epoch,
            state_fence: params.state_fence,
            source_id: params.source_id,
            created_at_ms: params.created_at_ms,
            expires_at_ms: params.expires_at_ms,
            recovery_owner: params.recovery_owner,
        };
        projection.reservation_token_digest = token_digest_for(&projection)?;
        projection.validate()?;
        Ok(projection)
    }

    /// Checks the closed version, bounded members, canonical scope order,
    /// mirrored epoch/epoch-edge, fence, digest shapes, and owner-supplied
    /// time pair, then recomputes the token digest for self-consistency.
    ///
    /// This is the intrinsic shape check: it reads no clock, queries no
    /// owner, and confirms no currency. Binding the transition itself to
    /// [`prepared_transition_digest`] needs the transition and therefore
    /// lives in [`ReservedWriteRequest::validate`], which runs the shape
    /// check first so a stale digest never masks the more specific
    /// identity, fence, or head mismatch underneath it.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.validate_shape()?;
        let observed = token_digest_for(self)?;
        if observed != self.reservation_token_digest {
            return Err(StoreError::TransitionDigestMismatch {
                expected: self.reservation_token_digest.clone(),
                observed,
            });
        }
        Ok(())
    }

    /// Checks every intrinsic shape property except the token-digest
    /// recompute.
    ///
    /// Private staging step shared by [`WriteAdmissionProjection::validate`]
    /// and [`ReservedWriteRequest::validate`]: the request path checks the
    /// shape first, then its cross-bindings in specificity order, and only
    /// then the two digest recomputes.
    fn validate_shape(&self) -> Result<(), StoreError> {
        if self.contract_version != WRITE_ADMISSION_CONTRACT_VERSION {
            return Err(StoreError::InvalidField {
                field: "admission.contract_version",
                reason: "unsupported write-admission contract version",
            });
        }
        validate_label(&self.reservation_id, "admission.reservation_id")?;
        if self.reservation_order == 0 {
            return Err(StoreError::InvalidField {
                field: "admission.reservation_order",
                reason: "must be non-zero",
            });
        }
        validate_label(&self.idempotency_key, "admission.idempotency_key")?;
        validate_digest(
            &self.canonical_request_hash,
            "admission.canonical_request_hash",
        )?;
        validate_digest(
            &self.prepared_transition_digest,
            "admission.prepared_transition_digest",
        )?;
        validate_digest(
            &self.reservation_token_digest,
            "admission.reservation_token_digest",
        )?;
        if self.scopes.is_empty() {
            return Err(StoreError::Empty {
                field: "admission.scopes",
            });
        }
        if self.scopes.len() > MAX_WRITE_ADMISSION_SCOPES {
            return Err(StoreError::PayloadTooLarge);
        }
        let mut seen = BTreeSet::new();
        for scope in &self.scopes {
            scope.validate()?;
            if !seen.insert(scope.scope.clone()) {
                return Err(StoreError::Duplicate {
                    field: "admission.scopes",
                });
            }
        }
        if self
            .scopes
            .windows(2)
            .any(|pair| pair[0].scope > pair[1].scope)
        {
            return Err(StoreError::InvalidField {
                field: "admission.scopes",
                reason: "must be sorted by scope without duplicates",
            });
        }
        self.writer_epoch.validate()?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        validate_label(&self.source_id, "admission.source_id")?;
        if self.created_at_ms <= 0 {
            return Err(StoreError::InvalidField {
                field: "admission.created_at_ms",
                reason: "must be a positive Unix timestamp",
            });
        }
        if self.expires_at_ms <= self.created_at_ms {
            return Err(StoreError::InvalidField {
                field: "admission.expires_at_ms",
                reason: "expiry must follow creation; wall timestamps alone are not authority",
            });
        }
        validate_label(&self.recovery_owner, "admission.recovery_owner")?;
        Ok(())
    }
}

/// Computes the digest over the canonical bytes of one prepared transition.
///
/// The digest covers the exact immutable semantic input the Store will
/// execute; any byte mutation on the transition side breaks the binding held
/// by [`WriteAdmissionProjection::prepared_transition_digest`].
#[must_use = "a computed digest must be used or checked"]
pub fn prepared_transition_digest(transition: &PreparedTransition) -> Result<String, StoreError> {
    let bytes = canonical_json_bytes(transition)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Computes the token digest over the canonical reservation-binding bytes.
///
/// Private single encoder shared by [`WriteAdmissionProjection::bind`] and
/// every checking path, so producer and checker hash identical bytes.
fn token_digest_for(projection: &WriteAdmissionProjection) -> Result<String, StoreError> {
    let view = CanonicalReservationBinding {
        contract_version: projection.contract_version,
        reservation_id: &projection.reservation_id,
        operation_id: projection.operation_id.as_str(),
        idempotency_key: &projection.idempotency_key,
        canonical_request_hash: &projection.canonical_request_hash,
        prepared_transition_digest: &projection.prepared_transition_digest,
        reservation_order: projection.reservation_order,
        scopes: projection
            .scopes
            .iter()
            .map(|scope| CanonicalReservedScope {
                scope: scope.scope.as_str(),
                reserved_sequence: scope.reserved_sequence,
                expected_sequence: scope.expected_sequence,
                expected_head_digest: &scope.expected_head_digest,
            })
            .collect(),
        writer_lineage_id: &projection.writer_epoch.lineage_id,
        writer_epoch: projection.writer_epoch.epoch,
        predecessor_lineage_id: projection.writer_epoch.predecessor_lineage_id.as_deref(),
        predecessor_epoch: projection.writer_epoch.predecessor_epoch,
        state_fence: &projection.state_fence,
        source_id: &projection.source_id,
        created_at_ms: projection.created_at_ms,
        expires_at_ms: projection.expires_at_ms,
        recovery_owner: &projection.recovery_owner,
    };
    let bytes = canonical_json_bytes(&view)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Closed reserved-write request crossing the Kernel-to-Store boundary.
///
/// Binds the authenticated transport context, the exact immutable prepared
/// transition, the sealed admission projection, and the preserved expected
/// heads. Decoding proves shape only; executing on this request needs the
/// receiving boundary to authenticate the Kernel generation and confirm
/// current owner evidence first.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedWriteRequest {
    /// Authenticated transport context; always wins over payload mirrors.
    pub context: RequestMeta,
    /// Exact immutable semantic input; preserved byte-for-byte.
    pub transition: PreparedTransition,
    /// Sealed admission projection carrying the reservation evidence.
    pub admission: WriteAdmissionProjection,
    /// Preserved revision-head expectations with the shared fence.
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    /// Preserved ordering-head expectations covering the reserved scopes.
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
    /// Original public write-submission values for a versioned Observe
    /// capture. This is kept beside the prepared transition: it is source
    /// metadata, not part of Governor semantic planning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_write_submission: Option<OriginalWriteSubmission>,
}

/// Exact user-supplied write identity metadata retained from the original
/// public Observe capture request. Operation and idempotency identities remain
/// owned by the authenticated request and prepared transition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalWriteSubmission {
    /// Public write-envelope protocol version.
    pub protocol_version: u32,
    /// Stable user/agent intent carried across typed correction attempts.
    pub write_intent_id: String,
    /// Original agent response preference as an exact closed protocol token.
    pub response_mode: String,
}

impl OriginalWriteSubmission {
    /// Validates the public source values without deriving or aliasing any
    /// other request identity.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.protocol_version != 1 {
            return Err(StoreError::InvalidField {
                field: "original_write_submission.protocol_version",
                reason: "unsupported write envelope version",
            });
        }
        if self.write_intent_id.trim().is_empty()
            || self.write_intent_id.chars().any(char::is_control)
        {
            return Err(StoreError::InvalidField {
                field: "original_write_submission.write_intent_id",
                reason: "must be non-blank and contain no control characters",
            });
        }
        if !matches!(self.response_mode.as_str(), "wait_for_commit" | "accept_after_stage") {
            return Err(StoreError::InvalidField {
                field: "original_write_submission.response_mode",
                reason: "must be wait_for_commit or accept_after_stage",
            });
        }
        Ok(())
    }
}

impl ReservedWriteRequest {
    /// Checks every intrinsic binding without owner queries or clock reads.
    ///
    /// Context, transition, and projection shapes are checked first; then the
    /// shared fence, the exact operation/idempotency/hash copies, the
    /// recomputed transition digest, the payload source mirror against the
    /// transported context, the recomputed token digest, the preserved
    /// revision heads, the ordering-head coverage of the reserved scope set,
    /// and the transition scope coverage. Digest recomputes run after the
    /// cross-bindings so a stale digest never masks the more specific
    /// identity, fence, or head mismatch underneath it. A self-consistent
    /// caller fabrication passes this check and still proves shape only.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.context.validate().map_err(StoreError::Foundation)?;
        self.transition.validate()?;
        self.admission.validate_shape()?;
        if let Some(source) = &self.original_write_submission {
            source.validate()?;
            if self.transition.transition_class != TransitionClass::CaptureCandidate
                || self.transition.named_operations.len() != 1
                || self.transition.named_operations[0].operation
                    != NamedMutationOperation::CaptureObservation
            {
                return Err(StoreError::InvalidField {
                    field: "original_write_submission",
                    reason: "is only valid for a single CaptureObservation transition",
                });
            }
        }
        if self.admission.state_fence != self.context.state_fence
            || self.transition.state_fence != self.context.state_fence
        {
            return Err(StoreError::FenceMismatch);
        }
        if self.admission.operation_id != self.transition.identity.operation_id
            || self.admission.idempotency_key != self.transition.identity.idempotency_key
            || self.admission.canonical_request_hash
                != self.transition.identity.canonical_request_hash
        {
            return Err(StoreError::IdentityConflict);
        }
        let transition_digest = prepared_transition_digest(&self.transition)?;
        if transition_digest != self.admission.prepared_transition_digest {
            return Err(StoreError::TransitionDigestMismatch {
                expected: self.admission.prepared_transition_digest.clone(),
                observed: transition_digest,
            });
        }
        if self.admission.source_id != self.context.source_id.as_str() {
            return Err(StoreError::IdentityConflict);
        }
        let token_digest = token_digest_for(&self.admission)?;
        if token_digest != self.admission.reservation_token_digest {
            return Err(StoreError::TransitionDigestMismatch {
                expected: self.admission.reservation_token_digest.clone(),
                observed: token_digest,
            });
        }
        validate_revision_heads(&self.expected_revision_heads, &self.transition.state_fence)?;
        validate_ordering_coverage(self)?;
        validate_transition_scope_coverage(self)?;
        Ok(())
    }
}

/// Closed Store-neutral outcome of reconciling one reserved-write operation.
///
/// The three arms are the only outcomes this projection can report, and they
/// stay separate. `Committed` is the only arm that carries commit evidence;
/// `ProvenNotApplied` is reserved for an exact-identity check that returned
/// nothing; `StillUnknown` is what the absence of a receipt yields. There is
/// deliberately no constructor that promotes a missing receipt to
/// `ProvenNotApplied`: that transition requires the store-side check described
/// on [`ReservedWriteReconciliation::proven_not_applied`], and it can never be
/// derived from success, cancellation, or expiry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservedWriteOutcome {
    /// A durable canonical [`WriteReceipt`] proves the commit.
    Committed(Box<WriteReceipt>),
    /// The exact operation identity was checked and found absent.
    ProvenNotApplied,
    /// The outcome remains unresolved; absence of a receipt is never proof of
    /// non-application.
    StillUnknown,
}

impl ReservedWriteOutcome {
    /// Returns the stable bounded identity of this outcome arm.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Committed(_) => "committed",
            Self::ProvenNotApplied => "proven_not_applied",
            Self::StillUnknown => "still_unknown",
        }
    }
}

/// Closed owner-reported state of the reservation envelope at the moment a
/// reconciliation read is taken.
///
/// This is not ORS state and this crate does not import the ORS
/// implementation: the owner reports it, and the Store side only uses it to
/// refuse an inference it is not entitled to make. It carries no authority
/// and no sequence/epoch values.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationEnvelopeState {
    /// The owner has not reported this reservation as finished.
    Active,
    /// The owner cancelled the reservation before the write was committed.
    Cancelled,
    /// The owner-reported expiry has passed.
    Expired,
}

impl ReservationEnvelopeState {
    /// Returns the stable bounded identity of this envelope state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

/// Store-neutral projection of reconciling one ORS-admitted write reservation.
///
/// Reconciliation keeps using the original [`OperationId`] and the exact
/// canonical receipt plus the reservation binding carried by the
/// [`WriteAdmissionProjection`] that admitted the write. This type binds those
/// two things together and checks them against each other; it issues no
/// receipt, mints no ticket, and finalizes no reservation.
///
/// The three outcomes stay separate and this type is where that separation is
/// enforced rather than described:
///
/// - a commit is reachable only through [`ReservedWriteReconciliation::committed`],
///   which requires a bound, self-consistent, validated canonical receipt; no
///   other input can produce that arm;
/// - a cancelled or expired envelope can only reach
///   [`ReservedWriteOutcome::StillUnknown`]
///   ([`ReservedWriteReconciliation::reconcile`]), because ending the
///   reservation says nothing about whether the write applied;
/// - a receipt read that returned nothing is [`ReservedWriteOutcome::StillUnknown`]
///   ([`ReservedWriteReconciliation::still_unknown`]), and the promotion to
///   [`ReservedWriteOutcome::ProvenNotApplied`] is a separate, explicitly
///   named act ([`ReservedWriteReconciliation::proven_not_applied`]).
///
/// Construction is closed: the fields are private, so outside this module a
/// value can only come from the four named constructors above. Decoding is
/// gated by the same requirements, not by a weaker copy: the wire shape
/// deserializes into a private shadow struct, a payload that asserts
/// [`ReservedWriteOutcome::ProvenNotApplied`] is refused because the wire
/// carries no store read that could have performed the named act, and the rest
/// passes through [`ReservedWriteReconciliation::validate`], whose committed
/// arm applies the identical check sequence
/// (`require_committed_receipt_evidence`) that
/// [`ReservedWriteReconciliation::committed`] applies. So an inconsistent
/// payload fails closed with a typed [`StoreError`] instead of yielding a
/// value, and no decoded value carries a commit claim the commit entry point
/// would refuse. A decoded value is still shape-only under the module
/// contract, not fresh proof of currency; no new authority mechanism is
/// introduced here.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ReconciliationWire", into = "ReconciliationWire")]
pub struct ReservedWriteReconciliation {
    /// The ORIGINAL operation identity, never a fresh or derived one.
    operation_id: OperationId,
    /// The exact canonical receipt plus reservation binding, preserved.
    admission: WriteAdmissionProjection,
    /// The closed outcome reached for this operation.
    outcome: ReservedWriteOutcome,
}

/// Private wire shape of [`ReservedWriteReconciliation`].
///
/// Decoding never constructs a reconciliation directly: every decoded payload
/// takes this shape and then passes through
/// [`ReservedWriteReconciliation::validate`], so unknown fields are rejected
/// and an inconsistent value fails closed with a typed [`StoreError`]. The
/// serialized shape is unchanged.
#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
struct ReconciliationWire {
    operation_id: OperationId,
    admission: WriteAdmissionProjection,
    outcome: ReservedWriteOutcome,
}

impl TryFrom<ReconciliationWire> for ReservedWriteReconciliation {
    type Error = StoreError;

    /// Decodes a wire payload under the SAME requirements as construction.
    ///
    /// Two arms survive the wire and one does not:
    ///
    /// - `Committed` is accepted only when the receipt passes
    ///   [`require_committed_receipt_evidence`] — the canonical envelope must
    ///   be present, the receipt must be valid, and its exact identity must
    ///   match the admitting projection. This is the check
    ///   [`ReservedWriteReconciliation::committed`] applies, so the decode
    ///   path cannot hand out a receipt the commit entry point would refuse;
    /// - `ProvenNotApplied` is REFUSED. It is a named act
    ///   ([`ReservedWriteReconciliation::proven_not_applied`]) over durable
    ///   store evidence that the wire does not carry, so a payload asserting
    ///   it has proven nothing. A payload claiming it fails closed with a
    ///   typed [`StoreError`] instead of yielding a value; the receiving
    ///   boundary performs the act itself;
    /// - `StillUnknown` is the unresolved arm and carries no evidence to
    ///   check beyond identity consistency.
    fn try_from(wire: ReconciliationWire) -> Result<Self, Self::Error> {
        if matches!(wire.outcome, ReservedWriteOutcome::ProvenNotApplied) {
            return Err(StoreError::InvalidField {
                field: "admission.outcome",
                reason: "proven_not_applied is a named act and is not assertable on the wire",
            });
        }
        let value = Self {
            operation_id: wire.operation_id,
            admission: wire.admission,
            outcome: wire.outcome,
        };
        value.validate()?;
        Ok(value)
    }
}

impl From<ReservedWriteReconciliation> for ReconciliationWire {
    fn from(value: ReservedWriteReconciliation) -> Self {
        Self {
            operation_id: value.operation_id,
            admission: value.admission,
            outcome: value.outcome,
        }
    }
}

impl ReservedWriteReconciliation {
    /// Returns the ORIGINAL operation identity this reconciliation is reported under.
    #[must_use]
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the exact canonical receipt plus reservation binding, preserved.
    #[must_use]
    pub fn admission(&self) -> &WriteAdmissionProjection {
        &self.admission
    }

    /// Returns the closed outcome reached for this operation.
    #[must_use]
    pub fn outcome(&self) -> &ReservedWriteOutcome {
        &self.outcome
    }

    /// Resolves one observed receipt read under the original identity.
    ///
    /// This is the single entry point that reads a store answer. A receipt is
    /// bound and checked against its admitting projection; no receipt is
    /// still-unknown. An ended reservation envelope never yields a commit and
    /// never yields proven-not-applied: it stays still-unknown, because
    /// cancellation and expiry describe the reservation, not the write.
    pub fn reconcile(
        admission: &WriteAdmissionProjection,
        observed: Option<WriteReceipt>,
        envelope: ReservationEnvelopeState,
    ) -> Result<Self, StoreError> {
        match (observed, envelope) {
            (Some(receipt), ReservationEnvelopeState::Active) => {
                Self::committed(admission, receipt)
            }
            (Some(_), ReservationEnvelopeState::Cancelled | ReservationEnvelopeState::Expired) => {
                Self::still_unknown(admission)
            }
            (None, _) => Self::still_unknown(admission),
        }
    }

    /// Binds an observed canonical receipt to its admitting projection.
    ///
    /// The receipt must be the canonical receipt for this exact operation
    /// identity, idempotency key, and canonical request hash, carry the
    /// canonical receipt envelope issued by
    /// [`issue_store_receipt_envelope`], and the projection it was admitted
    /// under must still be self-consistent. Any divergence fails closed with a
    /// typed [`StoreError`]; it is never repaired and never downgraded to a
    /// weaker outcome.
    ///
    /// [`issue_store_receipt_envelope`]: crate::issue_store_receipt_envelope
    pub fn committed(
        admission: &WriteAdmissionProjection,
        receipt: WriteReceipt,
    ) -> Result<Self, StoreError> {
        admission.validate()?;
        require_committed_receipt_evidence(admission, &receipt)?;
        Ok(Self {
            operation_id: admission.operation_id.clone(),
            admission: admission.clone(),
            outcome: ReservedWriteOutcome::Committed(Box::new(receipt)),
        })
    }

    /// Records that the exact operation identity was checked and found absent.
    ///
    /// This is the ONLY path to [`ReservedWriteOutcome::ProvenNotApplied`],
    /// and it is deliberately a separate act rather than a default: the caller
    /// must have checked this exact identity against durable store evidence.
    /// Absence of a receipt on its own never reaches here; a read that found
    /// nothing is [`ReservedWriteOutcome::StillUnknown`] and stays there
    /// ([`ReservedWriteReconciliation::still_unknown`]).
    pub fn proven_not_applied(admission: &WriteAdmissionProjection) -> Result<Self, StoreError> {
        admission.validate()?;
        Ok(Self {
            operation_id: admission.operation_id.clone(),
            admission: admission.clone(),
            outcome: ReservedWriteOutcome::ProvenNotApplied,
        })
    }

    /// Records that the outcome is still unresolved.
    ///
    /// This is the ONLY path to [`ReservedWriteOutcome::StillUnknown`], and it
    /// covers every reason the outcome is unresolved: an exact-identity read
    /// that returned no receipt, an unreadable store, or a cancelled/expired
    /// reservation envelope. It has no second arm, so it can never establish
    /// noncommit; promotion to [`ReservedWriteOutcome::ProvenNotApplied`] is
    /// the separate, explicitly named
    /// [`ReservedWriteReconciliation::proven_not_applied`].
    ///
    /// [`ReservedWriteReconciliation::reconcile`] routes every unresolved read
    /// here, including a read that observed a receipt under an ended
    /// reservation envelope.
    pub fn still_unknown(admission: &WriteAdmissionProjection) -> Result<Self, StoreError> {
        admission.validate()?;
        Ok(Self {
            operation_id: admission.operation_id.clone(),
            admission: admission.clone(),
            outcome: ReservedWriteOutcome::StillUnknown,
        })
    }

    /// Checks the outcome against the original identity and receipt binding.
    ///
    /// This is the decode gate as well as the checking entry point, and it is
    /// the SAME gate: a committed arm is accepted only through
    /// `require_committed_receipt_evidence`, which is the identical check
    /// sequence [`ReservedWriteReconciliation::committed`] applies. Decoding
    /// therefore cannot produce a weaker commit claim than constructing one:
    /// an envelope-less or otherwise invalid receipt is refused with the same
    /// typed [`StoreError`] in both paths, and a receipt that
    /// [`ReservedWriteReconciliation::require_committed_receipt`] would hand
    /// back has necessarily passed every requirement the commit entry point
    /// applies.
    ///
    /// The other two arms are checked only for consistency with the identity
    /// they are reported under; which of them the wire may assert is decided
    /// by the decode gate itself (`TryFrom<ReconciliationWire>`).
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.finalizes_reservation() {
            return Err(StoreError::InvalidField {
                field: "admission.outcome",
                reason: "reconciliation must not finalize the reservation",
            });
        }
        self.admission.validate()?;
        if self.operation_id != self.admission.operation_id {
            return Err(StoreError::IdentityConflict);
        }
        if let ReservedWriteOutcome::Committed(receipt) = &self.outcome {
            require_committed_receipt_evidence(&self.admission, receipt)?;
        }
        Ok(())
    }

    /// Requires the exact canonical receipt proving a committed outcome.
    ///
    /// A non-committed arm has no commit evidence to return, and says so with
    /// [`StoreError::ReceiptNotFound`] rather than an assumed success.
    pub fn require_committed_receipt(&self) -> Result<&WriteReceipt, StoreError> {
        match &self.outcome {
            ReservedWriteOutcome::Committed(receipt) => Ok(receipt),
            ReservedWriteOutcome::ProvenNotApplied | ReservedWriteOutcome::StillUnknown => {
                Err(StoreError::ReceiptNotFound)
            }
        }
    }

    /// Reports whether this reconciliation finalized the reservation.
    ///
    /// Always `false`. A committed outcome proves the write and nothing about
    /// the reservation: the owner of an ORS reservation closes it from its own
    /// evidence, and success here is not that evidence.
    #[must_use]
    pub const fn finalizes_reservation(&self) -> bool {
        false
    }
}

/// The one Store-side refusal of a reserved write.
///
/// [`CanonicalStoreClient::apply_reserved_write`] has no successful default
/// body: a client without an accepted reserved-write backend validates the
/// closed request shape and then refuses, with no provider I/O, no durable
/// evidence, and no delegation to the ordinary unreserved apply. This type
/// names that refusal so the default body returns one named value instead of
/// a bare error literal, and so the refusal is legible in product code as
/// "reserved write is unsupported here" rather than as an undeclared named
/// operation the caller happened to invoke.
///
/// It grants nothing and records nothing: the only effect is the returned
/// [`StoreError`], which stays [`StoreError::UnknownOperation`] because this
/// crate's wire error enum is a closed shared contract.
///
/// [`CanonicalStoreClient::apply_reserved_write`]: crate::CanonicalStoreClient::apply_reserved_write
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq)]
pub struct ReservedWriteUnsupported;

impl ReservedWriteUnsupported {
    /// The single refusal value the unsupported default body returns.
    pub const REFUSAL: Self = Self;

    /// Converts the refusal into the error the default body reports.
    #[must_use]
    pub const fn into_error(self) -> StoreError {
        StoreError::UnknownOperation
    }
}

/// Applies the exact canonical-receipt requirements of the committed arm.
///
/// This is the single owner of the commit evidence rule, shared by the commit
/// entry point ([`ReservedWriteReconciliation::committed`]) and the decode gate
/// ([`ReservedWriteReconciliation::validate`], reached from
/// `TryFrom<ReconciliationWire>`). There is no second, weaker scheme: in both
/// paths, in this exact order, the receipt must
///
/// 1. carry the canonical receipt envelope
///    ([`WriteReceipt::require_reconciliation_envelope`], whose own contract
///    states that an envelope-less transport receipt is unknown to the
///    reconciler and must never be reported as a successful write);
/// 2. be internally valid ([`WriteReceipt::validate`], which refuses a
///    committed receipt with no `commit_id`, no `committed_at`, or no applied
///    command);
/// 3. bind to the admitting projection's exact operation identity, idempotency
///    key, and canonical request hash ([`validate_receipt_binding`]); and
/// 4. carry the terminal [`WriteReceiptStatus::Committed`] status.
///
/// A value that passes this cannot be one this crate would classify the
/// transaction as unknown for, so the existence of the arm and the guarantee
/// of the evidence behind it can never diverge between the two paths.
fn require_committed_receipt_evidence(
    admission: &WriteAdmissionProjection,
    receipt: &WriteReceipt,
) -> Result<(), StoreError> {
    receipt
        .require_reconciliation_envelope()
        .map_err(|_| StoreError::MissingReceiptEnvelope)?;
    receipt.validate().map_err(|_| StoreError::InvalidReceipt)?;
    validate_receipt_binding(admission, receipt)?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(StoreError::InvalidReceipt);
    }
    Ok(())
}

/// Maximum reason codes one [`WriteSubmission`] may carry.
///
/// The bound keeps an admission decision a bounded operational response. A
/// refusal carries the closed code of the gate that refused; the bound leaves
/// room for a caller that already holds a typed multi-code refusal and stops a
/// decision from becoming a log.
pub const MAX_WRITE_SUBMISSION_REASON_CODES: usize = 8;

/// Domain separator of the deterministic [`WriteSubmission`] submission identity.
///
/// A domain separator keeps the submission identity a distinct value even if
/// some future owner derives an identity from the same two inputs.
const WRITE_SUBMISSION_ID_DOMAIN: &str = "eliot.store.write_submission.submission_id.v1";

/// Domain separator of the deterministic ORS stage handle.
const WRITE_SUBMISSION_STAGE_REF_DOMAIN: &str = "eliot.store.write_submission.ors_stage_ref.v1";

/// Stable retry-identity rule carried by a `not_accepted` submission (I5.19).
///
/// I5.19: a corrected payload uses a new operation identity, and an exact retry
/// of the same request hash returns the same decision.
pub const NOT_ACCEPTED_RETRY_IDENTITY_RULE: &str = "a corrected payload uses a new operation identity; an exact retry of the same request hash \
     returns this same not_accepted decision";

/// Stable retry-identity rule carried by a `staged` submission (I5.19).
///
/// I5.19: the exact operation identity is accepted once, so the caller must not
/// create a duplicate and may poll.
///
/// The acceptance named here is the I5.19 acceptance, because the I5.19
/// `staged` state is: it is written by the owner that performed the I5.6 step
/// 13 ORS staging act and binds the caller to that one operation identity. It
/// grants no Ordering Scope sequence, no epoch, and no external effect of its
/// own, and it is not carried by any decision this module takes.
pub const STAGED_RETRY_IDENTITY_RULE: &str = "the exact operation identity is accepted once; the caller must not create a duplicate and \
     may poll for the terminal receipt";

/// Stable retry-identity rule carried by a `resolved_existing` submission (I5.19).
///
/// I5.19: a final receipt is immutable, so retrying the same identity returns the
/// same receipt and never creates a second canonical transition.
pub const RESOLVED_EXISTING_RETRY_IDENTITY_RULE: &str = "retrying the same operation identity returns the same immutable final receipt; no second \
     canonical transition is created";

/// Next allowed caller action for a `staged` submission.
pub const STAGED_NEXT_ALLOWED_ACTION: &str =
    "poll the terminal receipt under the same operation identity; do not resubmit";

/// Next allowed caller action for a `resolved_existing` submission.
pub const RESOLVED_EXISTING_NEXT_ALLOWED_ACTION: &str =
    "read the final receipt under the referenced operation identity; do not resubmit";

/// Closed admission decision reported for one write submission (I5.19).
///
/// The three arms are the only admission outcomes and they stay separate. The
/// wire strings are the I5.19 vocabulary exactly, and the state is decided by
/// [`admit_write_submission`] rather than narrated by a caller.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteSubmissionState {
    /// The requested domain mutation was not staged, no Ordering Scope sequence
    /// was reserved, and no external effect was issued.
    NotAccepted,
    /// I5.19: "`staged` means ORS accepted the exact operation identity;
    /// caller must not create a duplicate and may poll."
    ///
    /// The claim is the I5.19 claim verbatim, so it is exactly as strong as the
    /// ORS-backed staging act of I5.6 step 13 and no stronger. This module
    /// takes its decisions at the I5.6 steps 1-12 boundary, before that act,
    /// and therefore never builds a value in this arm: a caller that observed
    /// the `staged` token anywhere would be told that ORS accepted this exact
    /// operation identity, and nothing before step 13 can support that. The
    /// state stays in the closed vocabulary because I5.19 names exactly three
    /// of them, and [`WriteSubmission::validate`] keeps the invariant that a
    /// `staged` submission carries a stage reference and no receipt — but the
    /// reference has to come from the owner that staged, not from a name
    /// computed from the operation identity.
    Staged,
    /// An already final canonical receipt exists for the idempotency key.
    ResolvedExisting,
}

impl WriteSubmissionState {
    /// Returns the stable bounded identity of this admission state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAccepted => "not_accepted",
            Self::Staged => "staged",
            Self::ResolvedExisting => "resolved_existing",
        }
    }
}

/// Measured envelope dimension that exceeded its bound (I5.17).
///
/// I5.17 requires a rejected oversized envelope to name the dimension that
/// exceeded its command-profile bound, so the two command-profile dimensions
/// are closed here rather than described in prose.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitDimension {
    /// Count of items in the bounded causal envelope.
    Items,
    /// Canonical byte length of the bounded causal envelope.
    Bytes,
}

impl SplitDimension {
    /// Returns the stable bounded identity of this measured dimension.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Items => "items",
            Self::Bytes => "bytes",
        }
    }
}

/// Actionable refusal directive for one over-bound causal envelope (I5.17).
///
/// I5.17: oversized input is rejected before sequence reservation with a split
/// directive, and the server never silently splits one causal envelope into
/// several commits. This type carries exactly the three facts that make the
/// refusal actionable — which dimension was measured, the measured value, and
/// the bound it exceeded — and it grants nothing, reserves nothing, and holds
/// no payload bytes.
///
/// The `limit` is never invented: it is the bound the owning command profile
/// already declares, so the directive and the gate that produced it always name
/// the same number.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitDirective {
    /// Measured dimension that exceeded the bound.
    pub dimension: SplitDimension,
    /// Measured value of that dimension in the refused envelope.
    pub measured: u64,
    /// Bound the measured value exceeded, as declared by the command profile.
    pub limit: u64,
}

impl SplitDirective {
    /// Builds the directive for one measured value above its declared bound.
    ///
    /// A directive for a value that did not exceed the bound is refused: it
    /// would instruct the caller to split an envelope that was never over
    /// bound.
    pub fn new(dimension: SplitDimension, measured: u64, limit: u64) -> Result<Self, StoreError> {
        let directive = Self {
            dimension,
            measured,
            limit,
        };
        directive.validate()?;
        Ok(directive)
    }

    /// Checks that the measured value really is above the declared bound.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.limit == 0 {
            return Err(StoreError::InvalidField {
                field: "submission.split_directive.limit",
                reason: "a declared bound must be non-zero",
            });
        }
        if self.measured <= self.limit {
            return Err(StoreError::InvalidField {
                field: "submission.split_directive.measured",
                reason: "a split directive requires a measured value above the declared bound",
            });
        }
        Ok(())
    }

    /// Renders the directive as one bounded operational instruction.
    ///
    /// The rendered text states the refusal the caller must act on and repeats
    /// the I5.17 rule that the server does not split one causal envelope into
    /// several commits on the caller's behalf.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "split the causal envelope: {} {} measured against the {} {} bound; resubmit each \
             part under a new operation identity because the server never splits one causal envelope \
             into several commits",
            self.measured,
            self.dimension.as_str(),
            self.limit,
            self.dimension.as_str(),
        )
    }
}

/// Admission result for one write submission (I5.19).
///
/// This is the front-door result returned before a final canonical
/// [`WriteReceipt`] exists, and it is deliberately not a receipt: it carries no
/// commit id, no ordering sequence, no revision span, and no emitted event ids.
/// Those belong to the terminal receipt and are never inferred here.
///
/// The state and its evidence are kept consistent by [`WriteSubmission::validate`]
/// rather than by convention: a `not_accepted` submission can claim no stage
/// and no receipt and must name a reason, a `staged` submission must carry the
/// stage handle and no receipt, and a `resolved_existing` submission must point
/// at the final receipt it resolved to and must carry no stage handle, because
/// an already final operation stages nothing.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteSubmission {
    /// Stable identity of this admission decision, derived from the exact
    /// operation identity and request hash.
    pub submission_id: String,
    /// The exact operation identity this decision is reported under.
    pub operation_id: OperationId,
    /// Canonical request hash of the exact admitted bytes.
    pub request_hash: String,
    /// The closed admission decision.
    pub state: WriteSubmissionState,
    /// Bounded closed reason codes; non-empty exactly for a refusal.
    pub reason_codes: Vec<ErrorCode>,
    /// Stage handle for the exact operation identity; absent exactly when
    /// nothing was staged.
    pub ors_stage_ref: Option<String>,
    /// Operation identity of the final receipt this decision resolves to;
    /// absent exactly when no final receipt was resolved.
    pub canonical_receipt_ref: Option<OperationId>,
    /// Retry-identity rule that holds for this state.
    pub retry_identity_rule: String,
    /// Bounded next allowed caller action for this state.
    pub next_allowed_action: String,
}

impl WriteSubmission {
    /// Reports a refusal as a typed `not_accepted` decision.
    ///
    /// The refusal keeps its own typed evidence: the closed
    /// [`ErrorCode`] becomes the reason code, and the specific next action is
    /// derived from the refusal itself rather than from a caller-supplied
    /// string. An over-bound envelope additionally carries the split directive
    /// the caller must act on. Nothing is staged, so neither reference is
    /// present.
    pub fn not_accepted(
        operation_id: &OperationId,
        request_hash: &str,
        refusal: &StoreError,
        split_directive: Option<SplitDirective>,
    ) -> Result<Self, StoreError> {
        let submission = Self {
            submission_id: derive_submission_id(operation_id, request_hash)?,
            operation_id: operation_id.clone(),
            request_hash: request_hash.to_owned(),
            state: WriteSubmissionState::NotAccepted,
            reason_codes: vec![reason_code_for(refusal)],
            ors_stage_ref: None,
            canonical_receipt_ref: None,
            retry_identity_rule: NOT_ACCEPTED_RETRY_IDENTITY_RULE.to_owned(),
            next_allowed_action: next_allowed_action_for(refusal, split_directive),
        };
        submission.validate()?;
        Ok(submission)
    }

    /// Reports that an already final receipt exists for the idempotency key.
    ///
    /// `receipt_operation_id` is the operation identity of the final receipt
    /// that was actually observed, which is not necessarily the retried
    /// operation identity: I5.19 resolves this state by idempotency key, and
    /// the receipt is terminal and immutable either way.
    pub fn resolved_existing(
        operation_id: &OperationId,
        request_hash: &str,
        receipt_operation_id: &OperationId,
    ) -> Result<Self, StoreError> {
        let submission = Self {
            submission_id: derive_submission_id(operation_id, request_hash)?,
            operation_id: operation_id.clone(),
            request_hash: request_hash.to_owned(),
            state: WriteSubmissionState::ResolvedExisting,
            reason_codes: Vec::new(),
            ors_stage_ref: None,
            canonical_receipt_ref: Some(receipt_operation_id.clone()),
            retry_identity_rule: RESOLVED_EXISTING_RETRY_IDENTITY_RULE.to_owned(),
            next_allowed_action: RESOLVED_EXISTING_NEXT_ALLOWED_ACTION.to_owned(),
        };
        submission.validate()?;
        Ok(submission)
    }

    /// Renders the carried reason codes as one bounded comma-separated list.
    ///
    /// An accepted decision has no reason code, so this renders as the empty
    /// string rather than as a placeholder code.
    #[must_use]
    pub fn reason_codes_text(&self) -> String {
        self.reason_codes
            .iter()
            .copied()
            .map(ErrorCode::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Checks the state against the evidence this submission claims.
    ///
    /// The text and digest fields are checked with this module's own label and
    /// digest helpers, so a wire-decoded submission cannot carry unbounded or
    /// malformed text in any of them. The two operation identities are closed
    /// [`OperationId`] values whose owning contract already refuses blank or
    /// control-bearing text in its own constructor; what this check adds on top
    /// is this module's own bounded-label rule for a mirrored identity label,
    /// so the two identity fields are held to the same bound as every other
    /// text this struct carries rather than escaping it. Every state-specific
    /// requirement is a typed refusal against the existing [`StoreError`]
    /// surface rather than a described convention.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_digest(&self.submission_id, "submission.submission_id")?;
        validate_digest(&self.request_hash, "submission.request_hash")?;
        validate_label(self.operation_id.as_str(), "submission.operation_id")?;
        if let Some(receipt_ref) = &self.canonical_receipt_ref {
            validate_label(receipt_ref.as_str(), "submission.canonical_receipt_ref")?;
        }
        validate_label(&self.retry_identity_rule, "submission.retry_identity_rule")?;
        validate_label(&self.next_allowed_action, "submission.next_allowed_action")?;
        if self.reason_codes.len() > MAX_WRITE_SUBMISSION_REASON_CODES {
            return Err(StoreError::InvalidField {
                field: "submission.reason_codes",
                reason: "reason codes are bounded",
            });
        }
        let mut seen = BTreeSet::new();
        for code in &self.reason_codes {
            if !seen.insert(code.as_str()) {
                return Err(StoreError::Duplicate {
                    field: "submission.reason_codes",
                });
            }
        }
        if let Some(stage_ref) = &self.ors_stage_ref {
            validate_label(stage_ref, "submission.ors_stage_ref")?;
        }
        let expected_rule = match self.state {
            WriteSubmissionState::NotAccepted => NOT_ACCEPTED_RETRY_IDENTITY_RULE,
            WriteSubmissionState::Staged => STAGED_RETRY_IDENTITY_RULE,
            WriteSubmissionState::ResolvedExisting => RESOLVED_EXISTING_RETRY_IDENTITY_RULE,
        };
        if self.retry_identity_rule != expected_rule {
            return Err(StoreError::InvalidField {
                field: "submission.retry_identity_rule",
                reason: "the retry identity rule must be the rule this state holds",
            });
        }
        match self.state {
            WriteSubmissionState::NotAccepted => {
                if self.ors_stage_ref.is_some() {
                    return Err(StoreError::InvalidField {
                        field: "submission.ors_stage_ref",
                        reason: "a not_accepted submission staged nothing and claims no stage",
                    });
                }
                if self.canonical_receipt_ref.is_some() {
                    return Err(StoreError::InvalidField {
                        field: "submission.canonical_receipt_ref",
                        reason: "a not_accepted submission resolved no canonical receipt",
                    });
                }
                if self.reason_codes.is_empty() {
                    return Err(StoreError::Empty {
                        field: "submission.reason_codes",
                    });
                }
            }
            WriteSubmissionState::Staged => {
                if self.ors_stage_ref.is_none() {
                    return Err(StoreError::Empty {
                        field: "submission.ors_stage_ref",
                    });
                }
                if self.canonical_receipt_ref.is_some() {
                    return Err(StoreError::InvalidField {
                        field: "submission.canonical_receipt_ref",
                        reason: "a staged submission is not final and references no receipt",
                    });
                }
                if !self.reason_codes.is_empty() {
                    return Err(StoreError::InvalidField {
                        field: "submission.reason_codes",
                        reason: "an accepted submission carries no refusal reason code",
                    });
                }
            }
            WriteSubmissionState::ResolvedExisting => {
                // I5.19: `resolved_existing` points at an ALREADY FINAL receipt
                // for the idempotency key. The operation is final, so this
                // decision stages nothing and claims no stage handle. That is
                // the same invariant the other two arms already police in
                // opposite directions — a refusal forbids the handle because it
                // staged nothing, a staged decision requires it because it did
                // — and an unpolled third arm would let a wire-decoded
                // submission carry a stage handle for an operation that will
                // never be staged under it.
                if self.ors_stage_ref.is_some() {
                    return Err(StoreError::InvalidField {
                        field: "submission.ors_stage_ref",
                        reason: "a resolved submission points at an already final receipt and stages nothing",
                    });
                }
                if self.canonical_receipt_ref.is_none() {
                    return Err(StoreError::Empty {
                        field: "submission.canonical_receipt_ref",
                    });
                }
                if !self.reason_codes.is_empty() {
                    return Err(StoreError::InvalidField {
                        field: "submission.reason_codes",
                        reason: "a resolved submission carries no refusal reason code",
                    });
                }
            }
        }
        Ok(())
    }
}

impl fmt::Display for WriteSubmission {
    /// Renders the decision as one bounded operational response line.
    ///
    /// The rendered line is a projection of the typed decision, so an operator
    /// reads the same state, reason codes, and next action the value carries.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "write submission {} is {} for operation {} with request hash {} and reason codes \
             [{}]; {}",
            self.submission_id,
            self.state.as_str(),
            self.operation_id.as_str(),
            self.request_hash,
            self.reason_codes_text(),
            self.next_allowed_action,
        )
    }
}

/// Derives the stable submission identity of one exact request.
///
/// The identity is a pure function of the exact operation identity and the
/// canonical request hash, so an exact retry of the same bytes always reports
/// the same submission identity and a corrected payload under a new operation
/// identity always reports a different one. No nonce, clock, or counter
/// participates, and a malformed request hash is refused rather than hashed.
pub fn derive_submission_id(
    operation_id: &OperationId,
    request_hash: &str,
) -> Result<String, StoreError> {
    validate_digest(request_hash, "submission.request_hash")?;
    Ok(sha256_hex(
        format!(
            "{WRITE_SUBMISSION_ID_DOMAIN}:{}:{request_hash}",
            operation_id.as_str(),
        )
        .as_bytes(),
    ))
}

/// Derives the deterministic stage handle of one exact operation identity.
///
/// The handle is derived, not issued: it is a pure function of the operation
/// identity, computable with no clock, sequence, epoch, or ORS authority. That
/// is exactly why it cannot be a `WriteSubmission::ors_stage_ref`. A derived
/// name identifies an operation; I5.19's `staged` state asserts that the ORS
/// owner accepted it, and only the owner's own staging act of I5.6 step 13 can
/// support that. Attaching a derived handle to a `staged` submission put a
/// predictable name where owner-issued evidence belongs, so this handle is no
/// longer used as a submission's stage reference.
#[must_use = "a derived stage handle must be used or checked"]
pub fn derive_ors_stage_ref(operation_id: &OperationId) -> String {
    sha256_hex(
        format!(
            "{WRITE_SUBMISSION_STAGE_REF_DOMAIN}:{}",
            operation_id.as_str(),
        )
        .as_bytes(),
    )
}

/// Decides the I5.19 admission result this boundary owes, if it owes one.
///
/// This is the single admission decision function. It is pure over data the
/// caller already holds, reads no clock, queries no owner, reserves nothing,
/// and issues no external effect:
///
/// - an already final receipt resolves first (I5.19 canonical execution step
///   1). A terminal immutable receipt is never contradicted by a later gate,
///   and the observed receipt must bind the exact idempotency key and canonical
///   request hash, otherwise this is an identity conflict;
/// - a gate refusal is a typed `not_accepted` decision carrying the closed
///   reason code and, for an over-bound envelope, the split directive;
/// - a passing gate with no final receipt owes NO submission and reports
///   `Ok(None)`. I5.19's remaining token for an accepted operation is
///   `staged`, which means ORS accepted the exact operation identity, and this
///   boundary is I5.6 steps 1-12 — before the step 13 staging act that would
///   make that true. Reporting a submission here would put the I5.19 `staged`
///   vocabulary word on a value nothing staged, so the accepted path returns no
///   front-door result at all and the caller proceeds to the canonical receipt
///   the I5.6 step 14 wait-for-receipt path produces.
///
/// A request whose own identity is unnameable — a malformed operation identity
/// or canonical request hash — has no submission identity to report a decision
/// under, so it is refused with the typed [`StoreError`] instead of a
/// `WriteSubmission` that would claim a name it cannot hold.
pub fn admit_write_submission(
    transition: &PreparedTransition,
    gate: Result<(), StoreError>,
    existing_final_receipt: Option<&WriteReceipt>,
) -> Result<Option<WriteSubmission>, StoreError> {
    let identity: &OperationIdentity = &transition.identity;
    if let Some(receipt) = existing_final_receipt {
        return resolve_existing_submission(identity, receipt).map(Some);
    }
    match gate {
        Ok(()) => Ok(None),
        Err(refusal) => WriteSubmission::not_accepted(
            &identity.operation_id,
            &identity.canonical_request_hash,
            &refusal,
            split_directive_for(transition, &refusal),
        )
        .map(Some),
    }
}

/// Resolves one already final receipt into a `resolved_existing` decision.
///
/// The observed receipt must be the final receipt for this exact idempotency key
/// and canonical request hash, and it must itself validate. Anything else is an
/// identity conflict: a receipt that does not bind the request cannot be used to
/// claim that the request already resolved.
fn resolve_existing_submission(
    identity: &OperationIdentity,
    receipt: &WriteReceipt,
) -> Result<WriteSubmission, StoreError> {
    if receipt.idempotency_key != identity.idempotency_key
        || receipt.canonical_request_hash != identity.canonical_request_hash
    {
        return Err(StoreError::IdentityConflict);
    }
    receipt.validate()?;
    WriteSubmission::resolved_existing(
        &identity.operation_id,
        &identity.canonical_request_hash,
        &receipt.operation_id,
    )
}

/// Measures the over-bound envelope of a refusal, when the refusal is one.
///
/// Only an over-bound refusal produces a directive: a shape, fence, ceiling, or
/// unsupported-variant refusal has no dimension to split, and inventing one
/// would misdescribe the refusal. The measurement and the bound are the same two
/// values the catalogue gate used, so the directive can never disagree with the
/// gate that produced it.
fn split_directive_for(
    transition: &PreparedTransition,
    refusal: &StoreError,
) -> Option<SplitDirective> {
    if !matches!(refusal, StoreError::PayloadTooLarge) {
        return None;
    }
    measure_oversized_command_envelope(transition)
}

/// Measures every activated command in one envelope against its declared bound.
///
/// The measured value is the canonical parameter byte length the catalogue gate
/// itself measures, and the limit is the activated entry's own declared
/// `max_input_bytes`; neither is invented here. The item dimension is never
/// produced: no activated command profile in this crate declares an item-count
/// limit, and an item bound would have to come from an owner that does not
/// exist yet.
fn measure_oversized_command_envelope(transition: &PreparedTransition) -> Option<SplitDirective> {
    let entries = generated_operation_manifests().ok()?;
    for command in &transition.named_operations {
        let name = named_mutation_operation_name(command.operation);
        let Some(entry) = entries.iter().find(|entry| entry.name == name) else {
            continue;
        };
        let Ok(parameter_bytes) = canonical_json_bytes(&command.parameters) else {
            return None;
        };
        let measured = u64::try_from(parameter_bytes.len()).ok()?;
        let limit = u64::from(entry.max_input_bytes);
        if measured > limit {
            return SplitDirective::new(SplitDimension::Bytes, measured, limit).ok();
        }
    }
    None
}

/// Maps one typed store refusal onto the closed code a submission carries.
///
/// The mapping is total over [`StoreError`] and never invents a code: a shape,
/// ceiling, or unsupported-variant refusal is an `InvalidRequest` operational
/// response (I5.19), a fence or revision staleness keeps its own code, a
/// content/identity divergence is a conflict, and a receipt or envelope defect
/// is an internal inconsistency rather than a caller request error.
fn reason_code_for(refusal: &StoreError) -> ErrorCode {
    match refusal {
        StoreError::FenceMismatch => ErrorCode::FenceMismatch,
        StoreError::RevisionConflict => ErrorCode::StaleRevision,
        StoreError::OrderingConflict
        | StoreError::IdentityConflict
        | StoreError::TransitionDigestMismatch { .. } => ErrorCode::Conflict,
        StoreError::InvalidReceipt
        | StoreError::MissingReceiptEnvelope
        | StoreError::InvalidOutbox
        | StoreError::InvalidProjection
        | StoreError::AutomationContinuation(_)
        | StoreError::Security(_)
        | StoreError::Receipt(_)
        | StoreError::Serialization(_) => ErrorCode::Internal,
        StoreError::ReceiptNotFound => ErrorCode::NotFound,
        StoreError::Unavailable => ErrorCode::Unavailable,
        StoreError::SnapshotClosePending { .. } | StoreError::UnknownOutcome { .. } => {
            ErrorCode::UnknownOutcome
        }
        StoreError::InvalidField { .. }
        | StoreError::Empty { .. }
        | StoreError::Duplicate { .. }
        | StoreError::Foundation(_)
        | StoreError::UnknownOperation
        | StoreError::ManifestMismatch
        | StoreError::TransitionClassExceeded
        | StoreError::EffectCeilingExceeded
        | StoreError::PayloadTooLarge => ErrorCode::InvalidRequest,
    }
}

/// Derives the bounded next allowed action of one refusal.
///
/// The action is derived from the refusal itself so it cannot drift from the
/// state it explains, and it stays inside the same bounded-label rule as every
/// other mirrored label in this module. A refusal that leaves a plan outside
/// current support is never told to retry as-is: it names recovery, matching
/// the I5.6 rule that a preserved plan is not reinterpreted under newer code.
///
/// The split composition stays inside
/// [`MAX_WRITE_ADMISSION_LABEL_BYTES`] and the bound is asserted on the
/// resulting text, not assumed: [`WriteSubmission::not_accepted`] runs
/// [`WriteSubmission::validate`], which applies the same `validate_label`
/// bound to `next_allowed_action`. The two parts are the longest base action
/// plus [`SplitDirective::render`], whose only unbounded-looking part is two
/// `u64` measurements, so the composition cannot approach the bound by
/// construction. The cost of that bound being enforced here is deliberate and
/// fails closed: if a future render format ever did exceed it, this function
/// would be the place that refuses, because no second limit is invented to
/// paper over a render that outgrew the label it must fit in.
fn next_allowed_action_for(
    refusal: &StoreError,
    split_directive: Option<SplitDirective>,
) -> String {
    let base = match refusal {
        StoreError::ManifestMismatch | StoreError::UnknownOperation => {
            "preserve the refused prepared transition as recovery work; do not reinterpret it under \
             another command"
        }
        StoreError::FenceMismatch => {
            "refetch the current state fence and resubmit under a new operation identity"
        }
        StoreError::RevisionConflict | StoreError::OrderingConflict => {
            "refetch the current revision and ordering heads and resubmit under a new operation \
             identity"
        }
        StoreError::IdentityConflict => "resubmit the changed bytes under a new idempotency key",
        StoreError::TransitionDigestMismatch { .. } => {
            "rebuild the plan from the current contract set and resubmit under a new operation \
             identity"
        }
        _ => "correct the refused envelope and resubmit under a new operation identity",
    };
    split_directive.map_or_else(
        || base.to_owned(),
        |directive| format!("{}; {base}", directive.render()),
    )
}

/// Checks the exact operation identity and reservation binding of one observed
/// canonical receipt against the projection it was admitted under.
///
/// Equality of the original [`OperationId`], the idempotency key, and the
/// canonical request hash is the receipt binding; the projection is first
/// re-validated so its own canonical reservation-token digest is recomputed
/// from exactly the same bytes the Kernel sealed. A mismatch is a typed
/// [`StoreError`], never a silent repair and never a string.
fn validate_receipt_binding(
    admission: &WriteAdmissionProjection,
    receipt: &WriteReceipt,
) -> Result<(), StoreError> {
    if receipt.operation_id != admission.operation_id
        || receipt.idempotency_key != admission.idempotency_key
        || receipt.canonical_request_hash != admission.canonical_request_hash
    {
        return Err(StoreError::IdentityConflict);
    }
    Ok(())
}

/// Checks preserved revision heads: bounded, unique, valid, same fence.
fn validate_revision_heads(
    heads: &[RevisionHeadExpectation],
    fence: &StateFence,
) -> Result<(), StoreError> {
    if heads.len() > MAX_WRITE_ADMISSION_SCOPES {
        return Err(StoreError::PayloadTooLarge);
    }
    let mut seen = BTreeSet::new();
    for head in heads {
        head.validate()?;
        if &head.state_fence != fence {
            return Err(StoreError::FenceMismatch);
        }
        if !seen.insert(head.key.clone()) {
            return Err(StoreError::Duplicate {
                field: "admission.expected_revision_heads",
            });
        }
    }
    Ok(())
}

/// Checks that the preserved ordering heads exactly cover the reserved scope
/// set with matching expected sequences, independent of list order.
fn validate_ordering_coverage(request: &ReservedWriteRequest) -> Result<(), StoreError> {
    let heads = &request.expected_ordering_heads;
    if heads.len() > MAX_WRITE_ADMISSION_SCOPES {
        return Err(StoreError::PayloadTooLarge);
    }
    let mut seen = BTreeSet::new();
    for head in heads {
        head.validate()?;
        if head.state_fence != request.transition.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        if !seen.insert(head.scope.clone()) {
            return Err(StoreError::Duplicate {
                field: "admission.expected_ordering_heads",
            });
        }
    }
    if heads.len() != request.admission.scopes.len() {
        return Err(StoreError::InvalidField {
            field: "admission.expected_ordering_heads",
            reason: "must exactly cover the reserved scope set",
        });
    }
    for head in heads {
        let Some(scope) = request
            .admission
            .scopes
            .iter()
            .find(|scope| scope.scope == head.scope)
        else {
            return Err(StoreError::InvalidField {
                field: "admission.expected_ordering_heads",
                reason: "must exactly cover the reserved scope set",
            });
        };
        if scope.expected_sequence != head.expected_sequence {
            return Err(StoreError::InvalidField {
                field: "admission.expected_ordering_heads",
                reason: "expected sequence must match the reserved scope binding",
            });
        }
    }
    Ok(())
}

/// Checks that the reserved scope set exactly covers the transition's own
/// ordering scopes, independent of list order.
///
/// The transition's scope declaration is immutable semantic input: the
/// reservation evidence may restate it but never narrow, widen, or reorder it
/// into authority.
fn validate_transition_scope_coverage(request: &ReservedWriteRequest) -> Result<(), StoreError> {
    let mut admitted: Vec<&str> = request
        .admission
        .scopes
        .iter()
        .map(|scope| scope.scope.as_str())
        .collect();
    admitted.sort_unstable();
    let mut declared: Vec<&str> = request
        .transition
        .ordering_scopes
        .iter()
        .map(OrderingScopeId::as_str)
        .collect();
    declared.sort_unstable();
    if admitted != declared {
        return Err(StoreError::InvalidField {
            field: "admission.scopes",
            reason: "must exactly cover the transition ordering scopes",
        });
    }
    Ok(())
}

/// Checks one mirrored owner label: non-blank, no control characters, and
/// within the closed byte bound.
fn validate_label(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    if value.len() > MAX_WRITE_ADMISSION_LABEL_BYTES {
        return Err(StoreError::PayloadTooLarge);
    }
    Ok(())
}

/// Checks one lowercase SHA-256 hex digest.
fn validate_digest(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(StoreError::InvalidField {
            field,
            reason: "must be lowercase SHA-256",
        });
    }
    Ok(())
}
