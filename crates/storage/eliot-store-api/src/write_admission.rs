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
//! # Non-goals
//!
//! No wire-enum activation, no change to the existing apply signature, no
//! adapter/Kernel/ORS implementation, and no new receipt issuer. The
//! separately reviewed wire integration adds and versions the reserved
//! operation and gates it on a real backend, preserving legacy compatibility
//! or explicit refusal.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    OperationId, OrderingHeadExpectation, OrderingScopeId, PreparedTransition, RequestMeta,
    RevisionHeadExpectation, StoreError, canonical_json_bytes, sha256_hex,
};
use eliot_contracts::StateFence;

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
