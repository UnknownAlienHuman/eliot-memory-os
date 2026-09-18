//! Kernel-owned binding of Store writes to durable ORS reservations (issue #992).
//!
//! Architecture traceability: `I5.7` keeps one ORS coordinator for uncommitted
//! precedence (`reserve -> eligible -> execute -> finalize/release` over one
//! monotonic `reservation_order`) and the canonical Store for committed heads;
//! `I5.4` keeps the admitted [`PreparedTransition`][eliot_store_api::PreparedTransition]
//! the immutable semantic unit; `I5.27` binds operation identity over canonical
//! bytes; `I14.21` preserves `Executing`/`Reconciling` identity until exact
//! receipt reconciliation; `I14.3` keeps cancellation and reconciliation on the
//! protected reserve; `I7.20` requires typed failures that preserve operation
//! identity without leaking payload material.
//!
//! ## Owner table
//!
//! ```text
//! Owner                              Evidence
//! ---------------------------------- ------------------------------------------
//! ORS (`RedbRecoveryStore`)          uncommitted reservation order, scope
//!                                    sequences, lifecycle states, envelopes;
//!                                    bound evidence provider verifies heads
//!                                    and reconciliation inside ORS
//! Store (`CanonicalStoreClient`)     committed heads and `WriteReceipt`s with
//!                                    the reconciliation envelope (#991)
//! #990 projection                    byte-exact reservation binding carried
//!                                    across the authenticated boundary
//! This module                         composition of the three above: no new
//!                                    reservation database, scheduler, epoch
//!                                    issuer, semantic admission, receipt
//!                                    issuer, or second state owner
//! ```
//!
//! ## Construction rule
//!
//! [`CompositionReservation::bind`] takes only the composition-owned ORS
//! handle (whose canonical evidence provider was bound at composition by
//! `open_with_evidence`) and the active writer epoch. It never accepts a
//! caller-supplied verifier, an unrelated ORS handle as authority, or a
//! claimed issuer: a token minted by a foreign ORS is unknown to this ORS and
//! fails at the first lifecycle call, and an ORS opened without evidence
//! fails reservation with a canonical-evidence error. Both are proved by the
//! `992/2` suite.
//!
//! ## Compatible profile rule
//!
//! The per-operation [`ReservationSeed`] must be compatible with the live
//! composition authority: the owner writer epoch must name the exact fence
//! lineage and sequence, the seed operation must equal the admitted Store
//! operation, and the observed head set must exactly cover the admitted
//! transition scopes with matching sequences. Anything else fails closed
//! before any ORS or Store mutation. Wall-clock expiry enforcement stays with
//! the scheduler owner; the adapter preserves the ordered owner-supplied
//! creation/expiry pair and rejects an inverted pair.
//!
//! ## Send ordering (no orphaned tokens)
//!
//! ```text
//! reserve -> eligible -> [admission lease] -> project -> send once ->
//!   Ok(Committed)   -> begin_execute -> reconcile -> Finalized
//!   Ok(not-applied) -> begin_execute -> reconcile -> Released (+gap)
//!   Err(unknown)    -> begin_execute -> mark_unknown -> Reconciling
//!   Err(refused)    -> release (still Eligible, proved no effect)
//! ```
//!
//! `begin_execute` runs only after the single send resolves, so a refused
//! backend never strands an `Executing` reservation without receipt evidence.
//! Cancellation before possible submission releases only `Reserved`/`Eligible`
//! tokens; once `Executing`/`Reconciling`, release is rejected and identity is
//! preserved until exact receipt reconciliation.

use std::collections::BTreeSet;
use std::sync::Arc;

use eliot_contracts::{EpochId, RequestMetadata};
use eliot_ors::{
    CanonicalDisposition, CanonicalReconciliation, CanonicalScopeObservation, EpochIdentity,
    EpochLineage, ExpectedOrderingHead, OpaqueLabel, OperationIdentity as OrsOperationIdentity,
    OperationalRecoveryStore, RecoveryAccessClass, RecoveryCursor, RecoveryEnvelopeContext,
    RecoveryOwner, RecoveryPage, RecoveryPayloadEnvelope, RedbRecoveryStore, ReservationRecord,
    ReservationRequest, ScopeReservationRequest, StateFenceSnapshot, WriterReservationToken,
};
use eliot_platform::SecretReference;
use eliot_security_contracts::PrivacyClass;
use eliot_store_api::{
    CanonicalRequestView, OrderingHeadExpectation, OrderingScopeId,
    PreparedTransition, ReceiptEnvelope, ReservedScopeBinding, ReservedWriteRequest,
    RevisionHeadExpectation, WriteAdmissionParams, WriteAdmissionProjection, WriteReceipt,
    WriteReceiptStatus, WriterEpochBinding, prepared_transition_digest,
    verify_canonical_request_hash,
};

/// Composition-owned key reference under which the Kernel stages reservation
/// envelopes. Labels only; no secret bytes live here or cross this boundary.
pub const RESERVATION_KEY_PROVIDER: &str = "kernel-reservation-key";
/// Key name within [`RESERVATION_KEY_PROVIDER`] for store-write reservations.
pub const RESERVATION_KEY_NAME: &str = "store-write-reservation-v1";
/// Visibility label preserved on every reservation envelope without
/// interpretation by ORS.
pub const RESERVATION_VISIBILITY: &str = "owner-only";
/// Reason label recorded when a send resolves to a still-unknown outcome.
pub const UNKNOWN_OUTCOME_REASON: &str = "store-unknown-outcome";

/// Typed failure for reserved-write binding, dispatch, and reconciliation.
///
/// Every variant preserves the operation identity it refuses; no variant
/// carries payload bytes, digests, or secret material. ORS and Store failures
/// pass through unchanged so tests and operators match the exact owner error.
#[derive(Debug, thiserror::Error)]
pub enum ReservationWriteError {
    /// Admitted shape refused before any ORS or Store mutation.
    #[error("reserved write admission refused for operation {operation_id}: {detail}")]
    Admission {
        /// Admitted operation the refusal preserves.
        operation_id: String,
        /// Exact refused property.
        detail: String,
    },
    /// Reservation binding mismatch: the presented evidence does not bind the
    /// exact admitted transition, fence, scope set, or token.
    #[error("reserved write binding mismatch for operation {operation_id}: {detail}")]
    Binding {
        /// Admitted operation the refusal preserves.
        operation_id: String,
        /// Exact mismatched binding.
        detail: String,
    },
    /// The Store backend has no reserved-write capability. This is explicit
    /// unsupported behavior, never a silent unreserved `Apply` fallback.
    #[error("reserved write unsupported for operation {operation_id}: {detail}")]
    Unsupported {
        /// Admitted operation the refusal preserves.
        operation_id: String,
        /// Exact missing capability.
        detail: String,
    },
    /// The send resolved to a still-unknown outcome. The reservation is
    /// `Reconciling` (or still `Eligible` when execution never started) and
    /// must be reconciled by exact receipt evidence, never retried blindly.
    #[error("reserved write outcome unknown for operation {operation_id}: {detail}")]
    Unknown {
        /// Admitted operation the report preserves.
        operation_id: String,
        /// Exact unknown observation.
        detail: String,
    },
    /// Durable ORS lifecycle refusal, preserved verbatim.
    #[error(transparent)]
    Ors(#[from] eliot_ors::OrsError),
    /// Store contract refusal, preserved verbatim.
    #[error(transparent)]
    Store(#[from] eliot_store_api::StoreError),
}

/// Composition-bound reservation owner: the one owned ORS handle plus the
/// active writer epoch from trusted Kernel composition.
///
/// There is deliberately no constructor accepting an evidence provider, a
/// second ORS handle, or a claimed epoch: the evidence provider stays bound
/// inside the ORS handle, and the writer epoch must be the composition-active
/// one or every lifecycle call fails with the owner error.
pub struct CompositionReservation {
    ors: Arc<RedbRecoveryStore>,
    writer_epoch: EpochLineage,
}

impl CompositionReservation {
    /// Binds the composition-owned ORS handle and active writer epoch.
    ///
    /// The epoch lineage edge is validated without granting epoch authority;
    /// currency against the live fence is re-checked at every transition
    /// boundary, never once here.
    pub fn bind(
        ors: Arc<RedbRecoveryStore>,
        writer_epoch: EpochLineage,
    ) -> Result<Self, ReservationWriteError> {
        writer_epoch
            .validate()
            .map_err(ReservationWriteError::Ors)?;
        Ok(Self { ors, writer_epoch })
    }

    /// Returns the bound active writer epoch.
    pub fn writer_epoch(&self) -> &EpochLineage {
        &self.writer_epoch
    }

    /// Returns the exact current writer identity checked at every lifecycle step.
    fn writer_identity(&self) -> &EpochIdentity {
        &self.writer_epoch.current
    }
}

/// Caller-observed canonical head evidence for one ordering scope.
///
/// The digest restates owner-observed canonical head bytes; this type allocates
/// no sequence and mints no digest. Sequences are cross-checked against the
/// admitted `OrderingHeadExpectation` set at reservation time.
#[derive(Clone, Debug)]
pub struct ObservedHead {
    /// Ordering scope under reservation.
    pub scope: String,
    /// Expected head sequence the reservation extends; must be non-zero and
    /// must equal the admitted expectation for the scope.
    pub expected_sequence: u64,
    /// Digest of the exact observed canonical head bytes (lowercase SHA-256).
    pub expected_head_digest: String,
    /// Owner revision-head observation, if any.
    pub revision_head: Option<String>,
}

impl ObservedHead {
    fn validate(&self) -> Result<(), ReservationWriteError> {
        if self.scope.trim().is_empty()
            || self.scope.chars().any(char::is_control)
            || self.scope.len() > 1024
        {
            return Err(ReservationWriteError::Admission {
                operation_id: String::new(),
                detail: "observed head scope must be non-blank bounded text".to_owned(),
            });
        }
        if self.expected_sequence == 0 {
            return Err(ReservationWriteError::Admission {
                operation_id: String::new(),
                detail: format!(
                    "observed head sequence must be non-zero for scope {}",
                    self.scope
                ),
            });
        }
        if self.expected_head_digest.len() != 64
            || self
                .expected_head_digest
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ReservationWriteError::Admission {
                operation_id: String::new(),
                detail: format!(
                    "observed head digest must be lowercase SHA-256 for scope {}",
                    self.scope
                ),
            });
        }
        if let Some(revision) = &self.revision_head
            && (revision.trim().is_empty() || revision.chars().any(char::is_control))
        {
            return Err(ReservationWriteError::Admission {
                operation_id: String::new(),
                detail: format!(
                    "observed revision head must be non-blank text for scope {}",
                    self.scope
                ),
            });
        }
        Ok(())
    }
}

/// Per-operation reservation inputs supplied by the Kernel caller.
///
/// Identity and head evidence must be exactly compatible with the admitted
/// transition and expected-head sets; [`reserve_for_transition`] checks every
/// binding before any ORS mutation. The payload bytes are caller-owned opaque
/// bytes (the canonical transition bytes in tests); ORS stores them with an
/// integrity binding and never interprets them.
#[derive(Clone, Debug)]
pub struct ReservationSeed {
    /// ORS reservation identity label; unique per operation.
    pub reservation_id: String,
    /// Store operation identity; must equal the admitted transition's
    /// operation id exactly, binding the ORS operation to the Store operation.
    pub operation_id: String,
    /// Recovery owner identity preserved without granting authority.
    pub recovery_owner: String,
    /// Caller-owned opaque bytes staged under the key reference below.
    pub payload_bytes: Vec<u8>,
    /// Composition-owned key provider label (no secret bytes).
    pub key_provider: String,
    /// Composition-owned key name label (no secret bytes).
    pub key_name: String,
    /// Visibility label preserved without interpretation.
    pub visibility: String,
    /// Owner creation time in Unix milliseconds.
    pub created_at_ms: i64,
    /// Owner known time in Unix milliseconds; must not precede creation.
    pub known_at_ms: i64,
    /// Owner expiry time in Unix milliseconds; must follow creation.
    pub expires_at_ms: i64,
    /// Complete observed head set covering the admitted transition scopes.
    pub heads: Vec<ObservedHead>,
}

impl ReservationSeed {
    fn validate(&self, operation_id: &str) -> Result<(), ReservationWriteError> {
        let label = |value: &str, field: &'static str| {
            if value.trim().is_empty() || value.chars().any(char::is_control) || value.len() > 1024
            {
                return Err(ReservationWriteError::Admission {
                    operation_id: operation_id.to_owned(),
                    detail: format!("reservation seed {field} must be non-blank bounded text"),
                });
            }
            Ok(())
        };
        label(&self.reservation_id, "reservation_id")?;
        label(&self.operation_id, "operation_id")?;
        label(&self.recovery_owner, "recovery_owner")?;
        label(&self.key_provider, "key_provider")?;
        label(&self.key_name, "key_name")?;
        label(&self.visibility, "visibility")?;
        if self.operation_id != operation_id {
            return Err(ReservationWriteError::Binding {
                operation_id: operation_id.to_owned(),
                detail: "reservation seed operation must equal the admitted transition operation"
                    .to_owned(),
            });
        }
        if self.payload_bytes.is_empty() {
            return Err(ReservationWriteError::Admission {
                operation_id: operation_id.to_owned(),
                detail: "reservation seed payload must be non-empty opaque bytes".to_owned(),
            });
        }
        if self.known_at_ms < self.created_at_ms {
            return Err(ReservationWriteError::Admission {
                operation_id: operation_id.to_owned(),
                detail: "reservation seed known time must not precede creation".to_owned(),
            });
        }
        if self.expires_at_ms <= self.created_at_ms {
            return Err(ReservationWriteError::Admission {
                operation_id: operation_id.to_owned(),
                detail:
                    "reservation seed expiry must follow creation; wall timestamps alone are not authority"
                        .to_owned(),
            });
        }
        if self.heads.is_empty() || self.heads.len() > eliot_ors::MAX_RECOVERY_PAGE as usize {
            return Err(ReservationWriteError::Admission {
                operation_id: operation_id.to_owned(),
                detail: "reservation seed must carry a bounded non-empty head set".to_owned(),
            });
        }
        let mut seen = BTreeSet::new();
        for head in &self.heads {
            head.validate().map_err(|error| match error {
                ReservationWriteError::Admission { detail, .. } => {
                    ReservationWriteError::Admission {
                        operation_id: operation_id.to_owned(),
                        detail,
                    }
                }
                other => other,
            })?;
            if !seen.insert(head.scope.clone()) {
                return Err(ReservationWriteError::Admission {
                    operation_id: operation_id.to_owned(),
                    detail: "reservation seed heads must not repeat a scope".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// A reserved token with the creation time the #990 projection seals.
///
/// The token alone does not carry creation time, so reservation returns this
/// bundle: projection takes it back instead of a re-supplied timestamp that
/// could fork the token digest.
#[derive(Debug)]
pub struct SealedReservation {
    /// Immutable ORS-issued token checked at every lifecycle step.
    pub token: WriterReservationToken,
    /// Owner creation time sealed into the projection.
    pub created_at_ms: i64,
}

/// Validates the exact admitted transition, scope set, and expected heads
/// shared by reservation and gateway admission.
///
/// Mirrors the `KernelStoreGateway::apply` gates (source rule excepted: the
/// caller rule lives at the gateway boundary, the binding rules live here):
/// context/transition validation, fence equality, canonical request-hash
/// recompute over the exact values about to be bound, and exact scope/head
/// coverage with one shared fence.
fn validate_admitted(
    context: &RequestMetadata,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), ReservationWriteError> {
    let operation_id = transition.identity.operation_id.as_str().to_owned();
    let admission = |detail: String| ReservationWriteError::Admission {
        operation_id: operation_id.clone(),
        detail,
    };
    context
        .validate()
        .map_err(|error| admission(error.to_string()))?;
    transition
        .validate()
        .map_err(|error| admission(error.to_string()))?;
    if transition.state_fence != context.state_fence {
        return Err(admission(
            "transition state fence does not match request metadata".to_owned(),
        ));
    }
    let view = CanonicalRequestView::from_apply(
        context,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    );
    verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash)
        .map_err(|error| admission(error.to_string()))?;
    let mut declared: Vec<&str> = transition
        .ordering_scopes
        .iter()
        .map(OrderingScopeId::as_str)
        .collect();
    declared.sort_unstable();
    declared.dedup();
    if declared.len() != transition.ordering_scopes.len() {
        return Err(admission(
            "transition ordering scopes must not repeat a scope".to_owned(),
        ));
    }
    let mut expected: Vec<&str> = expected_ordering_heads
        .iter()
        .map(|head| head.scope.as_str())
        .collect();
    expected.sort_unstable();
    if expected != declared {
        return Err(admission(
            "expected ordering heads must exactly cover the transition ordering scopes".to_owned(),
        ));
    }
    for head in expected_ordering_heads {
        head.validate()
            .map_err(|error| admission(error.to_string()))?;
        if head.state_fence != context.state_fence {
            return Err(admission(
                "expected ordering head fence must equal the admitted fence".to_owned(),
            ));
        }
    }
    for head in expected_revision_heads {
        head.validate()
            .map_err(|error| admission(error.to_string()))?;
        if head.state_fence != context.state_fence {
            return Err(admission(
                "expected revision head fence must equal the admitted fence".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Checks the bound writer epoch against the exact live fence tuple.
///
/// Same-authority rule (Implements #64): the epoch sequence must equal the
/// fence authority sequence and the lineage label must equal the fence
/// lineage. Equal sequences across lineages stay unrelated and fail closed.
fn check_epoch_against_fence(
    writer_epoch: &EpochLineage,
    context: &RequestMetadata,
    operation_id: &str,
) -> Result<u64, ReservationWriteError> {
    let fence_epoch = &context.state_fence.authority_epoch;
    let observed = fence_epoch.sequence.get();
    if writer_epoch.current.epoch != observed
        || writer_epoch.current.lineage_id.as_str() != fence_epoch.lineage_id.as_str()
    {
        return Err(ReservationWriteError::Binding {
            operation_id: operation_id.to_owned(),
            detail: "bound writer epoch is outside the admitted fence authority".to_owned(),
        });
    }
    Ok(observed)
}

/// Atomically reserves every admitted scope through the actual ORS operation,
/// or none.
///
/// The single `stage_and_reserve` write transaction assigns one monotonic
/// `reservation_order` across all scopes; a failure anywhere (duplicate scope,
/// head mismatch, stale epoch, unbound evidence) reserves nothing. The exact
/// replay of an existing reservation id returns the durable token unchanged;
/// changed content under the same id is rejected later at projection time, not
/// silently rebound here.
pub fn reserve_for_transition(
    owner: &CompositionReservation,
    seed: &ReservationSeed,
    context: &RequestMetadata,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<SealedReservation, ReservationWriteError> {
    let operation_id = transition.identity.operation_id.as_str().to_owned();
    validate_admitted(
        context,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    )?;
    seed.validate(&operation_id)?;
    let observed_sequence = check_epoch_against_fence(&owner.writer_epoch, context, &operation_id)?;
    let mut observed: Vec<(&str, u64)> = seed
        .heads
        .iter()
        .map(|head| (head.scope.as_str(), head.expected_sequence))
        .collect();
    observed.sort_unstable();
    let mut declared: Vec<(&str, u64)> = expected_ordering_heads
        .iter()
        .map(|head| (head.scope.as_str(), head.expected_sequence))
        .collect();
    declared.sort_unstable();
    if observed != declared {
        return Err(ReservationWriteError::Binding {
            operation_id: operation_id.clone(),
            detail:
                "observed head set must exactly cover the admitted scopes with matching sequences"
                    .to_owned(),
        });
    }
    let fence_snapshot = StateFenceSnapshot::capture(&context.state_fence, observed_sequence)
        .map_err(ReservationWriteError::Ors)?;
    let envelope = RecoveryPayloadEnvelope::encrypted(
        RecoveryEnvelopeContext {
            operation_or_checkpoint_id: OrsOperationIdentity::new(&seed.operation_id)
                .map_err(ReservationWriteError::Ors)?,
            privacy_and_visibility_class: RecoveryAccessClass {
                privacy: PrivacyClass::Private,
                visibility: OpaqueLabel::new(seed.visibility.clone())
                    .map_err(ReservationWriteError::Ors)?,
            },
            authority_epoch: owner.writer_epoch.clone(),
            state_fence: fence_snapshot,
            created_at_ms: seed.created_at_ms,
            known_at_ms: seed.known_at_ms,
            expires_at_ms: Some(seed.expires_at_ms),
        },
        SecretReference::new(seed.key_provider.clone(), seed.key_name.clone()).map_err(
            |error| ReservationWriteError::Admission {
                operation_id: operation_id.clone(),
                detail: format!("reservation seed key reference is invalid: {error}"),
            },
        )?,
        seed.payload_bytes.clone(),
    )
    .map_err(ReservationWriteError::Ors)?;
    let transition_digest = prepared_transition_digest(transition)?;
    let mut scopes: Vec<ScopeReservationRequest> = seed
        .heads
        .iter()
        .map(|head| {
            Ok(ScopeReservationRequest {
                scope: OpaqueLabel::new(head.scope.clone()).map_err(ReservationWriteError::Ors)?,
                expected_head: ExpectedOrderingHead {
                    sequence: head.expected_sequence,
                    head_sha256: head.expected_head_digest.clone(),
                    revision_head: head.revision_head.clone(),
                },
            })
        })
        .collect::<Result<_, ReservationWriteError>>()?;
    scopes.sort_by(|left, right| left.scope.cmp(&right.scope));
    let token = owner.ors.stage_and_reserve(ReservationRequest {
        reservation_id: OpaqueLabel::new(seed.reservation_id.clone())
            .map_err(ReservationWriteError::Ors)?,
        envelope,
        writer_epoch: owner.writer_epoch.clone(),
        scopes,
        prepared_transition_sha256: transition_digest.clone(),
        expires_at_ms: seed.expires_at_ms,
        recovery_owner: RecoveryOwner::new(seed.recovery_owner.clone())
            .map_err(ReservationWriteError::Ors)?,
    })?;
    if token.reservation_order == 0
        || token.prepared_transition_sha256 != transition_digest
        || token.operation_id.as_str() != seed.operation_id
    {
        return Err(ReservationWriteError::Binding {
            operation_id,
            detail: "ORS token does not bind the admitted reservation inputs".to_owned(),
        });
    }
    Ok(SealedReservation {
        token,
        created_at_ms: seed.created_at_ms,
    })
}

/// Projects exactly one eligible token to the #990 sealed request sent through #991.
///
/// The projection mapping is exhaustive and canonical: token order, scope set
/// with reserved sequences, writer lineage, fence, source mirror, owner times,
/// and both recomputed digests. A transition mutated after reservation fails
/// here with a digest mismatch; an exact replay projects the identical bytes.
pub fn project_reserved_write(
    sealed: &SealedReservation,
    context: &RequestMetadata,
    transition: &PreparedTransition,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<ReservedWriteRequest, ReservationWriteError> {
    let operation_id = transition.identity.operation_id.as_str().to_owned();
    validate_admitted(
        context,
        transition,
        &expected_revision_heads,
        &expected_ordering_heads,
    )?;
    let token = &sealed.token;
    if token.operation_id.as_str() != operation_id {
        return Err(ReservationWriteError::Binding {
            operation_id,
            detail: "token operation does not match the admitted transition operation".to_owned(),
        });
    }
    let observed_sequence = token.state_fence.observed_authority_epoch;
    let fenced = StateFenceSnapshot::capture(&context.state_fence, observed_sequence)
        .map_err(ReservationWriteError::Ors)?;
    if fenced != token.state_fence {
        return Err(ReservationWriteError::Binding {
            operation_id: operation_id.clone(),
            detail: "admitted fence does not match the reservation fence".to_owned(),
        });
    }
    let transition_digest = prepared_transition_digest(transition)?;
    if transition_digest != token.prepared_transition_sha256 {
        return Err(ReservationWriteError::Binding {
            operation_id,
            detail:
                "transition content changed after reservation; exact replay is required, rebind is refused"
                    .to_owned(),
        });
    }
    let writer_epoch = &token.writer_epoch;
    let scopes = token
        .scopes
        .iter()
        .map(|scope| {
            Ok(ReservedScopeBinding {
                scope: OrderingScopeId::new(scope.scope.as_str()).map_err(|error| {
                    ReservationWriteError::Binding {
                        operation_id: transition.identity.operation_id.as_str().to_owned(),
                        detail: format!("reserved scope identity is invalid: {error}"),
                    }
                })?,
                reserved_sequence: scope.reserved_sequence,
                expected_sequence: scope.expected_head.sequence,
                expected_head_digest: scope.expected_head.head_sha256.clone(),
            })
        })
        .collect::<Result<Vec<_>, ReservationWriteError>>()?;
    let params = WriteAdmissionParams {
        reservation_id: token.reservation_id.as_str().to_owned(),
        reservation_order: token.reservation_order,
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        scopes,
        writer_epoch: WriterEpochBinding {
            lineage_id: writer_epoch.current.lineage_id.as_str().to_owned(),
            epoch: writer_epoch.current.epoch,
            predecessor_lineage_id: writer_epoch
                .predecessor
                .as_ref()
                .map(|prior| prior.lineage_id.as_str().to_owned()),
            predecessor_epoch: writer_epoch.predecessor.as_ref().map(|prior| prior.epoch),
        },
        state_fence: context.state_fence.clone(),
        source_id: context.source_id.as_str().to_owned(),
        created_at_ms: sealed.created_at_ms,
        expires_at_ms: token.expires_at_ms,
        recovery_owner: token.recovery_owner.as_str().to_owned(),
    };
    let admission = WriteAdmissionProjection::bind(transition, params)?;
    let request = ReservedWriteRequest {
        context: context.clone(),
        transition: transition.clone(),
        admission,
        expected_revision_heads,
        expected_ordering_heads,
    };
    request.validate()?;
    Ok(request)
}

/// Advances a head reservation to eligibility after all predecessors close.
///
/// A missing predecessor fails with the owner `PredecessorPending` error and
/// dispatches nothing. No admission lease, Kernel lock, provider permit, or
/// protected-control resource is held: this is a bounded ORS-local check.
pub fn ensure_eligible(
    owner: &CompositionReservation,
    token: &WriterReservationToken,
) -> Result<ReservationRecord, ReservationWriteError> {
    Ok(owner.ors.mark_eligible(token)?)
}

/// Starts execution under the exact immutable writer epoch.
///
/// A stale executor fails with the owner `StaleWriterEpoch` error and can
/// neither execute nor finalize another generation's token.
pub fn begin_execute(
    owner: &CompositionReservation,
    token: &WriterReservationToken,
) -> Result<ReservationRecord, ReservationWriteError> {
    Ok(owner.ors.begin_execute(token, owner.writer_identity())?)
}

/// Releases work that has not executed under the exact writer epoch.
///
/// Valid only from `Reserved`/`Eligible`: before-send cancellation releases
/// exactly this token and nothing else. From `Executing`/`Reconciling` the
/// owner rejects with `InvalidTransition`, preserving identity until exact
/// receipt reconciliation: cancellation, timeout, or socket replacement can
/// never finalize or free such a reservation.
pub fn cancel_before_send(
    owner: &CompositionReservation,
    token: &WriterReservationToken,
) -> Result<ReservationRecord, ReservationWriteError> {
    Ok(owner.ors.release(token, owner.writer_identity())?)
}

/// Marks an ambiguous effect non-replayable until canonical reconciliation.
///
/// Called when the single send resolves to a still-unknown outcome after
/// execution started. The scope recovery block closes dependent allocation
/// while leaving unrelated scopes eligible.
pub fn mark_unknown_outcome(
    owner: &CompositionReservation,
    token: &WriterReservationToken,
) -> Result<ReservationRecord, ReservationWriteError> {
    let reason = OpaqueLabel::new(UNKNOWN_OUTCOME_REASON).map_err(ReservationWriteError::Ors)?;
    Ok(owner
        .ors
        .mark_unknown(token, owner.writer_identity(), reason)?)
}

/// Builds the exact receipt-evidence closure for one token from a verified
/// Store receipt, without mutating ORS.
///
/// The receipt must be the committed-or-terminally-not-applied answer to the
/// same operation: operation identity, fence snapshot, scope/sequence
/// coverage, and the envelope binding are all re-checked here, and the owner
/// re-checks them again with its evidence provider at [`finalize_reservation`].
/// A receipt without a reconciliation envelope (still unknown) fails here and
/// stays distinct from proved-not-applied. This constructs evidence, never
/// authority: only [`finalize_reservation`] closes the token.
pub fn reconcile_receipt(
    token: &WriterReservationToken,
    receipt: &WriteReceipt,
) -> Result<CanonicalReconciliation, ReservationWriteError> {
    let operation_id = token.operation_id.as_str().to_owned();
    receipt.validate().map_err(|error| {
        if error == eliot_store_api::StoreError::MissingReceiptEnvelope {
            ReservationWriteError::Unknown {
                operation_id: operation_id.clone(),
                detail: "Store receipt carries no reconciliation envelope; outcome stays unknown"
                    .to_owned(),
            }
        } else {
            ReservationWriteError::Store(error)
        }
    })?;
    let disposition = match receipt.status {
        WriteReceiptStatus::Committed => CanonicalDisposition::Committed,
        WriteReceiptStatus::Rejected
        | WriteReceiptStatus::Cancelled
        | WriteReceiptStatus::DeadLetter => CanonicalDisposition::Rejected,
    };
    let envelope = receipt.require_reconciliation_envelope().map_err(|error| {
        if error == eliot_store_api::StoreError::MissingReceiptEnvelope {
            ReservationWriteError::Unknown {
                operation_id: operation_id.clone(),
                detail: "Store receipt carries no reconciliation envelope; outcome stays unknown"
                    .to_owned(),
            }
        } else {
            ReservationWriteError::Store(error)
        }
    })?;
    check_receipt_token_binding(token, receipt, envelope, &operation_id)?;
    let receipt_id = OpaqueLabel::new(envelope.identity.receipt_id.as_str())
        .map_err(ReservationWriteError::Ors)?;
    let scopes = token
        .scopes
        .iter()
        .map(|reserved| CanonicalScopeObservation {
            scope: reserved.scope.clone(),
            prior_head: reserved.expected_head.clone(),
            committed_sequence: reserved.reserved_sequence,
            committed_head_sha256: envelope.identity.canonical_sha256.clone(),
            committed_revision_head: None,
            receipt_id: receipt_id.clone(),
        })
        .collect();
    Ok(CanonicalReconciliation {
        reservation_id: token.reservation_id.clone(),
        operation_id: token.operation_id.clone(),
        reservation_order: token.reservation_order,
        state_fence: token.state_fence.clone(),
        recovery_owner: token.recovery_owner.clone(),
        scopes,
        receipt: envelope.clone(),
        disposition,
    })
}

/// Re-checks the same-operation binding between a verified receipt and a
/// token: operation identity (receipt and envelope), fence snapshot, exact
/// scope/sequence coverage, and the single-scope causal sequence.
///
/// Staging step shared with [`reconcile_receipt`] so the constructor stays a
/// composition of audited checks rather than one long body.
fn check_receipt_token_binding(
    token: &WriterReservationToken,
    receipt: &WriteReceipt,
    envelope: &ReceiptEnvelope,
    operation_id: &str,
) -> Result<(), ReservationWriteError> {
    let binding = |detail: &str| ReservationWriteError::Binding {
        operation_id: operation_id.to_owned(),
        detail: detail.to_owned(),
    };
    if receipt.operation_id.as_str() != operation_id {
        return Err(binding(
            "Store receipt operation does not match the reservation operation",
        ));
    }
    if envelope.core.operation.operation_id.as_str() != operation_id {
        return Err(binding(
            "receipt envelope operation does not match the reservation operation",
        ));
    }
    let fenced = StateFenceSnapshot::capture(
        &receipt.state_fence,
        envelope.core.authority.authority_epoch.sequence.get(),
    )
    .map_err(ReservationWriteError::Ors)?;
    if fenced != token.state_fence {
        return Err(binding(
            "Store receipt fence does not match the reservation fence",
        ));
    }
    if receipt.ordering_sequences.len() != token.scopes.len() {
        return Err(binding(
            "Store receipt scope set does not cover the reserved scope set",
        ));
    }
    for reserved in &token.scopes {
        let covered = receipt.ordering_sequences.iter().any(|head| {
            head.scope.as_str() == reserved.scope.as_str()
                && head.sequence == reserved.reserved_sequence
        });
        if !covered {
            return Err(binding("Store receipt misses a reserved scope sequence"));
        }
    }
    if token.scopes.len() == 1
        && envelope.core.causal.transaction_sequence.value() != token.scopes[0].reserved_sequence
    {
        return Err(binding(
            "receipt causal sequence does not match the reserved sequence",
        ));
    }
    Ok(())
}

/// Closes an executing/unknown reservation from exact receipt evidence.
///
/// `Committed` finalizes; terminally-not-applied (`Rejected`, including the
/// dead-letter gap) releases with the terminal receipt bound. The owner
/// verifies the reconciliation through the composition-bound evidence provider
/// and advances all token scopes atomically. Partial release, a stale
/// executor, and another generation's token are rejected by the owner.
pub fn finalize_reservation(
    owner: &CompositionReservation,
    reconciliation: &CanonicalReconciliation,
) -> Result<ReservationRecord, ReservationWriteError> {
    Ok(owner.ors.reconcile(reconciliation)?)
}

/// Lists unresolved (non-terminal) reservations ordered by the ORS recovery
/// projection, bounded by `limit`.
///
/// Used on restart/rebind to recover every affected token and original
/// operation before new eligible writes, and by migration drain to account for
/// all reservations without forced release.
pub fn unresolved_reservations(
    owner: &CompositionReservation,
    limit: u16,
) -> Result<Vec<ReservationRecord>, ReservationWriteError> {
    let cursor = eliot_ors::RecoveryCursor::new(0, limit).map_err(ReservationWriteError::Ors)?;
    let page = owner.ors.recover_page(cursor)?;
    Ok(page
        .records
        .into_iter()
        .filter(|record| {
            !matches!(
                record.state,
                eliot_ors::ReservationState::Finalized | eliot_ors::ReservationState::Released
            )
        })
        .collect())
}

/// Derives the composition writer epoch from the exact live fence tuple.
///
/// Helper for the gateway boundary: the lineage label and sequence come from
/// the trusted composition fence, never from caller text. The predecessor
/// edge stays empty here; succession edges are owned by the epoch authority,
/// not by this binding.
pub fn writer_epoch_for_fence(
    context: &RequestMetadata,
) -> Result<EpochLineage, ReservationWriteError> {
    writer_epoch_for_fence_from_epoch(&context.state_fence.authority_epoch)
}

/// Derives the composition writer epoch from one live authority epoch.
///
/// Used where no admitted fence is presented (cancellation, drain): the epoch
/// comes from the live composition authority observed under the service lock,
/// never from caller text.
pub fn writer_epoch_for_fence_from_epoch(
    epoch: &EpochId,
) -> Result<EpochLineage, ReservationWriteError> {
    Ok(EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new(epoch.lineage_id.as_str())
                .map_err(ReservationWriteError::Ors)?,
            epoch: epoch.sequence.get(),
        },
        predecessor: None,
    })
}

/// Reads one bounded ORS recovery page without filtering.
///
/// Used by migration drain to account for every reservation, including the
/// truncation signal, before exclusivity.
pub fn recovery_page(
    owner: &CompositionReservation,
    limit: u16,
) -> Result<RecoveryPage, ReservationWriteError> {
    let cursor = RecoveryCursor::new(0, limit).map_err(ReservationWriteError::Ors)?;
    Ok(owner.ors.recover_page(cursor)?)
}

/// Builds the per-operation seed the gateway supplies from composition-owned
/// labels and caller-owned opaque bytes.
///
/// The key reference and visibility are the fixed composition labels; the
/// payload bytes are the canonical transition bytes staged opaquely.
pub fn gateway_seed(
    reservation_id: String,
    transition: &PreparedTransition,
    recovery_owner: String,
    created_at_ms: i64,
    known_at_ms: i64,
    expires_at_ms: i64,
    heads: Vec<ObservedHead>,
) -> Result<ReservationSeed, ReservationWriteError> {
    let payload_bytes = eliot_contracts::canonical_json_bytes(transition).map_err(|error| {
        ReservationWriteError::Admission {
            operation_id: transition.identity.operation_id.as_str().to_owned(),
            detail: format!("transition canonical bytes do not encode: {error}"),
        }
    })?;
    Ok(ReservationSeed {
        reservation_id,
        operation_id: transition.identity.operation_id.as_str().to_owned(),
        recovery_owner,
        payload_bytes,
        key_provider: RESERVATION_KEY_PROVIDER.to_owned(),
        key_name: RESERVATION_KEY_NAME.to_owned(),
        visibility: RESERVATION_VISIBILITY.to_owned(),
        created_at_ms,
        known_at_ms,
        expires_at_ms,
        heads,
    })
}
