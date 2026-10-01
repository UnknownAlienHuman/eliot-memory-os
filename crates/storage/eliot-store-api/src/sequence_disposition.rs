//! Canonical `SequenceDisposition` contract for a poison-operation ordering
//! gap (issue #1684).
//!
//! Architecture traceability: `I14.9` requires that after bounded retries a
//! proven-no-effect operation is dead-lettered, opens a `SequenceGap` for its
//! reserved position, and that the gap closes **only** through a canonical
//! `SequenceDisposition` receipt. `I5.19` requires that `DEAD_LETTER` is
//! terminal only when the original mutation is proven not applied, that the
//! gap's ordering position still requires disposition, and that an ambiguous
//! effect never fabricates a final `DEAD_LETTER` receipt. `I5.7` keeps one ORS
//! coordinator for uncommitted precedence and the canonical Store for committed
//! heads, and `I5.27` binds idempotency over canonical bytes.
//!
//! ## What this contract is
//!
//! It is a **typed payload inside the existing receipt/transition contract
//! surface**, not a new receipt store, writer, envelope, or lifecycle root
//! (`I5.19` "Receipt taxonomy and common envelope"). It restates:
//!
//! ```text
//! poison operation record   the exact dead-lettered operation identity, its
//!                           canonical request hash, immutable transition
//!                           digest, writer epoch, retry policy, no-effect
//!                           evidence, gap identity and every affected
//!                           scope/sequence/head binding;
//! disposition request      the named authorized choice plus the exact gap and
//!                           head revisions it was decided against.
//! ```
//!
//! Common identity, authority, fence, provenance and terminal semantics live
//! in [`ReservedWriteRequest`][crate::ReservedWriteRequest] /
//! [`WriteReceipt`][crate::WriteReceipt] and are never redefined here. This
//! module adds no second receipt envelope, no signature, no MAC, no nonce and
//! no policy constant.
//!
//! ## The three authorized choices and their identity roles
//!
//! `I5.19` and `I5.27` are read together, because `replace_same_identity` is
//! the only choice that could otherwise sound like a same-identity rewrite:
//!
//! ```text
//! skip_proven_no_effect
//!   Positions the ORIGINAL operation and its gap. Requires the no-effect
//!   evidence to still be current: a stale or absent proof is refused. The
//!   reserved position itself is explicitly dispositioned; nothing else
//!   changes and the original dead-letter receipt stays immutable.
//!
//! cancel_dependents
//!   Positions the DEPENDENT SET, not the gap. Each recorded dependent carries
//!   the exact outcome the disposition asserts for it. `cancellation
//!   requested` is not `cancellation proved`: only a proved outcome
//!   disposition a dependent, and an unproved dependent stays in the retained
//!   frontier rather than being declared cancelled. The reserved position
//!   itself remains blocked; this choice never dispositions it.
//!
//! replace_same_identity
//!   Preserves the original operation/gap lineage and never rewrites the
//!   terminal `DEAD_LETTER` receipt. The replacement is a SEPARATELY IDENTIFIED
//!   governed control/replacement revision with an explicit link to the
//!   original, and it requires a NEW operation identity and NEW idempotency
//!   key. Reusing the original idempotency key with different canonical
//!   request bytes is `IDENTITY_CONFLICT` (`I5.27`) and performs no
//!   transition: this choice is a lineage link, never a silent re-admission of
//!   changed bytes under the original key.
//! ```
//!
//! ## Authorization is not an operator flag
//!
//! There is deliberately no Boolean, no operator-supplied enum switch and no
//! self-hash in this module. A request is admissible only when it names this
//! operation's own gap and carries the exact current head revisions; whether
//! the caller may reach the gap-control route at all is a capability decision
//! made by the receiving boundary against the authenticated transport identity,
//! never a field inside the payload (`crates/storage/eliot-store-api/src/wire.rs`).
//!
//! ## Refusal, retry and terminal outcome stay separate
//!
//! [`PoisonAttemptOutcome`] is the closed classification of one bounded attempt:
//!
//! ```text
//! Refused    no ordering position was allocated; nothing can be terminalized.
//! Retry      the attempt is spent; the reservation keeps its reserved position.
//! Terminal   proven no-effect: the ONLY arm that can request dead lettering.
//! Unknown    timeout, lost response, expired lease, missing receipt or a failed
//!            query. Never no-effect proof, never terminal, even when the
//!            bounded retry budget is exhausted.
//! ```
//!
//! An exhausted retry budget on an [`PoisonAttemptOutcome::Unknown`] arm keeps
//! the operation under reconciliation with its original identity. Nothing in
//! this contract can turn it into a terminal dead letter.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    MAX_WRITE_ADMISSION_LABEL_BYTES, MAX_WRITE_ADMISSION_SCOPES, NamedMutationOperation,
    OperationId, OrderingHeadExpectation, OrderingScopeId, PreparedTransition,
    ReservedScopeBinding, RevisionHeadExpectation, StoreError, TransitionClass,
    WriterEpochBinding, canonical_json_bytes, sha256_hex,
};
use eliot_contracts::StateFence;

/// Closed contract version of the canonical sequence-disposition payload
/// (issue #1684).
///
/// Additive change is preferred: an unknown version fails closed instead of
/// decoding through a compatibility fallback.
pub const SEQUENCE_DISPOSITION_CONTRACT_VERSION: u16 = 2;

/// Maximum dependent operations recorded in one `cancel_dependents`
/// disposition.
///
/// Bounded so a traversal that cannot reach its whole dependent set reports an
/// incomplete frontier instead of growing without limit: the caller retains
/// the unproved remainder and the disposition itself refuses to claim the
/// dependents it never identified (`I14.9` step "bound dependent traversal").
pub const MAX_SEQUENCE_DISPOSITION_DEPENDENTS: usize = 256;

/// Maximum bytes of the one no-effect evidence handle bound to a poison
/// operation.
pub const MAX_NO_EFFECT_EVIDENCE_BYTES: usize = 4096;

/// Closed classification of one bounded attempt on a poison operation
/// (issue #1684, `I14.20` "Write submission and ORS operation").
///
/// The arms are the whole refusal/retry/terminal distinction and are never
/// collapsed. Exactly one arm — [`PoisonAttemptOutcome::Terminal`] — carries
/// proven no-effect and is therefore the only arm that can request dead
/// lettering. Everything else keeps the original operation identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PoisonAttemptOutcome {
    /// Rejected before sequence assignment: no ordering position was
    /// allocated, so there is nothing to dead-letter or disposition.
    Refused,
    /// The attempt is spent and may be retried under the same reservation; the
    /// reserved position is unchanged.
    Retry,
    /// The attempt is spent and the canonical owner proved the original
    /// mutation was **not** applied. This is the only no-effect proof.
    Terminal,
    /// The attempt left the outcome ambiguous: a timeout, a lost response, an
    /// expired lease, a missing receipt, or a failed query. Not a no-effect
    /// proof; the operation stays `UNKNOWN_OUTCOME`/`RECONCILING` under its
    /// original identity, including when the retry budget is exhausted.
    Unknown,
}

/// Why an attempt was refused before sequence assignment.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PoisonRefusalReason {
    /// The request was rejected before any ordering position was reserved, so
    /// it consumed no sequence and cannot be dead-lettered.
    PreAssignmentRejection,
}

/// Bounded retry policy bound to one poison operation (issue #1684).
///
/// The revision and the counter are stored together with the operation so
/// attempt accounting survives restart: a fresh process re-reads the recorded
/// attempt count instead of restarting the budget. `max_attempts` is the
/// bounded budget; `attempts` is the number of attempts already spent.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedRetryPolicy {
    /// Policy revision this operation was admitted under. A changed revision is
    /// a different policy, never a silently extended budget.
    pub revision: u32,
    /// Bounded attempt budget; must be non-zero.
    pub max_attempts: u32,
    /// Attempts already spent; must not exceed `max_attempts`.
    pub attempts: u32,
}

impl BoundedRetryPolicy {
    /// Reports whether the bounded retry budget is exhausted.
    ///
    /// Exhaustion is not terminalization: it only means no further attempt is
    /// admitted. An ambiguous outcome stays ambiguous.
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.attempts >= self.max_attempts
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.max_attempts == 0 {
            return Err(StoreError::InvalidField {
                field: "disposition.retry_policy.max_attempts",
                reason: "must be non-zero",
            });
        }
        if self.attempts > self.max_attempts {
            return Err(StoreError::InvalidField {
                field: "disposition.retry_policy.attempts",
                reason: "spent attempts must not exceed the bounded budget",
            });
        }
        Ok(())
    }
}

/// The one exact no-effect proof bound to a poison operation (issue #1684).
///
/// `I5.19`: "If any canonical/external effect is unknown, no final
/// `DEAD_LETTER` receipt is fabricated." This value is the evidence the
/// canonical owner produced; it is opaque bytes plus the digest of those exact
/// bytes, and its `kind` must be `PROVEN_NO_EFFECT`. A timeout, a lost
/// response, an expired lease, a missing receipt, or a failed query is not
/// this kind and cannot be recorded as it.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum NoEffectEvidenceKind {
    /// The canonical owner proved the original mutation was not applied.
    ProvenNoEffect,
}

/// Exact no-effect evidence: the closed kind, the producer's opaque handle
/// bytes, and the digest over exactly those bytes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoEffectEvidence {
    /// Closed evidence kind; only proven non-application is admissible.
    pub kind: NoEffectEvidenceKind,
    /// Opaque producer-owned evidence handle. Never a payload or a secret.
    pub evidence: String,
    /// Lowercase SHA-256 over exactly `evidence`.
    pub evidence_sha256: String,
}

impl NoEffectEvidence {
    /// Checks the closed kind, the bounded opaque handle and its recomputed
    /// digest.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.kind != NoEffectEvidenceKind::ProvenNoEffect {
            return Err(StoreError::InvalidField {
                field: "disposition.no_effect_evidence.kind",
                reason: "only proven no-effect evidence is admissible",
            });
        }
        validate_label(&self.evidence, "disposition.no_effect_evidence.evidence")?;
        if self.evidence.len() > MAX_NO_EFFECT_EVIDENCE_BYTES {
            return Err(StoreError::PayloadTooLarge);
        }
        validate_digest(
            &self.evidence_sha256,
            "disposition.no_effect_evidence.evidence_sha256",
        )?;
        let observed = sha256_hex(self.evidence.as_bytes());
        if observed != self.evidence_sha256 {
            return Err(StoreError::TransitionDigestMismatch {
                expected: self.evidence_sha256.clone(),
                observed,
            });
        }
        Ok(())
    }
}

/// Identity of the open `SequenceGap` a disposition resolves (issue #1684).
///
/// The gap is the reserved ordering position whose canonical meaning is
/// missing. It is named by the operation that reserved it, the exact scope
/// sequences it blocked, and the digest of the durable gap record. A gap whose
/// digest changed, or whose scope set is not the reserved scope set, is stale
/// and fails closed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceGapIdentity {
    /// Gap identity; unique per reserved position set.
    pub gap_id: String,
    /// Digest over the exact durable gap record, including the `DEAD_LETTER`
    /// receipt and its gap/Problem relation. Compared against the current gap
    /// so a changed or superseded gap is refused.
    pub gap_sha256: String,
}

/// The original `DEAD_LETTER` operation bound to the gap (issue #1684).
///
/// Every field here is the ORIGINAL, immutable identity. The
/// `original_canonical_request_hash` is what makes changed-content conflict
/// detectable: reusing the original idempotency key with a different canonical
/// request hash is `IDENTITY_CONFLICT` (`I5.27`) and no transition occurs.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeadLetterOperation {
    /// The dead-lettered operation identity, preserved forever.
    pub operation_id: OperationId,
    /// The original idempotency key, preserved exactly.
    pub idempotency_key: String,
    /// The original canonical request hash over the admitted bytes.
    pub canonical_request_hash: String,
    /// Digest over the exact immutable transition that was admitted.
    pub prepared_transition_digest: String,
    /// Writer epoch/fence that held the reservation.
    pub writer_epoch: WriterEpochBinding,
    /// Receipt id of the immutable `DEAD_LETTER` receipt. A disposition never
    /// rewrites it.
    pub dead_letter_receipt_id: String,
    /// Digest over the exact immutable `DEAD_LETTER` receipt bytes.
    pub dead_letter_receipt_sha256: String,
    /// The `SequenceGap` this dead letter opened.
    pub gap: SequenceGapIdentity,
    /// Bounded retry policy and spent-attempt accounting at dead-letter time.
    pub retry_policy: BoundedRetryPolicy,
    /// The exact no-effect evidence that authorises the dead letter.
    pub no_effect_evidence: NoEffectEvidence,
}

impl DeadLetterOperation {
    fn validate(&self) -> Result<(), StoreError> {
        validate_label(
            self.operation_id.as_str(),
            "disposition.original_operation_id",
        )?;
        validate_label(&self.idempotency_key, "disposition.idempotency_key")?;
        validate_digest(
            &self.canonical_request_hash,
            "disposition.canonical_request_hash",
        )?;
        validate_digest(
            &self.prepared_transition_digest,
            "disposition.prepared_transition_digest",
        )?;
        self.writer_epoch.validate()?;
        validate_label(
            &self.dead_letter_receipt_id,
            "disposition.dead_letter_receipt_id",
        )?;
        validate_digest(
            &self.dead_letter_receipt_sha256,
            "disposition.dead_letter_receipt_sha256",
        )?;
        validate_label(&self.gap.gap_id, "disposition.gap.gap_id")?;
        validate_digest(&self.gap.gap_sha256, "disposition.gap.gap_sha256")?;
        self.retry_policy.validate()?;
        self.no_effect_evidence.validate()
    }
}

/// The affected ordering scopes of the gap: every scope of the original
/// multi-scope reservation, with the reserved sequence, the expected head it
/// extends, and the CURRENT head revision the disposition is decided against.
///
/// `I5.7` all-or-none rule: this set is the complete reserved scope set or the
/// disposition is refused. A disposition that advances only some heads is not
/// constructible here.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedScope {
    /// One reserved ordering scope of the original reservation.
    pub reserved: ReservedScopeBinding,
    /// The exact current head revision the disposition is decided against. Must
    /// be the current canonical head for the scope, so a stale or foreign
    /// head fails closed in the store transaction.
    pub expected_head_sequence: u64,
    /// Digest over the exact current canonical head bytes for the scope.
    pub expected_head_sha256: String,
}

impl AffectedScope {
    fn validate(&self) -> Result<(), StoreError> {
        self.reserved.validate()?;
        if self.expected_head_sequence == 0 {
            return Err(StoreError::InvalidField {
                field: "disposition.affected_scopes.expected_head_sequence",
                reason: "must be non-zero",
            });
        }
        validate_digest(
            &self.expected_head_sha256,
            "disposition.affected_scopes.expected_head_sha256",
        )
    }
}

/// The one permitted outcome of a dependent operation named by a
/// `cancel_dependents` disposition (issue #1684).
///
/// `cancellation requested` is not `cancellation proved`. Only
/// [`DependentOutcome::Cancelled`] and [`DependentOutcome::ProvedNoEffect`]
/// assert that a dependent's effect did not happen.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum DependentOutcome {
    /// The dependent operation's effect was proved absent.
    ProvedNoEffect,
    /// The dependent operation was proved cancelled with no effect.
    Cancelled,
    /// The dependent committed; it is retained as an independent fact and the
    /// gap is not resolved by cancelling it.
    Committed,
    /// Cancellation was requested but not proved: the dependent is NOT
    /// dispositioned. The disposition retains it in the incomplete frontier
    /// instead of declaring the cancellation complete.
    CancellationRequested,
}

/// One dependent operation recorded by a `cancel_dependents` disposition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependentDisposition {
    /// The dependent operation identity, preserved.
    pub operation_id: OperationId,
    /// The exact outcome asserted for this dependent.
    pub outcome: DependentOutcome,
    /// Ordering scope the dependent declared, if any.
    pub scope: Option<OrderingScopeId>,
    /// Opaque evidence handle for the asserted outcome. Never a payload.
    pub evidence: String,
}

impl DependentDisposition {
    fn validate(&self) -> Result<(), StoreError> {
        validate_label(
            self.operation_id.as_str(),
            "disposition.dependents.operation_id",
        )?;
        validate_label(&self.evidence, "disposition.dependents.evidence")?;
        if let Some(scope) = &self.scope {
            validate_label(scope.as_str(), "disposition.dependents.scope")?;
        }
        Ok(())
    }
}

/// A governed replacement revision linked to the dead-lettered original
/// (issue #1684, `replace_same_identity`).
///
/// The replacement is a NEWLY IDENTIFIED operation with its own idempotency
/// key and its own canonical request hash. It carries an explicit link back to
/// the original operation and gap so lineage is preserved, and the original
/// `DEAD_LETTER` receipt is never rewritten. A replacement whose canonical
/// request hash equals the original's under the original key is refused by
/// [`SequenceDispositionRequest::validate`] as an identity conflict, never
/// silently accepted.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementLink {
    /// The replacement operation identity; distinct from the original.
    pub replacement_operation_id: OperationId,
    /// The replacement's own idempotency key; never the original key.
    pub replacement_idempotency_key: String,
    /// The replacement's canonical request hash over the replacement bytes.
    pub replacement_canonical_request_hash: String,
    /// The original operation identity this replacement supersedes for the
    /// same semantic intent.
    pub original_operation_id: OperationId,
    /// The gap the replacement is admitted against.
    pub gap: SequenceGapIdentity,
}

impl ReplacementLink {
    fn validate(&self, original: &DeadLetterOperation) -> Result<(), StoreError> {
        validate_label(
            self.replacement_operation_id.as_str(),
            "disposition.replacement.replacement_operation_id",
        )?;
        validate_label(
            &self.replacement_idempotency_key,
            "disposition.replacement.replacement_idempotency_key",
        )?;
        validate_digest(
            &self.replacement_canonical_request_hash,
            "disposition.replacement.replacement_canonical_request_hash",
        )?;
        if self.original_operation_id != original.operation_id {
            return Err(StoreError::InvalidField {
                field: "disposition.replacement.original_operation_id",
                reason: "replacement must link to the original operation identity",
            });
        }
        if self.gap != original.gap {
            return Err(StoreError::InvalidField {
                field: "disposition.replacement.gap",
                reason: "replacement must link to the same gap",
            });
        }
        if self.replacement_operation_id == original.operation_id {
            return Err(StoreError::InvalidField {
                field: "disposition.replacement.replacement_operation_id",
                reason: "replacement must be separately identified from the original",
            });
        }
        if self.replacement_idempotency_key == original.idempotency_key {
            return Err(StoreError::IdentityConflict);
        }
        Ok(())
    }
}

/// The three authorized disposition choices (issue #1684, `I14.9`).
///
/// These are the ONLY ways a blocked reserved position may be resolved. Each
/// variant is self-validating against the original operation record, so a
/// caller cannot pair a choice with evidence that does not support it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum SequenceDispositionChoice {
    /// Resolve the reserved position as proven-no-effect. Requires the current
    /// no-effect evidence; dispositions the reserved position itself.
    SkipProvenNoEffect {
        /// The no-effect evidence that must still be current.
        no_effect_evidence: NoEffectEvidence,
    },
    /// Record the exact dependent set and the outcome asserted for each. Does
    /// NOT disposition the reserved position; it only dispositions the named
    /// dependents.
    CancelDependents {
        /// The exact dependent set. Cancellation-requested dependents stay in
        /// the retained frontier and do not close the gap.
        dependents: Vec<DependentDisposition>,
    },
    /// Admit a separately identified replacement revision linked to the
    /// original, without rewriting the original terminal receipt.
    ReplaceSameIdentity {
        /// The governed replacement revision.
        replacement: ReplacementLink,
    },
}

impl SequenceDispositionChoice {
    /// Stable bounded identity of the choice, for status/read projections.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SkipProvenNoEffect { .. } => "skip_proven_no_effect",
            Self::CancelDependents { .. } => "cancel_dependents",
            Self::ReplaceSameIdentity { .. } => "replace_same_identity",
        }
    }

    /// Reports whether this choice dispositions the blocked reserved position
    /// itself.
    ///
    /// Only `skip_proven_no_effect` and `replace_same_identity` do;
    /// `cancel_dependents` only dispositions the named dependents.
    #[must_use]
    pub const fn dispositions_reserved_position(&self) -> bool {
        match self {
            Self::SkipProvenNoEffect { .. } | Self::ReplaceSameIdentity { .. } => true,
            Self::CancelDependents { .. } => false,
        }
    }

    fn validate(&self, original: &DeadLetterOperation) -> Result<(), StoreError> {
        match self {
            Self::SkipProvenNoEffect { no_effect_evidence } => {
                no_effect_evidence.validate()?;
                if *no_effect_evidence != original.no_effect_evidence {
                    return Err(StoreError::StaleDisposition {
                        detail: "skip_proven_no_effect requires the current no-effect evidence",
                    });
                }
                Ok(())
            }
            Self::CancelDependents { dependents } => {
                if dependents.is_empty() {
                    return Err(StoreError::Empty {
                        field: "disposition.cancel_dependents.dependents",
                    });
                }
                if dependents.len() > MAX_SEQUENCE_DISPOSITION_DEPENDENTS {
                    return Err(StoreError::PayloadTooLarge);
                }
                let mut seen = BTreeSet::new();
                for dependent in dependents {
                    dependent.validate()?;
                    if !seen.insert(dependent.operation_id.clone()) {
                        return Err(StoreError::Duplicate {
                            field: "disposition.cancel_dependents.dependents",
                        });
                    }
                }
                Ok(())
            }
            Self::ReplaceSameIdentity { replacement } => replacement.validate(original),
        }
    }
}

/// The complete poison-operation record bound to one blocked reserved
/// position (issue #1684, step 1).
///
/// Every field is the complete record: original operation identity, canonical
/// request hash, immutable transition digest, writer epoch/fence, the
/// original `DEAD_LETTER` receipt, bounded retry policy and spent attempts, the
/// exact no-effect evidence, the gap identity, and the complete affected
/// scope/sequence/head bindings.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoisonOperationRecord {
    /// The original, immutable dead-lettered operation.
    pub original: DeadLetterOperation,
    /// Every scope of the original multi-scope reservation, with reserved
    /// sequence and current head revision. All-or-none.
    pub affected_scopes: Vec<AffectedScope>,
}

impl PoisonOperationRecord {
    fn validate(&self) -> Result<(), StoreError> {
        self.original.validate()?;
        if self.affected_scopes.is_empty() {
            return Err(StoreError::Empty {
                field: "disposition.affected_scopes",
            });
        }
        if self.affected_scopes.len() > MAX_WRITE_ADMISSION_SCOPES {
            return Err(StoreError::PayloadTooLarge);
        }
        let mut seen = BTreeSet::new();
        for scope in &self.affected_scopes {
            scope.validate()?;
            if !seen.insert(scope.reserved.scope.clone()) {
                return Err(StoreError::Duplicate {
                    field: "disposition.affected_scopes",
                });
            }
        }
        Ok(())
    }

    /// The one gap identity this record is bound to.
    #[must_use]
    pub const fn gap(&self) -> &SequenceGapIdentity {
        &self.original.gap
    }
}

/// One closed sequence-disposition request crossing the governed
/// gap-control route (issue #1684).
///
/// This is the named, authorized transition admitted against the exact current
/// gap/head revisions. It is NOT reachable by an ordinary write: the request
/// carries no [`PreparedTransition`][crate::PreparedTransition] and no domain
/// mutation, only the poison-operation record and the chosen disposition. A
/// normal write has no way to construct this shape because the store contract
/// surface names it as its own operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceDispositionRequest {
    /// Closed contract version, always
    /// [`SEQUENCE_DISPOSITION_CONTRACT_VERSION`].
    pub contract_version: u16,
    /// Fence shared by the authenticated transport context and the record.
    pub state_fence: StateFence,
    /// The complete poison-operation record.
    pub operation: PoisonOperationRecord,
    /// The chosen authorized disposition.
    pub choice: SequenceDispositionChoice,
    /// The separately identified, Governor-prepared control transition that
    /// records the disposition and its Problem-owner consequence. Its own
    /// immutable receipt is the handoff evidence ORS consumes; it must never
    /// reuse the original dead-letter operation identity. Its sole
    /// `ApplyProblemOwnerState` parameter map carries
    /// `sequence_disposition: { operation, choice, expected_ordering_heads }`
    /// exactly as this request presents them, so the committed owner receipt
    /// can be read back after a crash and compared without reconstructing the
    /// decision.
    pub control_transition: PreparedTransition,
    /// Exact revision heads admitted by the control transition.
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    /// Exact canonical ordering heads observed before the control transition.
    /// The Store rechecks both these sequence values and the recorded head
    /// digests inside the same transaction that commits the disposition.
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
}

/// Exact sequence-disposition evidence embedded in the separately identified
/// Problem-owner control transition. This keeps the original immutable record,
/// selected choice, and the complete head snapshot in the canonical receipt
/// body so restart reconciliation can compare the committed decision byte for
/// byte.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceDispositionEvidence {
    /// Original operation and its complete affected-scope bindings.
    pub operation: PoisonOperationRecord,
    /// Choice applied by the control transition.
    pub choice: SequenceDispositionChoice,
    /// Full, independent current ordering-head snapshot.
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
}

impl SequenceDispositionEvidence {
    /// Validates the owner evidence shape and exact all-scope head binding.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.operation.validate()?;
        self.choice.validate(&self.operation.original)?;
        let mut expected: Vec<_> = self.operation.affected_scopes.iter()
            .map(|scope| (scope.reserved.scope.clone(), scope.expected_head_sequence))
            .collect();
        expected.sort();
        let mut supplied = Vec::with_capacity(self.expected_ordering_heads.len());
        for head in &self.expected_ordering_heads {
            head.validate()?;
            supplied.push((head.scope.clone(), head.expected_sequence));
        }
        supplied.sort();
        if supplied != expected {
            return Err(StoreError::InvalidField {
                field: "sequence_disposition.expected_ordering_heads",
                reason: "must bind every affected scope exactly once",
            });
        }
        Ok(())
    }
}

impl SequenceDispositionRequest {
    /// Checks the closed version, the complete operation record, the chosen
    /// disposition against that record, and the all-or-none affected scope set.
    ///
    /// This is the intrinsic shape check. It reads no clock, allocates no
    /// sequence, and cannot by itself authorize a transition; the receiving
    /// boundary must confirm current owner evidence (authority, the exact
    /// current gap, and the current head revisions) inside the actual store
    /// transaction. A stale, foreign, partial, or duplicate-but-changed
    /// disposition fails closed here or in that transaction.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.contract_version != SEQUENCE_DISPOSITION_CONTRACT_VERSION {
            return Err(StoreError::InvalidField {
                field: "disposition.contract_version",
                reason: "unsupported sequence-disposition contract version",
            });
        }
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        self.operation.validate()?;
        self.choice.validate(&self.operation.original)?;
        self.control_transition.validate()?;
        if self.control_transition.state_fence != self.state_fence
            || self.control_transition.identity.operation_id
                == self.operation.original.operation_id
            || self.control_transition.identity.idempotency_key
                == self.operation.original.idempotency_key
            || self.control_transition.transition_class != TransitionClass::RecoverySchema
            || self.control_transition.named_operations.len() != 1
            || self.control_transition.named_operations[0].operation
                != NamedMutationOperation::ApplyProblemOwnerState
        {
            return Err(StoreError::InvalidField {
                field: "disposition.control_transition",
                reason: "must be a separately identified, fenced Problem-owner control transition",
            });
        }
        let mut expected_heads: Vec<_> = self
            .operation
            .affected_scopes
            .iter()
            .map(|scope| {
                (
                    scope.reserved.scope.clone(),
                    scope.expected_head_sequence,
                    scope.reserved.reserved_sequence,
                )
            })
            .collect();
        expected_heads.sort();
        let mut supplied_heads: Vec<_> = self
            .expected_ordering_heads
            .iter()
            .map(|head| (head.scope.clone(), head.expected_sequence))
            .collect();
        supplied_heads.sort();
        let mut transition_scopes = self.control_transition.ordering_scopes.clone();
        transition_scopes.sort();
        let closes_gap = self.choice.dispositions_reserved_position();
        let required_transition_scopes = if closes_gap {
            expected_heads
                .iter()
                .map(|(scope, _, _)| scope.clone())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let expected_scope_heads: Vec<_> = expected_heads
            .iter()
            .map(|(scope, sequence, _)| (scope.clone(), *sequence))
            .collect();
        if transition_scopes != required_transition_scopes
            || supplied_heads != expected_scope_heads
            || (closes_gap
                && expected_heads
                    .iter()
                    .any(|(_, head, reserved)| head.checked_add(1) != Some(*reserved)))
        {
            return Err(StoreError::InvalidField {
                field: "disposition.control_transition.ordering_heads",
                reason: "a closing control transition must advance every affected scope into the reserved position; dependent-only control leaves the gap open",
            });
        }
        for head in &self.expected_ordering_heads {
            head.validate()?;
            if head.state_fence != self.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        for head in &self.expected_revision_heads {
            head.validate()?;
            if head.state_fence != self.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        if !self.choice.dispositions_reserved_position()
            && !matches!(
                self.choice,
                SequenceDispositionChoice::CancelDependents { .. }
            )
        {
            return Err(StoreError::InvalidField {
                field: "disposition.choice",
                reason: "only skip_proven_no_effect or replace_same_identity dispositions a \
                         reserved position",
            });
        }
        Ok(())
    }
}

/// Read-only recovery projection of one blocked reserved position (issue
/// #1684, step 7).
///
/// Returned by the existing status/read routes with role/privacy filtering
/// applied. It is a read view, never authority: an operator Boolean, an enum
/// value, or a self-hash is not authorization.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceGapStatus {
    /// The gap identity.
    pub gap_id: String,
    /// The original operation identity and its preserved original receipt.
    pub original: DeadLetterOperation,
    /// The complete affected scope set with reserved sequences and current
    /// head revisions.
    pub affected_scopes: Vec<AffectedScope>,
    /// The disposition choices this gap currently supports, given the evidence
    /// on record. The next authorized action is the first supported choice.
    pub supported_choices: Vec<String>,
    /// The next authorized action, or `None` when no choice is supported by
    /// current evidence.
    pub next_authorized_action: Option<String>,
}

/// One plain digest over the canonical bytes of a poison-operation record.
///
/// Used to bind the record the disposition decision was taken against, so a
/// changed record is detected as a duplicate-but-changed disposition and fails
/// closed. One encoder only; the same helper validates on decode.
#[must_use = "a computed digest must be used or checked"]
pub fn poison_operation_record_digest(
    record: &PoisonOperationRecord,
) -> Result<String, StoreError> {
    let bytes = canonical_json_bytes(record)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
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
