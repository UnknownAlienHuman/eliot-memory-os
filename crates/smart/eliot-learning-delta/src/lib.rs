//! Deterministic, evidence-bound derivation of one attempt learning outcome.
//!
//! The caller owns issuance and authentication of immutable policy, owner
//! relations, and pre-action freeze records. This crate checks structural and
//! byte/digest consistency across those records and emits only a
//! `CandidateArtifact` result; it does not promote authority or perform I/O.
//! The six borrowed retry materials are owner-supplied canonical load-bearing
//! content. Cosmetic handles and metadata are lineage only: the core hashes
//! and compares the validated bytes/digests and does not infer equivalence from
//! arbitrary prose or normalize free-form plans.
//!
//! Boundary authorization is derived, never asserted: [`derive_boundaries`]
//! turns owner-recorded [`LifecycleActivity`] values into
//! [`ConsequentialBoundary`] values and applies the ordinary-read exclusion
//! through [`status_for_tool`], so naming a boundary alone authorizes nothing.
//! Behavioural effect additionally passes the admission gate
//! ([`check_delivery_typed`]) and is refused with a typed [`DeliveryRefusal`].

#![forbid(unsafe_code)]

mod boundary;
mod derive;
mod evidence;
mod gate;
mod input;
mod policy;
mod result;
mod retry;
mod stored;

pub use boundary::{
    ConsequentialBoundary, LifecycleActivity, derive_boundaries, is_non_consequential_tool,
    require_consequential, status_for_boundary, status_for_tool,
};

pub use derive::derive_attempt_learning_outcome;
pub use evidence::{EvidenceKind, EvidenceReceipt, SemanticOutcome};
pub use gate::{
    AdmissionReceipt, DeliveryRefusal, check_delivery, check_delivery_typed, delivery_allowed,
    select_deliverable_indices,
};
pub use input::{
    AttemptEvidence, AttemptInvocationBinding, AttemptStatus, BeforeSelector, ChangeRequest,
    DependencyEvidence, DependencyRole, DependencyStatus, DerivationContext, EvaluationContext,
    EvaluatorBinding, FrozenPropertyBinding, NoChangeProof, NoChangeRequest, OwnerEmptyDeclaration,
    RefinerDraft,
};
pub use policy::{DerivationPolicy, NoChangeWitness, RetryReason, SurfacePermission};
pub use result::LearningDeltaError;
pub use retry::{
    PriorRetryLineage, RetryAssessment, RetryContext, canonical_retry_fingerprint,
    prior_retry_lineage, retry_reason_name,
};
pub use stored::{
    AttemptCloseDisposition, RetryEquivalence, RetryEquivalenceBasis, StoredDeltaDisposition,
    StoredLearningDelta, StoredRetryRelation,
};

pub use eliot_learning_contracts::{
    AttemptLearningOutcome, ChangeSurface, MemberId, OwnerId, SlotId, TargetId, ValueState,
};
