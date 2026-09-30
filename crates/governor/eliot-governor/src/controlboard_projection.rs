//! Private semantic assembly of the `ControlBoard` read projection.
//!
//! This module compiles one refresh-consistent [`ControlBoardGovernorSnapshot`]
//! over the existing Governor owners (coordination, problem, observation,
//! task, read scope) plus the Kernel-issued named-read digests retained in
//! recovery. It creates no owner, registry, Store client, authority, or
//! second canonical path: every byte digested here is already owned and
//! fenced by the composition, and the snapshot is only published through
//! [`GovernorComposition::controlboard_snapshot`](crate::composition::GovernorComposition::controlboard_snapshot)
//! after the readiness gate.
//!
//! G-11/I-12 grounding: the composition owns no dedicated report owner (see
//! [`RecoveryOwner::ALL`](crate::composition::RecoveryOwner); there is no
//! report entry among the sixteen owners). The G-11 binding is served by the
//! coordination owner and the I-12 binding by the observation evidence
//! journal, which is the provenance substrate for reports. Both binding
//! digests cover the full joint owner assembly under domain separation, and
//! both receipt references are the exact Kernel-issued named-read value
//! digests for the payload bytes assembled here. Nothing is fabricated: an
//! owner that cannot be read fails the assembly instead of producing a
//! placeholder.
//!
//! The snapshot carries no board items or provenance edges. Owner records
//! (tasks, coordination events, journal entries) carry no `ControlBoard`
//! visibility, privacy, or epistemic facts, and inventing them would be a
//! privacy expansion. An empty-items view over real bindings is the honest
//! projection; it is distinct from a missing provider, which stays a typed
//! `PLAN_GAP` at the surface. Command families that need item projections
//! remain deferred until their owners expose the required contract.
//!
//! Anchored-review obligations are the one exception, and only in owner-issued
//! form: [`ControlBoardReviewBatch`] reproduces the coordination owner's own
//! retained records verbatim and adds no visibility, privacy, or role fact, so
//! no `ControlBoard` DTO can be filled from it yet. Those records are
//! nevertheless load-bearing here — the G-11 review-projection binding digest
//! covers them — so a review that moves, is answered, or is disposed changes
//! the served binding instead of being reported as an unchanged board. The
//! batch denominator is the coordination owner's separately recorded
//! expectation, so an unrecorded expectation reads as unknown rather than as
//! a complete review section.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::{ArtifactId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_coordination::{
    AnchorResolution, CoordinationOwner, PeerReviewLifecycle, PeerReviewStanding,
    ReviewRecommendation,
};
use eliot_evaluation_contracts::HumanAttentionEvaluation;
use eliot_observation::ObservationJournal;
use eliot_store_api::ScopeRevisionView;
use eliot_task::TaskLifecycleOwner;
use serde::Serialize;
use thiserror::Error;

use crate::attention_evaluation_commit::{
    AttentionEvaluationValidity, AttentionUnknownSummary, attention_evaluation_validity,
    attention_unknown_summary,
};

/// Fail-closed errors for `ControlBoard` projection assembly.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ControlBoardProjectionError {
    /// The assembly fence is not a valid shared fence.
    #[error("controlboard projection fence is invalid: {0}")]
    Fence(String),
    /// The board revision must be non-zero.
    #[error("controlboard projection read revision must be non-zero")]
    ZeroRevision,
    /// A Kernel-issued receipt digest is not a lowercase SHA-256 value.
    #[error("controlboard projection receipt reference is invalid: {0}")]
    Receipt(String),
    /// Owner state could not be serialized for the binding digest.
    #[error("controlboard projection owner state is invalid: {0}")]
    Owner(String),
}

/// One provider-issued identity binding assembled from a real owner read.
///
/// `binding_id` names the actual Governor owner, `binding_digest` binds the
/// full joint owner assembly at the snapshot fence and revision under domain
/// separation, and `receipt_ref` is the exact Kernel-issued named-read value
/// digest for that owner's payload bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardOwnerBinding {
    /// Stable identity of the Governor owner serving this binding.
    pub binding_id: String,
    /// Digest over the joint owner assembly for this binding domain.
    pub binding_digest: String,
    /// Kernel-issued named-read value digest for the owner's payload bytes.
    pub receipt_ref: String,
}

/// One artifact's anchored-review obligations, reproduced from the
/// coordination owner.
///
/// This is the owner-issued detail record the G-11 review projection serves,
/// not a board row: it carries no `Visibility`, no privacy class, and no
/// capability decision, so no role filter can be evaluated from it and none is
/// claimed. Every obligation keeps its own historical anchor, reviewed
/// revision and digest, and its own outcome, so one answered review never
/// presents a multi-item batch as complete. `outstanding` is derived from the
/// coordination owner's separately recorded expectation, never from the
/// obligations this struct also carries; when no expectation was recorded the
/// denominator is `None` and no completeness may be inferred.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardReviewBatch {
    /// Artifact identity this batch is anchored to.
    pub artifact_id: String,
    /// Currently admitted artifact head revision, absent when none was
    /// admitted. This is the current target and is deliberately separate from
    /// each obligation's own `artifact_revision`, so a review of an older
    /// revision cannot be read as approving the head.
    pub current_artifact_revision: Option<u64>,
    /// Digest bound at the currently admitted head revision, absent when none
    /// was admitted. The current target is the (`current_artifact_revision`,
    /// `current_artifact_digest`) pair: an unchanged digest across a head move
    /// is not new content, and a changed digest never inherits the old
    /// approval. Both live in the coordination artifact-revision space, not in
    /// `ViewRevision` or source-commit space.
    pub current_artifact_digest: Option<String>,
    /// Owner-recorded expected-review count, absent when unrecorded.
    pub expected: Option<u64>,
    /// Retained obligation count.
    pub submitted: u64,
    /// Retained obligations that reached a recorded disposition.
    pub disposed: u64,
    /// Expected reviews still lacking a recorded disposition, absent when the
    /// owner recorded no expectation.
    pub outstanding: Option<u64>,
    /// Every retained obligation for this artifact, in `review_id` order.
    pub obligations: Vec<ControlBoardReviewBatchObligation>,
}

/// One retained anchored-review obligation as the owner holds it.
///
/// Every field reproduces an owner-retained fact verbatim: the stable
/// review/request identity, the immutable reviewed revision and digest, the
/// author session, the submitted anchor, this item's own lifecycle, standing
/// and recommendation, the retained rejection reason and conflict linkage,
/// the carried evidence, and the record fence the obligation was admitted
/// under. No visibility,
/// privacy, role, or recipient fact is carried because the owner retains
/// none; none is invented here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardReviewBatchObligation {
    /// Stable review identity.
    pub review_id: String,
    /// Stable request identity this review answers, so the item stays
    /// joinable to its review request.
    pub request_id: String,
    /// Exact reviewed artifact revision; never rewritten by a later head.
    pub artifact_revision: u64,
    /// Exact reviewed artifact digest at that revision.
    pub artifact_digest: String,
    /// Author of this obligation.
    pub reviewer_session_id: String,
    /// Historical anchor selector exactly as submitted.
    pub anchor_field: String,
    /// Anchor resolution claimed at submit.
    pub anchor_resolution: AnchorResolution,
    /// This obligation's own lifecycle.
    pub lifecycle: PeerReviewLifecycle,
    /// This obligation's own standing.
    pub standing: PeerReviewStanding,
    /// This obligation's own recommendation; one item's recommendation never
    /// disposes another item.
    pub recommendation: ReviewRecommendation,
    /// Reason retained when this obligation was rejected.
    pub rejection_reason: Option<String>,
    /// Conflict this obligation's recommendation is contested under, when the
    /// owner retained one. A contested item keeps its own outcome; no other
    /// item's answer discharges it.
    pub conflict_id: Option<String>,
    /// Evidence references the obligation itself carries.
    pub evidence_refs: Vec<String>,
    /// Record fence the retained obligation was admitted under.
    pub state_fence: StateFence,
}

/// Refresh-consistent `ControlBoard` snapshot assembled over Governor owners.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardGovernorSnapshot {
    /// Exact fence every assembled owner was built at.
    pub fence: StateFence,
    /// Read-owner named-read revision this snapshot was taken at.
    pub read_revision: u64,
    /// Live coordination sequence observed during assembly.
    pub coordination_sequence: u64,
    /// G-11 review-projection binding served by the coordination owner.
    pub g11_coordination: ControlBoardOwnerBinding,
    /// I-12 report-projection binding served by the observation journal.
    pub i12_report: ControlBoardOwnerBinding,
    /// Anchored-review obligations the coordination owner retains, in artifact
    /// identity order. Empty only when the owner itself retains no review
    /// expectation, obligation, or artifact head; a missing owner would fail
    /// the assembly rather than reach this field.
    pub review_batches: Vec<ControlBoardReviewBatch>,
}

/// Borrowed assembly inputs. The caller retains every owner; this struct only
/// borrows them for one deterministic compilation.
pub struct ControlBoardProjectionParts<'a> {
    /// Fence all supplied owners were built at.
    pub fence: &'a StateFence,
    /// Read-owner named-read revision bound to this snapshot.
    pub read_revision: u64,
    /// Durable application coordination owner.
    pub coordination: &'a CoordinationOwner,
    /// Durable task lifecycle owner.
    pub task: &'a TaskLifecycleOwner,
    /// Candidate observation journal owner.
    pub observation: &'a ObservationJournal,
    /// Durable problem revision map.
    pub problem_revisions: &'a BTreeMap<String, u64>,
    /// Canonical read scope view.
    pub read_scope: &'a ScopeRevisionView,
    /// Kernel-issued value digest for the coordination payload bytes.
    pub coordination_receipt_digest: &'a str,
    /// Kernel-issued value digest for the observation payload bytes.
    pub observation_receipt_digest: &'a str,
}

/// Stable owner identity bound into the G-11 coordination binding.
pub const G11_OWNER_BINDING_ID: &str = "governor-owner:coordination";
/// Stable owner identity bound into the I-12 report binding.
pub const I12_OWNER_BINDING_ID: &str = "governor-owner:observation";

fn validates_as_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Compiles one deterministic snapshot over the supplied owners.
///
/// The compilation is pure: identical owner state, fence, revision, and
/// receipt digests produce identical bytes. Any unreadable owner state, zero
/// revision, invalid fence, or malformed receipt digest fails closed without
/// a placeholder.
pub fn compile_controlboard_snapshot(
    parts: &ControlBoardProjectionParts<'_>,
) -> Result<ControlBoardGovernorSnapshot, ControlBoardProjectionError> {
    parts
        .fence
        .validate()
        .map_err(|error| ControlBoardProjectionError::Fence(error.to_string()))?;
    if parts.read_revision == 0 {
        return Err(ControlBoardProjectionError::ZeroRevision);
    }
    for (digest, owner) in [
        (parts.coordination_receipt_digest, "coordination"),
        (parts.observation_receipt_digest, "observation"),
    ] {
        if !validates_as_lower_sha256(digest) {
            return Err(ControlBoardProjectionError::Receipt(owner.to_owned()));
        }
    }
    let coordination_bytes = serde_json::to_vec(&(
        parts.coordination.current_sequence(),
        parts.coordination.events(),
    ))
    .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let task_bytes = serde_json::to_vec(&parts.task.snapshot())
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let observation_bytes = serde_json::to_vec(&parts.observation.snapshot())
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let problem_bytes = serde_json::to_vec(&parts.problem_revisions)
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let scope_bytes = serde_json::to_vec(&parts.read_scope)
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let review_batches = project_review_batches(parts.coordination);
    let review_bytes = serde_json::to_vec(&review_batches)
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let owner_digests = (
        sha256_hex(&coordination_bytes),
        sha256_hex(&task_bytes),
        sha256_hex(&observation_bytes),
        sha256_hex(&problem_bytes),
        sha256_hex(&scope_bytes),
    );
    // The G-11 binding is the review projection, so it also covers the
    // coordination owner's retained review obligations. The I-12 binding is
    // the observation report projection and deliberately does not: a moved or
    // disposed review must change the review binding, not the report binding.
    let bind = |binding_id: &str, receipt_ref: &str, review_digest: Option<&str>| {
        canonical_json_bytes(&(
            binding_id,
            parts.fence,
            parts.read_revision,
            &owner_digests,
            review_digest,
        ))
        .map(|bytes| ControlBoardOwnerBinding {
            binding_id: binding_id.to_owned(),
            binding_digest: sha256_hex(&bytes),
            receipt_ref: receipt_ref.to_owned(),
        })
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))
    };
    let review_digest = sha256_hex(&review_bytes);
    Ok(ControlBoardGovernorSnapshot {
        fence: parts.fence.clone(),
        read_revision: parts.read_revision,
        coordination_sequence: parts.coordination.current_sequence(),
        g11_coordination: bind(
            G11_OWNER_BINDING_ID,
            parts.coordination_receipt_digest,
            Some(&review_digest),
        )?,
        i12_report: bind(I12_OWNER_BINDING_ID, parts.observation_receipt_digest, None)?,
        review_batches,
    })
}

/// Reproduces the coordination owner's retained review obligations verbatim.
///
/// This performs no completeness arithmetic of its own: every count and the
/// outstanding denominator come from
/// [`CoordinationOwner::peer_review_batches`], which reads the owner's
/// separately recorded expectation, so a batch can never be closed by this
/// projection's own list. The only thing decided here is the shape: the
/// surface-visible record repeats the owner's fields and invents no
/// visibility, privacy, or role fact.
fn project_review_batches(coordination: &CoordinationOwner) -> Vec<ControlBoardReviewBatch> {
    coordination
        .peer_review_batches()
        .into_iter()
        .map(|batch| ControlBoardReviewBatch {
            artifact_id: batch.artifact_id,
            current_artifact_revision: batch.current_artifact_revision,
            current_artifact_digest: batch.current_artifact_digest,
            expected: batch.expected,
            submitted: batch.submitted,
            disposed: batch.disposed,
            outstanding: batch.outstanding,
            obligations: batch
                .obligations
                .into_iter()
                .map(|obligation| ControlBoardReviewBatchObligation {
                    review_id: obligation.review_id,
                    request_id: obligation.request_id,
                    artifact_revision: obligation.artifact_revision,
                    artifact_digest: obligation.artifact_digest,
                    reviewer_session_id: obligation.reviewer_session_id,
                    anchor_field: obligation.anchor_field,
                    anchor_resolution: obligation.anchor_resolution,
                    lifecycle: obligation.lifecycle,
                    standing: obligation.standing,
                    recommendation: obligation.recommendation,
                    rejection_reason: obligation.rejection_reason,
                    conflict_id: obligation.conflict_id,
                    evidence_refs: obligation.evidence_refs,
                    state_fence: obligation.state_fence,
                })
                .collect(),
        })
        .collect()
}

/// One persisted Human-attention-evaluation revision as the `ControlBoard`
/// read projection serves it (issue #1784 W5 readback half).
///
/// The row reproduces the persisted record's identity, window, validity, and
/// observed/unknown/not-applicable counts, and only the evidence references
/// the record's own manifest binds. It carries no aggregate score, no
/// superiority badge, no visibility or privacy fact, and no Problem,
/// approval, or policy outcome: an evaluation result neither resolves a
/// Problem nor grants an approval nor changes policy (I11.2), and a quieter
/// profile is shown alongside its missed-risk, harm, and false-block/task
/// costs rather than as an automatic positive (I11.7). A stale or invalidated
/// revision is visibly unusable for current tuning through
/// `unusable_for_current_tuning`; suppressing a notification never removes its
/// persistent obligation, which lives with the notification owner, not here.
/// Unknowns render as unknown counts from the read-back bytes — a prevented
/// action with no observed harm is not a false alarm, and missing follow-up
/// is not zero harm — because the persist leg re-proves the digest over the
/// exact producer bytes instead of substituting defaults.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardAttentionEvaluationRow {
    /// Evaluation identity this revision belongs to.
    pub evaluation_id: String,
    /// Monotonic revision within the evaluation, starting at one.
    pub revision: u64,
    /// Observation window the record binds.
    pub window_id: String,
    /// Current-applicability verdict at the supplied observation instant.
    pub validity: AttentionEvaluationValidity,
    /// Per-group observed/unknown/not-applicable counts; denominators for
    /// display, never ranking inputs.
    pub summary: AttentionUnknownSummary,
    /// Manifest-bound evidence references, exactly as persisted.
    pub evidence_refs: Vec<String>,
    /// True unless the revision is currently valid: expired and invalidated
    /// revisions are retained for history but unusable for current tuning.
    pub unusable_for_current_tuning: bool,
}

/// Projects one persisted evaluation revision into its board row.
///
/// The record is re-validated structurally; validity is evaluated against the
/// caller-supplied observation instant so unknown expiry timing never
/// silently passes. The join invents no visibility, privacy, role, score, or
/// lifecycle fact.
pub fn project_attention_evaluation_row(
    record: &HumanAttentionEvaluation,
    observed_now_ms: Option<i64>,
) -> Result<ControlBoardAttentionEvaluationRow, ControlBoardProjectionError> {
    record
        .validate()
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let validity = attention_evaluation_validity(record, observed_now_ms);
    let unusable_for_current_tuning = validity != AttentionEvaluationValidity::Current;
    Ok(ControlBoardAttentionEvaluationRow {
        evaluation_id: record.evaluation_id.as_str().to_owned(),
        revision: record.revision,
        window_id: record
            .observation_window
            .specification
            .window_id
            .as_str()
            .to_owned(),
        validity,
        summary: attention_unknown_summary(record),
        evidence_refs: record
            .evidence_manifest
            .evidence_refs
            .iter()
            .map(ArtifactId::to_string)
            .collect(),
        unusable_for_current_tuning,
    })
}

/// Authorizes one evidence-expansion request against the persisted manifest.
///
/// Every requested reference must be listed in the record's own evidence
/// manifest; a foreign reference fails the whole expansion rather than
/// serving a partial grant. The check is re-evaluated per call against the
/// presented record and never widens into a cached grant.
pub fn expand_attention_evidence(
    record: &HumanAttentionEvaluation,
    requested: &[ArtifactId],
) -> Result<Vec<ArtifactId>, ControlBoardProjectionError> {
    record
        .validate()
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let mut granted = Vec::with_capacity(requested.len());
    for candidate in requested {
        if !record
            .evidence_manifest
            .evidence_refs
            .iter()
            .any(|bound| bound == candidate)
        {
            return Err(ControlBoardProjectionError::Owner(format!(
                "attention evaluation evidence expansion refused for foreign reference {candidate}"
            )));
        }
        if !granted.contains(candidate) {
            granted.push(candidate.clone());
        }
    }
    Ok(granted)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_store_api::ScopeId;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn fence() -> StateFence {
        StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn scope(fence: &StateFence) -> ScopeRevisionView {
        ScopeRevisionView {
            scope_id: ScopeId::new("scope").expect("scope id"),
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            state_fence: fence.clone(),
        }
    }

    fn parts<'a>(
        fence: &'a StateFence,
        coordination: &'a CoordinationOwner,
        task: &'a TaskLifecycleOwner,
        observation: &'a ObservationJournal,
        problems: &'a BTreeMap<String, u64>,
        read_scope: &'a ScopeRevisionView,
        digests: &'a (String, String),
    ) -> ControlBoardProjectionParts<'a> {
        ControlBoardProjectionParts {
            fence,
            read_revision: 7,
            coordination,
            task,
            observation,
            problem_revisions: problems,
            read_scope,
            coordination_receipt_digest: &digests.0,
            observation_receipt_digest: &digests.1,
        }
    }

    fn digests() -> (String, String) {
        ("a".repeat(64), "b".repeat(64))
    }

    #[test]
    fn empty_owners_assemble_a_deterministic_empty_projection() {
        let fence = fence();
        let coordination = CoordinationOwner::new();
        let task = TaskLifecycleOwner::new(test_epoch(TEST_LINEAGE_A, 1), fence.clone())
            .expect("task owner");
        let observation = ObservationJournal::default();
        let problems = BTreeMap::new();
        let read_scope = scope(&fence);
        let digests = digests();
        let input = parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &problems,
            &read_scope,
            &digests,
        );
        let first = compile_controlboard_snapshot(&input).expect("snapshot");
        let second = compile_controlboard_snapshot(&input).expect("snapshot");
        assert_eq!(first, second);
        assert_eq!(first.fence, fence);
        assert_eq!(first.read_revision, 7);
        assert_eq!(first.g11_coordination.binding_id, G11_OWNER_BINDING_ID);
        assert_eq!(first.i12_report.binding_id, I12_OWNER_BINDING_ID);
        assert_ne!(
            first.g11_coordination.binding_digest,
            first.i12_report.binding_digest
        );
        assert_eq!(first.g11_coordination.receipt_ref, "a".repeat(64));
        assert_eq!(first.i12_report.receipt_ref, "b".repeat(64));
    }

    #[test]
    fn owner_bytes_are_load_bearing_not_canned() {
        let fence = fence();
        let coordination = CoordinationOwner::new();
        let task = TaskLifecycleOwner::new(test_epoch(TEST_LINEAGE_A, 1), fence.clone())
            .expect("task owner");
        let observation = ObservationJournal::default();
        let read_scope = scope(&fence);
        let empty_problems = BTreeMap::new();
        let digests = digests();
        let idle = compile_controlboard_snapshot(&parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &empty_problems,
            &read_scope,
            &digests,
        ))
        .expect("snapshot");
        let mut one_problem = BTreeMap::new();
        one_problem.insert("problem-1".to_owned(), 2);
        let changed = compile_controlboard_snapshot(&parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &one_problem,
            &read_scope,
            &digests,
        ))
        .expect("snapshot");
        assert_ne!(
            idle.g11_coordination.binding_digest,
            changed.g11_coordination.binding_digest
        );
        assert_ne!(
            idle.i12_report.binding_digest,
            changed.i12_report.binding_digest
        );
    }

    #[test]
    fn zero_revision_and_malformed_receipts_fail_closed() {
        let fence = fence();
        let coordination = CoordinationOwner::new();
        let task = TaskLifecycleOwner::new(test_epoch(TEST_LINEAGE_A, 1), fence.clone())
            .expect("task owner");
        let observation = ObservationJournal::default();
        let problems = BTreeMap::new();
        let read_scope = scope(&fence);
        let digests = digests();
        let mut input = parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &problems,
            &read_scope,
            &digests,
        );
        input.read_revision = 0;
        assert_eq!(
            compile_controlboard_snapshot(&input),
            Err(ControlBoardProjectionError::ZeroRevision)
        );
        let mut input = parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &problems,
            &read_scope,
            &digests,
        );
        input.coordination_receipt_digest = "not-a-digest";
        assert!(matches!(
            compile_controlboard_snapshot(&input),
            Err(ControlBoardProjectionError::Receipt(_))
        ));
    }
}
