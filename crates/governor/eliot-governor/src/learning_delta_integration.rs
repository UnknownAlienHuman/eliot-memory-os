//! Production caller wiring consequential learning-delta derivation to Governor admission.
//!
//! Derivation here is candidate-only: it proposes a durable stored record with
//! lineage, never a behavioral effect. The durable record carries the exact
//! prior observable digest forward to the next materially related attempt.
//! Delivery of any behavioral effect requires a verified Governor admission
//! issued for the stored delta (I12.24 line 179).
//!
//! Only the nine consequential boundaries derive; ordinary reads
//! (`read_file`/`grep`) are not consequential and never derive (line 181).

use eliot_contracts::{ArtifactId, StateFence};
use eliot_learning_contracts::{AttemptLearningOutcome, CampaignLearningStateView};
use eliot_learning_delta::{
    AdmissionReceipt, AttemptEvidence, ConsequentialBoundary, DerivationContext, DerivationPolicy,
    LearningDeltaError, RefinerDraft, StoredLearningDelta, delivery_allowed,
    derive_attempt_learning_outcome,
};

use crate::Governor;
use crate::learning_admission::{
    LEARNING_ADMISSION_SCHEMA_VERSION, LearningAdmissionClaim, LearningAdmissionError,
    LearningAdmissionPermit, issue_learning_admission, verify_learning_admission,
};

/// Derive a candidate learning outcome only at a consequential boundary.
///
/// Fail-closed trigger rule (W1 trigger wiring, W2 boundary trigger, W3 read
/// exclusion): when `boundary` is `None` the caller observed no consequential
/// boundary (e.g. an ordinary `read_file`/`grep`) and this returns
/// `Err(LearningDeltaError::NonConsequential)` without invoking derivation.
/// When `boundary` is `Some`, the boundary was consequential and derivation
/// runs as candidate-only proposal; behavioral effect still needs admission.
pub fn derive_delta_at_boundary(
    state_view: &CampaignLearningStateView,
    evidence: &AttemptEvidence,
    context: &DerivationContext<'_>,
    draft: Option<&RefinerDraft>,
    policy: &DerivationPolicy,
    boundary: Option<ConsequentialBoundary>,
) -> Result<AttemptLearningOutcome, LearningDeltaError> {
    match boundary {
        None => Err(LearningDeltaError::NonConsequential),
        Some(_) => derive_attempt_learning_outcome(state_view, evidence, context, draft, policy),
    }
}

/// Build the Governor admission claim bound to one stored delta.
///
/// W6 binding of one stored delta to Governor admission: the stored delta's
/// artifact id becomes the claim's candidate subject (`candidate_id`), so the
/// subsequent permit authorizes at most that exact candidate. Mint-time
/// trimming is handled by issuance; inputs are stored as given.
#[allow(clippy::too_many_arguments)]
pub fn admission_claim_for_delta(
    campaign_id: &str,
    target_task_id: &str,
    fence: StateFence,
    delta_artifact_id: &str,
    overlay_id: Option<&str>,
    scope_ref: &str,
    authority_ref: &str,
    retention_ref: &str,
    evaluator_ref: &str,
    rollback_ref: &str,
) -> LearningAdmissionClaim {
    LearningAdmissionClaim {
        schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
        source_campaign_id: campaign_id.to_owned(),
        target_task_id: target_task_id.to_owned(),
        fence,
        overlay_id: overlay_id.map(str::to_owned),
        candidate_id: Some(delta_artifact_id.to_owned()),
        scope_ref: scope_ref.to_owned(),
        authority_ref: authority_ref.to_owned(),
        retention_ref: retention_ref.to_owned(),
        evaluator_ref: evaluator_ref.to_owned(),
        rollback_ref: rollback_ref.to_owned(),
    }
}

/// Issue a Governor admission permit for a stored-delta claim.
///
/// Governor admission is required before any behavioral effect (I12.24 line
/// 179): derivation output stays candidate-only until the owner mints a
/// permit for the bound claim. Thin wrapper over `issue_learning_admission`.
pub fn issue_delta_admission(
    governor: &Governor,
    claim: &LearningAdmissionClaim,
) -> Result<LearningAdmissionPermit, LearningAdmissionError> {
    issue_learning_admission(governor, claim)
}

/// Verify that a delta delivery permit is currently admitted.
///
/// Admitted-only delivery (A4): returns `true` only when
/// `verify_learning_admission` rebinds the permit to the live owner
/// epoch/generation and the current fence. Any refusal means no delivery.
pub fn verify_delta_delivery(
    governor: &Governor,
    permit: &LearningAdmissionPermit,
    current_fence: &StateFence,
) -> bool {
    verify_learning_admission(governor, permit, current_fence).is_ok()
}

/// Check whether a stored delta may be delivered under a receipt.
///
/// An unadmitted proposal is stored but not delivered: delivery requires a
/// verified admission receipt bound to the delta artifact and digest. Thin
/// wrapper over `delivery_allowed`.
pub fn delta_delivery_allowed(
    receipt: Option<&AdmissionReceipt>,
    delta: &StoredLearningDelta,
) -> bool {
    delivery_allowed(receipt, &delta.delta_artifact, &delta.delta_digest)
}

/// Canonical retry lineage referencing the durable delta.
///
/// Retry's canonical lineage references the durable delta (A1); the delta's
/// equivalent-retry/reason records equivalence (A2) and changed
/// hypothesis/strategy is recorded in candidate changes (A3). Lineage carries
/// the digest so the retry binds to the exact prior observable and evidence.
pub fn retry_lineage_for_delta(delta: &StoredLearningDelta) -> (&ArtifactId, &str) {
    delta.lineage_for_retry()
}
