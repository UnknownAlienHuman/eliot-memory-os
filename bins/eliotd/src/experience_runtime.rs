//! Experience runtime driver: terminal observation/quality invocation over
//! the real bridge client (#223 B-consumer lane).
//!
//! Daemon-side production edge for the experience lane, mirroring
//! [`governor_local_read`](super::governor_local_read): a per-call factory
//! over [`DaemonComposition::context_read_client`], so the composition
//! retains no client and no thread and a Governor refresh surfaces as an
//! exact fence mismatch instead of silent divergence. Two drivers:
//!
//! - [`read_current_position`]: the TRUE edge position read. Issues the
//!   existing `GetCurrentEpistemicPosition` catalogue read (scope-bound,
//!   `ExactFence`, `position` subject) through the real
//!   [`KernelContextReadClient`] and extracts the `Current` admitted
//!   position from the durable readback. Works today: capability and
//!   store handler both exist.
//! - [`produce_journal_projection`]: the terminal journal-leg call. Runs
//!   the provider chain
//!   ([`produce_journal_read`](eliot_experience_provider::produce_journal_read))
//!   with the real bridge client and caller-supplied live presence. Fails
//!   closed with `UnknownOperation` until the store side registers the
//!   `GetAuditRange` handler (#19 join); the call itself rides existing
//!   path machinery, exactly like the projection-inputs port-shape probe.
//!
//! Bank/feedback durable supply stays canonical-owner side, and
//! per-attempt receipts plus obligation handles arrive with the trigger
//! edge (O1 registration hunk): this driver invents none of them. No
//! policy, admission, or semantic rule lives here; fence agreement and
//! response identity fail closed before any shaping.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use eliot_contracts::{ArtifactId, RequestMetadata};
use eliot_cognitive_quality::QualityAssessmentCandidate;
use eliot_epistemic_contracts::{CurrentEpistemicPosition, Currentness};
use eliot_experience_provider::{
    JournalShapeOutput, ProduceJournalInputs, ProviderError, SelfQualityInputs,
    produce_journal_read, produce_self_quality,
};
use eliot_learning_contracts::HarnessActivationReceiptCandidate;
use eliot_observation_contracts::{
    BankProjection, FeedbackProjection, JournalProjection, ObservationScope,
};
use eliot_receipts::WorkScopeId;
use eliot_store_api::{
    CanonicalReadClient, NamedReadOperation, NamedReadRequest, ReadConsistency, RevisionKey,
    ScopeId, StoreError, epistemic_revision::EpistemicPositionReadback,
};
use thiserror::Error;

use super::{DaemonComposition, DaemonKernelClient};

/// Typed failures of the experience runtime driver.
#[derive(Debug, Error)]
pub enum ExperienceDriverError {
    /// The bridge client could not be constructed from the composition.
    #[error("daemon composition refused the bridge client: {0}")]
    Composition(String),
    /// The bridge call failed.
    #[error("bridge read failed: {0}")]
    Bridge(#[from] StoreError),
    /// The provider chain rejected the read.
    #[error("experience provider: {0}")]
    Provider(#[from] ProviderError),
    /// The position readback holds no usable current position.
    #[error("position field {field}: {reason}")]
    Position {
        field: &'static str,
        reason: &'static str,
    },
}

/// Read the TRUE admitted edge position through the real bridge client.
///
/// Issues `GetCurrentEpistemicPosition` (scope-bound, `ExactFence`, exact
/// `position` subject) via a per-call client from the composition,
/// validates the response identity and fence, parses the durable
/// readback, and returns the `Current` admitted position. A superseded or
/// absent current position fails closed; nothing is synthesized.
pub async fn read_current_position(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    scope: ScopeId,
    position_subject: String,
) -> Result<CurrentEpistemicPosition, ExperienceDriverError> {
    if position_subject.trim().is_empty()
        || position_subject.chars().any(char::is_control)
    {
        return Err(ExperienceDriverError::Position {
            field: "position_subject",
            reason: "must be non-blank and free of control characters",
        });
    }
    ctx.validate().map_err(|_| ExperienceDriverError::Position {
        field: "request_metadata",
        reason: "invalid request metadata",
    })?;
    let client = composition
        .context_read_client(kernel)
        .map_err(|error| ExperienceDriverError::Composition(error.to_string()))?;
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "position".to_owned(),
        serde_json::Value::String(position_subject),
    );
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetCurrentEpistemicPosition,
        scope_id: Some(scope),
        consistency: ReadConsistency::ExactFence,
        state_fence: ctx.state_fence.clone(),
        parameters,
    };
    request
        .validate()
        .map_err(ExperienceDriverError::Bridge)?;
    let response: eliot_store_api::NamedReadResponse =
        client.execute_named(request).await?;
    response
        .validate()
        .map_err(ExperienceDriverError::Bridge)?;
    if response.operation != NamedReadOperation::GetCurrentEpistemicPosition {
        return Err(ExperienceDriverError::Position {
            field: "response.operation",
            reason: "bridge did not answer the position read",
        });
    }
    if !response.state_fence.is_compatible_with(&ctx.state_fence) {
        return Err(ExperienceDriverError::Position {
            field: "response.state_fence",
            reason: "bridge fence is not compatible with the read fence",
        });
    }
    let readback: EpistemicPositionReadback =
        serde_json::from_value(response.payload.clone()).map_err(|_| {
            ExperienceDriverError::Position {
                field: "response.payload",
                reason: "position readback is not the versioned shape",
            }
        })?;
    for position in &readback.positions {
        position
            .validate()
            .map_err(|_| ExperienceDriverError::Position {
                field: "positions",
                reason: "admitted position is invalid",
            })?;
    }
    readback
        .positions
        .iter()
        .find(|position| position.currentness == Currentness::Current)
        .cloned()
        .ok_or(ExperienceDriverError::Position {
            field: "positions",
            reason: "no current admitted position in the readback",
        })
}

/// Journal-leg driver inputs: projection context plus live binding.
pub struct ExperienceJournalDriverInputs<'a> {
    /// Stable identity minted by the caller for the projection envelope.
    pub projection_id: ArtifactId,
    /// Read scope governing the projection and the bridge read.
    pub scope: ObservationScope,
    /// Store scope the audit range is read in.
    pub scope_id: ScopeId,
    /// Read consistency for the bridge fetch.
    pub consistency: ReadConsistency,
    /// Record ids read from the live journal at call time for binding.
    pub admitted_record_ids: &'a BTreeSet<String>,
    /// Required revision minimums per head key (revision monotonicity).
    pub minimum_revisions: &'a BTreeMap<RevisionKey, u64>,
}

/// Terminal journal-leg call over the real bridge client.
///
/// Builds the per-call client from the composition and runs the full
/// provider chain (bridge fetch, V1 shaping, Smart view assembly, live
/// presence binding) under the caller-admitted fence in `ctx`. The call
/// itself is production machinery; until the store side registers the
/// `GetAuditRange` handler it fails closed with `UnknownOperation`,
/// exactly like the projection-inputs port-shape probe.
pub async fn produce_journal_projection(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    inputs: &ExperienceJournalDriverInputs<'_>,
) -> Result<JournalShapeOutput, ExperienceDriverError> {
    ctx.validate().map_err(|_| ExperienceDriverError::Position {
        field: "request_metadata",
        reason: "invalid request metadata",
    })?;
    let client = composition
        .context_read_client(kernel)
        .map_err(|error| ExperienceDriverError::Composition(error.to_string()))?;
    produce_journal_read(
        &client,
        &ProduceJournalInputs {
            projection_id: inputs.projection_id.clone(),
            scope: inputs.scope.clone(),
            fence: ctx.state_fence.clone(),
            scope_id: inputs.scope_id.clone(),
            consistency: inputs.consistency.clone(),
            admitted_record_ids: inputs.admitted_record_ids,
            minimum_revisions: inputs.minimum_revisions,
        },
    )
    .await
    .map_err(ExperienceDriverError::Provider)
}

/// Self-quality assessment inputs: owner envelopes plus edge inputs.
pub struct ExperienceQualityDriverInputs<'a> {
    /// Assessment identity minted by the caller.
    pub assessment_id: ArtifactId,
    /// Work scope governing the assessment.
    pub assessment_scope: WorkScopeId,
    /// Store scope the position read runs in.
    pub scope_id: ScopeId,
    /// Exact position subject the bridge read selects.
    pub position_subject: String,
    /// Owner journal envelope, when journal evidence is cited.
    pub journal: Option<&'a JournalProjection>,
    /// Owner bank envelope, when bank evidence is cited.
    pub bank: Option<&'a BankProjection>,
    /// Owner feedback envelope, when feedback is cited.
    pub feedback: Option<&'a FeedbackProjection>,
    /// Per-attempt receipt candidates (at least one; edge-supplied).
    pub receipts: &'a [HarnessActivationReceiptCandidate],
    /// Obligation-profile handles cited by handle only (edge-supplied).
    pub obligation_handles: &'a [ArtifactId],
}

/// Terminal self-quality invocation with a true bridge-read position.
///
/// Reads the TRUE admitted edge position through the real bridge client,
/// then invokes the Smart consumer
/// ([`produce_self_quality`](eliot_experience_provider::produce_self_quality))
/// over the supplied owner envelopes plus edge receipts and obligation
/// handles. Journal-only assessment stays valid while bank/feedback
/// supply pends; per-attempt receipts remain edge-supplied because no
/// live harness receipt flow exists in-repo (the sole existing-owner
/// producer is the meta activation assessment over live learning-plane
/// inputs, which have no live supplier either). No finding, verdict,
/// score, or completeness posture is emitted: the candidate freezes the
/// assessed closure for Governor/Human review.
pub async fn assess_experience_quality(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    inputs: &ExperienceQualityDriverInputs<'_>,
) -> Result<QualityAssessmentCandidate, ExperienceDriverError> {
    let position = read_current_position(
        composition,
        kernel,
        ctx,
        inputs.scope_id.clone(),
        inputs.position_subject.clone(),
    )
    .await?;
    produce_self_quality(&SelfQualityInputs {
        assessment_id: inputs.assessment_id.clone(),
        scope: inputs.assessment_scope.clone(),
        fence: ctx.state_fence.clone(),
        journal: inputs.journal,
        bank: inputs.bank,
        feedback: inputs.feedback,
        position: &position,
        receipts: inputs.receipts,
        obligation_handles: inputs.obligation_handles,
    })
    .map_err(ExperienceDriverError::Provider)
}
