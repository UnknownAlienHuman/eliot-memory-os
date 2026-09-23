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
use eliot_context_contracts::ActiveUnderstandingView;
use eliot_dreamer_contracts::self_query::AcceptedSourceProjection;
use eliot_epistemic_contracts::{CurrentEpistemicPosition, Currentness, ProviderContribution};
use eliot_experience_provider::{
    BankShapeInputs, ExperienceView, FeedbackShapeInputs, JournalShapeOutput, ProduceJournalInputs,
    ProviderError, RetentionContext, SelfQualityInputs, SelfQualityRecheckInputs, WithheldMember,
    assess_and_recheck, produce_common_ground_assessment, produce_journal_read,
    produce_memory_quality, produce_understanding_assessment,
};
use eliot_learning_contracts::HarnessActivationReceiptCandidate;
use eliot_memory_quality::{MemoryEcologyAssessment, QualityRequest};
use eliot_observation::{
    GovernorObservationError,
    bank_admission::{
        BankStoreSnapshot, ExperienceRevisionLedger, FeedbackStoreSnapshot,
        bank_records_from_range_payload, feedback_records_from_range_payload,
        supply_bank_projection_from_store, supply_feedback_projection_from_store,
    },
};
use eliot_observation_contracts::{
    ObservationScope, ProjectionCoverage, ProjectionOmission, RetentionHold, RetentionSchedule,
};
use eliot_understanding_assessment::{
    AssessmentClosure, AssessmentScope, CommonGroundAssessment, CommonGroundInput, EvidenceCite,
    ExperienceEvidence, OwnerContext, ScopedUnderstandingAssessment,
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
    /// The Governor owner rejected admission, supply, or readback parsing.
    #[error("governor observation owner: {0}")]
    Governor(#[from] GovernorObservationError),
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
    /// Read scope governing the projection (consumer-owned filtering).
    pub scope: ObservationScope,
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
            consistency: inputs.consistency.clone(),
            admitted_record_ids: inputs.admitted_record_ids,
            minimum_revisions: inputs.minimum_revisions,
        },
    )
    .await
    .map_err(ExperienceDriverError::Provider)
}

/// Bank-family event inputs: durable range payload plus the read
/// context the edge owns.
pub struct ExperienceBankEventInputs {
    /// Verbatim durable range payload (`records` array of wrapper rows or
    /// owner-held bare documents) from the bank range read.
    pub payload: serde_json::Value,
    /// Stable identity minted by the caller for the bank envelope.
    pub projection_id: ArtifactId,
    /// Owner revision marker read at, supplied with the durable read.
    pub source_revision: String,
    /// Owner coverage binding for the durable read.
    pub coverage: ProjectionCoverage,
    /// Owner omissions for the durable read.
    pub omissions: Vec<ProjectionOmission>,
    /// Owner source identity cursors resolve under (edge passes the
    /// Governor bank source identity); never invented here.
    pub source_id: String,
}

/// Feedback-family event inputs. Same durable-read rule as bank.
pub struct ExperienceFeedbackEventInputs {
    /// Verbatim durable range payload from the feedback range read.
    pub payload: serde_json::Value,
    /// Stable identity minted by the caller for the feedback envelope.
    pub projection_id: ArtifactId,
    /// Owner revision marker read at, supplied with the durable read.
    pub source_revision: String,
    /// Owner coverage binding for the durable read.
    pub coverage: ProjectionCoverage,
    /// Owner omissions for the durable read.
    pub omissions: Vec<ProjectionOmission>,
    /// Owner source identity cursors resolve under (edge passes the
    /// Governor feedback source identity); never invented here.
    pub source_id: String,
}

/// Governed trigger event for one terminal experience-quality run.
///
/// Understanding leg inputs: everything except outcome-side experience.
///
/// The entry binds outcome-side experience evidence from its own live
/// envelopes; all other inputs arrive edge-supplied from their owners
/// (compiled view, accepted sources, contribution, scope, cites,
/// closure). Product claims stay false unless the edge holds out
/// evidence for them.
pub struct UnderstandingEventInputs<'a> {
    /// Already-compiled understanding view, by handle (edge-supplied).
    pub view: &'a ActiveUnderstandingView,
    /// Accepted-source projection for citation checks (edge-supplied).
    pub sources: &'a AcceptedSourceProjection,
    /// Optional admitted epistemic contribution, echoed by digest/claim.
    pub contribution: Option<&'a ProviderContribution>,
    /// Denominator anchor.
    pub scope: AssessmentScope,
    /// Subject route or coupled system.
    pub subject: String,
    /// Transfer boundary and requalification text.
    pub transfer_boundary: String,
    /// Material unknowns cites.
    pub material_unknowns: Vec<EvidenceCite>,
    /// Abstention precision/coverage cites, where applicable.
    pub abstention: Vec<EvidenceCite>,
    /// Unanswerable/stale case cites, where applicable.
    pub unanswerable: Vec<EvidenceCite>,
    /// Counterfactual intervention cites, where applicable.
    pub counterfactual: Vec<EvidenceCite>,
    /// Rival/prediction/discriminator/verifier/revision closure.
    pub closure: AssessmentClosure,
    /// True when the verdict backs a product claim (held-out required).
    pub product_claims: bool,
}

/// Common-ground leg inputs: everything except outcome-side experience.
///
/// Same binding rule as [`UnderstandingEventInputs`]: the entry binds
/// outcome-side experience evidence from its own live envelopes; all
/// other inputs arrive edge-supplied from their owners.
pub struct CommonGroundEventInputs<'a> {
    /// Already-compiled understanding view, by handle (edge-supplied).
    pub view: &'a ActiveUnderstandingView,
    /// Accepted-source projection for citation checks (edge-supplied).
    pub sources: &'a AcceptedSourceProjection,
    /// Optional admitted epistemic contribution, echoed by digest/claim.
    pub contribution: Option<&'a ProviderContribution>,
    /// Denominator anchor.
    pub scope: AssessmentScope,
    /// Terminology compatibility cites.
    pub terminology: Vec<EvidenceCite>,
    /// Reference compatibility cites.
    pub reference: Vec<EvidenceCite>,
    /// Commitment compatibility cites.
    pub commitment: Vec<EvidenceCite>,
    /// Action-consequence compatibility cites.
    pub action_consequence: Vec<EvidenceCite>,
    /// Survival-across-change cites.
    pub survival: Vec<EvidenceCite>,
    /// Public inheritance transfer refs.
    pub transfer_refs: Vec<EvidenceCite>,
    /// Requalification scope for tacit competence.
    pub requalification_scope: String,
    /// Rival/prediction/discriminator/verifier/revision closure.
    pub closure: AssessmentClosure,
    /// True when the verdict backs a product claim (held-out required).
    pub product_claims: bool,
}

/// The event producer (operator/planner edge, O1 trigger) assembles this
/// from explicit owner-issued inputs only: bridge scope and position
/// subject, journal presence inputs, durable bank/feedback documents with
/// their read context, the owner-issued retention schedule with
/// caller-carried holds, per-attempt receipts, obligation handles, edge
/// attestation, plus the memory request and understanding leg when those
/// families run. Reads stay reads: nothing here writes, persists, or
/// submits; the entry returns the frozen candidates plus the validated
/// views and gap postures for the consuming review path.
pub struct ExperienceQualityEvent<'a> {
    /// Assessment identity minted by the caller.
    pub assessment_id: ArtifactId,
    /// Work scope governing the assessment.
    pub assessment_scope: WorkScopeId,
    /// Read scope governing projections and views.
    pub scope: ObservationScope,
    /// Store scope bridge reads run in.
    pub scope_id: ScopeId,
    /// Exact position subject the bridge position read selects.
    pub position_subject: String,
    /// Journal leg inputs, when the journal family is cited.
    pub journal: Option<ExperienceJournalDriverInputs<'a>>,
    /// Bank-family durable inputs.
    pub bank: ExperienceBankEventInputs,
    /// Feedback-family durable inputs.
    pub feedback: ExperienceFeedbackEventInputs,
    /// Owner-issued retention schedule in force for this run.
    pub schedule: &'a RetentionSchedule,
    /// Schedule-issued hold terms by record-handle text.
    pub holds: &'a BTreeMap<String, RetentionHold>,
    /// Per-attempt receipt candidates (at least one; edge-supplied).
    pub receipts: &'a [HarnessActivationReceiptCandidate],
    /// Obligation-profile handles cited by handle only (edge-supplied).
    pub obligation_handles: &'a [ArtifactId],
    /// Edge-attested handles for bodies cited by handle only.
    pub attested_handles: Vec<ArtifactId>,
    /// Memory-quality request, when the memory family runs (edge-supplied
    /// owner batch, applicability verdict, projections, and receipts).
    pub memory: Option<QualityRequest>,
    /// Understanding leg inputs, when the understanding family runs
    /// (edge-supplied owner context minus outcome experience, which the
    /// entry binds from its own live envelopes).
    pub understanding: Option<UnderstandingEventInputs<'a>>,
    /// Common-ground leg inputs, when the common-ground family runs
    /// (same outcome-experience binding rule as the scoped leg).
    pub common_ground: Option<CommonGroundEventInputs<'a>>,
}

/// Terminal output bundle: frozen candidates plus validated views and gaps.
pub struct ExperienceQualityEventOutput {
    /// Frozen self-quality candidate, assessed and re-resolved.
    pub candidate: QualityAssessmentCandidate,
    /// Validated journal view, when the journal family was cited.
    pub journal_view: Option<ExperienceView>,
    /// Validated bank view over owner-issued refs.
    pub bank_view: ExperienceView,
    /// Validated feedback view over owner-issued refs.
    pub feedback_view: ExperienceView,
    /// Withheld bank records with honest postures for gap emission.
    pub bank_withheld: Vec<WithheldMember>,
    /// Withheld feedback records with honest postures for gap emission.
    pub feedback_withheld: Vec<WithheldMember>,
    /// Memory ecology assessment, when the memory family ran.
    pub memory_assessment: Option<MemoryEcologyAssessment>,
    /// Scoped understanding assessment, when the understanding family ran.
    pub understanding: Option<ScopedUnderstandingAssessment>,
    /// Common-ground assessment, when the common-ground family ran.
    pub common_ground: Option<CommonGroundAssessment>,
}

/// Terminal event entry: trigger event to reviewed candidate.
///
/// Runs the full connected runtime path in source terms: TRUE position
/// bridge read, optional journal bridge leg with live presence binding,
/// bank/feedback range-payload consume through the owner supply drivers
/// ([`supply_bank_projection_from_store`] /
/// [`supply_feedback_projection_from_store`]: wrapper-aware decode with
/// digest re-proof, retention gating, per-ref snapshot resolution),
/// provider view shaping with retention postures and live revalidation,
/// then the consuming call
/// ([`assess_and_recheck`](eliot_experience_provider::assess_and_recheck)):
/// assess over true owner envelopes plus edge receipts, immediately
/// re-resolved against the same inputs plus edge attestation. The ledger
/// is ephemeral per run (rebuilt from decoded records, no durable
/// state). Any drift, malformation, withheld-but-uncited material, or
/// missing family fails closed; nothing partial is emitted as complete
/// and nothing is persisted or submitted by this entry.
#[allow(clippy::too_many_lines)]
pub async fn run_experience_quality_event(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    event: &ExperienceQualityEvent<'_>,
) -> Result<ExperienceQualityEventOutput, ExperienceDriverError> {
    ctx.validate().map_err(|_| ExperienceDriverError::Position {
        field: "request_metadata",
        reason: "invalid request metadata",
    })?;
    if let Some(journal) = &event.journal
        && journal.scope != event.scope
    {
        return Err(ExperienceDriverError::Position {
            field: "event.journal.scope",
            reason: "journal leg scope does not match event scope",
        });
    }
    let position = read_current_position(
        composition,
        kernel,
        ctx,
        event.scope_id.clone(),
        event.position_subject.clone(),
    )
    .await?;
    let (journal_envelope, journal_view) = match &event.journal {
        Some(inputs) => {
            let shaped = produce_journal_projection(composition, kernel, ctx, inputs).await?;
            (Some(shaped.projection), Some(shaped.view))
        }
        None => (None, None),
    };
    let mut ledger = ExperienceRevisionLedger::new();
    let bank_records = bank_records_from_range_payload(&event.bank.payload)?;
    let bank_live = supply_bank_projection_from_store(
        &mut ledger,
        BankStoreSnapshot {
            records: &bank_records,
            source_revision: event.bank.source_revision.clone(),
            coverage: event.bank.coverage.clone(),
            omissions: event.bank.omissions.clone(),
        },
        event.bank.projection_id.clone(),
        event.scope.clone(),
        ctx.state_fence.clone(),
        event.schedule,
        event.holds,
    )?;
    let bank_shaped = eliot_experience_provider::shape_bank_view(
        &BankShapeInputs {
            scope: event.scope.clone(),
            fence: ctx.state_fence.clone(),
            records: &bank_records,
            live: &bank_live,
            source_id: event.bank.source_id.as_str(),
            retention: &RetentionContext {
                schedule: event.schedule,
                holds: event.holds,
            },
        },
    )?;
    let feedback_records = feedback_records_from_range_payload(&event.feedback.payload)?;
    let feedback_live = supply_feedback_projection_from_store(
        &mut ledger,
        FeedbackStoreSnapshot {
            records: &feedback_records,
            source_revision: event.feedback.source_revision.clone(),
            coverage: event.feedback.coverage.clone(),
            omissions: event.feedback.omissions.clone(),
        },
        event.feedback.projection_id.clone(),
        event.scope.clone(),
        ctx.state_fence.clone(),
        event.schedule,
        event.holds,
    )?;
    let feedback_shaped = eliot_experience_provider::shape_feedback_view(
        &FeedbackShapeInputs {
            scope: event.scope.clone(),
            fence: ctx.state_fence.clone(),
            records: &feedback_records,
            live: &feedback_live,
            source_id: event.feedback.source_id.as_str(),
            retention: &RetentionContext {
                schedule: event.schedule,
                holds: event.holds,
            },
        },
    )?;
    let candidate = assess_and_recheck(SelfQualityRecheckInputs {
        assess: SelfQualityInputs {
            assessment_id: event.assessment_id.clone(),
            scope: event.assessment_scope.clone(),
            fence: ctx.state_fence.clone(),
            journal: journal_envelope.as_ref(),
            bank: Some(&bank_live),
            feedback: Some(&feedback_live),
            position: &position,
            receipts: event.receipts,
            obligation_handles: event.obligation_handles,
        },
        attested_handles: event.attested_handles.clone(),
    })?;
    let memory_assessment = match &event.memory {
        Some(request) => Some(produce_memory_quality(request)?),
        None => None,
    };
    let mut experience = Vec::new();
    if let Some(journal) = journal_envelope.as_ref() {
        experience.push(ExperienceEvidence::Journal(journal));
    }
    experience.push(ExperienceEvidence::Bank(&bank_live));
    experience.push(ExperienceEvidence::Feedback(&feedback_live));
    let understanding = match &event.understanding {
        Some(inputs) => {
            let scoped = eliot_understanding_assessment::ScopedInput {
                owner: OwnerContext {
                    view: inputs.view,
                    sources: inputs.sources,
                    contribution: inputs.contribution,
                    experience: &experience,
                },
                scope: inputs.scope.clone(),
                subject: inputs.subject.clone(),
                transfer_boundary: inputs.transfer_boundary.clone(),
                material_unknowns: inputs.material_unknowns.clone(),
                abstention: inputs.abstention.clone(),
                unanswerable: inputs.unanswerable.clone(),
                counterfactual: inputs.counterfactual.clone(),
                closure: inputs.closure.clone(),
                product_claims: inputs.product_claims,
            };
            Some(produce_understanding_assessment(scoped)?)
        }
        None => None,
    };
    let common_ground = match &event.common_ground {
        Some(inputs) => {
            let common = CommonGroundInput {
                owner: OwnerContext {
                    view: inputs.view,
                    sources: inputs.sources,
                    contribution: inputs.contribution,
                    experience: &experience,
                },
                scope: inputs.scope.clone(),
                terminology: inputs.terminology.clone(),
                reference: inputs.reference.clone(),
                commitment: inputs.commitment.clone(),
                action_consequence: inputs.action_consequence.clone(),
                survival: inputs.survival.clone(),
                transfer_refs: inputs.transfer_refs.clone(),
                requalification_scope: inputs.requalification_scope.clone(),
                closure: inputs.closure.clone(),
                product_claims: inputs.product_claims,
            };
            Some(produce_common_ground_assessment(common)?)
        }
        None => None,
    };
    Ok(ExperienceQualityEventOutput {
        candidate,
        journal_view,
        bank_view: bank_shaped.view,
        feedback_view: feedback_shaped.view,
        bank_withheld: bank_shaped.withheld,
        feedback_withheld: feedback_shaped.withheld,
        memory_assessment,
        understanding,
        common_ground,
    })
}
