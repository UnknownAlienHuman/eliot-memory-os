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

use eliot_cognitive_quality::QualityAssessmentCandidate;
use eliot_context_contracts::ActiveUnderstandingView;
use eliot_contracts::{ArtifactId, RequestMetadata, StateFence};
use eliot_dreamer_contracts::self_query::AcceptedSourceProjection;
use eliot_dreamer_memory_revision::{
    NegativeMemoryExtinctionCandidate, RevisionError, RevisionIntake,
};
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
        bank_records_from_range_payload, feedback_records_from_range_payload, produce_bank_commit,
        produce_feedback_commit, supply_bank_projection_from_store,
        supply_feedback_projection_from_store,
    },
};
use eliot_observation_contracts::{
    AgentFeedbackRecord, ExperienceBankRecord, ObservationScope, ProjectionCoverage,
    ProjectionOmission, RetentionHold, RetentionSchedule,
};
use eliot_protocol::RequestIdentity;
use eliot_receipts::{RequestBinding, WorkScopeId};
use eliot_store_api::{
    CanonicalReadClient, EXPERIENCE_PAGE_NEXT_CURSOR, NamedReadOperation, NamedReadRequest,
    OrderingHeadExpectation, ReadConsistency, RevisionHeadExpectation, RevisionKey, ScopeId,
    StoreError, WriteReceipt, epistemic_revision::EpistemicPositionReadback,
};
use eliot_understanding_assessment::{
    AssessmentClosure, AssessmentScope, CommonGroundAssessment, CommonGroundInput, EvidenceCite,
    ExperienceEvidence, OwnerContext, ScopedUnderstandingAssessment,
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
    /// Admitted commit ingress could not be derived from retained state.
    #[error("commit ingress field {field}: {reason}")]
    Ingress {
        field: &'static str,
        reason: &'static str,
    },
    /// The Governor-backed experience commit failed.
    #[error("experience commit failed: {0}")]
    Commit(String),
}

/// Maps a Dreamer memory-revision owner rejection into the Governor
/// leg of the driver error.
///
/// The observer-shape rejection maps exactly
/// ([`RevisionError::Observation`] into
/// [`GovernorObservationError::Observation`]: both name
/// `eliot_observation_contracts::ObservationError`). The remaining
/// intake/candidate rejections have no exact Governor counterpart, so
/// they narrow to [`GovernorObservationError::InvalidField`] with the
/// owner-issued field path forwarded verbatim and a fixed reason naming
/// the violated intake contract. The wrapped source detail is not
/// preserved; the field plus reason still fail closed at the same
/// boundary. This mirrors the `produce_memory_quality` pattern: the
/// owner call returns its own error and `?` converts at the call site.
impl From<RevisionError> for ExperienceDriverError {
    fn from(error: RevisionError) -> Self {
        ExperienceDriverError::Governor(match error {
            RevisionError::Observation(inner) => GovernorObservationError::Observation(inner),
            RevisionError::Context(_) => GovernorObservationError::InvalidField {
                field: "dmr.intake.projection",
                reason: "admitted task/safety projection rejected its shape",
            },
            RevisionError::SelfQuery(_) => GovernorObservationError::InvalidField {
                field: "dmr.intake.query",
                reason: "frozen self-query input or accepted-source projection rejected its shape",
            },
            RevisionError::ScopeMismatch { field } => GovernorObservationError::InvalidField {
                field,
                reason: "admitted scope identity does not match its governing scope",
            },
            RevisionError::FenceMismatch { field } => GovernorObservationError::InvalidField {
                field,
                reason: "admitted fence is incompatible with its governing fence",
            },
            RevisionError::DigestMismatch { field } => GovernorObservationError::InvalidField {
                field,
                reason: "posed digest does not match the frozen query it claims",
            },
            RevisionError::StaleCitation { field } => GovernorObservationError::InvalidField {
                field,
                reason: "cited source triple is stale or uncited",
            },
            RevisionError::Bounds { field } => GovernorObservationError::InvalidField {
                field,
                reason: "admitted intake bound exceeded",
            },
            RevisionError::NotDigestible => GovernorObservationError::InvalidField {
                field: "dmr.candidate.digest",
                reason: "candidate is not canonically encodable",
            },
        })
    }
}

/// Dreamer memory-revision consumer invocation: propose one advisory
/// extinction candidate over admitted intake.
///
/// Calls the released [`propose`](eliot_dreamer_memory_revision::propose)
/// consumer with the edge-supplied owner intake (owner-neutral failure
/// observation, revision evidence refs, admitted task/safety
/// projections, frozen self-query/accepted-source refs, pose digest,
/// candidate id). Intake contract violations fail closed as
/// [`ExperienceDriverError::Governor`]; valid intake with insufficient
/// evidence yields `Ok` with state `Inconclusive` or `Unsupported`
/// naming the exact missing evidence. No automatic trigger lives here:
/// the caller passes intake only when the trigger edge already holds
/// every admitted member; nothing is synthesized from the quality
/// event's bank/feedback envelopes.
pub fn propose_memory_extinction_candidate(
    intake: &RevisionIntake<'_>,
) -> Result<NegativeMemoryExtinctionCandidate, ExperienceDriverError> {
    Ok(eliot_dreamer_memory_revision::propose(intake)?)
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
    if position_subject.trim().is_empty() || position_subject.chars().any(char::is_control) {
        return Err(ExperienceDriverError::Position {
            field: "position_subject",
            reason: "must be non-blank and free of control characters",
        });
    }
    ctx.validate()
        .map_err(|_| ExperienceDriverError::Position {
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
    request.validate().map_err(ExperienceDriverError::Bridge)?;
    let response: eliot_store_api::NamedReadResponse = client.execute_named(request).await?;
    response.validate().map_err(ExperienceDriverError::Bridge)?;
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
    let readback: EpistemicPositionReadback = serde_json::from_value(response.payload.clone())
        .map_err(|_| ExperienceDriverError::Position {
            field: "response.payload",
            reason: "position readback is not the versioned shape",
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
    ctx.validate()
        .map_err(|_| ExperienceDriverError::Position {
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
    /// Owner-minted bank continuation cursor echoed verbatim from the
    /// consumed range payload (`next_cursor`), or `None` when the page
    /// ends the enumeration.
    ///
    /// Multi-page enumeration contract: the trigger edge re-issues the
    /// owner range read with this cursor echoed back as the `cursor`
    /// selector and runs this entry again per page until the echoed
    /// cursor is `None`. Cursors bind fence plus revision heads exactly
    /// like the audit range, so a cursor read under drifted fence/heads
    /// fails closed at the store and the caller restarts from the head
    /// page; this entry never synthesizes or advances a cursor itself.
    pub bank_next_cursor: Option<String>,
    /// Owner-minted feedback continuation cursor, same contract as
    /// `bank_next_cursor` above.
    pub feedback_next_cursor: Option<String>,
    /// Scoped understanding assessment, when the understanding family ran.
    pub understanding: Option<ScopedUnderstandingAssessment>,
    /// Common-ground assessment, when the common-ground family ran.
    pub common_ground: Option<CommonGroundAssessment>,
}

/// Echoes the owner-minted range continuation cursor from a consumed
/// bank/feedback range payload, if the page carries one.
///
/// Reads only the [`EXPERIENCE_PAGE_NEXT_CURSOR`] member minted by the
/// owner page envelope
/// ([`ExperienceRangePage`](eliot_store_api::ExperienceRangePage)): a
/// missing member, a non-string member, or a blank cursor echoes as
/// `None` (page ends the enumeration). The cursor is echoed verbatim,
/// never parsed or advanced here; multi-page iteration belongs to the
/// trigger edge per the output contract.
fn range_next_cursor(payload: &serde_json::Value) -> Option<String> {
    payload
        .get(EXPERIENCE_PAGE_NEXT_CURSOR)
        .and_then(serde_json::Value::as_str)
        .filter(|cursor| !cursor.trim().is_empty())
        .map(str::to_owned)
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
    ctx.validate()
        .map_err(|_| ExperienceDriverError::Position {
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
    let bank_shaped = eliot_experience_provider::shape_bank_view(&BankShapeInputs {
        scope: event.scope.clone(),
        fence: ctx.state_fence.clone(),
        records: &bank_records,
        live: &bank_live,
        source_id: event.bank.source_id.as_str(),
        retention: &RetentionContext {
            schedule: event.schedule,
            holds: event.holds,
        },
    })?;
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
    let feedback_shaped = eliot_experience_provider::shape_feedback_view(&FeedbackShapeInputs {
        scope: event.scope.clone(),
        fence: ctx.state_fence.clone(),
        records: &feedback_records,
        live: &feedback_live,
        source_id: event.feedback.source_id.as_str(),
        retention: &RetentionContext {
            schedule: event.schedule,
            holds: event.holds,
        },
    })?;
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
        bank_next_cursor: range_next_cursor(&event.bank.payload),
        feedback_next_cursor: range_next_cursor(&event.feedback.payload),
        understanding,
        common_ground,
    })
}

/// Terminal event entry with an optional admitted extinction intake.
///
/// Runs [`run_experience_quality_event`] unchanged, then — only when
/// `revision` is `Some` — proposes one advisory extinction candidate
/// via [`propose_memory_extinction_candidate`] over that intake.
/// `Some` must be an already-admitted [`RevisionIntake`] held by the
/// trigger edge (the O1-owned daemon trigger assembles it from
/// owner-issued members); this entry never synthesizes intake from
/// the quality event's bank/feedback envelopes and owns no automatic
/// trigger. `None` skips the revision lane entirely. This entry calls
/// [`run_experience_quality_event`] and then the propose wrapper,
/// so both symbols have a production caller in this file; the
/// read-only base path is unaffected.
pub async fn run_experience_quality_event_with_revision(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    event: &ExperienceQualityEvent<'_>,
    revision: Option<&RevisionIntake<'_>>,
) -> Result<
    (
        ExperienceQualityEventOutput,
        Option<NegativeMemoryExtinctionCandidate>,
    ),
    ExperienceDriverError,
> {
    let output = run_experience_quality_event(composition, kernel, ctx, event).await?;
    let extinction = revision
        .map(propose_memory_extinction_candidate)
        .transpose()?;
    Ok((output, extinction))
}

/// Daemon-edge commit lifecycle bound in milliseconds.
///
/// Bounds this run's commit lifecycle only, mirroring the Kernel-client
/// ingress precedent (`daemon_kernel_client` 30s window). It bounds no
/// identity and proves nothing: authority stays with admitted metadata,
/// fence agreement, and the owner checks downstream.
const COMMIT_INGRESS_DEADLINE_MS: u64 = 30_000;

/// Terminal output bundle: durable commit receipts per family.
pub struct ExperienceCommitOutput {
    /// Owner receipts for committed bank records, in input order.
    pub bank_receipts: Vec<WriteReceipt>,
    /// Owner receipts for committed feedback records, in input order.
    pub feedback_receipts: Vec<WriteReceipt>,
    /// True when the composition's dependent view is stale/pending after
    /// this batch, echoed from the composition status projection.
    ///
    /// P2 stale-projection marking: every per-record commit publishes
    /// its owner change through the composition's refresh/stale
    /// discipline (a failed post-commit refresh keeps the already
    /// durable receipt and marks the dependent view stale/pending
    /// instead of hiding divergence). This flag echoes that marker so
    /// the caller can observe it without a second status read; when
    /// set, projections must not be trusted until the caller drops this
    /// composition and re-runs authenticated connect+start. There is no
    /// `refresh_dependent_view` entry: refresh runs inside the
    /// per-record composition commit calls, never as a separate step
    /// from this file.
    pub view_stale: bool,
}

/// Derives admitted commit ingress from retained invocation state.
///
/// Clones the validated invocation metadata (`ctx`) verbatim — the
/// admission contour that invoked this driver — and requires its fence
/// to equal the retained admitted Kernel fence: invocation/Kernel fence
/// drift fails closed here, before any identity exists. The idempotency
/// key is the owner-derived commit key for the exact record being
/// committed (computed by `produce_bank_commit` /
/// `produce_feedback_commit` from admitted record content, never
/// invented); the deadline bounds this run per
/// [`COMMIT_INGRESS_DEADLINE_MS`]; the cancellation identity binds the
/// commit lifecycle to that same record key. Record-fence, scope, and
/// key agreement are re-checked by the commit caller and the owner
/// downstream; nothing here mints identity, heads, or proofs.
pub fn derive_commit_ingress(
    ctx: &RequestMetadata,
    kernel_fence: &StateFence,
    commit_key: &str,
) -> Result<RequestIdentity, ExperienceDriverError> {
    ctx.validate().map_err(|_| ExperienceDriverError::Ingress {
        field: "request_metadata",
        reason: "retained invocation metadata is invalid",
    })?;
    if ctx.state_fence != *kernel_fence {
        return Err(ExperienceDriverError::Ingress {
            field: "request_metadata.state_fence",
            reason: "invocation fence differs from the admitted Kernel fence",
        });
    }
    if commit_key.trim().is_empty() || commit_key.chars().any(char::is_control) {
        return Err(ExperienceDriverError::Ingress {
            field: "idempotency_key",
            reason: "owner-derived commit key is blank or carries control characters",
        });
    }
    Ok(RequestIdentity {
        request: RequestBinding {
            metadata: ctx.clone(),
            state_fence: ctx.state_fence.clone(),
        },
        idempotency_key: commit_key.to_owned(),
        deadline_unix_ms: super::unix_ms().saturating_add(COMMIT_INGRESS_DEADLINE_MS),
        cancellation_id: format!("{commit_key}:cancel"),
    })
}

/// Terminal commit entry: admitted event records to durable rows.
///
/// O1 trigger seam (transcription-ready): the O1 copy transcribes this
/// exact entry plus [`derive_commit_ingress`] and
/// [`ExperienceCommitOutput`]; the read entry
/// ([`run_experience_quality_event`]) is unchanged and stays read-only.
/// Checklist for the O1 copy:
/// - call with the SAME decoded record slices the read entry consumed
///   (bank/feedback range payloads already digest re-proved upstream);
/// - pass `event.scope_id` verbatim; scope/record mismatch fails closed
///   in the commit caller with an exact owner error;
/// - pass edge-supplied live head expectations when held, else empty
///   vectors (no expectations are fabricated here);
/// - per-record receipts return in input order; a mid-batch failure
///   returns `Err` while already-durable receipts stay durable under
///   their deterministic idempotency keys. Every success is retained on
///   the composition as it happens and retained keys are skipped on
///   retry without re-deriving expectations (P1-1, #1942), so retry is
///   convergent and never double-persists.
///
/// Runs, in source terms: ledger rebuild from the admitted slices (only
/// the greatest admitted revision per handle passes the owner
/// sequencing gate; older revisions fail closed, never silently
/// skipped), per-record owner commit payload (`produce_bank_commit` /
/// `produce_feedback_commit`), admitted ingress derivation, the
/// canonical Governor commit caller (`commit_experience_bank` /
/// `commit_experience_feedback`), and returns the owner `WriteReceipt`s
/// unmodified. Proof refs are verbatim admitted refs from the
/// edge-supplied per-attempt receipts (admission + activation-request
/// receipt identities, blanks dropped); nothing is inferred.
#[allow(clippy::too_many_arguments)]
pub async fn commit_experience_event_records(
    composition: &mut DaemonComposition,
    ctx: &RequestMetadata,
    event: &ExperienceQualityEvent<'_>,
    bank_records: &[ExperienceBankRecord],
    feedback_records: &[AgentFeedbackRecord],
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<ExperienceCommitOutput, ExperienceDriverError> {
    ctx.validate().map_err(|_| ExperienceDriverError::Ingress {
        field: "request_metadata",
        reason: "retained invocation metadata is invalid",
    })?;
    let kernel_fence = composition.kernel_snapshot().state_fence().clone();
    let mut proof_refs: Vec<String> = Vec::new();
    for receipt in event.receipts {
        for identity in [
            receipt.admission_receipt.as_str(),
            receipt.activation_request_receipt.as_str(),
        ] {
            if !identity.trim().is_empty()
                && !proof_refs.iter().any(|existing| existing == identity)
            {
                proof_refs.push(identity.to_owned());
            }
        }
    }
    let mut ledger = ExperienceRevisionLedger::new();
    ledger.rebuild_bank(bank_records);
    ledger.rebuild_feedback(feedback_records);
    let mut bank_receipts = Vec::with_capacity(bank_records.len());
    for record in bank_records {
        let commit_key = produce_bank_commit(&ledger, record)
            .map_err(ExperienceDriverError::Governor)?
            .idempotency_key;
        // P1-1 (#1942): a key this composition already committed is durable
        // under that key. Reuse the retained receipt without re-deriving
        // ingress or re-submitting: a retry under freshly derived expected
        // heads would hash differently and wedge permanently in
        // `IdentityConflict`. The store triple rule is untouched and no new
        // operation identity is minted.
        if let Some(receipt) = composition.committed_experience_receipt(&commit_key) {
            bank_receipts.push(receipt);
            continue;
        }
        let identity = derive_commit_ingress(ctx, &kernel_fence, &commit_key)?;
        let receipt = composition
            .commit_experience_bank_record(
                &identity,
                &ledger,
                record,
                event.scope_id.clone(),
                proof_refs.clone(),
                expected_revision_heads.clone(),
                expected_ordering_heads.clone(),
            )
            .await
            .map_err(|error| ExperienceDriverError::Commit(error.to_string()))?;
        composition.note_experience_committed(commit_key, receipt.clone());
        bank_receipts.push(receipt);
    }
    let mut feedback_receipts = Vec::with_capacity(feedback_records.len());
    for record in feedback_records {
        let commit_key = produce_feedback_commit(&ledger, record)
            .map_err(ExperienceDriverError::Governor)?
            .idempotency_key;
        // P1-1 (#1942): same convergent-retry rule as the bank leg above.
        if let Some(receipt) = composition.committed_experience_receipt(&commit_key) {
            feedback_receipts.push(receipt);
            continue;
        }
        let identity = derive_commit_ingress(ctx, &kernel_fence, &commit_key)?;
        let receipt = composition
            .commit_experience_feedback_record(
                &identity,
                &ledger,
                record,
                event.scope_id.clone(),
                proof_refs.clone(),
                expected_revision_heads.clone(),
                expected_ordering_heads.clone(),
            )
            .await
            .map_err(|error| ExperienceDriverError::Commit(error.to_string()))?;
        composition.note_experience_committed(commit_key, receipt.clone());
        feedback_receipts.push(receipt);
    }
    let view_stale = composition.status().health.as_str() == "stale";
    Ok(ExperienceCommitOutput {
        bank_receipts,
        feedback_receipts,
        view_stale,
    })
}
