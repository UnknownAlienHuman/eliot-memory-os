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

use eliot_contracts::{ArtifactId, RequestMetadata, StateFence};
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
        produce_bank_commit, produce_feedback_commit,
        supply_bank_projection_from_store, supply_feedback_projection_from_store,
    },
};
use eliot_observation_contracts::{
    AgentFeedbackRecord, ExperienceBankRecord, ObservationScope, ProjectionCoverage,
    ProjectionOmission, RetentionHold, RetentionSchedule,
};
use eliot_protocol::RequestIdentity;
use eliot_receipts::{RequestBinding, WorkScopeId};
use eliot_store_api::{
    CanonicalReadClient, NamedReadOperation, NamedReadRequest, OrderingHeadExpectation, ReadConsistency,
    RevisionHeadExpectation, RevisionKey, ScopeId, StoreError, WriteReceipt,
    epistemic_revision::EpistemicPositionReadback,
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
    /// Admitted commit ingress could not be derived: the invocation
    /// metadata, fence agreement, commit key, or lifecycle scope is
    /// missing or malformed. Nothing was committed.
    #[error("ingress field {field}: {reason}")]
    Ingress {
        field: &'static str,
        reason: &'static str,
    },
    /// The Governor-backed experience commit failed.
    #[error("experience commit failed: {0}")]
    Commit(String),
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
///
/// Ingress derivation (every field traces to an owner source or an
/// explicitly edge-supplied param; nothing here mints authority):
/// fence and request binding clone verbatim from the admitted `ctx`
/// metadata (validated, never constructed); scope, projection ids,
/// minimums, schedules, holds, receipts, obligation and attested
/// handles arrive edge-supplied with owner-side validation at each
/// boundary; revision cursors resolve only through the shared owner
/// constructors, and a wrong edge-supplied source identity fails
/// closed at revalidation because live cursors never match it; request
/// lifetimes borrow caller-owned values documented on each input
/// struct. No deadline, cancellation, head, or proof value is minted
/// anywhere on this path.
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

/// Derive admitted commit ingress for one record commit.
///
/// Binds the owner-derived commit key into a [`RequestIdentity`] whose
/// request binding clones the admitted invocation metadata verbatim
/// (identity, session, task, product, source, fence, clock) with the
/// fence echoed as the binding fence. The lifecycle scope
/// (`deadline_unix_ms`, `cancellation_id`) arrives edge-supplied: no
/// admitted source carries a commit deadline or cancellation scope, so
/// minting either here would invent lifecycle authority — the trigger
/// edge owns its lifecycle and passes it explicitly, exactly as it
/// passes receipts and handles. The commit key itself is owner-derived
/// (the `idempotency_key` the owner commit payload carries for the
/// record), never minted: caller-supplied keys are rejected.
///
/// Fence agreement (admitted metadata versus the retained Kernel
/// fence), key text, cancellation text, and the assembled identity
/// shape all fail closed before any identity exists; the canonical
/// owner re-validates the identity again downstream. This is the O1
/// seam for the trigger's commit legs: O1 calls it per record with the
/// same admitted `ctx`, the live Kernel fence, the owner-derived key,
/// and its own lifecycle scope, then passes the identity to the
/// canonical commit caller.
/// Terminal output bundle: durable commit receipts per family.
pub struct ExperienceCommitOutput {
    /// Owner receipts for committed bank records, in input order.
    pub bank_receipts: Vec<WriteReceipt>,
    /// Owner receipts for committed feedback records, in input order.
    pub feedback_receipts: Vec<WriteReceipt>,
}
pub fn derive_commit_ingress(
    ctx: &RequestMetadata,
    kernel_fence: &StateFence,
    commit_key: &str,
    deadline_unix_ms: u64,
    cancellation_id: String,
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
    if cancellation_id.trim().is_empty() || cancellation_id.chars().any(char::is_control) {
        return Err(ExperienceDriverError::Ingress {
            field: "cancellation_id",
            reason: "edge cancellation scope is blank or carries control characters",
        });
    }
    let identity = RequestIdentity {
        request: RequestBinding {
            metadata: ctx.clone(),
            state_fence: ctx.state_fence.clone(),
        },
        idempotency_key: commit_key.to_owned(),
        deadline_unix_ms,
        cancellation_id,
    };
    identity.validate().map_err(|_| ExperienceDriverError::Ingress {
        field: "request_identity",
        reason: "derived ingress identity is invalid",
    })?;
    Ok(identity)
}

/// Terminal commit entry: admitted event records to durable rows.
///
/// Arc-callable: takes `composition` by shared reference so trigger
/// contexts holding `Arc<DaemonComposition>` can invoke it with no
/// lock, no restructuring, and no second authority. No refresh runs
/// here and no stale flag is set (both need `&mut`); the owning
/// context runs [`DaemonComposition::refresh_dependent_view`] on its
/// own mutably-held discipline afterwards, and until then projections
/// read through the composition may lag the durable store. Reads stay
/// reads and writes stay owner-checked: the canonical Governor commit
/// caller re-validates identity, fence, scope, and heads downstream.
///
/// Runs, in source terms: ledger rebuild from the admitted slices (only
/// the greatest admitted revision per handle passes the owner
/// sequencing gate; older revisions fail closed, never silently
/// skipped), per-record owner commit payload (`produce_bank_commit` /
/// `produce_feedback_commit`), admitted ingress derivation with
/// edge-owned lifecycle scope, the canonical Governor commit caller
/// (`commit_experience_bank` / `commit_experience_feedback`), and
/// returns the owner `WriteReceipt`s unmodified. Proof refs are
/// verbatim admitted refs from the edge-supplied per-attempt receipts
/// (admission + activation-request receipt identities, blanks
/// dropped); nothing is inferred.
#[allow(clippy::too_many_arguments)]
pub async fn commit_experience_event_records(
    composition: &DaemonComposition,
    ctx: &RequestMetadata,
    event: &ExperienceQualityEvent<'_>,
    bank_records: &[ExperienceBankRecord],
    feedback_records: &[AgentFeedbackRecord],
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
    deadline_unix_ms: u64,
    cancellation_id: String,
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
        let identity = derive_commit_ingress(
            ctx,
            &kernel_fence,
            &commit_key,
            deadline_unix_ms,
            cancellation_id.clone(),
        )?;
        let receipt = eliot_governor::commit_experience_bank(
            &composition.governor,
            &identity,
            &ledger,
            record,
            event.scope_id.clone(),
            proof_refs.clone(),
            expected_revision_heads.clone(),
            expected_ordering_heads.clone(),
        )
        .await
        .map_err(ExperienceDriverError::Governor)?;
        bank_receipts.push(receipt);
    }
    let mut feedback_receipts = Vec::with_capacity(feedback_records.len());
    for record in feedback_records {
        let commit_key = produce_feedback_commit(&ledger, record)
            .map_err(ExperienceDriverError::Governor)?
            .idempotency_key;
        let identity = derive_commit_ingress(
            ctx,
            &kernel_fence,
            &commit_key,
            deadline_unix_ms,
            cancellation_id.clone(),
        )?;
        let receipt = eliot_governor::commit_experience_feedback(
            &composition.governor,
            &identity,
            &ledger,
            record,
            event.scope_id.clone(),
            proof_refs.clone(),
            expected_revision_heads.clone(),
            expected_ordering_heads.clone(),
        )
        .await
        .map_err(ExperienceDriverError::Governor)?;
        feedback_receipts.push(receipt);
    }
    Ok(ExperienceCommitOutput {
        bank_receipts,
        feedback_receipts,
    })
}
