//! O1-owned experience audit trigger: staged assembly of one admitted
//! terminal event over live owners, evaluated per activation completion
//! (issue #223, B-terminal lane).
//!
//! Division: `experience_runtime` is the in-candidate B-owned driver over
//! the real owner modules (range planning, range consume, retention-gated
//! shaping, assess plus recheck, admitted commit chain); O1 owns this
//! scheduling entrypoint plus its trigger application. This module resolves
//! every event input from live reads in a fixed stage order — agreed ctx,
//! bridge client, admitted scope binding, scope-identity derivation,
//! supplier-gated fields, then scope-bound range fetch, owner decode, and
//! live revision-head expectations — and either fires the read entry or
//! reports the exact missing inputs. It synthesizes no scope, subject,
//! records, schedule, receipts, handles, or identities beyond
//! caller-correlation ids the entry contract assigns to the caller
//! (`assessment_id`, envelope `projection_id`), duplicates no owner type,
//! holds no supplier state, and invents no Session or authority. A field
//! without a live supplier resolves to `None` naming its exact absent
//! owner and idles the evaluation as
//! [`Pending`](ExperienceAuditOutcome::Pending) — never fabricated, never
//! defaulted into delivery. Failures record with identities preserved and
//! never fail the activation loop that hosts this evaluation.
//!
//! Correlation versus authority (read carefully): the audit ctx below is
//! agreed live state (Kernel fence equals Governor fence, live handshake
//! session when held, daemon product/source stamp, validated shape) —
//! genuine admission currency for READS, retained across the whole
//! evaluation so every leg binds the same fence. It is NOT a retained
//! admitted `RequestIdentity` and must never be presented as one: commit
//! authorization comes from the owner path itself (owner-derived commit
//! keys in `derive_commit_ingress`, exact admission checks in
//! `commit_canonical` downstream). The request id here is caller
//! correlation only; task stays unbound per I5.5 and is never inferred.
//!
//! Stage notes: bank/feedback range reads are scope-addressed
//! (`requires_scope_id`), so no range I/O runs before an admitted scope
//! binds; decoded record slices are the SAME values the read entry
//! consumes and the commit entry re-commits (single decode, shared
//! slices); revision-head expectations map 1:1 from live response heads
//! (zero revisions filtered — the owner validator rejects them) while
//! ordering expectations pass empty until an ordering-head supplier exists
//! (the commit checklist permits empty vectors, never fabricated ones).
//! The commit entry runs `&self`-clean through narrowed forwarders with
//! the refresh discipline separated (`refresh_dependent_view` runs on the
//! mutably-held owning context; the Arc-held trigger re-checks fence
//! currency after commits instead of silently skipping staleness).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    ArtifactId, ClockReading, ProductId, RequestId, RequestMetadata, SourceId, fences_match_exact,
};
use eliot_learning_contracts::HarnessActivationReceiptCandidate;
use eliot_observation::bank_admission::{
    bank_records_from_range_payload, feedback_records_from_range_payload,
};
use eliot_observation_contracts::{
    AgentFeedbackRecord, ExperienceBankRecord, ObservationScope, ProjectionCoverage,
    ProjectionOmission, RetentionHold, RetentionSchedule,
};
use eliot_receipts::WorkScopeId;
use eliot_store_api::{
    EXPERIENCE_PARAM_MAX_RECORDS, MAX_EXPERIENCE_PAGE_RECORDS, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, ReadConsistency, RevisionHeadExpectation, ScopeId, WriteReceiptStatus,
};

use crate::attempt_execution_chain::{
    ExecutionChainError, MissingOwner, supply_governor_fence, supply_live_kernel_fence,
    supply_owner_session,
};
use crate::experience_runtime::{
    ExperienceBankEventInputs, ExperienceDriverError, ExperienceFeedbackEventInputs,
    ExperienceQualityEvent, commit_experience_event_records, run_experience_quality_event,
};
use crate::{DaemonComposition, DaemonKernelClient};

/// Outcome of one experience audit trigger evaluation: completed with a
/// reviewed candidate, pended with the exact missing inputs, or failed on
/// live fence disagreement with the fence preserved. Debug-only: the
/// `Failed` payload carries owner errors without clone/equality semantics.
#[derive(Debug)]
pub enum ExperienceAuditOutcome {
    /// The admitted event ran to a reviewed candidate with validated views
    /// and gap postures, projected observably.
    Completed,
    /// No audit: the exact inputs absent at evaluation time, in
    /// deterministic input order. Normal idle, never an error.
    Pending {
        /// Missing-input inventory.
        missing: Vec<MissingOwner>,
    },
    /// The live fences disagree; the audit ctx cannot bind. Never fails
    /// the activation loop that hosts this evaluation.
    Failed(ExecutionChainError),
}

/// Build the audit request context this evaluation can genuinely bind.
///
/// Reads the live Kernel fence and the Governor admitted fence and requires
/// agreement (any audit ctx binds the live fence, so a moved fence fails
/// closed before anything else is touched); binds the live handshake
/// session when one holds — an absent handshake leaves the session unbound
/// because reads stay reads, while a corrupt binding fails closed;
/// stamps the daemon product/source identity; and validates the whole
/// context. See the module docs for the correlation-versus-authority
/// boundary: this context admits reads, never commits. Task stays unbound
/// per I5.5 and is never inferred here.
pub fn audit_request_context(
    kernel: &DaemonKernelClient,
    composition: &DaemonComposition,
) -> Result<RequestMetadata, ExecutionChainError> {
    let live_fence = supply_live_kernel_fence(kernel);
    let governor_fence = supply_governor_fence(composition);
    if !fences_match_exact(&live_fence, &governor_fence) {
        return Err(ExecutionChainError::StaleAdmissionFence);
    }
    let session = match supply_owner_session(kernel) {
        Ok(session) => Some(session),
        Err(ExecutionChainError::NoLiveOwnerSession) => None,
        Err(error) => return Err(error),
    };
    let context = RequestMetadata {
        request_id: RequestId::new("eliotd:experience:quality-event")
            .map_err(ExecutionChainError::OwnerIdentity)?,
        session_id: session,
        task_id: None,
        product_id: ProductId::new(crate::SERVICE_NAME)
            .map_err(ExecutionChainError::OwnerIdentity)?,
        source_id: SourceId::new(crate::SERVICE_NAME)
            .map_err(ExecutionChainError::OwnerIdentity)?,
        state_fence: live_fence,
        clock: ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    context
        .validate()
        .map_err(ExecutionChainError::OwnerIdentity)?;
    Ok(context)
}

/// Plan one scope-addressed experience range read (pure, no I/O).
///
/// Builds the catalogue read with the admitted scope, `ExactFence`
/// consistency, and the complete page bound (`MAX_EXPERIENCE_PAGE_RECORDS`
/// as a decimal string per the owner parameter table) and validates it.
/// Bank and feedback legs share this single planner; no second shape
/// exists. Scope arrives only through the typed `scope_id` field — a
/// blank scope never becomes a request.
fn plan_experience_range(
    operation: NamedReadOperation,
    scope_id: ScopeId,
    fence: &eliot_contracts::StateFence,
) -> Result<NamedReadRequest, ExecutionChainError> {
    let refused = |reason: String| ExecutionChainError::SupplierReadRejected {
        owner: "experience range planner",
        reason,
    };
    let mut parameters = BTreeMap::new();
    parameters.insert(
        EXPERIENCE_PARAM_MAX_RECORDS.to_owned(),
        serde_json::Value::String(MAX_EXPERIENCE_PAGE_RECORDS.to_string()),
    );
    let request = NamedReadRequest {
        operation,
        scope_id: Some(scope_id),
        consistency: ReadConsistency::ExactFence,
        state_fence: fence.clone(),
        parameters,
    };
    request.validate().map_err(|error| refused(error.to_string()))?;
    Ok(request)
}

/// Fetch one planned range read and verify the readback.
///
/// Executes through the canonical bridge client and checks the three
/// readback bindings before returning anything: the operation echo must
/// match the request, the response fence must equal the agreed live fence
/// exactly, and the response must validate (heads unique and well-formed).
/// Any disagreement fails closed with its exact owner detail — a moved
/// fence or a foreign payload never becomes records.
async fn fetch_experience_range<R: eliot_store_api::CanonicalReadClient + ?Sized>(
    reads: &R,
    request: NamedReadRequest,
    fence: &eliot_contracts::StateFence,
) -> Result<NamedReadResponse, ExecutionChainError> {
    let refused = |owner: &'static str, reason: String| ExecutionChainError::SupplierReadRejected {
        owner,
        reason,
    };
    let operation = request.operation;
    let response = reads
        .execute_named(request)
        .await
        .map_err(|error| refused("experience range bridge", error.to_string()))?;
    if response.operation != operation {
        return Err(refused(
            "experience range readback",
            "bridge response operation does not echo the requested read".to_owned(),
        ));
    }
    if response.state_fence != *fence {
        return Err(refused(
            "experience range readback",
            "bridge response fence differs from the agreed live fence".to_owned(),
        ));
    }
    response
        .validate()
        .map_err(|error| refused("experience range readback", error.to_string()))?;
    Ok(response)
}

/// Map live response heads to commit revision expectations.
///
/// One expectation per head with a nonzero revision (the owner validator
/// rejects zero); heads that fail validation fail the mapping closed.
/// Empty input maps to empty output — no expectations are fabricated.
fn live_revision_expectations(
    response: &NamedReadResponse,
) -> Result<Vec<RevisionHeadExpectation>, ExecutionChainError> {
    let mut expectations = Vec::with_capacity(response.revision_heads.len());
    for head in &response.revision_heads {
        if head.revision == 0 {
            continue;
        }
        let expectation = RevisionHeadExpectation {
            key: head.key.clone(),
            expected_revision: head.revision,
            state_fence: head.state_fence.clone(),
        };
        expectation
            .validate()
            .map_err(|error| ExecutionChainError::SupplierReadRejected {
                owner: "revision head expectations",
                reason: error.to_string(),
            })?;
        expectations.push(expectation);
    }
    Ok(expectations)
}

/// Caller-correlation millisecond clock for assessment/envelope ids.
///
/// Correlation only: the entry contract assigns `assessment_id` and
/// envelope `projection_id` minting to the caller, and commit idempotency
/// comes from owner-derived record keys downstream. This clock proves
/// nothing and binds nothing.
fn correlation_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| {
            u64::try_from(duration.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX)
        })
}

/// Evaluate one experience audit trigger step over live owners.
///
/// Stages, in order: agreed ctx; bridge client; admitted scope binding
/// (the scope-addressed range legs cannot run before one binds, and no
/// scope is ever defaulted); scope-identity derivation; supplier-gated
/// fields (position subject, retention schedule, per-attempt receipts,
/// bank/feedback source identities and read context — each names its
/// exact absent owner and resolves to `None` until its supplier lane
/// lands); then, on a complete resolution, scope-bound range fetch with
/// readback verification, owner decode into the shared record slices,
/// live revision-head expectations, event assembly, the read entry, and
/// the commit entry with the shared decoded slices, projecting the
/// reviewed candidate plus verified commit receipts observably. Commit
/// errors distinguish pre-write ingress refusals (nothing committed)
/// from unknown-persistence failures (convergent retry, nothing
/// claimed); receipts prove success by Committed status plus shape
/// validation (never by fence equality), project observably even on
/// later-stage failure, and corroborate durability against live
/// revision heads. Anything missing
/// idles as pending with exact owners. Deterministic and side-effect
/// free except for the live owner/bridge reads plus, on a complete
/// event, the read entry's own bridge reads and the commit entry's
/// canonical writes; the trigger itself mutates nothing (view refresh
/// stays with the mutably-held owning context).
pub async fn evaluate_experience_audit(
    kernel: &Arc<DaemonKernelClient>,
    composition: &DaemonComposition,
) -> ExperienceAuditOutcome {
    let _span = tracing::info_span!("eliotd.experience_audit_poll").entered();
    let context = match audit_request_context(kernel, composition) {
        Ok(context) => context,
        Err(error) => return ExperienceAuditOutcome::Failed(error),
    };
    let reads = match composition.context_read_client(kernel) {
        Ok(reads) => reads,
        Err(error) => {
            return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                owner: "bridge read client",
                reason: error.to_string(),
            });
        }
    };
    let mut missing = Vec::new();
    // Admitted scope binding: the only legitimate source of read-scope
    // identities. Unbound or stale-at-live-fence reads as missing, never
    // as a defaulted scope.
    let binding = match composition.work_scope_binding(&context.state_fence) {
        Ok(binding) => binding,
        Err(error) => {
            return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                owner: "scope binding read",
                reason: error.to_string(),
            });
        }
    };
    let scope_ref: Option<String> = match binding {
        Some(snapshot) => Some(snapshot.binding.scope.scope_ref.clone()),
        None => {
            missing.push(MissingOwner {
                owner: "scope binder",
                artifact: "admitted WorkScope binding at the live fence",
                absent_read: "no WorkScope binding retained for the agreed fence; scope-addressed range legs (bank, feedback, position, journal) cannot name a scope",
            });
            None
        }
    };
    // Supplier-gated fields: no live supplier exists in-tree for any of
    // these today (position-subject binder, retention-schedule owner,
    // harness receipt producer, Governor bank/feedback source identities,
    // durable-read context beyond response heads). Each resolves to `None`
    // naming its exact absent owner; none is defaulted, minted as
    // authority, or inferred. Their resolution sites below are where
    // supplier landings plug in — activation needs no structural change.
    let position_subject: Option<String> = None;
    if position_subject.is_none() {
        missing.push(MissingOwner {
            owner: "position subject owner",
            artifact: "position subject text",
            absent_read: "no admitted position subject; free text never becomes a read selector",
        });
    }
    let schedule: Option<RetentionSchedule> = None;
    let holds: BTreeMap<String, RetentionHold> = BTreeMap::new();
    if schedule.is_none() {
        missing.push(MissingOwner {
            owner: "retention schedule owner",
            artifact: "RetentionSchedule plus holds",
            absent_read: "no owner-issued retention schedule retained for this run; no holds are claimed",
        });
    }
    let receipts: Vec<HarnessActivationReceiptCandidate> = Vec::new();
    if receipts.is_empty() {
        missing.push(MissingOwner {
            owner: "per-attempt receipts",
            artifact: "HarnessActivationReceiptCandidate set",
            absent_read: "no per-attempt receipt candidates; the read entry requires at least one edge-supplied receipt and the harness receipt owner is absent in-tree",
        });
    }
    let bank_source: Option<(String, String, ProjectionCoverage, Vec<ProjectionOmission>)> = None;
    let feedback_source: Option<(String, String, ProjectionCoverage, Vec<ProjectionOmission>)> =
        None;
    if bank_source.is_none() || feedback_source.is_none() {
        missing.push(MissingOwner {
            owner: "bank/feedback source identities",
            artifact: "Governor bank/feedback source identities plus read context",
            absent_read: "no owner-issued source identity, revision marker, coverage, or omissions for either family; the edge passes the Governor source identity and none is retained",
        });
    }
    // Completeness gate: every field above must resolve live before any
    // range I/O runs or any entry fires. No range fetch is attempted for
    // unconsumable data and no entry fires on a partial event.
    let complete = scope_ref.is_some()
        && position_subject.is_some()
        && schedule.is_some()
        && !receipts.is_empty()
        && bank_source.is_some()
        && feedback_source.is_some();
    if !complete {
        tracing::debug!(
            missing_owners = missing.len(),
            fence_generation = context.state_fence.resource_generation.value(),
            "experience audit pended: audit inputs absent"
        );
        return ExperienceAuditOutcome::Pending { missing };
    }
    // Live stages below this point run only on a complete resolution.
    // Each `let ... else` below is statically reachable but runtime-dead
    // until its supplier lane lands; the gate above already proved
    // completeness, so these arms document the invariant instead of
    // panicking on it.
    let Some(scope_text) = scope_ref else {
        return ExperienceAuditOutcome::Pending { missing };
    };
    let scope_id = match ScopeId::new(scope_text.clone()) {
        Ok(scope_id) => scope_id,
        Err(error) => {
            return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                owner: "scope binder",
                reason: error.to_string(),
            });
        }
    };
    let work_scope_id = match WorkScopeId::new(scope_text.clone()) {
        Ok(work_scope_id) => work_scope_id,
        Err(error) => {
            return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                owner: "scope binder",
                reason: error.to_string(),
            });
        }
    };
    let observation_scope = ObservationScope {
        work_scope: work_scope_id.clone(),
        task_ref: None,
        attempt_ref: None,
        module_or_route_ref: None,
    };
    if let Err(error) = observation_scope.validate() {
        return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
            owner: "scope binder",
            reason: error.to_string(),
        });
    }
    let Some(subject) = position_subject else {
        return ExperienceAuditOutcome::Pending { missing };
    };
    let Some(retention) = schedule else {
        return ExperienceAuditOutcome::Pending { missing };
    };
    if receipts.is_empty() {
        return ExperienceAuditOutcome::Pending { missing };
    }
    let Some((bank_revision, bank_source_id, bank_coverage, bank_omissions)) = bank_source else {
        return ExperienceAuditOutcome::Pending { missing };
    };
    let Some((feedback_revision, feedback_source_id, feedback_coverage, feedback_omissions)) =
        feedback_source
    else {
        return ExperienceAuditOutcome::Pending { missing };
    };
    // Scope-bound range fetch with readback verification, then owner
    // decode into the shared slices the read entry consumes and the
    // commit entry re-commits.
    let bank_request = match plan_experience_range(
        NamedReadOperation::GetExperienceBankRange,
        scope_id.clone(),
        &context.state_fence,
    ) {
        Ok(request) => request,
        Err(error) => return ExperienceAuditOutcome::Failed(error),
    };
    let feedback_request = match plan_experience_range(
        NamedReadOperation::GetAgentFeedbackRange,
        scope_id.clone(),
        &context.state_fence,
    ) {
        Ok(request) => request,
        Err(error) => return ExperienceAuditOutcome::Failed(error),
    };
    let bank_response = match fetch_experience_range(&reads, bank_request, &context.state_fence).await
    {
        Ok(response) => response,
        Err(error) => return ExperienceAuditOutcome::Failed(error),
    };
    let feedback_response = match fetch_experience_range(
        &reads,
        feedback_request,
        &context.state_fence,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => return ExperienceAuditOutcome::Failed(error),
    };
    let bank_records: Vec<ExperienceBankRecord> =
        match bank_records_from_range_payload(&bank_response.payload) {
            Ok(records) => records,
            Err(error) => {
                return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                    owner: "bank durable supply",
                    reason: error.to_string(),
                });
            }
        };
    let feedback_records: Vec<AgentFeedbackRecord> =
        match feedback_records_from_range_payload(&feedback_response.payload) {
            Ok(records) => records,
            Err(error) => {
                return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                    owner: "feedback durable supply",
                    reason: error.to_string(),
                });
            }
        };
    let mut revision_expectations = match live_revision_expectations(&bank_response) {
        Ok(expectations) => expectations,
        Err(error) => return ExperienceAuditOutcome::Failed(error),
    };
    match live_revision_expectations(&feedback_response) {
        Ok(expectations) => revision_expectations.extend(expectations),
        Err(error) => return ExperienceAuditOutcome::Failed(error),
    };
    tracing::debug!(
        bank_records = bank_records.len(),
        feedback_records = feedback_records.len(),
        revision_expectations = revision_expectations.len(),
        fence_generation = context.state_fence.resource_generation.value(),
        "experience audit resolved live range material",
    );
    // Event assembly from resolved live inputs. Caller-minted correlation
    // ids only where the entry contract assigns minting to the caller;
    // every other field resolved live above.
    let stamp = correlation_ms();
    let assessment_id = match ArtifactId::new(format!("eliotd:experience:audit:{stamp}")) {
        Ok(assessment_id) => assessment_id,
        Err(error) => {
            return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                owner: "assessment correlation",
                reason: error.to_string(),
            });
        }
    };
    let bank_projection_id = match ArtifactId::new(format!("eliotd:experience:bank:{stamp}")) {
        Ok(projection_id) => projection_id,
        Err(error) => {
            return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                owner: "assessment correlation",
                reason: error.to_string(),
            });
        }
    };
    let feedback_projection_id =
        match ArtifactId::new(format!("eliotd:experience:feedback:{stamp}")) {
            Ok(projection_id) => projection_id,
            Err(error) => {
                return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                    owner: "assessment correlation",
                    reason: error.to_string(),
                });
            }
        };
    let no_obligations: Vec<ArtifactId> = Vec::new();
    let event = ExperienceQualityEvent {
        assessment_id,
        assessment_scope: work_scope_id,
        scope: observation_scope,
        scope_id: scope_id.clone(),
        position_subject: subject,
        journal: None,
        bank: ExperienceBankEventInputs {
            payload: bank_response.payload.clone(),
            projection_id: bank_projection_id,
            source_revision: bank_revision,
            coverage: bank_coverage,
            omissions: bank_omissions,
            source_id: bank_source_id,
        },
        feedback: ExperienceFeedbackEventInputs {
            payload: feedback_response.payload.clone(),
            projection_id: feedback_projection_id,
            source_revision: feedback_revision,
            coverage: feedback_coverage,
            omissions: feedback_omissions,
            source_id: feedback_source_id,
        },
        schedule: &retention,
        holds: &holds,
        receipts: receipts.as_slice(),
        obligation_handles: no_obligations.as_slice(),
        attested_handles: Vec::new(),
        memory: None,
        understanding: None,
        common_ground: None,
    };
    // Terminal read entry: admitted event to reviewed candidate. Anything
    // drifted, malformed, withheld-but-uncited, or missing fails closed
    // inside the entry; nothing partial emits as complete and nothing
    // persists. The output projects observably with bounded identities;
    // failures record with identities preserved and never fail the
    // activation loop.
    //
    // Edge-owned commit lifecycle bound: the trigger edge owns its
    // lifecycle scope per the ingress design (deadline/cancellation
    // arrive explicit from the edge, never minted owner-side). The bound
    // mirrors the established daemon Kernel-client ingress precedent
    // (30s window): it bounds this run only, proves nothing, and carries
    // no authority — admission stays with fence agreement plus the
    // owner-derived commit keys and downstream owner checks.
    const TRIGGER_COMMIT_LIFECYCLE_MS: u64 = 30_000;
    let commit_deadline_unix_ms = correlation_ms().saturating_add(TRIGGER_COMMIT_LIFECYCLE_MS);
    let output = match run_experience_quality_event(composition, kernel, &context, &event).await {
        Ok(output) => output,
        Err(error) => {
            return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                owner: "experience driver",
                reason: error.to_string(),
            });
        }
    };
    // Terminal commit entry: the SAME decoded record slices the read
    // entry consumed, re-committed with live revision expectations and
    // empty ordering expectations. Per-record receipts return in input
    // order under deterministic idempotency keys. Error meaning is
    // exact, never collapsed: an `Ingress` refusal fired before any
    // write (the entry documents nothing committed), while any later
    // failure leaves persistence outcome UNKNOWN — already-durable
    // receipts stay durable and retry is convergent, but this evaluation
    // claims neither success nor failure of persistence.
    let commit = match commit_experience_event_records(
        composition,
        &context,
        &event,
        &bank_records,
        &feedback_records,
        revision_expectations,
        Vec::new(),
        commit_deadline_unix_ms,
    )
    .await
    {
        Ok(commit) => commit,
        Err(ExperienceDriverError::Ingress { field, reason }) => {
            return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                owner: "experience commit ingress",
                reason: format!("{field}: {reason}; nothing was committed"),
            });
        }
        Err(error) => {
            return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                owner: "experience commit",
                reason: format!(
                    "{error}; persistence outcome unknown past validation — already-durable receipts stay durable under idempotency keys, retry is convergent"
                ),
            });
        }
    };
    // Receipt verification: every returned receipt must carry Committed
    // status and validate its shape. A non-committed or malformed
    // receipt from the commit caller is an owner disagreement, never a
    // success — success is proven by receipts, never by fence equality.
    for receipt in commit
        .bank_receipts
        .iter()
        .chain(commit.feedback_receipts.iter())
    {
        if receipt.status != WriteReceiptStatus::Committed {
            return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                owner: "experience commit readback",
                reason: "commit caller returned a non-committed receipt".to_owned(),
            });
        }
        if let Err(error) = receipt.validate() {
            return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                owner: "experience commit readback",
                reason: error.to_string(),
            });
        }
    }
    // Durable-receipt projection: counts plus per-receipt canonical
    // digests, so committed records stay recorded even if a later stage
    // fails. Digests are bounded owner hex, never identities.
    let committed_digests: Vec<&str> = commit
        .bank_receipts
        .iter()
        .chain(commit.feedback_receipts.iter())
        .map(|receipt| receipt.canonical_request_hash.as_str())
        .collect();
    tracing::debug!(
        bank_committed = commit.bank_receipts.len(),
        feedback_committed = commit.feedback_receipts.len(),
        committed_digests = ?committed_digests,
        "experience audit projected durable commit receipts",
    );
    // Post-commit fence currency: an Arc-held trigger cannot refresh the
    // dependent view itself (no `&mut`), so staleness is handled
    // explicitly instead of silently skipped — re-read the live fence
    // and fail closed on drift. Committed receipts stay durable under
    // their idempotency keys (projected above); the next tick retries
    // convergently and the mutably-held owning context runs
    // `refresh_dependent_view` on its own discipline.
    let post_fence = supply_live_kernel_fence(kernel);
    if !fences_match_exact(&post_fence, &context.state_fence) {
        return ExperienceAuditOutcome::Failed(ExecutionChainError::StaleAdmissionFence);
    }
    // Revision-delta durability corroboration: every receipt delta's
    // `after` revision must be present-or-surpassed in the live heads.
    // A live head BELOW a committed `after` means the store lost a
    // write (integrity failure, fail closed). Heads at or above prove
    // the writes landed; they do NOT prove view currency — projections
    // refresh on the owning context's discipline, so currency beyond
    // the fence is reported as delegated, never claimed. An unreadable
    // heads leg degrades to explicit unverified (traced), never silent.
    let heads_request = NamedReadRequest {
        operation: NamedReadOperation::GetRevisionHeads,
        scope_id: None,
        consistency: ReadConsistency::ExactFence,
        state_fence: context.state_fence.clone(),
        parameters: BTreeMap::new(),
    };
    if let Err(error) = heads_request.validate() {
        return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
            owner: "revision heads planner",
            reason: error.to_string(),
        });
    }
    match fetch_experience_range(&reads, heads_request, &context.state_fence).await {
        Ok(heads_response) => {
            for receipt in commit
                .bank_receipts
                .iter()
                .chain(commit.feedback_receipts.iter())
            {
                for delta in &receipt.revision_before_after {
                    let live = heads_response
                        .revision_heads
                        .iter()
                        .find(|head| head.key == delta.key)
                        .map(|head| head.revision)
                        .unwrap_or(0);
                    if live < delta.after {
                        return ExperienceAuditOutcome::Failed(
                            ExecutionChainError::SupplierReadRejected {
                                owner: "revision currency readback",
                                reason: "live revision head is below a committed after-revision".to_owned(),
                            },
                        );
                    }
                }
            }
            tracing::debug!(
                live_heads = heads_response.revision_heads.len(),
                "experience audit corroborated commit durability against live heads",
            );
        }
        Err(error) => {
            tracing::debug!(
                reason = %error.to_string(),
                "experience audit could not verify revision currency; durability rests on committed receipts, view refresh stays delegated",
            );
        }
    }
    tracing::info!(
        assessment = %crate::diagnostics::sanitize_identity(
            output.candidate.assessment_id.as_str()
        ),
        candidate_digest = %output.candidate.digest,
        journal_present = output.journal_view.is_some(),
        bank_withheld = output.bank_withheld.len(),
        feedback_withheld = output.feedback_withheld.len(),
        bank_records = bank_records.len(),
        feedback_records = feedback_records.len(),
        bank_committed = commit.bank_receipts.len(),
        feedback_committed = commit.feedback_receipts.len(),
        "experience audit completed with reviewed candidate and committed records",
    );
    ExperienceAuditOutcome::Completed
}
