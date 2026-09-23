//! O1-owned experience audit trigger: staged assembly of one admitted
//! terminal event over live owners, evaluated per activation completion
//! (issue #223, B-terminal lane).
//!
//! Division: `experience_runtime` is the in-candidate B-owned driver over
//! the real owner modules (range planning, range consume, retention-gated
//! shaping, assess plus recheck, admitted commit chain); O1 owns this
//! scheduling entrypoint plus its trigger application. This module resolves
//! every event input from live reads in a fixed stage order — audit ctx,
//! bridge client, admitted scope binding, scope-bound range reads, owner
//! decode, then the completeness gate — and either fires both terminal
//! entries or reports the exact missing inputs. It synthesizes no scope,
//! subject, records, schedule, receipts, handles, or identities beyond
//! caller-correlation ids the entry contract assigns to the caller
//! (`assessment_id`, envelope `projection_id`), duplicates no owner type,
//! holds no supplier state, and invents no Session or authority. A stage
//! without a live supplier idles as
//! [`Pending`](ExperienceAuditOutcome::Pending) with its exact owner —
//! never fabricated, never defaulted into delivery. Failures record with
//! identities preserved and never fail the activation loop that hosts this
//! evaluation.
//!
//! Stage notes: bank/feedback range reads are scope-addressed
//! (`requires_scope_id`), so no range I/O runs before an admitted scope
//! binds; revision-head expectations map 1:1 from live response heads
//! (zero revisions filtered — the owner validator rejects them) and
//! ordering expectations stay empty until an ordering-head supplier
//! exists (the commit checklist permits empty vectors, never fabricated
//! ones); decoded record slices are the SAME values the read entry
//! consumes and the commit entry re-commits (single decode, shared
//! slices); the commit entry additionally needs M1's `&mut`-to-`&self`
//! narrowing before an `Arc`-held composition can invoke it (CONTROL
//! handoff — the read entry already takes `&self` and fires first).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    ArtifactId, ClockReading, ProductId, RequestId, RequestMetadata, SourceId, fences_match_exact,
};
use eliot_observation::bank_admission::{
    bank_records_from_range_payload, feedback_records_from_range_payload,
};
use eliot_observation_contracts::{
    AgentFeedbackRecord, ExperienceBankRecord, ObservationScope,
};
use eliot_receipts::WorkScopeId;
use eliot_store_api::{
    CanonicalReadClient, EXPERIENCE_PARAM_MAX_RECORDS, MAX_EXPERIENCE_PAGE_RECORDS,
    NamedReadOperation, NamedReadRequest, NamedReadResponse, ReadConsistency, RevisionHeadExpectation,
    ScopeId,
};

use crate::attempt_execution_chain::{
    ExecutionChainError, MissingOwner, supply_governor_fence, supply_live_kernel_fence,
    supply_owner_session,
};
use crate::experience_runtime::{
    ExperienceBankEventInputs, ExperienceFeedbackEventInputs, ExperienceQualityEvent,
    run_experience_quality_event,
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
/// context. The request id is caller correlation for this evaluation, not
/// authority: fence agreement plus the live session carry admission, and
/// commit idempotency comes from owner-derived record keys downstream.
/// Task stays unbound: task binding requires TaskSelectionEvidence
/// (I5.5) and is never inferred here.
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
/// match the request, the response fence must equal the live agreed
/// fence exactly, and the response must validate (heads unique and
/// well-formed). Any disagreement fails closed with its exact owner
/// detail — a moved fence or a foreign payload never becomes records.
async fn fetch_experience_range<R: CanonicalReadClient + ?Sized>(
    reads: &R,
    request: &NamedReadRequest,
    fence: &eliot_contracts::StateFence,
) -> Result<NamedReadResponse, ExecutionChainError> {
    let refused = |owner: &'static str, reason: String| ExecutionChainError::SupplierReadRejected {
        owner,
        reason,
    };
    let response = reads
        .execute_named(request.clone())
        .await
        .map_err(|error| refused("experience range bridge", error.to_string()))?;
    if response.operation != request.operation {
        return refused(
            "experience range readback",
            "bridge response operation does not echo the requested read".to_owned(),
        );
    }
    if response.state_fence != *fence {
        return refused(
            "experience range readback",
            "bridge response fence differs from the agreed live fence".to_owned(),
        );
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
/// (the scope-addressed range legs cannot run before one binds);
/// scope-identity derivation; scope-bound bank/feedback range fetch with
/// readback verification; owner decode into the shared record slices;
/// live revision-head expectations; then the completeness gate over the
/// fields with no live supplier yet (position subject, retention
/// schedule, per-attempt receipts, bank/feedback source identities and
/// read context). A complete event fires the read entry and projects the
/// reviewed candidate observably; anything missing idles as pending with
/// exact owners. Deterministic and side-effect free except for the live
/// owner/bridge reads plus, on a complete event, the read entry's own
/// bridge reads; mutates nothing. The commit entry fires from the same
/// gate once M1 narrows its `&mut` borrow (CONTROL handoff): an
/// `Arc`-held composition cannot lend `&mut`, and the underlying
/// canonical commit is already `&self` (only the refresh/stale mark
/// needs exclusivity).
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
    // Fields with no live supplier in-tree. Each names its exact absent
    // owner; none is defaulted, minted as authority, or inferred.
    let mut missing_scope = binding.is_none();
    let mut missing_subject = true;
    let mut missing_schedule = true;
    let mut missing_receipts = true;
    let mut missing_sources = true;
    let mut missing_read_context = true;
    if binding.is_none() {
        missing.push(MissingOwner {
            owner: "scope binder",
            artifact: "admitted WorkScope binding at the live fence",
            absent_read: "no WorkScope binding retained for the agreed fence; scope-addressed range legs (bank, feedback, position, journal) cannot name a scope",
        });
    }
    missing.push(MissingOwner {
        owner: "position subject owner",
        artifact: "position subject text",
        absent_read: "no admitted position subject; free text never becomes a read selector",
    });
    missing.push(MissingOwner {
        owner: "retention schedule owner",
        artifact: "RetentionSchedule plus holds",
        absent_read: "no owner-issued retention schedule retained for this run",
    });
    missing.push(MissingOwner {
        owner: "per-attempt receipts",
        artifact: "HarnessActivationReceiptCandidate set",
        absent_read: "no per-attempt receipt candidates; the read entry requires at least one edge-supplied receipt and the harness receipt owner is absent in-tree",
    });
    missing.push(MissingOwner {
        owner: "bank/feedback source identities",
        artifact: "Governor bank/feedback source identities",
        absent_read: "no owner-issued source identity for either family; the edge passes the Governor source identity and none is retained",
    });
    missing.push(MissingOwner {
        owner: "bank/feedback read context",
        artifact: "durable-read revision marker, coverage, omissions",
        absent_read: "no owner-issued read context beyond response heads; markers are derived only with live range reads under an admitted scope",
    });
    // Completeness gate: every field above must resolve live before any
    // range I/O runs or any entry fires. The gate is a runtime condition
    // over live state, not a static branch: when suppliers land, the
    // stages below activate with no code change.
    let complete = !missing_scope
        && !missing_subject
        && !missing_schedule
        && !missing_receipts
        && !missing_sources
        && !missing_read_context;
    if !complete {
        tracing::debug!(
            missing_owners = missing.len(),
            fence_generation = context.state_fence.resource_generation.value(),
            "experience audit pended: audit inputs absent"
        );
        return ExperienceAuditOutcome::Pending { missing };
    }
    // Live stages below this point run only on a complete resolution.
    // Scope-identity derivation from the admitted binding.
    let snapshot = match binding {
        Some(snapshot) => snapshot,
        None => {
            return ExperienceAuditOutcome::Pending { missing };
        }
    };
    let scope_ref = snapshot.binding.scope.scope_ref.clone();
    let scope_id = match ScopeId::new(scope_ref.clone()) {
        Ok(scope_id) => scope_id,
        Err(error) => {
            return ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                owner: "scope binder",
                reason: error.to_string(),
            });
        }
    };
    let work_scope_id = match WorkScopeId::new(scope_ref.clone()) {
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
    let bank_response = match fetch_experience_range(&reads, &bank_request, &context.state_fence).await
    {
        Ok(response) => response,
        Err(error) => return ExperienceAuditOutcome::Failed(error),
    };
    let feedback_response = match fetch_experience_range(
        &reads,
        &feedback_request,
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
        Err(error) => return ExperienceAuditO
...[truncated 6154 chars]