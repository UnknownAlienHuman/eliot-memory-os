//! O1-owned experience audit scheduling: live fence currency plus the exact
//! missing audit inputs, evaluated per activation completion (issue #223,
//! B-terminal lane).
//!
//! Division: `experience_runtime` is the in-candidate B-owned thin driver
//! over the real owner modules (range planning, range consume,
//! retention-gated shaping, assess plus recheck); O1 owns this scheduling
//! entrypoint plus its trigger application. This module
//! therefore evaluates only what O1 owns with live types: the audit
//! request context it can genuinely bind (live fence agreement, live
//! session when the handshake holds one, validated metadata), then the
//! exact missing-input inventory. It builds no event, synthesizes no
//! scope, subject, records, schedule, receipts, or handles, duplicates no
//! owner type, holds no supplier state, and invents no Session or
//! authority. Without a supplied bundle every evaluation reports
//! [`Pending`](ExperienceAuditOutcome::Pending) with exact owners — never
//! fabricated, never defaulted into delivery.
//!
//! Proposed registration hunk (exact shape, applied): the arm below passes
//! an explicit admitted bundle (None until the onboarding/transport
//! suppliers deliver one) into the evaluated call
//! `eliotd::experience_runtime::run_experience_quality_event(composition,
//! kernel, &ctx, &event)`, with `ctx` from [`audit_request_context`] and
//! the event assembled from owner-issued inputs only. Failures record with
//! identities preserved and never fail the activation loop that hosts this
//! evaluation.

use std::sync::Arc;

use eliot_contracts::{
    ClockReading, ProductId, RequestId, RequestMetadata, SourceId, fences_match_exact,
};

use crate::attempt_execution_chain::{
    ExecutionChainError, MissingOwner, supply_governor_fence, supply_live_kernel_fence,
    supply_owner_session,
};
use crate::experience_runtime::{ExperienceQualityEvent, run_experience_quality_event};
use crate::{DaemonComposition, DaemonKernelClient};

/// Outcome of one experience audit scheduling evaluation: completed with a
/// reviewed candidate, pended with the exact missing inputs, or failed on
/// live fence disagreement with the fence preserved. Debug-only: the
/// `Failed` payload carries owner errors without clone/equality semantics.
#[derive(Debug)]
pub enum ExperienceAuditOutcome {
    /// The admitted event ran to a reviewed candidate with validated views
    /// and gap postures, projected observably below.
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
/// context. Task stays unbound: task binding requires TaskSelectionEvidence
/// (I5.5) and is never inferred here. This supplier is consumed by the
/// evaluation below and will bind the B-consumer call once its entry is
/// authorized for import.
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

/// Evaluate one experience audit scheduling step over live owners.
///
/// Binds the audit request context first (fence currency, session when
/// held, validated metadata — a corrupt context fails closed with its
/// exact error instead of evaluating against stale bindings), then either
/// runs an explicitly supplied admitted event bundle through the B-consumer
/// entry or reports every audit input missing with its exact owner.
/// Nothing on the admitted-event path exists live in-candidate, and this
/// evaluation fabricates none of it: an absent bundle idles as pending,
/// never a defaulted delivery. Deterministic and side-effect free except
/// for the live owner reads plus, on a supplied bundle, the B entry's own
/// bridge reads; mutates nothing.
pub async fn evaluate_experience_audit(
    kernel: &Arc<DaemonKernelClient>,
    composition: &DaemonComposition,
    event: Option<&ExperienceQualityEvent<'_>>,
) -> ExperienceAuditOutcome {
    let _span = tracing::info_span!("eliotd.experience_audit_poll").entered();
    let context = match audit_request_context(kernel, composition) {
        Ok(context) => context,
        Err(error) => return ExperienceAuditOutcome::Failed(error),
    };
    let missing = vec![
        MissingOwner {
            owner: "position read scope binder",
            artifact: "ScopeId position scope",
            absent_read: "no position scope bound; GetCurrentEpistemicPosition takes an explicit scope_id, never defaulted (the audit range leg itself is scope-free; scope filtering stays consumer-owned)",
        },
        MissingOwner {
            owner: "position subject owner",
            artifact: "position subject text",
            absent_read: "no admitted position subject; free text never becomes a read selector",
        },
        MissingOwner {
            owner: "journal presence binder",
            artifact: "live journal presence",
            absent_read: "no live journal presence binding for the audit leg",
        },
        MissingOwner {
            owner: "bank durable supply",
            artifact: "durable range payload plus read context",
            absent_read: "no verbatim bank range payload (records array); bank durable supply stays canonical-owner side, consumed via bank_records_from_range_payload plus supply_bank_projection_from_store when it lands — no fake refs or receipts",
        },
        MissingOwner {
            owner: "feedback durable supply",
            artifact: "durable range payload plus read context",
            absent_read: "no verbatim feedback range payload; feedback durable supply stays canonical-owner side, consumed via feedback_records_from_range_payload plus supply_feedback_projection_from_store when it lands — no fake refs or receipts",
        },
        MissingOwner {
            owner: "retention schedule owner",
            artifact: "RetentionSchedule plus holds",
            absent_read: "no owner-issued retention schedule retained for this run",
        },
        MissingOwner {
            owner: "per-attempt receipts",
            artifact: "HarnessActivationReceiptCandidate set",
            absent_read: "no per-attempt receipt candidates; harness receipt owner absent in-tree",
        },
        MissingOwner {
            owner: "obligation handles",
            artifact: "edge obligation and attested handles",
            absent_read: "no edge-supplied obligation or attested handles",
        },
        MissingOwner {
            owner: "B-consumer entry",
            artifact: "ExperienceQualityEvent bundle",
            absent_read: "no admitted event bundle assembled; the run_experience_quality_event entry is live in-candidate and the trigger passes an explicit bundle (None today), never a defaulted one",
        },
        MissingOwner {
            owner: "store audit handler",
            artifact: "GetAuditRange registration",
            absent_read: "store side has not registered the GetAuditRange handler (scope-free, no parameters per catalogue row 867b962e); the journal leg fails closed UnknownOperation per B design (#19 join)",
        },
    ];
    tracing::debug!(
        missing_owners = missing.len(),
        fence_generation = context.state_fence.resource_generation.value(),
        "experience audit pended: audit inputs absent"
    );
    let Some(event) = event else {
        return ExperienceAuditOutcome::Pending { missing };
    };
    // Admitted bundle path: the B-consumer entry runs the full connected
    // runtime (TRUE position read, optional journal leg, range-payload
    // consume with digest re-proof, retention-gated shaping, assess plus
    // recheck) and returns the frozen candidate with validated views and
    // gap postures. Anything drifted, malformed, withheld-but-uncited, or
    // missing fails closed inside the entry; nothing partial emits as
    // complete and nothing persists. The output projects observably with
    // bounded identities; failures record with identities preserved and
    // never fail the activation loop.
    match run_experience_quality_event(composition, kernel, &context, event).await {
        Ok(output) => {
            tracing::info!(
                assessment = %crate::diagnostics::sanitize_identity(
                    output.candidate.assessment_id.as_str()
                ),
                candidate_digest = %output.candidate.digest,
                journal_present = output.journal_view.is_some(),
                bank_withheld = output.bank_withheld.len(),
                feedback_withheld = output.feedback_withheld.len(),
                "experience audit completed with reviewed candidate",
            );
            ExperienceAuditOutcome::Completed
        }
        Err(error) => {
            ExperienceAuditOutcome::Failed(ExecutionChainError::SupplierReadRejected {
                owner: "experience driver",
                reason: error.to_string(),
            })
        }
    }
}
