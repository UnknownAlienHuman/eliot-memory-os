//! O1-owned experience audit scheduling: live fence currency plus the exact
//! missing audit inputs, evaluated per activation completion (issue #223,
//! B-terminal lane).
//!
//! Division (root-serialized, B-consumer lane owns the producer side): the
//! B consumer owns `experience_runtime` plus actual quality invocation
//! (`produce_self_quality`, validated views, `run_experience_quality_event`
//! at approved work/223-integration-candidate @22f57172 — branch-only,
//! never imported here); O1 owns this scheduling entrypoint. This module
//! therefore evaluates only what O1 owns with live types: the audit
//! request context it can genuinely bind (live fence agreement, live
//! session when the handshake holds one, validated metadata), then the
//! exact missing-input inventory. It builds no event, synthesizes no
//! scope, subject, records, schedule, receipts, or handles, duplicates no
//! B-owned type, holds no supplier state, and invents no Session or
//! authority. When B's entry is authorized for import, the arm below grows
//! the real call; until then every evaluation reports
//! [`Pending`](ExperienceAuditOutcome::Pending) with exact owners — never
//! fabricated, never defaulted into delivery.
//!
//! Proposed registration hunk (exact shape, NOT applied — B module absent
//! in-candidate, import unauthorized):
//!
//! ```text
//! use eliotd::experience_runtime::run_experience_quality_event; // B-owned
//! match run_experience_quality_event(composition, kernel, &ctx, &event).await {
//!     Ok(output) => project candidate + validated views + gap postures,
//!     Err(error) => record with identities preserved, loop never fails,
//! }
//! ```
//!
//! with `ctx`: `RequestMetadata` bound to the live fence (session/task from
//! live activation bindings, product/source `SERVICE_NAME`, validated);
//! `event`: `ExperienceQualityEvent` assembled from owner-issued inputs
//! only (assessment identity minted per run as caller correlation;
//! scopes, subjects, records, schedule, holds, receipts, and handles from
//! their owners, never synthesized). Failures record with identities
//! preserved and never fail the activation loop that hosts this
//! evaluation.

use eliot_contracts::{
    ClockReading, ProductId, RequestId, RequestMetadata, SourceId, fences_match_exact,
};

use crate::attempt_execution_chain::{
    ExecutionChainError, MissingOwner, supply_governor_fence, supply_live_kernel_fence,
    supply_owner_session,
};
use crate::{DaemonComposition, DaemonKernelClient};

/// Outcome of one experience audit scheduling evaluation: pended with the
/// exact missing inputs, or failed on live fence disagreement with the
/// fence preserved. Debug-only: the `Failed` payload carries owner errors
/// without clone/equality semantics. No `Ready` variant exists yet: nothing
/// can deliver until the B-consumer entry and its inputs land.
#[derive(Debug)]
pub enum ExperienceAuditOutcome {
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
/// exact error instead of evaluating against stale bindings), then reports
/// every audit input missing with its exact owner: nothing on this path
/// exists live in-candidate, and this evaluation fabricates none of it.
/// Deterministic and side-effect free except for the live owner reads;
/// mutates nothing.
pub fn evaluate_experience_audit(
    kernel: &DaemonKernelClient,
    composition: &DaemonComposition,
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
            artifact: "run_experience_quality_event invocation",
            absent_read: "B-consumer entry not reconciled in-candidate (approved work/223-integration-candidate @22f57172, single terminal seam); import not authorized, trigger application stays O1",
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
    ExperienceAuditOutcome::Pending { missing }
}
