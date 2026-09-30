//! O1 daemon ingress for the admitted authority grant-revocation saga
//! (issue #686).
//!
//! Architecture traceability: A00-03 makes "restoration of revoked influence
//! after recovery" a fail-closed boundary; A12-03 keeps the canonical second
//! phase on the one governed write path; I5.27 defines idempotency over
//! canonical bytes; I1.8 keeps the daemon/Kernel call path behind the
//! authenticated transport.
//!
//! # What this module is
//!
//! One production pass that reads, over the authenticated front door, the
//! durable closure receipts the Kernel's P-07 owner committed, and reports
//! exactly which of them are still missing their canonical second phase. It
//! is driven from the daemon's polled owner-feed pass
//! (`daemon_runtime::run_owner_feed_sync`) and it never gates readiness and
//! never fails the daemon.
//!
//! Every value it reports is the owner's own committed bytes, served verbatim
//! by `eliot_kernel_service::serve_grant_closure_receipt` and re-decoded under
//! the closure receipt's own contract. Nothing here is derived from the graph
//! under audit, no digest is recomputed, and no identity is minted.
//!
//! # What this module deliberately does NOT do, and why
//!
//! It does not drive
//! [`eliot_governor::GovernorComposition::apply_admitted_authority_revocation`].
//! Two independent, measured facts block that, and both are properties of the
//! shipped tree rather than of this composition root:
//!
//! 1. **No admitted revocation decision exists in `eliotd`.** A
//!    [`eliot_authority::GrantRevocationRequest`] needs a target grant, its
//!    snapshot, and its `AuthorityBinding`. The daemon holds none of them as a
//!    decision: `git grep -nw GrantRevocationRequest -- bins/eliotd` resolves
//!    to `kernel_authority_client.rs:170` (the `P07AuthorityPort::revoke_grant`
//!    method that *receives* one) and `kernel_authority_client.rs:795` (inside
//!    `mod tests`). `KernelAuthorityClient::revoke_grant` is itself callerless
//!    in this crate, so the daemon never asks the Kernel to revoke anything.
//!    The owner feed does not help: it RESTORES the graph from already-applied
//!    history, so every grant the durable evidence has revoked is already
//!    `GrantStatus::Revoked` in the recovered snapshot and there is nothing
//!    live left to revoke.
//! 2. **The one thing the daemon CAN derive is unreachable through that
//!    method.** A committed first phase whose second phase never completed is
//!    exactly the case `apply_admitted_authority_revocation` exists to resume,
//!    but that method re-strikes the Kernel-first `revoke_grant`, and the
//!    Kernel correctly refuses it: `admitted_grant_hydrations` retains out
//!    every `non_admissible` grant
//!    (`crates/kernel/eliot-kernel-core/src/governor_closure_source.rs`), and
//!    `admit_p07_target_against_current_grant_graph` answers `NotAdmitted` for
//!    any target outside that set
//!    (`bins/eliot-kernel/src/daemon_request_dispatch.rs`). The second-phase
//!    resume the pass below reports therefore needs a public second-phase-only
//!    entry in `eliot-governor`, which does not exist:
//!    `GovernorComposition::reconcile_canonical_revocation` and
//!    `GovernorComposition::link_closure_second_phase` are both private.
//!
//! The exact missing owner is named in
//! [`AUTHORITY_REVOCATION_RESUME_BLOCKED`]: the authenticated Human/Policy
//! maintenance-request ingress that `maintenance_trigger_evaluator.rs` already
//! holds fail-closed at `explicit_request = false` (issue #1692), and whose
//! `GRANT_DISCLOSURE_CLOSURE` family is already registered with the effect
//! "grant closure publication and disclosure revocation" in
//! `maintenance_family_catalog.rs`. That owner must admit the revocation
//! decision naming the target grant, its snapshot and its `AuthorityBinding`;
//! only then can a daemon pass build a `GrantRevocationRequest` that is not a
//! fabrication.
//!
//! Forbidden boundary: no ORS access (the Kernel owns ORS in its own
//! process), no second grant graph, no fabricated request, identity or
//! receipt, no epoch invention, and no refusal read as an empty result. A
//! refusal from the closure-receipt read is a typed failure of this pass, never
//! "this grant needs no closure".

use std::sync::Arc;

use eliot_authority::GrantStatus;
use eliot_contracts::StateFence;
use eliot_governor::CompositionError;
use eliot_receipts::{GrantClosureReceipt, GrantClosureState};
use eliot_store_api::REVOCATION_HISTORY_MAX_RECORDS;

use super::daemon_kernel_client::DaemonKernelClient;
use super::DaemonComposition;

/// Daemon->Kernel front-door read of one committed closure receipt.
const GRANT_CLOSURE_RECEIPT_OPERATION: &str = "grant_closure_receipt";
/// Typed receipt kind answered by the closure-receipt read arm.
const GRANT_CLOSURE_RECEIPT_KIND: &str = "grant_closure_receipt";
/// Typed refusal kind answered by the same arm. A refusal is never read as
/// "no committed closure": the durable reason is surfaced and the pass fails
/// closed.
const GRANT_CLOSURE_RECEIPT_REFUSAL_KIND: &str = "grant_closure_receipt_refused";
/// Wire reason `StoreError::ReceiptNotFound` renders to. It is the ONLY
/// tolerated refusal, and it means exactly what it says: the Kernel's P-07
/// owner holds no committed closure for that target, so no first phase ran.
/// The same literal and the same `StoreError` variant are already bound in
/// `owner_feed.rs` (`RECEIPT_NOT_FOUND_REASON`).
const RECEIPT_NOT_FOUND_REASON: &str = "receipt not found";

/// The exact owner and entry that must exist before any daemon pass can drive
/// the canonical second phase of a grant revocation, reported on every pending
/// record this pass finds.
///
/// Naming it here rather than leaving the pass silent is the point: a pending
/// canonical second phase is real, actionable, durable state, and today
/// nothing in the shipped daemon can finish it. Reporting it without naming
/// the blocker would present an unfinished obligation as a handled one.
pub const AUTHORITY_REVOCATION_RESUME_BLOCKED: &str =
    "no admitted owner drives the canonical second phase: the authenticated \
     Human/Policy maintenance-request ingress held at explicit_request=false \
     in bins/eliotd/src/maintenance_trigger_evaluator.rs (#1692) must admit the \
     revocation decision naming the target grant, its snapshot and its \
     AuthorityBinding; eliot-governor must additionally expose a public \
     second-phase-only resume, because \
     GovernorComposition::apply_admitted_authority_revocation re-strikes the \
     Kernel-first revoke_grant that the Kernel refuses with NotAdmitted for a \
     grant its own owner already fences, and its \
     reconcile_canonical_revocation/link_closure_second_phase helpers are \
     private";

/// One grant the recovered owner graph names, captured before the composition
/// lock is released.
///
/// The status is carried verbatim from the restored
/// [`eliot_authority::GrantRecoveryRecord`]; nothing here decides that a grant
/// needs revoking. It is the candidate set a revocation decision would be
/// drawn from once an owner admits one.
#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorityRevocationCandidate {
    /// Exact recovered grant identity.
    grant_id: String,
    /// Exact recovered lifecycle status of that grant.
    status: GrantStatus,
}

/// Owned inputs captured while the daemon composition lock is held briefly.
///
/// The State Fence, the graph revision and the candidate set stay bound
/// together after the lock is released; no borrowed composition state crosses
/// into transport I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRevocationIngressPlan {
    state_fence: StateFence,
    revision: u64,
    candidates: Vec<AuthorityRevocationCandidate>,
}

impl AuthorityRevocationIngressPlan {
    /// Returns the exact grant-graph revision this plan was captured at.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// One committed first-phase closure whose canonical second phase has not been
/// linked yet.
///
/// Every field is the owner's own committed value served by the Kernel. The
/// `resume_blocked` marker is this module's honest statement that the durable
/// obligation is real and currently undrivable, not that it was discharged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingCanonicalSecondPhase {
    /// Target grant the committed closure fenced.
    pub grant_id: String,
    /// Immutable first-phase closure operation identity, as committed.
    pub closure_operation_id: String,
    /// Kernel-issued authority revocation receipt the closure recorded.
    pub authority_receipt_id: String,
    /// Governor snapshot the closure committed under.
    pub snapshot_id: String,
    /// Lifecycle status this daemon's own recovered graph carries for the
    /// target. Reported beside the committed closure because the two are
    /// independent: a target the recovered graph still reads `Active` or
    /// `PendingActivation` while its Kernel/ORS closure is already `Revoked`
    /// is the sharpest form of the reconciliation gap, and one that reads
    /// `Revoked` shows the fence propagated into this projection while the
    /// canonical second phase still did not.
    pub recovered_status: GrantStatus,
    /// Why this pass cannot finish the second phase. Always
    /// [`AUTHORITY_REVOCATION_RESUME_BLOCKED`].
    pub resume_blocked: &'static str,
}

/// What one ingress pass proved about the durable closure state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRevocationIngressReport {
    revision: u64,
    candidates_examined: usize,
    committed_closures: usize,
    pending_second_phase: Vec<PendingCanonicalSecondPhase>,
}

impl AuthorityRevocationIngressReport {
    /// Returns the grant-graph revision the pass was bound to.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns how many recovered grants were read for a committed closure.
    #[must_use]
    pub const fn candidates_examined(&self) -> usize {
        self.candidates_examined
    }

    /// Returns how many of those hold a committed first-phase closure.
    #[must_use]
    pub const fn committed_closures(&self) -> usize {
        self.committed_closures
    }

    /// Returns the committed closures still missing their canonical second
    /// phase, in the candidate order they were read.
    #[must_use]
    pub fn pending_second_phase(&self) -> &[PendingCanonicalSecondPhase] {
        &self.pending_second_phase
    }
}

/// Captures the exact admitted authority state one ingress pass reads from.
///
/// This function is synchronous and performs no Kernel transport calls. The
/// daemon calls it under the composition mutex and releases that mutex before
/// awaiting [`scan_authority_revocation_ingress`].
///
/// A zero graph revision is a typed owner error, including when there are no
/// candidates. A candidate set larger than the catalogue history bound is a
/// typed recovery error rather than a silent truncation: a bounded read that
/// dropped grants would report an incomplete pending set as a complete one.
pub fn capture_authority_revocation_ingress_plan(
    composition: &DaemonComposition,
) -> Result<AuthorityRevocationIngressPlan, CompositionError> {
    let snapshot = composition.governor.owners().authority.snapshot()?;
    let revision = snapshot.grant_graph.revision;
    if revision == 0 {
        return Err(CompositionError::Owner(
            "authority revocation ingress live graph revision is zero".to_owned(),
        ));
    }
    let state_fence = composition.governor.kernel_snapshot().state_fence();
    if snapshot.state_fence != state_fence {
        return Err(CompositionError::Recovery(
            "authority revocation ingress owner snapshot is not bound to the composition Kernel generation"
                .to_owned(),
        ));
    }
    if snapshot.grant_graph.grants.len() > REVOCATION_HISTORY_MAX_RECORDS as usize {
        return Err(CompositionError::Recovery(format!(
            "authority revocation ingress recovered {} grants, above the {REVOCATION_HISTORY_MAX_RECORDS} bound of one pass",
            snapshot.grant_graph.grants.len()
        )));
    }
    let candidates = snapshot
        .grant_graph
        .grants
        .iter()
        .map(|record| AuthorityRevocationCandidate {
            grant_id: record.grant_id.clone(),
            status: record.status,
        })
        .collect();
    Ok(AuthorityRevocationIngressPlan {
        state_fence,
        revision,
        candidates,
    })
}

/// Runs one authority-revocation ingress pass over the authenticated Kernel
/// transport and reports the durable second phases that are still pending.
///
/// The pass is a pure read of owner-committed state. It never strikes a fence,
/// never commits a canonical envelope, never links a second phase, and never
/// presents a revocation request: this daemon holds no admitted revocation
/// decision (see the module documentation and
/// [`AUTHORITY_REVOCATION_RESUME_BLOCKED`]). What it does do is make the
/// unfinished canonical obligation visible and bounded instead of leaving it
/// implied by an absence.
///
/// Refusals fail the pass closed and are never degraded to an empty report: a
/// refusal other than `receipt not found` means the durable state could not be
/// established, and an absent closure is reported as "no first phase ran",
/// which is a fact about the owner, not an empty success.
///
/// A plan captured under a superseded Kernel generation refuses before any
/// transport is touched, so a stale read can never be reported as current.
pub async fn scan_authority_revocation_ingress(
    plan: AuthorityRevocationIngressPlan,
    kernel: &Arc<DaemonKernelClient>,
) -> Result<AuthorityRevocationIngressReport, CompositionError> {
    if kernel.snapshot().state_fence() != plan.state_fence {
        return Err(CompositionError::Recovery(
            "authority revocation ingress plan is bound to a different Kernel generation State Fence"
                .to_owned(),
        ));
    }
    let mut committed_closures = 0usize;
    let mut pending_second_phase = Vec::new();
    for candidate in &plan.candidates {
        let Some(closure) = read_committed_closure(kernel, &plan.state_fence, &candidate.grant_id)
            .await?
        else {
            // The Kernel's own owner holds no committed closure for this
            // target: no first phase ever ran against it. That is a fact
            // about the owner, not an empty result and not a failure.
            continue;
        };
        committed_closures += 1;
        if closure.state == GrantClosureState::Revoked && closure.canonical_receipt.is_none() {
            pending_second_phase.push(PendingCanonicalSecondPhase {
                grant_id: closure.declaration.target_grant_id,
                closure_operation_id: closure.operation_id,
                authority_receipt_id: closure.authority_receipt.receipt_id,
                snapshot_id: closure.authority_receipt.snapshot_id,
                recovered_status: candidate.status,
                resume_blocked: AUTHORITY_REVOCATION_RESUME_BLOCKED,
            });
        }
    }
    Ok(AuthorityRevocationIngressReport {
        revision: plan.revision,
        candidates_examined: plan.candidates.len(),
        committed_closures,
        pending_second_phase,
    })
}

/// Reads one committed closure receipt verbatim from the Kernel's retained
/// P-07 owner, or reports that the owner holds none for this target.
///
/// `Ok(None)` is exactly `StoreError::ReceiptNotFound` at the Kernel: no
/// committed closure exists. Every other outcome, including any other durable
/// refusal, a transport failure, an unexpected response kind, and a closure
/// that does not name the presented target or fence, is a typed failure of the
/// pass.
async fn read_committed_closure(
    kernel: &Arc<DaemonKernelClient>,
    state_fence: &StateFence,
    target_grant_id: &str,
) -> Result<Option<GrantClosureReceipt>, CompositionError> {
    let value = kernel
        .transact_async(
            GRANT_CLOSURE_RECEIPT_OPERATION,
            serde_json::json!({
                "state_fence": state_fence,
                "target_grant_id": target_grant_id,
            }),
        )
        .await
        .map_err(|error| {
            CompositionError::Recovery(format!(
                "grant closure receipt read transport for {target_grant_id}: {error}"
            ))
        })?;
    let object = value.as_object().ok_or_else(|| {
        CompositionError::Owner(
            "grant closure receipt read is not a typed object".to_owned(),
        )
    })?;
    let payload = match object.get("kind").and_then(serde_json::Value::as_str) {
        Some(GRANT_CLOSURE_RECEIPT_KIND) => object.get("value").cloned().ok_or_else(|| {
            CompositionError::Owner(
                "grant closure receipt read is missing its payload".to_owned(),
            )
        })?,
        Some(GRANT_CLOSURE_RECEIPT_REFUSAL_KIND) => {
            let reason = object
                .get("value")
                .and_then(|value| value.get("reason"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unspecified durable refusal");
            if reason == RECEIPT_NOT_FOUND_REASON {
                return Ok(None);
            }
            return Err(CompositionError::Recovery(format!(
                "Kernel refused the committed closure read for {target_grant_id}: {reason}"
            )));
        }
        other => {
            return Err(CompositionError::Owner(format!(
                "grant closure receipt read returned an unexpected kind: {other:?}"
            )));
        }
    };
    let closure: GrantClosureReceipt = serde_json::from_value(payload).map_err(|error| {
        CompositionError::Owner(format!(
            "grant closure receipt for {target_grant_id} does not decode: {error}"
        ))
    })?;
    // The ORIGINAL recorded value revalidates under its own receipt contract.
    // Nothing is recomputed here, so a served closure that fails its own
    // contract is a contract failure rather than a fact to be reported.
    closure.validate().map_err(|error| {
        CompositionError::Owner(format!(
            "committed closure for {target_grant_id} fails its own receipt contract: {error}"
        ))
    })?;
    // Re-prove the served bytes against what this pass presented. The Kernel
    // checks the same two facts, but the report is this daemon's own artifact
    // and may not rest on the far side's word for it.
    if closure.declaration.target_grant_id != target_grant_id {
        return Err(CompositionError::Recovery(format!(
            "committed closure for {target_grant_id} names a different target"
        )));
    }
    if closure.authority.state_fence != *state_fence {
        return Err(CompositionError::Recovery(format!(
            "committed closure for {target_grant_id} is bound to a different State Fence"
        )));
    }
    Ok(Some(closure))
}
