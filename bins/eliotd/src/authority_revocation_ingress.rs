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
//! durable closure receipts the Kernel's P-07 owner committed, hands every
//! bounded still-pending second phase to the maintenance-request owner for
//! re-admission of the exact operation, drives every owner-admitted one
//! through the transport half the daemon can lawfully perform, and reports
//! exactly which of them are still missing their canonical second phase. It
//! is driven from the daemon's polled owner-feed pass
//! (`daemon_runtime::run_owner_feed_sync`) — which runs from startup, after
//! restore, on every tick — and it never gates readiness and
//! never fails the daemon.
//!
//! Restart contract (issue #2100 item 7): every owner-feed pass, including the
//! first pass after a restart, scans the whole bounded candidate denominator
//! and routes every pending closure through the owner re-admission path
//! before this pass reports. An over-bound denominator fails the pass closed
//! instead of truncating, and an owner-refused closure stays
//! pending/recovery-required — never complete — so no pass ever presents an
//! empty or settled result that effect admission could mistake for a finished
//! saga.
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
//! 1. **No fresh revocation decision exists in `eliotd`, and none is
//!    fabricated here.** A [`eliot_authority::GrantRevocationRequest`] needs a
//!    target grant, its snapshot, and its `AuthorityBinding`. The daemon holds
//!    none of them as a fresh decision, and #1692 still holds the
//!    maintenance-request ingress at `explicit_request = false` because no
//!    authenticated Human UI/CLI ingress exists. What the maintenance-request
//!    owner CAN do — and now does, through
//!    [`AdmittedMaintenanceRevocation::readmit_pending_closure`] — is re-admit
//!    the exact operation the owners already committed, rebuilt field for
//!    field from the Kernel owner's committed closure bytes plus the live
//!    admitted fence. Nothing is derived from the restored graph and nothing
//!    from a diagnostic row: a diagnostic tick alone stays non-authoritative.
//! 2. **The canonical envelope commit stays with the Governor resume entry.**
//!    The admitted handoff IS now driven for everything the daemon can prove
//!    over the transport ([`drive_pending_second_phases`]): the owner's
//!    committed bytes are re-read, bound to the admitted operation by content,
//!    and — when the owner serves a Store-issued canonical receipt for the
//!    admitted operation — linked idempotently through the Kernel-owned link
//!    with a content-compared read-back. But committing a FRESH canonical
//!    envelope needs the canonical operation/request identities plus the
//!    Governor graph transition and canonical writer: the public
//!    second-phase-only resume in `eliot-governor`, which does not exist:
//!    `GovernorComposition::reconcile_canonical_revocation` and
//!    `GovernorComposition::link_closure_second_phase` are both private, and
//!    `GovernorComposition::apply_admitted_authority_revocation` re-strikes
//!    the Kernel-first `revoke_grant` that the Kernel correctly refuses with
//!    `NotAdmitted` for a grant its own owner already fences (the target is
//!    retained out of `admitted_grant_hydrations` as `non_admissible` in
//!    `crates/kernel/eliot-kernel-core/src/governor_closure_source.rs`, and
//!    `admit_p07_target_against_current_grant_graph` answers `NotAdmitted`
//!    for any target outside that set in
//!    `bins/eliot-kernel/src/daemon_request_dispatch.rs`). A row with no
//!    observable receipt therefore stays pending; the drive mints no
//!    operation, request, or receipt identity, and presenting the admitted
//!    value to the fresh Kernel-first saga stays forbidden.
//!
//! The exact remaining gap is named in
//! [`AUTHORITY_REVOCATION_RESUME_BLOCKED`]: `eliot-governor` must expose the
//! public second-phase-only resume accepting the owner-admitted value. The
//! maintenance-request half of that contract — the owner that re-admits the
//! exact operation — now exists in
//! [`crate::maintenance_trigger_evaluator::AdmittedMaintenanceRevocation`],
//! and the daemon drive below tenders every admitted handoff it cannot finish
//! to that entry's contract; only the Governor canonical-commit half is still
//! missing.
//!
//! Forbidden boundary: no ORS access (the Kernel owns ORS in its own
//! process), no second grant graph, no fabricated request, identity or
//! receipt, no epoch invention, and no refusal read as an empty result. A
//! refusal from the closure-receipt read is a typed failure of this pass, never
//! "this grant needs no closure".

use std::sync::Arc;

use eliot_authority::GrantStatus;
use eliot_contracts::StateFence;
use eliot_governor::{
    CompositionError, GrantClosureSecondPhaseLink, KernelGenerationSnapshotProvider,
};
use eliot_receipts::{GrantClosureReceipt, GrantClosureState, ReceiptIdentity};
use eliot_store_api::REVOCATION_HISTORY_MAX_RECORDS;

use super::DaemonComposition;
use super::daemon_kernel_client::DaemonKernelClient;
use super::maintenance_trigger_evaluator::AdmittedMaintenanceRevocation;

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

/// The exact remaining gap before any daemon pass can drive the canonical
/// second phase of a grant revocation, reported on every pending record this
/// pass finds.
///
/// The authenticated Human/Policy maintenance-request owner now re-admits the
/// exact committed operation for each pending closure
/// ([`AdmittedMaintenanceRevocation`]), so the obligation is held by an owner
/// instead of merely diagnosed, and [`drive_pending_second_phases`] drives
/// every admitted obligation through the transport half the daemon can prove.
/// What is still missing is the Governor canonical-commit half:
/// `eliot-governor` must expose a public second-phase-only resume accepting
/// that admitted value.
///
/// Naming it here rather than leaving the pass silent is the point: a pending
/// canonical second phase is real, actionable, durable state. Reporting it
/// without naming the blocker would present an unfinished obligation as a
/// handled one.
pub const AUTHORITY_REVOCATION_RESUME_BLOCKED: &str = "no Governor entry drives the canonical second phase: eliot-governor \
     must expose a public second-phase-only resume accepting the owner-admitted \
     AdmittedMaintenanceRevocation, because \
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
/// `resume_blocked` marker is this module's honest statement of the remaining
/// Governor drive gap, not a claim that the obligation was discharged. The
/// `admission` field records what the maintenance-request owner did with the
/// obligation: only a [`PendingRevocationAdmission::Admitted`] row carries
/// owner authority; a refused row is a non-authoritative diagnostic of a still
/// pending obligation.
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
    /// canonical second phase still did not. Diagnostic only: it never
    /// enters the owner admission.
    pub recovered_status: GrantStatus,
    /// Why this pass cannot finish the second phase. Always
    /// [`AUTHORITY_REVOCATION_RESUME_BLOCKED`].
    pub resume_blocked: &'static str,
    /// What the maintenance-request owner did with this obligation.
    pub admission: PendingRevocationAdmission,
}

/// What the maintenance-request owner did with one pending second phase.
///
/// The pass hands every bounded pending closure to the owner; the owner
/// re-admits the exact operation or refuses it with a closed reason. Only
/// [`PendingRevocationAdmission::Admitted`] carries authority forward to the
/// Governor second-phase-only resume entry. A
/// [`PendingRevocationAdmission::Refused`] row stays
/// pending/recovery-required: it is a diagnostic tick, never an admission and
/// never a completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingRevocationAdmission {
    /// The owner re-admitted the exact committed operation. This is the
    /// authoritative handoff the Governor second-phase-only resume entry
    /// consumes. Boxed so the refused rows do not pay for an obligation they
    /// do not hold (`clippy::large_enum_variant`).
    Admitted(Box<AdmittedMaintenanceRevocation>),
    /// The owner refused to re-admit the committed bytes. The closure stays
    /// pending; the reason is fixed diagnostic text.
    Refused {
        /// Closed owner refusal reason. Fixed text, never authority.
        reason: &'static str,
    },
}

impl PendingRevocationAdmission {
    /// Returns true exactly when the owner re-admitted the operation.
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted(_))
    }

    /// Returns the admitted handoff, if the owner re-admitted this obligation.
    #[must_use]
    pub fn admitted(&self) -> Option<&AdmittedMaintenanceRevocation> {
        match self {
            Self::Admitted(admitted) => Some(admitted.as_ref()),
            Self::Refused { .. } => None,
        }
    }

    /// Returns the closed owner refusal reason, if the owner refused.
    #[must_use]
    pub const fn refusal_reason(&self) -> Option<&'static str> {
        match self {
            Self::Admitted(_) => None,
            Self::Refused { reason } => Some(*reason),
        }
    }
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

    /// Returns the owner-admitted resume handoffs tendered by this pass, in
    /// candidate order.
    ///
    /// These are the authoritative obligations: each one is an exact
    /// re-admitted operation the Governor second-phase-only resume entry
    /// consumes. Diagnostic-only rows (owner-refused) are excluded; they stay
    /// pending/recovery-required and are visible through
    /// [`Self::pending_second_phase`] instead.
    #[must_use]
    pub fn admitted_revocations(&self) -> Vec<&AdmittedMaintenanceRevocation> {
        self.pending_second_phase
            .iter()
            .filter_map(|row| row.admission.admitted())
            .collect()
    }

    /// Returns how many pending closures the owner refused to re-admit on
    /// this pass. Refused rows stay pending/recovery-required, never
    /// complete.
    #[must_use]
    pub fn refused_second_phase(&self) -> usize {
        self.pending_second_phase
            .iter()
            .filter(|row| !row.admission.is_admitted())
            .count()
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
/// transport, hands every bounded still-pending second phase to the
/// maintenance-request owner for re-admission, and reports the durable second
/// phases that are still pending.
///
/// The pass reads only owner-committed state. It never strikes a fence, never
/// commits a canonical envelope, never links a second phase, and never
/// presents a revocation request to a fresh saga: the one revocation value it
/// builds is the owner's own re-admission of the exact committed operation,
/// tendered for the Governor second-phase-only resume entry alone (see the
/// module documentation and [`AUTHORITY_REVOCATION_RESUME_BLOCKED`]). Driving
/// an admitted row to its linked proof is [`drive_pending_second_phases`],
/// on this scan's report — never this scan. A
/// diagnostic tick alone stays non-authoritative: only a
/// [`PendingRevocationAdmission::Admitted`] row carries authority forward,
/// and an owner-refused row stays pending/recovery-required.
///
/// Refusals fail the pass closed and are never degraded to an empty report: a
/// refusal other than `receipt not found` means the durable state could not be
/// established, and an absent closure is reported as "no first phase ran",
/// which is a fact about the owner, not an empty success. An over-bound
/// candidate denominator likewise fails the pass in
/// [`capture_authority_revocation_ingress_plan`] rather than scanning a
/// truncated set as if it were complete.
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
        let Some(closure) =
            read_committed_closure(kernel, &plan.state_fence, &candidate.grant_id).await?
        else {
            // The Kernel's own owner holds no committed closure for this
            // target: no first phase ever ran against it. That is a fact
            // about the owner, not an empty result and not a failure.
            continue;
        };
        committed_closures += 1;
        if closure.state == GrantClosureState::Revoked && closure.canonical_receipt.is_none() {
            // Hand the obligation to the maintenance-request owner: it
            // re-admits the exact committed operation from the Kernel owner's
            // bytes plus the live admitted fence this pass is bound to, or
            // refuses it with a closed reason. The recovered status beside it
            // stays diagnostic-only and never enters the admission.
            let admission =
                AdmittedMaintenanceRevocation::readmit_pending_closure(&plan.state_fence, &closure);
            let admission = match admission {
                Ok(admitted) => PendingRevocationAdmission::Admitted(Box::new(admitted)),
                Err(error) => PendingRevocationAdmission::Refused {
                    reason: error.refusal_reason(),
                },
            };
            pending_second_phase.push(PendingCanonicalSecondPhase {
                grant_id: closure.declaration.target_grant_id,
                closure_operation_id: closure.operation_id,
                authority_receipt_id: closure.authority_receipt.receipt_id,
                snapshot_id: closure.authority_receipt.snapshot_id,
                recovered_status: candidate.status,
                resume_blocked: AUTHORITY_REVOCATION_RESUME_BLOCKED,
                admission,
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
        CompositionError::Owner("grant closure receipt read is not a typed object".to_owned())
    })?;
    let payload = match object.get("kind").and_then(serde_json::Value::as_str) {
        Some(GRANT_CLOSURE_RECEIPT_KIND) => object.get("value").cloned().ok_or_else(|| {
            CompositionError::Owner("grant closure receipt read is missing its payload".to_owned())
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

/// Daemon->Kernel front-door read of the completed canonical second phases of
/// one authority root (issue #2100, `R6`).
const QUERY_GRANT_CLOSURE_LINKS_OPERATION: &str = "query_grant_closure_canonical_receipts";
/// Typed receipt kind answered by the canonical second-phase read arm.
const GRANT_CLOSURE_LINKS_KIND: &str = "grant_closure_canonical_receipts";
/// Typed refusal kind answered by the same arm. A refusal is never read as an
/// absent link: the durable reason is surfaced and the drive fails closed.
const GRANT_CLOSURE_LINKS_REFUSAL_KIND: &str = "grant_closure_canonical_receipts_refused";
/// The only canonical second-phase payload shape this daemon build accepts.
const GRANT_CLOSURE_LINKS_VERSION: u32 = 1;
/// Daemon->Kernel front-door write of one canonical second-phase link,
/// recorded against the one durable ORS store that owns the immutable
/// first-phase row, in the Kernel process.
const LINK_GRANT_CLOSURE_RECEIPT_OPERATION: &str = "link_grant_closure_canonical_receipt";
/// Typed receipt kind answered by the canonical second-phase link arm: the
/// proved read-back of the durable link.
const GRANT_CLOSURE_LINK_KIND: &str = "grant_closure_canonical_receipt_link";
/// Typed refusal kind answered by the same arm. An uncommitted first phase,
/// an immutable conflict, or a transient failure all refuse with their
/// durable reason; none of them is a completed link.
const GRANT_CLOSURE_LINK_REFUSAL_KIND: &str = "grant_closure_canonical_receipt_link_refused";

/// Wire shape answered by the canonical second-phase read arm: the completed
/// links of one root, read from the Kernel's durable ORS snapshot.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantClosureCanonicalLinksWire {
    version: u32,
    authority_root_ref: String,
    grant_graph_revision: u64,
    links: Vec<GrantClosureCanonicalLinkWire>,
}

/// One completed canonical second phase, named by its immutable first-phase
/// closure operation. The daemon never derives either value: both come from
/// the Kernel's durable read.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantClosureCanonicalLinkWire {
    closure_operation_id: String,
    canonical_receipt: ReceiptIdentity,
}

/// Wire shape answered by the canonical second-phase link arm: the proved
/// read-back of the durable link. Unknown fields are ignored rather than
/// refused: the served value is the owner's full closure projection, and this
/// drive reads only the two facts its content proof compares — the verbatim
/// first-phase commit bytes and the durably linked receipt identity.
#[derive(serde::Deserialize)]
struct GrantClosureLinkProjectionWire {
    commit: GrantClosureReceipt,
    second_phase: Option<ReceiptIdentity>,
}

/// What driving one owner-admitted pending second phase proved.
///
/// A [`SecondPhaseDriveOutcome::Linked`] row is proved by content, never by
/// existence: the re-read first-phase bytes bind the admitted operation
/// (operation identity, target, snapshot, fence, and graph revision), and the
/// durably linked read-back binds those same bytes plus the exact
/// Store-issued receipt identity. A
/// [`SecondPhaseDriveOutcome::StillPending`] row observed no committable
/// canonical receipt: the canonical envelope commit stays with the public
/// Governor second-phase-only resume entry, so the drive mints nothing and
/// the row stays pending/recovery-required under
/// [`AUTHORITY_REVOCATION_RESUME_BLOCKED`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecondPhaseDriveOutcome {
    /// The canonical second phase is durably linked and proved by content.
    /// Boxed so the still-pending rows do not pay for a proof they do not
    /// hold (`clippy::large_enum_variant`).
    Linked(Box<GrantClosureSecondPhaseLink>),
    /// No committable canonical receipt is observable; the row stays
    /// pending. The reason is fixed diagnostic text, never authority.
    StillPending {
        /// Closed non-authoritative reason. Fixed text, never authority.
        reason: &'static str,
    },
}

impl SecondPhaseDriveOutcome {
    /// Returns true exactly when the drive proved the second phase linked.
    #[must_use]
    pub const fn is_linked(&self) -> bool {
        matches!(self, Self::Linked(_))
    }

    /// Returns the proved durable link, if the drive proved one.
    #[must_use]
    pub fn link(&self) -> Option<&GrantClosureSecondPhaseLink> {
        match self {
            Self::Linked(link) => Some(link.as_ref()),
            Self::StillPending { .. } => None,
        }
    }

    /// Returns the closed non-authoritative reason, if the row stays pending.
    #[must_use]
    pub const fn pending_reason(&self) -> Option<&'static str> {
        match self {
            Self::Linked(_) => None,
            Self::StillPending { reason } => Some(*reason),
        }
    }
}

/// One owner-admitted pending second phase the drive attempted.
///
/// Every field but `outcome` is the admitted operation's own identity, echoed
/// for the caller that logs the drive beside the scan report. Owner-refused
/// rows never appear here: a refusal carries no authority to drive, so those
/// rows stay pending untouched and remain visible only through
/// [`AuthorityRevocationIngressReport::pending_second_phase`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrivenSecondPhase {
    /// Target grant the committed closure fenced, as admitted.
    pub grant_id: String,
    /// Immutable first-phase closure operation identity, as admitted.
    pub closure_operation_id: String,
    /// What the drive proved for this obligation.
    pub outcome: SecondPhaseDriveOutcome,
}

/// What one second-phase drive pass proved about the admitted obligations.
///
/// The drive attempts every [`PendingRevocationAdmission::Admitted`] row of
/// the scan report and touches no refused row. A row the drive proves linked
/// is finished; a row that stays pending keeps its
/// [`AUTHORITY_REVOCATION_RESUME_BLOCKED`] obligation for the next pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingSecondPhaseDriveReport {
    driven: Vec<DrivenSecondPhase>,
}

impl PendingSecondPhaseDriveReport {
    /// Returns the admitted rows the drive attempted, in scan order.
    #[must_use]
    pub fn driven(&self) -> &[DrivenSecondPhase] {
        &self.driven
    }

    /// Returns how many admitted rows the drive proved linked by content.
    #[must_use]
    pub fn linked(&self) -> usize {
        self.driven
            .iter()
            .filter(|row| row.outcome.is_linked())
            .count()
    }

    /// Returns how many admitted rows stay pending/recovery-required.
    #[must_use]
    pub fn still_pending(&self) -> usize {
        self.driven
            .iter()
            .filter(|row| !row.outcome.is_linked())
            .count()
    }
}

/// Drives every owner-admitted pending canonical second phase the scan
/// reported, through the authenticated Kernel transport, and reports what
/// each admitted obligation proved.
///
/// For every [`PendingRevocationAdmission::Admitted`] row the drive calls
/// [`drive_admitted_pending_second_phase`]: the owner's committed closure
/// bytes are re-read over the authenticated Kernel read, bound to the
/// admitted operation by content, and — when an honestly observed
/// Store-issued canonical receipt exists for the admitted operation — linked
/// idempotently through the Kernel-owned ORS link and proved by a
/// content-compared read-back. Owner-refused rows are never touched: a
/// refusal carries no authority, so those rows stay pending/recovery-required
/// exactly as the scan reported them.
///
/// The `&mut` reaches the Governor composition whose live State Fence binds
/// every read: the drive re-verifies the live composition fence against the
/// Kernel generation before touching transport, so a superseded generation
/// refuses instead of driving under a stale fence. The drive performs no
/// Governor mutation — no public second-phase-only Governor entry exists to
/// call (see [`AUTHORITY_REVOCATION_RESUME_BLOCKED`]), and the fresh
/// Kernel-first saga stays forbidden for an already fenced target — and it
/// mints no operation, request, or receipt identity: the canonical envelope
/// commit that would produce a fresh receipt stays with the Governor resume
/// entry, and a row with no observable receipt stays pending.
///
/// A transport failure, an unexpected response kind, or a durable refusal
/// fails the drive closed and is never degraded to a partial report: the
/// daemon retries on a later owner-feed pass, exactly like the scan.
pub async fn drive_pending_second_phases(
    composition: &mut DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    report: &AuthorityRevocationIngressReport,
) -> Result<PendingSecondPhaseDriveReport, CompositionError> {
    let live_fence = composition.governor.kernel_snapshot().state_fence();
    if kernel.snapshot().state_fence() != live_fence {
        return Err(CompositionError::Recovery(
            "authority revocation drive is bound to a different Kernel generation State Fence"
                .to_owned(),
        ));
    }
    let mut driven = Vec::new();
    for pending in report.pending_second_phase() {
        let Some(admitted) = pending.admission.admitted() else {
            // Owner-refused rows carry no authority to drive. They stay
            // pending/recovery-required untouched; the scan report keeps
            // naming them.
            continue;
        };
        let outcome =
            drive_admitted_pending_second_phase(kernel, &live_fence, admitted).await?;
        driven.push(DrivenSecondPhase {
            grant_id: pending.grant_id.clone(),
            closure_operation_id: pending.closure_operation_id.clone(),
            outcome,
        });
    }
    Ok(PendingSecondPhaseDriveReport { driven })
}

/// Drives one owner-admitted pending second phase to its proved outcome.
///
/// The admitted handoff is the only authority this function acts on: the
/// closure bytes are re-read from the Kernel owner that committed them, the
/// re-read bytes are bound to the admitted operation field for field, and the
/// only receipt identity ever presented to the link is one the owner itself
/// served — either already recorded on the re-read closure, or served by the
/// canonical-links read for the admitted operation. A row with no observable
/// receipt stays pending instead of minting one.
async fn drive_admitted_pending_second_phase(
    kernel: &Arc<DaemonKernelClient>,
    live_fence: &StateFence,
    admitted: &AdmittedMaintenanceRevocation,
) -> Result<SecondPhaseDriveOutcome, CompositionError> {
    let request = admitted.request();
    let target_grant_id = request.grant_id.as_str();
    let Some(closure) = read_committed_closure(kernel, live_fence, target_grant_id).await? else {
        // The scan observed a committed closure for this target on this same
        // pass; the owner serving none now is incoherent durable state, not
        // proof that no first phase ran. Fail closed.
        return Err(CompositionError::Recovery(format!(
            "committed closure for {target_grant_id} is no longer served while its second phase is driven"
        )));
    };
    // Bind the re-read bytes to the admitted operation by content, exactly as
    // the Governor's own closure read-back binds request, snapshot, and
    // fence: a disagreement means the served bytes are not the admitted
    // obligation, so they are refused rather than driven.
    if closure.operation_id != admitted.closure_operation_id()
        || closure.declaration.target_grant_id != target_grant_id
        || closure.authority_receipt.snapshot_id != request.snapshot_id.as_str()
        || closure.authority.state_fence != request.binding.state_fence
        || closure.declaration.grant_graph_revision != admitted.graph_revision()
        || closure.state != GrantClosureState::Revoked
    {
        return Err(CompositionError::Recovery(format!(
            "re-read closure for {target_grant_id} does not bind the admitted revocation operation"
        )));
    }
    if let Some(canonical_receipt) = closure.canonical_receipt.clone() {
        // The link landed after the scan: the owner's own bytes already carry
        // the Store-issued receipt. The content binding above proves these
        // are the admitted bytes, so the second phase is finished — verified,
        // not assumed.
        let link = GrantClosureSecondPhaseLink::new(closure, canonical_receipt);
        return Ok(SecondPhaseDriveOutcome::Linked(Box::new(link)));
    }
    // The first phase is committed but no canonical receipt is observable on
    // it. The canonical-links read is the only honest source of one on the
    // daemon path: the Kernel commits the first-phase row and the canonical
    // receipt separately, so a receipt committed without its link landing is
    // still observable here.
    let Some(canonical_receipt) = read_committed_canonical_receipt(
        kernel,
        live_fence,
        &closure,
        admitted.closure_operation_id(),
    )
    .await?
    else {
        // No canonical envelope was ever committed for the admitted
        // operation. Committing it needs the canonical operation/request
        // identities plus the Governor graph transition and canonical writer
        // — the public Governor second-phase-only resume — so the drive
        // mints nothing and the obligation stays pending.
        return Ok(SecondPhaseDriveOutcome::StillPending {
            reason: AUTHORITY_REVOCATION_RESUME_BLOCKED,
        });
    };
    let link =
        link_closure_second_phase(kernel, live_fence, &closure, &canonical_receipt).await?;
    Ok(SecondPhaseDriveOutcome::Linked(Box::new(link)))
}

/// Reads the Store-issued canonical receipt the durable ORS projection links
/// to one admitted closure operation, if the Kernel holds one.
///
/// The selector root is the re-read closure's own committed
/// `authority_root_ref`, never a daemon-derived value, and the served view is
/// re-proved here exactly as the owner-feed read proves it: version, root
/// echo, and non-zero revision. A served link for another operation is not
/// ours; duplicate disagreeing links for ours are incoherent durable state
/// and fail closed. Any refusal — including `receipt not found`, which the
/// closure read above already rules out for a bound owner — fails the drive
/// closed and is never read as "no canonical receipt exists".
async fn read_committed_canonical_receipt(
    kernel: &Arc<DaemonKernelClient>,
    live_fence: &StateFence,
    closure: &GrantClosureReceipt,
    closure_operation_id: &str,
) -> Result<Option<ReceiptIdentity>, CompositionError> {
    let origin_ref = closure.declaration.authority_root_ref.as_str();
    let value = kernel
        .transact_async(
            QUERY_GRANT_CLOSURE_LINKS_OPERATION,
            serde_json::json!({
                "state_fence": live_fence,
                "authority_root_ref": origin_ref,
                "max_records": REVOCATION_HISTORY_MAX_RECORDS,
            }),
        )
        .await
        .map_err(|error| {
            CompositionError::Recovery(format!(
                "canonical closure link read transport for {origin_ref}: {error}"
            ))
        })?;
    let object = value.as_object().ok_or_else(|| {
        CompositionError::Owner("canonical closure link read is not a typed object".to_owned())
    })?;
    match object.get("kind").and_then(serde_json::Value::as_str) {
        Some(GRANT_CLOSURE_LINKS_KIND) => {}
        Some(GRANT_CLOSURE_LINKS_REFUSAL_KIND) => {
            let reason = object
                .get("value")
                .and_then(|value| value.get("reason"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unspecified durable refusal");
            return Err(CompositionError::Recovery(format!(
                "Kernel refused the durable canonical closure link read for {origin_ref}: {reason}"
            )));
        }
        other => {
            return Err(CompositionError::Owner(format!(
                "canonical closure link read returned an unexpected kind: {other:?}"
            )));
        }
    }
    let value = object.get("value").cloned().ok_or_else(|| {
        CompositionError::Owner("canonical closure link read is missing its payload".to_owned())
    })?;
    let served: GrantClosureCanonicalLinksWire =
        serde_json::from_value(value).map_err(|error| {
            CompositionError::Owner(format!(
                "canonical closure link read does not decode for {origin_ref}: {error}"
            ))
        })?;
    if served.version != GRANT_CLOSURE_LINKS_VERSION
        || served.authority_root_ref != origin_ref
        || served.grant_graph_revision == 0
    {
        return Err(CompositionError::Recovery(format!(
            "canonical closure link read for {origin_ref} is bound to another root, version, or zero revision"
        )));
    }
    let mut canonical_receipt = None;
    for link in served.links {
        if link.closure_operation_id != closure_operation_id {
            continue;
        }
        if let Some(previous) = canonical_receipt.as_ref()
            && previous != &link.canonical_receipt
        {
            return Err(CompositionError::Recovery(format!(
                "durable canonical closure links disagree for {closure_operation_id}"
            )));
        }
        canonical_receipt = Some(link.canonical_receipt);
    }
    Ok(canonical_receipt)
}

/// Links one honestly observed Store-issued canonical receipt to its
/// immutable first-phase closure through the Kernel-owned ORS store, and
/// proves the read-back by content.
///
/// This is the daemon-side half of
/// `eliot_governor::GrantClosureCanonicalLinkPort::link_grant_closure_canonical_receipt`,
/// transported: the request presents the ORIGINAL admitted closure operation
/// identity plus the exact receipt identity the owner served — never a
/// re-derived or freshly minted one — and the served projection is compared
/// by content on the owner's committed bytes, never by existence and never
/// by shape: the linked operation identity, the whole declared closure
/// membership, and the exact linked canonical receipt. An identical link is
/// idempotent; a different identity is an immutable refusal the drive fails
/// closed on.
async fn link_closure_second_phase(
    kernel: &Arc<DaemonKernelClient>,
    live_fence: &StateFence,
    closure: &GrantClosureReceipt,
    canonical_receipt: &ReceiptIdentity,
) -> Result<GrantClosureSecondPhaseLink, CompositionError> {
    let closure_operation_id = closure.operation_id.as_str();
    let value = kernel
        .transact_async(
            LINK_GRANT_CLOSURE_RECEIPT_OPERATION,
            serde_json::json!({
                "state_fence": live_fence,
                "closure_operation_id": closure_operation_id,
                "canonical_receipt": canonical_receipt,
            }),
        )
        .await
        .map_err(|error| {
            CompositionError::Recovery(format!(
                "canonical closure link transport for {closure_operation_id}: {error}"
            ))
        })?;
    let object = value.as_object().ok_or_else(|| {
        CompositionError::Owner("canonical closure link is not a typed object".to_owned())
    })?;
    let payload = match object.get("kind").and_then(serde_json::Value::as_str) {
        Some(GRANT_CLOSURE_LINK_KIND) => object.get("value").cloned().ok_or_else(|| {
            CompositionError::Owner("canonical closure link is missing its payload".to_owned())
        })?,
        Some(GRANT_CLOSURE_LINK_REFUSAL_KIND) => {
            let reason = object
                .get("value")
                .and_then(|value| value.get("reason"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unspecified durable refusal");
            return Err(CompositionError::Recovery(format!(
                "Kernel refused the canonical second-phase link for {closure_operation_id}: {reason}"
            )));
        }
        other => {
            return Err(CompositionError::Owner(format!(
                "canonical closure link returned an unexpected kind: {other:?}"
            )));
        }
    };
    let projection: GrantClosureLinkProjectionWire =
        serde_json::from_value(payload).map_err(|error| {
            CompositionError::Owner(format!(
                "canonical closure link read-back does not decode for {closure_operation_id}: {error}"
            ))
        })?;
    // The ORIGINAL recorded first-phase bytes revalidate under their own
    // receipt contract. Nothing is recomputed here, so a served projection
    // that fails its own contract is a contract failure rather than a link.
    projection.commit.validate().map_err(|error| {
        CompositionError::Owner(format!(
            "linked closure for {closure_operation_id} fails its own receipt contract: {error}"
        ))
    })?;
    if projection.commit.operation_id != closure.operation_id
        || projection.commit.declaration != closure.declaration
        || projection.second_phase.as_ref() != Some(canonical_receipt)
    {
        return Err(CompositionError::Recovery(format!(
            "durable second-phase read-back does not bind the canonical closure receipt for {closure_operation_id}"
        )));
    }
    Ok(GrantClosureSecondPhaseLink::new(
        closure.clone(),
        canonical_receipt.clone(),
    ))
}
