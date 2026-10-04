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
//! re-admission of the exact operation, and reports exactly which of them are
//! still missing their canonical second phase. It is driven from the daemon's
//! polled owner-feed pass
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
//! 2. **The admitted handoff is unreachable through that method.** A committed
//!    first phase whose second phase never completed is exactly the case
//!    `apply_admitted_authority_revocation` exists to resume, but that method
//!    re-strikes the Kernel-first `revoke_grant`, and the Kernel correctly
//!    refuses it: `admitted_grant_hydrations` retains out every
//!    `non_admissible` grant
//!    (`crates/kernel/eliot-kernel-core/src/governor_closure_source.rs`), and
//!    `admit_p07_target_against_current_grant_graph` answers `NotAdmitted` for
//!    any target outside that set
//!    (`bins/eliot-kernel/src/daemon_request_dispatch.rs`). Presenting the
//!    admitted value to that fresh Kernel-first saga is therefore forbidden.
//!
//! # What this module DOES drive
//!
//! The admitted handoff is tendered to
//! `GovernorComposition::apply_pending_canonical_revocation` — the public
//! second-phase-only resume, which never re-strikes the Kernel — through
//! [`admit_canonical_revocation_resumes`], which composes the three admitted
//! identities that entry requires. The durable second-phase link travels
//! through `DaemonKernelClient`'s
//! [`GrantClosureCanonicalLinkPort`](eliot_governor::GrantClosureCanonicalLinkPort)
//! implementation, which records it over the Kernel route that owns ORS inside
//! the Kernel process. The driver is
//! `bins/eliotd/src/daemon_runtime.rs::report_authority_revocation_ingress`.
//!
//! The exact remaining gap is named in
//! [`AUTHORITY_REVOCATION_CANONICAL_RECORD_BLOCKED`]. The closed Store
//! catalogue no longer refuses the operation outright: issue #686 activated the
//! `RecordAuthorityRevocation` row, so a well-formed revocation is admitted and
//! typed-validated instead of failing closed at the gate. What that activation
//! did NOT prove is the execution behind the row, and this branch now supplies
//! most of it: the per-backend durable write handler
//! (`crates/storage/eliot-store-surreal-adapter/src/apply/surreal_authority_revocation.rs`,
//! registered in that crate's `apply.rs` and appended into the canonical
//! transaction by `append_authority_revocation_statements`), plus the
//! count-test migration of every stale assertion in this branch to the true
//! catalogue size of forty-eight entries — six sites in
//! `crates/storage/eliot-store-api/tests/operation_manifest_catalogue.rs` and
//! one each in that crate's `reactive_state_wire.rs`,
//! `user_automation_state_wire.rs` and `notification_state_wire.rs`, plus
//! `bins/eliotd/tests/epistemic_readback.rs`. What is still
//! genuinely absent is the CONSUMER TRIPLE of the paired read: the named read
//! `GetAuthorityRevocationHistory` is deliberately and truthfully unactivated,
//! because the Kernel intercepts it and serves it from the retained P-07 ORS
//! before the store bridge sees it
//! (`bins/eliot-kernel/src/daemon_request_dispatch.rs`, handler
//! `crates/kernel/eliot-kernel-service/src/owner_history.rs`). The store
//! therefore cannot read back what it can now write. A row being writable is
//! still not the same as a resumed obligation being PROVED to commit end to
//! end, so a resumed revocation stays recorded as a pending stricter revocation
//! instead of being reported as a recorded revocation.
//!
//! Forbidden boundary: no ORS access (the Kernel owns ORS in its own
//! process), no second grant graph, no fabricated request, identity or
//! receipt, no epoch invention, and no refusal read as an empty result. A
//! refusal from the closure-receipt read is a typed failure of this pass, never
//! "this grant needs no closure".

use std::sync::Arc;

use eliot_authority::{GrantRevocationRequest, GrantStatus, RevocationOperationIdentity};
use eliot_contracts::StateFence;
use eliot_contracts::{
    ClockReading, OperationId, ReceiptId, TaskId, TransactionSequence, canonical_json_bytes,
    sha256_hex,
};
use eliot_governor::{CompositionError, KernelGenerationSnapshotProvider};
use eliot_protocol::RequestIdentity;
use eliot_receipts::{GrantClosureReceipt, GrantClosureState};
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
/// Closed semantic command kind of the canonical second-phase resume write.
///
/// It is the daemon's I5.27 identity coordinate for this operation, so it is
/// named once here and reused for both the transport request identity and the
/// canonical revocation operation id rather than spelled at each use.
const CANONICAL_REVOCATION_RESUME_OPERATION: &str = "authority.revocation.resume";
/// Domain separator and version of the pass-level observation digest below.
const CLOSURE_RECEIPT_READ_DIGEST_INPUT: &str =
    "authority-revocation-ingress.closure-receipt-read.v1";
/// Typed degradation emitted when no admitted revocation operation identity
/// reaches the Governor resume, naming the exact owner that must supply one.
const REVOCATION_OPERATION_IDENTITY_ABSENT: &str = "revocation operation identity absent";

/// The exact remaining gap in the canonical second phase of a grant
/// revocation, reported on every pending record this pass finds.
///
/// The drive itself is no longer missing: the authenticated Human/Policy
/// maintenance-request owner re-admits the exact committed operation for each
/// pending closure ([`AdmittedMaintenanceRevocation`]), and
/// `daemon_runtime::report_authority_revocation_ingress` feeds that admitted
/// value to `GovernorComposition::apply_pending_canonical_revocation`, whose
/// durable link half runs through the Kernel route that owns ORS.
///
/// What still cannot complete is the canonical record itself. The closed Store
/// catalogue
/// (`crates/storage/eliot-store-api/src/operation_catalogue.rs`) no longer
/// refuses `NamedMutationOperation::RecordAuthorityRevocation`:
/// `StoreError::UnknownOperation` at that gate is gone, because issue #686
/// activated the row, so a well-formed revocation is typed-validated and
/// admitted to the canonical write path instead of being turned away at the
/// catalogue.
///
/// The gap that remains is a missing half of the pair, not the gate. This branch
/// delivers the per-backend write handler, and what it is proven to do is
/// RENDER the row inside the canonical transaction - the durable commit itself
/// is not proven on this slice, and nothing here may be read as claiming it
/// (`crates/storage/eliot-store-surreal-adapter/src/apply/surreal_authority_revocation.rs`,
/// registered in that crate's `apply.rs` and appended into the canonical
/// transaction by `append_authority_revocation_statements`) and migrates every
/// stale catalogue count-test in this branch to the true catalogue size of
/// forty-eight entries: six sites in
/// `crates/storage/eliot-store-api/tests/operation_manifest_catalogue.rs`, plus
/// one each in that crate's `reactive_state_wire.rs`,
/// `user_automation_state_wire.rs` and `notification_state_wire.rs`, plus
/// `bins/eliotd/tests/epistemic_readback.rs`. What is still absent is the
/// CONSUMER TRIPLE of the
/// paired read: `GetAuthorityRevocationHistory` is deliberately and truthfully
/// unactivated, because the Kernel intercepts that named read and serves it
/// from the retained P-07 ORS before the store bridge sees it
/// (`bins/eliot-kernel/src/daemon_request_dispatch.rs`, handler
/// `crates/kernel/eliot-kernel-service/src/owner_history.rs`), so the store
/// cannot read back what it can now write. A row being writable is not the
/// same as a resumed obligation being PROVED to commit end to end, so this pass
/// still reports it as a pending stricter revocation, never as a recorded one.
///
/// What the value below states is the residual gap exactly as this branch leaves
/// it: the catalogue gate admits the command and a proven per-backend handler
/// renders the row into the canonical transaction, so the remaining gap is a missing READ-BACK
/// rather than a missing gate. The paired read `GetAuthorityRevocationHistory` still carries no
/// consumer triple, because the Kernel serves it from the retained P-07 ORS
/// before the store bridge sees it, and nothing on this branch executes the
/// store end to end, so a resumed revocation is not yet proved to commit. The
/// value is therefore written in the true present tense: `lib.rs` re-exports it
/// and a `tracing::warn!` emits it on every pending revocation, where a reason
/// clause still naming the catalogue gate would send an operator to debug the
/// wrong layer. Nothing in this repository matches on the literal, so no
/// in-tree consumer constrains its text.
///
/// Naming it here rather than leaving the pass silent is the point: a pending
/// canonical second phase is real, actionable, durable state. Reporting it
/// without naming the blocker would present an unfinished obligation as a
/// handled one.
pub const AUTHORITY_REVOCATION_CANONICAL_RECORD_BLOCKED: &str = "canonical second phase cannot complete: the Store catalogue now admits \
     NamedMutationOperation::RecordAuthorityRevocation and a proven per-backend handler renders the row \
     into the canonical transaction, but the paired read GetAuthorityRevocationHistory has no consumer \
     triple because the Kernel serves it from the retained P-07 ORS, so a resumed revocation is not yet \
     proved to commit end to end and the obligation stays pending instead of becoming a recorded revocation";

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

    /// Returns the exact State Fence this pass is bound to.
    ///
    /// The Governor resume composes its admitted identities under this same
    /// fence, and the composition re-checks each of them against the live fence
    /// and against the committed closure before it acts.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }
}

/// One committed first-phase closure whose canonical second phase has not been
/// linked yet.
///
/// Every field is the owner's own committed value served by the Kernel. The
/// `resume_blocked` marker is this module's honest statement of the remaining
/// store-side read-back gap, not a claim that the obligation was discharged:
/// the Governor drive itself works, and what is missing is the store-side read
/// back of the record it can now write.
/// The `admission` field records what the maintenance-request owner did with
/// the obligation: only a [`PendingRevocationAdmission::Admitted`] row carries
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
    /// Why this pass cannot finish the canonical record itself. Always
    /// [`AUTHORITY_REVOCATION_CANONICAL_RECORD_BLOCKED`].
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

/// One owner-admitted pending second phase, composed into exactly the inputs
/// the Governor second-phase-only resume entry consumes.
///
/// The three identities are the same indivisible admission
/// `GovernorComposition::apply_pending_canonical_revocation` takes: the
/// canonical operation id, the admitted canonical request identity, and the
/// admitted revocation operation identity. They are composed here, together
/// and never separately, because the composition refuses a mixture of two
/// different operations.
///
/// Every coordinate is an owner-proved fact, never a value derived from the
/// graph under audit:
///
/// * the request and the committed closure are the owner's own committed bytes,
///   re-admitted by the maintenance-request owner and carried verbatim;
/// * the canonical operation id is a pure function of the ORIGINAL recorded
///   first-phase closure operation id, so an exact replay resolves to the same
///   operation and a changed closure conflicts under it (I5.27);
/// * the canonical request identity is this daemon's own I5.27 transport
///   identity, minted by the single daemon owner over exactly those committed
///   closure bytes;
/// * the revocation operation identity's five coordinates are the
///   Kernel-validated session principal, the admitted generation this pass runs
///   under, the committed authority root namespace the closure declares, the
///   pass-level closure-receipt read digest as the observation, and the causal
///   `transaction_sequence` of the admitted generation — never a wall clock
///   reading and never a value taken from the recovered graph.
#[derive(Clone, Debug)]
pub struct AdmittedCanonicalRevocationResume {
    request: GrantRevocationRequest,
    committed_closure: GrantClosureReceipt,
    canonical_operation_id: OperationId,
    canonical_request_identity: RequestIdentity,
    operation: RevocationOperationIdentity,
}

impl AdmittedCanonicalRevocationResume {
    /// Returns the exact re-admitted revocation request.
    #[must_use]
    pub const fn request(&self) -> &GrantRevocationRequest {
        &self.request
    }

    /// Returns the ORIGINAL committed first-phase closure receipt the resume
    /// runs against.
    #[must_use]
    pub const fn committed_closure(&self) -> &GrantClosureReceipt {
        &self.committed_closure
    }

    /// Returns the admitted canonical operation identity of this resume.
    #[must_use]
    pub const fn canonical_operation_id(&self) -> &OperationId {
        &self.canonical_operation_id
    }

    /// Returns the admitted canonical request identity of this resume.
    #[must_use]
    pub const fn canonical_request_identity(&self) -> &RequestIdentity {
        &self.canonical_request_identity
    }

    /// Returns the admitted revocation operation identity of this resume.
    #[must_use]
    pub const fn operation(&self) -> &RevocationOperationIdentity {
        &self.operation
    }
}

/// Composes one Governor second-phase-only resume handoff per owner-admitted
/// pending closure, under the admitted identities that handoff requires.
///
/// An empty admitted set composes nothing and returns an empty vector: a pass
/// that found no pending canonical second phase performs no Kernel exchange and
/// mints no identity.
///
/// `state_fence` must be the pass's own admitted fence and `revision` its
/// captured grant-graph revision, so the composed operation identities name
/// the exact observation this pass made. The composition re-checks each composed
/// identity against its own live fence and against the committed closure bytes
/// before it acts, so nothing here is taken on trust.
///
/// # Errors
///
/// Returns [`CompositionError::Recovery`] when the Kernel has admitted no
/// validated session binding for this connection — the principal coordinate is
/// unavailable and is never invented — and [`CompositionError::Owner`] when the
/// owner facts are present but not admissible (unusable identity text, or a
/// canonicalization failure over the committed closure bytes).
pub fn admit_canonical_revocation_resumes(
    state_fence: &StateFence,
    revision: u64,
    admitted: &[&AdmittedMaintenanceRevocation],
    kernel: &Arc<DaemonKernelClient>,
) -> Result<Vec<AdmittedCanonicalRevocationResume>, CompositionError> {
    if admitted.is_empty() {
        return Ok(Vec::new());
    }
    // The principal is the Kernel-authenticated session binding this
    // connection proved during its handshake, and it doubles as the I5.27
    // principal-and-scope coordinate of the composed request identities. Absent
    // before any validated handshake, which degrades the pass instead of
    // inventing a session.
    let principal = kernel.validated_session_binding().ok_or_else(|| {
        CompositionError::Recovery(format!(
            "{REVOCATION_OPERATION_IDENTITY_ABSENT}: no Kernel-validated session binding \
             (graph revision {revision}, {} admitted pending closure(s))",
            admitted.len()
        ))
    })?;
    let observing_receipt =
        observed_closure_receipt_read_identity(state_fence, revision, admitted)?;
    let epoch = state_fence.authority_epoch.clone();
    let generation = format!("{}:{}", epoch.lineage_id.as_str(), epoch.sequence.get());
    // The resume is the installation's own recovery work, not product task
    // work, so the admitted task is the generation the resume runs under. The
    // coordinate is still required and still refuses blank text.
    let admitted_task = TaskId::new(format!("kernel-generation:{generation}"))
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    let transaction_sequence = TransactionSequence::new(state_fence.resource_generation.value())
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    let mut resumes = Vec::with_capacity(admitted.len());
    for row in admitted {
        let committed_closure = row.committed_closure();
        // The canonical operation id is a pure function of the ORIGINAL recorded
        // first-phase operation identity: an exact replay of one pending
        // obligation is the same canonical operation, while a changed closure
        // under it is the I5.27 changed-payload conflict rather than a second
        // operation.
        let canonical_operation_id = OperationId::new(format!(
            "{CANONICAL_REVOCATION_RESUME_OPERATION}:{}",
            row.closure_operation_id()
        ))
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
        // The canonical request bytes are the owner's own committed closure the
        // resume is about to record against. Nothing is re-derived, so a changed
        // closure derives a different request identity under the same operation.
        let canonical_request = serde_json::to_value(committed_closure)
            .map_err(|error| CompositionError::Owner(error.to_string()))?;
        let canonical_request_identity = kernel
            .canonical_write_identity(
                CANONICAL_REVOCATION_RESUME_OPERATION,
                &principal,
                &canonical_request,
            )
            .map_err(|error| CompositionError::Provider(error.to_string()))?;
        let operation = RevocationOperationIdentity::admit(
            principal.clone(),
            admitted_task.clone(),
            committed_closure.declaration.authority_root_ref.clone(),
            observing_receipt.clone(),
            ClockReading {
                valid_time_ms: None,
                known_time_ms: None,
                transaction_sequence: Some(transaction_sequence),
                monotonic_ns: None,
            },
        )
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
        resumes.push(AdmittedCanonicalRevocationResume {
            request: row.request().clone(),
            committed_closure: committed_closure.clone(),
            canonical_operation_id,
            canonical_request_identity,
            operation,
        });
    }
    Ok(resumes)
}

/// The pass-level observation identity the composed revocation operation
/// identities name as their observing receipt.
///
/// It is a digest-bound fold over the exact `(closure operation, Kernel-issued
/// revocation receipt, owner snapshot)` triples this pass read over the
/// authenticated front door, bound to the admitted authority epoch and graph
/// revision. It is therefore the identity of the READ, not one of the closures
/// under recheck, so the origin-bound re-derivation the Governor composition
/// performs over its own graph cannot certify itself through it.
fn observed_closure_receipt_read_identity(
    state_fence: &StateFence,
    revision: u64,
    admitted: &[&AdmittedMaintenanceRevocation],
) -> Result<ReceiptId, CompositionError> {
    let read: Vec<(&str, &str, &str)> = admitted
        .iter()
        .map(|row| {
            let authority_receipt = &row.committed_closure().authority_receipt;
            (
                row.closure_operation_id(),
                authority_receipt.receipt_id.as_str(),
                authority_receipt.snapshot_id.as_str(),
            )
        })
        .collect();
    // The admitted rows arrive in the pass's own candidate order and are pushed
    // in that order, so the preimage is deterministic across passes and
    // restarts.
    let digest = sha256_hex(
        &canonical_json_bytes(&(
            CLOSURE_RECEIPT_READ_DIGEST_INPUT,
            state_fence.authority_epoch.sequence.get(),
            revision,
            read,
        ))
        .map_err(|error| CompositionError::Owner(error.to_string()))?,
    );
    ReceiptId::new(digest).map_err(|error| CompositionError::Owner(error.to_string()))
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
/// module documentation and
/// [`AUTHORITY_REVOCATION_CANONICAL_RECORD_BLOCKED`]). A
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
                resume_blocked: AUTHORITY_REVOCATION_CANONICAL_RECORD_BLOCKED,
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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expects for fixed-valid protocol fixtures"
    )]

    use super::*;

    use eliot_contracts::{ContractId, EpochId, EpochLineageId, ResourceGeneration};
    use eliot_receipts::{AuthorityBinding, EffectClass, ProofCeiling};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "7d3fbb1e-0a2f-4c1f-9a2e-3f5f9d0c1a44";
    const TEST_PRINCIPAL: &str = "principal:kernel-session-1";

    fn test_fence() -> StateFence {
        let lineage = EpochLineageId::new(TEST_LINEAGE).expect("test epoch lineage");
        let epoch = EpochId::new(
            lineage,
            NonZeroU64::new(1).expect("test epoch sequence is non-zero"),
        )
        .expect("test authority epoch");
        StateFence::new(
            epoch,
            ResourceGeneration::new(1).expect("test resource generation"),
        )
    }

    fn kernel_with_session(fence: &StateFence) -> Arc<DaemonKernelClient> {
        let mut client =
            DaemonKernelClient::new_for_test(fence.authority_epoch.clone(), fence.clone());
        client.seed_validated_session_binding_for_test(TEST_PRINCIPAL);
        Arc::new(client)
    }

    /// One committed revoked first phase whose canonical second phase has not
    /// been linked, in exactly the shape the closure receipt contract requires.
    fn committed_pending_closure(
        fence: &StateFence,
        idempotency_digest: &str,
    ) -> GrantClosureReceipt {
        let closure = GrantClosureReceipt {
            schema: eliot_receipts::GRANT_CLOSURE_SCHEMA.to_owned(),
            version: eliot_receipts::GRANT_CLOSURE_VERSION,
            operation_id: "closure-op-1".to_owned(),
            idempotency_digest: idempotency_digest.to_owned(),
            declaration: eliot_receipts::GrantClosureDeclaration {
                schema: eliot_receipts::GRANT_CLOSURE_SCHEMA.to_owned(),
                version: eliot_receipts::GRANT_CLOSURE_VERSION,
                target_grant_id: "grant-a".to_owned(),
                authority_root_ref: "authority:root-1".to_owned(),
                grant_graph_revision: 7,
                members: vec![eliot_receipts::GrantClosureMemberDeclaration {
                    validity: eliot_contracts::LogicalValidityInterval {
                        issued_at: 1,
                        expires_at: 10,
                    },
                    grant_id: "grant-a".to_owned(),
                    parent_grant_id: None,
                }],
                preserved: Vec::new(),
                proof_ceiling: ProofCeiling::ObservedExternalEffect,
            },
            authority: AuthorityBinding {
                authority_id: ContractId::new("authority:test").expect("authority id"),
                authority_owner: "test-owner".to_owned(),
                authority_epoch: fence.authority_epoch.clone(),
                state_fence: fence.clone(),
                allowed_effect: EffectClass::ExternalEffect,
                proof_ceiling: ProofCeiling::ObservedExternalEffect,
            },
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
            authority_receipt: eliot_receipts::GrantClosureAuthorityReceiptRef {
                receipt_id: "revocation-closure-op-1".to_owned(),
                snapshot_id: "snap-1".to_owned(),
                authority_epoch: fence.authority_epoch.clone(),
                state: GrantClosureState::Revoked,
            },
            ors_member_receipts: vec![eliot_receipts::GrantClosureOrsReceiptRef {
                record_id: "ors-member-1".to_owned(),
                subject_id: "grant-a".to_owned(),
                operation_order: 1,
                state: GrantClosureState::Revoked,
                state_sha256: "e".repeat(64),
            }],
            fenced_introductions: Vec::new(),
            ors_introduction_receipts: Vec::new(),
            canonical_receipt: None,
            state: GrantClosureState::Revoked,
        };
        closure
            .validate()
            .expect("the committed closure satisfies its own receipt contract");
        closure
    }

    /// Positive case: one owner-admitted pending closure composes exactly one
    /// resume handoff whose every coordinate is the owner's own committed
    /// material, and the composition is idempotent for one unchanged closure
    /// while a changed payload under the same first-phase operation derives a
    /// different canonical request identity (I5.27).
    ///
    /// WHY IT FAILS WITHOUT THIS CHANGE: `admit_canonical_revocation_resumes`
    /// does not exist at base, and no base method composes the three admitted
    /// identities the Governor second-phase-only resume entry requires. The
    /// nearest base surface, `AdmittedMaintenanceRevocation`, carried only the
    /// derived request and the closure operation id — so the canonical operation
    /// id, the admitted canonical request identity and the five-coordinate
    /// revocation operation identity could not be produced from owner material
    /// at all, and the resume entry had no input to consume. The asserted
    /// operation-id stability and changed-payload divergence are therefore
    /// base-unreachable, not base-passing.
    #[test]
    fn admitted_pending_closure_composes_one_stable_resume_handoff() {
        let fence = test_fence();
        let kernel = kernel_with_session(&fence);
        let closure = committed_pending_closure(&fence, &"d".repeat(64));
        let admitted = AdmittedMaintenanceRevocation::readmit_pending_closure(&fence, &closure)
            .expect("the committed closure is an admissible pending obligation");

        let resumes = admit_canonical_revocation_resumes(&fence, 7, &[&admitted], &kernel)
            .expect("an admitted pending closure composes a resume handoff");
        assert_eq!(resumes.len(), 1, "one admitted row is one resume handoff");
        let resume = &resumes[0];
        // The owner's own committed bytes travel verbatim; nothing is re-derived.
        assert_eq!(resume.committed_closure(), &closure);
        assert_eq!(resume.request().grant_id.as_str(), "grant-a");
        assert_eq!(resume.request().snapshot_id.as_str(), "snap-1");
        // The canonical operation id is a pure function of the ORIGINAL recorded
        // first-phase operation identity, so an unchanged closure replays into
        // the same canonical operation.
        assert_eq!(
            resume.canonical_operation_id().as_str(),
            format!(
                "{CANONICAL_REVOCATION_RESUME_OPERATION}:{}",
                closure.operation_id
            )
        );

        let replayed = admit_canonical_revocation_resumes(&fence, 7, &[&admitted], &kernel)
            .expect("an exact replay composes the same handoff");
        assert_eq!(
            replayed[0].canonical_operation_id(),
            resume.canonical_operation_id(),
            "an exact replay must resolve to the same canonical operation"
        );
        assert_eq!(
            replayed[0].canonical_request_identity().idempotency_key,
            resume.canonical_request_identity().idempotency_key,
            "an exact replay must resolve to the same idempotency key"
        );

        // A changed payload under the same first-phase operation keeps the same
        // canonical operation identity and derives a different request identity,
        // so the store sees the I5.27 changed-payload conflict rather than a
        // second operation.
        let changed = committed_pending_closure(&fence, &"f".repeat(64));
        assert_eq!(
            changed.operation_id, closure.operation_id,
            "the fixture must vary only the payload for this check to mean anything"
        );
        let changed_admitted =
            AdmittedMaintenanceRevocation::readmit_pending_closure(&fence, &changed)
                .expect("the changed committed closure is still admissible");
        let conflict = admit_canonical_revocation_resumes(&fence, 7, &[&changed_admitted], &kernel)
            .expect("a changed payload still composes the same canonical operation");
        assert_eq!(
            conflict[0].canonical_operation_id(),
            resume.canonical_operation_id(),
            "a changed payload must not open a second canonical operation"
        );
        assert_ne!(
            conflict[0].canonical_request_identity().idempotency_key,
            resume.canonical_request_identity().idempotency_key,
            "a changed payload must derive a different idempotency key under the same operation"
        );
    }

    /// Refusal case: with no Kernel-validated session binding there is no
    /// admitted principal coordinate, so the composition refuses and mints
    /// nothing rather than inventing one. An empty admitted set still composes
    /// nothing successfully, which is what makes the refusal the absent owner
    /// and not a blanket failure of the pass.
    ///
    /// WHY IT FAILS WITHOUT THIS CHANGE: the composition does not exist at base,
    /// and `AdmittedMaintenanceRevocation` at base is minted from the committed
    /// closure alone — it never needed a principal, so no base surface could
    /// report the absent owner. Asserting the typed `Recovery` refusal and the
    /// empty-set success together pins the refusal to the missing
    /// principal/session-binding coordinate alone.
    #[test]
    fn canonical_revocation_resume_refuses_without_a_validated_session_binding() {
        let fence = test_fence();
        // No validated handshake: the session binding is still absent.
        let kernel = Arc::new(DaemonKernelClient::new_for_test(
            fence.authority_epoch.clone(),
            fence.clone(),
        ));
        assert!(kernel.validated_session_binding().is_none());
        let closure = committed_pending_closure(&fence, &"d".repeat(64));
        let admitted = AdmittedMaintenanceRevocation::readmit_pending_closure(&fence, &closure)
            .expect("the committed closure is an admissible pending obligation");

        // A pass that admitted nothing composes nothing, without needing a
        // principal: no identity is minted for an absent obligation.
        assert!(
            admit_canonical_revocation_resumes(&fence, 7, &[], &kernel)
                .expect("an empty admitted set composes no identity")
                .is_empty()
        );

        let error = admit_canonical_revocation_resumes(&fence, 7, &[&admitted], &kernel)
            .expect_err("no admitted principal means no resume handoff");
        let CompositionError::Recovery(detail) = &error else {
            panic!("the refusal must be a Recovery refusal, got: {error:?}");
        };
        assert!(
            detail.contains(REVOCATION_OPERATION_IDENTITY_ABSENT),
            "the refusal must name the absent owner, got: {error:?}"
        );
    }
}
