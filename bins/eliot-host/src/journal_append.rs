mod readiness_append;
#[cfg(windows)]
pub(super) use readiness_append::{
    append_authenticated_kernel_readiness, append_authenticated_kernel_readiness_with_heartbeat,
};

use super::{HostError, fresh_identity, fresh_lineage_id, operation, record_fence, sha256_json};
use eliot_host_state::{
    ActivationState, AppendDisposition, AppendReceipt, CleanMarker, DrainCommitRecord, DrainRecord,
    DrainState, EliotActivationRecord, EpochTransition, FailureRecoveryDirective,
    HostInstallationEpoch, HostKernelStoreLineage, HostState, HostStateJournalService,
    HostStateRecord, JOURNAL_VERSION, JournalBackend, JournalError, JournalManifest,
    KernelJobBinding, KernelReadinessObservationRecord, KernelRecord, LifecycleTimestamps,
    PreparedAppend, PriorKernelDisposition, PriorKernelSource, ReadinessEvidence, ReconcileOutcome,
    RecordFence, WakeDisposition, record_checksum,
};
#[cfg(windows)]
use eliot_host_state::{StoreRebindRecord, StoreRebindState};
#[cfg(windows)]
use eliot_kernel_service::StoreRebindReceipt;
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::{
    HealthDimension, HealthVector, ServiceProcessRecord, ServiceProcessState,
};

use crate::host_diagnostics::{BoundedField, bound_field};

// F-LOG-HOST-6 (#981) shared observation vocabulary for the nine-file family.
//
// One typed value, one disposition enum and one emitter serve all nine
// instrumented files: journal append, readiness append, epoch reopen,
// readiness gate, restart state, pending codec, recovery evidence and recovery
// fence. Every record is emitted through the #889 facade, which owns the one
// emission spelling surface of this process: `info!` is re-exported by
// `host_diagnostics`, `HOST_DIAGNOSTICS_TARGET` is its single target, and
// `note_event_log_sink_status` is the canonical bounded observer for the live
// Event Log disposition. The `windows_event_log` wrapper stays the only OS
// seam; no Event Log FFI is acquired here and no sink outcome alters a
// result, an order, a persistence call or a cleanup step.
//
// Two halves, two owners, and only one of them closed. The disposition half is
// closed: 37 variants, one per decision a semantic owner has already made, and
// [`HostJournalDisposition::as_str`] is their only spelling. The boundary half
// is a bare `&'static str` naming one owner's own frozen boundary literal, and
// this module deliberately declares no closed set for it, so it is not a second
// vocabulary in disguise: adding a boundary spelling is the tracked family
// fixture's decision, and every literal below was checked against that fixture
// rather than invented here.
//
// Observation-only contract: every helper projects facts the semantic owner has
// already produced. Arguments are a frozen boundary spelling plus
// already-owned nonsecret handles — never records, receipts, record or codec
// bytes, credentials, environment values or arbitrary error text — so bounding
// limits size, not sensitivity (I15.4). Requested append, applied commit,
// exact replay, known noncommit and unknown outcome stay distinct (I14.21):
// possible loss is never promoted into a receipt, a readable snapshot is never
// read as a pending reconciliation, and a known noncommit is never rewritten
// as an unknown one.
//
// These primitives own no terminal: the single terminal per failed operation
// stays with the outermost owner boundary in `lib.rs` (#891) or Host
// composition (#893). Every site emits exactly one record, so no correlated
// lower-stage detail is counted twice, and there is no dedup cache.

/// Closed disposition vocabulary of the nine-file #981 observation family.
///
/// One variant per disposition a semantic owner has already decided. A variant
/// names what that owner proved; none is a lifecycle, a recovery directive, a
/// new authority or a repair step (I14.20), and none is inferred from a record
/// that was merely readable. An identity the owner does not hold stays
/// unavailable in its own slot, never replaced by a default or by the order in
/// which records were emitted (I5.16).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HostJournalDisposition {
    /// The boundary was reached and the owner reported no further outcome.
    BoundaryReached,
    /// The journal owner applied this append as a new durable commit.
    CommitApplied,
    /// The journal owner returned the exact existing record: readback of the
    /// original effect, never a second append.
    CommitReplayed,
    /// The journal owner proved this exact transaction committed.
    ReconcileCommitted,
    /// The journal owner proved no commit exists for this exact transaction.
    ReconcileNotCommitted,
    /// The journal owner could not resolve the outcome; it stays unknown and is
    /// never rewritten into either neighbouring disposition (I14.21).
    ReconcileStillUnknown,
    /// The commit is known and this call verified the replay receipt for it.
    ReconcileReadbackVerified,
    /// The commit is known and this call's replay readback failed.
    ReconcileReadbackFailed,
    /// This call created the durable publication.
    PublicationCreated,
    /// This call replayed an exact existing durable publication.
    PublicationReplayed,
    /// The durable effect is committed and a later cleanup step did not
    /// complete: the effect stands and its residue stays observable.
    CleanupIncomplete,
    /// The denominator was exactly zero: no pending transaction existed.
    DenominatorEmpty,
    /// Every pending transaction of this reopen reconciled as committed.
    DenominatorReconciled,
    /// The startup fence is clear: no unresolved Store recovery binding.
    FenceClear,
    /// The startup fence holds one or more unresolved Store recovery bindings.
    FenceUnresolved,
    /// The retained lease matches this contour and is inside its deadline.
    LeaseValid,
    /// The retained lease's deadline has passed.
    LeaseExpired,
    /// The retained lease belongs to a moved or foreign contour.
    LeaseContourMoved,
    /// The retained lease's contour lacks a complete supervision or store proof.
    LeaseProofIncomplete,
    /// No lease was retained for this contour.
    LeaseAbsent,
    /// A retry deadline is still pending for this exact contour.
    RetryPending,
    /// A fresh probe is due for this exact contour.
    ProbeDue,
    /// The gate granted the journaled current contour a lease.
    ReadinessGranted,
    /// The gate refused the grant because the contour is not complete.
    ReadinessRefused,
    /// Readiness degraded with the exact retained failure kind.
    ReadinessDegraded,
    /// The supervised branch degraded without a retained contour.
    BranchDegraded,
    /// The requested evidence file is absent: explicit incomplete evidence.
    EvidenceAbsent,
    /// The read evidence validated against the requested mutation.
    EvidenceValidated,
    /// The read evidence cannot be used: malformed, oversized, or not a file.
    EvidenceUnusable,
    /// The read evidence names another mutation, request or inner binding.
    EvidenceMismatched,
    /// The named evidence belongs to another durable Host epoch or activation.
    EvidenceForeign,
    /// The read evidence is readable but incomplete for the owner's use.
    EvidenceIncomplete,
    /// The evidence path could not be inspected at all.
    EvidenceUnreadable,
    /// The fence carries exactly this durable binding identity.
    FenceBound,
    /// The fence's inner binding has no journal record yet: a recoverable
    /// unknown, never permission for a fresh contour.
    FenceInnerUnresolved,
    /// The owner kept the exact epoch or activation generation it already
    /// held: this open advances no lineage.
    OwnerEpochRetained,
    /// The owner created a fresh direct-child epoch or activation generation
    /// under a newly minted lineage.
    OwnerEpochChildCreated,
}

impl HostJournalDisposition {
    /// Stable diagnostic name. Every variant maps to a distinct string; the
    /// name projects the owner's own disposition and is never a lifecycle
    /// state of its own (I14.20).
    #[must_use]
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::BoundaryReached => "boundary_reached",
            Self::CommitApplied => "commit_applied",
            Self::CommitReplayed => "commit_replayed",
            Self::ReconcileCommitted => "reconcile_committed",
            Self::ReconcileNotCommitted => "reconcile_not_committed",
            Self::ReconcileStillUnknown => "reconcile_still_unknown",
            Self::ReconcileReadbackVerified => "reconcile_readback_verified",
            Self::ReconcileReadbackFailed => "reconcile_readback_failed",
            Self::PublicationCreated => "publication_created",
            Self::PublicationReplayed => "publication_replayed",
            Self::CleanupIncomplete => "cleanup_incomplete",
            Self::DenominatorEmpty => "denominator_empty",
            Self::DenominatorReconciled => "denominator_reconciled",
            Self::FenceClear => "fence_clear",
            Self::FenceUnresolved => "fence_unresolved",
            Self::LeaseValid => "lease_valid",
            Self::LeaseExpired => "lease_expired",
            Self::LeaseContourMoved => "lease_contour_moved",
            Self::LeaseProofIncomplete => "lease_proof_incomplete",
            Self::LeaseAbsent => "lease_absent",
            Self::RetryPending => "retry_pending",
            Self::ProbeDue => "probe_due",
            Self::ReadinessGranted => "readiness_granted",
            Self::ReadinessRefused => "readiness_refused",
            Self::ReadinessDegraded => "readiness_degraded",
            Self::BranchDegraded => "branch_degraded",
            Self::EvidenceAbsent => "evidence_absent",
            Self::EvidenceValidated => "evidence_validated",
            Self::EvidenceUnusable => "evidence_unusable",
            Self::EvidenceMismatched => "evidence_mismatched",
            Self::EvidenceForeign => "evidence_foreign",
            Self::EvidenceIncomplete => "evidence_incomplete",
            Self::EvidenceUnreadable => "evidence_unreadable",
            Self::FenceBound => "fence_bound",
            Self::FenceInnerUnresolved => "fence_inner_unresolved",
            Self::OwnerEpochRetained => "owner_epoch_retained",
            Self::OwnerEpochChildCreated => "owner_epoch_child_created",
        }
    }
}

/// One narrow typed observation of a nine-file #981 boundary.
///
/// Every slot holds an identity the semantic owner already produced at the call
/// site, or `None` when that owner holds no such value. Each slot renders with
/// its own `<slot>_missing` flag, so an unavailable identity stays explicitly
/// unavailable instead of being reconstructed from temporal order (I5.16).
/// Bounded handles are truncated by the facade's `bound_field` before they
/// reach the record; that bound limits size only, so callers pass
/// already-owned nonsecret handles and never journal bytes, codec bytes,
/// credentials, configuration, environment values, user payloads or arbitrary
/// error text (I15.4, I07.20).
///
/// Every slot is private to this module family: a sibling boundary reaches this
/// value only through [`HostJournalObservation::new`] and the builders below,
/// so no other file can assemble or mutate a record behind the emitter.
///
/// Builder precedence is last write wins, and a later builder silently
/// discards whatever an earlier builder wrote to the same slot. The slots with
/// more than one writer are exactly the installation, epoch and activation
/// triples, plus `operation`, `transaction` and `record_checksum`:
/// [`Self::with_host`], [`Self::with_record_fence`],
/// [`Self::with_prepared_append`], [`Self::with_installation`],
/// [`Self::with_host_epoch`], [`Self::with_activation_generation`],
/// [`Self::with_operation`], [`Self::with_transaction`],
/// [`Self::with_record_checksum`] and [`Self::with_receipt`] each name the
/// slots they overwrite. A chain must therefore call one builder per shared
/// slot; a chain that would bind both a caller-side and an owner-side contour
/// has to choose which one the record carries, because binding both silently
/// keeps only the last.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HostJournalObservation {
    boundary: &'static str,
    disposition: HostJournalDisposition,
    operation: Option<BoundedField>,
    transaction: Option<BoundedField>,
    record_checksum: Option<BoundedField>,
    receipt_sequence: Option<u64>,
    installation: Option<BoundedField>,
    host_epoch: Option<u64>,
    host_lineage: Option<BoundedField>,
    activation_id: Option<BoundedField>,
    activation_generation: Option<BoundedField>,
    activation_epoch: Option<u64>,
    fence: Option<BoundedField>,
    mutation: Option<BoundedField>,
    request_digest: Option<BoundedField>,
    contour: Option<BoundedField>,
    lease: Option<BoundedField>,
    ors_receipt: Option<BoundedField>,
    watchdog: Option<BoundedField>,
    recovery: Option<BoundedField>,
    failure: Option<&'static str>,
    cardinality: Option<u64>,
    committed: Option<u64>,
}

impl HostJournalObservation {
    /// One boundary observation: the owner's own frozen boundary literal naming the
    /// boundary it reached, plus the disposition that owner decided there. The
    /// boundary literal is a bare `&'static str` and this module closes no set over
    /// it; the tracked family fixture owns which spellings exist. Every identity
    /// slot starts explicitly unavailable and is filled only by a value the owner
    /// already holds.
    #[must_use]
    pub(super) const fn new(boundary: &'static str, disposition: HostJournalDisposition) -> Self {
        Self {
            boundary,
            disposition,
            operation: None,
            transaction: None,
            record_checksum: None,
            receipt_sequence: None,
            installation: None,
            host_epoch: None,
            host_lineage: None,
            activation_id: None,
            activation_generation: None,
            activation_epoch: None,
            fence: None,
            mutation: None,
            request_digest: None,
            contour: None,
            lease: None,
            ors_receipt: None,
            watchdog: None,
            recovery: None,
            failure: None,
            cardinality: None,
            committed: None,
        }
    }

    /// Attaches the owner's own operation or request identity handle. This
    /// builder writes `operation`, so a later `with_prepared_append` silently
    /// discards the value this one wrote.
    #[must_use]
    pub(super) fn with_operation(mut self, operation: &str) -> Self {
        self.operation = Some(bound_field(operation));
        self
    }

    /// Attaches the journal transaction identity the owner holds for this
    /// operation. This builder writes `transaction`, so a later `with_receipt`
    /// or `with_prepared_append` silently discards the value this one wrote.
    #[must_use]
    pub(super) fn with_transaction(mut self, handle: &PlatformHandle) -> Self {
        self.transaction = Some(bound_field(handle.as_str()));
        self
    }

    /// Attaches the owner-computed checksum of the exact retained record. This
    /// builder writes `record_checksum`, so a later `with_prepared_append`
    /// silently discards the value this one wrote.
    #[must_use]
    pub(super) fn with_record_checksum(mut self, checksum: &str) -> Self {
        self.record_checksum = Some(bound_field(checksum));
        self
    }

    /// Attaches the journal owner's own append receipt: its stable transaction
    /// identity and the sequence the reducer assigned after durable commit or
    /// exact replay. This builder writes `transaction` and `receipt_sequence`
    /// only: the receipt's disposition reaches the record as the second argument
    /// of [`HostJournalObservation::new`], so no field here re-derives it. A
    /// later `with_transaction` or `with_prepared_append` discards the
    /// transaction identity this builder just wrote.
    #[must_use]
    pub(super) fn with_receipt(mut self, receipt: &AppendReceipt) -> Self {
        self.transaction = Some(bound_field(receipt.transaction_id().as_str()));
        self.receipt_sequence = Some(receipt.sequence());
        self
    }

    /// Attaches every identity one prepared append already carries: its
    /// operation identity, journal transaction identity, record checksum and
    /// the exact Host installation epoch it was prepared under. This builder
    /// writes `operation`, `transaction`, `record_checksum`, `installation`,
    /// `host_epoch` and `host_lineage`, so a later `with_operation`,
    /// `with_transaction`, `with_record_checksum`, `with_host`,
    /// `with_record_fence`, `with_installation` or `with_host_epoch` silently
    /// discards the corresponding value this one wrote.
    #[must_use]
    pub(super) fn with_prepared_append(mut self, prepared: &PreparedAppend) -> Self {
        self.operation = Some(bound_field(prepared.operation.operation_id.as_str()));
        self.transaction = Some(bound_field(prepared.transaction_id.as_str()));
        self.record_checksum = Some(bound_field(prepared.record_checksum.as_str()));
        self = self.with_host(&prepared.host);
        self
    }

    /// Attaches the exact durable Host installation identity: its installation
    /// handle plus the current epoch sequence and lineage. This builder writes
    /// `installation`, `host_epoch` and `host_lineage`, so a later
    /// `with_record_fence`, `with_prepared_append`, `with_installation` or
    /// `with_host_epoch` silently discards the corresponding value this one
    /// wrote.
    #[must_use]
    pub(super) fn with_host(mut self, host: &HostInstallationEpoch) -> Self {
        self.installation = Some(bound_field(host.installation.as_str()));
        self.host_epoch = Some(host.epoch.current.sequence.get());
        self.host_lineage = Some(bound_field(host.epoch.current.lineage_id.as_str()));
        self
    }

    /// Attaches the exact record fence a durable record is owned by: its Host
    /// installation epoch, activation identity and activation generation. This
    /// builder writes `installation`, `host_epoch`, `host_lineage`,
    /// `activation_id`, `activation_generation` and `activation_epoch`, so a
    /// later `with_host`, `with_prepared_append`, `with_installation`,
    /// `with_host_epoch` or `with_activation_generation` silently discards the
    /// corresponding value this one wrote. Call it once per chain: it is the
    /// widest contour builder in the vocabulary.
    #[must_use]
    pub(super) fn with_record_fence(mut self, fence: &RecordFence) -> Self {
        self = self.with_host(&fence.host);
        self.activation_id = Some(bound_field(fence.activation_id.as_str()));
        self.activation_generation = Some(bound_field(
            fence.activation_generation.current.lineage_id.as_str(),
        ));
        self.activation_epoch = Some(fence.activation_generation.current.sequence.get());
        self
    }

    /// Attaches the exact activation generation the owner minted or retained.
    /// This builder writes `activation_generation` and `activation_epoch`, so a
    /// later `with_record_fence` or `with_prepared_append` silently discards
    /// the corresponding value this one wrote.
    #[must_use]
    pub(super) fn with_activation_generation(mut self, generation: &EpochTransition) -> Self {
        self.activation_generation = Some(bound_field(generation.current.lineage_id.as_str()));
        self.activation_epoch = Some(generation.current.sequence.get());
        self
    }

    /// Attaches the exact Host epoch sequence the owner already read. This
    /// builder writes `host_epoch`, so a later `with_host`, `with_record_fence`
    /// or `with_prepared_append` silently discards the value this one wrote.
    #[must_use]
    pub(super) const fn with_host_epoch(mut self, host_epoch: u64) -> Self {
        self.host_epoch = Some(host_epoch);
        self
    }

    /// Attaches the exact Host epoch lineage the owner already read.
    #[must_use]
    pub(super) fn with_host_lineage(mut self, lineage: &str) -> Self {
        self.host_lineage = Some(bound_field(lineage));
        self
    }

    /// Attaches the exact durable installation identity the owner was given
    /// before it read its own epoch. This builder writes `installation`, so a
    /// later `with_host`, `with_record_fence` or `with_prepared_append`
    /// silently discards the value this one wrote.
    #[must_use]
    pub(super) fn with_installation(mut self, installation: &str) -> Self {
        self.installation = Some(bound_field(installation));
        self
    }

    /// Attaches the exact supervision lease identity the owner observed.
    #[must_use]
    pub(super) fn with_lease(mut self, lease: &str) -> Self {
        self.lease = Some(bound_field(lease));
        self
    }

    /// Attaches the exact `ORS` receipt digest the owner observed.
    #[must_use]
    pub(super) fn with_ors_receipt(mut self, receipt: &str) -> Self {
        self.ors_receipt = Some(bound_field(receipt));
        self
    }

    /// Attaches the exact independent-supervision publication digest the owner
    /// observed.
    #[must_use]
    pub(super) fn with_watchdog(mut self, publication: &str) -> Self {
        self.watchdog = Some(bound_field(publication));
        self
    }

    /// Attaches the exact Store or activation fence handle the owner compared
    /// against.
    #[must_use]
    pub(super) fn with_fence(mut self, fence: &str) -> Self {
        self.fence = Some(bound_field(fence));
        self
    }

    /// Attaches the owner-issued contour digest the owner observed for this
    /// boundary: an identity the owner already holds, never the configuration
    /// content or any other configuration value it was computed over.
    #[must_use]
    pub(super) fn with_contour(mut self, contour: &str) -> Self {
        self.contour = Some(bound_field(contour));
        self
    }

    /// Attaches the owner-issued mutation digest of the exact restart or
    /// recovery request.
    #[must_use]
    pub(super) fn with_mutation(mut self, digest: &str) -> Self {
        self.mutation = Some(bound_field(digest));
        self
    }

    /// Attaches the owner-computed request digest of the exact request.
    #[must_use]
    pub(super) fn with_request_digest(mut self, digest: &str) -> Self {
        self.request_digest = Some(bound_field(digest));
        self
    }

    /// Attaches the exact Store recovery binding identity this read or fence
    /// is about.
    #[must_use]
    pub(super) fn with_recovery_binding(mut self, binding: &str) -> Self {
        self.recovery = Some(bound_field(binding));
        self
    }

    /// Attaches the closed readiness failure kind the gate retained. The value
    /// is the contract's own frozen name, never free text.
    #[must_use]
    pub(super) const fn with_failure(mut self, failure: &'static str) -> Self {
        self.failure = Some(failure);
        self
    }

    /// Attaches the exact denominator this boundary actually considered.
    #[must_use]
    pub(super) const fn with_cardinality(mut self, cardinality: u64) -> Self {
        self.cardinality = Some(cardinality);
        self
    }

    /// Attaches the exact numerator of that denominator which resolved as
    /// committed.
    #[must_use]
    pub(super) const fn with_committed(mut self, committed: u64) -> Self {
        self.committed = Some(committed);
        self
    }
}

/// Projects the journal owner's own append disposition onto this family's
/// closed vocabulary.
///
/// The journal owner alone decides whether a call committed a new frame or
/// returned the exact existing one; this projection only renames that decision
/// and never re-derives it, so an applied commit and an idempotent replay can
/// never be reported as the same durable append (I14.20).
const fn append_disposition(disposition: AppendDisposition) -> HostJournalDisposition {
    match disposition {
        AppendDisposition::Applied => HostJournalDisposition::CommitApplied,
        AppendDisposition::Replayed => HostJournalDisposition::CommitReplayed,
    }
}

/// Emits one #981 boundary observation through the #889 facade.
///
/// The live Event Log disposition is observed through the facade's canonical
/// bounded helper rather than a discarded probe, then exactly one `INFO`
/// subordinate record carries this owner's frozen boundary literal, its
/// typed disposition, and every identity slot with its own truncation and
/// absence record. When that sink helper cannot carry a Host record it
/// writes its own separate, boundary-free `host.event_log_sink_unavailable`
/// record, so a boundary observation may produce a second record that
/// describes only the standing sink disposition and no owner effect. All
/// macro arguments are precomputed bounded values, so a filtered event
/// evaluates no extra effectful operation. The record is evidence only:
/// it never changes a result, an order, a persistence call, a gate decision
/// or a cleanup step, and it is never a terminal emission.
pub(super) fn observe_host_journal_boundary(observation: &HostJournalObservation) {
    crate::host_diagnostics::note_event_log_sink_status();
    let operation = observation.operation.as_ref();
    let transaction = observation.transaction.as_ref();
    let record_checksum = observation.record_checksum.as_ref();
    let installation = observation.installation.as_ref();
    let host_lineage = observation.host_lineage.as_ref();
    let activation_id = observation.activation_id.as_ref();
    let activation_generation = observation.activation_generation.as_ref();
    let fence = observation.fence.as_ref();
    let mutation = observation.mutation.as_ref();
    let request_digest = observation.request_digest.as_ref();
    let contour = observation.contour.as_ref();
    let lease = observation.lease.as_ref();
    let ors_receipt = observation.ors_receipt.as_ref();
    let watchdog = observation.watchdog.as_ref();
    let recovery = observation.recovery.as_ref();
    crate::host_diagnostics::info!(
        target: crate::host_diagnostics::HOST_DIAGNOSTICS_TARGET,
        event = "host.journal_boundary",
        stage = crate::host_diagnostics::EntrypointStage::Startup.as_str(),
        boundary = observation.boundary,
        disposition = observation.disposition.as_str(),
        operation = operation.map_or("", BoundedField::text),
        operation_bytes = operation.map_or(0, BoundedField::original_bytes),
        operation_truncated = operation.is_some_and(BoundedField::truncated),
        operation_missing = operation.is_none(),
        transaction = transaction.map_or("", BoundedField::text),
        transaction_missing = transaction.is_none(),
        record_checksum = record_checksum.map_or("", BoundedField::text),
        record_checksum_missing = record_checksum.is_none(),
        receipt_sequence = observation.receipt_sequence.unwrap_or(0),
        receipt_sequence_missing = observation.receipt_sequence.is_none(),
        installation = installation.map_or("", BoundedField::text),
        installation_missing = installation.is_none(),
        host_epoch = observation.host_epoch.unwrap_or(0),
        host_epoch_missing = observation.host_epoch.is_none(),
        host_lineage = host_lineage.map_or("", BoundedField::text),
        host_lineage_missing = host_lineage.is_none(),
        activation_id = activation_id.map_or("", BoundedField::text),
        activation_id_missing = activation_id.is_none(),
        activation_generation = activation_generation.map_or("", BoundedField::text),
        activation_generation_missing = activation_generation.is_none(),
        activation_epoch = observation.activation_epoch.unwrap_or(0),
        activation_epoch_missing = observation.activation_epoch.is_none(),
        fence = fence.map_or("", BoundedField::text),
        fence_missing = fence.is_none(),
        mutation = mutation.map_or("", BoundedField::text),
        mutation_missing = mutation.is_none(),
        request_digest = request_digest.map_or("", BoundedField::text),
        request_digest_missing = request_digest.is_none(),
        contour = contour.map_or("", BoundedField::text),
        contour_missing = contour.is_none(),
        lease = lease.map_or("", BoundedField::text),
        lease_missing = lease.is_none(),
        ors_receipt = ors_receipt.map_or("", BoundedField::text),
        ors_receipt_missing = ors_receipt.is_none(),
        watchdog = watchdog.map_or("", BoundedField::text),
        watchdog_missing = watchdog.is_none(),
        recovery = recovery.map_or("", BoundedField::text),
        recovery_missing = recovery.is_none(),
        failure = observation.failure.unwrap_or(""),
        failure_missing = observation.failure.is_none(),
        cardinality = observation.cardinality.unwrap_or(0),
        cardinality_missing = observation.cardinality.is_none(),
        committed = observation.committed.unwrap_or(0),
        committed_missing = observation.committed.is_none(),
        "host journal-family boundary observed"
    );
}

/// F-LOG-HOST-6 (#981) journal-append observation helper.
///
/// The per-file seam of the family's shared vocabulary: it names the journal
/// append boundary set and delegates to the one shared emitter, so the journal
/// family cannot grow a second emission surface or a second terminal.
fn host_journal_observe(observation: &HostJournalObservation) {
    observe_host_journal_boundary(observation);
}

/// Checks every identity that the authoritative Job termination observation
/// can be compared against in the durable Kernel binding.
///
/// The Job API gives us the terminated root process identity, image and Job
/// name.  The durable process record supplies the authority binding that
/// admitted that root: owner, exact PID/start handle and a non-zero authority
/// epoch.  A match on only a non-zero PID (or only the image) would permit a
/// substituted child to be recorded as the previous Kernel.
pub(super) fn exact_termination_binding_matches(
    job: &KernelJobBinding,
    expected_process: &ServiceProcessRecord,
    observed_process_id: u32,
    observed_start_time_100ns: u64,
    observed_image_path: &str,
    observed_job_name: &str,
) -> bool {
    observed_process_id == job.root_pid
        && observed_start_time_100ns == job.root_start_time_100ns
        && observed_image_path == job.root_image_path.as_str()
        && observed_job_name == job.job_name.as_str()
        && expected_process.owner == job.owner.as_str()
        && expected_process.process_id
            == format!("pid:{}:start:{}", job.root_pid, job.root_start_time_100ns)
        && expected_process.authority_epoch.value() != 0
}

pub(super) fn terminated_prior_kernel(
    prior: &KernelRecord,
    terminated: &eliot_platform_windows::TerminatedJobChild,
) -> Result<PriorKernelDisposition, HostError> {
    let job = prior.candidate_job_binding.clone().ok_or_else(|| {
        HostError::OwnerLeaseRecovery("prior Kernel Job binding is absent".to_owned())
    })?;
    let expected_process = prior.process.clone().ok_or_else(|| {
        HostError::OwnerLeaseRecovery("prior Kernel process binding is absent".to_owned())
    })?;
    if !exact_termination_binding_matches(
        &job,
        &expected_process,
        terminated.process().process_id,
        terminated.process().start_time_100ns,
        &terminated.process().image_path,
        terminated.job_identity().name(),
    ) || !terminated.history().complete()
        || !terminated.job_empty()
        || !terminated.root_reaped()
    {
        return Err(HostError::RecoveryRequired(
            "Terminated Kernel evidence does not match exact durable prior binding".to_owned(),
        ));
    }
    let mut process = expected_process;
    process.state = ServiceProcessState::Stopped;
    process.health = HealthVector {
        liveness: HealthDimension::Unknown,
        readiness: HealthDimension::Unknown,
        freshness: HealthDimension::Unknown,
        compatibility: HealthDimension::Unknown,
        integrity: HealthDimension::Unknown,
        capacity: HealthDimension::Unknown,
    };
    Ok(PriorKernelDisposition::Terminated(PriorKernelSource {
        host: prior.fence.host.clone(),
        activation_identity: prior.activation_identity.clone(),
        generation: prior.kernel_generation.clone(),
        job,
        process,
        history_complete: terminated.history().complete(),
        job_empty: terminated.job_empty(),
        root_reaped: terminated.root_reaped(),
    }))
}

/// I1.9 A1 gate: permits a Host-managed Kernel restart only when the valid
/// journal `Kernel` record carries this relaunch's approved artifact and
/// full process lineage for that approval, the journal itself binds the
/// approved config to that exact record, the relaunch config is the approved
/// config, and the record is owned by the current activation fence.
///
/// The record is the original journal recording: it is revalidated with the
/// existing [`KernelRecord::validate`], never replaced by a freshly
/// recomputed checksum over a held copy. The approved artifact bound here is
/// the exact digest the relaunch is about to start; the required lineage is
/// the record's own generation/Job/process binding (`kernel_generation`,
/// `candidate_job_binding`, `process`), which must be present in that same
/// record.
///
/// The approved CONFIG is bound through the journal's own record-bound
/// approval, not through two live values. I1.9 requires the journal to hold
/// "approved artifact/config hashes"; the record that carries the approved
/// config for one exact Kernel record is
/// [`KernelReadinessObservationRecord`], whose `config_digest` is admitted
/// only together with the `active_kernel_record_checksum` of the record that
/// was active when the observation was appended. This gate therefore joins
/// the retained observations to the retained record with the same
/// record-checksum-to-config join the Watchdog lease load already performs:
/// the authorizing record's journal checksum is recomputed from the journal's
/// own record, and the ORIGINAL recorded observation — never a copy of it — is
/// admitted through [`KernelReadinessObservationRecord::validate_against`],
/// which runs that record's own `validate()` and refuses an observation that
/// is not bound to this exact record, fence, Job root and authority epoch.
/// An observation bound to a superseded record, a missing observation, an
/// observation naming a different approved config, or a valid but unrelated
/// current manifest therefore refuses the restart instead of authorizing it.
///
/// The remaining config leg joins the relaunch descriptor to the approved
/// Phase-B config: `materialized_config_digest` (the Phase-B config the
/// relaunch will actually start) must equal `approved_config` (the Phase-B
/// digest the committed activation fence binds to the active manifest),
/// mirroring the Store leg's `approved_config_hash` requirement digest bind.
/// Both config legs therefore read the Phase-B live domain — never the
/// manifest's Phase-A staged-file digest — so the gate stays satisfiable on
/// a normally materialised contour and still refuses live drift. The fence
/// bind requires the record's
/// `RecordFence` to equal the fence recomputed from the current Host
/// installation epoch, activation id and activation generation, so a
/// stale-activation record cannot authorize a restart. Absence, invalidity, an
/// artifact or config mismatch, missing lineage, or a foreign fence refuses
/// the restart as manual recovery instead of reconstructing or approximating
/// state from a live PID or a directory listing.
#[allow(
    clippy::too_many_arguments,
    reason = "the restart join keeps retained approval, record-bound config approval, relaunch descriptor and owner fence explicit so no binding is inferred"
)]
pub(super) fn require_journal_kernel_restart_record(
    current: &KernelRecord,
    readiness_observations: &[KernelReadinessObservationRecord],
    kernel_artifact: &PlatformHandle,
    approved_config: &PlatformHandle,
    materialized_config_digest: &PlatformHandle,
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> Result<(), HostError> {
    current.validate().map_err(|error| {
        HostError::RecoveryRequired(format!(
            "Kernel restart refused: durable Kernel record is invalid ({error}); manual recovery required"
        ))
    })?;
    if current.approved_artifact_hash != *kernel_artifact {
        return Err(HostError::RecoveryRequired(
            "Kernel restart refused: durable Kernel record does not bind the approved relaunch artifact; manual recovery required"
                .to_owned(),
        ));
    }
    if current.candidate_job_binding.is_none() || current.process.is_none() {
        return Err(HostError::RecoveryRequired(
            "Kernel restart refused: durable Kernel record carries no PID/Job lineage for the approved artifact; manual recovery required"
                .to_owned(),
        ));
    }
    if !journal_record_binds_approved_config(current, readiness_observations, approved_config) {
        return Err(HostError::RecoveryRequired(
            "Kernel restart refused: no valid HostStateJournal record binds the approved config to the authorizing Kernel record; manual recovery required"
                .to_owned(),
        ));
    }
    if *approved_config != *materialized_config_digest {
        return Err(HostError::RecoveryRequired(
            "Kernel restart refused: relaunch config is not the approved config; manual recovery required"
                .to_owned(),
        ));
    }
    if current.fence != record_fence(host, activation_id, activation_generation) {
        return Err(HostError::RecoveryRequired(
            "Kernel restart refused: durable Kernel record is not owned by the current activation fence; manual recovery required"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Reports whether the retained journal state binds `approved_config` to
/// `current` as one record-bound approval pair.
///
/// `approved_config` is stated in the Phase-B live domain: the retained
/// observation carries the Phase-B digest admitted at readiness, so the
/// caller resolves the manifest's approval into that domain before calling.
///
/// The binding is proved by the journal's own owner: the authorizing record's
/// journal checksum is recomputed from the record the journal itself retained,
/// and every retained observation is admitted through the existing
/// [`KernelReadinessObservationRecord::validate_against`], which revalidates
/// the ORIGINAL recorded observation and refuses any observation whose
/// recorded `active_kernel_record_checksum`, fence, Job root, process or
/// authority epoch is not this exact record's. A record without such an
/// observation, and an observation that approves a different config, are both
/// unbound — no checksum is recomputed over a held copy of the observation and
/// no approval is inferred from a manifest, a live process or a directory.
fn journal_record_binds_approved_config(
    current: &KernelRecord,
    readiness_observations: &[KernelReadinessObservationRecord],
    approved_config: &PlatformHandle,
) -> bool {
    let Ok(authorizing_checksum) = record_checksum(&HostStateRecord::Kernel(current.clone()))
    else {
        return false;
    };
    readiness_observations.iter().any(|observation| {
        observation
            .validate_against(current, &authorizing_checksum)
            .is_ok()
            && observation.config_digest == *approved_config
    })
}

/// The proven ingress one fresh activation generation is created for.
///
/// I1.5 requires the durable `EliotActivationRecord` to carry the real
/// `trigger_class`, `requester` and `requested_capabilities` of the request
/// that started the contour. The creation append is the only place those fields
/// may be established: `activation_transition` admits no same-state update, so
/// every later value is inherited from the generation's creation record. Writing
/// a fixed spelling here instead would make every generation claim the same
/// ingress regardless of what actually started it.
pub(super) struct ActivationIngress {
    /// Durable I1.5 `trigger_class` spelling of the starting request.
    pub(super) trigger_class: &'static str,
    /// Durable I1.5 `requester_principal_session_or_scheduler` of that request.
    pub(super) requester: String,
    /// Capability requirement the starting request admitted, spelled by the
    /// `ActivationTriggerClass` vocabulary.
    pub(super) capabilities: &'static [&'static str],
}

pub(super) fn initial_activation_record(
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
    state: ActivationState,
    label: &str,
    ingress: &ActivationIngress,
) -> Result<EliotActivationRecord, HostError> {
    let ready = matches!(
        state,
        ActivationState::ControlReady | ActivationState::Active
    );
    let drain_generation = matches!(
        state,
        ActivationState::Draining | ActivationState::StoppedClean
    )
    .then(|| activation_generation.clone());
    if ingress.capabilities.is_empty() {
        return Err(HostError::OwnerLeaseRecovery(format!(
            "activation generation {label} has no proven ingress capability requirement"
        )));
    }
    let mut requested_capabilities = Vec::with_capacity(ingress.capabilities.len());
    for capability in ingress.capabilities {
        let handle = PlatformHandle::new(*capability)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        if !requested_capabilities.contains(&handle) {
            requested_capabilities.push(handle);
        }
    }
    Ok(EliotActivationRecord {
        fence: record_fence(host, activation_id, activation_generation),
        operation: operation(label)?,
        activation_id: activation_id.clone(),
        trigger_class: PlatformHandle::new(ingress.trigger_class)
            .map_err(|error| HostError::Platform(error.to_string()))?,
        trigger_evidence: vec![
            PlatformHandle::new("host-owner-lease-held")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
        requester_principal_session_or_scheduler: PlatformHandle::new(&ingress.requester)
            .map_err(|error| HostError::Platform(error.to_string()))?,
        requested_capabilities,
        candidate_scope: host.installation.clone(),
        state,
        drain_generation,
        lineage: HostKernelStoreLineage {
            host_epoch: host.epoch.current.clone(),
            kernel_epoch: EpochTransition::genesis(fresh_lineage_id()?).current,
            watchdog_epoch: EpochTransition::genesis(fresh_lineage_id()?).current,
            store_generation: EpochTransition::genesis(fresh_lineage_id()?).current,
        },
        readiness: ReadinessEvidence {
            supervision_ready: ready,
            control_ready: ready,
            evidence_refs: vec![
                PlatformHandle::new(if ready {
                    "kernel-ready-receipt-validated"
                } else {
                    "host-lifecycle-not-ready"
                })
                .map_err(|error| HostError::Platform(error.to_string()))?,
            ],
        },
        governance_profile: PlatformHandle::new(if ready {
            "runtime-live-v3"
        } else {
            // I1.5 (#1750): a fresh activation has no verified Watchdog
            // branch yet, so it persists the degraded profile instead of
            // claiming independently supervised live governance. The profile
            // turns live only on a proven-ready transition below.
            "runtime-degraded-v3"
        })
        .map_err(|error| HostError::Platform(error.to_string()))?,
        runtime_lease_refs: Vec::new(),
        supervision_lease_refs: Vec::new(),
        wake_intent_refs: Vec::new(),
        drain_commit_ref: None,
        wake_during_drain_disposition: None,
        boot_session_evidence: vec![
            PlatformHandle::new("host-process-epoch")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
        power_transition_evidence: Vec::new(),
        timestamps: LifecycleTimestamps {
            started_at: (state != ActivationState::Stopped)
                .then(|| fresh_identity("host-started-at"))
                .transpose()?,
            ready_at: ready.then(|| fresh_identity("host-ready-at")).transpose()?,
            draining_at: (state == ActivationState::Draining)
                .then(|| fresh_identity("host-draining-at"))
                .transpose()?,
            stopped_at: (state == ActivationState::StoppedClean)
                .then(|| fresh_identity("host-stopped-at"))
                .transpose()?,
        },
        failure_and_recovery_directive: None,
    })
}

pub(super) fn transition_activation_record(
    current: &EliotActivationRecord,
    state: ActivationState,
    label: &str,
) -> Result<EliotActivationRecord, HostError> {
    let mut next = current.clone();
    next.operation = operation(label)?;
    next.state = state;
    let ready = matches!(
        state,
        ActivationState::ControlReady | ActivationState::Active
    );
    next.readiness.control_ready = ready;
    next.readiness.supervision_ready = ready;
    if state == ActivationState::Starting {
        // A new explicit activation attempt does not inherit readiness or a
        // recovery directive from the stopped/degraded generation. The new
        // attempt must publish fresh evidence before any live transition.
        // Keep one explicit non-live marker because the durable readiness
        // projection requires a non-empty evidence set even while Starting.
        next.readiness.evidence_refs = vec![
            PlatformHandle::new("host-starting-fresh-readiness-required")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ];
        next.timestamps.ready_at = None;
        next.failure_and_recovery_directive = None;
        next.governance_profile = PlatformHandle::new("runtime-degraded-v3")
            .map_err(|error| HostError::Platform(error.to_string()))?;
    }
    // I1.5 (#1750): governance turns live only on a proven-ready transition.
    // On Windows that transition runs after the Watchdog SCM verification and
    // the ProbeReady watchdog-branch gate; other platforms have no
    // independently-supervised readiness (ProbeReady fails closed, I1.7), so
    // the live profile must never be read as an independent-supervision claim
    // there. Any other transition preserves the current profile instead of
    // rewriting history.
    if ready {
        next.governance_profile = PlatformHandle::new("runtime-live-v3")
            .map_err(|error| HostError::Platform(error.to_string()))?;
    }
    if ready {
        next.readiness.evidence_refs = vec![
            PlatformHandle::new("kernel-ready-receipt-validated")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ];
        next.timestamps.ready_at = Some(fresh_identity("host-ready-at")?);
    }
    if state == ActivationState::Draining {
        next.drain_generation = Some(next.fence.activation_generation.clone());
        next.timestamps.draining_at = Some(fresh_identity("host-draining-at")?);
    }
    if state == ActivationState::StoppedClean {
        next.timestamps.stopped_at = Some(fresh_identity("host-stopped-at")?);
        // I1.5 W4 release: a clean stop ends the generation's fenced
        // authority, so the generation releases the runtime-lease references
        // it held. The obligations were snapshotted into the
        // `DrainCommitRecord` at linearization
        // (`drain_commit_record_for_stop`); recovery terminals (`Failed`,
        // `DegradedRecovery`) keep their refs because reconciliation is still
        // owed there.
        next.runtime_lease_refs = Vec::new();
    }
    Ok(next)
}

/// Carries the exact fresh readiness evidence into the activation record.
/// The generic transition helper intentionally remains small for historical
/// callers, while a live supervised transition must not erase the heartbeat
/// receipt that authorized it.
pub(super) fn transition_activation_record_with_evidence(
    current: &EliotActivationRecord,
    state: ActivationState,
    label: &str,
    evidence_refs: &[PlatformHandle],
) -> Result<EliotActivationRecord, HostError> {
    let mut next = transition_activation_record(current, state, label)?;
    if matches!(
        state,
        ActivationState::ControlReady | ActivationState::Active
    ) && !evidence_refs.is_empty()
    {
        next.readiness.evidence_refs = evidence_refs.to_vec();
    }
    Ok(next)
}

/// Projects a live contour loss as an explicit recovery state. The caller
/// supplies the bounded failure reference and recovery directive; this helper
/// only records that fact and never invents a Watchdog-specific cause.
pub(super) fn degraded_activation(
    current: &EliotActivationRecord,
    label: &str,
    failure_ref: &PlatformHandle,
    directive: &str,
) -> Result<EliotActivationRecord, HostError> {
    let mut next = transition_activation_record(current, ActivationState::DegradedRecovery, label)?;
    next.governance_profile = PlatformHandle::new("runtime-degraded-v3")
        .map_err(|error| HostError::Platform(error.to_string()))?;
    next.readiness.evidence_refs = vec![failure_ref.clone()];
    next.timestamps.ready_at = None;
    next.failure_and_recovery_directive = Some(FailureRecoveryDirective {
        failure_ref: failure_ref.clone(),
        recovery_owner: PlatformHandle::new("host-composition")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        directive: PlatformHandle::new(directive)
            .map_err(|error| HostError::Platform(error.to_string()))?,
    });
    Ok(next)
}

/// Single reconcile-decision choke for every `ProductionHostStateJournal` write.
///
/// Both generic `HostStateRecord` appends and readiness-observation appends
/// funnel their `OutcomeUnknown` reconciliation through this helper so the
/// retry/fail-closed policy has exactly one owner. The underlying journal
/// admission stays distinct (`append` rejects readiness observations by
/// design; `append_readiness_observation` enforces the approved contour), but
/// the durable-outcome handling does not fork. Each caller performs its own
/// retry append so its by-value record stays consumed (moved) into the retry
/// instead of only cloned inside a closure.
fn reconcile_unknown_outcome<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    transaction_id: &PlatformHandle,
) -> Result<bool, HostError> {
    match journal.reconcile(transaction_id)? {
        ReconcileOutcome::Committed => {
            let observed = HostJournalObservation::new(
                "host.journal reconcile committed observed",
                HostJournalDisposition::ReconcileCommitted,
            )
            .with_transaction(transaction_id);
            host_journal_observe(&observed);
            Ok(true)
        }
        // I14.21: a proven noncommit and an unresolved outcome are different
        // facts with different recovery behaviour. Both arms stay fail-closed
        // here because that is this owner's existing policy, but the record
        // must never report one as the other.
        ReconcileOutcome::NotCommitted => {
            let observed = HostJournalObservation::new(
                "host.journal reconcile not committed observed",
                HostJournalDisposition::ReconcileNotCommitted,
            )
            .with_transaction(transaction_id);
            host_journal_observe(&observed);
            Err(HostError::Journal(JournalError::OutcomeUnknown {
                transaction_id: transaction_id.clone(),
            }))
        }
        ReconcileOutcome::StillUnknown => {
            let observed = HostJournalObservation::new(
                "host.journal reconcile unknown observed",
                HostJournalDisposition::ReconcileStillUnknown,
            )
            .with_transaction(transaction_id);
            host_journal_observe(&observed);
            Err(HostError::Journal(JournalError::OutcomeUnknown {
                transaction_id: transaction_id.clone(),
            }))
        }
    }
}

pub(super) fn append_reconciled<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    record: HostStateRecord,
) -> Result<AppendReceipt, HostError> {
    host_journal_observe(&HostJournalObservation::new(
        "host.journal append requested",
        HostJournalDisposition::BoundaryReached,
    ));
    match journal.append(record.clone()) {
        Ok(receipt) => {
            // The journal owner decides whether this call committed a new frame
            // or returned the exact existing one; the record names that
            // disposition instead of labelling both a durable append.
            let disposition = append_disposition(receipt.disposition());
            let boundary = match receipt.disposition() {
                AppendDisposition::Applied => "host.journal append durable observed",
                AppendDisposition::Replayed => "host.journal append replay observed",
            };
            let observed =
                HostJournalObservation::new(boundary, disposition).with_receipt(&receipt);
            host_journal_observe(&observed);
            Ok(receipt)
        }
        Err(JournalError::OutcomeUnknown { transaction_id }) => {
            let observed = HostJournalObservation::new(
                "host.journal append outcome unknown observed",
                HostJournalDisposition::ReconcileStillUnknown,
            )
            .with_transaction(&transaction_id);
            host_journal_observe(&observed);
            if reconcile_unknown_outcome(journal, &transaction_id)? {
                // The commit is known; this call only reads the exact original
                // transaction back. Both answers are observed separately, so a
                // failed readback can never read as an unknown commit and never
                // reads as a second append.
                match journal.append(record) {
                    Ok(receipt) => {
                        let observed = HostJournalObservation::new(
                            "host.journal reconcile readback observed",
                            HostJournalDisposition::ReconcileReadbackVerified,
                        )
                        .with_receipt(&receipt);
                        host_journal_observe(&observed);
                        Ok(receipt)
                    }
                    Err(error) => {
                        let observed = HostJournalObservation::new(
                            "host.journal reconcile readback failed observed",
                            HostJournalDisposition::ReconcileReadbackFailed,
                        )
                        .with_transaction(&transaction_id);
                        host_journal_observe(&observed);
                        Err(HostError::Journal(error))
                    }
                }
            } else {
                // Unreachable today: the choke fails closed instead of returning
                // `Ok(false)`. Retained fail-closed so semantics stay identical
                // if the policy ever evolves.
                Err(HostError::Journal(JournalError::OutcomeUnknown {
                    transaction_id,
                }))
            }
        }
        Err(error) => {
            host_journal_observe(&HostJournalObservation::new(
                "host.journal append rejected observed",
                HostJournalDisposition::BoundaryReached,
            ));
            Err(HostError::Journal(error))
        }
    }
}

#[cfg(windows)]
pub(super) fn append_store_rebind_terminal<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    mut record: StoreRebindRecord,
    state: StoreRebindState,
    receipt: Option<&StoreRebindReceipt>,
) -> Result<(), HostError> {
    let observed = HostJournalObservation::new(
        "host.journal rebind terminal requested",
        HostJournalDisposition::BoundaryReached,
    )
    .with_operation(record.operation_id.as_str())
    .with_request_digest(record.request_digest.as_str());
    host_journal_observe(&observed);
    if record.state == state && state == StoreRebindState::Unknown {
        let observed = HostJournalObservation::new(
            "host.journal rebind unknown noop observed",
            HostJournalDisposition::BoundaryReached,
        )
        .with_operation(record.operation_id.as_str())
        .with_request_digest(record.request_digest.as_str());
        host_journal_observe(&observed);
        return Ok(());
    }
    match state {
        StoreRebindState::Committed => {
            let receipt = receipt.ok_or_else(|| {
                HostError::RecoveryRequired(
                    "committed Store rebind disposition has no receipt".to_owned(),
                )
            })?;
            if receipt.operation_id != record.operation_id
                || receipt.request_digest != record.request_digest.as_str()
                || receipt.requirement_digest != record.requirement.as_str()
                || receipt.candidate_binding_digest != record.candidate_binding_digest.as_str()
                || receipt.store_fence != record.store_fence.as_str()
                || receipt.process_binding.process.process_id != record.process_id
                || receipt.process_binding.process.start_time_100ns
                    != record.process_start_time_100ns
                || receipt.process_binding.process.image_path != record.process_image_path.as_str()
                || receipt.process_binding.job != record.job_name
                || receipt.generation.value() != record.generation
                || receipt.authority_epoch.sequence.get() != record.authority_epoch
            {
                return Err(HostError::RecoveryRequired(
                    "Store rebind startup receipt did not match exact journal identity".to_owned(),
                ));
            }
            receipt
                .validate()
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            record.receipt_request_digest = Some(
                PlatformHandle::new(receipt.request_digest.clone())
                    .map_err(|error| HostError::Platform(error.to_string()))?,
            );
            record.receipt_store_fence = Some(
                PlatformHandle::new(receipt.store_fence.clone())
                    .map_err(|error| HostError::Platform(error.to_string()))?,
            );
        }
        StoreRebindState::Aborted | StoreRebindState::Unknown => {
            record.receipt_request_digest = None;
            record.receipt_store_fence = None;
        }
        StoreRebindState::Pending => {
            return Err(HostError::RecoveryRequired(
                "Store rebind terminal helper received Pending".to_owned(),
            ));
        }
    }
    record.state = state;
    record.operation = operation(&format!(
        "store-rebind:{}:{}",
        record.operation_id.as_str(),
        match state {
            StoreRebindState::Committed => "committed",
            StoreRebindState::Aborted => "aborted",
            StoreRebindState::Unknown => "unknown",
            StoreRebindState::Pending => unreachable!(),
        }
    ))?;
    // The rebind owner's own request identity is read before the record is moved
    // into the append. Without it this boundary would carry only the receipt the
    // shared append already recorded for the very same effect, and the two
    // records would differ only in their boundary label.
    let rebind_operation = record.operation_id.clone();
    let rebind_request_digest = record.request_digest.clone();
    let receipt = append_reconciled(journal, HostStateRecord::StoreRebind(record))?;
    let observed = HostJournalObservation::new(
        "host.journal rebind terminal appended",
        append_disposition(receipt.disposition()),
    )
    .with_operation(rebind_operation.as_str())
    .with_request_digest(rebind_request_digest.as_str())
    .with_receipt(&receipt);
    host_journal_observe(&observed);
    Ok(())
}

#[cfg(windows)]
pub(super) fn persist_store_rebind_disposition<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    operation_id: &PlatformHandle,
    request_digest: &str,
    disposition: StoreRebindState,
) -> Result<(), HostError> {
    let observed = HostJournalObservation::new(
        "host.journal rebind disposition requested",
        HostJournalDisposition::BoundaryReached,
    )
    .with_operation(operation_id.as_str())
    .with_request_digest(request_digest);
    host_journal_observe(&observed);
    if !matches!(
        disposition,
        StoreRebindState::Aborted | StoreRebindState::Unknown
    ) {
        return Err(HostError::RecoveryRequired(
            "invalid Store rebind terminal disposition".to_owned(),
        ));
    }
    let record = journal
        .snapshot()?
        .store_rebinds
        .into_iter()
        .find(|record| {
            record.operation_id == *operation_id
                && record.request_digest.as_str() == request_digest
                && matches!(
                    record.state,
                    StoreRebindState::Pending | StoreRebindState::Unknown
                )
        })
        .ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store rebind terminal disposition has no exact pending journal record".to_owned(),
            )
        })?;
    if record.state == StoreRebindState::Unknown && disposition == StoreRebindState::Unknown {
        let observed = HostJournalObservation::new(
            "host.journal rebind unknown noop observed",
            HostJournalDisposition::BoundaryReached,
        )
        .with_operation(record.operation_id.as_str())
        .with_request_digest(record.request_digest.as_str());
        host_journal_observe(&observed);
        return Ok(());
    }
    let mut terminal = record;
    terminal.state = disposition;
    terminal.operation = operation(&format!(
        "store-rebind:{}:{}",
        terminal.operation_id.as_str(),
        match disposition {
            StoreRebindState::Aborted => "aborted",
            StoreRebindState::Unknown => "unknown",
            StoreRebindState::Pending | StoreRebindState::Committed => unreachable!(),
        }
    ))?;
    terminal.receipt_request_digest = None;
    terminal.receipt_store_fence = None;
    let receipt = append_reconciled(journal, HostStateRecord::StoreRebind(terminal))?;
    let observed = HostJournalObservation::new(
        "host.journal rebind disposition appended",
        append_disposition(receipt.disposition()),
    )
    .with_operation(operation_id.as_str())
    .with_request_digest(request_digest)
    .with_receipt(&receipt);
    host_journal_observe(&observed);
    Ok(())
}

/// Builds the I1.5 `DrainCommit` linearization record for Host stop,
/// carrying the Kernel lease/receipt snapshot observed in the journal into
/// `lease_and_pending_operation_snapshot`.
///
/// The snapshot is the exact live authority Host must fence before stopping:
/// the activation's runtime and supervision lease refs, the latest readiness
/// observation's predecessor lease identity and ORS receipt, and every
/// non-terminal store-rebind operation. An empty snapshot is honest only
/// when the journal proves no lease or pending operation remains; callers
/// must not substitute a placeholder. The `drain_generation` correlation
/// binds this commit to the `Requested`/`Draining` records that precede it.
pub(super) fn drain_commit_record_for_stop(
    snapshot: &HostState,
    activation: &EliotActivationRecord,
    drain_generation: &EpochTransition,
) -> Result<DrainCommitRecord, HostError> {
    let mut lease_and_pending: Vec<PlatformHandle> = Vec::new();
    lease_and_pending.extend(activation.runtime_lease_refs.iter().cloned());
    lease_and_pending.extend(activation.supervision_lease_refs.iter().cloned());
    if let Some(readiness) = snapshot.readiness_observations.last()
        && let Some(predecessor) = readiness.active_supervision_lease.as_ref()
    {
        lease_and_pending.push(
            PlatformHandle::new(predecessor.supervision_lease_id.clone())
                .map_err(|error| HostError::Platform(error.to_string()))?,
        );
        lease_and_pending.push(
            PlatformHandle::new(predecessor.ors_receipt_sha256.clone())
                .map_err(|error| HostError::Platform(error.to_string()))?,
        );
    }
    for rebind in snapshot.store_rebinds.iter().filter(|record| {
        matches!(
            record.state,
            eliot_host_state::StoreRebindState::Pending
                | eliot_host_state::StoreRebindState::Unknown
        )
    }) {
        lease_and_pending.push(rebind.operation_id.clone());
    }
    Ok(DrainCommitRecord {
        fence: activation.fence.clone(),
        operation: operation("host-drain-commit")?,
        drain_generation: drain_generation.clone(),
        last_admission_closed_at: fresh_identity("host-admission-closed-at")?,
        lease_and_pending_operation_snapshot: lease_and_pending,
        authority_epochs_fenced: vec![activation.lineage.kernel_epoch.clone()],
        processes_modules_and_store_branches_to_stop: vec![
            PlatformHandle::new("canonical-store-branch")
                .map_err(|error| HostError::Platform(error.to_string()))?,
            PlatformHandle::new("kernel-branch")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
        wake_during_drain_disposition: WakeDisposition::QueueNextGeneration,
        irreversible_stage: PlatformHandle::new("authority-fenced")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        recovery_owner: PlatformHandle::new("host-composition")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        committed_at: fresh_identity("host-drain-committed-at")?,
    })
}

/// Names at most eight residual identities in a refusal; a longer set reports
/// its exact remaining length instead of growing the error without bound.
fn bounded_residual_list(handles: &[PlatformHandle]) -> String {
    const MAX_LISTED: usize = 8;
    let mut text = handles
        .iter()
        .take(MAX_LISTED)
        .map(PlatformHandle::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if handles.len() > MAX_LISTED {
        text.push_str(", and ");
        text.push_str(&(handles.len() - MAX_LISTED).to_string());
        text.push_str(" more");
    }
    text
}

/// Refuses a drain-shutdown clean marker unless the journal proves the exact
/// combination #1686 (I14.23, I1.5 idle-drain steps 6-8) requires before
/// `StoppedClean`: the drain is still `Draining` (never cancelled, failed or
/// stuck pre-commit), the `DrainCommit` linearization is present and bound to
/// this activation fence and drain generation, the covered Kernel record (when
/// present) belongs to this exact activation, no Store rebind operation is
/// left `Pending`/`Unknown`, and every lease ref the activation still names is
/// fenced inside the commit snapshot.
///
/// The gate projects only facts the Host journal itself owns. It is not, and
/// must never be read as, proof of what the journal cannot observe: the Kernel
/// coordinator's own prepared/intentional publication lives kernel-side and
/// has no Host-visible field; live descendant termination (empty Job, reaped
/// root) is enforced by the caller's store-first termination step and
/// re-projected by `terminated_prior_kernel` on the next observe, never by
/// this marker; the sibling Watchdog stop and the Governor-owned
/// checkpoint/flush acknowledgements are separate owners' evidence. A missing
/// piece below therefore refuses the marker as explicit incomplete recovery
/// with the exact residual and safe next action instead of completing a clean
/// shutdown.
fn refuse_clean_marker_without_drain_termination_evidence(
    snapshot: &HostState,
    activation: &EliotActivationRecord,
    drain: &DrainRecord,
) -> Result<(), HostError> {
    if drain.state != DrainState::Draining {
        return Err(HostError::RecoveryRequired(format!(
            "Host drain ended as {:?}, not Draining; a cancelled, failed or unlinearized drain is never a clean stop; re-drive the drain to its commit or recover the degraded contour",
            drain.state
        )));
    }
    let commit = snapshot.drain_commit.as_ref().ok_or_else(|| {
        HostError::RecoveryRequired(
            "Host drain has no DrainCommit linearization for this generation; append the DrainCommit before the clean marker; a pre-commit wake cancels the drain instead of completing it"
                .to_owned(),
        )
    })?;
    if commit.fence != activation.fence || commit.drain_generation != drain.drain_generation {
        return Err(HostError::RecoveryRequired(
            "Host DrainCommit is not bound to this activation fence and drain generation; append the DrainCommit linearization for this exact generation before the clean marker"
                .to_owned(),
        ));
    }
    if let Some(kernel) = snapshot.kernel.as_ref()
        && (kernel.fence.activation_id != activation.activation_id
            || kernel.fence.activation_generation != activation.fence.activation_generation
            || kernel.activation_identity != activation.activation_id)
    {
        return Err(HostError::RecoveryRequired(
            "Host clean marker covers a foreign Kernel contour; reconcile the current generation's Kernel record before claiming this generation clean"
                .to_owned(),
        ));
    }
    let open_rebinds: Vec<PlatformHandle> = snapshot
        .store_rebinds
        .iter()
        .filter(|record| {
            matches!(
                record.state,
                eliot_host_state::StoreRebindState::Pending
                    | eliot_host_state::StoreRebindState::Unknown
            )
        })
        .map(|record| record.operation_id.clone())
        .collect();
    if !open_rebinds.is_empty() {
        return Err(HostError::RecoveryRequired(format!(
            "Store obligations remain without a terminal disposition: {}; reconcile each exact operation through the Store rebind owner before the clean marker",
            bounded_residual_list(&open_rebinds)
        )));
    }
    let unfenced: Vec<PlatformHandle> = activation
        .runtime_lease_refs
        .iter()
        .chain(activation.supervision_lease_refs.iter())
        .filter(|lease| !commit.lease_and_pending_operation_snapshot.contains(*lease))
        .cloned()
        .collect();
    if !unfenced.is_empty() {
        return Err(HostError::RecoveryRequired(format!(
            "Authority remains outside the drain commit snapshot: {}; fence every live lease in the DrainCommit linearization before the clean marker",
            bounded_residual_list(&unfenced)
        )));
    }
    Ok(())
}

pub(super) fn clean_marker_record(
    snapshot: &HostState,
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> Result<HostStateRecord, HostError> {
    let activation = snapshot.activation.as_ref().ok_or_else(|| {
        HostError::RecoveryRequired(
            "Host clean marker has no durable activation for this generation; start or recover the activation contour before claiming a clean stop"
                .to_owned(),
        )
    })?;
    if activation.activation_id != *activation_id
        || activation.fence.activation_generation != *activation_generation
    {
        return Err(HostError::RecoveryRequired(
            "Host clean marker names a superseded activation generation; reconcile the current activation contour before claiming a clean stop"
                .to_owned(),
        ));
    }
    if let Some(drain) = snapshot.drain.as_ref() {
        refuse_clean_marker_without_drain_termination_evidence(snapshot, activation, drain)?;
    }
    Ok(HostStateRecord::CleanMarker(CleanMarker {
        fence: record_fence(host, activation_id, activation_generation),
        operation: operation("host-clean-marker")?,
        manifest: JournalManifest {
            schema_version: JOURNAL_VERSION,
            last_sequence: snapshot.sequence,
            last_checksum: PlatformHandle::new(
                snapshot.last_checksum.as_deref().unwrap_or("GENESIS"),
            )
            .map_err(|error| HostError::Platform(error.to_string()))?,
        },
        shutdown_evidence_refs: vec![
            PlatformHandle::new("host-owner-release-fenced")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
    }))
}

#[cfg(test)]
pub(super) fn append_clean_marker<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> Result<(), HostError> {
    let fence = record_fence(host, activation_id, activation_generation);
    let observed = HostJournalObservation::new(
        "host.journal clean marker requested",
        HostJournalDisposition::BoundaryReached,
    )
    .with_record_fence(&fence);
    host_journal_observe(&observed);
    let snapshot = journal.snapshot()?;
    append_reconciled(
        journal,
        clean_marker_record(&snapshot, host, activation_id, activation_generation)?,
    )?;
    Ok(())
}

/// Digest of the immutable installer identity that a fresh Host journal
/// activation must carry before it can be reconciled.  The journal does not
/// become an authority source: this binding is written into the new
/// Starting/ControlReady contour after a crash and never turns historical
/// Active evidence into live process proof.
pub(super) fn pending_activation_binding(
    pending: &eliot_installation::PendingActivation,
) -> Result<PlatformHandle, HostError> {
    let digest = sha256_json(&(
        "pending-activation-binding-v2",
        &pending.transaction_id,
        &pending.plan_digest,
        &pending.manifest.generation,
        &pending.config_digest,
        &pending.kernel_artifact_digest,
        &pending.store_bridge_artifact_digest,
        &pending.canonical_store_artifact_digest,
        &pending.host_executable_path,
        &pending.host_artifact_digest,
        &pending.runtime_state_roots_digest,
        &pending.manifest_digest,
        pending
            .phase_b_prepared
            .as_ref()
            .map(|prepared| &prepared.prepared_digest),
    ))?;
    PlatformHandle::new(format!("pending-activation-binding:{digest}"))
        .map_err(|error| HostError::Platform(error.to_string()))
}

#[cfg(test)]
pub(super) fn test_activation_ingress() -> ActivationIngress {
    ActivationIngress {
        trigger_class: crate::activation_lifecycle::ActivationTriggerClass::AgentBridgeAttach
            .as_str(),
        requester: "test-requester".to_owned(),
        capabilities: crate::activation_lifecycle::control_contour_capabilities(),
    }
}

#[cfg(test)]
mod governance_profile_tests {
    use super::super::{fresh_host_epoch, root_epoch};
    use super::*;

    #[test]
    fn fresh_activation_stays_degraded_until_ready_is_proven() -> Result<(), HostError> {
        let installation = PlatformHandle::new("installation:test")
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let host = fresh_host_epoch(installation, None)?;
        let activation_id = fresh_identity("governance-activation")?;
        let activation_generation = root_epoch(fresh_lineage_id()?);
        let starting = initial_activation_record(
            &host,
            &activation_id,
            &activation_generation,
            ActivationState::Starting,
            "host-open",
            &test_activation_ingress(),
        )?;
        assert_eq!(starting.governance_profile.as_str(), "runtime-degraded-v3");
        let active =
            transition_activation_record(&starting, ActivationState::Active, "host-active")?;
        assert_eq!(active.governance_profile.as_str(), "runtime-live-v3");
        Ok(())
    }
}
