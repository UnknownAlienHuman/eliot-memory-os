//! Production N4 Governor composition contracts.
//!
//! The daemon owns one value of [`GovernorComposition`].  This module only
//! composes pure Governor projections and the neutral Kernel transition port;
//! it does not open a store, construct a provider adapter, execute a process,
//! or infer readiness from a local fallback.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use self::authority_recovery::map_transition_receipt_error;
use crate::activation_outcome::{
    GovernorActivationOutcome, GovernorCandidateCoverage, GovernorRetryDirective,
    GovernorSelectionDirective,
};
use crate::canonical_projections::{
    GovernorProjectionError, compose_canonical_projections, emit_canonical_projection_set,
};
use crate::controlboard_projection::{
    ControlBoardGovernorSnapshot, ControlBoardProjectionParts, compile_controlboard_snapshot,
};
use crate::finish_attempt::{
    PreparedFinishDecision, PreparedKernelExchange, current_plan_envelope,
};
use crate::migration_inventory::PRODUCT_PROOF_PLAN;
use crate::negative_memory_gate::{
    self, NegativeMemoryGateDecision, NegativeMemoryGateInput, evaluate_negative_memory_gate,
};
use crate::negative_memory_probe::{
    NegativeMemoryProbeExecutor, admit_negative_memory_probe, execute_negative_memory_probe,
};
use crate::observation_reconciliation::GovernorObservationReconciliation;
use crate::operator_reconciliation::GovernorOperatorReconciliation;
use crate::owner_closure_feed::{
    OwnerPublishPort, synchronize_owner_feed, synchronize_owner_feed_with_canonical_receipts,
    synchronize_owner_feed_with_quarantine_evidence,
};
use crate::owner_projection_refresh::{coherence_result, compare_scope_heads};
use crate::problem_owner_transitions::ProblemOwnerAuthorizationRefusal;
use crate::scan_disclosure_owner::{InstallationScanContour, InstallationScanDisclosureStore};
use crate::scope_identity_admission::{ensure_snapshot_fresh, require_fresh_matched_binding};
use crate::skill_lifecycle::GovernorSkillLifecycle;
use crate::task_lifecycle::GovernorTaskLifecycle;
use crate::{
    FinishAttemptError, Governor, GovernorConfig, GovernorFinishAttempt, GovernorState,
    QueueLimits, STARTUP_ORDER, ServiceId, ServiceObservation,
};
use eliot_authority::{
    CrossRootQuarantineEvidence, GrantActivationRequest, GrantId, GrantRevocationRequest,
    GrantStatus, IntroductionActivationRequest, IntroductionId, IntroductionRevocationRequest,
    IntroductionStatus, P07AuthorityPort, P07PortError, RevocationOperationIdentity,
    RevocationOrigin, RevocationTransitionDisposition, RevocationTransitionRequest,
    RootTransitionActivationReceipt, RootTransitionActivationRequest,
};
use eliot_budget::{BudgetLedger, BudgetLedgerRecoverySnapshot};
use eliot_canonical::{
    AcceptanceCoverage, CanonicalError, CanonicalWriteEnvelope, FinishAttemptDraft,
    FinishDecisionOutcome, FinishEvidence,
};
use eliot_change_monitor::ChangeMonitor;
use eliot_config::ConfigPolicySnapshot;
use eliot_context_contracts::{CanonicalProjectionSet, ContextBinding};
use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractVersion, EpochId, OperationId,
    ResourceGeneration, SessionId, StateFence, TaskId, canonical_json_bytes, fences_match_exact,
    sha256_hex,
};
use eliot_coordination::{
    ActiveWorkLeaseProjection, ActiveWorkLeaseSelection, CoordinationError, CoordinationOwner,
};
use eliot_diagnostic::{
    CONTRACT_NAME as DIAGNOSTIC_CONTRACT, DiagnosticClassifier, DiagnosticEvent, DiagnosticInput,
    DiagnosticSeverity, DiagnosticStatus,
};
use eliot_evaluation_contracts::{TerminalVerifierBinding, VerifierEvidenceRef};
use eliot_finish::{
    DescendantClosure, FinishDecisionReceipt, FinishError, FinishLifecycleAction, FinishService,
};
use eliot_influence::RevocationBounds;
use eliot_instrument_api::{
    CaptureProvenance, EvidenceAxes, EvidenceCoverage, EvidenceFreshness, ExecutionStatus,
    InstrumentInvocation, InstrumentKind, NormalizedEvidence, RawEvidence, RawEvidenceSource,
    VerificationOutcome, VerificationRun, WorkscopeIdentity,
};
use eliot_instrument_nextest::{
    NextestTestEvent, NextestTestStatus, catalog_test_id, parse_test_events,
};
use eliot_maintenance::{
    AutomationDecision, AutomationTriggerDecision, MaintenanceController, MaintenanceError,
    MaintenanceFamily, MaintenanceJob, MaintenanceJobState, MaintenanceStateStore,
    RefusedReceiptStatus, maintenance_decision_ref,
};
use eliot_module_registry::ModuleCatalog;
use eliot_module_registry::ModuleCatalogSnapshot;
use eliot_observation::{ObservationJournal, ObservationJournalEntry};
use eliot_ors::{
    ColdStartReadinessClaim, ColdStartReadinessOrsRecord, ColdStartReadinessOwnerKey,
    ColdStartReadinessRecordOwner, ColdStartReadinessStageOutcome,
    ColdStartReadinessTerminalDisposition, ScanDisclosureRecordOwner,
};
use eliot_protocol::RequestIdentity;
use eliot_receipts::{GrantClosureReceipt, ReceiptIdentity};
use eliot_runtime_contracts::{
    AuthorityActivationReceipt, AuthorityRevocationReceipt, AuthorityState, RuntimeLease,
};
use eliot_security_contracts::{PrivacyClass, RevocationReason};
use eliot_session::{SessionLifecycleOwner, SessionLifecycleSnapshot, SessionState};
use eliot_skill::{SkillLifecycleView, SkillRegistry};
use eliot_store_api::{
    CanonicalReadClient, OrderingHeadExpectation, PreparedTransition, ProblemOwnerTransition,
    RevisionHeadExpectation, ScopeRevisionView, StoreHealth, TaskContractAcceptanceSet,
    WriteReceipt,
};
use eliot_task::{TaskLifecycleOwner, TaskLifecycleSnapshot, TaskRecord, TaskState};
use eliot_testd_core::{
    JobState, RawArtifactStream, ReceiptBinding, TestJob, TestdSourceObservation,
    TestdSourceObservationRange, TestdStore, TestdTerminalCompletionEvidence, VerificationReceipt,
};
use eliot_workscope::{
    AuthorityBasis, BootstrapScanEvidence, BootstrapScanOutcome, BootstrapScanner,
    ColdStartController, ColdStartTrigger, DiscoveryLeaseKey, DiscoveryReadLease,
    GenerationEvidence, GoverningSourceAdmission, GoverningSourceSet, GuardTrigger, GuardVerdict,
    IdentityEvidence, IdentityLegOutcome, LeaseJoin, LooseScanQuarantine, MaterialAdmission,
    MaterialReadinessDirective, MaterialReadinessInputs, ObservedScopeResources, OnboardingLease,
    PrivacyBoundary, PrivacyProfile, QuarantinedScopeRecord, ReadinessLifecycle,
    RepositoryLineageIdentity, RequestedEffect, ResolutionAuthentication, ResolutionRequest,
    ScanDisclosureOwnerBinding, ScanReceiptHandle, ScannerResolverInputs, ScopeBinding,
    ScopeBindingDisposition, ScopeBindingGuard, ScopeIdentity, ScopeKind,
    ScopeRelocationOrAttachReceipt, ScopeResolution, SourceAdmissionRequest, TaskBindingInput,
    TaskBindingState, TaskIntakeCandidate, TaskSelectionRequired, TriggerAdmission, TriggerReport,
    WorkScopeBindingOwner, WorkScopeBindingSnapshot, WorkScopeCandidate, WorkScopeCandidateSet,
    WorkScopeDescriptor, WorkScopeError, WorkScopeResolutionReceipt, WorkScopeResolver,
    WorkspaceInstanceIdentity, admit_at_trigger, admit_initial_binding, check_at_trigger,
    evaluate_material_request, issue_resolution_receipt, produce_attach_receipt,
    rebind_with_receipt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

#[path = "authority_recovery.rs"]
mod authority_recovery;
pub use authority_recovery::{
    AuthorityOwner, AuthorityOwnerSnapshot, AuthorityPresentationState, AuthorityRestoreOutcome,
    PresentedAuthorityRequest, RetainedAuthorityRequest,
};
#[path = "authority_revocation.rs"]
mod authority_revocation;
pub use authority_revocation::{
    AUTHORITY_REVOCATION_KERNEL_FIRST_REASON, authority_revocation_envelope,
    authority_revocation_envelope_from_closure, canonical_receipt_identity,
    decode_revocation_history_evidence, revocation_history_read_request,
};
#[path = "genesis_owner_packet.rs"]
mod genesis_owner_packet;
pub use genesis_owner_packet::GovernorGenesisPacket as GovernorGenesisRequest;
pub use genesis_owner_packet::{
    GOVERNOR_GENESIS_PACKET_SCHEMA, GOVERNOR_GENESIS_PACKET_VERSION, GovernorGenesisOwnerRecord,
    GovernorGenesisPacket,
};
#[path = "native_worker_binding.rs"]
mod native_worker_binding;
pub use native_worker_binding::{
    NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_ID, NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_VERSION,
    NativeWorkerExecutableBinding, NativeWorkerLifecycleBinding, process_invocation_digest_for,
};

/// Canonical write result kept together with the negative-memory decision
/// that admitted that exact request.
///
/// The decision is returned rather than discarded so the caller's action
/// response can reference the same rule revision the effect was admitted
/// under, instead of restating it from its own memory of the request.
#[derive(Clone, Debug)]
pub struct NegativeMemoryGatedCommit {
    /// The canonical receipt for the committed request.
    pub receipt: WriteReceipt,
    /// The exact bound decision used immediately before dispatch.
    pub decision: NegativeMemoryGateDecision,
}

/// Measures the gate input against the canonical request it is gating.
///
/// These are content comparisons, not shape checks. The gate's request fence
/// must be the envelope's own request fence; the store-observed read fence must
/// equal that same fence, so the read is measured against this operation rather
/// than merely existing; and the read must have been addressed to the scope
/// this write addresses, so a snapshot resolved in another scope cannot be
/// presented as this request's rule set.
///
/// # Errors
///
/// Returns [`CompositionError::Recovery`] naming the exact binding that does
/// not hold. No canonical commit is attempted.
pub fn bind_gate_to_request(
    gate: &NegativeMemoryGateInput<'_>,
    envelope: &CanonicalWriteEnvelope,
) -> Result<(), CompositionError> {
    if gate.state_fence != &envelope.request.state_fence {
        return Err(CompositionError::Recovery(
            "negative-memory gate: the gate request fence is not this write's request fence"
                .to_owned(),
        ));
    }
    if gate.resolved.store_observed_fence() != &envelope.request.state_fence {
        return Err(CompositionError::Recovery(
            "negative-memory gate: the store-observed read fence is not this write's request fence"
                .to_owned(),
        ));
    }
    if gate.resolved.scope_id() != &envelope.scope_id {
        return Err(CompositionError::Recovery(
            "negative-memory gate: the rule read was addressed to a different scope than this write"
                .to_owned(),
        ));
    }
    Ok(())
}

/// The only application write port exposed to the daemon.
///
/// The port accepts a Canonical-produced [`PreparedTransition`] and carries
/// it to the authenticated Kernel generation.  It deliberately does not
/// expose a store client, query surface, provider SDK, or completion API.
pub trait KernelTransitionPort: Send + Sync {
    /// Applies one prepared transition under the exact admitted request
    /// identity. The identity carries the original caller/fence binding plus
    /// the admitted idempotency, deadline and cancellation terms; the port
    /// must forward those terms unchanged and never synthesize defaults.
    fn apply_prepared<'a>(
        &'a self,
        identity: &RequestIdentity,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> KernelPortFuture<'a, WriteReceipt>;

    /// Reconciles one operation by its exact canonical identity.
    fn receipt(&self, operation_id: OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>>;

    /// Returns a bounded Kernel-owned health observation.
    fn health(&self) -> KernelPortFuture<'_, StoreHealth>;

    /// Reads the exact current Task Controller source heads used as CAS
    /// expectations for one recipe-bearing task transition. Implementations
    /// that do not expose the campaign source read route fail closed; no
    /// transition may guess `None` for an existing head.
    fn campaign_source_heads(
        &self,
        _task_id: &TaskId,
        _scope_id: &str,
        _state_fence: &StateFence,
    ) -> KernelPortFuture<'_, crate::campaign_task_sources::TaskControllerCampaignSourceHeads> {
        Box::pin(async {
            Err(KernelPortError::NotAdmitted(
                "Task Controller campaign source-head read is not admitted".to_owned(),
            ))
        })
    }

    /// Reads the contract owner's exact `TaskContract` acceptance-item
    /// enumeration for one task at one task revision under the exact fence
    /// (issue #1741, I7.9).
    ///
    /// I7.9 requires the Finish service to rehydrate the current
    /// `TaskContract` and its acceptance items. This read is the only route
    /// that can produce them: the canonical plan enumerates the obligations a
    /// plan *declares*, and the task-selection evidence states an acceptance
    /// identity that is caller-stated at intake, so neither is an enumeration
    /// the contract owner issued.
    ///
    /// Implementations must forward the exact task id, the exact task revision,
    /// and the exact fence unchanged, and must return the owner's own
    /// committed set. Implementations that do not expose this route fail
    /// closed; no consumer may synthesize the denominator locally, guess an
    /// empty obligation set, or fall back to the plan's own list.
    fn task_contract_acceptance_set(
        &self,
        _task_id: &TaskId,
        _task_revision: u64,
        _state_fence: &StateFence,
    ) -> KernelPortFuture<'_, TaskContractAcceptanceSet> {
        Box::pin(async {
            Err(KernelPortError::NotAdmitted(
                "TaskContract owner acceptance-set read is not admitted".to_owned(),
            ))
        })
    }
}

/// Object-safe future returned by a neutral Kernel transition port.
pub type KernelPortFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, KernelPortError>> + Send + 'a>>;

/// Typed failure at the neutral Kernel port.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum KernelPortError {
    /// The authenticated generation is stale or inconsistent with the request.
    #[error("Kernel generation contract mismatch: {0}")]
    Contract(String),
    /// The Kernel could not establish an outcome at the boundary.
    #[error("Kernel transition outcome is unknown: {0}")]
    Unknown(String),
    /// The authenticated Kernel generation is not currently admitted.
    #[error("Kernel generation is not admitted: {0}")]
    NotAdmitted(String),
}

/// The proved canonical second phase of one grant closure, carried across the
/// process boundary in transport-neutral types.
///
/// The daemon composition root does not depend on `eliot-ors` and must never
/// gain it (the Kernel owns ORS inside the Kernel process, so the daemon has
/// to reach the link through the authenticated transport). This record is
/// therefore the port's return type instead of an in-process ORS projection:
/// it names exactly the two facts the reconciliation proof reads — the
/// ORIGINAL committed first-phase closure row and the exact Store-issued
/// canonical receipt identity durably linked to it — and both are re-served
/// verbatim from the owner's own committed bytes. No digest is recomputed and
/// no field is re-derived here or by any implementor.
///
/// The link is mandatory, not optional: the durable second phase either exists
/// and is returned, or the implementor answers `Err`. An absent link is an
/// unestablished outcome, so a type that could carry "no link" as a success
/// value would be a fabricated receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantClosureSecondPhaseLink {
    /// The ORIGINAL committed first-phase closure row, served verbatim. The
    /// first-phase bytes are never rewritten by the second phase.
    closure: GrantClosureReceipt,
    /// The exact Store-issued canonical receipt identity durably linked to
    /// `closure` by this call.
    canonical_receipt: ReceiptIdentity,
}

impl GrantClosureSecondPhaseLink {
    /// Binds the ORIGINAL committed first-phase closure to the exact durable
    /// canonical receipt linked against it.
    ///
    /// An implementor MUST pass the owner's verbatim committed closure and the
    /// owner's verbatim linked receipt identity. It is not a constructor for an
    /// unrecorded link: a first phase that did not commit, or a link the owner
    /// does not hold, is a typed [`KernelPortError`], never a value here.
    pub fn new(closure: GrantClosureReceipt, canonical_receipt: ReceiptIdentity) -> Self {
        Self {
            closure,
            canonical_receipt,
        }
    }

    /// Returns the ORIGINAL committed first-phase closure the link was recorded
    /// against. The caller compares its `operation_id` and `declaration` by
    /// content against the closure it read back, never by shape.
    pub const fn closure(&self) -> &GrantClosureReceipt {
        &self.closure
    }

    /// Returns the exact durable canonical second-phase receipt link.
    pub const fn canonical_receipt(&self) -> &ReceiptIdentity {
        &self.canonical_receipt
    }
}

/// Narrow durable boundary for the canonical second phase of a grant
/// closure. The Kernel-side adapter must delegate this call to
/// `eliot_ors::OperationalRecoveryStore::link_grant_closure_canonical_receipt`;
/// Governor never edits the first-phase closure row.
///
/// Like [`GrantClosureReceiptPort`], this port is transport-neutral: every type
/// in its signature is reachable from a daemon-side dependency set that holds
/// no in-process ORS, so the saga arm that records the canonical second phase
/// is implementable by the process that owns the decision. `operation_id` is
/// the ORIGINAL closure operation identity string already recorded in the
/// first-phase [`GrantClosureReceipt`]; an adapter that needs a typed ORS
/// operation identity constructs it from these exact bytes at the boundary
/// that calls the store, which is where that validation belongs.
pub trait GrantClosureCanonicalLinkPort: Send + Sync {
    /// Links the exact Store-issued `ReceiptIdentity` to the immutable
    /// first-phase closure operation, and returns the proved read-back so the
    /// caller re-checks it instead of taking the owner's word for it.
    ///
    /// Returns a typed [`KernelPortError`] when the first phase has not
    /// committed for `operation_id`, when the link conflicts with an existing
    /// one, or when the owner's read-back does not bind the presented receipt.
    fn link_grant_closure_canonical_receipt(
        &self,
        operation_id: &str,
        canonical_receipt: &ReceiptIdentity,
    ) -> Result<GrantClosureSecondPhaseLink, KernelPortError>;
}

/// Readback boundary for the durable closure committed by the first P-07
/// phase. A caller-provided closure is not accepted by the reconciliation
/// method; the Kernel/ORS adapter must return the exact committed receipt.
pub trait GrantClosureReceiptPort: Send + Sync {
    /// Reads the committed closure for the exact revocation request.
    fn grant_closure_receipt(
        &self,
        request: &GrantRevocationRequest,
    ) -> Result<GrantClosureReceipt, KernelPortError>;
}

/// The exact post-Kernel phase of a grant revocation whose canonical handoff
/// did not complete.
///
/// The Kernel/ORS first phase has already committed and fenced the target by
/// the time any of these is observed, so the phase names only what is still
/// missing from the canonical side. It is an honest-progress marker, never a
/// weakening: an unresolved phase leaves the revocation strictly stronger
/// than any right, and it never authorizes reminting a grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalRevocationPhase {
    /// The durable closure read-back did not return the exact revoked closure
    /// bound to the presented request, snapshot and fence.
    ClosureReadback,
    /// The canonical Store commit of the revocation envelope did not complete.
    CanonicalCommit,
    /// The ORS second-phase link of the Store-issued canonical receipt did not
    /// complete or did not read back binding this closure operation.
    SecondPhaseLink,
}

/// One Kernel-first grant revocation whose canonical second phase is pending.
///
/// Retained when — and only when — the Kernel/ORS first phase committed and
/// its receipt validated, so the record can never be weaker than the
/// mechanical fence it follows. It names the exact target grant, the exact
/// snapshot the Kernel receipt bound, the exact Kernel-issued revocation
/// identity, and the phase that has not completed.
///
/// This is the "visible stricter revocation intent" the asymmetric saga
/// requires when the canonical writer cannot accept the handoff: the
/// composition keeps reporting the grant as revoked and keeps refusing to
/// activate it, instead of restoring the right so a store can be made to
/// agree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingCanonicalRevocation {
    /// Exact fenced target grant identity.
    pub grant_id: String,
    /// Exact snapshot the Kernel-issued revocation receipt was bound to.
    pub snapshot_id: String,
    /// Exact Kernel-issued revocation identity that already took effect.
    pub revocation_id: String,
    /// The canonical phase that has not completed.
    pub phase: CanonicalRevocationPhase,
}

/// The admitted canonical identity one grant-revocation saga commits under.
///
/// The operation identity, the canonical operation id and the canonical
/// request identity are one indivisible admission: they are composed together
/// by the caller from admitted ingress and are never derived from the durable
/// closure. They travel as one value so the prepare step cannot be handed a
/// mixture of two different operations.
#[derive(Clone, Copy, Debug)]
struct CanonicalRevocationCommit<'a> {
    canonical_operation_id: &'a OperationId,
    canonical_request_identity: &'a RequestIdentity,
    operation: &'a RevocationOperationIdentity,
}

/// Internal carrier for a canonical-phase refusal: which phase failed and the
/// typed error to report. Never surfaced directly; the composition retains the
/// matching [`PendingCanonicalRevocation`] first.
struct PendingCanonicalHandoff {
    phase: CanonicalRevocationPhase,
    error: CompositionError,
}

/// Explicit Kernel-owned recovery route used before Governor readiness.
///
/// The route is deliberately split into closed operations so a production
/// adapter must perform the owner named reads, canonical head read, receipt
/// replay read, and durable-job read.  A digest in launch.json cannot
/// substitute for any one of these operations.
pub trait KernelRecoveryPort: Send + Sync {
    /// Reads one fixed owner projection under the exact fence and handoff.
    fn named_read(
        &self,
        request: KernelNamedReadRequest,
    ) -> Result<Option<KernelNamedReadReply>, KernelPortError>;

    /// Atomically seeds the complete Governor genesis owner set through the
    /// Canonical→Kernel→Store path.  Implementations must return success only
    /// for an idempotent all-absent genesis state; partial/unknown state must
    /// fail closed and never be filled locally.
    fn initialize_governor_genesis(
        &self,
        request: &GovernorGenesisRequest,
    ) -> Result<(), KernelPortError>;

    /// Reads the canonical revision and ordering heads.
    fn canonical_scope(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<ScopeRevisionView, KernelPortError>;

    /// Reads terminal receipts used for exact replay/reconciliation.
    fn receipts(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Vec<WriteReceipt>, KernelPortError>;

    /// Reads all durable application jobs and their current revisions.
    fn durable_jobs(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Vec<MaintenanceJob>, KernelPortError>;
}

/// Explicit Kernel-owned service observation route used after owner recovery.
///
/// Service observations are runtime admission evidence, not durable Governor
/// owner state. Keeping this route separate prevents them from being folded
/// into the owner recovery snapshot or its diagnostic digest.
pub trait KernelServiceObservationPort: Send + Sync {
    /// Reads the ordered Governor service observations under the exact fence.
    fn services(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Vec<KernelServiceRecovery>, KernelPortError>;
}

/// Explicit durable-job persistence route retained by the one Maintenance
/// owner.  It is not an in-memory fallback and cannot be replaced by a second
/// scheduler or a direct store adapter in `eliotd`.
pub trait KernelDurableJobPort: Send + Sync {
    /// Loads one exact job identity from the Kernel-owned durable job ledger.
    fn load_durable_job(
        &self,
        job_id: &str,
        state_fence: &StateFence,
    ) -> Result<Option<MaintenanceJob>, KernelPortError>;

    /// Persists one validated job revision in the Kernel-owned durable ledger.
    fn save_durable_job(&self, job: &MaintenanceJob) -> Result<(), KernelPortError>;
}

/// Exact authenticated Kernel snapshot expected by N4.
///
/// `artifact_digest`, `protected_snapshot_digest`, and `principal` are all
/// part of the identity.  Matching only generation/epoch is insufficient for
/// a replaceable local service.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGenerationSnapshot {
    /// Fixed Kernel service identity.
    pub service: String,
    /// Exact negotiated protocol string.
    pub protocol: String,
    /// Active resource generation.
    pub generation: ResourceGeneration,
    /// Active authority epoch.
    pub authority_epoch: EpochId,
    /// SHA-256 of the admitted Kernel artifact.
    pub artifact_digest: String,
    /// SHA-256 of the protected full handoff snapshot.
    pub protected_snapshot_digest: String,
    /// Authenticated Kernel principal identity.
    pub principal: String,
}

impl KernelGenerationSnapshot {
    /// Validates the closed snapshot shape.
    pub fn validate(&self) -> Result<(), KernelPortError> {
        for (value, field) in [
            (&self.service, "service"),
            (&self.protocol, "protocol"),
            (&self.artifact_digest, "artifact_digest"),
            (&self.protected_snapshot_digest, "protected_snapshot_digest"),
            (&self.principal, "principal"),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(KernelPortError::Contract(format!(
                    "{field} must be non-blank and free of controls"
                )));
            }
        }
        for (value, field) in [
            (&self.artifact_digest, "artifact_digest"),
            (&self.protected_snapshot_digest, "protected_snapshot_digest"),
        ] {
            if value.len() != 64
                || value
                    .bytes()
                    .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(KernelPortError::Contract(format!(
                    "{field} must be a lowercase SHA-256 digest"
                )));
            }
        }
        if self.generation.value() == 0 {
            return Err(KernelPortError::Contract(
                "generation and authority_epoch must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the exact state fence represented by this snapshot.
    #[must_use]
    pub fn state_fence(&self) -> StateFence {
        StateFence::new(self.authority_epoch.clone(), self.generation)
    }
}

/// Exact snapshot expected from the Host-approved launch handoff.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGenerationExpectation {
    /// Expected Kernel service identity.
    pub service: String,
    /// Expected negotiated protocol.
    pub protocol: String,
    /// Expected artifact digest.
    pub artifact_digest: String,
    /// Expected protected snapshot digest.
    pub protected_snapshot_digest: String,
    /// Expected authenticated principal.
    pub principal: String,
    /// Expected resource generation.
    pub generation: ResourceGeneration,
    /// Expected authority epoch.
    pub authority_epoch: EpochId,
}

impl KernelGenerationExpectation {
    /// Converts an authenticated snapshot into a fixed expectation.
    pub fn from_snapshot(snapshot: &KernelGenerationSnapshot) -> Result<Self, KernelPortError> {
        snapshot.validate()?;
        Ok(Self {
            service: snapshot.service.clone(),
            protocol: snapshot.protocol.clone(),
            artifact_digest: snapshot.artifact_digest.clone(),
            protected_snapshot_digest: snapshot.protected_snapshot_digest.clone(),
            principal: snapshot.principal.clone(),
            generation: snapshot.generation,
            authority_epoch: snapshot.authority_epoch.clone(),
        })
    }

    /// Rejects every identity or fence mismatch before composition.
    pub fn admits(&self, observed: &KernelGenerationSnapshot) -> Result<(), KernelPortError> {
        observed.validate()?;
        if self.service != observed.service
            || self.protocol != observed.protocol
            || self.artifact_digest != observed.artifact_digest
            || self.protected_snapshot_digest != observed.protected_snapshot_digest
            || self.principal != observed.principal
            || self.generation != observed.generation
            || !self
                .authority_epoch
                .is_same_authority(&observed.authority_epoch)
        {
            return Err(KernelPortError::Contract(
                "observed Kernel snapshot does not match Host-approved expectation".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Fixed owner names used for duplicate-owner detection and recovery binding.
pub const OWNER_IDS: [&str; 16] = [
    "work_scope",
    "task",
    "session",
    "canonical",
    "authority",
    "budget",
    "config",
    "coordination",
    "finish",
    "problem",
    "observation",
    "read",
    "skill",
    "module_registry",
    "maintenance",
    "change_monitor",
];

/// Versioned payload schema for every named owner read.
pub const OWNER_SNAPSHOT_SCHEMA: &str = "eliot.governor.owner.snapshot.v1";
/// Bounded payload size accepted from the Kernel recovery route.
pub const MAX_OWNER_SNAPSHOT_BYTES: usize = 512 * 1024;

/// Closed owner selector for Kernel-backed named recovery reads.
///
/// The selector is intentionally not a free-form string.  A Kernel adapter
/// must implement every owner read in this set before the daemon can become
/// ready; an omitted owner is a recovery failure rather than an empty local
/// default.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOwner {
    /// `WorkScope` projection.
    WorkScope,
    /// Task projection.
    Task,
    /// Session projection.
    Session,
    /// Canonical projection.
    Canonical,
    /// Authority projection.
    Authority,
    /// Budget projection.
    Budget,
    /// Config projection.
    Config,
    /// Policy projection (optional; served independently of [`RecoveryOwner::ALL`]).
    Policy,
    /// Coordination projection.
    Coordination,
    /// Finish projection.
    Finish,
    /// Problem projection.
    Problem,
    /// Observation projection.
    Observation,
    /// Read projection.
    Read,
    /// Skill projection.
    Skill,
    /// Module Registry projection.
    ModuleRegistry,
    /// Maintenance projection.
    Maintenance,
    /// Change Monitor projection.
    ChangeMonitor,
}

impl RecoveryOwner {
    /// Every owner in the required exact order.
    pub const ALL: [Self; 16] = [
        Self::WorkScope,
        Self::Task,
        Self::Session,
        Self::Canonical,
        Self::Authority,
        Self::Budget,
        Self::Config,
        Self::Coordination,
        Self::Finish,
        Self::Problem,
        Self::Observation,
        Self::Read,
        Self::Skill,
        Self::ModuleRegistry,
        Self::Maintenance,
        Self::ChangeMonitor,
    ];

    /// Stable wire identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkScope => "work_scope",
            Self::Task => "task",
            Self::Session => "session",
            Self::Canonical => "canonical",
            Self::Authority => "authority",
            Self::Budget => "budget",
            Self::Config => "config",
            Self::Policy => "policy",
            Self::Coordination => "coordination",
            Self::Finish => "finish",
            Self::Problem => "problem",
            Self::Observation => "observation",
            Self::Read => "read",
            Self::Skill => "skill",
            Self::ModuleRegistry => "module_registry",
            Self::Maintenance => "maintenance",
            Self::ChangeMonitor => "change_monitor",
        }
    }
}

/// One exact named-read request sent to the authenticated Kernel generation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelNamedReadRequest {
    /// The closed owner being recovered.
    pub owner: RecoveryOwner,
    /// The expected active fence.
    pub state_fence: StateFence,
    /// The protected Kernel handoff digest.
    pub protected_snapshot_digest: String,
}

/// Evidence returned by one Kernel-owned named recovery read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelNamedReadReply {
    /// The owner that was read.
    pub owner: RecoveryOwner,
    /// Fence observed by the Kernel while reading it.
    pub state_fence: StateFence,
    /// Durable owner revision observed by the Kernel.
    pub revision: u64,
    /// Closed schema identifier for the payload bytes.
    pub schema: String,
    /// Exact bounded canonical owner snapshot bytes read by the Kernel.
    pub payload: Vec<u8>,
    /// Digest of the exact canonical owner payload bytes.
    pub value_digest: String,
}

/// One service observation recovered from the Kernel-owned state/control
/// route.  It is used to drive the existing Governor startup state machine;
/// no local observation is fabricated by the daemon.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelServiceRecovery {
    /// Normative Governor service identity.
    pub service: ServiceId,
    /// Exact recovered observation.
    pub observation: ServiceObservation,
}

/// The complete typed result of Kernel recovery required before readiness.
///
/// Every field is provider-owned evidence.  The daemon never constructs this
/// value from the launch config, a protected digest, or an in-memory default.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorRecoverySnapshot {
    /// Fence under which all reads were performed.
    pub state_fence: StateFence,
    /// Protected Kernel handoff digest used by every read.
    pub protected_snapshot_digest: String,
    /// Exactly one durable named read for each Governor owner.
    pub owner_reads: Vec<KernelNamedReadReply>,
    /// Optional Policy named read, served independently of the required
    /// owner set. `None` means the Kernel does not serve Policy yet:
    /// policy-gated evidence stays explicitly absent (fail-closed) and the
    /// required-set validation above is unaffected.
    pub policy_read: Option<KernelNamedReadReply>,
    /// Canonical revision/order heads recovered by the Kernel.
    pub canonical_scope: ScopeRevisionView,
    /// Exact terminal receipts available for operation replay/reconciliation.
    pub receipts: Vec<WriteReceipt>,
    /// Durable application jobs recovered by the Kernel-owned job route.
    pub durable_jobs: Vec<MaintenanceJob>,
}

impl GovernorRecoverySnapshot {
    fn owner_read(&self, owner: RecoveryOwner) -> Result<&KernelNamedReadReply, CompositionError> {
        self.owner_reads
            .iter()
            .find(|read| read.owner == owner)
            .ok_or_else(|| {
                CompositionError::Recovery(format!("missing named read {}", owner.as_str()))
            })
    }

    fn validate(
        &self,
        expected_fence: &StateFence,
        expected_digest: &str,
    ) -> Result<(), CompositionError> {
        self.state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if &self.state_fence != expected_fence
            || self.protected_snapshot_digest != expected_digest
            || !is_sha256(&self.protected_snapshot_digest)
        {
            return Err(CompositionError::Recovery(
                "Kernel recovery is not bound to the active fence and protected snapshot"
                    .to_owned(),
            ));
        }

        let expected_owners: BTreeSet<RecoveryOwner> = RecoveryOwner::ALL.into_iter().collect();
        let observed_owners: BTreeSet<RecoveryOwner> =
            self.owner_reads.iter().map(|read| read.owner).collect();
        if self.owner_reads.len() != expected_owners.len() || observed_owners != expected_owners {
            return Err(CompositionError::Recovery(
                "Kernel recovery did not return exactly one named read per owner".to_owned(),
            ));
        }
        for read in &self.owner_reads {
            if read.state_fence != *expected_fence
                || read.revision == 0
                || read.schema != OWNER_SNAPSHOT_SCHEMA
                || read.payload.is_empty()
                || read.payload.len() > MAX_OWNER_SNAPSHOT_BYTES
                || !is_sha256(&read.value_digest)
                || sha256_hex(&read.payload) != read.value_digest
            {
                return Err(CompositionError::Recovery(format!(
                    "named read {} has invalid fence, revision, or payload digest",
                    read.owner.as_str()
                )));
            }
        }

        self.canonical_scope
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self.canonical_scope.state_fence != *expected_fence {
            return Err(CompositionError::Recovery(
                "canonical named read returned a stale state fence".to_owned(),
            ));
        }
        let mut receipt_ids = BTreeSet::new();
        for receipt in &self.receipts {
            receipt
                .validate()
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
            if receipt.state_fence != *expected_fence
                || !receipt_ids.insert(receipt.operation_id.clone())
            {
                return Err(CompositionError::Recovery(
                    "receipt replay set has a duplicate or stale operation identity".to_owned(),
                ));
            }
        }
        let mut job_ids = BTreeSet::new();
        for job in &self.durable_jobs {
            job.validate()
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
            if job.state_fence != *expected_fence || !job_ids.insert(job.job_id.clone()) {
                return Err(CompositionError::Recovery(
                    "durable job recovery has a duplicate or stale identity".to_owned(),
                ));
            }
        }

        Ok(())
    }
}

/// Closed payload for a stateless or separately-read owner projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyOwnerSnapshot {
    /// Exact owner fence.
    pub state_fence: StateFence,
    /// Durable owner revision.
    pub revision: u64,
}

impl EmptyOwnerSnapshot {
    fn validate(&self, expected_fence: &StateFence) -> Result<(), CompositionError> {
        if self.state_fence != *expected_fence || self.revision == 0 {
            return Err(CompositionError::Recovery(
                "empty owner snapshot has a stale fence or zero revision".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Config owner payload bound to the exact protected config digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigOwnerSnapshot {
    /// Exact owner fence.
    pub state_fence: StateFence,
    /// Durable configuration revision.
    pub revision: u64,
    /// Digest of the immutable protected config bytes.
    pub config_digest: String,
}

/// Versioned semantic recovery state for the budget owner.
///
/// `Unconfigured` is the explicit genesis state. It carries no envelope,
/// authority, quota, reservation, or fabricated ledger. A configured owner
/// can only be admitted from the complete typed budget-ledger snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetOwnerSnapshot {
    /// Closed snapshot schema identity.
    pub schema: String,
    /// Closed snapshot schema version.
    pub version: u16,
    /// Exact owner fence.
    pub state_fence: StateFence,
    /// Durable semantic owner revision.
    pub revision: u64,
    /// Explicitly configured or unconfigured budget state.
    pub state: BudgetOwnerState,
}

/// The only admitted budget-owner states during recovery.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum BudgetOwnerState {
    /// Genesis has no budget policy or authority yet.
    Unconfigured,
    /// A complete, typed ledger restored from durable state.
    Configured {
        /// Full deterministic budget ledger recovery state.
        ledger: Box<BudgetLedgerRecoverySnapshot>,
    },
}

const BUDGET_OWNER_SNAPSHOT_SCHEMA: &str = "eliot.governor.budget-owner.v1";
const BUDGET_OWNER_SNAPSHOT_VERSION: u16 = 1;

impl BudgetOwnerSnapshot {
    #[cfg(test)]
    fn unconfigured(state_fence: StateFence, revision: u64) -> Self {
        Self {
            schema: BUDGET_OWNER_SNAPSHOT_SCHEMA.to_owned(),
            version: BUDGET_OWNER_SNAPSHOT_VERSION,
            state_fence,
            revision,
            state: BudgetOwnerState::Unconfigured,
        }
    }

    fn restore(
        &self,
        expected_fence: &StateFence,
    ) -> Result<Option<BudgetLedger>, CompositionError> {
        self.state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self.schema != BUDGET_OWNER_SNAPSHOT_SCHEMA
            || self.version != BUDGET_OWNER_SNAPSHOT_VERSION
            || self.state_fence != *expected_fence
            || self.revision == 0
        {
            return Err(CompositionError::Recovery(
                "budget snapshot has an invalid schema, stale fence, or zero revision".to_owned(),
            ));
        }
        match &self.state {
            BudgetOwnerState::Unconfigured => Ok(None),
            BudgetOwnerState::Configured { ledger } => {
                if ledger.authority.state_fence != self.state_fence {
                    return Err(CompositionError::Recovery(
                        "configured budget ledger has a stale nested authority fence".to_owned(),
                    ));
                }
                BudgetLedger::from_snapshot((**ledger).clone())
                    .map(Some)
                    .map_err(|error| {
                        CompositionError::Recovery(format!(
                            "configured budget ledger failed semantic restore: {error:?}"
                        ))
                    })
            }
        }
    }
}

/// Problem projection payload containing its durable revision map.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemOwnerSnapshot {
    /// Exact owner fence.
    pub state_fence: StateFence,
    /// Durable problem revision map.
    pub revisions: BTreeMap<String, u64>,
}

/// Read owner payload bound to the canonical scope read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOwnerSnapshot {
    /// Exact owner fence.
    pub state_fence: StateFence,
    /// Durable read projection revision.
    pub revision: u64,
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The proof ceiling the parked Windows acceptance item is evaluated at.
///
/// This is the only ceiling the acceptance owner records: it is a
/// build/inventory ceiling, so the build handle it produces can never be read
/// as a live-product `PASS` (issue #1903).
pub const PRODUCT_PROOF_CEILING: &str = "MIGRATION_INVENTORY_EVIDENCE_ONLY";

/// Narrows a product-proof contract refusal to this crate's error type.
///
/// The composition already reports every owner refusal as
/// [`CompositionError::Provider`]; this keeps the product-proof producer on
/// the same typed path instead of a string error, so a record the contract
/// rejects is an ordinary composition refusal the daemon already handles.
fn product_proof_error(error: impl std::fmt::Display) -> CompositionError {
    CompositionError::Provider(error.to_string())
}

/// The I18.22 execution position a finish lifecycle action actually reached.
///
/// The semantic outcome stays on the decision's own axis, so why a run did not
/// complete stays distinct from what it would have proven. A close of any kind
/// is a terminal position. A continuation or a suspension is not a terminal
/// position, so it is recorded as the terminal `Failed` position the owner
/// actually observed — the run did not complete and did not reach a verdict —
/// which keeps a non-terminal lifecycle action from being written as an
/// in-flight attempt the record cannot represent.
fn product_proof_execution(action: FinishLifecycleAction) -> ExecutionStatus {
    match action {
        FinishLifecycleAction::CloseCompleted => ExecutionStatus::Succeeded,
        FinishLifecycleAction::ClosePartial => ExecutionStatus::Partial,
        FinishLifecycleAction::CloseCancelled => ExecutionStatus::Cancelled,
        FinishLifecycleAction::CloseSuperseded => ExecutionStatus::Unknown,
        FinishLifecycleAction::ContinueActive | FinishLifecycleAction::EnterSuspended => {
            ExecutionStatus::Failed
        }
        FinishLifecycleAction::EnterBlocked => ExecutionStatus::Blocked,
    }
}

/// The exact required proof this composition's installed-route stage names.
///
/// The acceptance owner builds the parked stage in `eliot-finish`, and this
/// constant is the identical text the revision here uses, so the parked record
/// and its later revision name the same missing proof rather than drifting into
/// two requirements an operator would read as two different gaps.
const INSTALLED_ROUTE_REQUIRED_PROOF: &str =
    "installed Windows route pulse executed end to end on the target generation";

/// The observed installed-route stage a real finish receipt justifies.
///
/// A terminal succeeded position alone is NOT an installed-route observation.
/// The acceptance owner requires an installed-route receipt, so this reads the
/// Product Proof plan's own concrete receipt identity out of the decision's
/// *independently derived* artifact/verifier bindings — the set
/// `eliot-canonical` assembles from rehydrated evidence, not from this
/// product-proof path — and compares it against the plan's expected receipt
/// name. The decision's own digest and its own lifecycle action are the same
/// operation being measured, so neither can stand in for the independent
/// expected set. A finish decision that closed successfully while carrying no
/// installed-route receipt therefore yields no observed stage at all.
fn observed_installed_route_stage(
    receipt: &FinishDecisionReceipt,
) -> Option<eliot_reports::product_proof::ProductProofStageReceipt> {
    let expected = PRODUCT_PROOF_PLAN.installed_route_receipt;
    let observed = receipt
        .decision
        .proof
        .artifact_and_verifier_bindings
        .iter()
        .find_map(|binding| installed_route_receipt_id(binding, expected))?;
    Some(
        eliot_reports::product_proof::ProductProofStageReceipt::Observed {
            receipt_id: observed.to_owned(),
        },
    )
}

/// Extracts the installed-route receipt identity a binding handle names.
///
/// The handle is compared by content, not by shape: a binding cites the
/// concrete receipt name the plan requires, optionally qualified by the
/// generation or decision that produced it. Only an exact `ProductPulseReceipt`
/// name, on its own or as a trailing segment, counts — a binding that merely
/// contains the word is not an installed-route receipt.
fn installed_route_receipt_id<'a>(binding: &'a str, expected: &str) -> Option<&'a str> {
    let trimmed = binding.trim();
    if trimmed == expected {
        return Some(trimmed);
    }
    trimmed
        .rsplit([':', '/', '@', '#'])
        .find(|segment| segment.trim() == expected)
}

/// The installed-route stage receipt a real finish receipt justifies.
///
/// The stage cites the installed-route receipt the decision actually carried —
/// never the finish decision's own digest — so the record names the evidence
/// that proves the stage. Every other case, including a successfully closed
/// decision that carried no installed-route receipt, records the stage as
/// explicitly missing and names what the absent execution would have proven. A
/// simulated or absent launch receipt can never mark the installed route
/// observed, and the `PASS` refusal above it is untouched.
fn installed_route_stage(
    receipt: &FinishDecisionReceipt,
) -> eliot_reports::product_proof::ProductProofStageReceipt {
    match observed_installed_route_stage(receipt) {
        Some(observed) => observed,
        None => eliot_reports::product_proof::ProductProofStageReceipt::Missing {
            required_proof: INSTALLED_ROUTE_REQUIRED_PROOF.to_owned(),
        },
    }
}

/// The raw readback handles a retained finish decision actually carries.
///
/// The parked record must retain the evidence handles an operator needs for
/// forensic readback, and it may not invent one: these are the decision's own
/// derived artifact/verifier bindings, which `eliot-canonical` assembles from
/// rehydrated evidence and `FinishDecisionReceipt::validate()` already checks
/// for internal consistency. A decision that carries no binding therefore
/// retains an empty handle set, which is a recorded absence rather than a
/// fabricated log reference.
fn product_proof_raw_log_refs(receipt: Option<&FinishDecisionReceipt>) -> Vec<String> {
    receipt.map_or_else(Vec::new, |receipt| {
        let mut refs = Vec::new();
        refs.clone_from_slice(&receipt.decision.proof.artifact_and_verifier_bindings);
        refs
    })
}

/// Re-derives the evidence an unobserved product proof is still missing.
///
/// This is computed from the record's own retained stage and the plan's
/// concrete installed-route requirement rather than carried forward from a
/// prior revision's list, so a requirement can never be cleared by repeating
/// the same caller list. The installed-route proof text is read back off the
/// record's own `Missing` stage, so the two always name the same thing, and
/// the plan's receipt requirement is added independently so an operator sees
/// the concrete receipt that was never produced. The result is sorted, which
/// `ProductProofStatus::validate()` independently requires.
fn product_proof_missing_evidence(
    previous: &eliot_reports::product_proof::ProductProofStatus,
) -> Vec<String> {
    let mut missing: BTreeSet<String> = previous
        .missing_evidence
        .iter()
        .filter(|requirement| **requirement != INSTALLED_ROUTE_REQUIRED_PROOF)
        .cloned()
        .collect();
    if !previous.retained.installed_route_observed() {
        missing.insert(INSTALLED_ROUTE_REQUIRED_PROOF.to_owned());
        missing.insert(format!(
            "{} receipt bound to the installed route (expected by the Product Proof plan {})",
            PRODUCT_PROOF_PLAN.installed_route_receipt, PRODUCT_PROOF_PLAN.plan_path
        ));
    }
    missing.into_iter().collect()
}

/// Errors raised before daemon readiness.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CompositionError {
    /// A pure owner could not be built at the requested fence.
    #[error("owner construction failed: {0}")]
    Owner(String),
    /// A named Problem owner transition was refused because the store cannot
    /// re-derive the authorization its candidate record implies.
    ///
    /// The store compares the presented `authorization_digest` against one
    /// re-derived from the candidate record's *own* retained ownership-lease
    /// identity, so a record that retains none produces no digest the presented
    /// authorization could equal and the commit is refused there. Refusing here
    /// is what keeps the semantic verdict and the commit verdict one verdict: a
    /// prepare the store is bound to reject is not a weaker answer than success,
    /// it is a false one, and it arrives as a variant here so a caller can tell
    /// the two apart without reading prose.
    #[error(
        "problem owner transition {transition:?} refused for problem {problem_id} at revision {revision}: {reason}"
    )]
    ProblemOwnerTransitionUncommittable {
        /// The Problem whose owner transition was refused.
        problem_id: String,
        /// The revision the refused transition would have replaced.
        revision: u64,
        /// The named transition that was refused.
        transition: ProblemOwnerTransition,
        /// Which retained-identity shape the candidate record has.
        reason: ProblemOwnerAuthorizationRefusal,
    },
    /// Kernel snapshot or transition-port identity was not exact.
    #[error("Kernel provider mismatch: {0}")]
    Provider(String),
    /// Durable recovery did not prove the complete owner set.
    #[error("Governor recovery failed: {0}")]
    Recovery(String),
    /// Installation-bound scan disclosure refused an attach trigger's
    /// completion with its exact owner cause preserved (issue #2900 B6).
    ///
    /// Missing, inaccessible, corrupt, replaced, stale, invalidated,
    /// conflicted or unknown-commit scan records block completed readiness
    /// here instead of collapsing into a recovery string, so the caller can
    /// tell a lost record from a replaced one without re-reading the owner.
    #[error(transparent)]
    ScanDisclosure(#[from] WorkScopeError),
    /// Material readiness denied one effect with its exact receipt, directive,
    /// and missing-input details preserved for the caller.
    #[error(
        "material readiness denied {effect:?} for receipt {receipt_ref}: {directive:?}; missing inputs: {missing_inputs:?}"
    )]
    MaterialReadinessDenied {
        receipt_ref: String,
        effect: RequestedEffect,
        directive: MaterialReadinessDirective,
        missing_inputs: Vec<String>,
    },
    /// A scope-sensitive operation failed its observed `WorkScope` guard; the
    /// structured report preserves the exact identity legs and receipt.
    #[error(
        "scope guard withheld scope-sensitive operation ({identity:?}, {verdict:?}) at {trigger:?}"
    )]
    ScopeGuardWithheld {
        claimed_scope: String,
        observed_scope: String,
        trigger: GuardTrigger,
        identity: IdentityLegOutcome,
        verdict: GuardVerdict,
        report: Box<TriggerReport>,
    },
    /// A scope-sensitive operation lacked one or both caller-supplied inputs.
    #[error("scope-sensitive operation lacks required guard inputs at {trigger:?}")]
    ScopeSensitiveGuardInputsMissing {
        trigger: GuardTrigger,
        missing_observed_binding: bool,
        missing_source_closure: bool,
    },
    /// A live workspace observation named several instances at a use boundary,
    /// so the scope stays `AMBIGUOUS` and no candidate is selected (I4.2.1).
    #[error(
        "scope guard withheld {trigger:?}: {observed_instances} observed workspace instances, none selected"
    )]
    ScopeObservationAmbiguous {
        trigger: GuardTrigger,
        observed_instances: usize,
    },
    /// A startup transition was attempted out of order.
    #[error("startup order violation: expected {expected}, observed {observed}")]
    StartupOrder { expected: String, observed: String },
    /// The composition is not ready for semantic work.
    #[error("Governor is not ready")]
    NotReady,
    /// No exact active task binding is available for activation.
    #[error("activation task selection is required")]
    ActivationTaskSelectionRequired,
    /// More than one exact active task binding was observed.
    #[error("activation scope is ambiguous")]
    ActivationScopeAmbiguous { candidate_handles: Vec<String> },
    /// The exact `WorkScope` binding is not currently selected.
    #[error("activation scope selection is required")]
    ActivationScopeSelectionRequired,
    /// The semantic owner read was fenced or no longer current.
    #[error("activation owner fence is stale")]
    ActivationStaleFence,
    /// Canonical admission rejected the envelope.
    #[error("canonical admission: {0}")]
    Canonical(#[from] CanonicalError),
    /// P-07 authority activation refused, mismatched, or of unknown outcome.
    #[error("authority activation: {0}")]
    Authority(#[from] P07PortError),
    /// Kernel transition failed at the neutral port.
    #[error("Kernel transition: {0}")]
    Kernel(#[from] KernelPortError),
}

/// The Task Controller's verifier decision for one current plan revision.
///
/// The previous representation was `Option<CanonicalVerifierPlanBinding>`, which
/// cannot say *which* of two different situations it is reporting: a Task
/// Controller that has not yet decided a verifier request contract for this plan
/// revision, or a plan whose recorded decision has been lost. Issue #1741 made
/// that distinction load-bearing — with a bare `None` the finish path could not
/// tell a pending decision from a dead task, and the idempotence check in
/// `prepare_current_plan_admission` would absorb a later owner decision and leave
/// the task permanently unable to produce verifier-bound evidence.
///
/// A closed, two-member state makes the distinction explicit and keeps both
/// refusals:
///
/// * `Undecided` is the honest owner state before any decision. It carries an
///   explicit reason reference, so a consumer's refusal names the missing owner
///   decision instead of reporting a corrupt or absent binding.
/// * `Decided` is the exact owner-issued request contract, validated by its own
///   existing `validate`.
///
/// `Decided` boxes that contract. The two variants differ in size by more than an
/// order of magnitude — a `String` against a `PlannedVerifierRef` plus a dozen
/// contract ids, sets and maps — and inlining the large one into every
/// `CanonicalPlanBinding` inflates the whole owner image, which is retained and
/// re-read on every finish candidate. The box changes only where the bytes live:
/// `serde` and `schemars` treat `Box<T>` exactly as `T`, so the persisted and
/// generated shapes are byte-identical, and the `Decided` payload is still the
/// identical `CanonicalVerifierPlanBinding` content.
///
/// No consumer may read a verifier out of `Undecided`: every one that needs a
/// verifier goes through [`CanonicalPlanBinding::verifier_binding`], which
/// refuses with a typed `CompositionError` naming the state it found. The
/// requirement itself is unchanged; only the reason it is refused is now
/// nameable.
///
/// Nothing in this crate authors a `Decided` value. The state is reachable from
/// persisted owner bytes, exactly as `CanonicalVerifierPlanBinding` itself is, and
/// `GovernorFinishAttempt::admit_task_controller_plan` carries a retained
/// decision forward verbatim rather than authoring or discarding one.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "verifier_state")]
pub enum CanonicalVerifierPlanState {
    /// The Task Controller has published no verifier request contract for this
    /// plan revision. `reason_ref` is the owner-side reference explaining that,
    /// not a synthesized label.
    Undecided { reason_ref: String },
    /// The Task Controller published this exact verifier request contract.
    Decided {
        binding: Box<CanonicalVerifierPlanBinding>,
    },
}

impl CanonicalVerifierPlanState {
    /// The owner-side reference recorded when no verifier decision exists.
    ///
    /// This is the only value [`Self::default`] produces, and it names the
    /// absent owner decision rather than standing in for one.
    pub const NO_VERIFIER_DECISION_REF: &'static str =
        "task-controller-published-no-verifier-request-contract";

    /// Validates the state and, when decided, the exact owner-issued contract.
    pub fn validate(&self) -> Result<(), CompositionError> {
        match self {
            Self::Undecided { reason_ref } => {
                if reason_ref.trim().is_empty() || reason_ref.chars().any(char::is_control) {
                    return Err(CompositionError::Recovery(
                        "canonical plan verifier state has an empty or malformed decision reference"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
            Self::Decided { binding } => binding.validate(),
        }
    }

    /// The exact owner-issued request contract, or a typed refusal that names the
    /// state it found.
    pub fn binding(&self) -> Result<&CanonicalVerifierPlanBinding, CompositionError> {
        match self {
            Self::Decided { binding } => Ok(binding.as_ref()),
            Self::Undecided { reason_ref } => Err(CompositionError::Recovery(format!(
                "canonical plan carries no verifier request contract because the Task Controller \
                 has published none for this plan revision ({reason_ref})"
            ))),
        }
    }
}

impl Default for CanonicalVerifierPlanState {
    fn default() -> Self {
        Self::Undecided {
            reason_ref: Self::NO_VERIFIER_DECISION_REF.to_owned(),
        }
    }
}

/// Exact current Canonical plan identity retained by the Governor owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPlanBinding {
    pub plan_id: String,
    pub plan_revision: String,
    pub task_id: TaskId,
    pub work_scope_id: String,
    /// The Task Controller's verifier decision for this plan revision.
    ///
    /// Explicitly typed so an absent decision is distinguishable from a lost one;
    /// see [`CanonicalVerifierPlanState`]. A plan that has not been given a
    /// verifier request contract still validates, and every consumer that needs
    /// one refuses through [`Self::verifier_binding`].
    #[serde(default)]
    pub verifier: CanonicalVerifierPlanState,
}

impl CanonicalPlanBinding {
    /// Constructs a bounded current-plan identity.
    ///
    /// The verifier dimension starts as [`CanonicalVerifierPlanState::Undecided`]:
    /// a plan identity is not an authority to pick a verifier, so this admits
    /// none. An owner decision binds one by changing this dimension, which is a
    /// different owner revision.
    pub fn new(
        plan_id: impl Into<String>,
        plan_revision: impl Into<String>,
        task_id: TaskId,
        work_scope_id: impl Into<String>,
    ) -> Result<Self, CompositionError> {
        let binding = Self {
            plan_id: plan_id.into(),
            plan_revision: plan_revision.into(),
            task_id,
            work_scope_id: work_scope_id.into(),
            verifier: CanonicalVerifierPlanState::default(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// The exact owner-issued verifier request contract for this plan, or a typed
    /// refusal that names whether the owner has simply not decided one yet.
    pub fn verifier_binding(&self) -> Result<&CanonicalVerifierPlanBinding, CompositionError> {
        self.verifier.binding()
    }

    /// Validates the bounded plan identity without consulting evidence.
    pub fn validate(&self) -> Result<(), CompositionError> {
        if self.plan_id.trim().is_empty() || self.plan_id.chars().any(char::is_control) {
            return Err(CompositionError::Recovery(
                "canonical plan id is blank or contains control characters".to_owned(),
            ));
        }
        if self.plan_revision.trim().is_empty() || self.plan_revision.chars().any(char::is_control)
        {
            return Err(CompositionError::Recovery(
                "canonical plan revision is blank or contains control characters".to_owned(),
            ));
        }
        if self.work_scope_id.trim().is_empty() || self.work_scope_id.chars().any(char::is_control)
        {
            return Err(CompositionError::Recovery(
                "canonical work scope id is blank or contains control characters".to_owned(),
            ));
        }
        // The verifier dimension is validated as the closed state it now is, not
        // skipped when absent: an `Undecided` must still carry a well-formed
        // owner-side reason reference, so "no decision yet" is always a stated
        // fact and never an unexplained hole.
        self.verifier.validate()?;
        Ok(())
    }
}

/// Verifier request identity selected by the canonical plan.
///
/// This is the owner-side expectation used to join a TestD invocation to the
/// exact verifier configuration. A terminal binding alone is insufficient:
/// its planned configuration hash and contract revision are intentionally
/// consumer-validated here.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalVerifierPlanBinding {
    pub planned: eliot_evaluation_contracts::PlannedVerifierRef,
    /// Registered instrument which performs the admitted verifier run.
    pub instrument: ContractId,
    /// Instrument kind admitted by the productive evaluator.
    pub kind: InstrumentKind,
    pub profile: String,
    /// Exact target carried by the admitted invocation.
    pub target: String,
    /// Exact instrument-level arguments carried by the admitted invocation.
    pub arguments: Vec<String>,
    pub declared_scope: String,
    pub input_artifacts: Vec<ArtifactId>,
    /// Required test ids selected by the canonical plan owner.
    pub required_test_ids: BTreeSet<String>,
    /// Full `TaskContract` acceptance denominator bound by the canonical plan
    /// owner (issue #325 P1, I7.9).
    ///
    /// The finish path enumerates exactly this set before joining executed
    /// verifier evidence. The selected `required_test_ids` inventory alone is
    /// never the acceptance denominator: an obligation omitted from the test
    /// list must still surface as an uncovered acceptance row rather than
    /// vanishing from the gate.
    pub required_acceptance_item_ids: BTreeSet<String>,
    /// Acceptance-set commitment bound by the canonical plan owner at this
    /// exact task revision (issue #325 P1, I7.9).
    ///
    /// Admission and the finish gate both require this digest to equal
    /// `task_acceptance_set_commitment(required_acceptance_item_ids)`, so it is
    /// a commitment over the enumerated set rather than a free label, and a
    /// plan that declares a different set than the one it committed to is
    /// refused instead of reporting a smaller set that reads as complete.
    pub task_acceptance_digest: String,
    /// Explicit join from each acceptance item to the nextest test ids that
    /// establish it (issue #325 P1).
    ///
    /// Many-to-many mappings are supported without equating test ids with
    /// acceptance ids. An item with no entry is unmapped and the verifier
    /// path reports it uncovered; an entry with an empty test set declares a
    /// non-test obligation that executed verifier runs alone cannot satisfy.
    /// Neither form ever shrinks the task denominator to the selected test
    /// list.
    pub acceptance_verifier_map: BTreeMap<String, BTreeSet<String>>,
    /// Registered evaluator identity and version used for this plan.
    pub evaluator: ContractId,
    pub evaluator_version: ContractVersion,
}

impl CanonicalVerifierPlanBinding {
    fn validate(&self) -> Result<(), CompositionError> {
        for (field, value) in [
            ("verifier_id", self.planned.verifier_id.as_str()),
            ("instrument", self.instrument.as_str()),
            ("profile", self.profile.as_str()),
            ("target", self.target.as_str()),
            ("declared_scope", self.declared_scope.as_str()),
            ("evaluator", self.evaluator.as_str()),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(CompositionError::Recovery(format!(
                    "canonical verifier plan {field} is blank or contains control characters"
                )));
            }
        }
        self.planned
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self.planned.scope != self.declared_scope {
            return Err(CompositionError::Recovery(
                "canonical verifier plan scope differs from declared scope".to_owned(),
            ));
        }
        if self.kind != InstrumentKind::Test {
            return Err(CompositionError::Recovery(
                "canonical verifier plan must bind the TEST instrument kind".to_owned(),
            ));
        }
        if self.instrument.as_str() != eliot_instrument_nextest::NEXTEST_INSTRUMENT {
            return Err(CompositionError::Recovery(
                "canonical verifier plan must bind the registered nextest instrument".to_owned(),
            ));
        }
        if self.evaluator.as_str() != eliot_verifier::CONTRACT_NAME
            || self.planned.verifier_id != self.evaluator
            || self.evaluator_version
                != ContractVersion::new(
                    eliot_verifier::CONTRACT_VERSION.0,
                    eliot_verifier::CONTRACT_VERSION.1,
                    eliot_verifier::CONTRACT_VERSION.2,
                )
        {
            return Err(CompositionError::Recovery(
                "canonical verifier plan is not bound to the current evaluator contract".to_owned(),
            ));
        }
        if self
            .arguments
            .iter()
            .any(|argument| argument.trim().is_empty() || argument.chars().any(char::is_control))
        {
            return Err(CompositionError::Recovery(
                "canonical verifier plan contains an invalid argument".to_owned(),
            ));
        }
        if self.required_test_ids.is_empty()
            || self
                .required_test_ids
                .iter()
                .any(|test_id| test_id.trim().is_empty() || test_id.chars().any(char::is_control))
        {
            return Err(CompositionError::Recovery(
                "canonical verifier plan has no required test ids".to_owned(),
            ));
        }
        // I7.9 / issue #325 P1: the plan must bind the full TaskContract
        // acceptance denominator, not just the selected test inventory. An
        // empty denominator would let the finish path shrink the task to the
        // test list, so admission fails closed here.
        self.validate_acceptance_denominator()?;
        if self.input_artifacts.is_empty()
            || self
                .input_artifacts
                .iter()
                .any(|artifact| artifact.as_str().trim().is_empty())
        {
            return Err(CompositionError::Recovery(
                "canonical verifier plan has no exact input artifact binding".to_owned(),
            ));
        }
        let config_hash = verifier_invocation_config_digest(&VerifierInvocationConfig {
            instrument: &self.instrument,
            kind: self.kind,
            profile: &self.profile,
            target: &self.target,
            arguments: &self.arguments,
            declared_scope: &self.declared_scope,
            input_artifacts: &self.input_artifacts,
            required_test_ids: &self.required_test_ids,
            required_acceptance_item_ids: &self.required_acceptance_item_ids,
            task_acceptance_digest: &self.task_acceptance_digest,
            acceptance_verifier_map: &self.acceptance_verifier_map,
            evaluator: &self.evaluator,
            evaluator_version: self.evaluator_version,
        })?;
        if self.planned.verifier_config_hash != config_hash {
            return Err(CompositionError::Recovery(
                "canonical verifier plan config hash does not bind its invocation shape".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validates the plan-bound `TaskContract` acceptance denominator and its
    /// explicit join to the selected test inventory (issue #325 P1, I7.9).
    fn validate_acceptance_denominator(&self) -> Result<(), CompositionError> {
        if self.required_acceptance_item_ids.is_empty()
            || self
                .required_acceptance_item_ids
                .iter()
                .any(|item_id| item_id.trim().is_empty() || item_id.chars().any(char::is_control))
        {
            return Err(CompositionError::Recovery(
                "canonical verifier plan has no required acceptance item ids".to_owned(),
            ));
        }
        // The contract acceptance digest is what makes the enumerated set the
        // contract's obligation set rather than the plan's own list, so it must
        // be a real digest and not an absent or free-text stand-in.
        if self.task_acceptance_digest.len() != 64
            || self
                .task_acceptance_digest
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(CompositionError::Recovery(
                "canonical verifier plan has no contract acceptance digest".to_owned(),
            ));
        }
        // The digest is accepted only when it is the commitment over THIS
        // enumeration. A format-valid digest that does not commit to the
        // declared set is refused at admission, so a plan cannot carry a digest
        // issued for a larger contract set alongside a narrowed item list and
        // reach the finish gate. Recomputing here also means the digest cannot
        // be satisfied by restating whatever label the caller already had.
        if task_acceptance_set_commitment(&self.required_acceptance_item_ids)?
            != self.task_acceptance_digest
        {
            return Err(CompositionError::Recovery(
                "canonical verifier plan acceptance digest does not commit to its declared \
                 acceptance item set"
                    .to_owned(),
            ));
        }
        for (item_id, test_ids) in &self.acceptance_verifier_map {
            if !self.required_acceptance_item_ids.contains(item_id) {
                return Err(CompositionError::Recovery(
                    "canonical verifier plan maps an unknown acceptance item".to_owned(),
                ));
            }
            if item_id.trim().is_empty() || item_id.chars().any(char::is_control) {
                return Err(CompositionError::Recovery(
                    "canonical verifier plan has an invalid acceptance item id".to_owned(),
                ));
            }
            for test_id in test_ids {
                if test_id.trim().is_empty()
                    || test_id.chars().any(char::is_control)
                    || !self.required_test_ids.contains(test_id)
                {
                    return Err(CompositionError::Recovery(
                        "canonical verifier plan maps an acceptance item outside its required test set"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Observed immutable invocation/evaluator identity recovered from the durable
/// TestD job. This is kept separate from `PlannedVerifierRef`: a terminal
/// binding may carry the plan as an expectation, but this record is populated
/// from the actual admitted invocation and evaluated run.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalVerifierInvocationBinding {
    pub instrument: ContractId,
    pub kind: InstrumentKind,
    pub profile: String,
    pub target: String,
    pub arguments: Vec<String>,
    pub declared_scope: String,
    pub input_artifacts: Vec<ArtifactId>,
    pub required_test_ids: BTreeSet<String>,
    /// `TaskContract` acceptance denominator observed with the admitted
    /// invocation; copied from the canonical plan so a persisted fact keeps
    /// the exact denominator its acceptance join used.
    pub required_acceptance_item_ids: BTreeSet<String>,
    /// `TaskContract` acceptance digest observed with the admitted invocation;
    /// copied from the canonical plan for the same reason.
    pub task_acceptance_digest: String,
    /// Acceptance-to-test join observed with the admitted invocation; copied
    /// from the canonical plan for the same reason.
    pub acceptance_verifier_map: BTreeMap<String, BTreeSet<String>>,
    pub evaluator: ContractId,
    pub evaluator_version: ContractVersion,
    pub config_hash: String,
}

impl CanonicalVerifierInvocationBinding {
    fn from_invocation(
        invocation: &InstrumentInvocation,
        plan: &CanonicalVerifierPlanBinding,
    ) -> Result<Self, CompositionError> {
        invocation.validate().map_err(|error| {
            verifier_fact_error(format!("TestD invocation validation failed: {error}"))
        })?;
        let config_hash = verifier_invocation_config_digest(&VerifierInvocationConfig {
            instrument: &invocation.instrument,
            kind: invocation.kind,
            profile: &invocation.profile,
            target: &invocation.target,
            arguments: &invocation.arguments,
            declared_scope: &invocation.declared_scope,
            input_artifacts: &invocation.input_artifacts,
            required_test_ids: &plan.required_test_ids,
            required_acceptance_item_ids: &plan.required_acceptance_item_ids,
            task_acceptance_digest: &plan.task_acceptance_digest,
            acceptance_verifier_map: &plan.acceptance_verifier_map,
            evaluator: &plan.evaluator,
            evaluator_version: plan.evaluator_version,
        })?;
        Ok(Self {
            instrument: invocation.instrument.clone(),
            kind: invocation.kind,
            profile: invocation.profile.clone(),
            target: invocation.target.clone(),
            arguments: invocation.arguments.clone(),
            declared_scope: invocation.declared_scope.clone(),
            input_artifacts: invocation.input_artifacts.clone(),
            required_test_ids: plan.required_test_ids.clone(),
            required_acceptance_item_ids: plan.required_acceptance_item_ids.clone(),
            task_acceptance_digest: plan.task_acceptance_digest.clone(),
            acceptance_verifier_map: plan.acceptance_verifier_map.clone(),
            evaluator: plan.evaluator.clone(),
            evaluator_version: plan.evaluator_version,
            config_hash,
        })
    }

    fn validate(&self) -> Result<(), CompositionError> {
        if self.kind != InstrumentKind::Test
            || self.instrument.as_str() != eliot_instrument_nextest::NEXTEST_INSTRUMENT
            || self.evaluator.as_str() != eliot_verifier::CONTRACT_NAME
            || self.profile.trim().is_empty()
            || self.target.trim().is_empty()
            || self.declared_scope.trim().is_empty()
            || self.input_artifacts.is_empty()
            || self.required_test_ids.is_empty()
            || self.required_acceptance_item_ids.is_empty()
            || self.task_acceptance_digest.len() != 64
            || self
                .task_acceptance_digest
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            || self.config_hash.len() != 64
            || self
                .config_hash
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(verifier_fact_error(
                "observed verifier invocation binding is incomplete or wrong-kind",
            ));
        }
        if self
            .arguments
            .iter()
            .any(|argument| argument.trim().is_empty() || argument.chars().any(char::is_control))
            || self
                .required_test_ids
                .iter()
                .any(|test_id| test_id.trim().is_empty() || test_id.chars().any(char::is_control))
            || self
                .required_acceptance_item_ids
                .iter()
                .any(|item_id| item_id.trim().is_empty() || item_id.chars().any(char::is_control))
            || self.acceptance_verifier_map.keys().any(|item_id| {
                item_id.trim().is_empty()
                    || item_id.chars().any(char::is_control)
                    || !self.required_acceptance_item_ids.contains(item_id)
            })
            || self
                .acceptance_verifier_map
                .values()
                .flat_map(BTreeSet::iter)
                .any(|test_id| {
                    test_id.trim().is_empty()
                        || test_id.chars().any(char::is_control)
                        || !self.required_test_ids.contains(test_id)
                })
        {
            return Err(verifier_fact_error(
                "observed verifier invocation binding has invalid text",
            ));
        }
        let recomputed = verifier_invocation_config_digest(&VerifierInvocationConfig {
            instrument: &self.instrument,
            kind: self.kind,
            profile: &self.profile,
            target: &self.target,
            arguments: &self.arguments,
            declared_scope: &self.declared_scope,
            input_artifacts: &self.input_artifacts,
            required_test_ids: &self.required_test_ids,
            required_acceptance_item_ids: &self.required_acceptance_item_ids,
            task_acceptance_digest: &self.task_acceptance_digest,
            acceptance_verifier_map: &self.acceptance_verifier_map,
            evaluator: &self.evaluator,
            evaluator_version: self.evaluator_version,
        })?;
        if recomputed != self.config_hash {
            return Err(verifier_fact_error(
                "observed verifier invocation config hash is not exact",
            ));
        }
        Ok(())
    }
}

/// Exact verifier invocation shape bound by the canonical plan owner into
/// `verifier_config_hash`.
///
/// Issue #325 P1: the `TaskContract` acceptance denominator and its explicit
/// test join are part of the hashed shape, so a stale hash can never attest
/// a substituted denominator.
struct VerifierInvocationConfig<'a> {
    instrument: &'a ContractId,
    kind: InstrumentKind,
    profile: &'a str,
    target: &'a str,
    arguments: &'a [String],
    declared_scope: &'a str,
    input_artifacts: &'a [ArtifactId],
    required_test_ids: &'a BTreeSet<String>,
    required_acceptance_item_ids: &'a BTreeSet<String>,
    task_acceptance_digest: &'a str,
    acceptance_verifier_map: &'a BTreeMap<String, BTreeSet<String>>,
    evaluator: &'a ContractId,
    evaluator_version: ContractVersion,
}

fn verifier_invocation_config_digest(
    config: &VerifierInvocationConfig<'_>,
) -> Result<String, CompositionError> {
    #[derive(Serialize)]
    struct Config<'a> {
        instrument: &'a ContractId,
        kind: InstrumentKind,
        profile: &'a str,
        target: &'a str,
        arguments: &'a [String],
        declared_scope: &'a str,
        input_artifacts: &'a [ArtifactId],
        required_test_ids: &'a BTreeSet<String>,
        required_acceptance_item_ids: &'a BTreeSet<String>,
        task_acceptance_digest: &'a str,
        acceptance_verifier_map: &'a BTreeMap<String, BTreeSet<String>>,
        evaluator: &'a ContractId,
        evaluator_version: ContractVersion,
    }
    let bytes = canonical_json_bytes(&Config {
        instrument: config.instrument,
        kind: config.kind,
        profile: config.profile,
        target: config.target,
        arguments: config.arguments,
        declared_scope: config.declared_scope,
        input_artifacts: config.input_artifacts,
        required_test_ids: config.required_test_ids,
        required_acceptance_item_ids: config.required_acceptance_item_ids,
        task_acceptance_digest: config.task_acceptance_digest,
        acceptance_verifier_map: config.acceptance_verifier_map,
        evaluator: config.evaluator,
        evaluator_version: config.evaluator_version,
    })
    .map_err(|error| {
        CompositionError::Recovery(format!("verifier config canonicalization failed: {error}"))
    })?;
    Ok(sha256_hex(&bytes))
}

/// Exact raw artifact identity carried by a durable TestD verifier receipt.
///
/// The bytes remain owned by TestD's durable receipt.  Canonical state keeps
/// the immutable handle, digest, and capture shape needed to prove that a
/// terminal verifier run used the same artifact lineage after rehydration.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalVerifierRawArtifactBinding {
    pub handle: String,
    pub content_type: String,
    pub length: u64,
    pub sha256: String,
    pub truncated: bool,
}

/// Exact TestD receipt identity retained by the canonical verifier fact.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalVerifierReceiptBinding {
    pub job_id: String,
    pub operation_id: String,
    pub process_tree_id: String,
    pub generation: u64,
    pub authority_epoch: EpochId,
    pub invocation_id: String,
    pub invocation_digest: String,
    pub execution: ExecutionStatus,
    pub receipt_sha256: String,
    pub allowed_contour_root: String,
    pub source_root: String,
    pub target_root: String,
    pub cache_root: String,
}

impl CanonicalVerifierReceiptBinding {
    fn from_binding(
        binding: &ReceiptBinding,
        execution: ExecutionStatus,
        receipt_sha256: String,
    ) -> Self {
        Self {
            job_id: binding.job_id.clone(),
            operation_id: binding.operation_id.clone(),
            process_tree_id: binding.process_tree_id.clone(),
            generation: binding.generation,
            authority_epoch: binding.authority_epoch.clone(),
            invocation_id: binding.invocation_id.clone(),
            invocation_digest: binding.invocation_digest.clone(),
            execution,
            receipt_sha256,
            allowed_contour_root: binding.allowed_contour_root.clone(),
            source_root: binding.source_root.clone(),
            target_root: binding.target_root.clone(),
            cache_root: binding.cache_root.clone(),
        }
    }
}

/// Immutable source identity captured by the TestD owner around execution.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalVerifierSourceObservation {
    pub repository_root: String,
    pub branch: String,
    pub commit: String,
    pub dirty_state_sha256: String,
}

impl CanonicalVerifierSourceObservation {
    fn from_testd(observation: &TestdSourceObservation) -> Self {
        Self {
            repository_root: observation.repository_root.clone(),
            branch: observation.branch.clone(),
            commit: observation.commit.clone(),
            dirty_state_sha256: observation.dirty_state_sha256.clone(),
        }
    }

    fn validate(&self, expected_root: &str) -> Result<(), CompositionError> {
        let commit_valid = matches!(self.commit.len(), 40 | 64)
            && self
                .commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        let dirty_digest_valid = self.dirty_state_sha256.len() == 64
            && self
                .dirty_state_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if self.repository_root != expected_root
            || !std::path::Path::new(&self.repository_root).is_absolute()
            || std::path::Path::new(&self.repository_root)
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || self.repository_root.chars().any(char::is_control)
            || self.branch.trim().is_empty()
            || self.branch.chars().any(char::is_control)
            || !commit_valid
            || !dirty_digest_valid
        {
            return Err(verifier_fact_error(
                "persisted source observation is malformed or outside the admitted repository",
            ));
        }
        Ok(())
    }
}

/// Before/after source identity retained with the canonical verifier fact.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalVerifierSourceObservationRange {
    pub before: CanonicalVerifierSourceObservation,
    pub after: CanonicalVerifierSourceObservation,
}

impl CanonicalVerifierSourceObservationRange {
    fn from_testd(range: &TestdSourceObservationRange) -> Self {
        Self {
            before: CanonicalVerifierSourceObservation::from_testd(&range.before),
            after: CanonicalVerifierSourceObservation::from_testd(&range.after),
        }
    }

    fn validate(&self, expected_root: &str) -> Result<(), CompositionError> {
        self.before.validate(expected_root)?;
        self.after.validate(expected_root)?;
        if self.before.repository_root != self.after.repository_root {
            return Err(verifier_fact_error(
                "source observation changed repository roots during verification",
            ));
        }
        Ok(())
    }

    fn unchanged(&self) -> bool {
        self.before == self.after
    }
}

/// One physical TestD effect bound to the task and verifier run.
///
/// This is a retained execution receipt reference, not an assertion that the
/// effect is closed.  Descendant/effect closure remains a later canonical
/// owner phase.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalVerifierEffectBinding {
    pub task_id: String,
    pub job_id: String,
    pub operation_id: String,
    pub process_tree_id: String,
    pub state_fence: StateFence,
    pub execution: ExecutionStatus,
    pub receipt_sha256: String,
}

impl CanonicalVerifierEffectBinding {
    fn validate(
        &self,
        expected_task_id: &str,
        expected_fence: &StateFence,
    ) -> Result<(), CompositionError> {
        if self.task_id != expected_task_id
            || self.state_fence != *expected_fence
            || self.job_id.trim().is_empty()
            || self.operation_id.trim().is_empty()
            || self.process_tree_id.trim().is_empty()
            || self.job_id.chars().any(char::is_control)
            || self.operation_id.chars().any(char::is_control)
            || self.process_tree_id.chars().any(char::is_control)
            || self.receipt_sha256.len() != 64
            || self
                .receipt_sha256
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(CompositionError::Recovery(
                "canonical verifier effect binding is not task/fence bound".to_owned(),
            ));
        }
        self.state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if !self.execution.is_terminal() {
            return Err(CompositionError::Recovery(
                "canonical verifier effect binding is not terminal".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Canonical fact produced from a terminal TestD job and its persisted
/// verifier receipt.
///
/// The fact retains failed, stale, partial, and otherwise non-certifying
/// verifier runs for readback.  [`Self::certifies_completion`] is deliberately
/// derived from the bound execution/evaluation axes and never from a caller
/// label or task command.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalVerifierExecutionFact {
    pub task_id: String,
    pub task_revision: u64,
    pub plan: CanonicalPlanBinding,
    pub state_fence: StateFence,
    pub job_id: String,
    pub job_state: String,
    pub receipt: CanonicalVerifierReceiptBinding,
    /// Real branch, commit, and dirty-state observations retained by TestD.
    #[serde(default)]
    pub source_observation: Option<CanonicalVerifierSourceObservationRange>,
    pub verification_run: VerificationRun,
    /// Observed invocation/evaluator identity recovered from the TestD job.
    /// This is the non-tautological config/currentness join.
    pub invocation: CanonicalVerifierInvocationBinding,
    pub terminal_binding: TerminalVerifierBinding,
    pub input_artifact_bindings: Vec<ArtifactId>,
    pub raw_artifact_bindings: Vec<CanonicalVerifierRawArtifactBinding>,
    pub effect_reference_bindings: Vec<CanonicalVerifierEffectBinding>,
}

impl CanonicalVerifierExecutionFact {
    /// Builds a fact only from a terminal, durably receipt-bound TestD job.
    ///
    /// `receipt` must equal the full receipt retained by TestD after the
    /// worker/verifier transition.  The terminal binding and run are checked
    /// against the same invocation, fence, outcome, and artifact lineage.
    pub fn from_testd(
        task_id: &TaskId,
        task_revision: u64,
        plan: &CanonicalPlanBinding,
        state_fence: &StateFence,
        job: &TestJob,
        receipt: &VerificationReceipt,
        run: VerificationRun,
    ) -> Result<Self, CompositionError> {
        check_testd_receipt_terminal(job, receipt)?;
        let receipt_binding = receipt.binding();
        if job.receipt.as_ref() != Some(&receipt_binding)
            || job.verification_receipt.as_ref() != Some(receipt)
        {
            return Err(verifier_fact_error(
                "TestD verifier receipt is not the durably retained job receipt",
            ));
        }
        check_testd_receipt_fence(job, receipt, state_fence)?;
        let verifier_plan = admitted_testd_verifier_plan(plan, task_id, task_revision, job)?;
        let invocation = matched_testd_invocation(&job.invocation, verifier_plan)?;
        let terminal_binding =
            checked_testd_terminal_binding(&run, state_fence, job, receipt, verifier_plan)?;

        check_testd_artifact_lineage(receipt, &run, &terminal_binding)?;

        let receipt_sha256 =
            eliot_testd_core::verification_receipt_sha256(receipt).map_err(|error| {
                verifier_fact_error(format!("TestD receipt digest failed: {error}"))
            })?;
        let canonical_receipt = CanonicalVerifierReceiptBinding::from_binding(
            &receipt_binding,
            receipt.execution,
            receipt_sha256.clone(),
        );
        let fact = Self {
            task_id: task_id.as_str().to_owned(),
            task_revision,
            plan: plan.clone(),
            state_fence: state_fence.clone(),
            job_id: job.job_id.clone(),
            job_state: canonical_job_state(job.state).to_owned(),
            receipt: canonical_receipt,
            source_observation: receipt
                .source_observation
                .as_ref()
                .map(CanonicalVerifierSourceObservationRange::from_testd),
            verification_run: run,
            invocation,
            terminal_binding,
            input_artifact_bindings: job.invocation.input_artifacts.clone(),
            raw_artifact_bindings: receipt
                .raw_artifacts
                .iter()
                .map(|artifact| CanonicalVerifierRawArtifactBinding {
                    handle: artifact.handle.clone(),
                    content_type: artifact.content_type.clone(),
                    length: artifact.length,
                    sha256: artifact.sha256.clone(),
                    truncated: artifact.truncated,
                })
                .collect(),
            effect_reference_bindings: vec![CanonicalVerifierEffectBinding {
                task_id: task_id.as_str().to_owned(),
                job_id: receipt.job_id.clone(),
                operation_id: receipt.operation_id.clone(),
                process_tree_id: receipt.process_tree_id.clone(),
                state_fence: state_fence.clone(),
                execution: receipt.execution,
                receipt_sha256,
            }],
        };
        fact.validate(state_fence)?;
        Ok(fact)
    }

    /// Validates the persisted fact without consulting a caller or provider.
    pub fn validate(&self, expected_fence: &StateFence) -> Result<(), CompositionError> {
        let verifier_plan = checked_fact_identity_and_plan(self, expected_fence)?;
        check_fact_invocation_matches_plan(self, verifier_plan)?;
        check_fact_run_and_receipt(self, expected_fence, verifier_plan)?;
        check_fact_artifact_lineage(self)?;
        check_fact_terminal_effect_join(self, expected_fence)?;
        Ok(())
    }

    /// Whether the bound execution/evaluation is eligible to certify finish.
    ///
    /// `I7.9` (`docs/architecture/I07-09-strict-finish-input-and-outcomes.md:30`)
    /// forbids a verifier with execution status `NOT_EXECUTED` or `SIMULATED`,
    /// stale scope, a missing artifact binding, or an unknown outcome from
    /// supporting `VERIFIED_COMPLETE`.  Every clause is answered here by
    /// comparing the *recorded* axis of this fact, never by observing that a
    /// record exists:
    ///
    /// - simulated — the run's own bound invocation profile is compared against
    ///   the registered productive profile constant.  Equality with the
    ///   canonical plan's declared profile, already required by
    ///   [`Self::validate`] through `check_fact_invocation_matches_plan`, is an
    ///   identity check between two freely-typed labels and says nothing about
    ///   whether the run was executed productively.  The productive-profile
    ///   refusal in `evaluate_testd_verification_current` runs on the
    ///   publication path; this predicate is what the rehydration path and the
    ///   persisted evidence read-back in
    ///   [`CanonicalFinishEvidence::validate`] consult, so a simulated run
    ///   rehydrated from the canonical owner can be recorded neither as
    ///   certifying nor as an exact current run.
    /// - unexecuted and unknown — `ExecutionStatus::Succeeded` is required on
    ///   both the receipt binding and the run, so an admitted-but-not-started
    ///   or in-flight execution and an unestablishable outcome both fail; only
    ///   `VerificationOutcome::Pass` is accepted, so an unknown outcome stays
    ///   unknown and is never read as success or as absence of objection.
    /// - stale scope — `Exact*` freshness on the run and on every normalized
    ///   evidence event, an unchanged source observation, and a recorded
    ///   finish time.
    /// - missing artifact binding — non-empty raw artifact bindings, non-empty
    ///   raw and normalized run evidence, and no truncated artifact.
    #[must_use]
    pub fn certifies_completion(&self) -> bool {
        let fresh = matches!(
            self.verification_run.freshness,
            EvidenceFreshness::ExactCandidate
                | EvidenceFreshness::ExactCommit
                | EvidenceFreshness::ExactQuiescedWorktree
        );
        self.invocation.profile == eliot_testd_core::TESTD_PRODUCTIVE_PROFILE
            && self.job_state == "succeeded"
            && self.receipt.execution == ExecutionStatus::Succeeded
            && self.verification_run.execution == ExecutionStatus::Succeeded
            && self.verification_run.outcome == VerificationOutcome::Pass
            && self.verification_run.coverage == EvidenceCoverage::CompleteForScope
            && self.verification_run.finished_at.is_some()
            && fresh
            && self
                .source_observation
                .as_ref()
                .is_some_and(CanonicalVerifierSourceObservationRange::unchanged)
            && !self.raw_artifact_bindings.is_empty()
            && !self.verification_run.raw_evidence.is_empty()
            && !self.verification_run.evidence.is_empty()
            && self.verification_run.evidence.iter().all(|evidence| {
                matches!(
                    evidence.freshness,
                    EvidenceFreshness::ExactCandidate
                        | EvidenceFreshness::ExactCommit
                        | EvidenceFreshness::ExactQuiescedWorktree
                ) && evidence.coverage == EvidenceCoverage::CompleteForScope
            })
            && self
                .raw_artifact_bindings
                .iter()
                .all(|artifact| !artifact.truncated)
    }
}

/// Rejects a receipt that fails owner validation or a non-terminal job.
fn check_testd_receipt_terminal(
    job: &TestJob,
    receipt: &VerificationReceipt,
) -> Result<(), CompositionError> {
    receipt.validate(job).map_err(|error| {
        verifier_fact_error(format!("TestD receipt validation failed: {error}"))
    })?;
    if !job.state.is_terminal() {
        return Err(verifier_fact_error(
            "TestD verifier fact requires a terminal job",
        ));
    }
    Ok(())
}

/// Rejects a receipt that does not bind the current canonical fence.
fn check_testd_receipt_fence(
    job: &TestJob,
    receipt: &VerificationReceipt,
    state_fence: &StateFence,
) -> Result<(), CompositionError> {
    if job.execution != Some(receipt.execution)
        || job.invocation.request.state_fence != *state_fence
        || receipt.authority_epoch != state_fence.authority_epoch
        || receipt.generation != state_fence.resource_generation.value()
    {
        return Err(verifier_fact_error(
            "TestD receipt does not bind to the current canonical fence",
        ));
    }
    Ok(())
}

/// Admits the canonical verifier plan for one task revision and binds the
/// `TestD` request to it. Returns the borrowed verifier plan binding.
fn admitted_testd_verifier_plan<'a>(
    plan: &'a CanonicalPlanBinding,
    task_id: &TaskId,
    task_revision: u64,
    job: &TestJob,
) -> Result<&'a CanonicalVerifierPlanBinding, CompositionError> {
    if plan.task_id != *task_id || task_revision == 0 {
        return Err(verifier_fact_error(
            "verifier fact task or plan binding is invalid",
        ));
    }
    plan.validate()?;
    let verifier_plan = plan.verifier_binding().map_err(|error| {
        verifier_fact_error(format!(
            "canonical plan has no verifier profile/config/scope/artifact binding: {error}"
        ))
    })?;
    if job.invocation.request.task_id.as_ref() != Some(task_id) {
        return Err(verifier_fact_error(
            "TestD verifier request is not bound to the canonical plan",
        ));
    }
    Ok(verifier_plan)
}

/// Whether the observed invocation equals the exact canonical plan request,
/// including the plan-bound `TaskContract` acceptance denominator and its
/// explicit test join (issue #325 P1, I7.9).
fn verifier_invocation_matches_plan(
    invocation: &CanonicalVerifierInvocationBinding,
    verifier_plan: &CanonicalVerifierPlanBinding,
) -> bool {
    invocation.instrument == verifier_plan.instrument
        && invocation.kind == verifier_plan.kind
        && invocation.profile == verifier_plan.profile
        && invocation.target == verifier_plan.target
        && invocation.arguments == verifier_plan.arguments
        && invocation.declared_scope == verifier_plan.declared_scope
        && invocation.input_artifacts == verifier_plan.input_artifacts
        && invocation.required_test_ids == verifier_plan.required_test_ids
        && invocation.required_acceptance_item_ids == verifier_plan.required_acceptance_item_ids
        && invocation.task_acceptance_digest == verifier_plan.task_acceptance_digest
        && invocation.acceptance_verifier_map == verifier_plan.acceptance_verifier_map
        && invocation.evaluator == verifier_plan.evaluator
        && invocation.evaluator_version == verifier_plan.evaluator_version
        && invocation.config_hash == verifier_plan.planned.verifier_config_hash
}

/// Rebuilds the observed invocation binding and requires it to equal the
/// exact canonical plan request.
fn matched_testd_invocation(
    job_invocation: &InstrumentInvocation,
    verifier_plan: &CanonicalVerifierPlanBinding,
) -> Result<CanonicalVerifierInvocationBinding, CompositionError> {
    let invocation =
        CanonicalVerifierInvocationBinding::from_invocation(job_invocation, verifier_plan)?;
    if !verifier_invocation_matches_plan(&invocation, verifier_plan) {
        return Err(verifier_fact_error(
            "observed TestD invocation is not the exact canonical plan request",
        ));
    }
    Ok(invocation)
}

/// Validates the terminal execution outcome and builds its canonical binding.
fn checked_testd_terminal_binding(
    run: &VerificationRun,
    state_fence: &StateFence,
    job: &TestJob,
    receipt: &VerificationReceipt,
    verifier_plan: &CanonicalVerifierPlanBinding,
) -> Result<TerminalVerifierBinding, CompositionError> {
    run.validate().map_err(|error| {
        verifier_fact_error(format!("VerificationRun validation failed: {error}"))
    })?;
    if !run.execution.is_terminal()
        || run.state_fence != *state_fence
        || run.invocation_id.as_str() != job.invocation.request.request_id.as_str()
        || run.invocation_id.as_str() != receipt.invocation_id
        || run.execution != receipt.execution
    {
        return Err(verifier_fact_error(
            "VerificationRun is not the terminal TestD execution outcome",
        ));
    }
    let evidence_refs: Vec<_> = run
        .raw_evidence
        .iter()
        .cloned()
        .chain(
            run.evidence
                .iter()
                .map(|evidence| evidence.evidence_id.clone()),
        )
        .collect();
    let terminal_binding = TerminalVerifierBinding {
        planned: verifier_plan.planned.clone(),
        evidence: VerifierEvidenceRef {
            run_id: run.run_id.clone(),
            verifier_id: run.verifier.clone(),
            scope: run.scope.clone(),
            execution: run.execution,
            outcome: run.outcome,
            proof_ceiling: verifier_plan.planned.proof_ceiling,
            evidence_refs,
        },
    };
    terminal_binding.validate().map_err(|error| {
        verifier_fact_error(format!("terminal verifier binding invalid: {error}"))
    })?;
    if terminal_binding.evidence.run_id != run.run_id
        || terminal_binding.evidence.verifier_id != run.verifier
        || terminal_binding.evidence.scope != run.scope
        || terminal_binding.evidence.execution != run.execution
        || terminal_binding.evidence.outcome != run.outcome
    {
        return Err(verifier_fact_error(
            "terminal verifier binding does not match the executed run",
        ));
    }
    if terminal_binding.planned.verifier_id != verifier_plan.planned.verifier_id
        || terminal_binding.planned.scope != verifier_plan.declared_scope
        || terminal_binding.planned.verifier_config_hash
            != verifier_plan.planned.verifier_config_hash
        || terminal_binding.planned.contract_revision != verifier_plan.planned.contract_revision
        || run.verifier != verifier_plan.evaluator
        || run.scope != job.invocation.declared_scope
    {
        return Err(verifier_fact_error(
            "terminal verifier configuration is not the canonical requested profile/revision",
        ));
    }
    Ok(terminal_binding)
}

/// Requires the run's raw and normalized evidence to stay inside the `TestD`
/// receipt lineage bound by the terminal binding.
fn check_testd_artifact_lineage(
    receipt: &VerificationReceipt,
    run: &VerificationRun,
    terminal_binding: &TerminalVerifierBinding,
) -> Result<(), CompositionError> {
    let raw_handles: BTreeSet<String> = receipt
        .raw_artifacts
        .iter()
        .map(|artifact| artifact.handle.clone())
        .collect();
    let run_raw_handles: BTreeSet<String> =
        run.raw_evidence.iter().map(ToString::to_string).collect();
    if !run_raw_handles.is_subset(&raw_handles) {
        return Err(verifier_fact_error(
            "VerificationRun raw evidence is outside the TestD receipt",
        ));
    }
    for evidence in &run.evidence {
        if !raw_handles.contains(evidence.raw_artifact_id.as_str()) {
            return Err(verifier_fact_error(
                "normalized verifier evidence is outside the TestD receipt",
            ));
        }
    }
    let run_artifacts: BTreeSet<String> = run
        .raw_evidence
        .iter()
        .map(ToString::to_string)
        .chain(
            run.evidence
                .iter()
                .map(|evidence| evidence.evidence_id.to_string()),
        )
        .collect();
    if terminal_binding
        .evidence
        .evidence_refs
        .iter()
        .any(|reference| !run_artifacts.contains(reference.as_str()))
    {
        return Err(verifier_fact_error(
            "terminal verifier evidence references an unbound artifact",
        ));
    }
    Ok(())
}

/// Validates fact identity, fence, plan admission, and the observed
/// invocation shape. Returns the borrowed verifier plan binding.
fn checked_fact_identity_and_plan<'a>(
    fact: &'a CanonicalVerifierExecutionFact,
    expected_fence: &StateFence,
) -> Result<&'a CanonicalVerifierPlanBinding, CompositionError> {
    if &fact.state_fence != expected_fence
        || fact.task_id.trim().is_empty()
        || fact.task_id.chars().any(char::is_control)
        || fact.job_id.trim().is_empty()
        || fact.job_id.chars().any(char::is_control)
        || fact.task_revision == 0
    {
        return Err(verifier_fact_error(
            "canonical verifier fact has an invalid task, job, or fence",
        ));
    }
    fact.state_fence
        .validate()
        .map_err(|error| verifier_fact_error(error.to_string()))?;
    fact.plan.validate()?;
    if fact.plan.task_id.as_str() != fact.task_id {
        return Err(verifier_fact_error(
            "canonical verifier fact plan is task-mismatched",
        ));
    }
    let verifier_plan = fact.plan.verifier_binding().map_err(|error| {
        verifier_fact_error(format!(
            "persisted verifier fact has no canonical verifier plan binding: {error}"
        ))
    })?;
    fact.invocation.validate()?;
    Ok(verifier_plan)
}

/// Requires the persisted invocation to equal the canonical plan config,
/// including the acceptance denominator and test join (issue #325 P1, I7.9).
fn check_fact_invocation_matches_plan(
    fact: &CanonicalVerifierExecutionFact,
    verifier_plan: &CanonicalVerifierPlanBinding,
) -> Result<(), CompositionError> {
    if !verifier_invocation_matches_plan(&fact.invocation, verifier_plan) {
        return Err(verifier_fact_error(
            "persisted verifier invocation does not match canonical plan config",
        ));
    }
    Ok(())
}

/// Validates input artifacts, the terminal run, its binding, and the exact
/// `TestD` receipt/source join.
fn check_fact_run_and_receipt(
    fact: &CanonicalVerifierExecutionFact,
    expected_fence: &StateFence,
    verifier_plan: &CanonicalVerifierPlanBinding,
) -> Result<(), CompositionError> {
    if fact.input_artifact_bindings.is_empty()
        || fact.input_artifact_bindings != verifier_plan.input_artifacts
    {
        return Err(verifier_fact_error(
            "persisted verifier input artifacts are not the canonical plan artifacts",
        ));
    }
    fact.verification_run.validate().map_err(|error| {
        verifier_fact_error(format!("persisted VerificationRun is invalid: {error}"))
    })?;
    if !fact.verification_run.execution.is_terminal()
        || fact.verification_run.state_fence != *expected_fence
    {
        return Err(verifier_fact_error(
            "persisted verifier run is not terminal or is stale",
        ));
    }
    fact.terminal_binding.validate().map_err(|error| {
        verifier_fact_error(format!("persisted terminal binding is invalid: {error}"))
    })?;
    if fact.terminal_binding.evidence.run_id != fact.verification_run.run_id
        || fact.terminal_binding.evidence.verifier_id != fact.verification_run.verifier
        || fact.terminal_binding.evidence.scope != fact.verification_run.scope
        || fact.terminal_binding.evidence.execution != fact.verification_run.execution
        || fact.terminal_binding.evidence.outcome != fact.verification_run.outcome
    {
        return Err(verifier_fact_error(
            "persisted terminal binding does not match the run",
        ));
    }
    validate_canonical_receipt_binding(&fact.receipt, &fact.state_fence)?;
    match &fact.source_observation {
        Some(observation) => observation.validate(&fact.receipt.source_root)?,
        None if fact.receipt.execution == ExecutionStatus::Succeeded => {
            return Err(verifier_fact_error(
                "successful verifier fact lacks an observed source identity",
            ));
        }
        None => {}
    }
    if fact.receipt.job_id != fact.job_id
        || fact.receipt.invocation_id != fact.verification_run.invocation_id.as_str()
        || fact.receipt.execution != fact.verification_run.execution
    {
        return Err(verifier_fact_error(
            "persisted receipt binding does not match the run",
        ));
    }
    if fact.verification_run.verifier != verifier_plan.evaluator
        || fact.verification_run.scope != fact.invocation.declared_scope
        || fact.verification_run.invocation_id.as_str() != fact.receipt.invocation_id
    {
        return Err(verifier_fact_error(
            "persisted verifier run is not bound to the admitted evaluator invocation",
        ));
    }
    Ok(())
}

/// Validates raw artifact bindings and the exact artifact lineage join.
fn check_fact_artifact_lineage(
    fact: &CanonicalVerifierExecutionFact,
) -> Result<(), CompositionError> {
    let mut handles = BTreeSet::new();
    for artifact in &fact.raw_artifact_bindings {
        if artifact.handle.trim().is_empty()
            || artifact.content_type.trim().is_empty()
            || artifact.handle.chars().any(char::is_control)
            || artifact.content_type.chars().any(char::is_control)
            || artifact.sha256.len() != 64
            || artifact
                .sha256
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            || !handles.insert(artifact.handle.clone())
        {
            return Err(verifier_fact_error(
                "persisted verifier artifact binding is invalid or duplicated",
            ));
        }
    }
    let run_artifacts: BTreeSet<String> = fact
        .verification_run
        .raw_evidence
        .iter()
        .map(ToString::to_string)
        .chain(
            fact.verification_run
                .evidence
                .iter()
                .map(|evidence| evidence.evidence_id.to_string()),
        )
        .collect();
    if fact
        .verification_run
        .raw_evidence
        .iter()
        .any(|reference| !handles.contains(reference.as_str()))
        || fact
            .verification_run
            .evidence
            .iter()
            .any(|evidence| !handles.contains(evidence.raw_artifact_id.as_str()))
        || fact
            .terminal_binding
            .evidence
            .evidence_refs
            .iter()
            .any(|reference| !run_artifacts.contains(reference.as_str()))
    {
        return Err(verifier_fact_error(
            "persisted verifier artifact lineage is not exact",
        ));
    }
    for evidence in &fact.verification_run.evidence {
        let Some(raw_handles) = evidence.value.get("raw_artifact_handles") else {
            continue;
        };
        let raw_handles = raw_handles.as_array().ok_or_else(|| {
            verifier_fact_error("normalized evidence raw_artifact_handles is not an array")
        })?;
        let mut seen_raw_handles = BTreeSet::new();
        for raw_handle in raw_handles {
            let raw_handle = raw_handle.as_str().ok_or_else(|| {
                verifier_fact_error(
                    "normalized evidence raw_artifact_handles contains a non-string value",
                )
            })?;
            if !handles.contains(raw_handle) || !seen_raw_handles.insert(raw_handle) {
                return Err(verifier_fact_error(
                    "normalized evidence names an unbound or duplicate raw artifact",
                ));
            }
        }
    }
    Ok(())
}

/// Requires a terminal job state and the exact single `TestD` effect receipt
/// join.
fn check_fact_terminal_effect_join(
    fact: &CanonicalVerifierExecutionFact,
    expected_fence: &StateFence,
) -> Result<(), CompositionError> {
    if !matches!(
        fact.job_state.as_str(),
        "succeeded" | "failed" | "cancelled" | "quarantined"
    ) {
        return Err(verifier_fact_error(
            "persisted verifier fact does not identify a terminal TestD job",
        ));
    }
    if fact.effect_reference_bindings.len() != 1
        || fact.effect_reference_bindings.iter().any(|effect| {
            effect.validate(&fact.task_id, expected_fence).is_err()
                || effect.receipt_sha256 != fact.receipt.receipt_sha256
                || effect.job_id != fact.receipt.job_id
                || effect.operation_id != fact.receipt.operation_id
                || effect.process_tree_id != fact.receipt.process_tree_id
                || effect.execution != fact.receipt.execution
        })
    {
        return Err(verifier_fact_error(
            "persisted verifier fact does not join its exact TestD effect receipt",
        ));
    }
    Ok(())
}

/// Domain separator for the `TaskContract` acceptance-set commitment, so this
/// digest can never be confused with a digest over any other collection.
const TASK_ACCEPTANCE_SET_DOMAIN: &str = "eliot/task-acceptance-set/v1";

/// Derives the acceptance-set commitment from the *enumerated* obligation set.
///
/// This is the mechanism that makes the contract acceptance digest load-bearing
/// rather than a free label. Before it existed, both sides of
/// [`ContractAcceptanceDenominator::admits`] validated only that the digest was
/// 64 lowercase hex characters, so a plan could declare a narrowed
/// `required_acceptance_item_ids` set while carrying a digest copied from a
/// larger contract set, and the equality check passed while proving nothing
/// about set identity. Binding the digest to the sorted enumeration closes that:
/// the plan's declared set and the owner's stated digest are then no longer two
/// independently typed labels, but one value and a hash of it, so a plan cannot
/// narrow the denominator without the recomputed commitment no longer matching
/// what the owner admitted.
///
/// The digest is over the sorted item ids only. It deliberately does not read a
/// submitter `satisfied` flag, a coverage row, or any other party-asserted
/// status: a claim about an obligation is not an identity of the obligation set.
///
/// # Errors
///
/// Returns [`CompositionError::Recovery`] when the set cannot be canonicalized.
///
/// Crate-private rather than private to this module so the finish owner can
/// re-derive the same commitment over its own rehydrated enumeration. It is a
/// pure hash of the set it is handed: it admits nothing, mints no identity, and
/// cannot by itself satisfy any check that compares its result.
pub(crate) fn task_acceptance_set_commitment(
    item_ids: &BTreeSet<String>,
) -> Result<String, CompositionError> {
    #[derive(Serialize)]
    struct Commitment<'a> {
        domain: &'a str,
        item_ids: &'a BTreeSet<String>,
    }
    let bytes = canonical_json_bytes(&Commitment {
        domain: TASK_ACCEPTANCE_SET_DOMAIN,
        item_ids,
    })
    .map_err(|error| {
        CompositionError::Recovery(format!(
            "task acceptance set canonicalization failed: {error}"
        ))
    })?;
    Ok(sha256_hex(&bytes))
}

/// The rehydrated current `TaskContract` acceptance set for one task
/// revision, read from the owner that holds the contract at the finish
/// decision.
///
/// This is the denominator of acceptance coverage (issue #325 P1, I7.9). It is
/// deliberately a distinct value from the canonical plan: a plan may *declare*
/// which obligations it believes exist, but only the contract owner decides
/// which obligations exist, and a plan that disagrees is refused rather than
/// silently shrinking the set the gate is computed over.
///
/// The set reaches the finish decision already bound to the owner by
/// [`ContractAcceptanceDenominator::admits`], so `item_ids` may only be a plan
/// enumeration that survives that proof. The construction site
/// (`produce_finish_evidence`) therefore still reads the ids from the plan
/// because the enumeration itself has to travel with the plan, and the owner
/// supplies the commitment that makes the enumeration provable rather than
/// merely plausible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractAcceptanceDenominator {
    /// Contract identity the acceptance set was rehydrated for.
    pub task_id: String,
    /// Exact task revision the contract set was read at.
    pub task_revision: u64,
    /// Contract acceptance digest at that revision, from the contract owner.
    pub acceptance_digest: String,
    /// Every acceptance item the current contract requires.
    pub item_ids: BTreeSet<String>,
}

impl ContractAcceptanceDenominator {
    /// Whether the plan's declared acceptance set is the set the owner committed
    /// to.
    ///
    /// The plan enumerates the obligations; the task-selection owner states the
    /// commitment it admitted for this exact task revision. The two are compared
    /// by *recomputing* the commitment from the plan's enumeration and requiring
    /// it to equal the owner's digest, so the check has set-identity content
    /// rather than label-equality content.
    ///
    /// This matters because a bare digest comparison proves nothing. Both
    /// `CanonicalVerifierPlanBinding::task_acceptance_digest` and
    /// `TaskSelectionEvidence::acceptance_digest` are validated only as 64
    /// lowercase hex characters, and the intake path that produces the selection
    /// digest can supply a caller-stated value or `sha256_hex` over the task
    /// goal. Under a bare comparison a plan could therefore declare one
    /// obligation of the contract's three and still pass, carrying a digest
    /// copied from a different (larger) set — a completeness check validated
    /// against a copy of one party's own list, which is the defect this
    /// replaces.
    ///
    /// The commitment is recomputed here rather than trusted from the plan
    /// binding, so the plan cannot satisfy this by restating a digest.
    fn admits(&self, verifier_plan: &CanonicalVerifierPlanBinding) -> bool {
        if self.item_ids.is_empty() || self.item_ids != verifier_plan.required_acceptance_item_ids {
            return false;
        }
        self.task_acceptance_set_commitment()
            .is_ok_and(|commitment| commitment == self.acceptance_digest)
    }

    /// Recomputes the commitment over the enumerated set this denominator
    /// carries, so `admits` never has to trust a digest reported by the plan.
    fn task_acceptance_set_commitment(&self) -> Result<String, CompositionError> {
        task_acceptance_set_commitment(&self.item_ids)
    }
}

/// One contract-owner acceptance-item set, admitted only by the owner's own
/// neutral read.
///
/// This type exists to carry *provenance* rather than data. The neutral
/// [`TaskContractAcceptanceSet`] is a store-neutral wire payload with public
/// fields and a self-satisfiable `validate()`, and any store adapter has to be
/// able to decode one — so it can never be the thing the finish path trusts.
/// Handing that payload to [`AcceptanceDenominatorError::bind`] as a plain
/// reference let a caller mint a set whose `items` equal the canonical plan's
/// declared list and whose `acceptance_digest` equals the plan's own
/// `task_acceptance_digest`, which is already forced to equal
/// `task_acceptance_set_commitment(plan_ids)`. That is a self-satisfiable
/// input: the comparison in `bind` was correct and the value being compared
/// was caller-authored, so the owner was never actually consulted.
///
/// The field is private, there is no `Default`, no `From`, no `Deserialize` and
/// no public constructor, so the only way to obtain one of these values is to
/// await [`KernelTransitionPort::task_contract_acceptance_set`] and admit the
/// result. I7.9 requires the Finish service to *rehydrate* the current
/// `TaskContract` and its acceptance items; a type whose construction is
/// unreachable except through the owner read is what makes "rehydrated" an
/// enforced property instead of a convention.
#[derive(Clone, Debug)]
pub struct RehydratedContractAcceptanceSet {
    /// Private on purpose: an accessible field would restore the very bypass
    /// this type exists to close, because a caller could then write into it.
    owner_set: TaskContractAcceptanceSet,
}

impl RehydratedContractAcceptanceSet {
    /// The only constructor, and it is crate-private on purpose.
    ///
    /// Its single production caller is
    /// `GovernorFinishAttempt::rehydrate_task_contract_acceptance`, which is the
    /// one place the finish path performs the owner's named read. Nothing in
    /// this crate can build this value from a literal, and nothing outside this
    /// crate can build it at all.
    pub(crate) const fn admit_owner_read(owner_set: TaskContractAcceptanceSet) -> Self {
        Self { owner_set }
    }

    /// The owner's own payload, exactly as the read returned it.
    ///
    /// This is the only way to read the admitted set, and it is crate-private:
    /// a consumer outside `eliot-governor` can pass one of these values on but
    /// cannot take one apart and reassemble a self-satisfiable payload for
    /// [`AcceptanceDenominatorError::bind`], because `bind` accepts only this
    /// type.
    pub(crate) const fn owner_set(&self) -> &TaskContractAcceptanceSet {
        &self.owner_set
    }
}

/// Closed failure set of the contract-owner acceptance denominator join.
///
/// Every arm is a refusal: no arm has a success meaning, and no arm names a
/// fallback set. In particular there is no arm that keeps the plan's declared
/// enumeration when the owner set is absent, because that is precisely the
/// narrowing defect I7.9 closes.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AcceptanceDenominatorError {
    /// The contract owner published no acceptance set for this task id.
    #[error("the contract owner has no acceptance item set for this task")]
    OwnerSetAbsent,
    /// The rehydrated set belongs to a different task than the finish attempt.
    #[error("the rehydrated contract acceptance set names another task")]
    TaskSubstituted,
    /// The rehydrated set is not current at the exact admitted task revision.
    #[error("the rehydrated contract acceptance set is not at the admitted task revision")]
    TaskRevisionStale,
    /// The rehydrated set was read under a different State Fence.
    #[error("the rehydrated contract acceptance set was read under another State Fence")]
    FenceStale,
    /// The owner set does not validate against the closed owner contract.
    #[error("the rehydrated contract acceptance set is malformed: {0}")]
    Malformed(String),
    /// The task-selection owner evidence does not commit to the enumerated set.
    ///
    /// This is the additional conjunct the design enforced before the
    /// owner-enumeration rehydration landed, and which that change dropped: the
    /// accepted task-and-plan-bound observation receipts' recorded
    /// `acceptance_digest` had to reproduce `task_acceptance_set_commitment`
    /// over the enumerated obligation set. The receipt digest is still
    /// cross-checked between receipts for mutual agreement, but on its own that
    /// only proves the receipts agree with each other, not that either commits
    /// to the denominator. Restoring the commitment keeps a receipt whose digest
    /// was issued for a different set from riding under an owner enumeration.
    #[error(
        "task-bound observation evidence does not commit to the enumerated acceptance item set"
    )]
    SelectionEvidenceDisagrees,
    /// The plan's declared enumeration is not the contract owner's enumeration.
    ///
    /// Reported item by item, never as a count alone, so the mismatch names
    /// exactly which obligations each side claims.
    #[error(
        "the canonical plan declares {} acceptance item(s) the contract owner does not \
         require, and omits {} obligation(s) it does",
        plan_only.len(),
        owner_only.len()
    )]
    PlanDisagreesWithContract {
        /// Obligations the plan declares that the contract owner does not require.
        plan_only: Vec<String>,
        /// Obligations the contract owner requires that the plan does not declare.
        owner_only: Vec<String>,
    },
}

impl AcceptanceDenominatorError {
    /// Joins the contract owner's enumeration with the plan's declared
    /// enumeration and returns the denominator the coverage gate is computed
    /// over.
    ///
    /// The denominator's `item_ids` are the CONTRACT OWNER's enumeration. The
    /// plan's `required_acceptance_item_ids` are compared against it item by
    /// item and are never adopted: a plan that declares a strict subset would
    /// otherwise report a smaller denominator as complete, and a plan that
    /// declares a strict superset would make the gate carry an obligation the
    /// contract never required. Neither is silently preferred over the other.
    ///
    /// `acceptance_digest` is the owner's OWN recorded value, never recomputed
    /// here and never taken from the caller. The existing
    /// [`CanonicalContractAcceptance::validate`] then proves that recorded
    /// value commits to the owner enumeration retained beside it, so a
    /// caller-stated digest issued for a different (larger) set cannot ride
    /// under an owner enumeration.
    ///
    /// `owner_set` is a [`RehydratedContractAcceptanceSet`], not the neutral
    /// payload. That is the whole enforcement: this signature has no arm that
    /// accepts a caller-assembled set, so a caller that narrows the
    /// denominator cannot reach this comparison at all — it cannot produce the
    /// argument. Before the parameter carried the neutral payload, a caller
    /// could build `items` equal to the plan's list and `acceptance_digest`
    /// equal to the plan's own `task_acceptance_digest` and pass here with
    /// zero owner involvement.
    pub(crate) fn bind(
        task_id: &str,
        task_revision: u64,
        owner_set: &RehydratedContractAcceptanceSet,
        verifier_plan: &CanonicalVerifierPlanBinding,
    ) -> Result<CanonicalContractAcceptance, Self> {
        let owner_set = owner_set.owner_set();
        owner_set
            .validate()
            .map_err(|error| Self::Malformed(error.to_string()))?;
        if owner_set.task_id.as_str() != task_id {
            return Err(Self::TaskSubstituted);
        }
        if owner_set.task_revision != task_revision {
            return Err(Self::TaskRevisionStale);
        }
        let owner_item_ids = owner_set.item_ids();
        if owner_item_ids.is_empty() {
            return Err(Self::OwnerSetAbsent);
        }
        let plan_only = verifier_plan
            .required_acceptance_item_ids
            .difference(&owner_item_ids)
            .cloned()
            .collect::<Vec<_>>();
        let owner_only = owner_item_ids
            .difference(&verifier_plan.required_acceptance_item_ids)
            .cloned()
            .collect::<Vec<_>>();
        if !plan_only.is_empty() || !owner_only.is_empty() {
            return Err(Self::PlanDisagreesWithContract {
                plan_only,
                owner_only,
            });
        }
        let acceptance = CanonicalContractAcceptance {
            task_id: task_id.to_owned(),
            task_revision,
            acceptance_digest: owner_set.acceptance_digest.clone(),
            item_ids: owner_item_ids,
        };
        acceptance
            .validate(task_id, task_revision)
            .map_err(|error| Self::Malformed(error.to_string()))?;
        Ok(acceptance)
    }
}

/// Rebuilds acceptance dispositions from the terminal verifier evidence
/// joined against the current canonical owner plan. Persisted `satisfied`
/// flags are never an independent source of acceptance truth.
///
/// I7.9 / issue #325 P1: the denominator is the rehydrated current
/// `TaskContract` acceptance set. The plan's
/// `required_acceptance_item_ids` is only *admitted* as that set by
/// [`ContractAcceptanceDenominator::admits`], which recomputes the
/// acceptance-set commitment from the plan's own enumeration and refuses unless
/// it equals the digest the caller rehydrated from the contract-owning
/// task-selection evidence at this exact task revision and fence. A plan that
/// names fewer obligations than the set the owner committed to therefore cannot
/// produce a smaller denominator that reads as complete: the coverage call
/// itself fails closed. The commitment is a hash of the enumeration rather than
/// a compared label, so it cannot be satisfied by restating a digest.
///
/// The denominator is never the selected `required_test_ids` inventory and
/// never the fact-embedded plan clone alone — a fact whose plan drifted from
/// the current owner plan fails closed here too. Every required acceptance
/// item is enumerated before any verifier evidence is joined; unmapped items
/// stay uncovered and can never yield `VERIFIED_COMPLETE` downstream. A
/// persisted `satisfied` flag is a submitter claim and is never read here.
pub(crate) fn acceptance_coverage_from_verifier_fact(
    contract: &ContractAcceptanceDenominator,
    plan: &CanonicalPlanBinding,
    fact: &CanonicalVerifierExecutionFact,
) -> Result<Vec<AcceptanceCoverage>, CompositionError> {
    if fact.plan != *plan {
        return Err(verifier_fact_error(
            "canonical verifier fact plan drifted from the current canonical owner plan",
        ));
    }
    let verifier_plan = plan.verifier_binding().map_err(|error| {
        verifier_fact_error(format!(
            "canonical finish plan has no verifier item bindings: {error}"
        ))
    })?;
    if !contract.admits(verifier_plan) {
        return Err(verifier_fact_error(
            "canonical verifier plan acceptance set disagrees with the rehydrated current TaskContract",
        ));
    }
    let run_ref = fact.verification_run.run_id.to_string();
    let run_is_current = matches!(
        fact.verification_run.freshness,
        EvidenceFreshness::ExactCandidate
            | EvidenceFreshness::ExactCommit
            | EvidenceFreshness::ExactQuiescedWorktree
    );
    let mut acceptance = Vec::with_capacity(contract.item_ids.len());
    for item_id in &contract.item_ids {
        acceptance.push(acceptance_coverage_for_item(
            item_id,
            verifier_plan,
            fact,
            &run_ref,
            run_is_current,
        ));
    }
    Ok(acceptance)
}

/// Projects one acceptance item's coverage from the executed verifier run.
///
/// This is the per-item half of [`acceptance_coverage_from_verifier_fact`], which
/// keeps the plan/fact/denominator refusals and delegates the projection here, so
/// neither half can grow into the other. It is a pure move of that loop body: it
/// raises no refusal of its own, so the only thing a caller can observe is the
/// `AcceptanceCoverage` it returns, and every check, comparison, order and effect
/// in it is the one the loop already performed.
///
/// The denominator decision is unchanged. `requires_verifier` is false only for an
/// explicitly empty mapping, so a *missing* mapping stays a verifier gap;
/// `satisfied` is true only for a current run whose every mapped test was observed
/// and every one of them passed; and a `mapped_events == 0` item keeps its
/// disposition tied to the raw run artifacts actually inspected rather than a
/// minted placeholder. A persisted `satisfied` flag is never an input here.
fn acceptance_coverage_for_item(
    item_id: &str,
    verifier_plan: &CanonicalVerifierPlanBinding,
    fact: &CanonicalVerifierExecutionFact,
    run_ref: &str,
    run_is_current: bool,
) -> AcceptanceCoverage {
    // Explicit acceptance-to-test join owned by the canonical plan. A
    // missing entry is an unmapped obligation; an empty test set declares
    // a non-test obligation that executed verifier runs alone cannot
    // satisfy. Neither form shrinks the denominator to the test list.
    let mapped = verifier_plan
        .acceptance_verifier_map
        .get(item_id)
        .cloned()
        .unwrap_or_default();
    let mut evidence_refs = BTreeSet::new();
    let mut mapped_events = 0_usize;
    let mut all_mapped_observed = true;
    let mut all_pass = true;
    for test_id in &mapped {
        let test_events = fact
            .verification_run
            .evidence
            .iter()
            .filter(|event| {
                event
                    .value
                    .get("nextest_test_id")
                    .and_then(serde_json::Value::as_str)
                    == Some(test_id.as_str())
            })
            .collect::<Vec<_>>();
        if test_events.is_empty() {
            all_mapped_observed = false;
        }
        for event in test_events {
            mapped_events += 1;
            evidence_refs.insert(event.evidence_id.to_string());
            evidence_refs.insert(event.raw_artifact_id.to_string());
            if let Some(handles) = event
                .value
                .get("raw_artifact_handles")
                .and_then(serde_json::Value::as_array)
            {
                evidence_refs.extend(
                    handles
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned),
                );
            }
            if event
                .value
                .get("nextest_status")
                .and_then(serde_json::Value::as_str)
                != Some("PASS")
            {
                all_pass = false;
            }
        }
    }
    if mapped_events == 0 {
        // Keep the negative item disposition tied to the actual raw run
        // artifacts inspected; never mint a placeholder item receipt.
        evidence_refs.extend(
            fact.verification_run
                .raw_evidence
                .iter()
                .map(ToString::to_string),
        );
    }
    // An item is satisfied only for a current run where every bound test
    // executed and every bound execution passed. Failed, stale,
    // not-executed, simulated (non-productive, hence non-certifying and
    // stale-marked upstream), unmapped, and non-test obligations stay
    // uncovered here and fail closed in `derive_finish_decision`.
    let satisfied = run_is_current && !mapped.is_empty() && all_mapped_observed && all_pass;
    let verifier_run_refs = if mapped_events == 0 {
        Vec::new()
    } else {
        vec![run_ref.to_owned()]
    };
    // Only an explicit empty mapping declares a non-test obligation that
    // does not require a verifier run. A missing mapping stays a
    // verifier gap so absent coverage fails closed downstream.
    let requires_verifier = !matches!(
        verifier_plan.acceptance_verifier_map.get(item_id),
        Some(tests) if tests.is_empty()
    );
    AcceptanceCoverage {
        item_id: item_id.to_owned(),
        satisfied,
        evidence_refs: evidence_refs.into_iter().collect(),
        verifier_run_refs,
        requires_verifier,
    }
}

fn verifier_fact_error(reason: impl Into<String>) -> CompositionError {
    CompositionError::Recovery(format!(
        "canonical verifier execution fact: {}",
        reason.into()
    ))
}

fn canonical_job_state(state: JobState) -> &'static str {
    match state {
        JobState::Succeeded => "succeeded",
        JobState::Failed => "failed",
        JobState::Cancelled => "cancelled",
        JobState::Quarantined => "quarantined",
        JobState::Queued | JobState::Running | JobState::RetryWait => "non_terminal",
    }
}

fn validate_canonical_receipt_binding(
    binding: &CanonicalVerifierReceiptBinding,
    expected_fence: &StateFence,
) -> Result<(), CompositionError> {
    let text_fields = [
        (&binding.job_id, "job_id"),
        (&binding.operation_id, "operation_id"),
        (&binding.process_tree_id, "process_tree_id"),
        (&binding.invocation_id, "invocation_id"),
        (&binding.invocation_digest, "invocation_digest"),
        (&binding.allowed_contour_root, "allowed_contour_root"),
        (&binding.source_root, "source_root"),
        (&binding.target_root, "target_root"),
        (&binding.cache_root, "cache_root"),
    ];
    if text_fields
        .iter()
        .any(|(value, _)| value.trim().is_empty() || value.chars().any(char::is_control))
        || binding.generation != expected_fence.resource_generation.value()
        || binding.authority_epoch != expected_fence.authority_epoch
        || !binding.execution.is_terminal()
    {
        return Err(verifier_fact_error(
            "persisted TestD receipt identity is stale or malformed",
        ));
    }
    Ok(())
}

/// Persisted current-plan authority for one exact Governor fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalAdmissionSnapshot {
    pub state_fence: StateFence,
    pub owner_revision: u64,
    pub current_plan: Option<CanonicalPlanBinding>,
    /// Last terminal verifier execution fact admitted for this exact task,
    /// plan, artifact lineage, and fence.
    #[serde(default)]
    pub verifier_execution_fact: Option<CanonicalVerifierExecutionFact>,
    /// Canonical evidence required to evaluate a finish candidate.  The
    /// candidate draft never supplies this record; it is rehydrated with the
    /// current canonical owner image and must carry the same fence as it.
    #[serde(default)]
    pub finish_evidence: Option<CanonicalFinishEvidence>,
}

/// The acceptance set the finish coverage was computed over, retained with the
/// canonical finish evidence so the persisted owner image carries the
/// denominator rather than only the plan's claim about it.
///
/// Issue #325 P1, I7.9. `acceptance_digest` is the contract-side identity,
/// rehydrated from the task-selection owner; `item_ids` is the enumeration the
/// plan declares for that digest. The digest is what makes the enumeration
/// admissible as the contract's obligation set, because `validate` recomputes
/// it over the retained enumeration — so a plan bound to a different contract
/// revision, or one that declares a set its digest does not commit to, is
/// refused instead of quietly reporting a smaller denominator. Recomputing on
/// the read path also means a persisted record cannot be rehydrated with a
/// digest that was merely well-formed.
///
/// Absent on the wire is a rehydration gap, never an empty obligation set:
/// [`CanonicalFinishEvidence::validate`] refuses it, so a record persisted
/// without the contract's acceptance set cannot be read back as complete
/// coverage.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalContractAcceptance {
    /// Contract identity the acceptance set was rehydrated for.
    pub task_id: String,
    /// Exact task revision the contract set was read at.
    pub task_revision: u64,
    /// Contract acceptance digest at that revision, from the contract owner.
    pub acceptance_digest: String,
    /// Every acceptance item the current contract requires.
    pub item_ids: BTreeSet<String>,
}

impl CanonicalContractAcceptance {
    fn validate(&self, task_id: &str, task_revision: u64) -> Result<(), CompositionError> {
        if self.task_id != task_id
            || self.task_revision != task_revision
            || self.acceptance_digest.len() != 64
            || self
                .acceptance_digest
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            || self.item_ids.is_empty()
            || self
                .item_ids
                .iter()
                .any(|item_id| item_id.trim().is_empty() || item_id.chars().any(char::is_control))
        {
            return Err(CompositionError::Recovery(
                "canonical contract acceptance set is absent, stale, or malformed".to_owned(),
            ));
        }
        // The retained digest is only the contract's acceptance identity when it
        // commits to the retained enumeration. Without this, a record could be
        // rehydrated with any 64-hex digest beside any item set and would read
        // back as an owner-issued acceptance set that was never issued.
        if task_acceptance_set_commitment(&self.item_ids)? != self.acceptance_digest {
            return Err(CompositionError::Recovery(
                "canonical contract acceptance digest does not commit to its retained acceptance \
                 item set"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn denominator(&self) -> ContractAcceptanceDenominator {
        ContractAcceptanceDenominator {
            task_id: self.task_id.clone(),
            task_revision: self.task_revision,
            acceptance_digest: self.acceptance_digest.clone(),
            item_ids: self.item_ids.clone(),
        }
    }
}

/// Canonical owner evidence consumed by the Governor finish path.
///
/// This is deliberately a projection owned by the canonical owner, rather
/// than a second finish machine.  `FinishService` derives the decision from
/// this record; the Store only persists the resulting receipt projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalFinishEvidence {
    /// Fence at which the evidence was observed.
    pub state_fence: StateFence,
    /// Rehydrated current `TaskContract` acceptance set: the denominator the
    /// acceptance coverage below was computed over (issue #325 P1, I7.9).
    ///
    /// It is rehydrated from the contract owner with the rest of this record
    /// and is never accepted from the finish caller, so the persisted receipt
    /// cannot claim a complete coverage set the contract owner never named.
    pub contract_acceptance: CanonicalContractAcceptance,
    /// Acceptance, artifact, verifier, and effect evidence from canonical
    /// state.  It is never accepted from the finish caller.
    pub evidence: FinishEvidence,
    /// Exact effect receipts joined to the terminal verifier owner fact.
    pub effect_reference_bindings: Vec<CanonicalVerifierEffectBinding>,
    /// Closure observation for admitted descendants and external effects.
    pub descendant_closure: DescendantClosure,
    /// Authority owner reference for finish evaluation.
    pub finish_authority_ref: String,
    /// Optional explicit authority for a closing lifecycle action.
    pub closure_authority_ref: Option<String>,
}

impl CanonicalFinishEvidence {
    /// Validates the evidence against one active canonical fence.
    pub fn validate(&self, expected_fence: &StateFence) -> Result<(), CompositionError> {
        if &self.state_fence != expected_fence {
            return Err(CompositionError::Recovery(
                "canonical finish evidence has a stale state fence".to_owned(),
            ));
        }
        self.state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        self.evidence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self.evidence.task_id.trim().is_empty()
            || self.evidence.task_id.chars().any(char::is_control)
        {
            return Err(CompositionError::Recovery(
                "canonical finish evidence task identity is invalid".to_owned(),
            ));
        }
        // The acceptance denominator is rehydrated with the rest of this record
        // and must name this exact task revision. A missing or drifted
        // contract acceptance set is a recovery gap, never an empty
        // obligation set that would let the coverage gate read as complete.
        self.contract_acceptance
            .validate(&self.evidence.task_id, self.evidence.current_task_revision)?;
        if self.finish_authority_ref.trim().is_empty()
            || self.finish_authority_ref.chars().any(char::is_control)
        {
            return Err(CompositionError::Recovery(
                "canonical finish authority reference is invalid".to_owned(),
            ));
        }
        if let Some(reference) = &self.closure_authority_ref
            && (reference.trim().is_empty() || reference.chars().any(char::is_control))
        {
            return Err(CompositionError::Recovery(
                "canonical closure authority reference is invalid".to_owned(),
            ));
        }
        if self.effect_reference_bindings.is_empty()
            || self.effect_reference_bindings.iter().any(|effect| {
                effect
                    .validate(&self.evidence.task_id, expected_fence)
                    .is_err()
            })
        {
            return Err(CompositionError::Recovery(
                "canonical finish evidence has no valid owner-bound effect receipt".to_owned(),
            ));
        }
        match &self.descendant_closure {
            DescendantClosure::Complete { receipt_ref }
                if !self.evidence.artifact_refs.contains(receipt_ref) =>
            {
                return Err(CompositionError::Recovery(
                    "complete descendant closure is missing its owner receipt artifact".to_owned(),
                ));
            }
            DescendantClosure::Incomplete { unresolved_refs }
                if unresolved_refs
                    .iter()
                    .any(|reference| !self.evidence.unresolved_effect_refs.contains(reference)) =>
            {
                return Err(CompositionError::Recovery(
                    "descendant closure is not joined to unresolved effect dispositions".to_owned(),
                ));
            }
            DescendantClosure::Unknown { reason_ref }
                if !self.evidence.unresolved_effect_refs.contains(reason_ref)
                    && !self.evidence.artifact_refs.contains(reason_ref) =>
            {
                return Err(CompositionError::Recovery(
                    "unknown descendant closure has no canonical owner reference".to_owned(),
                ));
            }
            DescendantClosure::Complete { .. }
            | DescendantClosure::Incomplete { .. }
            | DescendantClosure::Unknown { .. } => {}
        }
        Ok(())
    }

    fn validate_owner_joins(
        &self,
        plan: &CanonicalPlanBinding,
        fact: &CanonicalVerifierExecutionFact,
    ) -> Result<(), CompositionError> {
        if self.evidence.task_id != fact.task_id
            || self.evidence.current_task_revision != fact.task_revision
            || plan != &fact.plan
            || plan.task_id.as_str() != self.evidence.task_id
            || self.effect_reference_bindings != fact.effect_reference_bindings
        {
            return Err(CompositionError::Recovery(
                "canonical finish evidence does not join the current plan, task, or verifier effect owner"
                    .to_owned(),
            ));
        }
        let run_ref = fact.verification_run.run_id.to_string();
        if self.evidence.executed_verifier_run_refs != [run_ref.clone()] {
            return Err(CompositionError::Recovery(
                "canonical finish evidence does not name its exact executed verifier run"
                    .to_owned(),
            ));
        }
        let expected_stale = if fact.certifies_completion() {
            Vec::new()
        } else {
            vec![run_ref]
        };
        if self.evidence.stale_verifier_run_refs != expected_stale {
            return Err(CompositionError::Recovery(
                "canonical verifier execution/outcome disposition is not joined to finish evidence"
                    .to_owned(),
            ));
        }
        if self.evidence.acceptance
            != acceptance_coverage_from_verifier_fact(
                &self.contract_acceptance.denominator(),
                plan,
                fact,
            )?
        {
            return Err(CompositionError::Recovery(
                "canonical per-item acceptance dispositions differ from verifier evidence"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

impl CanonicalAdmissionSnapshot {
    /// Constructs a snapshot only after validating its complete bounded shape.
    pub fn new(
        state_fence: StateFence,
        owner_revision: u64,
        current_plan: Option<CanonicalPlanBinding>,
    ) -> Result<Self, CompositionError> {
        let snapshot = Self {
            state_fence,
            owner_revision,
            current_plan,
            verifier_execution_fact: None,
            finish_evidence: None,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Validates snapshot identity and counters without choosing a plan.
    pub fn validate(&self) -> Result<(), CompositionError> {
        self.state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self.owner_revision == 0 {
            return Err(CompositionError::Recovery(
                "canonical owner revision is zero".to_owned(),
            ));
        }
        if let Some(current_plan) = &self.current_plan {
            current_plan.validate()?;
        }
        if let Some(fact) = &self.verifier_execution_fact {
            fact.validate(&self.state_fence)?;
            let current_plan = self.current_plan.as_ref().ok_or_else(|| {
                CompositionError::Recovery(
                    "canonical verifier fact has no current plan owner".to_owned(),
                )
            })?;
            if current_plan != &fact.plan || current_plan.task_id.as_str() != fact.task_id {
                return Err(CompositionError::Recovery(
                    "canonical verifier fact does not match the current plan".to_owned(),
                ));
            }
        }
        if let Some(finish_evidence) = &self.finish_evidence {
            finish_evidence.validate(&self.state_fence)?;
            let current_plan = self.current_plan.as_ref().ok_or_else(|| {
                CompositionError::Recovery(
                    "canonical finish evidence has no current plan owner".to_owned(),
                )
            })?;
            let fact = self.verifier_execution_fact.as_ref().ok_or_else(|| {
                CompositionError::Recovery(
                    "canonical finish evidence has no verifier execution owner".to_owned(),
                )
            })?;
            finish_evidence.validate_owner_joins(current_plan, fact)?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalAdmissionSnapshotWire {
    state_fence: StateFence,
    owner_revision: u64,
    current_plan: Option<CanonicalPlanBinding>,
    #[serde(default)]
    verifier_execution_fact: Option<CanonicalVerifierExecutionFact>,
    #[serde(default)]
    finish_evidence: Option<CanonicalFinishEvidence>,
}

impl<'de> Deserialize<'de> for CanonicalAdmissionSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CanonicalAdmissionSnapshotWire::deserialize(deserializer)?;
        let snapshot = Self {
            state_fence: wire.state_fence,
            owner_revision: wire.owner_revision,
            current_plan: wire.current_plan,
            verifier_execution_fact: wire.verifier_execution_fact,
            finish_evidence: wire.finish_evidence,
        };
        snapshot
            .validate()
            .map(|()| snapshot)
            .map_err(serde::de::Error::custom)
    }
}

/// Canonical owner with no store or provider field.
#[derive(Clone, Debug)]
pub struct CanonicalAdmissionOwner {
    state_fence: StateFence,
    scope: ScopeRevisionView,
    snapshot: CanonicalAdmissionSnapshot,
}

/// One coherent semantic activation projection assembled from owner reads.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorActivationSnapshot {
    pub state_fence: StateFence,
    /// Current canonical owner revision observed with this snapshot.
    pub owner_revision: u64,
    pub principal_id: String,
    pub session_id: String,
    pub task_id: TaskId,
    pub work_unit_id: String,
    pub work_scope_id: String,
    pub task_revision: u64,
    pub plan_id: String,
    pub plan_revision: String,
}

impl CanonicalAdmissionOwner {
    /// Creates the sole semantic Canonical owner for one fence.
    pub fn new(
        state_fence: StateFence,
        scope: ScopeRevisionView,
        snapshot: CanonicalAdmissionSnapshot,
    ) -> Result<Self, CompositionError> {
        state_fence
            .validate()
            .map_err(|error| CompositionError::Owner(error.to_string()))?;
        scope
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if scope.state_fence != state_fence {
            return Err(CompositionError::Recovery(
                "canonical scope snapshot fence does not match owner fence".to_owned(),
            ));
        }
        snapshot.validate()?;
        if snapshot.state_fence != state_fence {
            return Err(CompositionError::Recovery(
                "canonical admission snapshot fence does not match owner fence".to_owned(),
            ));
        }
        Ok(Self {
            state_fence,
            scope,
            snapshot,
        })
    }

    /// Produces the immutable transition; no transport is touched here.
    pub fn prepare(
        &self,
        envelope: &CanonicalWriteEnvelope,
    ) -> Result<PreparedTransition, CompositionError> {
        if envelope.request.state_fence != self.state_fence {
            return Err(CompositionError::Provider(
                "Canonical request fence does not match the active Kernel fence".to_owned(),
            ));
        }
        Ok(envelope.prepare()?)
    }

    /// Sends only a Canonical-produced transition to the neutral Kernel port
    /// under the exact admitted request identity.
    ///
    /// The identity comes from admitted ingress, not from the envelope: the
    /// envelope's request binding and idempotency key must agree exactly with
    /// the admitted identity, and the immutable transition derived from the
    /// envelope must agree with both. Any substitution of the binding,
    /// operation/idempotency terms, deadline or cancellation fails closed
    /// here; nothing is rehashed or repaired locally, preserving the shared
    /// canonical hashing contract. The transport peer stays distinct from the
    /// initiating principal/session: this method never rewrites the
    /// identity's source. `prepare()` alone remains non-authorizing.
    pub(crate) async fn commit<P: KernelTransitionPort + ?Sized>(
        &self,
        port: &P,
        identity: &RequestIdentity,
        envelope: CanonicalWriteEnvelope,
    ) -> Result<WriteReceipt, CompositionError> {
        identity
            .validate()
            .map_err(|error| CompositionError::Provider(error.to_string()))?;
        if envelope.request != identity.request.metadata {
            return Err(CompositionError::Provider(
                "admitted request binding does not match the Canonical envelope request".to_owned(),
            ));
        }
        if envelope.idempotency_key != identity.idempotency_key {
            return Err(CompositionError::Provider(
                "admitted idempotency key does not match the Canonical envelope".to_owned(),
            ));
        }
        let expected_revision_heads = envelope.expected_revision_heads.clone();
        let expected_ordering_heads = envelope.expected_ordering_heads.clone();
        let transition = self.prepare(&envelope)?;
        if transition.identity.idempotency_key != identity.idempotency_key
            || transition.state_fence != identity.request.metadata.state_fence
        {
            return Err(CompositionError::Provider(
                "immutable transition does not agree with the admitted request identity".to_owned(),
            ));
        }
        Ok(port
            .apply_prepared(
                identity,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await?)
    }

    /// Returns the active fence without exposing mutable canonical state.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the canonical revision/order heads used for admission.
    #[must_use]
    pub const fn scope(&self) -> &ScopeRevisionView {
        &self.scope
    }

    /// Reads the exact current plan only under its retained state fence.
    pub fn read_current_plan(
        &self,
        state_fence: &StateFence,
    ) -> Result<CanonicalPlanBinding, CompositionError> {
        state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self.state_fence != *state_fence
            || self.scope.state_fence != *state_fence
            || self.snapshot.state_fence != *state_fence
        {
            return Err(CompositionError::Recovery(
                "canonical plan read used a stale state fence".to_owned(),
            ));
        }
        self.snapshot.validate()?;
        self.snapshot.current_plan.clone().ok_or_else(|| {
            CompositionError::Recovery(
                "canonical current plan is absent; semantic activation is unavailable".to_owned(),
            )
        })
    }

    /// Reads the current plan for activation through typed failure classes.
    /// Unlike the general finish/recovery reader, this boundary never exposes
    /// human error text as a semantic classifier.
    pub(crate) fn read_current_activation_plan(
        &self,
        state_fence: &StateFence,
    ) -> Result<CanonicalPlanBinding, CompositionError> {
        state_fence
            .validate()
            .map_err(|_| CompositionError::ActivationStaleFence)?;
        if self.state_fence != *state_fence
            || self.scope.state_fence != *state_fence
            || self.snapshot.state_fence != *state_fence
        {
            return Err(CompositionError::ActivationStaleFence);
        }
        self.snapshot
            .validate()
            .map_err(|_| CompositionError::ActivationStaleFence)?;
        self.snapshot
            .current_plan
            .clone()
            .ok_or(CompositionError::ActivationScopeSelectionRequired)
    }

    /// Returns the durable canonical owner revision used by a finish-evidence
    /// compare-and-set.
    #[must_use]
    pub const fn owner_revision(&self) -> u64 {
        self.snapshot.owner_revision
    }

    /// Builds the next canonical owner image after a verifier has completed
    /// and its durable TestD row has been rehydrated. The fact is retained
    /// even when its execution/outcome is non-certifying; finish evaluation
    /// must see the real failed, stale, partial, or unknown run rather than a
    /// caller assertion or a missing-value default.
    pub fn prepare_verifier_execution_fact(
        &self,
        fact: CanonicalVerifierExecutionFact,
    ) -> Result<CanonicalAdmissionSnapshot, CompositionError> {
        fact.validate(&self.state_fence)?;
        if let Some(plan) = &self.snapshot.current_plan
            && (plan.task_id.as_str() != fact.task_id
                || plan.plan_id != fact.plan.plan_id
                || plan.plan_revision != fact.plan.plan_revision)
        {
            return Err(CompositionError::Recovery(
                "verifier execution fact does not match the current canonical plan".to_owned(),
            ));
        }
        let owner_revision = self.snapshot.owner_revision.checked_add(1).ok_or_else(|| {
            CompositionError::Recovery("canonical owner revision overflow".to_owned())
        })?;
        let snapshot = CanonicalAdmissionSnapshot {
            state_fence: self.state_fence.clone(),
            owner_revision,
            current_plan: self.snapshot.current_plan.clone(),
            verifier_execution_fact: Some(fact),
            finish_evidence: self.snapshot.finish_evidence.clone(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Reads the exact verifier execution fact retained by the canonical
    /// owner at the active fence. Absence is a recovery gap, never an empty
    /// verifier result.
    pub fn read_verifier_execution_fact(
        &self,
        state_fence: &StateFence,
    ) -> Result<CanonicalVerifierExecutionFact, CompositionError> {
        state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self.state_fence != *state_fence
            || self.scope.state_fence != *state_fence
            || self.snapshot.state_fence != *state_fence
        {
            return Err(CompositionError::Recovery(
                "canonical verifier fact read used a stale state fence".to_owned(),
            ));
        }
        let fact = self
            .snapshot
            .verifier_execution_fact
            .clone()
            .ok_or_else(|| {
                CompositionError::Recovery(
                    "canonical verifier execution fact is absent; completion proof is unavailable"
                        .to_owned(),
                )
            })?;
        fact.validate(state_fence)?;
        Ok(fact)
    }

    /// Builds the next canonical admission owner image that carries one
    /// Task Controller's current plan revision (issue #1741, I7.9).
    ///
    /// # Why this producer exists
    ///
    /// `current_plan` is `None` in the all-absent genesis payload, and until this
    /// method nothing could ever make it `Some`. The genesis packet is by
    /// construction the canonical all-absent image — its `validate` pins every
    /// owner payload to exactly that form, so a plan installed there would be a
    /// fabricated second plan authority rather than an owner-issued one — and
    /// both pre-existing producers ([`Self::prepare_verifier_execution_fact`]
    /// and [`Self::prepare_finish_evidence`]) only ever *carry forward*
    /// `self.snapshot.current_plan`. The plan dimension was therefore
    /// write-once-absent, so [`Self::read_current_plan`] and
    /// `read_current_activation_plan` refused on every live daemon, which
    /// dead-ended `prepare_finish_evidence` at its `read_current_plan` call
    /// before it could ever reach the contract owner's acceptance denominator.
    ///
    /// # Ownership (A00-07:50, A02-02:22, A10-04:22, I06-10:70, I07-21:9)
    ///
    /// Architecture names the Task Controller as the role that owns "the current
    /// plan revision" of one task under the active Authority Epoch, holding a
    /// `TaskControllerLease`, and withholds that authority from the Main Agent
    /// and from workers (`I10-15:194`: "workers cannot mutate the current plan
    /// in place"). This is that owner boundary on the existing
    /// [`CanonicalAdmissionOwner`]: it extends the existing scheme and invents no
    /// new plan identity type, vocabulary, or admission path.
    ///
    /// The plan is admitted only for a task it names, only under this exact
    /// fence, and only when the resulting image validates. Re-admitting the plan
    /// the owner already holds is idempotent: the caller compares the derived
    /// binding against [`Self::read_current_plan`] and skips the write, so this
    /// never mints a second owner revision for the same plan. A verifier
    /// execution fact or finish evidence already retained under a *different*
    /// plan cannot survive the transition, because
    /// [`CanonicalAdmissionSnapshot::validate`] refuses a fact or evidence image
    /// that does not match `current_plan` — the old plan's derived state is
    /// dropped with it rather than carried across a plan change.
    pub fn prepare_current_plan(
        &self,
        plan: CanonicalPlanBinding,
    ) -> Result<CanonicalAdmissionSnapshot, CompositionError> {
        plan.validate()?;
        let owner_revision = self.snapshot.owner_revision.checked_add(1).ok_or_else(|| {
            CompositionError::Recovery("canonical owner revision overflow".to_owned())
        })?;
        let snapshot = CanonicalAdmissionSnapshot {
            state_fence: self.state_fence.clone(),
            owner_revision,
            current_plan: Some(plan),
            verifier_execution_fact: self.snapshot.verifier_execution_fact.clone(),
            finish_evidence: self.snapshot.finish_evidence.clone(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Builds the next canonical admission owner image after a Governor-owned
    /// finish-evidence derivation.  This is a pure owner transition payload;
    /// persistence is performed only by the Kernel transition port.
    pub fn prepare_finish_evidence(
        &self,
        evidence: CanonicalFinishEvidence,
    ) -> Result<CanonicalAdmissionSnapshot, CompositionError> {
        evidence.validate(&self.state_fence)?;
        if let Some(plan) = &self.snapshot.current_plan
            && plan.task_id.as_str() != evidence.evidence.task_id
        {
            return Err(CompositionError::Recovery(
                "finish evidence task does not match the current canonical plan".to_owned(),
            ));
        }
        let owner_revision = self.snapshot.owner_revision.checked_add(1).ok_or_else(|| {
            CompositionError::Recovery("canonical owner revision overflow".to_owned())
        })?;
        let snapshot = CanonicalAdmissionSnapshot {
            state_fence: self.state_fence.clone(),
            owner_revision,
            current_plan: self.snapshot.current_plan.clone(),
            verifier_execution_fact: self.snapshot.verifier_execution_fact.clone(),
            finish_evidence: Some(evidence),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Reads the canonical finish evidence at the exact active fence.
    ///
    /// The result is owner state recovered from the Kernel named read.  A
    /// missing record is a plan gap, never an empty evidence default, because
    /// the finish service must not derive proof from the caller draft.
    pub fn read_finish_evidence(
        &self,
        state_fence: &StateFence,
    ) -> Result<CanonicalFinishEvidence, CompositionError> {
        state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self.state_fence != *state_fence || self.scope.state_fence != *state_fence {
            return Err(CompositionError::Recovery(
                "canonical finish evidence read used a stale state fence".to_owned(),
            ));
        }
        let evidence = self.snapshot.finish_evidence.clone().ok_or_else(|| {
            CompositionError::Recovery(
                "canonical finish evidence owner is absent; completion proof is unavailable"
                    .to_owned(),
            )
        })?;
        evidence.validate(state_fence)?;
        Ok(evidence)
    }
}

/// Config projection bound to the Host-approved generation.
#[derive(Clone, Debug)]
pub struct ConfigOwner {
    state_fence: StateFence,
    snapshot_digest: String,
}

impl ConfigOwner {
    /// Returns the recovered configuration identity.
    #[must_use]
    pub fn snapshot_digest(&self) -> &str {
        &self.snapshot_digest
    }

    /// Returns the fence of the recovered configuration projection.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }
}

/// Policy owner payload bound to the exact protected policy digest.
///
/// Unlike [`ConfigOwnerSnapshot`], the full normative [`ConfigPolicySnapshot`]
/// travels in the payload: policy-gated paths consume actual admitted settings
/// (required settings stay fail-closed while no Configured snapshot exists),
/// never a bare digest. The digest binds the exact snapshot bytes; it is never
/// a relabeled Config digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyOwnerSnapshot {
    /// Exact owner fence.
    pub state_fence: StateFence,
    /// Durable policy revision; must equal the embedded snapshot revision.
    pub revision: u64,
    /// Digest of the canonical embedded snapshot bytes.
    pub policy_digest: String,
    /// The admitted immutable Config/Policy snapshot content.
    pub snapshot: ConfigPolicySnapshot,
}

/// Policy projection bound to the Host-approved generation.
///
/// `None` at the owner set means the Kernel does not serve the Policy named
/// read yet: policy-gated evidence stays explicitly absent (fail-closed),
/// never defaulted. A present owner is always a fully correlated recovery.
#[derive(Clone, Debug)]
pub struct PolicyOwner {
    state_fence: StateFence,
    revision: u64,
    canonical_digest: String,
    snapshot_digest: String,
    snapshot: ConfigPolicySnapshot,
}

impl PolicyOwner {
    /// Recovers the Policy owner from one Kernel named-read reply, correlating
    /// owner, fence, revision, and digest against the actual canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Recovery`] for a foreign owner, stale fence,
    /// zero revision, out-of-bound or digest-mismatched payload, a rejected
    /// snapshot schema, or any fence/revision/digest disagreement between the
    /// reply, the wire envelope, and the embedded snapshot.
    pub fn recover(
        reply: &KernelNamedReadReply,
        expected_fence: &StateFence,
    ) -> Result<Self, CompositionError> {
        if reply.owner != RecoveryOwner::Policy {
            return Err(CompositionError::Recovery(
                "policy named read carries a foreign owner".to_owned(),
            ));
        }
        if reply.state_fence != *expected_fence
            || reply.revision == 0
            || reply.schema != OWNER_SNAPSHOT_SCHEMA
            || reply.payload.is_empty()
            || reply.payload.len() > MAX_OWNER_SNAPSHOT_BYTES
            || !is_sha256(&reply.value_digest)
            || sha256_hex(&reply.payload) != reply.value_digest
        {
            return Err(CompositionError::Recovery(
                "policy named read has invalid fence, revision, or payload digest".to_owned(),
            ));
        }
        let wire: PolicyOwnerSnapshot =
            serde_json::from_slice(&reply.payload).map_err(|error| {
                CompositionError::Recovery(format!(
                    "owner {} payload schema rejected: {error}",
                    RecoveryOwner::Policy.as_str()
                ))
            })?;
        let canonical = canonical_json_bytes(&wire).map_err(|error| {
            CompositionError::Recovery(format!(
                "owner {} payload could not be canonicalized: {error}",
                RecoveryOwner::Policy.as_str()
            ))
        })?;
        if canonical != reply.payload {
            return Err(CompositionError::Recovery(format!(
                "owner {} payload is not canonical JSON",
                RecoveryOwner::Policy.as_str()
            )));
        }
        if wire.revision != reply.revision {
            return Err(CompositionError::Recovery(
                "policy snapshot revision does not match its named-read revision".to_owned(),
            ));
        }
        wire.snapshot
            .validate()
            .map_err(|error| CompositionError::Recovery(format!("policy snapshot: {error}")))?;
        if wire.snapshot.state_fence != *expected_fence {
            return Err(CompositionError::Recovery(
                "policy snapshot has a stale state fence".to_owned(),
            ));
        }
        if wire.snapshot.revision.value() != wire.revision {
            return Err(CompositionError::Recovery(
                "policy snapshot revision does not match its envelope revision".to_owned(),
            ));
        }
        let snapshot_bytes = canonical_json_bytes(&wire.snapshot).map_err(|error| {
            CompositionError::Recovery(format!(
                "policy snapshot could not be canonicalized: {error}"
            ))
        })?;
        if wire.policy_digest != sha256_hex(&snapshot_bytes) {
            return Err(CompositionError::Recovery(
                "policy digest does not match the canonical snapshot bytes".to_owned(),
            ));
        }
        Ok(Self {
            state_fence: expected_fence.clone(),
            revision: wire.revision,
            canonical_digest: reply.value_digest.clone(),
            snapshot_digest: wire.policy_digest,
            snapshot: wire.snapshot,
        })
    }

    /// Returns the fence of the recovered policy projection.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the durable policy revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the Kernel-observed canonical payload digest retained at recovery.
    #[must_use]
    pub fn canonical_digest(&self) -> &str {
        &self.canonical_digest
    }

    /// Returns the digest bound to the canonical snapshot bytes at recovery.
    #[must_use]
    pub fn snapshot_digest(&self) -> &str {
        &self.snapshot_digest
    }

    /// Returns the admitted snapshot content policy-gated paths consume.
    #[must_use]
    pub const fn snapshot(&self) -> &ConfigPolicySnapshot {
        &self.snapshot
    }

    /// Recomputes the snapshot digest from the live retained snapshot.
    ///
    /// The mirror comparison at publish time uses this live recomputation
    /// against [`Self::canonical_digest`]: equality holds while the retained
    /// canonical state is intact, without ever substituting a Config digest.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Recovery`] when the snapshot cannot be
    /// canonicalized (fail-closed, never a default digest).
    pub fn rebuilt_digest(&self) -> Result<String, CompositionError> {
        let bytes = canonical_json_bytes(&self.snapshot).map_err(|error| {
            CompositionError::Recovery(format!(
                "retained policy snapshot could not be canonicalized: {error}"
            ))
        })?;
        Ok(sha256_hex(&bytes))
    }

    /// Recomputes the canonical envelope digest from the retained parts.
    ///
    /// Rebuilds the exact [`PolicyOwnerSnapshot`] envelope admitted at
    /// recovery and hashes its canonical bytes: the Policy mirror's rebuilt
    /// half for startup evidence. Equality with [`Self::canonical_digest`]
    /// proves the recovery channel carried the Kernel-served bytes intact;
    /// live-projection rebuild (re-reading canonical state at publish time)
    /// awaits the Kernel-served live projection and is requested in the
    /// carrier hunk, never synthesized here.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Recovery`] when the envelope cannot be
    /// canonicalized (fail-closed, never a default digest).
    pub fn rebuilt_envelope_digest(&self) -> Result<String, CompositionError> {
        let wire = PolicyOwnerSnapshot {
            state_fence: self.state_fence.clone(),
            revision: self.revision,
            policy_digest: self.snapshot_digest.clone(),
            snapshot: self.snapshot.clone(),
        };
        let bytes = canonical_json_bytes(&wire).map_err(|error| {
            CompositionError::Recovery(format!(
                "retained policy envelope could not be canonicalized: {error}"
            ))
        })?;
        Ok(sha256_hex(&bytes))
    }
}

/// Budget projection bound to the active authority fence.
#[derive(Clone, Debug)]
pub struct BudgetOwner {
    state_fence: StateFence,
    revision: u64,
    ledger: Option<BudgetLedger>,
}

impl BudgetOwner {
    /// Returns the active budget fence.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the durable semantic owner revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the exact configured ledger, or `None` for explicit genesis
    /// `Unconfigured` state. No transition is exposed here.
    #[must_use]
    pub fn ledger(&self) -> Option<&BudgetLedger> {
        self.ledger.as_ref()
    }

    /// Emits the same deterministic semantic recovery snapshot admitted for
    /// this owner.
    pub fn snapshot(&self) -> Result<BudgetOwnerSnapshot, CompositionError> {
        let state = match &self.ledger {
            Some(ledger) => BudgetOwnerState::Configured {
                ledger: Box::new(ledger.snapshot().map_err(|error| {
                    CompositionError::Recovery(format!(
                        "configured budget ledger snapshot failed: {error:?}"
                    ))
                })?),
            },
            None => BudgetOwnerState::Unconfigured,
        };
        Ok(BudgetOwnerSnapshot {
            schema: BUDGET_OWNER_SNAPSHOT_SCHEMA.to_owned(),
            version: BUDGET_OWNER_SNAPSHOT_VERSION,
            state_fence: self.state_fence.clone(),
            revision: self.revision,
            state,
        })
    }
}

/// Problem projection owner.  Problems are not canonical store state.
#[derive(Clone, Debug)]
pub struct ProblemOwner {
    state_fence: StateFence,
    revisions: BTreeMap<String, u64>,
}

impl ProblemOwner {
    /// Returns the active problem fence.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the number of recovered problem revisions.
    ///
    /// Live status: no production caller. Whether a projection reads this or the
    /// accessor is retired is an owner decision.
    #[must_use]
    pub fn revision_count(&self) -> usize {
        self.revisions.len()
    }
}

/// Read projection owner. Reads are admitted through a future Kernel read
/// operation, never by opening a store from the daemon.
#[derive(Clone, Debug)]
pub struct ReadOwner {
    state_fence: StateFence,
    scope: ScopeRevisionView,
}

impl ReadOwner {
    fn new(state_fence: StateFence, scope: ScopeRevisionView) -> Result<Self, CompositionError> {
        if scope.state_fence != state_fence {
            return Err(CompositionError::Recovery(
                "read projection scope has a stale fence".to_owned(),
            ));
        }
        Ok(Self { state_fence, scope })
    }

    /// Returns the fence required for all future reads.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the recovered canonical scope view used by read admission.
    #[must_use]
    pub const fn scope(&self) -> &ScopeRevisionView {
        &self.scope
    }
}

/// Maintenance persistence adapter backed by the authenticated Kernel job
/// route.  This type deliberately has no local map or default implementation.
pub struct KernelDurableJobStore<P: ?Sized> {
    kernel: Arc<P>,
    state_fence: StateFence,
}

impl<P: KernelDurableJobPort + ?Sized> KernelDurableJobStore<P> {
    fn new(kernel: Arc<P>, state_fence: StateFence) -> Self {
        Self {
            kernel,
            state_fence,
        }
    }
}

impl<P: KernelDurableJobPort + ?Sized> MaintenanceStateStore for KernelDurableJobStore<P> {
    fn load(&mut self, job_id: &str) -> Result<Option<MaintenanceJob>, MaintenanceError> {
        self.kernel
            .load_durable_job(job_id, &self.state_fence)
            .map_err(|error| MaintenanceError::Store(error.to_string()))
    }

    fn save(&mut self, job: &MaintenanceJob) -> Result<(), MaintenanceError> {
        if job.state_fence != self.state_fence {
            return Err(MaintenanceError::FenceMismatch);
        }
        self.kernel
            .save_durable_job(job)
            .map_err(|error| MaintenanceError::Store(error.to_string()))
    }
}

/// All N4 owners, each represented by one field and one mutable projection.
pub struct GovernorOwners<P: ?Sized> {
    /// `WorkScope` identity/binding owner.
    pub work_scope: Option<WorkScopeBindingOwner>,
    /// Durable task lifecycle owner.
    pub task: TaskLifecycleOwner,
    /// Durable session lifecycle owner.
    pub session: SessionLifecycleOwner,
    /// Canonical semantic admission owner.
    pub canonical: CanonicalAdmissionOwner,
    /// Pure authority idempotency owner.
    pub authority: AuthorityOwner,
    /// Budget reservation projection owner.
    pub budget: BudgetOwner,
    /// Host-approved configuration projection owner.
    pub config: ConfigOwner,
    /// Host-approved policy projection owner. `None` while the Kernel does
    /// not serve the Policy named read; policy-gated evidence then stays
    /// explicitly absent (fail-closed), never defaulted.
    pub policy: Option<PolicyOwner>,
    /// Durable application coordination owner.
    pub coordination: CoordinationOwner,
    /// Finish candidate projection owner.
    pub finish: FinishService,
    /// Problem projection owner.
    pub problem: ProblemOwner,
    /// Candidate observation journal owner.
    pub observation: ObservationJournal,
    /// Read admission projection owner.
    pub read: ReadOwner,
    /// Skill lifecycle owner.
    pub skill: SkillRegistry,
    /// Module Registry owner.
    pub module_registry: ModuleCatalog,
    /// Maintenance job owner.
    pub maintenance: MaintenanceController<KernelDurableJobStore<P>>,
    /// Change-monitor projection owner.
    pub change_monitor: ChangeMonitor,
}

impl<P: KernelDurableJobPort + ?Sized> GovernorOwners<P> {
    #[allow(
        clippy::too_many_lines,
        reason = "recovery reconstructs every closed owner in a fixed authority-sensitive order"
    )]
    fn from_recovery(
        kernel: Arc<P>,
        state_fence: &StateFence,
        config_snapshot_digest: String,
        recovery: &GovernorRecoverySnapshot,
    ) -> Result<Self, CompositionError> {
        let authority_epoch = state_fence.authority_epoch.clone();
        let task_snapshot: TaskLifecycleSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Task)?;
        let task = TaskLifecycleOwner::from_snapshot(
            authority_epoch.clone(),
            state_fence.clone(),
            task_snapshot,
        )
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let session_snapshot: SessionLifecycleSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Session)?;
        let session = SessionLifecycleOwner::from_snapshot(
            authority_epoch,
            state_fence.clone(),
            session_snapshot,
        )
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let authority_snapshot: AuthorityOwnerSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Authority)?;
        let authority_snapshot =
            if let Some(owner_hydrations) = authority_snapshot.owner_hydrations.clone() {
                AuthorityOwnerSnapshot::new_with_owner_hydrations(
                    authority_snapshot.state_fence.clone(),
                    authority_snapshot.grant_graph.clone(),
                    authority_snapshot.effect_authorizer.clone(),
                    owner_hydrations,
                )?
            } else {
                authority_snapshot
            };
        // W6 (#1142): this is the SYNCHRONOUS Kernel recovery composition,
        // and it is where a restore rehydrates the authority owner on the
        // daemon's live recovery path. It holds no CURRENT durable
        // revocation history: `recover_from_kernel` reads owner records
        // through the sync `KernelRecoveryPort`, while the only durable
        // revocation ledger is served by the async `GetAuthorityRevocationHistory`
        // named read that `owner_closure_feed::synchronize_owner_feed`
        // drives. So the constructor below is the fail-closed one: it
        // restores the genesis authority owner and REFUSES any payload
        // carrying grant lineage or effect authorizations, instead of
        // reinstating a snapshot's own `revoked` list as if it were
        // current. Restoring authority that could have been revoked since
        // the backup is a revocation that never happened, and "this route
        // could not read the ledger" is not "nothing was revoked." The
        // non-empty owner is restored through
        // `AuthorityOwner::from_snapshot_with_revocation_history`, which
        // re-derives every closure against the current committed history
        // before any grant becomes effective.
        let authority = AuthorityOwner::from_snapshot(&authority_snapshot, state_fence)?;
        let budget_read_revision = recovery.owner_read(RecoveryOwner::Budget)?.revision;
        let budget_snapshot: BudgetOwnerSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Budget)?;
        if budget_snapshot.revision != budget_read_revision {
            return Err(CompositionError::Recovery(
                "budget snapshot revision does not match its Kernel named-read revision".to_owned(),
            ));
        }
        let budget_revision = budget_snapshot.revision;
        let budget_ledger = budget_snapshot.restore(state_fence)?;
        let config_snapshot: ConfigOwnerSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Config)?;
        if &config_snapshot.state_fence != state_fence
            || config_snapshot.revision == 0
            || config_snapshot.config_digest != config_snapshot_digest
        {
            return Err(CompositionError::Recovery(
                "config owner snapshot is not bound to the protected launch digest".to_owned(),
            ));
        }
        let policy = match &recovery.policy_read {
            Some(reply) => Some(PolicyOwner::recover(reply, state_fence)?),
            None => None,
        };
        let coordination_wire: CoordinationOwner =
            decode_owner_snapshot(recovery, RecoveryOwner::Coordination)?;
        let coordination = CoordinationOwner::from_snapshot_at(
            coordination_wire,
            state_fence.authority_epoch.clone(),
            state_fence,
        )
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let finish_receipts: Vec<FinishDecisionReceipt> =
            decode_owner_snapshot(recovery, RecoveryOwner::Finish)?;
        if finish_receipts
            .iter()
            .any(|receipt| &receipt.state_fence != state_fence)
        {
            return Err(CompositionError::Recovery(
                "finish receipt snapshot contains a stale state fence".to_owned(),
            ));
        }
        let finish = FinishService::from_receipts(finish_receipts)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let problem_snapshot: ProblemOwnerSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Problem)?;
        if &problem_snapshot.state_fence != state_fence
            || problem_snapshot
                .revisions
                .values()
                .any(|revision| *revision == 0)
        {
            return Err(CompositionError::Recovery(
                "problem owner snapshot has a stale fence or zero revision".to_owned(),
            ));
        }
        let observation_entries: Vec<ObservationJournalEntry> =
            decode_owner_snapshot(recovery, RecoveryOwner::Observation)?;
        let observation = ObservationJournal::from_entries(observation_entries)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let read_snapshot: ReadOwnerSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Read)?;
        if &read_snapshot.state_fence != state_fence || read_snapshot.revision == 0 {
            return Err(CompositionError::Recovery(
                "read owner snapshot has a stale fence or zero revision".to_owned(),
            ));
        }
        let skill_views: Vec<SkillLifecycleView> =
            decode_owner_snapshot(recovery, RecoveryOwner::Skill)?;
        if skill_views
            .iter()
            .any(|view| &view.state_fence != state_fence)
        {
            return Err(CompositionError::Recovery(
                "skill snapshot contains a stale state fence".to_owned(),
            ));
        }
        let skill = SkillRegistry::from_snapshot(skill_views)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let module_registry_read = recovery.owner_read(RecoveryOwner::ModuleRegistry)?;
        let module_snapshot: ModuleCatalogSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::ModuleRegistry)?;
        if module_snapshot.catalog_revision != module_registry_read.revision
            || module_snapshot.state_fence != *state_fence
        {
            return Err(CompositionError::Recovery(
                "module catalog snapshot revision or fence does not match its Kernel named-read owner"
                    .to_owned(),
            ));
        }
        let module_registry = ModuleCatalog::from_snapshot(module_snapshot)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let change_snapshot: eliot_change_monitor::ChangeMonitorSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::ChangeMonitor)?;
        let change_monitor = eliot_change_monitor::ChangeMonitor::from_snapshot(change_snapshot)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let work_scope = if let Ok(snapshot) =
            decode_owner_snapshot::<WorkScopeBindingSnapshot>(recovery, RecoveryOwner::WorkScope)
        {
            let owner = WorkScopeBindingOwner::from_snapshot(snapshot)
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
            owner
                .read_current(state_fence)
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
            Some(owner)
        } else {
            let empty: EmptyOwnerSnapshot =
                decode_owner_snapshot(recovery, RecoveryOwner::WorkScope)?;
            empty.validate(state_fence)?;
            None
        };
        let owner = RecoveryOwner::Maintenance;
        {
            let empty: EmptyOwnerSnapshot = decode_owner_snapshot(recovery, owner)?;
            empty.validate(state_fence)?;
        }
        let canonical_snapshot: CanonicalAdmissionSnapshot =
            decode_owner_snapshot(recovery, RecoveryOwner::Canonical)?;
        let canonical_read_revision = recovery.owner_read(RecoveryOwner::Canonical)?.revision;
        if canonical_snapshot.owner_revision != canonical_read_revision {
            return Err(CompositionError::Recovery(
                "canonical snapshot revision does not match its Kernel named-read revision"
                    .to_owned(),
            ));
        }
        let canonical = CanonicalAdmissionOwner::new(
            state_fence.clone(),
            recovery.canonical_scope.clone(),
            canonical_snapshot,
        )?;
        let read = ReadOwner::new(state_fence.clone(), recovery.canonical_scope.clone())?;
        Ok(Self {
            work_scope,
            task,
            session,
            canonical,
            authority,
            budget: BudgetOwner {
                state_fence: state_fence.clone(),
                revision: budget_revision,
                ledger: budget_ledger,
            },
            config: ConfigOwner {
                state_fence: state_fence.clone(),
                snapshot_digest: config_snapshot_digest,
            },
            policy,
            coordination,
            finish,
            problem: ProblemOwner {
                state_fence: state_fence.clone(),
                revisions: problem_snapshot.revisions,
            },
            observation,
            read,
            skill,
            module_registry,
            maintenance: MaintenanceController::new(KernelDurableJobStore::new(
                kernel,
                state_fence.clone(),
            )),
            change_monitor,
        })
    }

    /// Returns the fixed owner identity list used for duplicate detection.
    #[must_use]
    pub const fn owner_ids(&self) -> [&'static str; 16] {
        OWNER_IDS
    }
}

/// Startup phase of the one Governor composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositionReadiness {
    /// No provider or recovery proof has been admitted.
    Constructing,
    /// Exact Kernel/provider and owner recovery have been admitted.
    Ready,
    /// Shutdown has begun; no new work may be admitted.
    Stopped,
}

/// Bound on the in-process scope-quarantine projection retained by
/// [`GovernorComposition`] (issue #1787, W6). A later mismatch must not
/// silently discard an earlier unresolved conflict, so mismatches accumulate
/// up to this bound instead of overwriting one slot; the bound itself keeps
/// the projection from growing without owner storage. Durable quarantine with
/// restart recovery still belongs to the `WorkScope` owner path.
const MAX_RETAINED_SCOPE_QUARANTINE_RECORDS: usize = 8;

/// One daemon-owned Governor composition. There is no second provider or
/// process executor hidden behind this value.
///
/// The in-process scope-quarantine projection below keeps at most
/// [`MAX_RETAINED_SCOPE_QUARANTINE_RECORDS`] records (one per mandatory
/// trigger plus margin); older records evict first. It is a diagnostic
/// projection only, never durable owner state.
pub struct GovernorComposition<P: ?Sized> {
    kernel: Arc<P>,
    /// Retained P-07 authority port. `None` means diagnosed degradation
    /// (reads/degraded status only) and never issues rights.
    authority_activation: Option<Arc<dyn P07AuthorityPort>>,
    governor: Governor,
    owners: GovernorOwners<P>,
    snapshot: KernelGenerationSnapshot,
    recovery: GovernorRecoverySnapshot,
    service_observations: Vec<KernelServiceRecovery>,
    readiness: CompositionReadiness,
    /// Exact P-07 presentations retained with their owner snapshots until
    /// exact reconciliation, keyed by [`PresentedAuthorityRequest::ledger_key`].
    authority_presentations: BTreeMap<String, RetainedAuthorityRequest>,
    /// Kernel-first grant revocations whose canonical second phase has not
    /// completed, keyed by target grant id.
    ///
    /// The Kernel/ORS first phase already committed and fenced the target, so
    /// every entry here is strictly stronger than any right the graph or a
    /// stale presentation still shows. An entry is removed only when the
    /// second-phase link commits; a failed retry never clears it.
    pending_canonical_revocations: BTreeMap<String, PendingCanonicalRevocation>,
    /// Installation-bound durable owner for exact cold-start lease and terminal
    /// receipt records. Compatible callers join through this owner.
    cold_start_readiness_owner: Option<Arc<dyn ColdStartReadinessRecordOwner>>,
    cold_start_readiness_contour: Option<InstallationScanContour>,
    cold_start_readiness_claims: BTreeMap<String, ColdStartReadinessOwnerClaim>,
    /// Bounded in-process diagnostic projection of scope-identity mismatches
    /// (issue #1787, W6 partial projection). Newest record is last; a later
    /// mismatch appends instead of overwriting, up to
    /// [`MAX_RETAINED_SCOPE_QUARANTINE_RECORDS`] records, so one unresolved
    /// conflict cannot silently discard another. This is not durable,
    /// rehydrated, or an authority for rebind: durable quarantine with an
    /// owner-issued write/readback receipt and restart recovery belongs to
    /// the `WorkScope` owner path. Read the latest with
    /// [`Self::last_scope_quarantine`]; read the full bounded history with
    /// [`Self::scope_quarantine_history`].
    scope_quarantine: Vec<QuarantinedScopeRecord>,
}

fn testd_finished_clock(job: &TestJob) -> ClockReading {
    let finished_at_ms = job.updated_at_ms.min(i64::MAX as u64) as i64;
    ClockReading {
        valid_time_ms: Some(finished_at_ms),
        known_time_ms: Some(finished_at_ms),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

/// Converts the durable TestD bytes into the standard raw-evidence contract.
/// TestD's storage digest is length-domain-separated; the verifier receives a
/// fresh standard digest over the exact retained bytes, so no handle or
/// process-exit label can substitute for the captured stream.
fn testd_raw_evidence(
    job: &TestJob,
    receipt: &VerificationReceipt,
) -> Result<Vec<RawEvidence>, CompositionError> {
    receipt.validate(job).map_err(|error| {
        CompositionError::Recovery(format!("TestD receipt validation failed: {error}"))
    })?;
    let mut artifacts = receipt.raw_artifacts.clone();
    artifacts.sort_by(|left, right| {
        left.capture_sequence
            .cmp(&right.capture_sequence)
            .then_with(|| left.handle.cmp(&right.handle))
    });
    artifacts
        .into_iter()
        .map(|artifact| {
            let artifact_id = ArtifactId::new(artifact.handle.clone()).map_err(|error| {
                CompositionError::Recovery(format!("raw verifier artifact id is invalid: {error}"))
            })?;
            let sha256 = sha256_hex(&artifact.bytes);
            let content_type = match artifact.stream {
                RawArtifactStream::Stdout => {
                    eliot_instrument_nextest::NEXTEST_STDOUT_CONTENT_TYPE.to_owned()
                }
                RawArtifactStream::Stderr => {
                    eliot_instrument_nextest::NEXTEST_STDERR_CONTENT_TYPE.to_owned()
                }
                RawArtifactStream::Unknown => artifact.content_type.clone(),
            };
            let raw = RawEvidence {
                artifact_id,
                invocation_id: job.invocation.request.request_id.clone(),
                source: RawEvidenceSource::Process,
                content_type,
                bytes: artifact.bytes,
                sha256,
                captured_at: artifact.captured_at,
                truncated: artifact.truncated,
            };
            raw.validate().map_err(|error| {
                CompositionError::Recovery(format!("raw verifier artifact is invalid: {error}"))
            })?;
            Ok(raw)
        })
        .collect()
}

/// Shared inputs for building normalized nextest evidence items.
///
/// The context borrows the receipt projections owned by the nextest
/// normalization entry point so per-event builders stay small without
/// re-reading the receipt.
struct NextestItemContext<'a> {
    job: &'a TestJob,
    tool_identity: &'a str,
    plan: &'a CanonicalVerifierPlanBinding,
    source_before: &'a TestdSourceObservation,
    capture: &'a CaptureProvenance,
    classifier: &'a DiagnosticClassifier,
    observed_at: ClockReading,
    freshness: EvidenceFreshness,
    coverage: EvidenceCoverage,
}

/// Admits the before/after source observation for nextest normalization.
///
/// A missing observation degrades the run to unknown freshness and partial
/// coverage instead of failing: the evaluator owns outcome/coverage and the
/// projection only attaches what the receipt observed.
fn admitted_nextest_source<'a>(
    receipt: &'a VerificationReceipt,
    job: &TestJob,
    run: &mut VerificationRun,
) -> Result<Option<&'a TestdSourceObservation>, CompositionError> {
    let Some(source_observation) = receipt.source_observation.as_ref() else {
        run.freshness = EvidenceFreshness::Unknown;
        run.coverage = EvidenceCoverage::PartialForScope;
        return Ok(None);
    };
    source_observation.validate().map_err(|error| {
        CompositionError::Recovery(format!("source observation invalid: {error}"))
    })?;
    if source_observation.before.repository_root != job.target_roots.source_root
        || source_observation.after.repository_root != job.target_roots.source_root
    {
        return Err(CompositionError::Recovery(
            "source observation is outside the admitted TestD repository".to_owned(),
        ));
    }
    if !source_observation.unchanged() {
        run.freshness = EvidenceFreshness::Unknown;
        run.coverage = EvidenceCoverage::PartialForScope;
    }
    Ok(Some(&source_observation.before))
}

/// Joined nextest stdout: bytes, per-artifact byte spans backing raw
/// lineage, and whether any contributing artifact was truncated.
type NextestStdoutStream = (Vec<u8>, Vec<(usize, usize, ArtifactId)>, bool);

/// Joins the admitted nextest stdout artifacts into one event stream.
fn nextest_joined_stdout(raw: &[RawEvidence]) -> Result<NextestStdoutStream, CompositionError> {
    let stdout = raw
        .iter()
        .filter(|evidence| {
            evidence.content_type == eliot_instrument_nextest::NEXTEST_STDOUT_CONTENT_TYPE
                || evidence.content_type == "application/json"
        })
        .collect::<Vec<_>>();
    if stdout.is_empty() {
        return Err(CompositionError::Recovery(
            "registered nextest normalizer has no stdout event stream".to_owned(),
        ));
    }
    let stream_truncated = stdout.iter().any(|evidence| evidence.truncated);
    let mut stream = Vec::new();
    let mut spans = Vec::new();
    for evidence in stdout {
        let start = stream.len();
        stream.extend_from_slice(&evidence.bytes);
        spans.push((start, stream.len(), evidence.artifact_id.clone()));
    }
    Ok((stream, spans, stream_truncated))
}

/// Builds the capture provenance attached to normalized nextest items.
///
/// Every normalized item carries the owner-observed executable identity,
/// config hash, WorkScope/candidate identity, profile revision, and
/// truncation signal of the exact run it was parsed from. Timing detail
/// stays on the run clocks; the `TestD` receipt projects no Job Object
/// resource accounting, so `resource_outcome` stays absent rather than
/// invented. Parse success is proven by the fail-closed full-consumption
/// check, so no parse note is attached.
fn nextest_capture_provenance(
    tool_identity: &str,
    plan: &CanonicalVerifierPlanBinding,
    source_before: &TestdSourceObservation,
    job: &TestJob,
    stream_truncated: bool,
) -> CaptureProvenance {
    CaptureProvenance {
        executable_identity: Some(tool_identity.to_owned()),
        config_hash: Some(plan.planned.verifier_config_hash.clone()),
        workscope: Some(WorkscopeIdentity {
            branch: Some(source_before.branch.clone()),
            commit: Some(source_before.commit.clone()),
            dirty_state_sha256: Some(source_before.dirty_state_sha256.clone()),
            target: Some(job.invocation.target.clone()),
            scope: Some(job.invocation.declared_scope.clone()),
        }),
        profile_revision: Some(job.invocation.profile.clone()),
        resource_outcome: None,
        truncated: stream_truncated,
        parse_note: None,
    }
}

/// Parses per-line nextest events, proving the joined stream lost nothing.
fn nextest_line_events(
    stream: &[u8],
    expected: usize,
) -> Result<Vec<NextestTestEvent>, CompositionError> {
    let mut line_start = 0usize;
    let mut line_events = Vec::new();
    for line_end in stream
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
        .chain((!stream.is_empty() && !stream.ends_with(b"\n")).then_some(stream.len()))
    {
        if line_end < line_start {
            continue;
        }
        let line = &stream[line_start..line_end];
        if !line.iter().all(u8::is_ascii_whitespace) {
            line_events.extend(parse_test_events(line).map_err(|error| {
                CompositionError::Recovery(format!(
                    "registered nextest normalizer could not map joined event: {error}"
                ))
            })?);
        }
        line_start = line_end.saturating_add(1);
    }
    if line_events.len() != expected {
        return Err(CompositionError::Recovery(
            "registered nextest normalizer lost an event while joining stdout chunks".to_owned(),
        ));
    }
    Ok(line_events)
}

/// Maps every parsed line event to normalized owner evidence.
///
/// Non-completed events advance the consumption cursor without producing
/// items; the trailing check proves every parsed event was consumed.
fn nextest_completed_items(
    ctx: &NextestItemContext,
    stream: &[u8],
    spans: &[(usize, usize, ArtifactId)],
    line_events: &[NextestTestEvent],
) -> Result<Vec<NormalizedEvidence>, CompositionError> {
    let mut normalized = Vec::new();
    let mut line_start = 0usize;
    let mut event_index = 0usize;
    for line_end in stream
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
        .chain((!stream.is_empty() && !stream.ends_with(b"\n")).then_some(stream.len()))
    {
        let line = &stream[line_start..line_end];
        if !line.iter().all(u8::is_ascii_whitespace) {
            let line_event_count = parse_test_events(line)
                .map_err(|error| CompositionError::Recovery(error.to_string()))?
                .len();
            let handles = spans
                .iter()
                .filter(|(start, end, _)| *start < line_end && *end > line_start)
                .map(|(_, _, artifact_id)| artifact_id.clone())
                .collect::<Vec<_>>();
            if handles.is_empty() && line_event_count != 0 {
                return Err(CompositionError::Recovery(
                    "nextest event has no raw artifact lineage".to_owned(),
                ));
            }
            for _ in 0..line_event_count {
                let event = &line_events[event_index];
                event_index += 1;
                let NextestTestEvent::Completed { name, status } = event else {
                    continue;
                };
                normalized.push(nextest_completed_item(ctx, name, *status, &handles, line)?);
            }
        }
        line_start = line_end.saturating_add(1);
    }
    if event_index != line_events.len() {
        return Err(CompositionError::Recovery(
            "registered nextest normalizer did not consume every parsed event".to_owned(),
        ));
    }
    Ok(normalized)
}

const fn nextest_diagnostic_severity(status: NextestTestStatus) -> DiagnosticSeverity {
    match status {
        NextestTestStatus::Pass => DiagnosticSeverity::Information,
        NextestTestStatus::Fail
        | NextestTestStatus::Timeout
        | NextestTestStatus::Leak
        | NextestTestStatus::Cancelled => DiagnosticSeverity::Error,
        NextestTestStatus::Skip => DiagnosticSeverity::Warning,
    }
}

const fn nextest_diagnostic_status(status: NextestTestStatus) -> DiagnosticStatus {
    if matches!(status, NextestTestStatus::Pass) {
        DiagnosticStatus::Resolved
    } else {
        DiagnosticStatus::Active
    }
}

/// Builds one normalized evidence item for a completed nextest test.
fn nextest_completed_item(
    ctx: &NextestItemContext,
    name: &str,
    status: NextestTestStatus,
    handles: &[ArtifactId],
    line: &[u8],
) -> Result<NormalizedEvidence, CompositionError> {
    let status_label = nextest_status_label(status);
    let raw_observation_ref = handles.first().cloned().ok_or_else(|| {
        CompositionError::Recovery("nextest event has no raw artifact".to_owned())
    })?;
    let diagnostic = DiagnosticEvent::from_input(DiagnosticInput {
        project_id: ctx.job.invocation.request.product_id.to_string(),
        task_id: ctx
            .job
            .invocation
            .request
            .task_id
            .as_ref()
            .map(ToString::to_string),
        tool_id: ctx.job.invocation.instrument.to_string(),
        tool_version: ctx.tool_identity.to_owned(),
        config_hash: ctx.plan.planned.verifier_config_hash.clone(),
        branch: ctx.source_before.branch.clone(),
        commit: ctx.source_before.commit.clone(),
        dirty_state_hash: ctx.source_before.dirty_state_sha256.clone(),
        file_path: ctx.job.invocation.target.clone(),
        range: None,
        severity: nextest_diagnostic_severity(status),
        rule_id: format!("nextest.test.{}", status_label.to_ascii_lowercase()),
        message: format!("nextest test {name} completed with status {status_label}"),
        raw_observation_ref: raw_observation_ref.clone(),
        observed_at: ctx.observed_at,
        status: nextest_diagnostic_status(status),
    })
    .map_err(|error| {
        CompositionError::Recovery(format!(
            "registered diagnostic normalizer rejected nextest event: {error}"
        ))
    })?;
    let diagnostic = ctx.classifier.admit(diagnostic).map_err(|error| {
        CompositionError::Recovery(format!(
            "registered diagnostic normalizer rejected nextest event: {error}"
        ))
    })?;
    let evidence_id =
        ArtifactId::new(format!("nextest-evidence-{}", sha256_hex(line))).map_err(|error| {
            CompositionError::Recovery(format!("normalized evidence id is invalid: {error}"))
        })?;
    let mut value = serde_json::to_value(&diagnostic).map_err(|error| {
        CompositionError::Recovery(format!(
            "normalized diagnostic serialization failed: {error}"
        ))
    })?;
    value["raw_artifact_handles"] = serde_json::json!(handles);
    // Preserve the typed nextest item identity and outcome in the
    // normalized owner evidence. FinishAttempt joins these exact
    // fields to the canonical required-test set; diagnostic prose
    // and run-level status are not item-level acceptance proof.
    value["nextest_test_id"] = serde_json::json!(catalog_test_id(name));
    value["nextest_status"] = serde_json::json!(status_label);
    let mut item = NormalizedEvidence {
        evidence_id,
        raw_artifact_id: raw_observation_ref,
        normalizer: ContractId::new(DIAGNOSTIC_CONTRACT).map_err(|error| {
            CompositionError::Recovery(format!("diagnostic contract id is invalid: {error}"))
        })?,
        kind: "nextest.test".to_owned(),
        summary: format!("nextest test {name} completed with status {status_label}"),
        value,
        axes: EvidenceAxes::observed(),
        freshness: ctx.freshness,
        coverage: if ctx.plan.required_test_ids.contains(catalog_test_id(name)) {
            ctx.coverage
        } else {
            EvidenceCoverage::PartialForScope
        },
    };
    item.attach_capture_provenance(ctx.capture)
        .map_err(|error| {
            CompositionError::Recovery(format!(
                "normalized evidence capture attach failed: {error}"
            ))
        })?;
    Ok(item)
}

/// Runs the registered diagnostic normalizer over every completed nextest
/// event. The evaluator owns outcome/coverage; this projection only attaches
/// canonical event identity and keeps each normalized item linked to the
/// exact raw stream which produced it.
fn normalize_nextest_run(
    run: &mut VerificationRun,
    job: &TestJob,
    plan: &CanonicalVerifierPlanBinding,
    receipt: &VerificationReceipt,
    raw: &[RawEvidence],
    observed_at: ClockReading,
) -> Result<(), CompositionError> {
    if raw.is_empty() {
        return Err(CompositionError::Recovery(
            "nextest normalization has no raw artifact".to_owned(),
        ));
    }
    let Some(source_before) = admitted_nextest_source(receipt, job, run)? else {
        return Ok(());
    };
    let tool = receipt.tool_observation.as_ref().ok_or_else(|| {
        CompositionError::Recovery(
            "productive TestD receipt has no owner-observed tool identity".to_owned(),
        )
    })?;
    tool.validate().map_err(|error| {
        CompositionError::Recovery(format!("tool observation invalid: {error}"))
    })?;
    let tool_identity = tool.nextest_identity();
    let (stream, spans, stream_truncated) = nextest_joined_stdout(raw)?;
    // I10.8.5 capture attach: every normalized item carries the
    // owner-observed executable identity, config hash, WorkScope/candidate
    // identity, profile revision, and truncation signal of the exact run it
    // was parsed from.
    let capture =
        nextest_capture_provenance(&tool_identity, plan, source_before, job, stream_truncated);
    let events = parse_test_events(&stream).map_err(|error| {
        CompositionError::Recovery(format!(
            "registered nextest normalizer rejected the joined stdout stream: {error}"
        ))
    })?;
    let classifier = DiagnosticClassifier::default();
    let line_events = nextest_line_events(&stream, events.len())?;
    let ctx = NextestItemContext {
        job,
        tool_identity: &tool_identity,
        plan,
        source_before,
        capture: &capture,
        classifier: &classifier,
        observed_at,
        freshness: run.freshness,
        coverage: run.coverage,
    };
    let normalized = nextest_completed_items(&ctx, &stream, &spans, &line_events)?;
    if normalized.is_empty() {
        return Err(CompositionError::Recovery(
            "registered nextest normalizer produced no completed test evidence".to_owned(),
        ));
    }
    run.evidence = normalized;
    run.validate().map_err(|error| {
        CompositionError::Recovery(format!("normalized VerificationRun is invalid: {error}"))
    })
}

const fn nextest_status_label(status: NextestTestStatus) -> &'static str {
    match status {
        NextestTestStatus::Pass => "PASS",
        NextestTestStatus::Fail => "FAIL",
        NextestTestStatus::Skip => "SKIP",
        NextestTestStatus::Timeout => "TIMEOUT",
        NextestTestStatus::Leak => "LEAK",
        NextestTestStatus::Cancelled => "CANCELLED",
    }
}

pub(crate) fn evaluate_testd_verification_current(
    job: &TestJob,
    receipt: &VerificationReceipt,
    plan: &CanonicalVerifierPlanBinding,
) -> Result<VerificationRun, CompositionError> {
    if job.invocation.profile != eliot_testd_core::TESTD_PRODUCTIVE_PROFILE {
        return Err(CompositionError::Recovery(
            "current verifier evaluation requires the productive nextest profile".to_owned(),
        ));
    }
    let raw = testd_raw_evidence(job, receipt)?;
    let finished_at = testd_finished_clock(job);
    let mut run = eliot_verifier::evaluate_current(
        &job.invocation,
        &raw,
        &plan.required_test_ids,
        job.invocation.request.clock,
        finished_at,
    )
    .map_err(|error| {
        CompositionError::Recovery(format!(
            "registered nextest evaluator rejected durable TestD evidence: {error}"
        ))
    })?;
    normalize_nextest_run(&mut run, job, plan, receipt, &raw, finished_at)?;
    Ok(run)
}

/// The typed terminal result of one production authority request dispatched
/// through [`GovernorComposition::apply_authority_request`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityActionReceipt {
    /// A validated Kernel activation receipt.
    Activation(AuthorityActivationReceipt),
    /// A validated Kernel root-transition activation receipt. The record is
    /// boxed because it carries the whole committed transition evidence,
    /// which is far larger than the other two terminal receipts; the box is a
    /// representation choice only and changes no field or proof.
    RootTransitionActivation(Box<RootTransitionActivationReceipt>),
    /// A validated Kernel revocation receipt.
    Revocation(AuthorityRevocationReceipt),
    /// The three durable phases of one reconciled grant revocation. A grant
    /// revocation never reports a single-phase receipt: either the whole saga
    /// committed and proved its read-backs, or it returns `Err`. The record is
    /// boxed because it carries the whole committed first-phase closure
    /// together with its second-phase link, which is far larger than the other
    /// two terminal receipts; the box is a representation choice only and
    /// changes no field or proof.
    ReconciledGrantRevocation(Box<AuthorityRevocationReconciliation>),
}

/// The three durable phases of one grant revocation saga.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRevocationReconciliation {
    /// Kernel-issued first-phase revocation receipt.
    pub authority_receipt: AuthorityRevocationReceipt,
    /// Canonical write receipt proving the second phase committed.
    pub canonical_receipt: WriteReceipt,
    /// Proved canonical second phase: the ORIGINAL committed first-phase
    /// closure together with the exact Store-issued receipt durably linked to
    /// it, as the neutral [`GrantClosureSecondPhaseLink`] carries it.
    pub closure_projection: GrantClosureSecondPhaseLink,
}

/// Agent- and Human-facing projection of one retained terminal cold-start
/// receipt (issue #1790, cold-start surface production type).
///
/// Besides the compact readiness surface, this carries the receipt's typed
/// principal/session, scope/instance/lineage, task-selection, fence and source
/// bindings so a downstream #8 response can compare owner projections rather
/// than joining by display labels. Source references and generations remain
/// distinct fields; an opaque governance-profile reference is not a coverage
/// fingerprint or a profile revision. The complete bounded source-status
/// lists, proof disposition and recovery prompts preserve unavailable,
/// conflicting and no-proof states rather than reducing them to a readiness
/// token.
///
/// This is a projection, not an authenticated receipt or an integrity proof.
/// `OnboardingReadinessReceipt::validate` checks structure and internal
/// consistency but does not verify a stored payload digest, and `receipt_ref`
/// is not such a digest. Correct origin and freshness therefore depend on the
/// durable ORS readiness owner and #8's authenticated live
/// producer. This projection has no clock input, so it cannot independently
/// establish that the lease has not expired or been revoked; the live #8
/// caller must revalidate those facts before using readiness. `readiness` is
/// the `SCREAMING_SNAKE_CASE`
/// [`eliot_workscope::ReadinessLifecycle`] token (`UNSEEN`, `SCANNING`,
/// `NEEDS_SCOPE`, `NEEDS_TASK`, `NEEDS_SOURCES`, `READY_READ_ONLY`,
/// `READY_MATERIAL`, `DEGRADED`, `CONFLICTED`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ColdStartSurfaceView {
    pub receipt_ref: String,
    pub lease_ref: String,
    pub principal_ref: String,
    pub session_ref: String,
    pub scope: ScopeIdentity,
    pub scope_descriptor_revision: u64,
    pub instance: WorkspaceInstanceIdentity,
    pub lineage: Option<RepositoryLineageIdentity>,
    pub scope_resolution: eliot_workscope::ScopeResolutionState,
    pub task_binding: TaskBindingState,
    pub state_fence: StateFence,
    pub governing_source_set_ref: String,
    pub governing_source_generation: u64,
    pub governance_profile_ref: String,
    pub limiting_integration_evidence: Vec<String>,
    pub route_profile_ref: String,
    pub serializer_id: String,
    pub serializer_version: String,
    pub serializer_options_digest: String,
    pub tokenizer_id: String,
    pub tokenizer_version: String,
    pub tokenizer_hash: String,
    pub readiness: String,
    pub smallest_missing_question: Option<String>,
    pub lease_deadline: u64,
    pub receipt_revision: u64,
    pub proof_readiness: eliot_workscope::ProofReadiness,
    pub missing_inputs: Vec<String>,
    pub next_safe_action: String,
    pub discovered_source_refs: Vec<String>,
    pub admitted_source_refs: Vec<String>,
    pub conflicting_source_refs: Vec<String>,
    pub unavailable_source_refs: Vec<String>,
    pub scan_receipt_ref: Option<String>,
    pub workspace_instance_ref: String,
    pub projection_source_ref: String,
    pub projection_generation: u64,
}

/// Ephemeral capability held only by the composition invocation that won the
/// durable ORS claim. Restart recovery uses ORS readback and never restores
/// this process-local compile capability from serialized data.
#[derive(Clone)]
struct ColdStartReadinessOwnerClaim {
    claim: ColdStartReadinessClaim,
    record_key: String,
}

/// Maps one compiled readiness lifecycle to its canonical transport token.
///
/// The token matches the `SCREAMING_SNAKE_CASE` serialization of
/// [`eliot_workscope::ReadinessLifecycle`], which is also the token set the
/// bridge intake parses. A single explicit match keeps the wire contract in
/// one place instead of spreading string conversions across callers.
fn cold_start_readiness_token(lifecycle: ReadinessLifecycle) -> &'static str {
    match lifecycle {
        ReadinessLifecycle::Unseen => "UNSEEN",
        ReadinessLifecycle::Scanning => "SCANNING",
        ReadinessLifecycle::NeedsScope => "NEEDS_SCOPE",
        ReadinessLifecycle::NeedsTask => "NEEDS_TASK",
        ReadinessLifecycle::NeedsSources => "NEEDS_SOURCES",
        ReadinessLifecycle::ReadyReadOnly => "READY_READ_ONLY",
        ReadinessLifecycle::ReadyMaterial => "READY_MATERIAL",
        ReadinessLifecycle::Degraded => "DEGRADED",
        ReadinessLifecycle::Conflicted => "CONFLICTED",
    }
}

/// Owned preparation of this composition's existing maintenance admission
/// (issue #1693).
///
/// Produced by [`GovernorComposition::prepare_maintenance_admission`] under
/// the composition's current state and fence, carried by the caller across
/// its outside-borrow owner I/O, and consumed by
/// [`GovernorComposition::adopt_maintenance_admission`], which rechecks the
/// fence and the revision before constructing anything. The `job_id` is the
/// exact identity the admission would persist, so the caller's load observes
/// the same key the adoption constructs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedMaintenanceAdmission {
    /// Fence the admission was prepared under; adoption requires the active
    /// fence to still match it exactly.
    pub state_fence: StateFence,
    /// Maintenance named-read revision at preparation; adoption requires it
    /// to be unchanged.
    pub maintenance_revision: u64,
    /// Registered maintenance family the prepared decision admits.
    pub family: MaintenanceFamily,
    /// Affected scope the prepared decision admits.
    pub scope_ref: String,
    /// Trigger identity the prepared decision admits.
    pub trigger_id: String,
    /// Durable idempotency identity the admission would persist. The caller
    /// loads this key through its own Durable Job store handle outside any
    /// composition borrow.
    pub job_id: String,
    /// Stable identity of the exact source decision this admission is prepared
    /// from, so the adopted job attributes its later source results to the
    /// decision that admitted the work.
    pub decision_ref: String,
}

impl<P: KernelGenerationPort + ?Sized> GovernorComposition<P> {
    /// Builds one composition only after exact provider and recovery checks.
    pub fn new(
        kernel: Arc<P>,
        authority_activation: Option<Arc<dyn P07AuthorityPort>>,
        expected: &KernelGenerationExpectation,
        queues: QueueLimits,
    ) -> Result<Self, CompositionError> {
        let snapshot = kernel.snapshot().clone();
        expected
            .admits(&snapshot)
            .map_err(|error| CompositionError::Provider(error.to_string()))?;
        let state_fence = snapshot.state_fence();
        let recovery = recover_from_kernel(
            kernel.as_ref(),
            &state_fence,
            &snapshot.protected_snapshot_digest,
        )?;
        recovery.validate(&state_fence, &snapshot.protected_snapshot_digest)?;
        let service_observations = kernel
            .services(&state_fence, &snapshot.protected_snapshot_digest)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        validate_service_observations(&service_observations, &state_fence)?;
        let mut governor = Governor::new(GovernorConfig {
            authority_epoch: snapshot.authority_epoch.clone(),
            resource_generation: snapshot.generation,
            queues,
            background_pause_interactive_depth: 1,
        })
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
        governor
            .begin_startup()
            .map_err(|error| CompositionError::StartupOrder {
                expected: "Constructed -> Starting".to_owned(),
                observed: error.to_string(),
            })?;
        for service in STARTUP_ORDER {
            let recovered = service_observations
                .iter()
                .find(|candidate| candidate.service == service)
                .ok_or_else(|| {
                    CompositionError::Recovery(format!("missing service {service:?}"))
                })?;
            governor
                .admit_service(service, recovered.observation.clone())
                .map_err(|error| CompositionError::StartupOrder {
                    expected: format!("admit {service:?}"),
                    observed: error.to_string(),
                })?;
        }
        if governor.snapshot().state != GovernorState::Ready {
            return Err(CompositionError::NotReady);
        }
        let owners = GovernorOwners::from_recovery(
            kernel.clone(),
            &state_fence,
            snapshot.protected_snapshot_digest.clone(),
            &recovery,
        )?;
        Ok(Self {
            kernel,
            authority_activation,
            governor,
            owners,
            snapshot,
            recovery,
            service_observations,
            readiness: CompositionReadiness::Ready,
            authority_presentations: BTreeMap::new(),
            pending_canonical_revocations: BTreeMap::new(),
            cold_start_readiness_owner: None,
            cold_start_readiness_contour: None,
            cold_start_readiness_claims: BTreeMap::new(),
            scope_quarantine: Vec::new(),
        })
    }

    /// Returns the one owner set.
    #[must_use]
    pub const fn owners(&self) -> &GovernorOwners<P> {
        &self.owners
    }

    /// Retains one execution-evidence page in the existing Skill lifecycle
    /// owner and returns its resulting position. This narrow write seam keeps
    /// the rest of the owner set immutable to daemon callers; it does not
    /// imply durable persistence or restart recovery for the observation.
    #[allow(clippy::result_large_err)]
    pub fn record_skill_execution_evidence(
        &mut self,
        skill_id: &str,
        skill_revision: &str,
        package_digest: &str,
        ingest_attempt_id: &str,
        entry: &eliot_skill::SkillCatalogueEntry,
        executions: &[eliot_skill::SkillExecutionEvidence],
    ) -> Result<SkillLifecycleView, eliot_skill::SkillError> {
        self.owners.skill.record_execution_evidence(
            skill_id,
            skill_revision,
            package_digest,
            ingest_attempt_id,
            entry,
            executions,
        )
    }

    /// Prepares this composition's existing maintenance admission under its
    /// current state and fence (issue #1693).
    ///
    /// This is the narrow maintenance admission seam, and the reason no
    /// unrestricted `owners_mut` exists: preparing (and, separately, adopting)
    /// this one admission is everything an `eliotd` caller needs, and it never
    /// exposes any other owner mutably. Preparation is a pure read of the
    /// current fence and the maintenance named-read revision plus a check
    /// that the Governor decision admits one job; it performs no owner I/O.
    /// The caller performs the owner I/O itself — loading the prior job for
    /// [`PreparedMaintenanceAdmission::job_id`] through its own Durable Job
    /// store handle — outside any composition borrow, and then adopts the
    /// result through [`Self::adopt_maintenance_admission`], which rechecks
    /// the fence and the revision before anything is constructed. The existing
    /// Durable Job store is the only persistence involved; no maintenance
    /// runner is created.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::NotReady`] when the composition is not
    /// ready, or [`CompositionError::Recovery`] when the decision does not
    /// admit a job, its identities are empty, or the maintenance named read
    /// is missing.
    pub fn prepare_maintenance_admission(
        &self,
        decision: &AutomationTriggerDecision,
    ) -> Result<PreparedMaintenanceAdmission, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        if decision.decision != AutomationDecision::Start || !decision.admits_job {
            return Err(CompositionError::Recovery(
                "maintenance admission preparation requires a START decision that admits one job"
                    .to_owned(),
            ));
        }
        if decision.trigger_id.is_empty() || decision.scope_ref.is_empty() {
            return Err(CompositionError::Recovery(
                "maintenance admission preparation requires a non-empty trigger and scope identity"
                    .to_owned(),
            ));
        }
        let state_fence = self.snapshot.state_fence();
        let maintenance_revision = self
            .recovery
            .owner_read(RecoveryOwner::Maintenance)?
            .revision;
        // The exact identity `MaintenanceController::admit` would persist for
        // this decision, so the caller's outside-borrow load observes the same
        // key the adoption below constructs.
        let job_id = format!("maintenance:{}:{}", decision.family, decision.trigger_id);
        Ok(PreparedMaintenanceAdmission {
            state_fence,
            maintenance_revision,
            family: decision.family,
            scope_ref: decision.scope_ref.clone(),
            trigger_id: decision.trigger_id.clone(),
            job_id,
            // The owner's own decision reference, derived from the decision's
            // stable identity rather than chosen here, so the adopted job and an
            // owner-admitted job attribute their results identically.
            decision_ref: maintenance_decision_ref(decision),
        })
    }

    /// Adopts a prepared maintenance admission after rechecking the fence and
    /// the revision (issue #1693).
    ///
    /// The caller passes what its outside-borrow owner I/O saw: the prior job
    /// stored under the prepared identity, if any, plus the freshly observed
    /// lease, budget reference, attempt bound and session requirement. This
    /// method rechecks that the composition still stands on the prepared fence
    /// and the prepared maintenance revision, refuses an already-recorded
    /// identity and refuses conflicting work while an older job's effects are
    /// unsettled or its resource custody unreleased, then constructs the
    /// admitted job exactly as `MaintenanceController::admit` would — without
    /// persisting it. Persisting the returned job through the caller's own
    /// Durable Job store handle stays outside the composition borrow.
    ///
    /// A generation change invalidates the old key's applicability but settles
    /// nothing: only a prior job in a terminal state (`Cancelled`,
    /// `Completed`, `Failed`) releases its scope. Any other prior job for the
    /// same family and scope — an older generation's unsettled effects as much
    /// as a same-generation duplicate — is refused until that obligation is
    /// reconciled.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::NotReady`] when the composition is not
    /// ready, or [`CompositionError::Recovery`] when the fence or the revision
    /// moved since preparation, the identity is already recorded, a prior job
    /// for the same family and scope is not settled, or the constructed job
    /// does not validate.
    pub fn adopt_maintenance_admission(
        &self,
        prepared: &PreparedMaintenanceAdmission,
        prior_job: Option<&MaintenanceJob>,
        runtime_lease: RuntimeLease,
        budget_ref: String,
        max_attempts: u32,
        user_session_required: bool,
    ) -> Result<MaintenanceJob, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        if self.snapshot.state_fence() != prepared.state_fence {
            return Err(CompositionError::Recovery(
                "maintenance admission preparation is not bound to the active fence".to_owned(),
            ));
        }
        let maintenance_revision = self
            .recovery
            .owner_read(RecoveryOwner::Maintenance)?
            .revision;
        if maintenance_revision != prepared.maintenance_revision {
            return Err(CompositionError::Recovery(
                "maintenance revision moved since admission preparation".to_owned(),
            ));
        }
        if let Some(prior) = prior_job {
            if prior.job_id == prepared.job_id {
                return Err(CompositionError::Recovery(
                    "maintenance admission identity is already recorded".to_owned(),
                ));
            }
            let settled = matches!(
                prior.state,
                MaintenanceJobState::Cancelled
                    | MaintenanceJobState::Completed
                    | MaintenanceJobState::Failed
            );
            if prior.family == prepared.family && prior.scope_ref == prepared.scope_ref && !settled
            {
                return Err(CompositionError::Recovery(
                    "an older maintenance job for this family and scope is not settled: reconcile its effects and release its resource custody before admitting conflicting work"
                        .to_owned(),
                ));
            }
        }
        if budget_ref.is_empty() {
            return Err(CompositionError::Recovery(
                "maintenance admission requires a non-empty budget reference".to_owned(),
            ));
        }
        let job = MaintenanceJob {
            job_id: prepared.job_id.clone(),
            trigger_id: prepared.trigger_id.clone(),
            // The adoption names the same decision reference the owner's own
            // `admit` would, derived from that decision's stable identity, so
            // every later source result on this job is attributed to the
            // decision that admitted the work rather than to a reference the
            // adoption chose.
            decision_ref: prepared.decision_ref.clone(),
            family: prepared.family,
            scope_ref: prepared.scope_ref.clone(),
            state_fence: prepared.state_fence.clone(),
            runtime_lease,
            state: MaintenanceJobState::Admitted,
            checkpoint: None,
            max_attempts,
            attempts: 0,
            budget_ref,
            outcome_ref: None,
            user_session_required,
            result_obligations: Vec::new(),
        };
        job.validate().map_err(|error| {
            CompositionError::Recovery(format!("adopted maintenance job is invalid: {error}"))
        })?;
        Ok(job)
    }

    /// Records on the retained job revision that the canonical observation
    /// route admitted one result this job owed an observation for.
    ///
    /// This is the narrow durable half of the result-to-observation path, and
    /// the reason it lives beside [`Self::retained_durable_job`] rather than in
    /// a new owner: the receipt is settled onto the same Kernel durable-job
    /// ledger the transitions already write through, so the job state and the
    /// observation it owes stay in one store with one atomic boundary. Nothing
    /// here claims improvement, reconciles an outstanding obligation, or
    /// writes an outcome.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::NotReady`] when the composition is not
    /// ready, and [`CompositionError::Recovery`] when the maintenance owner
    /// refuses the receipt — an unknown publication identity, a conflicting
    /// second receipt under one identity, an already-unavailable delivery, a
    /// job that is not retained, or a stale fence. The owner's own
    /// [`MaintenanceError`] is preserved in the detail so a dangling
    /// publication identity stays distinguishable from a transport failure.
    pub fn admit_maintenance_observation_receipt(
        &mut self,
        job_id: &str,
        publication_id: &str,
        observation_receipt_ref: &str,
    ) -> Result<MaintenanceJob, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        // The maintenance owner performs the read, the settlement and the
        // single durable write through the same Kernel durable-job ledger its
        // lifecycle transitions already use. This seam exists only because the
        // owner set is otherwise immutable to `eliotd` callers.
        let fence = self.snapshot.state_fence();
        self.owners
            .maintenance
            .admit_observation_receipt(job_id, &fence, publication_id, observation_receipt_ref)
            .map_err(|error| {
                CompositionError::Recovery(format!(
                    "maintenance observation receipt was not admitted: {error}"
                ))
            })
    }

    /// Records the explicit coverage gap for one refused maintenance result
    /// writeback, on the same Kernel durable-job ledger the transitions and
    /// receipt admissions already write through.
    ///
    /// `refused_operation_id` and `refused_status` are the exact facts the
    /// canonical route returned: a gap may only be recorded against a terminal
    /// non-committed store receipt, because a readiness or transport refusal
    /// produced no receipt and must leave the obligation `Pending` for a later
    /// retry. `RefusedReceiptStatus` has no `Committed` member, so an admission
    /// cannot be recorded here at all. The gap identity is derived by the owner
    /// from those values together with the publication identity, so a caller
    /// cannot name a gap it did not earn and a repeated refusal of the same
    /// result reconciles onto the same gap instead of appending another.
    ///
    /// This records a coverage consequence; it never admits an observation,
    /// never reconciles an outstanding obligation and never writes an outcome.
    /// An already-admitted receipt under that identity is refused rather than
    /// downgraded to a gap.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::NotReady`] when the composition is not ready,
    /// and [`CompositionError::Recovery`] when the maintenance owner refuses the
    /// gap — an unknown publication identity, a conflicting recorded gap, or an
    /// already-admitted observation. The owner's own [`MaintenanceError`] is
    /// preserved in the detail so a dangling publication identity stays
    /// distinguishable from a transport failure.
    pub fn record_maintenance_observation_gap(
        &mut self,
        job_id: &str,
        publication_id: &str,
        refused_operation_id: &str,
        refused_status: RefusedReceiptStatus,
    ) -> Result<MaintenanceJob, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let fence = self.snapshot.state_fence();
        self.owners
            .maintenance
            .record_observation_gap(
                job_id,
                &fence,
                publication_id,
                refused_operation_id,
                refused_status,
            )
            .map_err(|error| {
                CompositionError::Recovery(format!(
                    "maintenance observation gap was not recorded: {error}"
                ))
            })
    }

    /// Appends one delayed utility evaluation to a retained maintenance job.
    ///
    /// The maintenance owner reads its own retained obligation chain, runs the
    /// delayed comparison over it, and appends the resulting evaluation revision
    /// through the same Kernel durable-job ledger the lifecycle transitions and
    /// receipt admissions already write through. Nothing here concludes utility:
    /// the verdict is the observation contract's own predicate over the evidence
    /// the caller supplied, and every metric that comparison did not observe
    /// stays explicitly unknown.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::NotReady`] when the composition is not
    /// ready, and [`CompositionError::Recovery`] when the maintenance owner
    /// refuses the evaluation. The owner's own [`MaintenanceError`] is
    /// preserved in the detail so a malformed comparison stays distinguishable
    /// from a transport failure.
    pub fn evaluate_maintenance_utility(
        &mut self,
        job_id: &str,
        evaluation_window: eliot_observation_contracts::CoverageInterval,
        evidence: &eliot_maintenance::UtilityEvaluationEvidence,
    ) -> Result<MaintenanceJob, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let fence = self.snapshot.state_fence();
        self.owners
            .maintenance
            .evaluate_utility(job_id, &fence, evaluation_window, evidence)
            .map_err(|error| {
                CompositionError::Recovery(format!(
                    "maintenance utility evaluation was not appended: {error}"
                ))
            })
    }

    /// Returns the retained durable maintenance job for one exact job identity.
    ///
    /// The read goes through the same authenticated Kernel durable-job route the
    /// maintenance owner writes through, so the returned revision and the
    /// result-to-observation obligations its transitions appended are the ones the
    /// owner actually persisted in that single atomic write. Nothing is
    /// reconstructed here: an absent job is `Ok(None)`, which is unavailable
    /// rather than resolved, and the read fails closed when the job is not
    /// retained under this fence.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::NotReady`] when the composition is not ready
    /// and [`CompositionError::Kernel`] with the transport's own
    /// [`KernelPortError`] when the durable-job read or the retained revision's
    /// validation is refused.
    pub fn retained_durable_job(
        &self,
        job_id: &str,
    ) -> Result<Option<MaintenanceJob>, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        // The retained snapshot's own fence, owned here because the projection
        // builds a fresh `StateFence`. The read borrows it, and the binding
        // check below compares against the same owned value, so neither use
        // moves it.
        let fence = self.snapshot.state_fence();
        let job = self
            .kernel
            .load_durable_job(job_id, &fence)
            .map_err(CompositionError::Kernel)?;
        if let Some(job) = &job {
            job.validate().map_err(|error| {
                CompositionError::Recovery(format!(
                    "retained durable maintenance job is invalid: {error}"
                ))
            })?;
            if job.job_id != job_id || job.state_fence != fence {
                return Err(CompositionError::Recovery(
                    "retained durable maintenance job is not bound to this fence and identity"
                        .to_owned(),
                ));
            }
        }
        Ok(job)
    }

    /// Returns the latest process-local scope-identity mismatch projection
    /// (issue #1787). It is not durable and is lost when this composition is
    /// dropped or restarted.
    ///
    /// `None` means no mismatch has been observed since construction. The
    /// retained binding is never replaced by this record.
    #[must_use]
    pub fn last_scope_quarantine(&self) -> Option<&QuarantinedScopeRecord> {
        self.scope_quarantine.last()
    }

    /// Returns the bounded in-process quarantine history with authenticated
    /// readback (issue #1787, AUD3 readback leg).
    ///
    /// Every returned record was built through
    /// [`QuarantinedScopeRecord::for_report`] and
    /// [`QuarantinedScopeRecord::validate`] at retention; this read
    /// re-validates each record through the same existing validator so a
    /// corrupt projection fails here instead of reaching a rebind decision.
    /// An empty history means no mismatch has been observed since
    /// construction (unavailable, not committed). This is not durable, not
    /// rehydrated, and never an authority for rebind: committed,
    /// possible-commit, and retired states belong to the durable `WorkScope`
    /// owner path. The STITCH consumer is the future rebind/recovery
    /// reconciliation.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Recovery`] when any retained record fails
    /// its existing validation.
    pub fn scope_quarantine_history(&self) -> Result<&[QuarantinedScopeRecord], CompositionError> {
        for record in &self.scope_quarantine {
            record.validate().map_err(|error| {
                CompositionError::Recovery(format!(
                    "retained scope quarantine history is corrupt: {error}"
                ))
            })?;
        }
        Ok(&self.scope_quarantine)
    }

    /// Rehydrates one verifier execution fact from the current Governor task,
    /// plan, and the current durable TestD owner row. The caller supplies only
    /// the durable job identity; it cannot pass a held `TestJob` image or a
    /// verifier verdict, and it cannot pass a task revision either — the current
    /// revision is the task-lifecycle owner record's own value, because
    /// `StateFence::task_revision` is structurally `None` on every production
    /// Kernel-generation fence. The store read, task/plan join, persisted
    /// receipt, execution run, artifact lineage, and canonical fence are checked
    /// by the one fact constructor.
    pub fn rehydrate_testd_verifier_execution_fact(
        &self,
        task_id: &TaskId,
        job_id: &str,
        testd: &TestdStore,
    ) -> Result<CanonicalVerifierExecutionFact, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let fence = self.snapshot.state_fence();
        let task = self.owners.task.task(task_id).ok_or_else(|| {
            CompositionError::Recovery(format!("canonical task {} is absent", task_id.as_str()))
        })?;
        if task.task_id != *task_id || task.revision == 0 || task.state_fence != fence {
            return Err(CompositionError::Recovery(
                "canonical task owner is stale for verifier rehydration".to_owned(),
            ));
        }
        // The task revision the fact is bound to is the owner record's own
        // current value, proved non-zero and fence-bound above.
        let task_revision = task.revision;
        let plan = self.owners.canonical.read_current_plan(&fence)?;
        if plan.task_id != *task_id {
            return Err(CompositionError::Recovery(
                "canonical verifier plan is task-mismatched".to_owned(),
            ));
        }
        let job = testd
            .get(job_id)
            .map_err(|error| {
                CompositionError::Recovery(format!("TestD owner read failed: {error}"))
            })?
            .ok_or_else(|| {
                CompositionError::Recovery(format!("durable TestD job {job_id} is absent"))
            })?;
        let verifier_plan = plan.verifier_binding().map_err(|error| {
            CompositionError::Recovery(format!(
                "canonical plan has no verifier profile/config/scope/artifact binding: {error}"
            ))
        })?;
        let receipt = job.verification_receipt.as_ref().ok_or_else(|| {
            CompositionError::Recovery(
                "durable TestD job has no full verification receipt".to_owned(),
            )
        })?;
        let run = evaluate_testd_verification_current(&job, receipt, verifier_plan)?;
        CanonicalVerifierExecutionFact::from_testd(
            task_id,
            task_revision,
            &plan,
            &fence,
            &job,
            receipt,
            run,
        )
    }

    /// Prepares the canonical owner image for a TestD verifier fact. The
    /// returned snapshot is committed only through the existing canonical
    /// transition/CAS path; no public setter can install a caller assertion.
    pub fn prepare_testd_verifier_execution_fact(
        &self,
        task_id: &TaskId,
        job_id: &str,
        testd: &TestdStore,
    ) -> Result<CanonicalAdmissionSnapshot, CompositionError> {
        let fact = self.rehydrate_testd_verifier_execution_fact(task_id, job_id, testd)?;
        self.owners.canonical.prepare_verifier_execution_fact(fact)
    }

    /// Reads the canonical verifier plan only from this ready composition's
    /// retained owner and the exact admitted state fence.
    pub fn read_current_plan(
        &self,
        state_fence: &StateFence,
    ) -> Result<CanonicalPlanBinding, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        self.owners.canonical.read_current_plan(state_fence)
    }

    /// Admits the Task Controller's current plan revision for one task from
    /// owner state alone, and returns the exact exchange that leg still owes
    /// (issue #1741, I7.9).
    ///
    /// This is the production producer for `CanonicalAdmissionSnapshot::current_plan`.
    /// It performs no transport and mutates nothing, so the caller holds its
    /// composition borrow for this call alone and releases it before
    /// [`PreparedKernelExchange::exchange`].
    ///
    /// # Where the plan identity comes from
    ///
    /// Every field is read from an owner, never taken from a caller:
    ///
    /// * `plan_id` / `plan_revision` — the plan identity the Task-selection
    ///   owner's accepted, same-fence, task-bound observation receipt already
    ///   records (`ObservationPlanBinding`). That receipt is the durable owner
    ///   record of the admitted plan revision, and it is the same record the
    ///   finish path's `matches_plan` join compares the owner plan against, so
    ///   the plan admitted here cannot disagree with the evidence it is later
    ///   joined to.
    /// * `task_id` / `task_revision` — the live task-lifecycle owner record, so
    ///   the admitted plan is current by construction rather than by a
    ///   caller-asserted revision. A task is the documented unit of plan
    ///   ownership (A10-04:22: "exactly one Task Controller owns the current
    ///   plan revision for the Authority Epoch"), so the plan is bound to the
    ///   owner record that holds that authority.
    /// * `work_scope_id` — the same selection receipt's `work_scope_ref`.
    ///
    /// The verifier request contract is deliberately *not* supplied here. The
    /// governing fragments assign plan-revision ownership to the Task Controller
    /// (A00-07:50, A02-02:22, A10-04:22, I07-21:9) and keep the verifier under an
    /// Evaluation Contract (A05-05, I07-27), but name no owner that publishes a
    /// `CanonicalVerifierPlanBinding` — and none exists: the type has no struct
    /// literal anywhere in the tree, so it is reachable only by deserialization.
    /// It is therefore left absent, which [`CanonicalPlanBinding::validate`]
    /// admits, so the plan *identity* is admitted on the evidence that actually
    /// exists and every consumer that requires a verifier keeps refusing on its
    /// own pre-existing typed check rather than reading a synthesized contract.
    ///
    /// # Idempotence
    ///
    /// When the owner already holds exactly this plan, `None` is returned and no
    /// owner revision is minted: a re-admission of an already-current plan must
    /// not look like a new canonical fact. `Some` is returned only when the
    /// owner image would actually change.
    ///
    /// # Publication
    ///
    /// Preparing does not publish. The derived image becomes the owner image only
    /// through a later [`Self::refresh_from_kernel`], because
    /// [`Self::accept_prepared_exchange`] re-checks the pre-commit fence and
    /// nothing else. A caller that derives any later leg from
    /// [`Self::read_current_plan`] — [`Self::prepare_finish_evidence`] is the
    /// one that does — must therefore publish this leg first, or it reads the
    /// pre-publish image and refuses on the all-absent `current_plan`. That is a
    /// publication obligation on the caller, not a second plan authority here.
    ///
    /// # Fail-closed
    ///
    /// Refuses, without mutating anything, when the composition is not ready;
    /// when the task is absent, stale for the fence, at a zero revision, or not
    /// in a plan-bearing state; when the Task-selection owner has no accepted,
    /// same-fence, task-bound, plan-bearing, uncontaminated receipt for this
    /// exact task revision; when those receipts disagree about the plan identity;
    /// or when the resulting owner image does not validate. There is no
    /// synthesized plan and no fallback to the genesis image.
    pub fn prepare_current_plan_admission(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        task_id: &TaskId,
    ) -> Result<Option<PreparedKernelExchange>, FinishAttemptError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(FinishAttemptError::Composition(CompositionError::NotReady));
        }
        identity
            .validate()
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
        if identity.request.state_fence != identity.request.metadata.state_fence {
            return Err(FinishError::FenceMismatch.into());
        }
        let fence = identity.request.metadata.state_fence.clone();
        if self.owners.canonical.state_fence() != &fence {
            return Err(FinishError::FenceMismatch.into());
        }
        if identity.request.metadata.task_id.as_ref() != Some(task_id) {
            return Err(FinishError::Canonical(
                eliot_canonical::CanonicalError::TaskBindingMismatch,
            )
            .into());
        }
        let service = self.finish_attempt_service();
        let plan = service.admit_task_controller_plan(task_id)?;
        // Already current: the owner holds exactly this plan, so there is no
        // owner image to publish and no revision to advance.
        if self
            .owners
            .canonical
            .read_current_plan(&fence)
            .is_ok_and(|current| current == plan)
        {
            return Ok(None);
        }
        let snapshot = self.owners.canonical.prepare_current_plan(plan)?;
        let envelope = current_plan_envelope(identity, operation_id, &snapshot, task_id)?;
        Ok(Some(
            service.prepare_current_plan_exchange(identity, envelope)?,
        ))
    }

    /// Returns the authenticated Kernel snapshot admitted at construction.
    #[must_use]
    pub const fn kernel_snapshot(&self) -> &KernelGenerationSnapshot {
        &self.snapshot
    }

    /// Returns the provider-owned recovery evidence retained for exact replay
    /// and diagnostics.
    #[must_use]
    pub const fn recovery(&self) -> &GovernorRecoverySnapshot {
        &self.recovery
    }

    /// Returns the separate Kernel-owned service observations used for ordered
    /// Governor admission; these are not part of owner recovery.
    #[must_use]
    pub fn service_observations(&self) -> &[KernelServiceRecovery] {
        &self.service_observations
    }

    /// Returns current readiness; construction never returns a partially ready value.
    #[must_use]
    pub const fn readiness(&self) -> CompositionReadiness {
        self.readiness
    }

    /// Returns the Governor lifecycle projection.
    #[must_use]
    pub fn governor(&self) -> &Governor {
        &self.governor
    }

    /// Compiles the `ControlBoard` read projection over the current owners.
    ///
    /// The snapshot is assembled from the live coordination, problem,
    /// observation, task, and read-scope owners at the retained fence, with
    /// the board revision and receipt references taken from the
    /// refresh-consistent recovery named reads. Only a fully admitted
    /// composition publishes: any other readiness fails closed so the
    /// surface reports a typed provider gap instead of a stale projection.
    pub fn controlboard_snapshot(&self) -> Result<ControlBoardGovernorSnapshot, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let fence = self.snapshot.state_fence();
        if self.owners.read.state_fence() != &fence {
            return Err(CompositionError::Recovery(
                "read owner projection is not bound to the active fence".to_owned(),
            ));
        }
        let read_revision = self.recovery.owner_read(RecoveryOwner::Read)?.revision;
        let coordination_receipt = self
            .recovery
            .owner_read(RecoveryOwner::Coordination)?
            .value_digest
            .clone();
        let observation_receipt = self
            .recovery
            .owner_read(RecoveryOwner::Observation)?
            .value_digest
            .clone();
        compile_controlboard_snapshot(&ControlBoardProjectionParts {
            fence: &fence,
            read_revision,
            coordination: &self.owners.coordination,
            task: &self.owners.task,
            observation: &self.owners.observation,
            problem_revisions: &self.owners.problem.revisions,
            read_scope: self.owners.read.scope(),
            coordination_receipt_digest: &coordination_receipt,
            observation_receipt_digest: &observation_receipt,
        })
        .map_err(|error| CompositionError::Owner(error.to_string()))
    }

    /// Composes this ready composition's owner-neutral canonical projection set
    /// for one task, from its own live owners.
    ///
    /// This is the Governor's producer boundary for the value an orientation
    /// consumer presents. The four inputs are the composition's own retained
    /// owners — the `task` and `session` lifecycle snapshots, the admitted
    /// `work_scope` binding read at the retained fence, and the `observation`
    /// journal's deterministic entries — under the one admitted
    /// [`StateFence`]. The pure composer returns the Governor's own
    /// [`GovernorProjectionSet`](crate::GovernorProjectionSet) first, with every
    /// absent member recorded as a
    /// [`ProjectionOmission`](crate::ProjectionOmission) rather than filler,
    /// and the emitted
    /// [`CanonicalProjectionSet`] is produced only when all four records
    /// exist; an absent member is a typed
    /// [`GovernorProjectionError::MemberOmitted`] naming which one.
    ///
    /// Only a fully admitted composition composes, matching
    /// [`Self::controlboard_snapshot`]: a degraded or recovering composition
    /// fails closed rather than projecting from a partially hydrated owner.
    ///
    /// The `work_scope` owner is optional by construction (the Kernel may not
    /// yet serve the binding); its absence is the same fail-closed refusal here,
    /// because an affordance projection authorized for no admitted scope is
    /// exactly the empty-affordance case the consumer contract rejects.
    pub fn canonical_projections(
        &self,
        binding: &ContextBinding,
        task_id: &TaskId,
    ) -> Result<CanonicalProjectionSet, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let fence = self.snapshot.state_fence();
        if !fences_match_exact(&binding.state_fence, &fence) {
            return Err(CompositionError::Owner(
                GovernorProjectionError::FenceMismatch.to_string(),
            ));
        }
        let scope_owner = self.owners.work_scope.as_ref().ok_or_else(|| {
            CompositionError::Owner(
                GovernorProjectionError::MemberOmitted("affordance").to_string(),
            )
        })?;
        let scope_snapshot = scope_owner
            .read_current(&fence)
            .map_err(|error| CompositionError::Owner(error.to_string()))?;
        let set = compose_canonical_projections(
            &self.owners.task.snapshot(),
            &self.owners.session.snapshot(),
            &scope_snapshot,
            &self.owners.observation.snapshot(),
            task_id,
            &fence,
        )
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
        emit_canonical_projection_set(binding, &set)
            .map_err(|error| CompositionError::Owner(error.to_string()))
    }

    /// Borrows the single Skill lifecycle owner as a canonical
    /// [`SkillLifecycleApi`](eliot_skill::SkillLifecycleApi) adapter.
    ///
    /// The adapter reads the current `skill: SkillRegistry` owner (recovered
    /// via the `Skill` named read) together with the canonical admission owner
    /// and the retained neutral Kernel port. It creates no per-caller
    /// registry; promotion commits through the existing canonical path and
    /// publishes only via `refresh_from_kernel` at the returned receipt
    /// revisions.
    #[must_use]
    pub fn skill_lifecycle(&self) -> GovernorSkillLifecycle<'_, P> {
        GovernorSkillLifecycle::new(
            &self.owners.skill,
            &self.owners.canonical,
            self.kernel.as_ref(),
        )
    }

    /// Borrows the single task lifecycle owner as a canonical
    /// [`GovernorTaskLifecycle`](crate::GovernorTaskLifecycle) adapter.
    ///
    /// The adapter reads the current `task: TaskLifecycleOwner` owner
    /// (recovered via the `Task` recovery owner) together with the canonical
    /// admission owner and the retained neutral Kernel port. It creates no
    /// per-caller owner; proposals and guarded transitions validate against
    /// a scratch clone (including the task-revision compare-and-swap base
    /// and the exact legal-transition rule), commit through the existing
    /// canonical path as one `UpdateTaskState` / `TaskControl` transition,
    /// and publish only via `refresh_from_kernel` at the returned receipt
    /// revisions.
    #[must_use]
    pub fn task_lifecycle(&self) -> GovernorTaskLifecycle<'_, P> {
        GovernorTaskLifecycle::new(
            &self.owners.task,
            &self.owners.canonical,
            self.kernel.as_ref(),
        )
    }

    /// Borrows the single Governor FinishAttempt adapter.
    ///
    /// The adapter rehydrates the current task and canonical finish-evidence
    /// sources at the retained fence. The composition's production method
    /// publishes the Governor-derived `owner/canonical` evidence CAS and
    /// refreshes its readback before the adapter evaluates the existing
    /// [`FinishService`]. It never consumes provider result state as proof.
    #[must_use]
    pub fn finish_attempt_service(&self) -> GovernorFinishAttempt<'_, P> {
        let finish_revision = self
            .recovery
            .owner_reads
            .iter()
            .find(|read| read.owner == RecoveryOwner::Finish)
            .map_or(0, |read| read.revision);
        GovernorFinishAttempt::new(
            &self.owners,
            &self.owners.canonical,
            self.kernel.as_ref(),
            finish_revision,
        )
    }

    /// Admits one Kernel-side change observation transfer into the live
    /// Governor change-monitor owner (issue #1824, I10.21 AUD7).
    ///
    /// This is the Governor head of the Kernel-to-Governor observation
    /// bridge: the transfer carries the hint, the previously admitted
    /// original, two independent direct content reads, and the read-only
    /// Git receipts, and admission runs the existing
    /// [`ChangeMonitor::confirm_kernel_readback`](eliot_change_monitor::ChangeMonitor::confirm_kernel_readback)
    /// owner path with its validators, so a failed transfer stays a pending
    /// hint and governed acceptance stays blocked (fail-closed). The daemon
    /// bridge that builds the transfer from Kernel evidence is the remaining
    /// caller.
    ///
    /// Live-state hydration only: [`Self::refresh_from_kernel`] rebuilds
    /// every owner from the Store named-read snapshot, so transfers admitted
    /// here persist across restart only once the snapshot write-back leg
    /// persists [`ChangeMonitor::snapshot`](eliot_change_monitor::ChangeMonitor::snapshot)
    /// through a Store owner mutation (no such mutation exists yet; the
    /// Store record still carries the genesis default).
    pub fn ingest_kernel_change_transfer(
        &mut self,
        transfer: &eliot_change_monitor::KernelHintReadback,
    ) -> Result<eliot_change_monitor::ChangeHintConfirmation, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        self.owners
            .change_monitor
            .confirm_kernel_readback(transfer)
            .map_err(|error| {
                CompositionError::Recovery(format!(
                    "governor change-monitor transfer refused: {error}"
                ))
            })
    }

    /// Resolves one historical anchor against the live Governor
    /// change-monitor owner and returns the published evidence-bearing
    /// observation (issue #1824, I10.21 AUD6).
    ///
    /// Candidates are constructed from the owner's own admitted
    /// after-states for the original target through
    /// [`AnchorCandidate::from_admitted_after_state`](eliot_change_monitor::AnchorCandidate::from_admitted_after_state),
    /// in snapshot insertion order, with caller-supplied extra candidates
    /// (VCS/content/code-intelligence adapters own that discovery)
    /// appended; the resolution itself runs the existing deterministic
    /// order over the live snapshot. The returned observation records the
    /// algorithm version, every input, the matching evidence tier, and
    /// confidence, and is serializable through the contract identity
    /// schema set. `ambiguous` carries no chosen target, `deleted` stays
    /// historically addressable through admitted deletion evidence, and
    /// neither is ever auto-attached here: attachment stays with the
    /// anchored-review route, which I10.18 forbids from creating a second
    /// store. The daemon review trigger that supplies the original anchor
    /// is the remaining caller.
    pub fn resolve_anchored_review(
        &self,
        original: &eliot_change_monitor::AnchorReference,
        extra_candidates: &[eliot_change_monitor::AnchorCandidate],
    ) -> Result<eliot_change_monitor::AnchorResolutionObservation, CompositionError> {
        let snapshot = self.owners.change_monitor.snapshot();
        let mut candidates = Vec::new();
        for record in &snapshot.observations {
            let Some(after) = record.observation.after.as_ref() else {
                continue;
            };
            if after.resource_ref != original.target.id.as_str() {
                continue;
            }
            let candidate = eliot_change_monitor::AnchorCandidate::from_admitted_after_state(
                original, after, None, false,
            )
            .map_err(|error| {
                CompositionError::Recovery(format!(
                    "governor anchor candidate refused admitted state: {error}"
                ))
            })?;
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }
        for candidate in extra_candidates {
            if !candidates.contains(candidate) {
                candidates.push(candidate.clone());
            }
        }
        eliot_change_monitor::EvolvingAnchorResolver
            .resolve_observed(original, &candidates, &snapshot)
            .map_err(|error| {
                CompositionError::Recovery(format!("governor anchor resolution refused: {error}"))
            })
    }

    /// Returns the terminal product-proof record this composition's
    /// ProductProof/FinishService acceptance owner builds for the parked
    /// Windows acceptance item (issue #1903).
    ///
    /// The composition owns the single [`FinishService`] in
    /// [`GovernorOwners::finish`], so this is the owner boundary itself. Every
    /// value the record carries is read, not composed: the executable identity
    /// and its content digest are this composition's own retained
    /// [`KernelGenerationSnapshot`], the finish authority is that snapshot's own
    /// service and generation, and the stage receipts are the receipts the
    /// owner already holds through [`FinishService::receipts`]. No stage value,
    /// sha, or timestamp is invented here.
    ///
    /// The returned rollup is the owner's own fail-closed rollup, unmodified.
    /// While no accepted finish decision carries a runtime-domain receipt, the
    /// installed-route stage is recorded as `Missing`, the outcome is
    /// `Blocked`, and the rollup is `Refused`. Nothing in this method relaxes
    /// the `PASS` refusal: a record is only a pass when the owner actually
    /// observed an installed-route execution.
    pub fn product_proof_status(
        &self,
    ) -> Result<
        (
            eliot_reports::product_proof::ProductProofStatus,
            eliot_reports::product_proof::ProductProofRollup,
        ),
        CompositionError,
    > {
        let snapshot = &self.snapshot;
        // The identity this record would launch is the exact Host-approved
        // generation this composition is running under, so the record names the
        // bytes that would run. `installed` stays `false` because an
        // installed-route execution has not launched them.
        let executable = eliot_reports::product_proof::ProductProofExecutableIdentity::new(
            format!("{}.exe", snapshot.service),
            Some(snapshot.artifact_digest.clone()),
            false,
        )
        .map_err(product_proof_error)?;
        // The platform is this process's real compiled target, read from the
        // toolchain, so the record names the environment that would run the
        // proof rather than an assumed one.
        let environment = eliot_reports::product_proof::ProductProofEnvironmentIdentity::new(
            format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            Some(snapshot.principal.clone()),
        )
        .map_err(product_proof_error)?;
        // The finish authority is the snapshot's own service and generation, so
        // the record cites the generation actually running rather than a
        // composed constant.
        let finish_authority_ref = format!(
            "eliot.governor.finish/{}/{}",
            snapshot.service,
            snapshot.generation.value()
        );
        // The stage receipts are the receipts this owner already retains. The
        // build evidence handle is bound to the newest retained accepted
        // decision's own receipt digest, so the parked record's build handle
        // cites a real receipt rather than an assumed one. The installed-route
        // stage is left absent: only the revision below can observe it.
        let receipts = self.owners.finish.receipts();
        let observed = receipts
            .iter()
            .find(|receipt| receipt.decision.outcome == FinishDecisionOutcome::VerifiedComplete);
        // The readback handles are bound to a local first: the stage inputs
        // borrow them, so the record must not hold a reference into a
        // temporary that ends with this statement.
        let raw_log_refs = product_proof_raw_log_refs(observed);
        let inputs = eliot_finish::product_proof::ProductProofStageInputs {
            finish_authority_ref: &finish_authority_ref,
            proof_ceiling: PRODUCT_PROOF_CEILING,
            decision_receipt_digest: observed.map(|receipt| receipt.receipt_digest.as_str()),
            runtime_receipt_ref: None,
            raw_log_refs: &raw_log_refs,
            executable: Some(executable),
            environment: Some(environment),
        };
        // The owner builds the parked record first — a parked run was never
        // attempted, so it is exactly the current state — and the same record is
        // then revised from the owner's latest retained receipt, so the next
        // installed Windows attempt updates this one acceptance item in place
        // instead of a second record appearing. The revision is what carries a
        // real observation, so `parked` never has to accept one: with no
        // retained receipt the parked record stands unchanged, which is the
        // current truthful state.
        let parked = self
            .owners
            .finish
            .product_proof_parked(&inputs)
            .map_err(product_proof_error)?;
        let status = match receipts.last() {
            Some(receipt) => self.revise_product_proof_status(&parked, receipt)?.0,
            None => parked,
        };
        let rollup = status.rollup();
        Ok((status, rollup))
    }

    /// Revises the same product-proof record from a retained finish decision
    /// receipt (issue #1903).
    ///
    /// This is the update path the audit requires: the next installed Windows
    /// attempt is described by the finish decision the acceptance owner
    /// already derived and retained, so the same acceptance item keeps one
    /// record and is updated in place rather than a parallel record appearing.
    /// Nothing is invented here — the run identity is the receipt's own
    /// `decision_id`, the semantic outcome is
    /// [`outcome_of_decision`](eliot_finish::product_proof::outcome_of_decision)
    /// of the receipt's own decision, the execution position is that same
    /// decision mapped to its lifecycle action, and the I18.22 failure class is
    /// [`failure_class_of_execution`](eliot_finish::product_proof::failure_class_of_execution)
    /// of that position. The fail-closed rule is untouched: a `Pass` still
    /// requires an observed installed-route execution.
    pub fn revise_product_proof_status(
        &self,
        previous: &eliot_reports::product_proof::ProductProofStatus,
        receipt: &FinishDecisionReceipt,
    ) -> Result<
        (
            eliot_reports::product_proof::ProductProofStatus,
            eliot_reports::product_proof::ProductProofRollup,
        ),
        CompositionError,
    > {
        let execution = product_proof_execution(receipt.lifecycle_action);
        // The installed-route stage is observed only when the decision actually
        // carries the plan's installed-route receipt, NOT merely because it
        // closed as completed. A succeeded position without that receipt leaves
        // the stage missing, so a simulated absent launch receipt can never be
        // rolled up as `PASS`.
        let installed_route = installed_route_stage(receipt);
        let observed = installed_route.is_observed();
        let outcome = eliot_finish::product_proof::outcome_of_decision(&receipt.decision);
        let attempt = match eliot_finish::product_proof::failure_class_of_execution(execution) {
            Some(failure_class) => {
                eliot_reports::product_proof::ProductProofRunAttempt::incomplete(
                    receipt.decision_id.clone(),
                    execution,
                    failure_class,
                    format!(
                        "installed Windows attempt {} ended {:?}: {}",
                        receipt.decision_id, execution, receipt.decision.next_allowed_action
                    ),
                )
            }
            None => eliot_reports::product_proof::ProductProofRunAttempt::completed(
                receipt.decision_id.clone(),
                execution,
                format!(
                    "installed Windows attempt {} completed: {}",
                    receipt.decision_id, receipt.decision.next_allowed_action
                ),
            ),
        }
        .map_err(product_proof_error)?;
        // The installed-route receipt identity is read once, here, before the
        // stage receipt is moved into the retained record below, so the live
        // evidence below cites the same value rather than a recomputed one.
        let observed_receipt_id = match &installed_route {
            eliot_reports::product_proof::ProductProofStageReceipt::Observed { receipt_id } => {
                Some(receipt_id.clone())
            }
            eliot_reports::product_proof::ProductProofStageReceipt::Missing { .. } => None,
        };
        // The retained evidence is rebuilt from this same record's identities
        // plus the receipt's own raw-log handles, so the revision never drops a
        // previously retained fact and never invents one.
        let retained = eliot_reports::product_proof::ProductProofRetainedEvidence {
            raw_log_refs: previous.retained.raw_log_refs.clone(),
            executable: previous.retained.executable.clone(),
            environment: previous.retained.environment.clone(),
            stage_receipts: eliot_reports::product_proof::ProductProofStageReceipts {
                installed_route,
            },
        };
        // The still-missing evidence is recomputed from this record's own state
        // and the plan's concrete requirement, not copied from the prior
        // revision's list. Copying the same caller list forward would let an
        // attempt "clear" the requirement without ever satisfying it; here an
        // unobserved installed route always re-derives the exact proof that is
        // still absent. A record whose installed route is observed clears the
        // list only because this same call established that observation.
        let missing_evidence = if observed {
            Vec::new()
        } else {
            product_proof_missing_evidence(previous)
        };
        let live_evidence = if observed {
            // The live evidence cites the *installed-route* receipt identity the
            // decision carried, not the finish decision's own digest, so the
            // evidence bound to the product property is the one that actually
            // proves it. The revision still binds to the exact retained finish
            // bytes, so the digest is computed from content, never supplied.
            let receipt_id = observed_receipt_id
                .clone()
                .ok_or_else(|| product_proof_error("product proof stage receipt disappeared"))?;
            vec![
                eliot_reports::product_proof::ProductProofEvidence::new(
                    eliot_reports::product_proof::ProductProofEvidenceDomain::Runtime,
                    format!("installed-route-receipt:{receipt_id}"),
                    format!(
                        "installed route attempt {} produced the installed-route receipt {receipt_id}",
                        receipt.decision_id
                    ),
                    eliot_reports::projection::ReportInputRevision::new(
                        eliot_reports::projection::ReportInputSource::ProductSupport,
                        receipt.attempt_id.clone(),
                        receipt.task_revision,
                        &canonical_json_bytes(&receipt).map_err(product_proof_error)?,
                    )
                    .map_err(product_proof_error)?,
                )
                .map_err(product_proof_error)?,
            ]
        } else {
            Vec::new()
        };
        let reason = format!(
            "installed Windows attempt {} recorded as {:?} for finish authority {}",
            receipt.decision_id, outcome, receipt.finish_authority_ref
        );
        let status = self
            .owners
            .finish
            .revise_product_proof_status(
                previous,
                eliot_finish::product_proof::ProductProofRevision {
                    attempt,
                    outcome,
                    reason: &reason,
                    missing_evidence,
                    live_evidence,
                    retained,
                },
            )
            .map_err(product_proof_error)?;
        let rollup = status.rollup();
        Ok((status, rollup))
    }

    /// Publishes the current durable `TestD` verifier execution fact through
    /// the same canonical owner CAS used by `FinishEvidence`. The caller gives
    /// only the job identity; `TestD` currentness and the full receipt/run are
    /// re-read inside the Governor service before the write.
    ///
    /// This is the composed form of the three phases below, for the caller that
    /// holds only `&self`. The `TestD` owner drain drives
    /// [`Self::prepare_testd_verifier_execution_fact_from_evidence`],
    /// [`PreparedKernelExchange::exchange`] and
    /// [`Self::accept_prepared_exchange`] itself, so that no composition lock is
    /// held across the Kernel exchange.
    pub async fn publish_testd_verifier_execution_fact(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        task_id: &TaskId,
        job_id: &str,
        testd: &TestdStore,
    ) -> Result<Option<WriteReceipt>, FinishAttemptError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(FinishAttemptError::Composition(CompositionError::NotReady));
        }
        self.finish_attempt_service()
            .publish_testd_verifier_execution_fact(identity, operation_id, task_id, job_id, testd)
            .await
    }

    /// Prepares the exact exchange that publishes the verifier-execution owner
    /// from complete identity-joined terminal evidence supplied by the Kernel
    /// owner route. The daemon-side entry: no `TestdStore` handle crosses the
    /// daemon boundary.
    ///
    /// This half performs no transport and mutates nothing, so the caller holds
    /// its composition borrow for this call alone and releases it before
    /// [`PreparedKernelExchange::exchange`].
    pub fn prepare_testd_verifier_execution_fact_from_evidence(
        &self,
        evidence: &TestdTerminalCompletionEvidence,
    ) -> Result<Option<PreparedKernelExchange>, FinishAttemptError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(FinishAttemptError::Composition(CompositionError::NotReady));
        }
        self.finish_attempt_service()
            .prepare_testd_verifier_execution_fact_from_evidence(evidence)
    }

    /// Rehydrates the contract owner's acceptance-item enumeration for one
    /// finish candidate, at the exact task id the admitted request carries
    /// (issue #1741, I7.9).
    ///
    /// This is the async half of the denominator join and the only place the
    /// finish path may obtain it. It is deliberately separate from
    /// [`Self::prepare_finish_evidence`], which stays synchronous: the
    /// preparation is pure, so a caller can run this read first and then
    /// prepare with the owner's set in hand instead of holding a composition
    /// borrow across a Kernel round trip for the write legs.
    ///
    /// The task revision is resolved inside the finish owner from the live
    /// task-lifecycle owner record, so this boundary names only the task and
    /// never a caller-held revision.
    ///
    /// A read that is absent, refused, unadmitted, or bound to another task,
    /// revision or fence is a typed
    /// [`AcceptanceDenominatorError`], never a substituted plan list.
    pub async fn rehydrate_task_contract_acceptance(
        &self,
        task_id: &TaskId,
    ) -> Result<RehydratedContractAcceptanceSet, FinishAttemptError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(FinishAttemptError::Composition(CompositionError::NotReady));
        }
        self.finish_attempt_service()
            .rehydrate_task_contract_acceptance(task_id)
            .await
    }

    /// Prepares the exact exchange that publishes the Governor-derived
    /// canonical finish-evidence owner image for one candidate. `None` means
    /// the derived image is already current, so nothing is owed.
    ///
    /// `contract_acceptance` is the contract owner's rehydrated enumeration
    /// from [`Self::rehydrate_task_contract_acceptance`], carried as a
    /// [`RehydratedContractAcceptanceSet`]. The caller supplies that value
    /// rather than this method reading it, so the whole preparation stays pure
    /// and no composition borrow crosses the read — and it can only supply one
    /// that the owner read produced, because the type has no public
    /// constructor.
    ///
    /// This method transports nothing, so the caller may hold its composition
    /// borrow for this call alone. The refresh that publishes the evidence leg's
    /// committed image belongs to [`Self::prepare_finish_decision`].
    pub fn prepare_finish_evidence(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        draft: &FinishAttemptDraft,
        contract_acceptance: &RehydratedContractAcceptanceSet,
    ) -> Result<Option<PreparedKernelExchange>, FinishAttemptError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(FinishAttemptError::Composition(CompositionError::NotReady));
        }
        self.finish_attempt_service().prepare_finish_evidence(
            identity,
            operation_id,
            draft,
            contract_acceptance,
        )
    }

    /// Prepares the exact exchange that persists the finish decision.
    ///
    /// The refresh runs here, synchronously and under the caller's `&mut self`,
    /// because the decision must be evaluated against the canonical image the
    /// evidence leg actually published — never against a pre-publish snapshot.
    /// No transport is touched, so the caller may hold its composition borrow
    /// for this call alone.
    pub fn prepare_finish_decision(
        &mut self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        draft: FinishAttemptDraft,
    ) -> Result<PreparedFinishDecision, FinishAttemptError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(FinishAttemptError::Composition(CompositionError::NotReady));
        }
        self.refresh_from_kernel()
            .map_err(FinishAttemptError::Composition)?;
        self.finish_attempt_service()
            .prepare_finish_decision(identity, operation_id, draft)
    }

    /// Re-checks a completed exchange against the live canonical owner.
    ///
    /// The prepared leg captured its owner fence before the caller began the
    /// exchange, and the exchange ran with no composition borrow, so this is
    /// where a fence that moved in the meantime refuses the leg with the same
    /// typed mismatch the prepare half uses. Nothing is re-derived and no
    /// receipt is repaired.
    pub fn accept_prepared_exchange(
        &self,
        prepared: &PreparedKernelExchange,
    ) -> Result<(), FinishAttemptError> {
        self.finish_attempt_service()
            .accept_prepared_exchange(prepared)
    }

    /// Runs the production `FinishAttempt` path and returns only after the
    /// canonical receipt has committed. Publication is performed by the
    /// daemon composition through `refresh_from_kernel`, using the same
    /// committed-receipt boundary as the other daemon callers.
    ///
    /// This is the composed form of [`Self::prepare_finish_evidence`],
    /// [`Self::prepare_finish_decision`] and [`Self::accept_prepared_exchange`]
    /// for a caller that holds `&mut self` and accepts that borrow across the
    /// exchanges. A caller that must not hold a lock across Kernel IO — the
    /// `TestD` owner drain — runs the same phases itself over the same
    /// Governor-derived exchanges, identities, fence and receipt checks, in
    /// this same order.
    ///
    /// The order is load-bearing: the evidence leg is exchanged and admitted
    /// before the decision is prepared, so the decision is derived against the
    /// canonical image the evidence leg actually published and never against a
    /// pre-publish snapshot.
    pub async fn finish_attempt(
        &mut self,
        identity: &RequestIdentity,
        operation_id: OperationId,
        draft: FinishAttemptDraft,
    ) -> Result<FinishDecisionReceipt, FinishAttemptError> {
        // I7.9, issue #1741: the contract owner's acceptance-item enumeration is
        // rehydrated first, so the evidence leg's denominator is the owner's
        // enumeration rather than the plan's declared list.
        let task_id = TaskId::new(draft.task_id.clone())
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
        let contract_acceptance = self.rehydrate_task_contract_acceptance(&task_id).await?;
        let evidence =
            self.prepare_finish_evidence(identity, &operation_id, &draft, &contract_acceptance)?;
        if let Some(prepared) = evidence.as_ref() {
            let _receipt = prepared.exchange(self.kernel.as_ref()).await?;
            self.accept_prepared_exchange(prepared)?;
        }
        // Refreshes the owner, so the decision sees the evidence leg's image.
        let decision = self.prepare_finish_decision(identity, &operation_id, draft)?;
        if let Some(prepared) = decision.exchange() {
            let _receipt = prepared.exchange(self.kernel.as_ref()).await?;
            self.accept_prepared_exchange(prepared)?;
        }
        Ok(decision.into_decision())
    }

    /// Borrows the single observation/verified-repair reconciliation owner as
    /// a canonical [`GovernorObservationReconciliation`] adapter.
    ///
    /// The adapter reads the current `observation: ObservationJournal` owner
    /// (recovered via the `Observation` named read) together with the
    /// `ProblemOwner` revision map, the canonical admission owner, and the
    /// retained neutral Kernel port. It creates no per-caller journal or
    /// problem map; admission commits through the existing canonical path
    /// and publishes only via `refresh_from_kernel` at the returned receipt
    /// revisions.
    #[must_use]
    pub fn observation_reconciliation(&self) -> GovernorObservationReconciliation<'_, P> {
        GovernorObservationReconciliation::new(
            &self.owners.observation,
            &self.owners.problem.revisions,
            &self.owners.canonical,
            self.kernel.as_ref(),
            self.readiness,
        )
    }

    /// Borrows the single operator-command reconciliation owner as a canonical
    /// [`GovernorOperatorReconciliation`] adapter.
    ///
    /// The adapter reads the canonical admission owner together with the
    /// retained neutral Kernel port. It creates no per-caller ledger: operator
    /// admission commits through the existing canonical path and every retry
    /// reconciles through the Kernel receipt route, so a newly created board
    /// resolves the original operation identity instead of re-admitting it.
    /// Publication follows `refresh_from_kernel` at the returned receipt
    /// revisions.
    #[must_use]
    pub fn operator_reconciliation(&self) -> GovernorOperatorReconciliation<'_, P> {
        GovernorOperatorReconciliation::new(
            &self.owners.canonical,
            self.kernel.as_ref(),
            self.readiness,
        )
    }

    /// Runs the `ScopeBindingGuard` at one mandatory trigger against the live
    /// retained `WorkScope` binding (issue #1787, `CanonicalWrite` trigger
    /// wiring).
    ///
    /// Reads the live [`WorkScopeBindingOwner`] at the retained fence and
    /// evaluates [`check_at_trigger`] with the caller-supplied observation:
    /// mechanical truth enters only through `observed`, never from retained
    /// fields. Without governing-source closure only the identity legs run, so
    /// a mismatching observation withholds or quarantines exactly as with a
    /// receipt while an identity-clear observation withholds pending source
    /// closure instead of allowing. Fails closed when no binding is retained
    /// or the owner read disagrees with the fence.
    ///
    /// Live status: no production caller. The live trigger evaluation is
    /// `check_material_readiness_for_effect`, which inlines the same
    /// `check_at_trigger` call against its own owner read; this entry is the
    /// unwired thin variant. Whether it is wired to that path or retired is an
    /// owner decision.
    pub fn check_work_scope_at_trigger(
        &self,
        observed: &ScopeBinding,
        trigger: GuardTrigger,
    ) -> Result<TriggerReport, CompositionError> {
        let owner = self.owners.work_scope.as_ref().ok_or_else(|| {
            CompositionError::Recovery(
                "WorkScope binding is unbound; guard revalidation is unavailable".to_owned(),
            )
        })?;
        let fence = self.snapshot.state_fence();
        let snapshot = owner
            .read_current(&fence)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        Ok(check_at_trigger(&snapshot.binding, observed, None, trigger))
    }

    /// Admits one trigger-gated operation against live `WorkScope` authority
    /// (issue #1787, admission wiring).
    ///
    /// Joins the live owner read, the retained resource descriptor, and the
    /// owner-issued resolution receipt through [`admit_at_trigger`]. Authority
    /// comes from the live owner read and the retained descriptor, never from
    /// receipt fields alone. Fails closed when no binding is retained.
    ///
    /// Live status: no production caller. Whether it is wired to a dispatch
    /// ingress or retired is an owner decision.
    pub fn admit_work_scope_at_trigger(
        &self,
        descriptor: &WorkScopeDescriptor,
        receipt: &WorkScopeResolutionReceipt,
        observed_generation: &GenerationEvidence,
        fence: &StateFence,
        trigger: GuardTrigger,
    ) -> Result<TriggerAdmission, CompositionError> {
        let Some(owner) = self.owners.work_scope.as_ref() else {
            return Err(CompositionError::Recovery(
                "WorkScope binding is unbound; trigger admission is unavailable".to_owned(),
            ));
        };
        admit_at_trigger(
            owner,
            descriptor,
            receipt,
            observed_generation,
            fence,
            trigger,
        )
        .map_err(|error| CompositionError::Recovery(error.to_string()))
    }

    /// Admits an authorized relocation/attach receipt as the new expected
    /// `WorkScope` binding (issue #1787, rebind wiring).
    ///
    /// Validates the receipt through [`rebind_with_receipt`] and requires the
    /// derived binding to be identity-clear against the caller-supplied live
    /// observation: a rebind that disagrees with what is actually observed
    /// fails instead of installing a stale binding. The returned binding is
    /// the expected binding for the next owner snapshot; persisting it as the
    /// current owner snapshot belongs to the recovery/bootstrap path that
    /// owns owner writes.
    ///
    /// Live status: no production caller. Whether it is wired to a relocation or
    /// attach ingress or retired is an owner decision.
    pub fn rebind_work_scope_with_receipt(
        receipt: &ScopeRelocationOrAttachReceipt,
        expected_scope_ref: &str,
        privacy_class: PrivacyClass,
        governing_source_generation: u64,
        fence: &StateFence,
        observed: &ScopeBinding,
    ) -> Result<ScopeBinding, CompositionError> {
        let binding = rebind_with_receipt(
            receipt,
            expected_scope_ref,
            privacy_class,
            governing_source_generation,
            fence,
        )
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if eliot_workscope::identity_legs(&binding, observed) != IdentityLegOutcome::IdentityClear {
            return Err(CompositionError::Recovery(
                "rebound WorkScope binding disagrees with the live observation".to_owned(),
            ));
        }
        Ok(binding)
    }

    /// Runs one scope-identity resolution request through the evidence-first
    /// order (issue #1787, resolver production caller).
    ///
    /// Entry for attach callers: the request carries session/task authority
    /// references, binding tokens, resumed-task evidence, host handles,
    /// registered instances or relocation receipts, lineage evidence, or a
    /// manifest boundary, plus supporting-only evidence that can withhold a
    /// unique outcome but never select. The first tier with usable evidence
    /// decides; ambiguity preserves the candidate set instead of selecting.
    ///
    /// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
    pub fn resolve_scope_identity(
        request: &ResolutionRequest,
    ) -> Result<ScopeResolution, CompositionError> {
        WorkScopeResolver::resolve(request)
            .map(|outcome| outcome.resolution)
            .map_err(|error| CompositionError::Recovery(error.to_string()))
    }

    /// Resolves scanner-derived inputs through the evidence-first resolver
    /// (issue #1787, scanner-seam production caller).
    ///
    /// Runs [`BootstrapScanner::resolve_with_scan`] for an attach caller:
    /// discovery evidence populates only the host-handles, lineage, and
    /// manifest-boundary tiers, so resolution can distinguish candidates but
    /// never authenticates a scope; owner issuance stays separate.
    ///
    /// Live status: no production caller. Whether a scanner ingress builds these
    /// inputs or the entry is retired is an owner decision.
    pub fn resolve_scope_identity_from_scan(
        inputs: &ScannerResolverInputs,
        candidates: &WorkScopeCandidateSet,
    ) -> Result<ScopeResolution, CompositionError> {
        BootstrapScanner::resolve_with_scan(inputs, candidates)
            .map(|outcome| outcome.resolution)
            .map_err(|error| CompositionError::Recovery(error.to_string()))
    }

    /// Issues a durable resolution receipt from the live owner binding (issue
    /// #1787, issuance production caller).
    ///
    /// Issuance reads `owner` at `fence` and requires the retained binding to
    /// match `descriptor` with a `MATCHED` guard receipt; `Authenticated`
    /// issuance additionally requires the supplied source closure to
    /// re-validate. The receipt proves owner issuance; its fields alone do not.
    ///
    /// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
    #[allow(
        clippy::too_many_arguments,
        reason = "issuance joins every durable receipt field in one owner-checked entry"
    )]
    pub fn issue_scope_resolution_receipt(
        &self,
        receipt_ref: &str,
        proposal_ref: &str,
        descriptor: &WorkScopeDescriptor,
        owner: &WorkScopeBindingOwner,
        fence: &StateFence,
        authentication: ResolutionAuthentication,
        supporting_evidence: Vec<IdentityEvidence>,
        rejected_candidate_refs: Vec<String>,
        unresolved_candidate_refs: Vec<String>,
        authority_ref: &str,
        source_closure: Option<(&GoverningSourceSet, &PrivacyProfile)>,
    ) -> Result<WorkScopeResolutionReceipt, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        issue_resolution_receipt(
            receipt_ref,
            proposal_ref,
            descriptor,
            owner,
            fence,
            authentication,
            supporting_evidence,
            rejected_candidate_refs,
            unresolved_candidate_refs,
            authority_ref,
            source_closure,
        )
        .map_err(|error| CompositionError::Recovery(error.to_string()))
    }

    /// Enforces the scope binding guard at one trigger (issue #1787, guard
    /// admission-chain production caller).
    ///
    /// Reads the retained binding at the retained fence, evaluates `observed`
    /// at `trigger` with the caller-retained source closure, and returns the
    /// current snapshot only when the report is `MATCHED` (identity-clear
    /// `Allow` with a full `MATCHED` receipt). Any other report withholds
    /// with the structured [`CompositionError::ScopeGuardWithheld`] carrying
    /// the exact trigger report; an identity mismatch is additionally
    /// retained in the bounded process-local diagnostic projection before
    /// withholding. The retained binding, task state, and project memory
    /// are untouched on any failure.
    ///
    /// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
    pub fn require_scope_guard_for_observed(
        &mut self,
        observed: &ScopeBinding,
        source_closure: Option<(&GoverningSourceSet, &PrivacyProfile)>,
        trigger: GuardTrigger,
    ) -> Result<WorkScopeBindingSnapshot, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let fence = self.snapshot.state_fence();
        let owner = self.owners.work_scope.as_ref().ok_or_else(|| {
            CompositionError::Recovery(
                "WorkScope binding is unbound; scope-guarded work is unavailable".to_owned(),
            )
        })?;
        let snapshot = owner
            .read_current(&fence)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let report = check_at_trigger(&snapshot.binding, observed, source_closure, trigger);
        if report.is_matched() {
            Ok(snapshot)
        } else {
            if report.identity != IdentityLegOutcome::IdentityClear {
                self.push_scope_quarantine_record(
                    &snapshot.binding,
                    observed,
                    &report,
                    fence.resource_generation.value(),
                )?;
            }
            Err(CompositionError::ScopeGuardWithheld {
                claimed_scope: snapshot.binding.scope.scope_ref.clone(),
                observed_scope: observed.scope.scope_ref.clone(),
                trigger: report.trigger,
                identity: report.identity,
                verdict: report.verdict,
                report: Box::new(report),
            })
        }
    }

    /// Admits an authorized relocation/attach receipt as the new expected
    /// `WorkScope` binding (issue #1787, rebind production caller).
    ///
    /// The receipt must name the retained scope and match the retained fence;
    /// the new binding carries the observed workspace-instance identity and
    /// generation, and admission additionally requires a fresh `MATCHED`
    /// source-closure check for that instance. Afterwards the same operation
    /// is admitted only with the observed identity and fence. The prior
    /// identity stays preserved inside the receipt. The returned owner is not
    /// retained here: persist it with
    /// [`Self::install_admitted_work_scope_owner`], which enforces
    /// generation-aligned installation at the same fence.
    ///
    /// Live status: no production caller, and the "production caller" in the
    /// summary line is aspirational rather than measured. Measured on this tree
    /// by symbol, this rebind has exactly **one** code reference,
    /// [`Self::admit_observed_scope_attach`]; that entry's only code reference
    /// is the daemon's `DaemonComposition::admit_scope_attach`, which itself has
    /// zero call sites. So the rebind is transitively dead at depth three and no
    /// live path admits an authorized relocation. The daemon-side entry already
    /// discloses why it is additionally circular — the Governor fails closed
    /// unless a `WorkScope` owner is already retained, and that entry is the only
    /// daemon path that installs one — so a caller cannot be added here without
    /// inventing authority. Whether a caller is added or this entry is retired is
    /// an owner decision.
    ///
    /// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
    pub fn admit_scope_relocation(
        &self,
        receipt: &ScopeRelocationOrAttachReceipt,
        privacy_class: PrivacyClass,
        governing_source_generation: u64,
        sources: &GoverningSourceSet,
        privacy: &PrivacyProfile,
        owner_revision: u64,
    ) -> Result<WorkScopeBindingOwner, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let fence = self.snapshot.state_fence();
        let owner = self.owners.work_scope.as_ref().ok_or_else(|| {
            CompositionError::Recovery(
                "WorkScope binding is unbound; relocation has no retained scope".to_owned(),
            )
        })?;
        let retained = owner
            .read_current(&fence)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let relocated = rebind_with_receipt(
            receipt,
            &retained.binding.scope.scope_ref,
            privacy_class,
            governing_source_generation,
            &fence,
        )
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let fresh = ScopeBindingGuard.check(&relocated, &relocated, sources, privacy);
        if fresh.disposition != ScopeBindingDisposition::Matched {
            return Err(CompositionError::Recovery(
                "relocation source closure is not matched for the observed instance".to_owned(),
            ));
        }
        let snapshot = WorkScopeBindingSnapshot::new(fence, owner_revision, relocated, fresh)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        WorkScopeBindingOwner::new(snapshot)
            .map_err(|error| CompositionError::Recovery(error.to_string()))
    }

    /// Admits an observed workspace instance as an attach to the retained scope
    /// (issue #1787, attach production caller).
    ///
    /// This is the owning thin caller for the attach trigger path: `observed`
    /// is the live mechanical observation already derived from workspace facts
    /// (the daemon trigger ingress observes the explicit root and derives at
    /// the admission fence generation; the CLI scope-observe ingress derives
    /// the same shape as evidence). The entry produces the owner-issued attach
    /// receipt from that observation, the retained descriptor and owner, and
    /// the explicit authorization reference, then admits it through
    /// [`Self::admit_scope_relocation`], which rebinds with the receipt and
    /// requires a fresh `MATCHED` source-closure check for the observed
    /// instance. Both the receipt and the admitted owner return, so the caller
    /// retains the authorization evidence alongside the new binding; persist
    /// the owner with [`Self::install_admitted_work_scope_owner`]. The prior
    /// identity stays preserved inside the receipt; the retained binding, task
    /// state, and project memory are untouched on any failure. Live status:
    /// reachable from the daemon `admit_scope_attach` entry; no live attach
    /// transport calls that entry yet (BLOCKED-BY attach-transport).
    ///
    /// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
    #[allow(
        clippy::too_many_arguments,
        reason = "attach admission joins the live observation, retained records, authorization, and source closure in one entry"
    )]
    pub fn admit_observed_scope_attach(
        &self,
        receipt_ref: &str,
        observed: &ObservedScopeResources,
        descriptor: &WorkScopeDescriptor,
        authorizing_ref: &str,
        privacy_class: PrivacyClass,
        governing_source_generation: u64,
        sources: &GoverningSourceSet,
        privacy: &PrivacyProfile,
        owner_revision: u64,
    ) -> Result<(ScopeRelocationOrAttachReceipt, WorkScopeBindingOwner), CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let fence = self.snapshot.state_fence();
        let owner = self.owners.work_scope.as_ref().ok_or_else(|| {
            CompositionError::Recovery(
                "WorkScope binding is unbound; attach has no retained scope".to_owned(),
            )
        })?;
        let receipt = produce_attach_receipt(
            receipt_ref,
            descriptor,
            owner,
            observed,
            authorizing_ref,
            &fence,
        )
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let bound = self.admit_scope_relocation(
            &receipt,
            privacy_class,
            governing_source_generation,
            sources,
            privacy,
            owner_revision,
        )?;
        Ok((receipt, bound))
    }

    /// Admits the initial binding for a newly resolved scope (issue #1787,
    /// bootstrap-constructor entry).
    ///
    /// Used when no retained owner exists yet: the bootstrap caller supplies
    /// the described scope, the binding it actually read, the current
    /// observation, and the source closure that authenticates it. Admission
    /// mints the owner only after descriptor agreement, clear identity legs,
    /// and a fresh `MATCHED` guard check at the retained fence. Persist the
    /// minted owner with [`Self::install_admitted_work_scope_owner`]. Live
    /// status: no production caller. `git grep -n admit_initial_scope_binding`
    /// returns only this definition and one intra-doc link in
    /// [`Self::install_admitted_work_scope_owner`]'s own doc. The nearest live
    /// rebind entry is [`Self::admit_observed_scope_attach`], reached from the
    /// daemon scope-attach ingress and persisting through the same
    /// installer; no bootstrap ingress supplies the described scope this entry
    /// requires. Whether one is wired to it or this entry is retired is an
    /// owner decision.
    ///
    /// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
    pub fn admit_initial_scope_binding(
        &self,
        descriptor: &WorkScopeDescriptor,
        owner_revision: u64,
        binding: &ScopeBinding,
        observed: &ScopeBinding,
        sources: &GoverningSourceSet,
        privacy: &PrivacyProfile,
    ) -> Result<WorkScopeBindingOwner, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let fence = self.snapshot.state_fence();
        admit_initial_binding(
            descriptor,
            owner_revision,
            &fence,
            binding,
            observed,
            sources,
            privacy,
        )
        .map_err(|error| CompositionError::Recovery(error.to_string()))
    }

    /// Persists an admitted `WorkScope` owner as the retained binding
    /// (issue #1787, rebind/attach persistence).
    ///
    /// Installs the owner minted by [`Self::admit_scope_relocation`],
    /// [`Self::admit_observed_scope_attach`], or
    /// [`Self::admit_initial_scope_binding`] only when it is readable at the
    /// retained fence, its guard receipt is freshly `MATCHED` and agrees with
    /// the binding on every identity field, and the binding generation equals
    /// the fence generation, so the same operation is admitted afterwards
    /// only with that instance identity and generation fence. Anything else
    /// fails without touching the retained binding.
    pub fn install_admitted_work_scope_owner(
        &mut self,
        owner: WorkScopeBindingOwner,
    ) -> Result<WorkScopeBindingSnapshot, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let fence = self.snapshot.state_fence();
        let snapshot = owner
            .read_current(&fence)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        ensure_snapshot_fresh(&snapshot, "install admitted WorkScope owner")?;
        if snapshot.binding.scope.generation != fence.resource_generation.value() {
            return Err(CompositionError::Recovery(
                "admitted WorkScope binding generation disagrees with the installation fence"
                    .to_owned(),
            ));
        }
        self.owners.work_scope = Some(owner);
        Ok(snapshot)
    }

    /// Retains one scope-identity mismatch in the bounded in-process
    /// diagnostic projection (issue #1787, W6 partial projection).
    ///
    /// Builds the [`QuarantinedScopeRecord`] for `report` through its
    /// existing constructor and validator, then appends it instead of
    /// overwriting: a record whose stable idempotency identity is already
    /// retained adds no new evidence, anything else appends with
    /// oldest-first eviction at
    /// [`MAX_RETAINED_SCOPE_QUARANTINE_RECORDS`]. The retained binding,
    /// task state, and project memory stay untouched. Construction or
    /// identity failure is never silent: it fails closed here so the
    /// conflicting evidence cannot disappear while the write is withheld.
    /// This projection is not durable, rehydrated, or an authority for
    /// rebind; durable quarantine still belongs to the `WorkScope`
    /// owner path.
    fn push_scope_quarantine_record(
        &mut self,
        expected: &ScopeBinding,
        observed: &ScopeBinding,
        report: &TriggerReport,
        fence_generation: u64,
    ) -> Result<(), CompositionError> {
        let record = QuarantinedScopeRecord::for_report(
            expected,
            observed,
            report,
            fence_generation,
        )
        .map_err(|error| {
            CompositionError::Recovery(format!(
                "scope guard withheld at trigger {:?} after scope mismatch, but its process-local diagnostic could not be retained: {error}",
                report.trigger
            ))
        })?;
        let (_, idempotency_key) = record.operation_identity().map_err(|error| {
            CompositionError::Recovery(format!(
                "scope guard withheld at trigger {:?} after scope mismatch, but its quarantine identity could not be derived: {error}",
                report.trigger
            ))
        })?;
        // Preserve every unresolved conflict instead of overwriting one
        // slot: a record whose stable idempotency identity is already
        // retained anywhere in the bounded history adds no new evidence,
        // anything else appends with oldest-first eviction at the bound.
        // The retained binding, task state, and project memory stay
        // untouched; durable quarantine still belongs to the WorkScope
        // owner path.
        let already_retained = self.scope_quarantine.iter().any(|retained| {
            retained
                .operation_identity()
                .is_ok_and(|(_, retained_key)| retained_key == idempotency_key)
        });
        if !already_retained {
            if self.scope_quarantine.len() >= MAX_RETAINED_SCOPE_QUARANTINE_RECORDS {
                self.scope_quarantine.remove(0);
            }
            self.scope_quarantine.push(record);
        }
        Ok(())
    }

    /// Checks the canonical write against the caller-supplied, actual observed
    /// `WorkScope` at the current Kernel fence (issue #1787, W5). The write's
    /// claimed scope must match that observation, and it proceeds only when
    /// the guard returns `Allow` with a fresh `MATCHED` source-closure receipt.
    /// The observed binding is never derived from the retained binding or the
    /// write claim. Missing binding or source closure fails closed. Identity
    /// mismatches append to the bounded process-local diagnostic projection
    /// (no silent overwrite, no state or memory transfer); durable quarantine
    /// and restart recovery remain partial (W6).
    /// Runs the retained `WorkScope` guard at one I4.2.1 use boundary from a
    /// live resource observation (issue #1746, W3).
    ///
    /// This is the guard at every boundary the architecture names — session
    /// attach/resume, first tool/process event for a task, agent/process
    /// launch, a root/worktree/cwd/editor-workspace change, and a
    /// scope-sensitive canonical write or Material effect — not only at the
    /// canonical-write boundary [`Self::check_canonical_write_work_scope`]
    /// already covered. The trigger is supplied by the boundary, never guessed.
    ///
    /// The comparison input is derived from the observation itself:
    /// [`eliot_workscope::observed_scope_binding`] builds the observed
    /// [`ScopeBinding`] from the live instance/lineage/generation the caller
    /// read plus the *retained* scope reference, so a caller cwd, a normalized
    /// path string, or a caller-chosen scope label can never stand in for a real
    /// workspace read. An observation of several instances is refused as
    /// [`CompositionError::ScopeObservationAmbiguous`] without picking one.
    ///
    /// The verdict is preserved in full. On success the fresh `MATCHED`
    /// [`TriggerReport`] is returned; otherwise the typed
    /// [`CompositionError::ScopeGuardWithheld`] carries the exact identity leg
    /// (`DIFFERENT_INSTANCE`, `AMBIGUOUS`, `STALE_BINDING`) and the
    /// receipt disposition (`MATCHED`, `STALE_BINDING`, `DIFFERENT_INSTANCE`,
    /// `AMBIGUOUS`, `CONFLICTED`), and every non-identity-clear outcome also
    /// retains the conflicting lineage in the bounded process-local quarantine
    /// projection. A mismatching observation never moves the retained binding,
    /// a task, or any scope's memory, and it never re-binds silently: a
    /// relocation still needs its explicit owner receipt through
    /// [`Self::admit_scope_relocation`].
    #[allow(
        clippy::too_many_arguments,
        reason = "use-boundary guard joins the observation, privacy, source closure, and trigger in one fail-closed entry"
    )]
    pub fn check_work_scope_at_use_boundary(
        &mut self,
        observed: &ObservedScopeResources,
        observed_privacy_class: PrivacyClass,
        governing_source_generation: u64,
        source_closure: Option<(&GoverningSourceSet, &PrivacyProfile)>,
        trigger: GuardTrigger,
    ) -> Result<TriggerReport, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let fence = self.snapshot.state_fence();
        let owner = self.owners.work_scope.as_ref().ok_or_else(|| {
            CompositionError::Recovery(
                "WorkScope binding is unbound; scope-guarded work is unavailable".to_owned(),
            )
        })?;
        let snapshot = owner
            .read_current(&fence)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        ensure_snapshot_fresh(&snapshot, "use-boundary WorkScope is not fresh")?;
        let observed_binding = eliot_workscope::observed_scope_binding(
            &snapshot.binding,
            observed,
            observed_privacy_class,
            governing_source_generation,
        )
        .map_err(|error| match error {
            eliot_workscope::WorkScopeError::AmbiguousObservation { observed_instances } => {
                CompositionError::ScopeObservationAmbiguous {
                    trigger,
                    observed_instances,
                }
            }
            other => CompositionError::Recovery(other.to_string()),
        })?;
        let report = check_at_trigger(
            &snapshot.binding,
            &observed_binding,
            source_closure,
            trigger,
        );
        if !report.is_matched() {
            if report.identity != IdentityLegOutcome::IdentityClear {
                self.push_scope_quarantine_record(
                    &snapshot.binding,
                    &observed_binding,
                    &report,
                    fence.resource_generation.value(),
                )?;
            }
            return Err(CompositionError::ScopeGuardWithheld {
                claimed_scope: snapshot.binding.scope.scope_ref.clone(),
                observed_scope: observed_binding.scope.scope_ref.clone(),
                trigger: report.trigger,
                identity: report.identity,
                verdict: report.verdict,
                report: Box::new(report),
            });
        }
        Ok(report)
    }

    /// Partial-key task-selection lookup that always fail-closes (issue
    /// #1746, W4).
    ///
    /// Partial lease-key terms cannot authorize durable task selection
    /// (#1790): this entry never resolves a snapshot from them and never
    /// synthesizes selection source/evidence, so a task-relative dispatch leg
    /// that reaches it withholds instead of admitting on a partial identity.
    /// Callers holding the full readiness claim use
    /// [`Self::current_task_selection_for_claim`], which validates the
    /// retained receipt (with its owner-proven selection source/evidence refs
    /// from `TaskIntakeCandidate::promote` via [`Self::promote_task_intake`])
    /// against the live Governor fence and freshly matched `WorkScope` and
    /// joins a current task contract to the unique live activation. This
    /// entry never prefers the latest or most similar task, and it never
    /// creates one.
    ///
    /// # Errors
    ///
    /// Always returns `CompositionError::Recovery` directing the caller to
    /// supply the full readiness claim.
    pub fn current_task_selection(
        &self,
        now: u64,
        _lineage_candidate_ref: &str,
        _workspace_instance_candidate_ref: &str,
        _privacy_class: PrivacyClass,
        _governing_source_generation: u64,
    ) -> Result<
        (
            Option<GovernorActivationSnapshot>,
            eliot_workscope::OnboardingReadinessReceipt,
        ),
        CompositionError,
    > {
        let _ = now;
        Err(CompositionError::Recovery(
            "partial cold-start identity cannot authorize durable task selection; supply the full readiness claim"
                .to_owned(),
        ))
    }

    /// Resolves task selection only from the exact durable terminal receipt
    /// named by a full ORS readiness claim.
    pub fn current_task_selection_for_claim(
        &self,
        now: u64,
        claim: &ColdStartReadinessClaim,
    ) -> Result<
        (
            Option<GovernorActivationSnapshot>,
            eliot_workscope::OnboardingReadinessReceipt,
        ),
        CompositionError,
    > {
        let (_, receipt) = self.cold_start_readiness_terminal_for_claim(claim, now)?;
        let live_fence = self.snapshot.state_fence();
        match receipt.task_binding.clone() {
            TaskBindingState::CurrentTaskContract {
                task_ref,
                task_revision,
                ..
            } => {
                if receipt.scope_resolution != eliot_workscope::ScopeResolutionState::Authenticated
                    || receipt.readiness != eliot_workscope::ReadinessLifecycle::ReadyMaterial
                {
                    return Err(CompositionError::ActivationStaleFence);
                }
                let activation = self.read_unique_agent_activation(now)?;
                if !fences_match_exact(&activation.state_fence, &live_fence)
                    || receipt.principal_ref != activation.principal_id
                    || receipt.session_ref != activation.session_id
                    || receipt.scope.scope_ref != activation.work_scope_id
                    || task_ref != activation.task_id.as_str()
                    || task_revision != activation.task_revision
                {
                    return Err(CompositionError::ActivationStaleFence);
                }
                Ok((Some(activation), receipt))
            }
            TaskBindingState::None_
            | TaskBindingState::Exploratory { .. }
            | TaskBindingState::Stale { .. }
            | TaskBindingState::Ambiguous { .. } => Ok((None, receipt)),
        }
    }

    /// Admits one scope-sensitive canonical write whose observed binding and
    /// source closure the caller already holds (issue #1787).
    pub fn check_canonical_write_work_scope(
        &mut self,
        scope_id: &str,
        observed: &ScopeBinding,
        source_closure: Option<(&GoverningSourceSet, &PrivacyProfile)>,
    ) -> Result<TriggerReport, CompositionError> {
        let owner = self.owners.work_scope.as_ref().ok_or_else(|| {
            CompositionError::Recovery(
                "canonical write has no retained WorkScope binding; write withheld".to_owned(),
            )
        })?;
        let fence = self.snapshot.state_fence();
        let snapshot = owner
            .read_current(&fence)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        ensure_snapshot_fresh(&snapshot, "canonical-write WorkScope is not fresh")?;
        observed
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let report = check_at_trigger(
            &snapshot.binding,
            observed,
            source_closure,
            GuardTrigger::CanonicalWrite,
        );
        let claimed_scope_matches_observation = scope_id == observed.scope.scope_ref.as_str();
        if !claimed_scope_matches_observation || !report.is_matched() {
            if report.identity != IdentityLegOutcome::IdentityClear {
                self.push_scope_quarantine_record(
                    &snapshot.binding,
                    observed,
                    &report,
                    fence.resource_generation.value(),
                )?;
            }
            return Err(CompositionError::ScopeGuardWithheld {
                claimed_scope: scope_id.to_owned(),
                observed_scope: observed.scope.scope_ref.clone(),
                trigger: report.trigger,
                identity: report.identity,
                verdict: report.verdict,
                report: Box::new(report),
            });
        }
        Ok(report)
    }

    /// Admits governing sources for one scope generation (issue #1791,
    /// governing-source admission production caller).
    ///
    /// Owning thin entry for daemon/scanner ingress: runs
    /// [`eliot_workscope::admit_governing_sources`] over the caller-built
    /// request (candidates from authenticated receipts or discovery leases,
    /// applicable authority claims, proven bindings/contracts, declared
    /// precedences), then enforces the admission fence before returning: an
    /// expired admission and an admitted record without authority fail closed
    /// here instead of reaching readiness. The returned admission is the
    /// caller input for cold-start compilation of that scope generation.
    /// Live status: owning thin entry for daemon/scanner ingress; no live
    /// attach transport builds a `SourceAdmissionRequest` yet
    /// (BLOCKED-BY attach-transport).
    pub fn admit_governing_sources_for_scope(
        request: SourceAdmissionRequest,
        now: u64,
    ) -> Result<GoverningSourceAdmission, CompositionError> {
        let admission = eliot_workscope::admit_governing_sources(request)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        admission
            .require_live(now)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        admission
            .require_admitted_authority()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        Ok(admission)
    }

    /// Builds the `TASK_SELECTION_REQUIRED` intake shape for one scope
    /// (issue #1791, task-selection production caller).
    ///
    /// Owning thin entry for the activation path: when no current task
    /// exists, the daemon answers with the minimal valid intake shape (goal,
    /// acceptance, owner, scope plus a complete example) and the bounded
    /// exploratory offer from [`eliot_workscope::task_selection_required`],
    /// so the emitted selection directive always has a backing intake shape.
    /// Live status: owning thin entry for the activation path; the live
    /// activation projection emits its own directive without calling this
    /// entry yet (BLOCKED-BY activation/task-ingress).
    pub fn task_selection_intake_shape(
        scope_ref: &str,
    ) -> Result<TaskSelectionRequired, CompositionError> {
        eliot_workscope::task_selection_required(scope_ref)
            .map_err(|error| CompositionError::Recovery(error.to_string()))
    }

    /// Promotes one task-intake candidate through its owner/delegation path
    /// (issue #1791, intake-promotion production caller).
    ///
    /// Owning thin entry for task ingress: runs
    /// [`eliot_workscope::TaskIntakeCandidate::promote`] with the existing
    /// task binding the delegation names (`parent`, read from live governor
    /// task state), so a `Current` binding input only ever arises from the
    /// required owner or a proven delegation, never from direct construction.
    /// The admitted selection act travels with the input: the admitting
    /// decision owner (or delegating binding) as `selection_source_ref` and
    /// the exact intake as `evidence_ref`, which the receipt compiler carries
    /// into the terminal receipt for the bind path to compare.
    /// Live status: owning thin entry for task ingress; no live task ingress
    /// builds a `TaskIntakeCandidate` yet (BLOCKED-BY task-ingress).
    pub fn promote_task_intake(
        candidate: &TaskIntakeCandidate,
        basis: &AuthorityBasis,
        parent: &TaskBindingState,
        task_revision: u64,
    ) -> Result<TaskBindingInput, CompositionError> {
        candidate
            .promote(basis, parent, task_revision)
            .map_err(|error| CompositionError::Recovery(error.to_string()))
    }

    /// Admits one bounded exploratory binding without task authority
    /// (issue #1791, exploratory-admission production caller).
    ///
    /// Owning thin entry for orientation ingress: runs
    /// [`eliot_workscope::TaskIntakeCandidate::admit_exploratory`], whose
    /// read-only binding can never authorize scope-sensitive Material
    /// effects. Live status: owning thin entry for orientation ingress; no
    /// live orientation ingress calls this entry yet (BLOCKED-BY task-ingress).
    pub fn admit_exploratory_task_intake(
        candidate: &TaskIntakeCandidate,
    ) -> Result<TaskBindingInput, CompositionError> {
        candidate
            .admit_exploratory()
            .map_err(|error| CompositionError::Recovery(error.to_string()))
    }

    /// Maps a cold-start driver failure to its typed composition cause
    /// (issue #2900 B6).
    ///
    /// A compilation failure already carries its typed [`WorkScopeError`]
    /// owner cause — including the scan receipt missing/inaccessible/corrupt/
    /// replaced states that block completed readiness — so it travels
    /// unchanged instead of collapsing into a recovery string. A lease
    /// refusal has no owner cause and keeps the existing recovery string.
    fn cold_start_driver_error(error: eliot_workscope::CompileDriverError) -> CompositionError {
        match error {
            eliot_workscope::CompileDriverError::Compile(inner) => inner.into(),
            eliot_workscope::CompileDriverError::Lease(_) => {
                CompositionError::Recovery(error.to_string())
            }
        }
    }

    /// Binds the installation-owned durable scan disclosure store (issue
    /// #2900, defect D + W12 construction ingress).
    ///
    /// The installation/session owner admits the contour (installation
    /// identity plus admitted ORS object and generation) and supplies the
    /// canonical Store/ORS owner handle; this entry only admits the binding
    /// and maps it into [`InstallationScanDisclosureStore`]. The adapter owns
    /// no filesystem, takes no paths, launches no processes and makes no
    /// model calls. The bound store is the exact port
    /// [`Self::run_cold_start_trigger_scan`] takes before
    /// [`BootstrapScanner::scan`]: no trigger scan completes without the
    /// owner receipt, and the live terminal readiness receipt references the
    /// durable scan handle through
    /// [`Self::compile_cold_start_at_trigger`]'s `scan_receipt`.
    ///
    /// Caller: STITCH. The canonical owner handle lives with the Kernel
    /// installation owner (`RedbRecoveryStore::open` in
    /// `bins/eliot-kernel/src/composition_bootstrap.rs` implements
    /// `ScanDisclosureRecordOwner`); no live Governor/`eliotd` producer
    /// threads that handle to this entry yet, so no live attach ingress
    /// constructs the store today. A malformed contour fails closed without
    /// touching the durable owner.
    pub fn bind_installation_scan_store(
        installation_id: &str,
        ors_object_ref: &str,
        ors_generation: u64,
        owner: std::sync::Arc<dyn ScanDisclosureRecordOwner>,
    ) -> Result<InstallationScanDisclosureStore, CompositionError> {
        let contour = InstallationScanContour::bind(
            installation_id.to_owned(),
            ors_object_ref.to_owned(),
            ors_generation,
        )
        .map_err(CompositionError::ScanDisclosure)?;
        InstallationScanDisclosureStore::bind(contour, owner)
            .map_err(CompositionError::ScanDisclosure)
    }

    /// Runs one I4.4.1 cold-start trigger's discovery pass through the
    /// privacy-bounded scanner (issue #1790, cold-start trigger production
    /// caller; issue #2900, installation-bound durable owner).
    ///
    /// Owning thin entry for attach/onboarding ingress: the caller names the
    /// trigger (first project open, attach/launch, unknown workspace,
    /// onboarding request, stale generation, or resume without a current
    /// task) and supplies the discovery lease, lease key, owner-bound
    /// disclosure store, owner binding, privacy boundary, scan evidence and
    /// identity inputs the trigger's scanner pass requires. The store is the
    /// installation-bound durable owner, never a caller-chosen directory or
    /// an in-memory fallback: the pass in [`ColdStartController::run_trigger_scan`]
    /// authorizes the trigger's read set against the discovery lease and
    /// binds it to the scan evidence first, admits the owner binding, and
    /// only then does [`BootstrapScanner::scan`] run and durably persist the
    /// receipt through the owner. No trigger reaches the scanner past an
    /// unadmitted or unattested read, and no trigger scan completes without
    /// the owner receipt. A completed outcome is additionally replayed
    /// through the same owner before return: the persisted handle is read
    /// back under the same binding and its receipt identity is compared
    /// against this operation's receipt, so a missing, inaccessible,
    /// corrupt, replaced, stale, invalidated or unknown-commit record
    /// surfaces its typed [`WorkScopeError`] cause through
    /// [`CompositionError::ScanDisclosure`] instead of a completed outcome
    /// (issue #2900 B2/B6).
    /// Live status: owning thin entry for attach/onboarding ingress; no live
    /// attach ingress builds the scanner inputs yet (BLOCKED-BY
    /// attach-transport: `bins/eliotd` `ScopeAttachIngress` carries no
    /// discovery lease).
    #[allow(
        clippy::too_many_arguments,
        reason = "trigger scan carries the trigger, lease, key, owner store, owner binding, privacy, evidence, and identity inputs in one fail-closed entry"
    )]
    pub fn run_cold_start_trigger_scan(
        trigger: ColdStartTrigger,
        discovery_lease: &mut DiscoveryReadLease,
        lease_key: &DiscoveryLeaseKey,
        store: &mut InstallationScanDisclosureStore,
        binding: &ScanDisclosureOwnerBinding,
        candidate_privacy: PrivacyClass,
        privacy_boundary: Option<&PrivacyBoundary>,
        evidence: &BootstrapScanEvidence,
        proposed_kind: ScopeKind,
        identity_fingerprint: &str,
        verifier_candidates: &[String],
        governing_source_refs: Vec<String>,
        now: u64,
    ) -> Result<BootstrapScanOutcome, CompositionError> {
        let outcome = ColdStartController::run_trigger_scan(
            trigger,
            discovery_lease,
            lease_key,
            &mut *store,
            binding,
            candidate_privacy,
            privacy_boundary,
            evidence,
            proposed_kind,
            identity_fingerprint,
            verifier_candidates,
            governing_source_refs,
            now,
        )
        .map_err(Self::cold_start_driver_error)?;
        match &outcome {
            BootstrapScanOutcome::Completed { persisted, .. } => {
                persisted
                    .validate()
                    .map_err(CompositionError::ScanDisclosure)?;
                let replayed =
                    eliot_workscope::ScanDisclosureStore::readback(store, persisted, binding)
                        .map_err(CompositionError::ScanDisclosure)?;
                if replayed.scan_ref != persisted.receipt_ref {
                    return Err(CompositionError::ScanDisclosure(
                        WorkScopeError::ScanReceiptReplaced,
                    ));
                }
            }
            BootstrapScanOutcome::PrivacyBoundaryRequired { .. } => {}
        }
        Ok(outcome)
    }

    /// Quarantines one loose `scan-disclosure-*.json` capture left by the
    /// retired caller-chosen directory implementation (issue #2900,
    /// migration ingress).
    ///
    /// Owning thin entry for attach/onboarding ingress: the caller hands over
    /// the suspected filename and its bytes, and the installation-bound store
    /// classifies the file without adopting it. A matching filename alone is
    /// not owner provenance, so even well-formed bytes stay quarantined for
    /// the migration owner instead of becoming readable evidence.
    ///
    /// Live status: no production caller. No attach/onboarding ingress hands
    /// over a loose capture today. Whether the migration owner calls this or the
    /// entry is retired is an owner decision.
    pub fn quarantine_loose_scan_disclosure_capture(
        store: &InstallationScanDisclosureStore,
        file_name: &str,
        bytes: &[u8],
    ) -> Result<LooseScanQuarantine, CompositionError> {
        store
            .quarantine_loose_capture(file_name, bytes)
            .map_err(CompositionError::ScanDisclosure)
    }

    /// Binds the separate durable readiness table to the admitted installation
    /// contour. Rebinding is allowed only for the exact same contour; the
    /// transport owner may be refreshed without changing storage authority.
    pub fn bind_cold_start_readiness_owner(
        &mut self,
        contour: &InstallationScanContour,
        owner: Arc<dyn ColdStartReadinessRecordOwner>,
    ) -> Result<(), CompositionError> {
        if let Some(bound) = self.cold_start_readiness_contour.as_ref()
            && bound != contour
        {
            return Err(CompositionError::Recovery(
                "cold-start readiness owner cannot change its installation contour".to_owned(),
            ));
        }
        let owner = contour
            .bind_cold_start_readiness_owner(owner)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        self.cold_start_readiness_contour = Some(contour.clone());
        self.cold_start_readiness_owner = Some(owner);
        Ok(())
    }

    /// Builds the exact durable readiness key from the admitted lease,
    /// candidate, governing sources, scanner evidence, owner binding, and
    /// retained installation contour. Candidate source names alone cannot
    /// construct this claim: the source set must validate against the
    /// admitted privacy profile and the scan receipt must read back through
    /// its installation-bound owner.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the claim validates one complete lease, source set, scanner receipt, and installation contour before constructing its durable key"
    )]
    pub fn build_cold_start_readiness_claim(
        &self,
        proposed: &OnboardingLease,
        candidate: &WorkScopeCandidate,
        sources: &GoverningSourceSet,
        privacy: &PrivacyProfile,
        scan: &BootstrapScanEvidence,
        scan_store: &InstallationScanDisclosureStore,
        scan_binding: &ScanDisclosureOwnerBinding,
        scan_receipt: &ScanReceiptHandle,
    ) -> Result<ColdStartReadinessClaim, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        proposed
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        candidate
            .scope
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        candidate
            .instance
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        scan.validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        scan_binding
            .admit()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        privacy
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        sources
            .validate_for(&candidate.scope, privacy)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;

        let contour = self.cold_start_readiness_contour.as_ref().ok_or_else(|| {
            CompositionError::Recovery(
                "cold-start readiness owner has no admitted installation contour".to_owned(),
            )
        })?;
        if contour != scan_store.contour()
            || scan_binding.installation_id != contour.installation_id()
            || candidate.scope.lineage_ref.as_deref()
                != Some(proposed.lineage_candidate_ref.as_str())
            || candidate.scope.instance_ref != proposed.workspace_instance_candidate_ref
            || candidate.instance.instance_ref != proposed.workspace_instance_candidate_ref
            || candidate.instance.root_identity != candidate.scope.root_identity
            || candidate.privacy_class != proposed.privacy_class
            || !privacy.admits(candidate.privacy_class)
            || sources.scope_ref != candidate.scope.scope_ref
            || sources.generation != proposed.governing_source_generation
            || scan.canonical_root_ref != candidate.scope.root_identity
            || scan.filesystem_identity_ref != candidate.instance.root_identity
            || scan_binding.candidate_root_ref != candidate.scope.root_identity
        {
            return Err(CompositionError::Recovery(
                "cold-start readiness evidence does not match its exact candidate and owner binding"
                    .to_owned(),
            ));
        }

        let live_fence = self.snapshot.state_fence();
        live_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let fence_bytes = canonical_json_bytes(&live_fence)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if scan_binding.state_fence_ref.as_deref() != Some(sha256_hex(&fence_bytes).as_str()) {
            return Err(CompositionError::ActivationStaleFence);
        }

        let replayed =
            eliot_workscope::ScanDisclosureStore::readback(scan_store, scan_receipt, scan_binding)
                .map_err(CompositionError::ScanDisclosure)?;
        if replayed.scan_ref != scan_receipt.receipt_ref {
            return Err(CompositionError::ScanDisclosure(
                WorkScopeError::ScanReceiptReplaced,
            ));
        }

        let mut governing_source_digests: Vec<String> = sources
            .sources
            .iter()
            .map(|source| source.digest.clone())
            .collect();
        governing_source_digests.sort();
        governing_source_digests.dedup();
        let key = ColdStartReadinessOwnerKey {
            installation_id: contour.installation_id().to_owned(),
            lineage_candidate_ref: proposed.lineage_candidate_ref.clone(),
            workspace_instance_candidate_ref: proposed.workspace_instance_candidate_ref.clone(),
            filesystem_identity_ref: candidate.instance.root_identity.clone(),
            vcs_identity_ref: candidate.instance.vcs_identity_ref.clone(),
            privacy_boundary_ref: scan_binding.privacy_boundary_ref.clone(),
            privacy_class: candidate.privacy_class,
            governing_source_set_ref: format!(
                "governing-source-set:{}:{}",
                sources.scope_ref, sources.generation
            ),
            governing_source_generation: sources.generation,
            governing_source_digests,
            dirty_summary_ref: scan.vcs_dirty_summary_ref.clone(),
            state_fence: live_fence,
        };
        let lease_bytes = canonical_json_bytes(proposed)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let lease_bytes = String::from_utf8(lease_bytes)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        ColdStartReadinessClaim::new(
            key,
            proposed.lease_ref.clone(),
            proposed.deadline,
            lease_bytes,
        )
        .map_err(|error| CompositionError::Recovery(error.to_string()))
    }

    fn readiness_join_from_record(
        record: &ColdStartReadinessOrsRecord,
        now: u64,
        created: bool,
    ) -> Result<LeaseJoin, CompositionError> {
        record
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let lease: OnboardingLease = serde_json::from_str(&record.claim.lease_bytes)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        lease
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if lease.lease_ref != record.claim.lease_ref
            || lease.deadline != record.claim.lease_deadline
            || lease.lineage_candidate_ref != record.claim.key.lineage_candidate_ref
            || lease.workspace_instance_candidate_ref
                != record.claim.key.workspace_instance_candidate_ref
            || lease.privacy_class != record.claim.key.privacy_class
            || lease.governing_source_generation != record.claim.key.governing_source_generation
        {
            return Err(CompositionError::ActivationStaleFence);
        }
        if let Some(terminal) = record.terminal.as_ref() {
            if now > record.claim.lease_deadline {
                return Err(CompositionError::ActivationStaleFence);
            }
            let receipt: eliot_workscope::OnboardingReadinessReceipt =
                serde_json::from_str(&terminal.receipt_bytes)
                    .map_err(|error| CompositionError::Recovery(error.to_string()))?;
            receipt
                .validate()
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
            let surface = receipt
                .surface(&lease)
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
            return Ok(LeaseJoin::JoinedTerminal {
                lease_ref: lease.lease_ref,
                surface,
                receipt: Box::new(receipt),
            });
        }
        if now > record.claim.lease_deadline {
            return Err(CompositionError::ActivationStaleFence);
        }
        if created {
            Ok(LeaseJoin::Created {
                lease_ref: lease.lease_ref,
            })
        } else {
            Ok(LeaseJoin::Joined {
                lease_ref: lease.lease_ref,
            })
        }
    }

    /// Joins one I4.4.1 trigger to the durable cold-start single-flight
    /// lease (issue #1790, single-flight join production caller).
    ///
    /// The join runs against the installation-bound ORS readiness owner,
    /// so compatible concurrent attaches coalesce on exact workspace
    /// filesystem/VCS identity plus privacy boundary plus governing-source
    /// generation, and a changed governing-source digest or dirty-base summary
    /// at the same generation splits the lease instead of reusing the first
    /// lease's scope/task decision. The candidate and scanner evidence are
    /// mandatory: the lease key is verified against the exact candidate and
    /// the scan evidence before [`ColdStartController::check_discovery`]
    /// authorizes the trigger's scanner pass, so a trigger can never ride on
    /// unattested reads. Joining never creates a `WorkScope` and never infers
    /// a latest task; `JoinedTerminal` carries the shared terminal surface
    /// every waiter of the lease receives.
    /// Live status: owning thin entry for attach/onboarding ingress; no live
    /// attach ingress builds the lease inputs yet (BLOCKED-BY
    /// attach-transport: `bins/eliotd` `ScopeAttachIngress` carries no
    /// discovery or onboarding lease). Measured on this tree, that means zero
    /// call sites: the defining line is this entry's only reference in any
    /// crate. Two helpers are dead transitively with it and are named here
    /// because a name-level scan cannot see that:
    /// [`Self::build_cold_start_readiness_claim`] and the private
    /// `Self::readiness_join_from_record` are called only from this entry and
    /// from `Self::compile_cold_start_at_trigger`, which itself has zero call
    /// sites (`Caller: STITCH`), so neither helper runs. The nearest live cold-
    /// start trigger evaluation is `bins/eliotd/src/daemon_runtime.rs`'s
    /// `trigger_cold_start_controller`, which calls
    /// `ColdStartController::check_discovery_with_scan` directly and cannot
    /// build these lease inputs. Whether an attach ingress builds them or this
    /// entry is retired is an owner decision; no caller was added to close the
    /// gap.
    #[allow(
        clippy::too_many_arguments,
        reason = "evidence-bound join carries trigger, leases, candidate, sources, and scan evidence in one fail-closed entry"
    )]
    pub fn join_cold_start_lease(
        &mut self,
        trigger: ColdStartTrigger,
        discovery_lease: &DiscoveryReadLease,
        proposed: &OnboardingLease,
        candidate: &WorkScopeCandidate,
        sources: &GoverningSourceSet,
        privacy: &PrivacyProfile,
        scan: &BootstrapScanEvidence,
        scan_store: &InstallationScanDisclosureStore,
        scan_binding: &ScanDisclosureOwnerBinding,
        scan_receipt: &ScanReceiptHandle,
        now: u64,
    ) -> Result<LeaseJoin, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        ColdStartController::check_discovery_with_scan(trigger, discovery_lease, scan, now)
            .map_err(|error| {
                CompositionError::Recovery(format!("cold-start lease join refused: {error:?}"))
            })?;
        let claim = self.build_cold_start_readiness_claim(
            proposed,
            candidate,
            sources,
            privacy,
            scan,
            scan_store,
            scan_binding,
            scan_receipt,
        )?;
        let owner = self.cold_start_readiness_owner.as_ref().ok_or_else(|| {
            CompositionError::Recovery("cold-start readiness ORS owner is not bound".to_owned())
        })?;
        let outcome = owner
            .claim_cold_start_readiness(&claim, now)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let (record, created) = match outcome {
            ColdStartReadinessStageOutcome::Stored { record } => (*record, true),
            ColdStartReadinessStageOutcome::AlreadyBound { record } => (*record, false),
        };
        record
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if record.claim.key != claim.key
            || record.claim.binding_digest != claim.binding_digest
            || record.claim.base_identity_digest != claim.base_identity_digest
        {
            return Err(CompositionError::ActivationStaleFence);
        }
        if created && record.terminal.is_none() {
            self.cold_start_readiness_claims.insert(
                record.claim.binding_digest.clone(),
                ColdStartReadinessOwnerClaim {
                    claim,
                    record_key: record.record_key.clone(),
                },
            );
        }
        Self::readiness_join_from_record(&record, now, created)
    }

    /// Drives one I4.4.1 trigger end to end — join, compile, publish — against
    /// the retained registry (issue #1790, cold-start compilation production
    /// caller; issue #2900, durable scan receipt reference).
    ///
    /// The trigger that creates the lease compiles exactly one
    /// [`eliot_workscope::OnboardingReadinessReceipt`] through
    /// [`ColdStartController::compile`] before the first scope-sensitive work
    /// and publishes it as the lease terminal, so compatible concurrent
    /// attaches receive the same receipt and no worker independently creates
    /// a second `WorkScope` or "latest task" while the lease is active. The
    /// terminal receipt always references the exact durable scan receipt
    /// that fed the compilation: the caller supplies the installation-bound
    /// scan store, the owner binding admitted for this trigger, and the
    /// durable handle the trigger scan returned, and this entry reads the
    /// handle back through the owner before compiling. A missing handle, or
    /// a missing, inaccessible, corrupt, replaced, stale, invalidated or
    /// unknown-commit record, fails with its typed [`WorkScopeError`] cause
    /// through [`CompositionError::ScanDisclosure`] and never produces a
    /// terminal receipt — there is no in-memory-only or loose-file fallback,
    /// and an absent scan reference is never compiled as empty (issue #2900
    /// W12/B2/B6). An
    /// already-terminal lease returns its `JoinedTerminal` surface without
    /// recompiling; a lease owned by an in-flight trigger returns `Joined`
    /// without a second compilation.
    /// Live status: owning thin entry for attach/onboarding ingress; no live
    /// attach ingress builds the compilation inputs yet (BLOCKED-BY
    /// attach-transport: `bins/eliotd` `ScopeAttachIngress` carries no
    /// discovery or onboarding lease). Caller: STITCH.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "cold-start compilation joins every frozen receipt field and the durable terminal in one owner-checked entry"
    )]
    pub fn compile_cold_start_at_trigger(
        &mut self,
        trigger: ColdStartTrigger,
        discovery_lease: &DiscoveryReadLease,
        proposed: &OnboardingLease,
        receipt_ref: &str,
        principal_ref: &str,
        session_ref: &str,
        scope: &ScopeIdentity,
        instance: &WorkspaceInstanceIdentity,
        lineage: Option<&RepositoryLineageIdentity>,
        candidate: &WorkScopeCandidate,
        sources: &GoverningSourceSet,
        state_fence: &StateFence,
        governance_profile_ref: &str,
        limiting_integration_evidence: Vec<String>,
        route_profile_ref: &str,
        serializer_id: &str,
        serializer_version: &str,
        serializer_options_digest: &str,
        tokenizer_id: &str,
        tokenizer_version: &str,
        tokenizer_hash: &str,
        projection_source_ref: &str,
        projection_generation: u64,
        privacy: &PrivacyProfile,
        task: TaskBindingInput,
        scan: &BootstrapScanEvidence,
        scan_store: &InstallationScanDisclosureStore,
        scan_binding: &ScanDisclosureOwnerBinding,
        scan_receipt: Option<&ScanReceiptHandle>,
        now: u64,
    ) -> Result<LeaseJoin, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let scan_handle = scan_receipt.ok_or(CompositionError::ScanDisclosure(
            WorkScopeError::ScanReceiptMissing,
        ))?;
        ColdStartController::check_discovery_with_scan(trigger, discovery_lease, scan, now)
            .map_err(|error| {
                CompositionError::Recovery(format!("cold-start lease join refused: {error:?}"))
            })?;
        let claim = self.build_cold_start_readiness_claim(
            proposed,
            candidate,
            sources,
            privacy,
            scan,
            scan_store,
            scan_binding,
            scan_handle,
        )?;
        if !fences_match_exact(&claim.key.state_fence, state_fence) {
            return Err(CompositionError::ActivationStaleFence);
        }
        let retained_claim = self
            .cold_start_readiness_claims
            .get(&claim.binding_digest)
            .cloned()
            .ok_or_else(|| {
                CompositionError::Recovery(
                    "this composition did not win the durable cold-start lease claim".to_owned(),
                )
            })?;
        if retained_claim.claim.key != claim.key
            || retained_claim.claim.binding_digest != claim.binding_digest
            || retained_claim.claim.lease_ref != claim.lease_ref
        {
            return Err(CompositionError::ActivationStaleFence);
        }
        let owner = self.cold_start_readiness_owner.as_ref().ok_or_else(|| {
            CompositionError::Recovery("cold-start readiness ORS owner is not bound".to_owned())
        })?;
        let record = owner
            .load_cold_start_readiness(&retained_claim.record_key)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?
            .ok_or_else(|| {
                CompositionError::Recovery(
                    "durable cold-start lease disappeared before compilation".to_owned(),
                )
            })?;
        record
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if record.record_key != retained_claim.record_key
            || record.claim.key != claim.key
            || record.claim.binding_digest != claim.binding_digest
        {
            return Err(CompositionError::ActivationStaleFence);
        }
        if record.terminal.is_some() {
            let joined = Self::readiness_join_from_record(&record, now, false)?;
            self.cold_start_readiness_claims
                .remove(&claim.binding_digest);
            return Ok(joined);
        }
        if now > record.claim.lease_deadline {
            self.cold_start_readiness_claims
                .remove(&claim.binding_digest);
            return Err(CompositionError::ActivationStaleFence);
        }
        let lease: OnboardingLease = serde_json::from_str(&record.claim.lease_bytes)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let replayed =
            eliot_workscope::ScanDisclosureStore::readback(scan_store, scan_handle, scan_binding)
                .map_err(CompositionError::ScanDisclosure)?;
        if replayed.scan_ref != scan_handle.receipt_ref {
            return Err(CompositionError::ScanDisclosure(
                WorkScopeError::ScanReceiptReplaced,
            ));
        }
        let mut receipt = ColdStartController
            .compile(
                receipt_ref,
                &lease,
                principal_ref,
                session_ref,
                scope,
                instance,
                lineage,
                candidate,
                sources,
                state_fence,
                governance_profile_ref,
                limiting_integration_evidence,
                route_profile_ref,
                serializer_id,
                serializer_version,
                serializer_options_digest,
                tokenizer_id,
                tokenizer_version,
                tokenizer_hash,
                projection_source_ref,
                projection_generation,
                privacy,
                task,
                Some(scan_handle),
                now,
            )
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        receipt.receipt_revision = record.record_revision;
        receipt
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let receipt_bytes = canonical_json_bytes(&receipt)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let receipt_bytes = String::from_utf8(receipt_bytes)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let disposition = match receipt.readiness {
            ReadinessLifecycle::ReadyMaterial | ReadinessLifecycle::ReadyReadOnly => {
                ColdStartReadinessTerminalDisposition::Ready
            }
            ReadinessLifecycle::NeedsTask
                if matches!(receipt.task_binding, TaskBindingState::Ambiguous { .. }) =>
            {
                ColdStartReadinessTerminalDisposition::Ambiguous
            }
            _ => ColdStartReadinessTerminalDisposition::Failed,
        };
        let terminal_record = owner
            .publish_cold_start_readiness(
                &record.record_key,
                &claim.binding_digest,
                &record.claim.lease_ref,
                disposition,
                &receipt.receipt_ref,
                &receipt_bytes,
            )
            .map_err(|error| CompositionError::Recovery(error.to_string()))?
            .ok_or_else(|| {
                CompositionError::Recovery(
                    "durable cold-start terminal publication had no readback".to_owned(),
                )
            })?;
        terminal_record
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        self.cold_start_readiness_claims
            .remove(&claim.binding_digest);
        Self::readiness_join_from_record(&terminal_record, now, false)
    }

    /// Projects the retained terminal cold-start surface for one exact lease
    /// key (issue #1790, readiness-surface production caller).
    ///
    /// Reads and validates the terminal receipt the retained single-flight
    /// registry published for the exact workspace filesystem/VCS identity,
    /// privacy boundary and governing-source generation. The returned
    /// [`ColdStartSurfaceView`] copies its principal/session, scope, task or
    /// selection state, fence, profile/source references and generations,
    /// readiness, source-status evidence and recovery prompts directly from
    /// that receipt (plus the exact lease deadline). A key with no published
    /// terminal fails closed instead of projecting an uncompiled disposition.
    /// Live status: owning thin entry for the bridge delivery path; the live
    /// bridge note path consumes no governor surface yet (BLOCKED-BY
    /// bridge-transport: `bins/eliot-agent-bridge` `BootstrapContext`
    /// intake).
    pub fn cold_start_surface_for_lease(
        &self,
        lineage_candidate_ref: &str,
        workspace_instance_candidate_ref: &str,
        privacy_class: PrivacyClass,
        governing_source_generation: u64,
    ) -> Result<ColdStartSurfaceView, CompositionError> {
        self.cold_start_owner_readback_for_lease(
            lineage_candidate_ref,
            workspace_instance_candidate_ref,
            privacy_class,
            governing_source_generation,
        )
        .map(|(_, surface)| surface)
    }

    /// Projects the exact durable cold-start terminal named by a full owner
    /// claim. Reads revalidate the stored lease, terminal revision, current
    /// `StateFence`, and freshly matched `WorkScope` before returning a surface.
    ///
    /// Live status: no production caller. Whether a full owner claim reaches
    /// this projection or the entry is retired is an owner decision.
    pub fn cold_start_surface_for_claim(
        &self,
        claim: &ColdStartReadinessClaim,
        now: u64,
    ) -> Result<ColdStartSurfaceView, CompositionError> {
        self.cold_start_owner_readback_for_claim(claim, now)
            .map(|(_, surface)| surface)
    }

    /// Reads the exact retained terminal lease and surface from ORS after
    /// restart. A partial identity cannot name the full binding digest, and
    /// the process-local claim map is never a fallback.
    pub fn cold_start_owner_readback_for_claim(
        &self,
        claim: &ColdStartReadinessClaim,
        now: u64,
    ) -> Result<(OnboardingLease, ColdStartSurfaceView), CompositionError> {
        let (lease, receipt) = self.cold_start_readiness_terminal_for_claim(claim, now)?;
        let surface = Self::cold_start_surface_view(&lease, &receipt)?;
        Ok((lease, surface))
    }

    fn cold_start_readiness_terminal_for_claim(
        &self,
        claim: &ColdStartReadinessClaim,
        now: u64,
    ) -> Result<(OnboardingLease, eliot_workscope::OnboardingReadinessReceipt), CompositionError>
    {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        claim
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let contour = self.cold_start_readiness_contour.as_ref().ok_or_else(|| {
            CompositionError::Recovery(
                "cold-start readiness owner has no admitted installation contour".to_owned(),
            )
        })?;
        if claim.key.installation_id != contour.installation_id() {
            return Err(CompositionError::ActivationStaleFence);
        }
        let live_fence = self.snapshot.state_fence();
        if !fences_match_exact(&claim.key.state_fence, &live_fence) {
            return Err(CompositionError::ActivationStaleFence);
        }
        let owner = self.cold_start_readiness_owner.as_ref().ok_or_else(|| {
            CompositionError::Recovery("cold-start readiness ORS owner is not bound".to_owned())
        })?;
        let record = owner
            .load_cold_start_readiness_for_binding(&claim.binding_digest)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?
            .ok_or_else(|| {
                CompositionError::Recovery(
                    "no durable cold-start lease for the complete readiness key".to_owned(),
                )
            })?;
        record
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if record.claim.key != claim.key
            || record.claim.binding_digest != claim.binding_digest
            || now > record.claim.lease_deadline
        {
            return Err(CompositionError::ActivationStaleFence);
        }
        let terminal = record.terminal.as_ref().ok_or_else(|| {
            CompositionError::Recovery(
                "durable cold-start lease has no terminal readiness receipt".to_owned(),
            )
        })?;
        let lease: OnboardingLease = serde_json::from_str(&record.claim.lease_bytes)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let receipt: eliot_workscope::OnboardingReadinessReceipt =
            serde_json::from_str(&terminal.receipt_bytes)
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        lease
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        receipt
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if lease.lease_ref != record.claim.lease_ref
            || lease.deadline != record.claim.lease_deadline
            || lease.lineage_candidate_ref != claim.key.lineage_candidate_ref
            || lease.workspace_instance_candidate_ref != claim.key.workspace_instance_candidate_ref
            || lease.privacy_class != claim.key.privacy_class
            || lease.governing_source_generation != claim.key.governing_source_generation
            || receipt.lease_ref != lease.lease_ref
            || receipt.governing_source_generation != lease.governing_source_generation
            || receipt.expiry_tick != lease.deadline
            || receipt.expiry_tick < now
            || !fences_match_exact(&receipt.state_fence, &live_fence)
        {
            return Err(CompositionError::ActivationStaleFence);
        }
        if let Some(owner) = self.owners.work_scope.as_ref() {
            let scope = owner
                .read_current(&live_fence)
                .map_err(map_activation_scope_error)?;
            ensure_snapshot_fresh(
                &scope,
                "cold-start surface WorkScope is not freshly matched",
            )?;
            if receipt.scope != scope.binding.scope
                || receipt.instance.instance_ref != scope.binding.scope.instance_ref
                || receipt.instance.root_identity != scope.binding.scope.root_identity
                || receipt.instance.generation != scope.binding.scope.generation
                || receipt.governing_source_generation != scope.binding.governing_source_generation
            {
                return Err(CompositionError::ActivationStaleFence);
            }
        } else if receipt.readiness == ReadinessLifecycle::ReadyMaterial {
            return Err(CompositionError::ActivationScopeSelectionRequired);
        }
        Ok((lease, receipt))
    }

    fn cold_start_surface_view(
        lease: &OnboardingLease,
        receipt: &eliot_workscope::OnboardingReadinessReceipt,
    ) -> Result<ColdStartSurfaceView, CompositionError> {
        let surface = receipt
            .surface(lease)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        Ok(ColdStartSurfaceView {
            receipt_ref: surface.receipt_ref,
            lease_ref: receipt.lease_ref.clone(),
            principal_ref: receipt.principal_ref.clone(),
            session_ref: receipt.session_ref.clone(),
            scope: receipt.scope.clone(),
            scope_descriptor_revision: receipt.scope_descriptor_revision,
            instance: receipt.instance.clone(),
            lineage: receipt.lineage.clone(),
            scope_resolution: receipt.scope_resolution,
            task_binding: receipt.task_binding.clone(),
            state_fence: receipt.state_fence.clone(),
            governing_source_set_ref: receipt.governing_source_set_ref.clone(),
            governing_source_generation: receipt.governing_source_generation,
            governance_profile_ref: receipt.governance_profile_ref.clone(),
            limiting_integration_evidence: receipt.limiting_integration_evidence.clone(),
            route_profile_ref: receipt.route_profile_ref.clone(),
            serializer_id: receipt.serializer_id.clone(),
            serializer_version: receipt.serializer_version.clone(),
            serializer_options_digest: receipt.serializer_options_digest.clone(),
            tokenizer_id: receipt.tokenizer_id.clone(),
            tokenizer_version: receipt.tokenizer_version.clone(),
            tokenizer_hash: receipt.tokenizer_hash.clone(),
            readiness: cold_start_readiness_token(surface.readiness).to_owned(),
            smallest_missing_question: surface.smallest_missing_question,
            lease_deadline: surface.lease_deadline,
            receipt_revision: receipt.receipt_revision,
            proof_readiness: receipt.proof_readiness,
            missing_inputs: receipt.missing_inputs.clone(),
            next_safe_action: receipt.next_safe_action.clone(),
            discovered_source_refs: receipt.discovered_source_refs.clone(),
            admitted_source_refs: receipt.admitted_source_refs.clone(),
            conflicting_source_refs: receipt.conflicting_source_refs.clone(),
            unavailable_source_refs: receipt.unavailable_source_refs.clone(),
            scan_receipt_ref: receipt.scan_receipt_ref.clone(),
            workspace_instance_ref: receipt.instance.instance_ref.clone(),
            projection_source_ref: receipt.projection_source_ref.clone(),
            projection_generation: receipt.projection_generation,
        })
    }

    /// Compatibility entry for callers holding only a partial lease identity.
    /// Such fields cannot reproduce the ORS binding digest, so this method
    /// deliberately fails closed. Use [`Self::cold_start_owner_readback_for_claim`].
    pub fn cold_start_owner_readback_for_lease(
        &self,
        _lineage_candidate_ref: &str,
        _workspace_instance_candidate_ref: &str,
        _privacy_class: PrivacyClass,
        _governing_source_generation: u64,
    ) -> Result<(eliot_workscope::OnboardingLease, ColdStartSurfaceView), CompositionError> {
        Err(CompositionError::Recovery(
            "partial cold-start identity cannot authorize durable readback; supply the full readiness claim"
                .to_owned(),
        ))
    }

    /// Applies one Canonical-admitted transition through the sole retained
    /// Kernel port under the exact admitted request identity. Callers cannot
    /// provide a second client or bypass Canonical admission with an
    /// arbitrary transition. The identity comes from admitted ingress;
    /// `prepare()` alone is not an authorization.
    pub async fn commit_canonical(
        &self,
        identity: &RequestIdentity,
        envelope: CanonicalWriteEnvelope,
    ) -> Result<WriteReceipt, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        // Issue #1787: a task-bound canonical write is scope-sensitive work and
        // requires the retained binding to be freshly `MATCHED` at the request
        // fence. The retained guard receipt must agree with the binding on
        // every identity field and the write must address the bound scope; any
        // drift fails the write before any canonical commit, without selecting
        // another candidate or transferring task state or project memory.
        // Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
        if envelope.task_id.is_some() {
            let scope = require_fresh_matched_binding(
                self.owners.work_scope.as_ref(),
                &envelope.request.state_fence,
                "canonical write work scope is not freshly matched",
            )?;
            if scope.binding.scope.scope_ref != envelope.scope_id.as_str() {
                return Err(CompositionError::Recovery(
                    "canonical write addresses a different WorkScope than the bound scope"
                        .to_owned(),
                ));
            }
        }
        self.owners
            .canonical
            .commit(self.kernel.as_ref(), identity, envelope)
            .await
    }

    /// Applies one canonical transition only after the governed negative-memory
    /// gate admits the exact request (issue #1731 W4, I12.19).
    ///
    /// This is the mechanical gate application I1.8 names for the semantic
    /// layer: the Governor — the owner allowed to interpret policy — evaluates
    /// the bounded pure matcher over the caller-resolved rule snapshot, and a
    /// refusing decision fails the write **before** any `PreparedTransition` is
    /// built or handed to Kernel. Nothing here is interpreted downstream: Kernel
    /// still performs only its own mechanical authority/fence/order checks
    /// (`crates/kernel/AGENTS.md`), and the store still persists only an already
    /// prepared transition.
    ///
    /// The gate is evaluated through [`evaluate_negative_memory_gate`], which is
    /// total and pure. Its rule input (`gate.resolved`) is a
    /// [`ResolvedNegativeMemoryRuleSet`](crate::negative_memory_read::ResolvedNegativeMemoryRuleSet),
    /// whose fields are private and are filled only by the bounded named-read
    /// resolver: this method re-reads nothing and invents no rule, but it also
    /// **cannot** skip the gate, because the gate input is a required parameter
    /// rather than an option. A caller that has not resolved an owner-observed
    /// rule set therefore cannot reach this method at all, and one that resolved
    /// an incomplete or revision-moved set is refused rather than allowed
    /// through.
    ///
    /// Before the gate runs, [`bind_gate_to_request`] measures the gate input
    /// against **this envelope**: the gate's request State Fence must be the
    /// envelope's own request State Fence, the store-observed read fence must
    /// equal it, and the read must have been addressed to the envelope's own
    /// scope. Those are content comparisons against the operation being
    /// admitted, so a rule set resolved for a different generation or a
    /// different scope cannot be presented as this request's snapshot.
    ///
    /// A `Proceed` decision — including a near-match warning — lets the ordinary
    /// authorization path run unchanged; the warning confers nothing and is
    /// available to the caller through the returned decision. A `Block`,
    /// `RequireCheck` or `Unavailable` decision becomes a typed
    /// [`CompositionError::Recovery`] carrying the exact rule revision, admitted
    /// policy identity or required discriminating check, so the refusal is never
    /// reduced to an opaque failure.
    pub async fn commit_canonical_gated_by_negative_memory(
        &self,
        identity: &RequestIdentity,
        envelope: CanonicalWriteEnvelope,
        gate: &NegativeMemoryGateInput<'_>,
    ) -> Result<NegativeMemoryGatedCommit, CompositionError> {
        bind_gate_to_request(gate, &envelope)?;
        let decision = evaluate_negative_memory_gate(gate);
        if let Some(refusal) = negative_memory_gate::refusal_as_composition_error(&decision) {
            return Err(refusal);
        }
        let receipt = self.commit_canonical(identity, envelope).await?;
        Ok(NegativeMemoryGatedCommit { receipt, decision })
    }

    /// Commits a canonical write after running the discriminating check a
    /// [`NegativeMemoryGateDecision::RequireCheck`] demands.
    ///
    /// A `RequireCheck` is a DEMAND rather than a verdict, so this entry runs
    /// the demanded check itself rather than leaving it unrun: the gate is
    /// evaluated once to learn which check the matched rule declares, the
    /// proposal is built only from that decision and this envelope's own
    /// owner-observed rule set, the probe is executed through the
    /// caller-supplied read-only executor, and the gate is evaluated a SECOND
    /// time with the resulting admission. The second evaluation is the same
    /// pure function with one more input, so the probe result cannot grant
    /// anything the first evaluation would have refused for any other reason.
    ///
    /// A probe that fails to execute, that is served at another fence, or whose
    /// verifier is not the record's own leaves the second decision a
    /// `RequireCheck` refusal. There is no path here where an unexecuted check
    /// becomes a pass, and the write is refused in that case exactly as the
    /// plain gated commit refuses it.
    ///
    /// # Live status
    ///
    /// This entry currently has NO production caller; the function body is
    /// reachable only by naming it. A source implementation is not evidence of
    /// a live edge, so the earlier claim that this was "the production caller
    /// for the read-only probe executor" was false and has been removed.
    ///
    /// The probe executor IS live, through a different arrangement:
    /// `commit_gated_action` in the `eliotd` negative-memory action gate
    /// (`bins/eliotd/src/negative_memory_action_gate.rs`) runs the same
    /// two-phase sequence inline — it admits the proposal with
    /// `admit_negative_memory_probe`, executes it over the retained
    /// `store_named_async` read-only route through a
    /// `NamedReadProbeExecutor`, and then commits through
    /// [`Self::commit_canonical_gated_by_negative_memory`] rather than through
    /// this entry. The demanded check therefore does run on the live path; this
    /// governor entry is the unwired duplicate of that sequence, and the two
    /// can be reconciled only by making one of them the arrangement the daemon
    /// uses.
    ///
    /// Whether this entry is wired to that dispatch or retired is an owner
    /// decision, not a documentation one. It is retained here unchanged because
    /// removing a `pub` entry from the governor surface is an API decision for
    /// the governor owner (#18/#19), not a documentation fix.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] when the gate refuses after the probe, when
    /// the probe cannot be proposed for the returned decision, or when the
    /// underlying canonical commit fails. A probe refusal is reported as the
    /// gate's own typed refusal rather than flattened, so the caller learns
    /// that the action was held for an unexecuted check.
    pub async fn commit_canonical_gated_by_executed_check(
        &self,
        identity: &RequestIdentity,
        envelope: CanonicalWriteEnvelope,
        gate: &NegativeMemoryGateInput<'_>,
        probe: &dyn NegativeMemoryProbeExecutor,
    ) -> Result<NegativeMemoryGatedCommit, CompositionError> {
        bind_gate_to_request(gate, &envelope)?;
        let first = evaluate_negative_memory_gate(gate);
        let admission = if matches!(first, NegativeMemoryGateDecision::RequireCheck { .. }) {
            let proposal = admit_negative_memory_probe(&first, gate.resolved)
                .map_err(|refusal| CompositionError::Recovery(format!("{refusal}")))?;
            Some(
                execute_negative_memory_probe(&proposal, probe)
                    .await
                    .map_err(|refusal| CompositionError::Recovery(format!("{refusal}")))?,
            )
        } else {
            None
        };
        let resolved_input = NegativeMemoryGateInput {
            probe_admission: admission.as_ref(),
            ..gate.clone()
        };
        let decision = evaluate_negative_memory_gate(&resolved_input);
        if let Some(refusal) = negative_memory_gate::refusal_as_composition_error(&decision) {
            return Err(refusal);
        }
        let receipt = self.commit_canonical(identity, envelope).await?;
        Ok(NegativeMemoryGatedCommit { receipt, decision })
    }

    /// Admits one scope-sensitive effect under material readiness
    /// (issue #1789, readiness-gate production caller).
    ///
    /// Evaluates [`evaluate_material_request`] for `effect` over the presented
    /// readiness facts. The effect class matters: only
    /// [`RequestedEffect::CanonicalWrite`] and
    /// [`RequestedEffect::MaterialEffect`] need `READY_MATERIAL`
    /// ([`RequestedEffect::requires_material_readiness`]); the read-only
    /// orientation family is admitted in any orientable lifecycle once
    /// currency holds, so the exploratory-versus-mutation distinction is
    /// evaluated per effect, never hardcoded. Currency is judged against the
    /// retained Kernel fence, never a caller-presented fence: the evaluated
    /// inputs carry the presented receipt, descriptor, coverage, guard
    /// receipt, lease, and tick with the live fence substituted, so a stale
    /// receipt fails even when it agrees with its own fence (re-evaluation
    /// on fence change is owned here, not delegated to the presenter).
    ///
    /// For admitted [`RequestedEffect::CanonicalWrite`] and
    /// [`RequestedEffect::MaterialEffect`], this also requires the caller's
    /// actual observed binding and a full governing-source closure check at
    /// their respective mandatory guard triggers against the current owner
    /// snapshot at the retained Kernel fence. The observation is never derived
    /// from the receipt or retained binding. Other effects may pass `None` for
    /// either scope input, preserving safe read-only and cold-capture behavior.
    /// The presented receipt must name exactly the live `WorkScope` binding
    /// read at that fence. A readiness denial preserves its typed directive; a
    /// scope-guard failure preserves the structured guard report and retains
    /// conflicting identity evidence in the bounded process-local diagnostic
    /// projection (fail-closed retention; never durable, never an authority
    /// for rebind).
    pub fn check_material_readiness_for_effect(
        &mut self,
        effect: RequestedEffect,
        readiness: &MaterialReadinessInputs<'_>,
        observed: Option<&ScopeBinding>,
        source_closure: Option<(&GoverningSourceSet, &PrivacyProfile)>,
    ) -> Result<MaterialAdmission, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let live_fence = self.kernel_snapshot().state_fence().clone();
        let effective = MaterialReadinessInputs {
            fence: &live_fence,
            ..*readiness
        };
        let admission = evaluate_material_request(&effective, effect).map_err(|error| {
            CompositionError::Recovery(format!("material readiness inputs are malformed: {error}"))
        })?;
        if matches!(admission, MaterialAdmission::Admitted { .. }) {
            let owner = self.owners.work_scope.as_ref().ok_or_else(|| {
                CompositionError::Recovery(
                    "WorkScope binding is unbound; material readiness cannot bind an authenticated instance"
                        .to_owned(),
                )
            })?;
            let snapshot = owner
                .read_current(&live_fence)
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
            if snapshot.binding.scope != readiness.receipt.scope {
                return Err(CompositionError::Recovery(format!(
                    "material readiness receipt addresses scope {} while WorkScope is bound to {}",
                    readiness.receipt.scope.scope_ref, snapshot.binding.scope.scope_ref,
                )));
            }
            let trigger = match effect {
                RequestedEffect::CanonicalWrite => Some(GuardTrigger::CanonicalWrite),
                RequestedEffect::MaterialEffect => Some(GuardTrigger::MaterialEffect),
                _ => None,
            };
            if let Some(trigger) = trigger {
                let missing_observed_binding = observed.is_none();
                let missing_source_closure = source_closure.is_none();
                let (Some(observed), Some((sources, privacy))) = (observed, source_closure) else {
                    return Err(CompositionError::ScopeSensitiveGuardInputsMissing {
                        trigger,
                        missing_observed_binding,
                        missing_source_closure,
                    });
                };
                observed
                    .validate()
                    .map_err(|error| CompositionError::Recovery(error.to_string()))?;
                ensure_snapshot_fresh(&snapshot, "scope-sensitive WorkScope is not fresh")?;
                let report = check_at_trigger(
                    &snapshot.binding,
                    observed,
                    Some((sources, privacy)),
                    trigger,
                );
                if !report.is_matched() {
                    if report.identity != IdentityLegOutcome::IdentityClear {
                        self.push_scope_quarantine_record(
                            &snapshot.binding,
                            observed,
                            &report,
                            live_fence.resource_generation.value(),
                        )?;
                    }
                    return Err(CompositionError::ScopeGuardWithheld {
                        claimed_scope: readiness.receipt.scope.scope_ref.clone(),
                        observed_scope: observed.scope.scope_ref.clone(),
                        trigger: report.trigger,
                        identity: report.identity,
                        verdict: report.verdict,
                        report: Box::new(report),
                    });
                }
            }
        }
        Ok(admission)
    }

    /// Admits one scope-sensitive canonical write under material readiness
    /// (issue #1789, readiness-gate production caller).
    ///
    /// Evaluates [`Self::check_material_readiness_for_effect`] for
    /// [`RequestedEffect::CanonicalWrite`] over the presented readiness
    /// facts. Currency is judged against the retained Kernel fence, never a
    /// caller-presented fence: the evaluated inputs carry the presented
    /// receipt, descriptor, coverage, guard receipt, lease, and tick with
    /// the live fence substituted, so a stale receipt fails even when it
    /// agrees with its own fence (re-evaluation on fence change is owned
    /// here, not delegated to the presenter).
    ///
    /// An admission is then bound to the retained authenticated instance:
    /// the presented receipt must name exactly the live `WorkScope` binding
    /// read at the retained fence. Without a retained binding there is no
    /// authenticated instance to bind, so the write fails closed. A malformed
    /// bundle fails as [`CompositionError::Recovery`]. A typed denial is
    /// returned as [`CompositionError::MaterialReadinessDenied`] with its
    /// receipt, requested effect, directive, and exact missing inputs; nothing
    /// is committed on any failure. A scope-guard mismatch retains the
    /// conflicting evidence in the bounded process-local diagnostic
    /// projection before withholding.
    pub fn check_material_readiness_for_write(
        &mut self,
        readiness: &MaterialReadinessInputs<'_>,
        observed: &ScopeBinding,
        sources: &GoverningSourceSet,
        privacy: &PrivacyProfile,
    ) -> Result<MaterialAdmission, CompositionError> {
        self.check_material_readiness_for_effect(
            RequestedEffect::CanonicalWrite,
            readiness,
            Some(observed),
            Some((sources, privacy)),
        )
    }

    /// Applies one Canonical-admitted transition only after material
    /// readiness admits the write (issue #1789, canonical-write production
    /// path).
    ///
    /// Runs [`Self::check_material_readiness_for_write`] and commits through
    /// the existing [`Self::commit_canonical`] path only when the admission
    /// is `Admitted`. A typed denial (`TASK_SELECTION_REQUIRED`,
    /// `AMBIGUOUS_RESULT`, `GOVERNING_CONTEXT_REQUIRED`,
    /// `READINESS_REEVALUATION_REQUIRED`) fails the write before any
    /// canonical commit: nothing is launched on a denial. The daemon
    /// canonical-write edge calls this method instead of `commit_canonical`
    /// directly; safe-capture experience commits keep using `commit_canonical`
    /// because the contract permits safe capture before `READY_MATERIAL`.
    /// A scope-guard mismatch retains the conflicting evidence in the
    /// bounded process-local diagnostic projection before withholding.
    pub async fn commit_canonical_with_readiness(
        &mut self,
        identity: &RequestIdentity,
        envelope: CanonicalWriteEnvelope,
        readiness: &MaterialReadinessInputs<'_>,
        observed: &ScopeBinding,
        sources: &GoverningSourceSet,
        privacy: &PrivacyProfile,
    ) -> Result<WriteReceipt, CompositionError> {
        match self.check_material_readiness_for_write(readiness, observed, sources, privacy)? {
            MaterialAdmission::Admitted { .. } => self.commit_canonical(identity, envelope).await,
            MaterialAdmission::Denied {
                receipt_ref,
                effect,
                directive,
                missing_inputs,
            } => Err(CompositionError::MaterialReadinessDenied {
                receipt_ref,
                effect,
                directive,
                missing_inputs,
            }),
        }
    }

    /// Checks the task, session, and `WorkScope` owners backing a native
    /// worker executable binding: `task_revision` must equal the task owner
    /// revision at the retained fence, `session_id` must name a session at
    /// that fence on the retained authority with `route_ref` equal to its
    /// admitted `model_route`, and the bound `WorkScope` must equal
    /// `work_scope_id` with a freshly `MATCHED` guard receipt (Issue #1787:
    /// a stale or drifted guard receipt cannot back a native executable
    /// binding; rebind or revalidate first). Any drift fails closed as
    /// `Recovery` without selecting another candidate or transferring task
    /// state or project memory.
    fn check_native_binding_identity(
        &self,
        fence: &StateFence,
        task_id: &str,
        task_revision: u64,
        session_id: &str,
        route_ref: &str,
        work_scope_id: &str,
    ) -> Result<(), CompositionError> {
        let task_key = TaskId::new(task_id.to_owned())
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let task = self.owners.task.task(&task_key).ok_or_else(|| {
            CompositionError::Recovery("native binding task has no owner record".to_owned())
        })?;
        if task.revision != task_revision || task.state_fence != *fence {
            return Err(CompositionError::Recovery(
                "native binding task revision is stale or foreign".to_owned(),
            ));
        }
        let session_key = SessionId::new(session_id.to_owned())
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let session = self.owners.session.session(&session_key).ok_or_else(|| {
            CompositionError::Recovery("native binding session has no owner record".to_owned())
        })?;
        if session.state_fence != *fence
            || session.authority_epoch != fence.authority_epoch
            || session.model_route != route_ref
        {
            return Err(CompositionError::Recovery(
                "native binding session/route is stale or foreign".to_owned(),
            ));
        }
        let scope = require_fresh_matched_binding(
            self.owners.work_scope.as_ref(),
            fence,
            "native binding work scope is not freshly matched",
        )?;
        if scope.binding.scope.scope_ref != work_scope_id {
            return Err(CompositionError::Recovery(
                "native binding work scope does not match the bound WorkScope".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_native_binding_facet_and_catalog(
        &self,
        facet_manifest_ref: &str,
        module_catalog_revision: u64,
    ) -> Result<String, CompositionError> {
        let canonical_facet_ref = native_worker_binding::canonical_native_worker_facet_ref()
            .map_err(CompositionError::Recovery)?;
        if facet_manifest_ref != canonical_facet_ref {
            return Err(CompositionError::Recovery(
                "native binding facet manifest ref does not match the canonical ELIOT native-worker facet ref"
                    .to_owned(),
            ));
        }
        // A catalog change requires new admission; a stale caller cannot
        // refresh this binding against its own revision.
        if module_catalog_revision != self.owners.module_registry.revision() {
            return Err(CompositionError::Recovery(
                "native binding catalog revision is not the live Module Catalog revision"
                    .to_owned(),
            ));
        }
        Ok(canonical_facet_ref)
    }

    /// Publishes one versioned Governor-owned executable binding projection
    /// (T9-01 M1, `T9.md` 3.2) for a registered native-worker attempt.
    ///
    /// The binding is a pure projection over admitted owner records at the
    /// retained fence: `state_fence`, `authority_epoch`, and `generation` are
    /// taken from the retained Kernel snapshot, never from the caller. The
    /// caller-supplied `plan_id` / `plan_revision` / `task_id` /
    /// `work_scope_id` must equal the current canonical plan at that fence,
    /// `task_revision` must equal the task owner revision, `session_id` must
    /// name a session at the fence with `route_ref` equal to its admitted
    /// `model_route`, `work_scope_id` must equal the bound `WorkScope` scope,
    /// and `config_snapshot_digest` must equal the retained protected snapshot
    /// digest. Any mismatch fails closed as `Recovery` (stale), never repaired
    /// locally. T9-02 enforces the remaining currentness (route/adapter/
    /// config/facet/grant/epoch change makes stale) at the Kernel before
    /// resume; this method binds to the current fence/epoch and refuses a
    /// stale fence.
    ///
    /// This method performs no transport: the caller commits a sibling
    /// `PreparedTransition` through the existing `commit_canonical` path and
    /// correlates by `operation_id` / `canonical_request_hash` / `state_fence`.
    /// The admitted capability cell, Module Catalog revision and
    /// `NativeWorkerLifecycleBinding` are required caller-supplied owner
    /// inputs; this method does not infer or refresh those values.
    /// The supplied revision must equal the live `module_registry` revision at
    /// publish: a binding is compiled against the current catalog, never a
    /// stale one (Implements #22 W1). A catalog change makes the binding
    /// stale; it needs a new admission, never a local repair.
    /// All parameters are required; blank or malformed input fails closed.
    /// `facet_manifest_ref` must match the canonical ELIOT-owned native-worker
    /// facet contract exactly; Governor does not accept a caller-invented ref.
    #[allow(
        clippy::too_many_arguments,
        reason = "M1 binding joins every T9.md 3.2 denominator field in one versioned projection"
    )]
    pub fn publish_native_worker_binding(
        &self,
        claim_id: &str,
        registration_id: &str,
        installation_id: &str,
        task_id: &str,
        work_unit_id: &str,
        work_scope_id: &str,
        attempt: u32,
        lease_id: &str,
        operation_id: &str,
        canonical_request_hash: &str,
        principal_id: &str,
        session_id: &str,
        worker_generation: u64,
        process_tree_id: &str,
        process_generation: u64,
        process_fence: &str,
        route_ref: &str,
        adapter_id: &str,
        adapter_revision: u64,
        artifact_digest: &str,
        config_digest: &str,
        protocol_digest: &str,
        command_ref: &str,
        facet_manifest_ref: &str,
        capability_cell: eliot_contracts::CapabilityCellId,
        introduction_refs: Vec<String>,
        supporting_grant_refs: Vec<String>,
        grant_graph_revision: u64,
        module_catalog_revision: u64,
        effective_ceiling: eliot_store_api::EffectClass,
        credential_refs: Vec<String>,
        resource_refs: Vec<String>,
        lifecycle_binding: NativeWorkerLifecycleBinding,
        replay_stream_id: &str,
        launch_nonce: &str,
        process_invocation_digest: &str,
        deadline_unix_ms: u64,
        expires_at_unix_ms: u64,
        plan_id: &str,
        plan_revision: &str,
        task_revision: u64,
        config_snapshot_digest: &str,
        admission_revision_ref: &str,
    ) -> Result<NativeWorkerExecutableBinding, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let canonical_facet_ref = self.validate_native_binding_facet_and_catalog(
            facet_manifest_ref,
            module_catalog_revision,
        )?;
        let fence = self.snapshot.state_fence();
        let authority_epoch = self.snapshot.authority_epoch.clone();
        let generation = self.snapshot.generation;
        if config_snapshot_digest != self.snapshot.protected_snapshot_digest
            || config_snapshot_digest != self.owners.config.snapshot_digest()
        {
            return Err(CompositionError::Recovery(
                "native binding config snapshot is not the retained protected snapshot".to_owned(),
            ));
        }
        let plan = self.owners.canonical.read_current_plan(&fence)?;
        if plan.plan_id != plan_id
            || plan.plan_revision != plan_revision
            || plan.task_id.as_str() != task_id
            || plan.work_scope_id != work_scope_id
        {
            return Err(CompositionError::Recovery(
                "native binding plan/task/scope does not match the current canonical plan"
                    .to_owned(),
            ));
        }
        self.check_native_binding_identity(
            &fence,
            task_id,
            task_revision,
            session_id,
            route_ref,
            work_scope_id,
        )?;
        let mut binding = NativeWorkerExecutableBinding {
            claim_id: claim_id.to_owned(),
            registration_id: registration_id.to_owned(),
            task_id: task_id.to_owned(),
            work_unit_id: work_unit_id.to_owned(),
            work_scope_id: work_scope_id.to_owned(),
            attempt,
            lease_id: lease_id.to_owned(),
            operation_id: operation_id.to_owned(),
            canonical_request_hash: canonical_request_hash.to_owned(),
            installation_id: installation_id.to_owned(),
            principal_id: principal_id.to_owned(),
            session_id: session_id.to_owned(),
            worker_generation,
            process_tree_id: process_tree_id.to_owned(),
            job_object_lineage_ref: lifecycle_binding.job_object_lineage_ref,
            process_generation,
            process_fence: process_fence.to_owned(),
            route_ref: route_ref.to_owned(),
            adapter_id: adapter_id.to_owned(),
            adapter_revision,
            artifact_digest: artifact_digest.to_owned(),
            config_digest: config_digest.to_owned(),
            protocol_digest: protocol_digest.to_owned(),
            command_ref: command_ref.to_owned(),
            facet_manifest_ref: canonical_facet_ref,
            capability_cell,
            introduction_refs,
            supporting_grant_refs,
            grant_graph_revision,
            module_catalog_revision,
            capability_cell_registry_digest: lifecycle_binding.capability_cell_registry_digest,
            kernel_execution_manifest_digest: lifecycle_binding.kernel_execution_manifest_digest,
            resource_limits_digest: lifecycle_binding.resource_limits_digest,
            cancellation_policy_ref: lifecycle_binding.cancellation_policy_ref,
            checkpoint_policy_digest: lifecycle_binding.checkpoint_policy_digest,
            drain_policy_ref: lifecycle_binding.drain_policy_ref,
            restart_policy_digest: lifecycle_binding.restart_policy_digest,
            effective_ceiling,
            credential_refs,
            resource_refs,
            replay_stream_id: replay_stream_id.to_owned(),
            launch_nonce: launch_nonce.to_owned(),
            process_invocation_digest: process_invocation_digest.to_owned(),
            state_fence: fence,
            authority_epoch: authority_epoch.clone(),
            generation,
            deadline_unix_ms,
            expires_at_unix_ms,
            plan_id: plan_id.to_owned(),
            plan_revision: plan_revision.to_owned(),
            task_revision,
            config_snapshot_digest: config_snapshot_digest.to_owned(),
            admission_revision_ref: admission_revision_ref.to_owned(),
            wire_id: NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_VERSION,
            binding_digest: String::new(),
        };
        let digest = binding
            .compute_digest()
            .map_err(CompositionError::Recovery)?;
        binding.binding_digest = digest;
        binding.validate().map_err(CompositionError::Recovery)?;
        Ok(binding)
    }

    /// Publishes one versioned Governor-owned executable binding projection
    /// (T9-01 M1) with the R1 production `process_invocation_digest` derived
    /// from the exact process invocation value.
    ///
    /// This is the production producer for the dispatch join: it
    /// canonicalizes the exact invocation JSON with the same
    /// `canonical_json_bytes` + `sha256_hex` the wire uses (via
    /// [`process_invocation_digest_for`]), so the published binding carries
    /// the real invocation digest, never a placeholder. Canonicalization
    /// failure fails closed as [`CompositionError::Recovery`]; no digest is
    /// synthesized. Every other field follows
    /// [`Self::publish_native_worker_binding`] exactly, including the
    /// sibling-`commit_canonical` correlation contract (`operation_id` /
    /// `canonical_request_hash` / `state_fence`).
    #[allow(
        clippy::too_many_arguments,
        reason = "R1 producer joins every T9.md 3.2 denominator field plus the exact invocation value in one versioned projection"
    )]
    pub fn publish_native_worker_binding_for_invocation(
        &self,
        claim_id: &str,
        registration_id: &str,
        installation_id: &str,
        task_id: &str,
        work_unit_id: &str,
        work_scope_id: &str,
        attempt: u32,
        lease_id: &str,
        operation_id: &str,
        canonical_request_hash: &str,
        principal_id: &str,
        session_id: &str,
        worker_generation: u64,
        process_tree_id: &str,
        process_generation: u64,
        process_fence: &str,
        route_ref: &str,
        adapter_id: &str,
        adapter_revision: u64,
        artifact_digest: &str,
        config_digest: &str,
        protocol_digest: &str,
        command_ref: &str,
        facet_manifest_ref: &str,
        capability_cell: eliot_contracts::CapabilityCellId,
        introduction_refs: Vec<String>,
        supporting_grant_refs: Vec<String>,
        grant_graph_revision: u64,
        module_catalog_revision: u64,
        effective_ceiling: eliot_store_api::EffectClass,
        credential_refs: Vec<String>,
        resource_refs: Vec<String>,
        lifecycle_binding: NativeWorkerLifecycleBinding,
        replay_stream_id: &str,
        launch_nonce: &str,
        process_invocation: &serde_json::Value,
        deadline_unix_ms: u64,
        expires_at_unix_ms: u64,
        plan_id: &str,
        plan_revision: &str,
        task_revision: u64,
        config_snapshot_digest: &str,
        admission_revision_ref: &str,
    ) -> Result<NativeWorkerExecutableBinding, CompositionError> {
        let derived = native_worker_binding::process_invocation_digest_for(process_invocation)
            .map_err(CompositionError::Recovery)?;
        self.publish_native_worker_binding(
            claim_id,
            registration_id,
            installation_id,
            task_id,
            work_unit_id,
            work_scope_id,
            attempt,
            lease_id,
            operation_id,
            canonical_request_hash,
            principal_id,
            session_id,
            worker_generation,
            process_tree_id,
            process_generation,
            process_fence,
            route_ref,
            adapter_id,
            adapter_revision,
            artifact_digest,
            config_digest,
            protocol_digest,
            command_ref,
            facet_manifest_ref,
            capability_cell,
            introduction_refs,
            supporting_grant_refs,
            grant_graph_revision,
            module_catalog_revision,
            effective_ceiling,
            credential_refs,
            resource_refs,
            lifecycle_binding,
            replay_stream_id,
            launch_nonce,
            &derived,
            deadline_unix_ms,
            expires_at_unix_ms,
            plan_id,
            plan_revision,
            task_revision,
            config_snapshot_digest,
            admission_revision_ref,
        )
    }

    /// Re-reads Kernel-owned owner projections and publishes a coherent live
    /// update without a daemon restart.
    ///
    /// This closes the `commit_canonical` publication gap: owner state
    /// committed through the canonical path becomes visible to Governor
    /// readers after one successful refresh instead of only after a restart.
    ///
    /// Fail-closed behavior:
    /// - The retained generation/epoch/identity is re-admitted through
    ///   `KernelGenerationExpectation::admits`; any change is
    ///   `CompositionError::Recovery` telling the daemon to drop this
    ///   composition and re-run authenticated connect+start. A new generation
    ///   is never inferred locally.
    /// - Owner reads re-run the exact authenticated `recover_from_kernel`
    ///   path under the retained fence and protected-snapshot digest,
    ///   including the all-empty genesis branch. Partial state is an error;
    ///   no default is manufactured.
    /// - A post-read canonical scope must agree with the recovered heads on
    ///   scope identity, fence, and every revision/ordering head; mid-read
    ///   revision churn blocks publication.
    /// - Service observations are re-validated and owners are rebuilt through
    ///   `GovernorOwners::from_recovery`. Only a fully coherent result swaps
    ///   `owners`, `recovery`, and `service_observations`. On any failure the
    ///   previous projection and receipts are kept untouched; callers observe
    ///   `Err`, never a false success.
    /// - The orchestration lifecycle object is retained: re-validated
    ///   observations still satisfy the required-base admission proved at
    ///   construction under the same fence.
    /// - Operator command replay lives in Kernel ORS behind the receipt route
    ///   (see `operator_reconciliation`); the refresh swaps Governor owners
    ///   only and never resets that durable identity.
    pub fn refresh_from_kernel(&mut self) -> Result<(), CompositionError> {
        let observed = self.kernel.snapshot().clone();
        let expected =
            KernelGenerationExpectation::from_snapshot(&self.snapshot).map_err(|error| {
                CompositionError::Recovery(format!(
                    "retained Kernel snapshot is no longer well-formed: {error}"
                ))
            })?;
        expected.admits(&observed).map_err(|error| {
            CompositionError::Recovery(format!(
                "Kernel generation changed; drop this composition and re-run authenticated \
                 connect+start before publishing projections: {error}"
            ))
        })?;
        let state_fence = self.snapshot.state_fence();
        let protected_snapshot_digest = self.snapshot.protected_snapshot_digest.clone();
        let recovery = recover_from_kernel(
            self.kernel.as_ref(),
            &state_fence,
            &protected_snapshot_digest,
        )?;
        recovery.validate(&state_fence, &protected_snapshot_digest)?;
        let post_scope = self
            .kernel
            .canonical_scope(&state_fence, &protected_snapshot_digest)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        coherence_result(compare_scope_heads(
            &recovery.canonical_scope,
            &post_scope,
            &state_fence,
        ))?;
        let service_observations = self
            .kernel
            .services(&state_fence, &protected_snapshot_digest)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        validate_service_observations(&service_observations, &state_fence)?;
        let owners = GovernorOwners::from_recovery(
            self.kernel.clone(),
            &state_fence,
            protected_snapshot_digest.clone(),
            &recovery,
        )?;
        self.owners = owners;
        self.recovery = recovery;
        self.service_observations = service_observations;
        Ok(())
    }

    /// Returns whether a live P-07 authority port was retained. `None` means
    /// diagnosed degradation (reads/degraded status only); it never issues
    /// rights and every activation entry point fails closed with
    /// [`P07PortError::Unavailable`].
    #[must_use]
    pub fn authority_activation_available(&self) -> bool {
        self.authority_activation.is_some()
    }

    /// Dispatches one exact durable authority request through the retained
    /// production P-07 port. The daemon composition root owns construction of
    /// the request from its admitted canonical source; this method is the
    /// single application seam that gives all four authority operations a
    /// production caller without reimplementing receipt reconciliation.
    ///
    /// A grant revocation is the only arm with a canonical second phase, so it
    /// is the only arm that reads `canonical_operation_id`,
    /// `canonical_request_identity`, `operation`, `durable_link`, and
    /// `closure_source`: they are forwarded verbatim to
    /// [`Self::revoke_grant_and_reconcile`] in the order that method mandates
    /// — Kernel/ORS fences the exact graph revision first, then the durable
    /// closure read-back and the prepared authority-revocation transition,
    /// then the canonical envelope commit, then the ORS second-phase link. The
    /// other three arms never touch them.
    ///
    /// `operation` is the admitted revocation operation identity the bounded
    /// closure and the prepared canonical revocation transition are computed
    /// under. It is required and never defaulted: the durable closure receipt
    /// carries a fence, a membership and a digest but none of the identity's
    /// five coordinates, so preparing under a synthesized identity would make
    /// the authority graph's own recheck certify itself.
    ///
    /// The canonical operation identity and admitted request identity are
    /// composed by the caller from admitted ingress and are never derived
    /// from the durable closure, so an exact replay of one operation resolves
    /// to the same receipt while the same operation under a changed payload
    /// conflicts at the store instead of reconciling to a different closure.
    ///
    /// The grant-revocation arm runs through
    /// [`Self::apply_admitted_authority_revocation`], which admits the
    /// presented operation against the live composition generation before
    /// the saga starts. Live status: production seam for all four authority
    /// families; the daemon composition root's authority pass is its one
    /// production caller (BLOCKED-BY authority-transport: that pass does not
    /// yet build one of these requests from an admitted canonical source).
    pub async fn apply_authority_request<L, C>(
        &mut self,
        request: PresentedAuthorityRequest,
        canonical_operation_id: &OperationId,
        canonical_request_identity: &RequestIdentity,
        operation: &RevocationOperationIdentity,
        durable_link: &L,
        closure_source: &C,
    ) -> Result<AuthorityActionReceipt, CompositionError>
    where
        L: GrantClosureCanonicalLinkPort + ?Sized,
        C: GrantClosureReceiptPort + ?Sized,
    {
        match request {
            PresentedAuthorityRequest::GrantActivation(request) => self
                .activate_grant(&request)
                .map(AuthorityActionReceipt::Activation),
            PresentedAuthorityRequest::GrantRevocation(request) => self
                .apply_admitted_authority_revocation(
                    &request,
                    canonical_operation_id,
                    canonical_request_identity,
                    operation,
                    durable_link,
                    closure_source,
                )
                .await
                .map(|reconciliation| {
                    AuthorityActionReceipt::ReconciledGrantRevocation(Box::new(reconciliation))
                }),
            PresentedAuthorityRequest::IntroductionActivation(request) => self
                .activate_introduction(&request)
                .map(AuthorityActionReceipt::Activation),
            PresentedAuthorityRequest::IntroductionRevocation(request) => self
                .revoke_introduction(&request)
                .map(AuthorityActionReceipt::Revocation),
            PresentedAuthorityRequest::RootTransition(request) => self
                .activate_root_transition(&request)
                .map(|receipt| AuthorityActionReceipt::RootTransitionActivation(Box::new(receipt))),
        }
    }

    /// Applies one admitted grant revocation through the complete
    /// Kernel-first saga under the live composition generation (#686).
    ///
    /// This is the production ingress for the revocation half of
    /// [`Self::apply_authority_request`], and the only entry that reaches
    /// [`Self::revoke_grant_and_reconcile`] and through it
    /// [`Self::revoke_grant`], the `GrantGraph` closure revoke, and the
    /// `RetainedAuthorityRequest` unknown-outcome surface. It admits nothing
    /// itself: the daemon composition root still builds the
    /// [`GrantRevocationRequest`] and both canonical identities from its own
    /// admitted ingress, and both durable boundary ports are still the
    /// existing owners that hold the ORS first-phase row and the
    /// Kernel-issued receipt. No second graph, ledger, authority machine or
    /// Store client is introduced here.
    ///
    /// Fail-closed order, all of it ahead of any transport:
    /// - The composition must be `Ready` and must still retain a live P-07
    ///   port. A degraded composition issues no right and starts no saga.
    /// - The presented binding State Fence must equal the live composition
    ///   State Fence, and the admitted canonical request identity must carry
    ///   that same fence. An operation compiled against a superseded
    ///   generation refuses here instead of being presented to the current
    ///   Kernel owner and retained against a different owner snapshot
    ///   (A00-03: restoration of revoked influence after recovery is a hard
    ///   boundary; I6.15 keeps the Governor the owner of the semantic gating
    ///   around the receipts this port returns).
    /// - A retained presentation for the same grant must carry the exact
    ///   same bytes. Changed content under a retained operation identity
    ///   returns `IdentityConflict` and performs no transition (I5.27), so a
    ///   lost acknowledgement can never become a second, differently shaped
    ///   revocation, and a replay of the exact bytes still resolves to the
    ///   retained receipt rather than minting a new identity.
    /// - A pending stricter canonical revocation for the same grant must
    ///   name the same snapshot. Re-presenting that exact operation resumes
    ///   its unfinished second phase under the same canonical operation
    ///   identity; presenting different content under an already fenced
    ///   grant returns `IdentityConflict` instead of a fresh blind retry, and
    ///   the retained record is never cleared by a refusal.
    ///
    /// Everything past admission is the existing saga, unchanged: Kernel
    /// fences the exact graph revision first, the durable closure is read
    /// back and validated against this request's snapshot and fence, the
    /// authority graph's own origin-bound re-derivation is proven to bind
    /// that closure, the canonical envelope is compiled from that closure and
    /// committed, and the Store-issued receipt identity is linked to the
    /// immutable first-phase row and read back. The returned record is only
    /// ever the evidence those owners supplied.
    ///
    /// `operation` is the admitted revocation operation identity the bounded
    /// closure and the prepared canonical revocation transition are computed
    /// under, forwarded verbatim to [`Self::revoke_grant_and_reconcile`]. It
    /// is required, never defaulted.
    ///
    /// Live status: production ingress for the revocation half; the daemon
    /// composition root's polled authority pass is its one production caller
    /// (BLOCKED-BY authority-revocation-transport: that pass builds no
    /// revocation request and holds no `GrantClosureReceiptPort` /
    /// `GrantClosureCanonicalLinkPort` adapter yet).
    pub async fn apply_admitted_authority_revocation<L, C>(
        &mut self,
        request: &GrantRevocationRequest,
        canonical_operation_id: &OperationId,
        canonical_request_identity: &RequestIdentity,
        operation: &RevocationOperationIdentity,
        durable_link: &L,
        closure_source: &C,
    ) -> Result<AuthorityRevocationReconciliation, CompositionError>
    where
        L: GrantClosureCanonicalLinkPort + ?Sized,
        C: GrantClosureReceiptPort + ?Sized,
    {
        self.require_ready_for_authority()?;
        // Resolve the retained port here as well: a diagnosed degradation must
        // refuse before the saga starts, never half-way through it.
        self.authority_port()?;
        let live_fence = self.snapshot.state_fence();
        if request.binding.state_fence != live_fence {
            return Err(CompositionError::Recovery(
                "admitted grant revocation is not bound to the live composition State Fence"
                    .to_owned(),
            ));
        }
        if canonical_request_identity.request.metadata.state_fence != live_fence {
            return Err(CompositionError::Provider(
                "admitted canonical request identity is not bound to the live composition State Fence"
                    .to_owned(),
            ));
        }
        let presented = PresentedAuthorityRequest::GrantRevocation(request.clone());
        let ledger_key = presented.ledger_key();
        if let Some(retained) = self.authority_presentations.get(ledger_key.as_str())
            && retained.request() != &presented
        {
            return Err(CompositionError::Authority(P07PortError::IdentityConflict));
        }
        if let Some(pending) = self
            .pending_canonical_revocations
            .get(request.grant_id.as_str())
            && pending.snapshot_id != request.snapshot_id.as_str()
        {
            return Err(CompositionError::Authority(P07PortError::IdentityConflict));
        }
        self.revoke_grant_and_reconcile(
            request,
            canonical_operation_id,
            canonical_request_identity,
            operation,
            durable_link,
            closure_source,
        )
        .await
    }

    /// Presents one canonical grant activation to the retained P-07 port and
    /// records `PendingActivation -> Active` only after the exact
    /// Kernel-issued receipt validates `Active`.
    ///
    /// Fail-closed behavior:
    /// - Without a retained port, or when the composition is not ready, no
    ///   right is issued.
    /// - The recovered grant must still be `PendingActivation`; a restored
    ///   `Active`, an unknown grant, or a second activation on a recorded
    ///   identity fails closed instead of issuing twice.
    /// - An `UnknownOutcome` retains the exact request with its owner snapshot
    ///   until exact reconciliation; the grant stays pending, never active.
    /// - A receipt bound to another snapshot or epoch, or failing
    ///   `validate()`, leaves the retained state untouched.
    pub fn activate_grant(
        &mut self,
        request: &GrantActivationRequest,
    ) -> Result<AuthorityActivationReceipt, CompositionError> {
        self.require_ready_for_authority()?;
        let port = self.authority_port()?;
        let presented = PresentedAuthorityRequest::GrantActivation(request.clone());
        self.require_activatable_grant(&presented)?;
        let receipt = match port.activate_grant(request) {
            Ok(receipt) => receipt,
            Err(P07PortError::UnknownOutcome { snapshot_id }) => {
                self.note_unknown_outcome(presented, &snapshot_id)?;
                return Err(CompositionError::Authority(P07PortError::UnknownOutcome {
                    snapshot_id,
                }));
            }
            Err(error) => return Err(CompositionError::Authority(error)),
        };
        let retained = self.retain_presentation(presented)?;
        retained.note_activated(&receipt)?;
        Ok(receipt)
    }

    /// Presents one exact root-transition activation to the retained P-07 port
    /// and records `Pending -> Active` only after the exact transition receipt
    /// validates `Committed` against the retained request.
    ///
    /// Fail-closed behavior:
    /// - Without a retained port, or when the composition is not ready, no
    ///   crossing is presented.
    /// - An exact replay of an active identity is re-presented to the owner;
    ///   the complete returned receipt must equal the retained validated
    ///   receipt. The process-local receipt is never returned as a substitute
    ///   for owner readback.
    /// - Changed content under the retained transition identity returns
    ///   `IdentityConflict` before transport.
    /// - An `UnknownOutcome` retains the exact request with its owner snapshot
    ///   until exact reconciliation; the crossing stays unadmitted, never
    ///   active.
    /// - A receipt bound to another snapshot or epoch, a receipt that
    ///   disagrees with the retained bytes, or a non-committed disposition
    ///   leaves the retained state untouched.
    pub fn activate_root_transition(
        &mut self,
        request: &RootTransitionActivationRequest,
    ) -> Result<RootTransitionActivationReceipt, CompositionError> {
        self.require_ready_for_authority()?;
        let port = self.authority_port()?;
        let presented = PresentedAuthorityRequest::RootTransition(Box::new(request.clone()));
        let retained_receipt = self.require_admissible_transition(&presented)?;
        let receipt = match port.activate_root_transition(request) {
            Ok(receipt) => receipt,
            Err(P07PortError::UnknownOutcome { snapshot_id }) => {
                // A prior validated receipt remains historical evidence, but
                // a failed owner readback cannot be replaced by that local
                // copy. Keep the retained Active state unchanged and report
                // the owner's unresolved outcome.
                if retained_receipt.is_none() {
                    self.note_unknown_outcome(presented, &snapshot_id)?;
                } else if &snapshot_id != request.snapshot_id() {
                    return Err(CompositionError::Authority(P07PortError::InvalidBinding));
                }
                return Err(CompositionError::Authority(P07PortError::UnknownOutcome {
                    snapshot_id,
                }));
            }
            Err(error) => return Err(CompositionError::Authority(error)),
        };

        if let Some(retained_receipt) = retained_receipt {
            receipt.validate(request).map_err(|error| {
                CompositionError::Authority(map_transition_receipt_error(&error))
            })?;
            if receipt != retained_receipt {
                return Err(CompositionError::Authority(P07PortError::IdentityConflict));
            }
            return Ok(receipt);
        }

        let retained = self.retain_presentation(presented)?;
        retained.note_transition_activated(&receipt)?;
        Ok(receipt)
    }

    /// Revokes one grant through the retained P-07 port, Kernel first. The
    /// Kernel-issued revocation receipt is validated before the local
    /// projection is reconciled; when that reconciliation cannot complete, the
    /// retained revocation intent keeps effects blocked instead of reporting
    /// an active right.
    pub fn revoke_grant(
        &mut self,
        request: &GrantRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, CompositionError> {
        self.require_ready_for_authority()?;
        let port = self.authority_port()?;
        let presented = PresentedAuthorityRequest::GrantRevocation(request.clone());
        let receipt = match port.revoke_grant(request) {
            Ok(receipt) => receipt,
            Err(P07PortError::UnknownOutcome { snapshot_id }) => {
                self.note_unknown_outcome(presented, &snapshot_id)?;
                return Err(CompositionError::Authority(P07PortError::UnknownOutcome {
                    snapshot_id,
                }));
            }
            Err(error) => return Err(CompositionError::Authority(error)),
        };
        receipt
            .validate()
            .map_err(|_| CompositionError::Authority(P07PortError::InvalidBinding))?;
        if receipt.snapshot_id != request.snapshot_id.as_str()
            || !receipt
                .authority_epoch
                .is_same_authority(&request.binding.state_fence.authority_epoch)
        {
            return Err(CompositionError::Authority(P07PortError::InvalidBinding));
        }
        // Canonical-second reconciliation: absorb the validated Kernel receipt
        // into the local projection. The graph mutation runs before the ledger
        // files the receipt.
        let graph_reconciled = self
            .owners
            .authority
            .grants
            .revoke(&request.grant_id)
            .is_ok();
        if graph_reconciled {
            self.owners.authority.invalidate_owner_hydrations();
        }
        let retained = self.retain_presentation(presented)?;
        if !graph_reconciled {
            // Kernel already fenced this grant (the receipt above validated),
            // but the local projection cannot reconcile it — typically a grant
            // unknown to the recovered graph. The visible revocation intent is
            // strictly stronger than any right, so effects stay blocked.
            retained.note_revocation_intended();
            return Err(CompositionError::Recovery(
                "grant revocation reconciled at Kernel but not in the recovered graph; \
                 revocation intent retained and effects remain blocked"
                    .to_owned(),
            ));
        }
        if retained.note_revoked(&receipt).is_err() {
            retained.note_revocation_intended();
            return Err(CompositionError::Recovery(
                "grant revocation receipt could not be filed; \
                 revocation intent retained and effects remain blocked"
                    .to_owned(),
            ));
        }
        Ok(receipt)
    }

    /// Runs the complete grant-revocation saga in its required order.
    ///
    /// The retained P-07 port first requests the exact graph revision and
    /// durable descendant closure from Kernel/ORS. Only after that receipt is
    /// validated does Governor fence the declared closure in its own
    /// projection, prove that the authority graph's own origin-bound
    /// re-derivation binds that exact durable closure, compile the canonical
    /// declaration from the durable [`GrantClosureReceipt`] and commit it. The
    /// Store-issued canonical receipt identity is finally linked to the
    /// immutable ORS first-phase row.
    ///
    /// `operation` is the admitted revocation operation identity both the
    /// bounded closure and the prepared canonical revocation transition are
    /// computed under. It is required, never defaulted, and is forwarded
    /// verbatim to [`Self::reconcile_canonical_revocation`].
    ///
    /// Every failure after the Kernel first phase retains a
    /// [`PendingCanonicalRevocation`] before returning. The mechanical fence
    /// has already taken effect at that point, so the retained record is
    /// strictly stronger than any right: the grant keeps reporting as revoked,
    /// a later activation is refused, and a failed retry never clears it. The
    /// record is removed only when the second-phase link commits, which is the
    /// one outcome that proves canonical reconciliation completed.
    ///
    /// Its one production ingress is [`Self::apply_admitted_authority_revocation`],
    /// which admits the presented operation against the live composition
    /// generation before the Kernel first phase is struck;
    /// [`Self::apply_authority_request`] reaches it through the
    /// `GrantRevocation` arm.
    pub async fn revoke_grant_and_reconcile<
        L: GrantClosureCanonicalLinkPort + ?Sized,
        C: GrantClosureReceiptPort + ?Sized,
    >(
        &mut self,
        request: &GrantRevocationRequest,
        canonical_operation_id: &OperationId,
        canonical_request_identity: &RequestIdentity,
        operation: &RevocationOperationIdentity,
        durable_link: &L,
        closure_source: &C,
    ) -> Result<AuthorityRevocationReconciliation, CompositionError> {
        // The first call is intentionally before the closure readback and
        // before canonical envelope construction: Kernel/ORS must fence the
        // exact graph revision first.
        let authority_receipt = self.revoke_grant(request)?;
        let reconciled = self
            .reconcile_canonical_revocation(
                request,
                &authority_receipt,
                &CanonicalRevocationCommit {
                    canonical_operation_id,
                    canonical_request_identity,
                    operation,
                },
                durable_link,
                closure_source,
            )
            .await;
        match reconciled {
            Ok(reconciliation) => {
                self.pending_canonical_revocations
                    .remove(request.grant_id.as_str());
                Ok(reconciliation)
            }
            Err(pending) => {
                self.pending_canonical_revocations.insert(
                    request.grant_id.as_str().to_owned(),
                    PendingCanonicalRevocation {
                        grant_id: request.grant_id.as_str().to_owned(),
                        snapshot_id: authority_receipt.snapshot_id.clone(),
                        revocation_id: authority_receipt.revocation_id.clone(),
                        phase: pending.phase,
                    },
                );
                Err(pending.error)
            }
        }
    }

    /// Runs only the canonical second phase of the grant-revocation saga and
    /// reports which phase refused, so the caller can retain a pending
    /// stricter revocation against the exact Kernel-issued identity.
    ///
    /// This method is reached only after [`Self::revoke_grant`] returned a
    /// validated Kernel revocation receipt, so every refusal here is a refusal
    /// to finish a handoff whose mechanical fence already took effect.
    ///
    /// The prepared canonical revocation transition is computed here, before
    /// this projection fences the declared closure, because it is the
    /// authority graph's own origin-bound re-derivation at the CURRENT graph
    /// revision that the durable declaration is then held against.
    async fn reconcile_canonical_revocation<
        L: GrantClosureCanonicalLinkPort + ?Sized,
        C: GrantClosureReceiptPort + ?Sized,
    >(
        &mut self,
        request: &GrantRevocationRequest,
        authority_receipt: &AuthorityRevocationReceipt,
        commit: &CanonicalRevocationCommit<'_>,
        durable_link: &L,
        closure_source: &C,
    ) -> Result<AuthorityRevocationReconciliation, PendingCanonicalHandoff> {
        let closure = closure_source
            .grant_closure_receipt(request)
            .map_err(|error| PendingCanonicalHandoff {
                phase: CanonicalRevocationPhase::ClosureReadback,
                error: CompositionError::Owner(error.to_string()),
            })?;
        closure
            .validate()
            .map_err(|error| PendingCanonicalHandoff {
                phase: CanonicalRevocationPhase::ClosureReadback,
                error: CompositionError::Owner(error.to_string()),
            })?;
        if closure.state != eliot_receipts::GrantClosureState::Revoked
            || closure.declaration.target_grant_id != request.grant_id.as_str()
            || closure.authority_receipt.snapshot_id != request.snapshot_id.as_str()
            || closure.authority.state_fence != request.binding.state_fence
            || commit
                .canonical_request_identity
                .request
                .metadata
                .state_fence
                != closure.authority.state_fence
        {
            return Err(PendingCanonicalHandoff {
                phase: CanonicalRevocationPhase::ClosureReadback,
                error: CompositionError::Recovery(
                    "grant revocation closure does not bind the exact request, snapshot, and fence"
                        .to_owned(),
                ),
            });
        }
        if authority_receipt.revocation_id != closure.authority_receipt.receipt_id
            || authority_receipt.snapshot_id != closure.authority_receipt.snapshot_id
            || !authority_receipt
                .authority_epoch
                .is_same_authority(&closure.authority.state_fence.authority_epoch)
            || authority_receipt.state != AuthorityState::Revoked
        {
            return Err(PendingCanonicalHandoff {
                phase: CanonicalRevocationPhase::ClosureReadback,
                error: CompositionError::Authority(P07PortError::InvalidBinding),
            });
        }
        // The declared closure is admitted; before this projection fences it
        // and advances its own graph revision, the authority graph prepares
        // the canonical revocation transition over the SAME target and
        // closure and proves that its own origin-bound re-derivation binds
        // the durable declaration this saga is about to commit.
        self.prepare_revocation_transition_for_commit(request, &closure, commit)
            .map_err(|error| PendingCanonicalHandoff {
                phase: CanonicalRevocationPhase::ClosureReadback,
                error,
            })?;
        // The Kernel already fenced the complete declared closure. Fence the
        // exact same declared members in this projection so an already-issued
        // narrower descendant cannot keep reading an effective right out of the
        // recovered graph while the canonical writer is behind. Membership is
        // taken from the durable declaration, never re-derived here, and a
        // member this graph cannot resolve refuses instead of being skipped.
        self.owners
            .authority
            .grants
            .revoke_declared_closure(&request.grant_id, &closure.declaration.affected_grants())
            .map_err(|error| PendingCanonicalHandoff {
                phase: CanonicalRevocationPhase::ClosureReadback,
                error: CompositionError::Owner(error.to_string()),
            })?;
        self.owners.authority.invalidate_owner_hydrations();
        let envelope = authority_revocation_envelope_from_closure(
            commit.canonical_request_identity,
            commit.canonical_operation_id,
            &closure,
        )
        .map_err(|error| PendingCanonicalHandoff {
            phase: CanonicalRevocationPhase::CanonicalCommit,
            error,
        })?;
        let canonical_receipt = self
            .commit_canonical(commit.canonical_request_identity, envelope)
            .await
            .map_err(|error| PendingCanonicalHandoff {
                phase: CanonicalRevocationPhase::CanonicalCommit,
                error,
            })?;
        let receipt_identity = canonical_receipt_identity(&canonical_receipt).map_err(|error| {
            PendingCanonicalHandoff {
                phase: CanonicalRevocationPhase::SecondPhaseLink,
                error,
            }
        })?;
        // The ORIGINAL recorded first-phase operation identity, not a
        // re-derived or freshly minted one. `closure.validate()` above already
        // revalidated this exact field under the closure receipt contract, and
        // an adapter that needs a typed ORS operation identity rebuilds it from
        // these same bytes at the boundary that actually calls the store.
        let closure_projection =
            Self::link_closure_second_phase(durable_link, &closure, &receipt_identity)?;
        Ok(AuthorityRevocationReconciliation {
            authority_receipt: authority_receipt.clone(),
            canonical_receipt,
            closure_projection,
        })
    }

    /// Links the canonical second phase of one grant revocation through the
    /// durable boundary and proves the read-back.
    ///
    /// The owner-side link is keyed by the ORIGINAL recorded first-phase
    /// operation identity, never a re-derived or freshly minted one. The
    /// read-back is compared by CONTENT on the owner's committed bytes, never
    /// by existence and never by shape: the linked operation identity, the
    /// whole declared closure membership, and the exact linked canonical
    /// receipt. A disagreement is the second-phase refusal the saga retains a
    /// pending stricter revocation for.
    fn link_closure_second_phase<L: GrantClosureCanonicalLinkPort + ?Sized>(
        durable_link: &L,
        closure: &GrantClosureReceipt,
        receipt_identity: &ReceiptIdentity,
    ) -> Result<GrantClosureSecondPhaseLink, PendingCanonicalHandoff> {
        let closure_projection = durable_link
            .link_grant_closure_canonical_receipt(closure.operation_id.as_str(), receipt_identity)
            .map_err(|error| PendingCanonicalHandoff {
                phase: CanonicalRevocationPhase::SecondPhaseLink,
                error: CompositionError::Owner(error.to_string()),
            })?;
        if closure_projection.closure().operation_id != closure.operation_id
            || closure_projection.closure().declaration != closure.declaration
            || closure_projection.canonical_receipt() != receipt_identity
        {
            return Err(PendingCanonicalHandoff {
                phase: CanonicalRevocationPhase::SecondPhaseLink,
                error: CompositionError::Recovery(
                    "durable second-phase readback does not bind the canonical closure receipt"
                        .to_owned(),
                ),
            });
        }
        Ok(closure_projection)
    }

    /// Prepares the authority crate's canonical revocation transition over
    /// THIS composition's own grant graph and proves it binds the exact
    /// durable closure the Kernel/ORS first phase committed.
    ///
    /// [`authority_revocation_envelope_from_closure`] compiles the canonical
    /// record from the durable `GrantClosureReceipt`: it revalidates that
    /// receipt with its own `validate()` and digests the membership, revision
    /// and fence the declaration itself carries. The membership it records is
    /// therefore the declaration's own word about itself. This step adds the
    /// independent half the declaration cannot supply: the authority graph
    /// re-derives the origin-bound affected set itself, at the CURRENT live
    /// graph revision and under the same State Fence, from the admitted
    /// operation identity, and the saga refuses unless those two derivations
    /// agree. `A00-03` names "restoration of revoked influence after recovery"
    /// a fail-closed boundary, and a declaration whose membership the shipped
    /// graph cannot reproduce is exactly the case that must not be written.
    ///
    /// The comparison is by CONTENT, never by existence or shape: the whole
    /// re-derived affected set, and the authority epoch every re-derived
    /// member was proven under. Nothing is recomputed, defaulted or
    /// manufactured here. The prepared transition's own `graph_revision` is
    /// deliberately NOT compared with `closure.declaration.grant_graph_revision`:
    /// those are two owners' counters — the Kernel's enumeration revision and
    /// this projection's own revision, which `GrantGraph::revoke` and
    /// `GrantGraph::revoke_declared_closure` have each already advanced past
    /// that point — so no equality between them would mean anything.
    ///
    /// A declaration the authority graph cannot reproduce is refused here
    /// rather than written. That is the intended direction: the closure's
    /// `validate()` already refuses a cross-root member, so a durable
    /// membership this graph re-derives as larger is evidence the recorded
    /// closure is narrower than the authority's own denominator, and the
    /// canonical revocation record must not be minted from it.
    ///
    /// What is presented is the owner's own material, never a synthesized
    /// coordinate: the operation identity and idempotency key are the admitted
    /// canonical ones, the snapshot and State Fence are the ones the durable
    /// closure records, the bounds are the same default bounds the canonical
    /// record is committed under, and the reason is the terminal
    /// `SourceRevoked` state the durable influence closure records. The
    /// disposition is [`RevocationTransitionDisposition::Prepared`] and no
    /// write receipt is presented, because at this point nothing has been
    /// written: the canonical commit is the NEXT step, and no durable receipt
    /// exists yet to present. A committed presentation is never synthesized
    /// from a receipt this step has not been given.
    ///
    /// `prior` is `None` because this composition retains no prepared
    /// transition between calls: its durable second-phase progress is the
    /// [`PendingCanonicalRevocation`] record, and the I5.27 same-operation /
    /// changed-payload conflict is already enforced on the retained
    /// presentation bytes at
    /// [`Self::apply_admitted_authority_revocation`]. The prepared
    /// transition's own replay gate therefore has nothing to read here, and
    /// claiming a prior it does not hold would be a fabricated one.
    fn prepare_revocation_transition_for_commit(
        &self,
        request: &GrantRevocationRequest,
        closure: &GrantClosureReceipt,
        commit: &CanonicalRevocationCommit<'_>,
    ) -> Result<(), CompositionError> {
        let origin = RevocationOrigin::Grant(request.grant_id.clone());
        let prepared = self
            .owners
            .authority
            .grants
            .prepare_revocation_transition(
                &origin,
                &RevocationTransitionRequest {
                    operation_id: commit.canonical_operation_id.as_str().to_owned(),
                    idempotency_key: commit.canonical_request_identity.idempotency_key.clone(),
                    snapshot_id: request.snapshot_id.clone(),
                    state_fence: closure.authority.state_fence.clone(),
                    bounds: RevocationBounds::default_bounds(),
                    reason: RevocationReason::SourceRevoked,
                    disposition: RevocationTransitionDisposition::Prepared,
                    write_receipt: None,
                    operation: commit.operation.clone(),
                },
                None,
            )
            .map_err(|error| CompositionError::Owner(error.to_string()))?;
        // The whole re-derived membership and the authority epoch every member
        // was proven under. Any disagreement is a reconciliation refusal, not a
        // widening and not a silent repair.
        let declared_affected: BTreeSet<String> =
            closure.declaration.affected_grants().into_iter().collect();
        if prepared.affected() != &declared_affected
            || !prepared
                .authority_epoch()
                .is_same_authority(&closure.authority_receipt.authority_epoch)
        {
            return Err(CompositionError::Recovery(
                "prepared authority revocation transition does not bind the durable closure \
                 membership and authority epoch"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Presents one canonical introduction activation to the retained P-07
    /// port. The same receipt gate as [`Self::activate_grant`] applies:
    /// `Active` is recorded only after the exact Kernel-issued receipt
    /// validates, and a second activation on a recorded identity fails closed.
    pub fn activate_introduction(
        &mut self,
        request: &IntroductionActivationRequest,
    ) -> Result<AuthorityActivationReceipt, CompositionError> {
        self.require_ready_for_authority()?;
        let port = self.authority_port()?;
        let presented = PresentedAuthorityRequest::IntroductionActivation(request.clone());
        if let Some(retained) = self
            .authority_presentations
            .get(presented.ledger_key().as_str())
            && matches!(retained.state(), AuthorityPresentationState::Active { .. })
        {
            return Err(CompositionError::Authority(P07PortError::InvalidBinding));
        }
        let receipt = match port.activate_introduction(request) {
            Ok(receipt) => receipt,
            Err(P07PortError::UnknownOutcome { snapshot_id }) => {
                self.note_unknown_outcome(presented, &snapshot_id)?;
                return Err(CompositionError::Authority(P07PortError::UnknownOutcome {
                    snapshot_id,
                }));
            }
            Err(error) => return Err(CompositionError::Authority(error)),
        };
        let retained = self.retain_presentation(presented)?;
        retained.note_activated(&receipt)?;
        Ok(receipt)
    }

    /// Revokes one introduction through the retained P-07 port, Kernel first,
    /// with the same revocation-intent fallback as [`Self::revoke_grant`].
    /// Introductions have no recovered graph fallback, so the validated Kernel
    /// receipt files directly into the retained presentation.
    pub fn revoke_introduction(
        &mut self,
        request: &IntroductionRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, CompositionError> {
        self.require_ready_for_authority()?;
        let port = self.authority_port()?;
        let presented = PresentedAuthorityRequest::IntroductionRevocation(request.clone());
        let receipt = match port.revoke_introduction(request) {
            Ok(receipt) => receipt,
            Err(P07PortError::UnknownOutcome { snapshot_id }) => {
                self.note_unknown_outcome(presented, &snapshot_id)?;
                return Err(CompositionError::Authority(P07PortError::UnknownOutcome {
                    snapshot_id,
                }));
            }
            Err(error) => return Err(CompositionError::Authority(error)),
        };
        let retained = self.retain_presentation(presented)?;
        if retained.note_revoked(&receipt).is_err() {
            retained.note_revocation_intended();
            return Err(CompositionError::Recovery(
                "introduction revocation receipt could not be filed; \
                 revocation intent retained and effects remain blocked"
                    .to_owned(),
            ));
        }
        Ok(receipt)
    }

    /// Returns the effective grant status: retained receipt-driven state
    /// composes over the recovered graph status. Only a validated `Active`
    /// receipt reports `Active`; revocation intent reports `Revoked`; anything
    /// unresolved keeps the recovered status. `None` means the recovered graph
    /// carries no such grant and no presentation was retained.
    ///
    /// A pending stricter canonical revocation composes over both and reports
    /// `Revoked`: its Kernel/ORS fence already took effect, so neither the
    /// recovered graph nor a stale presentation may be read as a live right
    /// just because the canonical writer is still catching up.
    #[must_use]
    pub fn authority_grant_status(&self, grant_id: &GrantId) -> Option<GrantStatus> {
        if self
            .pending_canonical_revocations
            .contains_key(grant_id.as_str())
        {
            return Some(GrantStatus::Revoked);
        }
        let key = format!("grant:{grant_id}");
        let graph = self.recovered_grant_status(grant_id);
        match self.authority_presentations.get(&key) {
            Some(retained) => Some(retained.grant_status(graph)),
            None => graph,
        }
    }

    /// Returns the effective introduction status. Introductions have no
    /// recovered graph fallback: only a validated receipt reports `Active`,
    /// revocation intent reports `Revoked`, and anything unresolved reports
    /// nothing rather than an effective right.
    ///
    /// Live status: no production caller. Nothing in the repository reads this
    /// status; the introduction receipts retained by
    /// `activate_introduction`/`revoke_introduction` are not projected through
    /// it. Whether a presentation surface is wired to read it or the accessor is
    /// retired is an owner decision.
    #[must_use]
    pub fn authority_introduction_status(
        &self,
        introduction_id: &IntroductionId,
    ) -> Option<IntroductionStatus> {
        let key = format!("introduction:{introduction_id}");
        self.authority_presentations
            .get(&key)
            .and_then(RetainedAuthorityRequest::introduction_status)
    }

    fn require_ready_for_authority(&self) -> Result<(), CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        Ok(())
    }

    fn authority_port(&self) -> Result<Arc<dyn P07AuthorityPort>, CompositionError> {
        self.authority_activation
            .clone()
            .ok_or_else(|| CompositionError::Authority(P07PortError::Unavailable))
    }

    /// Resolves the canonical grant for an activation presentation: the
    /// recovered graph must still carry it as `PendingActivation`. Restored
    /// `Active` history, unknown grants, and already-recorded activations fail
    /// closed before any transport is touched.
    ///
    /// A grant whose Kernel-first revocation committed refuses as well, in
    /// both recorded shapes: a presentation already in a revocation state, and
    /// a pending stricter canonical revocation whose second phase never
    /// completed. Neither is restored here, and neither reaches the owner, so
    /// a delayed activation retry cannot undo a committed revocation.
    fn require_activatable_grant(
        &self,
        presented: &PresentedAuthorityRequest,
    ) -> Result<(), CompositionError> {
        let PresentedAuthorityRequest::GrantActivation(request) = presented else {
            return Err(CompositionError::Authority(P07PortError::InvalidBinding));
        };
        if self
            .pending_canonical_revocations
            .contains_key(request.grant_id.as_str())
        {
            return Err(CompositionError::Authority(P07PortError::InvalidBinding));
        }
        if self.recovered_grant_status(&request.grant_id) != Some(GrantStatus::PendingActivation) {
            return Err(CompositionError::Authority(P07PortError::InvalidBinding));
        }
        if let Some(retained) = self
            .authority_presentations
            .get(presented.ledger_key().as_str())
            && matches!(
                retained.state(),
                AuthorityPresentationState::Active { .. }
                    | AuthorityPresentationState::RevocationIntended
                    | AuthorityPresentationState::Revoked { .. }
            )
        {
            return Err(CompositionError::Authority(P07PortError::InvalidBinding));
        }
        Ok(())
    }

    /// Resolves the transition identity for an activation presentation.
    /// Changed content under a retained identity conflicts before transport.
    /// An exact active replay returns its retained receipt only as a
    /// comparison value; the caller must obtain and validate owner readback
    /// before returning a result.
    fn require_admissible_transition(
        &self,
        presented: &PresentedAuthorityRequest,
    ) -> Result<Option<RootTransitionActivationReceipt>, CompositionError> {
        let PresentedAuthorityRequest::RootTransition(request) = presented else {
            return Err(CompositionError::Authority(P07PortError::InvalidBinding));
        };
        let incoming = request.record();
        let conflicting_identity = self.authority_presentations.values().any(|retained| {
            let PresentedAuthorityRequest::RootTransition(previous) = retained.request() else {
                return false;
            };
            let held = previous.record();
            (held.transition_id == incoming.transition_id
                || held.operation_id == incoming.operation_id
                || held.idempotency_key == incoming.idempotency_key)
                && previous != request
        });
        if conflicting_identity {
            return Err(CompositionError::Authority(P07PortError::IdentityConflict));
        }
        if let Some(retained) = self
            .authority_presentations
            .get(presented.ledger_key().as_str())
        {
            if retained.request() != presented {
                return Err(CompositionError::Authority(P07PortError::IdentityConflict));
            }
            if matches!(retained.state(), AuthorityPresentationState::Active { .. }) {
                return retained
                    .transition_receipt()
                    .cloned()
                    .map(Some)
                    .ok_or(CompositionError::Authority(P07PortError::InvalidBinding));
            }
        }
        Ok(None)
    }

    fn recovered_grant_status(&self, grant_id: &GrantId) -> Option<GrantStatus> {
        self.owners
            .authority
            .grants
            .recovery_snapshot()
            .ok()?
            .grants
            .iter()
            .find(|record| record.grant_id == grant_id.as_str())
            .map(|record| record.status)
    }

    /// Retains the exact presentation with the current owner snapshot,
    /// preserving an already-recorded reconciliation state. A conflicting
    /// presentation under the same identity fails closed.
    fn retain_presentation(
        &mut self,
        presented: PresentedAuthorityRequest,
    ) -> Result<&mut RetainedAuthorityRequest, CompositionError> {
        let key = presented.ledger_key();
        if let Some(retained) = self.authority_presentations.get(&key) {
            if retained.request() != &presented {
                return Err(CompositionError::Authority(P07PortError::InvalidBinding));
            }
        } else {
            let snapshot = self.owners.authority.snapshot()?;
            let retained = RetainedAuthorityRequest::retain(presented, snapshot)?;
            self.authority_presentations.insert(key.clone(), retained);
        }
        self.authority_presentations.get_mut(&key).ok_or_else(|| {
            CompositionError::Recovery("retained authority presentation vanished".to_owned())
        })
    }

    /// Files a lost acknowledgement against the retained presentation. The
    /// grant stays pending; only the exact snapshot reconciles it.
    fn note_unknown_outcome(
        &mut self,
        presented: PresentedAuthorityRequest,
        snapshot_id: &eliot_authority::SnapshotId,
    ) -> Result<(), CompositionError> {
        let retained = self.retain_presentation(presented)?;
        retained.note_unknown_outcome(snapshot_id)
    }

    /// Restores the authority owner with live revocation-history evidence
    /// (`#2100` owner-closure join).
    ///
    /// Builds the closed `GetAuthorityRevocationHistory` read for one exact
    /// origin, executes it through the canonical read client (the Kernel
    /// serves its durable fence state on the `store_named` route), decodes
    /// the reply against the expected fence, and restores the authority
    /// owner with that evidence. A transport failure, a fence disagreement,
    /// an absent history, or a stale/invalid view refuses before any owner
    /// state is installed: unavailable history is never absence of
    /// revocation.
    ///
    /// `operation` is the admitted revocation operation identity this
    /// restore runs under, supplied by the durable boundary that admitted
    /// it and forwarded verbatim. It is required, never defaulted: the
    /// snapshot is a grant/effect payload and the decoded history carries
    /// only a fence, a durable source revision, and per-closure owner
    /// namespace/digest/bounds records, so none of the identity's five
    /// coordinates is derivable here. Restoring under a synthesized
    /// identity would make the origin-bound recheck certify itself.
    pub async fn restore_authority_with_live_history<R: CanonicalReadClient + ?Sized>(
        reads: &R,
        snapshot: &AuthorityOwnerSnapshot,
        state_fence: &StateFence,
        origin_ref: &str,
        max_records: u32,
        operation: &RevocationOperationIdentity,
    ) -> Result<AuthorityRestoreOutcome, CompositionError> {
        let request = revocation_history_read_request(state_fence, origin_ref, max_records)?;
        let response = reads
            .execute_named(request)
            .await
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let evidence = decode_revocation_history_evidence(&response, state_fence, origin_ref)?;
        AuthorityOwner::from_snapshot_with_revocation_history(
            snapshot,
            state_fence,
            Some(&evidence),
            operation,
        )
    }

    /// Synchronizes the Kernel P-07 owner from live Governor state after
    /// a revision advance (`#2100` owner-closure feed call).
    ///
    /// Binds the feed to the live composition snapshot and fence at call
    /// time — never caller-supplied — and runs the full
    /// read→decode→restore→publish→readback exchange through
    /// [`synchronize_owner_feed`]; a stale trigger refuses before any
    /// publish, and no owner state installs until the Kernel readback
    /// proves the exact published bytes.
    ///
    /// No production caller. The owning daemon runtime does not call this
    /// method: on provider-revision advance and on recovery it captures its
    /// own owner-feed plan and calls the free
    /// [`synchronize_owner_feed_with_canonical_receipts`] directly (see
    /// `bins/eliotd/src/owner_feed.rs`). This method is only a
    /// bound-snapshot wrapper over that same free function and is
    /// currently unreferenced. Whether it is wired or retired is an owner
    /// decision; it must not be read as a live entry point.
    ///
    /// `operation` is the admitted revocation operation identity the
    /// underlying feed restores under; it is forwarded verbatim to
    /// [`synchronize_owner_feed`] and is required, never defaulted.
    pub async fn synchronize_kernel_owner<
        R: CanonicalReadClient + ?Sized,
        K: OwnerPublishPort + ?Sized,
    >(
        &self,
        reads: &R,
        kernel: &K,
        origin_refs: &[String],
        max_records: u32,
        expected_revision: u64,
        operation: RevocationOperationIdentity,
    ) -> Result<u64, CompositionError> {
        let snapshot = self.owners.authority.snapshot()?;
        let state_fence = self.snapshot.state_fence();
        synchronize_owner_feed(
            reads,
            kernel,
            snapshot,
            &state_fence,
            origin_refs,
            max_records,
            expected_revision,
            operation,
        )
        .await
    }

    /// Synchronizes the Kernel P-07 owner with canonical second-phase links
    /// read from the durable ORS boundary. The legacy method above remains the
    /// fail-closed empty-link entry point; a caller that has read completed
    /// links must not use that legacy path.
    ///
    /// No production caller. The owning daemon runtime reads the completed
    /// links itself, binds the captured plan, and calls the free
    /// [`synchronize_owner_feed_with_canonical_receipts`] directly (see
    /// `bins/eliotd/src/owner_feed.rs`) rather than this method. This method
    /// is only a bound-snapshot wrapper over that same free function and is
    /// currently unreferenced; whether it is wired or retired is an owner
    /// decision.
    ///
    /// `operation` is the admitted revocation operation identity the
    /// underlying feed restores under; it is forwarded verbatim to
    /// [`synchronize_owner_feed_with_canonical_receipts`] and is
    /// required, never defaulted.
    #[allow(
        clippy::too_many_arguments,
        reason = "the durable feed boundary keeps read, publish, roots, history, revision, canonical receipt evidence, and the admitted operation identity explicit"
    )]
    pub async fn synchronize_kernel_owner_with_canonical_receipts<
        R: CanonicalReadClient + ?Sized,
        K: OwnerPublishPort + ?Sized,
    >(
        &self,
        reads: &R,
        kernel: &K,
        origin_refs: &[String],
        max_records: u32,
        expected_revision: u64,
        canonical_receipts: BTreeMap<String, ReceiptIdentity>,
        operation: RevocationOperationIdentity,
    ) -> Result<u64, CompositionError> {
        let snapshot = self.owners.authority.snapshot()?;
        let state_fence = self.snapshot.state_fence();
        synchronize_owner_feed_with_canonical_receipts(
            reads,
            kernel,
            snapshot,
            &state_fence,
            origin_refs,
            max_records,
            expected_revision,
            canonical_receipts,
            operation,
        )
        .await
    }

    /// Synchronizes the Kernel P-07 owner with canonical second-phase links
    /// plus owner quarantine evidence records read from the durable
    /// boundary. Absent evidence leaves the affected omissions explicitly
    /// unresolved; it is never reconstructed here.
    ///
    /// No production caller. The owning daemon runtime supplies no quarantine
    /// evidence and calls the free
    /// [`synchronize_owner_feed_with_canonical_receipts`] instead (see
    /// `bins/eliotd/src/owner_feed.rs`), so this method is currently
    /// unreferenced; whether it is wired or retired is an owner decision.
    ///
    /// `operation` is the admitted revocation operation identity the
    /// underlying feed restores under; it is forwarded verbatim to
    /// [`synchronize_owner_feed_with_quarantine_evidence`] and is
    /// required, never defaulted.
    #[allow(
        clippy::too_many_arguments,
        reason = "the durable feed boundary keeps read, publish, roots, history, revision, canonical receipt evidence, quarantine evidence, and the admitted operation identity explicit"
    )]
    pub async fn synchronize_kernel_owner_with_quarantine_evidence<
        R: CanonicalReadClient + ?Sized,
        K: OwnerPublishPort + ?Sized,
    >(
        &self,
        reads: &R,
        kernel: &K,
        origin_refs: &[String],
        max_records: u32,
        expected_revision: u64,
        canonical_receipts: BTreeMap<String, ReceiptIdentity>,
        quarantine_evidence: BTreeMap<String, CrossRootQuarantineEvidence>,
        operation: RevocationOperationIdentity,
    ) -> Result<u64, CompositionError> {
        let snapshot = self.owners.authority.snapshot()?;
        let state_fence = self.snapshot.state_fence();
        synchronize_owner_feed_with_quarantine_evidence(
            reads,
            kernel,
            snapshot,
            &state_fence,
            origin_refs,
            max_records,
            expected_revision,
            canonical_receipts,
            quarantine_evidence,
            operation,
        )
        .await
    }

    /// Reads one coherent semantic activation from all required owner records.
    ///
    /// No semantic identity is accepted from the caller: coordination first
    /// proves one unique live work lease, then task, `WorkScope` and Canonical
    /// owners must agree on its exact fence and linked identities.
    ///
    /// Split note: activation admission validates one coherent semantic owner
    /// projection before binding. The seam is still one ordered admission
    /// cascade; each owner agreement is now a named private function, so every
    /// guard still runs in the same order over the same effects.
    pub fn read_unique_agent_activation(
        &self,
        now: u64,
    ) -> Result<GovernorActivationSnapshot, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        let state_fence = self.snapshot.state_fence();
        let work = self.prove_unique_activation_work(now, &state_fence)?;
        let task_id = self.admit_activation_lifecycle_session(now, &state_fence, &work)?;
        let task = self.admit_activation_task(&task_id, &state_fence)?;
        let (work_scope_id, plan) = self.admit_activation_plan(&task_id, &state_fence)?;
        Ok(GovernorActivationSnapshot {
            state_fence,
            owner_revision: self.owners.canonical.owner_revision(),
            principal_id: work.session.principal_id,
            session_id: work.session.session_id,
            task_id,
            work_unit_id: work.work_item.work_item_id,
            work_scope_id,
            task_revision: task.revision,
            plan_id: plan.plan_id,
            plan_revision: plan.plan_revision,
        })
    }

    /// Proves exactly one live work lease for this exact fence.
    ///
    /// No selection, more than one selection and any coordination read failure
    /// are three distinct typed refusals; only the unique validated projection
    /// is ever handed to the rest of the admission cascade.
    fn prove_unique_activation_work(
        &self,
        now: u64,
        state_fence: &StateFence,
    ) -> Result<ActiveWorkLeaseProjection, CompositionError> {
        let work = match self.owners.coordination.read_active_work_lease_selection(
            now,
            state_fence.authority_epoch.clone(),
            state_fence,
        ) {
            Ok(ActiveWorkLeaseSelection::None) => {
                return Err(CompositionError::ActivationTaskSelectionRequired);
            }
            Ok(ActiveWorkLeaseSelection::Unique { projection }) => *projection,
            Ok(ActiveWorkLeaseSelection::Ambiguous { projections }) => {
                return Err(CompositionError::ActivationScopeAmbiguous {
                    candidate_handles: projections
                        .into_iter()
                        .map(|projection| projection.work_item.work_item_id)
                        .collect(),
                });
            }
            Err(error) => return Err(map_activation_coordination_error(error)),
        };
        Ok(work)
    }

    /// Proves the one live owner session named by the unique work lease and
    /// returns the exact task id that session is bound to.
    ///
    /// The semantic ids are rebuilt from the lease itself, the stored session
    /// must be that same active session under the same authority epoch and the
    /// same fence, its lease window must still be live, and any task scope it
    /// names must be the same task.
    fn admit_activation_lifecycle_session(
        &self,
        now: u64,
        state_fence: &StateFence,
        work: &ActiveWorkLeaseProjection,
    ) -> Result<TaskId, CompositionError> {
        let task_id = TaskId::new(work.work_item.task_id.clone())
            .map_err(|_| CompositionError::ActivationTaskSelectionRequired)?;
        let lifecycle_session_id = SessionId::new(work.session.session_id.clone())
            .map_err(|_| CompositionError::ActivationTaskSelectionRequired)?;
        let lifecycle_session = self
            .owners
            .session
            .session(&lifecycle_session_id)
            .ok_or(CompositionError::ActivationTaskSelectionRequired)?;
        if lifecycle_session.session_id != lifecycle_session_id
            || lifecycle_session.status != SessionState::Active
            || !lifecycle_session
                .authority_epoch
                .is_same_authority(&state_fence.authority_epoch)
            || lifecycle_session.state_fence != *state_fence
        {
            return Err(CompositionError::ActivationStaleFence);
        }
        if lifecycle_session.started_at == 0
            || lifecycle_session.heartbeat_at < lifecycle_session.started_at
            || lifecycle_session.expires_at == 0
            || lifecycle_session.expires_at < lifecycle_session.heartbeat_at
            || lifecycle_session.heartbeat_at > now
            || now > lifecycle_session.expires_at
        {
            return Err(CompositionError::NotReady);
        }
        if let Some(scoped_task_id) = &lifecycle_session.task_scope
            && scoped_task_id != task_id.as_str()
        {
            return Err(CompositionError::ActivationTaskSelectionRequired);
        }
        Ok(task_id)
    }

    /// Proves the durable task owner agrees with the admitted session.
    ///
    /// The task must be the same task under the same fence, must be at a
    /// nonzero revision in an authorized or running state, and must be the
    /// exact revision the fence names when the fence names one.
    fn admit_activation_task(
        &self,
        task_id: &TaskId,
        state_fence: &StateFence,
    ) -> Result<&TaskRecord, CompositionError> {
        let task = self
            .owners
            .task
            .task(task_id)
            .ok_or(CompositionError::ActivationTaskSelectionRequired)?;
        if task.task_id != *task_id || task.state_fence != *state_fence {
            return Err(CompositionError::ActivationStaleFence);
        }
        if task.revision == 0
            || !matches!(
                task.state,
                TaskState::ActionAuthorized | TaskState::Executing | TaskState::Verifying
            )
        {
            return Err(CompositionError::ActivationTaskSelectionRequired);
        }
        if let Some(expected_revision) = state_fence.task_revision
            && expected_revision.value() != task.revision
        {
            return Err(CompositionError::ActivationStaleFence);
        }
        Ok(task)
    }

    /// Proves the `WorkScope` and Canonical owners agree with the admitted
    /// task, and returns the bound work scope id with the current plan.
    ///
    /// The scope must be installed, freshly `MATCHED`, and the plan must name
    /// the same task and the same bound work scope, so a drifted scope is
    /// never paired with a plan the #1115 v2 resolution would publish.
    fn admit_activation_plan(
        &self,
        task_id: &TaskId,
        state_fence: &StateFence,
    ) -> Result<(String, CanonicalPlanBinding), CompositionError> {
        let scope_owner = self
            .owners
            .work_scope
            .as_ref()
            .ok_or(CompositionError::ActivationScopeSelectionRequired)?;
        let scope = scope_owner
            .read_current(state_fence)
            // #1115: the activation boundary maps every `WorkScopeError` into a
            // typed `CompositionError` class, so a scope failure is a semantic
            // classifier here and never human error text.
            .map_err(map_activation_scope_error)?;
        // Issue #1787: activation cannot proceed on a stale or drifted guard
        // receipt; a generation change requires a fresh `MATCHED` receipt. The
        // freshness gate runs before the plan read, so a drifted scope is never
        // paired with a plan the #1115 v2 resolution would publish.
        ensure_snapshot_fresh(&scope, "activation work scope is not freshly matched")?;
        // #1115: activation reads the plan through the typed reader, which
        // fails closed on a stale fence and on a missing selection rather than
        // surfacing the general reader's recovery text.
        let plan = self
            .owners
            .canonical
            .read_current_activation_plan(state_fence)?;
        if plan.task_id != *task_id || plan.work_scope_id != scope.binding.scope.scope_ref {
            return Err(CompositionError::ActivationScopeSelectionRequired);
        }
        Ok((scope.binding.scope.scope_ref, plan))
    }

    /// Returns the current canonical owner revision used by activation
    /// dependency observations.
    #[must_use]
    pub fn activation_owner_revision(&self) -> u64 {
        self.owners.canonical.owner_revision()
    }

    /// Returns the current revision of the named activation-readiness
    /// dependency. The value combines the canonical owner revision with the
    /// live readiness phase, so a successor cannot claim material change from
    /// elapsed time alone.
    #[must_use]
    pub fn activation_dependency_revision(&self) -> String {
        let readiness_revision = match self.readiness {
            CompositionReadiness::Constructing => "constructing",
            CompositionReadiness::Ready => "ready",
            CompositionReadiness::Stopped => "stopped",
        };
        format!(
            "{}:{}",
            self.owners.canonical.owner_revision(),
            readiness_revision
        )
    }

    /// Governor-internal typed semantic outcome for activation resolution.
    ///
    /// This is the sole typed discriminator; it classifies every resolver path
    /// without silent coercion to success. Callers must match exhaustively and
    /// map losslessly to the protocol v2 result; dropping an error variant is a
    /// composition defect.
    pub fn resolve_activation_outcome(&self, now: u64) -> GovernorActivationOutcome {
        let dependency_revision = self.activation_dependency_revision();
        if self.readiness != CompositionReadiness::Ready {
            return GovernorActivationOutcome::NotReady {
                recovery_handle: "governor.readiness:not-ready".to_owned(),
                retry: GovernorRetryDirective::new(
                    "governor.readiness",
                    dependency_revision,
                    now.saturating_add(1).max(1),
                ),
            };
        }
        match self.read_unique_agent_activation(now) {
            Ok(snapshot) => GovernorActivationOutcome::Resolved(snapshot),
            Err(error) => {
                // #66 A2: an ambiguity finding must name the actual competing
                // bindings. The unique-read error may discard them, so re-read
                // the live selection here instead of manufacturing handles.
                if matches!(error, CompositionError::ActivationScopeAmbiguous { .. }) {
                    return self.scope_ambiguous_outcome_from_selection(now);
                }
                classify_activation_error(&error, now, &dependency_revision)
            }
        }
    }

    /// Builds the `ScopeAmbiguous` outcome from the exact active-work
    /// selection (#66 A2).
    ///
    /// Each candidate handle names one actual competing work binding
    /// (`scope:candidate:{work_item_id}`), sorted and deduplicated, bounded by
    /// `eliot_protocol::MAX_AGENT_ACTIVATION_CANDIDATES` (a truncated
    /// denominator reports `Partial` coverage instead of claiming `Complete`).
    /// When the selection cannot supply at least two distinct candidates (a
    /// lost race between the two reads), the finding is an internal failure
    /// for this ticket: never a manufactured placeholder pair and never
    /// downgraded to task selection.
    fn scope_ambiguous_outcome_from_selection(&self, now: u64) -> GovernorActivationOutcome {
        let state_fence = self.snapshot.state_fence();
        let selection = self.owners.coordination.read_active_work_lease_selection(
            now,
            state_fence.authority_epoch.clone(),
            &state_fence,
        );
        let Ok(eliot_coordination::ActiveWorkLeaseSelection::Ambiguous { projections }) = selection
        else {
            return GovernorActivationOutcome::FailedInternal {
                failure_handle: "governor.ambiguity-selection-unreadable:recovery".to_owned(),
            };
        };
        let mut handles: Vec<String> = projections
            .iter()
            .map(|projection| format!("scope:candidate:{}", projection.work_item.work_item_id))
            .collect();
        handles.sort();
        handles.dedup();
        let complete = handles.len() <= eliot_protocol::MAX_AGENT_ACTIVATION_CANDIDATES;
        if !complete {
            handles.truncate(eliot_protocol::MAX_AGENT_ACTIVATION_CANDIDATES);
        }
        if handles.len() < 2 {
            return GovernorActivationOutcome::FailedInternal {
                failure_handle: "governor.ambiguity-selection-unreadable:recovery".to_owned(),
            };
        }
        GovernorActivationOutcome::ScopeAmbiguous {
            selection: GovernorSelectionDirective::new(
                handles,
                if complete {
                    GovernorCandidateCoverage::Complete
                } else {
                    GovernorCandidateCoverage::Partial
                },
                "governor.scope-ambiguous:recovery",
            ),
        }
    }

    /// Stops this composition without creating a second shutdown authority.
    pub fn stop(&mut self) {
        self.readiness = CompositionReadiness::Stopped;
    }
}

/// Supplies the exact authenticated generation snapshot for a Kernel port.
pub trait KernelGenerationSnapshotProvider {
    /// Returns the immutable snapshot established by authenticated handoff.
    fn snapshot(&self) -> &KernelGenerationSnapshot;
}

/// Authenticated Kernel generation client required by the daemon.
///
/// A pipe name or caller-supplied generation is not sufficient: an admitted
/// type must expose both the neutral transition port and the immutable
/// authenticated snapshot.
pub trait KernelGenerationPort:
    KernelTransitionPort
    + KernelGenerationSnapshotProvider
    + KernelRecoveryPort
    + KernelServiceObservationPort
    + KernelDurableJobPort
{
}

impl<T> KernelGenerationPort for T where
    T: KernelTransitionPort
        + KernelGenerationSnapshotProvider
        + KernelRecoveryPort
        + KernelServiceObservationPort
        + KernelDurableJobPort
{
}

fn recover_from_kernel<P: KernelRecoveryPort + ?Sized>(
    kernel: &P,
    state_fence: &StateFence,
    protected_snapshot_digest: &str,
) -> Result<GovernorRecoverySnapshot, CompositionError> {
    let mut canonical_scope = kernel
        .canonical_scope(state_fence, protected_snapshot_digest)
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    let mut owner_reads = Vec::with_capacity(RecoveryOwner::ALL.len());
    let mut missing = 0usize;
    for owner in RecoveryOwner::ALL {
        let read = kernel
            .named_read(KernelNamedReadRequest {
                owner,
                state_fence: state_fence.clone(),
                protected_snapshot_digest: protected_snapshot_digest.to_owned(),
            })
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if let Some(read) = read {
            owner_reads.push(read);
        } else {
            missing += 1;
        }
    }
    if missing != 0 {
        if missing != RecoveryOwner::ALL.len()
            || state_fence.authority_epoch.sequence.get() != 1
            || state_fence.resource_generation != ResourceGeneration::genesis()
            || state_fence.task_revision.is_some()
            || state_fence.policy_revision.is_some()
            || state_fence.integration_revision.is_some()
            || !canonical_scope.revision_heads.is_empty()
            || !canonical_scope.ordering_heads.is_empty()
        {
            return Err(CompositionError::Recovery(
                "Kernel returned partial or non-genesis owner state; local fill is forbidden"
                    .to_owned(),
            ));
        }
        let genesis_request =
            GovernorGenesisPacket::genesis(state_fence, protected_snapshot_digest)?;
        kernel
            .initialize_governor_genesis(&genesis_request)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        owner_reads.clear();
        for owner in RecoveryOwner::ALL {
            let read = kernel
                .named_read(KernelNamedReadRequest {
                    owner,
                    state_fence: state_fence.clone(),
                    protected_snapshot_digest: protected_snapshot_digest.to_owned(),
                })
                .map_err(|error| CompositionError::Recovery(error.to_string()))?
                .ok_or_else(|| {
                    CompositionError::Recovery(
                        "genesis initialization did not produce every owner record".to_owned(),
                    )
                })?;
            owner_reads.push(read);
        }
        canonical_scope = kernel
            .canonical_scope(state_fence, protected_snapshot_digest)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    }
    let receipts = kernel
        .receipts(state_fence, protected_snapshot_digest)
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    let durable_jobs = kernel
        .durable_jobs(state_fence, protected_snapshot_digest)
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    // The Policy read rides outside the required set: an unserved owner
    // yields `None` (explicit absence) instead of failing recovery, while a
    // transport failure still fails closed. Genesis seeding covers only the
    // required owners; Policy is served independently afterwards.
    let policy_read = kernel
        .named_read(KernelNamedReadRequest {
            owner: RecoveryOwner::Policy,
            state_fence: state_fence.clone(),
            protected_snapshot_digest: protected_snapshot_digest.to_owned(),
        })
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    Ok(GovernorRecoverySnapshot {
        state_fence: state_fence.clone(),
        protected_snapshot_digest: protected_snapshot_digest.to_owned(),
        owner_reads,
        policy_read,
        canonical_scope,
        receipts,
        durable_jobs,
    })
}

fn validate_service_observations(
    observations: &[KernelServiceRecovery],
    expected_fence: &StateFence,
) -> Result<(), CompositionError> {
    let mut services = BTreeSet::new();
    for recovered in observations {
        if !services.insert(recovered.service)
            || recovered.observation.generation != expected_fence.resource_generation
            || !recovered
                .observation
                .authority_epoch
                .is_same_authority(&expected_fence.authority_epoch)
            || recovered.observation.state != eliot_runtime_contracts::ServiceProcessState::Ready
            || !recovered.observation.health.is_fully_healthy()
        {
            return Err(CompositionError::Recovery(
                "service observation is incomplete, stale, or unhealthy".to_owned(),
            ));
        }
    }
    if services.len() != STARTUP_ORDER.len()
        || STARTUP_ORDER
            .iter()
            .any(|service| !services.contains(service))
    {
        return Err(CompositionError::Recovery(
            "Kernel service observation did not return every ordered Governor service".to_owned(),
        ));
    }
    Ok(())
}

fn map_activation_coordination_error(error: CoordinationError) -> CompositionError {
    match error {
        CoordinationError::NoActiveBinding => CompositionError::ActivationTaskSelectionRequired,
        CoordinationError::AmbiguousActiveBinding => CompositionError::ActivationScopeAmbiguous {
            candidate_handles: Vec::new(),
        },
        CoordinationError::FenceMismatch
        | CoordinationError::EpochMismatch
        | CoordinationError::LeaseOwnerMismatch { .. } => CompositionError::ActivationStaleFence,
        CoordinationError::SessionExpired
        | CoordinationError::LeaseExpired
        | CoordinationError::LeaseNotYetValid => CompositionError::NotReady,
        other => {
            CompositionError::Recovery(format!("coordination activation read failed: {other}"))
        }
    }
}

fn map_activation_scope_error(error: WorkScopeError) -> CompositionError {
    match error {
        WorkScopeError::StateFenceMismatch => CompositionError::ActivationStaleFence,
        WorkScopeError::BindingReceiptNotMatched
        | WorkScopeError::BindingReceiptMismatch
        | WorkScopeError::InvalidStateFence => CompositionError::ActivationScopeSelectionRequired,
        other => CompositionError::Recovery(format!("WorkScope activation read failed: {other}")),
    }
}

fn classify_activation_error(
    error: &CompositionError,
    now: u64,
    dependency_revision: &str,
) -> GovernorActivationOutcome {
    match error {
        CompositionError::NotReady => GovernorActivationOutcome::NotReady {
            recovery_handle: "governor.readiness:not-ready".to_owned(),
            retry: GovernorRetryDirective::new(
                "governor.readiness",
                dependency_revision.to_owned(),
                now.saturating_add(1).max(1),
            ),
        },
        CompositionError::ActivationTaskSelectionRequired => {
            GovernorActivationOutcome::TaskSelectionRequired {
                selection: GovernorSelectionDirective::new(
                    Vec::new(),
                    GovernorCandidateCoverage::Unknown,
                    "governor.task-selection:recovery",
                ),
            }
        }
        CompositionError::ActivationScopeAmbiguous { candidate_handles } => {
            let coverage = if candidate_handles.is_empty() {
                GovernorCandidateCoverage::Unknown
            } else {
                GovernorCandidateCoverage::Complete
            };
            GovernorActivationOutcome::ScopeAmbiguous {
                selection: GovernorSelectionDirective::new(
                    candidate_handles.clone(),
                    coverage,
                    "governor.scope-ambiguous:recovery",
                ),
            }
        }
        CompositionError::ActivationScopeSelectionRequired => {
            GovernorActivationOutcome::ScopeSelectionRequired {
                selection: GovernorSelectionDirective::new(
                    Vec::new(),
                    GovernorCandidateCoverage::Unknown,
                    "governor.scope-selection:recovery",
                ),
            }
        }
        CompositionError::ActivationStaleFence => GovernorActivationOutcome::StaleFence {
            recovery_handle: "governor.stale-fence:recovery".to_owned(),
            observed_state_fence: None,
        },
        _ => GovernorActivationOutcome::FailedInternal {
            failure_handle: "governor.internal:activation-resolution-failed".to_owned(),
        },
    }
}

fn decode_owner_snapshot<T: DeserializeOwned + Serialize>(
    recovery: &GovernorRecoverySnapshot,
    owner: RecoveryOwner,
) -> Result<T, CompositionError> {
    let read = recovery.owner_read(owner)?;
    let decoded: T = serde_json::from_slice(&read.payload).map_err(|error| {
        CompositionError::Recovery(format!(
            "owner {} payload schema rejected: {error}",
            owner.as_str()
        ))
    })?;
    let canonical = canonical_json_bytes(&decoded).map_err(|error| {
        CompositionError::Recovery(format!(
            "owner {} payload could not be canonicalized: {error}",
            owner.as_str()
        ))
    })?;
    if canonical != read.payload {
        return Err(CompositionError::Recovery(format!(
            "owner {} payload is not canonical JSON",
            owner.as_str()
        )));
    }
    Ok(decoded)
}

/// Explicit Host-approved config projection used by the daemon loader.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorLaunchConfig {
    /// Daemon identity.
    pub instance_id: String,
    /// Exact Kernel generation snapshot expected from Host handoff.
    pub kernel: KernelGenerationExpectation,
    /// Digest of the protected full Governor launch snapshot.
    pub protected_snapshot_digest: String,
}

impl GovernorLaunchConfig {
    /// Validates that the launch config is itself a bounded protected snapshot.
    pub fn validate(&self) -> Result<(), CompositionError> {
        if self.instance_id.trim().is_empty() || self.instance_id.chars().any(char::is_control) {
            return Err(CompositionError::Provider(
                "instance_id must be non-blank and free of controls".to_owned(),
            ));
        }
        let snapshot = KernelGenerationSnapshot {
            service: self.kernel.service.clone(),
            protocol: self.kernel.protocol.clone(),
            generation: self.kernel.generation,
            authority_epoch: self.kernel.authority_epoch.clone(),
            artifact_digest: self.kernel.artifact_digest.clone(),
            protected_snapshot_digest: self.protected_snapshot_digest.clone(),
            principal: self.kernel.principal.clone(),
        };
        snapshot.validate()?;
        if snapshot.protected_snapshot_digest != self.kernel.protected_snapshot_digest {
            return Err(CompositionError::Provider(
                "launch config protected snapshot digest is not bound to Kernel expectation"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Compatibility alias retained for daemon callers that use `QueueLimits`.
pub type GovernorQueueLimits = QueueLimits;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expects for fixed-valid protocol fixtures"
    )]

    use super::*;
    use crate::{STARTUP_ORDER, ServiceId};
    use eliot_budget::{BudgetEnvelope, BudgetLedger, ProviderToolAttribution, QuotaState};
    use eliot_canonical::CanonicalWriteEnvelope;
    use eliot_config::Applicability;
    use eliot_contracts::{
        ClockReading, ContractId, ProductId, RequestId, RequestMetadata, SessionId, SourceId,
        TaskId,
    };
    use eliot_coordination::{
        RegisterSession as CoordinationRegisterSession, WorkItem, WorkLeaseRequest, WorkState,
    };
    use eliot_protocol::RequestIdentity;
    use eliot_receipts::{AuthorityBinding, EffectClass, ProofCeiling, RequestBinding};
    use eliot_runtime_contracts::{AuthorityState, HealthVector, ServiceProcessState};
    use eliot_session::{RegisterSession, SessionCommand, SessionCommandContext};
    use eliot_store_api::{
        CommitId, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
        OperationManifestDigest, OrderingHead, OrderingHeadExpectation, OrderingScopeId,
        Resubmission, RevisionHead, RevisionKey, ScopeId, SecurityContext, TransitionClass,
        WriteReceipt, WriteReceiptStatus, validate_store_receipt_envelope,
    };
    use eliot_task::{TaskCommandContext, TaskLifecycleEvent, TaskProposal, TaskRecord};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            eliot_contracts::EpochLineageId::new(lineage).expect("valid test lineage"),
            std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    struct FakeKernel {
        snapshot: KernelGenerationSnapshot,
        payloads: BTreeMap<RecoveryOwner, Vec<u8>>,
        /// Post-construction owner overrides keyed by owner. `Some(bytes)`
        /// replaces the seeded payload; `None` drops the read to simulate
        /// partial recovery. Checked before `payloads`/`missing`.
        live_reads: Mutex<BTreeMap<RecoveryOwner, Option<Vec<u8>>>>,
        /// Staged canonical scope views. While more than one view is staged,
        /// calls consume them in order (simulating heads moving between
        /// reads); a single remaining view is served stably; empty falls back
        /// to the default empty view.
        staged_scopes: Mutex<Vec<ScopeRevisionView>>,
        /// Terminal receipts served by the receipts route.
        receipts: Vec<WriteReceipt>,
        /// Committed transitions keyed by operation id, served by the
        /// transition-port receipt route for exact reconciliation.
        committed: Mutex<BTreeMap<OperationId, (RequestIdentity, WriteReceipt)>>,
        /// Number of actual gateway executions. Idempotent replays of an
        /// already committed operation resolve to the stored receipt without
        /// incrementing this count.
        apply_calls: Mutex<u64>,
        missing: Option<RecoveryOwner>,
        genesis_all_absent: bool,
        genesis_seeded: Arc<AtomicBool>,
        service_observations: Option<Vec<KernelServiceRecovery>>,
        service_failure: bool,
    }

    impl KernelGenerationSnapshotProvider for FakeKernel {
        fn snapshot(&self) -> &KernelGenerationSnapshot {
            &self.snapshot
        }
    }

    impl KernelTransitionPort for FakeKernel {
        fn apply_prepared<'a>(
            &'a self,
            identity: &RequestIdentity,
            transition: PreparedTransition,
            expected_revision_heads: Vec<RevisionHeadExpectation>,
            expected_ordering_heads: Vec<OrderingHeadExpectation>,
        ) -> KernelPortFuture<'a, WriteReceipt> {
            let identity = identity.clone();
            Box::pin(async move {
                identity
                    .validate()
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                transition
                    .validate()
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                // Exact binding agreement: the admitted identity's request
                // binding, fence and idempotency terms must match the
                // immutable transition. Substitutions fail closed here and
                // are never repaired or rehashed.
                if identity.request.metadata.state_fence != transition.state_fence
                    || identity.request.state_fence != transition.state_fence
                {
                    return Err(KernelPortError::Contract(
                        "fake gateway: identity fence does not match the transition fence"
                            .to_owned(),
                    ));
                }
                if identity.idempotency_key != transition.identity.idempotency_key {
                    return Err(KernelPortError::Contract(
                        "fake gateway: identity idempotency does not match the transition"
                            .to_owned(),
                    ));
                }
                for head in &expected_revision_heads {
                    head.validate()
                        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                    if head.state_fence != transition.state_fence {
                        return Err(KernelPortError::Contract(
                            "fake gateway: revision head fence does not match the transition"
                                .to_owned(),
                        ));
                    }
                }
                for head in &expected_ordering_heads {
                    head.validate()
                        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                    if head.state_fence != transition.state_fence {
                        return Err(KernelPortError::Contract(
                            "fake gateway: ordering head fence does not match the transition"
                                .to_owned(),
                        ));
                    }
                }
                let mut committed = self.committed.lock().expect("committed lock");
                if let Some((_, receipt)) = committed.get(&transition.identity.operation_id) {
                    // Exact idempotent replay: the same operation identity
                    // resolves to the stored receipt without re-execution. A
                    // different idempotency or hash under a committed
                    // operation id is an identity conflict, never a silent
                    // second execution.
                    if receipt.idempotency_key == transition.identity.idempotency_key
                        && receipt.canonical_request_hash
                            == transition.identity.canonical_request_hash
                    {
                        return Ok(receipt.clone());
                    }
                    return Err(KernelPortError::Contract(
                        "fake gateway: committed operation identity conflict".to_owned(),
                    ));
                }
                // Issue the store-owned receipt envelope through the real
                // shared contract: no canned receipt bypasses validation.
                let sequence = u64::try_from(committed.len())
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?
                    + 1;
                let operation_id = transition.identity.operation_id.clone();
                let candidate = WriteReceipt {
                    operation_id: operation_id.clone(),
                    idempotency_key: transition.identity.idempotency_key.clone(),
                    canonical_request_hash: transition.identity.canonical_request_hash.clone(),
                    transition_class: transition.transition_class,
                    status: WriteReceiptStatus::Committed,
                    commit_id: Some(
                        CommitId::new(format!("commit-{operation_id}"))
                            .map_err(|error| KernelPortError::Contract(error.to_string()))?,
                    ),
                    state_fence: transition.state_fence.clone(),
                    ordering_sequences: Vec::new(),
                    revision_before_after: Vec::new(),
                    applied_command_ids: vec!["cmd-1".to_owned()],
                    emitted_event_ids: Vec::new(),
                    projection_refs: Vec::new(),
                    outbox_refs: Vec::new(),
                    operation_manifest_digest: transition.operation_manifest_digest.clone(),
                    // Issue-#18 bindings are copied exactly from the admitted
                    // transition, never defaulted; equality is enforced by
                    // the receipt-issuing path below.
                    admission_digest: transition.admission_digest.clone(),
                    mutation_plan_digest: transition.mutation_plan_digest.clone(),
                    semantic_source_revisions: transition.semantic_source_revisions.clone(),
                    // I5.19: bound from the admitted transition, never
                    // defaulted; equality is enforced by the receipt-issuing
                    // path below.
                    policy_config_schema_versions:
                        eliot_store_api::PolicyConfigSchemaVersions::bound_to(&transition),
                    error_code: None,
                    resubmission: Resubmission::None,
                    committed_at: Some(format!("commit-sequence-{sequence:016}")),
                    envelope: None,
                };
                candidate
                    .validate()
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                let envelope = eliot_store_api::issue_store_receipt_envelope(
                    &identity.request.metadata,
                    &transition,
                    &candidate,
                    sequence,
                )
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                let mut receipt = candidate;
                receipt.envelope = Some(envelope);
                eliot_store_api::validate_store_receipt_envelope(
                    &identity.request.metadata,
                    &transition,
                    &receipt,
                )
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                *self.apply_calls.lock().expect("apply call lock") += 1;
                committed.insert(operation_id, (identity, receipt.clone()));
                Ok(receipt)
            })
        }

        fn receipt(&self, operation_id: OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>> {
            Box::pin(async move {
                Ok(self
                    .committed
                    .lock()
                    .expect("committed lock")
                    .get(&operation_id)
                    .map(|(_, receipt)| receipt.clone()))
            })
        }

        fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
            Box::pin(async { Err(KernelPortError::NotAdmitted("test port".to_owned())) })
        }
    }

    impl KernelRecoveryPort for FakeKernel {
        fn named_read(
            &self,
            request: KernelNamedReadRequest,
        ) -> Result<Option<KernelNamedReadReply>, KernelPortError> {
            let live = self
                .live_reads
                .lock()
                .expect("live read lock")
                .get(&request.owner)
                .cloned();
            if let Some(live) = live {
                return match live {
                    Some(payload) => Ok(Some(KernelNamedReadReply {
                        owner: request.owner,
                        state_fence: request.state_fence,
                        revision: 1,
                        schema: OWNER_SNAPSHOT_SCHEMA.to_owned(),
                        value_digest: sha256_hex(&payload),
                        payload,
                    })),
                    None => Ok(None),
                };
            }
            if self.missing == Some(request.owner) {
                return Ok(None);
            }
            if self.genesis_all_absent && !self.genesis_seeded.load(Ordering::Acquire) {
                return Ok(None);
            }
            let payload = self
                .payloads
                .get(&request.owner)
                .cloned()
                .unwrap_or_else(|| {
                    owner_payload(
                        request.owner,
                        &request.state_fence,
                        &request.protected_snapshot_digest,
                    )
                });
            Ok(Some(KernelNamedReadReply {
                owner: request.owner,
                state_fence: request.state_fence,
                revision: 1,
                schema: OWNER_SNAPSHOT_SCHEMA.to_owned(),
                value_digest: sha256_hex(&payload),
                payload,
            }))
        }

        fn initialize_governor_genesis(
            &self,
            _request: &GovernorGenesisRequest,
        ) -> Result<(), KernelPortError> {
            self.genesis_seeded.store(true, Ordering::Release);
            Ok(())
        }

        fn canonical_scope(
            &self,
            state_fence: &StateFence,
            _protected_snapshot_digest: &str,
        ) -> Result<ScopeRevisionView, KernelPortError> {
            let mut staged = self.staged_scopes.lock().expect("staged scope lock");
            if staged.len() > 1 {
                return Ok(staged.remove(0));
            }
            if let Some(view) = staged.first() {
                return Ok(view.clone());
            }
            Ok(ScopeRevisionView {
                scope_id: ScopeId::new("governor").expect("scope"),
                revision_heads: Vec::new(),
                ordering_heads: Vec::new(),
                state_fence: state_fence.clone(),
            })
        }

        fn receipts(
            &self,
            _state_fence: &StateFence,
            _protected_snapshot_digest: &str,
        ) -> Result<Vec<WriteReceipt>, KernelPortError> {
            Ok(self.receipts.clone())
        }

        fn durable_jobs(
            &self,
            _state_fence: &StateFence,
            _protected_snapshot_digest: &str,
        ) -> Result<Vec<MaintenanceJob>, KernelPortError> {
            Ok(Vec::new())
        }
    }

    impl KernelServiceObservationPort for FakeKernel {
        fn services(
            &self,
            state_fence: &StateFence,
            _protected_snapshot_digest: &str,
        ) -> Result<Vec<KernelServiceRecovery>, KernelPortError> {
            if self.service_failure {
                return Err(KernelPortError::Unknown(
                    "test service observation failure".to_owned(),
                ));
            }
            Ok(self
                .service_observations
                .clone()
                .unwrap_or_else(|| service_observations(state_fence)))
        }
    }

    impl KernelDurableJobPort for FakeKernel {
        fn load_durable_job(
            &self,
            _job_id: &str,
            _state_fence: &StateFence,
        ) -> Result<Option<MaintenanceJob>, KernelPortError> {
            Ok(None)
        }

        fn save_durable_job(&self, _job: &MaintenanceJob) -> Result<(), KernelPortError> {
            Ok(())
        }
    }

    fn snapshot() -> KernelGenerationSnapshot {
        KernelGenerationSnapshot {
            service: "eliot-kernel".to_owned(),
            protocol: "eliot.kernel.v1".to_owned(),
            generation: ResourceGeneration::genesis(),
            authority_epoch: test_epoch(TEST_LINEAGE_A, 1),
            artifact_digest: "a".repeat(64),
            protected_snapshot_digest: "b".repeat(64),
            principal: "S-1-5-18".to_owned(),
        }
    }

    fn fake_kernel(snapshot: KernelGenerationSnapshot) -> FakeKernel {
        FakeKernel {
            snapshot,
            payloads: BTreeMap::new(),
            live_reads: Mutex::new(BTreeMap::new()),
            staged_scopes: Mutex::new(Vec::new()),
            receipts: Vec::new(),
            committed: Mutex::new(BTreeMap::new()),
            apply_calls: Mutex::new(0),
            missing: None,
            genesis_all_absent: false,
            genesis_seeded: Arc::new(AtomicBool::new(false)),
            service_observations: None,
            service_failure: false,
        }
    }

    fn service_observations(state_fence: &StateFence) -> Vec<KernelServiceRecovery> {
        STARTUP_ORDER
            .into_iter()
            .map(|service| KernelServiceRecovery {
                service,
                observation: ServiceObservation {
                    state: ServiceProcessState::Ready,
                    health: HealthVector::healthy(),
                    generation: state_fence.resource_generation,
                    authority_epoch: state_fence.authority_epoch.clone(),
                },
            })
            .collect()
    }

    fn canonical_scope(state_fence: &StateFence) -> ScopeRevisionView {
        ScopeRevisionView {
            scope_id: ScopeId::new("governor").expect("scope"),
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            state_fence: state_fence.clone(),
        }
    }

    fn owner_payload(
        owner: RecoveryOwner,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Vec<u8> {
        let value = match owner {
            RecoveryOwner::WorkScope | RecoveryOwner::Maintenance => {
                serde_json::to_value(EmptyOwnerSnapshot {
                    state_fence: state_fence.clone(),
                    revision: 1,
                })
            }
            RecoveryOwner::Canonical => serde_json::to_value(CanonicalAdmissionSnapshot {
                state_fence: state_fence.clone(),
                owner_revision: 1,
                current_plan: None,
                verifier_execution_fact: None,
                finish_evidence: None,
            }),
            RecoveryOwner::Task => serde_json::to_value(TaskLifecycleSnapshot {
                next_sequence: 1,
                tasks: BTreeMap::new(),
                events: Vec::new(),
                professional_execution: BTreeMap::new(),
            }),
            RecoveryOwner::Session => serde_json::to_value(SessionLifecycleSnapshot {
                next_sequence: 1,
                sessions: BTreeMap::new(),
                events: Vec::new(),
            }),
            RecoveryOwner::Authority => {
                let grant_graph = eliot_authority::GrantGraph::from_grants(std::iter::empty(), 1)
                    .and_then(|graph| graph.recovery_snapshot())
                    .expect("empty grant graph snapshot");
                let effect_authorizer = eliot_authority::EffectAuthorizer::default()
                    .snapshot()
                    .expect("empty effect authorizer snapshot");
                serde_json::to_value(
                    AuthorityOwnerSnapshot::new(
                        state_fence.clone(),
                        grant_graph,
                        effect_authorizer,
                    )
                    .expect("empty authority snapshot"),
                )
            }
            RecoveryOwner::Budget => {
                serde_json::to_value(BudgetOwnerSnapshot::unconfigured(state_fence.clone(), 1))
            }
            RecoveryOwner::Config => serde_json::to_value(ConfigOwnerSnapshot {
                state_fence: state_fence.clone(),
                revision: 1,
                config_digest: protected_snapshot_digest.to_owned(),
            }),
            RecoveryOwner::Coordination => serde_json::to_value(CoordinationOwner::new()),
            RecoveryOwner::Finish => serde_json::to_value(Vec::<FinishDecisionReceipt>::new()),
            RecoveryOwner::Problem => serde_json::to_value(ProblemOwnerSnapshot {
                state_fence: state_fence.clone(),
                revisions: BTreeMap::new(),
            }),
            RecoveryOwner::Observation => {
                serde_json::to_value(Vec::<ObservationJournalEntry>::new())
            }
            RecoveryOwner::Read => serde_json::to_value(ReadOwnerSnapshot {
                state_fence: state_fence.clone(),
                revision: 1,
            }),
            RecoveryOwner::Skill => serde_json::to_value(Vec::<SkillLifecycleView>::new()),
            RecoveryOwner::ModuleRegistry => serde_json::to_value(
                ModuleCatalog::new(state_fence.clone())
                    .expect("module")
                    .snapshot()
                    .expect("module snapshot"),
            ),
            RecoveryOwner::ChangeMonitor => {
                serde_json::to_value(eliot_change_monitor::ChangeMonitorSnapshot::default())
            }
            RecoveryOwner::Policy => serde_json::to_value(policy_owner_snapshot(state_fence)),
        }
        .expect("owner payload");
        canonical_json_bytes(&value).expect("owner payload bytes")
    }

    /// Builds the valid Policy owner snapshot the fake serves by default.
    ///
    /// Test-only canonical source: a complete normative snapshot bound to
    /// the request fence with revision 1. Tests for the absent path drop
    /// the read through `missing`/`live_reads` instead.
    fn policy_owner_snapshot(state_fence: &StateFence) -> PolicyOwnerSnapshot {
        let snapshot = eliot_config::ConfigPolicySnapshot {
            snapshot_id: "policy-snapshot-1".to_owned(),
            machine_id: "policy-machine".to_owned(),
            scope_id: "governor".to_owned(),
            revision: eliot_contracts::PolicyRevision::new(1).expect("policy revision"),
            source_completeness: eliot_config::SourceCompleteness::Complete,
            settings: vec![eliot_config::Setting {
                key: "mode".to_owned(),
                value_ref: "ref:mode".to_owned(),
                owner_ref: "human-1".to_owned(),
            }],
            policy_owner: eliot_config::HumanOwner {
                owner_ref: "human-1".to_owned(),
            },
            policy_fence: eliot_security_contracts::PolicyFence {
                policy_snapshot_id: "policy-snapshot-1".to_owned(),
                state_fence: state_fence.clone(),
            },
            state_fence: state_fence.clone(),
            parent_snapshot_id: None,
            rollback_of: None,
        };
        let policy_digest =
            sha256_hex(&canonical_json_bytes(&snapshot).expect("policy snapshot bytes"));
        PolicyOwnerSnapshot {
            state_fence: state_fence.clone(),
            revision: 1,
            policy_digest,
            snapshot,
        }
    }

    fn activation_canonical_snapshot(fence: &StateFence) -> CanonicalAdmissionSnapshot {
        CanonicalAdmissionSnapshot {
            state_fence: fence.clone(),
            owner_revision: 1,
            current_plan: Some(CanonicalPlanBinding {
                plan_id: "plan:current".to_owned(),
                plan_revision: "1".to_owned(),
                task_id: TaskId::new("task-1").expect("task id"),
                work_scope_id: "scope:work".to_owned(),
                verifier: CanonicalVerifierPlanState::default(),
            }),
            verifier_execution_fact: None,
            finish_evidence: None,
        }
    }

    fn activation_task_snapshot(fence: &StateFence) -> TaskLifecycleSnapshot {
        let task_id = TaskId::new("task-1").expect("task id");
        TaskLifecycleSnapshot {
            next_sequence: 2,
            tasks: BTreeMap::from([(
                task_id.clone(),
                TaskRecord {
                    task_id: task_id.clone(),
                    project_ref: "project-1".to_owned(),
                    goal: "activate me".to_owned(),
                    state: TaskState::ActionAuthorized,
                    revision: 1,
                    last_sequence: 1,
                    last_event_id: "task-event-1".to_owned(),
                    state_fence: fence.clone(),
                },
            )]),
            events: vec![TaskLifecycleEvent {
                sequence: 1,
                event_id: "task-event-1".to_owned(),
                request_id: "task-request-1".to_owned(),
                task_id,
                actor_ref: "agent-1".to_owned(),
                from: None,
                to: TaskState::ActionAuthorized,
                command: None,
                professional_execution: None,
                state_fence: fence.clone(),
                authority_epoch: fence.authority_epoch.clone(),
                observed_at: ClockReading::default(),
            }],
            professional_execution: BTreeMap::new(),
        }
    }

    fn activation_coordination_snapshot(
        fence: &StateFence,
    ) -> eliot_coordination::CoordinationOwner {
        let mut owner = eliot_coordination::CoordinationOwner::new();
        owner
            .register_session(CoordinationRegisterSession {
                request_id: "coord-session-request".to_owned(),
                session_id: "session-1".to_owned(),
                principal_id: "principal-1".to_owned(),
                route_ref: "route-1".to_owned(),
                authority_epoch: fence.authority_epoch.clone(),
                state_fence: fence.clone(),
                now: 1,
                heartbeat_deadline: 100,
            })
            .expect("coordination session");
        owner
            .register_work(
                WorkItem {
                    work_item_id: "work-1".to_owned(),
                    task_id: "task-1".to_owned(),
                    state: WorkState::Ready,
                    state_fence: fence.clone(),
                    owner_session_id: None,
                    lease_id: None,
                    attempt: 0,
                    checkpoint_ref: None,
                    result_ref: None,
                },
                "coord-work-request",
                "principal-1",
                ClockReading::default(),
            )
            .expect("coordination work");
        owner
            .acquire_work(WorkLeaseRequest {
                request_id: "coord-lease-request".to_owned(),
                lease_id: "lease-1".to_owned(),
                work_item_id: "work-1".to_owned(),
                session_id: "session-1".to_owned(),
                authority_epoch: fence.authority_epoch.clone(),
                state_fence: fence.clone(),
                now: 2,
                lease_duration: 40,
            })
            .expect("coordination lease");
        owner
    }

    fn activation_ambiguous_coordination_snapshot(
        fence: &StateFence,
    ) -> eliot_coordination::CoordinationOwner {
        let mut owner = activation_coordination_snapshot(fence);
        owner
            .register_session(CoordinationRegisterSession {
                request_id: "coord-session-request-2".to_owned(),
                session_id: "session-2".to_owned(),
                principal_id: "principal-2".to_owned(),
                route_ref: "route-2".to_owned(),
                authority_epoch: fence.authority_epoch.clone(),
                state_fence: fence.clone(),
                now: 1,
                heartbeat_deadline: 100,
            })
            .expect("second coordination session");
        owner
            .register_work(
                WorkItem {
                    work_item_id: "work-2".to_owned(),
                    task_id: "task-2".to_owned(),
                    state: WorkState::Ready,
                    state_fence: fence.clone(),
                    owner_session_id: None,
                    lease_id: None,
                    attempt: 0,
                    checkpoint_ref: None,
                    result_ref: None,
                },
                "coord-work-request-2",
                "principal-2",
                ClockReading::default(),
            )
            .expect("second coordination work");
        owner
            .acquire_work(WorkLeaseRequest {
                request_id: "coord-lease-request-2".to_owned(),
                lease_id: "lease-2".to_owned(),
                work_item_id: "work-2".to_owned(),
                session_id: "session-2".to_owned(),
                authority_epoch: fence.authority_epoch.clone(),
                state_fence: fence.clone(),
                now: 2,
                lease_duration: 40,
            })
            .expect("second coordination lease");
        owner
    }

    fn activation_session_snapshot(fence: &StateFence) -> SessionLifecycleSnapshot {
        let mut owner = SessionLifecycleOwner::new(fence.authority_epoch.clone(), fence.clone())
            .expect("session owner");
        let session_id = SessionId::new("session-1").expect("session id");
        owner
            .register(RegisterSession {
                request_id: "session-request-1".to_owned(),
                event_id: "session-event-1".to_owned(),
                session_id: session_id.clone(),
                agent_id: "agent-1".to_owned(),
                model_route: "route-1".to_owned(),
                harness: "harness-1".to_owned(),
                role: "worker".to_owned(),
                project_scope: "scope-1".to_owned(),
                task_scope: Some("task-1".to_owned()),
                capability_profile_id: "profile-1".to_owned(),
                parent_session_id: None,
                policy_snapshot_id: "policy-1".to_owned(),
                authority_epoch: fence.authority_epoch.clone(),
                state_fence: fence.clone(),
                now: 1,
                expires_at: 100,
            })
            .expect("session register");
        owner
            .apply(
                session_id,
                SessionCommandContext {
                    request_id: "session-activate-request".to_owned(),
                    event_id: "session-activate-event".to_owned(),
                    actor_ref: "agent-1".to_owned(),
                    state_fence: fence.clone(),
                    authority_epoch: fence.authority_epoch.clone(),
                    observed_at: ClockReading::default(),
                    now: 2,
                },
                SessionCommand::Activate,
            )
            .expect("session activate");
        owner.snapshot()
    }

    fn activation_scope_snapshot(fence: &StateFence) -> eliot_workscope::WorkScopeBindingSnapshot {
        serde_json::from_value(serde_json::json!({
            "state_fence": fence,
            "owner_revision": 1,
            "binding": {
                "scope": {
                    "scope_ref": "scope:work",
                    "kind": "git_repo",
                    "lineage_ref": "lineage:work",
                    "instance_ref": "instance:work",
                    "root_identity": "root:work",
                    "generation": 1
                },
                "privacy_class": "INTERNAL",
                "governing_source_generation": 1
            },
            "guard_receipt": {
                "expected_scope_ref": "scope:work",
                "observed_scope_ref": "scope:work",
                "expected_lineage_ref": "lineage:work",
                "observed_lineage_ref": "lineage:work",
                "expected_instance_ref": "instance:work",
                "observed_instance_ref": "instance:work",
                "disposition": "MATCHED",
                "source_generation": 1
            }
        }))
        .expect("work scope binding")
    }

    fn activation_fake(observed: &KernelGenerationSnapshot) -> FakeKernel {
        let fence = observed.state_fence();
        let mut fake = fake_kernel(observed.clone());
        fake.payloads.insert(
            RecoveryOwner::Coordination,
            canonical_json_bytes(&activation_coordination_snapshot(&fence))
                .expect("coordination bytes"),
        );
        fake.payloads.insert(
            RecoveryOwner::Session,
            canonical_json_bytes(&activation_session_snapshot(&fence)).expect("session bytes"),
        );
        fake.payloads.insert(
            RecoveryOwner::Task,
            canonical_json_bytes(&activation_task_snapshot(&fence)).expect("task bytes"),
        );
        fake.payloads.insert(
            RecoveryOwner::WorkScope,
            canonical_json_bytes(&activation_scope_snapshot(&fence)).expect("scope bytes"),
        );
        fake.payloads.insert(
            RecoveryOwner::Canonical,
            canonical_json_bytes(&activation_canonical_snapshot(&fence)).expect("canonical bytes"),
        );
        fake
    }

    #[test]
    fn owner_set_has_one_identity_per_owner() {
        let ids = OWNER_IDS;
        let unique: BTreeSet<_> = ids.into_iter().collect();
        assert_eq!(ids.len(), 16);
        assert_eq!(unique.len(), ids.len());
    }

    #[test]
    fn policy_owner_recovers_with_fence_revision_digest_correlation() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let composition = GovernorComposition::new(
            Arc::new(fake_kernel(observed.clone())),
            None,
            &expected,
            QueueLimits::default(),
        )
        .expect("composition");
        let policy = composition.owners().policy.as_ref().expect("policy owner");
        assert_eq!(policy.state_fence(), &observed.state_fence());
        assert_eq!(policy.revision(), 1);
        assert_eq!(
            policy.snapshot().snapshot_id,
            "policy-snapshot-1",
            "policy content comes from the recovered canonical snapshot"
        );
        let rebuilt = policy.rebuilt_digest().expect("rebuilt digest");
        assert_eq!(
            rebuilt,
            policy.snapshot_digest(),
            "live recomputation reproduces the recovery-bound digest"
        );
        let reply = composition
            .recovery()
            .policy_read
            .as_ref()
            .expect("policy read");
        assert_eq!(policy.canonical_digest(), reply.value_digest);
        assert_ne!(
            policy.canonical_digest(),
            composition.owners().config.snapshot_digest(),
            "policy evidence is never a relabeled config digest"
        );
    }

    #[test]
    fn absent_policy_read_leaves_explicit_unconfigured() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = fake_kernel(observed);
        fake.missing = Some(RecoveryOwner::Policy);
        let composition =
            GovernorComposition::new(Arc::new(fake), None, &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.owners().policy.is_none());
        assert!(composition.recovery().policy_read.is_none());
        assert_eq!(composition.readiness(), CompositionReadiness::Ready);
    }

    #[test]
    fn tampered_policy_digest_fails_recovery() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut wire = policy_owner_snapshot(&observed.state_fence());
        wire.policy_digest = "0".repeat(64);
        let mut fake = fake_kernel(observed);
        fake.payloads.insert(
            RecoveryOwner::Policy,
            canonical_json_bytes(&wire).expect("policy bytes"),
        );
        let result =
            GovernorComposition::new(Arc::new(fake), None, &expected, QueueLimits::default());
        assert!(matches!(result, Err(CompositionError::Recovery(_))));
    }

    #[test]
    fn provider_mismatch_is_rejected_before_owner_construction() {
        let observed = snapshot();
        let mut expected =
            KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        expected.authority_epoch = test_epoch(TEST_LINEAGE_A, 2);
        let provider = Arc::new(fake_kernel(observed));
        let result = GovernorComposition::new(provider, None, &expected, QueueLimits::default());
        assert!(matches!(result, Err(CompositionError::Provider(_))));
    }

    #[test]
    fn kernel_recovery_is_ready_and_start_order_is_fixed() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = fake_kernel(observed.clone());
        fake.payloads.insert(
            RecoveryOwner::Canonical,
            canonical_json_bytes(&activation_canonical_snapshot(&observed.state_fence()))
                .expect("canonical bytes"),
        );
        let provider = Arc::new(fake);
        let composition =
            GovernorComposition::new(provider, None, &expected, QueueLimits::default())
                .expect("composition");
        assert_eq!(composition.readiness(), CompositionReadiness::Ready);
        assert_eq!(STARTUP_ORDER[0], ServiceId::Config);
        assert_eq!(STARTUP_ORDER[15], ServiceId::Maintenance);
        let mut plan = composition
            .owners()
            .canonical
            .read_current_plan(&observed.state_fence())
            .expect("current canonical plan");
        assert_eq!(plan.plan_id, "plan:current");
        plan.plan_revision = "2".to_owned();
        assert_eq!(
            composition
                .owners()
                .canonical
                .read_current_plan(&observed.state_fence())
                .expect("current canonical plan")
                .plan_revision,
            "1"
        );
    }

    #[test]
    fn owner_recovery_snapshot_and_digest_exclude_service_observations() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let first = GovernorComposition::new(
            Arc::new(fake_kernel(observed.clone())),
            None,
            &expected,
            QueueLimits::default(),
        )
        .expect("first composition");

        let mut second_fake = fake_kernel(observed.clone());
        let mut reversed = service_observations(&observed.state_fence());
        reversed.reverse();
        second_fake.service_observations = Some(reversed);
        let second = GovernorComposition::new(
            Arc::new(second_fake),
            None,
            &expected,
            QueueLimits::default(),
        )
        .expect("second composition");

        assert_ne!(first.service_observations(), second.service_observations());
        assert_eq!(first.recovery(), second.recovery());
        let first_digest = sha256_hex(&serde_json::to_vec(first.recovery()).expect("recovery"));
        let second_digest = sha256_hex(&serde_json::to_vec(second.recovery()).expect("recovery"));
        assert_eq!(first_digest, second_digest);
        let encoded = serde_json::to_value(first.recovery()).expect("recovery JSON");
        assert!(encoded.get("services").is_none());
    }

    #[test]
    fn service_observation_failure_blocks_readiness() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = fake_kernel(observed);
        fake.service_failure = true;
        let result =
            GovernorComposition::new(Arc::new(fake), None, &expected, QueueLimits::default());
        assert!(matches!(result, Err(CompositionError::Recovery(_))));
    }

    #[test]
    fn canonical_owner_rejects_invalid_plan_and_fence_bindings() {
        let observed = snapshot();
        let active_fence = observed.state_fence();
        let scope = canonical_scope(&active_fence);
        let valid_plan = CanonicalPlanBinding::new(
            "plan:current",
            "1",
            TaskId::new("task-1").expect("task id"),
            "scope:work",
        )
        .expect("plan");
        let valid_snapshot =
            CanonicalAdmissionSnapshot::new(active_fence.clone(), 1, Some(valid_plan.clone()))
                .expect("snapshot");
        let owner = CanonicalAdmissionOwner::new(
            active_fence.clone(),
            scope.clone(),
            valid_snapshot.clone(),
        )
        .expect("owner");

        let stale_fence = StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::new(2).expect("resource generation"),
        );
        assert!(owner.read_current_plan(&stale_fence).is_err());
        let stale_snapshot =
            CanonicalAdmissionSnapshot::new(stale_fence.clone(), 1, Some(valid_plan.clone()))
                .expect("stale snapshot");
        assert!(
            CanonicalAdmissionOwner::new(active_fence.clone(), scope.clone(), stale_snapshot)
                .is_err()
        );
        assert!(
            CanonicalAdmissionOwner::new(stale_fence, scope.clone(), valid_snapshot.clone())
                .is_err()
        );

        let mut stale_scope = scope;
        stale_scope.state_fence = StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::new(2).expect("resource generation"),
        );
        assert!(
            CanonicalAdmissionOwner::new(active_fence.clone(), stale_scope, valid_snapshot)
                .is_err()
        );

        assert!(
            CanonicalPlanBinding::new(
                "",
                "1",
                TaskId::new("task-1").expect("task id"),
                "scope:work"
            )
            .is_err()
        );
        assert!(
            CanonicalPlanBinding::new(
                "plan:current\n",
                "1",
                TaskId::new("task-1").expect("task id"),
                "scope:work"
            )
            .is_err()
        );
        assert!(
            CanonicalPlanBinding::new(
                "plan:current",
                "",
                TaskId::new("task-1").expect("task id"),
                "scope:work"
            )
            .is_err()
        );
        assert!(
            CanonicalPlanBinding::new(
                "plan:current",
                "revision\n1",
                TaskId::new("task-1").expect("task id"),
                "scope:work"
            )
            .is_err()
        );
        assert!(
            CanonicalPlanBinding::new(
                "plan:current",
                "1",
                TaskId::new("task-1").expect("task id"),
                ""
            )
            .is_err()
        );
        assert!(CanonicalAdmissionSnapshot::new(active_fence, 0, Some(valid_plan),).is_err());
    }

    #[test]
    fn canonical_genesis_null_deserializes_validates_and_denies_activation() {
        let observed = snapshot();
        let payload = owner_payload(
            RecoveryOwner::Canonical,
            &observed.state_fence(),
            &observed.protected_snapshot_digest,
        );
        let decoded: CanonicalAdmissionSnapshot =
            serde_json::from_slice(&payload).expect("genesis canonical payload");
        assert_eq!(decoded.current_plan, None);
        decoded.validate().expect("genesis null snapshot");
        assert_eq!(
            payload,
            canonical_json_bytes(&decoded).expect("canonical genesis payload bytes")
        );

        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = activation_fake(&observed);
        fake.payloads.insert(RecoveryOwner::Canonical, payload);
        let composition =
            GovernorComposition::new(Arc::new(fake), None, &expected, QueueLimits::default())
                .expect("genesis null is recoverable");
        assert!(matches!(
            composition.read_unique_agent_activation(20),
            Err(CompositionError::Recovery(message))
                if message.contains("canonical current plan is absent")
        ));
    }

    #[test]
    fn canonical_recovery_rejects_the_old_empty_owner_snapshot() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = fake_kernel(observed.clone());
        let payload = canonical_json_bytes(&EmptyOwnerSnapshot {
            state_fence: observed.state_fence().clone(),
            revision: 1,
        })
        .expect("old canonical payload");
        fake.payloads.insert(RecoveryOwner::Canonical, payload);
        let result =
            GovernorComposition::new(Arc::new(fake), None, &expected, QueueLimits::default());
        assert!(matches!(result, Err(CompositionError::Recovery(_))));

        let mut legacy = fake_kernel(observed.clone());
        let legacy_unscoped = serde_json::json!({
            "state_fence": observed.state_fence(),
            "owner_revision": 1,
            "current_plan": {
                "plan_id": "plan:current",
                "plan_revision": "1"
            }
        });
        legacy.payloads.insert(
            RecoveryOwner::Canonical,
            serde_json::to_vec(&legacy_unscoped).expect("legacy canonical payload"),
        );
        let result =
            GovernorComposition::new(Arc::new(legacy), None, &expected, QueueLimits::default());
        assert!(matches!(result, Err(CompositionError::Recovery(_))));
    }

    #[test]
    fn first_boot_requires_and_rechecks_atomic_genesis_seed() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = fake_kernel(observed);
        fake.genesis_all_absent = true;
        let seeded = Arc::clone(&fake.genesis_seeded);
        let composition =
            GovernorComposition::new(Arc::new(fake), None, &expected, QueueLimits::default())
                .expect("genesis composition");
        assert!(seeded.load(Ordering::Acquire));
        assert_eq!(composition.readiness(), CompositionReadiness::Ready);
        assert_eq!(
            composition.recovery().owner_reads.len(),
            RecoveryOwner::ALL.len()
        );
    }

    #[test]
    fn restart_rehydrates_nonempty_task_and_session_snapshots() {
        let observed = snapshot();
        let fence = observed.state_fence();
        let mut task =
            TaskLifecycleOwner::new(fence.authority_epoch.clone(), fence.clone()).expect("task");
        let task_snapshot = {
            task.propose(TaskProposal {
                task_id: TaskId::new("task-1").expect("task id"),
                project_ref: "project-1".to_owned(),
                goal: "recover me".to_owned(),
                context: TaskCommandContext {
                    request_id: "task-request-1".to_owned(),
                    event_id: "task-event-1".to_owned(),
                    actor_ref: "actor-1".to_owned(),
                    state_fence: fence.clone(),
                    authority_epoch: fence.authority_epoch.clone(),
                    observed_at: ClockReading::default(),
                },
            })
            .expect("task proposal");
            task.snapshot()
        };
        let mut session = SessionLifecycleOwner::new(fence.authority_epoch.clone(), fence.clone())
            .expect("session");
        let session_snapshot = {
            session
                .register(RegisterSession {
                    request_id: "session-request-1".to_owned(),
                    event_id: "session-event-1".to_owned(),
                    session_id: SessionId::new("session-1").expect("session id"),
                    agent_id: "agent-1".to_owned(),
                    model_route: "route-1".to_owned(),
                    harness: "harness-1".to_owned(),
                    role: "worker".to_owned(),
                    project_scope: "scope-1".to_owned(),
                    task_scope: None,
                    capability_profile_id: "profile-1".to_owned(),
                    parent_session_id: None,
                    policy_snapshot_id: "policy-1".to_owned(),
                    authority_epoch: fence.authority_epoch.clone(),
                    state_fence: fence.clone(),
                    now: 1,
                    expires_at: 10,
                })
                .expect("session register");
            session.snapshot()
        };
        let mut fake = fake_kernel(observed.clone());
        fake.payloads.insert(
            RecoveryOwner::Task,
            canonical_json_bytes(&task_snapshot).expect("task bytes"),
        );
        fake.payloads.insert(
            RecoveryOwner::Session,
            canonical_json_bytes(&session_snapshot).expect("session bytes"),
        );
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let composition =
            GovernorComposition::new(Arc::new(fake), None, &expected, QueueLimits::default())
                .expect("composition");
        assert_eq!(composition.owners().task.snapshot(), task_snapshot);
        assert_eq!(composition.owners().session.snapshot(), session_snapshot);
    }

    #[test]
    fn unique_agent_activation_requires_and_returns_one_coherent_clone() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let composition = GovernorComposition::new(
            Arc::new(activation_fake(&observed)),
            None,
            &expected,
            QueueLimits::default(),
        )
        .expect("coherent composition");

        let first = composition
            .read_unique_agent_activation(20)
            .expect("activation");
        assert_eq!(first.principal_id, "principal-1");
        assert_eq!(first.session_id, "session-1");
        assert_eq!(first.task_id, TaskId::new("task-1").expect("task id"));
        assert_eq!(first.work_unit_id, "work-1");
        assert_eq!(first.work_scope_id, "scope:work");
        assert_eq!(first.plan_id, "plan:current");
        assert_eq!(first.plan_revision, "1");
        assert_eq!(
            first,
            composition.read_unique_agent_activation(20).expect("clone")
        );
    }

    #[test]
    fn activation_rejects_missing_or_invalid_lifecycle_session() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");

        let mut missing = activation_fake(&observed);
        missing.payloads.remove(&RecoveryOwner::Session);
        let composition =
            GovernorComposition::new(Arc::new(missing), None, &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());

        let mut inactive_snapshot = activation_session_snapshot(&observed.state_fence());
        inactive_snapshot
            .sessions
            .get_mut(&SessionId::new("session-1").expect("session id"))
            .expect("session")
            .status = eliot_session::SessionState::Idle;
        let mut inactive = activation_fake(&observed);
        inactive.payloads.insert(
            RecoveryOwner::Session,
            canonical_json_bytes(&inactive_snapshot).expect("inactive session bytes"),
        );
        let composition =
            GovernorComposition::new(Arc::new(inactive), None, &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());

        let mut expired_snapshot = activation_session_snapshot(&observed.state_fence());
        expired_snapshot
            .sessions
            .get_mut(&SessionId::new("session-1").expect("session id"))
            .expect("session")
            .expires_at = 10;
        let mut expired = activation_fake(&observed);
        expired.payloads.insert(
            RecoveryOwner::Session,
            canonical_json_bytes(&expired_snapshot).expect("expired session bytes"),
        );
        let composition =
            GovernorComposition::new(Arc::new(expired), None, &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());
    }

    #[test]
    fn recovery_rejects_malformed_coordination_heartbeat_before_readiness() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let valid = GovernorComposition::new(
            Arc::new(activation_fake(&observed)),
            None,
            &expected,
            QueueLimits::default(),
        )
        .expect("valid coordination heartbeat");
        assert!(valid.read_unique_agent_activation(20).is_ok());

        let mut malformed_owner = activation_fake(&observed);
        let mut coordination: serde_json::Value = serde_json::from_slice(
            malformed_owner
                .payloads
                .get(&RecoveryOwner::Coordination)
                .expect("coordination payload"),
        )
        .expect("coordination snapshot");
        coordination["work"]["work-1"]["owner_session_id"] =
            serde_json::Value::String("missing-session".to_owned());
        malformed_owner.payloads.insert(
            RecoveryOwner::Coordination,
            canonical_json_bytes(&coordination).expect("coordination bytes"),
        );
        assert!(
            GovernorComposition::new(
                Arc::new(malformed_owner),
                None,
                &expected,
                QueueLimits::default()
            )
            .is_err(),
            "recovery accepted an active work item with a missing session"
        );

        for (name, field, value) in [
            ("zero deadline", "heartbeat_deadline", 0),
            ("heartbeat after deadline", "last_heartbeat", 101),
        ] {
            let mut fake = activation_fake(&observed);
            let mut coordination: serde_json::Value = serde_json::from_slice(
                fake.payloads
                    .get(&RecoveryOwner::Coordination)
                    .expect("coordination payload"),
            )
            .expect("coordination snapshot");
            coordination["sessions"]["session-1"][field] = serde_json::Value::from(value);
            fake.payloads.insert(
                RecoveryOwner::Coordination,
                canonical_json_bytes(&coordination).expect("coordination bytes"),
            );
            assert!(
                GovernorComposition::new(Arc::new(fake), None, &expected, QueueLimits::default())
                    .is_err(),
                "recovery accepted {name}"
            );
        }
    }

    #[test]
    fn activation_rejects_session_scope_and_fence_disagreement() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");

        let mut scoped_snapshot = activation_session_snapshot(&observed.state_fence());
        scoped_snapshot
            .sessions
            .get_mut(&SessionId::new("session-1").expect("session id"))
            .expect("session")
            .task_scope = Some("task-other".to_owned());
        let mut scoped = activation_fake(&observed);
        scoped.payloads.insert(
            RecoveryOwner::Session,
            canonical_json_bytes(&scoped_snapshot).expect("scoped session bytes"),
        );
        let composition =
            GovernorComposition::new(Arc::new(scoped), None, &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());

        let stale_fence = StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::new(2).expect("generation"),
        );
        let mut stale_scope = activation_scope_snapshot(&stale_fence);
        stale_scope.state_fence = stale_fence;
        let mut stale = activation_fake(&observed);
        stale.payloads.insert(
            RecoveryOwner::WorkScope,
            canonical_json_bytes(&stale_scope).expect("stale scope bytes"),
        );
        assert!(
            GovernorComposition::new(Arc::new(stale), None, &expected, QueueLimits::default(),)
                .is_err()
        );

        let mut stale_task = activation_task_snapshot(&observed.state_fence());
        stale_task
            .tasks
            .get_mut(&TaskId::new("task-1").expect("task id"))
            .expect("task")
            .state_fence = StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::new(2).expect("generation"),
        );
        let mut stale_task_fake = activation_fake(&observed);
        stale_task_fake.payloads.insert(
            RecoveryOwner::Task,
            canonical_json_bytes(&stale_task).expect("stale task bytes"),
        );
        assert!(
            GovernorComposition::new(
                Arc::new(stale_task_fake),
                None,
                &expected,
                QueueLimits::default(),
            )
            .is_err()
        );

        let mut stale_session = activation_session_snapshot(&observed.state_fence());
        stale_session
            .sessions
            .get_mut(&SessionId::new("session-1").expect("session id"))
            .expect("session")
            .state_fence = StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::new(2).expect("generation"),
        );
        let mut stale_session_fake = activation_fake(&observed);
        stale_session_fake.payloads.insert(
            RecoveryOwner::Session,
            canonical_json_bytes(&stale_session).expect("stale session bytes"),
        );
        assert!(
            GovernorComposition::new(
                Arc::new(stale_session_fake),
                None,
                &expected,
                QueueLimits::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn activation_rejects_non_actionable_task_and_canonical_join_mismatch() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");

        let mut terminal_snapshot = activation_task_snapshot(&observed.state_fence());
        terminal_snapshot
            .tasks
            .get_mut(&TaskId::new("task-1").expect("task id"))
            .expect("task")
            .state = TaskState::DoneVerified;
        let mut terminal = activation_fake(&observed);
        terminal.payloads.insert(
            RecoveryOwner::Task,
            canonical_json_bytes(&terminal_snapshot).expect("terminal task bytes"),
        );
        let composition =
            GovernorComposition::new(Arc::new(terminal), None, &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());

        let mismatched_plan = CanonicalAdmissionSnapshot {
            state_fence: observed.state_fence(),
            owner_revision: 1,
            current_plan: Some(CanonicalPlanBinding {
                plan_id: "plan:current".to_owned(),
                plan_revision: "1".to_owned(),
                task_id: TaskId::new("task-other").expect("task id"),
                work_scope_id: "scope:work".to_owned(),
                verifier: CanonicalVerifierPlanState::default(),
            }),
            verifier_execution_fact: None,
            finish_evidence: None,
        };
        mismatched_plan.validate().expect("plan shape");
        let mut mismatch = activation_fake(&observed);
        mismatch.payloads.insert(
            RecoveryOwner::Canonical,
            canonical_json_bytes(&mismatched_plan).expect("mismatched plan bytes"),
        );
        let composition =
            GovernorComposition::new(Arc::new(mismatch), None, &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());
    }

    #[test]
    fn activation_rejects_ambiguous_coordination_without_map_order_selection() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = activation_fake(&observed);
        fake.payloads.insert(
            RecoveryOwner::Coordination,
            canonical_json_bytes(&activation_ambiguous_coordination_snapshot(
                &observed.state_fence(),
            ))
            .expect("ambiguous coordination bytes"),
        );
        let composition =
            GovernorComposition::new(Arc::new(fake), None, &expected, QueueLimits::default())
                .expect("composition");
        assert!(composition.read_unique_agent_activation(20).is_err());
    }

    #[test]
    fn payload_digest_and_partial_owner_state_fail_closed() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = fake_kernel(observed.clone());
        let mut payload = owner_payload(
            RecoveryOwner::Task,
            &observed.state_fence(),
            &observed.protected_snapshot_digest,
        );
        payload.push(b'x');
        fake.payloads.insert(RecoveryOwner::Task, payload);
        let result =
            GovernorComposition::new(Arc::new(fake), None, &expected, QueueLimits::default());
        assert!(matches!(result, Err(CompositionError::Recovery(_))));

        let mut partial = fake_kernel(observed.clone());
        partial.missing = Some(RecoveryOwner::Task);
        let result =
            GovernorComposition::new(Arc::new(partial), None, &expected, QueueLimits::default());
        assert!(matches!(result, Err(CompositionError::Recovery(_))));
    }

    #[test]
    fn recovery_rejects_semantically_valid_noncanonical_owner_bytes() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let payloads = [
            br#"{"tasks":{},"next_sequence":1,"events":[]}"#.as_slice(),
            br#"{ "events": [], "next_sequence": 1, "tasks": {} }"#.as_slice(),
        ];
        for payload in payloads {
            let mut fake = fake_kernel(observed.clone());
            fake.payloads.insert(RecoveryOwner::Task, payload.to_vec());
            let result =
                GovernorComposition::new(Arc::new(fake), None, &expected, QueueLimits::default());
            assert!(matches!(
                result,
                Err(CompositionError::Recovery(message))
                    if message.contains("owner task payload is not canonical JSON")
            ));
        }
    }

    fn configured_budget_snapshot(fence: &StateFence) -> BudgetOwnerSnapshot {
        let authority = AuthorityBinding {
            authority_id: ContractId::new("authority:budget").expect("authority id"),
            authority_owner: "budget-owner".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect: EffectClass::ExternalEffect,
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
        };
        let ledger = BudgetLedger::new(
            BudgetEnvelope {
                envelope_id: "budget:configured".to_owned(),
                policy_snapshot_id: "policy:budget".to_owned(),
                applicability: Applicability::Applicable,
                automation_policy_ref: "automation:budget".to_owned(),
                cost_authority_ref: "authority:budget".to_owned(),
                provider_tool: ProviderToolAttribution {
                    provider_ref: "provider:test".to_owned(),
                    tool_ref: "tool:test".to_owned(),
                },
                max_cost_micros: Some(1_000),
                quota_windows: vec![eliot_budget::QuotaWindow {
                    window_id: "requests".to_owned(),
                    state: QuotaState::Known { remaining: 10 },
                    source_ref: "meter:test".to_owned(),
                    confidence_ref: "observed".to_owned(),
                    observed_at_unix_ms: 1,
                    reset_at_unix_ms: Some(2),
                }],
            },
            authority,
        )
        .expect("configured ledger");
        BudgetOwnerSnapshot {
            schema: BUDGET_OWNER_SNAPSHOT_SCHEMA.to_owned(),
            version: BUDGET_OWNER_SNAPSHOT_VERSION,
            state_fence: fence.clone(),
            revision: 2,
            state: BudgetOwnerState::Configured {
                ledger: Box::new(ledger.snapshot().expect("ledger snapshot")),
            },
        }
    }

    #[test]
    fn configured_budget_owner_roundtrips_exact_typed_ledger() {
        let observed = snapshot();
        let fence = observed.state_fence();
        let owner_snapshot = configured_budget_snapshot(&fence);
        let ledger = owner_snapshot
            .restore(&fence)
            .expect("restore configured owner")
            .expect("configured ledger");
        assert_eq!(
            ledger.snapshot().expect("restored ledger snapshot"),
            match &owner_snapshot.state {
                BudgetOwnerState::Configured { ledger } => (**ledger).clone(),
                BudgetOwnerState::Unconfigured => panic!("configured fixture"),
            }
        );
        let owner = BudgetOwner {
            state_fence: observed.state_fence().clone(),
            revision: owner_snapshot.revision,
            ledger: Some(ledger),
        };
        assert_eq!(owner.snapshot().expect("owner snapshot"), owner_snapshot);
    }

    #[test]
    fn budget_owner_recovery_rejects_fence_schema_and_unknown_field_substitution() {
        let observed = snapshot();
        let fence = observed.state_fence();
        let valid = configured_budget_snapshot(&fence);

        let mut stale_outer = valid.clone();
        stale_outer.state_fence.resource_generation =
            ResourceGeneration::new(2).expect("generation");
        assert!(stale_outer.restore(&fence).is_err());

        let mut stale_nested = valid.clone();
        if let BudgetOwnerState::Configured { ledger } = &mut stale_nested.state {
            ledger.authority.state_fence.resource_generation =
                ResourceGeneration::new(2).expect("generation");
        }
        assert!(stale_nested.restore(&fence).is_err());

        let mut zero_revision = valid.clone();
        zero_revision.revision = 0;
        assert!(zero_revision.restore(&fence).is_err());

        let mut wrong_schema = valid.clone();
        wrong_schema.schema.push_str("-substituted");
        assert!(wrong_schema.restore(&fence).is_err());
        let mut wrong_version = valid.clone();
        wrong_version.version = 2;
        assert!(wrong_version.restore(&fence).is_err());

        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = fake_kernel(observed.clone());
        let mut substituted_revision =
            serde_json::to_value(BudgetOwnerSnapshot::unconfigured(observed.state_fence(), 1))
                .expect("budget json");
        substituted_revision["revision"] = serde_json::json!(2);
        let payload = canonical_json_bytes(&substituted_revision).expect("budget bytes");
        fake.payloads.insert(RecoveryOwner::Budget, payload);
        assert!(
            GovernorComposition::new(Arc::new(fake), None, &expected, QueueLimits::default())
                .is_err()
        );

        let encoded = serde_json::to_value(valid).expect("budget json");
        let mut unknown_top = encoded.clone();
        unknown_top["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<BudgetOwnerSnapshot>(unknown_top).is_err());
        let mut unknown_state = encoded;
        unknown_state["state"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<BudgetOwnerSnapshot>(unknown_state).is_err());
    }

    #[test]
    fn governor_activation_outcome_is_typed_and_losslessly_distinguished() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let coherent = GovernorComposition::new(
            Arc::new(activation_fake(&observed)),
            None,
            &expected,
            QueueLimits::default(),
        )
        .expect("coherent");
        let outcome = coherent.resolve_activation_outcome(20);
        assert!(outcome.is_resolved());
        assert_eq!(outcome.kind_str(), "RESOLVED");

        // NotReady when readiness is not Ready — tested via direct outcome construction
        // plus classification helper. This ensures transient retry is never dropped.
        let not_ready =
            crate::activation_outcome::fixture_not_ready("governor.readiness", "rev-1", 30);
        assert!(not_ready.is_transient_retry());
        assert_eq!(not_ready.kind_str(), "NOT_READY");
    }

    #[test]
    fn governor_outcome_never_coerces_error_to_resolved() {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");

        // Ambiguous coordination must become ScopeAmbiguous, not Resolved.
        let mut ambiguous_fake = activation_fake(&observed);
        ambiguous_fake.payloads.insert(
            RecoveryOwner::Coordination,
            canonical_json_bytes(&activation_ambiguous_coordination_snapshot(
                &observed.state_fence(),
            ))
            .expect("ambiguous bytes"),
        );
        let ambiguous = GovernorComposition::new(
            Arc::new(ambiguous_fake),
            None,
            &expected,
            QueueLimits::default(),
        )
        .expect("ambiguous composition");
        let outcome = ambiguous.resolve_activation_outcome(20);
        assert!(!outcome.is_resolved());
        assert_eq!(outcome.kind_str(), "SCOPE_AMBIGUOUS");

        // Stale fence via task revision mismatch must not become Resolved either.
        // Use a fresh coherent composition but verify the classification of a
        // synthetic stale error is not Resolved.
        let stale = classify_activation_error(
            &CompositionError::Recovery(
                "task revision does not match the activation fence".to_owned(),
            ),
            20,
            "1:Ready",
        );
        assert_eq!(stale.kind_str(), "STALE_FENCE");
        assert!(!stale.is_resolved());

        // Any FailedInternal must stay FailedInternal, never TaskSelectionRequired.
        let failed = classify_activation_error(
            &CompositionError::Recovery(
                "session lifecycle record is not an exact active activation match".to_owned(),
            ),
            20,
            "1:Ready",
        );
        // This particular message is treated as FailedInternal by the classifier
        // (it does not match the narrow TaskSelection pattern), proving that
        // internal defects are not downgraded to user ambiguity.
        assert_eq!(failed.kind_str(), "FAILED_INTERNAL");
        assert!(!failed.is_resolved());
    }

    fn refresh_task_snapshot(fence: &StateFence, goal: &str) -> TaskLifecycleSnapshot {
        let mut task =
            TaskLifecycleOwner::new(fence.authority_epoch.clone(), fence.clone()).expect("task");
        task.propose(TaskProposal {
            task_id: TaskId::new("task-1").expect("task id"),
            project_ref: "project-1".to_owned(),
            goal: goal.to_owned(),
            context: TaskCommandContext {
                request_id: "task-request-1".to_owned(),
                event_id: "task-event-1".to_owned(),
                actor_ref: "actor-1".to_owned(),
                state_fence: fence.clone(),
                authority_epoch: fence.authority_epoch.clone(),
                observed_at: ClockReading::default(),
            },
        })
        .expect("task proposal");
        task.snapshot()
    }

    fn refresh_heads(
        fence: &StateFence,
        task_revision: u64,
        ordering_sequence: u64,
    ) -> ScopeRevisionView {
        ScopeRevisionView {
            scope_id: ScopeId::new("governor").expect("scope"),
            revision_heads: vec![RevisionHead {
                key: RevisionKey::new("task:task-1").expect("revision key"),
                revision: task_revision,
                state_fence: fence.clone(),
            }],
            ordering_heads: vec![OrderingHead {
                scope: OrderingScopeId::new("scope:governor").expect("ordering scope"),
                sequence: ordering_sequence,
                state_fence: fence.clone(),
            }],
            state_fence: fence.clone(),
        }
    }

    #[test]
    fn refresh_publishes_committed_owner_change_across_restart() {
        let observed = snapshot();
        let fence = observed.state_fence();
        let task_id = TaskId::new("task-1").expect("task id");
        let mut fake = fake_kernel(observed.clone());
        fake.payloads.insert(
            RecoveryOwner::Task,
            canonical_json_bytes(&refresh_task_snapshot(&fence, "goal before refresh"))
                .expect("task bytes"),
        );
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let kernel = Arc::new(fake);
        let mut composition =
            GovernorComposition::new(kernel.clone(), None, &expected, QueueLimits::default())
                .expect("composition");
        assert_eq!(
            composition.owners().task.task(&task_id).expect("task").goal,
            "goal before refresh"
        );
        // The Kernel commits a new task revision plus a new stable canonical
        // head set; both reads of one refresh observe the same heads.
        kernel.live_reads.lock().expect("live read lock").insert(
            RecoveryOwner::Task,
            Some(
                canonical_json_bytes(&refresh_task_snapshot(&fence, "goal after refresh"))
                    .expect("task bytes"),
            ),
        );
        let moved_heads = refresh_heads(&fence, 2, 2);
        kernel
            .staged_scopes
            .lock()
            .expect("staged scope lock")
            .push(moved_heads.clone());
        composition
            .refresh_from_kernel()
            .expect("refresh publishes the committed change");
        assert_eq!(
            composition.owners().task.task(&task_id).expect("task").goal,
            "goal after refresh"
        );
        assert_eq!(composition.recovery().canonical_scope, moved_heads);
        // A restart rehydrates the same committed state, proving the refreshed
        // projection was Kernel-owned rather than locally fabricated.
        let restarted =
            GovernorComposition::new(kernel.clone(), None, &expected, QueueLimits::default())
                .expect("restart");
        assert_eq!(
            restarted.owners().task.task(&task_id).expect("task").goal,
            "goal after refresh"
        );
        assert_eq!(restarted.recovery().canonical_scope, moved_heads);
    }

    #[test]
    fn refresh_rejects_changed_heads_and_partial_recovery() {
        let observed = snapshot();
        let fence = observed.state_fence();
        let task_id = TaskId::new("task-1").expect("task id");
        let receipt = WriteReceipt {
            operation_id: OperationId::new("op-refresh-1").expect("operation id"),
            idempotency_key: "refresh-retry-1".to_owned(),
            canonical_request_hash: "d".repeat(64),
            transition_class: TransitionClass::TaskControl,
            status: WriteReceiptStatus::Committed,
            commit_id: Some(CommitId::new("commit-refresh-1").expect("commit id")),
            state_fence: fence.clone(),
            ordering_sequences: Vec::new(),
            revision_before_after: Vec::new(),
            applied_command_ids: vec!["cmd-1".to_owned()],
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: OperationManifestDigest::new("manifest")
                .expect("manifest digest"),
            // Standalone-fixture issue-#18 values (not bound to a
            // transition): this seed only exercises refresh/head
            // rejection, never digest bindings. Shapes stay valid so
            // `validate()` reaches the behavior under test.
            admission_digest: "e".repeat(64),
            mutation_plan_digest: "f".repeat(64),
            semantic_source_revisions: Vec::new(),
            // I5.19: standalone seed with no `PreparedTransition` in scope, so
            // the record is built explicitly from the store API's own in-force
            // constants. `fence` is in scope, so its policy binding is used and
            // the record still agrees with the fence, keeping `validate()`
            // below passing.
            policy_config_schema_versions: eliot_store_api::PolicyConfigSchemaVersions {
                policy_revision: fence.policy_revision,
                config_profile: eliot_store_api::OPERATION_CATALOGUE_PROFILE.to_owned(),
                schema_revision: eliot_store_api::CONTRACT_VERSION,
            },
            error_code: None,
            resubmission: Resubmission::None,
            committed_at: Some("commit-sequence-0000000000000001".to_owned()),
            envelope: None,
        };
        receipt.validate().expect("seeded receipt is valid");
        let mut fake = fake_kernel(observed.clone());
        fake.payloads.insert(
            RecoveryOwner::Task,
            canonical_json_bytes(&refresh_task_snapshot(&fence, "stable goal"))
                .expect("task bytes"),
        );
        fake.receipts.push(receipt.clone());
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let kernel = Arc::new(fake);
        let mut composition =
            GovernorComposition::new(kernel.clone(), None, &expected, QueueLimits::default())
                .expect("composition");
        assert_eq!(composition.recovery().receipts, vec![receipt.clone()]);
        let retained = composition.recovery().clone();

        // Heads move between the recovery reads and the post-read: publication
        // is blocked and the previous projection is kept.
        kernel
            .staged_scopes
            .lock()
            .expect("staged scope lock")
            .extend([refresh_heads(&fence, 2, 2), refresh_heads(&fence, 3, 2)]);
        let churned = composition.refresh_from_kernel();
        assert!(
            matches!(
                churned,
                Err(CompositionError::Recovery(ref message)) if message.contains("moved mid-read")
            ),
            "refresh accepted heads that moved mid-read: {churned:?}"
        );
        assert_eq!(composition.readiness(), CompositionReadiness::Ready);
        assert_eq!(*composition.recovery(), retained);
        assert_eq!(composition.recovery().receipts, vec![receipt.clone()]);
        assert_eq!(
            composition.owners().task.task(&task_id).expect("task").goal,
            "stable goal"
        );

        // One owner read goes missing: partial recovery fails closed without
        // manufacturing a default, preserving projection and receipt.
        kernel
            .live_reads
            .lock()
            .expect("live read lock")
            .insert(RecoveryOwner::Task, None);
        let partial = composition.refresh_from_kernel();
        assert!(
            matches!(
                partial,
                Err(CompositionError::Recovery(ref message)) if message.contains("partial")
            ),
            "refresh accepted partial recovery: {partial:?}"
        );
        assert_eq!(composition.readiness(), CompositionReadiness::Ready);
        assert_eq!(*composition.recovery(), retained);
        assert_eq!(composition.recovery().receipts, vec![receipt]);
        assert_eq!(
            composition.owners().task.task(&task_id).expect("task").goal,
            "stable goal"
        );
    }

    struct NoopWaker;

    impl std::task::Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    /// Drives an immediately-ready future without an external executor. The
    /// fake gateway never pends, so this terminates; it exists only because
    /// this crate takes no executor dependency.
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        use std::task::{Context, Poll};
        let waker = std::task::Waker::from(Arc::new(NoopWaker));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    /// Admitted ingress metadata. The source is an external principal, never
    /// the daemon transport peer, and the session is the initiating session.
    fn commit_metadata(fence: &StateFence) -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new("req-t1-2-1").expect("request id"),
            session_id: Some(SessionId::new("session-t1-2").expect("session id")),
            task_id: None,
            product_id: ProductId::new("test-product").expect("product id"),
            source_id: SourceId::new("agent-bridge").expect("source id"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        }
    }

    fn commit_identity(fence: &StateFence) -> RequestIdentity {
        let metadata = commit_metadata(fence);
        RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence.clone(),
            },
            idempotency_key: "idem-t1-2-1".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-t1-2-1".to_owned(),
        }
    }

    fn commit_envelope(
        fence: &StateFence,
        metadata: RequestMetadata,
        idempotency_key: &str,
        operation_id: &str,
    ) -> CanonicalWriteEnvelope {
        CanonicalWriteEnvelope {
            operation_id: OperationId::new(operation_id).expect("operation id"),
            request: metadata,
            idempotency_key: idempotency_key.to_owned(),
            scope_id: ScopeId::new("governor").expect("scope"),
            task_id: None,
            transition_class: TransitionClass::TaskControl,
            requested_effect_ceiling: EffectClass::ReversibleMutation,
            admission_contract_set_digest: "a".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest")
                .expect("manifest digest"),
            semantic_commands: vec![NamedMutationRequest {
                operation: NamedMutationOperation::UpdateTaskState,
                parameters: BTreeMap::new(),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
            expected_revision_heads: Vec::new(),
            expected_ordering_heads: vec![OrderingHeadExpectation {
                scope: OrderingScopeId::new("scope:governor").expect("ordering scope"),
                expected_sequence: 1,
                state_fence: fence.clone(),
            }],
        }
    }

    fn committed_composition() -> (Arc<FakeKernel>, GovernorComposition<FakeKernel>) {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let kernel = Arc::new(fake_kernel(observed));
        let composition =
            GovernorComposition::new(kernel.clone(), None, &expected, QueueLimits::default())
                .expect("composition");
        (kernel, composition)
    }

    /// Owned material-readiness facts for the issue #1789 gate tests.
    ///
    /// Every identity names the retained activation `WorkScope` binding
    /// (`scope:work` / `instance:work` / `lineage:work`, generation 1), so
    /// the Governor instance anchor passes and the gate verdict decides.
    struct MaterialReadinessBundle {
        receipt: eliot_workscope::OnboardingReadinessReceipt,
        descriptor: eliot_workscope::WorkScopeDescriptor,
        coverage: eliot_workscope::GoverningCoverage,
        guard: eliot_workscope::ScopeBindingGuardReceipt,
        lease: eliot_workscope::OnboardingLease,
    }

    impl MaterialReadinessBundle {
        fn inputs<'a>(
            &'a self,
            fence: &'a StateFence,
        ) -> eliot_workscope::MaterialReadinessInputs<'a> {
            eliot_workscope::MaterialReadinessInputs {
                receipt: &self.receipt,
                descriptor: &self.descriptor,
                coverage: &self.coverage,
                guard_receipt: &self.guard,
                lease: &self.lease,
                fence,
                now: 1,
            }
        }
    }

    fn readiness_scope() -> eliot_workscope::ScopeIdentity {
        eliot_workscope::ScopeIdentity {
            scope_ref: "scope:work".to_owned(),
            kind: eliot_workscope::ScopeKind::GitRepo,
            lineage_ref: Some("lineage:work".to_owned()),
            instance_ref: "instance:work".to_owned(),
            root_identity: "root:work".to_owned(),
            generation: 1,
        }
    }

    fn readiness_lineage() -> eliot_workscope::RepositoryLineageIdentity {
        eliot_workscope::RepositoryLineageIdentity {
            lineage_ref: "lineage:work".to_owned(),
            object_store_ref: "store:work".to_owned(),
            initial_history_ref: "history:work".to_owned(),
            normalized_remote_ref: None,
            manifest_identity_ref: None,
        }
    }

    fn readiness_instance() -> eliot_workscope::WorkspaceInstanceIdentity {
        eliot_workscope::WorkspaceInstanceIdentity {
            instance_ref: "instance:work".to_owned(),
            root_identity: "root:work".to_owned(),
            vcs_identity_ref: None,
            generation: 1,
        }
    }

    fn readiness_lease() -> eliot_workscope::OnboardingLease {
        eliot_workscope::OnboardingLease {
            lease_ref: "onboarding:work".to_owned(),
            lineage_candidate_ref: "lineage:work".to_owned(),
            workspace_instance_candidate_ref: "instance:work".to_owned(),
            privacy_class: eliot_security_contracts::PrivacyClass::Internal,
            governing_source_generation: 1,
            compiler_epoch: 1,
            state: eliot_workscope::OnboardingLeaseState::Compiling,
            deadline: 10,
        }
    }

    fn readiness_privacy() -> eliot_workscope::PrivacyProfile {
        eliot_workscope::PrivacyProfile {
            admitted_classes: vec![eliot_security_contracts::PrivacyClass::Internal],
        }
    }

    fn readiness_assurance(fence: &StateFence) -> eliot_security_contracts::SourceAssurance {
        serde_json::from_value(serde_json::json!({
            "source_ref": "architecture",
            "provenance_ref": "artifact:architecture",
            "integrity": "VERIFIED",
            "freshness": "CURRENT",
            "competence": "DOMAIN_VERIFIED",
            "independence": "INDEPENDENT",
            "privacy_class": serde_json::to_value(eliot_security_contracts::PrivacyClass::Internal)
                .expect("privacy class"),
            "instruction_taint": "CLEARED",
            "allowed_epistemic_use": ["OBSERVATION"],
            "allowed_effects": ["READ_ONLY"],
            "required_verifier": null,
            "quarantine": "NONE",
            "state_fence": fence,
        }))
        .expect("source assurance fixture")
    }

    fn readiness_sources(fence: &StateFence) -> eliot_workscope::GoverningSourceSet {
        eliot_workscope::GoverningSourceSet::new(
            "scope:work".to_owned(),
            1,
            vec![eliot_workscope::GoverningSource {
                source_ref: "architecture".to_owned(),
                role: eliot_workscope::GoverningSourceRole::Architecture,
                assurance: readiness_assurance(fence),
                applicable_generation: 1,
                status: eliot_workscope::SourceStatus::Admitted,
                domains: Vec::new(),
                digest: "a".repeat(64),
                authority_basis: None,
            }],
            Vec::new(),
        )
        .expect("source fixture")
    }

    fn readiness_descriptor(fence: &StateFence) -> eliot_workscope::WorkScopeDescriptor {
        eliot_workscope::WorkScopeDescriptor {
            scope_ref: "scope:work".to_owned(),
            descriptor_revision: 1,
            kind: eliot_workscope::ScopeKind::GitRepo,
            display_name: "work".to_owned(),
            lineage: Some(readiness_lineage()),
            instances: vec![readiness_instance()],
            owner_refs: vec!["owner:test".to_owned()],
            canonical_resource_refs: Vec::new(),
            root_identities: vec!["root:work".to_owned()],
            external_resource_refs: Vec::new(),
            truth_surface_refs: vec!["truth:work".to_owned()],
            verifier_refs: vec!["verifier:work".to_owned()],
            privacy: readiness_privacy(),
            authority_profile_ref: Some("authority:test".to_owned()),
            execution_identity: eliot_workscope::ResourceExecutionIdentity::Service,
            generation: eliot_workscope::GenerationEvidence {
                branch_ref: None,
                commit_ref: None,
                dirty_summary_ref: None,
                task_revision: None,
                resource_generation: ResourceGeneration::genesis(),
            },
            state_fence: fence.clone(),
            available_capabilities: Vec::new(),
            missing_capabilities: Vec::new(),
            lifecycle: eliot_workscope::ScopeLifecycle::Active,
        }
    }

    fn readiness_bundle(
        fence: &StateFence,
        task: eliot_workscope::TaskBindingInput,
    ) -> MaterialReadinessBundle {
        let scope = readiness_scope();
        let instance = readiness_instance();
        let lineage = readiness_lineage();
        let candidate = eliot_workscope::WorkScopeCandidate {
            scope: scope.clone(),
            descriptor_revision: 1,
            lineage: Some(lineage.clone()),
            instance: instance.clone(),
            privacy_class: eliot_security_contracts::PrivacyClass::Internal,
        };
        let sources = readiness_sources(fence);
        let privacy = readiness_privacy();
        let binding = eliot_workscope::ScopeBinding {
            scope: scope.clone(),
            privacy_class: eliot_security_contracts::PrivacyClass::Internal,
            governing_source_generation: 1,
        };
        let guard =
            eliot_workscope::ScopeBindingGuard.check(&binding, &binding, &sources, &privacy);
        let lease = readiness_lease();
        let receipt = eliot_workscope::ColdStartController
            .compile(
                "receipt:work",
                &lease,
                "principal:test",
                "session:test",
                &scope,
                &instance,
                Some(&lineage),
                &candidate,
                &sources,
                fence,
                "governance:test",
                vec!["integration:evidence:one".to_owned()],
                "route:test",
                "serializer:test",
                "serializer-version:test",
                "serializer-options:test",
                "tokenizer:test",
                "tokenizer-version:test",
                "tokenizer-hash:test",
                "projection:test",
                1,
                &privacy,
                task,
                None,
                1,
            )
            .expect("readiness receipt");
        MaterialReadinessBundle {
            receipt,
            descriptor: readiness_descriptor(fence),
            coverage: eliot_workscope::GoverningCoverage::AdmittedSources(sources),
            guard,
            lease,
        }
    }

    fn readiness_composition() -> (Arc<FakeKernel>, GovernorComposition<FakeKernel>) {
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let kernel = Arc::new(activation_fake(&observed));
        let composition =
            GovernorComposition::new(kernel.clone(), None, &expected, QueueLimits::default())
                .expect("composition");
        (kernel, composition)
    }

    #[test]
    fn canonical_write_without_task_is_denied_before_commit() {
        let (kernel, mut composition) = readiness_composition();
        let fence = composition.kernel_snapshot().state_fence().clone();
        let identity = commit_identity(&fence);
        let envelope = commit_envelope(
            &fence,
            identity.request.metadata.clone(),
            &identity.idempotency_key,
            "op-1789-no-task",
        );
        let bundle = readiness_bundle(&fence, eliot_workscope::TaskBindingInput::NoTask);
        let observed = eliot_workscope::ScopeBinding {
            scope: readiness_scope(),
            privacy_class: eliot_security_contracts::PrivacyClass::Internal,
            governing_source_generation: 1,
        };
        let sources = readiness_sources(&fence);
        let privacy = readiness_privacy();
        let denied = block_on(composition.commit_canonical_with_readiness(
            &identity,
            envelope,
            &bundle.inputs(&fence),
            &observed,
            &sources,
            &privacy,
        ));
        assert!(
            matches!(denied, Err(CompositionError::Recovery(ref message)) if message.contains("TASK_SELECTION_REQUIRED")),
            "no-task write was not denied with TASK_SELECTION_REQUIRED: {denied:?}"
        );
        assert_eq!(*kernel.apply_calls.lock().expect("apply call lock"), 0);
        assert!(kernel.committed.lock().expect("committed lock").is_empty());
    }

    #[test]
    fn canonical_write_with_full_grounding_commits() {
        let (kernel, mut composition) = readiness_composition();
        let fence = composition.kernel_snapshot().state_fence().clone();
        let identity = commit_identity(&fence);
        let envelope = commit_envelope(
            &fence,
            identity.request.metadata.clone(),
            &identity.idempotency_key,
            "op-1789-grounded",
        );
        let bundle = readiness_bundle(
            &fence,
            eliot_workscope::TaskBindingInput::Current {
                task_ref: "task:one".to_owned(),
                task_revision: 1,
                acceptance_digest: "digest:acceptance:one".to_owned(),
                selection_source_ref: "owner:test".to_owned(),
                evidence_ref: "intake:test".to_owned(),
            },
        );
        let observed = eliot_workscope::ScopeBinding {
            scope: readiness_scope(),
            privacy_class: eliot_security_contracts::PrivacyClass::Internal,
            governing_source_generation: 1,
        };
        let sources = readiness_sources(&fence);
        let privacy = readiness_privacy();
        let receipt = block_on(composition.commit_canonical_with_readiness(
            &identity,
            envelope,
            &bundle.inputs(&fence),
            &observed,
            &sources,
            &privacy,
        ))
        .expect("grounded write commits");
        assert_eq!(receipt.operation_id.as_str(), "op-1789-grounded");
        assert_eq!(receipt.status, WriteReceiptStatus::Committed);
        assert_eq!(*kernel.apply_calls.lock().expect("apply call lock"), 1);
    }

    #[test]
    fn admitted_identity_reaches_gateway_with_exact_terms() {
        let (kernel, composition) = committed_composition();
        let fence = composition.kernel_snapshot().state_fence();
        let identity = commit_identity(&fence);
        let envelope = commit_envelope(
            &fence,
            identity.request.metadata.clone(),
            &identity.idempotency_key,
            "op-t1-2-positive",
        );
        let receipt = block_on(composition.commit_canonical(&identity, envelope.clone()))
            .expect("admitted commit");
        // The gateway observed the exact admitted terms: initiating source
        // and session preserved, never rewritten to a transport peer.
        let stored = kernel
            .committed
            .lock()
            .expect("committed lock")
            .get(&receipt.operation_id)
            .expect("stored operation")
            .clone();
        assert_eq!(stored.0, identity);
        assert_eq!(stored.0.request.metadata.source_id.as_str(), "agent-bridge");
        assert_eq!(
            stored
                .0
                .request
                .metadata
                .session_id
                .as_ref()
                .expect("session")
                .as_str(),
            "session-t1-2"
        );
        assert_eq!(stored.0.deadline_unix_ms, 1_800_000_000_000);
        assert_eq!(stored.0.cancellation_id, "cancel-t1-2-1");
        // The exact validated receipt binds the same operation identity.
        assert_eq!(receipt.operation_id.as_str(), "op-t1-2-positive");
        assert_eq!(receipt.idempotency_key, identity.idempotency_key);
        assert_eq!(receipt.status, WriteReceiptStatus::Committed);
        let transition = envelope.prepare().expect("immutable transition");
        assert_eq!(
            receipt.canonical_request_hash,
            transition.identity.canonical_request_hash
        );
        validate_store_receipt_envelope(&identity.request.metadata, &transition, &receipt)
            .expect("shared receipt envelope");
        assert_eq!(*kernel.apply_calls.lock().expect("apply call lock"), 1);
    }

    #[test]
    fn substituted_binding_is_rejected_before_the_gateway() {
        let (kernel, composition) = committed_composition();
        let fence = composition.kernel_snapshot().state_fence();
        let identity = commit_identity(&fence);
        // A substituted request binding under the same fence is rejected even
        // though the envelope is internally well-formed.
        let mut substituted = identity.request.metadata.clone();
        substituted.source_id = SourceId::new("intruder").expect("source id");
        let substituted_envelope = commit_envelope(
            &fence,
            substituted,
            &identity.idempotency_key,
            "op-t1-2-substituted",
        );
        let rejected = block_on(composition.commit_canonical(&identity, substituted_envelope));
        assert!(
            matches!(rejected, Err(CompositionError::Provider(_))),
            "substituted binding was not rejected: {rejected:?}"
        );
        // A substituted idempotency key is rejected the same way.
        let idempotency_envelope = commit_envelope(
            &fence,
            identity.request.metadata.clone(),
            "idem-substituted",
            "op-t1-2-substituted-idem",
        );
        let rejected = block_on(composition.commit_canonical(&identity, idempotency_envelope));
        assert!(
            matches!(rejected, Err(CompositionError::Provider(_))),
            "substituted idempotency was not rejected: {rejected:?}"
        );
        // Neither rejection reached the gateway: no execution, no receipt.
        assert_eq!(*kernel.apply_calls.lock().expect("apply call lock"), 0);
        assert!(kernel.committed.lock().expect("committed lock").is_empty());
    }

    #[test]
    fn lost_acknowledgement_reconciles_to_the_same_operation_receipt() {
        let (kernel, composition) = committed_composition();
        let fence = composition.kernel_snapshot().state_fence();
        let identity = commit_identity(&fence);
        let envelope = commit_envelope(
            &fence,
            identity.request.metadata.clone(),
            &identity.idempotency_key,
            "op-t1-2-reconcile",
        );
        let receipt = block_on(composition.commit_canonical(&identity, envelope.clone()))
            .expect("admitted commit");
        // A lost acknowledgement resolves through exact receipt
        // reconciliation, not through a second execution.
        let reconciled = block_on(kernel.receipt(receipt.operation_id.clone()))
            .expect("receipt route")
            .expect("stored receipt");
        assert_eq!(reconciled, receipt);
        // A retry carrying a fresh deadline/cancellation for the same
        // operation replays the stored receipt instead of re-executing.
        let mut retry = identity.clone();
        retry.deadline_unix_ms = 1_900_000_000_000;
        retry.cancellation_id = "cancel-t1-2-retry".to_owned();
        let replayed =
            block_on(composition.commit_canonical(&retry, envelope)).expect("idempotent replay");
        assert_eq!(replayed, receipt);
        assert_eq!(
            *kernel.apply_calls.lock().expect("apply call lock"),
            1,
            "retry with a new deadline must not re-execute"
        );
    }

    #[test]
    fn operator_borrow_admits_through_the_retained_kernel_port() {
        let (kernel, composition) = committed_composition();
        let fence = composition.kernel_snapshot().state_fence();
        let identity = commit_identity(&fence);
        let operation_id = OperationId::new("op-operator-borrow").expect("operation id");
        let envelope = crate::operator_reconciliation::operator_command_envelope(
            &identity,
            &operation_id,
            "session-t1-2",
            &"a".repeat(64),
            &"b".repeat(64),
            1,
        )
        .expect("operator envelope");
        // The composition borrow admits through the retained Kernel port and
        // stores the operation in Kernel ORS for later receipt reconciliation.
        let receipt = block_on(
            composition
                .operator_reconciliation()
                .admit_operator_command(&identity, &operation_id, envelope),
        )
        .expect("operator admission");
        assert_eq!(receipt.operation_id, operation_id);
        assert_eq!(receipt.idempotency_key, identity.idempotency_key);
        assert_eq!(receipt.transition_class, TransitionClass::CaptureCandidate);
        assert_eq!(receipt.status, WriteReceiptStatus::Committed);
        assert_eq!(receipt.state_fence, fence);
        assert_eq!(*kernel.apply_calls.lock().expect("apply call lock"), 1);
        let stored = block_on(kernel.receipt(operation_id.clone()))
            .expect("receipt route")
            .expect("stored receipt");
        assert_eq!(stored, receipt);
    }

    #[test]
    fn commit_then_refresh_publishes_the_kernel_change() {
        let observed = snapshot();
        let fence = observed.state_fence();
        let mut fake = fake_kernel(observed.clone());
        fake.payloads.insert(
            RecoveryOwner::Task,
            canonical_json_bytes(&refresh_task_snapshot(&fence, "goal before commit"))
                .expect("task bytes"),
        );
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let kernel = Arc::new(fake);
        let mut composition =
            GovernorComposition::new(kernel.clone(), None, &expected, QueueLimits::default())
                .expect("composition");
        let identity = commit_identity(&fence);
        let envelope = commit_envelope(
            &fence,
            identity.request.metadata.clone(),
            &identity.idempotency_key,
            "op-t1-2-refresh",
        );
        let receipt =
            block_on(composition.commit_canonical(&identity, envelope)).expect("admitted commit");
        assert_eq!(receipt.status, WriteReceiptStatus::Committed);
        // The Kernel advances task state plus a new stable head set; one
        // refresh publishes both without a daemon restart.
        kernel.live_reads.lock().expect("live read lock").insert(
            RecoveryOwner::Task,
            Some(
                canonical_json_bytes(&refresh_task_snapshot(&fence, "goal after commit"))
                    .expect("task bytes"),
            ),
        );
        let moved_heads = refresh_heads(&fence, 2, 2);
        kernel
            .staged_scopes
            .lock()
            .expect("staged scope lock")
            .push(moved_heads.clone());
        composition
            .refresh_from_kernel()
            .expect("refresh publishes the committed change");
        let task_id = TaskId::new("task-1").expect("task id");
        assert_eq!(
            composition.owners().task.task(&task_id).expect("task").goal,
            "goal after commit"
        );
        assert_eq!(composition.recovery().canonical_scope, moved_heads);
    }

    /// Scripted P-07 port for the authority gating proof below. Each behavior
    /// is an explicit gate assertion, never a production success path: this
    /// double is `cfg(test)`-only, while end-to-end production activation
    /// awaits the Kernel P-07 front-door route (T6/#15).
    struct ScriptedAuthorityPort {
        behavior: Mutex<ScriptedAuthorityBehavior>,
    }

    #[derive(Clone)]
    enum ScriptedAuthorityBehavior {
        Unavailable,
        UnknownAck,
        NonActiveReceipt,
        Active { activation_id: String },
    }

    impl P07AuthorityPort for ScriptedAuthorityPort {
        fn activate_grant(
            &self,
            request: &GrantActivationRequest,
        ) -> Result<AuthorityActivationReceipt, P07PortError> {
            let behavior = self.behavior.lock().expect("script lock").clone();
            let snapshot_id = request.snapshot_id.as_str().to_owned();
            let authority_epoch = request.binding.state_fence.authority_epoch.clone();
            match behavior {
                ScriptedAuthorityBehavior::Unavailable => Err(P07PortError::Unavailable),
                ScriptedAuthorityBehavior::UnknownAck => Err(P07PortError::UnknownOutcome {
                    snapshot_id: request.snapshot_id.clone(),
                }),
                ScriptedAuthorityBehavior::NonActiveReceipt => Ok(AuthorityActivationReceipt {
                    activation_id: "act-scripted-non-active".to_owned(),
                    snapshot_id,
                    authority_epoch,
                    state: AuthorityState::PendingKernelActivation,
                }),
                ScriptedAuthorityBehavior::Active { activation_id } => {
                    Ok(AuthorityActivationReceipt {
                        activation_id,
                        snapshot_id,
                        authority_epoch,
                        state: AuthorityState::Active,
                    })
                }
            }
        }

        fn revoke_grant(
            &self,
            _request: &GrantRevocationRequest,
        ) -> Result<AuthorityRevocationReceipt, P07PortError> {
            Err(P07PortError::Unavailable)
        }

        fn activate_introduction(
            &self,
            _request: &IntroductionActivationRequest,
        ) -> Result<AuthorityActivationReceipt, P07PortError> {
            Err(P07PortError::Unavailable)
        }

        fn revoke_introduction(
            &self,
            _request: &IntroductionRevocationRequest,
        ) -> Result<AuthorityRevocationReceipt, P07PortError> {
            Err(P07PortError::Unavailable)
        }

        fn activate_root_transition(
            &self,
            _request: &eliot_authority::RootTransitionActivationRequest,
        ) -> Result<eliot_authority::RootTransitionActivationReceipt, P07PortError> {
            Err(P07PortError::Unavailable)
        }
    }

    fn pending_grant_fixture(
        grant_id: &str,
        fence: &StateFence,
    ) -> eliot_authority::CapabilityGrant {
        eliot_authority::CapabilityGrant {
            grant_id: eliot_authority::GrantId::new(grant_id).expect("grant id"),
            parent_grant_id: None,
            authority_root_ref: "authority:test-root".to_owned(),
            issuer: eliot_authority::PrincipalRef::new("principal:issuer").expect("issuer"),
            holder: eliot_authority::PrincipalRef::new("principal:holder").expect("holder"),
            authority: eliot_authority::AuthoritySet::new(
                ["op:test".to_owned()],
                ["res:test".to_owned()],
                EffectClass::ReversibleMutation,
            )
            .expect("authority set"),
            inherited_source_ceiling: None,
            binding: AuthorityBinding {
                authority_id: ContractId::new("authority:test").expect("authority id"),
                authority_owner: "test-owner".to_owned(),
                authority_epoch: fence.authority_epoch.clone(),
                state_fence: fence.clone(),
                allowed_effect: EffectClass::ExternalEffect,
                proof_ceiling: ProofCeiling::ObservedExternalEffect,
            },
            issued_at: eliot_authority::LogicalTime::new(1),
            expires_at: eliot_authority::LogicalTime::new(2),
            max_uses: 1,
            status: eliot_authority::GrantStatus::PendingActivation,
        }
    }

    fn authority_payload_with_pending_grants(fence: &StateFence) -> Vec<u8> {
        let graph = eliot_authority::GrantGraph::from_grants(
            [
                pending_grant_fixture("grant-a", fence),
                pending_grant_fixture("grant-b", fence),
            ],
            1,
        )
        .expect("pending grant graph");
        let effect_authorizer = eliot_authority::EffectAuthorizer::default()
            .snapshot()
            .expect("effect snapshot");
        let snapshot = AuthorityOwnerSnapshot::new(
            fence.clone(),
            graph.recovery_snapshot().expect("grant snapshot"),
            effect_authorizer,
        )
        .expect("authority snapshot");
        canonical_json_bytes(&serde_json::to_value(snapshot).expect("authority JSON"))
            .expect("authority bytes")
    }

    fn grant_activation_fixture(
        grant_id: &str,
        fence: &StateFence,
    ) -> eliot_authority::GrantActivationRequest {
        eliot_authority::GrantActivationRequest {
            grant_id: eliot_authority::GrantId::new(grant_id).expect("grant id"),
            snapshot_id: eliot_authority::SnapshotId::new("snap-1").expect("snapshot id"),
            binding: AuthorityBinding {
                authority_id: ContractId::new("authority:test").expect("authority id"),
                authority_owner: "test-owner".to_owned(),
                authority_epoch: fence.authority_epoch.clone(),
                state_fence: fence.clone(),
                allowed_effect: EffectClass::ExternalEffect,
                proof_ceiling: ProofCeiling::ObservedExternalEffect,
            },
        }
    }

    #[test]
    fn pending_grant_becomes_effective_only_after_real_activation() {
        let observed = snapshot();
        let fence = observed.state_fence();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let mut fake = fake_kernel(observed.clone());
        fake.payloads.insert(
            RecoveryOwner::Authority,
            authority_payload_with_pending_grants(&fence),
        );
        let script = Arc::new(ScriptedAuthorityPort {
            behavior: Mutex::new(ScriptedAuthorityBehavior::Unavailable),
        });
        let mut composition = GovernorComposition::new(
            Arc::new(fake),
            Some(script.clone() as Arc<dyn P07AuthorityPort>),
            &expected,
            QueueLimits::default(),
        )
        .expect("composition");
        assert!(composition.authority_activation_available());
        let grant_a = eliot_authority::GrantId::new("grant-a").expect("grant id");
        let grant_b = eliot_authority::GrantId::new("grant-b").expect("grant id");

        // Unavailable: the grant stays pending and is never read as effective.
        let request_a = grant_activation_fixture("grant-a", &fence);
        assert_eq!(
            composition.authority_grant_status(&grant_a),
            Some(eliot_authority::GrantStatus::PendingActivation)
        );
        let error = composition
            .activate_grant(&request_a)
            .expect_err("unavailable activation must fail closed");
        assert!(matches!(
            error,
            CompositionError::Authority(P07PortError::Unavailable)
        ));
        assert_eq!(
            composition.authority_grant_status(&grant_a),
            Some(eliot_authority::GrantStatus::PendingActivation)
        );

        // Lost acknowledgement: the exact request is retained under its
        // snapshot and the grant stays pending, never active.
        *script.behavior.lock().expect("script lock") = ScriptedAuthorityBehavior::UnknownAck;
        let error = composition
            .activate_grant(&request_a)
            .expect_err("unknown outcome must fail closed");
        match error {
            CompositionError::Authority(P07PortError::UnknownOutcome { snapshot_id }) => {
                assert_eq!(snapshot_id.as_str(), "snap-1");
            }
            other => panic!("expected an unknown outcome, got {other:?}"),
        }
        assert_eq!(
            composition.authority_grant_status(&grant_a),
            Some(eliot_authority::GrantStatus::PendingActivation)
        );

        // A receipt that fails validate() (non-Active) never flips the grant.
        *script.behavior.lock().expect("script lock") = ScriptedAuthorityBehavior::NonActiveReceipt;
        let request_b = grant_activation_fixture("grant-b", &fence);
        let error = composition
            .activate_grant(&request_b)
            .expect_err("non-active receipt must fail closed");
        assert!(matches!(
            error,
            CompositionError::Authority(P07PortError::InvalidBinding)
        ));
        assert_eq!(
            composition.authority_grant_status(&grant_b),
            Some(eliot_authority::GrantStatus::PendingActivation)
        );

        // A validated Active receipt flips pending -> active exactly once.
        *script.behavior.lock().expect("script lock") = ScriptedAuthorityBehavior::Active {
            activation_id: "act-a-1".to_owned(),
        };
        let receipt = composition
            .activate_grant(&request_a)
            .expect("validated active receipt");
        assert_eq!(receipt.activation_id, "act-a-1");
        assert_eq!(receipt.snapshot_id, "snap-1");
        assert_eq!(
            composition.authority_grant_status(&grant_a),
            Some(eliot_authority::GrantStatus::Active)
        );

        // A second activation on the recorded identity fails closed: the
        // receipt is not issued twice and the status never leaves Active for
        // a second proof.
        let error = composition
            .activate_grant(&request_a)
            .expect_err("second activation must fail closed");
        assert!(matches!(
            error,
            CompositionError::Authority(P07PortError::InvalidBinding)
        ));
        assert_eq!(
            composition.authority_grant_status(&grant_a),
            Some(eliot_authority::GrantStatus::Active)
        );

        // Without a retained port the same presentation is diagnosed
        // degradation: unavailable, never issuance.
        let mut degraded = GovernorComposition::new(
            Arc::new(fake_kernel(observed.clone())),
            None,
            &expected,
            QueueLimits::default(),
        )
        .expect("degraded composition");
        assert!(!degraded.authority_activation_available());
        let error = degraded
            .activate_grant(&request_a)
            .expect_err("missing port must fail closed");
        assert!(matches!(
            error,
            CompositionError::Authority(P07PortError::Unavailable)
        ));
    }

    fn r1_publish(
        composition: &GovernorComposition<FakeKernel>,
        claim_id: &str,
        operation_id: &str,
        invocation: &serde_json::Value,
    ) -> NativeWorkerExecutableBinding {
        composition
            .publish_native_worker_binding_for_invocation(
                claim_id,
                "reg-1",
                "install-1",
                "task-1",
                "work-1",
                "scope:work",
                1,
                "lease-1",
                operation_id,
                &"c".repeat(64),
                "principal-1",
                "session-1",
                1,
                "proc-tree-1",
                1,
                "process-fence-1",
                "route-1",
                "adapter-1",
                1,
                &"d".repeat(64),
                &"e".repeat(64),
                &"f".repeat(64),
                "cmd-1",
                "facet-1",
                eliot_contracts::CapabilityCellId::new("native-worker-core").expect("cell id"),
                vec!["intro-1".to_owned()],
                vec!["grant-1".to_owned()],
                1,
                1,
                eliot_store_api::EffectClass::ReversibleMutation,
                vec!["cred-1".to_owned()],
                vec!["res-1".to_owned()],
                NativeWorkerLifecycleBinding {
                    capability_cell_registry_digest: "5".repeat(64),
                    kernel_execution_manifest_digest: "9".repeat(64),
                    job_object_lineage_ref: "job-lineage-1".to_owned(),
                    resource_limits_digest: "8".repeat(64),
                    cancellation_policy_ref: "cancel-policy-1".to_owned(),
                    checkpoint_policy_digest: "7".repeat(64),
                    drain_policy_ref: "drain-policy-1".to_owned(),
                    restart_policy_digest: "6".repeat(64),
                },
                "stream-1",
                "0123456789abcdef",
                invocation,
                100,
                200,
                "plan:current",
                "1",
                1,
                &"b".repeat(64),
                "adm-1",
            )
            .expect("R1 publish builds")
    }

    #[test]
    fn r1_producer_derives_invocation_digest_from_exact_bytes() {
        // R1 production producer (Implements #22): the dispatch join carries
        // the real invocation digest derived from the exact invocation JSON,
        // never a placeholder. The caller still commits a sibling
        // `PreparedTransition` via `commit_canonical` correlated by
        // `operation_id` / `canonical_request_hash` / `state_fence`.
        let observed = snapshot();
        let expected = KernelGenerationExpectation::from_snapshot(&observed).expect("expectation");
        let composition = GovernorComposition::new(
            Arc::new(activation_fake(&observed)),
            None,
            &expected,
            QueueLimits::default(),
        )
        .expect("composition");
        let invocation = serde_json::json!({
            "claim_id": "claim-r1-1",
            "operation_id": "op-r1-1",
            "argv": ["--check"],
            "fence": {"generation": 1},
        });
        let derived = process_invocation_digest_for(&invocation).expect("derivation builds");
        assert_eq!(derived.len(), 64);
        let binding = r1_publish(&composition, "claim-r1-1", "op-r1-1", &invocation);
        assert_eq!(
            binding.process_invocation_digest, derived,
            "published binding must carry the derived invocation digest"
        );
        binding.validate().expect("published binding validates");
        // A mutated invocation derives a different digest, so the join gate
        // observes the change instead of a stable placeholder.
        let mutated = serde_json::json!({
            "claim_id": "claim-r1-1",
            "operation_id": "op-r1-1",
            "argv": ["--other"],
            "fence": {"generation": 1},
        });
        let mutated_digest =
            process_invocation_digest_for(&mutated).expect("mutated derivation builds");
        assert_ne!(
            derived, mutated_digest,
            "mutated invocation must derive a different digest"
        );
        let mutated_binding = r1_publish(&composition, "claim-r1-1", "op-r1-1", &mutated);
        assert_eq!(
            mutated_binding.process_invocation_digest, mutated_digest,
            "mutated publish must carry the mutated digest"
        );
        assert_ne!(
            binding.binding_digest, mutated_binding.binding_digest,
            "invocation change must move the binding digest"
        );
    }
}
