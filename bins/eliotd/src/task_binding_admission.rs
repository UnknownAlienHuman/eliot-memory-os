//! Task-binding admission for the daemon ingress boundary (issue #1929).
//!
//! Implements I5.5 capture/promotion split at the `eliotd` admission edge:
//! `eliot.observe` may retain a safe raw cold [`ObservationCandidate`] when
//! task selection is absent or ambiguous, while reusable task memory,
//! Claim/Failure/Procedure promotion, and task-control writes require the
//! canonical Governor [`TaskSelectionEvidence`] plus a valid current fence
//! and a `Compatible` disposition.
//!
//! The selection evidence is the canonical Governor-owned contract
//! (`eliot-observation`); this module defines no parallel shape and parses
//! no invented marker syntax. Field names, types, and validation rules come
//! from that contract: exact task handle, non-zero `TaskContract` revision,
//! lowercase acceptance digest, `WorkScope` identity, selection source and
//! evidence handles. The fence is bound by the authenticated caller context
//! (the `state_fence`/`expected_fence` parameters), matching the canonical
//! consumer where the submission envelope carries the single fence.
//!
//! This module is a pure validator. It owns no journal, store, task lifecycle,
//! or promotion state machine; it only classifies one admission attempt so the
//! Governor/store owners keep semantic ownership. It never selects the most
//! recent or open task and never guesses from resolver output: ambiguous input
//! stays cold. A contaminated selection (canonical crossover marker) never
//! promotes: captures stay cold and task-bound promotion rejects.
//!
//! # Daemon ingress entries, and which of them are live (issue #1929)
//!
//! Without an entry below this module was unreachable from the daemon: the
//! `eliotd` ingress admitted a capture or a task-relative write and only the
//! downstream store gate could object, so the daemon itself was a bypass
//! around I5.5. Three entries were added to close that chain:
//!
//! - [`admit_canonical_write`] — the composition-root named-mutation intake.
//!   The caller presents its compiled
//!   [`OnboardingReadinessReceipt`](eliot_workscope::OnboardingReadinessReceipt),
//!   so this is the only entry that can see its task binding. The receipt has
//!   no owner-proven selection source/evidence; a `CurrentTaskContract` binding
//!   is refused with `TASK_SELECTION_REQUIRED` until the task-intake owner
//!   supplies it. No source is synthesized from an unrelated profile or
//!   receipt handle. I5.6 step 4 verbatim — "resolve `TaskSelectionEvidence`
//!   and `TaskContract` compatibility when the command is task-relative".
//! - [`admit_named_mutation_capture`] — the transport edge
//!   (`DaemonKernelClient::apply_prepared`). No typed selection exists there, so
//!   this entry only decides the capture leg: a `CaptureObservation` naming no
//!   task is a cold unbound candidate and is never treated here as task-bound.
//!   It deliberately does not restate the store bridge's presence/agreement
//!   rule for task-bearing writes; that rule belongs to
//!   `eliot-store-surreal::task_binding_gate`, which re-derives it from the
//!   opaque proof handles before provider I/O. Neither replaces the other.
//! - [`observe_explicit_workspace`] — the daemon half of the `WorkScope`
//!   attach trigger. The daemon observes the explicit root mechanically; the
//!   Governor stays the receipt/admission owner
//!   (`GovernorComposition::admit_observed_scope_attach`), so this module
//!   mints no receipt of its own.
//!
//! - [`bind_current_task_selection`] — the applicability recheck admission
//!   needs (issue #1746, W4). It refuses a current task until the readiness
//!   receipt carries owner-proven selection source/evidence. Once that owner
//!   producer exists, the activation snapshot and receipt can be compared at
//!   the live fence. Structural validation of request-supplied
//!   `TaskSelectionEvidence` is never sufficient.
//!
//! No entry creates a second write path, re-derives a downstream layer's
//! decision, or accepts a task the caller did not name.
//!
//! # Measured reachability (issue #1929)
//!
//! Recorded because a checklist item satisfied against call-graph-dead code is
//! exactly the defect this issue audits. Measured on this tree by symbol, not
//! inferred:
//!
//! - [`admit_canonical_write`] has **one** production call site:
//!   [`DaemonComposition::commit_canonical_and_refresh`](super::DaemonComposition).
//!   An earlier revision of this file recorded *zero* call sites for it; that
//!   was false and is corrected here.
//! - `DaemonComposition::commit_canonical_and_refresh` itself has **zero**
//!   production call sites — its only in-tree mentions are documentation and a
//!   source-string assertion in `bins/eliotd/tests/agent_fabric_wiring.rs`. It
//!   is the composition-root canonical-commit entry and nothing in production
//!   calls it yet, so the typed evidence leg this module owns is reached from
//!   no live daemon path.
//! - [`admit_named_mutation_capture`] **is** live, through the neutral
//!   transport port: `PreparedKernelExchange::exchange` calls
//!   `KernelTransitionPort::apply_prepared`, implemented by
//!   `DaemonKernelClient` in `bins/eliotd/src/kernel_transition_client.rs`,
//!   whose `check_identity_binding` calls this entry before any transport is
//!   touched. The daemon run loop drives that port for its `TestD` terminal
//!   finish legs.
//! - [`observe_and_admit_task`] has **zero call sites**, so
//!   [`admit_task_bound_with_observed_scope`] is transitively dead with it.
//! - [`DaemonComposition::admit_scope_attach`](super::DaemonComposition) — the
//!   only caller of [`ScopeAttachIngress`] — has **zero call sites**, and
//!   `GovernorComposition::admit_observed_scope_attach` fails closed unless a
//!   `WorkScope` owner is *already* retained, so the entry is additionally
//!   circular: its only producer of the state it requires is itself.
//!
//! The single blocking symbol for the evidence leg is the compiled readiness
//! receipt. `TaskSelectionEvidence` needs a non-zero `task_revision` and a
//! lowercase `acceptance_digest`, and this repository has exactly one
//! production constructor of [`OnboardingReadinessReceipt`](eliot_workscope::OnboardingReadinessReceipt):
//! `eliot_workscope::ColdStartController::compile`. Its only production caller
//! is `eliot_workscope::OnboardingSingleFlight::compile_and_publish`, so the
//! receipt is reachable only through
//! `eliot_governor::GovernorComposition::compile_cold_start_at_trigger`, which
//! itself has zero call sites. No carrier on the write path holds the receipt
//! or the evidence: `eliot_protocol::RequestIdentity`,
//! `eliot_store_api::PreparedTransition`, `eliot_canonical::CanonicalWriteEnvelope`,
//! `DaemonKernelClient`, and `GovernorComposition`'s retained
//! `WorkScopeBindingOwner` all carry at most a bare `task_id`, and
//! `WorkScopeBindingSnapshot` is documented as carrying "no task, plan, session,
//! principal or kernel-generation authority".
//!
//! Consequence, stated rather than hidden: because `commit_canonical_and_refresh`
//! is not called, the typed task-bound leg of [`admit_canonical_write`] is
//! currently unreachable from the daemon. The two stable codes remain enforced
//! on the real write path by `eliot_store_surreal::task_binding_gate::gate_apply`,
//! which re-derives them from the opaque proof handles the transition actually
//! carries, and the live transport edge reports `ColdUnbound`, which is the
//! complete and honest answer for a task-free capture. Threading a selection
//! onto the transport edge requires the receipt owner above to exist first; it
//! must never be filled with a synthesized, reconstructed, or defaulted
//! selection.
//!
//! # Where a cold unbound candidate is retained (issue #1929)
//!
//! Retention is not this module's work and is not the `tracing` line its
//! callers emit — a log record is neither durable nor listable.
//! `eliot_store_surreal::task_binding_gate::gate_apply` classifies the unbound
//! capture `GateDisposition::ColdUnbound` so the write *proceeds* instead of
//! being rejected, and the durable owner is the store adapter:
//! `eliot_store_surreal_adapter`'s `plan::evidence_records` builds one
//! `EvidenceRecord` per `CaptureObservation` regardless of task binding, and
//! `apply::atomic_write` binds those records into the `write_receipt` row in
//! the same transaction that creates the receipt. The read-back symbol is the
//! `GetEvidencePack` named read served by
//! `eliot_store_surreal_adapter`'s `apply::read_boundary::read_evidence_records`.
//! A later governed binding transition therefore has a durable, listable
//! candidate to read, and the daemon's own contribution is the admission
//! decision plus its log projection.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use eliot_bootstrap::capture::{WorkspaceInstanceFacts, observe_workspace_instance};
use eliot_contracts::sha256_hex;
use eliot_contracts::{RequestMetadata, StateFence, TaskId};
use eliot_governor::{
    CanonicalWriteEnvelope, ColdStartSurfaceView, GoverningSourceSet, PrivacyProfile, ScopeBinding,
    WorkScopeDescriptor, derive_observed_resources,
};
use eliot_integration_coverage::{GovernanceProfile, IntegrationCoverageProfile};
use eliot_observation::TaskSelectionEvidence;
use eliot_protocol::{
    AgentActivationCandidateCoverage, AgentActivationResolutionDisposition,
    AgentActivationResolutionResult, AgentActivationResolutionTicket,
};
use eliot_security_contracts::PrivacyClass;
use eliot_store_api::{NamedMutationOperation, PreparedTransition};
use eliot_workscope::{
    BootstrapDiscoveryInputs, BootstrapScanEvidence, DiscoveryLeaseKey, DiscoveryLeaseRequest,
    DiscoveryRead, DiscoveryReadLease, ManifestEvidence, ObservedScopeResources, OnboardingLease,
    OnboardingReadinessReceipt, ReadinessLifecycle, ScopeBindingDisposition, ScopeResolutionState,
    TaskBindingState, issue_discovery_lease, task_selection_required,
};

/// Authenticated activation's bounded filesystem/VCS observation and its
/// scanner inputs. The ticket binds the explicit selector to the admitted
/// Bridge request and peer receipt; all identity/evidence fields below are
/// derived from the Host observer, never accepted from the caller.
#[derive(Clone, Debug)]
pub struct ColdStartDiscoveryInput {
    pub lease: DiscoveryReadLease,
    pub key: DiscoveryLeaseKey,
    pub discovery: BootstrapDiscoveryInputs,
}

/// Stable rejection code when task-bound promotion lacks current evidence.
pub const TASK_SELECTION_REQUIRED: &str = "TASK_SELECTION_REQUIRED";
/// Stable rejection code when evidence names another/incompatible `WorkScope`.
pub const TASK_SCOPE_INCOMPATIBLE: &str = "TASK_SCOPE_INCOMPATIBLE";

/// Compatibility disposition computed by the owning selector.
///
/// `Compatible` is the only disposition that admits reusable/task-bound
/// promotion. Any other disposition keeps the observation cold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatibilityDisposition {
    /// Selection, contract revision, digest, scope, and fence all agree.
    Compatible,
    /// Selection names another scope or an incompatible contract revision.
    Incompatible,
}

/// Requirement class of one canonical operation before any gating
/// (issue #1746, W1; frozen against I7.6 and I5.5, not renegotiated per
/// request).
///
/// - `DiscoveryReadOnly` — authenticated discovery/read-only preview. Reachable
///   without a selected task (`state`/task-selection/bootstrap must stay
///   reachable or the user cannot select one). Never grants a task effect.
/// - `SafeRawCapture` — `observe` raw capture. May retain an explicitly
///   unbound/provisional cold candidate under its valid identity, privacy, and
///   staging policy ([`admit_capture`]); grants no task effect.
/// - `TaskRelativeEffectful` — task-bound promotion, control, action,
///   verification, and Finish. Requires the exact applicable task evidence
///   ([`admit_task_bound`]). Unauthenticated requests never gain exceptions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalOperationRequirement {
    DiscoveryReadOnly,
    SafeRawCapture,
    TaskRelativeEffectful,
}

/// Maps the eight canonical MCP operations (I7.6) to their requirement class.
///
/// `state`/`query`/`packet` are authenticated read-only previews;
/// `observe` is the single safe raw capture surface; `act`/`verify`/
/// `coordinate`/`finish` are task-relative/effectful. A `None` return means
/// the name is not a canonical operation and is refused upstream, never
/// defaulted to a weaker class.
///
/// Designated caller (STITCH, surfaces lane): the agent-bridge MCP dispatcher
/// maps tool names through this table before submitting; the daemon write path
/// re-derives its own requirement from the typed [`NamedMutationOperation`]
/// via [`requirement_for_named_mutation`], so a renamed tool cannot smuggle a
/// weaker class past the gate.
#[must_use]
pub fn classify_canonical_operation(operation: &str) -> Option<CanonicalOperationRequirement> {
    match operation {
        "eliot.state" | "eliot.query" | "eliot.packet" => {
            Some(CanonicalOperationRequirement::DiscoveryReadOnly)
        }
        "eliot.observe" => Some(CanonicalOperationRequirement::SafeRawCapture),
        "eliot.act" | "eliot.verify" | "eliot.coordinate" | "eliot.finish" => {
            Some(CanonicalOperationRequirement::TaskRelativeEffectful)
        }
        _ => None,
    }
}

/// Maps one `eliot.observe` typed suboperation (I7.6) to its requirement.
///
/// Every capture suboperation — `observation`, `decision`, `failure`,
/// `outcome`, `influence_ack` — is safe raw capture at admission: whether one
/// capture becomes task-bound is decided by the exact selection evidence in
/// [`admit_capture`], never by the suboperation name.
///
/// Designated caller (STITCH, surfaces lane): the agent-bridge MCP dispatcher,
///
/// together with [`classify_canonical_operation`].
#[must_use]
pub fn classify_observe_suboperation(suboperation: &str) -> Option<CanonicalOperationRequirement> {
    match suboperation {
        "observation" | "decision" | "failure" | "outcome" | "influence_ack" => {
            Some(CanonicalOperationRequirement::SafeRawCapture)
        }
        _ => None,
    }
}

/// Maps one `eliot.coordinate` operation discriminator (I7.6) to its
/// requirement.
///
/// `inspect`/`wait` are read-only orientation over run lineage and durable
/// state; `delegate`/`audit`/`compare`/`cancel`/`send` create or reconcile
/// execution effects and are task-relative.
///
/// Designated caller (STITCH, surfaces lane): the agent-bridge MCP dispatcher,
/// together with [`classify_canonical_operation`].
#[must_use]
pub fn classify_coordinate_suboperation(
    suboperation: &str,
) -> Option<CanonicalOperationRequirement> {
    match suboperation {
        "inspect" | "wait" => Some(CanonicalOperationRequirement::DiscoveryReadOnly),
        "delegate" | "audit" | "compare" | "cancel" | "send" => {
            Some(CanonicalOperationRequirement::TaskRelativeEffectful)
        }
        _ => None,
    }
}

/// Maps one typed store mutation to its requirement class (issue #1746, W1).
///
/// This is the write-path side of the frozen table: `CaptureObservation` is
/// the safe raw capture leg, `UpdateTaskState`/`RecordFinishDecision`/
/// `RecordFinishEvidence` are the task-relative/effectful legs, and every
/// other named operation needs no task binding. Called by
/// [`admit_canonical_write`] to derive its capture/task-relative split, so the
/// split cannot drift from the table.
#[must_use]
pub fn requirement_for_named_mutation(
    operation: NamedMutationOperation,
) -> CanonicalOperationRequirement {
    match operation {
        NamedMutationOperation::CaptureObservation => CanonicalOperationRequirement::SafeRawCapture,
        NamedMutationOperation::UpdateTaskState
        | NamedMutationOperation::RecordFinishDecision
        | NamedMutationOperation::RecordFinishEvidence => {
            CanonicalOperationRequirement::TaskRelativeEffectful
        }
        _ => CanonicalOperationRequirement::DiscoveryReadOnly,
    }
}

/// Daemon dispatch entrypoint presenting one admission attempt
/// (issue #1746, A6).
///
/// Both entrypoints enforce the same binding through the same rule table
/// ([`entrypoint_requires_binding`]): the bridge transport edge
/// (`DaemonKernelClient::apply_prepared` via [`admit_named_mutation_capture`])
/// and the direct internal composition-root intake
/// ([`DaemonComposition::commit_canonical_and_refresh`](super::DaemonComposition)
/// via [`admit_canonical_write`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchEntrypoint {
    /// Bridge transport edge (`DaemonKernelClient::apply_prepared`).
    BridgeTransport,
    /// Direct internal composition-root intake
    /// (`DaemonComposition::commit_canonical_and_refresh`).
    DirectInternal,
}

/// Whether one dispatch entrypoint requires owner task evidence for one
/// requirement class (issue #1746, A6).
///
/// The table is deliberately entrypoint-independent: task-relative/effectful
/// work requires exact evidence at every entrypoint, while discovery/read-only
/// and safe raw capture (cold quarantined route) never do. The `entrypoint`
/// parameter forces every dispatch edge to declare itself and consult this one
/// shared rule instead of carrying a local copy. Consulted by
/// [`admit_canonical_write`] (`DirectInternal`) and
/// [`admit_named_mutation_capture`] (`BridgeTransport`).
#[must_use]
pub fn entrypoint_requires_binding(
    entrypoint: DispatchEntrypoint,
    requirement: CanonicalOperationRequirement,
) -> bool {
    match (entrypoint, requirement) {
        (
            DispatchEntrypoint::BridgeTransport | DispatchEntrypoint::DirectInternal,
            CanonicalOperationRequirement::TaskRelativeEffectful,
        ) => true,
        (
            DispatchEntrypoint::BridgeTransport | DispatchEntrypoint::DirectInternal,
            CanonicalOperationRequirement::DiscoveryReadOnly
            | CanonicalOperationRequirement::SafeRawCapture,
        ) => false,
    }
}

/// Safe raw cold candidate retained when selection is absent or ambiguous.
///
/// Carries no task activation, no support/influence promotion, and no finish
/// relevance: durable capture-first bytes only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationCandidate {
    /// Stable candidate identity derived by the caller.
    pub candidate_id: String,
    /// Fence under which the bytes were captured.
    pub state_fence: StateFence,
    /// Bounded reason; always the unbound-capture marker here.
    pub reason_ref: String,
}

impl ObservationCandidate {
    /// Builds the single cold unbound shape this module ever emits.
    pub fn cold_unbound(candidate_id: String, state_fence: StateFence) -> Self {
        Self {
            candidate_id,
            state_fence,
            reason_ref: "unbound-capture".to_owned(),
        }
    }

    /// Whether this candidate can affect task memory/support/finish (never).
    #[must_use]
    pub const fn affects_task(&self) -> bool {
        false
    }
}

/// Typed admission failure carrying exactly one stable code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskBindingError {
    code: &'static str,
    detail: String,
}

impl TaskBindingError {
    fn selection_required(detail: impl Into<String>) -> Self {
        Self {
            code: TASK_SELECTION_REQUIRED,
            detail: detail.into(),
        }
    }

    fn scope_incompatible(detail: impl Into<String>) -> Self {
        Self {
            code: TASK_SCOPE_INCOMPATIBLE,
            detail: detail.into(),
        }
    }

    /// Stable wire code (`TASK_SELECTION_REQUIRED` / `TASK_SCOPE_INCOMPATIBLE`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Bounded human detail (never a task guess).
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl std::fmt::Display for TaskBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for TaskBindingError {}

/// Result of splitting capture admission from task-bound promotion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureAdmission {
    /// Durably retainable cold bytes with no task effects.
    ColdUnbound(ObservationCandidate),
    /// Exact selection admitted for a later governed binding transition.
    TaskBound(TaskSelectionEvidence),
}

/// Disposition of one daemon ingress attempt (issue #1929).
///
/// The variant, not the transport, decides what the write means: a cold
/// candidate carries no task activation, support/influence promotion, or
/// finish relevance, while `TaskBound` is only ever returned after the exact
/// selection evidence passed [`admit_task_bound`].
#[expect(
    clippy::large_enum_variant,
    reason = "TaskBound carries the sealed dispatch identity by value so the effect gate revalidates the exact admitted bytes"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskBindingAdmission {
    /// Cold unbound capture: durable bytes with no task effect.
    ColdUnbound(ObservationCandidate),
    /// Exact task-bound transition admitted toward the governed owner commit.
    ///
    /// Carries the sealed [`DispatchedBinding`] (issue #1746, W6): the admitted
    /// operation identity is the evidence plus its task, scope, presented
    /// fence, and bootstrap/profile revision — never a mutable ambient
    /// selection. The dispatch edge must revalidate it against the live fence
    /// at the effect gate (see [`revalidate_dispatched_binding`] and
    /// [`revalidate_task_bound_for_effect`]) instead of reusing the
    /// caller-presented fence; a moved fence, task, scope, or profile revision
    /// conflicts for rebind, it is never rewritten under the old operation
    /// identity.
    TaskBound(DispatchedBinding),
    /// Task-relative transition whose selection decision belongs to the
    /// caller that owns the exact selection evidence, never to a capture
    /// edge. Reported, never admitted and never silently downgraded.
    TaskRelative,
    /// Not a capture-first or task-relative write; no binding is required.
    NotTaskRelative,
}

/// Task-selection disposition a caller-presented readiness receipt carries.
///
/// This is the I5.6 step-4 resolution result. A current task binding is
/// admitted only when its owner-proven selection source/evidence is available;
/// task/revision/digest shape by itself does not become selection evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskSelectionDisposition {
    /// The caller selected no task.
    Absent,
    /// One exploratory task is available for read-only orientation only.
    Exploratory {
        task_ref: String,
        task_revision: u64,
        acceptance_digest: String,
    },
    /// More than one candidate task handle survived selection; none is chosen.
    /// The owner-issued handles are carried verbatim so the caller can answer
    /// with the bounded eligible set instead of inventing a choice.
    Ambiguous(Vec<String>),
    /// A task selection names an older revision; preserve the exact identity
    /// for the owner's refresh/rebind response instead of treating it as absent.
    Stale {
        task_ref: String,
        task_revision: u64,
    },
    /// One current `TaskContract` revision with owner-proven selection evidence.
    Current(TaskSelectionEvidence),
}

/// Agent-facing result of resolving the current task selection.
///
/// Absence carries the existing bounded task-intake shape for the retained
/// scope; task-candidate ambiguity preserves the exact owner-issued handles
/// and remains distinct from active-work scope ambiguity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskSelectionResponse {
    /// No current selection; caller can answer with this scope's intake shape.
    Absent(Box<eliot_workscope::TaskSelectionRequired>),
    /// Exploratory binding stays explicitly read-only, not material task work.
    Exploratory {
        task_ref: String,
        task_revision: u64,
        acceptance_digest: String,
    },
    /// Multiple task candidates survived; none is selected.
    Ambiguous(Vec<String>),
    /// Stale task identity preserved for an explicit refresh/rebind response.
    Stale {
        task_ref: String,
        task_revision: u64,
    },
    /// One exact current `TaskContract` revision with its owner evidence.
    Current(TaskSelectionEvidence),
}

/// Typed identity correlation of one activation result to its exact ticket
/// (issue #1746, W2).
///
/// Every arm carries only owner-resolved values: the `Resolved` arm repeats
/// the principal/session/task/scope/revision the Governor's typed resolution
/// bound to the exact ticket, never a caller-supplied principal/task string
/// and never the bridge-process identity. Selection/retry/denial arms preserve
/// the exact owner-issued candidate handles and retry terms instead of
/// selecting the latest or most similar task. Stored Resolved/READY values are
/// projections, not authority: this correlation is valid only for the exact
/// ticket it was computed against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationCorrelation {
    /// Exact ticket-bound application identity with its owner revision fence.
    Resolved {
        principal_id: String,
        session_id: String,
        task_id: String,
        work_scope_id: String,
        task_revision: u64,
        owner_revision: u64,
        state_fence: StateFence,
    },
    /// No task is selected; the bounded eligible task handles survive verbatim.
    TaskSelectionRequired {
        candidate_handles: Vec<String>,
        candidate_coverage: AgentActivationCandidateCoverage,
        recovery_handle: String,
    },
    /// No scope is selected; the bounded eligible scope handles survive verbatim.
    ScopeSelectionRequired {
        candidate_handles: Vec<String>,
        candidate_coverage: AgentActivationCandidateCoverage,
        recovery_handle: String,
    },
    /// Several scopes survived; none is chosen.
    ScopeAmbiguous {
        candidate_handles: Vec<String>,
        candidate_coverage: AgentActivationCandidateCoverage,
        recovery_handle: String,
    },
    /// Transient hold: retry only under the exact owner-issued retry terms.
    Retry {
        recovery_handle: String,
        dependency_ref: String,
        observed_dependency_revision: String,
        not_before_unix_ms: u64,
    },
    /// The ticket fence moved; re-resolve at the observed fence, never reuse.
    Stale {
        recovery_handle: String,
        observed_state_fence: Option<StateFence>,
    },
    /// Terminal owner denial; carries no identity and selects nothing.
    Denied { failure_handle: String },
}

/// Correlates one typed activation result to its exact ticket through the
/// existing activation route (issue #1746, W2).
///
/// Runs the existing owner join
/// (`AgentActivationResolutionResult::validate_against`, owned by
/// `eliot-protocol`): exact ticket identity/digest/fence/cancellation match,
/// deadline and successor-observation terms. A result for another ticket, a
/// mismatching digest/fence, or an expired/cancelled identity fails closed
/// with `TASK_SCOPE_INCOMPATIBLE`. The typed disposition is then projected
/// without invention: `Resolved` repeats the owner binding plus the
/// authenticated owner revision; every selection arm preserves the exact
/// owner-issued candidate handles; `NotReady` preserves the exact retry terms;
/// `StaleFence` preserves the observed fence; `FailedInternal` stays a denial.
/// No caller principal/task string enters on any arm, and the bridge-process
/// identity is never copied as the end user.
///
/// Designated caller (STITCH, activation lane): the activation resolution
/// projection (`bins/eliotd/src/activation_projection.rs`,
/// `map_governor_outcome_to_protocol`, behind
/// `GovernorComposition::resolve_activation_outcome`) correlates each produced
/// ticket/result pair here before the daemon derives the
/// `GovernorActivationSnapshot` that [`bind_current_task_selection`] consumes.
/// Until that wiring lands, this entry selects nothing and stores nothing.
pub fn correlate_activation_result(
    ticket: &AgentActivationResolutionTicket,
    result: &AgentActivationResolutionResult,
) -> Result<ActivationCorrelation, TaskBindingError> {
    result.validate_against(ticket).map_err(|error| {
        TaskBindingError::scope_incompatible(format!(
            "activation result does not correlate to the exact ticket/request: {error}"
        ))
    })?;
    match &result.disposition {
        AgentActivationResolutionDisposition::Resolved { binding } => {
            let task_revision = binding.task_revision.parse::<u64>().map_err(|_| {
                TaskBindingError::scope_incompatible(
                    "activation binding carries no current task revision",
                )
            })?;
            if task_revision == 0 {
                return Err(TaskBindingError::scope_incompatible(
                    "activation binding carries no current task revision",
                ));
            }
            let evidence = result.owner_evidence.as_ref().ok_or_else(|| {
                TaskBindingError::scope_incompatible(
                    "resolved activation carries no authenticated owner evidence",
                )
            })?;
            Ok(ActivationCorrelation::Resolved {
                principal_id: binding.principal_id.clone(),
                session_id: binding.session_id.clone(),
                task_id: binding.task_id.clone(),
                work_scope_id: binding.work_scope_id.clone(),
                task_revision,
                owner_revision: evidence.owner_revision,
                state_fence: evidence.state_fence.clone(),
            })
        }
        AgentActivationResolutionDisposition::TaskSelectionRequired { selection } => {
            Ok(ActivationCorrelation::TaskSelectionRequired {
                candidate_handles: selection.candidate_handles.clone(),
                candidate_coverage: selection.candidate_coverage,
                recovery_handle: selection.recovery_handle.clone(),
            })
        }
        AgentActivationResolutionDisposition::ScopeSelectionRequired { selection } => {
            Ok(ActivationCorrelation::ScopeSelectionRequired {
                candidate_handles: selection.candidate_handles.clone(),
                candidate_coverage: selection.candidate_coverage,
                recovery_handle: selection.recovery_handle.clone(),
            })
        }
        AgentActivationResolutionDisposition::ScopeAmbiguous { selection } => {
            Ok(ActivationCorrelation::ScopeAmbiguous {
                candidate_handles: selection.candidate_handles.clone(),
                candidate_coverage: selection.candidate_coverage,
                recovery_handle: selection.recovery_handle.clone(),
            })
        }
        AgentActivationResolutionDisposition::NotReady {
            recovery_handle,
            retry,
        } => Ok(ActivationCorrelation::Retry {
            recovery_handle: recovery_handle.clone(),
            dependency_ref: retry.dependency_ref.clone(),
            observed_dependency_revision: retry.observed_dependency_revision.clone(),
            not_before_unix_ms: retry.not_before_unix_ms,
        }),
        AgentActivationResolutionDisposition::StaleFence {
            recovery_handle,
            observed_state_fence,
        } => Ok(ActivationCorrelation::Stale {
            recovery_handle: recovery_handle.clone(),
            observed_state_fence: observed_state_fence.clone(),
        }),
        AgentActivationResolutionDisposition::FailedInternal { failure_handle } => {
            Ok(ActivationCorrelation::Denied {
                failure_handle: failure_handle.clone(),
            })
        }
    }
}

/// Builds the agent-facing task-selection response for one caller-presented
/// readiness receipt (issue #1746, W4).
///
/// This is the typed Absent/Ambiguous-bounded answer constructor behind
/// [`resolve_task_selection`]: `Absent` carries this scope's bounded intake
/// shape from the existing task-intake owner
/// (`eliot_workscope::task_selection_required`); `Ambiguous` preserves the
/// exact owner-issued candidate handles verbatim (bounded 2..=16 by the
/// receipt owner) so the caller answers with the eligible set instead of
/// choosing; `Exploratory` stays explicitly read-only; `Stale` preserves the
/// exact revision for a refresh/rebind answer; `Current` without
/// owner-proven selection source/evidence is refused with
/// `TASK_SELECTION_REQUIRED` (structural validation of request-supplied
/// evidence is never sufficient). No task is ever auto-created to remove an
/// absence, and no cold capture is retroactively attached here.
///
/// Called by [`admit_canonical_write`] to derive its selection legs.
pub fn selection_response_for_receipt(
    receipt: &OnboardingReadinessReceipt,
) -> Result<TaskSelectionResponse, TaskBindingError> {
    match resolve_task_selection(receipt)? {
        TaskSelectionDisposition::Absent => {
            let intake = task_selection_required(&receipt.scope.scope_ref).map_err(|_| {
                TaskBindingError::selection_required(
                    "task selection is absent and no intake shape is available",
                )
            })?;
            Ok(TaskSelectionResponse::Absent(Box::new(intake)))
        }
        TaskSelectionDisposition::Exploratory {
            task_ref,
            task_revision,
            acceptance_digest,
        } => Ok(TaskSelectionResponse::Exploratory {
            task_ref,
            task_revision,
            acceptance_digest,
        }),
        TaskSelectionDisposition::Ambiguous(candidate_handles) => {
            Ok(TaskSelectionResponse::Ambiguous(candidate_handles))
        }
        TaskSelectionDisposition::Stale {
            task_ref,
            task_revision,
        } => Ok(TaskSelectionResponse::Stale {
            task_ref,
            task_revision,
        }),
        TaskSelectionDisposition::Current(evidence) => Ok(TaskSelectionResponse::Current(evidence)),
    }
}

/// Admits one `eliot.observe` capture without ever guessing a task.
///
/// - `selection = None` or `candidate_count != 1` (absent/ambiguous) admits
///   only [`CaptureAdmission::ColdUnbound`]: no activation, promotion, or
///   finish relevance.
/// - Exactly one canonical, valid, compatible, uncontaminated selection admits
///   [`CaptureAdmission::TaskBound`] for a later governed binding transition;
///   this function still performs no promotion itself. A contaminated
///   selection (canonical crossover marker) stays cold, mirroring the
///   Governor `Quarantined` disposition.
/// - There is deliberately no `latest_task`, `open_task`, or resolver-guess
///   input: ambiguity stays cold.
pub fn admit_capture(
    candidate_id: String,
    state_fence: StateFence,
    selection: Option<&TaskSelectionEvidence>,
    candidate_count: usize,
    compatibility: CompatibilityDisposition,
) -> Result<CaptureAdmission, TaskBindingError> {
    if state_fence.validate().is_err() {
        return Err(TaskBindingError::selection_required(
            "capture.state_fence is invalid",
        ));
    }
    if candidate_id.trim().is_empty() || candidate_id.chars().any(char::is_control) {
        return Err(TaskBindingError::selection_required(
            "capture.candidate_id is blank",
        ));
    }
    match selection {
        None => Ok(CaptureAdmission::ColdUnbound(
            ObservationCandidate::cold_unbound(candidate_id, state_fence),
        )),
        Some(evidence) => {
            if candidate_count != 1 {
                return Ok(CaptureAdmission::ColdUnbound(
                    ObservationCandidate::cold_unbound(candidate_id, state_fence),
                ));
            }
            evidence.validate().map_err(|error| {
                TaskBindingError::selection_required(format!(
                    "task selection evidence invalid: {error}"
                ))
            })?;
            if evidence.is_contaminated() {
                return Ok(CaptureAdmission::ColdUnbound(
                    ObservationCandidate::cold_unbound(candidate_id, state_fence),
                ));
            }
            match compatibility {
                CompatibilityDisposition::Compatible => {
                    Ok(CaptureAdmission::TaskBound(evidence.clone()))
                }
                CompatibilityDisposition::Incompatible => {
                    Err(TaskBindingError::scope_incompatible(
                        "task selection is incompatible with observation scope",
                    ))
                }
            }
        }
    }
}

/// Admits one task-relative reusable/control transition.
///
/// Requires the canonical selection evidence, the expected task and
/// `WorkScope` handles, a valid current fence that scopes this admission,
/// and a `Compatible` disposition. Missing evidence rejects with
/// `TASK_SELECTION_REQUIRED`; a `WorkScope`/task mismatch or an incompatible
/// disposition rejects with `TASK_SCOPE_INCOMPATIBLE` without changing either
/// task (this function mutates nothing). A contaminated selection never
/// promotes: it rejects as non-current evidence.
pub fn admit_task_bound(
    selection: Option<&TaskSelectionEvidence>,
    expected_task_ref: &str,
    expected_work_scope_ref: &str,
    expected_fence: &StateFence,
    compatibility: CompatibilityDisposition,
) -> Result<(), TaskBindingError> {
    let Some(evidence) = selection else {
        return Err(TaskBindingError::selection_required(
            "task-bound promotion requires current TaskSelectionEvidence",
        ));
    };
    evidence.validate().map_err(|error| {
        TaskBindingError::selection_required(format!("task selection evidence invalid: {error}"))
    })?;
    if evidence.is_contaminated() {
        return Err(TaskBindingError::selection_required(
            "task selection is contaminated",
        ));
    }
    if evidence.task_ref != expected_task_ref {
        return Err(TaskBindingError::scope_incompatible(
            "task selection names a different task",
        ));
    }
    if evidence.work_scope_ref != expected_work_scope_ref {
        return Err(TaskBindingError::scope_incompatible(
            "task selection names a different WorkScope",
        ));
    }
    if expected_fence.validate().is_err() {
        return Err(TaskBindingError::selection_required(
            "task-bound promotion requires a valid current fence",
        ));
    }
    match compatibility {
        CompatibilityDisposition::Compatible => Ok(()),
        CompatibilityDisposition::Incompatible => Err(TaskBindingError::scope_incompatible(
            "task selection is incompatible with the target WorkScope",
        )),
    }
}

/// Refuses a task-identity conflict between the admitted request context and
/// the write envelope (issue #1746, A2).
///
/// A task-relative write whose envelope names a different task than the
/// admitted context — or names no task at all — can never receive a task-bound
/// write: the former fails closed with `TASK_SCOPE_INCOMPATIBLE`, the latter
/// with `TASK_SELECTION_REQUIRED`. Neither arm changes a task. Called by
/// [`admit_canonical_write`] for its task-relative leg, so the wrong
/// workspace/task case rejects before any selection evidence is consulted.
pub fn refuse_task_identity_conflict(
    context_task_ref: Option<&str>,
    envelope_task_ref: Option<&str>,
) -> Result<String, TaskBindingError> {
    let Some(envelope_task_ref) = envelope_task_ref else {
        return Err(TaskBindingError::selection_required(
            "task-relative write names no task binding",
        ));
    };
    if envelope_task_ref.trim().is_empty() || envelope_task_ref.chars().any(char::is_control) {
        return Err(TaskBindingError::selection_required(
            "task-relative write names no task binding",
        ));
    }
    if let Some(context_task_ref) = context_task_ref
        && context_task_ref != envelope_task_ref
    {
        return Err(TaskBindingError::scope_incompatible(
            "task-relative write names a different task than the admitted context",
        ));
    }
    Ok(envelope_task_ref.to_owned())
}

/// Refuses a material effect without owner-proven selection evidence
/// (issue #1746, A7).
///
/// A READY lifecycle token, a successful handshake, or a pure DTO shape grants
/// nothing by itself: without owner evidence this entry fails closed with
/// `TASK_SELECTION_REQUIRED` however material the receipt claims to be, and
/// the READY token is never even read. With owner evidence the bootstrap must
/// additionally rest on an authenticated scope at material readiness, or the
/// effect is withheld with `TASK_SCOPE_INCOMPATIBLE`. Called by
/// [`admit_canonical_write`] for its task-relative leg before
/// [`admit_task_bound`].
pub fn refuse_ready_string_without_evidence(
    receipt: &OnboardingReadinessReceipt,
    has_owner_evidence: bool,
) -> Result<(), TaskBindingError> {
    if !has_owner_evidence {
        return Err(TaskBindingError::selection_required(
            "task-relative effect has no owner-proven selection evidence; readiness tokens grant nothing",
        ));
    }
    if receipt.scope_resolution != ScopeResolutionState::Authenticated
        || receipt.readiness != ReadinessLifecycle::ReadyMaterial
    {
        return Err(TaskBindingError::scope_incompatible(
            "task-relative effect rests on a bootstrap that is not authenticated material readiness",
        ));
    }
    Ok(())
}

/// Runs the existing `WorkScope` guard legs at one use boundary and returns
/// the typed disposition (issue #1746, W3; I4.2.1).
///
/// The observed binding is derived from the actual live workspace/resource
/// observation through the existing owner (`eliot_workscope::observed_scope_binding`:
/// exact instance/root, lineage, and resource generation — never a caller cwd
/// or a normalized path string), then checked with the existing
/// sources-independent identity legs (`eliot_workscope::identity_legs`).
/// `MATCHED` admits; stale, different-instance, ambiguous, or conflicted
/// observations fail closed with `TASK_SCOPE_INCOMPATIBLE` carrying the exact
/// disposition, and the retained binding, task state, and project memory stay
/// untouched. A relocation is not a silent move: the legs compare the exact
/// instance/root, lineage, and generation, so a moved observation reports
/// `DIFFERENT_INSTANCE` (or `STALE_BINDING` for a moved revision) and fails
/// closed; only an explicit owner receipt (`produce_attach_receipt` /
/// `rebind_with_receipt`, owned by `eliot-workscope` and admitted by
/// `GovernorComposition::admit_observed_scope_attach`) can establish a new
/// binding. A provisional scope never admits a
/// task-bound effect here: scope uncertainty permits only the quarantined
/// capture route ([`admit_capture`] `ColdUnbound`, conflicting lineage
/// preserved).
///
/// Called by [`admit_task_bound_with_observed_scope`].
pub fn scope_guard_disposition(
    expected: &ScopeBinding,
    observed: &ObservedScopeResources,
) -> Result<ScopeBindingDisposition, TaskBindingError> {
    let observed_binding = eliot_workscope::observed_scope_binding(
        expected,
        observed,
        expected.privacy_class,
        expected.governing_source_generation,
    )
    .map_err(|error| match error {
        eliot_workscope::WorkScopeError::AmbiguousObservation { observed_instances } => {
            TaskBindingError::scope_incompatible(format!(
                "task observation scope identity check AMBIGUOUS: {observed_instances} workspace instances observed"
            ))
        }
        other => TaskBindingError::scope_incompatible(format!(
            "task observation scope identity could not be established: {other}"
        )),
    })?;
    match eliot_workscope::identity_legs(expected, &observed_binding) {
        eliot_workscope::IdentityLegOutcome::IdentityClear => Ok(ScopeBindingDisposition::Matched),
        eliot_workscope::IdentityLegOutcome::DifferentInstance => {
            Ok(ScopeBindingDisposition::DifferentInstance)
        }
        eliot_workscope::IdentityLegOutcome::Ambiguous => Ok(ScopeBindingDisposition::Ambiguous),
        eliot_workscope::IdentityLegOutcome::StaleBinding => {
            Ok(ScopeBindingDisposition::StaleBinding)
        }
    }
}

/// Admits one task-relative transition with observed workspace identity.
///
/// Extends [`admit_task_bound`] with the sources-independent scope-identity
/// legs for the first tool-event trigger. It derives the observed binding from
/// the complete live workspace observation, including lineage, exact
/// instance/root, and resource generation. A mismatching checkout fails
/// closed with `TASK_SCOPE_INCOMPATIBLE` naming the exact disposition
/// (`DIFFERENT_INSTANCE`, `AMBIGUOUS`, or `STALE_BINDING`); the retained
/// binding, task state, and project memory are untouched. An identity-clear
/// result is only an identity check; this helper does not replace the full
/// source-closure guard required before a scope-sensitive effect.
///
/// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
#[allow(
    clippy::too_many_arguments,
    reason = "admission joins the retained binding, live observation, fence, and compatibility in one edge"
)]
pub fn admit_task_bound_with_observed_scope(
    selection: Option<&TaskSelectionEvidence>,
    expected_task_ref: &str,
    expected: &ScopeBinding,
    observed: &ObservedScopeResources,
    expected_fence: &StateFence,
    compatibility: CompatibilityDisposition,
) -> Result<(), TaskBindingError> {
    if selection.is_none() {
        return admit_task_bound(
            None,
            expected_task_ref,
            &expected.scope.scope_ref,
            expected_fence,
            compatibility,
        );
    }
    let observed_binding = scope_guard_disposition(expected, observed)?;
    match observed_binding {
        ScopeBindingDisposition::Matched => {}
        ScopeBindingDisposition::DifferentInstance => {
            return Err(TaskBindingError::scope_incompatible(
                "task observation scope identity check DIFFERENT_INSTANCE",
            ));
        }
        ScopeBindingDisposition::Ambiguous => {
            return Err(TaskBindingError::scope_incompatible(
                "task observation scope identity check AMBIGUOUS",
            ));
        }
        ScopeBindingDisposition::StaleBinding => {
            return Err(TaskBindingError::scope_incompatible(
                "task observation scope identity check STALE_BINDING",
            ));
        }
        ScopeBindingDisposition::ProvisionalRebind | ScopeBindingDisposition::Conflicted => {
            return Err(TaskBindingError::scope_incompatible(
                "task observation scope identity check CONFLICTED: rebind with an explicit owner receipt",
            ));
        }
    }
    admit_task_bound(
        selection,
        expected_task_ref,
        &expected.scope.scope_ref,
        expected_fence,
        compatibility,
    )
}

/// Resolves the exact task-selection disposition of one caller-presented
/// readiness receipt (I5.6 step 4, issue #1929).
///
/// A current binding lacks owner-proven selection source/evidence in the
/// receipt, so this function returns `TASK_SELECTION_REQUIRED` rather than
/// fabricating [`TaskSelectionEvidence`]. The governance profile and receipt
/// handle are unrelated to task selection and are not used as provenance.
/// Every non-current binding state keeps its typed meaning:
///
/// - [`TaskBindingState::None_`] — the caller selected no task;
/// - `Exploratory` — a task is named but the binding is explicitly
///   non-material, so it remains a read-only disposition;
/// - `Stale` — the exact named revision is no longer current and is preserved
///   for an owner refresh/rebind response;
/// - `Ambiguous` — several candidate handles survived selection and the receipt
///   is forbidden to prefer one, so the candidate count is preserved and the
///   disposition stays non-material.
///
/// There is deliberately no latest-task, open-task, or resolver-guess leg here:
/// ambiguity is reported, never resolved. The task-intake owner producer is
/// absent pending issue #8.
pub fn resolve_task_selection(
    receipt: &OnboardingReadinessReceipt,
) -> Result<TaskSelectionDisposition, TaskBindingError> {
    match &receipt.task_binding {
        TaskBindingState::CurrentTaskContract { .. } => Err(TaskBindingError::selection_required(
            "current task has no owner-proven selection source/evidence",
        )),
        TaskBindingState::Exploratory {
            task_ref,
            task_revision,
            acceptance_digest,
        } => Ok(TaskSelectionDisposition::Exploratory {
            task_ref: task_ref.clone(),
            task_revision: *task_revision,
            acceptance_digest: acceptance_digest.clone(),
        }),
        TaskBindingState::Ambiguous { candidate_handles } => Ok(
            TaskSelectionDisposition::Ambiguous(candidate_handles.clone()),
        ),
        TaskBindingState::Stale {
            task_ref,
            task_revision,
        } => Ok(TaskSelectionDisposition::Stale {
            task_ref: task_ref.clone(),
            task_revision: *task_revision,
        }),
        TaskBindingState::None_ => Ok(TaskSelectionDisposition::Absent),
    }
}

/// Rechecks one Governor-resolved task selection against the current
/// applicability and fence before any admission (I5.6 step 4, issue #1746 W4).
///
/// [`resolve_task_selection`] refuses `CurrentTaskContract` today because the
/// readiness receipt has no owner-proven selection source/evidence. If that
/// owner producer is added, this entry is the applicability leg required by
/// the issue: the acceptance digest, `TaskContract` revision, and `WorkScope`
/// from the owner-compiled receipt must name exactly what the activation route
/// proved at this exact fence — principal, session, task, non-zero revision,
/// and `WorkScope`. A selection naming another task, moved revision, or other
/// scope rejects with `TASK_SCOPE_INCOMPATIBLE` and admits nothing. Until then,
/// no current selection evidence escapes this entry.
///
/// Structure preserved, never resolved:
///
/// - [`TaskSelectionDisposition::Absent`] stays absent. No task is created to
///   remove a missing selection;
/// - [`TaskSelectionDisposition::Ambiguous`] keeps the owner-issued candidate
///   handles verbatim (bounded by the owner that produced them) so the caller
///   can return the typed selection/intake response. None is chosen;
/// - exploratory bindings remain explicitly read-only, and stale bindings
///   preserve the exact task and revision for an owner refresh/rebind response;
/// - a receipt compiled for a different `WorkScope` or a different fence is
///   refused before the binding state is even inspected.
///
/// It reads no caller-supplied `TaskSelectionEvidence`: structural validation
/// of evidence a request carried is never sufficient here.
pub fn bind_current_task_selection(
    activation: Option<&eliot_governor::GovernorActivationSnapshot>,
    receipt: &OnboardingReadinessReceipt,
    live_fence: &StateFence,
) -> Result<TaskSelectionDisposition, TaskBindingError> {
    receipt.validate().map_err(|error| {
        TaskBindingError::scope_incompatible(format!(
            "compiled readiness receipt is invalid: {error}"
        ))
    })?;
    if !eliot_contracts::fences_match_exact(&receipt.state_fence, live_fence) {
        return Err(TaskBindingError::scope_incompatible(
            "compiled readiness receipt was compiled at another fence",
        ));
    }
    let disposition = resolve_task_selection(receipt)?;
    let TaskSelectionDisposition::Current(evidence) = &disposition else {
        // The Governor's current-task owner returns no activation for these
        // receipt states. A contradictory activation must fail closed rather
        // than being discarded or reported as an ordinary task choice.
        if activation.is_some() {
            return Err(TaskBindingError::scope_incompatible(
                "activation route returned a task for a non-current TaskContract receipt",
            ));
        }
        return Ok(disposition);
    };
    let activation = activation.ok_or_else(|| {
        TaskBindingError::scope_incompatible(
            "current TaskContract receipt has no owner-validated activation snapshot",
        )
    })?;
    if !eliot_contracts::fences_match_exact(&activation.state_fence, live_fence) {
        return Err(TaskBindingError::scope_incompatible(
            "activation snapshot is not applicable at the current fence",
        ));
    }
    if receipt.principal_ref != activation.principal_id
        || receipt.session_ref != activation.session_id
        || receipt.scope.scope_ref != activation.work_scope_id
    {
        return Err(TaskBindingError::scope_incompatible(
            "compiled readiness receipt is bound to another principal, session, or WorkScope",
        ));
    }
    if evidence.task_ref != activation.task_id.as_str()
        || evidence.task_revision != activation.task_revision
        || evidence.work_scope_ref != activation.work_scope_id
    {
        return Err(TaskBindingError::scope_incompatible(
            "task selection is no longer the applicable TaskContract revision",
        ));
    }
    if receipt.scope_resolution != eliot_workscope::ScopeResolutionState::Authenticated {
        return Err(TaskBindingError::scope_incompatible(
            "task selection rests on a scope that is not authenticated",
        ));
    }
    if receipt.readiness != eliot_workscope::ReadinessLifecycle::ReadyMaterial {
        return Err(TaskBindingError::scope_incompatible(
            "task selection rests on a readiness that is not material-ready",
        ));
    }
    Ok(disposition)
}

/// Agent-facing bootstrap admission assembled from real owners
/// (issue #1746, W5; I7.8 step 4, I7.11).
#[expect(
    clippy::large_enum_variant,
    reason = "Material carries the owner-evidenced bootstrap identity by value so the dispatch gate sees the exact admitted fields"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapAdmission {
    /// Complete owner-evidenced bootstrap: may proceed to Material work only
    /// through the #1742 owner gate
    /// (`GovernorComposition::commit_canonical_with_readiness`, which runs
    /// `check_material_readiness_for_write`). This value is not Material
    /// authority by itself.
    Material(MaterialBootstrap),
    /// Diagnostic bootstrap: selection/intake data, never Material-ready.
    /// A bootstrap without a task always lands here.
    Diagnostic {
        reason: &'static str,
        next_safe_action: String,
    },
    /// No task is selected: answer with this scope's bounded intake shape.
    IntakeRequired(Box<eliot_workscope::TaskSelectionRequired>),
}

/// Owner-evidenced bootstrap identity carried toward the #1746 dispatch gate.
///
/// Every field repeats an owner-issued value bound to the same
/// session/scope/selection-state and source revisions: the receipt revision
/// and fence from the compiled [`OnboardingReadinessReceipt`], the governance
/// profile revision from the Governor-derived [`GovernanceProfile`], the
/// coverage fingerprint from the verified [`IntegrationCoverageProfile`], and
/// the projection source/generation from #8's `ColdStartSurfaceView`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterialBootstrap {
    pub receipt_ref: String,
    pub lease_ref: String,
    pub principal_ref: String,
    pub session_ref: String,
    pub scope_ref: String,
    pub task: TaskSelectionEvidence,
    pub state_fence: StateFence,
    pub receipt_revision: u64,
    pub governance_profile_ref: String,
    pub governance_revision: u64,
    pub coverage_fingerprint: String,
    pub projection_source_ref: String,
    pub projection_generation: u64,
}

/// Assembles one bootstrap from its real owners and admits it for dispatch
/// (issue #1746, W5; I7.8 step 4, I7.11).
///
/// Joins #8's response surface (`ColdStartSurfaceView` with boot delta) to the
/// compiled [`OnboardingReadinessReceipt`], the [`IntegrationCoverageProfile`],
/// and the derived [`GovernanceProfile`], all bound to the same
/// session/scope/task-or-selection-state and source revisions: receipt/lease,
/// principal/session, scope/instance/lineage, task binding, state fence,
/// governing-source set/generation, governance/route profile refs, receipt
/// revision, and projection source/generation must name the same values on
/// both sides, or the join fails closed with `TASK_SCOPE_INCOMPATIBLE`.
///
/// Unknown/unavailable/partial profile evidence is preserved, never defaulted:
/// absent coverage/governance profiles, or present-but-unverified ones, yield
/// `Diagnostic`, never `Material`. Empty sensor lists or a caller READY flag
/// cannot imply full readiness — and the surface's string readiness token is
/// never even read here (issue #1746, A7): only the receipt's typed
/// [`ReadinessLifecycle`] and the surface's typed [`ScopeResolutionState`]
/// decide. `Material` additionally requires an authenticated scope, material
/// readiness, exact current selection evidence, and fingerprint-matched
/// verified profiles; anything else is `Diagnostic` (without a task, always)
/// or `IntakeRequired` (no task selected). Budget previews and expansion
/// handles travel on the owners' surfaces; required selection, authority, and
/// recovery information is never dropped by this join.
///
/// Designated caller (STITCH, daemon composition lane):
/// `DaemonComposition::read_cold_start_surface_for_attach` supplies the exact
/// retained surface for the lease, and
/// [`DaemonComposition::commit_canonical_and_refresh`](super::DaemonComposition)
/// carries the admitted bootstrap toward the #1742 Material gate. This entry
/// mints no profile, receipt, or lease of its own.
#[allow(
    clippy::too_many_arguments,
    reason = "bootstrap joins the receipt, surface, both profiles, and the live fence in one edge"
)]
#[expect(
    clippy::too_many_lines,
    reason = "one owner join over receipt, surface, coverage, governance, and fence; splitting would scatter the fail-closed ordering"
)]
pub fn admit_bootstrap_context(
    receipt: &OnboardingReadinessReceipt,
    surface: &ColdStartSurfaceView,
    coverage: Option<&IntegrationCoverageProfile>,
    governance: Option<&GovernanceProfile>,
    live_fence: &StateFence,
) -> Result<BootstrapAdmission, TaskBindingError> {
    receipt.validate().map_err(|error| {
        TaskBindingError::scope_incompatible(format!(
            "compiled readiness receipt is invalid: {error}"
        ))
    })?;
    if !eliot_contracts::fences_match_exact(&receipt.state_fence, live_fence) {
        return Err(TaskBindingError::scope_incompatible(
            "compiled readiness receipt was compiled at another fence",
        ));
    }
    // Same session/scope/selection-state and source revisions on both sides.
    // Each comparison names its field so a drifted join diagnoses exactly.
    let bound = |field: &'static str, left: &str, right: &str| -> Result<(), TaskBindingError> {
        if left != right {
            return Err(TaskBindingError::scope_incompatible(format!(
                "bootstrap surface is bound to another {field}"
            )));
        }
        Ok(())
    };
    bound("receipt", &receipt.receipt_ref, &surface.receipt_ref)?;
    bound("lease", &receipt.lease_ref, &surface.lease_ref)?;
    bound("principal", &receipt.principal_ref, &surface.principal_ref)?;
    bound("session", &receipt.session_ref, &surface.session_ref)?;
    bound("scope", &receipt.scope.scope_ref, &surface.scope.scope_ref)?;
    bound(
        "instance",
        &receipt.instance.instance_ref,
        &surface.instance.instance_ref,
    )?;
    bound(
        "lineage",
        receipt
            .lineage
            .as_ref()
            .map_or("", |lineage| lineage.lineage_ref.as_str()),
        surface
            .lineage
            .as_ref()
            .map_or("", |lineage| lineage.lineage_ref.as_str()),
    )?;
    if receipt.task_binding != surface.task_binding {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap surface names another task-or-selection-state",
        ));
    }
    if !eliot_contracts::fences_match_exact(&receipt.state_fence, &surface.state_fence) {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap surface was projected at another fence",
        ));
    }
    bound(
        "governing-source set",
        &receipt.governing_source_set_ref,
        &surface.governing_source_set_ref,
    )?;
    if receipt.governing_source_generation != surface.governing_source_generation {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap surface names another governing-source generation",
        ));
    }
    bound(
        "governance profile",
        &receipt.governance_profile_ref,
        &surface.governance_profile_ref,
    )?;
    bound(
        "route profile",
        &receipt.route_profile_ref,
        &surface.route_profile_ref,
    )?;
    if receipt.receipt_revision != surface.receipt_revision {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap surface names another receipt revision",
        ));
    }
    bound(
        "projection source",
        &receipt.projection_source_ref,
        &surface.projection_source_ref,
    )?;
    if receipt.projection_generation != surface.projection_generation {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap surface names another projection generation",
        ));
    }
    // Profiles are owner evidence, never caller claims. Absent or unverified
    // profiles stay unknown: they cap the bootstrap at Diagnostic.
    let verified_profiles = match (coverage, governance) {
        (Some(coverage), Some(governance)) => {
            coverage.validate().map_err(|error| {
                TaskBindingError::scope_incompatible(format!(
                    "integration coverage profile is invalid: {error}"
                ))
            })?;
            if coverage.fingerprint != governance.fingerprint {
                return Err(TaskBindingError::scope_incompatible(
                    "coverage and governance profiles name different fingerprints",
                ));
            }
            coverage.verified && governance.verified
        }
        _ => false,
    };
    match selection_response_for_receipt(receipt)? {
        TaskSelectionResponse::Absent(intake) => Ok(BootstrapAdmission::IntakeRequired(intake)),
        TaskSelectionResponse::Ambiguous(_) => Ok(BootstrapAdmission::Diagnostic {
            reason: "task selection is ambiguous; answer with the bounded eligible handles",
            next_safe_action: receipt.next_safe_action.clone(),
        }),
        TaskSelectionResponse::Exploratory { .. } => Ok(BootstrapAdmission::Diagnostic {
            reason: "exploratory binding is read-only orientation, not material work",
            next_safe_action: receipt.next_safe_action.clone(),
        }),
        TaskSelectionResponse::Stale { .. } => Ok(BootstrapAdmission::Diagnostic {
            reason: "task selection is stale; refresh or rebind before material work",
            next_safe_action: receipt.next_safe_action.clone(),
        }),
        TaskSelectionResponse::Current(task) => {
            // `resolve_task_selection` refuses `CurrentTaskContract` until the
            // readiness receipt carries owner-proven selection source/evidence,
            // so this arm is unreachable today and becomes reachable only
            // through that owner producer — never through a caller READY flag.
            if receipt.scope_resolution != ScopeResolutionState::Authenticated
                || receipt.readiness != ReadinessLifecycle::ReadyMaterial
            {
                return Ok(BootstrapAdmission::Diagnostic {
                    reason: "bootstrap is not authenticated material readiness",
                    next_safe_action: receipt.next_safe_action.clone(),
                });
            }
            if !verified_profiles {
                return Ok(BootstrapAdmission::Diagnostic {
                    reason: "coverage or governance profile evidence is unknown or unverified",
                    next_safe_action: receipt.next_safe_action.clone(),
                });
            }
            let (Some(coverage), Some(governance)) = (coverage, governance) else {
                return Ok(BootstrapAdmission::Diagnostic {
                    reason: "coverage or governance profile evidence is unknown or unverified",
                    next_safe_action: receipt.next_safe_action.clone(),
                });
            };
            Ok(BootstrapAdmission::Material(MaterialBootstrap {
                receipt_ref: receipt.receipt_ref.clone(),
                lease_ref: receipt.lease_ref.clone(),
                principal_ref: receipt.principal_ref.clone(),
                session_ref: receipt.session_ref.clone(),
                scope_ref: receipt.scope.scope_ref.clone(),
                task,
                state_fence: receipt.state_fence.clone(),
                receipt_revision: receipt.receipt_revision,
                governance_profile_ref: receipt.governance_profile_ref.clone(),
                governance_revision: governance.revision,
                coverage_fingerprint: coverage.fingerprint.clone(),
                projection_source_ref: receipt.projection_source_ref.clone(),
                projection_generation: receipt.projection_generation,
            }))
        }
    }
}

/// Computes the `TaskContract` compatibility disposition for one write from
/// the caller's receipt: the selection is compatible only when the receipt was
/// compiled at the exact write fence and resolved the exact `WorkScope` the
/// write addresses.
///
/// Anything else is `Incompatible` and therefore rejects the task-relative
/// transition with `TASK_SCOPE_INCOMPATIBLE` instead of admitting it. This
/// reads only caller-presented terms; it resolves no authority of its own.
fn compatibility_for(
    receipt: &OnboardingReadinessReceipt,
    envelope: &CanonicalWriteEnvelope,
    write_fence: &StateFence,
) -> CompatibilityDisposition {
    if eliot_contracts::fences_match_exact(&receipt.state_fence, write_fence)
        && receipt.scope.scope_ref == envelope.scope_id.as_str()
    {
        CompatibilityDisposition::Compatible
    } else {
        CompatibilityDisposition::Incompatible
    }
}

/// Admits one daemon named-mutation write at the composition-root ingress
/// (issue #1929, I5.5 capture/promotion split, I5.6 step 4).
///
/// This is the composition-root named-mutation intake, and the only entry that
/// consumes a caller-presented [`OnboardingReadinessReceipt`]. Its one
/// production call site is
/// [`DaemonComposition::commit_canonical_and_refresh`](super::DaemonComposition);
/// that caller itself has zero production call sites, so the entry is not yet
/// reached in production. See the module's "Measured reachability" section for
/// the exact measurement. The write is split by what it actually is:
///
/// - a capture naming no task — the capture-first case — goes through
///   [`admit_capture`] and is returned as
///   [`TaskBindingAdmission::ColdUnbound`] unless the caller resolved one exact
///   compatible selection **and** the authenticated request names the task that
///   selection names. A selection naming a different task rejects with
///   `TASK_SCOPE_INCOMPATIBLE`; a selection whose admitted request names no task
///   at all stays cold, because that capture has no exact task selection for
///   this transition. It never affects task memory, support, influence, or
///   finish while cold;
/// - any task-relative write — one that names a task, or a task-control,
///   finish, or other task-bearing transition — requires the exact selection
///   and is admitted only through [`admit_task_bound`]. Absent, exploratory,
///   stale, or current-without-owner-proven-source evidence rejects with
///   `TASK_SELECTION_REQUIRED`; a selection naming a different task,
///   `WorkScope`, or moved fence rejects with `TASK_SCOPE_INCOMPATIBLE`,
///   mutating nothing;
/// - anything else is [`TaskBindingAdmission::NotTaskRelative`].
///
/// This entry never selects a task the caller did not name and never consults
/// recency, proximity, or the newest/open task. Its typed evidence is exactly
/// what the store bridge cannot see: the store gate re-derives presence and
/// agreement from the opaque proof handles, this gate verifies the
/// `TaskSelectionEvidence` values against the caller's own receipt. A
/// `TaskBound` admission carries the sealed [`DispatchedBinding`] forward; the
/// dispatch effect gate revalidates it against the live owners through
/// [`revalidate_dispatched_binding`] (and [`revalidate_task_bound_for_effect`]
/// for the fence leg) (issue #1746, W6/A5).
#[expect(
    clippy::too_many_lines,
    reason = "single dispatch edge sealing identity, scope, fence, and bootstrap revisions; splitting would scatter the conflict/rebind ordering"
)]
pub fn admit_canonical_write(
    candidate_id: String,
    context: &RequestMetadata,
    envelope: &CanonicalWriteEnvelope,
    receipt: &OnboardingReadinessReceipt,
    write_fence: &StateFence,
) -> Result<TaskBindingAdmission, TaskBindingError> {
    let compatibility = compatibility_for(receipt, envelope, write_fence);
    // Issue #1746, W1: the capture/task-relative split is derived from the
    // frozen requirement table, so gating cannot drift from the mapped
    // operation classes.
    let carries_requirement = |requirement: CanonicalOperationRequirement| {
        envelope
            .semantic_commands
            .iter()
            .any(|command| requirement_for_named_mutation(command.operation) == requirement)
    };
    let captures = carries_requirement(CanonicalOperationRequirement::SafeRawCapture);
    let task_relative = envelope.task_id.is_some()
        || carries_requirement(CanonicalOperationRequirement::TaskRelativeEffectful);
    // Issue #1746, W4: Absent stays absent and Ambiguous keeps its bounded
    // eligible handles through the single typed response constructor.
    // A task-free capture remains cold and unrelated non-task writes need
    // no task selection. Task-relative effects return the typed error.
    let (selection, candidate_count) = match selection_response_for_receipt(receipt) {
        Ok(TaskSelectionResponse::Absent(_)
        | TaskSelectionResponse::Exploratory { .. }
        | TaskSelectionResponse::Stale { .. }) => (None, 0_usize),
        Ok(TaskSelectionResponse::Ambiguous(candidate_handles)) => (None, candidate_handles.len()),
        Ok(TaskSelectionResponse::Current(evidence)) => (Some(evidence), 1_usize),
        Err(_) if !task_relative => (None, 0_usize),
        Err(error) => return Err(error),
    };

    if captures && !task_relative {
        // `admit_capture` consumes the candidate identity on each of its cold
        // arms, so the caller's own value is kept here: a capture that cannot
        // be shown to be task-bound is still retained cold, and this edge
        // mints no second candidate identity.
        let cold_candidate_id = candidate_id.clone();
        return match admit_capture(
            candidate_id,
            context.state_fence.clone(),
            selection.as_ref(),
            candidate_count,
            compatibility,
        )? {
            CaptureAdmission::ColdUnbound(candidate) => {
                Ok(TaskBindingAdmission::ColdUnbound(candidate))
            }
            CaptureAdmission::TaskBound(evidence) => {
                // The expected task is the one the authenticated admitted
                // request names, never the evidence's own value. Passing
                // `evidence.task_ref` as the expectation made this leg a
                // tautology: every check `admit_task_bound` performs here was
                // either already made by `admit_capture` (validate, not
                // contaminated) or structurally guaranteed by
                // `compatibility_for` (same fence, same `WorkScope`), so the
                // call could not reject and a `CurrentTaskContract` naming a
                // task other than the admitted one was still reported
                // task-bound. I5.5 requires the wrong-task case to reject.
                let Some(admitted_task_ref) = context.task_id.as_ref().map(TaskId::as_str) else {
                    // A capture whose admitted request names no task has no
                    // exact task selection for this transition. I5.5 keeps the
                    // capture-first observation cold instead of rejecting it,
                    // so the original observation is never discarded.
                    return Ok(TaskBindingAdmission::ColdUnbound(
                        ObservationCandidate::cold_unbound(
                            cold_candidate_id,
                            context.state_fence.clone(),
                        ),
                    ));
                };
                if evidence.task_ref != admitted_task_ref {
                    return Err(TaskBindingError::scope_incompatible(
                        "task-bound capture names a different task than the admitted context",
                    ));
                }
                admit_task_bound(
                    Some(&evidence),
                    admitted_task_ref,
                    envelope.scope_id.as_str(),
                    write_fence,
                    compatibility,
                )?;
                // Issue #1746, W6: seal the admitted identity (task, scope,
                // presented fence, bootstrap/profile revision) so the effect
                // gate revalidates it instead of reusing the caller fence.
                Ok(TaskBindingAdmission::TaskBound(seal_dispatched_binding(
                    evidence,
                    admitted_task_ref,
                    envelope.scope_id.as_str(),
                    write_fence,
                    receipt.receipt_revision,
                    &receipt.governance_profile_ref,
                    receipt.projection_generation,
                    cold_candidate_id,
                )?))
            }
        };
    }

    if task_relative {
        // Issue #1746, A6: the direct internal entrypoint enforces the same
        // binding rule as the bridge transport edge. Unreachable fail-closed:
        // the frozen table requires owner evidence for task-relative work at
        // every entrypoint.
        if !entrypoint_requires_binding(
            DispatchEntrypoint::DirectInternal,
            CanonicalOperationRequirement::TaskRelativeEffectful,
        ) {
            return Err(TaskBindingError::selection_required(
                "direct internal entrypoint cannot admit a task-relative effect without owner evidence",
            ));
        }
        // Issue #1746, A2: a wrong workspace/task identity cannot receive a
        // task-bound write. Issue #1746, A7: READY tokens grant nothing.
        let expected_task_ref = refuse_task_identity_conflict(
            context.task_id.as_ref().map(TaskId::as_str),
            envelope.task_id.as_deref(),
        )?;
        refuse_ready_string_without_evidence(receipt, selection.is_some())?;
        admit_task_bound(
            selection.as_ref(),
            &expected_task_ref,
            envelope.scope_id.as_str(),
            write_fence,
            compatibility,
        )?;
        let Some(evidence) = selection else {
            return Err(TaskBindingError::selection_required(
                "task-relative write admitted without selection evidence",
            ));
        };
        // Issue #1746, W6: seal the admitted identity for the effect gate.
        return Ok(TaskBindingAdmission::TaskBound(seal_dispatched_binding(
            evidence,
            &expected_task_ref,
            envelope.scope_id.as_str(),
            write_fence,
            receipt.receipt_revision,
            &receipt.governance_profile_ref,
            receipt.projection_generation,
            candidate_id,
        )?));
    }

    Ok(TaskBindingAdmission::NotTaskRelative)
}

/// Admitted operation/payload identity carried through dispatch
/// (issue #1746, W6).
///
/// The admitted binding is the exact [`TaskSelectionEvidence`] plus the task,
/// scope, presented fence, and bootstrap/profile revision it was admitted
/// under — never a mutable ambient selection. The effect gate revalidates it
/// with [`revalidate_dispatched_binding`]: a mismatch conflicts for rebind, it
/// is never rewritten to a new task under the old operation identity, never
/// duplicated, and already-possible effects keep this original identity for
/// reconciliation. Sealed only by [`seal_dispatched_binding`]; minted nowhere
/// else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchedBinding {
    /// Exact admitted selection evidence.
    pub evidence: TaskSelectionEvidence,
    /// Task the admitted request named (request-context task, or the envelope
    /// task when the context names none) — never the evidence's own value.
    pub admitted_task_ref: String,
    /// Write scope the binding was admitted for.
    pub scope_ref: String,
    /// Caller-presented fence admission ran against.
    pub presented_fence: StateFence,
    /// Bootstrap receipt revision admission ran against.
    pub receipt_revision: u64,
    /// Governance profile reference admission ran against.
    pub governance_profile_ref: String,
    /// Projection generation admission ran against.
    pub projection_generation: u64,
    /// Stable operation identity; preserved across revalidation, never mutated.
    pub operation_id: String,
}

/// Seals one admitted task-bound transition into its dispatch identity
/// (issue #1746, W6).
///
/// Checks the evidence against the exact admitted request task and write scope
/// before sealing: a selection naming another task or scope fails closed with
/// `TASK_SCOPE_INCOMPATIBLE` and seals nothing. Called by
/// [`admit_canonical_write`] for both task-bound arms, so every
/// [`TaskBindingAdmission::TaskBound`] carries its fence and bootstrap/profile
/// revision from birth.
#[allow(
    clippy::too_many_arguments,
    reason = "seal joins the evidence, admitted identities, presented fence, bootstrap revisions, and operation identity in one edge"
)]
pub fn seal_dispatched_binding(
    evidence: TaskSelectionEvidence,
    admitted_task_ref: &str,
    scope_ref: &str,
    presented_fence: &StateFence,
    receipt_revision: u64,
    governance_profile_ref: &str,
    projection_generation: u64,
    operation_id: String,
) -> Result<DispatchedBinding, TaskBindingError> {
    if evidence.task_ref != admitted_task_ref {
        return Err(TaskBindingError::scope_incompatible(
            "task-bound dispatch names a different task than the admitted context",
        ));
    }
    if evidence.work_scope_ref != scope_ref {
        return Err(TaskBindingError::scope_incompatible(
            "task-bound dispatch names a different WorkScope than the admitted write",
        ));
    }
    if operation_id.trim().is_empty() || operation_id.chars().any(char::is_control) {
        return Err(TaskBindingError::selection_required(
            "task-bound dispatch names no operation identity",
        ));
    }
    Ok(DispatchedBinding {
        evidence,
        admitted_task_ref: admitted_task_ref.to_owned(),
        scope_ref: scope_ref.to_owned(),
        presented_fence: presented_fence.clone(),
        receipt_revision,
        governance_profile_ref: governance_profile_ref.to_owned(),
        projection_generation,
        operation_id,
    })
}

/// Revalidates one sealed dispatch identity at the effect gate against the
/// live owners (issue #1746, W6/A5).
///
/// The live task/scope, bootstrap receipt revision, governance profile
/// reference, and fence come from the live owners at the existing
/// queued-claim/launch/effect gate — never from the request. An intervening
/// rebind, task revision, logout, or generation change fails closed with
/// `TASK_SCOPE_INCOMPATIBLE` for conflict/rebind: the old operation is not
/// rewritten to the new task under its identity, never duplicated, and
/// already-possible effects keep their original identity for reconciliation.
/// Shared safe status/recovery remains available under its own authority and
/// never passes through this entry.
///
/// Designated caller (STITCH, daemon composition lane): the pre-commit effect
/// gate in `DaemonComposition::commit_canonical_and_refresh`
/// (`bins/eliotd/src/lib.rs`), between the `ColdUnbound` admission projection
/// and the scope-sensitive trigger, passing the live Governor task/scope,
/// receipt revision, governance profile reference, and kernel-snapshot fence.
pub fn revalidate_dispatched_binding(
    binding: &DispatchedBinding,
    live_task_ref: Option<&str>,
    live_scope_ref: &str,
    live_receipt_revision: u64,
    live_governance_profile_ref: &str,
    live_fence: &StateFence,
) -> Result<(), TaskBindingError> {
    let Some(live_task_ref) = live_task_ref else {
        return Err(TaskBindingError::selection_required(
            "task-bound dispatch revalidation names no live task",
        ));
    };
    if live_task_ref != binding.admitted_task_ref {
        return Err(TaskBindingError::scope_incompatible(
            "dispatched task is not the admitted task; rebind under a new operation, no rewrite",
        ));
    }
    if live_scope_ref != binding.scope_ref {
        return Err(TaskBindingError::scope_incompatible(
            "dispatched WorkScope is not the admitted WorkScope; rebind, no rewrite",
        ));
    }
    if live_receipt_revision != binding.receipt_revision
        || live_governance_profile_ref != binding.governance_profile_ref
    {
        return Err(TaskBindingError::scope_incompatible(
            "admitted bootstrap/profile revision moved before effect; rebind at the live revision, no silent rebind",
        ));
    }
    revalidate_task_bound_for_effect(
        &binding.evidence,
        Some(binding.admitted_task_ref.as_str()),
        &binding.scope_ref,
        &binding.presented_fence,
        live_fence,
    )
}

/// Revalidates one admitted task-bound transition at the effect gate against
/// the live fence (issue #1746, W6/A5).
///
/// [`admit_canonical_write`] admits against the caller-presented write fence;
/// between that admission (bootstrap) and the commit (dispatch) the task,
/// scope, or generation may have moved. This entry carries the exact admitted
/// [`TaskSelectionEvidence`] forward and rejoins it here: the ORIGINAL
/// evidence is validated with the existing [`TaskSelectionEvidence::validate`],
/// contamination still refuses, the evidence task/scope must name exactly the
/// admitted request task and the write scope, and the presented fence must
/// still match the live owner fence exactly. A mismatch fails closed with
/// `TASK_SCOPE_INCOMPATIBLE` for conflict/rebind: the old operation is never
/// rewritten to the new task under its identity, never duplicated, and already
/// possible effects keep their original identity for reconciliation. This entry
/// mints no evidence and selects no task; `admitted_task_ref` is the exact
/// task the admitted request names (the request-context task, or the envelope
/// task when the context names none — the same value admission compared),
/// never the evidence's own value.
///
/// Designated caller (STITCH, daemon composition lane): the pre-commit effect
/// gate in `DaemonComposition::commit_canonical_and_refresh`
/// (`bins/eliotd/src/lib.rs`), between the `ColdUnbound` admission projection
/// and the scope-sensitive trigger, passing the admitted request task, the
/// envelope scope, the readiness fence as presented, and the live Governor
/// kernel-snapshot fence as live. Callers holding a sealed [`DispatchedBinding`]
/// prefer [`revalidate_dispatched_binding`], which checks the carried
/// task/scope/bootstrap revision first and delegates here for the fence leg.
pub fn revalidate_task_bound_for_effect(
    evidence: &TaskSelectionEvidence,
    admitted_task_ref: Option<&str>,
    expected_scope_ref: &str,
    presented_fence: &StateFence,
    live_fence: &StateFence,
) -> Result<(), TaskBindingError> {
    let Some(admitted_task_ref) = admitted_task_ref else {
        return Err(TaskBindingError::selection_required(
            "task-bound dispatch names no admitted task",
        ));
    };
    if admitted_task_ref.trim().is_empty() || admitted_task_ref.chars().any(char::is_control) {
        return Err(TaskBindingError::selection_required(
            "task-bound dispatch admitted task is blank",
        ));
    }
    evidence.validate().map_err(|error| {
        TaskBindingError::selection_required(format!("task selection evidence invalid: {error}"))
    })?;
    if evidence.is_contaminated() {
        return Err(TaskBindingError::selection_required(
            "task selection is contaminated",
        ));
    }
    if evidence.task_ref != admitted_task_ref {
        return Err(TaskBindingError::scope_incompatible(
            "dispatched task is not the admitted task; rebind under a new operation, no rewrite",
        ));
    }
    if evidence.work_scope_ref != expected_scope_ref {
        return Err(TaskBindingError::scope_incompatible(
            "dispatched WorkScope is not the admitted WorkScope; rebind, no rewrite",
        ));
    }
    if !eliot_contracts::fences_match_exact(presented_fence, live_fence) {
        return Err(TaskBindingError::scope_incompatible(
            "admitted fence moved before effect; rebind at the live fence, no silent rebind",
        ));
    }
    Ok(())
}

/// Admits the capture leg of one prepared transition at the daemon transport
/// edge (issue #1929, I5.5).
///
/// This is the production entry for `DaemonKernelClient::apply_prepared`'s
/// pre-transport admission: the last point inside the daemon where a
/// `CaptureObservation` can still be classified before it reaches Kernel and
/// the store. Its only decision is the capture leg:
///
/// - a `CaptureObservation` naming no task on either the admitted context or
///   the transition has no unique task selection, so it is admitted through
///   [`admit_capture`] as [`TaskBindingAdmission::ColdUnbound`] with no task
///   activation, support/influence promotion, or finish relevance;
/// - a `CaptureObservation` that names a task is task-relative, and this edge
///   reports [`TaskBindingAdmission::TaskRelative`] rather than guessing: the
///   binding decision belongs to the ingress that owns the exact selection
///   ([`admit_canonical_write`]) and is re-derived at the store gate from the
///   proof handles the transition actually carries. A typed selection is never
///   manufactured here, and an absent one is never treated as compatible;
/// - a transition with no capture at all is
///   [`TaskBindingAdmission::NotTaskRelative`].
///
/// It never selects the most recent or open task and never falls back to
/// resolver output.
///
/// # Why this entry has no `selection` parameter (issue #1929)
///
/// This edge is reached from `DaemonKernelClient::apply_prepared`, which
/// receives only a `PreparedTransition` and an `eliot_protocol::RequestIdentity`.
/// Neither carries a compiled readiness receipt or a `TaskSelectionEvidence`,
/// and neither does `DaemonKernelClient` or the retained Governor
/// `WorkScopeBindingOwner`; a `TaskSelectionEvidence` additionally requires a
/// non-zero `task_revision` and an `acceptance_digest` that this edge has no
/// legitimate source for. Adding the parameter anyway and passing `None` would
/// reproduce the present state under a new name, and synthesizing those two
/// fields would turn every typed rejection on this path into a rejection of
/// fabricated evidence — strictly worse than the `ColdUnbound` this edge
/// reports. The signature therefore has no selection parameter, which makes the
/// missing evidence owner structural rather than an assertion. The ingress that
/// would carry it, [`admit_canonical_write`], does have a production call site,
/// but that caller has none; see the module's "Measured reachability" section.
pub fn admit_named_mutation_capture(
    context: &RequestMetadata,
    transition: &PreparedTransition,
) -> Result<TaskBindingAdmission, TaskBindingError> {
    let captures = transition
        .named_operations
        .iter()
        .any(|named| named.operation == NamedMutationOperation::CaptureObservation);
    if !captures {
        return Ok(TaskBindingAdmission::NotTaskRelative);
    }
    let names_a_task = transition.task_id.is_some() || context.task_id.is_some();
    if names_a_task {
        // Issue #1746, A6: the bridge transport edge enforces the same binding
        // rule as the direct internal intake — a task-relative effect needs
        // owner evidence, so its binding decision belongs to the ingress that
        // owns the exact selection. The terminal arm is unreachable
        // fail-closed if the frozen table ever stops requiring it.
        if entrypoint_requires_binding(
            DispatchEntrypoint::BridgeTransport,
            CanonicalOperationRequirement::TaskRelativeEffectful,
        ) {
            return Ok(TaskBindingAdmission::TaskRelative);
        }
        return Err(TaskBindingError::selection_required(
            "bridge transport edge cannot admit a task-relative effect without owner evidence",
        ));
    }
    match admit_capture(
        transition.identity.operation_id.as_str().to_owned(),
        context.state_fence.clone(),
        None,
        0,
        CompatibilityDisposition::Compatible,
    )? {
        CaptureAdmission::ColdUnbound(candidate) => {
            Ok(TaskBindingAdmission::ColdUnbound(candidate))
        }
        CaptureAdmission::TaskBound(evidence) => {
            Err(TaskBindingError::selection_required(format!(
                "task-free capture must not carry a task selection: {}",
                evidence.evidence_ref
            )))
        }
    }
}

/// Observes one explicit workspace root and admits one task-relative
/// transition against the live observation.
///
/// This is the daemon trigger ingress for scope identity: absent selection
/// stays on the cold path with no observation performed, while a present
/// selection observes the explicit root mechanically (filesystem/VCS/project
/// facts, never invented), derives the observed instance and generation, and
/// admits only through [`admit_task_bound_with_observed_scope`]. A root that
/// cannot be observed, or an observation that disagrees with the retained
/// binding, fails closed with `TASK_SCOPE_INCOMPATIBLE`; the retained
/// binding, task state, and project memory are untouched. The root is always
/// explicit — the daemon never infers a workspace from cwd, proximity, or
/// recency. Live status: no live caller threads an explicit root yet; awaiting
/// the attach-transport owner (BLOCKED-BY attach-transport).
///
/// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
///
/// # Not yet reached (issue #1929)
///
/// This entry takes a caller-presented selection rather than owning one, and it
/// currently has zero call sites, which also makes
/// [`admit_task_bound_with_observed_scope`] transitively dead. Its two
/// remaining inputs are the reason: the daemon holds no retained
/// `ScopeBinding` (that requires `DaemonComposition::admit_scope_attach`, which
/// is itself uncalled and circular) and no explicit user workspace root — only
/// its own config and state directories, which are not a user `WorkScope` and
/// must never be attached as one. A production caller therefore needs the
/// attach-transport ingress named in the module's "Measured reachability"
/// section.
pub fn observe_and_admit_task(
    workspace_root: &Path,
    selection: Option<&TaskSelectionEvidence>,
    expected_task_ref: &str,
    expected: &ScopeBinding,
    expected_fence: &StateFence,
    compatibility: CompatibilityDisposition,
) -> Result<(), TaskBindingError> {
    if selection.is_none() {
        return admit_task_bound(
            None,
            expected_task_ref,
            &expected.scope.scope_ref,
            expected_fence,
            compatibility,
        );
    }
    let facts = observe_workspace_instance(workspace_root).map_err(|error| {
        TaskBindingError::scope_incompatible(format!("workspace observation failed: {error}"))
    })?;
    let observed = derive_observed_resources(&facts, expected_fence.resource_generation, None)
        .map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "observed workspace resources invalid: {error}"
            ))
        })?;
    admit_task_bound_with_observed_scope(
        selection,
        expected_task_ref,
        expected,
        &observed,
        expected_fence,
        compatibility,
    )
}

/// Exact retained cold-start tuple presented to the daemon attach boundary.
///
/// This carries an existing Governor lease and its previously returned
/// `ColdStartSurfaceView`; it is not an authority or a receipt constructor.
/// `DaemonComposition::read_cold_start_surface_for_attach` re-reads the
/// retained terminal for this exact lease key and returns it only when the
/// complete surface, lease reference/deadline, and supplied `StateFence` still
/// match. In particular the equality covers principal/session, scope and
/// descriptor revision, instance/lineage, task binding, source set/generation,
/// governance/route profiles, serializer/tokenizer identities, and projection
/// source/revision. No field is derived from an activation ticket or a display
/// label.
///
/// The producer remains the authenticated attach/onboarding owner. The type
/// itself does not authenticate these values; a caller must pass the exact
/// owner-issued lease/surface pair and the fence it observed at the same
/// boundary. Without that producer, there is deliberately no live daemon
/// caller.
#[derive(Clone, Debug)]
pub struct ColdStartAttachInput {
    /// The exact single-flight lease whose terminal is being attached.
    pub lease: OnboardingLease,
    /// The complete prior projection returned by the Governor for this lease.
    pub expected_surface: ColdStartSurfaceView,
    /// Fence observed by the authenticated attach boundary.
    pub state_fence: StateFence,
}

impl ColdStartAttachInput {
    /// Checks the key fields projected into the surface before the adapter
    /// performs the full retained-lease comparison.
    #[must_use]
    pub fn matches_lease(&self) -> bool {
        self.expected_surface.lease_ref == self.lease.lease_ref
            && self.expected_surface.lease_deadline == self.lease.deadline
            && self.expected_surface.scope.lineage_ref.as_deref()
                == Some(self.lease.lineage_candidate_ref.as_str())
            && self.expected_surface.scope.instance_ref
                == self.lease.workspace_instance_candidate_ref
            && self.expected_surface.instance.instance_ref
                == self.lease.workspace_instance_candidate_ref
            && self.expected_surface.governing_source_generation
                == self.lease.governing_source_generation
    }
}

/// Authenticated scope-attach ingress payload assembled from owned evidence.
///
/// The attach trigger builds exactly one of these per attach attempt from
/// evidence it already owns — never inferred from the activation ticket
/// (correlation-only by contract), the current directory, proximity, or
/// recency:
///
/// - `explicit_root`: the explicit host/session workspace path the trigger
///   was asked to attach (absolute; observed live, never a display name);
/// - `receipt_ref`: fresh bounded receipt identity minted per attempt;
/// - `descriptor`: the retained scope description the trigger resolves from
///   the onboarding path (the producer requires it to describe the live
///   owner binding on every identity field);
/// - `authorizing_ref`: the authenticated session/host authorization evidence
///   reference (the explicit Human/host binding token or session attach
///   record the trigger authenticated through owned IPC/session state) — a
///   reference only; the producer enforces non-blank, the trigger owns the
///   authentication;
/// - `privacy_class`, `governing_source_generation`, `sources`, `privacy`:
///   the scope's admitted privacy class and the onboarding-retained source
///   closure that authenticates the observed instance;
/// - `owner_revision`: caller-sequenced durable revision for the admitted
///   owner (same convention as the sibling admission entries).
///
/// [`ScopeAttachIngress::validate`] checks shape only: it never authenticates
/// the scope, the lineage, or the authorization — the live owner read at the
/// fence, the `MATCHED` guard, and the source closure inside
/// `GovernorComposition::admit_observed_scope_attach` do. Call sequence:
/// `validate`, then [`observe_explicit_workspace`] on `explicit_root`, then
/// `GovernorComposition::admit_observed_scope_attach` with every field below.
/// That call order is the production one in
/// `DaemonComposition::admit_scope_attach`.
///
/// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
#[derive(Clone, Debug)]
pub struct ScopeAttachIngress {
    /// Explicit absolute workspace root to observe live and attach.
    pub explicit_root: PathBuf,
    /// Fresh bounded receipt identity minted per attempt.
    pub receipt_ref: String,
    /// Retained scope description the observed instance attaches to.
    pub descriptor: WorkScopeDescriptor,
    /// Trigger-authenticated session/host authorization evidence reference.
    pub authorizing_ref: String,
    /// Admitted privacy class for the new binding.
    pub privacy_class: PrivacyClass,
    /// Source generation the onboarding closure authenticates.
    pub governing_source_generation: u64,
    /// Onboarding-retained governing sources for the observed instance.
    pub sources: GoverningSourceSet,
    /// Privacy boundary the new binding must satisfy.
    pub privacy: PrivacyProfile,
    /// Caller-sequenced durable revision for the admitted owner.
    pub owner_revision: u64,
}

impl ScopeAttachIngress {
    /// Validates the payload shape without authenticating anything.
    ///
    /// Malformed caller fields (blank references, zero counters) fail as
    /// `TASK_SELECTION_REQUIRED`; scope-identity disagreements (a descriptor
    /// that does not validate, a privacy class outside the admitted
    /// boundary) fail as `TASK_SCOPE_INCOMPATIBLE`. A non-absolute root
    /// fails as incompatible: only an explicit absolute path may be
    /// observed. The governing source set itself is checked at admission
    /// against the observed scope, never here.
    pub fn validate(&self) -> Result<(), TaskBindingError> {
        if !self.explicit_root.is_absolute() {
            return Err(TaskBindingError::scope_incompatible(
                "attach ingress explicit_root must be absolute",
            ));
        }
        if self.receipt_ref.trim().is_empty() || self.receipt_ref.chars().any(char::is_control) {
            return Err(TaskBindingError::selection_required(
                "attach ingress receipt_ref is blank",
            ));
        }
        if self.authorizing_ref.trim().is_empty()
            || self.authorizing_ref.chars().any(char::is_control)
        {
            return Err(TaskBindingError::selection_required(
                "attach ingress authorizing_ref is blank",
            ));
        }
        if self.governing_source_generation == 0 {
            return Err(TaskBindingError::selection_required(
                "attach ingress governing_source_generation is zero",
            ));
        }
        if self.owner_revision == 0 {
            return Err(TaskBindingError::selection_required(
                "attach ingress owner_revision is zero",
            ));
        }
        self.descriptor.validate().map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "attach ingress descriptor invalid: {error}"
            ))
        })?;
        self.privacy.validate().map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "attach ingress privacy boundary invalid: {error}"
            ))
        })?;
        if !self.privacy.admits(self.privacy_class) {
            return Err(TaskBindingError::scope_incompatible(
                "attach ingress privacy class is outside the admitted boundary",
            ));
        }
        Ok(())
    }
}

/// Observes one explicit workspace root and derives the observed scope
/// resources the `WorkScope` attach trigger admits against.
///
/// This is the daemon half of the attach ingress and the only mechanical step
/// it owns: the explicit absolute root is observed from filesystem/VCS/project
/// facts (never invented, never inferred from cwd, proximity, or recency) and
/// the observation is derived at the admission fence generation through the
/// same `derive_observed_resources` the CLI scope-observe ingress runs. A root
/// that cannot be observed, or one whose derived resources are invalid, fails
/// closed with `TASK_SCOPE_INCOMPATIBLE` carrying the exact detail; the
/// retained binding, task state, and project memory are untouched.
///
/// Receipt production and admission stay with the Governor owner
/// (`GovernorComposition::admit_observed_scope_attach`): this function mints no
/// receipt and installs no binding, so the daemon cannot become a second
/// `WorkScope` writer. The caller's admitted owner read, the fresh `MATCHED`
/// source-closure check, and the explicit authorization reference are the
/// Governor's terms, not this crate's.
pub fn observe_explicit_workspace(
    workspace_root: &Path,
    fence: &StateFence,
) -> Result<ObservedScopeResources, TaskBindingError> {
    observe_explicit_workspace_facts(workspace_root, fence).map(|(_, observed)| observed)
}

fn observe_explicit_workspace_facts(
    workspace_root: &Path,
    fence: &StateFence,
) -> Result<(WorkspaceInstanceFacts, ObservedScopeResources), TaskBindingError> {
    let facts = observe_workspace_instance(workspace_root).map_err(|error| {
        TaskBindingError::scope_incompatible(format!("workspace observation failed: {error}"))
    })?;
    let observed =
        derive_observed_resources(&facts, fence.resource_generation, None).map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "observed workspace resources invalid: {error}"
            ))
        })?;
    Ok((facts, observed))
}

/// Observes one authenticated activation selector and creates the exact
/// discovery lease/evidence inputs admitted by the privacy-bounded scanner.
///
/// Only Host-observed filesystem, VCS and root-manifest name facts are
/// populated. Known-format inspection and governing-source discovery remain
/// explicitly unresolved. No privacy class, boundary, source closure, or
/// task is inferred here; the scanner returns its smallest privacy question
/// until the applicable owner supplies those inputs.
#[allow(
    clippy::too_many_lines,
    reason = "bounded Host observations and the matching discovery lease are assembled in one auditable path"
)]
pub fn observe_cold_start_discovery(
    ticket: &eliot_protocol::AgentActivationResolutionTicket,
    fence: &StateFence,
    now: u64,
) -> Result<ColdStartDiscoveryInput, TaskBindingError> {
    let selector = ticket.workspace_selector.as_deref().ok_or_else(|| {
        TaskBindingError::selection_required(
            "activation has no explicit workspace selector for bounded discovery",
        )
    })?;
    let workspace_root = Path::new(selector);
    if !workspace_root.is_absolute() {
        return Err(TaskBindingError::scope_incompatible(
            "activation workspace selector must be an explicit absolute path",
        ));
    }
    if now == 0 {
        return Err(TaskBindingError::selection_required(
            "activation discovery clock is not available",
        ));
    }
    let (facts, observed) = observe_explicit_workspace_facts(workspace_root, fence)?;
    let instance = observed.instances.first().ok_or_else(|| {
        TaskBindingError::scope_incompatible("Host observer returned no workspace instance")
    })?;
    let instance_ref = instance.instance_ref.clone();
    let root_identity = instance.root_identity.clone();
    let proposed_kind = observed.kind;
    let mut allowed_reads = vec![DiscoveryRead::FilesystemIdentity];
    if facts.has_git {
        allowed_reads.push(DiscoveryRead::VcsIdentity);
    }
    if !facts.manifest_names.is_empty() {
        allowed_reads.push(DiscoveryRead::ManifestNamesAndHashes);
    }
    let request = DiscoveryLeaseRequest {
        proposer_ref: ticket.activation_request_id.as_str().to_owned(),
        session_ref: ticket.connection_id.clone(),
        host_ref: ticket.peer_admission_receipt_sha256.clone(),
        candidate_root_ref: root_identity.clone(),
        root_filesystem_identity_ref: root_identity.clone(),
        allowed_reads,
        consumption_limit: 3,
        deadline: ticket.kernel_deadline_unix_ms,
    };
    let key = DiscoveryLeaseKey {
        proposer_ref: request.proposer_ref.clone(),
        session_ref: request.session_ref.clone(),
        host_ref: request.host_ref.clone(),
        root_filesystem_identity_ref: request.root_filesystem_identity_ref.clone(),
    };
    let lease = issue_discovery_lease(&request).map_err(|error| {
        TaskBindingError::scope_incompatible(format!(
            "Host-observed discovery lease refused: {error}"
        ))
    })?;
    let mut attested_reads = vec![DiscoveryRead::FilesystemIdentity];
    if facts.has_git {
        attested_reads.push(DiscoveryRead::VcsIdentity);
    }
    let mut manifests = facts
        .manifest_names
        .iter()
        .map(|name| {
            let name_hash = sha256_hex(name.as_bytes());
            ManifestEvidence {
                manifest_ref: format!("manifest:{name_hash}"),
                name_hash,
            }
        })
        .collect::<Vec<_>>();
    manifests.sort_by(|left, right| left.manifest_ref.cmp(&right.manifest_ref));
    if !manifests.is_empty() {
        attested_reads.push(DiscoveryRead::ManifestNamesAndHashes);
    }
    let evidence = BootstrapScanEvidence {
        canonical_root_ref: root_identity.clone(),
        filesystem_identity_ref: root_identity,
        vcs_branch_ref: observed.generation.branch_ref.clone(),
        vcs_commit_ref: observed.generation.commit_ref.clone(),
        vcs_dirty_summary_ref: observed.generation.dirty_summary_ref.clone(),
        file_distribution: Vec::new(),
        manifests,
        build_profiles: Vec::new(),
        root_services: Vec::new(),
        editor_workspaces: Vec::new(),
        existing_records: Vec::new(),
        adapters: Vec::new(),
        recent_changes: Vec::new(),
        artifact_dirs: Vec::new(),
        execution_identity: None,
        broker_attached: None,
        redacted_literal_identities: Vec::new(),
        unresolved_fields: vec![
            DiscoveryRead::KnownFormatHeaders,
            DiscoveryRead::GoverningSourceCandidates,
        ],
        attested_reads,
    };
    let discovery = BootstrapDiscoveryInputs {
        scan_ref: format!("scan:{}", ticket.ticket_id),
        candidate_privacy: None,
        privacy_boundary: None,
        observed,
        policy: None,
        proposed_kind,
        identity_fingerprint: instance_ref,
        evidence,
        governing_source_refs: Vec::new(),
        now,
    };
    Ok(ColdStartDiscoveryInput {
        lease,
        key,
        discovery,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fence() -> StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("seq")).expect("epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    #[test]
    fn missing_selection_is_cold_without_task_effects() {
        let admission = admit_capture(
            "candidate-1".to_owned(),
            fence(),
            None,
            0,
            CompatibilityDisposition::Compatible,
        )
        .expect("absent selection stays cold");
        match admission {
            CaptureAdmission::ColdUnbound(candidate) => {
                assert_eq!(candidate.reason_ref, "unbound-capture");
                assert!(!candidate.affects_task());
            }
            CaptureAdmission::TaskBound(_) => panic!("absent selection must not bind a task"),
        }
    }
}
