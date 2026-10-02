//! Canonical `UnderstandingBootstrap` and ambiguity-safe task binding (I7.17).
//!
//! Architecture: I7.17 (convenience surfaces) projection of I4.4.1
//! (`OnboardingReadinessReceipt`, owned by the Governor/WorkScopeResolver) plus
//! I7.16 (actual `GovernanceProfile` with limiting integration evidence).
//!
//! Ownership: this module is a bounded read composition for bridge delivery
//! only. It creates no competing readiness authority: the canonical readiness
//! decision stays with `OnboardingReadinessReceipt`; this projection carries
//! its reference and disposition and can never report a stronger assessment
//! ([`cap_assessment`]). Task authority stays with the owning Governor/task
//! controller; this module only projects selection evidence and computes
//! `BOUND | UNIQUE | AMBIGUOUS | NONE` deterministically. It never silently
//! selects among multiple open candidates, never binds a historical
//! (non-current) task as current, and a task sourced solely via a
//! prior evaluation candidate stays [`CROSSOVER_CONTAMINATED`] until an
//! independent binding record is supplied. Any candidate marked historical
//! by the owning task producer carries [`HISTORICAL_CANDIDATE`] and is
//! refused with `SELECTION_HISTORICAL` on every bind path.
//!
//! Non-ownership: onboarding compilation, task admission, governance
//! derivation, coverage observation, and canonical stores. Field names mirror
//! the Governor-owned `TaskSelectionEvidence` where they overlap so the
//! projection stays comparable without duplicating that contract.

use eliot_agent_bridge_core::AttachBinding;
use eliot_context_contracts::{MeasurementStatus, SerializedContextMeasurement};
use eliot_governor::{
    ColdStartOwnerBootstrapReadback, ColdStartSurfaceView, CurrentTaskSelection,
};
use eliot_contracts::fences_match_exact;
use eliot_integration_coverage::{
    EventCompleteness, EventDisposition, GovernanceProfile, IntegrationCoverageProfile,
    LogicalEvent,
};
pub use eliot_workscope::{BootDelta, MAX_BOOT_DELTA_HANDLES};
use eliot_workscope::{OnboardingLease, OnboardingReadinessReceipt, TaskBindingState};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Marker preserved from the selection route while a task lacks an
/// independent binding record.
pub const CROSSOVER_CONTAMINATED: &str = "CROSSOVER_CONTAMINATED";

/// Marker carried when any selection candidate names a historical
/// (non-current) task supplied by the owning task producer.
///
/// Presence never selects: sole or authoritatively named historical
/// candidates fail closed with `SELECTION_HISTORICAL`.
pub const HISTORICAL_CANDIDATE: &str = "HISTORICAL_CANDIDATE";

/// Maximum candidate task handles projected in one bootstrap.
pub const MAX_CANDIDATE_HANDLES: usize = 16;
/// Maximum relevant/orientation/attention/problem/revision handles per list.
pub const MAX_HANDLES: usize = 32;
/// Maximum limiting integration evidence handles.
pub const MAX_EVIDENCE_HANDLES: usize = 8;
/// Maximum length of one opaque handle or reference.
pub const MAX_HANDLE_LEN: usize = 256;

/// One typed current `TaskContract` selection returned by the live Governor
/// owner. This is used only for a direct owner-result join; callers must not
/// construct it from a host selection string or a prior bootstrap.
pub type OwnerCurrentTaskSelection = CurrentTaskSelection;

/// Exact owner values joined before a #8 compiled-surface bootstrap can be
/// retained as current. The owner readback and delta arrive in one Governor
/// response; the bridge adds its retained authenticated attach binding and
/// live task/profile observations.
pub struct OwnerCompiledSurfaceInput<'a> {
    /// Single validated owner readback containing the original ORS terminal
    /// bytes and the owner-issued boot delta.
    pub owner_bootstrap: &'a ColdStartOwnerBootstrapReadback,
    /// Live attach binding retained by the bridge transport.
    pub attach_binding: &'a AttachBinding,
    /// Current TaskContract owner result, absent only for a non-current
    /// selection state such as no task, ambiguity, or exploratory work.
    pub current_selection: Option<&'a OwnerCurrentTaskSelection>,
    /// Current integration coverage. Missing remains unknown and cannot make
    /// a READY_MATERIAL response pass this admission.
    pub coverage: Option<&'a IntegrationCoverageProfile>,
    /// Current Governor-derived profile. Missing remains unknown.
    pub governance_profile: Option<&'a GovernanceProfile>,
}

/// Private-field proof that one exact Governor readback is bound to the live
/// bridge attach and its current owner task/profile values.
#[derive(Clone, Debug)]
pub struct OwnerCompiledSurfaceEvidence {
    owner_bootstrap: ColdStartOwnerBootstrapReadback,
    attach_binding: AttachBinding,
    current_selection: Option<OwnerCurrentTaskSelection>,
    governance: Option<GovernanceEvidence>,
}

impl OwnerCompiledSurfaceEvidence {
    /// The exact owner surface retained by the original ORS terminal.
    #[must_use]
    pub const fn surface(&self) -> &ColdStartSurfaceView {
        &self.owner_bootstrap.readback.surface
    }

    /// The exact boot delta returned beside the owner readback.
    #[must_use]
    pub const fn boot_delta(&self) -> &BootDelta {
        &self.owner_bootstrap.delta
    }

    /// The live authenticated bridge attach binding used for this join.
    #[must_use]
    pub const fn attach_binding(&self) -> &AttachBinding {
        &self.attach_binding
    }

    /// The exact owner task-contract selection, if one applies.
    #[must_use]
    pub const fn current_selection(&self) -> Option<&OwnerCurrentTaskSelection> {
        self.current_selection.as_ref()
    }

    /// The actual paired owner profiles, absent when the owner returned them
    /// unknown. Material admission requires the pair.
    #[must_use]
    pub const fn governance(&self) -> Option<&GovernanceEvidence> {
        self.governance.as_ref()
    }

    /// The complete exact owner response, including the raw ORS row and
    /// decoded receipt projection.
    #[must_use]
    pub const fn owner_bootstrap(&self) -> &ColdStartOwnerBootstrapReadback {
        &self.owner_bootstrap
    }
}

/// Validates the exact Governor owner response against the live attach and
/// joins its real task, coverage, governance and boot-delta evidence.
///
/// This is the only path that creates [`OwnerCompiledSurfaceEvidence`]. It
/// validates the original stored ORS terminal digest/bytes before decoding,
/// keeps the canonical claim/lease bytes intact, checks the receipt against
/// the projected compiled surface, compares the complete typed state fence
/// with the retained live attach, and rechecks a current task against the
/// owner-returned revision/digest/fence. Unknown profiles remain unknown for
/// non-material readiness; READY_MATERIAL requires all W5 owner legs.
pub fn admit_owner_compiled_surface(
    input: &OwnerCompiledSurfaceInput<'_>,
) -> Result<OwnerCompiledSurfaceEvidence, BootstrapError> {
    let owner = &input.owner_bootstrap.readback;
    owner
        .record
        .validate()
        .map_err(|error| BootstrapError::new("BOOTSTRAP_OWNER_TERMINAL_INVALID", error.to_string()))?;
    owner
        .lease
        .validate()
        .map_err(|error| BootstrapError::new("BOOTSTRAP_OWNER_LEASE_INVALID", error.to_string()))?;
    owner
        .receipt
        .validate()
        .map_err(|error| BootstrapError::new("BOOTSTRAP_OWNER_RECEIPT_INVALID", error.to_string()))?;

    if owner.record.claim.lease_ref != owner.lease.lease_ref
        || owner.record.claim.lease_deadline != owner.lease.deadline
    {
        return Err(BootstrapError::new(
            "BOOTSTRAP_OWNER_LEASE_MISMATCH",
            "owner lease projection differs from the exact validated ORS claim",
        ));
    }
    let retained_lease: OnboardingLease = serde_json::from_str(&owner.record.claim.lease_bytes)
        .map_err(|error| {
            BootstrapError::new(
                "BOOTSTRAP_OWNER_LEASE_BYTES_INVALID",
                format!("original owner claim lease bytes are invalid: {error}"),
            )
        })?;
    if retained_lease != owner.lease {
        return Err(BootstrapError::new(
            "BOOTSTRAP_OWNER_LEASE_MISMATCH",
            "decoded original claim lease bytes differ from the owner lease projection",
        ));
    }
    let terminal = owner.record.terminal.as_ref().ok_or_else(|| {
        BootstrapError::new(
            "BOOTSTRAP_OWNER_TERMINAL_MISSING",
            "owner record has no committed readiness terminal",
        )
    })?;
    if terminal.receipt_ref != owner.receipt.receipt_ref
        || terminal.receipt_revision != owner.receipt.receipt_revision
    {
        return Err(BootstrapError::new(
            "BOOTSTRAP_OWNER_RECEIPT_MISMATCH",
            "decoded receipt does not name the exact owner terminal identity",
        ));
    }
    let retained_receipt: OnboardingReadinessReceipt =
        serde_json::from_str(&terminal.receipt_bytes).map_err(|error| {
            BootstrapError::new(
                "BOOTSTRAP_OWNER_RECEIPT_BYTES_INVALID",
                format!("original owner terminal receipt bytes are invalid: {error}"),
            )
        })?;
    if retained_receipt != owner.receipt {
        return Err(BootstrapError::new(
            "BOOTSTRAP_OWNER_RECEIPT_MISMATCH",
            "decoded owner receipt differs from the exact original terminal receipt bytes",
        ));
    }

    let surface = &owner.surface;
    let receipt = &owner.receipt;
    if surface.receipt_ref != receipt.receipt_ref
        || surface.lease_ref != receipt.lease_ref
        || surface.principal_ref != receipt.principal_ref
        || surface.session_ref != receipt.session_ref
        || surface.scope != receipt.scope
        || surface.scope_descriptor_revision != receipt.scope_descriptor_revision
        || surface.instance != receipt.instance
        || surface.lineage != receipt.lineage
        || surface.task_binding != receipt.task_binding
        || surface.state_fence != receipt.state_fence
        || surface.governing_source_set_ref != receipt.governing_source_set_ref
        || surface.governing_source_generation != receipt.governing_source_generation
        || surface.governance_profile_ref != receipt.governance_profile_ref
        || surface.limiting_integration_evidence != receipt.limiting_integration_evidence
        || surface.route_profile_ref != receipt.route_profile_ref
        || surface.serializer_id != receipt.serializer_id
        || surface.serializer_version != receipt.serializer_version
        || surface.serializer_options_digest != receipt.serializer_options_digest
        || surface.tokenizer_id != receipt.tokenizer_id
        || surface.tokenizer_version != receipt.tokenizer_version
        || surface.tokenizer_hash != receipt.tokenizer_hash
        || surface.lease_deadline != receipt.expiry_tick
        || surface.receipt_revision != receipt.receipt_revision
        || surface.projection_source_ref != receipt.projection_source_ref
        || surface.projection_generation != receipt.projection_generation
    {
        return Err(BootstrapError::new(
            "BOOTSTRAP_OWNER_SURFACE_MISMATCH",
            "compiled surface projection differs from the exact terminal owner receipt",
        ));
    }
    if !fences_match_exact(&surface.state_fence, input.attach_binding.state_fence())
        || surface.principal_ref != input.attach_binding.principal_id().as_str()
        || surface.session_ref != input.attach_binding.session_id().as_str()
        || surface.scope.scope_ref != input.attach_binding.task_binding().work_scope_id()
        || surface.state_fence.task_revision.is_some_and(|revision| {
            revision.value().to_string() != input.attach_binding.task_binding().task_revision()
        })
    {
        return Err(BootstrapError::new(
            "BOOTSTRAP_OWNER_BINDING_MISMATCH",
            "owner surface principal/session/scope/task fence differs from the exact live attach binding",
        ));
    }

    match &receipt.task_binding {
        TaskBindingState::CurrentTaskContract {
            task_ref,
            task_revision,
            acceptance_digest,
            ..
        } => {
            let current = input.current_selection.ok_or_else(|| {
                BootstrapError::new(
                    "BOOTSTRAP_CURRENT_SELECTION_MISSING",
                    "READY_MATERIAL receipt has no current TaskContract owner read",
                )
            })?;
            if current.task_ref != *task_ref
                || current.task_revision != *task_revision
                || current.acceptance_digest != *acceptance_digest
                || current.work_scope_ref != receipt.scope.scope_ref
                || !fences_match_exact(&current.state_fence, &surface.state_fence)
                || current.task_ref != input.attach_binding.task_binding().task_id().as_str()
                || current.task_revision.to_string()
                    != input.attach_binding.task_binding().task_revision()
            {
                return Err(BootstrapError::new(
                    "BOOTSTRAP_CURRENT_SELECTION_STALE",
                    "live TaskContract owner read differs from the exact terminal selection or attach fence",
                ));
            }
        }
        TaskBindingState::None_
        | TaskBindingState::Ambiguous { .. }
        | TaskBindingState::Exploratory { .. }
        | TaskBindingState::Stale { .. } => {
            if input.current_selection.is_some() {
                return Err(BootstrapError::new(
                    "BOOTSTRAP_CURRENT_SELECTION_CONFLICT",
                    "live current TaskContract owner read contradicts the terminal selection state",
                ));
            }
            if receipt.readiness == eliot_workscope::ReadinessLifecycle::ReadyMaterial {
                return Err(BootstrapError::new(
                    "BOOTSTRAP_TASK_SELECTION_REQUIRED",
                    "READY_MATERIAL receipt does not carry one current TaskContract selection",
                ));
            }
        }
    }

    let governance = match (input.coverage, input.governance_profile) {
        (Some(coverage), Some(profile)) => {
            let evidence = GovernanceEvidence::from_owner_profiles(coverage, profile)?;
            if coverage.fingerprint != surface.governance_profile_ref
                || evidence.limiting_integration_evidence != surface.limiting_integration_evidence
            {
                return Err(BootstrapError::new(
                    "BOOTSTRAP_GOVERNANCE_OWNER_MISMATCH",
                    "owner coverage/governance profile differs from the exact receipt profile references",
                ));
            }
            Some(evidence)
        }
        (None, None) if receipt.readiness != eliot_workscope::ReadinessLifecycle::ReadyMaterial => {
            None
        }
        (None, None) => {
            return Err(BootstrapError::new(
                "BOOTSTRAP_GOVERNANCE_UNKNOWN",
                "READY_MATERIAL receipt has no current owner coverage and governance profiles",
            ));
        }
        _ => {
            return Err(BootstrapError::new(
                "BOOTSTRAP_GOVERNANCE_INCOMPLETE",
                "coverage and derived governance profile must be present together",
            ));
        }
    };

    input
        .owner_bootstrap
        .delta
        .validate(receipt.receipt_revision)
        .map_err(|error| BootstrapError::new(error.code, error.detail))?;
    if input.owner_bootstrap.delta.expansion_handle != receipt.receipt_ref {
        return Err(BootstrapError::new(
            "BOOTSTRAP_DELTA_EXPANSION_MISMATCH",
            "delta expansion handle must name the exact owner receipt that contains its full content",
        ));
    }

    Ok(OwnerCompiledSurfaceEvidence {
        owner_bootstrap: input.owner_bootstrap.clone(),
        attach_binding: input.attach_binding.clone(),
        current_selection: input.current_selection.cloned(),
        governance,
    })
}

/// Deterministic task-selection outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskSelectionDisposition {
    /// Authoritative selection evidence bound exactly one eligible task.
    Bound,
    /// Exactly one eligible task exists; no choice was made.
    Unique,
    /// Multiple candidates with no authoritative single selection; none chosen.
    Ambiguous,
    /// No bindable task (zero candidates or all blocked).
    None,
}

/// Scope level the selection evidence applies to.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeLevel {
    Session,
    Task,
    Project,
    Portfolio,
}

/// Agent-facing assessment. Never stronger than the referenced canonical
/// readiness disposition (see [`cap_assessment`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CurrentAssessment {
    NotOnboarded,
    Stale,
    Ready,
    Degraded,
}

/// Intake provenance of one delivered bootstrap projection (issue #8 P1).
///
/// A host-authored bootstrap carries caller-supplied context and task inputs;
/// it can never present itself as owner-issued. The sealed delivery path
/// stamps every bootstrap it returns, so the agent can tell whether the
/// projected task/scope/authority evidence came through the Governor-compiled
/// surface intake or was carried from host input and compared with this
/// operation only (live attach seal, frozen task set, governance shape).
/// Unwitnessed compositions (direct [`get_understanding_bootstrap`] callers)
/// always report [`ProjectionProvenance::HostCarried`]: their inputs are
/// caller-supplied by construction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectionProvenance {
    /// Governor-compiled readiness surface intake
    /// ([`BootstrapContext::from_compiled_surface`], sealed by
    /// `BridgeRunner::note_owner_surface`): readiness, task binding,
    /// route/workspace/projection and frozen serializer/tokenizer identities
    /// arrived on the owner surface. Receipt-digest authentication still
    /// depends on the live authenticated #8 producer.
    OwnerCompiled,
    /// Caller-supplied context and task inputs (every other intake):
    /// values were frozen under the live attach seal and re-checked at
    /// delivery, but no owner minted them on this path.
    #[default]
    HostCarried,
}

/// Freshness disposition of one delivered projection (issue #8 A2, TASK
/// Freshness).
///
/// Every delivered projection carries this instead of leaving currency
/// implicit. Vocabulary follows the item text (`current`,
/// `explicitly stale/partial`, `unavailable`); the refresh handle for a
/// non-current projection is the carried `next_safe_expansion`, and the exact
/// revisions are the carried receipt/projection/source references. A seal
/// that moved since note time never delivers a silent stale packet: sealed
/// delivery refuses with `BOOTSTRAP_SEAL_MISMATCH` instead.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectionFreshness {
    /// Owner-compiled surface delivered under the still-live attach seal:
    /// currency was established by the Governor compiler and the seal
    /// (session, fence, scope/task binding) has not moved since.
    Current,
    /// Host-carried values frozen under the live attach seal at note time and
    /// delivered only while that seal still holds. Owner currency is not
    /// independently established on this path: the ceiling is the live seal
    /// itself, and refresh travels through `next_safe_expansion` naming the
    /// referenced receipt.
    #[default]
    Partial,
    /// No projection source was stated (empty `projection_source_ref`): the
    /// projection has no observable source, and the next action is the
    /// carried `next_safe_expansion`.
    Unavailable,
}

/// Canonical readiness disposition from the referenced
/// `OnboardingReadinessReceipt` (I4.4.1 lifecycle).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadinessDisposition {
    Unseen,
    Scanning,
    NeedsScope,
    NeedsTask,
    NeedsSources,
    ReadyReadOnly,
    ReadyMaterial,
    Degraded,
    Conflicted,
}

/// Actual coverage and Governor-derived profiles projected with their
/// coverage-level gap evidence (I7.16).
///
/// The complete typed owner profiles remain attached so event disposition,
/// ordering, completeness, proof ceiling, source, gaps, authorization, and
/// freshness axes are not reduced to a label. The gap list is copied verbatim
/// from the integration owner as a bounded preview; the attached coverage
/// profile retains every gap. It may be empty when the owner reports no
/// profile-level gaps; absence of gaps does not itself claim readiness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceEvidence {
    pub profile_ref: String,
    pub profile_revision: String,
    pub coverage_profile: IntegrationCoverageProfile,
    pub governance_profile: GovernanceProfile,
    pub limiting_integration_evidence: Vec<String>,
}

impl GovernanceEvidence {
    /// Projects the typed coverage and governance snapshots supplied by their
    /// owners (I7.8 step 4, I7.16; issue #1746 W5).
    ///
    /// This constructor projects the supplied owner profiles without
    /// summarizing away either profile. It refuses ways a caller-authored
    /// readiness could otherwise imply full authority:
    ///
    /// - `IntegrationCoverageProfile::validate` requires every one of the ten
    ///   logical events to be present, so an empty sensor list is rejected by
    ///   the owner itself and can never be presented as coverage;
    /// - `GovernanceProfile` must agree with coverage identity, verification,
    ///   completeness, and the owner's derivation formula for both
    ///   authorization axes; all authorization and freshness fields remain in
    ///   the output. These structural checks do not authenticate the snapshot's
    ///   origin or prove its freshness; the owner transport remains STITCH;
    /// - the bounded gap preview copies the first owner gap handles verbatim;
    ///   the attached `IntegrationCoverageProfile` retains every gap and all
    ///   event dispositions, ordering, completeness, source and proof ceiling.
    ///   A complete profile with no gaps carries an empty preview.
    ///
    /// `profile_ref` is the exact coverage fingerprint and
    /// `profile_revision` the canonical decimal Governor revision.
    ///
    /// # Errors
    ///
    /// Returns `COVERAGE_INVALID` when the owner coverage does not validate,
    /// `GOVERNANCE_FINGERPRINT_MISMATCH`, `GOVERNANCE_COVERAGE_UNVERIFIED`,
    /// `GOVERNANCE_COMPLETENESS_MISMATCH`, or
    /// `GOVERNANCE_DERIVATION_MISMATCH` when the profile disagrees with the
    /// coverage or its derivation axes.
    pub fn from_owner_profiles(
        coverage: &IntegrationCoverageProfile,
        profile: &GovernanceProfile,
    ) -> Result<Self, BootstrapError> {
        coverage.validate().map_err(|error| {
            BootstrapError::new(
                "COVERAGE_INVALID",
                format!("integration coverage profile is not valid: {error}"),
            )
        })?;
        if profile.fingerprint != coverage.fingerprint {
            return Err(BootstrapError::new(
                "GOVERNANCE_FINGERPRINT_MISMATCH",
                "derived governance profile names another active coverage fingerprint",
            ));
        }
        if profile.verified != coverage.verified {
            return Err(BootstrapError::new(
                "GOVERNANCE_COVERAGE_UNVERIFIED",
                "derived governance profile claims a verification state its coverage does not carry",
            ));
        }
        if !coverage.verified {
            return Err(BootstrapError::new(
                "GOVERNANCE_COVERAGE_UNVERIFIED",
                "Governor derivation requires verified production coverage",
            ));
        }
        if profile.completeness != coverage.completeness {
            return Err(BootstrapError::new(
                "GOVERNANCE_COMPLETENESS_MISMATCH",
                "derived governance profile claims a completeness its coverage does not carry",
            ));
        }
        if profile.revision == 0 {
            return Err(BootstrapError::new(
                "GOVERNANCE_REVISION_MISSING",
                "derived governance profile has no current revision",
            ));
        }
        validate_governance_axes(coverage, profile)?;
        // The complete gap set remains in coverage_profile. This list is only
        // the bounded inline preview; a valid owner profile may have more gaps.
        let gaps: Vec<String> = coverage
            .gaps
            .iter()
            .take(MAX_EVIDENCE_HANDLES)
            .cloned()
            .collect();
        Ok(Self {
            profile_ref: coverage.fingerprint.clone(),
            profile_revision: profile.revision.to_string(),
            coverage_profile: coverage.clone(),
            governance_profile: profile.clone(),
            limiting_integration_evidence: gaps,
        })
    }
}

/// One task candidate considered for binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCandidate {
    pub handle: String,
    pub task_revision: Option<u64>,
    pub acceptance_digest: Option<String>,
    /// True when the owning task producer marks this handle as a
    /// historical (non-current) task that must never bind as current.
    ///
    /// Serde-defaulted so receipts compiled before the marker still parse
    /// as current (`false`); the Governor/task owner supplies `true` for
    /// historical corpus entries going forward.
    #[serde(default)]
    pub historical: bool,
    /// True when this handle arrived only through a prior evaluation
    /// candidate and has no independent binding record yet.
    #[serde(default)]
    pub prior_evaluation_candidate_only: bool,
    /// True when an independent binding record for this handle was supplied.
    #[serde(default)]
    pub independent_binding_supplied: bool,
}

/// Authoritative evidence selecting exactly one candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeSelection {
    pub selected_handle: String,
    pub reason: String,
    pub source: String,
}

/// Task-selection inputs for one composition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapTaskInputs {
    pub scope_level: ScopeLevel,
    #[serde(default)]
    pub candidates: Vec<TaskCandidate>,
    #[serde(default)]
    pub authoritative_selection: Option<AuthoritativeSelection>,
}

/// Owner-supplied context composed into one bootstrap.
///
/// The readiness half of this context is the compiled canonical surface
/// projection: `onboarding_readiness_ref` names the
/// `OnboardingReadinessReceipt`, `onboarding_disposition` carries its
/// lifecycle, and `smallest_missing_question`, `lease_deadline`, and
/// `receipt_revision` carry the surface the Governor compiler delivered.
/// The bridge never invents these values; it projects them and caps the
/// assessment at the referenced readiness (see [`cap_assessment`]).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapContext {
    pub principal_ref: String,
    pub profile_ref: String,
    pub workscope_ref: String,
    pub onboarding_readiness_ref: String,
    pub onboarding_disposition: ReadinessDisposition,
    /// Smallest missing question from the compiled readiness surface.
    ///
    /// `None` when the surface reports nothing missing; carried so agent and
    /// Human callers receive the exact question instead of a generic refusal.
    #[serde(default)]
    pub smallest_missing_question: Option<String>,
    /// Lease deadline from the compiled readiness surface (receipt expiry).
    ///
    /// Zero when an older producer did not state one; carried verbatim.
    /// Freshness adjudication stays with the Governor readiness owner.
    #[serde(default)]
    pub lease_deadline: u64,
    /// Receipt revision from the compiled readiness surface.
    ///
    /// Zero when an older producer did not state one; a changed revision at
    /// the same lease tells callers a revised receipt replaced the first.
    #[serde(default)]
    pub receipt_revision: u64,
    #[serde(default)]
    pub revision_refs: Vec<String>,
    #[serde(default)]
    pub orientation_handles: Vec<String>,
    #[serde(default)]
    pub attention_handles: Vec<String>,
    #[serde(default)]
    pub problem_handles: Vec<String>,
    pub role_lease_ref: String,
    pub state_fence_ref: String,
    pub governance: GovernanceEvidence,
    /// Workspace instance identity carried from the canonical receipt.
    ///
    /// Opaque owner handle identifying the exact workspace instance the
    /// receipt was compiled for (I4.4.1 `repository_lineage_and_workspace_
    /// instance`). Carried verbatim so a changed worktree stays
    /// representable in the projection; instance agreement itself is
    /// enforced by the Governor compiler and the attach seal, never by
    /// parsing this handle at the bridge.
    #[serde(default)]
    pub workspace_instance_ref: String,
    /// Projection source identity carried from the canonical receipt.
    ///
    /// Opaque owner handle naming the source whose generation below was
    /// observed; carried verbatim, never parsed.
    #[serde(default)]
    pub projection_source_ref: String,
    /// Projection generation carried from the canonical receipt.
    ///
    /// Zero when an older producer did not state one; carried verbatim so
    /// projection lag stays representable. Freshness adjudication stays
    /// with the Governor readiness owner.
    #[serde(default)]
    pub projection_generation: u64,
    /// Selected qualified route profile reference (opaque owner handle).
    ///
    /// Carried so the default bootstrap preserves the route profile the
    /// Decision Safety Floor below was selected under; the bridge never
    /// qualifies a route itself.
    #[serde(default)]
    pub route_profile_ref: String,
    /// Frozen serializer identity carried from the canonical receipt.
    ///
    /// Opaque owner values naming the exact serializer (id, version, and
    /// options digest) the Governor compiler froze for this receipt (I4.4.1
    /// freeze). The compiled-surface intake copies them verbatim; an older
    /// host producer that states none carries empty strings, never invented
    /// values. Bound-checked like every other carried reference.
    #[serde(default)]
    pub serializer_id: String,
    /// Frozen serializer version carried from the canonical receipt.
    #[serde(default)]
    pub serializer_version: String,
    /// Frozen serializer options digest carried from the canonical receipt.
    #[serde(default)]
    pub serializer_options_digest: String,
    /// Frozen tokenizer identity carried from the canonical receipt.
    ///
    /// Opaque owner values naming the exact tokenizer (id, version, and
    /// hash) the Governor compiler froze for this receipt (I4.4.1 freeze).
    /// Carried verbatim under the same rules as the serializer freeze above.
    #[serde(default)]
    pub tokenizer_id: String,
    /// Frozen tokenizer version carried from the canonical receipt.
    #[serde(default)]
    pub tokenizer_version: String,
    /// Frozen tokenizer hash carried from the canonical receipt.
    #[serde(default)]
    pub tokenizer_hash: String,
    /// Decision Safety Floor member handles carried in default output.
    ///
    /// Opaque owner handles (bounded like governance evidence); full floor
    /// content stays behind explicit expansion. Presence is not invented:
    /// an empty list projects no floor rather than a forged one.
    #[serde(default)]
    pub decision_safety_floor_refs: Vec<String>,
    #[serde(default)]
    pub supported_count: u32,
    #[serde(default)]
    pub verified_count: u32,
    #[serde(default)]
    pub candidate_count: u32,
    #[serde(default)]
    pub conflicts_unknowns: Vec<String>,
    pub next_safe_expansion: String,
    /// Bounded boot delta relative to the previous delivered bootstrap.
    ///
    /// Purely additive (I7.8 step 4): it never replaces the readiness, task
    /// selection, authority, or recovery fields above, so budgeting the preview
    /// cannot drop them. `None` when the owner produced no delta for this
    /// surface; it is never defaulted into an empty "nothing changed" claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_delta: Option<BootDelta>,
}

impl BootstrapContext {
    /// Ref-bound projection constructor over the canonical
    /// `OnboardingReadinessReceipt` (I4.4.1).
    ///
    /// The canonical readiness decision stays with the receipt; this only
    /// carries its reference (`receipt_ref` -> `onboarding_readiness_ref`) and
    /// passes the disposition through unchanged, plus the compiled surface
    /// values (`smallest_missing_question`, `lease_deadline`,
    /// `receipt_revision`) the Governor compiler delivered for this exact
    /// receipt. It can never invent readiness: the assessment is capped later
    /// by [`cap_assessment`] in [`get_understanding_bootstrap`]. The frozen
    /// serializer/tokenizer identities stay empty on this host-supplied path:
    /// only [`BootstrapContext::from_compiled_surface`] may carry them, copied
    /// verbatim from the Governor surface. Fails closed
    /// via `validate_context` on blank/unbounded refs and handles (reuse of
    /// `non_blank` / `bounded_list` codes such as `READINESS_REF_MISSING`).
    #[allow(clippy::too_many_arguments)]
    pub fn from_receipt(
        receipt_ref: String,
        principal_ref: String,
        profile_ref: String,
        workscope_ref: String,
        onboarding_disposition: ReadinessDisposition,
        smallest_missing_question: Option<String>,
        lease_deadline: u64,
        receipt_revision: u64,
        revision_refs: Vec<String>,
        orientation_handles: Vec<String>,
        attention_handles: Vec<String>,
        problem_handles: Vec<String>,
        role_lease_ref: String,
        state_fence_ref: String,
        governance: GovernanceEvidence,
        route_profile_ref: String,
        decision_safety_floor_refs: Vec<String>,
        workspace_instance_ref: String,
        projection_source_ref: String,
        projection_generation: u64,
        supported_count: u32,
        verified_count: u32,
        candidate_count: u32,
        conflicts_unknowns: Vec<String>,
        next_safe_expansion: String,
    ) -> Result<Self, BootstrapError> {
        let context = Self {
            principal_ref,
            profile_ref,
            workscope_ref,
            onboarding_readiness_ref: receipt_ref,
            onboarding_disposition,
            smallest_missing_question,
            lease_deadline,
            receipt_revision,
            revision_refs,
            orientation_handles,
            attention_handles,
            problem_handles,
            role_lease_ref,
            state_fence_ref,
            governance,
            route_profile_ref,
            serializer_id: String::new(),
            serializer_version: String::new(),
            serializer_options_digest: String::new(),
            tokenizer_id: String::new(),
            tokenizer_version: String::new(),
            tokenizer_hash: String::new(),
            decision_safety_floor_refs,
            workspace_instance_ref,
            projection_source_ref,
            projection_generation,
            supported_count,
            verified_count,
            candidate_count,
            conflicts_unknowns,
            next_safe_expansion,
            boot_delta: None,
        };
        validate_context(&context)?;
        Ok(context)
    }

    /// Ref-bound projection constructor over the Governor-compiled readiness
    /// surface (I4.4.1).
    ///
    /// Production intake for a surface the Governor compiler delivered: the
    /// caller supplies the [`ColdStartSurfaceView`] projected by
    /// `GovernorComposition::cold_start_surface_for_lease` from the retained
    /// terminal `OnboardingReadinessReceipt`, plus the owner-produced
    /// non-readiness context, and this builds the context through
    /// [`BootstrapContext::from_receipt`] so the same fail-closed validation
    /// applies. The readiness half (`onboarding_readiness_ref`,
    /// `onboarding_disposition`, `smallest_missing_question`,
    /// `lease_deadline`, `receipt_revision`, `workspace_instance_ref`,
    /// `projection_source_ref`, `projection_generation`) always comes from
    /// the compiled view; the bridge never invents it. An unknown readiness
    /// token fails closed with `READINESS_TOKEN_UNKNOWN` instead of guessing
    /// a disposition.
    /// Live status: owning intake for the bridge delivery path; the live
    /// bridge note path supplies no governor surface yet (BLOCKED-BY
    /// bridge-transport: `BridgeRunner::note_owner_snapshot` intake in
    /// `bins/eliot-agent-bridge/src/lib.rs`).
    #[allow(clippy::too_many_arguments)]
    pub fn from_compiled_surface(
        surface: &ColdStartSurfaceView,
        principal_ref: String,
        profile_ref: String,
        workscope_ref: String,
        revision_refs: Vec<String>,
        orientation_handles: Vec<String>,
        attention_handles: Vec<String>,
        problem_handles: Vec<String>,
        role_lease_ref: String,
        state_fence_ref: String,
        governance: GovernanceEvidence,
        route_profile_ref: String,
        decision_safety_floor_refs: Vec<String>,
        supported_count: u32,
        verified_count: u32,
        candidate_count: u32,
        conflicts_unknowns: Vec<String>,
        next_safe_expansion: String,
        boot_delta: Option<BootDelta>,
    ) -> Result<Self, BootstrapError> {
        if principal_ref != surface.principal_ref {
            return Err(BootstrapError::new(
                "BOOTSTRAP_PRINCIPAL_MISMATCH",
                "caller principal disagrees with the compiled owner surface",
            ));
        }
        if workscope_ref != surface.scope.scope_ref {
            return Err(BootstrapError::new(
                "BOOTSTRAP_SCOPE_MISMATCH",
                "caller WorkScope disagrees with the compiled owner surface",
            ));
        }
        if route_profile_ref != surface.route_profile_ref {
            return Err(BootstrapError::new(
                "BOOTSTRAP_ROUTE_PROFILE_MISMATCH",
                "caller route profile disagrees with the compiled owner surface",
            ));
        }
        let onboarding_disposition = match surface.readiness.as_str() {
            "UNSEEN" => ReadinessDisposition::Unseen,
            "SCANNING" => ReadinessDisposition::Scanning,
            "NEEDS_SCOPE" => ReadinessDisposition::NeedsScope,
            "NEEDS_TASK" => ReadinessDisposition::NeedsTask,
            "NEEDS_SOURCES" => ReadinessDisposition::NeedsSources,
            "READY_READ_ONLY" => ReadinessDisposition::ReadyReadOnly,
            "READY_MATERIAL" => ReadinessDisposition::ReadyMaterial,
            "DEGRADED" => ReadinessDisposition::Degraded,
            "CONFLICTED" => ReadinessDisposition::Conflicted,
            _ => {
                return Err(BootstrapError::new(
                    "READINESS_TOKEN_UNKNOWN",
                    "compiled readiness token is not a known lifecycle",
                ));
            }
        };
        if onboarding_disposition == ReadinessDisposition::ReadyMaterial {
            return Err(BootstrapError::new(
                "BOOTSTRAP_STATE_FENCE_UNBOUND",
                "material readiness cannot be projected while the supplied fence is opaque and cannot be compared with the typed owner fence",
            ));
        }
        Self::from_receipt(
            surface.receipt_ref.clone(),
            principal_ref,
            profile_ref,
            workscope_ref,
            onboarding_disposition,
            surface.smallest_missing_question.clone(),
            surface.lease_deadline,
            surface.receipt_revision,
            revision_refs,
            orientation_handles,
            attention_handles,
            problem_handles,
            role_lease_ref,
            state_fence_ref,
            governance,
            route_profile_ref,
            decision_safety_floor_refs,
            surface.workspace_instance_ref.clone(),
            surface.projection_source_ref.clone(),
            surface.projection_generation,
            supported_count,
            verified_count,
            candidate_count,
            conflicts_unknowns,
            next_safe_expansion,
        )
        .and_then(|mut context| {
            // The boot delta is bound to this exact compiled receipt revision,
            // so a delta left over from an earlier surface fails closed here
            // instead of being projected against a readiness it never described.
            context.boot_delta = boot_delta;
            // Freeze the exact serializer/tokenizer identities the Governor
            // compiler bound into this receipt (I4.4.1 freeze). Copied
            // verbatim from the owner surface, never parsed or defaulted: the
            // Governor receipt validation requires every one of them
            // non-blank, so a surface that states none fails closed here
            // instead of projecting an unidentified rendering.
            context.serializer_id.clone_from(&surface.serializer_id);
            context
                .serializer_version
                .clone_from(&surface.serializer_version);
            context
                .serializer_options_digest
                .clone_from(&surface.serializer_options_digest);
            context.tokenizer_id.clone_from(&surface.tokenizer_id);
            context
                .tokenizer_version
                .clone_from(&surface.tokenizer_version);
            context.tokenizer_hash.clone_from(&surface.tokenizer_hash);
            non_blank(&context.serializer_id, "SERIALIZER_ID_MISSING")?;
            non_blank(&context.serializer_version, "SERIALIZER_VERSION_MISSING")?;
            non_blank(
                &context.serializer_options_digest,
                "SERIALIZER_OPTIONS_MISSING",
            )?;
            non_blank(&context.tokenizer_id, "TOKENIZER_ID_MISSING")?;
            non_blank(&context.tokenizer_version, "TOKENIZER_VERSION_MISSING")?;
            non_blank(&context.tokenizer_hash, "TOKENIZER_HASH_MISSING")?;
            validate_context(&context)?;
            Ok(context)
        })
    }
}

/// Checks that caller-provided task inputs preserve the task disposition and
/// exact task content carried by the compiled owner surface. Selection
/// provenance still depends on the authenticated #8 producer; the bridge
/// never treats a matching caller-provided reason/source as owner evidence.
pub(crate) fn validate_task_inputs_match_surface(
    surface: &ColdStartSurfaceView,
    tasks: &BootstrapTaskInputs,
) -> Result<(), BootstrapError> {
    validate_tasks(tasks)?;
    let task_mismatch = || {
        BootstrapError::new(
            "BOOTSTRAP_TASK_SURFACE_MISMATCH",
            "caller task inputs disagree with the task or selection state in the compiled owner surface",
        )
    };
    let exact_task_candidate = |task_ref: &str,
                                task_revision: u64,
                                acceptance_digest: &str,
                                selection: Option<(&str, &str)>|
     -> Result<(), BootstrapError> {
        if tasks.scope_level != ScopeLevel::Task
            || tasks.candidates.len() != 1
            || tasks.candidates[0].handle != task_ref
            || tasks.candidates[0].task_revision != Some(task_revision)
            || tasks.candidates[0].acceptance_digest.as_deref() != Some(acceptance_digest)
            || tasks.candidates[0].historical
            || tasks.candidates[0].prior_evaluation_candidate_only
            || tasks.candidates[0].independent_binding_supplied
        {
            return Err(task_mismatch());
        }
        match (selection, tasks.authoritative_selection.as_ref()) {
            (Some((owner_source, owner_evidence)), Some(presented))
                if presented.selected_handle == task_ref
                    && presented.source == owner_source
                    && presented.reason == owner_evidence => {}
            (None, None) => {}
            _ => {
                return Err(BootstrapError::new(
                    "BOOTSTRAP_SELECTION_PROVENANCE_MISMATCH",
                    "task selection source and evidence must exactly match the compiled owner receipt",
                ));
            }
        }
        Ok(())
    };

    match &surface.task_binding {
        TaskBindingState::CurrentTaskContract {
            task_ref,
            task_revision,
            acceptance_digest,
            selection_source_ref,
            evidence_ref,
        } => exact_task_candidate(
            task_ref,
            *task_revision,
            acceptance_digest,
            Some((selection_source_ref, evidence_ref)),
        ),
        TaskBindingState::Exploratory {
            task_ref,
            task_revision,
            acceptance_digest,
        } => exact_task_candidate(task_ref, *task_revision, acceptance_digest, None),
        TaskBindingState::Ambiguous { candidate_handles } => {
            if tasks.scope_level != ScopeLevel::Task
                || candidate_handles.len() < 2
                || tasks.authoritative_selection.is_some()
                || tasks.candidates.len() != candidate_handles.len()
                || tasks
                    .candidates
                    .iter()
                    .zip(candidate_handles)
                    .any(|(candidate, handle)| {
                        candidate.handle != *handle
                            || candidate.task_revision.is_some()
                            || candidate.acceptance_digest.is_some()
                            || candidate.historical
                            || candidate.prior_evaluation_candidate_only
                            || candidate.independent_binding_supplied
                    })
            {
                return Err(task_mismatch());
            }
            Ok(())
        }
        TaskBindingState::None_ => {
            if !tasks.candidates.is_empty() || tasks.authoritative_selection.is_some() {
                return Err(task_mismatch());
            }
            Ok(())
        }
        TaskBindingState::Stale {
            task_ref,
            task_revision,
        } => {
            if tasks.scope_level != ScopeLevel::Task
                || tasks.candidates.len() != 1
                || tasks.candidates[0].handle != *task_ref
                || tasks.candidates[0].task_revision != Some(*task_revision)
                || tasks.candidates[0].acceptance_digest.is_some()
                || tasks.candidates[0].historical
                || tasks.candidates[0].prior_evaluation_candidate_only
                || tasks.candidates[0].independent_binding_supplied
                || tasks.authoritative_selection.is_some()
            {
                return Err(task_mismatch());
            }
            Err(BootstrapError::new(
                "BOOTSTRAP_TASK_STALE",
                "compiled owner surface carries a stale task binding that cannot be represented as a current bridge selection",
            ))
        }
    }
}

/// Selected task identity with its exact revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedTask {
    pub task_ref: String,
    pub task_revision: u64,
}

/// Projected task-selection evidence (I7.17 `TaskSelectionEvidence` row).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSelectionView {
    pub disposition: TaskSelectionDisposition,
    pub scope_level: ScopeLevel,
    pub candidate_task_handles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_task_and_revision: Option<SelectedTask>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance_digest: Option<String>,
    pub selection_source_and_reason: String,
    #[serde(default)]
    pub contamination_flags: Vec<String>,
}

/// Route-profiled payload measurement for one delivered default output
/// (I7.26 reversible payload budget).
///
/// Records the exact serialized size of the default bootstrap payload the
/// agent receives on the owner-selected route, bound to that route profile
/// reference. The size is an exact UTF-8 byte observation over the rendered
/// payload ([`SerializedContextMeasurement::utf8_bytes`]), never a tokenizer
/// estimate: approximate token estimates never prove preservation (I7.11).
/// No budget is invented here — the bridge neither qualifies routes nor mints
/// capacities; it observes and reports. Material kept out of the default
/// output stays reachable through `omitted_behind_handles`, which names the
/// exact expansion handles carried inline (`next_safe_expansion` plus the
/// boot-delta expansion handle when the owner produced one), so budgeting the
/// default output cannot silently drop content: every omission stays
/// reversible behind a named handle. `status` is `ExactUtf8` while a selected
/// qualified route profile is carried and `Unavailable` when no route profile
/// was selected (the byte count stays exact; route qualification is what is
/// missing).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePayloadMeasurement {
    /// Owner-selected route profile this payload was measured under.
    pub route_profile_ref: String,
    /// Exact rendered UTF-8 bytes of the default bootstrap payload,
    /// excluding this measurement envelope itself.
    pub measured_utf8_bytes: u64,
    /// Whether the observation is qualified by a selected route profile.
    pub status: MeasurementStatus,
    /// Expansion handles behind which omitted material stays reachable.
    pub omitted_behind_handles: Vec<String>,
}

/// Measures the rendered default-output payload under the owner-selected
/// route profile.
///
/// Serializes nothing itself: the caller supplies the already-rendered
/// payload bytes' string form and the expansion handles carried inline, and
/// this binds the exact byte observation to the route profile. At most the
/// two inline expansion handles (`next_safe_expansion`, boot-delta expansion)
/// are named, so the report is bounded by construction.
#[must_use]
pub fn measure_route_payload(
    route_profile_ref: &str,
    rendered_payload: &str,
    omitted_behind_handles: Vec<String>,
) -> RoutePayloadMeasurement {
    let status = if route_profile_ref.trim().is_empty() {
        MeasurementStatus::Unavailable
    } else {
        MeasurementStatus::ExactUtf8
    };
    RoutePayloadMeasurement {
        route_profile_ref: route_profile_ref.to_owned(),
        measured_utf8_bytes: SerializedContextMeasurement::utf8_bytes(rendered_payload),
        status,
        omitted_behind_handles,
    }
}

/// Bounded agent-facing projection of onboarding readiness plus current
/// cognitive state (I7.17 `UnderstandingBootstrap`).
///
/// The readiness half delivers the compiled canonical surface: disposition
/// plus the smallest missing question, lease deadline, and receipt revision
/// the Governor compiler issued, so agent and Human callers see the exact
/// question and expiry instead of a buried setup state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnderstandingBootstrap {
    pub onboarding_readiness_ref: String,
    pub onboarding_readiness_disposition: ReadinessDisposition,
    /// Smallest missing question from the compiled readiness surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smallest_missing_question: Option<String>,
    /// Lease deadline from the compiled readiness surface (receipt expiry).
    #[serde(default)]
    pub lease_deadline: u64,
    /// Receipt revision from the compiled readiness surface.
    #[serde(default)]
    pub receipt_revision: u64,
    pub principal_ref: String,
    pub profile_ref: String,
    pub workscope_ref: String,
    pub task_selection: TaskSelectionView,
    pub role_lease_ref: String,
    pub state_fence_ref: String,
    pub current_assessment: CurrentAssessment,
    /// Intake provenance stamp (issue #8 P1).
    ///
    /// Composition sets [`ProjectionProvenance::HostCarried`]; the sealed
    /// bridge delivery path upgrades it to
    /// [`ProjectionProvenance::OwnerCompiled`] only for snapshots retained
    /// through the Governor-compiled surface intake, so a host-authored
    /// bootstrap can never present itself as owner-issued.
    #[serde(default)]
    pub projection_provenance: ProjectionProvenance,
    /// Freshness disposition of this delivered projection (issue #8 A2).
    ///
    /// Composition reports [`ProjectionFreshness::Partial`] for stated
    /// sources and [`ProjectionFreshness::Unavailable`] when no projection
    /// source was stated; the sealed bridge delivery path upgrades a stated
    /// source to [`ProjectionFreshness::Current`] only for snapshots
    /// retained through the Governor-compiled surface intake while the live
    /// attach seal still holds.
    #[serde(default)]
    pub projection_freshness: ProjectionFreshness,
    /// Workspace instance identity projected from the composed context.
    #[serde(default)]
    pub workspace_instance_ref: String,
    /// Projection source identity projected from the composed context.
    #[serde(default)]
    pub projection_source_ref: String,
    /// Projection generation projected from the composed context.
    #[serde(default)]
    pub projection_generation: u64,
    pub route_profile_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decision_safety_floor_refs: Vec<String>,
    /// Frozen serializer identity projected from the compiled receipt.
    ///
    /// Empty when an older producer stated none; the owner-surface intake
    /// always carries the exact frozen values.
    #[serde(default)]
    pub serializer_id: String,
    /// Frozen serializer version projected from the compiled receipt.
    #[serde(default)]
    pub serializer_version: String,
    /// Frozen serializer options digest projected from the compiled receipt.
    #[serde(default)]
    pub serializer_options_digest: String,
    /// Frozen tokenizer identity projected from the compiled receipt.
    #[serde(default)]
    pub tokenizer_id: String,
    /// Frozen tokenizer version projected from the compiled receipt.
    #[serde(default)]
    pub tokenizer_version: String,
    /// Frozen tokenizer hash projected from the compiled receipt.
    #[serde(default)]
    pub tokenizer_hash: String,
    /// Route-profiled payload measurement for this default output.
    ///
    /// `None` on unsealed compositions; every sealed delivery attaches the
    /// exact measurement before returning, so each bootstrap the agent
    /// receives carries its own route-bound size observation plus the
    /// expansion handles behind which omitted material stays reachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_measurement: Option<RoutePayloadMeasurement>,
    pub supported_count: u32,
    pub verified_count: u32,
    pub candidate_count: u32,
    pub relevant_handles: Vec<String>,
    pub attention_handles: Vec<String>,
    pub problem_handles: Vec<String>,
    pub revision_refs: Vec<String>,
    pub conflicts_unknowns: Vec<String>,
    pub next_safe_expansion: String,
    /// Bounded boot delta projected from the owner (I7.8 step 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_delta: Option<BootDelta>,
    pub governance: GovernanceEvidence,
}

/// Fail-closed composition error; carries codes only, no secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapError {
    pub code: &'static str,
    pub detail: String,
}

impl BootstrapError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.code, self.detail)
    }
}

impl std::error::Error for BootstrapError {}

fn non_blank(value: &str, field: &'static str) -> Result<(), BootstrapError> {
    if value.trim().is_empty() {
        return Err(BootstrapError::new(field, "must be a non-blank reference"));
    }
    if value.len() > MAX_HANDLE_LEN {
        return Err(BootstrapError::new(field, "reference exceeds bound"));
    }
    Ok(())
}

fn bounded_list(values: &[String], field: &'static str, max: usize) -> Result<(), BootstrapError> {
    if values.len() > max {
        return Err(BootstrapError::new(field, "handle list exceeds bound"));
    }
    for value in values {
        non_blank(value, field)?;
    }
    Ok(())
}

/// Checks the two `GovernanceProfile` authorization axes against the derivation
/// contract. Freshness inputs remain owner-supplied fields in the typed
/// profile; this consistency check does not authenticate their origin.
fn validate_governance_axes(
    coverage: &IntegrationCoverageProfile,
    profile: &GovernanceProfile,
) -> Result<(), BootstrapError> {
    let pre_action_enforced = coverage.disposition(LogicalEvent::PreToolUse)
        == Some(EventDisposition::Enforced)
        && coverage.disposition(LogicalEvent::PermissionRequest)
            == Some(EventDisposition::Enforced);
    let expected_enforcement =
        coverage.verified && pre_action_enforced && profile.watchdog_fresh && profile.trace_fresh;
    let expected_complete_ops = coverage.verified
        && coverage.completeness == EventCompleteness::Complete
        && profile.watchdog_fresh
        && profile.trace_fresh;
    if profile.authorizes_enforcement != expected_enforcement
        || profile.authorizes_complete_coverage_ops != expected_complete_ops
    {
        return Err(BootstrapError::new(
            "GOVERNANCE_DERIVATION_MISMATCH",
            "governance authorization axes disagree with coverage and freshness",
        ));
    }
    Ok(())
}

fn validate_governance(governance: &GovernanceEvidence) -> Result<(), BootstrapError> {
    non_blank(&governance.profile_ref, "GOVERNANCE_PROFILE_MISSING")?;
    non_blank(&governance.profile_revision, "GOVERNANCE_REVISION_MISSING")?;
    governance.coverage_profile.validate().map_err(|error| {
        BootstrapError::new(
            "COVERAGE_INVALID",
            format!("integration coverage profile is not valid: {error}"),
        )
    })?;
    let profile = &governance.governance_profile;
    let coverage = &governance.coverage_profile;
    if governance.profile_ref != coverage.fingerprint || profile.fingerprint != coverage.fingerprint
    {
        return Err(BootstrapError::new(
            "GOVERNANCE_FINGERPRINT_MISMATCH",
            "governance evidence is not bound to its attached coverage fingerprint",
        ));
    }
    if profile.revision == 0 || governance.profile_revision != profile.revision.to_string() {
        return Err(BootstrapError::new(
            "GOVERNANCE_REVISION_MISMATCH",
            "governance evidence does not carry the exact current profile revision",
        ));
    }
    if profile.verified != coverage.verified {
        return Err(BootstrapError::new(
            "GOVERNANCE_COVERAGE_UNVERIFIED",
            "governance and coverage verification states disagree",
        ));
    }
    if !coverage.verified {
        return Err(BootstrapError::new(
            "GOVERNANCE_COVERAGE_UNVERIFIED",
            "Governor derivation requires verified production coverage",
        ));
    }
    if profile.completeness != coverage.completeness {
        return Err(BootstrapError::new(
            "GOVERNANCE_COMPLETENESS_MISMATCH",
            "governance and coverage completeness states disagree",
        ));
    }
    validate_governance_axes(coverage, profile)?;
    let expected_preview: Vec<String> = coverage
        .gaps
        .iter()
        .take(MAX_EVIDENCE_HANDLES)
        .cloned()
        .collect();
    if governance.limiting_integration_evidence != expected_preview {
        let code =
            if governance.limiting_integration_evidence.is_empty() && !coverage.gaps.is_empty() {
                "GOVERNANCE_EVIDENCE_MISSING"
            } else {
                "GOVERNANCE_EVIDENCE_MISMATCH"
            };
        return Err(BootstrapError::new(
            code,
            "limiting integration evidence does not preserve the owner coverage gaps",
        ));
    }
    bounded_list(
        &governance.limiting_integration_evidence,
        "GOVERNANCE_EVIDENCE_BOUND",
        MAX_EVIDENCE_HANDLES,
    )
}

fn validate_context(context: &BootstrapContext) -> Result<(), BootstrapError> {
    non_blank(&context.principal_ref, "PRINCIPAL_MISSING")?;
    non_blank(&context.profile_ref, "PROFILE_MISSING")?;
    non_blank(&context.workscope_ref, "WORKSCOPE_MISSING")?;
    non_blank(&context.onboarding_readiness_ref, "READINESS_REF_MISSING")?;
    non_blank(&context.role_lease_ref, "ROLE_LEASE_MISSING")?;
    non_blank(&context.state_fence_ref, "STATE_FENCE_MISSING")?;
    non_blank(&context.next_safe_expansion, "NEXT_SAFE_EXPANSION_MISSING")?;
    if context.revision_refs.is_empty() {
        return Err(BootstrapError::new(
            "REVISIONS_MISSING",
            "at least one current revision/freshness handle is required",
        ));
    }
    bounded_list(&context.revision_refs, "REVISIONS_BOUND", MAX_HANDLES)?;
    bounded_list(
        &context.orientation_handles,
        "ORIENTATION_BOUND",
        MAX_HANDLES,
    )?;
    bounded_list(&context.attention_handles, "ATTENTION_BOUND", MAX_HANDLES)?;
    bounded_list(&context.problem_handles, "PROBLEMS_BOUND", MAX_HANDLES)?;
    bounded_list(&context.conflicts_unknowns, "CONFLICTS_BOUND", MAX_HANDLES)?;
    if context.route_profile_ref.len() > MAX_HANDLE_LEN {
        return Err(BootstrapError::new(
            "ROUTE_PROFILE_BOUND",
            "route profile reference exceeds bound",
        ));
    }
    if !context.route_profile_ref.is_empty() {
        non_blank(&context.route_profile_ref, "ROUTE_PROFILE_MISSING")?;
    }
    // Frozen serializer/tokenizer identities: empty only when an older
    // producer stated none (the host-supplied path never invents them);
    // present values stay bounded references like every carried identity.
    for (value, missing) in [
        (&context.serializer_id, "SERIALIZER_ID_MISSING"),
        (&context.serializer_version, "SERIALIZER_VERSION_MISSING"),
        (
            &context.serializer_options_digest,
            "SERIALIZER_OPTIONS_MISSING",
        ),
        (&context.tokenizer_id, "TOKENIZER_ID_MISSING"),
        (&context.tokenizer_version, "TOKENIZER_VERSION_MISSING"),
        (&context.tokenizer_hash, "TOKENIZER_HASH_MISSING"),
    ] {
        if value.len() > MAX_HANDLE_LEN {
            return Err(BootstrapError::new(missing, "reference exceeds bound"));
        }
        if !value.is_empty() {
            non_blank(value, missing)?;
        }
    }
    if context.workspace_instance_ref.len() > MAX_HANDLE_LEN {
        return Err(BootstrapError::new(
            "WORKSPACE_INSTANCE_BOUND",
            "workspace instance reference exceeds bound",
        ));
    }
    if !context.workspace_instance_ref.is_empty() {
        non_blank(
            &context.workspace_instance_ref,
            "WORKSPACE_INSTANCE_MISSING",
        )?;
    }
    if let Some(question) = &context.smallest_missing_question {
        non_blank(question, "SMALLEST_QUESTION_MISSING")?;
        if question.len() > MAX_HANDLE_LEN {
            return Err(BootstrapError::new(
                "SMALLEST_QUESTION_BOUND",
                "smallest missing question exceeds bound",
            ));
        }
    }
    if context.projection_source_ref.len() > MAX_HANDLE_LEN {
        return Err(BootstrapError::new(
            "PROJECTION_SOURCE_BOUND",
            "projection source reference exceeds bound",
        ));
    }
    if !context.projection_source_ref.is_empty() {
        non_blank(&context.projection_source_ref, "PROJECTION_SOURCE_MISSING")?;
    }
    bounded_list(
        &context.decision_safety_floor_refs,
        "FLOOR_BOUND",
        MAX_EVIDENCE_HANDLES,
    )?;
    if let Some(delta) = &context.boot_delta {
        delta
            .validate(context.receipt_revision)
            .map_err(|error| BootstrapError::new(error.code, error.detail))?;
    }
    validate_governance(&context.governance)
}

fn validate_tasks(tasks: &BootstrapTaskInputs) -> Result<(), BootstrapError> {
    if tasks.candidates.len() > MAX_CANDIDATE_HANDLES {
        return Err(BootstrapError::new(
            "CANDIDATES_BOUND",
            "candidate task handles exceed bound",
        ));
    }
    for candidate in &tasks.candidates {
        non_blank(&candidate.handle, "CANDIDATE_HANDLE_MISSING")?;
        if let Some(digest) = &candidate.acceptance_digest {
            non_blank(digest, "ACCEPTANCE_DIGEST_MISSING")?;
        }
    }
    if let Some(selection) = &tasks.authoritative_selection {
        non_blank(&selection.selected_handle, "SELECTION_HANDLE_MISSING")?;
        non_blank(&selection.reason, "SELECTION_REASON_MISSING")?;
        non_blank(&selection.source, "SELECTION_SOURCE_MISSING")?;
    }
    Ok(())
}

/// Whether a candidate is blocked until independently rebound.
const fn is_crossover(candidate: &TaskCandidate) -> bool {
    candidate.prior_evaluation_candidate_only && !candidate.independent_binding_supplied
}

/// Whether the owning task producer marked this candidate historical.
/// A historical task is never current selection evidence.
const fn is_historical(candidate: &TaskCandidate) -> bool {
    candidate.historical
}

const fn assessment_rank(assessment: CurrentAssessment) -> u8 {
    match assessment {
        CurrentAssessment::NotOnboarded => 0,
        CurrentAssessment::Stale => 1,
        CurrentAssessment::Degraded => 2,
        CurrentAssessment::Ready => 3,
    }
}

/// Caps the projected assessment at the referenced canonical readiness so the
/// bootstrap can never overstate readiness. `READY_READ_ONLY` readiness cannot
/// support a `READY` assessment; anything before material readiness caps at
/// `NOT_ONBOARDED`, except `SCANNING` which caps at `STALE`.
///
/// Decision Safety Floor enforcement (default output): material readiness
/// without a selected qualified route profile (`route_profile_ref`) and at
/// least one Decision Safety Floor member (`decision_safety_floor_refs`)
/// cannot project `READY`; it degrades to `DEGRADED`. The bridge never
/// qualifies a route or invents floor content itself — it only enforces
/// presence of the owner-supplied refs carried verbatim in the context, so
/// an empty route/floor set projects no floor and withholds `READY` rather
/// than forging one.
#[must_use]
pub fn cap_assessment(
    readiness: ReadinessDisposition,
    requested: CurrentAssessment,
    route_profile_ref: &str,
    decision_safety_floor_refs: &[String],
) -> CurrentAssessment {
    let mut cap: u8 = match readiness {
        ReadinessDisposition::ReadyMaterial => 3,
        ReadinessDisposition::ReadyReadOnly
        | ReadinessDisposition::Degraded
        | ReadinessDisposition::Conflicted => 2,
        ReadinessDisposition::Scanning => 1,
        ReadinessDisposition::Unseen
        | ReadinessDisposition::NeedsScope
        | ReadinessDisposition::NeedsTask
        | ReadinessDisposition::NeedsSources => 0,
    };
    if cap == 3 && (route_profile_ref.trim().is_empty() || decision_safety_floor_refs.is_empty()) {
        cap = 2;
    }
    let wanted = assessment_rank(requested);
    let clamped = if wanted < cap { wanted } else { cap };
    match clamped {
        0 => CurrentAssessment::NotOnboarded,
        1 => CurrentAssessment::Stale,
        2 => CurrentAssessment::Degraded,
        _ => CurrentAssessment::Ready,
    }
}

fn selection_handles(tasks: &BootstrapTaskInputs) -> Vec<String> {
    tasks
        .candidates
        .iter()
        .map(|candidate| candidate.handle.clone())
        .collect()
}

fn selection_contamination_flags(tasks: &BootstrapTaskInputs) -> Vec<String> {
    let mut flags = Vec::new();
    if tasks.candidates.iter().any(is_crossover) {
        flags.push(CROSSOVER_CONTAMINATED.to_owned());
    }
    if tasks.candidates.iter().any(is_historical) {
        flags.push(HISTORICAL_CANDIDATE.to_owned());
    }
    flags
}

fn bind_authoritative(
    tasks: &BootstrapTaskInputs,
    selection: &AuthoritativeSelection,
    handles: Vec<String>,
    contamination_flags: Vec<String>,
) -> Result<TaskSelectionView, BootstrapError> {
    let Some(matched) = tasks
        .candidates
        .iter()
        .find(|candidate| candidate.handle == selection.selected_handle)
    else {
        return Err(BootstrapError::new(
            "SELECTION_UNKNOWN_HANDLE",
            "authoritative selection names no listed candidate; refusing to choose",
        ));
    };
    if is_crossover(matched) {
        return Err(BootstrapError::new(
            "SELECTION_CONTAMINATED",
            "authoritative selection names a crossover-contaminated candidate without an independent binding record; refusing to bind",
        ));
    }
    if is_historical(matched) {
        return Err(BootstrapError::new(
            "SELECTION_HISTORICAL",
            "authoritative selection names a historical task; current binding required, refusing to bind",
        ));
    }
    let Some(revision) = matched.task_revision else {
        return Err(BootstrapError::new(
            "SELECTION_REVISION_MISSING",
            "authoritative selection target carries no exact task revision; refusing to bind",
        ));
    };
    if revision == 0 {
        return Err(BootstrapError::new(
            "SELECTION_REVISION_MISSING",
            "authoritative selection target carries a zero task revision, not a current TaskContract revision; refusing to bind",
        ));
    }
    let Some(acceptance_digest) = matched.acceptance_digest.clone() else {
        return Err(BootstrapError::new(
            "SELECTION_ACCEPTANCE_MISSING",
            "authoritative selection target carries no acceptance digest; refusing to bind",
        ));
    };
    non_blank(&acceptance_digest, "SELECTION_ACCEPTANCE_MISSING")?;
    Ok(TaskSelectionView {
        disposition: TaskSelectionDisposition::Bound,
        scope_level: tasks.scope_level,
        candidate_task_handles: handles,
        selected_task_and_revision: Some(SelectedTask {
            task_ref: matched.handle.clone(),
            task_revision: revision,
        }),
        acceptance_digest: Some(acceptance_digest),
        selection_source_and_reason: format!("{}: {}", selection.source, selection.reason),
        contamination_flags,
    })
}

fn bind_uncontended(
    tasks: &BootstrapTaskInputs,
    handles: Vec<String>,
    contamination_flags: Vec<String>,
) -> Result<TaskSelectionView, BootstrapError> {
    if tasks.candidates.is_empty() {
        return Ok(TaskSelectionView {
            disposition: TaskSelectionDisposition::None,
            scope_level: tasks.scope_level,
            candidate_task_handles: handles,
            selected_task_and_revision: None,
            acceptance_digest: None,
            selection_source_and_reason: "no candidates; no task bound".to_owned(),
            contamination_flags,
        });
    }
    let only = &tasks.candidates[0];
    if is_historical(only) {
        return Err(BootstrapError::new(
            "SELECTION_HISTORICAL",
            "sole candidate is a historical task; current binding required, refusing to bind",
        ));
    }
    if is_crossover(only) {
        return Ok(TaskSelectionView {
            disposition: TaskSelectionDisposition::None,
            scope_level: tasks.scope_level,
            candidate_task_handles: handles,
            selected_task_and_revision: None,
            acceptance_digest: None,
            selection_source_and_reason:
                "sole candidate is crossover-contaminated; independent rebinding required"
                    .to_owned(),
            contamination_flags,
        });
    }
    let Some(revision) = only.task_revision else {
        return Err(BootstrapError::new(
            "SELECTION_REVISION_MISSING",
            "sole candidate carries no exact task revision; refusing to bind",
        ));
    };
    if revision == 0 {
        return Err(BootstrapError::new(
            "SELECTION_REVISION_MISSING",
            "sole candidate carries a zero task revision, not a current TaskContract revision; refusing to bind",
        ));
    }
    let Some(acceptance_digest) = only.acceptance_digest.clone() else {
        return Err(BootstrapError::new(
            "SELECTION_ACCEPTANCE_MISSING",
            "sole candidate carries no acceptance digest; refusing to bind",
        ));
    };
    non_blank(&acceptance_digest, "SELECTION_ACCEPTANCE_MISSING")?;
    Ok(TaskSelectionView {
        disposition: TaskSelectionDisposition::Unique,
        scope_level: tasks.scope_level,
        candidate_task_handles: handles,
        selected_task_and_revision: Some(SelectedTask {
            task_ref: only.handle.clone(),
            task_revision: revision,
        }),
        acceptance_digest: Some(acceptance_digest),
        selection_source_and_reason: "single eligible candidate; no choice made".to_owned(),
        contamination_flags,
    })
}

fn compose_selection(tasks: &BootstrapTaskInputs) -> Result<TaskSelectionView, BootstrapError> {
    let handles = selection_handles(tasks);
    let contamination_flags = selection_contamination_flags(tasks);
    if let Some(selection) = &tasks.authoritative_selection {
        return bind_authoritative(tasks, selection, handles, contamination_flags);
    }
    if tasks.candidates.len() <= 1 {
        return bind_uncontended(tasks, handles, contamination_flags);
    }
    Ok(TaskSelectionView {
        disposition: TaskSelectionDisposition::Ambiguous,
        scope_level: tasks.scope_level,
        candidate_task_handles: handles,
        selected_task_and_revision: None,
        acceptance_digest: None,
        selection_source_and_reason:
            "multiple eligible candidates without authoritative selection evidence; refusing to choose"
                .to_owned(),
        contamination_flags,
    })
}

/// Composes the bounded `UnderstandingBootstrap` over existing owners.
///
/// Validates the supplied context and task inputs, computes the deterministic
/// task-selection disposition, and caps the assessment at the referenced
/// canonical readiness. A host-authored readiness enum is not task authority:
/// without a bound task (`NONE`/`AMBIGUOUS`) the projection reports
/// `NOT_ONBOARDED` even when the referenced disposition claims material
/// readiness, so a forged `READY_MATERIAL` with no task can never project
/// `READY` (I4.4.1: `READY_MATERIAL` is always tied to one `TaskContract`
/// revision). Fails closed whenever governance evidence, identity,
/// revisions, acceptance, or selection integrity are missing.
///
/// This is the projection half of readiness admission (I7.17 bounded read
/// composition): it caps and labels, it never admits. Material-readiness
/// admission stays with the sealed note intakes — the host-snapshot intake
/// refuses `READY_MATERIAL` outright, and the compiled-surface intake binds
/// the typed owner fence — so a composed `READY` from caller-supplied inputs
/// alone is never agent-facing delivery. The composed projection is stamped
/// [`ProjectionProvenance::HostCarried`] with a
/// [`ProjectionFreshness::Partial`] (or `Unavailable` when no projection
/// source was stated) disposition; only the sealed bridge delivery path may
/// upgrade those stamps for a Governor-compiled snapshot delivered under the
/// still-live attach seal.
pub fn get_understanding_bootstrap(
    context: &BootstrapContext,
    tasks: &BootstrapTaskInputs,
    requested_assessment: CurrentAssessment,
) -> Result<UnderstandingBootstrap, BootstrapError> {
    validate_context(context)?;
    validate_tasks(tasks)?;
    let task_selection = compose_selection(tasks)?;
    let mut relevant_handles = context.orientation_handles.clone();
    relevant_handles.truncate(MAX_HANDLES);
    // Без привязанной задачи готовности нет: проекция не вправе подтверждать
    // READY по чужому слову хозяина входных данных. Привязанная задача
    // дополнительно ограничена Decision Safety Floor: без выбранного
    // qualified route profile и floor-членов оценка снижается до DEGRADED.
    let current_assessment = match task_selection.disposition {
        TaskSelectionDisposition::Bound | TaskSelectionDisposition::Unique => cap_assessment(
            context.onboarding_disposition,
            requested_assessment,
            &context.route_profile_ref,
            &context.decision_safety_floor_refs,
        ),
        TaskSelectionDisposition::Ambiguous | TaskSelectionDisposition::None => {
            CurrentAssessment::NotOnboarded
        }
    };
    Ok(UnderstandingBootstrap {
        onboarding_readiness_ref: context.onboarding_readiness_ref.clone(),
        onboarding_readiness_disposition: context.onboarding_disposition,
        smallest_missing_question: context.smallest_missing_question.clone(),
        lease_deadline: context.lease_deadline,
        receipt_revision: context.receipt_revision,
        principal_ref: context.principal_ref.clone(),
        profile_ref: context.profile_ref.clone(),
        workscope_ref: context.workscope_ref.clone(),
        task_selection,
        role_lease_ref: context.role_lease_ref.clone(),
        state_fence_ref: context.state_fence_ref.clone(),
        current_assessment,
        projection_provenance: ProjectionProvenance::HostCarried,
        projection_freshness: if context.projection_source_ref.is_empty() {
            ProjectionFreshness::Unavailable
        } else {
            ProjectionFreshness::Partial
        },
        workspace_instance_ref: context.workspace_instance_ref.clone(),
        projection_source_ref: context.projection_source_ref.clone(),
        projection_generation: context.projection_generation,
        route_profile_ref: context.route_profile_ref.clone(),
        decision_safety_floor_refs: context.decision_safety_floor_refs.clone(),
        serializer_id: context.serializer_id.clone(),
        serializer_version: context.serializer_version.clone(),
        serializer_options_digest: context.serializer_options_digest.clone(),
        tokenizer_id: context.tokenizer_id.clone(),
        tokenizer_version: context.tokenizer_version.clone(),
        tokenizer_hash: context.tokenizer_hash.clone(),
        payload_measurement: None,
        supported_count: context.supported_count,
        verified_count: context.verified_count,
        candidate_count: context.candidate_count,
        relevant_handles,
        attention_handles: context.attention_handles.clone(),
        problem_handles: context.problem_handles.clone(),
        revision_refs: context.revision_refs.clone(),
        conflicts_unknowns: context.conflicts_unknowns.clone(),
        next_safe_expansion: context.next_safe_expansion.clone(),
        boot_delta: context.boot_delta.clone(),
        governance: context.governance.clone(),
    })
}

/// Once-per-session auto-boot delivery gate.
///
/// The first successful ELIOT response in a session carries the bootstrap
/// exactly once; later responses carry none, while bounded explicit retrieval
/// through [`get_understanding_bootstrap`] stays available.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BootstrapSession {
    auto_boot_delivered: bool,
}

impl BootstrapSession {
    /// Returns the bootstrap on the first successful response, `None` after.
    /// Composition failures also yield `None` rather than an unbounded or
    /// invented bootstrap; the session still counts as undelivered so a later
    /// response with complete inputs can carry it.
    pub fn take_auto_boot(
        &mut self,
        context: &BootstrapContext,
        tasks: &BootstrapTaskInputs,
        requested_assessment: CurrentAssessment,
    ) -> Option<UnderstandingBootstrap> {
        if self.auto_boot_delivered {
            return None;
        }
        let bootstrap = get_understanding_bootstrap(context, tasks, requested_assessment).ok()?;
        self.auto_boot_delivered = true;
        Some(bootstrap)
    }

    /// Whether the once-per-session bootstrap was already delivered.
    #[must_use]
    pub const fn auto_boot_delivered(&self) -> bool {
        self.auto_boot_delivered
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_integration_coverage::{
        ALL_EVENTS, DispatchOrdering, EventCoverage, GovernorCoverageDerivation,
    };

    fn fixture_governance() -> GovernanceEvidence {
        let coverage_profile = IntegrationCoverageProfile {
            fingerprint: "governance-profile-1".to_owned(),
            verified: true,
            events: ALL_EVENTS
                .iter()
                .map(|event| EventCoverage {
                    event: *event,
                    disposition: if *event == LogicalEvent::PreToolUse {
                        EventDisposition::Observed
                    } else {
                        EventDisposition::Enforced
                    },
                    ordering: DispatchOrdering::PreDispatch,
                    completeness: EventCompleteness::Complete,
                    proof_ceiling: "read-only".to_owned(),
                    source: "owner-observation".to_owned(),
                    gaps: Vec::new(),
                })
                .collect(),
            completeness: EventCompleteness::Unknown,
            proof_ceiling: "read-only".to_owned(),
            source: "integration-owner".to_owned(),
            gaps: vec!["coverage-gap:source-freshness".to_owned()],
        };
        let mut derivation = GovernorCoverageDerivation::new();
        let governance_profile = derivation
            .derive(
                &coverage_profile,
                &eliot_integration_coverage::WatchdogEvidence {
                    supervisor_id: "watchdog:fixture".to_owned(),
                    fresh: true,
                    summary: "test fixture supervision".to_owned(),
                },
                eliot_integration_coverage::TraceFreshness::Fresh,
            )
            .expect("verified owner coverage derives a governance profile");
        GovernanceEvidence {
            profile_ref: "governance-profile-1".to_owned(),
            profile_revision: "1".to_owned(),
            governance_profile,
            limiting_integration_evidence: coverage_profile.gaps.clone(),
            coverage_profile,
        }
    }

    fn fixture_context(disposition: ReadinessDisposition) -> BootstrapContext {
        BootstrapContext {
            principal_ref: "principal-1".to_owned(),
            profile_ref: "SPINE_FUNCTIONAL".to_owned(),
            workscope_ref: "workscope-1".to_owned(),
            onboarding_readiness_ref: "readiness-receipt-1".to_owned(),
            onboarding_disposition: disposition,
            smallest_missing_question: Some("task_ref".to_owned()),
            lease_deadline: 10,
            receipt_revision: 1,
            revision_refs: vec!["source-gen-9".to_owned()],
            orientation_handles: vec!["orientation:project".to_owned()],
            attention_handles: vec!["attention:conflict-1".to_owned()],
            problem_handles: vec!["problem:stale-proof".to_owned()],
            role_lease_ref: "role-lease-1".to_owned(),
            state_fence_ref: "fence-epoch-3-gen-7".to_owned(),
            governance: fixture_governance(),
            route_profile_ref: "route-profile-constrained-1".to_owned(),
            serializer_id: "serializer-1".to_owned(),
            serializer_version: "serializer-version-1".to_owned(),
            serializer_options_digest: "serializer-options-1".to_owned(),
            tokenizer_id: "tokenizer-1".to_owned(),
            tokenizer_version: "tokenizer-version-1".to_owned(),
            tokenizer_hash: "tokenizer-hash-1".to_owned(),
            decision_safety_floor_refs: vec![
                "floor:goal-scope-authority".to_owned(),
                "floor:task-selection-proof".to_owned(),
            ],
            workspace_instance_ref: "instance:a".to_owned(),
            projection_source_ref: "projection-source-1".to_owned(),
            projection_generation: 9,
            supported_count: 4,
            verified_count: 3,
            candidate_count: 1,
            conflicts_unknowns: vec![],
            next_safe_expansion: "bind task before material effects".to_owned(),
            boot_delta: None,
        }
    }

    fn eligible_task(index: usize) -> TaskCandidate {
        TaskCandidate {
            handle: format!("task-{index}"),
            task_revision: Some(u64::try_from(index + 1).expect("index must fit")),
            acceptance_digest: Some("a".repeat(64)),
            historical: false,
            prior_evaluation_candidate_only: false,
            independent_binding_supplied: true,
        }
    }

    #[test]
    fn first_response_carries_bounded_bootstrap_with_governance_evidence() {
        let context = fixture_context(ReadinessDisposition::ReadyMaterial);
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Session,
            candidates: Vec::new(),
            authoritative_selection: None,
        };
        let mut session = BootstrapSession::default();
        let first = session
            .take_auto_boot(&context, &tasks, CurrentAssessment::Ready)
            .expect("first response must carry the bootstrap");
        // No task bound: a host-authored READY_MATERIAL must not project READY.
        assert_eq!(
            first.task_selection.disposition,
            TaskSelectionDisposition::None
        );
        assert_eq!(first.current_assessment, CurrentAssessment::NotOnboarded);
        assert_eq!(first.governance.profile_ref, "governance-profile-1");
        assert_eq!(first.governance.profile_revision, "1");
        assert!(!first.governance.limiting_integration_evidence.is_empty());
        assert!(first.task_selection.candidate_task_handles.len() <= MAX_CANDIDATE_HANDLES);
        assert!(first.relevant_handles.len() <= MAX_HANDLES);
        assert!(first.revision_refs.len() <= MAX_HANDLES);
        assert!(session.auto_boot_delivered());
        assert!(
            session
                .take_auto_boot(&context, &tasks, CurrentAssessment::Ready)
                .is_none(),
            "bootstrap must be delivered exactly once per session",
        );
        let framed = serde_json::to_vec(&first).expect("bootstrap must serialize");
        assert!(!framed.is_empty());
    }

    #[test]
    fn ten_eligible_tasks_are_ambiguous_and_select_none() {
        let context = fixture_context(ReadinessDisposition::ReadyMaterial);
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Project,
            candidates: (0..10).map(eligible_task).collect(),
            authoritative_selection: None,
        };
        let bootstrap = get_understanding_bootstrap(&context, &tasks, CurrentAssessment::Ready)
            .expect("composition must succeed");
        assert_eq!(
            bootstrap.task_selection.disposition,
            TaskSelectionDisposition::Ambiguous
        );
        assert_eq!(bootstrap.task_selection.candidate_task_handles.len(), 10);
        assert!(
            bootstrap
                .task_selection
                .selected_task_and_revision
                .is_none(),
            "ambiguous selection must choose no task",
        );
        assert!(bootstrap.task_selection.acceptance_digest.is_none());
        assert_eq!(
            bootstrap.current_assessment,
            CurrentAssessment::NotOnboarded,
            "ambiguous selection must never project READY",
        );
    }

    #[test]
    fn prior_evaluation_candidate_stays_crossover_contaminated_until_rebound() {
        let context = fixture_context(ReadinessDisposition::ReadyMaterial);
        let contaminated = TaskCandidate {
            handle: "task-eval-1".to_owned(),
            task_revision: Some(2),
            acceptance_digest: Some("b".repeat(64)),
            historical: false,
            prior_evaluation_candidate_only: true,
            independent_binding_supplied: false,
        };
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Task,
            candidates: vec![contaminated],
            authoritative_selection: None,
        };
        let blocked = get_understanding_bootstrap(&context, &tasks, CurrentAssessment::Ready)
            .expect("composition must succeed");
        assert_eq!(
            blocked.task_selection.disposition,
            TaskSelectionDisposition::None
        );
        assert!(blocked.task_selection.selected_task_and_revision.is_none());
        assert!(
            blocked
                .task_selection
                .contamination_flags
                .contains(&CROSSOVER_CONTAMINATED.to_owned())
        );
        let rebound_tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Task,
            candidates: vec![TaskCandidate {
                handle: "task-eval-1".to_owned(),
                task_revision: Some(2),
                acceptance_digest: Some("b".repeat(64)),
                historical: false,
                prior_evaluation_candidate_only: true,
                independent_binding_supplied: true,
            }],
            authoritative_selection: None,
        };
        let rebound =
            get_understanding_bootstrap(&context, &rebound_tasks, CurrentAssessment::Ready)
                .expect("composition must succeed");
        assert_eq!(
            rebound.task_selection.disposition,
            TaskSelectionDisposition::Unique
        );
        assert!(
            !rebound
                .task_selection
                .contamination_flags
                .contains(&CROSSOVER_CONTAMINATED.to_owned())
        );
        let selected = rebound
            .task_selection
            .selected_task_and_revision
            .expect("rebound task must be selected");
        assert_eq!(selected.task_ref, "task-eval-1");
    }

    #[test]
    fn authoritative_selection_binds_exactly_the_named_candidate() {
        let context = fixture_context(ReadinessDisposition::ReadyMaterial);
        let mut candidates: Vec<TaskCandidate> = (0..3).map(eligible_task).collect();
        candidates.push(TaskCandidate {
            handle: "task-eval-9".to_owned(),
            task_revision: Some(9),
            acceptance_digest: Some("c".repeat(64)),
            historical: false,
            prior_evaluation_candidate_only: true,
            independent_binding_supplied: false,
        });
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Project,
            candidates,
            authoritative_selection: Some(AuthoritativeSelection {
                selected_handle: "task-1".to_owned(),
                reason: "governor work assignment".to_owned(),
                source: "governor-ledger-4".to_owned(),
            }),
        };
        let bootstrap = get_understanding_bootstrap(&context, &tasks, CurrentAssessment::Ready)
            .expect("composition must succeed");
        assert_eq!(
            bootstrap.task_selection.disposition,
            TaskSelectionDisposition::Bound
        );
        let selected = bootstrap
            .task_selection
            .selected_task_and_revision
            .expect("bound selection names a task");
        assert_eq!(selected.task_ref, "task-1");
        assert_eq!(selected.task_revision, 2);
        assert_eq!(
            bootstrap.task_selection.acceptance_digest,
            Some("a".repeat(64))
        );
        assert_eq!(
            bootstrap.task_selection.selection_source_and_reason,
            "governor-ledger-4: governor work assignment"
        );
        // The untouched crossover candidate still flags the row, but the
        // bound task itself is the clean authoritative pick.
        assert!(
            bootstrap
                .task_selection
                .contamination_flags
                .contains(&CROSSOVER_CONTAMINATED.to_owned())
        );
    }

    #[test]
    fn authoritative_selection_refuses_unknown_and_contaminated_handles() {
        let context = fixture_context(ReadinessDisposition::ReadyMaterial);
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Project,
            candidates: (0..2).map(eligible_task).collect(),
            authoritative_selection: Some(AuthoritativeSelection {
                selected_handle: "task-ghost".to_owned(),
                reason: "stale ledger pointer".to_owned(),
                source: "governor-ledger-4".to_owned(),
            }),
        };
        let error = get_understanding_bootstrap(&context, &tasks, CurrentAssessment::Ready)
            .expect_err("selection of an unlisted handle must fail closed");
        assert_eq!(error.code, "SELECTION_UNKNOWN_HANDLE");
        let contaminated_tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Project,
            candidates: vec![TaskCandidate {
                handle: "task-eval-1".to_owned(),
                task_revision: Some(2),
                acceptance_digest: Some("b".repeat(64)),
                historical: false,
                prior_evaluation_candidate_only: true,
                independent_binding_supplied: false,
            }],
            authoritative_selection: Some(AuthoritativeSelection {
                selected_handle: "task-eval-1".to_owned(),
                reason: "evaluation trace".to_owned(),
                source: "dreamer-candidate-7".to_owned(),
            }),
        };
        let error =
            get_understanding_bootstrap(&context, &contaminated_tasks, CurrentAssessment::Ready)
                .expect_err("selection of a contaminated handle must fail closed");
        assert_eq!(error.code, "SELECTION_CONTAMINATED");
    }

    #[test]
    fn assessment_never_stronger_than_readiness() {
        let context = fixture_context(ReadinessDisposition::NeedsTask);
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Session,
            candidates: Vec::new(),
            authoritative_selection: None,
        };
        let bootstrap = get_understanding_bootstrap(&context, &tasks, CurrentAssessment::Ready)
            .expect("composition must succeed");
        assert_eq!(
            bootstrap.current_assessment,
            CurrentAssessment::NotOnboarded
        );
        let read_only = fixture_context(ReadinessDisposition::ReadyReadOnly);
        let capped = get_understanding_bootstrap(&read_only, &tasks, CurrentAssessment::Ready)
            .expect("composition must succeed");
        // No task bound, so even read-only readiness cannot project past
        // NOT_ONBOARDED: task selection is the readiness floor.
        assert_eq!(capped.current_assessment, CurrentAssessment::NotOnboarded);
    }

    #[test]
    fn unbound_or_defective_selection_never_reports_ready() {
        let forged = fixture_context(ReadinessDisposition::ReadyMaterial);
        let no_tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Session,
            candidates: Vec::new(),
            authoritative_selection: None,
        };
        let none = get_understanding_bootstrap(&forged, &no_tasks, CurrentAssessment::Ready)
            .expect("composition must succeed");
        assert_eq!(
            none.task_selection.disposition,
            TaskSelectionDisposition::None
        );
        assert_eq!(none.current_assessment, CurrentAssessment::NotOnboarded);

        let ambiguous_tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Project,
            candidates: (0..2).map(eligible_task).collect(),
            authoritative_selection: None,
        };
        let ambiguous =
            get_understanding_bootstrap(&forged, &ambiguous_tasks, CurrentAssessment::Ready)
                .expect("composition must succeed");
        assert_eq!(
            ambiguous.task_selection.disposition,
            TaskSelectionDisposition::Ambiguous
        );
        assert_eq!(
            ambiguous.current_assessment,
            CurrentAssessment::NotOnboarded
        );

        let zero_revision = BootstrapTaskInputs {
            scope_level: ScopeLevel::Task,
            candidates: vec![TaskCandidate {
                handle: "task-zero".to_owned(),
                task_revision: Some(0),
                acceptance_digest: Some("d".repeat(64)),
                historical: false,
                prior_evaluation_candidate_only: false,
                independent_binding_supplied: true,
            }],
            authoritative_selection: None,
        };
        let error = get_understanding_bootstrap(&forged, &zero_revision, CurrentAssessment::Ready)
            .expect_err("zero task revision must fail closed");
        assert_eq!(error.code, "SELECTION_REVISION_MISSING");

        let missing_acceptance = BootstrapTaskInputs {
            scope_level: ScopeLevel::Task,
            candidates: vec![TaskCandidate {
                handle: "task-noaccept".to_owned(),
                task_revision: Some(3),
                acceptance_digest: None,
                historical: false,
                prior_evaluation_candidate_only: false,
                independent_binding_supplied: true,
            }],
            authoritative_selection: None,
        };
        let error =
            get_understanding_bootstrap(&forged, &missing_acceptance, CurrentAssessment::Ready)
                .expect_err("missing acceptance digest must fail closed");
        assert_eq!(error.code, "SELECTION_ACCEPTANCE_MISSING");

        let forged_authoritative = BootstrapTaskInputs {
            scope_level: ScopeLevel::Project,
            candidates: vec![TaskCandidate {
                handle: "task-forged".to_owned(),
                task_revision: Some(0),
                acceptance_digest: None,
                historical: false,
                prior_evaluation_candidate_only: false,
                independent_binding_supplied: true,
            }],
            authoritative_selection: Some(AuthoritativeSelection {
                selected_handle: "task-forged".to_owned(),
                reason: "host claim".to_owned(),
                source: "host-input".to_owned(),
            }),
        };
        get_understanding_bootstrap(&forged, &forged_authoritative, CurrentAssessment::Ready)
            .expect_err("authoritative pick without revision and acceptance must fail closed");

        // A genuine bound task keeps its exact owner-supplied binding and READY.
        let genuine = BootstrapTaskInputs {
            scope_level: ScopeLevel::Project,
            candidates: vec![eligible_task(4)],
            authoritative_selection: Some(AuthoritativeSelection {
                selected_handle: "task-4".to_owned(),
                reason: "governor work assignment".to_owned(),
                source: "governor-ledger-4".to_owned(),
            }),
        };
        let bound = get_understanding_bootstrap(&forged, &genuine, CurrentAssessment::Ready)
            .expect("genuine binding must compose");
        assert_eq!(
            bound.task_selection.disposition,
            TaskSelectionDisposition::Bound
        );
        assert_eq!(bound.current_assessment, CurrentAssessment::Ready);
    }

    #[test]
    fn missing_governance_evidence_fails_closed() {
        let mut context = fixture_context(ReadinessDisposition::ReadyMaterial);
        context.governance.limiting_integration_evidence.clear();
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Session,
            candidates: Vec::new(),
            authoritative_selection: None,
        };
        let error = get_understanding_bootstrap(&context, &tasks, CurrentAssessment::Ready)
            .expect_err("bootstrap without limiting integration evidence must fail");
        assert_eq!(error.code, "GOVERNANCE_EVIDENCE_MISSING");
    }

    #[allow(clippy::too_many_arguments)]
    fn from_receipt_with(
        receipt_ref: &str,
        disposition: ReadinessDisposition,
    ) -> Result<BootstrapContext, BootstrapError> {
        BootstrapContext::from_receipt(
            receipt_ref.to_owned(),
            "principal-1".to_owned(),
            "SPINE_FUNCTIONAL".to_owned(),
            "workscope-1".to_owned(),
            disposition,
            Some("task_ref".to_owned()),
            10,
            1,
            vec!["source-gen-9".to_owned()],
            vec!["orientation:project".to_owned()],
            vec!["attention:conflict-1".to_owned()],
            vec!["problem:stale-proof".to_owned()],
            "role-lease-1".to_owned(),
            "fence-epoch-3-gen-7".to_owned(),
            fixture_governance(),
            "route-profile-constrained-1".to_owned(),
            vec![
                "floor:goal-scope-authority".to_owned(),
                "floor:task-selection-proof".to_owned(),
            ],
            "instance:a".to_owned(),
            "projection-source-1".to_owned(),
            9,
            4,
            3,
            1,
            Vec::new(),
            "bind task before material effects".to_owned(),
        )
    }

    #[test]
    fn from_receipt_carries_canonical_ref_and_caps_assessment() {
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Session,
            candidates: Vec::new(),
            authoritative_selection: None,
        };
        let ready = from_receipt_with("readiness-receipt-1", ReadinessDisposition::ReadyMaterial)
            .expect("ref-bound construction must succeed");
        assert_eq!(ready.onboarding_readiness_ref, "readiness-receipt-1");
        assert_eq!(
            ready.onboarding_disposition,
            ReadinessDisposition::ReadyMaterial
        );
        let bootstrap = get_understanding_bootstrap(&ready, &tasks, CurrentAssessment::Ready)
            .expect("composition must succeed");
        assert_eq!(bootstrap.onboarding_readiness_ref, "readiness-receipt-1");
        // Referenced READY_MATERIAL with no bound task is not task authority:
        // the projection reports the disposition but withholds READY.
        assert_eq!(
            bootstrap.onboarding_readiness_disposition,
            ReadinessDisposition::ReadyMaterial
        );
        assert_eq!(
            bootstrap.current_assessment,
            CurrentAssessment::NotOnboarded
        );

        let gated = from_receipt_with("readiness-receipt-2", ReadinessDisposition::NeedsTask)
            .expect("ref-bound construction must succeed");
        let capped = get_understanding_bootstrap(&gated, &tasks, CurrentAssessment::Ready)
            .expect("composition must succeed");
        assert_eq!(capped.current_assessment, CurrentAssessment::NotOnboarded);
    }

    #[test]
    fn from_receipt_blank_ref_fails_closed() {
        let error = from_receipt_with("", ReadinessDisposition::ReadyMaterial)
            .expect_err("blank receipt ref must fail closed");
        assert_eq!(error.code, "READINESS_REF_MISSING");
    }
}
