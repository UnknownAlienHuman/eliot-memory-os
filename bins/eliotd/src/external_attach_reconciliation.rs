//! External-agent attach reconciliation and Material-continuation gate
//! (issue #1782, I11.11 lines 25 and 27-42).
//!
//! I11.11 line 25, verbatim: "`Start work` first exposes the
//! `WorkScopeCandidateSet`, `ScopeBindingGuard` and
//! `OnboardingReadinessReceipt`; it cannot hide an ambiguous clone, missing
//! task or conflicting governing document behind an automatic agent launch."
//! I11.11 line 27, verbatim: "Attaching an already-running external agent does
//! not retroactively make its earlier activity observed or authorized. ELIOT
//! creates an `ExternalAttachReconciliationReceipt`". I11.11 line 42,
//! verbatim: "Pre-attach changes are candidate artifacts/observations and
//! cannot become proof, task completion or agent-attributed experience until
//! reconciled. If exact process/session or workspace ownership cannot be
//! established, the route attaches read-only or as a new bounded attempt with
//! an explicit blind interval. Any request to continue Material work before
//! that disposition returns `EXTERNAL_ATTACH_RECONCILIATION_REQUIRED`."
//!
//! I14.24 line 23 names the same containment leg and its continuation:
//! "treat pre-attach changes/effects as unattributed candidates; deny
//! proof/finish and further Material work until reconciliation" / "read-only
//! inspection and unrelated tasks continue" / "create
//! `ExternalAttachReconciliationReceipt`, verify workspace/effects and start a
//! new bounded attempt or explicit Human disposition".
//!
//! # What this module is, and what it deliberately is not
//!
//! It is a pure receipt compiler, disposition deriver and refusal gate. It
//! owns no journal, store, task lifecycle, credential, process or scheduling
//! state, exactly like [`task_binding_admission`](super::task_binding_admission);
//! it never launches, attaches to, inspects or kills a process, and it reads no
//! filesystem, process table, transcript, workspace or credential.
//!
//! Every value in the receipt is supplied by the caller from something the
//! caller actually observed. Nothing here is derived from recency, proximity,
//! process name, PID, current directory, executable discovery order, or
//! recency of a task: an ambiguous candidate set, an absent/stale task and a
//! conflicted governing document are reported, never resolved. I11.11 line 25's
//! "It never assumes the newest executable is healthy merely because it was
//! discovered" is not re-implemented here — that leg already belongs to
//! `eliotd::capability_admission::admit_production_route`, and duplicating it
//! would create a second route-health authority.
//!
//! The receipt reuses the existing owner types instead of restating them:
//! [`WorkScopeCandidateSet`] and [`OnboardingReadinessReceipt`] for the
//! observed candidates, [`ScopeBinding`] plus [`ScopeBindingGuardReceipt`] for
//! the workspace-ownership leg, and [`RequestedEffect`] for the Material-work
//! class. The reason-code identity is the existing
//! [`BridgeError::ExternalAttachReconciliationRequired`]; this module invents
//! no new code string and no new wire identity.
//!
//! # Live reachability
//!
//! [`admit_material_continuation`] is called from two in-crate sites:
//! `DaemonComposition::admit_material_continuation_after_attach`, whose caller
//! is the live `eliot.finish` claim path (`finish_attempt::serve_finish_claim`,
//! driven by the daemon runtime), and
//! `DaemonComposition::commit_canonical_and_refresh`. The latter has zero
//! production call sites on this tree, which is recorded here rather than
//! hidden: it is the composition-root Material canonical-write intake, and the
//! typed readiness leg it already runs is unreachable for the same measured
//! reason (see `task_binding_admission`'s "Measured reachability" section).
//!
//! [`reconcile_external_attach`] is called from one in-crate production
//! ingress: [`serve_bridge_external_attach`], which
//! `DaemonComposition::serve_bridge_external_attach` drives with the live
//! Bridge binding plus the live Governor fence and Kernel-issued owner session.
//! That composition ingress is the daemon side of the
//! `eliot-agent-bridge-core` external-attach transport
//! (`AttachRequest::external` plus `AttachView::reconciliation_required`):
//! it takes the exact [`AttachBinding`](eliot_agent_bridge_core::AttachBinding)
//! the trusted host activation boundary sealed, checks it against the live
//! owners, compiles the receipt through this compiler, and retains the
//! resulting versioned record is committed through the authenticated Kernel
//! owner and independently read back by exact claim key and current owner
//! session before reporting any gate-clearing view. Replay and the
//! Material-continuation recheck consume those durable readbacks, so a lost
//! response replays the same disposition and a stale or substituted binding
//! fails closed. This module remains a pure DTO/compiler; Governor/Kernel/ORS
//! own the durable row and its store-issued integrity validation.
//!
//! [`admit_automatic_agent_launch`] has no production call site yet: no
//! `Start work` surface exists in this crate, and no second launcher is added
//! to manufacture one.

#![forbid(unsafe_code)]

use eliot_agent_bridge_core::{AttachBinding, AttachKind, AttachRequest, BridgeError};
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_governor::MAX_EXTERNAL_ATTACH_RECEIPT_PAYLOAD_BYTES;
use eliot_process::{FencingToken, Generation};
use eliot_workscope::{
    CandidateDisposition, OnboardingReadinessReceipt, ReadinessLifecycle, RequestedEffect,
    ScopeBinding, ScopeBindingDisposition, ScopeBindingGuardReceipt, ScopeResolutionState,
    TaskBindingState, WorkScopeCandidateSet,
};
use serde::{Deserialize, Serialize};

/// Stable I7.20 reason code for a Material continuation refused before the
/// external-attach disposition exists (I11.11 line 42).
///
/// The refusal itself is [`BridgeError::ExternalAttachReconciliationRequired`],
/// whose `Display` is exactly this string; this constant exists so a surface
/// that projects the code into an agent-facing `reason_code` pair reuses the
/// documented identity instead of retyping it.
pub const EXTERNAL_ATTACH_RECONCILIATION_REQUIRED: &str = "EXTERNAL_ATTACH_RECONCILIATION_REQUIRED";

/// Rejects one free-form reference: non-blank and free of control characters.
fn reference(field: &'static str, value: &str) -> Result<String, Box<BridgeError>> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(Box::new(BridgeError::InvalidContract {
            field,
            reason: "reference must be non-blank and free of control characters",
        }));
    }
    Ok(value.to_owned())
}

/// Rejects one duplicate-bearing reference collection.
fn references(field: &'static str, values: &[String]) -> Result<(), Box<BridgeError>> {
    for value in values {
        reference(field, value)?;
    }
    let mut unique = values.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != values.len() {
        return Err(Box::new(BridgeError::InvalidContract {
            field,
            reason: "reference collection must not contain duplicates",
        }));
    }
    Ok(())
}

/// The explicit pre-attach interval ELIOT did not observe (I11.11 line 42).
///
/// The interval is computed, never supplied: it is the attach time minus the
/// last observation boundary the caller actually held. An attach time at or
/// before that boundary cannot describe an unobserved interval and fails
/// closed rather than clamping to a fabricated zero.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreAttachBlindInterval {
    /// Last observation boundary ELIOT itself held, in unix milliseconds.
    pub last_observation_boundary_unix_ms: u64,
    /// Attach time, in unix milliseconds, at which the external agent was
    /// reconciled.
    pub attach_unix_ms: u64,
}

impl PreAttachBlindInterval {
    /// Computes the blind interval from two observed timestamps.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidContract`] when the attach time is not
    /// after the last observation boundary, which would describe no blind
    /// interval at all.
    pub fn new(
        last_observation_boundary_unix_ms: u64,
        attach_unix_ms: u64,
    ) -> Result<Self, Box<BridgeError>> {
        if attach_unix_ms <= last_observation_boundary_unix_ms {
            return Err(Box::new(BridgeError::InvalidContract {
                field: "attach_time_and_pre_attach_blind_interval",
                reason: "attach time must be after the last observation boundary",
            }));
        }
        Ok(Self {
            last_observation_boundary_unix_ms,
            attach_unix_ms,
        })
    }

    /// The unobserved interval length in unix milliseconds.
    #[must_use]
    pub const fn duration_unix_ms(&self) -> u64 {
        self.attach_unix_ms - self.last_observation_boundary_unix_ms
    }
}

/// The external process/session/route and the identity actually established
/// for it (I11.11 receipt field
/// `external_process_session_route_and_actual_identity`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAgentIdentity {
    /// Observed external process reference the attach named.
    pub external_process_ref: String,
    /// Observed external session reference the attach named.
    pub external_session_ref: String,
    /// Observed route reference the external process runs on.
    pub route_ref: String,
    /// The identity that was actually established for that process/session, or
    /// `None` when it could not be established. It is never inferred from the
    /// process name, PID, executable path or current directory.
    pub actual_identity_ref: Option<String>,
}

impl ExternalAgentIdentity {
    fn validate(&self) -> Result<(), Box<BridgeError>> {
        reference(
            "external_process_session_route_and_actual_identity.external_process_ref",
            &self.external_process_ref,
        )?;
        reference(
            "external_process_session_route_and_actual_identity.external_session_ref",
            &self.external_session_ref,
        )?;
        reference(
            "external_process_session_route_and_actual_identity.route_ref",
            &self.route_ref,
        )?;
        if let Some(actual) = &self.actual_identity_ref {
            reference(
                "external_process_session_route_and_actual_identity.actual_identity_ref",
                actual,
            )?;
        }
        Ok(())
    }

    /// Whether exact process/session identity was established for this attach.
    #[must_use]
    pub fn process_session_established(&self) -> bool {
        self.actual_identity_ref.is_some()
    }
}

/// The observed workspace-instance/scope and task candidates, preserved
/// verbatim (I11.11 receipt field
/// `observed_workspace_instance_scope_and_task_candidates`).
///
/// The candidate set is the owner-issued
/// [`WorkScopeCandidateSet`]; it is carried, never resolved. Task candidates
/// are the handles the caller observed, and an ambiguous handle set is kept
/// as-is: this module has no authority to prefer one candidate over another.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedAttachCandidates {
    /// Owner-issued observed scope candidate set, carried unchanged.
    pub candidate_set: WorkScopeCandidateSet,
    /// Task candidate handles the caller observed, in their observed order.
    pub task_candidate_refs: Vec<String>,
}

impl ObservedAttachCandidates {
    fn validate(&self) -> Result<(), Box<BridgeError>> {
        reference(
            "observed_workspace_instance_scope_and_task_candidates.candidate_set.observed_root_ref",
            &self.candidate_set.observed_root_ref,
        )?;
        references(
            "observed_workspace_instance_scope_and_task_candidates.task_candidate_refs",
            &self.task_candidate_refs,
        )
    }
}

/// The last known base and the current workspace artifact delta (I11.11
/// receipt field
/// `last_known_base_and_current_workspace_artifact_delta`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceArtifactDelta {
    /// The last known base the caller held before the attach.
    pub last_known_base_ref: String,
    /// The current workspace the caller observed at the attach.
    pub current_workspace_ref: String,
    /// The artifact references the caller observed as the delta between them.
    pub delta_artifact_refs: Vec<String>,
}

impl WorkspaceArtifactDelta {
    fn validate(&self) -> Result<(), Box<BridgeError>> {
        reference(
            "last_known_base_and_current_workspace_artifact_delta.last_known_base_ref",
            &self.last_known_base_ref,
        )?;
        reference(
            "last_known_base_and_current_workspace_artifact_delta.current_workspace_ref",
            &self.current_workspace_ref,
        )?;
        references(
            "last_known_base_and_current_workspace_artifact_delta.delta_artifact_refs",
            &self.delta_artifact_refs,
        )
    }
}

/// Standing of everything imported from before the attach (I11.11 line 42).
///
/// `Candidate` is the only standing that exists: pre-attach changes are
/// candidate artifacts/observations. The three predicates below are the exact
/// negative claims the fragment makes, so no caller has to restate them.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum PreAttachStanding {
    /// Candidate artifact/observation: not proof, not task completion, not
    /// agent-attributed experience.
    Candidate,
}

impl PreAttachStanding {
    /// Pre-attach material is never proof.
    #[must_use]
    pub const fn is_proof(self) -> bool {
        false
    }

    /// Pre-attach material is never task completion.
    #[must_use]
    pub const fn is_task_completion(self) -> bool {
        false
    }

    /// Pre-attach material is never agent-attributed experience.
    #[must_use]
    pub const fn is_agent_attributed_experience(self) -> bool {
        false
    }
}

/// Transcript, event and tool coverage imported from the external agent
/// (I11.11 receipt field `imported_transcript_event_and_tool_coverage`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedPreAttachCoverage {
    /// Imported transcript and event references, as observed.
    pub transcript_event_refs: Vec<String>,
    /// Imported tool-call coverage references, as observed.
    pub tool_coverage_refs: Vec<String>,
}

impl ImportedPreAttachCoverage {
    fn validate(&self) -> Result<(), Box<BridgeError>> {
        references(
            "imported_transcript_event_and_tool_coverage.transcript_event_refs",
            &self.transcript_event_refs,
        )?;
        references(
            "imported_transcript_event_and_tool_coverage.tool_coverage_refs",
            &self.tool_coverage_refs,
        )
    }

    /// The standing of every imported reference in this coverage.
    ///
    /// Always [`PreAttachStanding::Candidate`]: importing pre-attach coverage
    /// never retroactively observes or authorizes it.
    #[must_use]
    pub const fn standing(&self) -> PreAttachStanding {
        PreAttachStanding::Candidate
    }
}

/// External effects that are known-but-unattributed, or that cannot be
/// enumerated at all (I11.11 receipt field
/// `known_unknown_or_unattributed_external_effects`).
///
/// `unknown_effects_present` is an observation, not a default: `false` means the
/// caller observed the effect set closed, `true` means the caller could not
/// enumerate it. An unenumerable effect set is never presented as empty.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEffectDisposition {
    /// Effects observed to exist but not attributable to this agent.
    pub known_unattributed_effect_refs: Vec<String>,
    /// Whether external effects exist that the caller could not enumerate.
    pub unknown_effects_present: bool,
}

impl ExternalEffectDisposition {
    fn validate(&self) -> Result<(), Box<BridgeError>> {
        references(
            "known_unknown_or_unattributed_external_effects.known_unattributed_effect_refs",
            &self.known_unattributed_effect_refs,
        )
    }
}

/// What happens to credentials the external process may hold.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum CredentialDisposition {
    /// The caller observed no credential in the attach.
    NoneObserved,
    /// Credentials were observed and stay with the external process; ELIOT
    /// neither adopted nor revoked them.
    RetainedByExternalProcess,
    /// Credentials were observed and revoked as part of the attach.
    RevokedByAttach,
}

/// Scope authority, the privacy boundary and the credential disposition of
/// the attach (I11.11 receipt field
/// `scope_authority_privacy_and_credential_disposition`).
///
/// Workspace ownership is read from the owner-issued
/// [`ScopeBindingGuardReceipt`]: only a `Matched` disposition establishes it.
/// This module does not run the guard and does not re-derive the receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeAuthorityDisposition {
    /// The observed scope binding the attach was admitted against.
    pub scope_binding: ScopeBinding,
    /// The owner-issued guard receipt for that binding.
    pub guard_receipt: ScopeBindingGuardReceipt,
    /// Disposition of the external process's credentials.
    pub credential_disposition: CredentialDisposition,
}

impl ScopeAuthorityDisposition {
    fn validate(&self) -> Result<(), Box<BridgeError>> {
        self.scope_binding
            .validate()
            .map_err(|_error| BridgeError::InvalidContract {
                field: "scope_authority_privacy_and_credential_disposition.scope_binding",
                reason: "observed scope binding did not validate against its own contract",
            })?;
        reference(
            "scope_authority_privacy_and_credential_disposition.guard_receipt.observed_scope_ref",
            &self.guard_receipt.observed_scope_ref,
        )?;
        Ok(())
    }

    /// Whether workspace ownership was established for the attached work.
    #[must_use]
    pub fn workspace_ownership_established(&self) -> bool {
        self.guard_receipt.disposition == ScopeBindingDisposition::Matched
    }
}

/// Verification, cleanup or Human decision the attach still requires (I11.11
/// receipt field
/// `required_verification_cleanup_or_human_decision`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum PendingAttachAction {
    /// Nothing beyond the continuation disposition itself is outstanding.
    NoneRequired,
    /// Verification the caller must still run.
    Verification { verification_refs: Vec<String> },
    /// Cleanup the caller must still perform.
    Cleanup { cleanup_refs: Vec<String> },
    /// An explicit Human decision the attach is waiting on.
    HumanDecision { decision_ref: String },
}

impl PendingAttachAction {
    fn validate(&self) -> Result<(), Box<BridgeError>> {
        match self {
            Self::NoneRequired => Ok(()),
            Self::Verification { verification_refs } => references(
                "required_verification_cleanup_or_human_decision.verification_refs",
                verification_refs,
            ),
            Self::Cleanup { cleanup_refs } => references(
                "required_verification_cleanup_or_human_decision.cleanup_refs",
                cleanup_refs,
            ),
            Self::HumanDecision { decision_ref } => reference(
                "required_verification_cleanup_or_human_decision.decision_ref",
                decision_ref,
            )
            .map(|_| ()),
        }
    }
}

/// How the attached route continues (I11.11 line 42).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ContinuationKind {
    /// Ownership was established: the route continues and its activity is
    /// attributed normally.
    AttributedContinuation,
    /// Ownership was not established: the route attaches read-only, with the
    /// explicit blind interval.
    ReadOnlyAttach,
    /// Ownership was not established: the route continues as a new bounded
    /// attempt with a new attempt identity and the explicit blind interval.
    NewBoundedAttempt,
}

/// The continuation kind and the new attempt identity (I11.11 receipt field
/// `continuation_kind_and_new_attempt_identity`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationDisposition {
    /// How the route continues.
    pub kind: ContinuationKind,
    /// The new attempt identity, present exactly for
    /// [`ContinuationKind::NewBoundedAttempt`].
    pub new_attempt_ref: Option<String>,
}

impl ContinuationDisposition {
    fn validate(&self) -> Result<(), Box<BridgeError>> {
        let new_attempt_ref = match &self.new_attempt_ref {
            Some(value) => {
                reference(
                    "continuation_kind_and_new_attempt_identity.new_attempt_ref",
                    value,
                )?;
                Some(value.clone())
            }
            None => None,
        };
        let consistent = match self.kind {
            ContinuationKind::AttributedContinuation | ContinuationKind::ReadOnlyAttach => {
                new_attempt_ref.is_none()
            }
            ContinuationKind::NewBoundedAttempt => new_attempt_ref.is_some(),
        };
        if !consistent {
            return Err(Box::new(BridgeError::InvalidContract {
                field: "continuation_kind_and_new_attempt_identity",
                reason: "a new attempt identity is present exactly for a new bounded attempt",
            }));
        }
        Ok(())
    }
}

/// Governor-owned reconciliation receipt for one attach of an already-running
/// external agent (I11.11 lines 27-40).
///
/// The nine fields are exactly the nine documented receipt fields, in the
/// documented order and under the documented names. The only producer is
/// [`reconcile_external_attach`], which validates every supplied observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAttachReconciliationReceipt {
    /// External process, session, route and the identity actually established.
    pub external_process_session_route_and_actual_identity: ExternalAgentIdentity,
    /// Attach time and the explicit pre-attach blind interval.
    pub attach_time_and_pre_attach_blind_interval: PreAttachBlindInterval,
    /// Observed workspace-instance/scope and task candidates.
    pub observed_workspace_instance_scope_and_task_candidates: ObservedAttachCandidates,
    /// Last known base and current workspace artifact delta.
    pub last_known_base_and_current_workspace_artifact_delta: WorkspaceArtifactDelta,
    /// Imported transcript, event and tool coverage.
    pub imported_transcript_event_and_tool_coverage: ImportedPreAttachCoverage,
    /// Known, unknown or unattributed external effects.
    pub known_unknown_or_unattributed_external_effects: ExternalEffectDisposition,
    /// Scope authority, privacy boundary and credential disposition.
    pub scope_authority_privacy_and_credential_disposition: ScopeAuthorityDisposition,
    /// Required verification, cleanup or Human decision.
    pub required_verification_cleanup_or_human_decision: PendingAttachAction,
    /// Continuation kind and new attempt identity.
    pub continuation_kind_and_new_attempt_identity: ContinuationDisposition,
}

impl ExternalAttachReconciliationReceipt {
    /// The explicit pre-attach blind interval, in unix milliseconds.
    #[must_use]
    pub fn pre_attach_blind_interval_ms(&self) -> u64 {
        self.attach_time_and_pre_attach_blind_interval
            .duration_unix_ms()
    }

    /// How the attached route continues.
    #[must_use]
    pub fn continuation_kind(&self) -> ContinuationKind {
        self.continuation_kind_and_new_attempt_identity.kind
    }

    /// Whether this receipt admits continuing Material work.
    ///
    /// Only an attributed continuation does: a read-only attach and a new
    /// bounded attempt both carry the explicit blind interval and have not
    /// reconciled their pre-attach material.
    #[must_use]
    pub fn admits_material_continuation(&self) -> bool {
        matches!(
            self.continuation_kind_and_new_attempt_identity.kind,
            ContinuationKind::AttributedContinuation
        )
    }

    /// The standing of every pre-attach artifact this receipt carries.
    #[must_use]
    pub fn pre_attach_standing(&self) -> PreAttachStanding {
        self.imported_transcript_event_and_tool_coverage.standing()
    }

    /// Whether exact process/session and workspace ownership were both
    /// established for this attach.
    #[must_use]
    pub fn ownership_established(&self) -> bool {
        self.external_process_session_route_and_actual_identity
            .process_session_established()
            && self
                .scope_authority_privacy_and_credential_disposition
                .workspace_ownership_established()
    }

    /// Re-checks the whole receipt without trusting the producer.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidContract`] for the first malformed field.
    /// The continuation/attempt-identity pairing and the blind interval are
    /// checked here, so a decoded or reconstructed receipt cannot claim an
    /// attributed continuation without an established owner.
    pub fn validate(&self) -> Result<(), Box<BridgeError>> {
        self.external_process_session_route_and_actual_identity
            .validate()?;
        if self
            .attach_time_and_pre_attach_blind_interval
            .attach_unix_ms
            <= self
                .attach_time_and_pre_attach_blind_interval
                .last_observation_boundary_unix_ms
        {
            return Err(Box::new(BridgeError::InvalidContract {
                field: "attach_time_and_pre_attach_blind_interval",
                reason: "attach time must be after the last observation boundary",
            }));
        }
        self.observed_workspace_instance_scope_and_task_candidates
            .validate()?;
        self.last_known_base_and_current_workspace_artifact_delta
            .validate()?;
        self.imported_transcript_event_and_tool_coverage
            .validate()?;
        self.known_unknown_or_unattributed_external_effects
            .validate()?;
        self.scope_authority_privacy_and_credential_disposition
            .validate()?;
        self.required_verification_cleanup_or_human_decision
            .validate()?;
        self.continuation_kind_and_new_attempt_identity.validate()?;
        // I11.11 line 42, enforced rather than documented: pre-attach changes
        // are candidate artifacts/observations and cannot become proof, task
        // completion or agent-attributed experience. A standing that ever
        // claimed otherwise fails the whole receipt closed here, so the
        // negative claim is checked at every gate that validates a receipt.
        let standing = self.pre_attach_standing();
        if standing.is_proof()
            || standing.is_task_completion()
            || standing.is_agent_attributed_experience()
        {
            return Err(Box::new(BridgeError::InvalidContract {
                field: "imported_transcript_event_and_tool_coverage",
                reason: "pre-attach coverage is candidate material and can never be proof, task completion, or agent-attributed experience",
            }));
        }
        if self.admits_material_continuation() && !self.ownership_established() {
            return Err(Box::new(BridgeError::InvalidContract {
                field: "continuation_kind_and_new_attempt_identity",
                reason: "an attributed continuation requires established process/session and workspace ownership",
            }));
        }
        Ok(())
    }
}

/// The continuation choice available when ownership was not established.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum UnownedContinuation {
    /// Attach read-only.
    ReadOnly,
    /// Continue as a new bounded attempt under a new attempt identity.
    NewBoundedAttempt,
}

/// Every observed input of one external attach.
///
/// The caller supplies these from what it actually observed. This module adds
/// no value of its own beyond the computed blind interval and the derived
/// continuation disposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAttachObservation {
    /// External process/session/route and the identity actually established.
    pub identity: ExternalAgentIdentity,
    /// Last observation boundary the caller held before the attach.
    pub last_observation_boundary_unix_ms: u64,
    /// Attach time, in unix milliseconds.
    pub attach_unix_ms: u64,
    /// Observed workspace-instance/scope and task candidates.
    pub observed_candidates: ObservedAttachCandidates,
    /// Last known base and current workspace artifact delta.
    pub artifact_delta: WorkspaceArtifactDelta,
    /// Imported transcript, event and tool coverage.
    pub imported_coverage: ImportedPreAttachCoverage,
    /// Known, unknown or unattributed external effects.
    pub external_effects: ExternalEffectDisposition,
    /// Scope authority, privacy boundary and credential disposition.
    pub authority: ScopeAuthorityDisposition,
    /// Required verification, cleanup or Human decision.
    pub pending_action: PendingAttachAction,
    /// The continuation choice, required exactly when ownership was not
    /// established and forbidden when it was.
    pub unowned_continuation: Option<UnownedContinuation>,
    /// The new attempt identity, required exactly for
    /// [`UnownedContinuation::NewBoundedAttempt`].
    pub new_attempt_ref: Option<String>,
}

/// Compiles the reconciliation receipt and disposition for one attach of an
/// already-running external agent (I11.11 lines 27-42).
///
/// The blind interval is computed from the two observed timestamps, and the
/// continuation kind is derived, not supplied:
///
/// - exact process/session identity **and** a `Matched`
///   [`ScopeBindingGuardReceipt`] establish ownership, so the route continues
///   under its own identity as an attributed continuation. Presenting a
///   read-only or new-bounded-attempt choice in that case fails closed: an
///   established owner is not re-homed by its own attach.
/// - otherwise the caller must choose [`UnownedContinuation::ReadOnly`] or
///   [`UnownedContinuation::NewBoundedAttempt`], and a new bounded attempt must
///   carry a new attempt identity. Omitting the choice fails closed, because
///   the fragment's alternative is exactly these two.
///
/// # Errors
///
/// Returns [`BridgeError::InvalidContract`] for a malformed observation, an
/// attach time that is not after the last observation boundary, an absent
/// continuation choice without established ownership, a choice presented with
/// established ownership, or a new attempt identity that is absent or
/// unrequested.
pub fn reconcile_external_attach(
    observation: &ExternalAttachObservation,
) -> Result<ExternalAttachReconciliationReceipt, Box<BridgeError>> {
    let blind_interval = PreAttachBlindInterval::new(
        observation.last_observation_boundary_unix_ms,
        observation.attach_unix_ms,
    )?;
    observation.identity.validate()?;
    observation.observed_candidates.validate()?;
    observation.artifact_delta.validate()?;
    observation.imported_coverage.validate()?;
    observation.external_effects.validate()?;
    observation.authority.validate()?;
    observation.pending_action.validate()?;

    let ownership_established = observation.identity.process_session_established()
        && observation.authority.workspace_ownership_established();
    let continuation_kind_and_new_attempt_identity = if ownership_established {
        if observation.unowned_continuation.is_some() {
            return Err(Box::new(BridgeError::InvalidContract {
                field: "observation.unowned_continuation",
                reason: "established ownership continues under the attached identity; no read-only or new bounded attempt applies",
            }));
        }
        if observation.new_attempt_ref.is_some() {
            return Err(Box::new(BridgeError::InvalidContract {
                field: "observation.new_attempt_ref",
                reason: "an attributed continuation keeps the attached attempt identity",
            }));
        }
        ContinuationDisposition {
            kind: ContinuationKind::AttributedContinuation,
            new_attempt_ref: None,
        }
    } else {
        let Some(choice) = observation.unowned_continuation else {
            return Err(Box::new(BridgeError::InvalidContract {
                field: "observation.unowned_continuation",
                reason: "without established process/session or workspace ownership the attach must be read-only or a new bounded attempt",
            }));
        };
        match choice {
            UnownedContinuation::ReadOnly => {
                if observation.new_attempt_ref.is_some() {
                    return Err(Box::new(BridgeError::InvalidContract {
                        field: "observation.new_attempt_ref",
                        reason: "a read-only attach mints no new attempt identity",
                    }));
                }
                ContinuationDisposition {
                    kind: ContinuationKind::ReadOnlyAttach,
                    new_attempt_ref: None,
                }
            }
            UnownedContinuation::NewBoundedAttempt => {
                let Some(new_attempt_ref) = observation.new_attempt_ref.as_deref() else {
                    return Err(Box::new(BridgeError::InvalidContract {
                        field: "observation.new_attempt_ref",
                        reason: "a new bounded attempt requires a new attempt identity",
                    }));
                };
                ContinuationDisposition {
                    kind: ContinuationKind::NewBoundedAttempt,
                    new_attempt_ref: Some(reference(
                        "observation.new_attempt_ref",
                        new_attempt_ref,
                    )?),
                }
            }
        }
    };

    let receipt = ExternalAttachReconciliationReceipt {
        external_process_session_route_and_actual_identity: observation.identity.clone(),
        attach_time_and_pre_attach_blind_interval: blind_interval,
        observed_workspace_instance_scope_and_task_candidates: observation
            .observed_candidates
            .clone(),
        last_known_base_and_current_workspace_artifact_delta: observation.artifact_delta.clone(),
        imported_transcript_event_and_tool_coverage: observation.imported_coverage.clone(),
        known_unknown_or_unattributed_external_effects: observation.external_effects.clone(),
        scope_authority_privacy_and_credential_disposition: observation.authority.clone(),
        required_verification_cleanup_or_human_decision: observation.pending_action.clone(),
        continuation_kind_and_new_attempt_identity,
    };
    receipt.validate()?;
    Ok(receipt)
}

/// Refuses any request to continue Material work before the attach disposition
/// exists (I11.11 line 42, I14.24 line 23).
///
/// - A read-only-inspection or other non-Material effect is admitted
///   unconditionally, so read-only inspection and unrelated tasks continue.
/// - With no reconciled attach, the gate is inert: nothing was attached, so
///   there is nothing to reconcile.
/// - With a reconciled attach, only an attributed continuation is admitted. A
///   read-only attach and a new bounded attempt both refuse with
///   [`BridgeError::ExternalAttachReconciliationRequired`], whose stable code is
///   [`EXTERNAL_ATTACH_RECONCILIATION_REQUIRED`].
///
/// # Errors
///
/// Returns [`BridgeError::InvalidContract`] when the presented receipt does not
/// validate, and
/// [`BridgeError::ExternalAttachReconciliationRequired`] when a Material effect
/// is requested before an attributed continuation exists.
pub fn admit_material_continuation(
    effect: RequestedEffect,
    attach: Option<&ExternalAttachReconciliationReceipt>,
) -> Result<(), Box<BridgeError>> {
    if !effect.requires_material_readiness() {
        return Ok(());
    }
    let Some(attach) = attach else {
        return Ok(());
    };
    attach.validate()?;
    if attach.admits_material_continuation() {
        return Ok(());
    }
    Err(Box::new(BridgeError::ExternalAttachReconciliationRequired))
}

/// The exact Bridge request/session/task/fence binding one external attach
/// presented (issue #1782 audit repair).
///
/// Every field is copied from the [`AttachBinding`](eliot_agent_bridge_core::AttachBinding)
/// the trusted host activation boundary sealed plus the
/// [`AttachRequest`](eliot_agent_bridge_core::AttachRequest) that carried it:
/// nothing is inferred, and no receipt field is mapped onto a binding field
/// by format. The receipt and this claim are linked by joint retention in
/// [`ExternalAttachIngressRecord`], never by a fabricated field mapping.
/// Replay and the Material-continuation recheck compare a presenting claim
/// against the retained one field for field: a stale or substituted binding
/// fails closed with [`BridgeError::StaleAuthority`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAttachBridgeClaim {
    /// Demand the attach was presented under.
    pub demand_ref: String,
    /// Transport connection the attach was presented on.
    pub connection_ref: String,
    /// Authenticated principal the host boundary admitted.
    pub principal_ref: String,
    /// Authenticated session the host boundary admitted.
    pub session_ref: String,
    /// Activation generation the host boundary sealed.
    pub activation_generation: Generation,
    /// State fence the host boundary sealed.
    pub state_fence: FencingToken,
    /// Admitted task identity.
    pub task_ref: String,
    /// Admitted work-unit identity.
    pub work_unit_ref: String,
    /// Admitted work-scope identity.
    pub work_scope_ref: String,
    /// Admitted task revision.
    pub task_revision: String,
    /// Admitted plan identity.
    pub plan_ref: String,
    /// Admitted plan revision.
    pub plan_revision: String,
}

impl ExternalAttachBridgeClaim {
    fn validate(&self) -> Result<(), Box<BridgeError>> {
        for (field, value) in [
            ("external_attach_binding.demand_ref", self.demand_ref.as_str()),
            (
                "external_attach_binding.connection_ref",
                self.connection_ref.as_str(),
            ),
            (
                "external_attach_binding.principal_ref",
                self.principal_ref.as_str(),
            ),
            (
                "external_attach_binding.session_ref",
                self.session_ref.as_str(),
            ),
            ("external_attach_binding.task_ref", self.task_ref.as_str()),
            (
                "external_attach_binding.work_unit_ref",
                self.work_unit_ref.as_str(),
            ),
            (
                "external_attach_binding.work_scope_ref",
                self.work_scope_ref.as_str(),
            ),
            (
                "external_attach_binding.task_revision",
                self.task_revision.as_str(),
            ),
            ("external_attach_binding.plan_ref", self.plan_ref.as_str()),
            (
                "external_attach_binding.plan_revision",
                self.plan_revision.as_str(),
            ),
        ] {
            reference(field, value)?;
        }
        if self.activation_generation.get() == 0
            || self.state_fence.generation().get() == 0
            || self.state_fence.canonical_epoch_digest().is_none()
        {
            return Err(Box::new(BridgeError::InvalidContract {
                field: "external_attach_binding.generation_and_fence",
                reason: "activation generation and state-fence evidence must be valid",
            }));
        }
        reference(
            "external_attach_binding.state_fence_nonce",
            self.state_fence.nonce(),
        )?;
        Ok(())
    }
}

/// Maximum canonical payload accepted for one durable ExternalAttach record.
/// I7.2 bounds an EBP frame at four MiB. The payload is carried as UTF-8 JSON
/// inside a JSON string, which can at most double its canonical byte length;
/// one quarter of the frame limit therefore leaves the other half for string
/// escaping and the bounded identity/operation envelope.
pub(crate) const MAX_EXTERNAL_ATTACH_RECORD_BYTES: usize =
    MAX_EXTERNAL_ATTACH_RECEIPT_PAYLOAD_BYTES;

const EXTERNAL_ATTACH_RECORD_SCHEMA_VERSION: u16 = 1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExternalAttachRecordEnvelope {
    schema_version: u16,
    record: ExternalAttachIngressRecord,
}

/// Exact canonical owner payload prepared from a validated original record.
/// `canonical_json` and its digest are retained together across the owner
/// write/readback; a new serialization cannot replace the original bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExternalAttachOwnerPayload {
    pub claim_key: String,
    pub canonical_json: String,
    pub payload_sha256: String,
}

/// Validates the original record, seals its complete closed DTO graph as
/// versioned canonical JSON, and derives the stable owner key from the full
/// exact Bridge claim. The receipt itself has no embedded digest field; the
/// returned payload digest binds its complete original serialized bytes.
pub(crate) fn encode_external_attach_owner_payload(
    record: &ExternalAttachIngressRecord,
) -> Result<ExternalAttachOwnerPayload, Box<BridgeError>> {
    validate_external_attach_durable_record(record)?;
    let Some(claim) = record.claim.as_ref() else {
        return Err(Box::new(BridgeError::InvalidContract {
            field: "external_attach_record.claim",
            reason: "durable Bridge receipt requires its exact attach claim",
        }));
    };
    let claim_key = external_attach_claim_key(claim)?;
    let envelope = ExternalAttachRecordEnvelope {
        schema_version: EXTERNAL_ATTACH_RECORD_SCHEMA_VERSION,
        record: record.clone(),
    };
    let bytes = canonical_json_bytes(&envelope).map_err(|_| {
        Box::new(BridgeError::InvalidContract {
            field: "external_attach_record",
            reason: "receipt record could not be canonically encoded",
        })
    })?;
    if bytes.is_empty() || bytes.len() > MAX_EXTERNAL_ATTACH_RECORD_BYTES {
        return Err(Box::new(BridgeError::InvalidContract {
            field: "external_attach_record",
            reason: "canonical receipt record exceeds its durable payload bound",
        }));
    }
    let canonical_json = String::from_utf8(bytes.clone()).map_err(|_| {
        Box::new(BridgeError::InvalidContract {
            field: "external_attach_record",
            reason: "canonical receipt record is not UTF-8 JSON",
        })
    })?;
    Ok(ExternalAttachOwnerPayload {
        claim_key,
        payload_sha256: sha256_hex(&bytes),
        canonical_json,
    })
}

/// Computes the stable owner key from the complete validated Bridge claim.
pub(crate) fn external_attach_claim_key(
    claim: &ExternalAttachBridgeClaim,
) -> Result<String, Box<BridgeError>> {
    claim.validate()?;
    let claim_bytes = canonical_json_bytes(claim).map_err(|_| {
        Box::new(BridgeError::InvalidContract {
            field: "external_attach_record.claim",
            reason: "Bridge claim could not be canonically encoded",
        })
    })?;
    Ok(format!("external_attach:{}", sha256_hex(&claim_bytes)))
}

/// Decodes an owner readback only when its bytes and digest are the exact
/// canonical versioned representation, then revalidates the original receipt
/// and Bridge claim before returning it to the caller.
pub(crate) fn decode_external_attach_owner_payload(
    canonical_json: &str,
    expected_sha256: &str,
) -> Result<ExternalAttachIngressRecord, Box<BridgeError>> {
    let bytes = canonical_json.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_EXTERNAL_ATTACH_RECORD_BYTES
        || sha256_hex(bytes) != expected_sha256
    {
        return Err(Box::new(BridgeError::InvalidContract {
            field: "external_attach_record.payload_sha256",
            reason: "durable owner payload is outside bounds or its digest does not match",
        }));
    }
    let envelope: ExternalAttachRecordEnvelope = serde_json::from_slice(bytes).map_err(|_| {
        Box::new(BridgeError::InvalidContract {
            field: "external_attach_record",
            reason: "durable owner payload is not a valid versioned record",
        })
    })?;
    if envelope.schema_version != EXTERNAL_ATTACH_RECORD_SCHEMA_VERSION {
        return Err(Box::new(BridgeError::InvalidContract {
            field: "external_attach_record.schema_version",
            reason: "durable owner payload uses an unsupported schema version",
        }));
    }
    validate_external_attach_durable_record(&envelope.record)?;
    let canonical = canonical_json_bytes(&envelope).map_err(|_| {
        Box::new(BridgeError::InvalidContract {
            field: "external_attach_record",
            reason: "durable owner payload could not be canonically re-encoded",
        })
    })?;
    if canonical != bytes {
        return Err(Box::new(BridgeError::InvalidContract {
            field: "external_attach_record",
            reason: "durable owner payload is not in canonical form",
        }));
    }
    Ok(envelope.record)
}

fn validate_external_attach_record(
    record: &ExternalAttachIngressRecord,
) -> Result<(), Box<BridgeError>> {
    record.receipt.validate()?;
    record.admitted_fence.validate().map_err(|_| {
        Box::new(BridgeError::InvalidContract {
            field: "external_attach_record.admitted_fence",
            reason: "admitted State Fence is invalid",
        })
    })?;
    let Some(claim) = record.claim.as_ref() else {
        return Err(Box::new(BridgeError::InvalidContract {
            field: "external_attach_record.claim",
            reason: "durable Bridge receipt requires its exact attach claim",
        }));
    };
    claim.validate()?;
    if let Some(session) = record.owner_session_binding.as_deref() {
        reference("external_attach_record.owner_session_binding", session)?;
    }
    Ok(())
}

/// Durable records must retain the authenticated Kernel owner session that
/// indexes their post-restart readback. The in-memory/diagnostic DTO remains
/// optionally bound for legacy callers, but it cannot cross the durable
/// publication boundary without that owner-issued binding.
fn validate_external_attach_durable_record(
    record: &ExternalAttachIngressRecord,
) -> Result<(), Box<BridgeError>> {
    validate_external_attach_record(record)?;
    let Some(owner_session_binding) = record.owner_session_binding.as_deref() else {
        return Err(Box::new(BridgeError::InvalidContract {
            field: "external_attach_record.owner_session_binding",
            reason: "durable receipt requires the authenticated Kernel owner session",
        }));
    };
    reference(
        "external_attach_record.owner_session_binding",
        owner_session_binding,
    )?;
    Ok(())
}

/// Copies the exact binding content of one Bridge external-attach request.
///
/// The request must be an [`AttachKind::External`] attach carrying its blind
/// interval, and its connection must still be the live binding's connection:
/// a transport replacement requires a reconnect, exactly as the core refuses
/// it. Every copied reference is re-validated through the same blank/control
/// rule the receipt compiler enforces, so a malformed binding fails here with
/// the same typed refusal instead of travelling into the record.
///
/// # Errors
///
/// Returns [`BridgeError::InvalidContract`] for a non-external request, a
/// missing blind interval, or a malformed reference, and
/// [`BridgeError::InvalidTransition`] when the request connection no longer
/// matches the live binding.
pub fn claim_bridge_attach(
    binding: &AttachBinding,
    request: &AttachRequest,
) -> Result<ExternalAttachBridgeClaim, Box<BridgeError>> {
    if request.attach_kind() != AttachKind::External {
        return Err(Box::new(BridgeError::InvalidContract {
            field: "attach_kind",
            reason: "only an external attach reconciles through this ingress",
        }));
    }
    if request.pre_attach_blind_interval().is_none() {
        return Err(Box::new(BridgeError::InvalidContract {
            field: "pre_attach_blind_interval",
            reason: "external attach must preserve its blind interval",
        }));
    }
    if request.connection_id().as_str() != binding.connection_id().as_str() {
        return Err(Box::new(BridgeError::InvalidTransition(
            "transport replacement requires reconnect",
        )));
    }
    let demand_ref = reference(
        "external_attach_binding.demand_ref",
        request.demand_id().as_str(),
    )?;
    let connection_ref = reference(
        "external_attach_binding.connection_ref",
        request.connection_id().as_str(),
    )?;
    let principal_ref = reference(
        "external_attach_binding.principal_ref",
        binding.principal_id().as_str(),
    )?;
    let session_ref = reference(
        "external_attach_binding.session_ref",
        binding.session_id().as_str(),
    )?;
    let task = binding.task_binding();
    let task_ref = reference("external_attach_binding.task_ref", task.task_id().as_str())?;
    let work_unit_ref = reference(
        "external_attach_binding.work_unit_ref",
        task.work_unit_id().as_str(),
    )?;
    let work_scope_ref = reference(
        "external_attach_binding.work_scope_ref",
        task.work_scope_id(),
    )?;
    let task_revision = reference(
        "external_attach_binding.task_revision",
        task.task_revision(),
    )?;
    let plan_ref = reference("external_attach_binding.plan_ref", task.plan_id())?;
    let plan_revision = reference(
        "external_attach_binding.plan_revision",
        task.plan_revision(),
    )?;
    Ok(ExternalAttachBridgeClaim {
        demand_ref,
        connection_ref,
        principal_ref,
        session_ref,
        activation_generation: binding.activation_generation(),
        state_fence: binding.state_fence().clone(),
        task_ref,
        work_unit_ref,
        work_scope_ref,
        task_revision,
        plan_ref,
        plan_revision,
    })
}

/// One retained external-attach ingress: the compiled receipt plus the exact
/// binding it was compiled under and the live owner evidence observed at
/// ingest (issue #1782 audit repair).
///
/// The receipt shape is unchanged: this record only joins it to the Bridge
/// binding claim, the admitted Governor fence, and the Kernel-issued owner
/// session binding observed when the receipt was compiled. `claim` is `None`
/// only for a receipt retained through the receipt-only path, which can never
/// satisfy a presenting-binding check. The fence and session snapshots are
/// what the Material-continuation recheck compares the live owners against:
/// workspace movement, source/task revision drift, logout, or session
/// replacement invalidates dependent use with
/// [`BridgeError::StaleAuthority`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAttachIngressRecord {
    /// Exact Bridge binding the receipt was compiled under, when the attach
    /// arrived through the Bridge ingress.
    pub claim: Option<ExternalAttachBridgeClaim>,
    /// Compiled reconciliation receipt, validated before retention.
    pub receipt: ExternalAttachReconciliationReceipt,
    /// Live Governor fence observed at ingest.
    pub admitted_fence: StateFence,
    /// Kernel-issued owner session binding observed at ingest, if one was
    /// noted.
    pub owner_session_binding: Option<String>,
}

/// Compiles and seals one Bridge external attach through the receipt compiler.
///
/// The owner-observed [`ExternalAttachObservation`] is fed into
/// [`reconcile_external_attach`] unchanged: this ingress adds no observation
/// of its own and resolves nothing. The compiled receipt is validated on the
/// original before it is sealed into the record, so a malformed compiler
/// output can never be retained. The caller persists the returned record
/// before reporting any gate-clearing view to the Bridge: the Bridge flag is
/// cleared only after this retention, never before.
///
/// # Errors
///
/// Returns the exact [`BridgeError`] from [`reconcile_external_attach`] or
/// [`ExternalAttachReconciliationReceipt::validate`] without collapsing it.
pub fn serve_bridge_external_attach(
    claim: ExternalAttachBridgeClaim,
    observation: &ExternalAttachObservation,
    live_fence: &StateFence,
    live_owner_session: Option<&str>,
) -> Result<ExternalAttachIngressRecord, Box<BridgeError>> {
    let receipt = reconcile_external_attach(observation)?;
    receipt.validate()?;
    Ok(ExternalAttachIngressRecord {
        claim: Some(claim),
        receipt,
        admitted_fence: live_fence.clone(),
        owner_session_binding: live_owner_session.map(str::to_owned),
    })
}

/// Reads back the retained disposition for the exact presenting binding.
///
/// A lost Bridge response replays through here: an exact content match
/// returns the same receipt with the same continuation and the same attempt
/// identity, minting nothing. Any other binding fails closed without touching
/// the retained record, so a replay can neither duplicate an attempt nor
/// reset the reconciliation state.
///
/// # Errors
///
/// Returns [`BridgeError::StaleAuthority`] when no attach is retained or the
/// presenting binding differs from the retained claim in any field, and
/// [`BridgeError::InvalidContract`] when the retained receipt itself no
/// longer validates.
pub fn replay_bridge_external_attach<'a>(
    record: Option<&'a ExternalAttachIngressRecord>,
    presenting: &ExternalAttachBridgeClaim,
) -> Result<&'a ExternalAttachReconciliationReceipt, Box<BridgeError>> {
    let Some(record) = record else {
        return Err(Box::new(BridgeError::NotAttached));
    };
    let Some(retained) = record.claim.as_ref() else {
        return Err(Box::new(BridgeError::StaleAuthority));
    };
    if retained != presenting {
        return Err(Box::new(BridgeError::StaleAuthority));
    }
    record.receipt.validate()?;
    Ok(&record.receipt)
}

/// The exact retained binding read back for the Bridge to verify (issue #1782
/// audit repair).
///
/// This is a readback, never a mint: every field is cloned from the retained
/// record. The Bridge verifies the returned request/session/task/fence/attempt
/// relation against its live attach instead of trusting a nonblank receipt
/// reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAttachBindingView {
    /// Demand the retained attach was presented under.
    pub demand_ref: String,
    /// Connection the retained attach was presented on.
    pub connection_ref: String,
    /// Authenticated principal of the retained attach.
    pub principal_ref: String,
    /// Authenticated session of the retained attach.
    pub session_ref: String,
    /// Activation generation of the retained attach.
    pub activation_generation: u64,
    /// Fence nonce of the retained attach.
    pub fence_nonce: String,
    /// Fence generation of the retained attach.
    pub fence_generation: u64,
    /// Admitted task identity of the retained attach.
    pub task_ref: String,
    /// Admitted work-unit identity of the retained attach.
    pub work_unit_ref: String,
    /// Admitted work-scope identity of the retained attach.
    pub work_scope_ref: String,
    /// Admitted task revision of the retained attach.
    pub task_revision: String,
    /// Admitted plan identity of the retained attach.
    pub plan_ref: String,
    /// Admitted plan revision of the retained attach.
    pub plan_revision: String,
    /// How the retained attach continues.
    pub continuation: ContinuationKind,
    /// New attempt identity, present exactly for a new bounded attempt.
    pub new_attempt_ref: Option<String>,
    /// Explicit pre-attach blind interval, in unix milliseconds.
    pub blind_interval_ms: u64,
}

/// Reads back the exact retained binding plus the retained disposition.
///
/// # Errors
///
/// Returns [`BridgeError::InvalidContract`] when the retained receipt no
/// longer validates. The view is read from the retained record only after
/// that check, so a stale receipt can never produce a verifying view.
pub fn binding_view(
    record: &ExternalAttachIngressRecord,
) -> Result<ExternalAttachBindingView, Box<BridgeError>> {
    let Some(claim) = record.claim.as_ref() else {
        return Err(Box::new(BridgeError::StaleAuthority));
    };
    record.receipt.validate()?;
    Ok(ExternalAttachBindingView {
        demand_ref: claim.demand_ref.clone(),
        connection_ref: claim.connection_ref.clone(),
        principal_ref: claim.principal_ref.clone(),
        session_ref: claim.session_ref.clone(),
        activation_generation: claim.activation_generation.get(),
        fence_nonce: claim.state_fence.nonce().to_owned(),
        fence_generation: claim.state_fence.generation().get(),
        task_ref: claim.task_ref.clone(),
        work_unit_ref: claim.work_unit_ref.clone(),
        work_scope_ref: claim.work_scope_ref.clone(),
        task_revision: claim.task_revision.clone(),
        plan_ref: claim.plan_ref.clone(),
        plan_revision: claim.plan_revision.clone(),
        continuation: record.receipt.continuation_kind(),
        new_attempt_ref: record
            .receipt
            .continuation_kind_and_new_attempt_identity
            .new_attempt_ref
            .clone(),
        blind_interval_ms: record.receipt.pre_attach_blind_interval_ms(),
    })
}

/// Admits one requested effect against the retained ingress record, rechecking
/// applicability before any Material continuation (issue #1782 audit repair).
///
/// Beyond the [`admit_material_continuation`] gate this re-derives nothing:
///
/// - a presenting Bridge binding must equal the retained claim field for
///   field, so a stale or substituted request/session/task/fence binding
///   cannot clear the gate;
/// - the live Governor fence must still equal the admitted fence, so
///   workspace movement or source/task revision drift invalidates dependent
///   use;
/// - the live owner session binding must still equal the recorded one, so a
///   logout, replacement, or fresh grant never revives the cached
///   disposition (I11.8: fresh authentication never revives cached grants).
///
/// Authentication staleness stays the stronger refusal: binding, fence, and
/// session mismatches report [`BridgeError::StaleAuthority`] ahead of the
/// disposition gate, which still reports
/// [`BridgeError::ExternalAttachReconciliationRequired`] for an unattributed
/// continuation.
///
/// # Errors
///
/// Returns [`BridgeError::InvalidContract`] when the retained receipt does
/// not validate, [`BridgeError::StaleAuthority`] for a stale or substituted
/// binding, fence, or session, and
/// [`BridgeError::ExternalAttachReconciliationRequired`] when a Material
/// effect is requested before an attributed continuation exists.
pub fn admit_material_continuation_for_record(
    effect: RequestedEffect,
    record: Option<&ExternalAttachIngressRecord>,
    presenting: Option<&ExternalAttachBridgeClaim>,
    live_fence: &StateFence,
    live_owner_session: Option<&str>,
) -> Result<(), Box<BridgeError>> {
    if !effect.requires_material_readiness() {
        return Ok(());
    }
    let Some(record) = record else {
        return Ok(());
    };
    record.receipt.validate()?;
    match (record.claim.as_ref(), presenting) {
        (Some(retained), Some(presenting)) => {
            if retained != presenting {
                return Err(Box::new(BridgeError::StaleAuthority));
            }
        }
        (None, Some(_)) => {
            return Err(Box::new(BridgeError::StaleAuthority));
        }
        (Some(_) | None, None) => {}
    }
    if record.admitted_fence != *live_fence {
        return Err(Box::new(BridgeError::StaleAuthority));
    }
    if record.owner_session_binding.as_deref() != live_owner_session {
        return Err(Box::new(BridgeError::StaleAuthority));
    }
    admit_material_continuation(effect, Some(&record.receipt))
}

/// Why `Start work` may not hide the presented state behind an automatic agent
/// launch (I11.11 line 25).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AutomaticLaunchRefusal {
    /// The observed candidate set is ambiguous, or resolves to more than one
    /// candidate, or the compiled scope resolution is ambiguous: an ambiguous
    /// clone (similar repository) is not hidden behind a launch.
    AmbiguousClone,
    /// The compiled readiness receipt reports conflicted governing sources.
    ConflictingGoverningDocument,
    /// No exact current task contract was presented: absent, ambiguous, stale,
    /// or still reported as needing a task.
    MissingTask,
    /// An attached external agent has no attributed continuation yet.
    ExternalAttachUnreconciled,
}

/// Refuses an automatic agent launch that would hide an ambiguous clone, a
/// missing task, a conflicting governing document, or an unreconciled external
/// attach (I11.11 line 25).
///
/// The decision reads only the owner-issued
/// [`WorkScopeCandidateSet`] and [`OnboardingReadinessReceipt`] the caller
/// already exposed at `Start work`, plus the attach receipt when one exists. It
/// resolves nothing and prefers no candidate: an ambiguous scope resolution, an
/// ambiguous or conflicted candidate set, a candidate count above one, a
/// conflicted readiness lifecycle, and a missing/stale/ambiguous task binding
/// each refuse. Nothing is inspected, discovered or launched here.
///
/// # Errors
///
/// Returns the exact [`AutomaticLaunchRefusal`] for the first blocking leg.
pub fn admit_automatic_agent_launch(
    candidates: &WorkScopeCandidateSet,
    readiness: &OnboardingReadinessReceipt,
    attach: Option<&ExternalAttachReconciliationReceipt>,
) -> Result<(), AutomaticLaunchRefusal> {
    if candidates.disposition == CandidateDisposition::Ambiguous
        || candidates.disposition == CandidateDisposition::Conflicted
        || candidates.candidates.len() > 1
        || readiness.scope_resolution == ScopeResolutionState::Ambiguous
    {
        return Err(AutomaticLaunchRefusal::AmbiguousClone);
    }
    if readiness.readiness == ReadinessLifecycle::Conflicted {
        return Err(AutomaticLaunchRefusal::ConflictingGoverningDocument);
    }
    if readiness.readiness == ReadinessLifecycle::NeedsTask
        || matches!(
            &readiness.task_binding,
            TaskBindingState::None_
                | TaskBindingState::Ambiguous { .. }
                | TaskBindingState::Stale { .. }
        )
    {
        return Err(AutomaticLaunchRefusal::MissingTask);
    }
    if let Some(attach) = attach
        && !attach.admits_material_continuation()
    {
        return Err(AutomaticLaunchRefusal::ExternalAttachUnreconciled);
    }
    Ok(())
}
