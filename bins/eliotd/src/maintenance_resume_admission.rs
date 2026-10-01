//! Fresh-admission resume gate for Governor maintenance jobs (I14.22 W6,
//! issue #1692).
//!
//! A stored `ADMITTED` fence, a stored `Active` lease, or a decision that was
//! valid when it was evaluated is not proof of current permission. This module
//! is the explicit continuity/admission decision a reauthenticated broker, a
//! changed route, or a policy revision receives before any new dependent
//! effect: [`decide_resume_admission`] revalidates the stored job against
//! freshly observed evidence and answers `ADMIT` with its continuity record or
//! `REFUSE` with a typed reason and the next allowed action. It is pure — no
//! store read, no write, no clock, no second ledger — so replaying it converges
//! instead of duplicating a job or a board obligation (A6), and refusing it
//! claims nothing durable.
//!
//! What the gate checks, in order:
//!
//! * the stored revision itself validates through the owner's own
//!   [`MaintenanceJob::validate`](eliot_maintenance::MaintenanceJob::validate);
//! * only `CHECKPOINTED` or `DEFERRED` work resumes: `UNKNOWN_OUTCOME` must go
//!   through `reconcile_unknown` first (earlier attempts are reconciled before
//!   replacement, and their immutable outcome stays in the obligation chain),
//!   `ADMITTED` must go through `start`, `RUNNING` is already running, and
//!   terminal states never resume;
//! * the attempt budget still admits another attempt;
//! * the live admitted fence still equals the admission fence (a moved fence
//!   refuses here; the controller's own `load_checked` re-verifies the same
//!   equality at the write, so a race between this gate and `resume` collapses
//!   to `FenceMismatch`, never to a silent admission);
//! * the bound policy/route evidence still names this family and scope (forged
//!   or misbound evidence grants nothing), the current mode is not `Off`, and
//!   the separate interactive-session requirement did not change under the job;
//! * a session-bound job resumes only with current authenticated User Broker
//!   evidence — a logout or revocation between decision and resume is caught
//!   here (A4) — while service-safe work is never gated on a session (A7);
//! * every earlier attempt's result obligation is settled (`Published` receipt
//!   or recorded `Unavailable` gap); a `Pending` publication refuses with the
//!   exact reopen path instead of replacing unreconciled work.
//!
//! # Live status
//!
//! This gate currently has NO production caller: nothing on the daemon run loop
//! calls `MaintenanceController::resume` yet, so there is no resume site to
//! guard. The execution owner (issue #18, `daemon_runtime`) is the named
//! stitch: call [`decide_resume_admission`] with the live admitted fence
//! immediately before `resume`, proceed only on [`ResumeAdmission::Admit`], and
//! render [`project_resume_status`] on the existing diagnostics/status path.
//!
//! # Stitches
//!
//! * `fix/1692-gate-join-W1a` (sibling W1 line) changes
//!   `MaintenanceBrokerEvidence::authenticated_session_available` to take the
//!   observation instant and re-validate the bound bundle under the same
//!   predicate name. This gate calls the base no-arg predicate; when that line
//!   merges, pass this gate's observation instant through at the marked site.
//! * Strict policy-revision equality (admission episode versus current episode)
//!   needs `admit` to persist the episode on the job. That is a
//!   `MaintenanceController::admit` contract change owned by
//!   `crates/governor/eliot-maintenance/src/lib.rs`; until it exists this gate
//!   compares the mode, the session requirement, and the family/scope binding,
//!   which is what the job carries today.
//!
//! Tokens and reusable desktop credentials never travel this path: the evidence
//! types carry only digests, references, and booleans, and the status
//! projection additionally passes every identity through
//! [`sanitize_identity`](super::diagnostics::sanitize_identity), which redacts
//! secret- or payload-bearing content.

#![forbid(unsafe_code)]

use eliot_contracts::StateFence;
use eliot_maintenance::{
    MaintenanceAutomationMode, MaintenanceBrokerEvidence, MaintenanceError, MaintenanceJob,
    MaintenanceJobState,
};
use eliot_observation_contracts::MaintenanceDeliveryState;
use eliot_runtime_contracts::LeaseState;
use serde::Serialize;

use super::diagnostics::sanitize_identity;
use super::notification_state_emit::MaintenanceNotificationEvidence;

/// Freshly observed evidence the resume admission is decided against.
///
/// The policy/route half reuses [`MaintenanceNotificationEvidence`], the exact
/// type the evaluation path already binds to the decision — no second policy
/// or route scheme. The broker half is the owner's own current observation,
/// and the fence is the live admitted fence, never a transported claim.
#[derive(Clone, Debug)]
pub struct ResumeFreshEvidence {
    /// Live admitted fence the resume would run under.
    pub fence: StateFence,
    /// Current Human-policy and actual-route evidence for this family/scope.
    pub notification: MaintenanceNotificationEvidence,
    /// Current authenticated User Broker observation.
    pub broker: MaintenanceBrokerEvidence,
}

/// Session continuity bound by one admitted resume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumeSessionBinding {
    /// The job requires an interactive session and current broker evidence
    /// establishes one.
    RequiredAndCurrent,
    /// The job is service-safe: no session gates it, and broker loss does not
    /// stop it.
    ServiceSafe,
}

/// Continuity record carried by one admitted resume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeContinuity {
    /// Attempt ordinal the admitted resume would begin.
    pub continued_attempt: u32,
    /// Session binding the resume was admitted under.
    pub session_binding: ResumeSessionBinding,
    /// Settled prior-attempt obligations reconciled before replacement.
    pub settled_obligations: usize,
}

/// Typed reason one resume admission is refused.
///
/// Every variant names a fail-closed gate, never a diagnostic guess. The next
/// allowed action travels beside the verdict in [`ResumeAdmission::Refuse`]
/// and in the projected [`ResumeStatus`], so an operator always sees the exact
/// reopen path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumeRefusalReason {
    /// The stored revision itself is invalid under the owner's validation.
    StoredJobInvalid,
    /// The lifecycle state does not resume: unknown outcomes reconcile first,
    /// admitted work starts first, running work is already running, and
    /// terminal work never resumes.
    IllegalResumeState,
    /// The attempt budget admits no further attempt.
    AttemptBudgetExhausted,
    /// The stored runtime lease is not active.
    LeaseInactive,
    /// The live fence moved past the admission fence.
    StaleFence,
    /// The bound evidence names another family/scope: forged or misbound
    /// evidence grants nothing.
    EvidenceMismatch,
    /// The current policy mode is `Off`: no automatic resume, and a
    /// reauthenticated broker is not permission for unrelated deferred work.
    AutomationOff,
    /// The separate interactive-session requirement changed under the job:
    /// this needs a fresh admission, not a resume.
    SessionRequirementChanged,
    /// A session-bound job resumes only with current broker evidence: logout
    /// or revocation between decision and resume is caught here.
    SessionUnavailable,
    /// An earlier attempt's result publication is still `Pending`: admit its
    /// receipt or record its gap first, then resume.
    UnsettledPriorAttempt,
}

impl ResumeRefusalReason {
    /// Stable wire name. The spelling is fixed text beside the owner's own
    /// `SCREAMING_SNAKE_CASE` vocabulary, not a restatement of it.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::StoredJobInvalid => "STORED_JOB_INVALID",
            Self::IllegalResumeState => "ILLEGAL_RESUME_STATE",
            Self::AttemptBudgetExhausted => "ATTEMPT_BUDGET_EXHAUSTED",
            Self::LeaseInactive => "LEASE_INACTIVE",
            Self::StaleFence => "STALE_FENCE",
            Self::EvidenceMismatch => "EVIDENCE_MISMATCH",
            Self::AutomationOff => "AUTOMATION_OFF",
            Self::SessionRequirementChanged => "SESSION_REQUIREMENT_CHANGED",
            Self::SessionUnavailable => "SESSION_UNAVAILABLE",
            Self::UnsettledPriorAttempt => "UNSETTLED_PRIOR_ATTEMPT",
        }
    }

    /// The next allowed action for this refusal.
    ///
    /// Each names the exact owner call that reopens the decision, so a refusal
    /// is an explicit routing rather than a dead end.
    #[must_use]
    pub const fn next_action(self) -> &'static str {
        match self {
            Self::StoredJobInvalid => "none: the stored revision is rejected; re-admit through a fresh evaluated decision",
            Self::IllegalResumeState => "reconcile_unknown for UNKNOWN_OUTCOME, start for ADMITTED, none otherwise",
            Self::AttemptBudgetExhausted => "none: the policy attempt budget is spent; a new evaluated decision admits new work",
            Self::LeaseInactive => "none through resume: re-acquire the runtime lease through its owner, then a fresh admission",
            Self::StaleFence => "re-evaluate the trigger under the live admitted fence",
            Self::EvidenceMismatch => "none: bind evidence issued for this family and scope",
            Self::AutomationOff => "none while the Human policy mode is off; a verified mandatory safety/recovery obligation follows its own protected owner",
            Self::SessionRequirementChanged => "fresh admission under the current policy, not resume of this job",
            Self::SessionUnavailable => "re-authenticate the User Broker session, then resume; service-safe work is unaffected",
            Self::UnsettledPriorAttempt => "admit_maintenance_observation_receipt or record_maintenance_observation_gap for the pending publication, then resume",
        }
    }
}

/// One refused resume admission: the typed reason plus the job state it was
/// decided against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeRefusal {
    /// Why the resume is refused.
    pub reason: ResumeRefusalReason,
    /// Lifecycle state the stored job was in.
    pub job_state: MaintenanceJobState,
}

/// Explicit continuity/admission decision for one resume request.
///
/// A reauthenticated broker, a changed route, or a policy revision receives
/// exactly one of these before any new dependent effect. It creates no job, no
/// board item, and no store write, so replaying it converges (A6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResumeAdmission {
    /// The resume is admitted with its continuity record.
    Admit(ResumeContinuity),
    /// The resume is refused with its typed reason.
    Refuse(ResumeRefusal),
}

impl ResumeAdmission {
    /// Whether the resume is admitted.
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admit(_))
    }

    /// Maps a refusal onto the maintenance owner's typed failure vocabulary.
    ///
    /// State refusals reuse the owner's own `IllegalTransition` — a resume the
    /// controller would refuse — and lease/budget/session refusals reuse the
    /// owner's matching variants, so callers keep one typed failure scheme.
    /// Gate-specific refusals that have no owner variant stay `InvalidField`
    /// naming this gate, never a forged owner state.
    #[must_use]
    pub const fn owner_error(refusal: &ResumeRefusal) -> MaintenanceError {
        match refusal.reason {
            ResumeRefusalReason::StoredJobInvalid
            | ResumeRefusalReason::EvidenceMismatch
            | ResumeRefusalReason::AutomationOff
            | ResumeRefusalReason::SessionRequirementChanged
            | ResumeRefusalReason::UnsettledPriorAttempt => {
                MaintenanceError::InvalidField("resume.admission")
            }
            ResumeRefusalReason::IllegalResumeState => MaintenanceError::IllegalTransition {
                from: refusal.job_state,
                to: MaintenanceJobState::Running,
            },
            ResumeRefusalReason::AttemptBudgetExhausted => MaintenanceError::BudgetExhausted,
            ResumeRefusalReason::LeaseInactive => MaintenanceError::LeaseInactive,
            ResumeRefusalReason::StaleFence => MaintenanceError::FenceMismatch,
            ResumeRefusalReason::SessionUnavailable => MaintenanceError::UserSessionUnavailable,
        }
    }
}

/// Decides one resume admission against freshly observed evidence.
///
/// Pure: it reads the stored job and the fresh evidence and invents neither,
/// so the same inputs always yield the same decision. The stored lease check
/// reads the lease the admission persisted; live lease revalidation at the
/// Kernel/dispatch boundary stays the execution owner's call at `start` time.
///
/// STITCH (`fix/1692-gate-join-W1a`): when the broker predicate takes the
/// observation instant, pass the instant this gate observed beside the fence
/// at the marked call below.
#[must_use]
pub fn decide_resume_admission(
    job: &MaintenanceJob,
    fresh: &ResumeFreshEvidence,
) -> ResumeAdmission {
    let refuse = |reason: ResumeRefusalReason| {
        ResumeAdmission::Refuse(ResumeRefusal {
            reason,
            job_state: job.state,
        })
    };
    if let Err(error) = job.validate() {
        // The owner's own validation already distinguishes lease, budget, and
        // chain defects; keep that distinction instead of flattening it.
        return match error {
            MaintenanceError::LeaseInactive => refuse(ResumeRefusalReason::LeaseInactive),
            MaintenanceError::InvalidField("attempt_budget") => {
                refuse(ResumeRefusalReason::AttemptBudgetExhausted)
            }
            _ => refuse(ResumeRefusalReason::StoredJobInvalid),
        };
    }
    match job.state {
        MaintenanceJobState::Checkpointed | MaintenanceJobState::Deferred => {}
        _ => return refuse(ResumeRefusalReason::IllegalResumeState),
    }
    if job.attempts >= job.max_attempts {
        return refuse(ResumeRefusalReason::AttemptBudgetExhausted);
    }
    if job.runtime_lease.state != LeaseState::Active {
        return refuse(ResumeRefusalReason::LeaseInactive);
    }
    if job.state_fence != fresh.fence {
        return refuse(ResumeRefusalReason::StaleFence);
    }
    if fresh.notification.policy.family != job.family
        || fresh.notification.policy.scope_ref != job.scope_ref
    {
        return refuse(ResumeRefusalReason::EvidenceMismatch);
    }
    if fresh.notification.policy.mode == MaintenanceAutomationMode::Off {
        return refuse(ResumeRefusalReason::AutomationOff);
    }
    if fresh.notification.policy.requires_interactive_session() != job.user_session_required {
        return refuse(ResumeRefusalReason::SessionRequirementChanged);
    }
    // STITCH (fix/1692-gate-join-W1a): pass the observation instant here once
    // `authenticated_session_available` takes it and re-validates the bound
    // broker bundle under the same predicate name.
    let session_current = fresh.broker.authenticated_session_available();
    if job.user_session_required && !session_current {
        return refuse(ResumeRefusalReason::SessionUnavailable);
    }
    let unsettled = job.result_obligations.iter().any(|obligation| {
        matches!(
            &obligation.delivery,
            MaintenanceDeliveryState::Pending { .. }
        )
    });
    if unsettled {
        return refuse(ResumeRefusalReason::UnsettledPriorAttempt);
    }
    ResumeAdmission::Admit(ResumeContinuity {
        // Guarded above: `attempts < max_attempts`, so the next ordinal stays
        // within the admitted budget.
        continued_attempt: job.attempts.saturating_add(1),
        session_binding: if job.user_session_required {
            ResumeSessionBinding::RequiredAndCurrent
        } else {
            ResumeSessionBinding::ServiceSafe
        },
        settled_obligations: job.result_obligations.len(),
    })
}

/// One earlier attempt's reconciliation standing, in obligation-chain order.
///
/// Earlier attempts are reconciled before replacement: every entry names the
/// sanitized publication identity, the outcome the attempt actually produced
/// in the owner's declared wire form, and whether its observation is settled
/// (`Published` receipt or recorded `Unavailable` gap) or still `Pending`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReconciledAttemptView {
    /// Sanitized publication identity of the obligation.
    pub publication_ref: String,
    /// Outcome class in the owner's declared wire form.
    pub outcome: String,
    /// Whether the obligation's observation is settled.
    pub settled: bool,
}

/// Reads the attempt-reconciliation standing of one stored job.
///
/// Pure projection over the job's append-only obligation chain: the original
/// uncertainty stays visible beside its resolution because the chain is never
/// rewritten, only appended to.
#[must_use]
pub fn attempt_reconciliation(job: &MaintenanceJob) -> Vec<ReconciledAttemptView> {
    job.result_obligations
        .iter()
        .map(|obligation| ReconciledAttemptView {
            publication_ref: sanitize_identity(&obligation.publication_id),
            outcome: wire_name(&obligation.execution_outcome),
            settled: !matches!(
                &obligation.delivery,
                MaintenanceDeliveryState::Pending { .. }
            ),
        })
        .collect()
}

/// Privacy-filtered resume status for the existing diagnostics/status path.
///
/// Every identity passes through [`sanitize_identity`](super::diagnostics::sanitize_identity):
/// secret- or payload-bearing content renders `REDACTED`, malformed content
/// renders `UNAVAILABLE`, and nothing longer than the identity bound travels.
/// Bindings render as exact values the evidence owners published (mode, policy
/// episode, route fingerprint/generation/suitability, session requirement and
/// currency) plus the admission verdict and the next allowed action — and no
/// token, credential, or reusable desktop secret, which the evidence types do
/// not carry at all.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResumeStatus {
    /// Sanitized durable job identity.
    pub job_ref: String,
    /// Sanitized trigger identity that admitted the job.
    pub trigger_ref: String,
    /// Sanitized source-decision reference.
    pub decision_ref: String,
    /// Registered family in its declared wire form.
    pub family: String,
    /// Sanitized affected scope.
    pub scope_ref: String,
    /// Lifecycle state in its declared wire form.
    pub state: String,
    /// Current automation mode in its declared wire form.
    pub mode: String,
    /// Policy episode: published revision/digest/override presence, or
    /// `unpublished` when no Human policy owner publishes.
    pub policy_episode: String,
    /// Actual route binding: sanitized fingerprint/generation and suitability,
    /// never a credential value.
    pub route_binding: String,
    /// Session binding: required+current, required+absent, or service-safe.
    pub session_binding: String,
    /// Attempts already begun.
    pub attempts_begun: u32,
    /// Maximum attempts admitted by policy.
    pub max_attempts: u32,
    /// Per-attempt reconciliation standing, in chain order.
    pub attempts: Vec<ReconciledAttemptView>,
    /// Admission verdict: `ADMIT` or the refusal wire name.
    pub verdict: String,
    /// Next allowed action for this verdict.
    pub next_action: String,
}

/// Projects the privacy-filtered resume status of one stored job.
///
/// The `admission` is the decision [`decide_resume_admission`] returned for
/// this same job and evidence, so the status reports the verdict that was
/// actually decided rather than re-deciding it.
#[must_use]
pub fn project_resume_status(
    job: &MaintenanceJob,
    fresh: &ResumeFreshEvidence,
    admission: &ResumeAdmission,
) -> ResumeStatus {
    let policy = &fresh.notification.policy;
    let route = &fresh.notification.route;
    let (verdict, next_action) = match admission {
        ResumeAdmission::Admit(_) => (
            "ADMIT".to_owned(),
            "proceed to MaintenanceController::resume under the live admitted fence".to_owned(),
        ),
        ResumeAdmission::Refuse(refusal) => (
            refusal.reason.wire_name().to_owned(),
            refusal.reason.next_action().to_owned(),
        ),
    };
    ResumeStatus {
        job_ref: sanitize_identity(&job.job_id),
        trigger_ref: sanitize_identity(&job.trigger_id),
        decision_ref: sanitize_identity(&job.decision_ref),
        family: job.family.to_string(),
        scope_ref: sanitize_identity(&job.scope_ref),
        state: job.state.to_string(),
        mode: wire_name(&policy.mode),
        policy_episode: policy_episode_summary(policy),
        route_binding: format!(
            "fingerprint={fingerprint}, generation={generation:?}, unattended_suitable={suitable}",
            fingerprint = route.capability_fingerprint.as_deref().map_or_else(
                || "unpublished".to_owned(),
                sanitize_identity
            ),
            generation = route.generation,
            suitable = route.unattended_suitable,
        ),
        session_binding: if job.user_session_required {
            if fresh.broker.authenticated_session_available() {
                "required+current".to_owned()
            } else {
                "required+absent".to_owned()
            }
        } else {
            "service-safe".to_owned()
        },
        attempts_begun: job.attempts,
        max_attempts: job.max_attempts,
        attempts: attempt_reconciliation(job),
        verdict,
        next_action,
    }
}

/// Renders the policy episode the owner published, or `unpublished`.
///
/// Mirrors what the notification key treats as episode material — revision,
/// digest, and override provenance — without restating the fingerprint scheme:
/// this is a status line, not key material.
fn policy_episode_summary(policy: &eliot_maintenance::MaintenancePolicyEvidence) -> String {
    if policy.revision.is_none()
        && policy.digest.is_none()
        && policy.override_provenance.is_none()
    {
        return "unpublished".to_owned();
    }
    format!(
        "revision={revision:?}, digest={digest}, override={override_presence}",
        revision = policy.revision,
        digest = policy.digest.as_deref().unwrap_or("unpublished"),
        override_presence = if policy.override_provenance.is_some() {
            "present"
        } else {
            "unpublished"
        },
    )
}

/// Renders one closed owner discriminator in its declared wire form.
///
/// Reuses the declaration (`SCREAMING_SNAKE_CASE` serialization) instead of
/// minting a second vocabulary beside the owner's.
fn wire_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => super::diagnostics::UNAVAILABLE.to_owned(),
    }
}
