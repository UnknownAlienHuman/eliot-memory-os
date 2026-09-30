//! Versioned, owner-neutral restart policy values, class eligibility, and the
//! durable restart-intensity ledger.
//!
//! This module validates policy declarations, decides whether a restart is
//! eligible under the declared class, and debits an attempt against the
//! owner's durable intensity record before any effect is dispatched. It does
//! not authorize effects, reconcile process identity, or launch a replacement;
//! persisting the record through the owner's compare-and-save path and
//! dispatching remain the owner's.

use eliot_contracts::{ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::RuntimeContractError;
use crate::control_reserve::{CapacityBottleneck, CapacityClass};

/// Encoding or contract validation failure for restart policy bindings.
#[derive(Debug, Error)]
pub enum RestartPolicyError {
    /// A policy or state-fence contract rejected its value.
    #[error(transparent)]
    Contract(#[from] RuntimeContractError),
    /// Canonical policy serialization failed.
    #[error("restart policy encoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
}

/// The restart class declared for one supervised child.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartClass {
    Permanent,
    Transient,
    Temporary,
}

/// Strategy declared for a named supervision group.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartGroupStrategy {
    OneForOne,
    RestForOne,
    OneForAll,
}

/// How a declared dependency affects activation and recovery.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartDependencyKind {
    Required,
    Optional,
    Advisory,
}

/// A locally declared event that invalidates dependent operational state.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RestartInvalidationTrigger {
    RequiredProtocolDigestMismatch,
    OperationalStateInvalidated,
    StateFenceInvalidated,
    HealthContractFailed,
}

/// One typed dependency edge in a restart policy. This declaration is not a
/// validated graph; graph-wide cycle and transitive-closure checks belong to
/// the catalog activation path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartDependency {
    pub dependency_id: String,
    pub kind: RestartDependencyKind,
    pub invalidation_triggers: Vec<RestartInvalidationTrigger>,
}

/// Bounded restart-intensity, delay, healthy-reset, and escalation values.
/// Every number is supplied by the admitted policy/profile; this contract has
/// no numeric defaults or global limits.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartIntensityPolicy {
    pub max_attempts_in_window: u32,
    pub window_millis: u64,
    pub backoff_initial_millis: u64,
    pub backoff_max_millis: u64,
    pub jitter_max_millis: u64,
    pub cooldown_millis: u64,
    pub reset_after_healthy_millis: u64,
    pub quarantine_after_attempts: u32,
    pub escalation_target: String,
}

/// Complete local versioned restart declaration value.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartPolicyV1 {
    pub policy_version: u16,
    pub subject_id: String,
    pub restart_class: RestartClass,
    pub group_id: String,
    pub group_strategy: RestartGroupStrategy,
    pub one_for_all_rationale: Option<String>,
    pub dependencies: Vec<RestartDependency>,
    pub intensity: RestartIntensityPolicy,
    pub source_manifest_revision: u64,
    pub source_profile_revision: u64,
}

impl RestartPolicyV1 {
    /// Validates locally provable policy consistency. This does not validate a
    /// complete dependency graph or prove an accepted measured group rationale.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        if self.policy_version != 1 {
            return Err(invalid(
                "policy_version",
                "unsupported restart policy version",
            ));
        }
        text(&self.subject_id, "subject_id")?;
        text(&self.group_id, "group_id")?;
        if self.source_manifest_revision == 0 || self.source_profile_revision == 0 {
            return Err(invalid(
                "source_revision",
                "manifest and profile revisions must be non-zero",
            ));
        }
        match (self.group_strategy, self.one_for_all_rationale.as_deref()) {
            (RestartGroupStrategy::OneForAll, Some(rationale)) => {
                text(rationale, "one_for_all_rationale")?;
            }
            (RestartGroupStrategy::OneForAll, None) => {
                return Err(invalid(
                    "one_for_all_rationale",
                    "one_for_all requires a named rationale",
                ));
            }
            (_, Some(_)) => {
                return Err(invalid(
                    "one_for_all_rationale",
                    "rationale is only valid for one_for_all",
                ));
            }
            (_, None) => {}
        }

        let mut dependency_ids = std::collections::BTreeSet::new();
        for dependency in &self.dependencies {
            text(&dependency.dependency_id, "dependency_id")?;
            if dependency.dependency_id == self.subject_id {
                return Err(invalid("dependency_id", "self dependency is invalid"));
            }
            if !dependency_ids.insert(&dependency.dependency_id) {
                return Err(invalid("dependencies", "dependency ids must be unique"));
            }
            if dependency.invalidation_triggers.is_empty() {
                return Err(invalid(
                    "invalidation_triggers",
                    "each declared edge requires an invalidation trigger",
                ));
            }
            let mut triggers = std::collections::BTreeSet::new();
            if dependency
                .invalidation_triggers
                .iter()
                .any(|trigger| !triggers.insert(*trigger))
            {
                return Err(invalid(
                    "invalidation_triggers",
                    "invalidation triggers must be unique",
                ));
            }
        }

        let intensity = &self.intensity;
        if intensity.max_attempts_in_window == 0
            || intensity.window_millis == 0
            || intensity.reset_after_healthy_millis == 0
            || intensity.quarantine_after_attempts == 0
            || intensity.quarantine_after_attempts > intensity.max_attempts_in_window
        {
            return Err(invalid(
                "intensity",
                "attempt, window, reset, and quarantine values are inconsistent",
            ));
        }
        if intensity.backoff_initial_millis > intensity.backoff_max_millis {
            return Err(invalid(
                "backoff_max_millis",
                "maximum backoff must not be below initial backoff",
            ));
        }
        text(&intensity.escalation_target, "escalation_target")?;
        Ok(())
    }

    /// Computes the canonical policy digest used by admission bindings.
    pub fn digest(&self) -> Result<String, RestartPolicyError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)?;
        Ok(sha256_hex(&bytes))
    }

    /// Binds this declaration to the admitted generation and its state fence.
    pub fn bind(
        &self,
        admitted_generation: ResourceGeneration,
        state_fence: StateFence,
    ) -> Result<RestartPolicyAdmissionBinding, RestartPolicyError> {
        state_fence.validate().map_err(RuntimeContractError::from)?;
        if admitted_generation != state_fence.resource_generation {
            return Err(invalid(
                "restart_policy_binding",
                "admitted generation must match the state fence generation",
            )
            .into());
        }
        Ok(RestartPolicyAdmissionBinding {
            policy_digest: self.digest()?,
            source_manifest_revision: self.source_manifest_revision,
            source_profile_revision: self.source_profile_revision,
            admitted_generation,
            state_fence,
        })
    }
}

/// Digest and immutable admission identity for a restart policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartPolicyAdmissionBinding {
    pub policy_digest: String,
    pub source_manifest_revision: u64,
    pub source_profile_revision: u64,
    pub admitted_generation: ResourceGeneration,
    pub state_fence: StateFence,
}

impl RestartPolicyAdmissionBinding {
    /// Checks that this admission carries the exact supplied policy digest and
    /// source revisions. The owner still verifies generation and fence currentness.
    pub fn validate_for(
        &self,
        policy: &RestartPolicyV1,
        admitted_generation: &ResourceGeneration,
        state_fence: &StateFence,
    ) -> Result<(), RestartPolicyError> {
        state_fence.validate().map_err(RuntimeContractError::from)?;
        if self.policy_digest != policy.digest()?
            || self.source_manifest_revision != policy.source_manifest_revision
            || self.source_profile_revision != policy.source_profile_revision
            || &self.admitted_generation != admitted_generation
            || &self.state_fence != state_fence
            || self.admitted_generation != self.state_fence.resource_generation
        {
            return Err(invalid(
                "restart_policy_binding",
                "policy, source revision, generation, or state fence does not match",
            )
            .into());
        }
        Ok(())
    }
}

/// Explicit disposition of a supervised child whose declared restart policy is
/// absent, legacy or unsupported.
///
/// I14.10 requires every supervised child to carry a bounded restart-intensity
/// window, backoff, cooldown, stable-uptime reset condition and quarantine
/// threshold, so a declaration this contract cannot admit is dispositioned
/// rather than interpreted. There is deliberately no variant that means
/// "restart without limit" or "assume the widest authority": a withheld child
/// performs no automatic restart at all and keeps exactly the effect authority
/// it was already admitted with, until its owner admits an explicit policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicyDisposition {
    /// The declared policy is the admitted version of this contract.
    Admitted {
        /// Digest of the admitted policy, which is what the admitted
        /// generation and the operational record are bound to.
        policy_digest: String,
    },
    /// No automatic restart is permitted for this child.
    Withheld {
        /// Policy version the unadmittable declaration named, or `None` when
        /// the desired manifest declared no versioned policy at all.
        declared_version: Option<u16>,
        /// The exact reason the declaration could not be admitted.
        reason: String,
    },
}

impl RestartPolicyDisposition {
    /// Whether this disposition permits any automatic restart. `Withheld`
    /// never does, so an absent or unsupported declaration cannot restart a
    /// child or be read as an unlimited budget.
    #[must_use]
    pub const fn permits_automatic_restart(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }

    /// The admitted policy digest, or `None` when no policy was admitted.
    #[must_use]
    pub fn policy_digest(&self) -> Option<&str> {
        match self {
            Self::Admitted { policy_digest } => Some(policy_digest.as_str()),
            Self::Withheld { .. } => None,
        }
    }

    /// Validates the disposition's own content.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        match self {
            Self::Admitted { policy_digest } => text(policy_digest, "policy_digest")?,
            Self::Withheld { reason, .. } => text(reason, "reason")?,
        }
        Ok(())
    }
}

/// Resolves the explicit disposition of one supervised child's declared restart
/// policy.
///
/// A declaration this contract admits is bound by the digest of that exact
/// policy, so the disposition records the declaration rather than
/// re-interpreting it. A missing declaration, or one this contract does not
/// admit, is withheld: it never becomes an unlimited restart budget and never
/// widens the child's effect authority, and the exact rejection reason travels
/// with the disposition so the gap is named rather than defaulted away.
pub fn dispose_restart_policy(
    declared: Option<&RestartPolicyV1>,
) -> Result<RestartPolicyDisposition, RestartPolicyError> {
    let Some(policy) = declared else {
        return Ok(RestartPolicyDisposition::Withheld {
            declared_version: None,
            reason: "the desired manifest declares no versioned restart policy".to_owned(),
        });
    };
    // The original declared value is validated with the contract's own
    // validator; its rejection reason is recorded rather than replaced by a
    // permissive interpretation of an unadmitted declaration.
    if let Err(rejection) = policy.validate() {
        return Ok(RestartPolicyDisposition::Withheld {
            declared_version: Some(policy.policy_version),
            reason: rejection.to_string(),
        });
    }
    Ok(RestartPolicyDisposition::Admitted {
        policy_digest: policy.digest()?,
    })
}

/// Current owner lifecycle relevant to automatic restart eligibility.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartOwnerLifecycle {
    Running,
    PlannedShutdown,
    Cancellation,
    Quiescing,
    Retiring,
}

/// Whether the old child identity is exact enough to permit replacement.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartIdentityEvidence {
    Exact,
    MissingOrAmbiguous,
}

/// Exit and health evidence supplied by the existing process/health owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartFailureEvidence {
    NormalExit,
    AbnormalExit,
    FailedHealthContract,
    NoRestartCondition,
}

/// Policy eligibility result. `Eligible` grants no launch or effect authority.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticRestartDecision {
    Eligible,
    SuppressedByOwnerLifecycle,
    TemporaryChild,
    NoMatchingFailureCondition,
    BlockedByUncertainIdentity,
}

/// Evaluates only the class/lifecycle/identity rule; no budget or effect
/// authorization is performed here.
pub fn decide_automatic_restart(
    policy: &RestartPolicyV1,
    owner_lifecycle: RestartOwnerLifecycle,
    identity: RestartIdentityEvidence,
    failure: RestartFailureEvidence,
) -> Result<AutomaticRestartDecision, RuntimeContractError> {
    policy.validate()?;
    Ok(decide_restart_class(
        policy.restart_class,
        owner_lifecycle,
        identity,
        failure,
    ))
}

/// The restart class rule on its own, with no declared policy required.
///
/// This is the same rule [`decide_automatic_restart`] applies after it has
/// validated a whole declaration. It reads only the class and the owner's
/// observed evidence, so an owner that has declared a restart class binds the
/// rule at its own restart decision without also having to declare, or to
/// invent, the intensity values it does not own. Granting no budget and no
/// effect authority, an owner still has to satisfy this rule before its own
/// declared budget and effect paths may run.
///
/// The order of the three refusals is itself the rule:
/// 1. an owner that is quiescing, retiring, draining, cancelling or otherwise
///    not `Running` never gets an automatic replacement, so a deliberate
///    shutdown, cancellation or retirement cannot provoke a restart loop;
/// 2. a `Temporary` child never restarts automatically, whatever the evidence;
/// 3. missing or ambiguous exit identity is a refusal, not a default. It is
///    neither a proved normal exit nor a proved abnormal one, so it must not
///    permit a replacement under any class, including `Permanent`, whose rule
///    is "restart after any exit" and which must still refuse an exit it
///    cannot prove it observed.
pub fn decide_restart_class(
    restart_class: RestartClass,
    owner_lifecycle: RestartOwnerLifecycle,
    identity: RestartIdentityEvidence,
    failure: RestartFailureEvidence,
) -> AutomaticRestartDecision {
    if owner_lifecycle != RestartOwnerLifecycle::Running {
        return AutomaticRestartDecision::SuppressedByOwnerLifecycle;
    }
    if restart_class == RestartClass::Temporary {
        return AutomaticRestartDecision::TemporaryChild;
    }
    if identity != RestartIdentityEvidence::Exact {
        return AutomaticRestartDecision::BlockedByUncertainIdentity;
    }
    let eligible = match restart_class {
        RestartClass::Permanent => matches!(
            failure,
            RestartFailureEvidence::NormalExit | RestartFailureEvidence::AbnormalExit
        ),
        RestartClass::Transient => matches!(
            failure,
            RestartFailureEvidence::AbnormalExit | RestartFailureEvidence::FailedHealthContract
        ),
        RestartClass::Temporary => false,
    };
    if eligible {
        AutomaticRestartDecision::Eligible
    } else {
        AutomaticRestartDecision::NoMatchingFailureCondition
    }
}

/// Stable identity of exactly one restart operation.
///
/// Every field is the content the decision was made from, so the same decision
/// replayed by a recreated supervisor derives the same identity and the attempt
/// it reserved is never debited twice. Varying any field derives a different
/// identity, which costs a further attempt rather than granting a free one.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartOperationIdentity {
    /// Child the restart replaces.
    pub subject_id: String,
    /// Generation of the child being replaced.
    pub original_generation: ResourceGeneration,
    /// Exact state fence observed for the replaced child.
    pub original_state_fence: StateFence,
    /// Policy digest the decision was taken under.
    pub policy_digest: String,
    /// Exit/health evidence the decision was taken from.
    pub failure: RestartFailureEvidence,
    /// Declared dependents selected to join this recovery.
    pub selected_dependents: Vec<String>,
    /// Effects still unresolved on the replaced child.
    pub unresolved_effects: Vec<String>,
}

impl RestartOperationIdentity {
    /// Validates the identity content that participates in derivation.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(&self.subject_id, "subject_id")?;
        text(&self.policy_digest, "policy_digest")?;
        self.original_state_fence.validate()?;
        if self.original_generation != self.original_state_fence.resource_generation {
            return Err(invalid(
                "original_generation",
                "original generation must match the state fence generation",
            ));
        }
        unique_texts(&self.selected_dependents, "selected_dependents")?;
        if self
            .selected_dependents
            .iter()
            .any(|dependent| dependent == &self.subject_id)
        {
            return Err(invalid(
                "selected_dependents",
                "a child cannot be its own selected dependent",
            ));
        }
        unique_texts(&self.unresolved_effects, "unresolved_effects")?;
        Ok(())
    }

    /// Derives the stable operation identity from this exact content.
    pub fn derive(&self) -> Result<String, RestartPolicyError> {
        self.validate()?;
        Ok(sha256_hex(&canonical_json_bytes(self)?))
    }
}

/// Durable operational record of one decided restart. It is the value an owner
/// writes through its own compare-and-save path before any effect is dispatched.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartDecisionRecord {
    /// Content the operation identity is derived from.
    pub operation: RestartOperationIdentity,
    /// Derived operation identity; recomputed and compared on validation.
    pub restart_operation_id: String,
    /// Manifest revision the policy was read from.
    pub source_manifest_revision: u64,
    /// Profile revision the policy was read from.
    pub source_profile_revision: u64,
    /// Capacity class the replacement would consume.
    pub capacity_class: CapacityClass,
    /// Bottlenecks already exhausted for this child at decision time.
    pub exhausted_bottlenecks: Vec<CapacityBottleneck>,
    /// Monotonic decision instant in the owner's bound clock domain.
    pub decided_at_millis: u64,
    /// Earliest instant the owner may dispatch the next attempt.
    pub next_allowed_at_millis: u64,
}

impl RestartDecisionRecord {
    /// Validates the record against the policy it was decided under. The
    /// operation identity is recomputed from content and compared with the
    /// recorded value; a matching shape is not accepted as a match.
    pub fn validate_for(
        &self,
        policy: &RestartPolicyV1,
        admitted_generation: &ResourceGeneration,
        state_fence: &StateFence,
    ) -> Result<(), RestartPolicyError> {
        policy.validate()?;
        self.operation.validate()?;
        state_fence.validate().map_err(RuntimeContractError::from)?;
        if self.operation.subject_id != policy.subject_id
            || self.operation.original_state_fence != *state_fence
            || self.operation.original_generation != *admitted_generation
            || self.source_manifest_revision != policy.source_manifest_revision
            || self.source_profile_revision != policy.source_profile_revision
        {
            return Err(invalid(
                "restart_decision_record",
                "child, generation, state fence, or source revision does not match the policy",
            )
            .into());
        }
        if self.restart_operation_id != self.operation.derive()? {
            return Err(invalid(
                "restart_operation_id",
                "recorded operation identity does not match its own content",
            )
            .into());
        }
        if self.source_manifest_revision == 0 || self.source_profile_revision == 0 {
            return Err(invalid(
                "source_revision",
                "manifest and profile revisions must be non-zero",
            )
            .into());
        }
        if self.next_allowed_at_millis < self.decided_at_millis {
            return Err(invalid(
                "next_allowed_at_millis",
                "next allowed time must not precede the decision",
            )
            .into());
        }
        let mut bottlenecks = std::collections::HashSet::new();
        if self
            .exhausted_bottlenecks
            .iter()
            .any(|bottleneck| !bottlenecks.insert(*bottleneck))
        {
            return Err(invalid(
                "exhausted_bottlenecks",
                "exhausted bottlenecks must be unique",
            )
            .into());
        }
        Ok(())
    }
}

/// Dispatch state of one reserved attempt. A reserved attempt is never refunded:
/// a launch that failed still consumed its debit and stays retained as evidence.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartAttemptOutcome {
    /// Debited and awaiting dispatch; the dispatch result is not yet known.
    Reserved,
    /// Dispatch ran and the launch did not produce an admitted replacement.
    LaunchFailed,
    /// Dispatch ran and the replacement reached admitted identity.
    ReplacementAdmitted,
}

/// One debited attempt in the durable intensity history.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartAttemptRecord {
    /// Derived operation identity this debit belongs to.
    pub restart_operation_id: String,
    /// Child the attempt belongs to.
    pub subject_id: String,
    /// Monotonic instant the debit was taken.
    pub reserved_at_millis: u64,
    /// Earliest instant the next attempt may be dispatched.
    pub next_allowed_at_millis: u64,
    /// Effects still unresolved when the attempt was debited.
    pub unresolved_effects: Vec<String>,
    /// Dispatch state of the attempt.
    pub outcome: RestartAttemptOutcome,
}

impl RestartAttemptRecord {
    /// Validates one retained attempt.
    pub fn validate(&self, subject_id: &str) -> Result<(), RuntimeContractError> {
        text(&self.restart_operation_id, "restart_operation_id")?;
        if self.subject_id != subject_id {
            return Err(invalid(
                "subject_id",
                "retained attempt belongs to a different child",
            ));
        }
        if self.next_allowed_at_millis < self.reserved_at_millis {
            return Err(invalid(
                "next_allowed_at_millis",
                "next allowed time must not precede the reservation",
            ));
        }
        unique_texts(&self.unresolved_effects, "unresolved_effects")?;
        Ok(())
    }
}

/// Why a restart attempt was refused before dispatch.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartDenial {
    /// The declared quarantine threshold is already reached.
    Quarantined {
        /// Attempts counted in the current window.
        attempts_in_window: u32,
        /// Declared quarantine threshold.
        quarantine_after_attempts: u32,
    },
    /// The declared attempt budget for the window is exhausted.
    IntensityBudgetExhausted {
        /// Attempts counted in the current window.
        attempts_in_window: u32,
        /// Declared per-window attempt limit.
        max_attempts_in_window: u32,
    },
    /// Elapsed time is unknown or moved backwards against the durable window.
    ClockRegressed {
        /// Supplied monotonic instant.
        now_millis: u64,
        /// Durable window start the instant was compared against.
        window_started_at_millis: u64,
    },
}

/// Result of asking the durable ledger to reserve one attempt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartReservation {
    /// A new attempt was debited and may now be dispatched.
    Admitted(RestartAttemptRecord),
    /// This exact operation identity already holds a debit; nothing was charged.
    Replayed(RestartAttemptRecord),
    /// No attempt was debited.
    Denied(RestartDenial),
}

/// Durable restart-intensity ledger for one child under one policy digest.
///
/// The window start and every debited attempt live in this value, so a
/// recreated supervisor that reloads its owner's durable record continues the
/// same window instead of starting a fresh budget. No operation on this type
/// discards an attempt, so a fresh budget is never obtained by dropping history.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartIntensityLedger {
    /// Child this ledger accounts for.
    pub subject_id: String,
    /// Policy digest the attempts were debited under.
    pub policy_digest: String,
    /// Monotonic instant the current window opened.
    pub window_started_at_millis: u64,
    /// Whether the declared quarantine threshold has been reached.
    pub quarantined: bool,
    /// Retained attempt history, oldest first.
    pub attempts: Vec<RestartAttemptRecord>,
}

impl RestartIntensityLedger {
    /// Creates the ledger for a child that has no recorded attempt yet.
    pub fn unbound(
        subject_id: &str,
        policy_digest: &str,
        window_started_at_millis: u64,
    ) -> Result<Self, RestartPolicyError> {
        text(subject_id, "subject_id")?;
        text(policy_digest, "policy_digest")?;
        Ok(Self {
            subject_id: subject_id.to_owned(),
            policy_digest: policy_digest.to_owned(),
            window_started_at_millis,
            quarantined: false,
            attempts: Vec::new(),
        })
    }

    /// Validates the retained history against this ledger's own identity.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        text(&self.subject_id, "subject_id")?;
        text(&self.policy_digest, "policy_digest")?;
        let mut operation_ids = std::collections::BTreeSet::new();
        for attempt in &self.attempts {
            attempt.validate(&self.subject_id)?;
            if !operation_ids.insert(&attempt.restart_operation_id) {
                return Err(invalid(
                    "attempts",
                    "an operation identity is debited more than once",
                ));
            }
        }
        Ok(())
    }

    /// The single definition of the current window endpoint.
    pub fn window_endpoint_millis(&self, window_millis: u64) -> u64 {
        self.window_started_at_millis.saturating_add(window_millis)
    }

    /// Counts the debits that fall inside the current window.
    pub fn attempts_in_window(&self) -> u32 {
        let count = self
            .attempts
            .iter()
            .filter(|attempt| attempt.reserved_at_millis >= self.window_started_at_millis)
            .count();
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// Opens the next window once the current one has elapsed. Attempts are
    /// never discarded here, so rolling the window cannot erase failed history
    /// or the unresolved effects it carries.
    pub fn roll_window(
        &mut self,
        now_millis: u64,
        window_millis: u64,
    ) -> Result<bool, RestartPolicyError> {
        if now_millis < self.window_started_at_millis {
            return Err(invalid(
                "now_millis",
                "elapsed time moved backwards against the durable window start",
            )
            .into());
        }
        if now_millis < self.window_endpoint_millis(window_millis) {
            return Ok(false);
        }
        self.window_started_at_millis = now_millis;
        Ok(true)
    }

    /// Reserves one attempt for `decision` before any effect is dispatched.
    ///
    /// Reservation is idempotent on the derived operation identity, so replaying
    /// the same decision never debits twice. The window is rolled from the
    /// supplied monotonic instant only; a backwards instant is refused rather
    /// than treated as elapsed time.
    pub fn reserve_attempt(
        &mut self,
        policy: &RestartPolicyV1,
        decision: &RestartDecisionRecord,
        admitted_generation: &ResourceGeneration,
        state_fence: &StateFence,
        now_millis: u64,
    ) -> Result<RestartReservation, RestartPolicyError> {
        decision.validate_for(policy, admitted_generation, state_fence)?;
        self.validate()?;
        if self.subject_id != decision.operation.subject_id
            || self.policy_digest != decision.operation.policy_digest
        {
            return Err(invalid(
                "restart_intensity_ledger",
                "decision and durable ledger cover a different child or policy",
            )
            .into());
        }
        if now_millis < self.window_started_at_millis {
            return Ok(RestartReservation::Denied(RestartDenial::ClockRegressed {
                now_millis,
                window_started_at_millis: self.window_started_at_millis,
            }));
        }
        if let Some(existing) = self
            .attempts
            .iter()
            .find(|attempt| attempt.restart_operation_id == decision.restart_operation_id)
        {
            return Ok(RestartReservation::Replayed(existing.clone()));
        }
        self.roll_window(now_millis, policy.intensity.window_millis)?;
        let attempts_in_window = self.attempts_in_window();
        if self.quarantined || attempts_in_window >= policy.intensity.quarantine_after_attempts {
            self.quarantined = true;
            return Ok(RestartReservation::Denied(RestartDenial::Quarantined {
                attempts_in_window,
                quarantine_after_attempts: policy.intensity.quarantine_after_attempts,
            }));
        }
        if attempts_in_window >= policy.intensity.max_attempts_in_window {
            return Ok(RestartReservation::Denied(
                RestartDenial::IntensityBudgetExhausted {
                    attempts_in_window,
                    max_attempts_in_window: policy.intensity.max_attempts_in_window,
                },
            ));
        }
        let attempt = RestartAttemptRecord {
            restart_operation_id: decision.restart_operation_id.clone(),
            subject_id: self.subject_id.clone(),
            reserved_at_millis: now_millis,
            next_allowed_at_millis: decision.next_allowed_at_millis,
            unresolved_effects: decision.operation.unresolved_effects.clone(),
            outcome: RestartAttemptOutcome::Reserved,
        };
        self.attempts.push(attempt.clone());
        Ok(RestartReservation::Admitted(attempt))
    }

    /// Records that the reserved attempt's launch did not produce an admitted
    /// replacement. The debit is kept: a failed launch is charged once and is
    /// never refunded, and the attempt stays retained as the failed evidence.
    pub fn record_launch_failure(
        &mut self,
        restart_operation_id: &str,
    ) -> Result<RestartAttemptRecord, RestartPolicyError> {
        let attempt = self
            .attempts
            .iter_mut()
            .find(|attempt| attempt.restart_operation_id == restart_operation_id)
            .ok_or_else(|| {
                RestartPolicyError::from(invalid(
                    "restart_operation_id",
                    "no reserved attempt carries this operation identity",
                ))
            })?;
        attempt.outcome = RestartAttemptOutcome::LaunchFailed;
        Ok(attempt.clone())
    }

    /// Records that the reserved attempt reached admitted replacement identity.
    pub fn record_replacement_admitted(
        &mut self,
        restart_operation_id: &str,
    ) -> Result<RestartAttemptRecord, RestartPolicyError> {
        let attempt = self
            .attempts
            .iter_mut()
            .find(|attempt| attempt.restart_operation_id == restart_operation_id)
            .ok_or_else(|| {
                RestartPolicyError::from(invalid(
                    "restart_operation_id",
                    "no reserved attempt carries this operation identity",
                ))
            })?;
        attempt.outcome = RestartAttemptOutcome::ReplacementAdmitted;
        Ok(attempt.clone())
    }

    /// Binds a new policy revision. The whole retained history and the
    /// quarantine disposition carry over, so a new revision cannot erase the
    /// failed attempts that led here.
    pub fn rebind_policy(&mut self, policy_digest: &str) -> Result<(), RestartPolicyError> {
        text(policy_digest, "policy_digest")?;
        self.policy_digest.clone_from(&policy_digest.to_owned());
        Ok(())
    }

    /// Drops retained attempts beyond the owner's retention limit, keeping
    /// everything needed to prove the current intensity and every unresolved
    /// effect. Pruning is never a precondition for admitting an attempt.
    pub fn prune_history(
        &mut self,
        retain_limit: usize,
        now_millis: u64,
    ) -> Result<usize, RestartPolicyError> {
        if now_millis < self.window_started_at_millis {
            return Err(invalid(
                "now_millis",
                "elapsed time moved backwards against the durable window start",
            )
            .into());
        }
        let total = self.attempts.len();
        let mut keep = vec![false; total];
        for (index, attempt) in self.attempts.iter().enumerate() {
            keep[index] = attempt.reserved_at_millis >= self.window_started_at_millis
                || attempt.outcome == RestartAttemptOutcome::Reserved
                || !attempt.unresolved_effects.is_empty();
        }
        let mut retained = 0usize;
        for index in (0..total).rev() {
            if keep[index] {
                continue;
            }
            if retained < retain_limit {
                keep[index] = true;
                retained += 1;
            }
        }
        let dropped = keep.iter().filter(|keep| !**keep).count();
        let mut attempts = Vec::with_capacity(total - dropped);
        for (attempt, retained) in self.attempts.iter().zip(keep) {
            if retained {
                attempts.push(attempt.clone());
            }
        }
        self.attempts = attempts;
        Ok(dropped)
    }
}

fn unique_texts(values: &[String], field: &'static str) -> Result<(), RuntimeContractError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value) {
            return Err(invalid(field, "values must be unique"));
        }
    }
    Ok(())
}

fn text(value: &str, field: &'static str) -> Result<(), RuntimeContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(invalid(
            field,
            "must be non-blank and contain no control characters",
        ));
    }
    Ok(())
}

fn invalid(field: &'static str, reason: &'static str) -> RuntimeContractError {
    RuntimeContractError::InvalidField { field, reason }
}
