//! I7.21 role-to-capability compilation bound to the transport lease.
//!
//! The I7.21 default agent role capability profiles are defaults compiled
//! into capability tokens at admission and at every role transition; a role
//! name never grants authority by itself. This module is the server-enforced
//! policy: [`compile_capability`] intersects the role default with `WorkScope`
//! narrowing and delegated authority, binds the result to the exact role,
//! scope, task/work item, route, `GovernanceProfile` revision, `State Fence`
//! (authority epoch), lease epoch and expiry, and [`CapabilityContext`]
//! revokes the preceding capability context on every explicit
//! [`CapabilityContext::transition`], updating the [`IndependenceProfile`].
//!
//! This type is transport-neutral: it invents no clock and no identity. The
//! owner supplies `context_id`, lease epochs and owner-observed Unix
//! milliseconds; validation fails closed on every mismatch.
//!
//! Scope: issue #1943. Only the Task Controller, Worker and Verifier Agent
//! profiles named by the acceptance criteria are encoded; no other role
//! label exists in this vocabulary, so no other label can authorize.

use std::collections::BTreeSet;
use std::fmt;

use eliot_contracts::EpochId;
use thiserror::Error;

/// Closed operation vocabulary enforced by [`CapabilityToken::authorize`].
///
/// Any operation outside this vocabulary is denied: unknown strings can
/// never authorize, so a role label cannot smuggle authority through an
/// unlisted operation name.
pub mod op {
    /// Observe bridge state.
    pub const STATE_READ: &str = "state.read";
    /// Observe the delegated work graph (Task Controller envelope only).
    pub const WORKGRAPH_READ: &str = "workgraph.read";
    /// Read the current plan revision.
    pub const PLAN_READ: &str = "plan.read";
    /// Revise the current plan revision inside the delegated task envelope.
    pub const PLAN_REVISE: &str = "plan.revise";
    /// Overwrite the active plan outside the controller envelope.
    pub const PLAN_OVERWRITE: &str = "plan.overwrite";
    /// Assign or reassign work inside the delegated task envelope.
    pub const TASK_ASSIGN: &str = "task.assign";
    /// Propose a bounded task disposition (never a finish).
    pub const TASK_DISPOSITION_PROPOSE: &str = "task.disposition.propose";
    /// Finish the task (I7.9 strict finish; never implied by a role label).
    pub const TASK_FINISH: &str = "task.finish";
    /// Redefine the user outcome objective.
    pub const OUTCOME_REDEFINE: &str = "outcome.redefine";
    /// Execute an effect without an Action Lease.
    pub const EFFECT_EXECUTE: &str = "effect.execute";
    /// Execute an effect covered by a Worktree/Action Lease.
    pub const EFFECT_LEASE_COVERED: &str = "effect.lease_covered";
    /// Deploy a module generation.
    pub const MODULE_DEPLOY: &str = "module.deploy";
    /// Write installation or Architecture policy.
    pub const POLICY_WRITE: &str = "policy.write";
    /// Write a schema.
    pub const SCHEMA_WRITE: &str = "schema.write";
    /// Promote a claim to truth or proof by assertion.
    pub const PROOF_PROMOTE: &str = "proof.promote";
    /// Read a packet bundle.
    pub const PACKET_READ: &str = "packet.read";
    /// Run a query.
    pub const QUERY: &str = "query";
    /// Observe without mutating.
    pub const OBSERVE: &str = "observe";
    /// Coordinate with other agents.
    pub const COORDINATE: &str = "coordinate";
    /// Act on the assigned work item only.
    pub const WORK_ITEM_ACT: &str = "work.item.act";
    /// Submit evidence or observations.
    pub const EVIDENCE_SUBMIT: &str = "evidence.submit";
    /// Submit a candidate result.
    pub const RESULT_CANDIDATE_SUBMIT: &str = "result.candidate.submit";
    /// Write outside the assigned paths.
    pub const PATH_UNRELATED_WRITE: &str = "path.unrelated.write";
    /// Run verification within the Evaluation Contract.
    pub const VERIFY: &str = "verify";
    /// Create a scoped evaluation candidate.
    pub const EVALUATION_CANDIDATE_CREATE: &str = "evaluation.candidate.create";
    /// Record a `VerificationRun` for a registered verifier ID.
    pub const VERIFICATION_RUN: &str = "verification.run";
    /// Mutate the implementation under judgement.
    pub const IMPLEMENTATION_MUTATE: &str = "implementation.mutate";
    /// Redefine acceptance criteria.
    pub const ACCEPTANCE_REDEFINE: &str = "acceptance.redefine";
    /// Redefine the verifier set.
    pub const VERIFIER_REDEFINE: &str = "verifier.redefine";
    /// Read budgets inside the delegated envelope.
    pub const BUDGET_READ: &str = "budget.read";
    /// Read conflicts inside the delegated envelope.
    pub const CONFLICT_READ: &str = "conflict.read";
    /// Coordinate agents inside the delegated envelope.
    pub const AGENT_COORDINATE: &str = "agent.coordinate";
}

/// Every operation this policy understands. Anything else is denied.
const KNOWN_OPERATIONS: &[&str] = &[
    op::STATE_READ,
    op::WORKGRAPH_READ,
    op::PLAN_READ,
    op::PLAN_REVISE,
    op::PLAN_OVERWRITE,
    op::TASK_ASSIGN,
    op::TASK_DISPOSITION_PROPOSE,
    op::TASK_FINISH,
    op::OUTCOME_REDEFINE,
    op::EFFECT_EXECUTE,
    op::EFFECT_LEASE_COVERED,
    op::MODULE_DEPLOY,
    op::POLICY_WRITE,
    op::SCHEMA_WRITE,
    op::PROOF_PROMOTE,
    op::PACKET_READ,
    op::QUERY,
    op::OBSERVE,
    op::COORDINATE,
    op::WORK_ITEM_ACT,
    op::EVIDENCE_SUBMIT,
    op::RESULT_CANDIDATE_SUBMIT,
    op::PATH_UNRELATED_WRITE,
    op::VERIFY,
    op::EVALUATION_CANDIDATE_CREATE,
    op::VERIFICATION_RUN,
    op::IMPLEMENTATION_MUTATE,
    op::ACCEPTANCE_REDEFINE,
    op::VERIFIER_REDEFINE,
    op::BUDGET_READ,
    op::CONFLICT_READ,
    op::AGENT_COORDINATE,
];

/// Agent roles with compiled capability profiles (I7.21, acceptance subset).
///
/// There is deliberately no catch-all or stringly-typed role: an unknown
/// role label cannot be constructed, so it can never authorize.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AgentRole {
    /// Current plan revision, assignment and bounded disposition proposals
    /// inside the delegated task envelope.
    TaskController,
    /// Lease-covered effects for the assigned item only.
    Worker,
    /// Scoped evaluation candidates and registered verifier runs only.
    Verifier,
}

impl fmt::Display for AgentRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::TaskController => "task-controller",
            Self::Worker => "worker",
            Self::Verifier => "verifier",
        };
        formatter.write_str(name)
    }
}

impl AgentRole {
    /// Parses an exact role label. Unknown labels are rejected so they can
    /// never authorize by name.
    ///
    /// # Errors
    ///
    /// Returns [`RoleLeaseError::UnknownRole`] for any other label.
    pub fn parse(label: &str) -> Result<Self, RoleLeaseError> {
        match label {
            "task-controller" => Ok(Self::TaskController),
            "worker" => Ok(Self::Worker),
            Self::VERIFIER_LABEL => Ok(Self::Verifier),
            _ => Err(RoleLeaseError::UnknownRole {
                label: label.to_owned(),
            }),
        }
    }

    const VERIFIER_LABEL: &'static str = "verifier";

    /// Whether this role may hold mutation authority after an explicit
    /// independence downgrade. Only [`AgentRole::Worker`] does; the
    /// verifier never mutates under its own context.
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        matches!(self, Self::Worker)
    }

    /// I7.21 normal-operation plus mutation-ceiling operations for this role.
    fn default_allow(self) -> &'static [&'static str] {
        match self {
            Self::TaskController => &[
                op::STATE_READ,
                op::WORKGRAPH_READ,
                op::PLAN_READ,
                op::PLAN_REVISE,
                op::TASK_ASSIGN,
                op::TASK_DISPOSITION_PROPOSE,
                op::BUDGET_READ,
                op::CONFLICT_READ,
                op::AGENT_COORDINATE,
            ],
            Self::Worker => &[
                op::STATE_READ,
                op::PACKET_READ,
                op::QUERY,
                op::OBSERVE,
                op::COORDINATE,
                op::WORK_ITEM_ACT,
                op::EVIDENCE_SUBMIT,
                op::RESULT_CANDIDATE_SUBMIT,
                op::EFFECT_LEASE_COVERED,
            ],
            Self::Verifier => &[
                op::STATE_READ,
                op::QUERY,
                op::VERIFY,
                op::OBSERVE,
                op::EVALUATION_CANDIDATE_CREATE,
                op::VERIFICATION_RUN,
            ],
        }
    }

    /// I7.21 explicitly forbidden operations for this role. These deny even
    /// if a narrowing set attempts to grant them.
    fn default_forbid(self) -> &'static [&'static str] {
        match self {
            Self::TaskController => &[
                op::OUTCOME_REDEFINE,
                op::TASK_FINISH,
                op::EFFECT_EXECUTE,
                op::MODULE_DEPLOY,
                op::POLICY_WRITE,
                op::PROOF_PROMOTE,
                op::PLAN_OVERWRITE,
                op::IMPLEMENTATION_MUTATE,
            ],
            Self::Worker => &[
                op::TASK_FINISH,
                op::PLAN_OVERWRITE,
                op::PLAN_REVISE,
                op::POLICY_WRITE,
                op::SCHEMA_WRITE,
                op::PATH_UNRELATED_WRITE,
                op::OUTCOME_REDEFINE,
                op::EFFECT_EXECUTE,
                op::TASK_ASSIGN,
            ],
            Self::Verifier => &[
                op::ACCEPTANCE_REDEFINE,
                op::VERIFIER_REDEFINE,
                op::IMPLEMENTATION_MUTATE,
                op::TASK_FINISH,
                op::PROOF_PROMOTE,
                op::PLAN_OVERWRITE,
                op::PLAN_REVISE,
                op::EFFECT_EXECUTE,
                op::EFFECT_LEASE_COVERED,
                op::WORK_ITEM_ACT,
            ],
        }
    }

    /// Whether this role requires a bound work item. Worker and verifier
    /// authority is meaningless without the exact item under judgement.
    const fn requires_work_item(self) -> bool {
        matches!(self, Self::Worker | Self::Verifier)
    }
}

/// Exact binding compiled into a capability token (I7.21 lease identity).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeBinding {
    /// Narrow role scope (e.g. task envelope or evaluation scope).
    pub scope: String,
    /// Exact task identifier.
    pub task_id: String,
    /// Exact work item; required for Worker and Verifier roles.
    pub work_item_id: Option<String>,
    /// Exact route the capability is valid on.
    pub route: String,
    /// `GovernanceProfile` revision the capability was compiled against.
    pub governance_revision: String,
    /// State Fence authority epoch the capability is bound to.
    pub authority_epoch: EpochId,
    /// Owner-assigned lease epoch; bumped on every role transition.
    pub lease_epoch: u64,
    /// Owner-observed issuance time (Unix ms).
    pub issued_at_unix_ms: u64,
    /// Owner-observed expiry (Unix ms); must exceed issuance.
    pub expires_at_unix_ms: u64,
}

/// `WorkScope` policy narrowing: an optional allow-subset intersected with the
/// role default. `None` means no narrowing. `WorkScope` may only narrow; it
/// can never widen a role default.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkScopePolicy {
    /// Subset of operations the `WorkScope` admits, or `None` for no narrowing.
    pub allow_subset: Option<BTreeSet<String>>,
}

/// Delegated authority narrowing: an optional allow-subset intersected with
/// the role default. Delegation may only narrow; it can never widen.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DelegatedAuthority {
    /// Subset of operations the delegation carries, or `None` for no narrowing.
    pub allow_subset: Option<BTreeSet<String>>,
}

/// Explicit separated-role / independence downgrade record.
///
/// A verifier that must implement requires a newly issued, explicitly
/// downgraded role context; this record is that proof. Without it, a
/// Verifier-to-Worker transition is rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndependenceDowngrade {
    /// Role being left (must equal the active context role).
    pub from_role: AgentRole,
    /// Role being entered (must be a mutating role).
    pub to_role: AgentRole,
    /// Owner-recorded reason for the downgrade.
    pub reason: String,
    /// Owner-observed record time (Unix ms).
    pub recorded_at_unix_ms: u64,
}

/// Non-ordinal independence profile updated on every role transition.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IndependenceProfile {
    /// Roles held in order, including the active one.
    pub roles_held: Vec<AgentRole>,
    /// Whether independence was ever explicitly downgraded.
    pub downgraded: bool,
    /// Explicit downgrade records, in order.
    pub downgrade_records: Vec<IndependenceDowngrade>,
}

/// Server-issued capability token: compiled role authority for one lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityToken {
    /// Owner-assigned capability context identity.
    context_id: String,
    /// Exact role this token carries.
    role: AgentRole,
    /// Exact binding this token is valid for.
    binding: ScopeBinding,
    /// Compiled allow set: role default narrowed by policy/delegation.
    allowed: BTreeSet<String>,
    /// Compiled forbid set: role forbidden operations, always denied.
    forbidden: BTreeSet<String>,
    /// Whether this context was closed by a later transition.
    revoked: bool,
    /// Context that superseded this one, when revoked by transition.
    superseded_by: Option<String>,
}

impl CapabilityToken {
    /// Returns the capability context identity.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the exact role this token carries.
    #[must_use]
    pub const fn role(&self) -> AgentRole {
        self.role
    }

    /// Returns the exact binding this token is valid for.
    #[must_use]
    pub const fn binding(&self) -> &ScopeBinding {
        &self.binding
    }

    /// Returns the compiled allow set.
    #[must_use]
    pub const fn allowed(&self) -> &BTreeSet<String> {
        &self.allowed
    }

    /// Returns the compiled forbid set.
    #[must_use]
    pub const fn forbidden(&self) -> &BTreeSet<String> {
        &self.forbidden
    }

    /// Returns whether this context was closed by a later transition.
    #[must_use]
    pub const fn revoked(&self) -> bool {
        self.revoked
    }

    /// Server-enforced authorization for one operation.
    ///
    /// `now_unix_ms` is owner-observed time; this function invents no clock.
    /// Denies when the context is revoked, the lease expired, the operation
    /// is unknown, or the operation is not in the compiled allow set. The
    /// forbid set denies even if the allow set somehow names the operation:
    /// a role label can never authorize a forbidden operation.
    ///
    /// # Errors
    ///
    /// Returns the exact denial reason; every denial fails closed.
    pub fn authorize(&self, operation: &str, now_unix_ms: u64) -> Result<(), RoleLeaseError> {
        if self.revoked {
            return Err(RoleLeaseError::ContextRevoked {
                context_id: self.context_id.clone(),
            });
        }
        if now_unix_ms >= self.binding.expires_at_unix_ms {
            return Err(RoleLeaseError::LeaseExpired {
                context_id: self.context_id.clone(),
            });
        }
        if !KNOWN_OPERATIONS.contains(&operation) {
            return Err(RoleLeaseError::UnknownOperation {
                operation: operation.to_owned(),
            });
        }
        if self.forbidden.contains(operation) {
            return Err(RoleLeaseError::ForbiddenOperation {
                role: self.role,
                operation: operation.to_owned(),
            });
        }
        if self.allowed.contains(operation) {
            Ok(())
        } else {
            Err(RoleLeaseError::NotAuthorized {
                role: self.role,
                operation: operation.to_owned(),
            })
        }
    }
}

/// Explicit role-transition record: closes one context, opens the next.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleTransitionRecord {
    /// Closed capability context.
    pub prev_context_id: String,
    /// Newly scoped capability context.
    pub new_context_id: String,
    /// Role left behind; its authority no longer applies.
    pub prev_role: AgentRole,
    /// Newly entered role.
    pub new_role: AgentRole,
    /// Lease epoch of the new context.
    pub lease_epoch: u64,
    /// Whether an explicit independence downgrade authorized this move.
    pub independence_downgraded: bool,
}

/// Live capability context: exactly one active token plus its history.
///
/// A single model process may perform several roles sequentially, but every
/// transition creates a new scoped capability context and updates the
/// independence profile; stronger authority from a previous role is revoked,
/// never silently retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityContext {
    active: CapabilityToken,
    revoked: Vec<CapabilityToken>,
    independence: IndependenceProfile,
    transitions: Vec<RoleTransitionRecord>,
}

impl CapabilityContext {
    /// Admits the first capability context for a process.
    ///
    /// # Errors
    ///
    /// Returns [`RoleLeaseError`] when compilation fails closed.
    pub fn admit(
        context_id: impl Into<String>,
        role: AgentRole,
        binding: ScopeBinding,
        workscope: &WorkScopePolicy,
        delegated: &DelegatedAuthority,
    ) -> Result<Self, RoleLeaseError> {
        let token = compile_capability(context_id, role, binding, workscope, delegated)?;
        let mut independence = IndependenceProfile::default();
        independence.roles_held.push(role);
        Ok(Self {
            active: token,
            revoked: Vec::new(),
            independence,
            transitions: Vec::new(),
        })
    }

    /// Returns the active capability token.
    #[must_use]
    pub const fn active(&self) -> &CapabilityToken {
        &self.active
    }

    /// Returns revoked (closed) capability contexts, in revocation order.
    #[must_use]
    pub const fn revoked(&self) -> &Vec<CapabilityToken> {
        &self.revoked
    }

    /// Returns the independence profile.
    #[must_use]
    pub const fn independence(&self) -> &IndependenceProfile {
        &self.independence
    }

    /// Returns the transition history, in order.
    #[must_use]
    pub const fn transitions(&self) -> &Vec<RoleTransitionRecord> {
        &self.transitions
    }

    /// Performs an explicit role transition.
    ///
    /// The preceding capability context is closed and revoked, a newly
    /// scoped context is created at `binding.lease_epoch` (which must exceed
    /// the active lease epoch), and the independence profile is updated. A
    /// Verifier moving to a mutating role requires an explicit
    /// [`IndependenceDowngrade`] record; without it the transition is
    /// rejected, so verifier self-implementation is impossible under the
    /// verifier context or by silent role relabeling.
    ///
    /// # Errors
    ///
    /// Returns [`RoleLeaseError`] when the downgrade proof is missing, the
    /// lease epoch does not advance, or compilation fails closed.
    #[allow(clippy::too_many_arguments)]
    pub fn transition(
        &mut self,
        new_context_id: impl Into<String>,
        new_role: AgentRole,
        new_binding: &ScopeBinding,
        workscope: &WorkScopePolicy,
        delegated: &DelegatedAuthority,
        downgrade: Option<IndependenceDowngrade>,
        now_unix_ms: u64,
    ) -> Result<RoleTransitionRecord, RoleLeaseError> {
        let prev_role = self.active.role;
        let downgraded = match (&prev_role, new_role, downgrade) {
            (AgentRole::Verifier, to, None) if to.is_mutating() => {
                return Err(RoleLeaseError::DowngradeRecordRequired {
                    from: prev_role,
                    to,
                });
            }
            (AgentRole::Verifier, to, Some(record)) if to.is_mutating() => {
                record.validate(prev_role, new_role, now_unix_ms)?;
                self.independence.downgraded = true;
                self.independence.downgrade_records.push(record);
                true
            }
            (_, _, Some(record)) => {
                record.validate(prev_role, new_role, now_unix_ms)?;
                self.independence.downgraded = true;
                self.independence.downgrade_records.push(record);
                true
            }
            (_, _, None) => false,
        };
        if new_binding.lease_epoch <= self.active.binding.lease_epoch {
            return Err(RoleLeaseError::LeaseEpochNotAdvanced {
                prev: self.active.binding.lease_epoch,
                next: new_binding.lease_epoch,
            });
        }
        let new_context_id = new_context_id.into();
        validate_context_id(&new_context_id)?;
        if new_context_id == self.active.context_id {
            return Err(RoleLeaseError::ContextIdReused {
                context_id: new_context_id,
            });
        }
        let token = compile_capability(
            new_context_id.clone(),
            new_role,
            new_binding.clone(),
            workscope,
            delegated,
        )?;
        let record = RoleTransitionRecord {
            prev_context_id: self.active.context_id.clone(),
            new_context_id: new_context_id.clone(),
            prev_role,
            new_role,
            lease_epoch: new_binding.lease_epoch,
            independence_downgraded: downgraded,
        };
        let prev = CapabilityToken {
            revoked: true,
            superseded_by: Some(new_context_id),
            ..self.active.clone()
        };
        self.revoked.push(prev);
        self.active = token;
        self.independence.roles_held.push(new_role);
        self.transitions.push(record.clone());
        Ok(record)
    }
}

impl IndependenceDowngrade {
    /// Validates that this record authorizes exactly `from -> to` at `now`.
    ///
    /// # Errors
    ///
    /// Returns [`RoleLeaseError`] on any mismatch; silence is not permission.
    pub fn validate(
        &self,
        from: AgentRole,
        to: AgentRole,
        now_unix_ms: u64,
    ) -> Result<(), RoleLeaseError> {
        if self.from_role != from || self.to_role != to {
            return Err(RoleLeaseError::DowngradeMismatch {
                expected_from: from,
                expected_to: to,
            });
        }
        if !self.to_role.is_mutating() {
            return Err(RoleLeaseError::DowngradeTargetNotMutating { to: self.to_role });
        }
        validate_non_empty("reason", &self.reason)?;
        if self.recorded_at_unix_ms > now_unix_ms {
            return Err(RoleLeaseError::DowngradeNotYetRecorded {
                recorded_at_unix_ms: self.recorded_at_unix_ms,
            });
        }
        Ok(())
    }
}

/// Failures of role-lease compilation, transition and authorization.
///
/// Every variant fails closed: no denial implies a narrower permission.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum RoleLeaseError {
    /// The role label is not part of the I7.21 acceptance vocabulary.
    #[error("unknown role label {label:?}: role names never grant authority")]
    UnknownRole {
        /// The rejected label.
        label: String,
    },
    /// A required text binding is empty or carries control characters.
    #[error("invalid binding {field:?}: empty or control characters")]
    InvalidBinding {
        /// Binding field name.
        field: &'static str,
    },
    /// A capability context identity is empty or carries control characters.
    #[error("invalid capability context identity: empty or control characters")]
    InvalidContextId,
    /// A capability context identity was reused across a transition.
    #[error(
        "capability context identity {context_id:?} reused: transitions must mint a new context"
    )]
    ContextIdReused {
        /// The reused identity.
        context_id: String,
    },
    /// Expiry does not exceed issuance.
    #[error("lease expiry {expires_at_unix_ms} does not exceed issuance {issued_at_unix_ms}")]
    InvalidLeaseWindow {
        /// Owner-observed issuance time.
        issued_at_unix_ms: u64,
        /// Owner-observed expiry.
        expires_at_unix_ms: u64,
    },
    /// The role requires a bound work item and none was supplied.
    #[error("role {role} requires a bound work item")]
    WorkItemRequired {
        /// The role.
        role: AgentRole,
    },
    /// `WorkScope` or delegation attempted to grant a forbidden operation.
    #[error("narrowing set attempted to grant forbidden operation {operation:?} for role {role}")]
    ForbiddenGrantAttempted {
        /// The role.
        role: AgentRole,
        /// The rejected operation.
        operation: String,
    },
    /// `WorkScope` or delegation named an unknown operation.
    #[error("narrowing set named unknown operation {operation:?}")]
    UnknownNarrowingOperation {
        /// The rejected operation.
        operation: String,
    },
    /// The new lease epoch does not exceed the active one.
    #[error("lease epoch {next} does not advance past {prev}")]
    LeaseEpochNotAdvanced {
        /// Active lease epoch.
        prev: u64,
        /// Proposed lease epoch.
        next: u64,
    },
    /// A verifier moving to a mutating role supplied no downgrade record.
    #[error(
        "role transition {from} -> {to} requires an explicit separated-role/independence downgrade record"
    )]
    DowngradeRecordRequired {
        /// Role left behind.
        from: AgentRole,
        /// Role entered.
        to: AgentRole,
    },
    /// The downgrade record does not match the performed transition.
    #[error("downgrade record authorizes {expected_from} -> {expected_to}")]
    DowngradeMismatch {
        /// Expected source role.
        expected_from: AgentRole,
        /// Expected target role.
        expected_to: AgentRole,
    },
    /// The downgrade target cannot mutate, so no downgrade applies.
    #[error("downgrade target {to} is not a mutating role")]
    DowngradeTargetNotMutating {
        /// Proposed target role.
        to: AgentRole,
    },
    /// The downgrade record is dated after the owner-observed now.
    #[error("downgrade recorded at {recorded_at_unix_ms}, after owner-observed now")]
    DowngradeNotYetRecorded {
        /// Record time.
        recorded_at_unix_ms: u64,
    },
    /// Authorization against a revoked (transition-closed) context.
    #[error("capability context {context_id:?} revoked by role transition")]
    ContextRevoked {
        /// The closed context.
        context_id: String,
    },
    /// Authorization after lease expiry.
    #[error("capability context {context_id:?} lease expired")]
    LeaseExpired {
        /// The expired context.
        context_id: String,
    },
    /// The operation is outside the closed vocabulary.
    #[error("unknown operation {operation:?}: denied")]
    UnknownOperation {
        /// The rejected operation.
        operation: String,
    },
    /// The operation is explicitly forbidden for this role.
    #[error("operation {operation:?} forbidden for role {role}: role labels cannot authorize it")]
    ForbiddenOperation {
        /// The role.
        role: AgentRole,
        /// The rejected operation.
        operation: String,
    },
    /// The operation is outside the compiled allow set.
    #[error("operation {operation:?} not authorized for role {role}")]
    NotAuthorized {
        /// The role.
        role: AgentRole,
        /// The rejected operation.
        operation: String,
    },
}

/// Compiles role defaults into a server-enforced capability token.
///
/// The allow set is `default(role) ∩ workscope ∩ delegated`; `WorkScope` and
/// delegation may only narrow. Any attempt to grant a forbidden or unknown
/// operation fails closed. The token binds the exact role, scope,
/// task/work item, route, `GovernanceProfile` revision, `State Fence` authority
/// epoch, lease epoch and expiry.
///
/// # Errors
///
/// Returns [`RoleLeaseError`] when any binding or narrowing input is invalid.
pub fn compile_capability(
    context_id: impl Into<String>,
    role: AgentRole,
    binding: ScopeBinding,
    workscope: &WorkScopePolicy,
    delegated: &DelegatedAuthority,
) -> Result<CapabilityToken, RoleLeaseError> {
    let context_id = context_id.into();
    validate_context_id(&context_id)?;
    validate_binding(role, &binding)?;
    for narrowing in [
        workscope.allow_subset.as_ref(),
        delegated.allow_subset.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        for operation in narrowing {
            if !KNOWN_OPERATIONS.contains(&operation.as_str()) {
                return Err(RoleLeaseError::UnknownNarrowingOperation {
                    operation: operation.clone(),
                });
            }
            if role.default_forbid().contains(&operation.as_str()) {
                return Err(RoleLeaseError::ForbiddenGrantAttempted {
                    role,
                    operation: operation.clone(),
                });
            }
        }
    }
    let mut allowed: BTreeSet<String> = role
        .default_allow()
        .iter()
        .map(|item| (*item).to_owned())
        .collect();
    if let Some(narrow) = workscope.allow_subset.as_ref() {
        allowed.retain(|item| narrow.contains(item));
    }
    if let Some(narrow) = delegated.allow_subset.as_ref() {
        allowed.retain(|item| narrow.contains(item));
    }
    let forbidden: BTreeSet<String> = role
        .default_forbid()
        .iter()
        .map(|item| (*item).to_owned())
        .collect();
    allowed.retain(|item| !forbidden.contains(item));
    Ok(CapabilityToken {
        context_id,
        role,
        binding,
        allowed,
        forbidden,
        revoked: false,
        superseded_by: None,
    })
}

fn validate_non_empty(field: &'static str, value: &str) -> Result<(), RoleLeaseError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(RoleLeaseError::InvalidBinding { field });
    }
    Ok(())
}

fn validate_context_id(context_id: &str) -> Result<(), RoleLeaseError> {
    if context_id.trim().is_empty() || context_id.chars().any(char::is_control) {
        return Err(RoleLeaseError::InvalidContextId);
    }
    Ok(())
}

fn validate_binding(role: AgentRole, binding: &ScopeBinding) -> Result<(), RoleLeaseError> {
    validate_non_empty("scope", &binding.scope)?;
    validate_non_empty("task_id", &binding.task_id)?;
    validate_non_empty("route", &binding.route)?;
    validate_non_empty("governance_revision", &binding.governance_revision)?;
    if role.requires_work_item() {
        match binding.work_item_id.as_ref() {
            Some(item) => validate_non_empty("work_item_id", item)?,
            None => {
                return Err(RoleLeaseError::WorkItemRequired { role });
            }
        }
    } else if let Some(item) = binding.work_item_id.as_ref() {
        validate_non_empty("work_item_id", item)?;
    }
    if binding.expires_at_unix_ms <= binding.issued_at_unix_ms {
        return Err(RoleLeaseError::InvalidLeaseWindow {
            issued_at_unix_ms: binding.issued_at_unix_ms,
            expires_at_unix_ms: binding.expires_at_unix_ms,
        });
    }
    Ok(())
}
